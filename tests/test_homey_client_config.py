import pytest
import httpx

from app.config import Settings
from app.homey_client import HomeyConfigurationError, HttpHomeyClient


def make_settings(**overrides) -> Settings:
    data = {
        "homey_use_mock": False,
        "homey_base_url": "http://10.5.2.201",
        "homey_token": "session-token",
    }
    data.update(overrides)
    return Settings(**data)


def test_http_client_accepts_private_homey_ip() -> None:
    client = HttpHomeyClient(make_settings())
    assert client.base_url == "http://10.5.2.201"


def test_http_client_rejects_athom_cloud_runtime_url() -> None:
    with pytest.raises(HomeyConfigurationError):
        HttpHomeyClient(make_settings(homey_base_url="https://api.athom.com"))


def test_http_client_rejects_public_runtime_ip() -> None:
    with pytest.raises(HomeyConfigurationError):
        HttpHomeyClient(make_settings(homey_base_url="https://8.8.8.8"))


def test_oauth2_session_mode_requires_oauth_settings() -> None:
    client = HttpHomeyClient(make_settings(homey_auth_mode="oauth2_session"))
    with pytest.raises(HomeyConfigurationError):
        import asyncio

        asyncio.run(client.status())


@pytest.mark.asyncio
async def test_oauth2_session_uses_cloud_only_for_tokens_and_local_for_runtime(monkeypatch) -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url)))
        if str(request.url) == "https://api.athom.com/oauth2/token":
            return httpx.Response(200, json={"access_token": "cloud-access", "refresh_token": "new-refresh", "expires_in": 3600})
        if str(request.url) == "https://api.athom.com/delegation/token?audience=homey":
            return httpx.Response(200, json="delegation-token")
        if str(request.url) == "http://10.5.2.201/api/manager/users/login":
            return httpx.Response(200, json="local-session-token")
        if str(request.url) == "http://10.5.2.201/api/manager/system":
            assert request.headers["authorization"] == "Bearer local-session-token"
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404, json={"error": "unexpected"})

    real_async_client = httpx.AsyncClient

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs) -> None:
            self.client = real_async_client(transport=httpx.MockTransport(handler))

        async def __aenter__(self):
            return self.client

        async def __aexit__(self, *args):
            await self.client.aclose()

    monkeypatch.setattr("app.homey_client.httpx.AsyncClient", FakeAsyncClient)

    client = HttpHomeyClient(
        make_settings(
            homey_auth_mode="oauth2_session",
            homey_oauth_client_id="client-id",
            homey_oauth_client_secret="client-secret",
            homey_oauth_refresh_token="refresh-token",
        )
    )

    assert await client.status() == {"connected": True, "mode": "http"}
    assert seen == [
        ("POST", "https://api.athom.com/oauth2/token"),
        ("POST", "https://api.athom.com/delegation/token?audience=homey"),
        ("POST", "http://10.5.2.201/api/manager/users/login"),
        ("GET", "http://10.5.2.201/api/manager/system"),
    ]


@pytest.mark.asyncio
async def test_oauth2_session_can_use_existing_access_token(monkeypatch) -> None:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url)))
        if str(request.url) == "https://api.athom.com/delegation/token?audience=homey":
            assert request.headers["authorization"] == "Bearer existing-cloud-access"
            return httpx.Response(200, json="delegation-token")
        if str(request.url) == "http://10.5.2.201/api/manager/users/login":
            return httpx.Response(200, json="local-session-token")
        if str(request.url) == "http://10.5.2.201/api/manager/system":
            assert request.headers["authorization"] == "Bearer local-session-token"
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404, json={"error": "unexpected"})

    real_async_client = httpx.AsyncClient

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs) -> None:
            self.client = real_async_client(transport=httpx.MockTransport(handler))

        async def __aenter__(self):
            return self.client

        async def __aexit__(self, *args):
            await self.client.aclose()

    monkeypatch.setattr("app.homey_client.httpx.AsyncClient", FakeAsyncClient)

    client = HttpHomeyClient(
        make_settings(
            homey_auth_mode="oauth2_session",
            homey_oauth_access_token="existing-cloud-access",
        )
    )

    assert await client.status() == {"connected": True, "mode": "http"}
    assert seen == [
        ("POST", "https://api.athom.com/delegation/token?audience=homey"),
        ("POST", "http://10.5.2.201/api/manager/users/login"),
        ("GET", "http://10.5.2.201/api/manager/system"),
    ]
