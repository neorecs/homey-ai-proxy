from fastapi.testclient import TestClient
import httpx

from app.config import Settings
from app.main import app, has_real_secret, homey_auth_configured, recent_commands, validate_oauth_state


client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_setup_page_is_public_but_does_not_expose_secret() -> None:
    from app import main

    previous_proxy_key = main.settings.proxy_api_key
    main.settings.proxy_api_key = "proxy-secret"
    try:
        response = client.get("/setup")
        assert response.status_code == 200
        assert "Homey AI Proxy Setup" in response.text
        assert "X-API-Key" in response.text
        assert "proxy-secret" not in response.text
    finally:
        main.settings.proxy_api_key = previous_proxy_key


def test_proxy_api_key_protects_homey_endpoints() -> None:
    from app import main

    main.settings.proxy_api_key = "proxy-secret"
    try:
        assert client.get("/health").status_code == 200

        missing_key = client.get("/homey/readiness")
        assert missing_key.status_code == 401

        wrong_key = client.get("/homey/readiness", headers={"X-API-Key": "wrong"})
        assert wrong_key.status_code == 401

        correct_key = client.get("/homey/readiness", headers={"X-API-Key": "proxy-secret"})
        assert correct_key.status_code == 200
        assert correct_key.json()["proxy_auth_enabled"] is True
    finally:
        main.settings.proxy_api_key = ""


def test_homey_readiness_reports_safe_mock_state() -> None:
    response = client.get("/homey/readiness")
    assert response.status_code == 200
    body = response.json()
    assert body["mock_mode"] is True
    assert body["auth_configured"] is True
    assert body["ready_for_live_test"] is False
    assert body["live"] is None
    response_text = str(body).lower()
    assert "homey_token" not in response_text
    assert "replace-with-your-homey-token" not in response_text


def test_homey_auth_configured_rejects_placeholder_static_token() -> None:
    settings = Settings(
        homey_use_mock=False,
        homey_auth_mode="static_token",
        homey_token="replace-with-your-homey-token",
    )
    assert homey_auth_configured(settings) is False
    assert has_real_secret("session-token") is True
    assert has_real_secret("replace-with-anything") is False


def test_homey_readiness_requires_proxy_key_for_real_homey() -> None:
    from app import main

    previous_use_mock = main.settings.homey_use_mock
    previous_proxy_key = main.settings.proxy_api_key
    previous_token = main.settings.homey_token
    try:
        main.settings.homey_use_mock = False
        main.settings.proxy_api_key = ""
        main.settings.homey_token = "session-token"
        response = client.get("/homey/readiness")
        assert response.status_code == 200
        body = response.json()
        assert body["mock_mode"] is False
        assert body["proxy_auth_enabled"] is False
        assert body["auth_configured"] is True
        assert body["ready_for_live_test"] is False
        assert body["next_step"] == "Set PROXY_API_KEY before allowing live Homey calls."
    finally:
        main.settings.homey_use_mock = previous_use_mock
        main.settings.proxy_api_key = previous_proxy_key
        main.settings.homey_token = previous_token


def test_homey_readiness_live_uses_mock_status() -> None:
    response = client.get("/homey/readiness?live=true")
    assert response.status_code == 200
    body = response.json()
    assert body["live"]["ok"] is True
    assert body["live"]["homey"]["mode"] == "mock"


def test_homey_oauth_authorize_url_requires_client_config() -> None:
    from app import main

    previous_client_id = main.settings.homey_oauth_client_id
    previous_client_secret = main.settings.homey_oauth_client_secret
    previous_redirect_uri = main.settings.homey_oauth_redirect_uri
    try:
        main.settings.homey_oauth_client_id = ""
        main.settings.homey_oauth_client_secret = ""
        main.settings.homey_oauth_redirect_uri = ""
        response = client.get("/homey/oauth/authorize-url")
        assert response.status_code == 400
    finally:
        main.settings.homey_oauth_client_id = previous_client_id
        main.settings.homey_oauth_client_secret = previous_client_secret
        main.settings.homey_oauth_redirect_uri = previous_redirect_uri


def test_homey_oauth_authorize_url_returns_state() -> None:
    from app import main

    previous_client_id = main.settings.homey_oauth_client_id
    previous_client_secret = main.settings.homey_oauth_client_secret
    previous_redirect_uri = main.settings.homey_oauth_redirect_uri
    try:
        main.settings.homey_oauth_client_id = "client-id"
        main.settings.homey_oauth_client_secret = "client-secret"
        main.settings.homey_oauth_redirect_uri = "http://proxy/homey/oauth/callback"
        response = client.get("/homey/oauth/authorize-url")
        assert response.status_code == 200
        body = response.json()
        assert validate_oauth_state(body["state"], main.settings) is True
        assert "https://api.athom.com/oauth2/authorise?" in body["authorization_url"]
        assert "client_id=client-id" in body["authorization_url"]
        assert "response_type=code" in body["authorization_url"]
        assert "authorization_type=code" not in body["authorization_url"]
    finally:
        main.settings.homey_oauth_client_id = previous_client_id
        main.settings.homey_oauth_client_secret = previous_client_secret
        main.settings.homey_oauth_redirect_uri = previous_redirect_uri


def test_homey_oauth_callback_rejects_unknown_state() -> None:
    response = client.get("/homey/oauth/callback?code=abc&state=unknown")
    assert response.status_code == 400


def test_homey_oauth_state_is_stateless() -> None:
    from app import main

    previous_proxy_key = main.settings.proxy_api_key
    previous_client_secret = main.settings.homey_oauth_client_secret
    try:
        main.settings.proxy_api_key = "proxy-secret"
        main.settings.homey_oauth_client_secret = "client-secret"
        state = main.create_oauth_state(main.settings)
        assert main.validate_oauth_state(state, main.settings) is True
    finally:
        main.settings.proxy_api_key = previous_proxy_key
        main.settings.homey_oauth_client_secret = previous_client_secret


def test_homey_oauth_callback_exchanges_code(monkeypatch) -> None:
    from app import main

    previous_client_id = main.settings.homey_oauth_client_id
    previous_client_secret = main.settings.homey_oauth_client_secret
    previous_redirect_uri = main.settings.homey_oauth_redirect_uri

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://api.athom.com/oauth2/token"
        assert request.method == "POST"
        assert request.headers["authorization"].startswith("Basic ")
        assert b"code=oauth-code" in request.content
        assert b"authorization_code=oauth-code" not in request.content
        assert b"redirect_uri=http%3A%2F%2Fproxy%2Fhomey%2Foauth%2Fcallback" in request.content
        return httpx.Response(
            200,
            json={
                "access_token": "cloud-access",
                "refresh_token": "cloud-refresh",
                "expires_in": 3600,
            },
        )

    real_async_client = httpx.AsyncClient

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs) -> None:
            self.client = real_async_client(transport=httpx.MockTransport(handler))

        async def __aenter__(self):
            return self.client

        async def __aexit__(self, *args):
            await self.client.aclose()

    monkeypatch.setattr("app.main.httpx.AsyncClient", FakeAsyncClient)

    try:
        main.settings.homey_oauth_client_id = "client-id"
        main.settings.homey_oauth_client_secret = "client-secret"
        main.settings.homey_oauth_redirect_uri = "http://proxy/homey/oauth/callback"
        state = main.create_oauth_state(main.settings)
        response = client.get(f"/homey/oauth/callback?code=oauth-code&state={state}")
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert body["env"]["HOMEY_AUTH_MODE"] == "oauth2_session"
        assert body["env"]["HOMEY_OAUTH_REFRESH_TOKEN"] == "cloud-refresh"
        assert body["env"]["HOMEY_OAUTH_ACCESS_TOKEN"] == "cloud-access"
        assert "client-secret" not in str(body)
    finally:
        main.settings.homey_oauth_client_id = previous_client_id
        main.settings.homey_oauth_client_secret = previous_client_secret
        main.settings.homey_oauth_redirect_uri = previous_redirect_uri


def test_homey_oauth_callback_returns_safe_error_detail(monkeypatch) -> None:
    from app import main

    previous_client_id = main.settings.homey_oauth_client_id
    previous_client_secret = main.settings.homey_oauth_client_secret
    previous_redirect_uri = main.settings.homey_oauth_redirect_uri

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={
                "error": "invalid_grant",
                "error_description": "Authorization code was invalid or expired",
            },
        )

    real_async_client = httpx.AsyncClient

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs) -> None:
            self.client = real_async_client(transport=httpx.MockTransport(handler))

        async def __aenter__(self):
            return self.client

        async def __aexit__(self, *args):
            await self.client.aclose()

    monkeypatch.setattr("app.main.httpx.AsyncClient", FakeAsyncClient)

    try:
        main.settings.homey_oauth_client_id = "client-id"
        main.settings.homey_oauth_client_secret = "client-secret"
        main.settings.homey_oauth_redirect_uri = "http://proxy/homey/oauth/callback"
        state = main.create_oauth_state(main.settings)
        response = client.get(f"/homey/oauth/callback?code=oauth-code&state={state}")
        assert response.status_code == 502
        assert response.json()["detail"] == "Homey OAuth2 code exchange failed: Authorization code was invalid or expired"
    finally:
        main.settings.homey_oauth_client_id = previous_client_id
        main.settings.homey_oauth_client_secret = previous_client_secret
        main.settings.homey_oauth_redirect_uri = previous_redirect_uri


def test_flow_start_endpoint_uses_mock_homey() -> None:
    response = client.post("/homey/flows/start", json={"flow_name": "AI - Presence test"})
    assert response.status_code == 200
    assert response.json()["success"] is True


def test_command_endpoint_maps_to_presence_flow() -> None:
    recent_commands.clear()
    response = client.post("/homey/command", json={"command": "test presence"})
    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["flow_name"] == "AI - Presence test"


def test_command_endpoint_blocks_risky_keyword() -> None:
    response = client.post("/homey/command", json={"command": "slot openen"})
    assert response.status_code == 403
