import pytest

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


def test_oauth2_session_mode_is_explicitly_not_runtime_implemented_yet() -> None:
    client = HttpHomeyClient(make_settings(homey_auth_mode="oauth2_session"))
    with pytest.raises(HomeyConfigurationError):
        import asyncio

        asyncio.run(client.status())
