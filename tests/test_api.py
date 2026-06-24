from fastapi.testclient import TestClient

from app.config import Settings
from app.main import app, has_real_secret, homey_auth_configured, recent_commands


client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


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


def test_homey_readiness_live_uses_mock_status() -> None:
    response = client.get("/homey/readiness?live=true")
    assert response.status_code == 200
    body = response.json()
    assert body["live"]["ok"] is True
    assert body["live"]["homey"]["mode"] == "mock"


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
