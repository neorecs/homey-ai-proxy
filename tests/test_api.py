from fastapi.testclient import TestClient

from app.main import app, recent_commands


client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


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
