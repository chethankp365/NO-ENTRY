import pytest
from backend.app.sim.engine import sim_engine

def test_websocket_snapshot_and_event(client):
    with client.websocket_connect("/ws/events") as websocket:
        # First message must be snapshot
        data = websocket.receive_json()
        assert data["type"] == "snapshot"
        assert "metrics" in data["data"]
        assert "hosts" in data["data"]
        assert "recent_events" in data["data"]

        # Send ping
        websocket.send_text("ping")
        resp = websocket.receive_text()
        assert resp == "pong"
