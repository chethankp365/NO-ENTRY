import pytest
import json
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

def test_terminal_websocket_commands(client):
    with client.websocket_connect("/ws/terminal") as websocket:
        # Drain initial 4 welcome banner lines
        for _ in range(4):
            banner = websocket.receive_json()
            assert banner["type"] == "output"

        # Execute whoami command
        websocket.send_json({"type": "command", "command": "whoami"})
        out = websocket.receive_json()
        assert out["type"] == "output"
        assert "kali" in out["data"]

        # Execute clear command
        websocket.send_json({"type": "command", "command": "clear"})
        clear_msg = websocket.receive_json()
        assert clear_msg["type"] == "clear"

def test_terminal_websocket_run_and_stop_scenario(client):
    with client.websocket_connect("/ws/terminal") as websocket:
        # Drain welcome banner
        for _ in range(4):
            msg = websocket.receive_json()
            assert msg["type"] == "output"

        # Start credential scenario
        websocket.send_json({"type": "run_scenario", "scenario_id": "credential"})
        start_msg = websocket.receive_json()
        assert start_msg["type"] == "scenario_start"
        assert start_msg["scenario_id"] == "credential"
        assert start_msg["total_steps"] > 0

        # Receive stage update
        stage_msg = websocket.receive_json()
        assert stage_msg["type"] == "stage"
        assert stage_msg["stage"].lower() == "recon"

        # Receive first terminal line
        line_msg = websocket.receive_json()
        assert line_msg["type"] == "output"

        # Stop the running scenario
        websocket.send_json({"type": "stop_scenario"})
        stopped_msg = websocket.receive_json()
        assert stopped_msg["type"] in ("scenario_stopped", "stage", "output")

def test_all_five_red_scenarios_valid(client):
    scenarios = ["web-breach", "ransomware", "credential", "insider", "exfiltration"]
    for sc in scenarios:
        with client.websocket_connect("/ws/terminal") as websocket:
            # Drain initial output
            for _ in range(4):
                websocket.receive_json()

            websocket.send_json({"type": "run_scenario", "scenario_id": sc})
            start_msg = websocket.receive_json()
            assert start_msg["type"] == "scenario_start"
            assert start_msg["scenario_id"] == sc
            assert start_msg["total_steps"] > 0
            # Read first stage
            stage_msg = websocket.receive_json()
            assert stage_msg["type"] == "stage"
            # Read first output line
            out_msg = websocket.receive_json()
            assert out_msg["type"] == "output"

def test_red_run_propagates_events_to_watch_websocket(client):
    """Verify that running a scenario in RED emits events that WATCH /ws/events receives."""
    with client.websocket_connect("/ws/events") as watch_ws:
        snapshot = watch_ws.receive_json()
        assert snapshot["type"] == "snapshot"

        with client.websocket_connect("/ws/terminal") as red_ws:
            # Drain welcome lines
            for _ in range(4):
                red_ws.receive_json()

            # Start web-breach
            red_ws.send_json({"type": "run_scenario", "scenario_id": "web-breach"})

            # Drain initial red messages until first event line (step 2 has active scan event)
            # Step 1: Recon line (no event)
            # Step 2: nmap scan line (has T1595 event)
            received_event_in_watch = False
            for _ in range(12):
                red_msg = red_ws.receive_json()
                if red_msg.get("type") == "output" and "nmap" in red_msg.get("data", ""):
                    break

            # Now check watch_ws for the matching event broadcast
            for _ in range(6):
                watch_msg = watch_ws.receive_json()
                if watch_msg.get("type") == "event":
                    data = watch_msg.get("data", {})
                    if data.get("technique_id") in ("T1595", "T1190"):
                        received_event_in_watch = True
                        break

            assert received_event_in_watch, "Expected simulation event from RED scenario in WATCH WebSocket stream"
            red_ws.send_json({"type": "stop_scenario"})

