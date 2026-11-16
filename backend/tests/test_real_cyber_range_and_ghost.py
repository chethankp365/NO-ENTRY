"""
Integration and Unit Tests for NO ENTRY Real Cyber Range, Lab Lifecycle,
Distinct Attacker/Target Identities, Terminal Execution, and GHOST AI Mentor.
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.labs.base import DockerStatus, LabSessionInfo
from backend.app.labs.manager import lab_manager


def test_lab_session_info_distinct_identities():
    """Verify that LabSessionInfo contains distinct attacker and target identities and ports."""
    info = LabSessionInfo(
        session_id="test_sess_001",
        room_id="red-09-sqli-fundamentals",
        operator_id="operator_001",
        runner_mode="emulated",
        target_url="http://10.10.18.90:8089",
        target_ip="10.10.18.90",
        target_port=8089,
        target_hostname="target",
        attacker_ip="10.10.18.10",
        attacker_hostname="attacker",
        open_ports=[22, 80, 8089],
        active_sessions_count=1,
    )
    cd = info.client_dict()
    assert cd["target_ip"] == "10.10.18.90"
    assert cd["attacker_ip"] == "10.10.18.10"
    assert cd["target_hostname"] == "target"
    assert cd["attacker_hostname"] == "attacker"
    assert cd["target_ip"] != cd["attacker_ip"]
    assert 8089 in cd["open_ports"]
    assert cd["active_sessions_count"] == 1


def test_lab_status_stopped_state(client):
    """Verify that lab status query returns STOPPED when no containers are active."""
    room_id = "red-09-sqli-fundamentals"
    # Ensure any active session is stopped first
    client.post(f"/api/academy/labs/{room_id}/stop")

    res = client.get(f"/api/academy/labs/{room_id}/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "STOPPED"
    assert "target_ip" in data
    assert "attacker_ip" in data
    assert data["target_ip"] != data["attacker_ip"]


def test_lab_lifecycle_start_stop_reset(client):
    """Verify complete lab lifecycle: START -> RUNNING -> RESET -> STOP -> STOPPED."""
    room_id = "red-09-sqli-fundamentals"

    # 1. START LAB
    start_res = client.post(f"/api/academy/labs/{room_id}/start")
    assert start_res.status_code == 200
    start_data = start_res.json()
    assert start_data["status"] == "RUNNING"
    assert start_data["target_ip"] is not None
    assert start_data["attacker_ip"] is not None
    assert start_data["target_ip"] != start_data["attacker_ip"]
    assert start_data["target_hostname"] == "target"
    assert start_data["attacker_hostname"] == "attacker"

    # 2. STATUS VERIFICATION
    status_res = client.get(f"/api/academy/labs/{room_id}/status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["status"] == "RUNNING"
    assert status_data["target_ip"] == start_data["target_ip"]

    # 3. RESET LAB
    reset_res = client.post(f"/api/academy/labs/{room_id}/reset")
    assert reset_res.status_code == 200
    reset_data = reset_res.json()
    assert reset_data["status"] == "RUNNING"

    # 4. STOP LAB
    stop_res = client.post(f"/api/academy/labs/{room_id}/stop")
    assert stop_res.status_code == 200
    assert stop_res.json()["stopped"] is True

    # 5. VERIFY STOPPED STATE
    final_status = client.get(f"/api/academy/labs/{room_id}/status")
    assert final_status.status_code == 200
    assert final_status.json()["status"] == "STOPPED"


def test_ghost_room_guide_six_steps(client):
    """Verify that GHOST provides 6-step guided path with tools and commands."""
    room_id = "red-09-sqli-fundamentals"
    res = client.get(f"/api/ghost/room/{room_id}/guide")
    assert res.status_code == 200
    data = res.json()
    assert data["room_id"] == room_id
    assert "steps" in data
    assert len(data["steps"]) == 6

    step1 = data["steps"][0]
    assert step1["step"] == 1
    assert "Environment" in step1["title"]
    assert "whoami" in step1["command"]

    step2 = data["steps"][1]
    assert step2["step"] == 2
    assert "Network" in step2["title"]
    assert "ip -br addr" in step2["command"]
    assert "ping" in step2["command"]

    step3 = data["steps"][2]
    assert step3["step"] == 3
    assert "Enumerate" in step3["title"]
    assert "nmap" in step3["command"]


def test_ghost_room_hints_progressive_levels(client):
    """Verify GHOST progressive hints (Level 1: Concept, 2: Tool, 3: Command, 4: Interpretation)."""
    room_id = "red-09-sqli-fundamentals"

    # Level 1: Objective
    h1 = client.get(f"/api/ghost/room/{room_id}/hint?level=1").json()
    assert h1["level"] == 1
    assert "Objective" in h1["label"]
    assert h1["command"] is None

    # Level 2: Tool
    h2 = client.get(f"/api/ghost/room/{room_id}/hint?level=2").json()
    assert h2["level"] == 2
    assert "Tool" in h2["label"]

    # Level 3: Concrete Command
    h3 = client.get(f"/api/ghost/room/{room_id}/hint?level=3").json()
    assert h3["level"] == 3
    assert "Command" in h3["label"]
    assert h3["command"] is not None
    assert "curl" in h3["command"]

    # Level 4: Interpretation
    h4 = client.get(f"/api/ghost/room/{room_id}/hint?level=4").json()
    assert h4["level"] == 4
    assert "Interpretation" in h4["label"]


def test_ghost_room_ask_with_context(client):
    """Verify GHOST Q&A returns accurate, context-aware answers."""
    room_id = "red-09-sqli-fundamentals"
    res = client.post(
        f"/api/ghost/room/{room_id}/ask",
        json={"question": "What is the target IP and how do I scan it?"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["room_id"] == room_id
    assert "target machine is hosted" in data["answer"]
    assert "nmap" in data["answer"]


def test_terminal_websocket_shows_distinct_identities(client):
    """Verify that WebSocket terminal output displays distinct operator and target identities."""
    room_id = "red-09-sqli-fundamentals"

    # Start lab
    client.post(f"/api/academy/labs/{room_id}/start")

    try:
        with client.websocket_connect(f"/ws/academy/{room_id}/terminal") as ws:
            chunks = []
            for _ in range(9):
                msg = ws.receive_json()
                if msg.get("type") == "output":
                    chunks.append(msg["data"])
            full_out = "".join(chunks)
            assert "operator@attacker" in full_out
            assert "target" in full_out
    finally:
        client.post(f"/api/academy/labs/{room_id}/stop")


def test_terminal_persistent_state_cd_and_env(client):
    """Verify that interactive terminal session retains working directory and env across sequential commands."""
    room_id = "red-09-sqli-fundamentals"
    client.post(f"/api/academy/labs/{room_id}/start")
    try:
        with client.websocket_connect(f"/ws/academy/{room_id}/terminal") as ws:
            # Drain initial banner and prompt until initial prompt arrives
            while True:
                msg = ws.receive_json()
                if "operator@noentry" in msg.get("data", ""):
                    break

            # Execute cd /tmp
            ws.send_json({"type": "command", "command": "cd /tmp"})
            prompt_msg = ws.receive_json()
            assert "/tmp" in prompt_msg["data"]

            # Execute pwd
            ws.send_json({"type": "command", "command": "pwd"})
            out_msg = ws.receive_json()
            assert "/tmp" in out_msg["data"]
            prompt_msg2 = ws.receive_json()
            assert "/tmp" in prompt_msg2["data"]

            # Execute export
            ws.send_json({"type": "command", "command": "export TEST_SUITE_VAR=persisted_val"})
            ws.receive_json()

            # Execute echo $TEST_SUITE_VAR
            ws.send_json({"type": "command", "command": "echo $TEST_SUITE_VAR"})
            val_msg = ws.receive_json()
            assert "persisted_val" in val_msg["data"]
    finally:
        client.post(f"/api/academy/labs/{room_id}/stop")
