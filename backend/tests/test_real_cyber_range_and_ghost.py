"""
Integration and Unit Tests for NO ENTRY Real Cyber Range, Lab Lifecycle,
Distinct Attacker/Target Identities, Terminal Execution, and GHOST AI Mentor.
"""

import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from conftest import drain_terminal_until_prompt
from backend.app.db.models import LabSessionRecord
from backend.app.labs.base import DockerStatus, LabSessionInfo
from backend.app.labs.manager import LabSessionManager, lab_manager


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
    client.post("/api/auth/guest")
    # Ensure any active session is stopped first
    client.post(f"/api/academy/labs/{room_id}/stop")

    res = client.get(f"/api/academy/labs/{room_id}/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "STOPPED"
    assert "target_ip" in data
    assert "attacker_ip" in data
    assert data["target_ip"] is None
    assert data["attacker_ip"] is None


def test_terminal_websocket_requires_authentication(client):
    """The terminal WebSocket must reject unauthenticated connections."""
    room_id = "red-09-sqli-fundamentals"
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/academy/{room_id}/terminal") as ws:
            ws.receive_json()


def test_lab_lifecycle_start_stop_reset(client):
    """Verify complete lab lifecycle: START -> RUNNING -> RESET -> STOP -> STOPPED."""
    room_id = "red-09-sqli-fundamentals"
    client.post("/api/auth/guest")

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


def test_lab_lifecycle_endpoints_require_authenticated_operator(client):
    """Lab REST identity must match the authenticated terminal WebSocket identity."""
    room_id = "red-09-sqli-fundamentals"
    requests = (
        ("get", f"/api/academy/labs/{room_id}/status"),
        ("post", f"/api/academy/labs/{room_id}/start"),
        ("post", f"/api/academy/labs/{room_id}/reset"),
        ("post", f"/api/academy/labs/{room_id}/stop"),
    )
    for method, path in requests:
        response = getattr(client, method)(path)
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_manager_restores_persisted_docker_session(session, monkeypatch):
    """A backend restart should recover a valid session from inspected Docker resources."""
    now = datetime.utcnow()
    record = LabSessionRecord(
        session_id="lab_restore_session",
        user_id=1,
        operator_id="op-restore",
        room_id="red-09-sqli-fundamentals",
        status="RUNNING",
        target_url="http://10.10.14.90:8089",
        target_ip="10.10.14.90",
        target_port=8089,
        runner_mode="docker",
        docker_available=True,
        network_id="noentry_net_restore",
        attacker_container_id="attacker-id",
        target_container_id="target-id",
        created_at=now,
        expires_at=now + timedelta(minutes=30),
    )
    session.add(record)
    session.commit()

    manager = LabSessionManager()

    async def restore_session(**kwargs):
        return LabSessionInfo(
            session_id=kwargs["session_id"],
            room_id=kwargs["room_id"],
            operator_id=kwargs["operator_id"],
            runner_mode="docker",
            status="RUNNING",
            target_url="http://10.10.14.90:8089",
            target_ip="10.10.14.90",
            target_port=8089,
            attacker_ip="10.10.14.10",
            network_id=kwargs["network_name"],
            attacker_container_id=kwargs["expected_attacker_id"],
            target_container_id=kwargs["expected_target_id"],
            created_at=kwargs["created_at"],
            expires_at=kwargs["expires_at"],
        )

    monkeypatch.setattr(manager._docker_runner, "restore_session", restore_session)
    await manager.restore_active_sessions(session)

    restored = manager.get_user_session("op-restore", "red-09-sqli-fundamentals")
    assert restored is not None
    assert restored.status == "RUNNING"
    assert restored.attacker_container_id == "attacker-id"
    assert restored.target_container_id == "target-id"


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
    assert step1["command"] is None

    step2 = data["steps"][1]
    assert step2["step"] == 2
    assert "Network" in step2["title"]
    assert step2["command"] is None

    step3 = data["steps"][2]
    assert step3["step"] == 3
    assert "Enumerate" in step3["title"]
    assert step3["command"] is None
    assert data["target_ip"] is None
    assert data["lab_status"] == "STOPPED"


def test_ghost_guide_tracks_backend_task_progress(client):
    """GHOST advances tasks only after the backend validator records completion."""
    room_id = "red-09-sqli-fundamentals"
    before = client.get(f"/api/ghost/room/{room_id}/guide").json()
    assert before["active_task_id"] == "task-01-detection"

    rejected = client.post(
        f"/api/academy/rooms/{room_id}/tasks/task-01-detection/submit",
        json={"answer": "not the answer"},
    ).json()
    assert rejected["completed"] is False
    still_on_task = client.get(f"/api/ghost/room/{room_id}/guide").json()
    assert still_on_task["active_task_id"] == "task-01-detection"

    accepted = client.post(
        f"/api/academy/rooms/{room_id}/tasks/task-01-detection/submit",
        json={"answer": "'"},
    ).json()
    assert accepted["completed"] is True
    after = client.get(f"/api/ghost/room/{room_id}/guide").json()
    assert after["active_task_id"] == "task-02-auth-bypass"
    room_detail = client.get(f"/api/academy/rooms/{room_id}").json()
    assert after["steps"][3]["title"] == f"Practise: {room_detail['tasks'][1]['title']}"


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
    assert h3["command"] is None
    assert h3["target_ip"] is None
    assert "<target-ip>" not in h3["hint"]

    # Level 4: Interpretation
    h4 = client.get(f"/api/ghost/room/{room_id}/hint?level=4").json()
    assert h4["level"] == 4
    assert "Interpretation" in h4["label"]


def test_ghost_tool_hint_uses_live_room_tools_and_target(client):
    """Active-room tool guidance must use the current target rather than stopped-state advice."""
    room_id = "red-09-sqli-fundamentals"
    info = LabSessionInfo(
        session_id="test_ghost_hint_active",
        room_id=room_id,
        operator_id="op-0x7f3a",
        runner_mode="docker",
        status="RUNNING",
        target_url="http://10.10.18.90:8089",
        target_ip="10.10.18.90",
        target_port=8089,
        target_hostname="target",
        attacker_ip="10.10.18.10",
        attacker_hostname="attacker",
        open_ports=[8089],
    )
    lab_manager._active_sessions[info.session_id] = info
    try:
        hint = client.get(f"/api/ghost/room/{room_id}/hint?level=2").json()
        assert "Browser" in hint["hint"]
        assert "curl" in hint["hint"]
        assert "10.10.18.90:8089" in hint["hint"]
        assert "Start the lab first" not in hint["hint"]

        payload_hint = client.get(
            f"/api/ghost/room/{room_id}/hint?level=3&task_id=task-02-auth-bypass"
        ).json()
        assert "admin' OR 1=1 --" in payload_hint["hint"]
        assert payload_hint["command"] is None
    finally:
        lab_manager._active_sessions.pop(info.session_id, None)


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
    assert "lab is not running" in data["answer"]
    assert "has not assigned a target IP" in data["answer"]
    assert data["ai_generated"] is False

    next_step = client.post(
        f"/api/ghost/room/{room_id}/ask",
        json={"question": "What is my next step?"},
    ).json()
    assert "start this room's Docker lab" in next_step["answer"]
    assert "10.10." not in next_step["answer"]


def test_terminal_websocket_shows_distinct_identities(client):
    """Verify that WebSocket terminal output displays distinct operator and target identities."""
    if not lab_manager.is_docker_available():
        pytest.skip("Real Docker is required for the Academy terminal test.")
    room_id = "red-09-sqli-fundamentals"
    assert client.post("/api/auth/guest").status_code == 200

    # Start lab
    start_response = client.post(f"/api/academy/labs/{room_id}/start")
    assert start_response.status_code == 200, start_response.text
    assert start_response.json()["status"] == "RUNNING"

    try:
        with client.websocket_connect(f"/ws/academy/{room_id}/terminal") as ws:
            chunks = [message["data"] for message in drain_terminal_until_prompt(ws)]
            full_out = "".join(chunks)
            assert "operator@attacker" in full_out
            assert "target" in full_out
    finally:
        client.post(f"/api/academy/labs/{room_id}/stop")


def test_terminal_persistent_state_cd_and_env(client):
    """Verify that interactive terminal session retains working directory and env across sequential commands."""
    if not lab_manager.is_docker_available():
        pytest.skip("Real Docker is required for the Academy terminal test.")
    room_id = "red-09-sqli-fundamentals"
    assert client.post("/api/auth/guest").status_code == 200
    start_response = client.post(f"/api/academy/labs/{room_id}/start")
    assert start_response.status_code == 200, start_response.text
    assert start_response.json()["status"] == "RUNNING"
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
            while prompt_msg.get("type") != "output":
                prompt_msg = ws.receive_json()
            assert "/tmp" in prompt_msg["data"]

            # Execute pwd
            ws.send_json({"type": "command", "command": "pwd"})
            out_msg = ws.receive_json()
            while out_msg.get("type") != "output":
                out_msg = ws.receive_json()
            assert "/tmp" in out_msg["data"]
            prompt_msg2 = ws.receive_json()
            while prompt_msg2.get("type") != "output":
                prompt_msg2 = ws.receive_json()
            assert "/tmp" in prompt_msg2["data"]

            # Execute export
            ws.send_json({"type": "command", "command": "export TEST_SUITE_VAR=persisted_val"})
            while ws.receive_json().get("type") != "output":
                pass

            # Execute echo $TEST_SUITE_VAR
            ws.send_json({"type": "command", "command": "echo $TEST_SUITE_VAR"})
            val_msg = ws.receive_json()
            while val_msg.get("type") != "output":
                val_msg = ws.receive_json()
            assert "persisted_val" in val_msg["data"]
            while ws.receive_json().get("type") != "exit_status":
                pass

            def execute_and_collect(command):
                ws.send_json({"type": "command", "command": command})
                output = []
                while True:
                    message = ws.receive_json()
                    if message.get("type") == "output":
                        output.append(message.get("data", ""))
                    elif message.get("type") == "exit_status":
                        return "".join(output), message["code"]

            identity_output, exit_code = execute_and_collect(
                "whoami && id && hostname && ip -br addr"
            )
            assert exit_code == 0
            assert "operator" in identity_output
            assert "uid=1000(operator)" in identity_output
            assert "attacker" in identity_output and "eth0" in identity_output
            guide_after_identity = client.get(f"/api/ghost/room/{room_id}/guide").json()
            assert guide_after_identity["steps"][0]["completed"] is True
            assert guide_after_identity["steps"][1]["completed"] is True
            assert guide_after_identity["active_step"] == 3

            target_ip = client.get(f"/api/academy/labs/{room_id}/status").json()["target_ip"]
            target_output, exit_code = execute_and_collect(
                f"curl -s http://{target_ip}:8089/"
            )
            assert exit_code == 0
            assert "VoltGear" in target_output

            _, exit_code = execute_and_collect("false")
            assert exit_code == 1

            scan_output, exit_code = execute_and_collect(
                f"nmap -sV --version-light -T4 --max-retries 1 -p 8089 {target_ip}"
            )
            assert exit_code == 0
            assert "Nmap done" in scan_output and "8089" in scan_output
            guide_after_scan = client.get(f"/api/ghost/room/{room_id}/guide").json()
            assert guide_after_scan["steps"][2]["completed"] is True
            assert guide_after_scan["active_step"] == 4

            ws.send_json({"type": "input", "data": "\x1b[A"})
            history_recall = ""
            while "nmap -sV --version-light -T4 --max-retries 1 -p 8089" not in history_recall:
                message = ws.receive_json()
                if message.get("type") == "output":
                    history_recall += message.get("data", "")
    finally:
        client.post(f"/api/academy/labs/{room_id}/stop")
