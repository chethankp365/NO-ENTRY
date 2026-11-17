"""
Unit and Integration Tests for NO ENTRY Practical Lab Engine.
Tests DockerLabRunner, ProcessLabRunner, target vulnerable application exploits,
LabSessionManager ownership, and terminal WebSocket communications.
"""

import asyncio
import pytest
from starlette.testclient import TestClient

from backend.app.labs.docker_runner import DockerLabRunner
from backend.app.labs.process_runner import ProcessLabRunner
from backend.app.labs.manager import lab_manager
from labs.red_room_09_sqli.target.app import target_app, init_target_db


def test_docker_runner_is_available_safe_check():
    """Verify DockerLabRunner.is_available() safely evaluates environment without throwing."""
    runner = DockerLabRunner()
    avail = runner.is_available()
    assert isinstance(avail, bool)


def test_target_app_sqli_auth_bypass_and_parameterized_remediation():
    """Verify the real target app's SQL injection vulnerabilities and remediation."""
    init_target_db()
    c = TestClient(target_app)

    # 1. Normal invalid login fails
    res_bad = c.post("/login", data={"username": "admin", "password": "wrongpassword"})
    assert res_bad.status_code == 401
    assert res_bad.json()["authenticated"] is False

    # 2. Vulnerable authentication bypass using tautology
    res_bypass = c.post("/login", data={"username": "admin' OR 1=1 --", "password": "x"})
    assert res_bypass.status_code == 200
    data_bypass = res_bypass.json()
    assert data_bypass["authenticated"] is True
    assert data_bypass["user"] == "admin"
    assert "NOENTRY{sqli_auth_bypass_success_3914}" in data_bypass["flag"]

    # 3. Remediated endpoint safely rejects the injection attack
    res_secure = c.post("/secure/login", data={"username": "admin' OR 1=1 --", "password": "x"})
    assert res_secure.status_code == 401
    assert res_secure.json()["authenticated"] is False


def test_target_app_union_sqli_and_numeric_filter():
    """Verify UNION data extraction and numeric injection endpoints on target app."""
    init_target_db()
    c = TestClient(target_app)

    # 1. Product search without query returns all
    res_norm = c.get("/search?q=Tactical")
    assert res_norm.status_code == 200
    assert res_norm.json()["count"] > 0

    # 2. UNION SELECT extraction against hidden_flags table
    union_payload = "' UNION SELECT 1, flag_name, flag_value, 4 FROM hidden_flags --"
    res_union = c.get(f"/search?q={union_payload}")
    assert res_union.status_code == 200
    union_data = res_union.json()
    assert any("NOENTRY{union_sqli_data_extraction_7129}" in str(r) for r in union_data["results"])

    # 3. Numeric filter challenge endpoint
    res_filter = c.get("/filter?category=1 UNION SELECT 1, flag_name, flag_value, 4 FROM hidden_flags WHERE id=2")
    assert res_filter.status_code == 200
    assert "NOENTRY{sqli_numeric_challenge_pivot_8842}" in res_filter.text


@pytest.mark.asyncio
async def test_process_runner_lifecycle_and_command_execution():
    """Verify ProcessLabRunner starts target app, executes curl, and resets database."""
    runner = ProcessLabRunner()
    session_id = "test_lab_session_lifecycle_001"

    # Start session
    info = await runner.start_session(session_id, "red-09-sqli-fundamentals", "op-test-1")
    assert info.status == "RUNNING"
    assert info.runner_mode == "emulated"
    assert info.docker_available is False
    assert info.target_port >= 8089

    # Execute system commands
    whoami = await runner.execute_command(session_id, "whoami")
    assert "operator" in whoami

    cat_notes = await runner.execute_command(session_id, "cat notes.txt")
    assert "ENGAGEMENT NOTES" in cat_notes

    # Process emulation uses its explicit loopback service URL, not a fictional target IP.
    curl_out = await runner.execute_command(session_id, f"curl -s {info.target_url}/")
    assert "VOLTGEAR" in curl_out

    # Execute SQLi auth bypass via curl command
    curl_bypass = await runner.execute_command(
        session_id,
        f'curl -s -X POST -d "username=admin\' OR 1=1 --&password=x" {info.target_url}/login'
    )
    assert "NOENTRY{sqli_auth_bypass_success_3914}" in curl_bypass

    # Reset session
    reset_info = await runner.reset_session(session_id)
    assert reset_info.status == "RUNNING"

    # Stop session
    stopped = await runner.stop_session(session_id)
    assert stopped is True


def test_api_lab_status_and_lifecycle_endpoints(client):
    """Test POST /api/academy/labs/{room_id}/start, status, reset, and stop."""
    room_id = "red-09-sqli-fundamentals"
    auth_res = client.post("/api/auth/guest")
    assert auth_res.status_code == 200

    # 1. Initial status when stopped
    res_status = client.get(f"/api/academy/labs/{room_id}/status")
    assert res_status.status_code == 200
    assert res_status.json()["status"] in ("STOPPED", "RUNNING")

    # 2. Start lab session
    res_start = client.post(f"/api/academy/labs/{room_id}/start")
    assert res_start.status_code == 200
    start_data = res_start.json()
    assert start_data["status"] == "RUNNING"
    assert start_data["room_id"] == room_id
    assert "target_url" in start_data

    # 3. Check status is now RUNNING
    res_active = client.get(f"/api/academy/labs/{room_id}/status")
    assert res_active.status_code == 200
    assert res_active.json()["status"] == "RUNNING"

    # 4. Reset lab
    res_reset = client.post(f"/api/academy/labs/{room_id}/reset")
    assert res_reset.status_code == 200
    assert res_reset.json()["status"] == "RUNNING"

    # 5. Stop lab
    res_stop = client.post(f"/api/academy/labs/{room_id}/stop")
    assert res_stop.status_code == 200
    assert res_stop.json()["stopped"] is True


def test_terminal_websocket_academy_interaction(client):
    """Test interactive WebSocket terminal connection to the academy lab."""
    if not lab_manager.is_docker_available():
        pytest.skip("Real Docker is required for the Academy terminal test.")
    room_id = "red-09-sqli-fundamentals"
    auth = client.post("/api/auth/guest")
    assert auth.status_code == 200

    # Ensure lab is active for the operator
    client.post(f"/api/academy/labs/{room_id}/start")

    try:
        with client.websocket_connect(f"/ws/academy/{room_id}/terminal") as ws:
            # Drain the banner until the real shell prompt is ready.
            initial_chunks = []
            while True:
                msg = ws.receive_json()
                assert msg["type"] == "output"
                initial_chunks.append(msg["data"])
                if "operator@noentry" in msg["data"] and "$ " in msg["data"]:
                    break

            full_banner = "".join(initial_chunks)
            assert "NO ENTRY ACADEMY" in full_banner

            # Send command through websocket
            ws.send_json({"type": "command", "command": "whoami"})
            command_output = []
            while True:
                resp = ws.receive_json()
                if resp["type"] == "output":
                    command_output.append(resp["data"])
                elif resp["type"] == "exit_status":
                    assert resp["code"] == 0
                    break
            assert "".join(command_output).strip() == "operator"
    finally:
        client.post(f"/api/academy/labs/{room_id}/stop")
