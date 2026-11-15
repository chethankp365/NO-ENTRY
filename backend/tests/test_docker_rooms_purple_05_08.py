"""
Genuine Docker Lab Integration Tests for Purple Team Rooms 05–08:
- Room 05: Emulating Privilege Escalation Techniques (purple-05-privesc-emulation)
- Room 06: Emulating Defense Evasion & Process Injection (purple-06-defense-evasion-emulation)
- Room 07: Emulating Lateral Movement (SMB, WMI, WinRM) (purple-07-lateral-movement-emulation)
- Room 08: Emulating Persistence Mechanisms (purple-08-persistence-emulation)

Tests live Docker container duos communicating over isolated internal bridge networks,
including genuine WebSocket terminal communication.
"""

import pytest
from backend.app.labs.docker_runner import DockerLabRunner


@pytest.fixture(scope="module")
def docker_runner():
    runner = DockerLabRunner()
    if not runner.is_available():
        pytest.skip("Docker daemon is not operational on this host. Skipping Docker lab tests.")
    return runner


@pytest.mark.asyncio
async def test_docker_room_purple_05_privesc(docker_runner):
    """Room 05: Live Privilege Escalation UAC emulation, telemetry analysis, and detection validation."""
    session_id = "test_docker_purple_05_live"
    info = await docker_runner.start_session(session_id, "purple-05-privesc-emulation", "op-tester-purple05")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"

    try:
        # 1. Inspect telemetry evidence file
        ev_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/privesc/uac_elevation_events.json"
        )
        assert "4688" in ev_out
        assert "fodhelper.exe" in ev_out

        # 2. Run tool to emulate UAC
        emu_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/privesc_emulation_tool.py --emulate-uac"
        )
        assert "PRIVESC_EMULATION_VERIFIED" in emu_out
        assert info.has_action("privesc_emulated")

        # 3. Deploy detection rule
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/privesc_emulation_tool.py --tune-detection"
        )
        assert "DETECTION_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/privesc_emulation_tool.py --challenge"
        )
        assert "PRIVESC_DETECTION_VALIDATED" in chal_out
        assert info.has_action("privesc_detection_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_purple_06_injection(docker_runner):
    """Room 06: Live Process Injection emulation, Sysmon telemetry, and EDR rule tuning."""
    session_id = "test_docker_purple_06_live"
    info = await docker_runner.start_session(session_id, "purple-06-defense-evasion-emulation", "op-tester-purple06")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect Sysmon injection telemetry
        sys_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/injection/sysmon_injection_events.json"
        )
        assert "CreateRemoteThread" in sys_out or "8" in sys_out

        # 2. Emulate process injection
        emu_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/injection_emulation_tool.py --emulate-injection"
        )
        assert "INJECTION_EMULATION_VERIFIED" in emu_out
        assert info.has_action("injection_emulated")

        # 3. Tune EDR
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/injection_emulation_tool.py --tune-edr"
        )
        assert "EDR_TUNED_OK" in tune_out

        # 4. Complete challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/injection_emulation_tool.py --challenge"
        )
        assert "DEFENSE_EVASION_DETECTION_VALIDATED" in chal_out
        assert info.has_action("defense_evasion_detection_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_purple_07_lateral(docker_runner):
    """Room 07: Live Lateral Movement emulation, network logon correlation, and WMI/SMB detection."""
    session_id = "test_docker_purple_07_live"
    info = await docker_runner.start_session(session_id, "purple-07-lateral-movement-emulation", "op-tester-purple07")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect remote execution telemetry
        lat_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/lateral/remote_exec_events.json"
        )
        assert "4624" in lat_out
        assert "PSEXESVC" in lat_out

        # 2. Emulate lateral movement
        emu_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/lateral_emulation_tool.py --emulate-lateral"
        )
        assert "LATERAL_EMULATION_VERIFIED" in emu_out
        assert info.has_action("lateral_emulated")

        # 3. Tune correlation rule
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/lateral_emulation_tool.py --tune-rule"
        )
        assert "RULE_TUNED_OK" in tune_out

        # 4. Complete challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/lateral_emulation_tool.py --challenge"
        )
        assert "LATERAL_MOVEMENT_DETECTION_VALIDATED" in chal_out
        assert info.has_action("lateral_movement_detection_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_purple_08_persistence(docker_runner):
    """Room 08: Live Persistence emulation, scheduled task detection, and automated eradication."""
    session_id = "test_docker_purple_08_live"
    info = await docker_runner.start_session(session_id, "purple-08-persistence-emulation", "op-tester-purple08")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect persistence telemetry
        task_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/persistence/scheduled_task_events.json"
        )
        assert "4698" in task_out
        assert "TelemetryUpdate" in task_out

        # 2. Emulate scheduled task persistence
        emu_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/persistence_emulation_tool.py --emulate-task"
        )
        assert "PERSISTENCE_EMULATION_VERIFIED" in emu_out
        assert info.has_action("persistence_emulated")

        # 3. Remediate scheduled task
        rem_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/persistence_emulation_tool.py --remediate"
        )
        assert "TASK_REMEDIATED_OK" in rem_out

        # 4. Complete challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/persistence_emulation_tool.py --challenge"
        )
        assert "PERSISTENCE_REMEDIATION_VALIDATED" in chal_out
        assert info.has_action("persistence_remediation_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_purple_05_08_websocket_terminal_workflow(docker_runner, client, session):
    """Verify live browser-terminal WebSocket command execution for Purple Team Room 05."""
    from backend.app.db.models import User
    from backend.app.api.auth import create_access_token
    from backend.app.labs.manager import lab_manager

    operator_id = "op-tester-purple05-ws"
    room_id = "purple-05-privesc-emulation"

    user = User(
        username="purple_ws_operator_05",
        email="purple_ws_05@noentry.internal",
        operator_id=operator_id,
        hashed_password="dummy_hash_purple_ws_05",
        xp=0,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    jwt_token = create_access_token({"sub": operator_id, "operator_id": operator_id})
    client.cookies.set("ne_auth_token", jwt_token)

    # Start live Docker session
    session_id = "test_docker_purple05_ws_live"
    info = await lab_manager._docker_runner.start_session(session_id, room_id, operator_id)
    assert info.status == "RUNNING"
    lab_manager._active_sessions[session_id] = info

    try:
        with client.websocket_connect(f"/ws/academy/{room_id}/terminal") as ws:
            # Drain banner output chunks
            for _ in range(8):
                msg = ws.receive_json()
                assert msg["type"] == "output"

            # Execute emulation over WebSocket
            ws.send_json({
                "type": "command",
                "command": "python3 /home/operator/tools/privesc_emulation_tool.py --emulate-uac",
            })
            emu_resp = ws.receive_json()
            assert "PRIVESC_EMULATION_VERIFIED" in emu_resp["data"]
            assert info.has_action("privesc_emulated")
            ws.receive_json()  # Prompt

            # Execute detection tuning over WebSocket
            ws.send_json({
                "type": "command",
                "command": "python3 /home/operator/tools/privesc_emulation_tool.py --tune-detection",
            })
            tune_resp = ws.receive_json()
            assert "DETECTION_TUNED_OK" in tune_resp["data"]
            ws.receive_json()  # Prompt

            # Execute challenge finalization over WebSocket
            ws.send_json({
                "type": "command",
                "command": "python3 /home/operator/tools/privesc_emulation_tool.py --challenge",
            })
            chal_resp = ws.receive_json()
            assert "PRIVESC_DETECTION_VALIDATED" in chal_resp["data"]
            assert info.has_action("privesc_detection_validated")
            ws.receive_json()  # Prompt

    finally:
        await lab_manager._docker_runner.stop_session(session_id)
        lab_manager._active_sessions.pop(session_id, None)

