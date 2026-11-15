"""
Genuine Docker Lab Integration Tests for Purple Team Rooms 01–04:
- Room 01: Purple Team Foundations (purple-01-purple-team-foundations)
- Room 02: MITRE ATT&CK Fundamentals (purple-02-mitre-attack-fundamentals)
- Room 03: Attack Simulation Planning (purple-03-attack-simulation-planning)
- Room 04: Reconnaissance vs Monitoring (purple-04-reconnaissance-vs-monitoring)

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
async def test_docker_room_purple_01_foundations(docker_runner):
    """Room 01: Live Purple Team Foundations scope submission, telemetry mapping, and exercise finalization."""
    session_id = "test_docker_purple_01_live"
    info = await docker_runner.start_session(session_id, "purple-01-purple-team-foundations", "op-tester-purple01")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"

    try:
        # 1. Inspect scope manifest
        manifest_out = await docker_runner.execute_command(
            session_id,
            "cat /home/operator/purple/scope_manifest.json"
        )
        assert "PT-2026-001" in manifest_out
        assert "T1059.001" in manifest_out
        assert "COLLABORATIVE_PAIRING" in manifest_out

        # 2. Submit purple scope
        scope_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/purple_foundations_tool.py --submit-scope"
        )
        assert "PURPLE_SCOPE_APPROVED" in scope_out

        # 3. Map telemetry
        map_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/purple_foundations_tool.py --map-telemetry"
        )
        assert "PURPLE_TELEMETRY_MAP_VERIFIED" in map_out
        assert info.has_action("purple_telemetry_mapped")

        # 4. Finalize exercise challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/purple_foundations_tool.py --finalize"
        )
        assert "PURPLE_FOUNDATIONS_EXERCISE_APPROVED" in chal_out
        assert info.has_action("purple_foundations_approved")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_purple_02_attck(docker_runner):
    """Room 02: Live MITRE ATT&CK Matrix evidence mapping and adversary lifecycle correlation."""
    session_id = "test_docker_purple_02_live"
    info = await docker_runner.start_session(session_id, "purple-02-mitre-attack-fundamentals", "op-tester-purple02")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect auth and persistence evidence
        auth_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/attck_evidence/auth_events.json"
        )
        assert "4769" in auth_out
        assert "T1558.003" in auth_out

        persist_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/attck_evidence/persistence_events.json"
        )
        assert "4657" in persist_out
        assert "T1547.001" in persist_out

        # 2. Map evidence
        map_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/attck_mapping_tool.py --map-evidence"
        )
        assert "ATTCK_EVIDENCE_MAPPING_VERIFIED" in map_out
        assert info.has_action("attck_evidence_mapped")

        # 3. Complete challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/attck_mapping_tool.py --challenge"
        )
        assert "ATTCK_LIFECYCLE_MAPPING_COMPLETE" in chal_out
        assert info.has_action("attck_lifecycle_complete")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_purple_03_simulation(docker_runner):
    """Room 03: Live Attack Simulation Planning governance, atomic step registration, and rollback specification."""
    session_id = "test_docker_purple_03_live"
    info = await docker_runner.start_session(session_id, "purple-03-attack-simulation-planning", "op-tester-purple03")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect simulation specification
        spec_out = await docker_runner.execute_command(
            session_id,
            "cat /home/operator/simulation/exercise_spec.json"
        )
        assert "SIM-2026-ALPHA" in spec_out
        assert "Rules of Engagement" in spec_out
        assert "10.10.14.90" in spec_out

        # 2. Validate simulation scope
        val_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/simulation_planner.py --validate-scope"
        )
        assert "SIMULATION_SCOPE_VALIDATED" in val_out

        # 3. Register simulation step
        step_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/simulation_planner.py --register-step"
        )
        assert "SIMULATION_STEP_REGISTERED" in step_out
        assert info.has_action("simulation_step_registered")

        # 4. Approve simulation plan challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/simulation_planner.py --approve-plan"
        )
        assert "ATTACK_SIMULATION_PLAN_APPROVED" in chal_out
        assert info.has_action("simulation_plan_approved")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_purple_04_recon_monitoring(docker_runner):
    """Room 04: Live Reconnaissance vs Monitoring correlation, Nmap analysis, and sensor threshold tuning."""
    session_id = "test_docker_purple_04_live"
    info = await docker_runner.start_session(session_id, "purple-04-reconnaissance-vs-monitoring", "op-tester-purple04")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect scan results and alerts
        scan_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/recon/scan_results.txt"
        )
        assert "8094" in scan_out
        assert "SYN" in scan_out

        alert_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/recon/sensor_alerts.log"
        )
        assert "PORT_SCAN_DETECTED" in alert_out
        assert "8094" in alert_out

        # 2. Correlate reconnaissance telemetry
        corr_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/recon_correlator.py --correlate"
        )
        assert "RECON_MONITORING_CORRELATION_CONFIRMED" in corr_out
        assert info.has_action("recon_correlation_confirmed")

        # 3. Tune threshold
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/recon_correlator.py --tune-threshold"
        )
        assert "THRESHOLD_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/recon_correlator.py --finalize"
        )
        assert "RECON_VS_MONITORING_VALIDATED" in chal_out
        assert info.has_action("recon_monitoring_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_purple_websocket_terminal_workflow(docker_runner, client, session):
    """Verify live browser-terminal WebSocket command execution for Purple Team exercises."""
    from backend.app.db.models import User
    from backend.app.api.auth import create_access_token
    from backend.app.labs.manager import lab_manager

    operator_id = "op-tester-purple-ws"
    room_id = "purple-01-purple-team-foundations"

    user = User(
        username="purple_ws_operator",
        email="purple_ws@noentry.internal",
        operator_id=operator_id,
        hashed_password="dummy_hash_purple_ws",
        xp=0,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    jwt_token = create_access_token({"sub": operator_id, "operator_id": operator_id})
    client.cookies.set("ne_auth_token", jwt_token)

    # Start live Docker session
    session_id = "test_docker_purple_ws_live"
    info = await lab_manager._docker_runner.start_session(session_id, room_id, operator_id)
    assert info.status == "RUNNING"
    lab_manager._active_sessions[session_id] = info

    try:
        with client.websocket_connect(f"/ws/academy/{room_id}/terminal") as ws:
            # Drain banner output chunks
            for _ in range(8):
                msg = ws.receive_json()
                assert msg["type"] == "output"

            # Execute scope submission over WebSocket
            ws.send_json({
                "type": "command",
                "command": "python3 /home/operator/tools/purple_foundations_tool.py --submit-scope",
            })
            scope_resp = ws.receive_json()
            assert "PURPLE_SCOPE_APPROVED" in scope_resp["data"]
            ws.receive_json()  # Prompt

            # Execute telemetry mapping over WebSocket
            ws.send_json({
                "type": "command",
                "command": "python3 /home/operator/tools/purple_foundations_tool.py --map-telemetry",
            })
            map_resp = ws.receive_json()
            assert "PURPLE_TELEMETRY_MAP_VERIFIED" in map_resp["data"]
            assert info.has_action("purple_telemetry_mapped")
            ws.receive_json()  # Prompt

            # Execute exercise finalization over WebSocket
            ws.send_json({
                "type": "command",
                "command": "python3 /home/operator/tools/purple_foundations_tool.py --finalize",
            })
            fin_resp = ws.receive_json()
            assert "PURPLE_FOUNDATIONS_EXERCISE_APPROVED" in fin_resp["data"]
            assert info.has_action("purple_foundations_approved")
            ws.receive_json()  # Prompt

    finally:
        await lab_manager._docker_runner.stop_session(session_id)
        lab_manager._active_sessions.pop(session_id, None)
