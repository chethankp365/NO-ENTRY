"""
Genuine Docker Lab Integration Tests for Final Purple Team Rooms 17–20:
- Room 17: EDR Telemetry Blinding & Bypass Emulation (purple-17-edr-bypass-emulation)
- Room 18: TTP Heatmap Generation & Coverage Scoring (purple-18-ttp-heatmap-generation)
- Room 19: Continuous Security Validation & Automated Testing (purple-19-continuous-security-validation)
- Room 20: Purple Team Capstone: Full Adversary Emulation Exercise (purple-20-capstone-purple-exercise)

Tests live Docker container duos communicating over isolated internal bridge networks,
including genuine WebSocket terminal communication.
"""

import pytest
from conftest import drain_terminal_until_prompt, execute_terminal_command
from backend.app.labs.docker_runner import DockerLabRunner


@pytest.fixture(scope="module")
def docker_runner():
    runner = DockerLabRunner()
    if not runner.is_available():
        pytest.skip("Docker daemon is not operational on this host. Skipping Docker lab tests.")
    return runner


@pytest.mark.asyncio
async def test_docker_room_purple_17_edr_bypass(docker_runner):
    """Room 17: Live AMSI bypass, ETW-TI telemetry analysis, and kernel correlation defense."""
    session_id = "test_docker_purple_17_live"
    info = await docker_runner.start_session(session_id, "purple-17-edr-bypass-emulation", "op-tester-purple17")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"

    try:
        # 1. Inspect telemetry evidence file
        ev_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/edr_bypass/amsi_etw_events.json"
        )
        assert "AmsiScanBuffer" in ev_out
        assert "ETW_TI_TAMPERING_DETECTED" in ev_out

        # 2. Run tool to emulate EDR bypass
        emu_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/edr_bypass_tool.py --emulate-bypass"
        )
        assert "EDR_BYPASS_EMULATION_VERIFIED" in emu_out
        assert info.has_action("edr_bypass_emulated")

        # 3. Deploy ETW-TI correlation rule
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/edr_bypass_tool.py --tune-etw"
        )
        assert "ETW_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/edr_bypass_tool.py --challenge"
        )
        assert "EDR_BYPASS_DETECTION_VALIDATED" in chal_out
        assert info.has_action("edr_bypass_detection_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_purple_18_heatmap(docker_runner):
    """Room 18: Live ATT&CK matrix layer generation, coverage scoring, and defense overlay tuning."""
    session_id = "test_docker_purple_18_live"
    info = await docker_runner.start_session(session_id, "purple-18-ttp-heatmap-generation", "op-tester-purple18")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"

    try:
        # 1. Inspect telemetry evidence file
        ev_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/heatmap/attck_coverage_matrix.json"
        )
        assert "T1059.001" in ev_out
        assert "coverage_score" in ev_out

        # 2. Run tool to emulate scoring
        emu_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/heatmap_tool.py --emulate-scoring"
        )
        assert "HEATMAP_EMULATION_VERIFIED" in emu_out
        assert info.has_action("heatmap_emulated")

        # 3. Tune defense overlay
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/heatmap_tool.py --tune-overlay"
        )
        assert "OVERLAY_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/heatmap_tool.py --challenge"
        )
        assert "HEATMAP_COVERAGE_VALIDATED" in chal_out
        assert info.has_action("heatmap_coverage_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_purple_19_continuous_validation(docker_runner):
    """Room 19: Live continuous automated adversary emulation pipeline and canary guardrail validation."""
    session_id = "test_docker_purple_19_live"
    info = await docker_runner.start_session(session_id, "purple-19-continuous-security-validation", "op-tester-purple19")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"

    try:
        # 1. Inspect pipeline run history
        ev_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/continuous_validation/pipeline_run_history.json"
        )
        assert "nightly-atomic-red-canary" in ev_out
        assert "tests_detected" in ev_out

        # 2. Emulate pipeline run
        emu_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/continuous_validation_tool.py --emulate-pipeline"
        )
        assert "CONTINUOUS_VALIDATION_EMULATION_VERIFIED" in emu_out
        assert info.has_action("continuous_validation_emulated")

        # 3. Tune guardrails
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/continuous_validation_tool.py --tune-guardrails"
        )
        assert "GUARDRAILS_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/continuous_validation_tool.py --challenge"
        )
        assert "CONTINUOUS_VALIDATION_DETECTION_VALIDATED" in chal_out
        assert info.has_action("continuous_validation_detection_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_purple_20_capstone(docker_runner):
    """Room 20: Full adversary emulation exercise, multi-phase APT29 campaign, and defense verification."""
    session_id = "test_docker_purple_20_live"
    info = await docker_runner.start_session(session_id, "purple-20-capstone-purple-exercise", "op-tester-purple20")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"

    try:
        # 1. Inspect exercise events
        ev_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/purple_capstone/apt29_exercise_events.json"
        )
        assert "APT29 / Cozy Bear" in ev_out
        assert "T1566.001" in ev_out

        # 2. Emulate multi-phase campaign
        emu_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/purple_capstone_tool.py --emulate-campaign"
        )
        assert "PURPLE_CAPSTONE_EMULATION_VERIFIED" in emu_out
        assert info.has_action("purple_capstone_emulated")

        # 3. Tune enterprise defense rules
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/purple_capstone_tool.py --tune-enterprise-rules"
        )
        assert "ENTERPRISE_RULES_TUNED_OK" in tune_out

        # 4. Complete Capstone challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/purple_capstone_tool.py --challenge"
        )
        assert "PURPLE_CAPSTONE_DETECTION_VALIDATED" in chal_out
        assert info.has_action("purple_capstone_detection_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_websocket_terminal_purple20(docker_runner, client, session):
    """Test authenticated WebSocket terminal executing Capstone commands live inside container."""
    from backend.app.db.models import User
    from backend.app.api.auth import create_access_token
    from backend.app.labs.manager import lab_manager

    operator_id = "op-tester-purple20-ws"
    room_id = "purple-20-capstone-purple-exercise"

    user = User(
        username="purple_ws_operator_20",
        email="purple_ws_20@noentry.internal",
        operator_id=operator_id,
        hashed_password="dummy_hash_purple_ws_20",
        xp=0,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    jwt_token = create_access_token({"sub": operator_id, "operator_id": operator_id})
    client.cookies.set("ne_auth_token", jwt_token)

    # Start live Docker session
    session_id = "test_docker_purple20_ws_live"
    info = await lab_manager._docker_runner.start_session(session_id, room_id, operator_id)
    assert info.status == "RUNNING"
    lab_manager._active_sessions[session_id] = info

    try:
        with client.websocket_connect(f"/ws/academy/{room_id}/terminal") as ws:
            drain_terminal_until_prompt(ws)

            # Execute emulation over WebSocket
            emu_resp = execute_terminal_command(
                ws, "python3 /home/operator/tools/purple_capstone_tool.py --emulate-campaign"
            )
            assert "PURPLE_CAPSTONE_EMULATION_VERIFIED" in emu_resp["data"]
            assert info.has_action("purple_capstone_emulated")

            # Execute rule tuning over WebSocket
            tune_resp = execute_terminal_command(
                ws, "python3 /home/operator/tools/purple_capstone_tool.py --tune-enterprise-rules"
            )
            assert "ENTERPRISE_RULES_TUNED_OK" in tune_resp["data"]

            # Execute challenge finalization over WebSocket
            chal_resp = execute_terminal_command(
                ws, "python3 /home/operator/tools/purple_capstone_tool.py --challenge"
            )
            assert "PURPLE_CAPSTONE_DETECTION_VALIDATED" in chal_resp["data"]
            assert info.has_action("purple_capstone_detection_validated")

    finally:
        await lab_manager._docker_runner.stop_session(session_id)
        lab_manager._active_sessions.pop(session_id, None)
