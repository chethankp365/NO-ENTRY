"""
Genuine Docker Lab Integration Tests for Detection Engineering Rooms 13–16:
- Room 13: Baseline Profiling & Threshold-Based Detections (detect-13-threshold-detections)
- Room 14: Correlation Rules: Multi-Event Detection (detect-14-correlation-rules)
- Room 15: Detection Testing with Unit Tests & Synthetic Logs (detect-15-unit-testing-rules)
- Room 16: YARA Rules for File & Memory Threat Hunting (detect-16-yara-hunting)

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
async def test_docker_room_detect_13_threshold(docker_runner):
    """Room 13: Live Baseline Profiling & Threshold-Based Detections evaluation and rolling window tuning."""
    session_id = "test_docker_detect_13_live"
    info = await docker_runner.start_session(session_id, "detect-13-threshold-detections", "op-tester-detect13")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"

    try:
        # 1. Inspect telemetry dataset
        dataset_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/threshold_baseline_events.json"
        )
        assert "ATTACK_PASSWORD_SPRAY_SPIKE" in dataset_out
        assert "THRESHOLD_EXCEEDED" in dataset_out

        # 2. Run detection emulation
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/threshold_tool.py --emulate-detection"
        )
        assert "THRESHOLD_DETECTION_VERIFIED" in emulate_out
        assert info.has_action("threshold_detection_verified")

        # 3. Tune rolling window parameters
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/threshold_tool.py --tune-window"
        )
        assert "ROLLING_WINDOW_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/threshold_tool.py --challenge"
        )
        assert "THRESHOLD_DETECTION_VALIDATED" in chal_out
        assert info.has_action("threshold_detection_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_detect_14_correlation(docker_runner):
    """Room 14: Live Correlation Rules: Multi-Event Detection evaluation and sequence tuning."""
    session_id = "test_docker_detect_14_live"
    info = await docker_runner.start_session(session_id, "detect-14-correlation-rules", "op-tester-detect14")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect telemetry dataset
        dataset_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/multi_event_correlation_stream.json"
        )
        assert "ATTACK_SPEARPHISHING_ATTACHMENT" in dataset_out
        assert "ATTACK_MACRO_EXECUTION" in dataset_out
        assert "ATTACK_C2_BEACON" in dataset_out

        # 2. Emulate multi-event correlation
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/correlation_rule_tool.py --emulate-correlation"
        )
        assert "CORRELATION_RULE_VERIFIED" in emulate_out
        assert info.has_action("correlation_rule_verified")

        # 3. Tune sequence constraints
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/correlation_rule_tool.py --tune-sequence"
        )
        assert "CORRELATION_SEQUENCE_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/correlation_rule_tool.py --challenge"
        )
        assert "CORRELATION_RULE_VALIDATED" in chal_out
        assert info.has_action("correlation_rule_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_detect_15_unit_testing(docker_runner):
    """Room 15: Live Detection Testing with Unit Tests & Synthetic Logs."""
    session_id = "test_docker_detect_15_live"
    info = await docker_runner.start_session(session_id, "detect-15-unit-testing-rules", "op-tester-detect15")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect synthetic test fixtures
        fixtures_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/synthetic_test_fixtures.json"
        )
        assert "FIX-POS-01" in fixtures_out
        assert "FIX-NEG-01" in fixtures_out

        # 2. Execute unit tests
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/detection_testing_tool.py --run-tests"
        )
        assert "DETECTION_UNIT_TEST_VERIFIED" in emulate_out
        assert info.has_action("detection_unit_test_verified")

        # 3. Tune fixtures and assertions
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/detection_testing_tool.py --tune-fixtures"
        )
        assert "FIXTURE_ASSERTIONS_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/detection_testing_tool.py --challenge"
        )
        assert "DETECTION_UNIT_TEST_VALIDATED" in chal_out
        assert info.has_action("detection_unit_test_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_detect_16_yara_hunting(docker_runner):
    """Room 16: Live YARA Rules for File & Memory Threat Hunting."""
    session_id = "test_docker_detect_16_live"
    info = await docker_runner.start_session(session_id, "detect-16-yara-hunting", "op-tester-detect16")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect memory samples
        samples_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/yara_target_memory_samples.json"
        )
        assert "SUSPICIOUS_REFLECTIVE_DLL" in samples_out
        assert "4D 5A 90" in samples_out

        # 2. Execute YARA scan
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/yara_hunting_tool.py --scan-memory"
        )
        assert "YARA_HUNTING_VERIFIED" in emulate_out
        assert info.has_action("yara_hunting_verified")

        # 3. Tune condition logic
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/yara_hunting_tool.py --tune-condition"
        )
        assert "YARA_CONDITION_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/yara_hunting_tool.py --challenge"
        )
        assert "YARA_HUNTING_VALIDATED" in chal_out
        assert info.has_action("yara_hunting_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_detect_16_websocket_terminal(client, session, docker_runner):
    """Room 16: End-to-end WebSocket interactive terminal test with live Docker."""
    from backend.app.db.models import User
    from backend.app.api.auth import create_access_token
    from backend.app.labs.manager import lab_manager

    operator_id = "op-tester-detect16-ws"
    room_id = "detect-16-yara-hunting"

    user = User(
        username="detect16_ws_operator",
        email="detect16_ws@noentry.internal",
        operator_id=operator_id,
        hashed_password="dummy_hash_detect16_ws",
        xp=0,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    jwt_token = create_access_token({"sub": operator_id, "operator_id": operator_id})
    client.cookies.set("ne_auth_token", jwt_token)

    # Start live Docker session
    session_id = "test_docker_detect16_ws_live"
    info = await lab_manager._docker_runner.start_session(session_id, room_id, operator_id)
    assert info.status == "RUNNING"
    lab_manager._active_sessions[session_id] = info

    try:
        with client.websocket_connect(f"/ws/academy/{room_id}/terminal") as ws:
            drain_terminal_until_prompt(ws)

            # Execute scan over WebSocket
            emulate_resp = execute_terminal_command(
                ws, "python3 /home/operator/tools/yara_hunting_tool.py --scan-memory"
            )
            assert "YARA_HUNTING_VERIFIED" in emulate_resp["data"]
            assert info.has_action("yara_hunting_verified")

            # Execute tuning over WebSocket
            tune_resp = execute_terminal_command(
                ws, "python3 /home/operator/tools/yara_hunting_tool.py --tune-condition"
            )
            assert "YARA_CONDITION_TUNED_OK" in tune_resp["data"]

            # Execute challenge over WebSocket
            fin_resp = execute_terminal_command(
                ws, "python3 /home/operator/tools/yara_hunting_tool.py --challenge"
            )
            assert "YARA_HUNTING_VALIDATED" in fin_resp["data"]
            assert info.has_action("yara_hunting_validated")

    finally:
        await lab_manager._docker_runner.stop_session(session_id)
        lab_manager._active_sessions.pop(session_id, None)
