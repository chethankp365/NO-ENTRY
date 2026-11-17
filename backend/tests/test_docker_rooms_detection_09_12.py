"""
Genuine Docker Lab Integration Tests for Detection Engineering Rooms 09–12:
- Room 09: Writing Web Application Detection Rules (SQLi, XSS, LFI) (detect-09-web-detection-rules)
- Room 10: ModSecurity Core Rule Set Tuning & Custom Rules (detect-10-modsec-crs-tuning)
- Room 11: Wazuh / OSSEC Rules & Decoders (detect-11-wazuh-decoders-rules)
- Room 12: Tuning Detections & Reducing False Positives (detect-12-reducing-false-positives)

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
async def test_docker_room_detect_09_web_rules(docker_runner):
    """Room 09: Live Web Application Detection Rules evaluation and URL decode tuning."""
    session_id = "test_docker_detect_09_live"
    info = await docker_runner.start_session(session_id, "detect-09-web-detection-rules", "op-tester-detect09")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"

    try:
        # 1. Inspect telemetry dataset
        telemetry_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/web_application_logs.json"
        )
        assert "ATTACK_SQLI_UNION" in telemetry_out
        assert "ATTACK_XSS_STORED" in telemetry_out
        assert "ATTACK_PATH_TRAVERSAL_LFI" in telemetry_out

        # 2. Run detection emulation
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/web_detection_tool.py --emulate-detection"
        )
        assert "WEB_DETECTION_VERIFIED" in emulate_out
        assert info.has_action("web_detection_verified")

        # 3. Tune URL decode normalization filter
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/web_detection_tool.py --tune-urldecode"
        )
        assert "URL_DECODE_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/web_detection_tool.py --challenge"
        )
        assert "WEB_DETECTION_VALIDATED" in chal_out
        assert info.has_action("web_detection_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_detect_10_modsec_crs(docker_runner):
    """Room 10: Live ModSecurity Core Rule Set evaluation and paranoia level tuning."""
    session_id = "test_docker_detect_10_live"
    info = await docker_runner.start_session(session_id, "detect-10-modsec-crs-tuning", "op-tester-detect10")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect telemetry dataset
        dataset_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/modsecurity_audit_events.json"
        )
        assert "ATTACK_SQLI_LIBINJECTION" in dataset_out
        assert "942100" in dataset_out

        # 2. Emulate detection rule
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/modsec_tuning_tool.py --emulate-detection"
        )
        assert "MODSEC_CRS_VERIFIED" in emulate_out
        assert info.has_action("modsec_crs_verified")

        # 3. Tune paranoia level and exclusions
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/modsec_tuning_tool.py --tune-paranoia"
        )
        assert "PARANOIA_LEVEL_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/modsec_tuning_tool.py --challenge"
        )
        assert "MODSEC_CRS_VALIDATED" in chal_out
        assert info.has_action("modsec_crs_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_detect_11_wazuh_rules(docker_runner):
    """Room 11: Live Wazuh decoders and custom rules evaluation and tuning."""
    session_id = "test_docker_detect_11_live"
    info = await docker_runner.start_session(session_id, "detect-11-wazuh-decoders-rules", "op-tester-detect11")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect telemetry dataset
        dataset_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/wazuh_log_corpus.json"
        )
        assert "custom_authd" in dataset_out
        assert "ATTACK_BRUTEFORCE_BURST" in dataset_out

        # 2. Emulate Wazuh decoders and rules
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/wazuh_decoders_tool.py --emulate-detection"
        )
        assert "WAZUH_RULES_VERIFIED" in emulate_out
        assert info.has_action("wazuh_rules_verified")

        # 3. Tune decoder regex
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/wazuh_decoders_tool.py --tune-decoder"
        )
        assert "DECODER_REGEX_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/wazuh_decoders_tool.py --challenge"
        )
        assert "WAZUH_RULES_VALIDATED" in chal_out
        assert info.has_action("wazuh_rules_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_detect_12_false_positive(docker_runner):
    """Room 12: Live Detection Tuning & False Positive Reduction evaluation."""
    session_id = "test_docker_detect_12_live"
    info = await docker_runner.start_session(session_id, "detect-12-reducing-false-positives", "op-tester-detect12")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect telemetry dataset
        dataset_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/tuning_baseline_telemetry.json"
        )
        assert "powershell.exe" in dataset_out
        assert "BENIGN_SCHEDULED_BACKUP" in dataset_out

        # 2. Emulate detection tuning
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/false_positive_tool.py --emulate-detection"
        )
        assert "FALSE_POSITIVE_TUNING_VERIFIED" in emulate_out
        assert info.has_action("false_positive_tuning_verified")

        # 3. Tune baseline exclusions
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/false_positive_tool.py --tune-baseline"
        )
        assert "BASELINE_EXCLUSION_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/false_positive_tool.py --challenge"
        )
        assert "FALSE_POSITIVE_TUNING_VALIDATED" in chal_out
        assert info.has_action("false_positive_tuning_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_detection_12_websocket_terminal_workflow(client, session, docker_runner):
    """Room 12: End-to-end WebSocket interactive terminal test with live Docker."""
    from backend.app.db.models import User
    from backend.app.api.auth import create_access_token
    from backend.app.labs.manager import lab_manager

    operator_id = "op-tester-detect12-ws"
    room_id = "detect-12-reducing-false-positives"

    user = User(
        username="detect12_ws_operator",
        email="detect12_ws@noentry.internal",
        operator_id=operator_id,
        hashed_password="dummy_hash_detect12_ws",
        xp=0,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    jwt_token = create_access_token({"sub": operator_id, "operator_id": operator_id})
    client.cookies.set("ne_auth_token", jwt_token)

    # Start live Docker session
    session_id = "test_docker_detect12_ws_live"
    info = await lab_manager._docker_runner.start_session(session_id, room_id, operator_id)
    assert info.status == "RUNNING"
    lab_manager._active_sessions[session_id] = info

    try:
        with client.websocket_connect(f"/ws/academy/{room_id}/terminal") as ws:
            drain_terminal_until_prompt(ws)

            # Execute emulation over WebSocket
            emulate_resp = execute_terminal_command(
                ws, "python3 /home/operator/tools/false_positive_tool.py --emulate-detection"
            )
            assert "FALSE_POSITIVE_TUNING_VERIFIED" in emulate_resp["data"]
            assert info.has_action("false_positive_tuning_verified")

            # Execute tuning over WebSocket
            tune_resp = execute_terminal_command(
                ws, "python3 /home/operator/tools/false_positive_tool.py --tune-baseline"
            )
            assert "BASELINE_EXCLUSION_TUNED_OK" in tune_resp["data"]

            # Execute challenge over WebSocket
            fin_resp = execute_terminal_command(
                ws, "python3 /home/operator/tools/false_positive_tool.py --challenge"
            )
            assert "FALSE_POSITIVE_TUNING_VALIDATED" in fin_resp["data"]
            assert info.has_action("false_positive_tuning_validated")

    finally:
        await lab_manager._docker_runner.stop_session(session_id)
        lab_manager._active_sessions.pop(session_id, None)
