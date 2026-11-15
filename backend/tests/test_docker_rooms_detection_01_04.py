"""
Genuine Docker Lab Integration Tests for Detection Engineering Rooms 01–04:
- Room 01: Detection Engineering Foundations & Detection-as-Code (detect-01-foundations-as-code)
- Room 02: Log Normalization & Taxonomy (ECS & CIM) (detect-02-log-normalization)
- Room 03: Sigma Rule Syntax & Component Structure (detect-03-sigma-syntax)
- Room 04: Writing Process Creation Rules (Sysmon Event ID 1) (detect-04-process-creation-rules)

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
async def test_docker_room_detect_01_foundations(docker_runner):
    """Room 01: Live Detection Engineering Foundations & Detection-as-Code pipeline validation."""
    session_id = "test_docker_detect_01_live"
    info = await docker_runner.start_session(session_id, "detect-01-foundations-as-code", "op-tester-detect01")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"

    try:
        # 1. Inspect pipeline telemetry
        pipe_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/ddlc_pipeline_events.json"
        )
        assert "RULE-DAC-104" in pipe_out
        assert "FLAGGED_HIGH_NOISE" in pipe_out

        # 2. Run pipeline emulation
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/detection_foundations_tool.py --emulate-pipeline"
        )
        assert "DETECTION_FOUNDATIONS_VERIFIED" in emulate_out
        assert info.has_action("detection_foundations_verified")

        # 3. Tune SNR
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/detection_foundations_tool.py --tune-snr"
        )
        assert "SNR_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/detection_foundations_tool.py --challenge"
        )
        assert "DETECTION_FOUNDATIONS_VALIDATED" in chal_out
        assert info.has_action("detection_foundations_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_detect_02_normalization(docker_runner):
    """Room 02: Live Log Normalization & Taxonomy (ECS & CIM) mapping and translation."""
    session_id = "test_docker_detect_02_live"
    info = await docker_runner.start_session(session_id, "detect-02-log-normalization", "op-tester-detect02")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect raw event schema
        schema_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/raw_event_schema.json"
        )
        assert "4688" in schema_out
        assert "process.executable" in schema_out

        # 2. Emulate normalization
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/log_normalization_tool.py --emulate-normalization"
        )
        assert "LOG_NORMALIZATION_VERIFIED" in emulate_out
        assert info.has_action("log_normalization_verified")

        # 3. Tune taxonomy
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/log_normalization_tool.py --tune-taxonomy"
        )
        assert "TAXONOMY_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/log_normalization_tool.py --challenge"
        )
        assert "LOG_NORMALIZATION_VALIDATED" in chal_out
        assert info.has_action("log_normalization_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_detect_03_sigma_syntax(docker_runner):
    """Room 03: Live Sigma Rule Syntax & Component Structure parsing and evaluation."""
    session_id = "test_docker_detect_03_live"
    info = await docker_runner.start_session(session_id, "detect-03-sigma-syntax", "op-tester-detect03")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect sample Sigma rule and dataset
        rule_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/sample_sigma_rule.yaml"
        )
        assert "selection_img" in rule_out
        assert "logsource" in rule_out

        # 2. Emulate parser
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/sigma_syntax_tool.py --emulate-parser"
        )
        assert "SIGMA_SYNTAX_VERIFIED" in emulate_out
        assert info.has_action("sigma_syntax_verified")

        # 3. Tune condition
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/sigma_syntax_tool.py --tune-condition"
        )
        assert "CONDITION_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/sigma_syntax_tool.py --challenge"
        )
        assert "SIGMA_SYNTAX_VALIDATED" in chal_out
        assert info.has_action("sigma_syntax_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_detect_04_process_creation(docker_runner):
    """Room 04: Live Process Creation Rules (Sysmon Event ID 1) detection and tuning."""
    session_id = "test_docker_detect_04_live"
    info = await docker_runner.start_session(session_id, "detect-04-process-creation-rules", "op-tester-detect04")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect Sysmon Event 1 telemetry
        sysmon_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/sysmon_event_1_dataset.json"
        )
        assert "certutil.exe" in sysmon_out
        assert "Ingress Tool Transfer" in sysmon_out

        # 2. Emulate detection
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/process_creation_tool.py --emulate-detection"
        )
        assert "PROCESS_CREATION_VERIFIED" in emulate_out
        assert info.has_action("process_creation_verified")

        # 3. Tune LOLBIN filter
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/process_creation_tool.py --tune-lolbin-filter"
        )
        assert "LOLBIN_FILTER_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/process_creation_tool.py --challenge"
        )
        assert "PROCESS_CREATION_VALIDATED" in chal_out
        assert info.has_action("process_creation_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_detect_websocket_terminal_workflow(docker_runner, client, session):
    """Verify live browser-terminal WebSocket command execution for Detection Engineering exercises."""
    from backend.app.db.models import User
    from backend.app.api.auth import create_access_token
    from backend.app.labs.manager import lab_manager

    operator_id = "op-tester-detect-ws"
    room_id = "detect-04-process-creation-rules"

    user = User(
        username="detect_ws_operator",
        email="detect_ws@noentry.internal",
        operator_id=operator_id,
        hashed_password="dummy_hash_detect_ws",
        xp=0,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    jwt_token = create_access_token({"sub": operator_id, "operator_id": operator_id})
    client.cookies.set("ne_auth_token", jwt_token)

    # Start live Docker session
    session_id = "test_docker_detect_ws_live"
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
                "command": "python3 /home/operator/tools/process_creation_tool.py --emulate-detection",
            })
            emulate_resp = ws.receive_json()
            assert "PROCESS_CREATION_VERIFIED" in emulate_resp["data"]
            assert info.has_action("process_creation_verified")
            ws.receive_json()  # Prompt

            # Execute tuning over WebSocket
            ws.send_json({
                "type": "command",
                "command": "python3 /home/operator/tools/process_creation_tool.py --tune-lolbin-filter",
            })
            tune_resp = ws.receive_json()
            assert "LOLBIN_FILTER_TUNED_OK" in tune_resp["data"]
            ws.receive_json()  # Prompt

            # Execute challenge over WebSocket
            ws.send_json({
                "type": "command",
                "command": "python3 /home/operator/tools/process_creation_tool.py --challenge",
            })
            fin_resp = ws.receive_json()
            assert "PROCESS_CREATION_VALIDATED" in fin_resp["data"]
            assert info.has_action("process_creation_validated")
            ws.receive_json()  # Prompt

    finally:
        await lab_manager._docker_runner.stop_session(session_id)
        lab_manager._active_sessions.pop(session_id, None)

