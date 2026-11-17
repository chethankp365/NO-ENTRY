"""
Genuine Docker Lab Integration Tests for Detection Engineering Rooms 17–20:
- Room 17: Snort / Suricata Network Signatures (detect-17-snort-suricata)
- Room 18: Threat Hunting Hypothesis Formulation (detect-18-threat-hunting-hypothesis)
- Room 19: CI/CD Pipelines for Detection Rules (detect-19-ci-cd-detection-pipelines)
- Room 20: Detection Engineering Capstone: Production Pipeline (detect-20-capstone-detection-pipeline)

Tests live Docker container duos communicating over isolated internal bridge networks,
including genuine WebSocket terminal communication for the platform capstone.
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
async def test_docker_room_detect_17_suricata(docker_runner):
    """Room 17: Live Snort / Suricata Network Signatures evaluation and PCRE tuning."""
    session_id = "test_docker_detect_17_live"
    info = await docker_runner.start_session(session_id, "detect-17-snort-suricata", "op-tester-detect17")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"

    try:
        # 1. Inspect telemetry dataset
        dataset_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/suricata_network_events.json"
        )
        assert "ATTACK_JNDI_INJECTION" in dataset_out

        # 2. Run signature emulation
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/suricata_tool.py --emulate-signature"
        )
        assert "SURICATA_SIGNATURE_VERIFIED" in emulate_out
        assert info.has_action("suricata_signature_verified")

        # 3. Tune PCRE clause
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/suricata_tool.py --tune-pcre"
        )
        assert "SURICATA_PCRE_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/suricata_tool.py --challenge"
        )
        assert "SURICATA_SIGNATURE_VALIDATED" in chal_out
        assert info.has_action("suricata_signature_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_detect_18_threat_hunting(docker_runner):
    """Room 18: Live Threat Hunting Hypothesis Formulation and baseline tuning."""
    session_id = "test_docker_detect_18_live"
    info = await docker_runner.start_session(session_id, "detect-18-threat-hunting-hypothesis", "op-tester-detect18")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect telemetry dataset
        dataset_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/threat_hunting_corpus.json"
        )
        assert "ATTACK_REMOTE_WMI_EXECUTION" in dataset_out

        # 2. Run hunt emulation
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/threat_hunting_tool.py --emulate-hunt"
        )
        assert "THREAT_HUNT_HYPOTHESIS_VERIFIED" in emulate_out
        assert info.has_action("threat_hunt_hypothesis_verified")

        # 3. Tune hypothesis exclusions
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/threat_hunting_tool.py --tune-hypothesis"
        )
        assert "HUNT_HYPOTHESIS_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/threat_hunting_tool.py --challenge"
        )
        assert "THREAT_HUNT_HYPOTHESIS_VALIDATED" in chal_out
        assert info.has_action("threat_hunt_hypothesis_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_detect_19_ci_cd_pipelines(docker_runner):
    """Room 19: Live CI/CD Detection Pipelines execution and branch protection tuning."""
    session_id = "test_docker_detect_19_live"
    info = await docker_runner.start_session(session_id, "detect-19-ci-cd-detection-pipelines", "op-tester-detect19")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect pipeline definition
        dataset_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/ci_cd_pipeline_definition.json"
        )
        assert "detection-as-code-ci-cd" in dataset_out

        # 2. Run pipeline emulation
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/pipeline_tool.py --emulate-pipeline"
        )
        assert "DETECTION_PIPELINE_VERIFIED" in emulate_out
        assert info.has_action("detection_pipeline_verified")

        # 3. Tune pipeline gates
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/pipeline_tool.py --tune-pipeline"
        )
        assert "PIPELINE_GATE_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/pipeline_tool.py --challenge"
        )
        assert "DETECTION_PIPELINE_VALIDATED" in chal_out
        assert info.has_action("detection_pipeline_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_detect_20_capstone_pipeline(docker_runner):
    """Room 20: Live Detection Engineering Capstone: Production Pipeline evaluation."""
    session_id = "test_docker_detect_20_live"
    info = await docker_runner.start_session(session_id, "detect-20-capstone-detection-pipeline", "op-tester-detect20")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect capstone pipeline definition
        dataset_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/capstone_enterprise_pipeline.json"
        )
        assert "VoltCorp Global SOC Infrastructure" in dataset_out
        assert "ENTERPRISE_PIPELINE_ONLINE" in dataset_out

        # 2. Run capstone production emulation
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/capstone_pipeline_tool.py --emulate-production"
        )
        assert "CAPSTONE_PIPELINE_VERIFIED" in emulate_out
        assert info.has_action("capstone_pipeline_verified")

        # 3. Tune production gates and playbook
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/capstone_pipeline_tool.py --tune-production"
        )
        assert "CAPSTONE_PRODUCTION_TUNED_OK" in tune_out

        # 4. Finalize capstone challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/capstone_pipeline_tool.py --challenge"
        )
        assert "CAPSTONE_PIPELINE_VALIDATED" in chal_out
        assert info.has_action("capstone_pipeline_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_detect_20_websocket_terminal(client, session, docker_runner):
    """Room 20: End-to-end WebSocket interactive terminal test with live Docker for Capstone."""
    from backend.app.db.models import User
    from backend.app.api.auth import create_access_token
    from backend.app.labs.manager import lab_manager

    operator_id = "op-tester-detect20-ws"
    room_id = "detect-20-capstone-detection-pipeline"

    user = User(
        username="detect20_ws_operator",
        email="detect20_ws@noentry.internal",
        operator_id=operator_id,
        hashed_password="dummy_hash_detect20_ws",
        xp=0,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    jwt_token = create_access_token({"sub": operator_id, "operator_id": operator_id})
    client.cookies.set("ne_auth_token", jwt_token)

    # Start live Docker session
    session_id = "test_docker_detect20_ws_live"
    info = await lab_manager._docker_runner.start_session(session_id, room_id, operator_id)
    assert info.status == "RUNNING"
    lab_manager._active_sessions[session_id] = info

    try:
        with client.websocket_connect(f"/ws/academy/{room_id}/terminal") as ws:
            drain_terminal_until_prompt(ws)

            # Execute production emulation over WebSocket
            emulate_resp = execute_terminal_command(
                ws, "python3 /home/operator/tools/capstone_pipeline_tool.py --emulate-production"
            )
            assert "CAPSTONE_PIPELINE_VERIFIED" in emulate_resp["data"]
            assert info.has_action("capstone_pipeline_verified")

            # Execute tuning over WebSocket
            tune_resp = execute_terminal_command(
                ws, "python3 /home/operator/tools/capstone_pipeline_tool.py --tune-production"
            )
            assert "CAPSTONE_PRODUCTION_TUNED_OK" in tune_resp["data"]

            # Execute challenge over WebSocket
            fin_resp = execute_terminal_command(
                ws, "python3 /home/operator/tools/capstone_pipeline_tool.py --challenge"
            )
            assert "CAPSTONE_PIPELINE_VALIDATED" in fin_resp["data"]
            assert info.has_action("capstone_pipeline_validated")

    finally:
        await lab_manager._docker_runner.stop_session(session_id)
        lab_manager._active_sessions.pop(session_id, None)
