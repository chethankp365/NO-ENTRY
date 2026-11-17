"""
Genuine Docker Lab Integration Tests for Purple Team Rooms 09–12:
- Room 09: Command & Control (C2) Traffic Emulation (purple-09-c2-framework-emulation)
- Room 10: Emulating Data Exfiltration Techniques (purple-10-exfiltration-emulation)
- Room 11: Ransomware Attack Emulation & Readiness (purple-11-ransomware-readiness)
- Room 12: Cloud Identity & IAM Privilege Escalation Emulation (purple-12-cloud-identity-emulation)

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
async def test_docker_room_purple_09_c2(docker_runner):
    """Room 09: Live C2 beacon traffic emulation, telemetry analysis, and detection validation."""
    session_id = "test_docker_purple_09_live"
    info = await docker_runner.start_session(session_id, "purple-09-c2-framework-emulation", "op-tester-purple09")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"

    try:
        # 1. Inspect telemetry evidence file
        ev_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/c2/beacon_traffic_events.json"
        )
        assert "/api/v1/ping" in ev_out
        assert "8309" in ev_out

        # 2. Run tool to emulate beaconing
        emu_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/c2_emulation_tool.py --emulate-beacon"
        )
        assert "C2_BEACON_EMULATION_VERIFIED" in emu_out
        assert info.has_action("c2_beacon_emulated")

        # 3. Deploy detection rule
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/c2_emulation_tool.py --tune-detection"
        )
        assert "DETECTION_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/c2_emulation_tool.py --challenge"
        )
        assert "C2_DETECTION_VALIDATED" in chal_out
        assert info.has_action("c2_detection_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_purple_10_exfiltration(docker_runner):
    """Room 10: Live Data Exfiltration staging, chunked egress emulation, and DLP validation."""
    session_id = "test_docker_purple_10_live"
    info = await docker_runner.start_session(session_id, "purple-10-exfiltration-emulation", "op-tester-purple10")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect staging and egress telemetry
        ev_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/exfil/staging_egress_events.json"
        )
        assert "STAGE_ARCHIVE" in ev_out
        assert "48200000" in ev_out

        # 2. Emulate exfiltration
        emu_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/exfil_emulation_tool.py --emulate-exfil"
        )
        assert "EXFILTRATION_EMULATION_VERIFIED" in emu_out
        assert info.has_action("exfil_emulated")

        # 3. Tune DLP
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/exfil_emulation_tool.py --tune-dlp"
        )
        assert "DLP_TUNED_OK" in tune_out

        # 4. Complete challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/exfil_emulation_tool.py --challenge"
        )
        assert "EXFILTRATION_DETECTION_VALIDATED" in chal_out
        assert info.has_action("exfil_detection_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_purple_11_ransomware(docker_runner):
    """Room 11: Live Ransomware precursor emulation, canary decoy access, and readiness validation."""
    session_id = "test_docker_purple_11_live"
    info = await docker_runner.start_session(session_id, "purple-11-ransomware-readiness", "op-tester-purple11")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect precursor telemetry
        ev_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/ransomware/precursor_events.json"
        )
        assert "vssadmin" in ev_out
        assert "finance_q4_canary.xlsx" in ev_out

        # 2. Inspect canary file
        canary_out = await docker_runner.execute_command(
            session_id,
            "cat /home/operator/decoy/finance_q4_canary.xlsx"
        )
        assert "CONFIDENTIAL_CANARY" in canary_out

        # 3. Emulate precursors & canary touch
        emu_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/ransomware_emulation_tool.py --emulate-precursors"
        )
        assert "RANSOMWARE_EMULATION_VERIFIED" in emu_out
        assert info.has_action("ransomware_emulated")

        # 4. Tune canary tripwire
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/ransomware_emulation_tool.py --tune-canary"
        )
        assert "CANARY_TUNED_OK" in tune_out

        # 5. Complete challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/ransomware_emulation_tool.py --challenge"
        )
        assert "RANSOMWARE_READINESS_VALIDATED" in chal_out
        assert info.has_action("ransomware_readiness_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_purple_12_cloud_identity(docker_runner):
    """Room 12: Live Cloud IMDS credential access, role assumption emulation, and CloudTrail pipeline tuning."""
    session_id = "test_docker_purple_12_live"
    info = await docker_runner.start_session(session_id, "purple-12-cloud-identity-emulation", "op-tester-purple12")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect CloudTrail telemetry
        ev_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/cloud/cloudtrail_iam_events.json"
        )
        assert "AssumeRole" in ev_out
        assert "ProdSecOpsAdminRole" in ev_out

        # 2. Emulate AssumeRole
        emu_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/cloud_iam_emulation_tool.py --emulate-assume-role"
        )
        assert "CLOUD_IAM_EMULATION_VERIFIED" in emu_out
        assert info.has_action("cloud_iam_emulated")

        # 3. Tune pipeline
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/cloud_iam_emulation_tool.py --tune-pipeline"
        )
        assert "PIPELINE_TUNED_OK" in tune_out

        # 4. Complete challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/cloud_iam_emulation_tool.py --challenge"
        )
        assert "CLOUD_IDENTITY_DETECTION_VALIDATED" in chal_out
        assert info.has_action("cloud_identity_detection_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_websocket_terminal_purple12(docker_runner, client, session):
    """Test authenticated WebSocket terminal executing commands live inside container."""
    from backend.app.db.models import User
    from backend.app.api.auth import create_access_token
    from backend.app.labs.manager import lab_manager

    operator_id = "op-tester-purple12-ws"
    room_id = "purple-12-cloud-identity-emulation"

    user = User(
        username="purple_ws_operator_12",
        email="purple_ws_12@noentry.internal",
        operator_id=operator_id,
        hashed_password="dummy_hash_purple_ws_12",
        xp=0,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    jwt_token = create_access_token({"sub": operator_id, "operator_id": operator_id})
    client.cookies.set("ne_auth_token", jwt_token)

    # Start live Docker session
    session_id = "test_docker_purple12_ws_live"
    info = await lab_manager._docker_runner.start_session(session_id, room_id, operator_id)
    assert info.status == "RUNNING"
    lab_manager._active_sessions[session_id] = info

    try:
        with client.websocket_connect(f"/ws/academy/{room_id}/terminal") as ws:
            drain_terminal_until_prompt(ws)

            # Execute emulation over WebSocket
            emu_resp = execute_terminal_command(
                ws, "python3 /home/operator/tools/cloud_iam_emulation_tool.py --emulate-assume-role"
            )
            assert "CLOUD_IAM_EMULATION_VERIFIED" in emu_resp["data"]
            assert info.has_action("cloud_iam_emulated")

            # Execute detection pipeline tuning over WebSocket
            tune_resp = execute_terminal_command(
                ws, "python3 /home/operator/tools/cloud_iam_emulation_tool.py --tune-pipeline"
            )
            assert "PIPELINE_TUNED_OK" in tune_resp["data"]

            # Execute challenge finalization over WebSocket
            chal_resp = execute_terminal_command(
                ws, "python3 /home/operator/tools/cloud_iam_emulation_tool.py --challenge"
            )
            assert "CLOUD_IDENTITY_DETECTION_VALIDATED" in chal_resp["data"]
            assert info.has_action("cloud_identity_detection_validated")

    finally:
        await lab_manager._docker_runner.stop_session(session_id)
        lab_manager._active_sessions.pop(session_id, None)
