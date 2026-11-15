"""
Genuine Docker Lab Integration Tests for Purple Team Rooms 13–16:
- Room 13: Supply Chain & Dependency Confusion Emulation (purple-13-supply-chain-emulation)
- Room 14: API Security & Broken Object Level Auth (BOLA) Emulation (purple-14-api-abuse-emulation)
- Room 15: Active Directory Attacks Emulation (Kerberoasting) (purple-15-active-directory-attacks-emulation)
- Room 16: CI/CD Pipeline & GitHub Actions Attack Emulation (purple-16-ci-cd-pipeline-emulation)

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
async def test_docker_room_purple_13_supply_chain(docker_runner):
    """Room 13: Live Dependency Confusion emulation, build telemetry analysis, and scope pinning validation."""
    session_id = "test_docker_purple_13_live"
    info = await docker_runner.start_session(session_id, "purple-13-supply-chain-emulation", "op-tester-purple13")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"

    try:
        # 1. Inspect telemetry evidence file
        ev_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/supply_chain/build_dependency_events.json"
        )
        assert "voltcorp-auth-core" in ev_out
        assert "99.0.0" in ev_out

        # 2. Run tool to emulate dependency confusion
        emu_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/supply_chain_tool.py --emulate-confusion"
        )
        assert "SUPPLY_CHAIN_EMULATION_VERIFIED" in emu_out
        assert info.has_action("supply_chain_emulated")

        # 3. Deploy scope pinning policy
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/supply_chain_tool.py --tune-pinning"
        )
        assert "PINNING_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/supply_chain_tool.py --challenge"
        )
        assert "SUPPLY_CHAIN_DETECTION_VALIDATED" in chal_out
        assert info.has_action("supply_chain_detection_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_purple_14_api_abuse(docker_runner):
    """Room 14: Live BOLA parameter tampering emulation and API gateway authorization validation."""
    session_id = "test_docker_purple_14_live"
    info = await docker_runner.start_session(session_id, "purple-14-api-abuse-emulation", "op-tester-purple14")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect access logs
        ev_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/api_abuse/api_access_events.json"
        )
        assert "usr-90124" in ev_out
        assert "usr-10442" in ev_out

        # 2. Emulate BOLA
        emu_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/api_abuse_tool.py --emulate-bola"
        )
        assert "BOLA_EMULATION_VERIFIED" in emu_out
        assert info.has_action("bola_emulated")

        # 3. Tune gateway authorization
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/api_abuse_tool.py --tune-gateway"
        )
        assert "GATEWAY_TUNED_OK" in tune_out

        # 4. Complete challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/api_abuse_tool.py --challenge"
        )
        assert "API_ABUSE_DETECTION_VALIDATED" in chal_out
        assert info.has_action("api_abuse_detection_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_purple_15_ad_attacks(docker_runner):
    """Room 15: Live Kerberoasting SPN ticket request emulation and Domain Controller detection."""
    session_id = "test_docker_purple_15_live"
    info = await docker_runner.start_session(session_id, "purple-15-active-directory-attacks-emulation", "op-tester-purple15")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect Kerberos audit events
        ev_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/ad_attacks/kerberos_audit_events.json"
        )
        assert "4769" in ev_out
        assert "0x17" in ev_out

        # 2. Emulate Kerberoasting
        emu_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/ad_attacks_tool.py --emulate-kerberoast"
        )
        assert "KERBEROASTING_EMULATION_VERIFIED" in emu_out
        assert info.has_action("kerberoasting_emulated")

        # 3. Tune DC detection rule
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/ad_attacks_tool.py --tune-dc-rule"
        )
        assert "DC_RULE_TUNED_OK" in tune_out

        # 4. Complete challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/ad_attacks_tool.py --challenge"
        )
        assert "AD_ATTACK_DETECTION_VALIDATED" in chal_out
        assert info.has_action("ad_attack_detection_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_purple_16_cicd_pipeline(docker_runner):
    """Room 16: Live CI/CD workflow injection emulation and OIDC / pipeline guardrails."""
    session_id = "test_docker_purple_16_live"
    info = await docker_runner.start_session(session_id, "purple-16-ci-cd-pipeline-emulation", "op-tester-purple16")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect workflow run logs
        ev_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/cicd/workflow_run_events.json"
        )
        assert "pr-builder.yml" in ev_out
        assert "pull_request_target" in ev_out

        # 2. Emulate pipeline attack
        emu_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/cicd_pipeline_tool.py --emulate-pipeline-attack"
        )
        assert "CICD_PIPELINE_EMULATION_VERIFIED" in emu_out
        assert info.has_action("cicd_pipeline_emulated")

        # 3. Tune pipeline audit and guardrails
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/cicd_pipeline_tool.py --tune-pipeline-audit"
        )
        assert "PIPELINE_AUDIT_TUNED_OK" in tune_out

        # 4. Complete challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/cicd_pipeline_tool.py --challenge"
        )
        assert "CICD_PIPELINE_DETECTION_VALIDATED" in chal_out
        assert info.has_action("cicd_pipeline_detection_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_websocket_terminal_purple16(docker_runner, client, session):
    """Test authenticated WebSocket terminal executing commands live inside container."""
    from backend.app.db.models import User
    from backend.app.api.auth import create_access_token
    from backend.app.labs.manager import lab_manager

    operator_id = "op-tester-purple16-ws"
    room_id = "purple-16-ci-cd-pipeline-emulation"

    user = User(
        username="purple_ws_operator_16",
        email="purple_ws_16@noentry.internal",
        operator_id=operator_id,
        hashed_password="dummy_hash_purple_ws_16",
        xp=0,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    jwt_token = create_access_token({"sub": operator_id, "operator_id": operator_id})
    client.cookies.set("ne_auth_token", jwt_token)

    # Start live Docker session
    session_id = "test_docker_purple16_ws_live"
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
                "command": "python3 /home/operator/tools/cicd_pipeline_tool.py --emulate-pipeline-attack",
            })
            emu_resp = ws.receive_json()
            assert "CICD_PIPELINE_EMULATION_VERIFIED" in emu_resp["data"]
            assert info.has_action("cicd_pipeline_emulated")
            ws.receive_json()  # Prompt

            # Execute guardrail tuning over WebSocket
            ws.send_json({
                "type": "command",
                "command": "python3 /home/operator/tools/cicd_pipeline_tool.py --tune-pipeline-audit",
            })
            tune_resp = ws.receive_json()
            assert "PIPELINE_AUDIT_TUNED_OK" in tune_resp["data"]
            ws.receive_json()  # Prompt

            # Execute challenge finalization over WebSocket
            ws.send_json({
                "type": "command",
                "command": "python3 /home/operator/tools/cicd_pipeline_tool.py --challenge",
            })
            chal_resp = ws.receive_json()
            assert "CICD_PIPELINE_DETECTION_VALIDATED" in chal_resp["data"]
            assert info.has_action("cicd_pipeline_detection_validated")
            ws.receive_json()  # Prompt

    finally:
        await lab_manager._docker_runner.stop_session(session_id)
        lab_manager._active_sessions.pop(session_id, None)

