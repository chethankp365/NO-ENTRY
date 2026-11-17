"""
Genuine Docker Lab Integration Tests for Detection Engineering Rooms 05–08:
- Room 05: Writing Network Connection Rules (Sysmon Event ID 3) (detect-05-network-connection-rules)
- Room 06: Writing File & Registry Integrity Rules (detect-06-file-registry-rules)
- Room 07: Detecting Authentication Abuse (Event IDs 4624/4625/4672) (detect-07-auth-abuse-rules)
- Room 08: Detecting PowerShell Obfuscation & Download Cradles (detect-08-powershell-obfuscation)

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
async def test_docker_room_detect_05_network_rules(docker_runner):
    """Room 05: Live Sysmon Event ID 3 network connection rule evaluation and tuning."""
    session_id = "test_docker_detect_05_live"
    info = await docker_runner.start_session(session_id, "detect-05-network-connection-rules", "op-tester-detect05")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"

    try:
        # 1. Inspect telemetry dataset
        telemetry_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/sysmon_event_3_dataset.json"
        )
        assert "rundll32.exe" in telemetry_out
        assert "8443" in telemetry_out

        # 2. Run detection emulation
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/network_connection_tool.py --emulate-detection"
        )
        assert "NETWORK_DETECTION_VERIFIED" in emulate_out
        assert info.has_action("network_connection_verified")

        # 3. Tune egress filter
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/network_connection_tool.py --tune-filter"
        )
        assert "NETWORK_FILTER_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/network_connection_tool.py --challenge"
        )
        assert "NETWORK_DETECTION_VALIDATED" in chal_out
        assert info.has_action("network_connection_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_detect_06_file_registry(docker_runner):
    """Room 06: Live File and Registry integrity monitoring rule evaluation and tuning."""
    session_id = "test_docker_detect_06_live"
    info = await docker_runner.start_session(session_id, "detect-06-file-registry-rules", "op-tester-detect06")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect telemetry dataset
        dataset_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/file_registry_dataset.json"
        )
        assert "ATTACK_PERSISTENCE_RUNKEY" in dataset_out
        assert "CurrentVersion" in dataset_out and "Run" in dataset_out

        # 2. Emulate detection rule
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/file_registry_tool.py --emulate-detection"
        )
        assert "FILE_REGISTRY_VERIFIED" in emulate_out
        assert info.has_action("file_registry_verified")

        # 3. Tune registry filter
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/file_registry_tool.py --tune-filter"
        )
        assert "REGISTRY_FILTER_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/file_registry_tool.py --challenge"
        )
        assert "FILE_REGISTRY_VALIDATED" in chal_out
        assert info.has_action("file_registry_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_detect_07_auth_abuse(docker_runner):
    """Room 07: Live Windows authentication abuse rule evaluation and baseline tuning."""
    session_id = "test_docker_detect_07_live"
    info = await docker_runner.start_session(session_id, "detect-07-auth-abuse-rules", "op-tester-detect07")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect telemetry dataset
        dataset_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/auth_abuse_dataset.json"
        )
        assert "0xC000006A" in dataset_out
        assert "ATTACK_PASSWORD_SPRAY" in dataset_out

        # 2. Emulate detection rule
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/auth_abuse_tool.py --emulate-detection"
        )
        assert "AUTH_ABUSE_VERIFIED" in emulate_out
        assert info.has_action("auth_abuse_verified")

        # 3. Tune baseline
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/auth_abuse_tool.py --tune-baseline"
        )
        assert "AUTH_BASELINE_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/auth_abuse_tool.py --challenge"
        )
        assert "AUTH_ABUSE_VALIDATED" in chal_out
        assert info.has_action("auth_abuse_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_detect_08_powershell_obfuscation(docker_runner):
    """Room 08: Live PowerShell obfuscation and download cradle detection rule evaluation and regex tuning."""
    session_id = "test_docker_detect_08_live"
    info = await docker_runner.start_session(session_id, "detect-08-powershell-obfuscation", "op-tester-detect08")
    assert info.status == "RUNNING"

    try:
        # 1. Inspect telemetry dataset
        dataset_out = await docker_runner.execute_command(
            session_id,
            "cat /var/log/detection/powershell_obfuscation_dataset.json"
        )
        assert "ATTACK_DOWNLOAD_CRADLE" in dataset_out
        assert "WebClient" in dataset_out

        # 2. Emulate detection rule
        emulate_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/powershell_obfuscation_tool.py --emulate-detection"
        )
        assert "POWERSHELL_DETECTION_VERIFIED" in emulate_out
        assert info.has_action("powershell_obfuscation_verified")

        # 3. Tune regex
        tune_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/powershell_obfuscation_tool.py --tune-regex"
        )
        assert "CRADLE_REGEX_TUNED_OK" in tune_out

        # 4. Finalize challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/powershell_obfuscation_tool.py --challenge"
        )
        assert "POWERSHELL_DETECTION_VALIDATED" in chal_out
        assert info.has_action("powershell_obfuscation_validated")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_websocket_browser_terminal_detection_08(client, session, docker_runner):
    """Room 08: Authenticated browser terminal WebSocket workflow over live Docker containers."""
    from backend.app.db.models import User
    from backend.app.api.auth import create_access_token
    from backend.app.labs.manager import lab_manager

    operator_id = "op-tester-detect08-ws"
    room_id = "detect-08-powershell-obfuscation"

    user = User(
        username="detect08_ws_operator",
        email="detect08_ws@noentry.internal",
        operator_id=operator_id,
        hashed_password="dummy_hash_detect08_ws",
        xp=0,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    jwt_token = create_access_token({"sub": operator_id, "operator_id": operator_id})
    client.cookies.set("ne_auth_token", jwt_token)

    # Start live Docker session
    session_id = "test_docker_detect08_ws_live"
    info = await lab_manager._docker_runner.start_session(session_id, room_id, operator_id)
    assert info.status == "RUNNING"
    lab_manager._active_sessions[session_id] = info

    try:
        with client.websocket_connect(f"/ws/academy/{room_id}/terminal") as ws:
            drain_terminal_until_prompt(ws)

            # Execute emulation over WebSocket
            emulate_resp = execute_terminal_command(
                ws, "python3 /home/operator/tools/powershell_obfuscation_tool.py --emulate-detection"
            )
            assert "POWERSHELL_DETECTION_VERIFIED" in emulate_resp["data"]
            assert info.has_action("powershell_obfuscation_verified")

            # Execute tuning over WebSocket
            tune_resp = execute_terminal_command(
                ws, "python3 /home/operator/tools/powershell_obfuscation_tool.py --tune-regex"
            )
            assert "CRADLE_REGEX_TUNED_OK" in tune_resp["data"]

            # Execute challenge over WebSocket
            fin_resp = execute_terminal_command(
                ws, "python3 /home/operator/tools/powershell_obfuscation_tool.py --challenge"
            )
            assert "POWERSHELL_DETECTION_VALIDATED" in fin_resp["data"]
            assert info.has_action("powershell_obfuscation_validated")

    finally:
        await lab_manager._docker_runner.stop_session(session_id)
        lab_manager._active_sessions.pop(session_id, None)
