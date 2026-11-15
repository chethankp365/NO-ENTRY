"""
Genuine Docker Lab Integration Tests for Blue Team Rooms 09–12:
- Room 09: Brute-Force Detection (blue-09-bruteforce-detection)
- Room 10: Malware Behaviour Analysis (blue-10-malware-behaviour-analysis)
- Room 11: Phishing Investigation (blue-11-phishing-investigation)
- Room 12: Endpoint Detection (blue-12-endpoint-detection)

Tests live container duo communicating over isolated internal bridge network.
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
async def test_docker_room_blue_09_bruteforce(docker_runner):
    """Room 09: Live brute-force log analysis, telemetry APIs, spraying detection, and challenge verification."""
    session_id = "test_docker_blue_09_live"
    info = await docker_runner.start_session(session_id, "blue-09-bruteforce-detection", "op-tester-blue09")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Execute operator brute-force detection CLI tool in attacker container
        cli_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/detect_bruteforce.py /var/log/auth_bruteforce.log"
        )
        assert "198.51.100.55" in cli_out
        assert "PASSWORD_SPRAY" in cli_out
        assert "NOENTRY{" not in cli_out

        # 2. Query telemetry API on target container
        telem_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8209/api/auth/telemetry"
        )
        assert "198.51.100.55" in telem_out
        assert "NOENTRY{" not in telem_out

        # 3. Query spraying detection API
        spray_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8209/api/auth/spray-indicators"
        )
        assert "PASSWORD_SPRAY" in spray_out
        assert "198.51.100.55" in spray_out
        assert "NOENTRY{" not in spray_out

        # 4. Verify GET on challenge returns NO flag
        chal_get = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8209/challenge"
        )
        assert "NOENTRY{" not in chal_get

        # 4b. Deploy spray correlation rule (prerequisite for challenge)
        rule_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"rule_name":"RULE_AUTH_BURST_SPRAY","threshold":5,"group_by":"source_ip"}}\' http://{target_ip}:8209/api/auth/rules'
        )
        assert "SIEM_SPRAY_CORRELATION_RULE_ACTIVE" in rule_out

        # 5. Submit attack correlation challenge via POST
        chal_post = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"source_ip":"198.51.100.55","attack_type":"PASSWORD_SPRAY","targeted_accounts_count":12}}\' http://{target_ip}:8209/challenge'
        )
        assert "BRUTEFORCE_RULE_VERIFIED" in chal_post
        assert info.has_action("bruteforce_challenge_verified")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_blue_10_malware_analysis(docker_runner):
    """Room 10: Live YARA scanning on sample, telemetry APIs, sandbox evasion analysis, and challenge verification."""
    session_id = "test_docker_blue_10_live"
    info = await docker_runner.start_session(session_id, "blue-10-malware-behaviour-analysis", "op-tester-blue10")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Execute YARA scanner CLI tool in attacker container
        yara_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/yara_scanner.py /home/operator/samples/dropper_sample.bin"
        )
        assert "VoltStage2_Payload" in yara_out
        assert "c2-stage.voltcorp.internal" in yara_out
        assert "NOENTRY{" not in yara_out

        # 2. Query dropper headers API
        drop_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8210/api/malware/sample/dropper/headers"
        )
        assert "invoice_dropper.bin" in drop_out
        assert "NOENTRY{" not in drop_out

        # 3. Query YARA validation API
        val_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"rule_text":"rule DropperTest {{ strings: $s1 = \\"VoltStage2\\" condition: $s1 }}"}}\' http://{target_ip}:8210/api/malware/yara/validate'
        )
        assert "YARA_SYNTAX_VALID" in val_out
        assert "NOENTRY{" not in val_out

        # 4. Verify GET on challenge returns NO flag
        chal_get = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8210/challenge"
        )
        assert "NOENTRY{" not in chal_get

        # 5. Submit malware capability triage challenge via POST
        chal_post = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"sample_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","c2_url":"http://c2-stage.voltcorp.internal/gate.php","persistence_mechanism":"Run"}}\' http://{target_ip}:8210/challenge'
        )
        assert "MALWARE_YARA_MATCH_VERIFIED" in chal_post
        assert info.has_action("malware_challenge_verified")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_blue_11_phishing(docker_runner):
    """Room 11: Live email header parser CLI, authentication telemetry, URL inspection, and challenge verification."""
    session_id = "test_docker_blue_11_live"
    info = await docker_runner.start_session(session_id, "blue-11-phishing-investigation", "op-tester-blue11")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Execute email parser CLI tool in attacker container
        email_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/inspect_email.py /home/operator/emails/password_reset.eml"
        )
        assert "v0ltcorp.internal" in email_out
        assert "198.51.100.99" in email_out
        assert "NOENTRY{" not in email_out

        # 2. Query quarantined emails API
        emails_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8211/api/phishing/emails"
        )
        assert "EML-2026-02" in emails_out
        assert "NOENTRY{" not in emails_out

        # 3. Query email headers API
        hdr_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8211/api/phishing/headers/EML-2026-02"
        )
        assert "v0ltcorp.internal" in hdr_out
        assert "198.51.100.99" in hdr_out
        assert "NOENTRY{" not in hdr_out

        # 4. Verify GET on challenge returns NO flag
        chal_get = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8211/challenge"
        )
        assert "NOENTRY{" not in chal_get

        # 4b. Submit phishing triage (prerequisite for gateway containment)
        triage_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"email_id":"EML-2026-02","threat_category":"SPEAR_PHISHING","spoofed_domain":"v0ltcorp.internal"}}\' http://{target_ip}:8211/api/phishing/triage'
        )
        assert "PHISHING_TRIAGE_VERIFIED_V0LTCORP" in triage_out

        # 5. Submit phishing triage challenge via POST
        chal_post = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"email_id":"EML-2026-02","dmarc_result":"FAIL","lookalike_domain":"v0ltcorp.internal","remediation_action":"BLOCK"}}\' http://{target_ip}:8211/challenge'
        )
        assert "PHISHING_INCIDENT_CONTAINED" in chal_post
        assert info.has_action("phishing_challenge_verified")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_blue_12_endpoint_detection(docker_runner):
    """Room 12: Live EDR query CLI tool, process tree APIs, persistence investigation, and challenge verification."""
    session_id = "test_docker_blue_12_live"
    info = await docker_runner.start_session(session_id, "blue-12-endpoint-detection", "op-tester-blue12")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Execute EDR query CLI tool in attacker container
        edr_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/edr_query.py /home/operator/endpoint_telemetry/endpoint_events.json"
        )
        assert "winword.exe" in edr_out
        assert "powershell.exe" in edr_out
        assert "198.51.100.88" in edr_out
        assert "NOENTRY{" not in edr_out

        # 2. Query process tree API
        proc_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8212/api/endpoint/telemetry/processes"
        )
        assert "winword.exe" in proc_out
        assert "powershell.exe" in proc_out
        assert "NOENTRY{" not in proc_out

        # 3. Query network telemetry API
        net_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8212/api/endpoint/telemetry/network"
        )
        assert "198.51.100.88" in net_out
        assert "NOENTRY{" not in net_out

        # 4. Verify GET on challenge returns NO flag
        chal_get = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8212/challenge"
        )
        assert "NOENTRY{" not in chal_get

        # 4b. Deploy behavioral LOLBIN detection rule (prerequisite for host containment)
        rule_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"parent_process":"winword.exe","child_process":"powershell.exe"}}\' http://{target_ip}:8212/api/endpoint/rules'
        )
        assert "EDR_LOLBIN_RULE_ACTIVE_CONFIRMED" in rule_out

        # 5. Submit EDR correlation challenge via POST
        chal_post = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"malicious_pid":"4812","parent_process":"winword.exe","lolbin":"powershell.exe","c2_ip":"198.51.100.88"}}\' http://{target_ip}:8212/challenge'
        )
        assert "EDR_CONTAINMENT_VERIFIED" in chal_post
        assert info.has_action("endpoint_challenge_verified")

    finally:
        await docker_runner.stop_session(session_id)
