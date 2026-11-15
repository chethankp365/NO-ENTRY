"""
Genuine Docker Lab Integration Tests for Blue Team Rooms 05–08:
- Room 05: Wireshark Fundamentals (blue-05-wireshark-fundamentals)
- Room 06: Log Analysis Fundamentals (blue-06-log-analysis-fundamentals)
- Room 07: SIEM Fundamentals (blue-07-siem-fundamentals)
- Room 08: Windows Event Investigation (blue-08-windows-event-investigation)

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
async def test_docker_room_blue_05_wireshark(docker_runner):
    """Room 05: Live packet dissection with tshark/tcpdump, HTTP stream inspection, DNS queries, TCP handshake, challenge."""
    session_id = "test_docker_blue_05_live"
    info = await docker_runner.start_session(session_id, "blue-05-wireshark-fundamentals", "op-tester-blue05")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Execute live tshark dissection on the pre-seeded PCAP in the attacker container
        tshark_out = await docker_runner.execute_command(
            session_id,
            "tshark -r /home/operator/pcaps/suspicious_http_dns.pcap -c 10"
        )
        assert len(tshark_out) > 50
        assert "NOENTRY{" not in tshark_out

        # 2. Query PCAP summary API
        sum_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8205/api/wireshark/summary"
        )
        assert "128" in sum_out
        assert "NOENTRY{" not in sum_out

        # 3. Query HTTP stream decoding API
        http_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8205/api/wireshark/http"
        )
        assert "telemetry.corp.noentry.internal" in http_out
        assert "NOENTRY{" not in http_out

        # 4. Query DNS query dissection API
        dns_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8205/api/wireshark/dns"
        )
        assert "c2-beacon.corp.noentry.internal" in dns_out
        assert "NOENTRY{" not in dns_out

        # 5. Query TCP handshake analysis API
        hs_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8205/api/wireshark/handshake"
        )
        assert "51420" in hs_out
        assert "NOENTRY{" not in hs_out

        # 6. Verify GET on challenge returns NO flag
        chal_get = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8205/challenge"
        )
        assert "NOENTRY{" not in chal_get

        # 7. Submit display filter challenge verification via POST
        chal_post = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"suspicious_domain":"c2-beacon.corp.noentry.internal","filter":"dns.qry.name contains \\"c2-beacon\\""}}\' http://{target_ip}:8205/challenge'
        )
        assert "WIRESHARK_DISPLAY_FILTER_VALIDATED" in chal_post

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_blue_06_log_analysis(docker_runner):
    """Room 06: Shell log analysis on Nginx and application logs, summary APIs, and multi-source correlation."""
    session_id = "test_docker_blue_06_live"
    info = await docker_runner.start_session(session_id, "blue-06-log-analysis-fundamentals", "op-tester-blue06")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Inspect live Nginx access log with shell tools
        nginx_grep = await docker_runner.execute_command(
            session_id,
            "grep '203.0.113.88' /var/log/nginx/access.log | head -n 5"
        )
        assert "203.0.113.88" in nginx_grep
        assert "NOENTRY{" not in nginx_grep

        # 2. Inspect live structured JSON application log
        app_log = await docker_runner.execute_command(
            session_id,
            "cat /var/log/app/app.log"
        )
        assert "CRITICAL" in app_log
        assert "SQL syntax error" in app_log
        assert "NOENTRY{" not in app_log

        # 3. Query Nginx summary API
        sum_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8206/api/logs/nginx/summary"
        )
        assert "203.0.113.88" in sum_out
        assert "500" in sum_out
        assert "NOENTRY{" not in sum_out

        # 4. Query structured application critical log API
        crit_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8206/api/logs/app/critical"
        )
        assert "CRITICAL" in crit_out
        assert "203.0.113.88" in crit_out
        assert "NOENTRY{" not in crit_out

        # 5. Verify GET on challenge returns NO flag
        chal_get = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8206/challenge"
        )
        assert "NOENTRY{" not in chal_get

        # 6. Submit multi-source log correlation challenge via POST
        chal_post = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"attacker_ip":"203.0.113.88","log_level":"CRITICAL"}}\' http://{target_ip}:8206/challenge'
        )
        assert "LOG_TRIAGE_INCIDENT_CORRELATED_SECURE" in chal_post

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_blue_07_siem(docker_runner):
    """Room 07: Live SIEM search index queries, correlated alert investigation, custom rule authoring, triage challenge."""
    session_id = "test_docker_blue_07_live"
    info = await docker_runner.start_session(session_id, "blue-07-siem-fundamentals", "op-tester-blue07")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Execute operator SIEM CLI tool for alerts
        alerts_cli = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/siem_query.py alerts"
        )
        assert "RULE_BRUTE_FORCE_EXFIL" in alerts_cli
        assert "198.51.100.77" in alerts_cli
        assert "NOENTRY{" not in alerts_cli

        # 2. Query SIEM search index via HTTP
        search_out = await docker_runner.execute_command(
            session_id,
            f"curl -s 'http://{target_ip}:8207/api/siem/search?severity=HIGH'"
        )
        assert "198.51.100.77" in search_out
        assert "AUTH_FAILURE" in search_out
        assert "NOENTRY{" not in search_out

        # 3. Query SIEM alerts API
        alerts_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8207/api/siem/alerts"
        )
        assert "ALRT-701" in alerts_out
        assert "RULE_BRUTE_FORCE_EXFIL" in alerts_out
        assert "NOENTRY{" not in alerts_out

        # 4. Deploy custom detection rule via POST
        rule_post = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"rule_name":"RULE_ANOMALOUS_EGRESS","condition":"bytes_out > 10000000","severity":"HIGH"}}\' http://{target_ip}:8207/api/siem/rules'
        )
        assert "SIEM_CUSTOM_DETECTION_RULE_ACTIVE" in rule_post

        # 5. Verify GET on challenge returns NO flag
        chal_get = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8207/challenge"
        )
        assert "NOENTRY{" not in chal_get

        # 6. Submit incident prioritization triage challenge via POST
        chal_post = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"alert_id":"ALRT-701","rule_name":"RULE_BRUTE_FORCE_EXFIL","priority":"CRITICAL"}}\' http://{target_ip}:8207/challenge'
        )
        assert "SIEM_TRIAGE_PRIORITIZATION_VALIDATED" in chal_post

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_blue_08_windows_event(docker_runner):
    """Room 08: Windows Security Event log investigation with CLI parser, APIs, and attack chain reconstruction."""
    session_id = "test_docker_blue_08_live"
    info = await docker_runner.start_session(session_id, "blue-08-windows-event-investigation", "op-tester-blue08")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Execute operator Windows event parser CLI tool
        proc_cli = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/investigate_win_events.py 4688"
        )
        assert "4688" in proc_cli
        assert "svc_admin" in proc_cli
        assert "NOENTRY{" not in proc_cli

        tamper_cli = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/investigate_win_events.py 1102"
        )
        assert "audit log was cleared" in tamper_cli
        assert "NOENTRY{" not in tamper_cli

        # 2. Query process creation telemetry API (Event 4688)
        proc_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8208/api/winevent/process"
        )
        assert "powershell.exe" in proc_out
        assert "NOENTRY{" not in proc_out

        # 3. Query group membership escalation telemetry API (Event 4732)
        group_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8208/api/winevent/groups"
        )
        assert "Administrators" in group_out
        assert "backdoor_admin" in group_out
        assert "NOENTRY{" not in group_out

        # 4. Query PowerShell scriptblock logging API (Event 4104)
        sb_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8208/api/winevent/scriptblock"
        )
        assert "payload.ps1" in sb_out
        assert "NOENTRY{" not in sb_out

        # 5. Query anti-forensics audit log tampering API (Event 1102)
        anti_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8208/api/winevent/antiforensics"
        )
        assert "1102" in anti_out
        assert "NOENTRY{" not in anti_out

        # 6. Verify GET on challenge returns NO flag
        chal_get = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8208/challenge"
        )
        assert "NOENTRY{" not in chal_get

        # 7. Submit kill-chain reconstruction challenge via POST
        chal_post = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"tamper_event_id":1102,"malicious_process":"powershell.exe","added_group":"Administrators"}}\' http://{target_ip}:8208/challenge'
        )
        assert "WIN_EVENT_CHAIN_RECONSTRUCTED_CONFIRMED" in chal_post

    finally:
        await docker_runner.stop_session(session_id)
