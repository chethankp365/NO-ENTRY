"""
Genuine Docker Lab Integration Tests for Blue Team Rooms 01–04:
- Room 01: Blue Team Foundations (blue-01-blue-team-foundations)
- Room 02: Windows Security Fundamentals (blue-02-windows-security-fundamentals)
- Room 03: Linux Security Monitoring (blue-03-linux-security-monitoring)
- Room 04: Network Traffic Analysis (blue-04-network-traffic-analysis)

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
async def test_docker_room_blue_01_soc(docker_runner):
    """Room 01: Live SOC event streams, SIEM alert correlation, triage submission, evidence timeline, containment."""
    session_id = "test_docker_blue_01_live"
    info = await docker_runner.start_session(session_id, "blue-01-blue-team-foundations", "op-tester-blue01")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Query live SIEM event stream
        events_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8201/api/soc/events"
        )
        assert "198.51.100.42" in events_out
        assert "NOENTRY{" not in events_out

        # 2. Query SIEM event stream via operator python tool
        py_events = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/soc_query.py"
        )
        assert "EVT-1003" in py_events
        assert "NOENTRY{" not in py_events

        # 3. Interrogate correlated SIEM alerts
        alerts_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8201/api/soc/alerts"
        )
        assert "T1110.003" in alerts_out
        assert "NOENTRY{" not in alerts_out

        # 4. Submit formal triage ticket via POST
        triage_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"event_id":"EVT-1003","classification":"TRUE_POSITIVE","severity":"HIGH"}}\' http://{target_ip}:8201/api/soc/triage'
        )
        assert "TRIAGE_CONFIRMED_EVT1003_SECURE" in triage_out

        # 5. Evidence timeline reconstruction via POST
        timeline_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"stage":"evidence","adversary_ip":"198.51.100.42","compromised_host":"DC-VOLT01"}}\' http://{target_ip}:8201/challenge'
        )
        assert "TIMELINE_RECONSTRUCTED_DC_VOLT01" in timeline_out

        # 6. Execute perimeter containment remediation via POST
        rem_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"block_ip":"198.51.100.42","action":"CONTAIN_SESSION"}}\' http://{target_ip}:8201/api/soc/remediate'
        )
        assert "CONTAINMENT_ENFORCED_IP_BLOCKED" in rem_out

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_blue_02_windows(docker_runner):
    """Room 02: Logon event triage (4624/4625), rogue account discovery (4720), privilege audit challenge, lockout hardening."""
    session_id = "test_docker_blue_02_live"
    info = await docker_runner.start_session(session_id, "blue-02-windows-security-fundamentals", "op-tester-blue02")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Query Windows logon event telemetry
        logon_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8202/api/windows/events/logon"
        )
        assert "10.10.14.2" in logon_out
        assert "NOENTRY{" not in logon_out

        # 2. Parse Windows events using local event tool
        evtx_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/parse_evtx.py"
        )
        assert "backdoor_admin" in evtx_out
        assert "NOENTRY{" not in evtx_out

        # 3. Interrogate privileged account creation events
        priv_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8202/api/windows/events/privileged"
        )
        assert "backdoor_admin" in priv_out
        assert "NOENTRY{" not in priv_out

        # 4. Privilege audit challenge via POST
        audit_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"audit_target":"backdoor_admin","abused_privilege":"SeDebugPrivilege"}}\' http://{target_ip}:8202/challenge'
        )
        assert "SEDEBUG_PRIVILEGE_AUDITED_CONFIRMED" in audit_out

        # 5. Lockout policy remediation via POST
        rem_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"lockout_threshold":5,"reset_duration_mins":30}}\' http://{target_ip}:8202/api/windows/remediate'
        )
        assert "LOCKOUT_POLICY_ENFORCED_5_ATTEMPTS" in rem_out

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_blue_03_linux(docker_runner):
    """Room 03: Linux auth log inspection, SSH brute-force analysis, sudo abuse detection, source attribution, fail2ban hardening."""
    session_id = "test_docker_blue_03_live"
    info = await docker_runner.start_session(session_id, "blue-03-linux-security-monitoring", "op-tester-blue03")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Local auth log grep inside container
        local_auth = await docker_runner.execute_command(
            session_id,
            "grep 'Failed password' /var/log/auth.log"
        )
        assert "192.0.2.144" in local_auth
        assert "NOENTRY{" not in local_auth

        # 2. Query target auth logs API
        auth_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8203/api/linux/logs/auth"
        )
        assert "192.0.2.144" in auth_out
        assert "NOENTRY{" not in auth_out

        # 3. Query sudo privilege abuse logs API
        sudo_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8203/api/linux/logs/sudo"
        )
        assert "/usr/bin/python3" in sudo_out
        assert "NOENTRY{" not in sudo_out

        # 4. Threat actor attribution challenge via POST
        attr_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"attacker_ip":"192.0.2.144","service":"sshd"}}\' http://{target_ip}:8203/challenge'
        )
        assert "ATTRIBUTION_CONFIRMED_192_0_2_144" in attr_out

        # 5. SSHD & fail2ban hardening remediation via POST
        rem_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"harden_ssh":true,"enable_fail2ban":true}}\' http://{target_ip}:8203/api/linux/remediate'
        )
        assert "SSHD_HARDENED_FAIL2BAN_ENABLED" in rem_out

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_blue_04_traffic(docker_runner):
    """Room 04: Real PCAP inspection with tcpdump, HTTP stream credential sniffing, DNS covert exfiltration, TLS enforcement."""
    session_id = "test_docker_blue_04_live"
    info = await docker_runner.start_session(session_id, "blue-04-network-traffic-analysis", "op-tester-blue04")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Genuine PCAP packet dissection with tcpdump inside attacker container
        tcpdump_out = await docker_runner.execute_command(
            session_id,
            "tcpdump -nn -r /home/operator/pcaps/incident_capture.pcap"
        )
        assert "10.10.14.2" in tcpdump_out
        assert "10.10.14.90" in tcpdump_out
        assert "NOENTRY{" not in tcpdump_out

        # 2. Query target PCAP summary API
        summary_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8204/api/traffic/summary"
        )
        assert "240" in summary_out
        assert "NOENTRY{" not in summary_out

        # 3. Query cleartext HTTP stream API
        http_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8204/api/traffic/streams/http"
        )
        assert "VoltSecret9921!" in http_out
        assert "NOENTRY{" not in http_out

        # 4. Query DNS exfiltration telemetry API
        dns_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8204/api/traffic/dns"
        )
        assert "exfil-chunk-data.corp.noentry.internal" in dns_out
        assert "NOENTRY{" not in dns_out

        # 5. Stream forensic challenge via POST
        stream_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"covert_channel":"dns","tunnel_domain":"exfil-chunk-data.corp.noentry.internal"}}\' http://{target_ip}:8204/challenge'
        )
        assert "COVERT_CHANNEL_EXFIL_IDENTIFIED" in stream_out

        # 6. TLS & DNS sinkhole remediation via POST
        rem_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"enforce_tls":true,"sinkhole_malicious_dns":true}}\' http://{target_ip}:8204/api/traffic/remediate'
        )
        assert "TLS_ENFORCED_DNS_SINKHOLED" in rem_out

    finally:
        await docker_runner.stop_session(session_id)
