"""
Genuine Docker Lab Integration Tests for Red Team Rooms 05–08:
- Room 05: Network Scanning (red-05-network-scanning)
- Room 06: Service Enumeration (red-06-service-enumeration)
- Room 07: Vulnerability Assessment (red-07-vulnerability-assessment)
- Room 08: Web Application Fundamentals (red-08-web-application-fundamentals)
Tests live container duo communicating over isolated internal bridge network (10.10.14.0/24).
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
async def test_docker_room_05_network_scanning(docker_runner):
    """Room 05: Host discovery, TCP port scanning, port 8085 inspection, and challenge."""
    session_id = "test_docker_room_05_live"
    info = await docker_runner.start_session(session_id, "red-05-network-scanning", "op-tester-05")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Host discovery via nmap ping sweep / probe
        ping_sweep = await docker_runner.execute_command(session_id, f"nmap -sn -PS8085,9001 {target_ip}")
        if target_ip not in ping_sweep:
            ping_sweep = await docker_runner.execute_command(session_id, f"nmap -sn {target_ip}")
        if target_ip not in ping_sweep:
            ping_sweep = await docker_runner.execute_command(session_id, f"ping -c 1 {target_ip}")
        assert target_ip in ping_sweep

        # 2. TCP port scan checking open vs closed ports
        port_scan = await docker_runner.execute_command(session_id, f"nmap -sT -p 8085,9001,9999 {target_ip}")
        assert "8085/tcp open" in port_scan
        assert "9001/tcp open" in port_scan
        assert "9999/tcp closed" in port_scan

        # 3. Port discovery on port 8085
        status_out = await docker_runner.execute_command(session_id, f"curl -s http://{target_ip}:8085/scan-status")
        assert "NOENTRY{nmap_port_discovery_open_4812}" in status_out

        # 4. Challenge on port 8085
        chal_out = await docker_runner.execute_command(session_id, f"curl -s http://{target_ip}:8085/challenge")
        assert "NOENTRY{net_scan_stealth_recon_7731}" in chal_out

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_06_service_enumeration(docker_runner):
    """Room 06: FTP banner (2121), SSH banner (2222), HTTP headers (8086), admin catalog."""
    session_id = "test_docker_room_06_live"
    info = await docker_runner.start_session(session_id, "red-06-service-enumeration", "op-tester-06")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. FTP banner on port 2121
        ftp_out = await docker_runner.execute_command(
            session_id,
            f"python3 -c \"import socket; s=socket.socket(); s.settimeout(3); s.connect(('{target_ip}', 2121)); print(s.recv(1024).decode())\""
        )
        assert "NOENTRY{ftp_banner_service_enumeration_5921}" in ftp_out

        # 2. SSH banner on port 2222
        ssh_out = await docker_runner.execute_command(
            session_id,
            f"python3 -c \"import socket; s=socket.socket(); s.settimeout(3); s.connect(('{target_ip}', 2222)); print(s.recv(1024).decode())\""
        )
        assert "SSH-2.0-OpenSSH_8.4p1-VoltCorp_Secure_Gateway_v2" in ssh_out

        # 3. HTTP headers on port 8086
        hdr_out = await docker_runner.execute_command(session_id, f"curl -I -s http://{target_ip}:8086/")
        assert "VoltCore-Enum-v3.1" in hdr_out

        # 4. Hidden administrative service catalog
        chal_out = await docker_runner.execute_command(session_id, f"curl -s http://{target_ip}:8086/admin-internal/")
        assert "NOENTRY{service_enumeration_master_3389}" in chal_out

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_07_vulnerability_assessment(docker_runner):
    """Room 07: Component inventory, CVE catalog inspection, CLI audit tool, audit report, patch verification."""
    session_id = "test_docker_room_07_live"
    info = await docker_runner.start_session(session_id, "red-07-vulnerability-assessment", "op-tester-07")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Query target components
        comp_out = await docker_runner.execute_command(session_id, f"curl -s http://{target_ip}:8087/api/components")
        assert "VoltCore HTTP Engine" in comp_out
        assert "2.14.0-legacy" in comp_out

        # 2. Local CVE catalog
        cat_out = await docker_runner.execute_command(session_id, "cat /home/operator/vuln_db/cve_catalog.json")
        assert "CVE-2024-2104" in cat_out
        assert "9.8" in cat_out

        # 3. Vulnerability audit script execution
        cli_out = await docker_runner.execute_command(session_id, "python3 /home/operator/tools/vuln_audit.py")
        assert "VULNERABILITY DETECTED" in cli_out

        # 4. Official audit findings report
        rep_out = await docker_runner.execute_command(session_id, f"curl -s http://{target_ip}:8087/audit/report")
        assert "NOENTRY{cve_vulnerability_assessment_master_8192}" in rep_out

        # 5. Patch remediation and verification
        rem_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -X POST http://{target_ip}:8087/audit/remediate -d 'action=apply_patch&cve=CVE-2024-2104'"
        )
        assert "NOENTRY{vuln_assessment_remediation_verified_9410}" in rem_out

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_08_web_application_fundamentals(docker_runner):
    """Room 08: Login authentication, cookie profile access, PUT method resource modification, disallowed 405."""
    session_id = "test_docker_room_08_live"
    info = await docker_runner.start_session(session_id, "red-08-web-application-fundamentals", "op-tester-08")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Login authentication and session cookie issuance
        login_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -X POST http://{target_ip}:8088/api/auth/login -d 'username=operator&password=voltpass123'"
        )
        assert "op_sess_88291a" in login_out

        # 2. Access protected endpoint using cookie
        prof_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -b 'session_id=op_sess_88291a' http://{target_ip}:8088/api/profile"
        )
        assert "NOENTRY{web_session_cookie_auth_2841}" in prof_out

        # 3. PUT request resource modification
        put_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -X PUT http://{target_ip}:8088/api/items/42 -H 'Content-Type: application/json' -d '{{\"price\": 0.00}}'"
        )
        assert "NOENTRY{web_http_put_method_master_7109}" in put_out

        # 4. Disallowed method returning 405 Method Not Allowed
        del_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -i -X DELETE http://{target_ip}:8088/api/profile"
        )
        assert "405" in del_out

    finally:
        await docker_runner.stop_session(session_id)
