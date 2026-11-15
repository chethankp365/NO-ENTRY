"""
Genuine Docker Lab Integration Tests for Red Team Rooms 01–04.
Tests live container duo (non-root attacker container + multi-port target container)
communicating over isolated internal bridge network (10.10.14.0/24).
"""

import pytest
from backend.app.labs.base import DockerStatus
from backend.app.labs.docker_runner import DockerLabRunner


@pytest.fixture(scope="module")
def docker_runner():
    runner = DockerLabRunner()
    if not runner.is_available():
        pytest.skip("Docker daemon is not operational on this host. Skipping Docker lab tests.")
    return runner


@pytest.mark.asyncio
async def test_docker_room_01_cybersecurity_foundations(docker_runner):
    """Room 01: Asset inspection, permissions, and internal audit endpoint."""
    session_id = "test_docker_room_01_live"
    info = await docker_runner.start_session(session_id, "red-01-cybersecurity-foundations", "op-tester-01")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Inspect assets directory
        ls_out = await docker_runner.execute_command(session_id, "ls -la /home/operator/assets")
        assert "customer_records.db" in ls_out
        assert "backup_codes.txt" in ls_out

        # 2. Read sensitive backup codes
        codes_out = await docker_runner.execute_command(session_id, "cat /home/operator/assets/backup_codes.txt")
        assert "NOENTRY{foundations_confidentiality_leak_8821}" in codes_out

        # 3. Query internal asset audit service on port 8081
        audit_out = await docker_runner.execute_command(session_id, f"curl -s http://{target_ip}:8081/audit")
        assert "AUDIT_COMPLETE" in audit_out
        assert "NOENTRY{cia_triad_integrity_breach_1042}" in audit_out

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_02_linux_for_hackers(docker_runner):
    """Room 02: Linux navigation, dotfiles, chmod, ps aux, and grep telemetry."""
    session_id = "test_docker_room_02_live"
    info = await docker_runner.start_session(session_id, "red-02-linux-for-hackers", "op-tester-02")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. whoami
        whoami = await docker_runner.execute_command(session_id, "whoami")
        assert whoami.strip() == "operator"

        # 2. Hidden dotfiles
        dot_out = await docker_runner.execute_command(
            session_id, "cat /home/operator/challenges/.secret_vault/flag_hidden.txt"
        )
        assert "NOENTRY{linux_hidden_dotfiles_revealed_3182}" in dot_out

        # 3. Permissions & script execution
        chmod_out = await docker_runner.execute_command(
            session_id,
            "chmod +x /home/operator/challenges/restricted_script.sh && /home/operator/challenges/restricted_script.sh",
        )
        assert "NOENTRY{linux_chmod_execution_unlocked_9104}" in chmod_out

        # 4. Background process inspection
        ps_out = await docker_runner.execute_command(session_id, "ps aux | grep shadow_agent")
        assert "NOENTRY{linux_process_inspection_7741}" in ps_out

        # 5. Telemetry log stream filtering
        grep_out = await docker_runner.execute_command(
            session_id, "grep SECURITY_FLAG /home/operator/challenges/system_telemetry.log"
        )
        assert "NOENTRY{linux_grep_stream_mastery_5239}" in grep_out

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_03_networking_fundamentals(docker_runner):
    """Room 03: IP addressing, subnet masks, raw TCP socket on 9001, and HTTP diagnostics."""
    session_id = "test_docker_room_03_live"
    info = await docker_runner.start_session(session_id, "red-03-networking-fundamentals", "op-tester-03")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Interface inspection
        ip_out = await docker_runner.execute_command(session_id, "ip addr show eth0")
        assert "/24" in ip_out
        assert "10.10." in ip_out

        # 2. Raw TCP socket on port 9001
        nc_out = await docker_runner.execute_command(session_id, f"nc -w 3 {target_ip} 9001 || true")
        if "NOENTRY{net_raw_tcp_socket_8832}" not in nc_out:
            # Fallback in case nc timeout flag differs in alpine
            nc_out = await docker_runner.execute_command(
                session_id,
                f"python3 -c \"import socket; s=socket.socket(); s.settimeout(3); s.connect(('{target_ip}', 9001)); print(s.recv(1024).decode())\"",
            )
        assert "NOENTRY{net_raw_tcp_socket_8832}" in nc_out

        # 3. HTTP client diagnostics on port 8080
        net_info = await docker_runner.execute_command(session_id, f"curl -s http://{target_ip}:8080/network-info")
        assert "/24" in net_info
        assert "NOENTRY{net_http_client_server_4419}" in net_info

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_04_reconnaissance(docker_runner):
    """Room 04: robots.txt discovery, staging portal, header banner grabbing, API metadata, and backup leak."""
    session_id = "test_docker_room_04_live"
    info = await docker_runner.start_session(session_id, "red-04-reconnaissance", "op-tester-04")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. robots.txt
        robots = await docker_runner.execute_command(session_id, f"curl -s http://{target_ip}:8090/robots.txt")
        assert "Disallow: /admin-portal-staging-7712/" in robots
        assert "Disallow: /secret-assets/" in robots

        # 2. Staging portal disclosed by robots.txt
        staging = await docker_runner.execute_command(
            session_id, f"curl -s http://{target_ip}:8090/admin-portal-staging-7712/"
        )
        assert "NOENTRY{recon_robots_hidden_endpoint_2901}" in staging

        # 3. Custom server header banner grabbing
        hdr_out = await docker_runner.execute_command(session_id, f"curl -I -s http://{target_ip}:8090/")
        assert "VoltCore-v2.14-Internal" in hdr_out
        assert "x-backend-server" in hdr_out.lower()

        # 4. API health & internal documentation metadata
        health = await docker_runner.execute_command(session_id, f"curl -s http://{target_ip}:8090/api/v1/health")
        assert "/api/v1/internal-docs" in health

        docs = await docker_runner.execute_command(session_id, f"curl -s http://{target_ip}:8090/api/v1/internal-docs")
        assert "NOENTRY{recon_api_metadata_harvest_6310}" in docs

        # 5. Directory discovery backup credentials leak
        bak = await docker_runner.execute_command(
            session_id, f"curl -s http://{target_ip}:8090/secret-assets/database_credentials.bak"
        )
        assert "NOENTRY{recon_dir_enumeration_master_9044}" in bak

    finally:
        await docker_runner.stop_session(session_id)
