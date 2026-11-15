"""
Genuine Docker Lab Integration Tests for Red Team Rooms 18–20:
- Room 18: Active Directory Fundamentals (red-18-active-directory-fundamentals)
- Room 19: Exploitation and Post-Exploitation (red-19-exploitation-post-exploitation)
- Room 20: Red Team Capstone (red-20-red-team-capstone)

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
async def test_docker_room_18_active_directory(docker_runner):
    """Room 18: Domain hierarchy discovery, LDAP SPN enumeration, Kerberos TGT issuance, challenge audit, GPO remediation."""
    session_id = "test_docker_room_18_live"
    info = await docker_runner.start_session(session_id, "red-18-active-directory-fundamentals", "op-tester-18")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Domain hierarchy discovery
        dom_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8099/api/ad/domain"
        )
        assert "NOENTRY{ad_domain_hierarchy_discovered_9102}" in dom_out

        # 2. LDAP directory query & SPN discovery
        ldap_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/ad_ldap_query.py"
        )
        assert "NOENTRY{ad_ldap_enumeration_spn_7812}" in ldap_out

        # 3. Kerberos AS-REQ / TGT request
        tgt_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"username":"svc_backup"}}\' http://{target_ip}:8099/api/ad/kerberos/request_tgt'
        )
        assert "NOENTRY{ad_kerberos_tgt_authentication_4419}" in tgt_out

        # 4. Domain misconfiguration audit
        audit_out = await docker_runner.execute_command(
            session_id,
            f'curl -s "http://{target_ip}:8099/challenge?audit=spn"'
        )
        assert "NOENTRY{ad_delegation_misconfig_master_3201}" in audit_out

        # 5. GPO Least-Privilege Remediation
        rem_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -X POST http://{target_ip}:8099/api/ad/remediate"
        )
        assert "NOENTRY{ad_gpo_least_privilege_secured_8891}" in rem_out

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_19_exploitation(docker_runner):
    """Room 19: Foothold exploit, post-recon telemetry, persistence marker, lateral challenge, incident cleanup."""
    session_id = "test_docker_room_19_live"
    info = await docker_runner.start_session(session_id, "red-19-exploitation-post-exploitation", "op-tester-19")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Controlled foothold exploitation via runner script
        foot_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/exploit_runner.py"
        )
        assert "NOENTRY{exploit_initial_foothold_access_6120}" in foot_out

        # 2. Host and environment telemetry reconnaissance
        recon_out = await docker_runner.execute_command(
            session_id,
            f'curl -s "http://{target_ip}:8100/api/post/recon?session=sess_post_99182"'
        )
        assert "NOENTRY{exploit_env_recon_telemetry_9941}" in recon_out

        # 3. Controlled persistence marker demonstration
        pers_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"session":"sess_post_99182","mechanism":"cron"}}\' http://{target_ip}:8100/api/post/persist'
        )
        assert "NOENTRY{exploit_persistence_mechanism_4182}" in pers_out

        # 4. Lateral movement risk analysis
        lat_out = await docker_runner.execute_command(
            session_id,
            f'curl -s "http://{target_ip}:8100/challenge?stage=lateral"'
        )
        assert "NOENTRY{exploit_lateral_exfil_master_7730}" in lat_out

        # 5. Incident cleanup and remediation
        rem_out = await docker_runner.execute_command(
            session_id,
            f"curl -s -X POST http://{target_ip}:8100/api/remediate"
        )
        assert "NOENTRY{exploit_cleanup_remediation_verified_2041}" in rem_out

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_20_red_team_capstone(docker_runner):
    """Room 20: Scope & ROE verification, perimeter recon, foothold exploit, privilege escalation, formal report."""
    session_id = "test_docker_room_20_live"
    info = await docker_runner.start_session(session_id, "red-20-red-team-capstone", "op-tester-20")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Scope and Rules of Engagement verification
        scope_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8101/api/capstone/scope"
        )
        assert "NOENTRY{capstone_scope_roe_verified_1092}" in scope_out

        # 2. Perimeter reconnaissance & service triage
        recon_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8101/api/capstone/recon"
        )
        assert "NOENTRY{capstone_service_discovery_5821}" in recon_out

        # 3. Foothold exploit against enterprise endpoint
        exploit_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"action":"foothold"}}\' http://{target_ip}:8101/api/capstone/exploit'
        )
        assert "NOENTRY{capstone_foothold_compromise_3319}" in exploit_out

        # 4. Privilege boundary breach to root
        priv_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d \'{{"technique":"suid"}}\' http://{target_ip}:8101/api/capstone/privesc'
        )
        assert "NOENTRY{capstone_privilege_breach_8804}" in priv_out

        # 5. Formal penetration assessment report submission
        rep_out = await docker_runner.execute_command(
            session_id,
            f'curl -s -X POST -H "Content-Type: application/json" -d @/home/operator/capstone/report_template.json http://{target_ip}:8101/api/capstone/report'
        )
        assert "NOENTRY{capstone_master_assessor_7749}" in rep_out

    finally:
        await docker_runner.stop_session(session_id)

