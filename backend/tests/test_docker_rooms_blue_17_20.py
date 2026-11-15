"""
Genuine Docker Lab Integration Tests for Blue Team Rooms 17–20:
- Room 17: Digital Forensics (blue-17-digital-forensics)
- Room 18: Windows and Linux Hardening (blue-18-windows-linux-hardening)
- Room 19: Threat Intelligence (blue-19-threat-intelligence)
- Room 20: Blue Team Capstone (blue-20-blue-team-capstone)

Tests live Docker container duos communicating over isolated internal bridge networks.
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
async def test_docker_room_blue_17_digital_forensics(docker_runner):
    """Room 17: Live SHA-256 evidence hashing, MACB filesystem extraction, timeline reconstruction."""
    session_id = "test_docker_blue_17_live"
    info = await docker_runner.start_session(session_id, "blue-17-digital-forensics", "op-tester-blue17")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Calculate SHA-256 of evidence artifact
        hash_out = await docker_runner.execute_command(
            session_id,
            "sha256sum /var/log/forensics/evidence_artifact.bin"
        )
        assert "34049ea3151168bea705f416fabb3c8919ba7563ad650cff2af6e1b7745fc465" in hash_out
        assert "NOENTRY{" not in hash_out

        # 2. Run forensics tool for timeline and MFT inspection
        time_tool_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/forensics_tool.py --timeline"
        )
        assert "89104" in time_tool_out
        assert "Temp_Exfil" in time_tool_out

        # 3. GET /challenge returns NO flag
        chal_get = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8217/challenge"
        )
        assert "NOENTRY{" not in chal_get

        # 4. Confirm timeline reconstruction via POST
        time_post_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"inode":89104,"event_type":"UNAUTHORIZED_STAGING_CREATION","timestamp":"2026-11-15T09:12:00Z"}}\' '
            f'http://{target_ip}:8217/api/forensics/timeline'
        )
        time_out = await docker_runner.execute_command(session_id, time_post_cmd)
        assert "FORENSICS_TIMELINE_CONFIRMED" in time_out
        assert info.has_action("forensics_timeline_confirmed")

        # 5. Submit final challenge
        chal_post_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"case_id":"FOR-2026-091","evidence_hash":"34049ea3151168bea705f416fabb3c8919ba7563ad650cff2af6e1b7745fc465","attacker_action":"DATA_STAGING_AND_TAMPERING"}}\' '
            f'http://{target_ip}:8217/challenge'
        )
        chal_out = await docker_runner.execute_command(session_id, chal_post_cmd)
        assert "DIGITAL_FORENSICS_INVESTIGATION_COMPLETE" in chal_out
        assert info.has_action("forensics_challenge_verified")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_blue_18_hardening(docker_runner):
    """Room 18: Live OS security auditing, Linux SSH/sudoers hardening, and Windows CIS compliance."""
    session_id = "test_docker_blue_18_live"
    info = await docker_runner.start_session(session_id, "blue-18-windows-linux-hardening", "op-tester-blue18")
    assert info.status == "RUNNING"
    target_ip = info.target_ip

    try:
        # 1. Audit Linux configuration
        linux_audit_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/hardening_audit.py --linux"
        )
        assert "PermitRootLogin yes" in linux_audit_out
        assert "NOPASSWD: ALL" in linux_audit_out

        # 2. Audit Windows configuration
        win_audit_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/hardening_audit.py --windows"
        )
        assert "AccountLockoutThreshold: 0" in win_audit_out

        # 3. Apply Linux hardening
        lin_apply_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"disable_root_ssh":true,"enforce_key_auth":true,"remove_wildcard_sudo":true}}\' '
            f'http://{target_ip}:8218/api/hardening/linux/apply'
        )
        lin_out = await docker_runner.execute_command(session_id, lin_apply_cmd)
        assert "LINUX_HARDENING_ENFORCED" in lin_out
        assert info.has_action("linux_hardening_enforced")

        # 4. Apply Windows hardening
        win_apply_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"lockout_threshold":5,"powershell_policy":"RemoteSigned","disable_smbv1":true}}\' '
            f'http://{target_ip}:8218/api/hardening/windows/apply'
        )
        await docker_runner.execute_command(session_id, win_apply_cmd)

        # 5. Submit dual OS challenge
        chal_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"target_scope":"DUAL_OS_ENTERPRISE","linux_remediated":true,"windows_remediated":true}}\' '
            f'http://{target_ip}:8218/challenge'
        )
        chal_out = await docker_runner.execute_command(session_id, chal_cmd)
        assert "SYSTEM_HARDENING_BASELINE_VERIFIED" in chal_out
        assert info.has_action("hardening_challenge_verified")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_blue_19_threat_intelligence(docker_runner):
    """Room 19: Live STIX 2.1 feed extraction, IOC classification, Diamond Model correlation, and ATT&CK mapping."""
    session_id = "test_docker_blue_19_live"
    info = await docker_runner.start_session(session_id, "blue-19-threat-intelligence", "op-tester-blue19")
    assert info.status == "RUNNING"
    target_ip = info.target_ip

    try:
        # 1. Run intel tool to extract IOCs
        iocs_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/intel_tool.py --iocs"
        )
        assert "198.51.100.77" in iocs_out
        assert "APT-VOLT-VIPER" in iocs_out

        # 2. Run ATT&CK mapping tool
        attck_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/intel_tool.py --attck"
        )
        assert "T1566.001" in attck_out
        assert "T1059.001" in attck_out

        # 3. Correlate indicators via POST
        corr_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"threat_actor":"APT-VOLT-VIPER","c2_ip":"198.51.100.77","c2_domain":"update-cdn.voltcorp-support.internal","malware_family":"VoltDrop"}}\' '
            f'http://{target_ip}:8219/api/intel/correlate'
        )
        corr_out = await docker_runner.execute_command(session_id, corr_cmd)
        assert "INTEL_CORRELATION_CONFIRMED" in corr_out
        assert info.has_action("intel_correlation_confirmed")

        # 4. Map ATT&CK technique via POST
        map_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"threat_actor":"APT-VOLT-VIPER","primary_technique":"T1566.001","secondary_technique":"T1059.001"}}\' '
            f'http://{target_ip}:8219/api/intel/attck-map'
        )
        await docker_runner.execute_command(session_id, map_cmd)

        # 5. Submit challenge dossier
        chal_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"campaign_id":"CMP-2026-VOLT","confidence_score":"HIGH","defensive_recommendation":"BLOCK_IP_AND_HASH_ON_PERIMETER"}}\' '
            f'http://{target_ip}:8219/challenge'
        )
        chal_out = await docker_runner.execute_command(session_id, chal_cmd)
        assert "THREAT_INTEL_ASSESSMENT_DELIVERED" in chal_out
        assert info.has_action("intel_challenge_verified")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_blue_20_capstone(docker_runner):
    """Room 20: Comprehensive 9-stage incident response investigation and root-cause remediation."""
    session_id = "test_docker_blue_20_live"
    info = await docker_runner.start_session(session_id, "blue-20-blue-team-capstone", "op-tester-blue20")
    assert info.status == "RUNNING"
    target_ip = info.target_ip

    try:
        # 1. Investigate via capstone investigator
        det_tool_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/capstone_investigator.py --detect"
        )
        assert "DB-PROD-01" in det_tool_out
        assert "198.51.100.77" in det_tool_out

        # 2. Stage 1 Detection
        det_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"stage":"DETECTION","adversary_ip":"198.51.100.77","compromised_asset":"DB-PROD-01"}}\' '
            f'http://{target_ip}:8220/api/capstone/detect'
        )
        det_out = await docker_runner.execute_command(session_id, det_cmd)
        assert "CAPSTONE_STAGE1_DETECT_OK" in det_out
        assert info.has_action("capstone_stage1_verified")

        # 3. Stage 2 Threat Hunting
        hunt_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"stage":"THREAT_HUNTING","malicious_pid":3912,"persistence_service":"svc_winupdater","technique":"T1059.001"}}\' '
            f'http://{target_ip}:8220/api/capstone/hunt'
        )
        hunt_out = await docker_runner.execute_command(session_id, hunt_cmd)
        assert "CAPSTONE_STAGE3_HUNT_OK" in hunt_out
        assert info.has_action("capstone_stage2_verified")

        # 4. Stage 3 Forensics
        for_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"stage":"FORENSICS","sha256_verified":true,"ram_hash":"7a35b1d9821811faec2984b2382903487f54921b72a912e84c980312fa890123"}}\' '
            f'http://{target_ip}:8220/api/capstone/forensics'
        )
        for_out = await docker_runner.execute_command(session_id, for_cmd)
        assert "CAPSTONE_STAGE4_FORENSICS_OK" in for_out
        assert info.has_action("capstone_stage3_verified")

        # 5. Stage 4 Triage
        tri_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"stage":"TRIAGE","incident_severity":"CRITICAL","threat_actor":"APT-VOLT-VIPER","exfil_volume_mb":2400}}\' '
            f'http://{target_ip}:8220/api/capstone/triage'
        )
        tri_out = await docker_runner.execute_command(session_id, tri_cmd)
        assert "CAPSTONE_STAGE6_TRIAGE_OK" in tri_out
        assert info.has_action("capstone_stage4_verified")

        # 6. Stage 5 Containment
        cont_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"stage":"CONTAINMENT","isolate_host":"DB-PROD-01","terminate_pid":3912,"revoke_token":"ST-VOLT-9921"}}\' '
            f'http://{target_ip}:8220/api/capstone/contain'
        )
        cont_out = await docker_runner.execute_command(session_id, cont_cmd)
        assert "CAPSTONE_STAGE7_CONTAIN_OK" in cont_out
        assert info.has_action("capstone_stage5_verified")

        # 7. Stage 6 Final Capstone Challenge
        chal_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"case_id":"CAPSTONE-IR-FINAL","incident_summary":"CRITICAL_APT_INTRUSION_CONTAINED","all_stages_complete":true}}\' '
            f'http://{target_ip}:8220/challenge'
        )
        chal_out = await docker_runner.execute_command(session_id, chal_cmd)
        assert "BLUE_TEAM_CAPSTONE_TRIUMPH" in chal_out
        assert info.has_action("capstone_final_verified")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_spoofing_prevention(docker_runner):
    """Verify that tampering with X-Operator-ID or query parameter is rejected with 403 FORBIDDEN."""
    session_id = "test_docker_spoof_prevent"
    info = await docker_runner.start_session(session_id, "blue-17-digital-forensics", "op-legit-user")
    target_ip = info.target_ip

    try:
        # Attempt to spoof operator identity in header
        spoof_cmd = (
            f'curl -s -w "\\nSTATUS:%{{http_code}}" -X POST -H "Content-Type: application/json" '
            f'-H "X-Operator-ID: op-impostor" '
            f'-d \'{{"inode":89104,"event_type":"UNAUTHORIZED_STAGING_CREATION","timestamp":"2026-11-15T09:12:00Z"}}\' '
            f'http://{target_ip}:8217/api/forensics/timeline'
        )
        spoof_out = await docker_runner.execute_command(session_id, spoof_cmd)
        assert "STATUS:403" in spoof_out or "IMPERSONATION_DETECTED" in spoof_out
    finally:
        await docker_runner.stop_session(session_id)

