"""
Genuine Docker Lab Integration Tests for Blue Team Rooms 13–16:
- Room 13: Network Intrusion Detection (blue-13-network-intrusion-detection)
- Room 14: Threat Hunting (blue-14-threat-hunting)
- Room 15: Incident Triage (blue-15-incident-triage)
- Room 16: Incident Response (blue-16-incident-response)

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
async def test_docker_room_blue_13_nids(docker_runner):
    """Room 13: Live NIDS traffic inspection, Snort rule deployment, and intrusion correlation."""
    session_id = "test_docker_blue_13_live"
    info = await docker_runner.start_session(session_id, "blue-13-network-intrusion-detection", "op-tester-blue13")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Run operator inspection tool for scan detection
        scan_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/inspect_nids.py --scan"
        )
        assert "198.51.100.99" in scan_out
        assert "NOENTRY{" not in scan_out

        # 2. Run operator inspection tool for beacon detection
        beacon_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/inspect_nids.py --beacon"
        )
        assert "203.0.113.88" in beacon_out
        assert "NOENTRY{" not in beacon_out

        # 3. Query telemetry and alerts API on target
        telem_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8213/api/nids/traffic"
        )
        assert "198.51.100.99" in telem_out
        assert "NOENTRY{" not in telem_out

        # 4. Verify GET on challenge returns NO flag
        chal_get = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8213/challenge"
        )
        assert "NOENTRY{" not in chal_get

        # 5. Deploy Snort signature rule (prerequisite)
        rule_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"rule_name":"RULE_NIDS_COVERT_BEACON","protocol":"tcp","action":"alert","dest_port":8443,"content":"HEARTBEAT_V2"}}\' '
            f'http://{target_ip}:8213/api/nids/rules'
        )
        rule_out = await docker_runner.execute_command(session_id, rule_cmd)
        assert "NIDS_SNORT_RULE_ACTIVE" in rule_out
        assert info.has_action("nids_rule_deployed")

        # 6. Submit intrusion challenge via POST
        chal_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"scanner_ip":"198.51.100.99","c2_ip":"203.0.113.88","threat_classification":"PORT_SCAN_AND_C2_BEACON"}}\' '
            f'http://{target_ip}:8213/challenge'
        )
        chal_out = await docker_runner.execute_command(session_id, chal_cmd)
        assert "NIDS_INTRUSION_DETECTED" in chal_out
        assert info.has_action("nids_challenge_verified")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_blue_14_threat_hunting(docker_runner):
    """Room 14: Live LOLBIN process execution hunting, persistence tracing, and Sigma deployment."""
    session_id = "test_docker_blue_14_live"
    info = await docker_runner.start_session(session_id, "blue-14-threat-hunting", "op-tester-blue14")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Run hunt query tool to trace Word spawning PowerShell
        hunt_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/hunt_query.py --parent winword.exe"
        )
        assert "4820" in hunt_out
        assert "T1059.001" in hunt_out
        assert "NOENTRY{" not in hunt_out

        # 2. Run hunt query tool to trace scheduled task persistence
        task_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/hunt_query.py --persistence"
        )
        assert "TelemetrySync" in task_out
        assert "NOENTRY{" not in task_out

        # 3. Query telemetry on target container
        telem_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8214/api/hunt/telemetry"
        )
        assert "4820" in telem_out
        assert "NOENTRY{" not in telem_out

        # 4. Verify GET on challenge returns NO flag
        chal_get = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8214/challenge"
        )
        assert "NOENTRY{" not in chal_get

        # 5. Deploy Sigma hunting query (prerequisite)
        query_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"query_name":"SIGMA_OFFICE_SPAWNS_POWERSHELL","mitre_technique":"T1059.001","parent_process":"winword.exe","child_process":"powershell.exe"}}\' '
            f'http://{target_ip}:8214/api/hunt/queries'
        )
        query_out = await docker_runner.execute_command(session_id, query_cmd)
        assert "HUNT_SIGMA_QUERY_ACTIVE" in query_out
        assert info.has_action("hunt_query_deployed")

        # 6. Submit threat hunting challenge via POST
        chal_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"mitre_technique":"T1059.001","malicious_pid":4820,"persistence_mechanism":"SCHEDULED_TASK"}}\' '
            f'http://{target_ip}:8214/challenge'
        )
        chal_out = await docker_runner.execute_command(session_id, chal_cmd)
        assert "THREAT_HUNT_HYPOTHESIS_CONFIRMED" in chal_out
        assert info.has_action("hunt_challenge_verified")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_blue_15_incident_triage(docker_runner):
    """Room 15: Live alert queue triage, asset blast radius analysis, and incident escalation."""
    session_id = "test_docker_blue_15_live"
    info = await docker_runner.start_session(session_id, "blue-15-incident-triage", "op-tester-blue15")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Run triage tool to list active alerts
        list_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/triage_tool.py --list"
        )
        assert "ALT-8820" in list_out
        assert "NOENTRY{" not in list_out

        # 2. Run triage tool to investigate critical exfiltration alert
        alert_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/triage_tool.py --alert ALT-8820"
        )
        assert "svc_db_sync" in alert_out
        assert "198.51.100.77" in alert_out
        assert "NOENTRY{" not in alert_out

        # 3. Query triage evidence API on target container
        ev_out = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8215/api/triage/evidence"
        )
        assert "DB-PROD-01" in ev_out
        assert "NOENTRY{" not in ev_out

        # 4. Verify GET on challenge returns NO flag
        chal_get = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8215/challenge"
        )
        assert "NOENTRY{" not in chal_get

        # 5. Formally classify alert (prerequisite)
        classify_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"alert_id":"ALT-8820","classification":"TRUE_POSITIVE","severity":"CRITICAL","asset_id":"DB-PROD-01"}}\' '
            f'http://{target_ip}:8215/api/triage/classify'
        )
        classify_out = await docker_runner.execute_command(session_id, classify_cmd)
        assert "TRIAGE_ALERT_CLASSIFIED_CRITICAL" in classify_out
        assert info.has_action("triage_alert_classified")

        # 6. Submit incident escalation challenge via POST
        chal_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"incident_type":"DATA_EXFILTRATION","compromised_account":"svc_db_sync","egress_ip":"198.51.100.77","exfil_volume_mb":2400}}\' '
            f'http://{target_ip}:8215/challenge'
        )
        chal_out = await docker_runner.execute_command(session_id, chal_cmd)
        assert "INCIDENT_TRIAGE_ESCALATION_VALIDATED" in chal_out
        assert info.has_action("triage_challenge_verified")

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_docker_room_blue_16_incident_response(docker_runner):
    """Room 16: Live containment, RAM evidence preservation, threat eradication, and lifecycle completion."""
    session_id = "test_docker_blue_16_live"
    info = await docker_runner.start_session(session_id, "blue-16-incident-response", "op-tester-blue16")
    assert info.status == "RUNNING"
    assert info.runner_mode == "docker"
    target_ip = info.target_ip

    try:
        # 1. Run IR manager tool to inspect incident status
        status_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/ir_manager.py --status"
        )
        assert "IR-2026-088" in status_out
        assert "DB-PROD-01" in status_out
        assert "3912" in status_out
        assert "NOENTRY{" not in status_out

        # 2. Run IR manager tool to inspect preserved evidence
        ev_out = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/ir_manager.py --evidence"
        )
        assert "WinPmem" in ev_out
        assert "7a35b1d9" in ev_out
        assert "NOENTRY{" not in ev_out

        # 3. Query incident status API on target container
        api_status = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8216/api/response/incident-status"
        )
        assert "IR-2026-088" in api_status
        assert "NOENTRY{" not in api_status

        # 4. Verify GET on challenge returns NO flag
        chal_get = await docker_runner.execute_command(
            session_id,
            f"curl -s http://{target_ip}:8216/challenge"
        )
        assert "NOENTRY{" not in chal_get

        # 5. Enforce rapid containment (prerequisite 1)
        contain_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"isolate_host":true,"revoke_tokens":true,"target_host":"DB-PROD-01"}}\' '
            f'http://{target_ip}:8216/api/response/contain'
        )
        contain_out = await docker_runner.execute_command(session_id, contain_cmd)
        assert "RESPONSE_CONTAINMENT_ENFORCED" in contain_out
        assert info.has_action("response_containment_enforced")

        # 6. Execute threat eradication (prerequisite 2)
        eradicate_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"terminate_pid":3912,"remove_service":"svc_winupdater","block_egress_ip":"198.51.100.77"}}\' '
            f'http://{target_ip}:8216/api/response/eradicate'
        )
        eradicate_out = await docker_runner.execute_command(session_id, eradicate_cmd)
        assert "RESPONSE_ERADICATION_COMPLETE" in eradicate_out
        assert info.has_action("response_eradication_complete")

        # 7. Submit incident response lifecycle verification via POST
        chal_cmd = (
            f'curl -s -X POST -H "Content-Type: application/json" '
            f'-d \'{{"incident_id":"IR-2026-088","lifecycle_standard":"NIST_SP_800_61","containment_verified":true,"eradication_verified":true}}\' '
            f'http://{target_ip}:8216/challenge'
        )
        chal_out = await docker_runner.execute_command(session_id, chal_cmd)
        assert "INCIDENT_RESPONSE_LIFECYCLE_VERIFIED" in chal_out
        assert info.has_action("response_challenge_verified")

    finally:
        await docker_runner.stop_session(session_id)

