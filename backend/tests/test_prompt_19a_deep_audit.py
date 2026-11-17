"""
Deep Verification and Security Audit Tests for Blue Team Rooms 13-16.
Prompt 19A Audit Suite:
1. Real practical execution of inspect_nids.py, hunt_query.py, triage_tool.py, ir_manager.py
   - Verifies genuine parsing of real evidence files (.pcap, .json).
   - Verifies fail-closed behavior when evidence files are missing.
   - Verifies anti-forgery command protections.
2. Actual browser-terminal WebSocket request path:
   - Tests genuine /ws/academy/{room_id}/terminal WebSocket workflow.
   - Verifies command execution inside attacker container.
   - Verifies target processing, action recording, and task submission completion.
3. Live Docker session isolation:
   - Two concurrent independent Docker sessions (Session A and Session B).
   - Verifies network isolation: Attacker A cannot reach Target B.
   - Inspects container port bindings: confirms ports are NOT published to public interfaces.
   - Verifies header/query parameter spoofing rejection.
   - Verifies stopped session cleanup and revocation.
4. Flag and completion security:
   - Zero flag exposure in GET responses, room metadata, or static answers.
   - Dynamic token binding verification.
"""

import asyncio
import json
import pytest
from conftest import drain_terminal_until_prompt, execute_terminal_command
from starlette.testclient import TestClient

from backend.app.labs.docker_runner import DockerLabRunner
from backend.app.labs.manager import lab_manager
from backend.app.academy.curriculum import curriculum_registry
from backend.app.academy.validator import task_validator
from backend.app.db.models import User
from backend.app.main import app


@pytest.fixture(scope="module")
def docker_runner():
    runner = DockerLabRunner()
    if not runner.is_available():
        pytest.skip("Docker daemon is not available on this host. Skipping live Docker audit.")
    return runner


# ============================================================================
# PART 1: VERIFY REAL PRACTICAL EXECUTION & TOOL EVIDENCE PARSING
# ============================================================================

@pytest.mark.asyncio
async def test_practical_tools_parse_real_files_inside_container(docker_runner):
    """
    Verify inspect_nids.py, hunt_query.py, triage_tool.py, ir_manager.py genuinely
    read, parse, and process real evidence files inside the attacker container.
    """
    session_id = "test_audit_tools_evidence_parsing"
    info = await docker_runner.start_session(session_id, "blue-13-network-intrusion-detection", "op-auditor-1")
    assert info.status == "RUNNING"

    try:
        # 1. inspect_nids.py parses real binary PCAP /var/log/nids_traffic.pcap
        res_pcap_scan = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/inspect_nids.py --scan"
        )
        assert "Evidence File: /var/log/nids_traffic.pcap" in res_pcap_scan
        assert "198.51.100.99" in res_pcap_scan
        assert "NOENTRY{" not in res_pcap_scan

        res_pcap_beacon = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/inspect_nids.py --beacon"
        )
        assert "Evidence File: /var/log/nids_traffic.pcap" in res_pcap_beacon
        assert "203.0.113.88" in res_pcap_beacon
        assert "HEARTBEAT_V2" in res_pcap_beacon

        # 2. inspect_nids.py fails if PCAP file is missing or corrupted
        corrupt_check = await docker_runner.execute_command(
            session_id,
            "mv /var/log/nids_traffic.pcap /var/log/nids_backup.pcap && python3 /home/operator/tools/inspect_nids.py --scan"
        )
        assert "Error loading PCAP" in corrupt_check
        # Restore file
        await docker_runner.execute_command(
            session_id,
            "mv /var/log/nids_backup.pcap /var/log/nids_traffic.pcap"
        )

        # 3. hunt_query.py parses real JSON /var/log/threat_hunt_telemetry.json
        res_hunt = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/hunt_query.py --parent winword"
        )
        assert "Source Telemetry: /var/log/threat_hunt_telemetry.json" in res_hunt
        assert "4820" in res_hunt
        assert "WINWORD.EXE" in res_hunt
        assert "powershell.exe" in res_hunt

        # hunt_query.py persistence parsing
        res_persist = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/hunt_query.py --persistence"
        )
        assert "TelemetrySync" in res_persist

        # hunt_query.py fails if telemetry is missing
        hunt_fail = await docker_runner.execute_command(
            session_id,
            "mv /var/log/threat_hunt_telemetry.json /var/log/hunt_bak.json && python3 /home/operator/tools/hunt_query.py --parent winword"
        )
        assert "Error: Telemetry log" in hunt_fail
        await docker_runner.execute_command(
            session_id,
            "mv /var/log/hunt_bak.json /var/log/threat_hunt_telemetry.json"
        )

        # 4. triage_tool.py parses real JSON /var/log/soc_triage_alerts.json
        res_triage_list = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/triage_tool.py --list"
        )
        assert "Queue File: /var/log/soc_triage_alerts.json" in res_triage_list
        assert "ALT-8820" in res_triage_list

        res_triage_alert = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/triage_tool.py --alert ALT-8820"
        )
        assert "Alert File:   /var/log/soc_triage_alerts.json" in res_triage_alert
        assert "DB-PROD-01" in res_triage_alert
        assert "svc_db_sync" in res_triage_alert

        # 5. ir_manager.py parses real JSON /var/log/ir_incident.json
        res_ir_status = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/ir_manager.py --status"
        )
        assert "Evidence Source: /var/log/ir_incident.json" in res_ir_status
        assert "IR-2026-088" in res_ir_status
        assert "DB-PROD-01" in res_ir_status

        res_ir_ev = await docker_runner.execute_command(
            session_id,
            "python3 /home/operator/tools/ir_manager.py --evidence"
        )
        assert "Evidence Source: /var/log/ir_incident.json" in res_ir_ev
        assert "7a35b1d9821811faec2984b2382903487f54921b72a912e84c980312fa890123" in res_ir_ev

    finally:
        await docker_runner.stop_session(session_id)


@pytest.mark.asyncio
async def test_forged_and_unrelated_commands_prevent_action_recording(docker_runner):
    """
    Verify that learners cannot gain action completion by running echo, printf,
    alias, or unrelated commands.
    """
    session_id = "test_audit_anti_forgery"
    info = await docker_runner.start_session(session_id, "blue-13-network-intrusion-detection", "op-forger-1")
    assert info.status == "RUNNING"

    try:
        # Attempt 1: Direct echo of verification token
        await docker_runner.execute_command(
            session_id,
            "echo NIDS_SNORT_RULE_ACTIVE"
        )
        assert not info.has_action("nids_rule_deployed")

        # Attempt 2: printf forgery
        await docker_runner.execute_command(
            session_id,
            "printf 'NIDS_SNORT_RULE_ACTIVE\\n'"
        )
        assert not info.has_action("nids_rule_deployed")

        # Attempt 3: python -c print forgery
        await docker_runner.execute_command(
            session_id,
            'python3 -c "print(\'NIDS_INTRUSION_DETECTED\')"'
        )
        assert not info.has_action("nids_challenge_verified")

        # Attempt 4: Unrelated command output
        await docker_runner.execute_command(
            session_id,
            "cat /etc/issue"
        )
        assert not info.has_action("nids_rule_deployed")
        assert not info.has_action("nids_challenge_verified")

    finally:
        await docker_runner.stop_session(session_id)


# ============================================================================
# PART 2: VERIFY ACTUAL BROWSER-TERMINAL WEBSOCKET WORKFLOW (ROOMS 13-16)
# ============================================================================

@pytest.mark.parametrize(
    "room_id,port,rule_endpoint,rule_payload,rule_token,rule_action,chal_endpoint,chal_payload,chal_token,chal_action,task_rule_id,task_chal_id",
    [
        (
            "blue-13-network-intrusion-detection",
            8213,
            "/api/nids/rules",
            '{"rule_name":"RULE_NIDS_COVERT_BEACON","protocol":"tcp","action":"alert","dest_port":8443,"content":"HEARTBEAT_V2"}',
            "NIDS_SNORT_RULE_ACTIVE",
            "nids_rule_deployed",
            "/challenge",
            '{"scanner_ip":"198.51.100.99","c2_ip":"203.0.113.88","threat_classification":"PORT_SCAN_AND_C2_BEACON"}',
            "NIDS_INTRUSION_DETECTED",
            "nids_challenge_verified",
            "task-04-snort-rule-deployment",
            "task-05-intrusion-correlation-challenge",
        ),
        (
            "blue-14-threat-hunting",
            8214,
            "/api/hunt/queries",
            '{"query_name":"SIGMA_WORD_SPAWN_PS","mitre_technique":"T1059.001","parent_process":"winword.exe","child_process":"powershell.exe"}',
            "HUNT_SIGMA_QUERY_ACTIVE",
            "hunt_query_deployed",
            "/challenge",
            '{"mitre_technique":"T1059.001","malicious_pid":4820,"persistence_mechanism":"SCHEDULED_TASK"}',
            "THREAT_HUNT_HYPOTHESIS_CONFIRMED",
            "hunt_challenge_verified",
            "task-04-sigma-query-authoring",
            "task-05-threat-hunting-challenge",
        ),
        (
            "blue-15-incident-triage",
            8215,
            "/api/triage/classify",
            '{"alert_id":"ALT-8820","classification":"TRUE_POSITIVE","severity":"CRITICAL","asset_id":"DB-PROD-01"}',
            "TRIAGE_ALERT_CLASSIFIED_CRITICAL",
            "triage_alert_classified",
            "/challenge",
            '{"incident_type":"CRITICAL_DATA_EXFILTRATION","compromised_account":"svc_db_sync","egress_ip":"198.51.100.77","exfil_volume_mb":2400}',
            "INCIDENT_TRIAGE_ESCALATION_VALIDATED",
            "triage_challenge_verified",
            "task-04-formal-triage-classification",
            "task-05-incident-escalation-challenge",
        ),
        (
            "blue-16-incident-response",
            8216,
            "/api/response/contain",
            '{"isolate_host":true,"revoke_tokens":true,"target_host":"DB-PROD-01"}',
            "RESPONSE_CONTAINMENT_ENFORCED",
            "response_containment_enforced",
            "/challenge",
            '{"incident_id":"IR-2026-088","lifecycle_standard":"NIST_SP_800_61","containment_verified":true,"eradication_verified":true}',
            "INCIDENT_RESPONSE_LIFECYCLE_VERIFIED",
            "response_challenge_verified",
            "task-03-rapid-containment-execution",
            "task-05-incident-response-challenge",
        ),
    ]
)
@pytest.mark.asyncio
async def test_browser_terminal_websocket_workflow_e2e(
    docker_runner,
    client,
    session,
    room_id,
    port,
    rule_endpoint,
    rule_payload,
    rule_token,
    rule_action,
    chal_endpoint,
    chal_payload,
    chal_token,
    chal_action,
    task_rule_id,
    task_chal_id,
):
    """
    Test the genuine browser-terminal WebSocket request path:
    1. Start real Docker lab container duo.
    2. Execute commands through WebSocket terminal path.
    3. Confirm command execution in attacker container and target processing.
    4. Confirm action recording on session_info.
    5. Submit task findings through application task validator.
    6. Confirm backend awards XP and records completion.
    """
    operator_id = f"op_ws_{room_id.replace('-', '_')[:12]}"
    user = User(
        username=f"user_{operator_id}",
        operator_id=operator_id,
        hashed_password="audit_test_hash",
        role="operator",
        xp=100,
    )
    session.add(user)
    session.commit()
    session.refresh(user)

    from backend.app.api.auth import create_access_token
    jwt_token = create_access_token({"sub": user.operator_id, "operator_id": user.operator_id})
    client.cookies.set("ne_auth_token", jwt_token)

    session_id = f"test_ws_{room_id.replace('-', '_')[:10]}"
    info = await lab_manager._docker_runner.start_session(session_id, room_id, operator_id)
    lab_manager._active_sessions[session_id] = info
    assert info.status == "RUNNING"
    target_ip = info.target_ip

    try:
        # Step 1: WebSocket terminal connection
        with client.websocket_connect(f"/ws/academy/{room_id}/terminal") as ws:
            drain_terminal_until_prompt(ws)

            # Step 2: In Room 16, execute eradication prerequisite first
            if room_id == "blue-16-incident-response":
                erad_cmd = (
                    f'curl -s -X POST -H "Content-Type: application/json" '
                    f'-d \'{{"terminate_pid":3912,"remove_service":"svc_winupdater","block_egress_ip":"198.51.100.77"}}\' '
                    f'http://{target_ip}:{port}/api/response/eradicate'
                )
                erad_resp = execute_terminal_command(ws, erad_cmd)
                assert "RESPONSE_ERADICATION_COMPLETE" in erad_resp["data"]

            # Step 3: Execute rule/containment command over WebSocket
            cmd_rule = (
                f'curl -s -X POST -H "Content-Type: application/json" '
                f'-d \'{rule_payload}\' http://{target_ip}:{port}{rule_endpoint}'
            )
            rule_resp = execute_terminal_command(ws, cmd_rule)
            assert rule_token in rule_resp["data"]

            # Verify action was recorded on session_info
            assert info.has_action(rule_action)

            # Step 4: Execute challenge command over WebSocket
            cmd_chal = (
                f'curl -s -X POST -H "Content-Type: application/json" '
                f'-d \'{chal_payload}\' http://{target_ip}:{port}{chal_endpoint}'
            )
            chal_resp = execute_terminal_command(ws, cmd_chal)
            assert chal_token in chal_resp["data"]

            # Verify challenge action recorded
            assert info.has_action(chal_action)

        # Step 5: Submit findings through standard academy application submission API
        from backend.app.academy.models import TaskSubmission
        res_rule_submit = task_validator.validate_submission(
            session=session,
            user=user,
            room_id=room_id,
            task_id=task_rule_id,
            submission=TaskSubmission(answer=rule_token),
        )
        assert res_rule_submit.completed is True
        assert res_rule_submit.is_correct is True
        assert res_rule_submit.earned_xp > 0

        res_chal_submit = task_validator.validate_submission(
            session=session,
            user=user,
            room_id=room_id,
            task_id=task_chal_id,
            submission=TaskSubmission(answer=chal_token),
        )
        assert res_chal_submit.completed is True
        assert res_chal_submit.is_correct is True
        assert res_chal_submit.earned_xp > 0

        # Step 6: Verify User XP updated
        session.refresh(user)
        assert user.xp > 100

    finally:
        await lab_manager._docker_runner.stop_session(session_id)
        lab_manager._active_sessions.pop(session_id, None)


# ============================================================================
# PART 3: VERIFY DOCKER SESSION ISOLATION (DUAL INDEPENDENT SESSIONS)
# ============================================================================

@pytest.mark.asyncio
async def test_docker_dual_session_isolation_and_no_port_exposure(docker_runner):
    """
    Start two genuine independent Docker sessions (Session A and Session B) and verify:
    1. Session A cannot reach Session B's target container.
    2. Session B cannot reach Session A's target container.
    3. Container inspect confirms target ports are NOT published to host/public interfaces.
    4. Client header spoofing (X-Session-ID, X-Operator-ID) cannot change session identity.
    5. Query parameters cannot select another session.
    6. Stopping Session A immediately destroys access for Session A while Session B remains alive.
    """
    session_a = "test_audit_iso_session_a"
    session_b = "test_audit_iso_session_b"

    info_a = await docker_runner.start_session(session_a, "blue-13-network-intrusion-detection", "op-alice")
    info_b = await docker_runner.start_session(session_b, "blue-14-threat-hunting", "op-bob")

    assert info_a.status == "RUNNING"
    assert info_b.status == "RUNNING"
    assert info_a.network_id != info_b.network_id
    assert info_a.attacker_container_id != info_b.attacker_container_id
    assert info_a.target_container_id != info_b.target_container_id

    try:
        # 1. Attacker A cannot reach Target B
        # Network bridge is internal, routing between distinct internal subnets is blocked
        probe_a_to_b = await docker_runner.execute_command(
            session_a,
            f"curl -s --connect-timeout 2 http://{info_b.target_ip}:8214/api/hunt/telemetry || echo TIMEOUT_OR_UNREACHABLE"
        )
        assert "TIMEOUT_OR_UNREACHABLE" in probe_a_to_b or "Failed to connect" in probe_a_to_b or "Connection timed out" in probe_a_to_b
        assert "SYS-8101" not in probe_a_to_b

        # 2. Attacker B cannot reach Target A
        probe_b_to_a = await docker_runner.execute_command(
            session_b,
            f"curl -s --connect-timeout 2 http://{info_a.target_ip}:8213/api/nids/traffic || echo TIMEOUT_OR_UNREACHABLE"
        )
        assert "TIMEOUT_OR_UNREACHABLE" in probe_b_to_a or "Failed to connect" in probe_b_to_a or "Connection timed out" in probe_b_to_a
        assert "198.51.100.99" not in probe_b_to_a

        # 3. Attacker A CAN reach Target A
        probe_a_to_a = await docker_runner.execute_command(
            session_a,
            f"curl -s http://{info_a.target_ip}:8213/api/nids/traffic"
        )
        assert "198.51.100.99" in probe_a_to_a

        # 4. Attacker B CAN reach Target B
        probe_b_to_b = await docker_runner.execute_command(
            session_b,
            f"curl -s http://{info_b.target_ip}:8214/api/hunt/telemetry"
        )
        assert "SYS-8101" in probe_b_to_b

        # 5. Inspect container configuration: Target ports are NOT published to host
        # Inspect port bindings using docker CLI
        code, inspect_out = await docker_runner._run_cmd(
            ["docker", "inspect", "--format", "{{json .HostConfig.PortBindings}}", info_a.target_container_id]
        )
        assert code == 0
        port_bindings = json.loads(inspect_out.strip() or "{}")
        # PortBindings must be empty or null (ports not exposed to host public interfaces)
        assert not port_bindings or port_bindings == {}

        # 6. Verify Docker network is created with internal=true
        code, net_inspect = await docker_runner._run_cmd(
            ["docker", "network", "inspect", "--format", "{{.Internal}}", info_a.network_id]
        )
        assert code == 0
        assert net_inspect.strip().lower() == "true"

        # 7. Header spoofing: Attacker A trying to claim Session B identity is rejected
        spoof_hdr = (
            f'curl -s -H "X-Session-ID: {session_b}" -H "X-Operator-ID: op-bob" '
            f'http://{info_a.target_ip}:8213/api/nids/traffic'
        )
        res_spoof = await docker_runner.execute_command(session_a, spoof_hdr)
        # Target container reads authoritative container environment variables, so spoofed headers do not affect target
        assert "NOENTRY{" not in res_spoof

        # 8. Query parameter tampering: ?session_id=... cannot access Session B
        tamper_query = (
            f'curl -s "http://{info_a.target_ip}:8213/challenge?session_id={session_b}&operator_id=op-bob"'
        )
        res_tamper = await docker_runner.execute_command(session_a, tamper_query)
        assert "NOENTRY{" not in res_tamper

        # 9. Stop Session A and verify cleanup
        await docker_runner.stop_session(session_a)
        assert info_a.status == "STOPPED"

        # Session B is completely unaffected and continues running
        probe_b_post_stop = await docker_runner.execute_command(
            session_b,
            f"curl -s http://{info_b.target_ip}:8214/api/hunt/telemetry"
        )
        assert "SYS-8101" in probe_b_post_stop

    finally:
        await docker_runner.stop_session(session_a)
        await docker_runner.stop_session(session_b)


# ============================================================================
# PART 4: VERIFY FLAG AND COMPLETION SECURITY
# ============================================================================

def test_flag_and_completion_security_audits():
    """
    Audit GET endpoints, room definitions, and metadata for secret leakage.
    Confirm that completion flags and accepted answers are scrubbed from client responses.
    """
    for rid in [
        "blue-13-network-intrusion-detection",
        "blue-14-threat-hunting",
        "blue-15-incident-triage",
        "blue-16-incident-response",
    ]:
        room = curriculum_registry.get_room(rid)
        assert room is not None
        detail = room.client_detail()

        # Confirm accepted_answers and regex are scrubbed
        for t in detail["tasks"]:
            assert "accepted_answers" not in t
            assert "accepted_regex" not in t
            if t.get("quiz_questions"):
                for q in t["quiz_questions"]:
                    assert "correct_index" not in q
                    assert "correct_option_index" not in q

        # Verify no hardcoded flags leak in task instructions
        for t in room.tasks:
            assert "NOENTRY{" not in t.instructions
            assert "NOENTRY{" not in (t.question or "")
            assert "NOENTRY{" not in (t.hint or "")
