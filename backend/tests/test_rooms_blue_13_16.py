"""
Comprehensive unit, security, workflow, and flag-leakage tests for
Blue Team Rooms 13–16:
- Room 13: Network Intrusion Detection (blue-13-network-intrusion-detection)
- Room 14: Threat Hunting (blue-14-threat-hunting)
- Room 15: Incident Triage (blue-15-incident-triage)
- Room 16: Incident Response (blue-16-incident-response)
"""

import time
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from backend.app.academy.curriculum import curriculum_registry
from backend.app.academy.models import TaskSubmission, TaskType, TrackEnum
from backend.app.academy.validator import TaskValidator
from backend.app.db.models import User
from backend.app.labs.base import generate_trusted_session_signature
from backend.app.labs.manager import lab_manager
from backend.app.labs.process_runner import ProcessLabRunner
from labs.red_room_09_sqli.target.app import (
    get_hunt_state,
    get_nids_state,
    get_response_state,
    get_triage_state,
    incident_response_app,
    nids_app,
    reset_target_in_memory_states,
    threat_hunt_app,
    triage_app,
)


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture
def test_users(db_session):
    u1 = User(
        username="learner_alpha",
        operator_id="OP-ALPHA-1316",
        email="alpha@noentry.local",
        hashed_password="pw",
        role="student",
        xp=0,
    )
    u2 = User(
        username="learner_beta",
        operator_id="OP-BETA-1316",
        email="beta@noentry.local",
        hashed_password="pw",
        role="student",
        xp=0,
    )
    db_session.add(u1)
    db_session.add(u2)
    db_session.commit()
    db_session.refresh(u1)
    db_session.refresh(u2)
    return u1, u2


# ============================================================================
# 1. CURRICULUM REGISTRATION & METADATA TESTS
# ============================================================================

def test_blue_rooms_13_16_curriculum_registration():
    rooms = [
        ("blue-13-network-intrusion-detection", 13, "Network Intrusion Detection"),
        ("blue-14-threat-hunting", 14, "Threat Hunting"),
        ("blue-15-incident-triage", 15, "Incident Triage"),
        ("blue-16-incident-response", 16, "Incident Response"),
    ]
    for r_id, num, title in rooms:
        room = curriculum_registry.get_room(r_id)
        assert room is not None, f"Room {r_id} not registered"
        assert room.room_number == num
        assert room.track == TrackEnum.BLUE
        assert room.title == title
        assert len(room.tasks) == 6, f"Room {r_id} must have exactly 6 tasks"
        assert room.total_xp == 350, f"Room {r_id} total XP must be 350"
        assert room.tasks[-1].task_type == TaskType.QUIZ
        assert len(room.tasks[-1].quiz_questions) == 5


# ============================================================================
# 2. ROOM-SPECIFIC PRACTICAL TASKS & PREREQUISITES
# ============================================================================

@pytest.mark.asyncio
async def test_room_blue_13_nids_workflow(db_session, test_users):
    u1, _ = test_users
    validator = TaskValidator()
    runner = ProcessLabRunner()
    reset_target_in_memory_states()

    info = await runner.start_session("sess-test-13", "blue-13-network-intrusion-detection", u1.operator_id)
    lab_manager._active_sessions[info.session_id] = info
    try:
        # Task 1: Architecture
        res1 = validator.validate_submission(
            db_session, u1, "blue-13-network-intrusion-detection",
            "task-01-nids-architecture-dissection",
            TaskSubmission(answer="Passive Mode"),
        )
        assert res1.is_correct is True
        assert res1.earned_xp == 50

        # Task 2: Reconnaissance source IP
        res2 = validator.validate_submission(
            db_session, u1, "blue-13-network-intrusion-detection",
            "task-02-nids-reconnaissance-investigation",
            TaskSubmission(answer="198.51.100.99"),
        )
        assert res2.is_correct is True
        assert res2.earned_xp == 60

        # Task 3: Covert C2 beacon IP
        res3 = validator.validate_submission(
            db_session, u1, "blue-13-network-intrusion-detection",
            "task-03-covert-beacon-detection",
            TaskSubmission(answer="203.0.113.88"),
        )
        assert res3.is_correct is True
        assert res3.earned_xp == 70

        # Task 5 before rule deployment should fail (prerequisite not met)
        res5_fail = validator.validate_submission(
            db_session, u1, "blue-13-network-intrusion-detection",
            "task-05-intrusion-correlation-challenge",
            TaskSubmission(answer="NIDS_INTRUSION_DETECTED"),
        )
        assert res5_fail.is_correct is False

        # Task 4: Deploy Snort Rule via curl
        curl_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"rule_name":"RULE_NIDS_COVERT_BEACON","protocol":"tcp","action":"alert","dest_port":8443,"content":"HEARTBEAT_V2"}\' '
            'http://10.10.14.90:8213/api/nids/rules'
        )
        out4 = await runner.execute_command(info.session_id, curl_cmd)
        assert "NIDS_SNORT_RULE_ACTIVE" in out4
        assert info.has_action("nids_rule_deployed")

        res4 = validator.validate_submission(
            db_session, u1, "blue-13-network-intrusion-detection",
            "task-04-snort-rule-deployment",
            TaskSubmission(answer="NIDS_SNORT_RULE_ACTIVE"),
        )
        assert res4.is_correct is True

        # Now execute Task 5 Challenge via curl
        curl_chal = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"scanner_ip":"198.51.100.99","c2_ip":"203.0.113.88","threat_classification":"PORT_SCAN_AND_C2_BEACON"}\' '
            'http://10.10.14.90:8213/challenge'
        )
        out5 = await runner.execute_command(info.session_id, curl_chal)
        assert "NIDS_INTRUSION_DETECTED" in out5
        assert info.has_action("nids_challenge_verified")

        res5 = validator.validate_submission(
            db_session, u1, "blue-13-network-intrusion-detection",
            "task-05-intrusion-correlation-challenge",
            TaskSubmission(answer="NIDS_INTRUSION_DETECTED"),
        )
        assert res5.is_correct is True

        # Task 6: Quiz
        res6 = validator.validate_submission(
            db_session, u1, "blue-13-network-intrusion-detection",
            "task-06-nids-quiz",
            TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0}),
        )
        assert res6.is_correct is True
        assert res6.room_completed is True
        assert u1.xp == 350
    finally:
        await runner.stop_session(info.session_id)


@pytest.mark.asyncio
async def test_room_blue_14_threat_hunting_workflow(db_session, test_users):
    u1, _ = test_users
    validator = TaskValidator()
    runner = ProcessLabRunner()
    reset_target_in_memory_states()

    info = await runner.start_session("sess-test-14", "blue-14-threat-hunting", u1.operator_id)
    lab_manager._active_sessions[info.session_id] = info
    try:
        # Task 1: Methodology / MITRE code
        res1 = validator.validate_submission(
            db_session, u1, "blue-14-threat-hunting",
            "task-01-threat-hunting-methodology",
            TaskSubmission(answer="T1059.001"),
        )
        assert res1.is_correct is True
        assert res1.earned_xp == 50

        # Task 2: Suspicious Child PID
        res2 = validator.validate_submission(
            db_session, u1, "blue-14-threat-hunting",
            "task-02-hunting-process-lineage",
            TaskSubmission(answer="4820"),
        )
        assert res2.is_correct is True

        # Task 3: Scheduled Task Persistence
        res3 = validator.validate_submission(
            db_session, u1, "blue-14-threat-hunting",
            "task-03-hunting-persistence-artifacts",
            TaskSubmission(answer="TelemetrySync"),
        )
        assert res3.is_correct is True

        # Task 4: Author & Deploy Sigma Query
        curl_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"query_name":"SIGMA_OFFICE_SPAWNS_POWERSHELL","mitre_technique":"T1059.001","parent_process":"winword.exe","child_process":"powershell.exe"}\' '
            'http://10.10.14.90:8214/api/hunt/queries'
        )
        out4 = await runner.execute_command(info.session_id, curl_cmd)
        assert "HUNT_SIGMA_QUERY_ACTIVE" in out4
        assert info.has_action("hunt_query_deployed")

        res4 = validator.validate_submission(
            db_session, u1, "blue-14-threat-hunting",
            "task-04-sigma-query-authoring",
            TaskSubmission(answer="HUNT_SIGMA_QUERY_ACTIVE"),
        )
        assert res4.is_correct is True

        # Task 5: Challenge verification
        curl_chal = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"mitre_technique":"T1059.001","malicious_pid":4820,"persistence_mechanism":"SCHEDULED_TASK"}\' '
            'http://10.10.14.90:8214/challenge'
        )
        out5 = await runner.execute_command(info.session_id, curl_chal)
        assert "THREAT_HUNT_HYPOTHESIS_CONFIRMED" in out5
        assert info.has_action("hunt_challenge_verified")

        res5 = validator.validate_submission(
            db_session, u1, "blue-14-threat-hunting",
            "task-05-threat-hunting-challenge",
            TaskSubmission(answer="THREAT_HUNT_HYPOTHESIS_CONFIRMED"),
        )
        assert res5.is_correct is True

        # Task 6: Quiz
        res6 = validator.validate_submission(
            db_session, u1, "blue-14-threat-hunting",
            "task-06-threat-hunting-quiz",
            TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0}),
        )
        assert res6.is_correct is True
        assert res6.room_completed is True
        assert u1.xp == 350
    finally:
        await runner.stop_session(info.session_id)


@pytest.mark.asyncio
async def test_room_blue_15_incident_triage_workflow(db_session, test_users):
    u1, _ = test_users
    validator = TaskValidator()
    runner = ProcessLabRunner()
    reset_target_in_memory_states()

    info = await runner.start_session("sess-test-15", "blue-15-incident-triage", u1.operator_id)
    lab_manager._active_sessions[info.session_id] = info
    try:
        # Task 1: Classification
        res1 = validator.validate_submission(
            db_session, u1, "blue-15-incident-triage",
            "task-01-triage-severity-matrix",
            TaskSubmission(answer="True Positive"),
        )
        assert res1.is_correct is True

        # Task 2: Alert ID
        res2 = validator.validate_submission(
            db_session, u1, "blue-15-incident-triage",
            "task-02-distinguishing-positives",
            TaskSubmission(answer="ALT-8820"),
        )
        assert res2.is_correct is True

        # Task 3: Compromised Account
        res3 = validator.validate_submission(
            db_session, u1, "blue-15-incident-triage",
            "task-03-asset-blast-radius",
            TaskSubmission(answer="svc_db_sync"),
        )
        assert res3.is_correct is True

        # Task 4: Submit formal classification via curl
        curl_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"alert_id":"ALT-8820","classification":"TRUE_POSITIVE","severity":"CRITICAL","asset_id":"DB-PROD-01"}\' '
            'http://10.10.14.90:8215/api/triage/classify'
        )
        out4 = await runner.execute_command(info.session_id, curl_cmd)
        assert "TRIAGE_ALERT_CLASSIFIED_CRITICAL" in out4
        assert info.has_action("triage_alert_classified")

        res4 = validator.validate_submission(
            db_session, u1, "blue-15-incident-triage",
            "task-04-formal-triage-classification",
            TaskSubmission(answer="TRIAGE_ALERT_CLASSIFIED_CRITICAL"),
        )
        assert res4.is_correct is True

        # Task 5: Challenge verification
        curl_chal = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"incident_type":"DATA_EXFILTRATION","compromised_account":"svc_db_sync","egress_ip":"198.51.100.77","exfil_volume_mb":2400}\' '
            'http://10.10.14.90:8215/challenge'
        )
        out5 = await runner.execute_command(info.session_id, curl_chal)
        assert "INCIDENT_TRIAGE_ESCALATION_VALIDATED" in out5
        assert info.has_action("triage_challenge_verified")

        res5 = validator.validate_submission(
            db_session, u1, "blue-15-incident-triage",
            "task-05-incident-escalation-challenge",
            TaskSubmission(answer="INCIDENT_TRIAGE_ESCALATION_VALIDATED"),
        )
        assert res5.is_correct is True

        # Task 6: Quiz
        res6 = validator.validate_submission(
            db_session, u1, "blue-15-incident-triage",
            "task-06-incident-triage-quiz",
            TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0}),
        )
        assert res6.is_correct is True
        assert res6.room_completed is True
        assert u1.xp == 350
    finally:
        await runner.stop_session(info.session_id)


@pytest.mark.asyncio
async def test_room_blue_16_incident_response_workflow(db_session, test_users):
    u1, _ = test_users
    validator = TaskValidator()
    runner = ProcessLabRunner()
    reset_target_in_memory_states()

    info = await runner.start_session("sess-test-16", "blue-16-incident-response", u1.operator_id)
    lab_manager._active_sessions[info.session_id] = info
    try:
        # Task 1: Containment Phase
        res1 = validator.validate_submission(
            db_session, u1, "blue-16-incident-response",
            "task-01-ir-lifecycle-frameworks",
            TaskSubmission(answer="Containment"),
        )
        assert res1.is_correct is True

        # Task 2: Volatile RAM
        res2 = validator.validate_submission(
            db_session, u1, "blue-16-incident-response",
            "task-02-order-of-volatility",
            TaskSubmission(answer="RAM"),
        )
        assert res2.is_correct is True

        # Task 3: Enforce Containment
        curl_cmd3 = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"isolate_host":true,"revoke_tokens":true,"target_host":"DB-PROD-01"}\' '
            'http://10.10.14.90:8216/api/response/contain'
        )
        out3 = await runner.execute_command(info.session_id, curl_cmd3)
        assert "RESPONSE_CONTAINMENT_ENFORCED" in out3
        assert info.has_action("response_containment_enforced")

        res3 = validator.validate_submission(
            db_session, u1, "blue-16-incident-response",
            "task-03-rapid-containment-execution",
            TaskSubmission(answer="RESPONSE_CONTAINMENT_ENFORCED"),
        )
        assert res3.is_correct is True

        # Task 4: Threat Eradication
        curl_cmd4 = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"terminate_pid":3912,"remove_service":"svc_winupdater","block_egress_ip":"198.51.100.77"}\' '
            'http://10.10.14.90:8216/api/response/eradicate'
        )
        out4 = await runner.execute_command(info.session_id, curl_cmd4)
        assert "RESPONSE_ERADICATION_COMPLETE" in out4
        assert info.has_action("response_eradication_complete")

        res4 = validator.validate_submission(
            db_session, u1, "blue-16-incident-response",
            "task-04-threat-eradication-execution",
            TaskSubmission(answer="RESPONSE_ERADICATION_COMPLETE"),
        )
        assert res4.is_correct is True

        # Task 5: Challenge verification
        curl_chal = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"incident_id":"IR-2026-088","lifecycle_standard":"NIST_SP_800_61","containment_verified":true,"eradication_verified":true}\' '
            'http://10.10.14.90:8216/challenge'
        )
        out5 = await runner.execute_command(info.session_id, curl_chal)
        assert "INCIDENT_RESPONSE_LIFECYCLE_VERIFIED" in out5
        assert info.has_action("response_challenge_verified")

        res5 = validator.validate_submission(
            db_session, u1, "blue-16-incident-response",
            "task-05-incident-response-challenge",
            TaskSubmission(answer="INCIDENT_RESPONSE_LIFECYCLE_VERIFIED"),
        )
        assert res5.is_correct is True

        # Task 6: Quiz
        res6 = validator.validate_submission(
            db_session, u1, "blue-16-incident-response",
            "task-06-incident-response-quiz",
            TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0}),
        )
        assert res6.is_correct is True
        assert res6.room_completed is True
        assert u1.xp == 350
    finally:
        await runner.stop_session(info.session_id)


# ============================================================================
# 3. FLAG LEAKAGE AUDIT (NO FLAGS EXPOSED ON GET OR METADATA)
# ============================================================================

def test_no_flag_leakage_on_get_endpoints():
    test_apps = [
        (nids_app, ["/", "/api/nids/traffic", "/api/nids/alerts", "/challenge"]),
        (threat_hunt_app, ["/", "/api/hunt/telemetry", "/api/hunt/persistence", "/api/hunt/hypotheses", "/challenge"]),
        (triage_app, ["/", "/api/triage/alerts", "/api/triage/evidence", "/api/triage/assets", "/challenge"]),
        (incident_response_app, ["/", "/api/response/incident-status", "/api/response/evidence", "/challenge"]),
    ]
    for app, endpoints in test_apps:
        client = TestClient(app)
        for ep in endpoints:
            resp = client.get(ep)
            assert "NOENTRY{" not in resp.text, f"GET {ep} leaked flag prefix NOENTRY{{"
            assert "VERIFIED-" not in resp.text, f"GET {ep} leaked dynamic session token VERIFIED-"


# ============================================================================
# 4. BROWSER-TERMINAL REQUEST PATH SECURITY TESTS (ALL 7 VECTORS)
# ============================================================================

def test_security_vector_1_cross_user_target_isolation():
    """Learner A cannot access or modify Learner B's target state."""
    reset_target_in_memory_states()
    state_a = get_nids_state("sess_a")
    state_b = get_nids_state("sess_b")

    state_a["rule_deployed"] = True
    assert state_b["rule_deployed"] is False, "State mutation in sess_a leaked into sess_b"


def test_security_vector_2_header_spoofing_rejected():
    """Learner A cannot impersonate Learner B by changing HTTP headers."""
    client = TestClient(nids_app)
    sess_b = "sess_victim_beta"
    op_b = "OP-BETA"
    exp = int(time.time()) + 3600
    valid_sig = generate_trusted_session_signature(sess_b, op_b, exp)

    # Learner A sends request claiming to be victim B in X-Session-ID, but without valid signature
    headers = {
        "X-Session-ID": sess_b,
        "X-Operator-ID": op_b,
    }
    resp = client.post("/challenge", headers=headers, json={"scanner_ip": "198.51.100.99"})
    assert resp.status_code == 401
    assert resp.json()["status"] == "UNAUTHORIZED"

    # Mismatched X-Session-ID vs signature session fails 403
    mismatched_headers = {
        "X-Lab-Auth-Signature": valid_sig,
        "X-Lab-Session-ID": sess_b,
        "X-Lab-Operator-ID": op_b,
        "X-Lab-Expires-At": str(exp),
        "X-Session-ID": "sess_attacker_alpha",  # Tampered header
    }
    resp2 = client.post("/challenge", headers=mismatched_headers, json={"scanner_ip": "198.51.100.99"})
    assert resp2.status_code == 403
    assert resp2.json()["error"] == "IMPERSONATION_DETECTED"


def test_security_vector_3_query_string_identity_manipulation_rejected():
    """Query-string identity manipulation is rejected."""
    client = TestClient(threat_hunt_app)
    sess_b = "sess_target_b"
    op_b = "OP-TARGET-B"
    exp = int(time.time()) + 3600
    valid_sig = generate_trusted_session_signature(sess_b, op_b, exp)

    # Learner passes spoofed operator in query param
    auth_headers = {
        "X-Lab-Auth-Signature": valid_sig,
        "X-Lab-Session-ID": sess_b,
        "X-Lab-Operator-ID": op_b,
        "X-Lab-Expires-At": str(exp),
    }
    resp = client.post(
        "/challenge?operator_id=OP-ATTACKER-EVIL",
        headers=auth_headers,
        json={"mitre_technique": "T1059.001", "malicious_pid": 4820, "persistence_mechanism": "SCHEDULED_TASK"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"] == "IMPERSONATION_DETECTED"


def test_security_vector_4_missing_or_invalid_credentials_fail_closed():
    """Missing or invalid session credentials fail closed with 401."""
    client = TestClient(triage_app)
    # No auth headers
    resp1 = client.post("/challenge", json={"incident_type": "DATA_EXFILTRATION"})
    assert resp1.status_code == 401
    assert resp1.json()["error"] == "AUTH_REQUIRED"

    # Invalid signature
    bad_headers = {
        "X-Lab-Auth-Signature": "forged_or_corrupt_signature",
        "X-Lab-Session-ID": "sess_x",
        "X-Lab-Operator-ID": "OP-X",
        "X-Lab-Expires-At": str(int(time.time()) + 3600),
    }
    resp2 = client.post("/challenge", headers=bad_headers, json={"incident_type": "DATA_EXFILTRATION"})
    assert resp2.status_code == 401
    assert resp2.json()["error"] == "INVALID_OR_EXPIRED_CREDENTIALS"


def test_security_vector_5_stopped_or_expired_session_fails():
    """Stopped or expired session cannot continue using target."""
    client = TestClient(incident_response_app)
    sess_id = "sess_expired_01"
    op_id = "OP-EXPIRED"
    past_exp = int(time.time()) - 300  # 5 minutes in the past
    expired_sig = generate_trusted_session_signature(sess_id, op_id, past_exp)

    headers = {
        "X-Lab-Auth-Signature": expired_sig,
        "X-Lab-Session-ID": sess_id,
        "X-Lab-Operator-ID": op_id,
        "X-Lab-Expires-At": str(past_exp),
    }
    resp = client.post(
        "/api/response/contain",
        headers=headers,
        json={"isolate_host": True, "revoke_tokens": True, "target_host": "DB-PROD-01"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"] == "INVALID_OR_EXPIRED_CREDENTIALS"


@pytest.mark.asyncio
async def test_security_vector_6_valid_activity_cross_session_isolation(db_session, test_users):
    """Valid activity in Session A cannot satisfy Session B's room requirements."""
    u_a, u_b = test_users
    validator = TaskValidator()
    runner = ProcessLabRunner()
    reset_target_in_memory_states()

    info_a = await runner.start_session("sess-iso-13a", "blue-13-network-intrusion-detection", u_a.operator_id)
    info_b = await runner.start_session("sess-iso-13b", "blue-13-network-intrusion-detection", u_b.operator_id)
    lab_manager._active_sessions[info_a.session_id] = info_a
    lab_manager._active_sessions[info_b.session_id] = info_b
    try:
        # Learner A deploys rule and verifies intrusion
        cmd_rule = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"rule_name":"RULE_NIDS_COVERT_BEACON","protocol":"tcp","action":"alert","dest_port":8443,"content":"HEARTBEAT_V2"}\' '
            'http://10.10.14.90:8213/api/nids/rules'
        )
        await runner.execute_command(info_a.session_id, cmd_rule)
        cmd_chal = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"scanner_ip":"198.51.100.99","c2_ip":"203.0.113.88","threat_classification":"PORT_SCAN_AND_C2_BEACON"}\' '
            'http://10.10.14.90:8213/challenge'
        )
        await runner.execute_command(info_a.session_id, cmd_chal)

        assert info_a.has_action("nids_challenge_verified")
        assert not info_b.has_action("nids_challenge_verified")

        # Learner B tries to submit Task 5 without doing the work
        res_b = validator.validate_submission(
            db_session, u_b, "blue-13-network-intrusion-detection",
            "task-05-intrusion-correlation-challenge",
            TaskSubmission(answer="NIDS_INTRUSION_DETECTED"),
        )
        assert res_b.is_correct is False
        assert "Investigation incomplete" in res_b.feedback
    finally:
        await runner.stop_session(info_a.session_id)
        await runner.stop_session(info_b.session_id)


@pytest.mark.asyncio
async def test_security_vector_7_command_forgery_rejected(db_session, test_users):
    """Command forgery and manual echo of tokens rejected."""
    u1, _ = test_users
    runner = ProcessLabRunner()
    reset_target_in_memory_states()

    info = await runner.start_session("sess-forge-15", "blue-15-incident-triage", u1.operator_id)
    lab_manager._active_sessions[info.session_id] = info
    try:
        # Learner tries to forge action by echoing token
        forge_cmd = 'echo "INCIDENT_TRIAGE_ESCALATION_VALIDATED"'
        out = await runner.execute_command(info.session_id, forge_cmd)
        assert not info.has_action("triage_challenge_verified")
    finally:
        await runner.stop_session(info.session_id)
