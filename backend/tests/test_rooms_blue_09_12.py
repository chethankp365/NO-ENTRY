"""
Unit, Process, and Security Verification Tests for Blue Team Rooms 09–12:
- Room 09: Brute-Force Detection (blue-09-bruteforce-detection)
- Room 10: Malware Behaviour Analysis (blue-10-malware-behaviour-analysis)
- Room 11: Phishing Investigation (blue-11-phishing-investigation)
- Room 12: Endpoint Detection (blue-12-endpoint-detection)
"""

import pytest
from sqlmodel import Session, select

from backend.app.academy.curriculum import curriculum_registry
from backend.app.academy.models import RoomStatus, TaskSubmission, TrackEnum
from backend.app.academy.validator import task_validator
from backend.app.db.models import User
from backend.app.labs.base import LabSessionInfo
from backend.app.labs.manager import lab_manager
from backend.app.labs.process_runner import ProcessLabRunner


@pytest.fixture
def test_user(session: Session):
    user = User(
        operator_id="op-blue-09-12",
        username="op_blue_09_12_tester",
        hashed_password="",
        role="operator",
        xp=0,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def test_blue_rooms_09_12_curriculum_registration():
    """Verify that Rooms 09–12 are registered with 6 tasks and 350 XP each."""
    expected_rooms = [
        ("blue-09-bruteforce-detection", 9, "Brute-Force Detection"),
        ("blue-10-malware-behaviour-analysis", 10, "Malware Behaviour Analysis"),
        ("blue-11-phishing-investigation", 11, "Phishing Investigation"),
        ("blue-12-endpoint-detection", 12, "Endpoint Detection"),
    ]

    for rid, num, expected_title in expected_rooms:
        room = curriculum_registry.get_room(rid)
        assert room is not None, f"Room {rid} not found in registry"
        assert room.room_number == num
        assert room.track == TrackEnum.BLUE
        assert room.title == expected_title
        assert room.status == RoomStatus.IMPLEMENTED
        assert len(room.tasks) == 6, f"Room {rid} must have exactly 6 tasks, got {len(room.tasks)}"
        assert room.total_xp == 350, f"Room {rid} total XP must be 350, got {room.total_xp}"
        assert room.concept is not None
        assert room.concept.technical_term
        assert room.concept.simple_analogy


def test_room_blue_09_bruteforce_tasks(session, test_user):
    """Test task validation, mistake feedback, and quiz for Blue Room 09."""
    rid = "blue-09-bruteforce-detection"

    # Task 1: Taxonomy question
    sub_bad1 = TaskSubmission(answer="credential stuffing")
    res_bad1 = task_validator.validate_submission(session, test_user, rid, "task-01-bruteforce-taxonomy", sub_bad1)
    assert res_bad1.is_correct is False
    assert "Testing common passwords across many accounts is Password Spraying" in res_bad1.mistake_explanation

    sub_good1 = TaskSubmission(answer="Password Spraying")
    res_good1 = task_validator.validate_submission(session, test_user, rid, "task-01-bruteforce-taxonomy", sub_good1)
    assert res_good1.is_correct is True
    assert res_good1.earned_xp == 50

    # Task 2: Auth log investigation
    sub_bad2 = TaskSubmission(answer="203.0.113.19")
    res_bad2 = task_validator.validate_submission(session, test_user, rid, "task-02-auth-log-stream-investigation", sub_bad2)
    assert res_bad2.is_correct is False
    assert "203.0.113.19 is conducting a dictionary attack" in res_bad2.mistake_explanation

    sub_good2 = TaskSubmission(answer="198.51.100.55")
    res_good2 = task_validator.validate_submission(session, test_user, rid, "task-02-auth-log-stream-investigation", sub_good2)
    assert res_good2.is_correct is True
    assert res_good2.earned_xp == 60

    # Task 3: Spray indicator correlation
    sub_bad3 = TaskSubmission(answer="T1110.001")
    res_bad3 = task_validator.validate_submission(session, test_user, rid, "task-03-spray-indicator-correlation", sub_bad3)
    assert res_bad3.is_correct is False

    sub_good3 = TaskSubmission(answer="T1110.003")
    res_good3 = task_validator.validate_submission(session, test_user, rid, "task-03-spray-indicator-correlation", sub_good3)
    assert res_good3.is_correct is True
    assert res_good3.earned_xp == 70

    # Task 4: SIEM threshold rule deployment
    from backend.app.labs.base import LabSessionInfo
    from backend.app.labs.manager import lab_manager
    sess = LabSessionInfo(
        session_id=f"sess_{test_user.operator_id}_{rid}",
        room_id=rid,
        operator_id=test_user.operator_id,
        runner_mode="emulated",
        status="RUNNING",
        target_url="http://127.0.0.1:8209",
    )
    lab_manager._active_sessions[sess.session_id] = sess
    sess.record_action("bruteforce_rule_deployed")

    sub_good4 = TaskSubmission(answer="SIEM_SPRAY_CORRELATION_RULE_ACTIVE")
    res_good4 = task_validator.validate_submission(session, test_user, rid, "task-04-siem-threshold-rule-deployment", sub_good4)
    assert res_good4.is_correct is True
    assert res_good4.earned_xp == 70

    # Task 5: Challenge verification
    sub_bad5 = TaskSubmission(answer="wrong_token")
    res_no_action = task_validator.validate_submission(session, test_user, rid, "task-05-bruteforce-correlation-challenge", sub_bad5)
    assert res_no_action.is_correct is False
    assert "Investigation incomplete" in res_no_action.feedback

    sess.record_action("bruteforce_challenge_verified")
    sub_good5 = TaskSubmission(answer="BRUTEFORCE_RULE_VERIFIED")
    res_good5 = task_validator.validate_submission(session, test_user, rid, "task-05-bruteforce-correlation-challenge", sub_good5)
    assert res_good5.is_correct is True
    assert res_good5.earned_xp == 50

    # Task 6: Technical quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-bruteforce-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.earned_xp == 50
    assert res_quiz.room_completed is True


def test_room_blue_10_malware_tasks(session, test_user):
    """Test task validation, mistake feedback, and quiz for Blue Room 10."""
    rid = "blue-10-malware-behaviour-analysis"

    # Task 1: Static vs Dynamic
    sub_bad1 = TaskSubmission(answer="it captures network traffic")
    res_bad1 = task_validator.validate_submission(session, test_user, rid, "task-01-static-vs-dynamic-analysis", sub_bad1)
    assert res_bad1.is_correct is False

    sub_good1 = TaskSubmission(answer="It does not execute the untrusted code")
    res_good1 = task_validator.validate_submission(session, test_user, rid, "task-01-static-vs-dynamic-analysis", sub_good1)
    assert res_good1.is_correct is True
    assert res_good1.earned_xp == 50

    # Task 2: SHA-256 hash
    sub_bad2 = TaskSubmission(answer="d41d8cd98f00b204e9800998ecf8427e")
    res_bad2 = task_validator.validate_submission(session, test_user, rid, "task-02-sample-hash-verification", sub_bad2)
    assert res_bad2.is_correct is False
    assert "That is the MD5 hash" in res_bad2.mistake_explanation

    sub_good2 = TaskSubmission(answer="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    res_good2 = task_validator.validate_submission(session, test_user, rid, "task-02-sample-hash-verification", sub_good2)
    assert res_good2.is_correct is True
    assert res_good2.earned_xp == 60

    # Task 3: PE persistence key
    sub_bad3 = TaskSubmission(answer="VirtualAlloc")
    res_bad3 = task_validator.validate_submission(session, test_user, rid, "task-03-pe-imports-persistence", sub_bad3)
    assert res_bad3.is_correct is False

    sub_good3 = TaskSubmission(answer="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
    res_good3 = task_validator.validate_submission(session, test_user, rid, "task-03-pe-imports-persistence", sub_good3)
    assert res_good3.is_correct is True
    assert res_good3.earned_xp == 70

    # Task 4: YARA rule validation
    from backend.app.labs.base import LabSessionInfo
    from backend.app.labs.manager import lab_manager
    sess = LabSessionInfo(
        session_id=f"sess_{test_user.operator_id}_{rid}",
        room_id=rid,
        operator_id=test_user.operator_id,
        runner_mode="emulated",
        status="RUNNING",
        target_url="http://127.0.0.1:8210",
    )
    lab_manager._active_sessions[sess.session_id] = sess
    sess.record_action("malware_yara_validated")

    sub_good4 = TaskSubmission(answer="YARA_SYNTAX_COMPILED_MATCHED")
    res_good4 = task_validator.validate_submission(session, test_user, rid, "task-04-yara-rule-syntax-validation", sub_good4)
    assert res_good4.is_correct is True
    assert res_good4.earned_xp == 70

    # Task 5: Challenge verification
    sub_bad5 = TaskSubmission(answer="wrong_token")
    res_no_action = task_validator.validate_submission(session, test_user, rid, "task-05-malware-yara-rule-challenge", sub_bad5)
    assert res_no_action.is_correct is False
    assert "Investigation incomplete" in res_no_action.feedback

    sess.record_action("malware_challenge_verified")
    sub_good5 = TaskSubmission(answer="MALWARE_YARA_MATCH_VERIFIED")
    res_good5 = task_validator.validate_submission(session, test_user, rid, "task-05-malware-yara-rule-challenge", sub_good5)
    assert res_good5.is_correct is True
    assert res_good5.earned_xp == 50

    # Task 6: Technical quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-malware-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.earned_xp == 50
    assert res_quiz.room_completed is True


def test_room_blue_11_phishing_tasks(session, test_user):
    """Test task validation, mistake feedback, and quiz for Blue Room 11."""
    rid = "blue-11-phishing-investigation"

    # Task 1: DMARC question
    sub_bad1 = TaskSubmission(answer="spf")
    res_bad1 = task_validator.validate_submission(session, test_user, rid, "task-01-email-auth-trio", sub_bad1)
    assert res_bad1.is_correct is False

    sub_good1 = TaskSubmission(answer="DMARC")
    res_good1 = task_validator.validate_submission(session, test_user, rid, "task-01-email-auth-trio", sub_good1)
    assert res_good1.is_correct is True
    assert res_good1.earned_xp == 50

    # Task 2: Email ID
    sub_bad2 = TaskSubmission(answer="EML-2026-01")
    res_bad2 = task_validator.validate_submission(session, test_user, rid, "task-02-quarantined-email-triage", sub_bad2)
    assert res_bad2.is_correct is False

    sub_good2 = TaskSubmission(answer="EML-2026-02")
    res_good2 = task_validator.validate_submission(session, test_user, rid, "task-02-quarantined-email-triage", sub_good2)
    assert res_good2.is_correct is True
    assert res_good2.earned_xp == 60

    # Task 3: Lookalike domain
    sub_bad3 = TaskSubmission(answer="voltcorp.internal")
    res_bad3 = task_validator.validate_submission(session, test_user, rid, "task-03-lookalike-domain-identification", sub_bad3)
    assert res_bad3.is_correct is False

    sub_good3 = TaskSubmission(answer="v0ltcorp.internal")
    res_good3 = task_validator.validate_submission(session, test_user, rid, "task-03-lookalike-domain-identification", sub_good3)
    assert res_good3.is_correct is True
    assert res_good3.earned_xp == 70

    # Task 4: Phishing triage
    from backend.app.labs.base import LabSessionInfo
    from backend.app.labs.manager import lab_manager
    sess = LabSessionInfo(
        session_id=f"sess_{test_user.operator_id}_{rid}",
        room_id=rid,
        operator_id=test_user.operator_id,
        runner_mode="emulated",
        status="RUNNING",
        target_url="http://127.0.0.1:8211",
    )
    lab_manager._active_sessions[sess.session_id] = sess
    sess.record_action("phishing_triage_verified")

    sub_good4 = TaskSubmission(answer="PHISHING_TRIAGE_VERIFIED_V0LTCORP")
    res_good4 = task_validator.validate_submission(session, test_user, rid, "task-04-phishing-triage-submission", sub_good4)
    assert res_good4.is_correct is True
    assert res_good4.earned_xp == 70

    # Task 5: Challenge verification
    sub_bad5 = TaskSubmission(answer="wrong_token")
    res_no_action = task_validator.validate_submission(session, test_user, rid, "task-05-phishing-triage-remediation-challenge", sub_bad5)
    assert res_no_action.is_correct is False
    assert "Investigation incomplete" in res_no_action.feedback

    sess.record_action("phishing_challenge_verified")
    sub_good5 = TaskSubmission(answer="PHISHING_INCIDENT_CONTAINED")
    res_good5 = task_validator.validate_submission(session, test_user, rid, "task-05-phishing-triage-remediation-challenge", sub_good5)
    assert res_good5.is_correct is True
    assert res_good5.earned_xp == 50

    # Task 6: Technical quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-phishing-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.earned_xp == 50
    assert res_quiz.room_completed is True


def test_room_blue_12_endpoint_tasks(session, test_user):
    """Test task validation, mistake feedback, and quiz for Blue Room 12."""
    rid = "blue-12-endpoint-detection"

    # Task 1: Abnormal parentage
    sub_bad1 = TaskSubmission(answer="explorer.exe")
    res_bad1 = task_validator.validate_submission(session, test_user, rid, "task-01-edr-process-parentage", sub_bad1)
    assert res_bad1.is_correct is False

    sub_good1 = TaskSubmission(answer="winword.exe")
    res_good1 = task_validator.validate_submission(session, test_user, rid, "task-01-edr-process-parentage", sub_good1)
    assert res_good1.is_correct is True
    assert res_good1.earned_xp == 50

    # Task 2: Suspicious PID
    sub_bad2 = TaskSubmission(answer="1204")
    res_bad2 = task_validator.validate_submission(session, test_user, rid, "task-02-edr-telemetry-query", sub_bad2)
    assert res_bad2.is_correct is False

    sub_good2 = TaskSubmission(answer="4812")
    res_good2 = task_validator.validate_submission(session, test_user, rid, "task-02-edr-telemetry-query", sub_good2)
    assert res_good2.is_correct is True
    assert res_good2.earned_xp == 60

    # Task 3: Foreign C2 socket IP
    sub_bad3 = TaskSubmission(answer="10.10.14.50")
    res_bad3 = task_validator.validate_submission(session, test_user, rid, "task-03-lolbin-c2-socket", sub_bad3)
    assert res_bad3.is_correct is False

    sub_good3 = TaskSubmission(answer="198.51.100.88")
    res_good3 = task_validator.validate_submission(session, test_user, rid, "task-03-lolbin-c2-socket", sub_good3)
    assert res_good3.is_correct is True
    assert res_good3.earned_xp == 70

    # Task 4: EDR rule deployment
    from backend.app.labs.base import LabSessionInfo
    from backend.app.labs.manager import lab_manager
    sess = LabSessionInfo(
        session_id=f"sess_{test_user.operator_id}_{rid}",
        room_id=rid,
        operator_id=test_user.operator_id,
        runner_mode="emulated",
        status="RUNNING",
        target_url="http://127.0.0.1:8212",
    )
    lab_manager._active_sessions[sess.session_id] = sess
    sess.record_action("endpoint_rule_deployed")

    sub_good4 = TaskSubmission(answer="EDR_LOLBIN_RULE_ACTIVE_CONFIRMED")
    res_good4 = task_validator.validate_submission(session, test_user, rid, "task-04-edr-rule-deployment", sub_good4)
    assert res_good4.is_correct is True
    assert res_good4.earned_xp == 70

    # Task 5: Challenge verification
    sub_bad5 = TaskSubmission(answer="wrong_token")
    res_no_action = task_validator.validate_submission(session, test_user, rid, "task-05-edr-threat-hunting-containment-challenge", sub_bad5)
    assert res_no_action.is_correct is False
    assert "Investigation incomplete" in res_no_action.feedback

    sess.record_action("endpoint_challenge_verified")
    sub_good5 = TaskSubmission(answer="EDR_CONTAINMENT_VERIFIED")
    res_good5 = task_validator.validate_submission(session, test_user, rid, "task-05-edr-threat-hunting-containment-challenge", sub_good5)
    assert res_good5.is_correct is True
    assert res_good5.earned_xp == 50

    # Task 6: Technical quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-endpoint-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.earned_xp == 50
    assert res_quiz.room_completed is True


@pytest.mark.asyncio
async def test_no_flag_exposure_on_get_requests():
    """Security check: Verify that GET requests across Blue Rooms 09-12 NEVER expose flags."""
    runner = ProcessLabRunner()

    # Room 09 (:8209)
    s09 = await runner.start_session("sec-blue-09", "blue-09-bruteforce-detection", "op-sec")
    try:
        t09 = await runner.execute_command("sec-blue-09", "curl -s http://10.10.14.90:8209/api/auth/telemetry")
        assert "NOENTRY{" not in t09
        ind09 = await runner.execute_command("sec-blue-09", "curl -s http://10.10.14.90:8209/api/auth/spray-indicators")
        assert "NOENTRY{" not in ind09
        c09 = await runner.execute_command("sec-blue-09", "curl -s http://10.10.14.90:8209/challenge")
        assert "NOENTRY{" not in c09
    finally:
        await runner.stop_session("sec-blue-09")

    # Room 10 (:8210)
    s10 = await runner.start_session("sec-blue-10", "blue-10-malware-behaviour-analysis", "op-sec")
    try:
        smp10 = await runner.execute_command("sec-blue-10", "curl -s http://10.10.14.90:8210/api/malware/samples")
        assert "NOENTRY{" not in smp10
        hdr10 = await runner.execute_command("sec-blue-10", "curl -s http://10.10.14.90:8210/api/malware/sample/dropper/headers")
        assert "NOENTRY{" not in hdr10
        c10 = await runner.execute_command("sec-blue-10", "curl -s http://10.10.14.90:8210/challenge")
        assert "NOENTRY{" not in c10
    finally:
        await runner.stop_session("sec-blue-10")

    # Room 11 (:8211)
    s11 = await runner.start_session("sec-blue-11", "blue-11-phishing-investigation", "op-sec")
    try:
        m11 = await runner.execute_command("sec-blue-11", "curl -s http://10.10.14.90:8211/api/phishing/emails")
        assert "NOENTRY{" not in m11
        h11 = await runner.execute_command("sec-blue-11", "curl -s http://10.10.14.90:8211/api/phishing/headers/EML-2026-02")
        assert "NOENTRY{" not in h11
        c11 = await runner.execute_command("sec-blue-11", "curl -s http://10.10.14.90:8211/challenge")
        assert "NOENTRY{" not in c11
    finally:
        await runner.stop_session("sec-blue-11")

    # Room 12 (:8212)
    s12 = await runner.start_session("sec-blue-12", "blue-12-endpoint-detection", "op-sec")
    try:
        p12 = await runner.execute_command("sec-blue-12", "curl -s http://10.10.14.90:8212/api/endpoint/telemetry/processes")
        assert "NOENTRY{" not in p12
        net12 = await runner.execute_command("sec-blue-12", "curl -s http://10.10.14.90:8212/api/endpoint/telemetry/network")
        assert "NOENTRY{" not in net12
        c12 = await runner.execute_command("sec-blue-12", "curl -s http://10.10.14.90:8212/challenge")
        assert "NOENTRY{" not in c12
    finally:
        await runner.stop_session("sec-blue-12")


@pytest.mark.asyncio
async def test_blue_09_12_process_lab_runner():
    """Verify local ProcessLabRunner executes queries and returns valid tokens for Rooms 09–12."""
    runner = ProcessLabRunner()

    # Room 09: Brute-Force Detection (:8209)
    sess09 = await runner.start_session("test-blue-09", "blue-09-bruteforce-detection", "op09")
    assert sess09.target_port == 8209
    detect_out = await runner.execute_command("test-blue-09", "python3 /home/operator/tools/detect_bruteforce.py")
    assert "PASSWORD_SPRAY (T1110.003)" in detect_out

    # Prerequisite: deploy rule
    rule_out = await runner.execute_command(
        "test-blue-09",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"rule_name":"RULE_AUTH_BURST_SPRAY","threshold":5,"group_by":"source_ip"}\' http://10.10.14.90:8209/api/auth/rules',
    )
    assert "SIEM_SPRAY_CORRELATION_RULE_ACTIVE" in rule_out

    chal09_out = await runner.execute_command(
        "test-blue-09",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"source_ip":"198.51.100.55","attack_type":"PASSWORD_SPRAY","targeted_accounts_count":12}\' http://10.10.14.90:8209/challenge',
    )
    assert "BRUTEFORCE_RULE_VERIFIED" in chal09_out
    assert "NOENTRY{" not in chal09_out
    await runner.stop_session("test-blue-09")

    # Room 10: Malware Behaviour Analysis (:8210)
    sess10 = await runner.start_session("test-blue-10", "blue-10-malware-behaviour-analysis", "op10")
    assert sess10.target_port == 8210
    yara_out = await runner.execute_command("test-blue-10", "python3 /home/operator/tools/yara_scanner.py")
    assert "VoltStage2_Payload" in yara_out

    # Prerequisite: compile YARA rule
    yara_rule_out = await runner.execute_command(
        "test-blue-10",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"rule_text":"rule Dropper_VoltStage_Win32 { strings: $a = \\"VoltStage2_Payload\\" condition: $a }"}\' http://10.10.14.90:8210/api/malware/yara/validate',
    )
    assert "YARA_SYNTAX_COMPILED_MATCHED" in yara_rule_out

    chal10_out = await runner.execute_command(
        "test-blue-10",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"sample_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","c2_url":"http://c2-stage.voltcorp.internal/gate.php","persistence_mechanism":"Registry RunKey"}\' http://10.10.14.90:8210/challenge',
    )
    assert "MALWARE_YARA_MATCH_VERIFIED" in chal10_out
    assert "NOENTRY{" not in chal10_out
    await runner.stop_session("test-blue-10")

    # Room 11: Phishing Investigation (:8211)
    sess11 = await runner.start_session("test-blue-11", "blue-11-phishing-investigation", "op11")
    assert sess11.target_port == 8211
    email_out = await runner.execute_command("test-blue-11", "python3 /home/operator/tools/inspect_email.py")
    assert "v0ltcorp.internal" in email_out

    # Prerequisite: submit triage
    triage_out = await runner.execute_command(
        "test-blue-11",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"email_id":"EML-2026-02","threat_category":"SPEAR_PHISHING","spoofed_domain":"v0ltcorp.internal"}\' http://10.10.14.90:8211/api/phishing/triage',
    )
    assert "PHISHING_TRIAGE_VERIFIED_V0LTCORP" in triage_out

    chal11_out = await runner.execute_command(
        "test-blue-11",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"email_id":"EML-2026-02","dmarc_result":"FAIL","lookalike_domain":"v0ltcorp.internal","remediation_action":"PURGE_AND_BLOCK"}\' http://10.10.14.90:8211/challenge',
    )
    assert "PHISHING_INCIDENT_CONTAINED" in chal11_out
    assert "NOENTRY{" not in chal11_out
    await runner.stop_session("test-blue-11")

    # Room 12: Endpoint Detection (:8212)
    sess12 = await runner.start_session("test-blue-12", "blue-12-endpoint-detection", "op12")
    assert sess12.target_port == 8212
    edr_out = await runner.execute_command("test-blue-12", "python3 /home/operator/tools/edr_query.py")
    assert "4812" in edr_out
    assert "powershell.exe" in edr_out

    # Prerequisite: deploy behavioral rule
    edr_rule_out = await runner.execute_command(
        "test-blue-12",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"parent_process":"winword.exe","child_process":"powershell.exe"}\' http://10.10.14.90:8212/api/endpoint/rules',
    )
    assert "EDR_LOLBIN_RULE_ACTIVE_CONFIRMED" in edr_rule_out

    chal12_out = await runner.execute_command(
        "test-blue-12",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"malicious_pid":4812,"parent_process":"winword.exe","lolbin":"powershell.exe","c2_ip":"198.51.100.88"}\' http://10.10.14.90:8212/challenge',
    )
    assert "EDR_CONTAINMENT_VERIFIED" in chal12_out
    assert "NOENTRY{" not in chal12_out
    await runner.stop_session("test-blue-12")


@pytest.mark.asyncio
async def test_blue_09_12_security_audit_and_session_isolation(session):
    """
    Security Audit for Blue Rooms 09-12:
    - Direct GET requests do not leak expected parameters or flags.
    - Premature challenge submissions without prerequisites fail (400).
    - Command forgery via echo does not record actions.
    - Dynamic verification token generation and session isolation.
    """
    audit_user_a = User(operator_id="op-audit-a", username="audit_user_a", hashed_password="", xp=0)
    audit_user_b = User(operator_id="op-audit-b", username="audit_user_b", hashed_password="", xp=0)
    session.add(audit_user_a)
    session.add(audit_user_b)
    session.commit()

    runner = ProcessLabRunner()
    rid = "blue-09-bruteforce-detection"
    sess_a = await runner.start_session("sess-sec-09a", rid, audit_user_a.operator_id)
    lab_manager._active_sessions[sess_a.session_id] = sess_a

    try:
        # 1. Direct GET does not expose expected parameter requirements
        get_out = await runner.execute_command("sess-sec-09a", "curl -s http://10.10.14.90:8209/challenge")
        assert "198.51.100.55" not in get_out
        assert "Method Not Allowed" in get_out or "ACTIVE" in get_out

        # 2. Premature POST without deploying prerequisite rule fails (400)
        premature_post = await runner.execute_command(
            "sess-sec-09a",
            'curl -s -X POST -H "Content-Type: application/json" -d \'{"source_ip":"198.51.100.55","attack_type":"PASSWORD_SPRAY","targeted_accounts_count":12}\' http://10.10.14.90:8209/challenge',
        )
        assert "REJECTED" in premature_post
        assert "Prerequisite incomplete" in premature_post

        # 3. Command forgery via echo is rejected by the runner
        echo_out = await runner.execute_command("sess-sec-09a", 'echo "BRUTEFORCE_RULE_VERIFIED"')
        assert not sess_a.has_action("bruteforce_challenge_verified")

        # 4. Deploy prerequisite rule
        rule_post = await runner.execute_command(
            "sess-sec-09a",
            'curl -s -X POST -H "Content-Type: application/json" -d \'{"rule_name":"RULE_AUTH_BURST_SPRAY","threshold":5,"group_by":"source_ip"}\' http://10.10.14.90:8209/api/auth/rules',
        )
        assert "SIEM_SPRAY_CORRELATION_RULE_ACTIVE" in rule_post
        assert sess_a.has_action("bruteforce_rule_deployed")

        # 5. Invalid POST parameters fail with 400
        bad_post = await runner.execute_command(
            "sess-sec-09a",
            'curl -s -X POST -H "Content-Type: application/json" -d \'{"source_ip":"bad.ip","attack_type":"WRONG","targeted_accounts_count":1}\' http://10.10.14.90:8209/challenge',
        )
        assert "REJECTED" in bad_post
        assert "NOENTRY{" not in bad_post

        # 6. Valid POST executes and automatically records action on session A
        good_post = await runner.execute_command(
            "sess-sec-09a",
            'curl -s -X POST -H "Content-Type: application/json" -d \'{"source_ip":"198.51.100.55","attack_type":"PASSWORD_SPRAY","targeted_accounts_count":12}\' http://10.10.14.90:8209/challenge',
        )
        assert "BRUTEFORCE_RULE_VERIFIED" in good_post
        assert sess_a.has_action("bruteforce_challenge_verified")

        # 7. User A successfully submits standard token
        sub = TaskSubmission(answer="BRUTEFORCE_RULE_VERIFIED")
        res_a = task_validator.validate_submission(session, audit_user_a, rid, "task-05-bruteforce-correlation-challenge", sub)
        assert res_a.is_correct is True

        # 8. Dynamic token verification
        dyn_token = sess_a.get_action_token("bruteforce_challenge_verified")
        assert dyn_token is not None
        assert "VERIFIED-BRUTEFORCE_CHALLENGE-" in dyn_token

        # 9. User B attempts to submit without running the lab -> REJECTED
        res_b = task_validator.validate_submission(session, audit_user_b, rid, "task-05-bruteforce-correlation-challenge", sub)
        assert res_b.is_correct is False
        assert "Investigation required" in res_b.feedback
    finally:
        await runner.stop_session("sess-sec-09a")

