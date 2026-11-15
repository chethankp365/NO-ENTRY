"""
Comprehensive Unit & Functional Tests for Blue Team Rooms 01–04:
- Room 01: Blue Team Foundations (blue-01-blue-team-foundations)
- Room 02: Windows Security Fundamentals (blue-02-windows-security-fundamentals)
- Room 03: Linux Security Monitoring (blue-03-linux-security-monitoring)
- Room 04: Network Traffic Analysis (blue-04-network-traffic-analysis)

Tests curriculum registration, adult technical concepts, task validation, mistake feedback,
hints, XP rewards, quiz evaluations, and local process lab execution.
"""

import pytest
from backend.app.academy.curriculum import curriculum_registry
from backend.app.academy.models import RoomStatus, TaskSubmission, TrackEnum
from backend.app.academy.validator import task_validator
from backend.app.db.models import User
from backend.app.labs.process_runner import ProcessLabRunner


@pytest.fixture
def test_user(session):
    u = User(username="op_blue_01_04_tester", operator_id="op-blue-01-04", hashed_password="")
    session.add(u)
    session.commit()
    session.refresh(u)
    return u


def test_blue_rooms_01_04_curriculum_registration():
    """Verify Rooms 01, 02, 03, and 04 are registered with complete metadata and adult tone."""
    room_ids = [
        ("blue-01-blue-team-foundations", 1, "Blue Team Foundations"),
        ("blue-02-windows-security-fundamentals", 2, "Windows Security Fundamentals"),
        ("blue-03-linux-security-monitoring", 3, "Linux Security Monitoring"),
        ("blue-04-network-traffic-analysis", 4, "Network Traffic Analysis"),
    ]

    for rid, num, title in room_ids:
        r = curriculum_registry.get_room(rid)
        assert r is not None, f"Room {rid} not found in registry"
        assert r.track == TrackEnum.BLUE
        assert r.room_number == num
        assert r.title == title
        assert r.status == RoomStatus.IMPLEMENTED
        assert len(r.tasks) == 6
        assert r.total_xp == 350
        assert r.concept is not None
        assert len(r.concept.simple_analogy) > 50
        assert len(r.concept.technical_definition) > 50
        assert "toddler" not in r.concept.simple_analogy.lower()
        assert "baby" not in r.concept.simple_analogy.lower()


def test_room_blue_01_soc_tasks(session, test_user):
    """Test task validation, mistake feedback, and quiz for Blue Room 01."""
    rid = "blue-01-blue-team-foundations"

    # Task 1: Lifecycle question
    sub_bad = TaskSubmission(answer="preparation")
    res_bad = task_validator.validate_submission(session, test_user, rid, "task-01-soc-fundamentals-lifecycle", sub_bad)
    assert res_bad.is_correct is False
    assert "Preparation is Phase 1" in res_bad.mistake_explanation

    sub_good = TaskSubmission(answer="Containment")
    res_good = task_validator.validate_submission(session, test_user, rid, "task-01-soc-fundamentals-lifecycle", sub_good)
    assert res_good.is_correct is True
    assert res_good.earned_xp == 50

    # Task 2: SIEM Event Stream Finding
    sub_bad2 = TaskSubmission(answer="EVT-1003")
    res_bad2 = task_validator.validate_submission(session, test_user, rid, "task-02-siem-event-stream-investigation", sub_bad2)
    assert res_bad2.is_correct is False
    assert "EVT-1003 is the event identifier" in res_bad2.mistake_explanation

    sub_good2 = TaskSubmission(answer="198.51.100.42")
    res_good2 = task_validator.validate_submission(session, test_user, rid, "task-02-siem-event-stream-investigation", sub_good2)
    assert res_good2.is_correct is True
    assert res_good2.earned_xp == 60

    # Task 3: Alert Correlation Finding
    sub_good3 = TaskSubmission(answer="T1110.003")
    res_good3 = task_validator.validate_submission(session, test_user, rid, "task-03-siem-alert-correlation", sub_good3)
    assert res_good3.is_correct is True
    assert res_good3.earned_xp == 70

    # Task 4: Triage Classification (POST Token)
    from backend.app.labs.base import LabSessionInfo
    from backend.app.labs.manager import lab_manager
    sess = LabSessionInfo(
        session_id=f"sess_{test_user.operator_id}_{rid}",
        room_id=rid,
        operator_id=test_user.operator_id,
        runner_mode="emulated",
        status="RUNNING",
        target_url="http://127.0.0.1:8201",
    )
    lab_manager._active_sessions[sess.session_id] = sess
    sess.record_action("soc_triage_verified")

    sub_good4 = TaskSubmission(answer="TRIAGE_CONFIRMED_EVT1003_SECURE")
    res_good4 = task_validator.validate_submission(session, test_user, rid, "task-04-incident-triage-classification", sub_good4)
    assert res_good4.is_correct is True
    assert res_good4.earned_xp == 70

    # Task 5: Evidence Timeline Challenge (POST Token)
    sub_good5 = TaskSubmission(answer="TIMELINE_RECONSTRUCTED_DC_VOLT01")

    # Submitting without action executed is rejected
    res_no_action = task_validator.validate_submission(session, test_user, rid, "task-05-evidence-timeline-challenge", sub_good5)
    assert res_no_action.is_correct is False
    assert "Investigation incomplete" in res_no_action.feedback

    # Once action is recorded, submission succeeds
    sess.record_action("soc_timeline_verified")
    res_good5 = task_validator.validate_submission(session, test_user, rid, "task-05-evidence-timeline-challenge", sub_good5)
    assert res_good5.is_correct is True
    assert res_good5.earned_xp == 50

    # Task 6: Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-soc-knowledge-assessment", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.earned_xp == 50


def test_room_blue_02_windows_tasks(session, test_user):
    """Test task validation, mistake feedback, and quiz for Blue Room 02."""
    rid = "blue-02-windows-security-fundamentals"

    # Task 1: Logon Types Question
    sub_bad = TaskSubmission(answer="3")
    res_bad = task_validator.validate_submission(session, test_user, rid, "task-01-windows-logon-types", sub_bad)
    assert res_bad.is_correct is False
    assert "LogonType 3 is Network logon" in res_bad.mistake_explanation

    sub_good = TaskSubmission(answer="10")
    res_good = task_validator.validate_submission(session, test_user, rid, "task-01-windows-logon-types", sub_good)
    assert res_good.is_correct is True
    assert res_good.earned_xp == 50

    # Task 2: Event 4624 Logon Audit Finding
    sub_bad2 = TaskSubmission(answer="EventID 4624")
    res_bad2 = task_validator.validate_submission(session, test_user, rid, "task-02-windows-logon-audit", sub_bad2)
    assert res_bad2.is_correct is False
    assert "4624 is the Windows Event ID" in res_bad2.mistake_explanation

    sub_good2 = TaskSubmission(answer="10.10.14.2")
    res_good2 = task_validator.validate_submission(session, test_user, rid, "task-02-windows-logon-audit", sub_good2)
    assert res_good2.is_correct is True
    assert res_good2.earned_xp == 60

    # Task 3: Event 4720 Account Creation Finding
    sub_good3 = TaskSubmission(answer="backdoor_admin")
    res_good3 = task_validator.validate_submission(session, test_user, rid, "task-03-windows-account-creation-audit", sub_good3)
    assert res_good3.is_correct is True
    assert res_good3.earned_xp == 70

    # Task 4: Privilege Audit Challenge (POST Token)
    from backend.app.labs.base import LabSessionInfo
    from backend.app.labs.manager import lab_manager
    sess = LabSessionInfo(
        session_id=f"sess_{test_user.operator_id}_{rid}",
        room_id=rid,
        operator_id=test_user.operator_id,
        runner_mode="emulated",
        status="RUNNING",
        target_url="http://127.0.0.1:8202",
    )
    lab_manager._active_sessions[sess.session_id] = sess
    sess.record_action("win_privilege_audited")

    sub_good4 = TaskSubmission(answer="SEDEBUG_PRIVILEGE_AUDITED_CONFIRMED")
    res_good4 = task_validator.validate_submission(session, test_user, rid, "task-04-windows-privilege-audit-challenge", sub_good4)
    assert res_good4.is_correct is True
    assert res_good4.earned_xp == 70

    # Task 5: Lockout Policy Remediation (POST Token)
    sub_good5 = TaskSubmission(answer="LOCKOUT_POLICY_ENFORCED_5_ATTEMPTS")

    res_no_action = task_validator.validate_submission(session, test_user, rid, "task-05-windows-remediation-hardening", sub_good5)
    assert res_no_action.is_correct is False
    assert "Investigation incomplete" in res_no_action.feedback

    sess.record_action("win_audit_remediation_verified")
    res_good5 = task_validator.validate_submission(session, test_user, rid, "task-05-windows-remediation-hardening", sub_good5)
    assert res_good5.is_correct is True
    assert res_good5.earned_xp == 50

    # Task 6: Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-windows-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.earned_xp == 50


def test_room_blue_03_linux_tasks(session, test_user):
    """Test task validation, mistake feedback, and quiz for Blue Room 03."""
    rid = "blue-03-linux-security-monitoring"

    # Task 1: Auth Log Location Question
    sub_bad = TaskSubmission(answer="/var/log/syslog")
    res_bad = task_validator.validate_submission(session, test_user, rid, "task-01-linux-auth-log-paths", sub_bad)
    assert res_bad.is_correct is False
    assert "contains general system messages" in res_bad.mistake_explanation

    sub_good = TaskSubmission(answer="/var/log/auth.log")
    res_good = task_validator.validate_submission(session, test_user, rid, "task-01-linux-auth-log-paths", sub_good)
    assert res_good.is_correct is True
    assert res_good.earned_xp == 50

    # Task 2: SSH Brute Force Investigation Finding
    sub_good2 = TaskSubmission(answer="192.0.2.144")
    res_good2 = task_validator.validate_submission(session, test_user, rid, "task-02-ssh-bruteforce-investigation", sub_good2)
    assert res_good2.is_correct is True
    assert res_good2.earned_xp == 60

    # Task 3: Sudo Privilege Abuse Finding
    sub_good3 = TaskSubmission(answer="/usr/bin/python3")
    res_good3 = task_validator.validate_submission(session, test_user, rid, "task-03-sudo-privilege-audit", sub_good3)
    assert res_good3.is_correct is True
    assert res_good3.earned_xp == 70

    # Task 4: Source Attribution Challenge (POST Token)
    from backend.app.labs.base import LabSessionInfo
    from backend.app.labs.manager import lab_manager
    sess = LabSessionInfo(
        session_id=f"sess_{test_user.operator_id}_{rid}",
        room_id=rid,
        operator_id=test_user.operator_id,
        runner_mode="emulated",
        status="RUNNING",
        target_url="http://127.0.0.1:8203",
    )
    lab_manager._active_sessions[sess.session_id] = sess
    sess.record_action("linux_attribution_verified")

    sub_good4 = TaskSubmission(answer="ATTRIBUTION_CONFIRMED_192_0_2_144")
    res_good4 = task_validator.validate_submission(session, test_user, rid, "task-04-threat-actor-attribution-challenge", sub_good4)
    assert res_good4.is_correct is True
    assert res_good4.earned_xp == 70

    # Task 5: Hardening & Fail2ban Remediation (POST Token)
    sub_good5 = TaskSubmission(answer="SSHD_HARDENED_FAIL2BAN_ENABLED")

    res_no_action = task_validator.validate_submission(session, test_user, rid, "task-05-linux-hardening-remediation", sub_good5)
    assert res_no_action.is_correct is False
    assert "Investigation incomplete" in res_no_action.feedback

    sess.record_action("linux_incident_verified")
    res_good5 = task_validator.validate_submission(session, test_user, rid, "task-05-linux-hardening-remediation", sub_good5)
    assert res_good5.is_correct is True
    assert res_good5.earned_xp == 50

    # Task 6: Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-linux-monitoring-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.earned_xp == 50


def test_room_blue_04_traffic_tasks(session, test_user):
    """Test task validation, mistake feedback, and quiz for Blue Room 04."""
    rid = "blue-04-network-traffic-analysis"

    # Task 1: Protocol Hierarchy Question
    sub_bad = TaskSubmission(answer="UDP")
    res_bad = task_validator.validate_submission(session, test_user, rid, "task-01-network-protocol-hierarchy", sub_bad)
    assert res_bad.is_correct is False
    assert "UDP (User Datagram Protocol) is connectionless" in res_bad.mistake_explanation

    sub_good = TaskSubmission(answer="TCP")
    res_good = task_validator.validate_submission(session, test_user, rid, "task-01-network-protocol-hierarchy", sub_good)
    assert res_good.is_correct is True
    assert res_good.earned_xp == 50

    # Task 2: PCAP Protocol Summary Finding
    sub_good2 = TaskSubmission(answer="240")
    res_good2 = task_validator.validate_submission(session, test_user, rid, "task-02-pcap-protocol-summary", sub_good2)
    assert res_good2.is_correct is True
    assert res_good2.earned_xp == 60

    # Task 3: Cleartext Credential Sniffing Finding
    sub_good3 = TaskSubmission(answer="VoltSecret9921!")
    res_good3 = task_validator.validate_submission(session, test_user, rid, "task-03-cleartext-credential-sniffing", sub_good3)
    assert res_good3.is_correct is True
    assert res_good3.earned_xp == 70

    # Task 4: DNS Covert Tunneling Finding
    sub_good4 = TaskSubmission(answer="exfil-chunk-data.corp.noentry.internal")
    res_good4 = task_validator.validate_submission(session, test_user, rid, "task-04-dns-covert-channel-detection", sub_good4)
    assert res_good4.is_correct is True
    assert res_good4.earned_xp == 70

    # Task 5: Stream Forensic Challenge (POST Token)
    # Part A security: Premature submission without session is rejected
    sub_good5 = TaskSubmission(answer="COVERT_CHANNEL_EXFIL_IDENTIFIED")
    res_premature = task_validator.validate_submission(session, test_user, rid, "task-05-pcap-stream-forensic-challenge", sub_good5)
    assert res_premature.is_correct is False
    assert "Investigation required" in res_premature.feedback

    from backend.app.labs.base import LabSessionInfo
    from backend.app.labs.manager import lab_manager
    sess = LabSessionInfo(
        session_id=f"sess_{test_user.operator_id}_{rid}",
        room_id=rid,
        operator_id=test_user.operator_id,
        runner_mode="emulated",
        status="RUNNING",
        target_url="http://127.0.0.1:8204",
    )
    lab_manager._active_sessions[sess.session_id] = sess

    res_no_action = task_validator.validate_submission(session, test_user, rid, "task-05-pcap-stream-forensic-challenge", sub_good5)
    assert res_no_action.is_correct is False
    assert "Investigation incomplete" in res_no_action.feedback

    sess.record_action("traffic_investigation_verified")
    res_good5 = task_validator.validate_submission(session, test_user, rid, "task-05-pcap-stream-forensic-challenge", sub_good5)
    assert res_good5.is_correct is True
    assert res_good5.earned_xp == 50

    # Task 6: Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-network-analysis-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.earned_xp == 50


@pytest.mark.asyncio
async def test_no_flag_exposure_on_get_requests():
    """Security verification: Assert that GET requests to Blue 01-04 endpoints NEVER leak flags."""
    runner = ProcessLabRunner()

    # Room 01 (:8201)
    s1 = await runner.start_session("sec-blue-01", "blue-01-blue-team-foundations", "op-sec")
    try:
        events = await runner.execute_command("sec-blue-01", "curl -s http://10.10.14.90:8201/api/soc/events")
        assert "NOENTRY{" not in events, f"Flag exposed in GET /api/soc/events: {events}"
        alerts = await runner.execute_command("sec-blue-01", "curl -s http://10.10.14.90:8201/api/soc/alerts")
        assert "NOENTRY{" not in alerts, f"Flag exposed in GET /api/soc/alerts: {alerts}"
        chall = await runner.execute_command("sec-blue-01", "curl -s http://10.10.14.90:8201/challenge")
        assert "NOENTRY{" not in chall, f"Flag exposed in GET /challenge: {chall}"
    finally:
        await runner.stop_session("sec-blue-01")

    # Room 02 (:8202)
    s2 = await runner.start_session("sec-blue-02", "blue-02-windows-security-fundamentals", "op-sec")
    try:
        logon = await runner.execute_command("sec-blue-02", "curl -s http://10.10.14.90:8202/api/windows/events/logon")
        assert "NOENTRY{" not in logon, f"Flag exposed in GET /api/windows/events/logon: {logon}"
        priv = await runner.execute_command("sec-blue-02", "curl -s http://10.10.14.90:8202/api/windows/events/privileged")
        assert "NOENTRY{" not in priv, f"Flag exposed in GET /api/windows/events/privileged: {priv}"
        chall = await runner.execute_command("sec-blue-02", "curl -s http://10.10.14.90:8202/challenge")
        assert "NOENTRY{" not in chall, f"Flag exposed in GET /challenge: {chall}"
    finally:
        await runner.stop_session("sec-blue-02")

    # Room 03 (:8203)
    s3 = await runner.start_session("sec-blue-03", "blue-03-linux-security-monitoring", "op-sec")
    try:
        auth = await runner.execute_command("sec-blue-03", "curl -s http://10.10.14.90:8203/api/linux/logs/auth")
        assert "NOENTRY{" not in auth, f"Flag exposed in GET /api/linux/logs/auth: {auth}"
        sudo = await runner.execute_command("sec-blue-03", "curl -s http://10.10.14.90:8203/api/linux/logs/sudo")
        assert "NOENTRY{" not in sudo, f"Flag exposed in GET /api/linux/logs/sudo: {sudo}"
        chall = await runner.execute_command("sec-blue-03", "curl -s http://10.10.14.90:8203/challenge")
        assert "NOENTRY{" not in chall, f"Flag exposed in GET /challenge: {chall}"
    finally:
        await runner.stop_session("sec-blue-03")

    # Room 04 (:8204)
    s4 = await runner.start_session("sec-blue-04", "blue-04-network-traffic-analysis", "op-sec")
    try:
        summary = await runner.execute_command("sec-blue-04", "curl -s http://10.10.14.90:8204/api/traffic/summary")
        assert "NOENTRY{" not in summary, f"Flag exposed in GET /api/traffic/summary: {summary}"
        dns = await runner.execute_command("sec-blue-04", "curl -s http://10.10.14.90:8204/api/traffic/dns")
        assert "NOENTRY{" not in dns, f"Flag exposed in GET /api/traffic/dns: {dns}"
        http = await runner.execute_command("sec-blue-04", "curl -s http://10.10.14.90:8204/api/traffic/streams/http")
        assert "NOENTRY{" not in http, f"Flag exposed in GET /api/traffic/streams/http: {http}"
        chall = await runner.execute_command("sec-blue-04", "curl -s http://10.10.14.90:8204/challenge")
        assert "NOENTRY{" not in chall, f"Flag exposed in GET /challenge: {chall}"
    finally:
        await runner.stop_session("sec-blue-04")


@pytest.mark.asyncio
async def test_process_lab_runner_blue_rooms():
    """Verify local ProcessLabRunner executes queries and returns valid tokens for Blue Team Rooms 01–04."""
    runner = ProcessLabRunner()

    # Room 01: Blue Team Foundations (:8201)
    sess01 = await runner.start_session("test-blue-01", "blue-01-blue-team-foundations", "op01")
    assert sess01.target_port == 8201

    out01_events = await runner.execute_command("test-blue-01", "curl -s http://10.10.14.90:8201/api/soc/events")
    assert "198.51.100.42" in out01_events
    assert "NOENTRY{" not in out01_events

    out01_alerts = await runner.execute_command("test-blue-01", "curl -s http://10.10.14.90:8201/api/soc/alerts")
    assert "T1110.003" in out01_alerts
    assert "NOENTRY{" not in out01_alerts

    out01_triage = await runner.execute_command(
        "test-blue-01",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"event_id":"EVT-1003","classification":"TRUE_POSITIVE","severity":"HIGH"}\' http://10.10.14.90:8201/api/soc/triage',
    )
    assert "TRIAGE_CONFIRMED_EVT1003_SECURE" in out01_triage

    out01_timeline = await runner.execute_command(
        "test-blue-01",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"stage":"evidence","adversary_ip":"198.51.100.42","compromised_host":"DC-VOLT01"}\' http://10.10.14.90:8201/challenge',
    )
    assert "TIMELINE_RECONSTRUCTED_DC_VOLT01" in out01_timeline

    out01_rem = await runner.execute_command(
        "test-blue-01",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"block_ip":"198.51.100.42","action":"CONTAIN_SESSION"}\' http://10.10.14.90:8201/api/soc/remediate',
    )
    assert "CONTAINMENT_ENFORCED_IP_BLOCKED" in out01_rem
    await runner.stop_session("test-blue-01")

    # Room 02: Windows Security Fundamentals (:8202)
    sess02 = await runner.start_session("test-blue-02", "blue-02-windows-security-fundamentals", "op02")
    assert sess02.target_port == 8202

    out02_logon = await runner.execute_command("test-blue-02", "curl -s http://10.10.14.90:8202/api/windows/events/logon")
    assert "10.10.14.2" in out02_logon
    assert "NOENTRY{" not in out02_logon

    out02_priv = await runner.execute_command("test-blue-02", "curl -s http://10.10.14.90:8202/api/windows/events/privileged")
    assert "backdoor_admin" in out02_priv
    assert "NOENTRY{" not in out02_priv

    out02_tok = await runner.execute_command(
        "test-blue-02",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"audit_target":"backdoor_admin","abused_privilege":"SeDebugPrivilege"}\' http://10.10.14.90:8202/challenge',
    )
    assert "SEDEBUG_PRIVILEGE_AUDITED_CONFIRMED" in out02_tok

    out02_rem = await runner.execute_command(
        "test-blue-02",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"lockout_threshold\":5,\"reset_duration_mins\":30}\' http://10.10.14.90:8202/api/windows/remediate',
    )
    assert "LOCKOUT_POLICY_ENFORCED_5_ATTEMPTS" in out02_rem
    await runner.stop_session("test-blue-02")

    # Room 03: Linux Security Monitoring (:8203)
    sess03 = await runner.start_session("test-blue-03", "blue-03-linux-security-monitoring", "op03")
    assert sess03.target_port == 8203

    out03_auth = await runner.execute_command("test-blue-03", "curl -s http://10.10.14.90:8203/api/linux/logs/auth")
    assert "192.0.2.144" in out03_auth
    assert "NOENTRY{" not in out03_auth

    out03_sudo = await runner.execute_command("test-blue-03", "curl -s http://10.10.14.90:8203/api/linux/logs/sudo")
    assert "/usr/bin/python3" in out03_sudo
    assert "NOENTRY{" not in out03_sudo

    out03_attr = await runner.execute_command(
        "test-blue-03",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"attacker_ip":"192.0.2.144","service":"sshd"}\' http://10.10.14.90:8203/challenge',
    )
    assert "ATTRIBUTION_CONFIRMED_192_0_2_144" in out03_attr

    out03_rem = await runner.execute_command(
        "test-blue-03",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"harden_ssh\":true,\"enable_fail2ban\":true}\' http://10.10.14.90:8203/api/linux/remediate',
    )
    assert "SSHD_HARDENED_FAIL2BAN_ENABLED" in out03_rem
    await runner.stop_session("test-blue-03")

    # Room 04: Network Traffic Analysis (:8204)
    sess04 = await runner.start_session("test-blue-04", "blue-04-network-traffic-analysis", "op04")
    assert sess04.target_port == 8204

    out04_sum = await runner.execute_command("test-blue-04", "curl -s http://10.10.14.90:8204/api/traffic/summary")
    assert "240" in out04_sum
    assert "NOENTRY{" not in out04_sum

    out04_http = await runner.execute_command("test-blue-04", "curl -s http://10.10.14.90:8204/api/traffic/streams/http")
    assert "VoltSecret9921!" in out04_http
    assert "NOENTRY{" not in out04_http

    out04_dns = await runner.execute_command("test-blue-04", "curl -s http://10.10.14.90:8204/api/traffic/dns")
    assert "exfil-chunk-data.corp.noentry.internal" in out04_dns
    assert "NOENTRY{" not in out04_dns

    out04_stream = await runner.execute_command(
        "test-blue-04",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"covert_channel":"dns","tunnel_domain":"exfil-chunk-data.corp.noentry.internal"}\' http://10.10.14.90:8204/challenge',
    )
    assert "COVERT_CHANNEL_EXFIL_IDENTIFIED" in out04_stream

    out04_rem = await runner.execute_command(
        "test-blue-04",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"enforce_tls\":true,\"sinkhole_malicious_dns\":true}\' http://10.10.14.90:8204/api/traffic/remediate',
    )
    assert "TLS_ENFORCED_DNS_SINKHOLED" in out04_rem
    await runner.stop_session("test-blue-04")


@pytest.mark.asyncio
async def test_part_a_security_review_blue_01_04(session):
    """
    Part A Security Review Requirements:
    1. Direct endpoint calls without proper investigation parameters fail (400).
    2. Submissions with invalid or incomplete evidence fail.
    3. Premature task completion without completing practical steps is rejected.
    4. Replaying tokens across different user sessions is prevented or isolated.
    """
    audit_user = User(operator_id="op-audit-sec-01", username="operator_audit_01", hashed_password="", xp=0)
    session.add(audit_user)
    session.commit()

    runner = ProcessLabRunner()
    rid = "blue-01-blue-team-foundations"
    sess = await runner.start_session("sec-rev-01", rid, audit_user.operator_id)
    from backend.app.labs.manager import lab_manager
    lab_manager._active_sessions[sess.session_id] = sess
    try:
        # 1. Direct GET does not leak flags/tokens or exact expected answers
        get_out = await runner.execute_command("sec-rev-01", "curl -s http://10.10.14.90:8201/challenge")
        assert "TIMELINE_RECONSTRUCTED" not in get_out
        assert "198.51.100.42" not in get_out
        assert "Method Not Allowed" in get_out or "ACTIVE" in get_out

        # 2. POST with invalid or incomplete parameters fails (400)
        bad_post = await runner.execute_command(
            "sec-rev-01",
            'curl -s -X POST -H "Content-Type: application/json" -d \'{"stage":"evidence","adversary_ip":"wrong.ip","compromised_host":"WRONG-HOST"}\' http://10.10.14.90:8201/challenge',
        )
        assert "REJECTED" in bad_post
        assert "TIMELINE_RECONSTRUCTED" not in bad_post

        # 3. Task submission before successful command execution in session fails
        sub = TaskSubmission(answer="TIMELINE_RECONSTRUCTED_DC_VOLT01")
        res_premature = task_validator.validate_submission(session, audit_user, rid, "task-05-evidence-timeline-challenge", sub)
        assert res_premature.is_correct is False
        assert "Investigation incomplete" in res_premature.feedback

        # 4. Premature POST to /challenge without completing prerequisite triage fails
        premature_post = await runner.execute_command(
            "sec-rev-01",
            'curl -s -X POST -H "Content-Type: application/json" -d \'{"stage":"evidence","adversary_ip":"198.51.100.42","compromised_host":"DC-VOLT01"}\' http://10.10.14.90:8201/challenge',
        )
        assert "REJECTED" in premature_post
        assert "Prerequisite incomplete" in premature_post

        # 5. Command forgery via echo does not satisfy runner action recording
        echo_out = await runner.execute_command("sec-rev-01", 'echo "TIMELINE_RECONSTRUCTED_DC_VOLT01"')
        assert not sess.has_action("soc_timeline_verified")

        # 6. Execute prerequisite triage
        triage_post = await runner.execute_command(
            "sec-rev-01",
            'curl -s -X POST -H "Content-Type: application/json" -d \'{"event_id":"EVT-1003","classification":"TRUE_POSITIVE","severity":"HIGH"}\' http://10.10.14.90:8201/api/soc/triage',
        )
        assert "TRIAGE_CONFIRMED_EVT1003_SECURE" in triage_post
        assert sess.has_action("soc_triage_verified")

        # 7. Valid POST to /challenge now succeeds and automatically records action
        good_post = await runner.execute_command(
            "sec-rev-01",
            'curl -s -X POST -H "Content-Type: application/json" -d \'{"stage":"evidence","adversary_ip":"198.51.100.42","compromised_host":"DC-VOLT01"}\' http://10.10.14.90:8201/challenge',
        )
        assert "TIMELINE_RECONSTRUCTED_DC_VOLT01" in good_post
        assert sess.has_action("soc_timeline_verified")

        # 8. Dynamic token generated on session
        dyn_token = sess.get_action_token("soc_timeline_verified")
        assert dyn_token is not None
        assert "VERIFIED-SOC_TIMELINE-" in dyn_token

        # 9. User A can now complete the task
        res_success = task_validator.validate_submission(session, audit_user, rid, "task-05-evidence-timeline-challenge", sub)
        assert res_success.is_correct is True

        # 10. Session isolation: User B attempting to submit the same token without running the lab is blocked
        user_b = User(operator_id="op-attacker-other", username="operator_b", hashed_password="", xp=0)
        session.add(user_b)
        session.commit()
        res_user_b = task_validator.validate_submission(session, user_b, rid, "task-05-evidence-timeline-challenge", sub)
        assert res_user_b.is_correct is False
        assert "Investigation required" in res_user_b.feedback
    finally:
        await runner.stop_session("sec-rev-01")
