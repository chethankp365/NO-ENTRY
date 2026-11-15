"""
Comprehensive Unit & Functional Tests for Blue Team Rooms 05–08:
- Room 05: Wireshark Fundamentals (blue-05-wireshark-fundamentals)
- Room 06: Log Analysis Fundamentals (blue-06-log-analysis-fundamentals)
- Room 07: SIEM Fundamentals (blue-07-siem-fundamentals)
- Room 08: Windows Event Investigation (blue-08-windows-event-investigation)

Tests curriculum registration, adult technical concepts, task validation, mistake feedback,
hints, XP rewards, quiz evaluations, local process lab execution, and security tests
asserting that GET requests to ports 8205–8208 do NOT expose flags.
"""

import pytest
from backend.app.academy.curriculum import curriculum_registry
from backend.app.academy.models import RoomStatus, TaskSubmission, TrackEnum
from backend.app.academy.validator import task_validator
from backend.app.db.models import User
from backend.app.labs.process_runner import ProcessLabRunner


@pytest.fixture
def test_user(session):
    u = User(username="op_blue_05_08_tester", operator_id="op-blue-05-08", hashed_password="")
    session.add(u)
    session.commit()
    session.refresh(u)
    return u


def test_blue_rooms_05_08_curriculum_registration():
    """Verify Rooms 05, 06, 07, and 08 are registered with complete metadata and adult tone."""
    room_ids = [
        ("blue-05-wireshark-fundamentals", 5, "Wireshark Fundamentals"),
        ("blue-06-log-analysis-fundamentals", 6, "Log Analysis Fundamentals"),
        ("blue-07-siem-fundamentals", 7, "SIEM Fundamentals"),
        ("blue-08-windows-event-investigation", 8, "Windows Event Investigation"),
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


def test_room_blue_05_wireshark_tasks(session, test_user):
    """Test task validation, mistake feedback, and quiz for Blue Room 05."""
    rid = "blue-05-wireshark-fundamentals"

    # Task 1: Display filter syntax
    sub_bad1 = TaskSubmission(answer="just tcp.flags.syn")
    res_bad1 = task_validator.validate_submission(session, test_user, rid, "task-01-wireshark-syn-filter", sub_bad1)
    assert res_bad1.is_correct is False
    assert "tcp.flags.syn == 1 matches both initial SYN packets" in res_bad1.mistake_explanation

    sub_good1 = TaskSubmission(answer="tcp.flags.syn == 1 && tcp.flags.ack == 0")
    res_good1 = task_validator.validate_submission(session, test_user, rid, "task-01-wireshark-syn-filter", sub_good1)
    assert res_good1.is_correct is True
    assert res_good1.earned_xp == 50

    # Task 2: Host header analysis
    sub_bad2 = TaskSubmission(answer="target.noentry.internal")
    res_bad2 = task_validator.validate_submission(session, test_user, rid, "task-02-http-stream-host-header", sub_bad2)
    assert res_bad2.is_correct is False
    assert "target.noentry.internal is the local target address" in res_bad2.mistake_explanation

    sub_good2 = TaskSubmission(answer="telemetry.corp.noentry.internal")
    res_good2 = task_validator.validate_submission(session, test_user, rid, "task-02-http-stream-host-header", sub_good2)
    assert res_good2.is_correct is True
    assert res_good2.earned_xp == 60

    # Task 3: DNS query analysis
    sub_bad3 = TaskSubmission(answer="target.noentry.internal")
    res_bad3 = task_validator.validate_submission(session, test_user, rid, "task-03-dns-c2-query-analysis", sub_bad3)
    assert res_bad3.is_correct is False

    sub_good3 = TaskSubmission(answer="c2-beacon.corp.noentry.internal")
    res_good3 = task_validator.validate_submission(session, test_user, rid, "task-03-dns-c2-query-analysis", sub_good3)
    assert res_good3.is_correct is True
    assert res_good3.earned_xp == 70

    # Task 4: TCP handshake client port
    sub_bad4 = TaskSubmission(answer="80")
    res_bad4 = task_validator.validate_submission(session, test_user, rid, "task-04-tcp-handshake-client-port", sub_bad4)
    assert res_bad4.is_correct is False
    assert "Port 80 is the destination" in res_bad4.mistake_explanation

    sub_good4 = TaskSubmission(answer="51420")
    res_good4 = task_validator.validate_submission(session, test_user, rid, "task-04-tcp-handshake-client-port", sub_good4)
    assert res_good4.is_correct is True
    assert res_good4.earned_xp == 70

    # Task 5: Challenge verification token
    sub_bad5 = TaskSubmission(answer="just verified")
    res_bad5 = task_validator.validate_submission(session, test_user, rid, "task-05-wireshark-challenge", sub_bad5)
    assert res_bad5.is_correct is False
    assert "Investigation required" in res_bad5.feedback

    from backend.app.labs.base import LabSessionInfo
    from backend.app.labs.manager import lab_manager
    sess = LabSessionInfo(
        session_id=f"sess_{test_user.operator_id}_{rid}",
        room_id=rid,
        operator_id=test_user.operator_id,
        runner_mode="emulated",
        status="RUNNING",
        target_url="http://127.0.0.1:8205",
    )
    lab_manager._active_sessions[sess.session_id] = sess

    res_no_action = task_validator.validate_submission(session, test_user, rid, "task-05-wireshark-challenge", sub_bad5)
    assert res_no_action.is_correct is False
    assert "Investigation incomplete" in res_no_action.feedback

    sess.record_action("wireshark_challenge_verified")
    sub_good5 = TaskSubmission(answer="WIRESHARK_DISPLAY_FILTER_VALIDATED")
    res_good5 = task_validator.validate_submission(session, test_user, rid, "task-05-wireshark-challenge", sub_good5)
    assert res_good5.is_correct is True
    assert res_good5.earned_xp == 50

    # Task 6: Technical Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-wireshark-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.earned_xp == 50


def test_room_blue_06_log_analysis_tasks(session, test_user):
    """Test task validation, mistake feedback, and quiz for Blue Room 06."""
    rid = "blue-06-log-analysis-fundamentals"

    # Task 1: Frequency pipeline
    sub_bad1 = TaskSubmission(answer="just sort")
    res_bad1 = task_validator.validate_submission(session, test_user, rid, "task-01-log-pipeline-frequency", sub_bad1)
    assert res_bad1.is_correct is False
    assert "Running sort alone" in res_bad1.mistake_explanation

    sub_good1 = TaskSubmission(answer="sort | uniq -c | sort -nr")
    res_good1 = task_validator.validate_submission(session, test_user, rid, "task-01-log-pipeline-frequency", sub_good1)
    assert res_good1.is_correct is True
    assert res_good1.earned_xp == 50

    # Task 2: Adversary IP
    sub_bad2 = TaskSubmission(answer="10.10.14.50")
    res_bad2 = task_validator.validate_submission(session, test_user, rid, "task-02-nginx-recon-ip", sub_bad2)
    assert res_bad2.is_correct is False
    assert "10.10.14.50 is internal staff workstation traffic" in res_bad2.mistake_explanation

    sub_good2 = TaskSubmission(answer="203.0.113.88")
    res_good2 = task_validator.validate_submission(session, test_user, rid, "task-02-nginx-recon-ip", sub_good2)
    assert res_good2.is_correct is True
    assert res_good2.earned_xp == 60

    # Task 3: SQLi Status Code
    sub_bad3 = TaskSubmission(answer="200")
    res_bad3 = task_validator.validate_submission(session, test_user, rid, "task-03-sqli-status-code", sub_bad3)
    assert res_bad3.is_correct is False
    assert "HTTP 200 represents success" in res_bad3.mistake_explanation

    sub_good3 = TaskSubmission(answer="500")
    res_good3 = task_validator.validate_submission(session, test_user, rid, "task-03-sqli-status-code", sub_good3)
    assert res_good3.is_correct is True
    assert res_good3.earned_xp == 70

    # Task 4: Structured Log Level
    sub_bad4 = TaskSubmission(answer="ERROR")
    res_bad4 = task_validator.validate_submission(session, test_user, rid, "task-04-structured-log-level", sub_bad4)
    assert res_bad4.is_correct is False

    sub_good4 = TaskSubmission(answer="CRITICAL")
    res_good4 = task_validator.validate_submission(session, test_user, rid, "task-04-structured-log-level", sub_good4)
    assert res_good4.is_correct is True
    assert res_good4.earned_xp == 70

    # Task 5: Multi-source Challenge
    sub_bad5 = TaskSubmission(answer="just correlated")
    res_bad5 = task_validator.validate_submission(session, test_user, rid, "task-05-log-analysis-challenge", sub_bad5)
    assert res_bad5.is_correct is False
    assert "Investigation required" in res_bad5.feedback

    from backend.app.labs.base import LabSessionInfo
    from backend.app.labs.manager import lab_manager
    sess = LabSessionInfo(
        session_id=f"sess_{test_user.operator_id}_{rid}",
        room_id=rid,
        operator_id=test_user.operator_id,
        runner_mode="emulated",
        status="RUNNING",
        target_url="http://127.0.0.1:8206",
    )
    lab_manager._active_sessions[sess.session_id] = sess

    res_no_action = task_validator.validate_submission(session, test_user, rid, "task-05-log-analysis-challenge", sub_bad5)
    assert res_no_action.is_correct is False
    assert "Investigation incomplete" in res_no_action.feedback

    sess.record_action("log_analysis_challenge_verified")
    sub_good5 = TaskSubmission(answer="LOG_TRIAGE_INCIDENT_CORRELATED_SECURE")
    res_good5 = task_validator.validate_submission(session, test_user, rid, "task-05-log-analysis-challenge", sub_good5)
    assert res_good5.is_correct is True
    assert res_good5.earned_xp == 50

    # Task 6: Technical Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-log-analysis-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.earned_xp == 50


def test_room_blue_07_siem_tasks(session, test_user):
    """Test task validation, mistake feedback, and quiz for Blue Room 07."""
    rid = "blue-07-siem-fundamentals"

    # Task 1: False Positive concept
    sub_bad1 = TaskSubmission(answer="false negative")
    res_bad1 = task_validator.validate_submission(session, test_user, rid, "task-01-siem-false-positive-concept", sub_bad1)
    assert res_bad1.is_correct is False
    assert "A False Negative occurs" in res_bad1.mistake_explanation

    sub_good1 = TaskSubmission(answer="False Positive")
    res_good1 = task_validator.validate_submission(session, test_user, rid, "task-01-siem-false-positive-concept", sub_good1)
    assert res_good1.is_correct is True
    assert res_good1.earned_xp == 50

    # Task 2: High Severity Triage
    sub_bad2 = TaskSubmission(answer="SIEM-002")
    res_bad2 = task_validator.validate_submission(session, test_user, rid, "task-02-siem-search-index-query", sub_bad2)
    assert res_bad2.is_correct is False
    assert "SIEM-002 is the event record identifier" in res_bad2.mistake_explanation

    sub_good2 = TaskSubmission(answer="198.51.100.77")
    res_good2 = task_validator.validate_submission(session, test_user, rid, "task-02-siem-search-index-query", sub_good2)
    assert res_good2.is_correct is True
    assert res_good2.earned_xp == 60

    # Task 3: Correlated alert rule name
    sub_bad3 = TaskSubmission(answer="ALRT-701")
    res_bad3 = task_validator.validate_submission(session, test_user, rid, "task-03-siem-correlated-alert-rule", sub_bad3)
    assert res_bad3.is_correct is False
    assert "ALRT-701 is the alert identifier" in res_bad3.mistake_explanation

    sub_good3 = TaskSubmission(answer="RULE_BRUTE_FORCE_EXFIL")
    res_good3 = task_validator.validate_submission(session, test_user, rid, "task-03-siem-correlated-alert-rule", sub_good3)
    assert res_good3.is_correct is True
    assert res_good3.earned_xp == 70

    # Task 4: Custom rule token
    from backend.app.labs.base import LabSessionInfo
    from backend.app.labs.manager import lab_manager
    sess = LabSessionInfo(
        session_id=f"sess_{test_user.operator_id}_{rid}",
        room_id=rid,
        operator_id=test_user.operator_id,
        runner_mode="emulated",
        status="RUNNING",
        target_url="http://127.0.0.1:8207",
    )
    lab_manager._active_sessions[sess.session_id] = sess
    sess.record_action("siem_rule_deployed")

    sub_bad4 = TaskSubmission(answer="RULE_REGISTERED")
    res_bad4 = task_validator.validate_submission(session, test_user, rid, "task-04-siem-custom-rule-deployment", sub_bad4)
    assert res_bad4.is_correct is False

    sub_good4 = TaskSubmission(answer="SIEM_CUSTOM_DETECTION_RULE_ACTIVE")
    res_good4 = task_validator.validate_submission(session, test_user, rid, "task-04-siem-custom-rule-deployment", sub_good4)
    assert res_good4.is_correct is True
    assert res_good4.earned_xp == 70

    # Task 5: Prioritization challenge
    sub_bad5 = TaskSubmission(answer="just prioritized")
    res_no_action = task_validator.validate_submission(session, test_user, rid, "task-05-siem-incident-prioritization-challenge", sub_bad5)
    assert res_no_action.is_correct is False
    assert "Investigation incomplete" in res_no_action.feedback

    sess.record_action("siem_challenge_verified")
    sub_good5 = TaskSubmission(answer="SIEM_TRIAGE_PRIORITIZATION_VALIDATED")
    res_good5 = task_validator.validate_submission(session, test_user, rid, "task-05-siem-incident-prioritization-challenge", sub_good5)
    assert res_good5.is_correct is True
    assert res_good5.earned_xp == 50

    # Task 6: Technical Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-siem-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.earned_xp == 50


def test_room_blue_08_win_event_tasks(session, test_user):
    """Test task validation, mistake feedback, and quiz for Blue Room 08."""
    rid = "blue-08-windows-event-investigation"

    # Task 1: Audit log cleared event id
    sub_bad1 = TaskSubmission(answer="4688")
    res_bad1 = task_validator.validate_submission(session, test_user, rid, "task-01-windows-event-log-tamper-id", sub_bad1)
    assert res_bad1.is_correct is False
    assert "Event ID 4688 records process creation" in res_bad1.mistake_explanation

    sub_good1 = TaskSubmission(answer="1102")
    res_good1 = task_validator.validate_submission(session, test_user, rid, "task-01-windows-event-log-tamper-id", sub_good1)
    assert res_good1.is_correct is True
    assert res_good1.earned_xp == 50

    # Task 2: Obfuscated PowerShell execution
    sub_bad2 = TaskSubmission(answer="explorer.exe")
    res_bad2 = task_validator.validate_submission(session, test_user, rid, "task-02-process-creation-powershell", sub_bad2)
    assert res_bad2.is_correct is False
    assert "explorer.exe was the parent process" in res_bad2.mistake_explanation

    sub_good2 = TaskSubmission(answer="powershell.exe")
    res_good2 = task_validator.validate_submission(session, test_user, rid, "task-02-process-creation-powershell", sub_good2)
    assert res_good2.is_correct is True
    assert res_good2.earned_xp == 60

    # Task 3: Security group escalation
    sub_bad3 = TaskSubmission(answer="backdoor_admin")
    res_bad3 = task_validator.validate_submission(session, test_user, rid, "task-03-security-group-escalation", sub_bad3)
    assert res_bad3.is_correct is False
    assert "backdoor_admin was the member added" in res_bad3.mistake_explanation

    sub_good3 = TaskSubmission(answer="Administrators")
    res_good3 = task_validator.validate_submission(session, test_user, rid, "task-03-security-group-escalation", sub_good3)
    assert res_good3.is_correct is True
    assert res_good3.earned_xp == 70

    # Task 4: Script block logging payload
    sub_bad4 = TaskSubmission(answer="198.51.100.77")
    res_bad4 = task_validator.validate_submission(session, test_user, rid, "task-04-powershell-scriptblock-logging", sub_bad4)
    assert res_bad4.is_correct is False

    sub_good4 = TaskSubmission(answer="payload.ps1")
    res_good4 = task_validator.validate_submission(session, test_user, rid, "task-04-powershell-scriptblock-logging", sub_good4)
    assert res_good4.is_correct is True
    assert res_good4.earned_xp == 70

    # Task 5: Kill-chain challenge
    sub_bad5 = TaskSubmission(answer="just reconstructed")
    res_bad5 = task_validator.validate_submission(session, test_user, rid, "task-05-windows-event-investigation-challenge", sub_bad5)
    assert res_bad5.is_correct is False
    assert "Investigation required" in res_bad5.feedback

    from backend.app.labs.base import LabSessionInfo
    from backend.app.labs.manager import lab_manager
    sess = LabSessionInfo(
        session_id=f"sess_{test_user.operator_id}_{rid}",
        room_id=rid,
        operator_id=test_user.operator_id,
        runner_mode="emulated",
        status="RUNNING",
        target_url="http://127.0.0.1:8208",
    )
    lab_manager._active_sessions[sess.session_id] = sess

    res_no_action = task_validator.validate_submission(session, test_user, rid, "task-05-windows-event-investigation-challenge", sub_bad5)
    assert res_no_action.is_correct is False
    assert "Investigation incomplete" in res_no_action.feedback

    sess.record_action("win_event_challenge_verified")
    sub_good5 = TaskSubmission(answer="WIN_EVENT_CHAIN_RECONSTRUCTED_CONFIRMED")
    res_good5 = task_validator.validate_submission(session, test_user, rid, "task-05-windows-event-investigation-challenge", sub_good5)
    assert res_good5.is_correct is True
    assert res_good5.earned_xp == 50

    # Task 6: Technical Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-windows-event-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.earned_xp == 50


@pytest.mark.asyncio
async def test_no_flag_exposure_on_get_requests():
    """Security audit test: Verify that NO GET endpoints across Ports 8205–8208 return flags directly."""
    runner = ProcessLabRunner()

    # Room 05: Wireshark Lab (:8205)
    sess05 = await runner.start_session("sec-blue-05", "blue-05-wireshark-fundamentals", "op05")
    assert sess05.target_port == 8205

    out05_root = await runner.execute_command("sec-blue-05", "curl -s http://10.10.14.90:8205/")
    assert "NOENTRY{" not in out05_root

    out05_sum = await runner.execute_command("sec-blue-05", "curl -s http://10.10.14.90:8205/api/wireshark/summary")
    assert "NOENTRY{" not in out05_sum

    out05_http = await runner.execute_command("sec-blue-05", "curl -s http://10.10.14.90:8205/api/wireshark/http")
    assert "NOENTRY{" not in out05_http

    out05_dns = await runner.execute_command("sec-blue-05", "curl -s http://10.10.14.90:8205/api/wireshark/dns")
    assert "NOENTRY{" not in out05_dns

    out05_hs = await runner.execute_command("sec-blue-05", "curl -s http://10.10.14.90:8205/api/wireshark/handshake")
    assert "NOENTRY{" not in out05_hs

    # Critical: /challenge via GET must NOT return a flag
    out05_chal_get = await runner.execute_command("sec-blue-05", "curl -s http://10.10.14.90:8205/challenge")
    assert "NOENTRY{" not in out05_chal_get
    assert "Method Not Allowed" in out05_chal_get

    await runner.stop_session("sec-blue-05")

    # Room 06: Log Analysis Lab (:8206)
    sess06 = await runner.start_session("sec-blue-06", "blue-06-log-analysis-fundamentals", "op06")
    assert sess06.target_port == 8206

    out06_root = await runner.execute_command("sec-blue-06", "curl -s http://10.10.14.90:8206/")
    assert "NOENTRY{" not in out06_root

    out06_nginx = await runner.execute_command("sec-blue-06", "curl -s http://10.10.14.90:8206/api/logs/nginx/summary")
    assert "NOENTRY{" not in out06_nginx

    out06_app = await runner.execute_command("sec-blue-06", "curl -s http://10.10.14.90:8206/api/logs/app/critical")
    assert "NOENTRY{" not in out06_app

    out06_chal_get = await runner.execute_command("sec-blue-06", "curl -s http://10.10.14.90:8206/challenge")
    assert "NOENTRY{" not in out06_chal_get
    assert "Method Not Allowed" in out06_chal_get

    await runner.stop_session("sec-blue-06")

    # Room 07: SIEM Lab (:8207)
    sess07 = await runner.start_session("sec-blue-07", "blue-07-siem-fundamentals", "op07")
    assert sess07.target_port == 8207

    out07_root = await runner.execute_command("sec-blue-07", "curl -s http://10.10.14.90:8207/")
    assert "NOENTRY{" not in out07_root

    out07_search = await runner.execute_command("sec-blue-07", "curl -s http://10.10.14.90:8207/api/siem/search")
    assert "NOENTRY{" not in out07_search

    out07_alerts = await runner.execute_command("sec-blue-07", "curl -s http://10.10.14.90:8207/api/siem/alerts")
    assert "NOENTRY{" not in out07_alerts

    out07_chal_get = await runner.execute_command("sec-blue-07", "curl -s http://10.10.14.90:8207/challenge")
    assert "NOENTRY{" not in out07_chal_get
    assert "Method Not Allowed" in out07_chal_get

    await runner.stop_session("sec-blue-07")

    # Room 08: Windows Event Investigation (:8208)
    sess08 = await runner.start_session("sec-blue-08", "blue-08-windows-event-investigation", "op08")
    assert sess08.target_port == 8208

    out08_root = await runner.execute_command("sec-blue-08", "curl -s http://10.10.14.90:8208/")
    assert "NOENTRY{" not in out08_root

    out08_proc = await runner.execute_command("sec-blue-08", "curl -s http://10.10.14.90:8208/api/winevent/process")
    assert "NOENTRY{" not in out08_proc

    out08_grp = await runner.execute_command("sec-blue-08", "curl -s http://10.10.14.90:8208/api/winevent/groups")
    assert "NOENTRY{" not in out08_grp

    out08_sb = await runner.execute_command("sec-blue-08", "curl -s http://10.10.14.90:8208/api/winevent/scriptblock")
    assert "NOENTRY{" not in out08_sb

    out08_anti = await runner.execute_command("sec-blue-08", "curl -s http://10.10.14.90:8208/api/winevent/antiforensics")
    assert "NOENTRY{" not in out08_anti

    out08_chal_get = await runner.execute_command("sec-blue-08", "curl -s http://10.10.14.90:8208/challenge")
    assert "NOENTRY{" not in out08_chal_get
    assert "Method Not Allowed" in out08_chal_get

    await runner.stop_session("sec-blue-08")


@pytest.mark.asyncio
async def test_blue_05_08_process_lab_runner():
    """Verify that ProcessLabRunner handles commands, simulations, and POST challenges for Rooms 05–08."""
    runner = ProcessLabRunner()

    # Room 05
    sess05 = await runner.start_session("proc-blue-05", "blue-05-wireshark-fundamentals", "op05")
    assert sess05.target_port == 8205

    tshark_out = await runner.execute_command("proc-blue-05", "tshark -r /home/operator/pcaps/suspicious_http_dns.pcap")
    assert "telemetry.corp.noentry.internal" in tshark_out or "c2-beacon" in tshark_out

    chal05_post = await runner.execute_command(
        "proc-blue-05",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"suspicious_domain":"c2-beacon.corp.noentry.internal","filter":"dns.qry.name contains \\"c2-beacon\\""}\' http://10.10.14.90:8205/challenge',
    )
    assert "WIRESHARK_DISPLAY_FILTER_VALIDATED" in chal05_post
    await runner.stop_session("proc-blue-05")

    # Room 06
    sess06 = await runner.start_session("proc-blue-06", "blue-06-log-analysis-fundamentals", "op06")
    assert sess06.target_port == 8206

    cat_log = await runner.execute_command("proc-blue-06", "cat /var/log/nginx/access.log")
    assert "203.0.113.88" in cat_log

    chal06_post = await runner.execute_command(
        "proc-blue-06",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"attacker_ip":"203.0.113.88","log_level":"CRITICAL"}\' http://10.10.14.90:8206/challenge',
    )
    assert "LOG_TRIAGE_INCIDENT_CORRELATED_SECURE" in chal06_post
    await runner.stop_session("proc-blue-06")

    # Room 07
    sess07 = await runner.start_session("proc-blue-07", "blue-07-siem-fundamentals", "op07")
    assert sess07.target_port == 8207

    siem_tool_out = await runner.execute_command("proc-blue-07", "python3 /home/operator/tools/siem_query.py alerts")
    assert "RULE_BRUTE_FORCE_EXFIL" in siem_tool_out

    rule_post = await runner.execute_command(
        "proc-blue-07",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"rule_name":"RULE_ANOMALOUS_EGRESS"}\' http://10.10.14.90:8207/api/siem/rules',
    )
    assert "SIEM_CUSTOM_DETECTION_RULE_ACTIVE" in rule_post

    chal07_post = await runner.execute_command(
        "proc-blue-07",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"alert_id":"ALRT-701","rule_name":"RULE_BRUTE_FORCE_EXFIL","priority":"CRITICAL"}\' http://10.10.14.90:8207/challenge',
    )
    assert "SIEM_TRIAGE_PRIORITIZATION_VALIDATED" in chal07_post
    await runner.stop_session("proc-blue-07")

    # Room 08
    sess08 = await runner.start_session("proc-blue-08", "blue-08-windows-event-investigation", "op08")
    assert sess08.target_port == 8208

    win_tool_out = await runner.execute_command("proc-blue-08", "python3 /home/operator/tools/investigate_win_events.py 4688")
    assert "powershell.exe" in win_tool_out

    chal08_post = await runner.execute_command(
        "proc-blue-08",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"tamper_event_id":1102,"malicious_process":"powershell.exe","added_group":"Administrators"}\' http://10.10.14.90:8208/challenge',
    )
    assert "WIN_EVENT_CHAIN_RECONSTRUCTED_CONFIRMED" in chal08_post
    await runner.stop_session("proc-blue-08")


@pytest.mark.asyncio
async def test_part_a_security_review_blue_05_08(session):
    """
    Part A Security Review for Blue Rooms 05-08:
    1. Direct endpoint calls without proper investigation parameters fail (400).
    2. Submissions with invalid or incomplete evidence fail.
    3. Premature task completion without completing practical steps is rejected.
    4. Replaying tokens across different user sessions is prevented or isolated.
    """
    audit_user = User(operator_id="op-audit-sec-0508", username="operator_audit_0508", hashed_password="", xp=0)
    session.add(audit_user)
    session.commit()

    runner = ProcessLabRunner()
    rid = "blue-08-windows-event-investigation"
    sess = await runner.start_session("sec-rev-08", rid, audit_user.operator_id)
    from backend.app.labs.manager import lab_manager
    lab_manager._active_sessions[sess.session_id] = sess

    try:
        # 1. Direct GET does not leak flags/tokens
        get_out = await runner.execute_command("sec-rev-08", "curl -s http://10.10.14.90:8208/challenge")
        assert "WIN_EVENT_CHAIN_RECONSTRUCTED" not in get_out
        assert "Method Not Allowed" in get_out or "ACTIVE" in get_out

        # 2. POST with invalid parameters fails (400)
        bad_post = await runner.execute_command(
            "sec-rev-08",
            'curl -s -X POST -H "Content-Type: application/json" -d \'{"tamper_event_id":9999,"malicious_process":"notepad.exe","added_group":"Guests"}\' http://10.10.14.90:8208/challenge',
        )
        assert "REJECTED" in bad_post
        assert "WIN_EVENT_CHAIN_RECONSTRUCTED" not in bad_post

        # 3. Premature submission fails
        sub = TaskSubmission(answer="WIN_EVENT_CHAIN_RECONSTRUCTED_CONFIRMED")
        res_premature = task_validator.validate_submission(session, audit_user, rid, "task-05-windows-event-investigation-challenge", sub)
        assert res_premature.is_correct is False
        assert "Investigation incomplete" in res_premature.feedback

        # 3b. Anti-command forgery test: echo must not satisfy action recording
        echo_out = await runner.execute_command("sec-rev-08", 'echo "WIN_EVENT_CHAIN_RECONSTRUCTED_CONFIRMED"')
        assert not sess.has_action("win_event_challenge_verified")

        # 4. Valid command execution records action
        good_post = await runner.execute_command(
            "sec-rev-08",
            'curl -s -X POST -H "Content-Type: application/json" -d \'{"tamper_event_id":1102,"malicious_process":"powershell.exe","added_group":"Administrators"}\' http://10.10.14.90:8208/challenge',
        )
        assert "WIN_EVENT_CHAIN_RECONSTRUCTED_CONFIRMED" in good_post
        assert sess.has_action("win_event_challenge_verified")

        # 4b. Dynamic session token verification
        dyn_token = sess.get_action_token("win_event_challenge_verified")
        assert dyn_token is not None
        assert "VERIFIED-WIN_EVENT_CHALLENGE-" in dyn_token

        # 5. User can now complete task
        res_success = task_validator.validate_submission(session, audit_user, rid, "task-05-windows-event-investigation-challenge", sub)
        assert res_success.is_correct is True

        # 6. Session isolation: User B cannot submit token without running lab
        user_b = User(operator_id="op-attacker-other-08", username="operator_b_08", hashed_password="", xp=0)
        session.add(user_b)
        session.commit()
        res_user_b = task_validator.validate_submission(session, user_b, rid, "task-05-windows-event-investigation-challenge", sub)
        assert res_user_b.is_correct is False
        assert "Investigation required" in res_user_b.feedback
    finally:
        await runner.stop_session("sec-rev-08")
