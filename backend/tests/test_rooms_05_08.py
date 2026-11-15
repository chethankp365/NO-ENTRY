"""
Comprehensive Unit & Functional Tests for Red Team Rooms 05–08:
- Room 05: Network Scanning (red-05-network-scanning)
- Room 06: Service Enumeration (red-06-service-enumeration)
- Room 07: Vulnerability Assessment (red-07-vulnerability-assessment)
- Room 08: Web Application Fundamentals (red-08-web-application-fundamentals)
Tests room curriculum registration, concepts, task validation, mistake feedback,
hints, XP rewards, quiz evaluations, and local process lab execution.
"""

import pytest
from backend.app.academy.curriculum import curriculum_registry
from backend.app.academy.models import RoomStatus, TaskSubmission, TrackEnum
from backend.app.academy.validator import task_validator
from backend.app.db.database import get_session
from backend.app.db.models import User
from backend.app.labs.process_runner import ProcessLabRunner


@pytest.fixture
def test_user(session):
    u = User(username="op_batch_05_08_tester", operator_id="op-batch-05-08", hashed_password="")
    session.add(u)
    session.commit()
    session.refresh(u)
    return u


def test_rooms_05_08_curriculum_registration():
    """Verify Rooms 05, 06, 07, and 08 are registered with full metadata."""
    room_ids = [
        ("red-05-network-scanning", 5, "Network Scanning"),
        ("red-06-service-enumeration", 6, "Service Enumeration"),
        ("red-07-vulnerability-assessment", 7, "Vulnerability Assessment"),
        ("red-08-web-application-fundamentals", 8, "Web Application Fundamentals"),
    ]

    for rid, num, title in room_ids:
        r = curriculum_registry.get_room(rid)
        assert r is not None, f"Room {rid} not found in registry"
        assert r.track == TrackEnum.RED
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


def test_room_05_network_scanning_tasks(session, test_user):
    """Test task validation, hint tracking, mistake feedback, and quiz for Room 05."""
    rid = "red-05-network-scanning"

    # Task 1: Port States - Mistake explanation
    sub_bad = TaskSubmission(answer="filtered")
    res_bad = task_validator.validate_submission(session, test_user, rid, "task-01-port-states", sub_bad)
    assert res_bad.is_correct is False
    assert "Filtered means the packet was dropped" in res_bad.mistake_explanation

    # Task 1: Correct answer
    sub_ok = TaskSubmission(answer="closed")
    res_ok = task_validator.validate_submission(session, test_user, rid, "task-01-port-states", sub_ok)
    assert res_ok.is_correct is True
    assert res_ok.earned_xp == 50

    # Task 2: Host discovery - Mistake explanation
    sub_bad2 = TaskSubmission(answer="10.10.14.2")
    res_bad2 = task_validator.validate_submission(session, test_user, rid, "task-02-host-discovery", sub_bad2)
    assert res_bad2.is_correct is False
    assert "workstation container" in res_bad2.mistake_explanation

    # Task 2: Correct answer
    sub_ip = TaskSubmission(answer="10.10.14.90")
    res_ip = task_validator.validate_submission(session, test_user, rid, "task-02-host-discovery", sub_ip)
    assert res_ip.is_correct is True

    # Task 3: High port
    sub_port = TaskSubmission(answer="9001")
    res_port = task_validator.validate_submission(session, test_user, rid, "task-03-tcp-scan-sweep", sub_port)
    assert res_port.is_correct is True

    # Task 4: Port discovery flag
    sub_flag4 = TaskSubmission(answer="NOENTRY{nmap_port_discovery_open_4812}")
    res_flag4 = task_validator.validate_submission(session, test_user, rid, "task-04-http-scanning-service", sub_flag4)
    assert res_flag4.is_correct is True

    # Task 5: Challenge flag
    sub_flag5 = TaskSubmission(answer="NOENTRY{net_scan_stealth_recon_7731}")
    res_flag5 = task_validator.validate_submission(session, test_user, rid, "task-05-challenge", sub_flag5)
    assert res_flag5.is_correct is True

    # Task 6: Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.room_completed is True


def test_room_06_service_enumeration_tasks(session, test_user):
    """Test task validation, hint tracking, mistake feedback, and quiz for Room 06."""
    rid = "red-06-service-enumeration"

    # Task 1: Scanning vs Enumeration
    sub_bad = TaskSubmission(answer="ip address")
    res_bad = task_validator.validate_submission(session, test_user, rid, "task-01-scanning-vs-enumeration", sub_bad)
    assert res_bad.is_correct is False
    assert "IP address was already discovered" in res_bad.mistake_explanation

    sub_t1 = TaskSubmission(answer="service versions")
    res_t1 = task_validator.validate_submission(session, test_user, rid, "task-01-scanning-vs-enumeration", sub_t1)
    assert res_t1.is_correct is True

    # Task 2: FTP banner flag
    sub_ftp = TaskSubmission(answer="NOENTRY{ftp_banner_service_enumeration_5921}")
    res_ftp = task_validator.validate_submission(session, test_user, rid, "task-02-ftp-banner", sub_ftp)
    assert res_ftp.is_correct is True

    # Task 3: SSH banner string
    sub_ssh = TaskSubmission(answer="OpenSSH_8.4p1")
    res_ssh = task_validator.validate_submission(session, test_user, rid, "task-03-ssh-banner", sub_ssh)
    assert res_ssh.is_correct is True

    # Task 4: HTTP header
    sub_hdr = TaskSubmission(answer="VoltCore-Enum-v3.1")
    res_hdr = task_validator.validate_submission(session, test_user, rid, "task-04-http-headers", sub_hdr)
    assert res_hdr.is_correct is True

    # Task 5: Challenge flag
    sub_flag = TaskSubmission(answer="NOENTRY{service_enumeration_master_3389}")
    res_flag = task_validator.validate_submission(session, test_user, rid, "task-05-challenge", sub_flag)
    assert res_flag.is_correct is True

    # Task 6: Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.room_completed is True


def test_room_07_vulnerability_assessment_tasks(session, test_user):
    """Test task validation, hint tracking, mistake feedback, and quiz for Room 07."""
    rid = "red-07-vulnerability-assessment"

    # Task 1: CVE acronym
    sub_bad = TaskSubmission(answer="CVSS")
    res_bad = task_validator.validate_submission(session, test_user, rid, "task-01-cve-definition", sub_bad)
    assert res_bad.is_correct is False
    assert "Common Vulnerability Scoring System" in res_bad.mistake_explanation

    sub_t1 = TaskSubmission(answer="CVE")
    res_t1 = task_validator.validate_submission(session, test_user, rid, "task-01-cve-definition", sub_t1)
    assert res_t1.is_correct is True

    # Task 2: Component version
    sub_comp = TaskSubmission(answer="2.14.0-legacy")
    res_comp = task_validator.validate_submission(session, test_user, rid, "task-02-component-inventory", sub_comp)
    assert res_comp.is_correct is True

    # Task 3: CVSS lookup
    sub_cvss = TaskSubmission(answer="9.8")
    res_cvss = task_validator.validate_submission(session, test_user, rid, "task-03-cvss-lookup", sub_cvss)
    assert res_cvss.is_correct is True

    # Task 4: Report flag
    sub_rep = TaskSubmission(answer="NOENTRY{cve_vulnerability_assessment_master_8192}")
    res_rep = task_validator.validate_submission(session, test_user, rid, "task-04-audit-report", sub_rep)
    assert res_rep.is_correct is True

    # Task 5: Remediation flag
    sub_rem = TaskSubmission(answer="NOENTRY{vuln_assessment_remediation_verified_9410}")
    res_rem = task_validator.validate_submission(session, test_user, rid, "task-05-challenge", sub_rem)
    assert res_rem.is_correct is True

    # Task 6: Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.room_completed is True


def test_room_08_web_application_fundamentals_tasks(session, test_user):
    """Test task validation, hint tracking, mistake feedback, and quiz for Room 08."""
    rid = "red-08-web-application-fundamentals"

    # Task 1: HTTP Method
    sub_bad = TaskSubmission(answer="POST")
    res_bad = task_validator.validate_submission(session, test_user, rid, "task-01-http-methods", sub_bad)
    assert res_bad.is_correct is False
    assert "POST is primarily used to submit data" in res_bad.mistake_explanation

    sub_t1 = TaskSubmission(answer="PUT")
    res_t1 = task_validator.validate_submission(session, test_user, rid, "task-01-http-methods", sub_t1)
    assert res_t1.is_correct is True

    # Task 2: Status code
    sub_t2 = TaskSubmission(answer="405")
    res_t2 = task_validator.validate_submission(session, test_user, rid, "task-02-status-codes", sub_t2)
    assert res_t2.is_correct is True

    # Task 3: Session token
    sub_t3 = TaskSubmission(answer="op_sess_88291a")
    res_t3 = task_validator.validate_submission(session, test_user, rid, "task-03-session-authentication", sub_t3)
    assert res_t3.is_correct is True

    # Task 4: Cookie auth flag
    sub_flag4 = TaskSubmission(answer="NOENTRY{web_session_cookie_auth_2841}")
    res_flag4 = task_validator.validate_submission(session, test_user, rid, "task-04-cookie-authorization", sub_flag4)
    assert res_flag4.is_correct is True

    # Task 5: Challenge flag (PUT)
    sub_flag5 = TaskSubmission(answer="NOENTRY{web_http_put_method_master_7109}")
    res_flag5 = task_validator.validate_submission(session, test_user, rid, "task-05-challenge", sub_flag5)
    assert res_flag5.is_correct is True

    # Task 6: Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.room_completed is True


@pytest.mark.asyncio
async def test_process_lab_runner_rooms_05_08_execution():
    """Verify ProcessLabRunner commands and simulated responses for Rooms 05–08."""
    runner = ProcessLabRunner()
    sess_id = "test_proc_rooms_05_08"

    info = await runner.start_session(sess_id, "red-05-network-scanning", "op-tester-5-8")
    assert info.status == "RUNNING"

    # Room 05 commands
    ping_sweep = await runner.execute_command(sess_id, "nmap -sn 10.10.14.0/24")
    assert "10.10.14.90" in ping_sweep

    port_scan = await runner.execute_command(sess_id, "nmap -sT -p- 10.10.14.90")
    assert "9001/tcp open" in port_scan
    assert "8085/tcp open" in port_scan

    curl_scan = await runner.execute_command(sess_id, "curl -s http://10.10.14.90:8085/scan-status")
    assert "NOENTRY{nmap_port_discovery_open_4812}" in curl_scan

    curl_challenge5 = await runner.execute_command(sess_id, "curl -s http://10.10.14.90:8085/challenge")
    assert "NOENTRY{net_scan_stealth_recon_7731}" in curl_challenge5

    # Room 06 commands
    ftp_banner = await runner.execute_command(sess_id, "nc 10.10.14.90 2121")
    assert "NOENTRY{ftp_banner_service_enumeration_5921}" in ftp_banner

    ssh_banner = await runner.execute_command(sess_id, "nc 10.10.14.90 2222")
    assert "SSH-2.0-OpenSSH_8.4p1-VoltCorp_Secure_Gateway_v2" in ssh_banner

    curl_headers = await runner.execute_command(sess_id, "curl -I -s http://10.10.14.90:8086/")
    assert "X-Service-Catalog: VoltCore-Enum-v3.1" in curl_headers

    curl_challenge6 = await runner.execute_command(sess_id, "curl -s http://10.10.14.90:8086/admin-internal/")
    assert "NOENTRY{service_enumeration_master_3389}" in curl_challenge6

    # Room 07 commands
    cat_cve = await runner.execute_command(sess_id, "cat /home/operator/vuln_db/cve_catalog.json")
    assert "CVE-2024-2104" in cat_cve
    assert "9.8" in cat_cve

    audit_cli = await runner.execute_command(sess_id, "python3 /home/operator/tools/vuln_audit.py")
    assert "VULNERABILITY DETECTED" in audit_cli

    curl_comp = await runner.execute_command(sess_id, "curl -s http://10.10.14.90:8087/api/components")
    assert "2.14.0-legacy" in curl_comp

    curl_rep = await runner.execute_command(sess_id, "curl -s http://10.10.14.90:8087/audit/report")
    assert "NOENTRY{cve_vulnerability_assessment_master_8192}" in curl_rep

    curl_rem = await runner.execute_command(
        sess_id,
        "curl -s -X POST http://10.10.14.90:8087/audit/remediate -d 'action=apply_patch&cve=CVE-2024-2104'"
    )
    assert "NOENTRY{vuln_assessment_remediation_verified_9410}" in curl_rem

    # Room 08 commands
    curl_login = await runner.execute_command(
        sess_id,
        "curl -s -X POST http://10.10.14.90:8088/api/auth/login -d 'username=operator&password=voltpass123'"
    )
    assert "op_sess_88291a" in curl_login

    curl_profile = await runner.execute_command(
        sess_id,
        "curl -s -b 'session_id=op_sess_88291a' http://10.10.14.90:8088/api/profile"
    )
    assert "NOENTRY{web_session_cookie_auth_2841}" in curl_profile

    curl_put = await runner.execute_command(
        sess_id,
        "curl -s -X PUT http://10.10.14.90:8088/api/items/42 -H 'Content-Type: application/json' -d '{\"price\": 0.00}'"
    )
    assert "NOENTRY{web_http_put_method_master_7109}" in curl_put

    curl_disallowed = await runner.execute_command(
        sess_id,
        "curl -s -i -X DELETE http://10.10.14.90:8088/api/profile"
    )
    assert "405" in curl_disallowed

    await runner.stop_session(sess_id)

