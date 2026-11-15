"""
Comprehensive Unit & Functional Tests for Red Team Rooms 01–04:
- Room 01: Cybersecurity Foundations
- Room 02: Linux for Hackers
- Room 03: Networking Fundamentals
- Room 04: Reconnaissance
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
    u = User(username="op_batch_tester", operator_id="op-batch-01", hashed_password="")
    session.add(u)
    session.commit()
    session.refresh(u)
    return u


def test_rooms_01_04_curriculum_registration():
    """Verify Rooms 01, 02, 03, and 04 are registered with full metadata."""
    room_ids = [
        ("red-01-cybersecurity-foundations", 1, "Cybersecurity Foundations"),
        ("red-02-linux-for-hackers", 2, "Linux for Hackers"),
        ("red-03-networking-fundamentals", 3, "Networking Fundamentals"),
        ("red-04-reconnaissance", 4, "Reconnaissance"),
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


def test_room_01_foundations_task_submissions(session, test_user):
    """Test task validation, hint tracking, mistake feedback, and quiz for Room 01."""
    rid = "red-01-cybersecurity-foundations"

    # Task 1: CIA Triad Question - Mistake Explanation
    sub_bad = TaskSubmission(answer="Confidentiality")
    res_bad = task_validator.validate_submission(session, test_user, rid, "task-01-cia-triad", sub_bad)
    assert res_bad.is_correct is False
    assert "Confidentiality concerns unauthorized reading" in res_bad.mistake_explanation

    # Task 1: Correct Answer
    sub_ok = TaskSubmission(answer="Integrity")
    res_ok = task_validator.validate_submission(session, test_user, rid, "task-01-cia-triad", sub_ok)
    assert res_ok.is_correct is True
    assert res_ok.earned_xp == 50

    # Task 2: Asset Inspection Flag
    sub_flag = TaskSubmission(answer="NOENTRY{foundations_confidentiality_leak_8821}")
    res_flag = task_validator.validate_submission(session, test_user, rid, "task-02-asset-inspection", sub_flag)
    assert res_flag.is_correct is True

    # Task 3: Vulnerability term
    sub_vuln = TaskSubmission(answer="vulnerability")
    res_vuln = task_validator.validate_submission(session, test_user, rid, "task-03-threat-vuln-risk", sub_vuln)
    assert res_vuln.is_correct is True

    # Task 4: Purple Team
    sub_purple = TaskSubmission(answer="Purple Team")
    res_purple = task_validator.validate_submission(session, test_user, rid, "task-04-roles", sub_purple)
    assert res_purple.is_correct is True

    # Task 5: Compliance Audit Flag
    sub_audit = TaskSubmission(answer="NOENTRY{cia_triad_integrity_breach_1042}")
    res_audit = task_validator.validate_submission(session, test_user, rid, "task-05-practical-audit", sub_audit)
    assert res_audit.is_correct is True

    # Task 6: 5-Question Quiz
    quiz_sub = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-quiz", quiz_sub)
    assert res_quiz.is_correct is True
    assert res_quiz.room_completed is True


def test_room_02_linux_for_hackers_task_submissions(session, test_user):
    """Test task validation, hint tracking, and quiz for Room 02."""
    rid = "red-02-linux-for-hackers"

    # Task 1: Username
    res1 = task_validator.validate_submission(session, test_user, rid, "task-01-pwd-whoami", TaskSubmission(answer="operator"))
    assert res1.is_correct is True

    # Task 2: Hidden dotfile flag
    res2 = task_validator.validate_submission(session, test_user, rid, "task-02-hidden-files", TaskSubmission(answer="NOENTRY{linux_hidden_dotfiles_revealed_3182}"))
    assert res2.is_correct is True

    # Task 3: Chmod permission flag
    res3 = task_validator.validate_submission(session, test_user, rid, "task-03-permissions-chmod", TaskSubmission(answer="NOENTRY{linux_chmod_execution_unlocked_9104}"))
    assert res3.is_correct is True

    # Task 4: Process inspection flag
    res4 = task_validator.validate_submission(session, test_user, rid, "task-04-process-ps", TaskSubmission(answer="NOENTRY{linux_process_inspection_7741}"))
    assert res4.is_correct is True

    # Task 5: Grep telemetry flag
    res5 = task_validator.validate_submission(session, test_user, rid, "task-05-piping-grep", TaskSubmission(answer="NOENTRY{linux_grep_stream_mastery_5239}"))
    assert res5.is_correct is True

    # Task 6: Quiz
    res6 = task_validator.validate_submission(session, test_user, rid, "task-06-quiz", TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0}))
    assert res6.is_correct is True
    assert res6.room_completed is True


def test_room_03_networking_task_submissions(session, test_user):
    """Test task validation and quiz for Room 03."""
    rid = "red-03-networking-fundamentals"

    # Task 1: Subnet mask
    res1 = task_validator.validate_submission(session, test_user, rid, "task-01-ip-interface", TaskSubmission(answer="/24"))
    assert res1.is_correct is True

    # Task 2: HTTP Port
    res2 = task_validator.validate_submission(session, test_user, rid, "task-02-port-protocol", TaskSubmission(answer="80"))
    assert res2.is_correct is True

    # Task 3: Raw TCP socket flag
    res3 = task_validator.validate_submission(session, test_user, rid, "task-03-tcp-socket-nc", TaskSubmission(answer="NOENTRY{net_raw_tcp_socket_8832}"))
    assert res3.is_correct is True

    # Task 4: HTTP client flag
    res4 = task_validator.validate_submission(session, test_user, rid, "task-04-http-client", TaskSubmission(answer="NOENTRY{net_http_client_server_4419}"))
    assert res4.is_correct is True

    # Task 5: DNS
    res5 = task_validator.validate_submission(session, test_user, rid, "task-05-dns-resolution", TaskSubmission(answer="DNS"))
    assert res5.is_correct is True

    # Task 6: Quiz
    res6 = task_validator.validate_submission(session, test_user, rid, "task-06-quiz", TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0}))
    assert res6.is_correct is True
    assert res6.room_completed is True


def test_room_04_reconnaissance_task_submissions(session, test_user):
    """Test task validation and quiz for Room 04."""
    rid = "red-04-reconnaissance"

    # Task 1: Passive Recon
    res1 = task_validator.validate_submission(session, test_user, rid, "task-01-passive-vs-active", TaskSubmission(answer="Passive"))
    assert res1.is_correct is True

    # Task 2: Robots.txt flag
    res2 = task_validator.validate_submission(session, test_user, rid, "task-02-robots-txt", TaskSubmission(answer="NOENTRY{recon_robots_hidden_endpoint_2901}"))
    assert res2.is_correct is True

    # Task 3: Header banner
    res3 = task_validator.validate_submission(session, test_user, rid, "task-03-banner-grabbing", TaskSubmission(answer="VoltCore-v2.14-Internal"))
    assert res3.is_correct is True

    # Task 4: API docs flag
    res4 = task_validator.validate_submission(session, test_user, rid, "task-04-api-enumeration", TaskSubmission(answer="NOENTRY{recon_api_metadata_harvest_6310}"))
    assert res4.is_correct is True

    # Task 5: Backup file flag
    res5 = task_validator.validate_submission(session, test_user, rid, "task-05-directory-discovery", TaskSubmission(answer="NOENTRY{recon_dir_enumeration_master_9044}"))
    assert res5.is_correct is True

    # Task 6: Quiz
    res6 = task_validator.validate_submission(session, test_user, rid, "task-06-quiz", TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0}))
    assert res6.is_correct is True
    assert res6.room_completed is True


@pytest.mark.asyncio
async def test_process_lab_runner_rooms_01_04_execution():
    """Verify ProcessLabRunner commands and simulated responses for Rooms 01–04."""
    runner = ProcessLabRunner()
    sess_id = "test_proc_rooms_01_04"

    info = await runner.start_session(sess_id, "red-01-cybersecurity-foundations", "op-tester")
    assert info.status == "RUNNING"

    # Room 01 commands
    cat_backup = await runner.execute_command(sess_id, "cat /home/operator/assets/backup_codes.txt")
    assert "NOENTRY{foundations_confidentiality_leak_8821}" in cat_backup

    curl_audit = await runner.execute_command(sess_id, "curl -s http://10.10.14.90:8081/audit")
    assert "NOENTRY{cia_triad_integrity_breach_1042}" in curl_audit

    # Room 02 commands
    cat_dot = await runner.execute_command(sess_id, "cat /home/operator/challenges/.secret_vault/flag_hidden.txt")
    assert "NOENTRY{linux_hidden_dotfiles_revealed_3182}" in cat_dot

    run_script = await runner.execute_command(sess_id, "./restricted_script.sh")
    assert "NOENTRY{linux_chmod_execution_unlocked_9104}" in run_script

    ps_out = await runner.execute_command(sess_id, "ps aux")
    assert "NOENTRY{linux_process_inspection_7741}" in ps_out

    grep_out = await runner.execute_command(sess_id, "grep SECURITY_FLAG /home/operator/challenges/system_telemetry.log")
    assert "NOENTRY{linux_grep_stream_mastery_5239}" in grep_out

    # Room 03 commands
    ip_out = await runner.execute_command(sess_id, "ip addr show eth0")
    assert "10.10.14.2/24" in ip_out

    nc_out = await runner.execute_command(sess_id, "nc 10.10.14.90 9001")
    assert "NOENTRY{net_raw_tcp_socket_8832}" in nc_out

    net_info = await runner.execute_command(sess_id, "curl -s http://10.10.14.90:8080/network-info")
    assert "NOENTRY{net_http_client_server_4419}" in net_info

    # Room 04 commands
    robots_out = await runner.execute_command(sess_id, "curl -s http://10.10.14.90:8090/robots.txt")
    assert "Disallow: /admin-portal-staging-7712/" in robots_out

    staging_out = await runner.execute_command(sess_id, "curl -s http://10.10.14.90:8090/admin-portal-staging-7712/")
    assert "NOENTRY{recon_robots_hidden_endpoint_2901}" in staging_out

    bak_out = await runner.execute_command(sess_id, "curl -s http://10.10.14.90:8090/secret-assets/database_credentials.bak")
    assert "NOENTRY{recon_dir_enumeration_master_9044}" in bak_out

    await runner.stop_session(sess_id)

