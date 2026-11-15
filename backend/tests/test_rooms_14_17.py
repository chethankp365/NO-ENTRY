"""
Comprehensive Unit & Functional Tests for Red Team Rooms 14–17:
- Room 14: Command Injection (red-14-command-injection)
- Room 15: Directory Traversal (red-15-directory-traversal)
- Room 16: Password Security & Key Stretching (red-16-password-security)
- Room 17: Privilege Escalation Fundamentals (red-17-privilege-escalation)

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
    u = User(username="op_batch_14_17_tester", operator_id="op-batch-14-17", hashed_password="")
    session.add(u)
    session.commit()
    session.refresh(u)
    return u


def test_rooms_14_17_curriculum_registration():
    """Verify Rooms 14, 15, 16, and 17 are registered with complete metadata."""
    room_ids = [
        ("red-14-command-injection", 14, "Command Injection"),
        ("red-15-directory-traversal", 15, "Directory Traversal"),
        ("red-16-password-security", 16, "Password Security & Key Stretching"),
        ("red-17-privilege-escalation", 17, "Privilege Escalation Fundamentals"),
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


def test_room_14_command_injection_tasks(session, test_user):
    """Test task validation, hint tracking, mistake feedback, and quiz for Room 14."""
    rid = "red-14-command-injection"

    # Task 1: Shell parameter - Mistake explanation
    sub_bad = TaskSubmission(answer="capture_output")
    res_bad = task_validator.validate_submission(session, test_user, rid, "task-01-cmd-injection-mechanics", sub_bad)
    assert res_bad.is_correct is False
    assert "capture_output captures standard output" in res_bad.mistake_explanation

    # Task 1: Correct answer (shell=True)
    sub_ok = TaskSubmission(answer="shell=True")
    res_ok = task_validator.validate_submission(session, test_user, rid, "task-01-cmd-injection-mechanics", sub_ok)
    assert res_ok.is_correct is True
    assert res_ok.earned_xp == 50

    # Task 2: Ping diagnostics flag
    sub_flag2 = TaskSubmission(answer="NOENTRY{cmd_injection_shell_metachars_8192}")
    res_flag2 = task_validator.validate_submission(session, test_user, rid, "task-02-ping-diagnostics-probing", sub_flag2)
    assert res_flag2.is_correct is True
    assert res_flag2.earned_xp == 60

    # Task 3: Command chaining flag
    sub_flag3 = TaskSubmission(answer="NOENTRY{cmd_injection_command_chain_3391}")
    res_flag3 = task_validator.validate_submission(session, test_user, rid, "task-03-command-chaining-operators", sub_flag3)
    assert res_flag3.is_correct is True

    # Task 4: Breakout challenge flag
    sub_flag4 = TaskSubmission(answer="NOENTRY{cmd_injection_operator_master_7140}")
    res_flag4 = task_validator.validate_submission(session, test_user, rid, "task-04-operator-breakout-challenge", sub_flag4)
    assert res_flag4.is_correct is True

    # Task 5: Safe API remediation flag
    sub_flag5 = TaskSubmission(answer="NOENTRY{cmd_injection_safe_api_remediated_5521}")
    res_flag5 = task_validator.validate_submission(session, test_user, rid, "task-05-safe-api-remediation", sub_flag5)
    assert res_flag5.is_correct is True

    # Task 6: Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-room-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.room_completed is True


def test_room_15_directory_traversal_tasks(session, test_user):
    """Test task validation, mistake explanations, and quiz for Room 15."""
    rid = "red-15-directory-traversal"

    # Task 1: Relative parent sequence - Mistake explanation
    sub_bad = TaskSubmission(answer="current")
    res_bad = task_validator.validate_submission(session, test_user, rid, "task-01-path-traversal-mechanics", sub_bad)
    assert res_bad.is_correct is False
    assert "current directory" in res_bad.mistake_explanation

    # Task 1: Correct answer (../)
    sub_ok = TaskSubmission(answer="../")
    res_ok = task_validator.validate_submission(session, test_user, rid, "task-01-path-traversal-mechanics", sub_ok)
    assert res_ok.is_correct is True

    # Task 2: Relative traversal flag
    sub_flag2 = TaskSubmission(answer="NOENTRY{dir_traversal_dot_dot_slash_4102}")
    res_flag2 = task_validator.validate_submission(session, test_user, rid, "task-02-relative-traversal-probing", sub_flag2)
    assert res_flag2.is_correct is True

    # Task 3: Arbitrary file download flag
    sub_flag3 = TaskSubmission(answer="NOENTRY{dir_traversal_arbitrary_file_read_9318}")
    res_flag3 = task_validator.validate_submission(session, test_user, rid, "task-03-arbitrary-file-disclosure", sub_flag3)
    assert res_flag3.is_correct is True

    # Task 4: URL encoding challenge flag
    sub_flag4 = TaskSubmission(answer="NOENTRY{dir_traversal_encoding_bypass_7749}")
    res_flag4 = task_validator.validate_submission(session, test_user, rid, "task-04-encoding-bypass-challenge", sub_flag4)
    assert res_flag4.is_correct is True

    # Task 5: Canonical path remediation flag
    sub_flag5 = TaskSubmission(answer="NOENTRY{dir_traversal_canonical_path_secured_2810}")
    res_flag5 = task_validator.validate_submission(session, test_user, rid, "task-05-canonical-path-remediation", sub_flag5)
    assert res_flag5.is_correct is True

    # Task 6: Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-room-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.room_completed is True


def test_room_16_password_security_tasks(session, test_user):
    """Test task validation, mistake feedback, and quiz for Room 16."""
    rid = "red-16-password-security"

    # Task 1: Salt concept - Mistake explanation
    sub_bad = TaskSubmission(answer="pepper")
    res_bad = task_validator.validate_submission(session, test_user, rid, "task-01-salting-principles", sub_bad)
    assert res_bad.is_correct is False
    assert "pepper is a secret application-wide key" in res_bad.mistake_explanation

    # Task 1: Correct answer (salt)
    sub_ok = TaskSubmission(answer="salt")
    res_ok = task_validator.validate_submission(session, test_user, rid, "task-01-salting-principles", sub_ok)
    assert res_ok.is_correct is True

    # Task 2: Unsalted MD5 dump flag
    sub_flag2 = TaskSubmission(answer="NOENTRY{pwd_sec_plaintext_md5_cracked_8912}")
    res_flag2 = task_validator.validate_submission(session, test_user, rid, "task-02-dump-unsalted-hashes", sub_flag2)
    assert res_flag2.is_correct is True

    # Task 3: Hash cracking verification flag
    sub_flag3 = TaskSubmission(answer="NOENTRY{pwd_sec_hash_collision_breach_3419}")
    res_flag3 = task_validator.validate_submission(session, test_user, rid, "task-03-hash-cracking-verification", sub_flag3)
    assert res_flag3.is_correct is True

    # Task 4: Key stretching challenge flag
    sub_flag4 = TaskSubmission(answer="NOENTRY{pwd_sec_key_stretching_master_6601}")
    res_flag4 = task_validator.validate_submission(session, test_user, rid, "task-04-key-stretching-challenge", sub_flag4)
    assert res_flag4.is_correct is True

    # Task 5: Password storage remediation flag
    sub_flag5 = TaskSubmission(answer="NOENTRY{pwd_sec_salted_bcrypt_hardened_4418}")
    res_flag5 = task_validator.validate_submission(session, test_user, rid, "task-05-password-remediation", sub_flag5)
    assert res_flag5.is_correct is True

    # Task 6: Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-room-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.room_completed is True


def test_room_17_privilege_escalation_tasks(session, test_user):
    """Test task validation, mistake feedback, and quiz for Room 17."""
    rid = "red-17-privilege-escalation"

    # Task 1: Escalation direction - Mistake explanation
    sub_bad = TaskSubmission(answer="horizontal")
    res_bad = task_validator.validate_submission(session, test_user, rid, "task-01-privesc-taxonomies", sub_bad)
    assert res_bad.is_correct is False
    assert "Horizontal escalation involves accessing accounts at the same privilege tier" in res_bad.mistake_explanation

    # Task 1: Correct answer (vertical)
    sub_ok = TaskSubmission(answer="vertical")
    res_ok = task_validator.validate_submission(session, test_user, rid, "task-01-privesc-taxonomies", sub_ok)
    assert res_ok.is_correct is True

    # Task 2: System audit flag
    sub_flag2 = TaskSubmission(answer="NOENTRY{privesc_permission_audit_discovered_9012}")
    res_flag2 = task_validator.validate_submission(session, test_user, rid, "task-02-system-permission-audit", sub_flag2)
    assert res_flag2.is_correct is True

    # Task 3: Sudo NOPASSWD misconfig flag
    sub_flag3 = TaskSubmission(answer="NOENTRY{privesc_sudo_nopasswd_misconfig_7821}")
    res_flag3 = task_validator.validate_submission(session, test_user, rid, "task-03-sudo-nopasswd-misconfiguration", sub_flag3)
    assert res_flag3.is_correct is True

    # Task 4: SUID execution simulation flag
    sub_flag4 = TaskSubmission(answer="NOENTRY{privesc_suid_boundary_breach_5194}")
    res_flag4 = task_validator.validate_submission(session, test_user, rid, "task-04-suid-execution-simulation", sub_flag4)
    assert res_flag4.is_correct is True

    # Task 5: Hardened sudoers remediation flag
    sub_flag5 = TaskSubmission(answer="NOENTRY{privesc_sudoers_hardened_secured_8892}")
    res_flag5 = task_validator.validate_submission(session, test_user, rid, "task-05-least-privilege-remediation", sub_flag5)
    assert res_flag5.is_correct is True

    # Task 6: Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-room-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.room_completed is True


@pytest.mark.asyncio
async def test_process_lab_runner_rooms_14_17_execution():
    """Verify ProcessLabRunner commands for Rooms 14-17."""
    runner = ProcessLabRunner()

    # Room 14 (Command Injection)
    sess14 = await runner.start_session("test_sess_14", "red-14-command-injection", "op-14")
    out_ping = await runner.execute_command("test_sess_14", "curl -s 'http://10.10.14.90:8095/api/diagnostics/ping?host=127.0.0.1%3Bid'")
    assert "NOENTRY{cmd_injection_shell_metachars_8192}" in out_ping

    out_dns = await runner.execute_command("test_sess_14", "curl -s 'http://10.10.14.90:8095/api/diagnostics/dns?domain=target.noentry.internal%26%26whoami'")
    assert "NOENTRY{cmd_injection_command_chain_3391}" in out_dns

    out_probe = await runner.execute_command("test_sess_14", "curl -s 'http://10.10.14.90:8095/challenge?probe=127.0.0.1%24(whoami)'")
    assert "NOENTRY{cmd_injection_operator_master_7140}" in out_probe

    out_rem14 = await runner.execute_command("test_sess_14", "curl -s -X POST http://10.10.14.90:8095/api/remediate")
    assert "NOENTRY{cmd_injection_safe_api_remediated_5521}" in out_rem14
    await runner.stop_session("test_sess_14")

    # Room 15 (Directory Traversal)
    sess15 = await runner.start_session("test_sess_15", "red-15-directory-traversal", "op-15")
    out_view = await runner.execute_command("test_sess_15", "curl -s 'http://10.10.14.90:8096/api/files/view?file=../../vault/recovery.key'")
    assert "NOENTRY{dir_traversal_dot_dot_slash_4102}" in out_view

    out_dl = await runner.execute_command("test_sess_15", "curl -s 'http://10.10.14.90:8096/api/files/download?file=/etc/telemetry.log'")
    assert "NOENTRY{dir_traversal_arbitrary_file_read_9318}" in out_dl

    out_enc = await runner.execute_command("test_sess_15", "curl -s 'http://10.10.14.90:8096/challenge?doc=%2e%2e%2fsecret'")
    assert "NOENTRY{dir_traversal_encoding_bypass_7749}" in out_enc

    out_rem15 = await runner.execute_command("test_sess_15", "curl -s -X POST http://10.10.14.90:8096/api/remediate")
    assert "NOENTRY{dir_traversal_canonical_path_secured_2810}" in out_rem15
    await runner.stop_session("test_sess_15")

    # Room 16 (Password Security)
    sess16 = await runner.start_session("test_sess_16", "red-16-password-security", "op-16")
    out_hashes = await runner.execute_command("test_sess_16", "cat /home/operator/hashes/hashes.txt")
    assert "5f4dcc3b5aa765d61d8327deb882cf99" in out_hashes

    out_dump = await runner.execute_command("test_sess_16", "curl -s http://10.10.14.90:8097/api/users/dump")
    assert "NOENTRY{pwd_sec_plaintext_md5_cracked_8912}" in out_dump

    out_ver = await runner.execute_command("test_sess_16", 'curl -s -X POST http://10.10.14.90:8097/api/verify -H "Content-Type: application/json" -d \'{"username":"alice","password":"password"}\'')
    assert "NOENTRY{pwd_sec_hash_collision_breach_3419}" in out_ver

    out_kdf = await runner.execute_command("test_sess_16", "curl -s 'http://10.10.14.90:8097/challenge?algorithm=bcrypt'")
    assert "NOENTRY{pwd_sec_key_stretching_master_6601}" in out_kdf

    out_rem16 = await runner.execute_command("test_sess_16", "curl -s -X POST http://10.10.14.90:8097/api/remediate")
    assert "NOENTRY{pwd_sec_salted_bcrypt_hardened_4418}" in out_rem16
    await runner.stop_session("test_sess_16")

    # Room 17 (Privilege Escalation)
    sess17 = await runner.start_session("test_sess_17", "red-17-privilege-escalation", "op-17")
    out_audit_sh = await runner.execute_command("test_sess_17", "sh /home/operator/tools/privesc_audit.sh")
    assert "backup_helper" in out_audit_sh

    out_audit_api = await runner.execute_command("test_sess_17", "curl -s http://10.10.14.90:8098/api/system/audit")
    assert "NOENTRY{privesc_permission_audit_discovered_9012}" in out_audit_api

    out_sudo = await runner.execute_command("test_sess_17", "curl -s 'http://10.10.14.90:8098/api/sudo/check?user=backup_svc'")
    assert "NOENTRY{privesc_sudo_nopasswd_misconfig_7821}" in out_sudo

    out_esc = await runner.execute_command("test_sess_17", 'curl -s -X POST http://10.10.14.90:8098/api/escalate/simulate -H "Content-Type: application/json" -d \'{"command":"whoami"}\'')
    assert "NOENTRY{privesc_suid_boundary_breach_5194}" in out_esc

    out_rem17 = await runner.execute_command("test_sess_17", "curl -s -X POST http://10.10.14.90:8098/api/remediate")
    assert "NOENTRY{privesc_sudoers_hardened_secured_8892}" in out_rem17
    await runner.stop_session("test_sess_17")
