"""
Comprehensive Unit & Functional Tests for Red Team Rooms 10–13:
- Room 10: Cross-Site Scripting (XSS) (red-10-cross-site-scripting)
- Room 11: Authentication Attacks (red-11-authentication-attacks)
- Room 12: Access Control Testing (red-12-access-control-testing)
- Room 13: File Upload Vulnerabilities (red-13-file-upload-vulnerabilities)
Tests room curriculum registration, adult concepts, task validation, mistake feedback,
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
    u = User(username="op_batch_10_13_tester", operator_id="op-batch-10-13", hashed_password="")
    session.add(u)
    session.commit()
    session.refresh(u)
    return u


def test_rooms_10_13_curriculum_registration():
    """Verify Rooms 10, 11, 12, and 13 are registered with full metadata."""
    room_ids = [
        ("red-10-cross-site-scripting", 10, "Cross-Site Scripting (XSS)"),
        ("red-11-authentication-attacks", 11, "Authentication Attacks"),
        ("red-12-access-control-testing", 12, "Access Control Testing"),
        ("red-13-file-upload-vulnerabilities", 13, "File Upload Vulnerabilities"),
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


def test_room_10_xss_tasks(session, test_user):
    """Test task validation, hint tracking, mistake feedback, and quiz for Room 10."""
    rid = "red-10-cross-site-scripting"

    # Task 1: Core XSS classification - Mistake explanation
    sub_bad = TaskSubmission(answer="reflected")
    res_bad = task_validator.validate_submission(session, test_user, rid, "task-01-xss-fundamentals", sub_bad)
    assert res_bad.is_correct is False
    assert "Reflected XSS echoes input immediately" in res_bad.mistake_explanation

    # Task 1: Correct answer (stored)
    sub_ok = TaskSubmission(answer="stored")
    res_ok = task_validator.validate_submission(session, test_user, rid, "task-01-xss-fundamentals", sub_ok)
    assert res_ok.is_correct is True
    assert res_ok.earned_xp == 50

    # Task 2: Reflected XSS flag
    sub_flag2 = TaskSubmission(answer="NOENTRY{xss_reflected_script_execution_4821}")
    res_flag2 = task_validator.validate_submission(session, test_user, rid, "task-02-reflected-xss", sub_flag2)
    assert res_flag2.is_correct is True

    # Task 3: Stored XSS flag
    sub_flag3 = TaskSubmission(answer="NOENTRY{xss_stored_comment_payload_9104}")
    res_flag3 = task_validator.validate_submission(session, test_user, rid, "task-03-stored-xss", sub_flag3)
    assert res_flag3.is_correct is True

    # Task 4: Attribute injection context challenge flag
    sub_flag4 = TaskSubmission(answer="NOENTRY{xss_context_encoding_defense_6623}")
    res_flag4 = task_validator.validate_submission(session, test_user, rid, "task-04-context-encoding-challenge", sub_flag4)
    assert res_flag4.is_correct is True

    # Task 5: Remediation flag
    sub_flag5 = TaskSubmission(answer="NOENTRY{xss_output_encoding_remediation_7812}")
    res_flag5 = task_validator.validate_submission(session, test_user, rid, "task-05-remediation-defense", sub_flag5)
    assert res_flag5.is_correct is True

    # Task 6: Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.room_completed is True


def test_room_11_auth_tasks(session, test_user):
    """Test task validation, mistake explanations, and quiz for Room 11."""
    rid = "red-11-authentication-attacks"

    # Task 1: Auth concept - Mistake explanation
    sub_bad = TaskSubmission(answer="authorization")
    res_bad = task_validator.validate_submission(session, test_user, rid, "task-01-auth-vs-authz", sub_bad)
    assert res_bad.is_correct is False
    assert "Authorization evaluates permissions" in res_bad.mistake_explanation

    # Task 1: Correct answer
    sub_ok = TaskSubmission(answer="authentication")
    res_ok = task_validator.validate_submission(session, test_user, rid, "task-01-auth-vs-authz", sub_ok)
    assert res_ok.is_correct is True

    # Task 2: Dictionary brute force flag
    sub_flag2 = TaskSubmission(answer="NOENTRY{auth_brute_force_dictionary_7190}")
    res_flag2 = task_validator.validate_submission(session, test_user, rid, "task-02-dictionary-attack", sub_flag2)
    assert res_flag2.is_correct is True

    # Task 3: Telemetry audit flag
    sub_flag3 = TaskSubmission(answer="NOENTRY{auth_log_analysis_telemetry_3481}")
    res_flag3 = task_validator.validate_submission(session, test_user, rid, "task-03-telemetry-audit", sub_flag3)
    assert res_flag3.is_correct is True

    # Task 4: Lockout policy challenge flag
    sub_flag4 = TaskSubmission(answer="NOENTRY{auth_lockout_policy_defense_5514}")
    res_flag4 = task_validator.validate_submission(session, test_user, rid, "task-04-lockout-challenge", sub_flag4)
    assert res_flag4.is_correct is True

    # Task 5: Rate limiting remediation flag
    sub_flag5 = TaskSubmission(answer="NOENTRY{auth_rate_limiting_bcrypt_hardened_9205}")
    res_flag5 = task_validator.validate_submission(session, test_user, rid, "task-05-remediation-hardening", sub_flag5)
    assert res_flag5.is_correct is True

    # Task 6: Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.room_completed is True


def test_room_12_access_tasks(session, test_user):
    """Test task validation, mistake feedback, and quiz for Room 12."""
    rid = "red-12-access-control-testing"

    # Task 1: IDOR acronym
    sub_ok = TaskSubmission(answer="IDOR")
    res_ok = task_validator.validate_submission(session, test_user, rid, "task-01-access-control-boundaries", sub_ok)
    assert res_ok.is_correct is True

    # Task 2: Horizontal IDOR flag
    sub_flag2 = TaskSubmission(answer="NOENTRY{idor_horizontal_privilege_access_8321}")
    res_flag2 = task_validator.validate_submission(session, test_user, rid, "task-02-horizontal-idor", sub_flag2)
    assert res_flag2.is_correct is True

    # Task 3: Vertical privilege escalation flag
    sub_flag3 = TaskSubmission(answer="NOENTRY{vertical_privilege_escalation_breach_4490}")
    res_flag3 = task_validator.validate_submission(session, test_user, rid, "task-03-vertical-privilege-escalation", sub_flag3)
    assert res_flag3.is_correct is True

    # Task 4: BOLA challenge flag
    sub_flag4 = TaskSubmission(answer="NOENTRY{bola_access_control_master_2951}")
    res_flag4 = task_validator.validate_submission(session, test_user, rid, "task-04-parameter-tampering-challenge", sub_flag4)
    assert res_flag4.is_correct is True

    # Task 5: Server-side RBAC remediation flag
    sub_flag5 = TaskSubmission(answer="NOENTRY{rbac_server_side_authorization_fixed_7134}")
    res_flag5 = task_validator.validate_submission(session, test_user, rid, "task-05-server-side-authorization-fix", sub_flag5)
    assert res_flag5.is_correct is True

    # Task 6: Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.room_completed is True


def test_room_13_upload_tasks(session, test_user):
    """Test task validation, magic byte verification, and quiz for Room 13."""
    rid = "red-13-file-upload-vulnerabilities"

    # Task 1: Magic bytes - Mistake explanation
    sub_bad = TaskSubmission(answer="ffd8ff")
    res_bad = task_validator.validate_submission(session, test_user, rid, "task-01-file-signatures-magic-bytes", sub_bad)
    assert res_bad.is_correct is False
    assert "JPEG images" in res_bad.mistake_explanation

    # Task 1: Correct magic bytes
    sub_ok = TaskSubmission(answer="89 50 4E 47")
    res_ok = task_validator.validate_submission(session, test_user, rid, "task-01-file-signatures-magic-bytes", sub_ok)
    assert res_ok.is_correct is True

    # Task 2: Extension bypass flag
    sub_flag2 = TaskSubmission(answer="NOENTRY{file_upload_extension_bypass_1892}")
    res_flag2 = task_validator.validate_submission(session, test_user, rid, "task-02-extension-bypass", sub_flag2)
    assert res_flag2.is_correct is True

    # Task 3: Path traversal flag
    sub_flag3 = TaskSubmission(answer="NOENTRY{file_upload_path_traversal_flag_6301}")
    res_flag3 = task_validator.validate_submission(session, test_user, rid, "task-03-path-traversal-upload", sub_flag3)
    assert res_flag3.is_correct is True

    # Task 4: MIME challenge flag
    sub_flag4 = TaskSubmission(answer="NOENTRY{upload_validation_defense_master_4029}")
    res_flag4 = task_validator.validate_submission(session, test_user, rid, "task-04-mime-spoofing-challenge", sub_flag4)
    assert res_flag4.is_correct is True

    # Task 5: Magic bytes remediation flag
    sub_flag5 = TaskSubmission(answer="NOENTRY{file_upload_magic_bytes_secured_8832}")
    res_flag5 = task_validator.validate_submission(session, test_user, rid, "task-05-upload-hardening-remediation", sub_flag5)
    assert res_flag5.is_correct is True

    # Task 6: Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.room_completed is True


@pytest.mark.asyncio
async def test_process_runner_rooms_10_13_simulation():
    """Verify ProcessLabRunner faithfully simulates practical exercises for Rooms 10–13."""
    runner = ProcessLabRunner()
    sess_info = await runner.start_session("proc-sess-10-13", "red-10-cross-site-scripting", "operator-10-13")
    assert sess_info.status == "RUNNING"

    # Room 10 (Port 8091): XSS
    out_xss_ref = await runner.execute_command(
        sess_info.session_id, 'curl -s "http://10.10.14.90:8091/reflected?q=<script>alert(1)</script>"'
    )
    assert "NOENTRY{xss_reflected_script_execution_4821}" in out_xss_ref

    out_xss_stored = await runner.execute_command(
        sess_info.session_id, 'curl -s -X POST http://10.10.14.90:8091/comments -d "author=attacker&comment=<script>alert(1)</script>"'
    )
    assert "NOENTRY{xss_stored_comment_payload_9104}" in out_xss_stored

    out_xss_chal = await runner.execute_command(
        sess_info.session_id, 'curl -s "http://10.10.14.90:8091/challenge?theme=\\"onmouseover=\\"alert(1)"'
    )
    assert "NOENTRY{xss_context_encoding_defense_6623}" in out_xss_chal

    out_xss_rem = await runner.execute_command(
        sess_info.session_id, 'curl -s -X POST http://10.10.14.90:8091/remediate'
    )
    assert "NOENTRY{xss_output_encoding_remediation_7812}" in out_xss_rem

    # Room 11 (Port 8092): Authentication
    out_pw = await runner.execute_command(sess_info.session_id, "cat /home/operator/wordlists/passwords.txt")
    assert "voltcorp2024" in out_pw

    out_auth_login = await runner.execute_command(
        sess_info.session_id, 'curl -s -X POST http://10.10.14.90:8092/api/login -d "username=support&password=voltcorp2024"'
    )
    assert "NOENTRY{auth_brute_force_dictionary_7190}" in out_auth_login

    out_auth_logs = await runner.execute_command(
        sess_info.session_id, "curl -s http://10.10.14.90:8092/api/logs"
    )
    assert "NOENTRY{auth_log_analysis_telemetry_3481}" in out_auth_logs

    out_auth_chal = await runner.execute_command(
        sess_info.session_id, 'curl -s "http://10.10.14.90:8092/challenge?action=verify_policy"'
    )
    assert "NOENTRY{auth_lockout_policy_defense_5514}" in out_auth_chal

    out_auth_rem = await runner.execute_command(
        sess_info.session_id, "curl -s -X POST http://10.10.14.90:8092/api/remediate"
    )
    assert "NOENTRY{auth_rate_limiting_bcrypt_hardened_9205}" in out_auth_rem

    # Room 12 (Port 8093): Access Control
    out_idor = await runner.execute_command(
        sess_info.session_id, "curl -s -H 'Authorization: Bearer bob_token' http://10.10.14.90:8093/api/documents/101"
    )
    assert "NOENTRY{idor_horizontal_privilege_access_8321}" in out_idor

    out_vertical = await runner.execute_command(
        sess_info.session_id, "curl -s -H 'Authorization: Bearer bob_token' http://10.10.14.90:8093/api/admin/users"
    )
    assert "NOENTRY{vertical_privilege_escalation_breach_4490}" in out_vertical

    out_access_chal = await runner.execute_command(
        sess_info.session_id, 'curl -s "http://10.10.14.90:8093/challenge?account_id=101"'
    )
    assert "NOENTRY{bola_access_control_master_2951}" in out_access_chal

    out_access_rem = await runner.execute_command(
        sess_info.session_id, "curl -s -X POST http://10.10.14.90:8093/api/remediate"
    )
    assert "NOENTRY{rbac_server_side_authorization_fixed_7134}" in out_access_rem

    # Room 13 (Port 8094): File Uploads
    out_uploads_ls = await runner.execute_command(sess_info.session_id, "ls -la /home/operator/uploads/")
    assert "poc.php.png" in out_uploads_ls

    out_up_bypass = await runner.execute_command(
        sess_info.session_id, "curl -s -F 'file=@/home/operator/uploads/poc.php.png' http://10.10.14.90:8094/api/upload"
    )
    assert "NOENTRY{file_upload_extension_bypass_1892}" in out_up_bypass

    out_up_trav = await runner.execute_command(
        sess_info.session_id, "curl -s -F 'file=@/home/operator/uploads/avatar.png;filename=../../uploads/poc.txt' http://10.10.14.90:8094/api/upload"
    )
    assert "NOENTRY{file_upload_path_traversal_flag_6301}" in out_up_trav

    out_up_chal = await runner.execute_command(
        sess_info.session_id, 'curl -s "http://10.10.14.90:8094/challenge?mime=application/x-php"'
    )
    assert "NOENTRY{upload_validation_defense_master_4029}" in out_up_chal

    out_up_rem = await runner.execute_command(
        sess_info.session_id, "curl -s -X POST http://10.10.14.90:8094/api/remediate"
    )
    assert "NOENTRY{file_upload_magic_bytes_secured_8832}" in out_up_rem

    await runner.stop_session(sess_info.session_id)
