"""
Comprehensive Unit & Functional Tests for Red Team Rooms 18–20:
- Room 18: Active Directory Fundamentals (red-18-active-directory-fundamentals)
- Room 19: Exploitation and Post-Exploitation (red-19-exploitation-post-exploitation)
- Room 20: Red Team Capstone (red-20-red-team-capstone)

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
    u = User(username="op_batch_18_20_tester", operator_id="op-batch-18-20", hashed_password="")
    session.add(u)
    session.commit()
    session.refresh(u)
    return u


def test_rooms_18_20_curriculum_registration():
    """Verify Rooms 18, 19, and 20 are registered with complete metadata and adult tone."""
    room_ids = [
        ("red-18-active-directory-fundamentals", 18, "Active Directory Fundamentals"),
        ("red-19-exploitation-post-exploitation", 19, "Exploitation and Post-Exploitation"),
        ("red-20-red-team-capstone", 20, "Red Team Capstone"),
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


def test_room_18_active_directory_tasks(session, test_user):
    """Test task validation, mistake feedback, and quiz for Room 18."""
    rid = "red-18-active-directory-fundamentals"

    # Task 1: Mistake feedback
    sub_bad = TaskSubmission(answer="DC01")
    res_bad = task_validator.validate_submission(session, test_user, rid, "task-01-ad-domain-hierarchy", sub_bad)
    assert res_bad.is_correct is False
    assert "DC01 is the domain controller hostname" in res_bad.mistake_explanation

    # Task 1: Correct flag
    sub1 = TaskSubmission(answer="NOENTRY{ad_domain_hierarchy_discovered_9102}")
    res1 = task_validator.validate_submission(session, test_user, rid, "task-01-ad-domain-hierarchy", sub1)
    assert res1.is_correct is True
    assert res1.earned_xp == 50

    # Task 2: LDAP SPN flag
    sub2 = TaskSubmission(answer="NOENTRY{ad_ldap_enumeration_spn_7812}")
    res2 = task_validator.validate_submission(session, test_user, rid, "task-02-ad-ldap-enumeration", sub2)
    assert res2.is_correct is True
    assert res2.earned_xp == 60

    # Task 3: Kerberos TGT flag
    sub3 = TaskSubmission(answer="NOENTRY{ad_kerberos_tgt_authentication_4419}")
    res3 = task_validator.validate_submission(session, test_user, rid, "task-03-ad-kerberos-authentication", sub3)
    assert res3.is_correct is True
    assert res3.earned_xp == 70

    # Task 4: Audit challenge flag
    sub4 = TaskSubmission(answer="NOENTRY{ad_delegation_misconfig_master_3201}")
    res4 = task_validator.validate_submission(session, test_user, rid, "task-04-ad-misconfiguration-audit", sub4)
    assert res4.is_correct is True
    assert res4.earned_xp == 70

    # Task 5: GPO Remediation flag
    sub5 = TaskSubmission(answer="NOENTRY{ad_gpo_least_privilege_secured_8891}")
    res5 = task_validator.validate_submission(session, test_user, rid, "task-05-ad-gpo-remediation", sub5)
    assert res5.is_correct is True
    assert res5.earned_xp == 50

    # Task 6: Room 18 Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-ad-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.room_completed is True


def test_room_19_exploitation_tasks(session, test_user):
    """Test task validation, mistake feedback, and quiz for Room 19."""
    rid = "red-19-exploitation-post-exploitation"

    # Task 1: Mistake feedback
    sub_bad = TaskSubmission(answer="sess_post_99182")
    res_bad = task_validator.validate_submission(session, test_user, rid, "task-01-exploit-foothold", sub_bad)
    assert res_bad.is_correct is False
    assert "sess_post_99182 is the session identifier" in res_bad.mistake_explanation

    # Task 1: Correct foothold flag
    sub1 = TaskSubmission(answer="NOENTRY{exploit_initial_foothold_access_6120}")
    res1 = task_validator.validate_submission(session, test_user, rid, "task-01-exploit-foothold", sub1)
    assert res1.is_correct is True
    assert res1.earned_xp == 50

    # Task 2: Post recon flag
    sub2 = TaskSubmission(answer="NOENTRY{exploit_env_recon_telemetry_9941}")
    res2 = task_validator.validate_submission(session, test_user, rid, "task-02-post-recon-telemetry", sub2)
    assert res2.is_correct is True
    assert res2.earned_xp == 60

    # Task 3: Persistence flag
    sub3 = TaskSubmission(answer="NOENTRY{exploit_persistence_mechanism_4182}")
    res3 = task_validator.validate_submission(session, test_user, rid, "task-03-exploit-persistence", sub3)
    assert res3.is_correct is True
    assert res3.earned_xp == 70

    # Task 4: Lateral challenge flag
    sub4 = TaskSubmission(answer="NOENTRY{exploit_lateral_exfil_master_7730}")
    res4 = task_validator.validate_submission(session, test_user, rid, "task-04-exploit-lateral-risk", sub4)
    assert res4.is_correct is True
    assert res4.earned_xp == 70

    # Task 5: Cleanup remediation flag
    sub5 = TaskSubmission(answer="NOENTRY{exploit_cleanup_remediation_verified_2041}")
    res5 = task_validator.validate_submission(session, test_user, rid, "task-05-exploit-cleanup-remediation", sub5)
    assert res5.is_correct is True
    assert res5.earned_xp == 50

    # Task 6: Room 19 Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-exploit-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.room_completed is True


def test_room_20_capstone_tasks(session, test_user):
    """Test task validation, mistake feedback, and quiz for Room 20."""
    rid = "red-20-red-team-capstone"

    # Task 1: Scope & ROE flag
    sub1 = TaskSubmission(answer="NOENTRY{capstone_scope_roe_verified_1092}")
    res1 = task_validator.validate_submission(session, test_user, rid, "task-01-capstone-scope-roe", sub1)
    assert res1.is_correct is True
    assert res1.earned_xp == 50

    # Task 2: Service discovery flag
    sub2 = TaskSubmission(answer="NOENTRY{capstone_service_discovery_5821}")
    res2 = task_validator.validate_submission(session, test_user, rid, "task-02-capstone-service-discovery", sub2)
    assert res2.is_correct is True
    assert res2.earned_xp == 60

    # Task 3: Foothold compromise flag
    sub3 = TaskSubmission(answer="NOENTRY{capstone_foothold_compromise_3319}")
    res3 = task_validator.validate_submission(session, test_user, rid, "task-03-capstone-foothold-exploit", sub3)
    assert res3.is_correct is True
    assert res3.earned_xp == 70

    # Task 4: Root breach flag
    sub4 = TaskSubmission(answer="NOENTRY{capstone_privilege_breach_8804}")
    res4 = task_validator.validate_submission(session, test_user, rid, "task-04-capstone-privilege-escalation", sub4)
    assert res4.is_correct is True
    assert res4.earned_xp == 70

    # Task 5: Master assessor report flag
    sub5 = TaskSubmission(answer="NOENTRY{capstone_master_assessor_7749}")
    res5 = task_validator.validate_submission(session, test_user, rid, "task-05-capstone-report-submission", sub5)
    assert res5.is_correct is True
    assert res5.earned_xp == 50

    # Task 6: Room 20 Quiz
    sub_quiz = TaskSubmission(quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0, "q5": 0})
    res_quiz = task_validator.validate_submission(session, test_user, rid, "task-06-capstone-quiz", sub_quiz)
    assert res_quiz.is_correct is True
    assert res_quiz.room_completed is True


@pytest.mark.asyncio
async def test_process_lab_runner_rooms_18_to_20():
    """Verify ProcessLabRunner commands and HTTP endpoints for Rooms 18, 19, and 20."""
    runner = ProcessLabRunner()

    # Room 18: Active Directory
    sess18 = await runner.start_session("test-proc-18", "red-18-active-directory-fundamentals", "op18")
    assert sess18.target_port == 8099

    out18_dom = await runner.execute_command("test-proc-18", "curl -s http://10.10.14.90:8099/api/ad/domain")
    assert "NOENTRY{ad_domain_hierarchy_discovered_9102}" in out18_dom

    out18_ldap = await runner.execute_command("test-proc-18", "python3 /home/operator/tools/ad_ldap_query.py")
    assert "NOENTRY{ad_ldap_enumeration_spn_7812}" in out18_ldap

    out18_tgt = await runner.execute_command(
        "test-proc-18",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"username":"svc_backup"}\' http://10.10.14.90:8099/api/ad/kerberos/request_tgt',
    )
    assert "NOENTRY{ad_kerberos_tgt_authentication_4419}" in out18_tgt

    out18_audit = await runner.execute_command("test-proc-18", 'curl -s "http://10.10.14.90:8099/challenge?audit=spn"')
    assert "NOENTRY{ad_delegation_misconfig_master_3201}" in out18_audit

    out18_rem = await runner.execute_command("test-proc-18", "curl -s -X POST http://10.10.14.90:8099/api/ad/remediate")
    assert "NOENTRY{ad_gpo_least_privilege_secured_8891}" in out18_rem
    await runner.stop_session("test-proc-18")

    # Room 19: Exploitation
    sess19 = await runner.start_session("test-proc-19", "red-19-exploitation-post-exploitation", "op19")
    assert sess19.target_port == 8100

    out19_foot = await runner.execute_command(
        "test-proc-19",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"payload":"check_prereq","service":"volt_dispatch"}\' http://10.10.14.90:8100/api/exploit/stage1',
    )
    assert "NOENTRY{exploit_initial_foothold_access_6120}" in out19_foot

    out19_rec = await runner.execute_command("test-proc-19", 'curl -s "http://10.10.14.90:8100/api/post/recon?session=sess_post_99182"')
    assert "NOENTRY{exploit_env_recon_telemetry_9941}" in out19_rec

    out19_pers = await runner.execute_command(
        "test-proc-19",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"session":"sess_post_99182","mechanism":"cron"}\' http://10.10.14.90:8100/api/post/persist',
    )
    assert "NOENTRY{exploit_persistence_mechanism_4182}" in out19_pers

    out19_lat = await runner.execute_command("test-proc-19", 'curl -s "http://10.10.14.90:8100/challenge?stage=lateral"')
    assert "NOENTRY{exploit_lateral_exfil_master_7730}" in out19_lat

    out19_rem = await runner.execute_command("test-proc-19", "curl -s -X POST http://10.10.14.90:8100/api/remediate")
    assert "NOENTRY{exploit_cleanup_remediation_verified_2041}" in out19_rem
    await runner.stop_session("test-proc-19")

    # Room 20: Capstone
    sess20 = await runner.start_session("test-proc-20", "red-20-red-team-capstone", "op20")
    assert sess20.target_port == 8101

    out20_scope = await runner.execute_command("test-proc-20", "curl -s http://10.10.14.90:8101/api/capstone/scope")
    assert "NOENTRY{capstone_scope_roe_verified_1092}" in out20_scope

    out20_recon = await runner.execute_command("test-proc-20", "curl -s http://10.10.14.90:8101/api/capstone/recon")
    assert "NOENTRY{capstone_service_discovery_5821}" in out20_recon

    out20_exploit = await runner.execute_command(
        "test-proc-20",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"action":"foothold"}\' http://10.10.14.90:8101/api/capstone/exploit',
    )
    assert "NOENTRY{capstone_foothold_compromise_3319}" in out20_exploit

    out20_priv = await runner.execute_command(
        "test-proc-20",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"technique":"suid"}\' http://10.10.14.90:8101/api/capstone/privesc',
    )
    assert "NOENTRY{capstone_privilege_breach_8804}" in out20_priv

    out20_rep = await runner.execute_command(
        "test-proc-20",
        'curl -s -X POST -H "Content-Type: application/json" -d \'{"assessment":"VoltDefense","critical_findings":[1,2,3]}\' http://10.10.14.90:8101/api/capstone/report',
    )
    assert "NOENTRY{capstone_master_assessor_7749}" in out20_rep
    await runner.stop_session("test-proc-20")

