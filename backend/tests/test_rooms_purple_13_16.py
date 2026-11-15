"""
Unit and Emulated Integration Tests for Purple Team Rooms 13–16:
- Room 13: Supply Chain & Dependency Confusion Emulation (purple-13-supply-chain-emulation)
- Room 14: API Security & Broken Object Level Auth (BOLA) Emulation (purple-14-api-abuse-emulation)
- Room 15: Active Directory Attacks Emulation (Kerberoasting) (purple-15-active-directory-attacks-emulation)
- Room 16: CI/CD Pipeline & GitHub Actions Attack Emulation (purple-16-ci-cd-pipeline-emulation)

Validates curriculum integration, task validation engine, anti-forgery,
prerequisite enforcement, trusted-session identity, and dual-session isolation.
"""

import pytest
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from backend.app.academy.curriculum import curriculum_registry
from backend.app.academy.models import RoomStatus, TaskSubmission, TrackEnum
from backend.app.academy.validator import TaskValidator
from backend.app.db.models import User
from backend.app.labs.manager import lab_manager
from backend.app.labs.process_runner import ProcessLabRunner


@pytest.fixture(name="db_session")
def db_session_fixture():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(name="test_user")
def test_user_fixture(db_session: Session):
    user = User(
        username="purple_operator_1316",
        email="purple_operator_1316@noentry.internal",
        operator_id="OP-PURPLE-1316-UNIT",
        hashed_password="dummy_test_hash_purple_1316",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(name="second_user")
def second_user_fixture(db_session: Session):
    user = User(
        username="purple_operator_isolate_1316",
        email="purple_operator_isolate_1316@noentry.internal",
        operator_id="OP-PURPLE-ISOLATE-1316",
        hashed_password="dummy_test_hash_purple_isolate_1316",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


# ============================================================================
# 1. CURRICULUM REGISTRATION & TRACK TOTALS
# ============================================================================

def test_rooms_purple_13_16_curriculum_registration():
    """Verify Purple Rooms 13-16 are fully registered and configured in the curriculum."""
    expected_rooms = [
        (13, "purple-13-supply-chain-emulation"),
        (14, "purple-14-api-abuse-emulation"),
        (15, "purple-15-active-directory-attacks-emulation"),
        (16, "purple-16-ci-cd-pipeline-emulation"),
    ]
    for r_num, expected_id in expected_rooms:
        room = curriculum_registry.get_room(expected_id)
        assert room is not None, f"Purple Room {expected_id} not found"
        assert room.room_number == r_num
        assert room.track == TrackEnum.PURPLE
        assert room.status == RoomStatus.IMPLEMENTED
        assert len(room.tasks) == 6
        assert room.total_xp == 350
        assert room.concept is not None
        assert room.concept.technical_term
        assert room.concept.overview
        assert "toddler" not in room.concept.simple_analogy.lower()
        assert "baby" not in room.concept.simple_analogy.lower()

    # Verify track statistics: 56 implemented across platform, 16 in Purple
    purple_rooms = curriculum_registry.list_rooms(track=TrackEnum.PURPLE)
    assert len(purple_rooms) == 20
    implemented_purple = [r for r in purple_rooms if r.status == RoomStatus.IMPLEMENTED]
    assert len(implemented_purple) >= 16

    counts = curriculum_registry.get_track_counts()
    assert counts["purple"]["total"] == 20
    assert counts["purple"]["implemented"] >= 16
    assert counts["red"]["implemented"] == 20
    assert counts["blue"]["implemented"] == 20


# ============================================================================
# 2. ROOM 13: SUPPLY CHAIN & DEPENDENCY CONFUSION EMULATION
# ============================================================================

@pytest.mark.asyncio
async def test_room_13_supply_chain_lifecycle(db_session: Session, test_user: User):
    """Test all tasks and validation for Purple Room 13."""
    validator = TaskValidator()
    room_id = "purple-13-supply-chain-emulation"

    # Task 1: Mechanics
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-supply-chain-mechanics",
        TaskSubmission(task_id="task-01-supply-chain-mechanics", answer="Dependency Confusion")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Log analysis
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-supply-chain-telemetry-analysis",
        TaskSubmission(task_id="task-02-supply-chain-telemetry-analysis", answer="voltcorp-internal-auth")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: ATT&CK Mapping
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-supply-chain-mapping",
        TaskSubmission(task_id="task-03-attck-supply-chain-mapping", answer="T1195.001")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Task 4: Emulation (fails before practical action)
    res4_fail = validator.validate_submission(
        db_session, test_user, room_id, "task-04-supply-chain-emulation",
        TaskSubmission(task_id="task-04-supply-chain-emulation", answer="SUPPLY_CHAIN_EMULATION_VERIFIED")
    )
    assert res4_fail.is_correct is False
    assert "Investigation" in res4_fail.feedback

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple13_{test_user.operator_id}"
    session_info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = session_info

    try:
        # Execute emulation command
        cmd_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/supply_chain_tool.py --emulate-confusion")
        assert "SUPPLY_CHAIN_EMULATION_VERIFIED" in cmd_out
        assert session_info.has_action("supply_chain_emulated")

        res4_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-04-supply-chain-emulation",
            TaskSubmission(task_id="task-04-supply-chain-emulation", answer="SUPPLY_CHAIN_EMULATION_VERIFIED")
        )
        assert res4_pass.is_correct is True
        assert res4_pass.completed is True

        # Task 5 before challenge completion -> rejected
        res5_fail = validator.validate_submission(
            db_session, test_user, room_id, "task-05-supply-chain-challenge",
            TaskSubmission(task_id="task-05-supply-chain-challenge", answer="SUPPLY_CHAIN_DETECTION_VALIDATED")
        )
        assert res5_fail.is_correct is False

        # Tune pinning rule and complete challenge
        tune_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/supply_chain_tool.py --tune-pinning")
        assert "INTERNAL_PINNING_POLICY_ENFORCED" in tune_out

        chal_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/supply_chain_tool.py --challenge")
        assert "SUPPLY_CHAIN_DETECTION_VALIDATED" in chal_out
        assert session_info.has_action("supply_chain_detection_validated")

        res5_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-05-supply-chain-challenge",
            TaskSubmission(task_id="task-05-supply-chain-challenge", answer="SUPPLY_CHAIN_DETECTION_VALIDATED")
        )
        assert res5_pass.is_correct is True
        assert res5_pass.completed is True
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 3. ROOM 14: API ABUSE & BOLA EMULATION
# ============================================================================

@pytest.mark.asyncio
async def test_room_14_api_abuse_lifecycle(db_session: Session, test_user: User):
    """Test all tasks and validation for Purple Room 14."""
    validator = TaskValidator()
    room_id = "purple-14-api-abuse-emulation"

    # Task 1: Mechanics
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-bola-mechanics",
        TaskSubmission(task_id="task-01-bola-mechanics", answer="BOLA")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Log analysis
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-api-telemetry-analysis",
        TaskSubmission(task_id="task-02-api-telemetry-analysis", answer="ACC-9042")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: ATT&CK Mapping
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-api-mapping",
        TaskSubmission(task_id="task-03-attck-api-mapping", answer="T1190")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Task 4: Emulation (fails before execution)
    res4_fail = validator.validate_submission(
        db_session, test_user, room_id, "task-04-bola-emulation",
        TaskSubmission(task_id="task-04-bola-emulation", answer="BOLA_EMULATION_VERIFIED")
    )
    assert res4_fail.is_correct is False

    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple14_{test_user.operator_id}"
    session_info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = session_info

    try:
        cmd_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/api_abuse_tool.py --emulate-bola")
        assert "BOLA_EMULATION_VERIFIED" in cmd_out
        assert session_info.has_action("bola_emulated")

        res4_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-04-bola-emulation",
            TaskSubmission(task_id="task-04-bola-emulation", answer="BOLA_EMULATION_VERIFIED")
        )
        assert res4_pass.is_correct is True
        assert res4_pass.completed is True

        # Task 5: Challenge
        tune_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/api_abuse_tool.py --tune-gateway")
        assert "OBJECT_LEVEL_AUTHZ_ENFORCED" in tune_out

        chal_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/api_abuse_tool.py --challenge")
        assert "API_ABUSE_DETECTION_VALIDATED" in chal_out
        assert session_info.has_action("api_abuse_detection_validated")

        res5_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-05-api-detection-challenge",
            TaskSubmission(task_id="task-05-api-detection-challenge", answer="API_ABUSE_DETECTION_VALIDATED")
        )
        assert res5_pass.is_correct is True
        assert res5_pass.completed is True
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 4. ROOM 15: ACTIVE DIRECTORY ATTACKS EMULATION (KERBEROASTING)
# ============================================================================

@pytest.mark.asyncio
async def test_room_15_ad_attacks_lifecycle(db_session: Session, test_user: User):
    """Test all tasks and validation for Purple Room 15."""
    validator = TaskValidator()
    room_id = "purple-15-active-directory-attacks-emulation"

    # Task 1: Mechanics
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-kerberoasting-mechanics",
        TaskSubmission(task_id="task-01-kerberoasting-mechanics", answer="SPN")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Log analysis
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-ad-telemetry-analysis",
        TaskSubmission(task_id="task-02-ad-telemetry-analysis", answer="0x17")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: ATT&CK Mapping
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-ad-mapping",
        TaskSubmission(task_id="task-03-attck-ad-mapping", answer="T1558.003")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Task 4: Emulation (fails before execution)
    res4_fail = validator.validate_submission(
        db_session, test_user, room_id, "task-04-kerberoasting-emulation",
        TaskSubmission(task_id="task-04-kerberoasting-emulation", answer="KERBEROASTING_EMULATION_VERIFIED")
    )
    assert res4_fail.is_correct is False

    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple15_{test_user.operator_id}"
    session_info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = session_info

    try:
        cmd_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/ad_attacks_tool.py --emulate-kerberoast")
        assert "KERBEROASTING_EMULATION_VERIFIED" in cmd_out
        assert session_info.has_action("kerberoasting_emulated")

        res4_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-04-kerberoasting-emulation",
            TaskSubmission(task_id="task-04-kerberoasting-emulation", answer="KERBEROASTING_EMULATION_VERIFIED")
        )
        assert res4_pass.is_correct is True
        assert res4_pass.completed is True

        # Task 5: Challenge
        tune_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/ad_attacks_tool.py --tune-dc-rule")
        assert "KERBEROS_DETECTION_RULE_ACTIVATED" in tune_out

        chal_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/ad_attacks_tool.py --challenge")
        assert "AD_ATTACK_DETECTION_VALIDATED" in chal_out
        assert session_info.has_action("ad_attack_detection_validated")

        res5_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-05-ad-detection-challenge",
            TaskSubmission(task_id="task-05-ad-detection-challenge", answer="AD_ATTACK_DETECTION_VALIDATED")
        )
        assert res5_pass.is_correct is True
        assert res5_pass.completed is True
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 5. ROOM 16: CI/CD PIPELINE & GITHUB ACTIONS ATTACK EMULATION
# ============================================================================

@pytest.mark.asyncio
async def test_room_16_cicd_pipeline_lifecycle(db_session: Session, test_user: User):
    """Test all tasks and validation for Purple Room 16."""
    validator = TaskValidator()
    room_id = "purple-16-ci-cd-pipeline-emulation"

    # Task 1: Mechanics
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-cicd-mechanics",
        TaskSubmission(task_id="task-01-cicd-mechanics", answer="pull_request_target")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Log analysis
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-cicd-telemetry-analysis",
        TaskSubmission(task_id="task-02-cicd-telemetry-analysis", answer="DEPLOY_AWS_SECRET_KEY")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: ATT&CK Mapping
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-cicd-mapping",
        TaskSubmission(task_id="task-03-attck-cicd-mapping", answer="T1195.002")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Task 4: Emulation (fails before execution)
    res4_fail = validator.validate_submission(
        db_session, test_user, room_id, "task-04-cicd-emulation",
        TaskSubmission(task_id="task-04-cicd-emulation", answer="CICD_PIPELINE_EMULATION_VERIFIED")
    )
    assert res4_fail.is_correct is False

    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple16_{test_user.operator_id}"
    session_info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = session_info

    try:
        cmd_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/cicd_pipeline_tool.py --emulate-pipeline-attack")
        assert "CICD_PIPELINE_EMULATION_VERIFIED" in cmd_out
        assert session_info.has_action("cicd_pipeline_emulated")

        res4_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-04-cicd-emulation",
            TaskSubmission(task_id="task-04-cicd-emulation", answer="CICD_PIPELINE_EMULATION_VERIFIED")
        )
        assert res4_pass.is_correct is True
        assert res4_pass.completed is True

        # Task 5: Challenge
        tune_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/cicd_pipeline_tool.py --tune-pipeline-audit")
        assert "CI_PIPELINE_GUARDRAILS_ARMED" in tune_out

        chal_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/cicd_pipeline_tool.py --challenge")
        assert "CICD_PIPELINE_DETECTION_VALIDATED" in chal_out
        assert session_info.has_action("cicd_pipeline_detection_validated")

        res5_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-05-cicd-detection-challenge",
            TaskSubmission(task_id="task-05-cicd-detection-challenge", answer="CICD_PIPELINE_DETECTION_VALIDATED")
        )
        assert res5_pass.is_correct is True
        assert res5_pass.completed is True
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 6. ANTI-FORGERY VALIDATION FOR ROOMS 13–16
# ============================================================================

@pytest.mark.asyncio
async def test_purple_anti_forgery_rejection_13_16(test_user: User):
    """Verify forged commands (echo, printf, python print) do not record actions."""
    runner = ProcessLabRunner()
    sess_id = f"proc_forgery_{test_user.operator_id}"
    session_info = await runner.start_session(sess_id, "purple-13-supply-chain-emulation", test_user.operator_id)
    lab_manager._active_sessions[sess_id] = session_info

    try:
        # Echo attempts
        await runner.execute_command(sess_id, "echo 'SUPPLY_CHAIN_EMULATION_VERIFIED'")
        assert not session_info.has_action("supply_chain_emulated")

        await runner.execute_command(sess_id, "echo 'BOLA_EMULATION_VERIFIED'")
        assert not session_info.has_action("bola_emulated")

        await runner.execute_command(sess_id, "printf 'KERBEROASTING_EMULATION_VERIFIED\\n'")
        assert not session_info.has_action("kerberoasting_emulated")

        await runner.execute_command(sess_id, "python3 -c 'print(\"CICD_PIPELINE_EMULATION_VERIFIED\")'")
        assert not session_info.has_action("cicd_pipeline_emulated")
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 7. DUAL-SESSION CROSS-SESSION ISOLATION FOR ROOMS 13–16
# ============================================================================

@pytest.mark.asyncio
async def test_purple_dual_session_isolation_13_16(db_session: Session, test_user: User, second_user: User):
    """Actions performed in session A must NOT satisfy validation in session B."""
    validator = TaskValidator()
    runner = ProcessLabRunner()

    sess_a = f"proc_sess_a_{test_user.operator_id}"
    sess_b = f"proc_sess_b_{second_user.operator_id}"
    sess_a_info = await runner.start_session(sess_a, "purple-13-supply-chain-emulation", test_user.operator_id)
    sess_b_info = await runner.start_session(sess_b, "purple-13-supply-chain-emulation", second_user.operator_id)
    lab_manager._active_sessions[sess_a] = sess_a_info
    lab_manager._active_sessions[sess_b] = sess_b_info

    try:
        # User A executes supply chain emulation
        await runner.execute_command(sess_a, "python3 /home/operator/tools/supply_chain_tool.py --emulate-confusion")
        assert sess_a_info.has_action("supply_chain_emulated")
        assert not sess_b_info.has_action("supply_chain_emulated")

        # User B attempts to validate task 4 without executing it
        res_user_b = validator.validate_submission(
            db_session, second_user, "purple-13-supply-chain-emulation", "task-04-supply-chain-emulation",
            TaskSubmission(task_id="task-04-supply-chain-emulation", answer="SUPPLY_CHAIN_EMULATION_VERIFIED")
        )
        assert res_user_b.is_correct is False
        assert "Investigation" in res_user_b.feedback
    finally:
        await runner.stop_session(sess_a)
        await runner.stop_session(sess_b)
        lab_manager._active_sessions.pop(sess_a, None)
        lab_manager._active_sessions.pop(sess_b, None)


# ============================================================================
# 8. ASSESSMENT QUIZZES FOR ROOMS 13–16
# ============================================================================

def test_purple_rooms_13_16_quizzes(db_session: Session, test_user: User):
    """Verify each room's quiz has 4 questions and evaluates correctly."""
    validator = TaskValidator()
    quiz_rooms = [
        ("purple-13-supply-chain-emulation", "task-06-supply-chain-quiz"),
        ("purple-14-api-abuse-emulation", "task-06-api-quiz"),
        ("purple-15-active-directory-attacks-emulation", "task-06-ad-quiz"),
        ("purple-16-ci-cd-pipeline-emulation", "task-06-cicd-quiz"),
    ]
    for rid, task_id in quiz_rooms:
        room = curriculum_registry.get_room(rid)
        quiz_task = room.tasks[-1]
        assert quiz_task.task_id == task_id
        assert len(quiz_task.quiz_questions) == 4

        # Wrong quiz submission first
        res_fail = validator.validate_submission(
            db_session, test_user, rid, task_id,
            TaskSubmission(task_id=task_id, quiz_answers={"q1": 1, "q2": 2, "q3": 3, "q4": 1})
        )
        assert res_fail.is_correct is False

        # Correct quiz submission (all index 0)
        res_ok = validator.validate_submission(
            db_session, test_user, rid, task_id,
            TaskSubmission(task_id=task_id, quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0})
        )
        assert res_ok.is_correct is True, f"Quiz failed for {rid}"
        assert res_ok.completed is True
