"""
Unit and Emulated Integration Tests for Final Purple Team Rooms 17–20:
- Room 17: EDR Telemetry Blinding & Bypass Emulation (purple-17-edr-bypass-emulation)
- Room 18: TTP Heatmap Generation & Coverage Scoring (purple-18-ttp-heatmap-generation)
- Room 19: Continuous Security Validation & Automated Testing (purple-19-continuous-security-validation)
- Room 20: Purple Team Capstone: Full Adversary Emulation Exercise (purple-20-capstone-purple-exercise)

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
        username="purple_operator_1720",
        email="purple_operator_1720@noentry.internal",
        operator_id="OP-PURPLE-1720-UNIT",
        hashed_password="dummy_test_hash_purple_1720",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(name="second_user")
def second_user_fixture(db_session: Session):
    user = User(
        username="purple_operator_isolate_1720",
        email="purple_operator_isolate_1720@noentry.internal",
        operator_id="OP-PURPLE-ISOLATE-1720",
        hashed_password="dummy_test_hash_purple_isolate_1720",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


# ============================================================================
# 1. CURRICULUM REGISTRATION & TRACK TOTALS
# ============================================================================

def test_rooms_purple_17_20_curriculum_registration():
    """Verify Rooms 17–20 exist, are marked IMPLEMENTED, have 6 tasks, and full track count is 60."""
    room_ids = [
        "purple-17-edr-bypass-emulation",
        "purple-18-ttp-heatmap-generation",
        "purple-19-continuous-security-validation",
        "purple-20-capstone-purple-exercise",
    ]
    for rid in room_ids:
        r = curriculum_registry.get_room(rid)
        assert r is not None, f"Room {rid} not found in curriculum"
        assert r.status == RoomStatus.IMPLEMENTED
        assert r.track == TrackEnum.PURPLE
        assert len(r.tasks) == 6
        assert r.concept is not None
        assert "toddler" not in r.concept.simple_analogy.lower()
        assert "baby" not in r.concept.simple_analogy.lower()

    # Verify track totals across platform
    counts = curriculum_registry.get_track_counts()
    assert counts["red"]["implemented"] == 20
    assert counts["red"]["planned"] == 0
    assert counts["blue"]["implemented"] == 20
    assert counts["blue"]["planned"] == 0
    assert counts["purple"]["implemented"] == 20
    assert counts["purple"]["planned"] == 0
    assert counts["detection"]["total"] == 20

    all_rooms = curriculum_registry.list_rooms()
    implemented_rooms = [r for r in all_rooms if r.status == RoomStatus.IMPLEMENTED]
    assert len(implemented_rooms) >= 60
    assert len(all_rooms) == 80


# ============================================================================
# 2. ROOM 17 LIFECYCLE: EDR TELEMETRY BLINDING & BYPASS EMULATION
# ============================================================================

@pytest.mark.asyncio
async def test_room_17_edr_bypass_lifecycle(db_session: Session, test_user: User):
    """Test all tasks and validation for Purple Room 17."""
    validator = TaskValidator()
    room_id = "purple-17-edr-bypass-emulation"

    # Task 1: Mechanics
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-edr-hooking-mechanics",
        TaskSubmission(task_id="task-01-edr-hooking-mechanics", answer="AMSI")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Telemetry analysis
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-edr-telemetry-analysis",
        TaskSubmission(task_id="task-02-edr-telemetry-analysis", answer="AmsiScanBuffer")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: ATT&CK Mapping
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-edr-mapping",
        TaskSubmission(task_id="task-03-attck-edr-mapping", answer="T1562.001")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Task 4: Emulation (fails before practical action)
    res4_fail = validator.validate_submission(
        db_session, test_user, room_id, "task-04-edr-bypass-emulation",
        TaskSubmission(task_id="task-04-edr-bypass-emulation", answer="EDR_BYPASS_EMULATION_VERIFIED")
    )
    assert res4_fail.is_correct is False
    assert "Investigation" in res4_fail.feedback

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple17_{test_user.operator_id}"
    session_info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = session_info

    try:
        # Execute emulation command
        cmd_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/edr_bypass_tool.py --emulate-bypass")
        assert "EDR_BYPASS_EMULATION_VERIFIED" in cmd_out
        assert session_info.has_action("edr_bypass_emulated")

        res4_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-04-edr-bypass-emulation",
            TaskSubmission(task_id="task-04-edr-bypass-emulation", answer="EDR_BYPASS_EMULATION_VERIFIED")
        )
        assert res4_pass.is_correct is True
        assert res4_pass.completed is True

        # Task 5 before challenge completion -> rejected
        res5_fail = validator.validate_submission(
            db_session, test_user, room_id, "task-05-edr-bypass-challenge",
            TaskSubmission(task_id="task-05-edr-bypass-challenge", answer="EDR_BYPASS_DETECTION_VALIDATED")
        )
        assert res5_fail.is_correct is False

        # Tune ETW rule and complete challenge
        tune_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/edr_bypass_tool.py --tune-etw")
        assert "ETW_TUNED_OK" in tune_out

        chal_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/edr_bypass_tool.py --challenge")
        assert "EDR_BYPASS_DETECTION_VALIDATED" in chal_out
        assert session_info.has_action("edr_bypass_detection_validated")

        res5_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-05-edr-bypass-challenge",
            TaskSubmission(task_id="task-05-edr-bypass-challenge", answer="EDR_BYPASS_DETECTION_VALIDATED")
        )
        assert res5_pass.is_correct is True
        assert res5_pass.completed is True
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 3. ROOM 18 LIFECYCLE: TTP HEATMAP GENERATION & COVERAGE SCORING
# ============================================================================

@pytest.mark.asyncio
async def test_room_18_heatmap_lifecycle(db_session: Session, test_user: User):
    """Test all tasks and validation for Purple Room 18."""
    validator = TaskValidator()
    room_id = "purple-18-ttp-heatmap-generation"

    # Task 1: Foundations
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-heatmap-foundations",
        TaskSubmission(task_id="task-01-heatmap-foundations", answer="ATT&CK Navigator")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Matrix coverage analysis
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-matrix-coverage-analysis",
        TaskSubmission(task_id="task-02-matrix-coverage-analysis", answer="T1003")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: ATT&CK Coverage metrics
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-coverage-metrics",
        TaskSubmission(task_id="task-03-attck-coverage-metrics", answer="Detection Coverage")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Task 4: Emulation (fails before practical action)
    res4_fail = validator.validate_submission(
        db_session, test_user, room_id, "task-04-heatmap-emulation",
        TaskSubmission(task_id="task-04-heatmap-emulation", answer="HEATMAP_EMULATION_VERIFIED")
    )
    assert res4_fail.is_correct is False
    assert "Investigation" in res4_fail.feedback

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple18_{test_user.operator_id}"
    session_info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = session_info

    try:
        # Execute emulation command
        cmd_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/heatmap_tool.py --emulate-scoring")
        assert "HEATMAP_EMULATION_VERIFIED" in cmd_out
        assert session_info.has_action("heatmap_emulated")

        res4_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-04-heatmap-emulation",
            TaskSubmission(task_id="task-04-heatmap-emulation", answer="HEATMAP_EMULATION_VERIFIED")
        )
        assert res4_pass.is_correct is True
        assert res4_pass.completed is True

        # Task 5 before challenge completion -> rejected
        res5_fail = validator.validate_submission(
            db_session, test_user, room_id, "task-05-heatmap-challenge",
            TaskSubmission(task_id="task-05-heatmap-challenge", answer="HEATMAP_COVERAGE_VALIDATED")
        )
        assert res5_fail.is_correct is False

        # Tune overlay and complete challenge
        tune_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/heatmap_tool.py --tune-overlay")
        assert "OVERLAY_TUNED_OK" in tune_out

        chal_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/heatmap_tool.py --challenge")
        assert "HEATMAP_COVERAGE_VALIDATED" in chal_out
        assert session_info.has_action("heatmap_coverage_validated")

        res5_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-05-heatmap-challenge",
            TaskSubmission(task_id="task-05-heatmap-challenge", answer="HEATMAP_COVERAGE_VALIDATED")
        )
        assert res5_pass.is_correct is True
        assert res5_pass.completed is True
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 4. ROOM 19 LIFECYCLE: CONTINUOUS SECURITY VALIDATION
# ============================================================================

@pytest.mark.asyncio
async def test_room_19_continuous_validation_lifecycle(db_session: Session, test_user: User):
    """Test all tasks and validation for Purple Room 19."""
    validator = TaskValidator()
    room_id = "purple-19-continuous-security-validation"

    # Task 1: Foundations
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-continuous-validation-foundations",
        TaskSubmission(task_id="task-01-continuous-validation-foundations", answer="Atomic Red Team")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Pipeline run telemetry
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-pipeline-run-telemetry",
        TaskSubmission(task_id="task-02-pipeline-run-telemetry", answer="T1059.001")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: ATT&CK Automation metrics
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-automation-metrics",
        TaskSubmission(task_id="task-03-attck-automation-metrics", answer="MTTD")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Task 4: Emulation (fails before practical action)
    res4_fail = validator.validate_submission(
        db_session, test_user, room_id, "task-04-continuous-validation-emulation",
        TaskSubmission(task_id="task-04-continuous-validation-emulation", answer="CONTINUOUS_VALIDATION_EMULATION_VERIFIED")
    )
    assert res4_fail.is_correct is False
    assert "Investigation" in res4_fail.feedback

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple19_{test_user.operator_id}"
    session_info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = session_info

    try:
        # Execute emulation command
        cmd_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/continuous_validation_tool.py --emulate-pipeline")
        assert "CONTINUOUS_VALIDATION_EMULATION_VERIFIED" in cmd_out
        assert session_info.has_action("continuous_validation_emulated")

        res4_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-04-continuous-validation-emulation",
            TaskSubmission(task_id="task-04-continuous-validation-emulation", answer="CONTINUOUS_VALIDATION_EMULATION_VERIFIED")
        )
        assert res4_pass.is_correct is True
        assert res4_pass.completed is True

        # Task 5 before challenge completion -> rejected
        res5_fail = validator.validate_submission(
            db_session, test_user, room_id, "task-05-continuous-validation-challenge",
            TaskSubmission(task_id="task-05-continuous-validation-challenge", answer="CONTINUOUS_VALIDATION_DETECTION_VALIDATED")
        )
        assert res5_fail.is_correct is False

        # Tune guardrails and complete challenge
        tune_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/continuous_validation_tool.py --tune-guardrails")
        assert "GUARDRAILS_TUNED_OK" in tune_out

        chal_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/continuous_validation_tool.py --challenge")
        assert "CONTINUOUS_VALIDATION_DETECTION_VALIDATED" in chal_out
        assert session_info.has_action("continuous_validation_detection_validated")

        res5_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-05-continuous-validation-challenge",
            TaskSubmission(task_id="task-05-continuous-validation-challenge", answer="CONTINUOUS_VALIDATION_DETECTION_VALIDATED")
        )
        assert res5_pass.is_correct is True
        assert res5_pass.completed is True
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 5. ROOM 20 LIFECYCLE: PURPLE TEAM CAPSTONE
# ============================================================================

@pytest.mark.asyncio
async def test_room_20_capstone_lifecycle(db_session: Session, test_user: User):
    """Test all tasks and validation for Purple Team Capstone (Room 20)."""
    validator = TaskValidator()
    room_id = "purple-20-capstone-purple-exercise"

    # Task 1: Threat intel
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-capstone-threat-intel",
        TaskSubmission(task_id="task-01-capstone-threat-intel", answer="APT29")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Campaign telemetry
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-capstone-campaign-telemetry",
        TaskSubmission(task_id="task-02-capstone-campaign-telemetry", answer="CMP-2026-APT29")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: ATT&CK Correlation
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-capstone-attck-correlation",
        TaskSubmission(task_id="task-03-capstone-attck-correlation", answer="Adversary Emulation Plan")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Task 4: Emulation (fails before practical action)
    res4_fail = validator.validate_submission(
        db_session, test_user, room_id, "task-04-capstone-emulation",
        TaskSubmission(task_id="task-04-capstone-emulation", answer="PURPLE_CAPSTONE_EMULATION_VERIFIED")
    )
    assert res4_fail.is_correct is False
    assert "Investigation" in res4_fail.feedback

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple20_{test_user.operator_id}"
    session_info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = session_info

    try:
        # Execute emulation command
        cmd_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/purple_capstone_tool.py --emulate-campaign")
        assert "PURPLE_CAPSTONE_EMULATION_VERIFIED" in cmd_out
        assert session_info.has_action("purple_capstone_emulated")

        res4_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-04-capstone-emulation",
            TaskSubmission(task_id="task-04-capstone-emulation", answer="PURPLE_CAPSTONE_EMULATION_VERIFIED")
        )
        assert res4_pass.is_correct is True
        assert res4_pass.completed is True

        # Task 5 before challenge completion -> rejected
        res5_fail = validator.validate_submission(
            db_session, test_user, room_id, "task-05-capstone-challenge",
            TaskSubmission(task_id="task-05-capstone-challenge", answer="PURPLE_CAPSTONE_DETECTION_VALIDATED")
        )
        assert res5_fail.is_correct is False

        # Tune enterprise rules and complete challenge
        tune_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/purple_capstone_tool.py --tune-enterprise-rules")
        assert "ENTERPRISE_RULES_TUNED_OK" in tune_out

        chal_out = await runner.execute_command(sess_id, "python3 /home/operator/tools/purple_capstone_tool.py --challenge")
        assert "PURPLE_CAPSTONE_DETECTION_VALIDATED" in chal_out
        assert session_info.has_action("purple_capstone_detection_validated")

        res5_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-05-capstone-challenge",
            TaskSubmission(task_id="task-05-capstone-challenge", answer="PURPLE_CAPSTONE_DETECTION_VALIDATED")
        )
        assert res5_pass.is_correct is True
        assert res5_pass.completed is True
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 6. ANTI-FORGERY VALIDATION FOR ROOMS 17–20
# ============================================================================

@pytest.mark.asyncio
async def test_purple_anti_forgery_rejection_17_20(test_user: User):
    """Verify forged commands (echo, printf, python print) do not record actions."""
    runner = ProcessLabRunner()
    sess_id = f"proc_forgery_{test_user.operator_id}"
    session_info = await runner.start_session(sess_id, "purple-17-edr-bypass-emulation", test_user.operator_id)
    lab_manager._active_sessions[sess_id] = session_info

    try:
        # Echo attempts
        await runner.execute_command(sess_id, "echo 'EDR_BYPASS_EMULATION_VERIFIED'")
        assert not session_info.has_action("edr_bypass_emulated")

        await runner.execute_command(sess_id, "echo 'HEATMAP_EMULATION_VERIFIED'")
        assert not session_info.has_action("heatmap_emulated")

        await runner.execute_command(sess_id, "printf 'CONTINUOUS_VALIDATION_EMULATION_VERIFIED\\n'")
        assert not session_info.has_action("continuous_validation_emulated")

        await runner.execute_command(sess_id, "python3 -c 'print(\"PURPLE_CAPSTONE_EMULATION_VERIFIED\")'")
        assert not session_info.has_action("purple_capstone_emulated")
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 7. DUAL-SESSION CROSS-SESSION ISOLATION FOR ROOMS 17–20
# ============================================================================

@pytest.mark.asyncio
async def test_purple_dual_session_isolation_17_20(db_session: Session, test_user: User, second_user: User):
    """Actions performed in session A must NOT satisfy validation in session B."""
    validator = TaskValidator()
    runner = ProcessLabRunner()

    sess_a = f"proc_sess_a_{test_user.operator_id}"
    sess_b = f"proc_sess_b_{second_user.operator_id}"
    sess_a_info = await runner.start_session(sess_a, "purple-17-edr-bypass-emulation", test_user.operator_id)
    sess_b_info = await runner.start_session(sess_b, "purple-17-edr-bypass-emulation", second_user.operator_id)
    lab_manager._active_sessions[sess_a] = sess_a_info
    lab_manager._active_sessions[sess_b] = sess_b_info

    try:
        # User A executes EDR bypass emulation
        await runner.execute_command(sess_a, "python3 /home/operator/tools/edr_bypass_tool.py --emulate-bypass")
        assert sess_a_info.has_action("edr_bypass_emulated")
        assert not sess_b_info.has_action("edr_bypass_emulated")

        # User B attempts to validate task 4 without executing it
        res_user_b = validator.validate_submission(
            db_session, second_user, "purple-17-edr-bypass-emulation", "task-04-edr-bypass-emulation",
            TaskSubmission(task_id="task-04-edr-bypass-emulation", answer="EDR_BYPASS_EMULATION_VERIFIED")
        )
        assert res_user_b.is_correct is False
        assert "Investigation" in res_user_b.feedback
    finally:
        await runner.stop_session(sess_a)
        await runner.stop_session(sess_b)
        lab_manager._active_sessions.pop(sess_a, None)
        lab_manager._active_sessions.pop(sess_b, None)


# ============================================================================
# 8. ASSESSMENT QUIZZES FOR ROOMS 17–20
# ============================================================================

def test_purple_rooms_17_20_quizzes(db_session: Session, test_user: User):
    """Verify each room's quiz has 4 questions and evaluates correctly."""
    validator = TaskValidator()
    quiz_rooms = [
        ("purple-17-edr-bypass-emulation", "task-06-edr-quiz"),
        ("purple-18-ttp-heatmap-generation", "task-06-heatmap-quiz"),
        ("purple-19-continuous-security-validation", "task-06-continuous-val-quiz"),
        ("purple-20-capstone-purple-exercise", "task-06-purple-capstone-quiz"),
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

