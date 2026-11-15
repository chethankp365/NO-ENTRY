"""
Unit and Emulated Integration Tests for Detection Engineering Rooms 01–04:
- Room 01: Detection Engineering Foundations & Detection-as-Code (detect-01-foundations-as-code)
- Room 02: Log Normalization & Taxonomy (ECS & CIM) (detect-02-log-normalization)
- Room 03: Sigma Rule Syntax & Component Structure (detect-03-sigma-syntax)
- Room 04: Writing Process Creation Rules (Sysmon Event ID 1) (detect-04-process-creation-rules)

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
        username="detection_engineer_0104",
        email="detection_engineer_0104@noentry.internal",
        operator_id="OP-DETECT-0104-UNIT",
        hashed_password="dummy_test_hash_detection",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(name="second_user")
def second_user_fixture(db_session: Session):
    user = User(
        username="detection_operator_isolate",
        email="detection_operator_isolate@noentry.internal",
        operator_id="OP-DETECT-ISOLATE-UNIT",
        hashed_password="dummy_test_hash_detect_isolate",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


# ============================================================================
# 1. CURRICULUM REGISTRATION & DETECTION TRACK TOTALS
# ============================================================================

def test_rooms_detection_01_04_curriculum_registration():
    """Verify Detection Rooms 01-04 are fully registered and configured in the curriculum."""
    for r_num in (1, 2, 3, 4):
        room = curriculum_registry.get_room(f"detect-0{r_num}")
        assert room is not None, f"Detection Room 0{r_num} not found"
        assert room.room_number == r_num
        assert room.track == TrackEnum.DETECTION
        assert room.status == RoomStatus.IMPLEMENTED
        assert len(room.tasks) == 6
        assert room.total_xp == 350
        assert room.concept is not None
        assert room.concept.technical_term
        assert room.concept.overview
        assert "toddler" not in room.concept.simple_analogy.lower()
        assert "baby" not in room.concept.simple_analogy.lower()

    # Verify track statistics
    detect_rooms = curriculum_registry.list_rooms(track=TrackEnum.DETECTION)
    assert len(detect_rooms) == 20
    implemented_detect = [r for r in detect_rooms if r.status == RoomStatus.IMPLEMENTED]
    planned_detect = [r for r in detect_rooms if r.status == RoomStatus.PLANNED]
    assert len(implemented_detect) >= 4
    assert len(planned_detect) <= 16

    counts = curriculum_registry.get_track_counts()
    assert counts["detection"]["total"] == 20
    assert counts["detection"]["implemented"] >= 4
    assert counts["detection"]["planned"] <= 16


# ============================================================================
# 2. ROOM 01: DETECTION ENGINEERING FOUNDATIONS & DAC LIFECYCLE
# ============================================================================

@pytest.mark.asyncio
async def test_room_01_detection_foundations_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 01."""
    validator = TaskValidator()
    room_id = "detect-01-foundations-as-code"

    # Task 1: Pyramid of Pain top tier
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-dac-mechanics",
        TaskSubmission(task_id="task-01-dac-mechanics", answer="TTPs")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Failed rule ID in pipeline
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-ddlc-telemetry-analysis",
        TaskSubmission(task_id="task-02-ddlc-telemetry-analysis", answer="RULE-DAC-104")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: Enterprise taxonomy
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-detection-mapping",
        TaskSubmission(task_id="task-03-attck-detection-mapping", answer="MITRE ATT&CK")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Task 4 without active lab -> rejected
    res4_fail = validator.validate_submission(
        db_session, test_user, room_id, "task-04-dac-pipeline-emulation",
        TaskSubmission(task_id="task-04-dac-pipeline-emulation", answer="DETECTION_FOUNDATIONS_VERIFIED")
    )
    assert res4_fail.is_correct is False
    assert "Investigation required" in res4_fail.feedback

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect01_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Run tool to emulate pipeline
        out_emulate = await runner.execute_command(sess_id, "python3 /home/operator/tools/detection_foundations_tool.py --emulate-pipeline")
        assert "DETECTION_FOUNDATIONS_VERIFIED" in out_emulate

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-dac-pipeline-emulation",
            TaskSubmission(task_id="task-04-dac-pipeline-emulation", answer="DETECTION_FOUNDATIONS_VERIFIED")
        )
        assert res4.is_correct is True
        assert res4.completed is True

        # Tune SNR
        out_tune = await runner.execute_command(sess_id, "python3 /home/operator/tools/detection_foundations_tool.py --tune-snr")
        assert "SNR_TUNED_OK" in out_tune

        # Finalize challenge
        out_chall = await runner.execute_command(sess_id, "python3 /home/operator/tools/detection_foundations_tool.py --challenge")
        assert "DETECTION_FOUNDATIONS_VALIDATED" in out_chall

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-dac-challenge",
            TaskSubmission(task_id="task-05-dac-challenge", answer="DETECTION_FOUNDATIONS_VALIDATED")
        )
        assert res5.is_correct is True
        assert res5.completed is True

        # Quiz
        quiz_sub = TaskSubmission(
            task_id="task-06-detection-foundations-quiz",
            answer="",
            quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0}
        )
        res6 = validator.validate_submission(db_session, test_user, room_id, "task-06-detection-foundations-quiz", quiz_sub)
        assert res6.is_correct is True
        assert res6.completed is True
        assert res6.room_completed is True
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 3. ROOM 02: LOG NORMALIZATION & TAXONOMY (ECS & CIM)
# ============================================================================

@pytest.mark.asyncio
async def test_room_02_log_normalization_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 02."""
    validator = TaskValidator()
    room_id = "detect-02-log-normalization"

    # Task 1: ECS
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-normalization-foundations",
        TaskSubmission(task_id="task-01-normalization-foundations", answer="Elastic Common Schema")
    )
    assert res1.is_correct is True

    # Task 2: process.executable
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-schema-mapping-analysis",
        TaskSubmission(task_id="task-02-schema-mapping-analysis", answer="process.executable")
    )
    assert res2.is_correct is True

    # Task 3: Common Information Model
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-splunk-cim-mapping",
        TaskSubmission(task_id="task-03-splunk-cim-mapping", answer="Common Information Model")
    )
    assert res3.is_correct is True

    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect02_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Emulate normalization
        out_emulate = await runner.execute_command(sess_id, "python3 /home/operator/tools/log_normalization_tool.py --emulate-normalization")
        assert "LOG_NORMALIZATION_VERIFIED" in out_emulate

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-normalization-emulation",
            TaskSubmission(task_id="task-04-normalization-emulation", answer="LOG_NORMALIZATION_VERIFIED")
        )
        assert res4.is_correct is True

        # Tune taxonomy
        out_tune = await runner.execute_command(sess_id, "python3 /home/operator/tools/log_normalization_tool.py --tune-taxonomy")
        assert "TAXONOMY_TUNED_OK" in out_tune

        # Challenge
        out_chall = await runner.execute_command(sess_id, "python3 /home/operator/tools/log_normalization_tool.py --challenge")
        assert "LOG_NORMALIZATION_VALIDATED" in out_chall

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-normalization-challenge",
            TaskSubmission(task_id="task-05-normalization-challenge", answer="LOG_NORMALIZATION_VALIDATED")
        )
        assert res5.is_correct is True

        # Quiz
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-normalization-quiz",
            TaskSubmission(task_id="task-06-normalization-quiz", answer="", quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0})
        )
        assert res6.is_correct is True
        assert res6.room_completed is True
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 4. ROOM 03: SIGMA RULE SYNTAX & COMPONENT STRUCTURE
# ============================================================================

@pytest.mark.asyncio
async def test_room_03_sigma_syntax_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 03."""
    validator = TaskValidator()
    room_id = "detect-03-sigma-syntax"

    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-sigma-structure-foundations",
        TaskSubmission(task_id="task-01-sigma-structure-foundations", answer="logsource")
    )
    assert res1.is_correct is True

    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-sigma-modifier-analysis",
        TaskSubmission(task_id="task-02-sigma-modifier-analysis", answer="contains")
    )
    assert res2.is_correct is True

    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-sigma-condition-logic",
        TaskSubmission(task_id="task-03-sigma-condition-logic", answer="selection and not filter")
    )
    assert res3.is_correct is True

    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect03_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        out_emulate = await runner.execute_command(sess_id, "python3 /home/operator/tools/sigma_syntax_tool.py --emulate-parser")
        assert "SIGMA_SYNTAX_VERIFIED" in out_emulate

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-sigma-syntax-emulation",
            TaskSubmission(task_id="task-04-sigma-syntax-emulation", answer="SIGMA_SYNTAX_VERIFIED")
        )
        assert res4.is_correct is True

        out_tune = await runner.execute_command(sess_id, "python3 /home/operator/tools/sigma_syntax_tool.py --tune-condition")
        assert "CONDITION_TUNED_OK" in out_tune

        out_chall = await runner.execute_command(sess_id, "python3 /home/operator/tools/sigma_syntax_tool.py --challenge")
        assert "SIGMA_SYNTAX_VALIDATED" in out_chall

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-sigma-syntax-challenge",
            TaskSubmission(task_id="task-05-sigma-syntax-challenge", answer="SIGMA_SYNTAX_VALIDATED")
        )
        assert res5.is_correct is True

        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-sigma-syntax-quiz",
            TaskSubmission(task_id="task-06-sigma-syntax-quiz", answer="", quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0})
        )
        assert res6.is_correct is True
        assert res6.room_completed is True
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 5. ROOM 04: WRITING PROCESS CREATION RULES (SYSMON EVENT ID 1)
# ============================================================================

@pytest.mark.asyncio
async def test_room_04_process_creation_rules_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 04."""
    validator = TaskValidator()
    room_id = "detect-04-process-creation-rules"

    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-sysmon-event1-mechanics",
        TaskSubmission(task_id="task-01-sysmon-event1-mechanics", answer="1")
    )
    assert res1.is_correct is True

    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-lolbin-telemetry-analysis",
        TaskSubmission(task_id="task-02-lolbin-telemetry-analysis", answer="-urlcache")
    )
    assert res2.is_correct is True

    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-lolbin-mapping",
        TaskSubmission(task_id="task-03-attck-lolbin-mapping", answer="T1105")
    )
    assert res3.is_correct is True

    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect04_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        out_emulate = await runner.execute_command(sess_id, "python3 /home/operator/tools/process_creation_tool.py --emulate-detection")
        assert "PROCESS_CREATION_VERIFIED" in out_emulate

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-process-creation-emulation",
            TaskSubmission(task_id="task-04-process-creation-emulation", answer="PROCESS_CREATION_VERIFIED")
        )
        assert res4.is_correct is True

        out_tune = await runner.execute_command(sess_id, "python3 /home/operator/tools/process_creation_tool.py --tune-lolbin-filter")
        assert "LOLBIN_FILTER_TUNED_OK" in out_tune

        out_chall = await runner.execute_command(sess_id, "python3 /home/operator/tools/process_creation_tool.py --challenge")
        assert "PROCESS_CREATION_VALIDATED" in out_chall

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-process-creation-challenge",
            TaskSubmission(task_id="task-05-process-creation-challenge", answer="PROCESS_CREATION_VALIDATED")
        )
        assert res5.is_correct is True

        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-process-creation-quiz",
            TaskSubmission(task_id="task-06-process-creation-quiz", answer="", quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0})
        )
        assert res6.is_correct is True
        assert res6.room_completed is True
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 6. ANTI-FORGERY & SECURITY AUDIT (ECHO / PRINTF REJECTION)
# ============================================================================

@pytest.mark.asyncio
async def test_anti_forgery_spoofing_rejected(db_session: Session, test_user: User):
    """Verify that forged echo/printf commands cannot trigger verification actions."""
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect_forge_{test_user.operator_id}"
    room_id = "detect-01-foundations-as-code"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Attempt to spoof token with echo
        out_forge = await runner.execute_command(sess_id, 'echo "DETECTION_FOUNDATIONS_VERIFIED"')
        assert "DETECTION_FOUNDATIONS_VERIFIED" in out_forge
        assert not info.has_action("detection_foundations_verified")

        # Attempt to spoof with printf
        out_printf = await runner.execute_command(sess_id, 'printf "DETECTION_FOUNDATIONS_VALIDATED\\n"')
        assert "DETECTION_FOUNDATIONS_VALIDATED" in out_printf
        assert not info.has_action("detection_foundations_validated")
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 7. CROSS-SESSION ISOLATION (DUAL OPERATOR TEST)
# ============================================================================

@pytest.mark.asyncio
async def test_dual_session_cross_session_isolation(db_session: Session, test_user: User, second_user: User):
    """Verify complete isolation between two distinct operator lab sessions."""
    runner = ProcessLabRunner()
    validator = TaskValidator()
    room_id = "detect-04-process-creation-rules"

    sess_1 = f"proc_isolate_detect1_{test_user.operator_id}"
    sess_2 = f"proc_isolate_detect2_{second_user.operator_id}"

    info_1 = await runner.start_session(sess_1, room_id, test_user.operator_id)
    info_2 = await runner.start_session(sess_2, room_id, second_user.operator_id)
    lab_manager._active_sessions[sess_1] = info_1
    lab_manager._active_sessions[sess_2] = info_2

    try:
        # Operator 1 performs the required emulation action
        await runner.execute_command(sess_1, "python3 /home/operator/tools/process_creation_tool.py --emulate-detection")
        assert info_1.has_action("process_creation_verified")
        assert not info_2.has_action("process_creation_verified")

        # Operator 1 can validate
        res1 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-process-creation-emulation",
            TaskSubmission(task_id="task-04-process-creation-emulation", answer="PROCESS_CREATION_VERIFIED")
        )
        assert res1.is_correct is True

        # Operator 2 CANNOT validate Task 4 because their session hasn't completed the action
        res2 = validator.validate_submission(
            db_session, second_user, room_id, "task-04-process-creation-emulation",
            TaskSubmission(task_id="task-04-process-creation-emulation", answer="PROCESS_CREATION_VERIFIED")
        )
        assert res2.is_correct is False
        assert "Investigation incomplete" in res2.feedback or "not been verified" in res2.feedback
    finally:
        await runner.stop_session(sess_1)
        await runner.stop_session(sess_2)
        lab_manager._active_sessions.pop(sess_1, None)
        lab_manager._active_sessions.pop(sess_2, None)
