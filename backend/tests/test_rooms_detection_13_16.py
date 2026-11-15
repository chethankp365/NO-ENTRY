"""
Unit and Emulated Integration Tests for Detection Engineering Rooms 13–16:
- Room 13: Baseline Profiling & Threshold-Based Detections (detect-13-threshold-detections)
- Room 14: Correlation Rules: Multi-Event Detection (detect-14-correlation-rules)
- Room 15: Detection Testing with Unit Tests & Synthetic Logs (detect-15-unit-testing-rules)
- Room 16: YARA Rules for File & Memory Threat Hunting (detect-16-yara-hunting)

Validates curriculum integration, task validation engine, anti-forgery guards,
prerequisite enforcement, trusted-session identity, and dual-session cross-isolation.
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
        username="detection_engineer_1316",
        email="detection_engineer_1316@noentry.internal",
        operator_id="OP-DETECT-1316-UNIT",
        hashed_password="dummy_test_hash_detection_1316",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(name="second_user")
def second_user_fixture(db_session: Session):
    user = User(
        username="detection_operator_isolate_1316",
        email="detection_operator_isolate_1316@noentry.internal",
        operator_id="OP-DETECT-ISOLATE-1316",
        hashed_password="dummy_test_hash_detect_isolate_1316",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


# ============================================================================
# 1. CURRICULUM REGISTRATION & DETECTION TRACK TOTALS
# ============================================================================

def test_rooms_detection_13_16_curriculum_registration():
    """Verify Detection Rooms 13-16 are fully registered and configured in the curriculum."""
    for r_num in (13, 14, 15, 16):
        room_alias = f"detect-{r_num:02d}"
        room = curriculum_registry.get_room(room_alias)
        assert room is not None, f"Detection Room {room_alias} not found"
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

    # Verify track statistics across platform
    all_rooms = curriculum_registry.list_rooms()
    assert len(all_rooms) == 80
    implemented_all = [r for r in all_rooms if r.status == RoomStatus.IMPLEMENTED]
    planned_all = [r for r in all_rooms if r.status == RoomStatus.PLANNED]
    assert len(implemented_all) >= 76
    assert len(planned_all) <= 4

    detect_rooms = curriculum_registry.list_rooms(track=TrackEnum.DETECTION)
    assert len(detect_rooms) == 20
    implemented_detect = [r for r in detect_rooms if r.status == RoomStatus.IMPLEMENTED]
    planned_detect = [r for r in detect_rooms if r.status == RoomStatus.PLANNED]
    assert len(implemented_detect) >= 16
    assert len(planned_detect) <= 4

    counts = curriculum_registry.get_track_counts()
    assert counts["detection"]["total"] == 20
    assert counts["detection"]["implemented"] >= 16
    assert counts["detection"]["planned"] <= 4


# ============================================================================
# 2. ROOM 13: BASELINE PROFILING & THRESHOLD-BASED DETECTIONS LIFECYCLE
# ============================================================================

@pytest.mark.asyncio
async def test_room_13_threshold_detections_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 13."""
    validator = TaskValidator()
    room_id = "detect-13-threshold-detections"

    # Task 1: Statistical metric
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-threshold-metric-mechanics",
        TaskSubmission(task_id="task-01-threshold-metric-mechanics", answer="standard deviation")
    )
    assert res1.is_correct is True

    # Task 2: Baseline threshold count
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-sliding-window-analysis",
        TaskSubmission(task_id="task-02-sliding-window-analysis", answer="50")
    )
    assert res2.is_correct is True

    # Task 3: MITRE ATT&CK Password Spraying
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-threshold-mapping",
        TaskSubmission(task_id="task-03-attck-threshold-mapping", answer="T1110.003")
    )
    assert res3.is_correct is True

    # Start lab session for practical tasks
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect13_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Task 4: Emulate threshold detection
        emulate_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/threshold_tool.py --emulate-detection"
        )
        assert "THRESHOLD_DETECTION_VERIFIED" in emulate_out
        assert info.has_action("threshold_detection_verified")

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-threshold-emulation",
            TaskSubmission(task_id="task-04-threshold-emulation", answer="THRESHOLD_DETECTION_VERIFIED")
        )
        assert res4.is_correct is True

        # Tune rolling window parameters
        tune_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/threshold_tool.py --tune-window"
        )
        assert "ROLLING_WINDOW_TUNED_OK" in tune_out

        # Task 5: Complete challenge
        challenge_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/threshold_tool.py --challenge"
        )
        assert "THRESHOLD_DETECTION_VALIDATED" in challenge_out
        assert info.has_action("threshold_detection_validated")

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-threshold-challenge",
            TaskSubmission(task_id="task-05-threshold-challenge", answer="THRESHOLD_DETECTION_VALIDATED")
        )
        assert res5.is_correct is True

        # Task 6: Quiz with 100% score
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-threshold-quiz",
            TaskSubmission(
                task_id="task-06-threshold-quiz",
                answer="",
                quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0},
            )
        )
        assert res6.is_correct is True
        assert res6.room_completed is True
        assert test_user.xp == 350
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 3. ROOM 14: CORRELATION RULES: MULTI-EVENT DETECTION LIFECYCLE
# ============================================================================

@pytest.mark.asyncio
async def test_room_14_correlation_rules_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 14."""
    validator = TaskValidator()
    room_id = "detect-14-correlation-rules"

    # Task 1: Join key
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-correlation-entity-keys",
        TaskSubmission(task_id="task-01-correlation-entity-keys", answer="host.name")
    )
    assert res1.is_correct is True

    # Task 2: Parent process
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-attack-chain-analysis",
        TaskSubmission(task_id="task-02-attack-chain-analysis", answer="winword.exe")
    )
    assert res2.is_correct is True

    # Task 3: MITRE ATT&CK Spearphishing Attachment
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-phishing-macro-mapping",
        TaskSubmission(task_id="task-03-attck-phishing-macro-mapping", answer="T1566.001")
    )
    assert res3.is_correct is True

    # Start lab session for practical tasks
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect14_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Task 4: Emulate multi-event correlation
        emulate_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/correlation_rule_tool.py --emulate-correlation"
        )
        assert "CORRELATION_RULE_VERIFIED" in emulate_out
        assert info.has_action("correlation_rule_verified")

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-correlation-emulation",
            TaskSubmission(task_id="task-04-correlation-emulation", answer="CORRELATION_RULE_VERIFIED")
        )
        assert res4.is_correct is True

        # Tune sequence constraints
        tune_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/correlation_rule_tool.py --tune-sequence"
        )
        assert "CORRELATION_SEQUENCE_TUNED_OK" in tune_out

        # Task 5: Complete challenge
        challenge_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/correlation_rule_tool.py --challenge"
        )
        assert "CORRELATION_RULE_VALIDATED" in challenge_out
        assert info.has_action("correlation_rule_validated")

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-correlation-challenge",
            TaskSubmission(task_id="task-05-correlation-challenge", answer="CORRELATION_RULE_VALIDATED")
        )
        assert res5.is_correct is True

        # Task 6: Quiz with 100% score
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-correlation-quiz",
            TaskSubmission(
                task_id="task-06-correlation-quiz",
                answer="",
                quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0},
            )
        )
        assert res6.is_correct is True
        assert res6.room_completed is True
        assert test_user.xp == 350
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 4. ROOM 15: DETECTION TESTING WITH UNIT TESTS & SYNTHETIC LOGS LIFECYCLE
# ============================================================================

@pytest.mark.asyncio
async def test_room_15_unit_testing_rules_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 15."""
    validator = TaskValidator()
    room_id = "detect-15-unit-testing-rules"

    # Task 1: Negative test fixture requirement
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-testing-principles-mechanics",
        TaskSubmission(task_id="task-01-testing-principles-mechanics", answer="negative")
    )
    assert res1.is_correct is True

    # Task 2: Test suite status
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-synthetic-fixture-analysis",
        TaskSubmission(task_id="task-02-synthetic-fixture-analysis", answer="PASSED")
    )
    assert res2.is_correct is True

    # Task 3: MITRE ATT&CK Command and Scripting Interpreter
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-scripting-interpreter-mapping",
        TaskSubmission(task_id="task-03-attck-scripting-interpreter-mapping", answer="T1059")
    )
    assert res3.is_correct is True

    # Start lab session for practical tasks
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect15_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Task 4: Run unit tests
        emulate_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/detection_testing_tool.py --run-tests"
        )
        assert "DETECTION_UNIT_TEST_VERIFIED" in emulate_out
        assert info.has_action("detection_unit_test_verified")

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-testing-unit-emulation",
            TaskSubmission(task_id="task-04-testing-unit-emulation", answer="DETECTION_UNIT_TEST_VERIFIED")
        )
        assert res4.is_correct is True

        # Tune test fixtures and assertions
        tune_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/detection_testing_tool.py --tune-fixtures"
        )
        assert "FIXTURE_ASSERTIONS_TUNED_OK" in tune_out

        # Task 5: Complete challenge
        challenge_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/detection_testing_tool.py --challenge"
        )
        assert "DETECTION_UNIT_TEST_VALIDATED" in challenge_out
        assert info.has_action("detection_unit_test_validated")

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-testing-unit-challenge",
            TaskSubmission(task_id="task-05-testing-unit-challenge", answer="DETECTION_UNIT_TEST_VALIDATED")
        )
        assert res5.is_correct is True

        # Task 6: Quiz with 100% score
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-testing-quiz",
            TaskSubmission(
                task_id="task-06-testing-quiz",
                answer="",
                quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0},
            )
        )
        assert res6.is_correct is True
        assert res6.room_completed is True
        assert test_user.xp == 350
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 5. ROOM 16: YARA RULES FOR FILE & MEMORY THREAT HUNTING LIFECYCLE
# ============================================================================

@pytest.mark.asyncio
async def test_room_16_yara_hunting_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 16."""
    validator = TaskValidator()
    room_id = "detect-16-yara-hunting"

    # Task 1: MZ Magic Header
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-yara-pe-header-mechanics",
        TaskSubmission(task_id="task-01-yara-pe-header-mechanics", answer="0x5A4D")
    )
    assert res1.is_correct is True

    # Task 2: Hex wildcard jump range
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-yara-hex-wildcard-analysis",
        TaskSubmission(task_id="task-02-yara-hex-wildcard-analysis", answer="4")
    )
    assert res2.is_correct is True

    # Task 3: MITRE ATT&CK Obfuscated Files or Information
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-obfuscation-mapping",
        TaskSubmission(task_id="task-03-attck-obfuscation-mapping", answer="T1027")
    )
    assert res3.is_correct is True

    # Start lab session for practical tasks
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect16_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Task 4: Scan memory with YARA
        emulate_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/yara_hunting_tool.py --scan-memory"
        )
        assert "YARA_HUNTING_VERIFIED" in emulate_out
        assert info.has_action("yara_hunting_verified")

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-yara-hunting-emulation",
            TaskSubmission(task_id="task-04-yara-hunting-emulation", answer="YARA_HUNTING_VERIFIED")
        )
        assert res4.is_correct is True

        # Tune YARA condition logic
        tune_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/yara_hunting_tool.py --tune-condition"
        )
        assert "YARA_CONDITION_TUNED_OK" in tune_out

        # Task 5: Complete challenge
        challenge_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/yara_hunting_tool.py --challenge"
        )
        assert "YARA_HUNTING_VALIDATED" in challenge_out
        assert info.has_action("yara_hunting_validated")

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-yara-hunting-challenge",
            TaskSubmission(task_id="task-05-yara-hunting-challenge", answer="YARA_HUNTING_VALIDATED")
        )
        assert res5.is_correct is True

        # Task 6: Quiz with 100% score
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-yara-quiz",
            TaskSubmission(
                task_id="task-06-yara-quiz",
                answer="",
                quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0},
            )
        )
        assert res6.is_correct is True
        assert res6.room_completed is True
        assert test_user.xp == 350
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 6. ANTI-FORGERY & DUAL-SESSION CROSS-SESSION ISOLATION
# ============================================================================

@pytest.mark.asyncio
async def test_anti_forgery_rejection_detection_rooms_13_16(db_session: Session, test_user: User):
    """Verify that forged echo/printf commands do not record challenge completion actions."""
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect_forgery_{test_user.operator_id}"
    info = await runner.start_session(sess_id, "detect-13-threshold-detections", test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Attempt forgery for Room 13
        await runner.execute_command(sess_id, "echo THRESHOLD_DETECTION_VERIFIED")
        assert not info.has_action("threshold_detection_verified")

        # Attempt forgery for Room 14
        await runner.execute_command(sess_id, "printf 'CORRELATION_RULE_VERIFIED\\n'")
        assert not info.has_action("correlation_rule_verified")

        # Attempt forgery for Room 15
        await runner.execute_command(sess_id, "echo DETECTION_UNIT_TEST_VERIFIED")
        assert not info.has_action("detection_unit_test_verified")

        # Attempt forgery for Room 16
        await runner.execute_command(sess_id, "echo YARA_HUNTING_VERIFIED")
        assert not info.has_action("yara_hunting_verified")
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


@pytest.mark.asyncio
async def test_dual_session_cross_session_isolation_13_16(
    db_session: Session, test_user: User, second_user: User
):
    """Verify that actions recorded in Session A do NOT bleed into Session B."""
    runner = ProcessLabRunner()
    room_id = "detect-16-yara-hunting"

    sess_a = f"proc_test_detect16_sessA_{test_user.operator_id}"
    sess_b = f"proc_test_detect16_sessB_{second_user.operator_id}"

    info_a = await runner.start_session(sess_a, room_id, test_user.operator_id)
    info_b = await runner.start_session(sess_b, room_id, second_user.operator_id)

    lab_manager._active_sessions[sess_a] = info_a
    lab_manager._active_sessions[sess_b] = info_b

    try:
        # Operator A completes emulation and challenge
        await runner.execute_command(sess_a, "python3 /home/operator/tools/yara_hunting_tool.py --scan-memory")
        await runner.execute_command(sess_a, "python3 /home/operator/tools/yara_hunting_tool.py --tune-condition")
        await runner.execute_command(sess_a, "python3 /home/operator/tools/yara_hunting_tool.py --challenge")

        assert info_a.has_action("yara_hunting_verified")
        assert info_a.has_action("yara_hunting_validated")

        # Operator B has NOT executed the tools -> must have no actions
        assert not info_b.has_action("yara_hunting_verified")
        assert not info_b.has_action("yara_hunting_validated")

        # Validator for Operator B must reject
        validator = TaskValidator()
        res_b = validator.validate_submission(
            db_session, second_user, room_id, "task-04-yara-hunting-emulation",
            TaskSubmission(task_id="task-04-yara-hunting-emulation", answer="YARA_HUNTING_VERIFIED")
        )
        assert res_b.is_correct is False
        assert "Investigation incomplete" in res_b.feedback
    finally:
        await runner.stop_session(sess_a)
        await runner.stop_session(sess_b)
        lab_manager._active_sessions.pop(sess_a, None)
        lab_manager._active_sessions.pop(sess_b, None)

