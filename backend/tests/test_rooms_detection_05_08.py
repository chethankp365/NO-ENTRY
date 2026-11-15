"""
Unit and Emulated Integration Tests for Detection Engineering Rooms 05–08:
- Room 05: Writing Network Connection Rules (Sysmon Event ID 3) (detect-05-network-connection-rules)
- Room 06: Writing File & Registry Integrity Rules (detect-06-file-registry-rules)
- Room 07: Detecting Authentication Abuse (Event IDs 4624/4625/4672) (detect-07-auth-abuse-rules)
- Room 08: Detecting PowerShell Obfuscation & Download Cradles (detect-08-powershell-obfuscation)

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
        username="detection_engineer_0508",
        email="detection_engineer_0508@noentry.internal",
        operator_id="OP-DETECT-0508-UNIT",
        hashed_password="dummy_test_hash_detection_0508",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(name="second_user")
def second_user_fixture(db_session: Session):
    user = User(
        username="detection_operator_isolate_0508",
        email="detection_operator_isolate_0508@noentry.internal",
        operator_id="OP-DETECT-ISOLATE-0508",
        hashed_password="dummy_test_hash_detect_isolate_0508",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


# ============================================================================
# 1. CURRICULUM REGISTRATION & DETECTION TRACK TOTALS
# ============================================================================

def test_rooms_detection_05_08_curriculum_registration():
    """Verify Detection Rooms 05-08 are fully registered and configured in the curriculum."""
    for r_num in (5, 6, 7, 8):
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

    # Verify track statistics across platform
    all_rooms = curriculum_registry.list_rooms()
    assert len(all_rooms) == 80
    implemented_all = [r for r in all_rooms if r.status == RoomStatus.IMPLEMENTED]
    planned_all = [r for r in all_rooms if r.status == RoomStatus.PLANNED]
    assert len(implemented_all) >= 68
    assert len(planned_all) <= 12

    detect_rooms = curriculum_registry.list_rooms(track=TrackEnum.DETECTION)
    assert len(detect_rooms) == 20
    implemented_detect = [r for r in detect_rooms if r.status == RoomStatus.IMPLEMENTED]
    planned_detect = [r for r in detect_rooms if r.status == RoomStatus.PLANNED]
    assert len(implemented_detect) >= 8
    assert len(planned_detect) <= 12

    counts = curriculum_registry.get_track_counts()
    assert counts["detection"]["total"] == 20
    assert counts["detection"]["implemented"] >= 8
    assert counts["detection"]["planned"] <= 12


# ============================================================================
# 2. ROOM 05: WRITING NETWORK CONNECTION RULES LIFECYCLE
# ============================================================================

@pytest.mark.asyncio
async def test_room_05_network_rules_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 05."""
    validator = TaskValidator()
    room_id = "detect-05-network-connection-rules"

    # Task 1: Sysmon Event ID for Network Connection
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-sysmon-event3-mechanics",
        TaskSubmission(task_id="task-01-sysmon-event3-mechanics", answer="3")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Anomalous destination port in dataset
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-network-telemetry-analysis",
        TaskSubmission(task_id="task-02-network-telemetry-analysis", answer="8443")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: MITRE ATT&CK technique for Non-Standard Port
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-nonstandard-port",
        TaskSubmission(task_id="task-03-attck-nonstandard-port", answer="T1571")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Task 4 without active lab -> rejected
    res4_fail = validator.validate_submission(
        db_session, test_user, room_id, "task-04-network-connection-emulation",
        TaskSubmission(task_id="task-04-network-connection-emulation", answer="NETWORK_DETECTION_VERIFIED")
    )
    assert res4_fail.is_correct is False
    assert "Investigation required" in res4_fail.feedback

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect05_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Run tool to emulate detection
        out_emulate = await runner.execute_command(sess_id, "python3 /home/operator/tools/network_connection_tool.py --emulate-detection")
        assert "NETWORK_DETECTION_VERIFIED" in out_emulate

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-network-connection-emulation",
            TaskSubmission(task_id="task-04-network-connection-emulation", answer="NETWORK_DETECTION_VERIFIED")
        )
        assert res4.is_correct is True
        assert res4.completed is True

        # Tune filter
        out_tune = await runner.execute_command(sess_id, "python3 /home/operator/tools/network_connection_tool.py --tune-filter")
        assert "NETWORK_FILTER_TUNED_OK" in out_tune

        # Challenge validation
        out_chal = await runner.execute_command(sess_id, "python3 /home/operator/tools/network_connection_tool.py --challenge")
        assert "NETWORK_DETECTION_VALIDATED" in out_chal

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-network-connection-challenge",
            TaskSubmission(task_id="task-05-network-connection-challenge", answer="NETWORK_DETECTION_VALIDATED")
        )
        assert res5.is_correct is True
        assert res5.completed is True

        # Task 6: Quiz
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-network-rules-quiz",
            TaskSubmission(
                task_id="task-06-network-rules-quiz",
                answer="",
                quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0}
            )
        )
        assert res6.is_correct is True
        assert res6.completed is True
        assert res6.room_completed is True
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 3. ROOM 06: WRITING FILE & REGISTRY INTEGRITY RULES LIFECYCLE
# ============================================================================

@pytest.mark.asyncio
async def test_room_06_file_registry_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 06."""
    validator = TaskValidator()
    room_id = "detect-06-file-registry-rules"

    # Task 1: Sysmon Event ID for FileCreate
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-sysmon-fim-eventids",
        TaskSubmission(task_id="task-01-sysmon-fim-eventids", answer="11")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Registry key targeted for persistence
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-registry-telemetry-analysis",
        TaskSubmission(task_id="task-02-registry-telemetry-analysis", answer="Run")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: MITRE ATT&CK Registry Run Keys technique
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-persistence-runkeys",
        TaskSubmission(task_id="task-03-attck-persistence-runkeys", answer="T1547.001")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect06_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Run tool to emulate detection
        out_emulate = await runner.execute_command(sess_id, "python3 /home/operator/tools/file_registry_tool.py --emulate-detection")
        assert "FILE_REGISTRY_VERIFIED" in out_emulate

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-file-registry-emulation",
            TaskSubmission(task_id="task-04-file-registry-emulation", answer="FILE_REGISTRY_VERIFIED")
        )
        assert res4.is_correct is True
        assert res4.completed is True

        # Tune filter
        out_tune = await runner.execute_command(sess_id, "python3 /home/operator/tools/file_registry_tool.py --tune-filter")
        assert "REGISTRY_FILTER_TUNED_OK" in out_tune

        # Challenge validation
        out_chal = await runner.execute_command(sess_id, "python3 /home/operator/tools/file_registry_tool.py --challenge")
        assert "FILE_REGISTRY_VALIDATED" in out_chal

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-file-registry-challenge",
            TaskSubmission(task_id="task-05-file-registry-challenge", answer="FILE_REGISTRY_VALIDATED")
        )
        assert res5.is_correct is True
        assert res5.completed is True

        # Task 6: Quiz
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-file-registry-quiz",
            TaskSubmission(
                task_id="task-06-file-registry-quiz",
                answer="",
                quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0}
            )
        )
        assert res6.is_correct is True
        assert res6.completed is True
        assert res6.room_completed is True
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 4. ROOM 07: DETECTING AUTHENTICATION ABUSE LIFECYCLE
# ============================================================================

@pytest.mark.asyncio
async def test_room_07_auth_abuse_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 07."""
    validator = TaskValidator()
    room_id = "detect-07-auth-abuse-rules"

    # Task 1: Event ID for Logon Failure
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-windows-auth-eventids",
        TaskSubmission(task_id="task-01-windows-auth-eventids", answer="4625")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: SubStatus code for bad password
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-auth-ntstatus-analysis",
        TaskSubmission(task_id="task-02-auth-ntstatus-analysis", answer="0xC000006A")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: MITRE ATT&CK technique for Password Spraying
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-password-spraying",
        TaskSubmission(task_id="task-03-attck-password-spraying", answer="T1110.003")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect07_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Run tool to emulate detection
        out_emulate = await runner.execute_command(sess_id, "python3 /home/operator/tools/auth_abuse_tool.py --emulate-detection")
        assert "AUTH_ABUSE_VERIFIED" in out_emulate

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-auth-abuse-emulation",
            TaskSubmission(task_id="task-04-auth-abuse-emulation", answer="AUTH_ABUSE_VERIFIED")
        )
        assert res4.is_correct is True
        assert res4.completed is True

        # Tune baseline
        out_tune = await runner.execute_command(sess_id, "python3 /home/operator/tools/auth_abuse_tool.py --tune-baseline")
        assert "AUTH_BASELINE_TUNED_OK" in out_tune

        # Challenge validation
        out_chal = await runner.execute_command(sess_id, "python3 /home/operator/tools/auth_abuse_tool.py --challenge")
        assert "AUTH_ABUSE_VALIDATED" in out_chal

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-auth-abuse-challenge",
            TaskSubmission(task_id="task-05-auth-abuse-challenge", answer="AUTH_ABUSE_VALIDATED")
        )
        assert res5.is_correct is True
        assert res5.completed is True

        # Task 6: Quiz
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-auth-abuse-quiz",
            TaskSubmission(
                task_id="task-06-auth-abuse-quiz",
                answer="",
                quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0}
            )
        )
        assert res6.is_correct is True
        assert res6.completed is True
        assert res6.room_completed is True
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 5. ROOM 08: DETECTING POWERSHELL OBFUSCATION LIFECYCLE
# ============================================================================

@pytest.mark.asyncio
async def test_room_08_powershell_obfuscation_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 08."""
    validator = TaskValidator()
    room_id = "detect-08-powershell-obfuscation"

    # Task 1: ScriptBlock logging Event ID
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-powershell-eventid-mechanics",
        TaskSubmission(task_id="task-01-powershell-eventid-mechanics", answer="4104")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Parameter abbreviation for encoded command
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-powershell-enc-analysis",
        TaskSubmission(task_id="task-02-powershell-enc-analysis", answer="-enc")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: MITRE ATT&CK PowerShell technique
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-powershell-technique",
        TaskSubmission(task_id="task-03-attck-powershell-technique", answer="T1059.001")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect08_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Run tool to emulate detection
        out_emulate = await runner.execute_command(sess_id, "python3 /home/operator/tools/powershell_obfuscation_tool.py --emulate-detection")
        assert "POWERSHELL_DETECTION_VERIFIED" in out_emulate

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-powershell-emulation",
            TaskSubmission(task_id="task-04-powershell-emulation", answer="POWERSHELL_DETECTION_VERIFIED")
        )
        assert res4.is_correct is True
        assert res4.completed is True

        # Tune regex
        out_tune = await runner.execute_command(sess_id, "python3 /home/operator/tools/powershell_obfuscation_tool.py --tune-regex")
        assert "CRADLE_REGEX_TUNED_OK" in out_tune

        # Challenge validation
        out_chal = await runner.execute_command(sess_id, "python3 /home/operator/tools/powershell_obfuscation_tool.py --challenge")
        assert "POWERSHELL_DETECTION_VALIDATED" in out_chal

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-powershell-challenge",
            TaskSubmission(task_id="task-05-powershell-challenge", answer="POWERSHELL_DETECTION_VALIDATED")
        )
        assert res5.is_correct is True
        assert res5.completed is True

        # Task 6: Quiz
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-powershell-quiz",
            TaskSubmission(
                task_id="task-06-powershell-quiz",
                answer="",
                quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0}
            )
        )
        assert res6.is_correct is True
        assert res6.completed is True
        assert res6.room_completed is True
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 6. ANTI-FORGERY & DUAL-SESSION CROSS-SESSION ISOLATION
# ============================================================================

@pytest.mark.asyncio
async def test_anti_forgery_rejection_detection_rooms(db_session: Session, test_user: User):
    """Verify that forged echo/printf commands do not record challenge completion actions."""
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect_forgery_{test_user.operator_id}"
    info = await runner.start_session(sess_id, "detect-05-network-connection-rules", test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Attempt forgery for Room 05
        await runner.execute_command(sess_id, "echo NETWORK_DETECTION_VERIFIED")
        assert not info.has_action("network_connection_verified")

        # Attempt forgery for Room 06
        await runner.execute_command(sess_id, "printf 'FILE_REGISTRY_VERIFIED\\n'")
        assert not info.has_action("file_registry_verified")

        # Attempt forgery for Room 07
        await runner.execute_command(sess_id, "echo AUTH_ABUSE_VERIFIED")
        assert not info.has_action("auth_abuse_verified")

        # Attempt forgery for Room 08
        await runner.execute_command(sess_id, "echo POWERSHELL_DETECTION_VERIFIED")
        assert not info.has_action("powershell_obfuscation_verified")
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


@pytest.mark.asyncio
async def test_dual_session_cross_session_isolation(
    db_session: Session, test_user: User, second_user: User
):
    """Verify that actions recorded in Session A do NOT bleed into Session B."""
    runner = ProcessLabRunner()
    room_id = "detect-08-powershell-obfuscation"

    sess_a = f"proc_test_detect08_sessA_{test_user.operator_id}"
    sess_b = f"proc_test_detect08_sessB_{second_user.operator_id}"

    info_a = await runner.start_session(sess_a, room_id, test_user.operator_id)
    info_b = await runner.start_session(sess_b, room_id, second_user.operator_id)

    lab_manager._active_sessions[sess_a] = info_a
    lab_manager._active_sessions[sess_b] = info_b

    try:
        # Operator A completes emulation and challenge
        await runner.execute_command(sess_a, "python3 /home/operator/tools/powershell_obfuscation_tool.py --emulate-detection")
        await runner.execute_command(sess_a, "python3 /home/operator/tools/powershell_obfuscation_tool.py --tune-regex")
        await runner.execute_command(sess_a, "python3 /home/operator/tools/powershell_obfuscation_tool.py --challenge")

        assert info_a.has_action("powershell_obfuscation_verified")
        assert info_a.has_action("powershell_obfuscation_validated")

        # Operator B has NOT executed the tools -> must have no actions
        assert not info_b.has_action("powershell_obfuscation_verified")
        assert not info_b.has_action("powershell_obfuscation_validated")

        # Validator for Operator B must reject
        validator = TaskValidator()
        res_b = validator.validate_submission(
            db_session, second_user, room_id, "task-04-powershell-emulation",
            TaskSubmission(task_id="task-04-powershell-emulation", answer="POWERSHELL_DETECTION_VERIFIED")
        )
        assert res_b.is_correct is False
        assert "Investigation incomplete" in res_b.feedback
    finally:
        await runner.stop_session(sess_a)
        await runner.stop_session(sess_b)
        lab_manager._active_sessions.pop(sess_a, None)
        lab_manager._active_sessions.pop(sess_b, None)
