"""
Unit and Emulated Integration Tests for Purple Team Rooms 05–08:
- Room 05: Emulating Privilege Escalation Techniques (purple-05-privesc-emulation)
- Room 06: Emulating Defense Evasion & Process Injection (purple-06-defense-evasion-emulation)
- Room 07: Emulating Lateral Movement (SMB, WMI, WinRM) (purple-07-lateral-movement-emulation)
- Room 08: Emulating Persistence Mechanisms (purple-08-persistence-emulation)

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
        username="purple_operator_0508",
        email="purple_operator_0508@noentry.internal",
        operator_id="OP-PURPLE-0508-UNIT",
        hashed_password="dummy_test_hash_purple_0508",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(name="second_user")
def second_user_fixture(db_session: Session):
    user = User(
        username="purple_operator_isolate_0508",
        email="purple_operator_isolate_0508@noentry.internal",
        operator_id="OP-PURPLE-ISOLATE-0508",
        hashed_password="dummy_test_hash_purple_isolate_0508",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


# ============================================================================
# 1. CURRICULUM REGISTRATION & PURPLE TRACK TOTALS
# ============================================================================

def test_rooms_purple_05_08_curriculum_registration():
    """Verify Purple Rooms 05-08 are fully registered and configured in the curriculum."""
    for r_num in (5, 6, 7, 8):
        room = curriculum_registry.get_room(f"purple-0{r_num}")
        assert room is not None, f"Purple Room 0{r_num} not found"
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

    # Verify track statistics
    purple_rooms = curriculum_registry.list_rooms(track=TrackEnum.PURPLE)
    assert len(purple_rooms) == 20
    implemented_purple = [r for r in purple_rooms if r.status == RoomStatus.IMPLEMENTED]
    planned_purple = [r for r in purple_rooms if r.status == RoomStatus.PLANNED]
    assert len(implemented_purple) >= 8

    counts = curriculum_registry.get_track_counts()
    assert counts["purple"]["total"] == 20
    assert counts["purple"]["implemented"] >= 8


# ============================================================================
# 2. ROOM 05: PRIVILEGE ESCALATION EMULATION
# ============================================================================

@pytest.mark.asyncio
async def test_room_05_privesc_emulation_lifecycle(db_session: Session, test_user: User):
    """Test all tasks and validation for Purple Room 05."""
    validator = TaskValidator()
    room_id = "purple-05-privesc-emulation"

    # Task 1: Privilege Mechanics & Integrity Level
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-privilege-mechanics-token-security",
        TaskSubmission(task_id="task-01-privilege-mechanics-token-security", answer="SeImpersonatePrivilege")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: UAC Elevation Telemetry Analysis
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-uac-elevation-telemetry-analysis",
        TaskSubmission(task_id="task-02-uac-elevation-telemetry-analysis", answer="4688")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: ATT&CK PrivEsc Technique Mapping
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-privesc-mapping",
        TaskSubmission(task_id="task-03-attck-privesc-mapping", answer="T1548.002")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Task 4 without lab -> rejected
    res4_fail = validator.validate_submission(
        db_session, test_user, room_id, "task-04-uac-emulation-telemetry",
        TaskSubmission(task_id="task-04-uac-emulation-telemetry", answer="PRIVESC_EMULATION_VERIFIED")
    )
    assert res4_fail.is_correct is False
    assert "Investigation required" in res4_fail.feedback

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple05_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Run tool command to emulate UAC
        emu_cmd = "python3 /home/operator/tools/privesc_emulation_tool.py --emulate-uac"
        out_emu = await runner.execute_command(sess_id, emu_cmd)
        assert "PRIVESC_EMULATION_VERIFIED" in out_emu
        assert info.has_action("privesc_emulated")

        # Now Task 4 succeeds
        res4_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-04-uac-emulation-telemetry",
            TaskSubmission(task_id="task-04-uac-emulation-telemetry", answer="PRIVESC_EMULATION_VERIFIED")
        )
        assert res4_pass.is_correct is True
        assert res4_pass.completed is True

        # Task 5 before challenge completion -> rejected
        res5_fail = validator.validate_submission(
            db_session, test_user, room_id, "task-05-privesc-detection-challenge",
            TaskSubmission(task_id="task-05-privesc-detection-challenge", answer="PRIVESC_DETECTION_VALIDATED")
        )
        assert res5_fail.is_correct is False

        # Deploy detection rule and complete challenge
        tune_cmd = "python3 /home/operator/tools/privesc_emulation_tool.py --tune-detection"
        out_tune = await runner.execute_command(sess_id, tune_cmd)
        assert "DETECTION_TUNED_OK" in out_tune

        chal_cmd = "python3 /home/operator/tools/privesc_emulation_tool.py --challenge"
        out_chal = await runner.execute_command(sess_id, chal_cmd)
        assert "PRIVESC_DETECTION_VALIDATED" in out_chal
        assert info.has_action("privesc_detection_validated")

        # Now Task 5 succeeds
        res5_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-05-privesc-detection-challenge",
            TaskSubmission(task_id="task-05-privesc-detection-challenge", answer="PRIVESC_DETECTION_VALIDATED")
        )
        assert res5_pass.is_correct is True
        assert res5_pass.completed is True

    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 3. ROOM 06: DEFENSE EVASION & PROCESS INJECTION
# ============================================================================

@pytest.mark.asyncio
async def test_room_06_defense_evasion_injection_lifecycle(db_session: Session, test_user: User):
    """Test all tasks and validation for Purple Room 06."""
    validator = TaskValidator()
    room_id = "purple-06-defense-evasion-emulation"

    # Task 1: Process Injection Windows API
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-process-injection-mechanics",
        TaskSubmission(task_id="task-01-process-injection-mechanics", answer="CreateProcess")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Sysmon Injection Telemetry (Target Process)
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-sysmon-injection-telemetry",
        TaskSubmission(task_id="task-02-sysmon-injection-telemetry", answer="svchost.exe")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: ATT&CK Injection Technique Mapping
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-injection-mapping",
        TaskSubmission(task_id="task-03-attck-injection-mapping", answer="T1055.012")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple06_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Run tool command to emulate injection
        emu_cmd = "python3 /home/operator/tools/injection_emulation_tool.py --emulate-injection"
        out_emu = await runner.execute_command(sess_id, emu_cmd)
        assert "INJECTION_EMULATION_VERIFIED" in out_emu
        assert info.has_action("injection_emulated")

        # Task 4 succeeds
        res4_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-04-process-injection-emulation",
            TaskSubmission(task_id="task-04-process-injection-emulation", answer="INJECTION_EMULATION_VERIFIED")
        )
        assert res4_pass.is_correct is True

        # Tune EDR and complete challenge
        tune_cmd = "python3 /home/operator/tools/injection_emulation_tool.py --tune-edr"
        out_tune = await runner.execute_command(sess_id, tune_cmd)
        assert "EDR_TUNED_OK" in out_tune

        chal_cmd = "python3 /home/operator/tools/injection_emulation_tool.py --challenge"
        out_chal = await runner.execute_command(sess_id, chal_cmd)
        assert "DEFENSE_EVASION_DETECTION_VALIDATED" in out_chal
        assert info.has_action("defense_evasion_detection_validated")

        # Task 5 succeeds
        res5_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-05-defense-evasion-challenge",
            TaskSubmission(task_id="task-05-defense-evasion-challenge", answer="DEFENSE_EVASION_DETECTION_VALIDATED")
        )
        assert res5_pass.is_correct is True

    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 4. ROOM 07: LATERAL MOVEMENT EMULATION
# ============================================================================

@pytest.mark.asyncio
async def test_room_07_lateral_movement_lifecycle(db_session: Session, test_user: User):
    """Test all tasks and validation for Purple Room 07."""
    validator = TaskValidator()
    room_id = "purple-07-lateral-movement-emulation"

    # Task 1: Logon Type 3
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-lateral-movement-logon-type",
        TaskSubmission(task_id="task-01-lateral-movement-logon-type", answer="3")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Service Installation Telemetry (PSEXESVC)
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-psexec-service-telemetry",
        TaskSubmission(task_id="task-02-psexec-service-telemetry", answer="PSEXESVC")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: ATT&CK Lateral Movement Technique Mapping
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-lateral-movement-mapping",
        TaskSubmission(task_id="task-03-attck-lateral-movement-mapping", answer="T1569.002")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple07_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Run tool command to emulate lateral movement
        emu_cmd = "python3 /home/operator/tools/lateral_emulation_tool.py --emulate-lateral"
        out_emu = await runner.execute_command(sess_id, emu_cmd)
        assert "LATERAL_EMULATION_VERIFIED" in out_emu
        assert info.has_action("lateral_emulated")

        # Task 4 succeeds
        res4_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-04-wmi-lateral-emulation",
            TaskSubmission(task_id="task-04-wmi-lateral-emulation", answer="LATERAL_EMULATION_VERIFIED")
        )
        assert res4_pass.is_correct is True

        # Tune rule and complete challenge
        tune_cmd = "python3 /home/operator/tools/lateral_emulation_tool.py --tune-rule"
        out_tune = await runner.execute_command(sess_id, tune_cmd)
        assert "RULE_TUNED_OK" in out_tune

        chal_cmd = "python3 /home/operator/tools/lateral_emulation_tool.py --challenge"
        out_chal = await runner.execute_command(sess_id, chal_cmd)
        assert "LATERAL_MOVEMENT_DETECTION_VALIDATED" in out_chal
        assert info.has_action("lateral_movement_detection_validated")

        # Task 5 succeeds
        res5_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-05-lateral-movement-challenge",
            TaskSubmission(task_id="task-05-lateral-movement-challenge", answer="LATERAL_MOVEMENT_DETECTION_VALIDATED")
        )
        assert res5_pass.is_correct is True

    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 5. ROOM 08: PERSISTENCE EMULATION & REMEDIATION
# ============================================================================

@pytest.mark.asyncio
async def test_room_08_persistence_lifecycle(db_session: Session, test_user: User):
    """Test all tasks and validation for Purple Room 08."""
    validator = TaskValidator()
    room_id = "purple-08-persistence-emulation"

    # Task 1: Scheduled Task Event ID 4698
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-persistence-event-id",
        TaskSubmission(task_id="task-01-persistence-event-id", answer="4698")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Action Path from Scheduled Task XML
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-scheduled-task-telemetry",
        TaskSubmission(task_id="task-02-scheduled-task-telemetry", answer="SecurityTelemetryUpdate")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: ATT&CK Scheduled Task Technique Mapping
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-scheduled-task-mapping",
        TaskSubmission(task_id="task-03-attck-scheduled-task-mapping", answer="T1053.005")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple08_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Run tool command to emulate scheduled task persistence
        emu_cmd = "python3 /home/operator/tools/persistence_emulation_tool.py --emulate-task"
        out_emu = await runner.execute_command(sess_id, emu_cmd)
        assert "PERSISTENCE_EMULATION_VERIFIED" in out_emu
        assert info.has_action("persistence_emulated")

        # Task 4 succeeds
        res4_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-04-scheduled-task-emulation",
            TaskSubmission(task_id="task-04-scheduled-task-emulation", answer="PERSISTENCE_EMULATION_VERIFIED")
        )
        assert res4_pass.is_correct is True

        # Remediate persistence and complete challenge
        rem_cmd = "python3 /home/operator/tools/persistence_emulation_tool.py --remediate"
        out_rem = await runner.execute_command(sess_id, rem_cmd)
        assert "TASK_REMEDIATED_OK" in out_rem

        chal_cmd = "python3 /home/operator/tools/persistence_emulation_tool.py --challenge"
        out_chal = await runner.execute_command(sess_id, chal_cmd)
        assert "PERSISTENCE_REMEDIATION_VALIDATED" in out_chal
        assert info.has_action("persistence_remediation_validated")

        # Task 5 succeeds
        res5_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-05-persistence-remediation-challenge",
            TaskSubmission(task_id="task-05-persistence-remediation-challenge", answer="PERSISTENCE_REMEDIATION_VALIDATED")
        )
        assert res5_pass.is_correct is True

    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 6. ANTI-FORGERY & ECHO/PRINTF REJECTION
# ============================================================================

@pytest.mark.asyncio
async def test_purple_anti_forgery_echo_printf_rejected(test_user: User):
    """Verify that forged echo or printf commands never award action completion."""
    runner = ProcessLabRunner()
    sess_id = f"proc_forgery_purple05_{test_user.operator_id}"
    info = await runner.start_session(sess_id, "purple-05-privesc-emulation", test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Attempt echo forgery
        cmd_echo = "echo PRIVESC_EMULATION_VERIFIED"
        await runner.execute_command(sess_id, cmd_echo)
        assert not info.has_action("privesc_emulated")

        # Attempt printf forgery
        cmd_printf = "printf 'PRIVESC_DETECTION_VALIDATED'"
        await runner.execute_command(sess_id, cmd_printf)
        assert not info.has_action("privesc_detection_validated")

        # Attempt python one-liner print forgery
        cmd_py = 'python3 -c "print(\'INJECTION_EMULATION_VERIFIED\')"'
        await runner.execute_command(sess_id, cmd_py)
        assert not info.has_action("injection_emulated")

    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 7. DUAL-SESSION ISOLATION
# ============================================================================

@pytest.mark.asyncio
async def test_purple_dual_session_isolation(test_user: User, second_user: User):
    """Verify that actions performed in Operator A's session never leak to Operator B."""
    runner = ProcessLabRunner()
    sess_a = f"proc_sess_a_{test_user.operator_id}"
    sess_b = f"proc_sess_b_{second_user.operator_id}"

    info_a = await runner.start_session(sess_a, "purple-07-lateral-movement-emulation", test_user.operator_id)
    info_b = await runner.start_session(sess_b, "purple-07-lateral-movement-emulation", second_user.operator_id)
    lab_manager._active_sessions[sess_a] = info_a
    lab_manager._active_sessions[sess_b] = info_b

    try:
        # Operator A emulates lateral movement and completes challenge
        await runner.execute_command(sess_a, "python3 /home/operator/tools/lateral_emulation_tool.py --emulate-lateral")
        await runner.execute_command(sess_a, "python3 /home/operator/tools/lateral_emulation_tool.py --tune-rule")
        await runner.execute_command(sess_a, "python3 /home/operator/tools/lateral_emulation_tool.py --challenge")

        assert info_a.has_action("lateral_emulated")
        assert info_a.has_action("lateral_movement_detection_validated")

        # Operator B has NOT executed actions and must NOT have them awarded
        assert not info_b.has_action("lateral_emulated")
        assert not info_b.has_action("lateral_movement_detection_validated")

    finally:
        await runner.stop_session(sess_a)
        await runner.stop_session(sess_b)
        lab_manager._active_sessions.pop(sess_a, None)
        lab_manager._active_sessions.pop(sess_b, None)


# ============================================================================
# 8. QUIZ VALIDATION ACROSS ROOMS 05–08
# ============================================================================

def test_purple_rooms_05_08_quizzes(db_session: Session, test_user: User):
    """Validate assessment quiz evaluation for Purple Rooms 05 through 08."""
    validator = TaskValidator()

    # Room 05 Quiz: Task 6 (all correct answers are index 0)
    res_q5 = validator.validate_submission(
        db_session, test_user, "purple-05-privesc-emulation", "task-06-privesc-quiz",
        TaskSubmission(task_id="task-06-privesc-quiz", quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0})
    )
    assert res_q5.is_correct is True
    assert res_q5.completed is True

    # Room 06 Quiz: Task 6
    res_q6 = validator.validate_submission(
        db_session, test_user, "purple-06-defense-evasion-emulation", "task-06-defense-evasion-quiz",
        TaskSubmission(task_id="task-06-defense-evasion-quiz", quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0})
    )
    assert res_q6.is_correct is True
    assert res_q6.completed is True

    # Room 07 Quiz: Task 6
    res_q7 = validator.validate_submission(
        db_session, test_user, "purple-07-lateral-movement-emulation", "task-06-lateral-movement-quiz",
        TaskSubmission(task_id="task-06-lateral-movement-quiz", quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0})
    )
    assert res_q7.is_correct is True
    assert res_q7.completed is True

    # Room 08 Quiz: Task 6
    res_q8 = validator.validate_submission(
        db_session, test_user, "purple-08-persistence-emulation", "task-06-persistence-quiz",
        TaskSubmission(task_id="task-06-persistence-quiz", quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0})
    )
    assert res_q8.is_correct is True
    assert res_q8.completed is True
