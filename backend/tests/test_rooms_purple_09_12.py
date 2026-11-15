"""
Unit and Emulated Integration Tests for Purple Team Rooms 09–12:
- Room 09: Command & Control (C2) Traffic Emulation (purple-09-c2-framework-emulation)
- Room 10: Emulating Data Exfiltration Techniques (purple-10-exfiltration-emulation)
- Room 11: Ransomware Attack Emulation & Readiness (purple-11-ransomware-readiness)
- Room 12: Cloud Identity & IAM Privilege Escalation Emulation (purple-12-cloud-identity-emulation)

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
        username="purple_operator_0912",
        email="purple_operator_0912@noentry.internal",
        operator_id="OP-PURPLE-0912-UNIT",
        hashed_password="dummy_test_hash_purple_0912",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(name="second_user")
def second_user_fixture(db_session: Session):
    user = User(
        username="purple_operator_isolate_0912",
        email="purple_operator_isolate_0912@noentry.internal",
        operator_id="OP-PURPLE-ISOLATE-0912",
        hashed_password="dummy_test_hash_purple_isolate_0912",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


# ============================================================================
# 1. CURRICULUM REGISTRATION & TRACK TOTALS
# ============================================================================

def test_rooms_purple_09_12_curriculum_registration():
    """Verify Purple Rooms 09-12 are fully registered and configured in the curriculum."""
    expected_rooms = [
        (9, "purple-09-c2-framework-emulation"),
        (10, "purple-10-exfiltration-emulation"),
        (11, "purple-11-ransomware-readiness"),
        (12, "purple-12-cloud-identity-emulation"),
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

    # Verify track statistics
    purple_rooms = curriculum_registry.list_rooms(track=TrackEnum.PURPLE)
    assert len(purple_rooms) == 20
    implemented_purple = [r for r in purple_rooms if r.status == RoomStatus.IMPLEMENTED]
    assert len(implemented_purple) >= 12

    counts = curriculum_registry.get_track_counts()
    assert counts["purple"]["total"] == 20
    assert counts["purple"]["implemented"] >= 12


# ============================================================================
# 2. ROOM 09: COMMAND & CONTROL (C2) TRAFFIC EMULATION
# ============================================================================

@pytest.mark.asyncio
async def test_room_09_c2_emulation_lifecycle(db_session: Session, test_user: User):
    """Test all tasks and validation for Purple Room 09."""
    validator = TaskValidator()
    room_id = "purple-09-c2-framework-emulation"

    # Task 1: Beaconing & Jitter Mechanics
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-c2-beacon-jitter-mechanics",
        TaskSubmission(task_id="task-01-c2-beacon-jitter-mechanics", answer="Jitter")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: C2 Beacon Traffic Analysis
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-c2-beacon-traffic-analysis",
        TaskSubmission(task_id="task-02-c2-beacon-traffic-analysis", answer="/api/v1/ping")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: ATT&CK C2 Mapping
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-c2-mapping",
        TaskSubmission(task_id="task-03-attck-c2-mapping", answer="T1071.001")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Task 4 without lab -> rejected
    res4_fail = validator.validate_submission(
        db_session, test_user, room_id, "task-04-c2-beacon-emulation",
        TaskSubmission(task_id="task-04-c2-beacon-emulation", answer="C2_BEACON_EMULATION_VERIFIED")
    )
    assert res4_fail.is_correct is False
    assert "Investigation required" in res4_fail.feedback

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple09_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Run tool command to emulate beaconing
        emu_cmd = "python3 /home/operator/tools/c2_emulation_tool.py --emulate-beacon"
        out_emu = await runner.execute_command(sess_id, emu_cmd)
        assert "C2_BEACON_EMULATION_VERIFIED" in out_emu
        assert info.has_action("c2_beacon_emulated")

        # Now Task 4 succeeds
        res4_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-04-c2-beacon-emulation",
            TaskSubmission(task_id="task-04-c2-beacon-emulation", answer="C2_BEACON_EMULATION_VERIFIED")
        )
        assert res4_pass.is_correct is True
        assert res4_pass.completed is True

        # Task 5 before challenge completion -> rejected
        res5_fail = validator.validate_submission(
            db_session, test_user, room_id, "task-05-c2-detection-challenge",
            TaskSubmission(task_id="task-05-c2-detection-challenge", answer="C2_DETECTION_VALIDATED")
        )
        assert res5_fail.is_correct is False

        # Tune detection rule and complete challenge
        tune_cmd = "python3 /home/operator/tools/c2_emulation_tool.py --tune-detection"
        out_tune = await runner.execute_command(sess_id, tune_cmd)
        assert "DETECTION_TUNED_OK" in out_tune

        chal_cmd = "python3 /home/operator/tools/c2_emulation_tool.py --challenge"
        out_chal = await runner.execute_command(sess_id, chal_cmd)
        assert "C2_DETECTION_VALIDATED" in out_chal
        assert info.has_action("c2_detection_validated")

        # Now Task 5 succeeds
        res5_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-05-c2-detection-challenge",
            TaskSubmission(task_id="task-05-c2-detection-challenge", answer="C2_DETECTION_VALIDATED")
        )
        assert res5_pass.is_correct is True
        assert res5_pass.completed is True

    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 3. ROOM 10: EMULATING DATA EXFILTRATION TECHNIQUES
# ============================================================================

@pytest.mark.asyncio
async def test_room_10_exfiltration_lifecycle(db_session: Session, test_user: User):
    """Test all tasks and validation for Purple Room 10."""
    validator = TaskValidator()
    room_id = "purple-10-exfiltration-emulation"

    # Task 1: Staging Mechanics
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-exfil-staging-mechanics",
        TaskSubmission(task_id="task-01-exfil-staging-mechanics", answer="zip -e")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Staging Directory Telemetry Analysis
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-exfil-telemetry-analysis",
        TaskSubmission(task_id="task-02-exfil-telemetry-analysis", answer="/tmp/.staging_vault")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: ATT&CK Exfiltration Mapping
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-exfil-mapping",
        TaskSubmission(task_id="task-03-attck-exfil-mapping", answer="T1560.001")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Task 4 without lab -> rejected
    res4_fail = validator.validate_submission(
        db_session, test_user, room_id, "task-04-exfil-emulation",
        TaskSubmission(task_id="task-04-exfil-emulation", answer="EXFILTRATION_EMULATION_VERIFIED")
    )
    assert res4_fail.is_correct is False
    assert "Investigation required" in res4_fail.feedback

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple10_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Run tool command to emulate exfiltration
        emu_cmd = "python3 /home/operator/tools/exfil_emulation_tool.py --emulate-exfil"
        out_emu = await runner.execute_command(sess_id, emu_cmd)
        assert "EXFILTRATION_EMULATION_VERIFIED" in out_emu
        assert info.has_action("exfil_emulated")

        # Now Task 4 succeeds
        res4_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-04-exfil-emulation",
            TaskSubmission(task_id="task-04-exfil-emulation", answer="EXFILTRATION_EMULATION_VERIFIED")
        )
        assert res4_pass.is_correct is True
        assert res4_pass.completed is True

        # Task 5 before challenge completion -> rejected
        res5_fail = validator.validate_submission(
            db_session, test_user, room_id, "task-05-exfil-challenge",
            TaskSubmission(task_id="task-05-exfil-challenge", answer="EXFILTRATION_DETECTION_VALIDATED")
        )
        assert res5_fail.is_correct is False

        # Tune DLP and complete challenge
        tune_cmd = "python3 /home/operator/tools/exfil_emulation_tool.py --tune-dlp"
        out_tune = await runner.execute_command(sess_id, tune_cmd)
        assert "DLP_TUNED_OK" in out_tune

        chal_cmd = "python3 /home/operator/tools/exfil_emulation_tool.py --challenge"
        out_chal = await runner.execute_command(sess_id, chal_cmd)
        assert "EXFILTRATION_DETECTION_VALIDATED" in out_chal
        assert info.has_action("exfil_detection_validated")

        # Now Task 5 succeeds
        res5_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-05-exfil-challenge",
            TaskSubmission(task_id="task-05-exfil-challenge", answer="EXFILTRATION_DETECTION_VALIDATED")
        )
        assert res5_pass.is_correct is True
        assert res5_pass.completed is True

    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 4. ROOM 11: RANSOMWARE ATTACK EMULATION & READINESS
# ============================================================================

@pytest.mark.asyncio
async def test_room_11_ransomware_lifecycle(db_session: Session, test_user: User):
    """Test all tasks and validation for Purple Room 11."""
    validator = TaskValidator()
    room_id = "purple-11-ransomware-readiness"

    # Task 1: Shadow Copy Deletion Mechanics
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-ransomware-inhibiting-recovery",
        TaskSubmission(task_id="task-01-ransomware-inhibiting-recovery", answer="vssadmin")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Canary Decoy Analysis
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-ransomware-telemetry-analysis",
        TaskSubmission(task_id="task-02-ransomware-telemetry-analysis", answer="finance_q4_canary.xlsx")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: ATT&CK Ransomware Mapping
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-ransomware-mapping",
        TaskSubmission(task_id="task-03-attck-ransomware-mapping", answer="T1490")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Task 4 without lab -> rejected
    res4_fail = validator.validate_submission(
        db_session, test_user, room_id, "task-04-ransomware-emulation",
        TaskSubmission(task_id="task-04-ransomware-emulation", answer="RANSOMWARE_EMULATION_VERIFIED")
    )
    assert res4_fail.is_correct is False
    assert "Investigation required" in res4_fail.feedback

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple11_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Run tool command to emulate precursors
        emu_cmd = "python3 /home/operator/tools/ransomware_emulation_tool.py --emulate-precursors"
        out_emu = await runner.execute_command(sess_id, emu_cmd)
        assert "RANSOMWARE_EMULATION_VERIFIED" in out_emu
        assert info.has_action("ransomware_emulated")

        # Now Task 4 succeeds
        res4_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-04-ransomware-emulation",
            TaskSubmission(task_id="task-04-ransomware-emulation", answer="RANSOMWARE_EMULATION_VERIFIED")
        )
        assert res4_pass.is_correct is True
        assert res4_pass.completed is True

        # Task 5 before challenge completion -> rejected
        res5_fail = validator.validate_submission(
            db_session, test_user, room_id, "task-05-ransomware-challenge",
            TaskSubmission(task_id="task-05-ransomware-challenge", answer="RANSOMWARE_READINESS_VALIDATED")
        )
        assert res5_fail.is_correct is False

        # Tune canary rule and complete challenge
        tune_cmd = "python3 /home/operator/tools/ransomware_emulation_tool.py --tune-canary"
        out_tune = await runner.execute_command(sess_id, tune_cmd)
        assert "CANARY_TUNED_OK" in out_tune

        chal_cmd = "python3 /home/operator/tools/ransomware_emulation_tool.py --challenge"
        out_chal = await runner.execute_command(sess_id, chal_cmd)
        assert "RANSOMWARE_READINESS_VALIDATED" in out_chal
        assert info.has_action("ransomware_readiness_validated")

        # Now Task 5 succeeds
        res5_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-05-ransomware-challenge",
            TaskSubmission(task_id="task-05-ransomware-challenge", answer="RANSOMWARE_READINESS_VALIDATED")
        )
        assert res5_pass.is_correct is True
        assert res5_pass.completed is True

    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 5. ROOM 12: CLOUD IDENTITY & IAM PRIVILEGE ESCALATION
# ============================================================================

@pytest.mark.asyncio
async def test_room_12_cloud_identity_lifecycle(db_session: Session, test_user: User):
    """Test all tasks and validation for Purple Room 12."""
    validator = TaskValidator()
    room_id = "purple-12-cloud-identity-emulation"

    # Task 1: Cloud IMDS IP
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-cloud-imds-mechanics",
        TaskSubmission(task_id="task-01-cloud-imds-mechanics", answer="169.254.169.254")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: CloudTrail High-Privilege Role Analysis
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-cloud-audit-telemetry-analysis",
        TaskSubmission(task_id="task-02-cloud-audit-telemetry-analysis", answer="ProdSecOpsAdminRole")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: ATT&CK Cloud Identity Mapping
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-cloud-mapping",
        TaskSubmission(task_id="task-03-attck-cloud-mapping", answer="T1552.005")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Task 4 without lab -> rejected
    res4_fail = validator.validate_submission(
        db_session, test_user, room_id, "task-04-cloud-iam-emulation",
        TaskSubmission(task_id="task-04-cloud-iam-emulation", answer="CLOUD_IAM_EMULATION_VERIFIED")
    )
    assert res4_fail.is_correct is False
    assert "Investigation required" in res4_fail.feedback

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple12_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Run tool command to emulate AssumeRole
        emu_cmd = "python3 /home/operator/tools/cloud_iam_emulation_tool.py --emulate-assume-role"
        out_emu = await runner.execute_command(sess_id, emu_cmd)
        assert "CLOUD_IAM_EMULATION_VERIFIED" in out_emu
        assert info.has_action("cloud_iam_emulated")

        # Now Task 4 succeeds
        res4_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-04-cloud-iam-emulation",
            TaskSubmission(task_id="task-04-cloud-iam-emulation", answer="CLOUD_IAM_EMULATION_VERIFIED")
        )
        assert res4_pass.is_correct is True
        assert res4_pass.completed is True

        # Task 5 before challenge completion -> rejected
        res5_fail = validator.validate_submission(
            db_session, test_user, room_id, "task-05-cloud-detection-challenge",
            TaskSubmission(task_id="task-05-cloud-detection-challenge", answer="CLOUD_IDENTITY_DETECTION_VALIDATED")
        )
        assert res5_fail.is_correct is False

        # Tune alert pipeline and complete challenge
        tune_cmd = "python3 /home/operator/tools/cloud_iam_emulation_tool.py --tune-pipeline"
        out_tune = await runner.execute_command(sess_id, tune_cmd)
        assert "PIPELINE_TUNED_OK" in out_tune

        chal_cmd = "python3 /home/operator/tools/cloud_iam_emulation_tool.py --challenge"
        out_chal = await runner.execute_command(sess_id, chal_cmd)
        assert "CLOUD_IDENTITY_DETECTION_VALIDATED" in out_chal
        assert info.has_action("cloud_identity_detection_validated")

        # Now Task 5 succeeds
        res5_pass = validator.validate_submission(
            db_session, test_user, room_id, "task-05-cloud-detection-challenge",
            TaskSubmission(task_id="task-05-cloud-detection-challenge", answer="CLOUD_IDENTITY_DETECTION_VALIDATED")
        )
        assert res5_pass.is_correct is True
        assert res5_pass.completed is True

    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 6. ANTI-FORGERY REJECTION AUDIT
# ============================================================================

@pytest.mark.asyncio
async def test_purple_anti_forgery_rejection_09_12(test_user: User):
    """Verify that forged shell commands (echo, printf, python print) never satisfy requirements."""
    runner = ProcessLabRunner()
    sess_id = f"proc_forgery_purple0912_{test_user.operator_id}"
    info = await runner.start_session(sess_id, "purple-09-c2-framework-emulation", test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Attempt echo forgery
        cmd_echo = "echo C2_BEACON_EMULATION_VERIFIED"
        await runner.execute_command(sess_id, cmd_echo)
        assert not info.has_action("c2_beacon_emulated")

        # Attempt printf forgery
        cmd_printf = "printf 'C2_DETECTION_VALIDATED'"
        await runner.execute_command(sess_id, cmd_printf)
        assert not info.has_action("c2_detection_validated")

        # Attempt python one-liner print forgery
        cmd_py = 'python3 -c "print(\'EXFILTRATION_EMULATION_VERIFIED\')"'
        await runner.execute_command(sess_id, cmd_py)
        assert not info.has_action("exfil_emulated")

        # Attempt echo forgery for ransomware
        cmd_echo_rw = "echo RANSOMWARE_EMULATION_VERIFIED"
        await runner.execute_command(sess_id, cmd_echo_rw)
        assert not info.has_action("ransomware_emulated")

        # Attempt printf forgery for cloud IAM
        cmd_printf_cloud = "printf 'CLOUD_IAM_EMULATION_VERIFIED'"
        await runner.execute_command(sess_id, cmd_printf_cloud)
        assert not info.has_action("cloud_iam_emulated")

    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 7. DUAL-SESSION ISOLATION
# ============================================================================

@pytest.mark.asyncio
async def test_purple_dual_session_isolation_09_12(test_user: User, second_user: User):
    """Verify that actions performed in Operator A's session never leak to Operator B."""
    runner = ProcessLabRunner()
    sess_a = f"proc_sess_a_{test_user.operator_id}"
    sess_b = f"proc_sess_b_{second_user.operator_id}"

    info_a = await runner.start_session(sess_a, "purple-10-exfiltration-emulation", test_user.operator_id)
    info_b = await runner.start_session(sess_b, "purple-10-exfiltration-emulation", second_user.operator_id)
    lab_manager._active_sessions[sess_a] = info_a
    lab_manager._active_sessions[sess_b] = info_b

    try:
        # Operator A emulates exfil and completes challenge
        await runner.execute_command(sess_a, "python3 /home/operator/tools/exfil_emulation_tool.py --emulate-exfil")
        await runner.execute_command(sess_a, "python3 /home/operator/tools/exfil_emulation_tool.py --tune-dlp")
        await runner.execute_command(sess_a, "python3 /home/operator/tools/exfil_emulation_tool.py --challenge")

        assert info_a.has_action("exfil_emulated")
        assert info_a.has_action("exfil_detection_validated")

        # Operator B has NOT executed actions and must NOT have them awarded
        assert not info_b.has_action("exfil_emulated")
        assert not info_b.has_action("exfil_detection_validated")

    finally:
        await runner.stop_session(sess_a)
        await runner.stop_session(sess_b)
        lab_manager._active_sessions.pop(sess_a, None)
        lab_manager._active_sessions.pop(sess_b, None)


# ============================================================================
# 8. QUIZ VALIDATION ACROSS ROOMS 09–12
# ============================================================================

def test_purple_rooms_09_12_quizzes(db_session: Session, test_user: User):
    """Validate assessment quiz evaluation for Purple Rooms 09 through 12."""
    validator = TaskValidator()

    # Room 09 Quiz: Task 6 (all correct answers are index 0)
    res_q9 = validator.validate_submission(
        db_session, test_user, "purple-09-c2-framework-emulation", "task-06-c2-quiz",
        TaskSubmission(task_id="task-06-c2-quiz", quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0})
    )
    assert res_q9.is_correct is True
    assert res_q9.completed is True

    # Room 10 Quiz: Task 6
    res_q10 = validator.validate_submission(
        db_session, test_user, "purple-10-exfiltration-emulation", "task-06-exfil-quiz",
        TaskSubmission(task_id="task-06-exfil-quiz", quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0})
    )
    assert res_q10.is_correct is True
    assert res_q10.completed is True

    # Room 11 Quiz: Task 6
    res_q11 = validator.validate_submission(
        db_session, test_user, "purple-11-ransomware-readiness", "task-06-ransomware-quiz",
        TaskSubmission(task_id="task-06-ransomware-quiz", quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0})
    )
    assert res_q11.is_correct is True
    assert res_q11.completed is True

    # Room 12 Quiz: Task 6
    res_q12 = validator.validate_submission(
        db_session, test_user, "purple-12-cloud-identity-emulation", "task-06-cloud-quiz",
        TaskSubmission(task_id="task-06-cloud-quiz", quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0})
    )
    assert res_q12.is_correct is True
    assert res_q12.completed is True

