"""
Unit and Emulated Integration Tests for Detection Engineering Rooms 17–20:
- Room 17: Snort / Suricata Network Signatures (detect-17-snort-suricata)
- Room 18: Threat Hunting Hypothesis Formulation (detect-18-threat-hunting-hypothesis)
- Room 19: CI/CD Pipelines for Detection Rules (detect-19-ci-cd-detection-pipelines)
- Room 20: Detection Engineering Capstone: Production Pipeline (detect-20-capstone-detection-pipeline)

Validates curriculum integration, task validation engine, anti-forgery guards,
prerequisite enforcement, trusted-session identity, and dual-session cross-isolation.
Completes verification for all 80 rooms across the platform.
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
        username="detection_engineer_1720",
        email="detection_engineer_1720@noentry.internal",
        operator_id="OP-DETECT-1720-UNIT",
        hashed_password="dummy_test_hash_detection_1720",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(name="second_user")
def second_user_fixture(db_session: Session):
    user = User(
        username="detection_operator_isolate_1720",
        email="detection_operator_isolate_1720@noentry.internal",
        operator_id="OP-DETECT-ISOLATE-1720",
        hashed_password="dummy_test_hash_detect_isolate_1720",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


# ============================================================================
# 1. CURRICULUM REGISTRATION & PLATFORM-WIDE 80-ROOM TOTALS
# ============================================================================

def test_rooms_detection_17_20_curriculum_registration():
    """Verify Detection Rooms 17-20 are fully registered and complete the 80-room platform."""
    for r_num in (17, 18, 19, 20):
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
        assert room.concept.simple_analogy
        assert room.concept.technical_definition
        assert room.concept.cybersecurity_context
        assert room.concept.why_it_matters
        assert room.concept.demonstration
        assert room.concept.remediation_guide
        assert "toddler" not in room.concept.simple_analogy.lower()
        assert "baby" not in room.concept.simple_analogy.lower()

    # Verify track statistics across platform: 100% complete (80/80)
    all_rooms = curriculum_registry.list_rooms()
    assert len(all_rooms) == 80
    implemented_all = [r for r in all_rooms if r.status == RoomStatus.IMPLEMENTED]
    planned_all = [r for r in all_rooms if r.status == RoomStatus.PLANNED]
    assert len(implemented_all) == 80
    assert len(planned_all) == 0

    counts = curriculum_registry.get_track_counts()
    assert counts["red"]["implemented"] == 20
    assert counts["red"]["planned"] == 0
    assert counts["blue"]["implemented"] == 20
    assert counts["blue"]["planned"] == 0
    assert counts["purple"]["implemented"] == 20
    assert counts["purple"]["planned"] == 0
    assert counts["detection"]["implemented"] == 20
    assert counts["detection"]["planned"] == 0


# ============================================================================
# 2. ROOM 17: SNORT / SURICATA NETWORK SIGNATURES LIFECYCLE
# ============================================================================

@pytest.mark.asyncio
async def test_room_17_snort_suricata_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 17."""
    validator = TaskValidator()
    room_id = "detect-17-snort-suricata"

    # Task 1: Flow keyword
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-snort-rule-header-mechanics",
        TaskSubmission(task_id="task-01-snort-rule-header-mechanics", answer="established")
    )
    assert res1.is_correct is True

    # Task 2: Signature Identifier keyword
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-suricata-sid-mechanics",
        TaskSubmission(task_id="task-02-suricata-sid-mechanics", answer="sid")
    )
    assert res2.is_correct is True

    # Task 3: MITRE ATT&CK Application Layer Protocol
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-network-protocol-mapping",
        TaskSubmission(task_id="task-03-attck-network-protocol-mapping", answer="T1071")
    )
    assert res3.is_correct is True

    # Start lab session for practical tasks
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect17_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Check dataset inspection
        cat_out = await runner.execute_command(
            sess_id, "cat /var/log/detection/suricata_network_events.json"
        )
        assert "ATTACK_JNDI_INJECTION" in cat_out

        # Task 4: Emulate signature
        emulate_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/suricata_tool.py --emulate-signature"
        )
        assert "SURICATA_SIGNATURE_VERIFIED" in emulate_out
        assert info.has_action("suricata_signature_verified")

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-snort-suricata-emulation",
            TaskSubmission(task_id="task-04-snort-suricata-emulation", answer="SURICATA_SIGNATURE_VERIFIED")
        )
        assert res4.is_correct is True

        # Tune PCRE clause
        tune_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/suricata_tool.py --tune-pcre"
        )
        assert "SURICATA_PCRE_TUNED_OK" in tune_out

        # Task 5: Complete challenge
        challenge_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/suricata_tool.py --challenge"
        )
        assert "SURICATA_SIGNATURE_VALIDATED" in challenge_out
        assert info.has_action("suricata_signature_validated")

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-snort-suricata-challenge",
            TaskSubmission(task_id="task-05-snort-suricata-challenge", answer="SURICATA_SIGNATURE_VALIDATED")
        )
        assert res5.is_correct is True

        # Task 6: Quiz with 100% score
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-snort-suricata-quiz",
            TaskSubmission(
                task_id="task-06-snort-suricata-quiz",
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
# 3. ROOM 18: THREAT HUNTING HYPOTHESIS FORMULATION LIFECYCLE
# ============================================================================

@pytest.mark.asyncio
async def test_room_18_threat_hunting_hypothesis_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 18."""
    validator = TaskValidator()
    room_id = "detect-18-threat-hunting-hypothesis"

    # Task 1: Core foundational artifact
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-hypothesis-structure-mechanics",
        TaskSubmission(task_id="task-01-hypothesis-structure-mechanics", answer="hypothesis")
    )
    assert res1.is_correct is True

    # Task 2: Core hunting KPI
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-hunt-metrics-dwell-time",
        TaskSubmission(task_id="task-02-hunt-metrics-dwell-time", answer="dwell time")
    )
    assert res2.is_correct is True

    # Task 3: MITRE ATT&CK Windows Management Instrumentation
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-lolbin-wmi-mapping",
        TaskSubmission(task_id="task-03-attck-lolbin-wmi-mapping", answer="T1047")
    )
    assert res3.is_correct is True

    # Start lab session for practical tasks
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect18_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Check dataset inspection
        cat_out = await runner.execute_command(
            sess_id, "cat /var/log/detection/threat_hunting_corpus.json"
        )
        assert "ATTACK_REMOTE_WMI_EXECUTION" in cat_out

        # Task 4: Emulate hunt
        emulate_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/threat_hunting_tool.py --emulate-hunt"
        )
        assert "THREAT_HUNT_HYPOTHESIS_VERIFIED" in emulate_out
        assert info.has_action("threat_hunt_hypothesis_verified")

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-threat-hunting-hypothesis-emulation",
            TaskSubmission(task_id="task-04-threat-hunting-hypothesis-emulation", answer="THREAT_HUNT_HYPOTHESIS_VERIFIED")
        )
        assert res4.is_correct is True

        # Tune hunt hypothesis
        tune_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/threat_hunting_tool.py --tune-hypothesis"
        )
        assert "HUNT_HYPOTHESIS_TUNED_OK" in tune_out

        # Task 5: Complete challenge
        challenge_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/threat_hunting_tool.py --challenge"
        )
        assert "THREAT_HUNT_HYPOTHESIS_VALIDATED" in challenge_out
        assert info.has_action("threat_hunt_hypothesis_validated")

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-threat-hunting-hypothesis-challenge",
            TaskSubmission(task_id="task-05-threat-hunting-hypothesis-challenge", answer="THREAT_HUNT_HYPOTHESIS_VALIDATED")
        )
        assert res5.is_correct is True

        # Task 6: Quiz with 100% score
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-threat-hunting-hypothesis-quiz",
            TaskSubmission(
                task_id="task-06-threat-hunting-hypothesis-quiz",
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
# 4. ROOM 19: CI/CD PIPELINES FOR DETECTION RULES LIFECYCLE
# ============================================================================

@pytest.mark.asyncio
async def test_room_19_ci_cd_detection_pipelines_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 19."""
    validator = TaskValidator()
    room_id = "detect-19-ci-cd-detection-pipelines"

    # Task 1: First fast-fail pipeline stage
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-pipeline-stage-mechanics",
        TaskSubmission(task_id="task-01-pipeline-stage-mechanics", answer="lint")
    )
    assert res1.is_correct is True

    # Task 2: Git peer review construct
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-git-workflow-branching",
        TaskSubmission(task_id="task-02-git-workflow-branching", answer="pull request")
    )
    assert res2.is_correct is True

    # Task 3: MITRE ATT&CK Compromise Software Supply Chain
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-cicd-pipeline-mapping",
        TaskSubmission(task_id="task-03-attck-cicd-pipeline-mapping", answer="T1195.002")
    )
    assert res3.is_correct is True

    # Start lab session for practical tasks
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect19_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Check dataset inspection
        cat_out = await runner.execute_command(
            sess_id, "cat /var/log/detection/ci_cd_pipeline_definition.json"
        )
        assert "detection-as-code-ci-cd" in cat_out

        # Task 4: Emulate pipeline run
        emulate_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/pipeline_tool.py --emulate-pipeline"
        )
        assert "DETECTION_PIPELINE_VERIFIED" in emulate_out
        assert info.has_action("detection_pipeline_verified")

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-detection-pipeline-emulation",
            TaskSubmission(task_id="task-04-detection-pipeline-emulation", answer="DETECTION_PIPELINE_VERIFIED")
        )
        assert res4.is_correct is True

        # Tune pipeline gate
        tune_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/pipeline_tool.py --tune-gate"
        )
        assert "PIPELINE_GATE_TUNED_OK" in tune_out

        # Task 5: Complete challenge
        challenge_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/pipeline_tool.py --challenge"
        )
        assert "DETECTION_PIPELINE_VALIDATED" in challenge_out
        assert info.has_action("detection_pipeline_validated")

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-detection-pipeline-challenge",
            TaskSubmission(task_id="task-05-detection-pipeline-challenge", answer="DETECTION_PIPELINE_VALIDATED")
        )
        assert res5.is_correct is True

        # Task 6: Quiz with 100% score
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-detection-pipeline-quiz",
            TaskSubmission(
                task_id="task-06-detection-pipeline-quiz",
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
# 5. ROOM 20: CAPSTONE LIFECYCLE (FINAL ROOM OF THE PLATFORM)
# ============================================================================

@pytest.mark.asyncio
async def test_room_20_capstone_detection_pipeline_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 20 (Platform Capstone)."""
    validator = TaskValidator()
    room_id = "detect-20-capstone-detection-pipeline"

    # Task 1: Operational triage document
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-capstone-lifecycle-mechanics",
        TaskSubmission(task_id="task-01-capstone-lifecycle-mechanics", answer="playbook")
    )
    assert res1.is_correct is True

    # Task 2: Standard log taxonomy
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-capstone-telemetry-taxonomy",
        TaskSubmission(task_id="task-02-capstone-telemetry-taxonomy", answer="ECS")
    )
    assert res2.is_correct is True

    # Task 3: MITRE ATT&CK OS Credential Dumping: LSASS Memory
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-lsass-dumping-mapping",
        TaskSubmission(task_id="task-03-attck-lsass-dumping-mapping", answer="T1003.001")
    )
    assert res3.is_correct is True

    # Start lab session for practical tasks
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect20_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Check dataset inspection
        cat_out = await runner.execute_command(
            sess_id, "cat /var/log/detection/capstone_enterprise_pipeline.json"
        )
        assert "VoltCorp Global SOC Infrastructure" in cat_out

        # Task 4: Emulate capstone pipeline
        emulate_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/capstone_pipeline_tool.py --emulate-capstone"
        )
        assert "CAPSTONE_PIPELINE_VERIFIED" in emulate_out
        assert info.has_action("capstone_pipeline_verified")

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-capstone-pipeline-emulation",
            TaskSubmission(task_id="task-04-capstone-pipeline-emulation", answer="CAPSTONE_PIPELINE_VERIFIED")
        )
        assert res4.is_correct is True

        # Tune production gate
        tune_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/capstone_pipeline_tool.py --tune-production"
        )
        assert "CAPSTONE_PRODUCTION_TUNED_OK" in tune_out

        # Task 5: Complete challenge
        challenge_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/capstone_pipeline_tool.py --challenge"
        )
        assert "CAPSTONE_PIPELINE_VALIDATED" in challenge_out
        assert info.has_action("capstone_pipeline_validated")

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-capstone-pipeline-challenge",
            TaskSubmission(task_id="task-05-capstone-pipeline-challenge", answer="CAPSTONE_PIPELINE_VALIDATED")
        )
        assert res5.is_correct is True

        # Task 6: Quiz with 100% score
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-capstone-pipeline-quiz",
            TaskSubmission(
                task_id="task-06-capstone-pipeline-quiz",
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
async def test_anti_forgery_rejection_detection_rooms_17_20(db_session: Session, test_user: User):
    """Verify that forged echo/printf commands do not record challenge completion actions."""
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect_forgery_{test_user.operator_id}"
    info = await runner.start_session(sess_id, "detect-17-snort-suricata", test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Attempt forgery for Room 17
        await runner.execute_command(sess_id, "echo SURICATA_SIGNATURE_VERIFIED")
        assert not info.has_action("suricata_signature_verified")

        # Attempt forgery for Room 18
        await runner.execute_command(sess_id, "printf 'THREAT_HUNT_HYPOTHESIS_VERIFIED\\n'")
        assert not info.has_action("threat_hunt_hypothesis_verified")

        # Attempt forgery for Room 19
        await runner.execute_command(sess_id, "echo DETECTION_PIPELINE_VERIFIED")
        assert not info.has_action("detection_pipeline_verified")

        # Attempt forgery for Room 20
        await runner.execute_command(sess_id, "echo CAPSTONE_PIPELINE_VERIFIED")
        assert not info.has_action("capstone_pipeline_verified")
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


@pytest.mark.asyncio
async def test_dual_session_cross_session_isolation_17_20(
    db_session: Session, test_user: User, second_user: User
):
    """Verify that actions recorded in Session A do NOT bleed into Session B."""
    runner = ProcessLabRunner()
    room_id = "detect-20-capstone-detection-pipeline"

    sess_a = f"proc_test_detect20_sessA_{test_user.operator_id}"
    sess_b = f"proc_test_detect20_sessB_{second_user.operator_id}"

    info_a = await runner.start_session(sess_a, room_id, test_user.operator_id)
    info_b = await runner.start_session(sess_b, room_id, second_user.operator_id)

    lab_manager._active_sessions[sess_a] = info_a
    lab_manager._active_sessions[sess_b] = info_b

    try:
        # Operator A completes emulation and challenge
        await runner.execute_command(sess_a, "python3 /home/operator/tools/capstone_pipeline_tool.py --emulate-capstone")
        await runner.execute_command(sess_a, "python3 /home/operator/tools/capstone_pipeline_tool.py --tune-production")
        await runner.execute_command(sess_a, "python3 /home/operator/tools/capstone_pipeline_tool.py --challenge")

        assert info_a.has_action("capstone_pipeline_verified")
        assert info_a.has_action("capstone_pipeline_validated")

        # Operator B has NOT executed the tools -> must have no actions
        assert not info_b.has_action("capstone_pipeline_verified")
        assert not info_b.has_action("capstone_pipeline_validated")

        # Validator for Operator B must reject
        validator = TaskValidator()
        res_b = validator.validate_submission(
            db_session, second_user, room_id, "task-04-capstone-pipeline-emulation",
            TaskSubmission(task_id="task-04-capstone-pipeline-emulation", answer="CAPSTONE_PIPELINE_VERIFIED")
        )
        assert res_b.is_correct is False
        assert "Investigation incomplete" in res_b.feedback
    finally:
        await runner.stop_session(sess_a)
        await runner.stop_session(sess_b)
        lab_manager._active_sessions.pop(sess_a, None)
        lab_manager._active_sessions.pop(sess_b, None)
