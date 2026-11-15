"""
Unit and Emulated Integration Tests for Detection Engineering Rooms 09–12:
- Room 09: Writing Web Application Detection Rules (SQLi, XSS, LFI) (detect-09-web-detection-rules)
- Room 10: ModSecurity Core Rule Set Tuning & Custom Rules (detect-10-modsec-crs-tuning)
- Room 11: Wazuh / OSSEC Rules & Decoders (detect-11-wazuh-decoders-rules)
- Room 12: Tuning Detections & Reducing False Positives (detect-12-reducing-false-positives)

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
        username="detection_engineer_0912",
        email="detection_engineer_0912@noentry.internal",
        operator_id="OP-DETECT-0912-UNIT",
        hashed_password="dummy_test_hash_detection_0912",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(name="second_user")
def second_user_fixture(db_session: Session):
    user = User(
        username="detection_operator_isolate_0912",
        email="detection_operator_isolate_0912@noentry.internal",
        operator_id="OP-DETECT-ISOLATE-0912",
        hashed_password="dummy_test_hash_detect_isolate_0912",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


# ============================================================================
# 1. CURRICULUM REGISTRATION & DETECTION TRACK TOTALS
# ============================================================================

def test_rooms_detection_09_12_curriculum_registration():
    """Verify Detection Rooms 09-12 are fully registered and configured in the curriculum."""
    for r_num in (9, 10, 11, 12):
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
    assert len(implemented_all) >= 72
    assert len(planned_all) <= 8

    detect_rooms = curriculum_registry.list_rooms(track=TrackEnum.DETECTION)
    assert len(detect_rooms) == 20
    implemented_detect = [r for r in detect_rooms if r.status == RoomStatus.IMPLEMENTED]
    planned_detect = [r for r in detect_rooms if r.status == RoomStatus.PLANNED]
    assert len(implemented_detect) >= 12
    assert len(planned_detect) <= 8

    counts = curriculum_registry.get_track_counts()
    assert counts["detection"]["total"] == 20
    assert counts["detection"]["implemented"] >= 12
    assert counts["detection"]["planned"] <= 8


# ============================================================================
# 2. ROOM 09: WRITING WEB APPLICATION DETECTION RULES LIFECYCLE
# ============================================================================

@pytest.mark.asyncio
async def test_room_09_web_detection_rules_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 09."""
    validator = TaskValidator()
    room_id = "detect-09-web-detection-rules"

    # Task 1: HTTP method field
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-web-log-schema-mechanics",
        TaskSubmission(task_id="task-01-web-log-schema-mechanics", answer="GET")
    )
    assert res1.is_correct is True

    # Task 2: SQLi comment delimiter
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-sqli-signature-analysis",
        TaskSubmission(task_id="task-02-sqli-signature-analysis", answer="--")
    )
    assert res2.is_correct is True

    # Task 3: MITRE ATT&CK Web Exploit Technique
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-web-exploit-mapping",
        TaskSubmission(task_id="task-03-attck-web-exploit-mapping", answer="T1190")
    )
    assert res3.is_correct is True

    # Start lab session for practical tasks
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect09_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Task 4: Emulate web detection rules
        emulate_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/web_detection_tool.py --emulate-detection"
        )
        assert "WEB_DETECTION_VERIFIED" in emulate_out
        assert info.has_action("web_detection_verified")

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-web-detection-emulation",
            TaskSubmission(task_id="task-04-web-detection-emulation", answer="WEB_DETECTION_VERIFIED")
        )
        assert res4.is_correct is True

        # Tune URL decode normalization filter
        tune_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/web_detection_tool.py --tune-urldecode"
        )
        assert "URL_DECODE_TUNED_OK" in tune_out

        # Task 5: Complete challenge
        challenge_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/web_detection_tool.py --challenge"
        )
        assert "WEB_DETECTION_VALIDATED" in challenge_out
        assert info.has_action("web_detection_validated")

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-web-detection-challenge",
            TaskSubmission(task_id="task-05-web-detection-challenge", answer="WEB_DETECTION_VALIDATED")
        )
        assert res5.is_correct is True

        # Task 6: Quiz with 100% score
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-web-detection-quiz",
            TaskSubmission(
                task_id="task-06-web-detection-quiz",
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
# 3. ROOM 10: MODSECURITY CORE RULE SET TUNING LIFECYCLE
# ============================================================================

@pytest.mark.asyncio
async def test_room_10_modsec_crs_tuning_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 10."""
    validator = TaskValidator()
    room_id = "detect-10-modsec-crs-tuning"
    test_user.xp = 0
    db_session.commit()

    # Task 1: ModSecurity execution phase for request headers
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-modsec-syntax-mechanics",
        TaskSubmission(task_id="task-01-modsec-syntax-mechanics", answer="2")
    )
    assert res1.is_correct is True

    # Task 2: Anomaly score critical threshold
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-crs-anomaly-scoring-analysis",
        TaskSubmission(task_id="task-02-crs-anomaly-scoring-analysis", answer="5")
    )
    assert res2.is_correct is True

    # Task 3: MITRE ATT&CK WAF Evasion Technique
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-waf-evasion-mapping",
        TaskSubmission(task_id="task-03-attck-waf-evasion-mapping", answer="T1505.003")
    )
    assert res3.is_correct is True

    # Start lab session for practical tasks
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect10_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Task 4: Emulate ModSecurity CRS evaluation
        emulate_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/modsec_tuning_tool.py --emulate-detection"
        )
        assert "MODSEC_CRS_VERIFIED" in emulate_out
        assert info.has_action("modsec_crs_verified")

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-modsec-crs-emulation",
            TaskSubmission(task_id="task-04-modsec-crs-emulation", answer="MODSEC_CRS_VERIFIED")
        )
        assert res4.is_correct is True

        # Tune paranoia level and rule exclusion
        tune_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/modsec_tuning_tool.py --tune-paranoia"
        )
        assert "PARANOIA_LEVEL_TUNED_OK" in tune_out

        # Task 5: Complete challenge
        challenge_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/modsec_tuning_tool.py --challenge"
        )
        assert "MODSEC_CRS_VALIDATED" in challenge_out
        assert info.has_action("modsec_crs_validated")

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-modsec-crs-challenge",
            TaskSubmission(task_id="task-05-modsec-crs-challenge", answer="MODSEC_CRS_VALIDATED")
        )
        assert res5.is_correct is True

        # Task 6: Quiz with 100% score
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-modsec-crs-quiz",
            TaskSubmission(
                task_id="task-06-modsec-crs-quiz",
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
# 4. ROOM 11: WAZUH / OSSEC RULES & DECODERS LIFECYCLE
# ============================================================================

@pytest.mark.asyncio
async def test_room_11_wazuh_rules_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 11."""
    validator = TaskValidator()
    room_id = "detect-11-wazuh-decoders-rules"
    test_user.xp = 0
    db_session.commit()

    # Task 1: Component that extracts raw fields
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-wazuh-pipeline-mechanics",
        TaskSubmission(task_id="task-01-wazuh-pipeline-mechanics", answer="decoder")
    )
    assert res1.is_correct is True

    # Task 2: Standard alert level threshold for SOC notifications
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-wazuh-severity-analysis",
        TaskSubmission(task_id="task-02-wazuh-severity-analysis", answer="7")
    )
    assert res2.is_correct is True

    # Task 3: MITRE ATT&CK Valid Accounts
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-hids-telemetry-mapping",
        TaskSubmission(task_id="task-03-attck-hids-telemetry-mapping", answer="T1078")
    )
    assert res3.is_correct is True

    # Start lab session for practical tasks
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect11_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Task 4: Emulate Wazuh custom decoder and rule
        emulate_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/wazuh_decoders_tool.py --emulate-detection"
        )
        assert "WAZUH_RULES_VERIFIED" in emulate_out
        assert info.has_action("wazuh_rules_verified")

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-wazuh-decoders-emulation",
            TaskSubmission(task_id="task-04-wazuh-decoders-emulation", answer="WAZUH_RULES_VERIFIED")
        )
        assert res4.is_correct is True

        # Tune decoder regex
        tune_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/wazuh_decoders_tool.py --tune-decoder"
        )
        assert "DECODER_REGEX_TUNED_OK" in tune_out

        # Task 5: Complete challenge
        challenge_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/wazuh_decoders_tool.py --challenge"
        )
        assert "WAZUH_RULES_VALIDATED" in challenge_out
        assert info.has_action("wazuh_rules_validated")

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-wazuh-decoders-challenge",
            TaskSubmission(task_id="task-05-wazuh-decoders-challenge", answer="WAZUH_RULES_VALIDATED")
        )
        assert res5.is_correct is True

        # Task 6: Quiz with 100% score
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-wazuh-rules-quiz",
            TaskSubmission(
                task_id="task-06-wazuh-rules-quiz",
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
# 5. ROOM 12: TUNING DETECTIONS & REDUCING FALSE POSITIVES LIFECYCLE
# ============================================================================

@pytest.mark.asyncio
async def test_room_12_false_positive_tuning_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Detection Room 12."""
    validator = TaskValidator()
    room_id = "detect-12-reducing-false-positives"
    test_user.xp = 0
    db_session.commit()

    # Task 1: Tuning metric (False Discovery Rate)
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-tuning-metric-mechanics",
        TaskSubmission(task_id="task-01-tuning-metric-mechanics", answer="FDR")
    )
    assert res1.is_correct is True

    # Task 2: Blind spot vulnerable field
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-blind-spot-vulnerability-analysis",
        TaskSubmission(task_id="task-02-blind-spot-vulnerability-analysis", answer="Image")
    )
    assert res2.is_correct is True

    # Task 3: MITRE ATT&CK Masquerading
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-masquerading-mapping",
        TaskSubmission(task_id="task-03-attck-masquerading-mapping", answer="T1036")
    )
    assert res3.is_correct is True

    # Start lab session for practical tasks
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect12_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Task 4: Emulate detection tuning baseline
        emulate_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/false_positive_tool.py --emulate-detection"
        )
        assert "FALSE_POSITIVE_TUNING_VERIFIED" in emulate_out
        assert info.has_action("false_positive_tuning_verified")

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-false-positive-emulation",
            TaskSubmission(task_id="task-04-false-positive-emulation", answer="FALSE_POSITIVE_TUNING_VERIFIED")
        )
        assert res4.is_correct is True

        # Tune baseline exclusions
        tune_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/false_positive_tool.py --tune-baseline"
        )
        assert "BASELINE_EXCLUSION_TUNED_OK" in tune_out

        # Task 5: Complete challenge
        challenge_out = await runner.execute_command(
            sess_id, "python3 /home/operator/tools/false_positive_tool.py --challenge"
        )
        assert "FALSE_POSITIVE_TUNING_VALIDATED" in challenge_out
        assert info.has_action("false_positive_tuning_validated")

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-false-positive-challenge",
            TaskSubmission(task_id="task-05-false-positive-challenge", answer="FALSE_POSITIVE_TUNING_VALIDATED")
        )
        assert res5.is_correct is True

        # Task 6: Quiz with 100% score
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-tuning-quiz",
            TaskSubmission(
                task_id="task-06-tuning-quiz",
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
async def test_anti_forgery_rejection_detection_rooms(db_session: Session, test_user: User):
    """Verify that forged echo/printf commands do not record challenge completion actions."""
    runner = ProcessLabRunner()
    sess_id = f"proc_test_detect_forgery_{test_user.operator_id}"
    info = await runner.start_session(sess_id, "detect-09-web-detection-rules", test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Attempt forgery for Room 09
        await runner.execute_command(sess_id, "echo WEB_DETECTION_VERIFIED")
        assert not info.has_action("web_detection_verified")

        # Attempt forgery for Room 10
        await runner.execute_command(sess_id, "printf 'MODSEC_CRS_VERIFIED\\n'")
        assert not info.has_action("modsec_crs_verified")

        # Attempt forgery for Room 11
        await runner.execute_command(sess_id, "echo WAZUH_RULES_VERIFIED")
        assert not info.has_action("wazuh_rules_verified")

        # Attempt forgery for Room 12
        await runner.execute_command(sess_id, "echo FALSE_POSITIVE_TUNING_VERIFIED")
        assert not info.has_action("false_positive_tuning_verified")
    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


@pytest.mark.asyncio
async def test_dual_session_cross_session_isolation(
    db_session: Session, test_user: User, second_user: User
):
    """Verify that actions recorded in Session A do NOT bleed into Session B."""
    runner = ProcessLabRunner()
    room_id = "detect-12-reducing-false-positives"

    sess_a = f"proc_test_detect12_sessA_{test_user.operator_id}"
    sess_b = f"proc_test_detect12_sessB_{second_user.operator_id}"

    info_a = await runner.start_session(sess_a, room_id, test_user.operator_id)
    info_b = await runner.start_session(sess_b, room_id, second_user.operator_id)

    lab_manager._active_sessions[sess_a] = info_a
    lab_manager._active_sessions[sess_b] = info_b

    try:
        # Operator A completes emulation and challenge
        await runner.execute_command(sess_a, "python3 /home/operator/tools/false_positive_tool.py --emulate-detection")
        await runner.execute_command(sess_a, "python3 /home/operator/tools/false_positive_tool.py --tune-baseline")
        await runner.execute_command(sess_a, "python3 /home/operator/tools/false_positive_tool.py --challenge")

        assert info_a.has_action("false_positive_tuning_verified")
        assert info_a.has_action("false_positive_tuning_validated")

        # Operator B has NOT executed the tools -> must have no actions
        assert not info_b.has_action("false_positive_tuning_verified")
        assert not info_b.has_action("false_positive_tuning_validated")

        # Validator for Operator B must reject
        validator = TaskValidator()
        res_b = validator.validate_submission(
            db_session, second_user, room_id, "task-04-false-positive-emulation",
            TaskSubmission(task_id="task-04-false-positive-emulation", answer="FALSE_POSITIVE_TUNING_VERIFIED")
        )
        assert res_b.is_correct is False
        assert "Investigation incomplete" in res_b.feedback
    finally:
        await runner.stop_session(sess_a)
        await runner.stop_session(sess_b)
        lab_manager._active_sessions.pop(sess_a, None)
        lab_manager._active_sessions.pop(sess_b, None)

