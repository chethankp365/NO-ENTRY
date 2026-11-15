"""
Unit and Emulated Integration Tests for Purple Team Rooms 01–04:
- Room 01: Purple Team Foundations (purple-01-purple-team-foundations)
- Room 02: MITRE ATT&CK Fundamentals (purple-02-mitre-attack-fundamentals)
- Room 03: Attack Simulation Planning (purple-03-attack-simulation-planning)
- Room 04: Reconnaissance vs Monitoring (purple-04-reconnaissance-vs-monitoring)

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
        username="purple_operator_0104",
        email="purple_operator_0104@noentry.internal",
        operator_id="OP-PURPLE-0104-UNIT",
        hashed_password="dummy_test_hash_purple",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(name="second_user")
def second_user_fixture(db_session: Session):
    user = User(
        username="purple_operator_isolate",
        email="purple_operator_isolate@noentry.internal",
        operator_id="OP-PURPLE-ISOLATE-UNIT",
        hashed_password="dummy_test_hash_purple_isolate",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


# ============================================================================
# 1. CURRICULUM REGISTRATION & PURPLE TRACK TOTALS
# ============================================================================

def test_rooms_purple_01_04_curriculum_registration():
    """Verify Purple Rooms 01-04 are fully registered and configured in the curriculum."""
    for r_num in (1, 2, 3, 4):
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
    assert len(implemented_purple) >= 4
    assert len(implemented_purple) + len(planned_purple) == 20

    counts = curriculum_registry.get_track_counts()
    assert counts["purple"]["total"] == 20
    assert counts["purple"]["implemented"] >= 4
    assert counts["purple"]["implemented"] + counts["purple"]["planned"] == 20


# ============================================================================
# 2. ROOM 01: PURPLE TEAM FOUNDATIONS VALIDATION
# ============================================================================

@pytest.mark.asyncio
async def test_room_01_purple_foundations_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Purple Room 01 (Purple Team Foundations)."""
    validator = TaskValidator()
    room_id = "purple-01-purple-team-foundations"

    # Task 1: Purple Mission & Collaboration
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-purple-team-mission-collaboration",
        TaskSubmission(task_id="task-01-purple-team-mission-collaboration", answer="Validate and improve defensive detection capabilities")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Exercise Scope Identifier
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-exercise-scope-objective",
        TaskSubmission(task_id="task-02-exercise-scope-objective", answer="PT-2026-001")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: ATT&CK Technique Selection
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-attck-technique-selection",
        TaskSubmission(task_id="task-03-attck-technique-selection", answer="T1059.001")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Task 4 without active lab -> rejected
    res4_fail = validator.validate_submission(
        db_session, test_user, room_id, "task-04-telemetry-mapping",
        TaskSubmission(task_id="task-04-telemetry-mapping", answer="PURPLE_TELEMETRY_MAP_VERIFIED")
    )
    assert res4_fail.is_correct is False
    assert "Investigation required" in res4_fail.feedback

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple01_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Submit Purple Scope
        scope_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"exercise_id":"PT-2026-001","collaboration_model":"COLLABORATIVE_PAIRING","focus_technique":"T1059.001"}\' '
            'http://127.0.0.1:8301/api/purple/scope'
        )
        out_scope = await runner.execute_command(sess_id, scope_cmd)
        assert "PURPLE_SCOPE_APPROVED" in out_scope

        # Map Telemetry
        map_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"exercise_id":"PT-2026-001","technique_id":"T1059.001","telemetry_source":"Sysmon EventID 1","detection_status":"LOGGED"}\' '
            'http://127.0.0.1:8301/api/purple/telemetry-map'
        )
        out_map = await runner.execute_command(sess_id, map_cmd)
        assert "PURPLE_TELEMETRY_MAP_VERIFIED" in out_map
        assert info.has_action("purple_telemetry_mapped")

        # Validate Task 4 with active action
        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-telemetry-mapping",
            TaskSubmission(task_id="task-04-telemetry-mapping", answer="PURPLE_TELEMETRY_MAP_VERIFIED")
        )
        assert res4.is_correct is True
        assert res4.completed is True

        # Complete Exercise Challenge
        chal_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"action":"FINALIZE_PURPLE_FOUNDATIONS","exercise_id":"PT-2026-001"}\' '
            'http://127.0.0.1:8301/challenge'
        )
        out_chal = await runner.execute_command(sess_id, chal_cmd)
        assert "PURPLE_FOUNDATIONS_EXERCISE_APPROVED" in out_chal
        assert info.has_action("purple_foundations_approved")

        # Validate Task 5
        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-purple-foundations-challenge",
            TaskSubmission(task_id="task-05-purple-foundations-challenge", answer="PURPLE_FOUNDATIONS_EXERCISE_APPROVED")
        )
        assert res5.is_correct is True
        assert res5.completed is True

        # Task 6: Technical Quiz
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-purple-foundations-quiz",
            TaskSubmission(task_id="task-06-purple-foundations-quiz", quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0})
        )
        assert res6.is_correct is True
        assert res6.completed is True

    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 3. ROOM 02: MITRE ATT&CK FUNDAMENTALS VALIDATION
# ============================================================================

@pytest.mark.asyncio
async def test_room_02_attck_fundamentals_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Purple Room 02 (MITRE ATT&CK Fundamentals)."""
    validator = TaskValidator()
    room_id = "purple-02-mitre-attack-fundamentals"

    # Task 1: ATT&CK Structure
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-attck-structure-tactics-techniques",
        TaskSubmission(task_id="task-01-attck-structure-tactics-techniques", answer="Tactic")
    )
    assert res1.is_correct is True

    # Task 2: Kerberoasting Technique
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-auth-artifact-kerberoasting-mapping",
        TaskSubmission(task_id="task-02-auth-artifact-kerberoasting-mapping", answer="T1558.003")
    )
    assert res2.is_correct is True

    # Task 3: Registry Persistence Technique
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-persistence-artifact-registry-mapping",
        TaskSubmission(task_id="task-03-persistence-artifact-registry-mapping", answer="T1547.001")
    )
    assert res3.is_correct is True

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple02_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Retrieve evidence
        get_ev_cmd = 'curl -s http://127.0.0.1:8302/api/attck/evidence'
        out_ev = await runner.execute_command(sess_id, get_ev_cmd)
        assert "ATTCK_EVIDENCE_LOGS" in out_ev

        # Map evidence
        map_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"techniques":["T1558.003","T1547.001"],"kerberoasting_technique":"T1558.003","persistence_technique":"T1547.001"}\' '
            'http://127.0.0.1:8302/api/attck/map-evidence'
        )
        out_map = await runner.execute_command(sess_id, map_cmd)
        assert "ATTCK_EVIDENCE_MAPPING_VERIFIED" in out_map
        assert info.has_action("attck_evidence_mapped")

        # Validate Task 4
        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-attck-evidence-mapping",
            TaskSubmission(task_id="task-04-attck-evidence-mapping", answer="ATTCK_EVIDENCE_MAPPING_VERIFIED")
        )
        assert res4.is_correct is True

        # Challenge completion
        chal_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"action":"SUBMIT_ATTCK_LIFECYCLE_MAPPING"}\' '
            'http://127.0.0.1:8302/challenge'
        )
        out_chal = await runner.execute_command(sess_id, chal_cmd)
        assert "ATTCK_LIFECYCLE_MAPPING_COMPLETE" in out_chal
        assert info.has_action("attck_lifecycle_complete")

        # Validate Task 5
        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-attck-mapping-challenge",
            TaskSubmission(task_id="task-05-attck-mapping-challenge", answer="ATTCK_LIFECYCLE_MAPPING_COMPLETE")
        )
        assert res5.is_correct is True

        # Task 6: Technical Quiz
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-attck-quiz",
            TaskSubmission(task_id="task-06-attck-quiz", quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0})
        )
        assert res6.is_correct is True

    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 4. ROOM 03: ATTACK SIMULATION PLANNING VALIDATION
# ============================================================================

@pytest.mark.asyncio
async def test_room_03_simulation_planning_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Purple Room 03 (Attack Simulation Planning)."""
    validator = TaskValidator()
    room_id = "purple-03-attack-simulation-planning"

    # Task 1: Governance RoE
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-simulation-governance-roe",
        TaskSubmission(task_id="task-01-simulation-governance-roe", answer="Rules of Engagement")
    )
    assert res1.is_correct is True

    # Task 2: Target Scope IP
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-target-identification-scope",
        TaskSubmission(task_id="task-02-target-identification-scope", answer="10.10.14.90")
    )
    assert res2.is_correct is True

    # Task 3: Rollback Objective
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-cleanup-rollback-planning",
        TaskSubmission(task_id="task-03-cleanup-rollback-planning", answer="To prevent leaving systems in an insecure state")
    )
    assert res3.is_correct is True

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple03_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Validate scope
        val_scope_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"target_ip":"10.10.14.90","roe_accepted":true,"simulation_id":"SIM-2026-ALPHA"}\' '
            'http://127.0.0.1:8303/api/simulation/validate-scope'
        )
        out_scope = await runner.execute_command(sess_id, val_scope_cmd)
        assert "SIMULATION_SCOPE_VALIDATED" in out_scope

        # Register simulation step
        step_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"technique_id":"T1059.001","command":"powershell.exe -ExecutionPolicy Bypass -File audit_check.ps1","rollback":"Remove audit_check.ps1"}\' '
            'http://127.0.0.1:8303/api/simulation/register-step'
        )
        out_step = await runner.execute_command(sess_id, step_cmd)
        assert "SIMULATION_STEP_REGISTERED" in out_step
        assert info.has_action("simulation_step_registered")

        # Validate Task 4
        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-register-simulation-step",
            TaskSubmission(task_id="task-04-register-simulation-step", answer="SIMULATION_STEP_REGISTERED")
        )
        assert res4.is_correct is True

        # Challenge completion
        chal_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"action":"APPROVE_SIMULATION_PLAN","plan_id":"SIM-2026-ALPHA"}\' '
            'http://127.0.0.1:8303/challenge'
        )
        out_chal = await runner.execute_command(sess_id, chal_cmd)
        assert "ATTACK_SIMULATION_PLAN_APPROVED" in out_chal
        assert info.has_action("simulation_plan_approved")

        # Validate Task 5
        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-simulation-planning-challenge",
            TaskSubmission(task_id="task-05-simulation-planning-challenge", answer="ATTACK_SIMULATION_PLAN_APPROVED")
        )
        assert res5.is_correct is True

        # Task 6: Technical Quiz
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-simulation-planning-quiz",
            TaskSubmission(task_id="task-06-simulation-planning-quiz", quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0})
        )
        assert res6.is_correct is True

    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 5. ROOM 04: RECONNAISSANCE VS MONITORING VALIDATION
# ============================================================================

@pytest.mark.asyncio
async def test_room_04_recon_monitoring_lifecycle(db_session: Session, test_user: User):
    """Test all 6 tasks for Purple Room 04 (Reconnaissance vs Monitoring)."""
    validator = TaskValidator()
    room_id = "purple-04-reconnaissance-vs-monitoring"

    # Task 1: Scan Type (SYN)
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-recon-mechanics-syn-scan",
        TaskSubmission(task_id="task-01-recon-mechanics-syn-scan", answer="SYN")
    )
    assert res1.is_correct is True

    # Task 2: Target Port 8094
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-port-enumeration-service-identification",
        TaskSubmission(task_id="task-02-port-enumeration-service-identification", answer="8094")
    )
    assert res2.is_correct is True

    # Task 3: Sensor Alert Name
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-defensive-sensor-telemetry-analysis",
        TaskSubmission(task_id="task-03-defensive-sensor-telemetry-analysis", answer="PORT_SCAN_DETECTED")
    )
    assert res3.is_correct is True

    # Start lab session
    runner = ProcessLabRunner()
    sess_id = f"proc_test_purple04_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    lab_manager._active_sessions[sess_id] = info

    try:
        # Correlate recon telemetry
        corr_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"scan_type":"SYN","targeted_port":"8094","sensor_alert":"PORT_SCAN_DETECTED"}\' '
            'http://127.0.0.1:8304/api/monitoring/correlate'
        )
        out_corr = await runner.execute_command(sess_id, corr_cmd)
        assert "RECON_MONITORING_CORRELATION_CONFIRMED" in out_corr
        assert info.has_action("recon_correlation_confirmed")

        # Validate Task 4
        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-recon-telemetry-correlation",
            TaskSubmission(task_id="task-04-recon-telemetry-correlation", answer="RECON_MONITORING_CORRELATION_CONFIRMED")
        )
        assert res4.is_correct is True

        # Tune threshold
        tune_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"syn_threshold_pps":20,"action":"ALERT"}\' '
            'http://127.0.0.1:8304/api/monitoring/tune-threshold'
        )
        out_tune = await runner.execute_command(sess_id, tune_cmd)
        assert "THRESHOLD_TUNED_OK" in out_tune

        # Challenge completion
        chal_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"action":"VALIDATE_RECON_MONITORING"}\' '
            'http://127.0.0.1:8304/challenge'
        )
        out_chal = await runner.execute_command(sess_id, chal_cmd)
        assert "RECON_VS_MONITORING_VALIDATED" in out_chal
        assert info.has_action("recon_monitoring_validated")

        # Validate Task 5
        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-recon-monitoring-challenge",
            TaskSubmission(task_id="task-05-recon-monitoring-challenge", answer="RECON_VS_MONITORING_VALIDATED")
        )
        assert res5.is_correct is True

        # Task 6: Technical Quiz
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-recon-monitoring-quiz",
            TaskSubmission(task_id="task-06-recon-monitoring-quiz", quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0})
        )
        assert res6.is_correct is True

    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 6. ANTI-FORGERY & DUAL-SESSION ISOLATION AUDIT
# ============================================================================

@pytest.mark.asyncio
async def test_purple_anti_forgery_echo_rejection(db_session: Session, test_user: User):
    """Echoing verification tokens without executing genuine tools must NOT award action verification."""
    runner = ProcessLabRunner()
    sess_id = f"proc_test_forgery_{test_user.operator_id}"
    info = await runner.start_session(sess_id, "purple-01-purple-team-foundations", test_user.operator_id)

    try:
        # Attacker tries to fake action via echo
        await runner.execute_command(sess_id, 'echo "PURPLE_TELEMETRY_MAP_VERIFIED"')
        assert not info.has_action("purple_telemetry_mapped")

        await runner.execute_command(sess_id, 'printf "PURPLE_FOUNDATIONS_EXERCISE_APPROVED\\n"')
        assert not info.has_action("purple_foundations_approved")
    finally:
        await runner.stop_session(sess_id)


@pytest.mark.asyncio
async def test_purple_dual_session_cross_session_isolation(db_session: Session, test_user: User, second_user: User):
    """User A completing Purple actions must NOT satisfy User B's tasks."""
    runner = ProcessLabRunner()
    sess_a = f"proc_test_dual_a_{test_user.operator_id}"
    sess_b = f"proc_test_dual_b_{second_user.operator_id}"
    room_id = "purple-01-purple-team-foundations"

    info_a = await runner.start_session(sess_a, room_id, test_user.operator_id)
    info_b = await runner.start_session(sess_b, room_id, second_user.operator_id)

    lab_manager._active_sessions[sess_a] = info_a
    lab_manager._active_sessions[sess_b] = info_b

    try:
        # User A executes scope submission and telemetry mapping
        await runner.execute_command(
            sess_a,
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"exercise_id":"PT-2026-001","collaboration_model":"COLLABORATIVE_PAIRING","focus_technique":"T1059.001"}\' '
            'http://127.0.0.1:8301/api/purple/scope'
        )
        await runner.execute_command(
            sess_a,
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"exercise_id":"PT-2026-001","technique_id":"T1059.001","telemetry_source":"Sysmon EventID 1","detection_status":"LOGGED"}\' '
            'http://127.0.0.1:8301/api/purple/telemetry-map'
        )

        assert info_a.has_action("purple_telemetry_mapped")
        assert not info_b.has_action("purple_telemetry_mapped")

        validator = TaskValidator()
        res_a = validator.validate_submission(
            db_session, test_user, room_id, "task-04-telemetry-mapping",
            TaskSubmission(task_id="task-04-telemetry-mapping", answer="PURPLE_TELEMETRY_MAP_VERIFIED")
        )
        assert res_a.is_correct is True

        # User B tries to submit the same answer without completing action in session B
        res_b = validator.validate_submission(
            db_session, second_user, room_id, "task-04-telemetry-mapping",
            TaskSubmission(task_id="task-04-telemetry-mapping", answer="PURPLE_TELEMETRY_MAP_VERIFIED")
        )
        assert res_b.is_correct is False
        assert "Investigation incomplete" in res_b.feedback

    finally:
        await runner.stop_session(sess_a)
        await runner.stop_session(sess_b)
        lab_manager._active_sessions.pop(sess_a, None)
        lab_manager._active_sessions.pop(sess_b, None)

