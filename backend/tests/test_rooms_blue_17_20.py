"""
Unit and Emulated Integration Tests for Blue Team Rooms 17–20:
- Room 17: Digital Forensics (blue-17-digital-forensics)
- Room 18: Windows and Linux Hardening (blue-18-windows-linux-hardening)
- Room 19: Threat Intelligence (blue-19-threat-intelligence)
- Room 20: Blue Team Capstone (blue-20-blue-team-capstone)

Validates curriculum integration, task validation engine, anti-forgery,
prerequisite enforcement, and dual-session isolation.
"""

import pytest
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from backend.app.academy.curriculum import curriculum_registry
from backend.app.academy.models import RoomStatus, TaskSubmission, TaskType, TrackEnum
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
        username="blue_operator_1720",
        email="blue_operator_1720@noentry.internal",
        operator_id="OP-BLUE-1720-UNIT",
        hashed_password="dummy_test_hash_1720",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(name="second_user")
def second_user_fixture(db_session: Session):
    user = User(
        username="blue_operator_isolate",
        email="blue_operator_isolate@noentry.internal",
        operator_id="OP-BLUE-ISOLATE-UNIT",
        hashed_password="dummy_test_hash_isolate",
        xp=0,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


# ============================================================================
# 1. CURRICULUM REGISTRATION & TRACK TOTALS
# ============================================================================

def test_rooms_17_20_curriculum_registration():
    """Verify Rooms 17-20 are fully registered and complete the 20-room Blue track."""
    for r_num in (17, 18, 19, 20):
        room = curriculum_registry.get_room(f"blue-{r_num}")
        assert room is not None
        assert room.room_number == r_num
        assert room.track == TrackEnum.BLUE
        assert room.status == RoomStatus.IMPLEMENTED
        assert len(room.tasks) == 6
        assert room.total_xp == 350
        assert room.concept is not None
        assert room.concept.technical_term
        assert room.concept.overview

    # Verify track statistics
    blue_rooms = curriculum_registry.list_rooms(track=TrackEnum.BLUE)
    assert len(blue_rooms) == 20
    implemented_blue = [r for r in blue_rooms if r.status == RoomStatus.IMPLEMENTED]
    assert len(implemented_blue) == 20

    counts = curriculum_registry.get_track_counts()
    assert counts["blue"]["total"] == 20
    assert counts["blue"]["implemented"] == 20
    assert counts["blue"]["planned"] == 0


# ============================================================================
# 2. ROOM 17: DIGITAL FORENSICS VALIDATION
# ============================================================================

@pytest.mark.asyncio
async def test_room_17_tasks_and_validation(db_session: Session, test_user: User):
    """Test all 6 tasks for Room 17 (Digital Forensics)."""
    validator = TaskValidator()
    room_id = "blue-17-digital-forensics"

    # Task 1: RFC 3227 Volatility
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-forensics-foundations-evidence",
        TaskSubmission(task_id="task-01-forensics-foundations-evidence", answer="RAM")
    )
    assert res1.is_correct is True
    assert res1.completed is True

    # Task 2: Evidence SHA-256 Hashing
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-evidence-integrity-hashing",
        TaskSubmission(task_id="task-02-evidence-integrity-hashing", answer="34049ea3151168bea705f416fabb3c8919ba7563ad650cff2af6e1b7745fc465")
    )
    assert res2.is_correct is True
    assert res2.completed is True

    # Task 3: MACB Inode Extraction
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-filesystem-metadata-timestamps",
        TaskSubmission(task_id="task-03-filesystem-metadata-timestamps", answer="89104")
    )
    assert res3.is_correct is True
    assert res3.completed is True

    # Task 4 without active lab -> rejected
    res4_fail = validator.validate_submission(
        db_session, test_user, room_id, "task-04-timeline-reconstruction",
        TaskSubmission(task_id="task-04-timeline-reconstruction", answer="FORENSICS_TIMELINE_CONFIRMED")
    )
    assert res4_fail.is_correct is False
    assert "Investigation required" in res4_fail.feedback

    # Start lab session and confirm timeline via simulated workstation
    runner = ProcessLabRunner()
    sess_id = f"proc_test_room17_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    from backend.app.labs.manager import lab_manager
    lab_manager._active_sessions[sess_id] = info

    try:
        # Submit timeline reconstruction
        post_timeline_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"inode":89104,"event_type":"UNAUTHORIZED_STAGING_CREATION","timestamp":"2026-11-15T09:12:00Z"}\' '
            f'http://127.0.0.1:8217/api/forensics/timeline'
        )
        out_time = await runner.execute_command(sess_id, post_timeline_cmd)
        assert "FORENSICS_TIMELINE_CONFIRMED" in out_time
        assert info.has_action("forensics_timeline_confirmed")

        # Validate task 4
        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-timeline-reconstruction",
            TaskSubmission(task_id="task-04-timeline-reconstruction", answer="FORENSICS_TIMELINE_CONFIRMED")
        )
        assert res4.is_correct is True
        assert res4.completed is True

        # Submit final challenge
        chal_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"case_id":"FOR-2026-091","evidence_hash":"34049ea3151168bea705f416fabb3c8919ba7563ad650cff2af6e1b7745fc465","attacker_action":"DATA_STAGING_AND_TAMPERING"}\' '
            f'http://127.0.0.1:8217/challenge'
        )
        out_chal = await runner.execute_command(sess_id, chal_cmd)
        assert "DIGITAL_FORENSICS_INVESTIGATION_COMPLETE" in out_chal
        assert info.has_action("forensics_challenge_verified")

        # Validate task 5
        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-digital-forensics-challenge",
            TaskSubmission(task_id="task-05-digital-forensics-challenge", answer="DIGITAL_FORENSICS_INVESTIGATION_COMPLETE")
        )
        assert res5.is_correct is True
        assert res5.completed is True

        # Task 6: Quiz
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-forensics-quiz",
            TaskSubmission(
                task_id="task-06-forensics-quiz",
                quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0}
            )
        )
        assert res6.is_correct is True
        assert res6.completed is True

    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 3. ROOM 18: HARDENING VALIDATION
# ============================================================================

@pytest.mark.asyncio
async def test_room_18_tasks_and_validation(db_session: Session, test_user: User):
    """Test all 6 tasks for Room 18 (Windows and Linux Hardening)."""
    validator = TaskValidator()
    room_id = "blue-18-windows-linux-hardening"

    # Task 1: Least Privilege
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-hardening-principles-defense-in-depth",
        TaskSubmission(task_id="task-01-hardening-principles-defense-in-depth", answer="Least Privilege")
    )
    assert res1.is_correct is True

    # Task 2: Root SSH
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-linux-audit-permissions-ssh",
        TaskSubmission(task_id="task-02-linux-audit-permissions-ssh", answer="PermitRootLogin")
    )
    assert res2.is_correct is True

    # Task 3: Account Lockout Threshold
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-windows-security-policy-audit",
        TaskSubmission(task_id="task-03-windows-security-policy-audit", answer="0")
    )
    assert res3.is_correct is True

    # Start lab
    runner = ProcessLabRunner()
    sess_id = f"proc_test_room18_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    from backend.app.labs.manager import lab_manager
    lab_manager._active_sessions[sess_id] = info

    try:
        # Apply Linux hardening
        linux_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"disable_root_ssh":true,"enforce_key_auth":true,"remove_wildcard_sudo":true}\' '
            f'http://127.0.0.1:8218/api/hardening/linux/apply'
        )
        out_lin = await runner.execute_command(sess_id, linux_cmd)
        assert "LINUX_HARDENING_ENFORCED" in out_lin
        assert info.has_action("linux_hardening_enforced")

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-apply-linux-hardening",
            TaskSubmission(task_id="task-04-apply-linux-hardening", answer="LINUX_HARDENING_ENFORCED")
        )
        assert res4.is_correct is True

        # Apply Windows hardening
        win_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"lockout_threshold":5,"powershell_policy":"RemoteSigned","disable_smbv1":true}\' '
            f'http://127.0.0.1:8218/api/hardening/windows/apply'
        )
        await runner.execute_command(sess_id, win_cmd)

        # Submit dual OS challenge
        chal_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"target_scope":"DUAL_OS_ENTERPRISE","linux_remediated":true,"windows_remediated":true}\' '
            f'http://127.0.0.1:8218/challenge'
        )
        out_chal = await runner.execute_command(sess_id, chal_cmd)
        assert "SYSTEM_HARDENING_BASELINE_VERIFIED" in out_chal
        assert info.has_action("hardening_challenge_verified")

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-hardening-verification-challenge",
            TaskSubmission(task_id="task-05-hardening-verification-challenge", answer="SYSTEM_HARDENING_BASELINE_VERIFIED")
        )
        assert res5.is_correct is True

        # Task 6: Quiz
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-hardening-quiz",
            TaskSubmission(task_id="task-06-hardening-quiz", quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0})
        )
        assert res6.is_correct is True

    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 4. ROOM 19: THREAT INTELLIGENCE VALIDATION
# ============================================================================

@pytest.mark.asyncio
async def test_room_19_tasks_and_validation(db_session: Session, test_user: User):
    """Test all 6 tasks for Room 19 (Threat Intelligence)."""
    validator = TaskValidator()
    room_id = "blue-19-threat-intelligence"

    # Task 1: Diamond Model
    res1 = validator.validate_submission(
        db_session, test_user, room_id, "task-01-cti-fundamentals-diamond-model",
        TaskSubmission(task_id="task-01-cti-fundamentals-diamond-model", answer="Capability")
    )
    assert res1.is_correct is True

    # Task 2: IOC C2 IP
    res2 = validator.validate_submission(
        db_session, test_user, room_id, "task-02-ioc-extraction-classification",
        TaskSubmission(task_id="task-02-ioc-extraction-classification", answer="198.51.100.77")
    )
    assert res2.is_correct is True

    # Task 3: MITRE ATT&CK ID
    res3 = validator.validate_submission(
        db_session, test_user, room_id, "task-03-stix-taxonomies-mitre-mapping",
        TaskSubmission(task_id="task-03-stix-taxonomies-mitre-mapping", answer="T1566.001")
    )
    assert res3.is_correct is True

    # Start lab
    runner = ProcessLabRunner()
    sess_id = f"proc_test_room19_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    from backend.app.labs.manager import lab_manager
    lab_manager._active_sessions[sess_id] = info

    try:
        # Correlate indicators
        corr_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"threat_actor":"APT-VOLT-VIPER","c2_ip":"198.51.100.77","c2_domain":"update-cdn.voltcorp-support.internal","malware_family":"VoltDrop"}\' '
            f'http://127.0.0.1:8219/api/intel/correlate'
        )
        out_corr = await runner.execute_command(sess_id, corr_cmd)
        assert "INTEL_CORRELATION_CONFIRMED" in out_corr
        assert info.has_action("intel_correlation_confirmed")

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-indicator-correlation-enrichment",
            TaskSubmission(task_id="task-04-indicator-correlation-enrichment", answer="INTEL_CORRELATION_CONFIRMED")
        )
        assert res4.is_correct is True

        # Map ATT&CK technique
        map_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"threat_actor":"APT-VOLT-VIPER","primary_technique":"T1566.001","secondary_technique":"T1059.001"}\' '
            f'http://127.0.0.1:8219/api/intel/attck-map'
        )
        await runner.execute_command(sess_id, map_cmd)

        # Submit intelligence challenge
        chal_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"campaign_id":"CMP-2026-VOLT","confidence_score":"HIGH","defensive_recommendation":"BLOCK_IP_AND_HASH_ON_PERIMETER"}\' '
            f'http://127.0.0.1:8219/challenge'
        )
        out_chal = await runner.execute_command(sess_id, chal_cmd)
        assert "THREAT_INTEL_ASSESSMENT_DELIVERED" in out_chal
        assert info.has_action("intel_challenge_verified")

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-threat-intel-challenge",
            TaskSubmission(task_id="task-05-threat-intel-challenge", answer="THREAT_INTEL_ASSESSMENT_DELIVERED")
        )
        assert res5.is_correct is True

        # Task 6: Quiz
        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-threat-intel-quiz",
            TaskSubmission(task_id="task-06-threat-intel-quiz", quiz_answers={"q1": 0, "q2": 0, "q3": 0, "q4": 0})
        )
        assert res6.is_correct is True

    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 5. ROOM 20: BLUE TEAM CAPSTONE FULL MULTI-STAGE LIFECYCLE
# ============================================================================

@pytest.mark.asyncio
async def test_room_20_capstone_full_lifecycle(db_session: Session, test_user: User):
    """Test all 6 progressive multi-stage tasks for Room 20 (Blue Team Capstone)."""
    validator = TaskValidator()
    room_id = "blue-20-blue-team-capstone"

    # Start lab
    runner = ProcessLabRunner()
    sess_id = f"proc_test_room20_{test_user.operator_id}"
    info = await runner.start_session(sess_id, room_id, test_user.operator_id)
    from backend.app.labs.manager import lab_manager
    lab_manager._active_sessions[sess_id] = info

    try:
        # Stage 1: Detection
        det_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"stage":"DETECTION","adversary_ip":"198.51.100.77","compromised_asset":"DB-PROD-01"}\' '
            f'http://127.0.0.1:8220/api/capstone/detect'
        )
        out_det = await runner.execute_command(sess_id, det_cmd)
        assert "CAPSTONE_STAGE1_DETECT_OK" in out_det
        assert info.has_action("capstone_stage1_verified")

        res1 = validator.validate_submission(
            db_session, test_user, room_id, "task-01-capstone-stage1-detection",
            TaskSubmission(task_id="task-01-capstone-stage1-detection", answer="CAPSTONE_STAGE1_DETECT_OK")
        )
        assert res1.is_correct is True

        # Stage 2: Threat Hunting
        hunt_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"stage":"THREAT_HUNTING","malicious_pid":3912,"persistence_service":"svc_winupdater","technique":"T1059.001"}\' '
            f'http://127.0.0.1:8220/api/capstone/hunt'
        )
        out_hunt = await runner.execute_command(sess_id, hunt_cmd)
        assert "CAPSTONE_STAGE3_HUNT_OK" in out_hunt
        assert info.has_action("capstone_stage2_verified")

        res2 = validator.validate_submission(
            db_session, test_user, room_id, "task-02-capstone-stage2-threat-hunting",
            TaskSubmission(task_id="task-02-capstone-stage2-threat-hunting", answer="CAPSTONE_STAGE3_HUNT_OK")
        )
        assert res2.is_correct is True

        # Stage 3: Forensics
        for_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"stage":"FORENSICS","sha256_verified":true,"ram_hash":"7a35b1d9821811faec2984b2382903487f54921b72a912e84c980312fa890123"}\' '
            f'http://127.0.0.1:8220/api/capstone/forensics'
        )
        out_for = await runner.execute_command(sess_id, for_cmd)
        assert "CAPSTONE_STAGE4_FORENSICS_OK" in out_for
        assert info.has_action("capstone_stage3_verified")

        res3 = validator.validate_submission(
            db_session, test_user, room_id, "task-03-capstone-stage3-forensic-preservation",
            TaskSubmission(task_id="task-03-capstone-stage3-forensic-preservation", answer="CAPSTONE_STAGE4_FORENSICS_OK")
        )
        assert res3.is_correct is True

        # Stage 4: Triage
        tri_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"stage":"TRIAGE","incident_severity":"CRITICAL","threat_actor":"APT-VOLT-VIPER","exfil_volume_mb":2400}\' '
            f'http://127.0.0.1:8220/api/capstone/triage'
        )
        out_tri = await runner.execute_command(sess_id, tri_cmd)
        assert "CAPSTONE_STAGE6_TRIAGE_OK" in out_tri
        assert info.has_action("capstone_stage4_verified")

        res4 = validator.validate_submission(
            db_session, test_user, room_id, "task-04-capstone-stage4-intelligence-triage",
            TaskSubmission(task_id="task-04-capstone-stage4-intelligence-triage", answer="CAPSTONE_STAGE6_TRIAGE_OK")
        )
        assert res4.is_correct is True

        # Stage 5: Containment
        cont_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"stage":"CONTAINMENT","isolate_host":"DB-PROD-01","terminate_pid":3912,"revoke_token":"ST-VOLT-9921"}\' '
            f'http://127.0.0.1:8220/api/capstone/contain'
        )
        out_cont = await runner.execute_command(sess_id, cont_cmd)
        assert "CAPSTONE_STAGE7_CONTAIN_OK" in out_cont
        assert info.has_action("capstone_stage5_verified")

        res5 = validator.validate_submission(
            db_session, test_user, room_id, "task-05-capstone-stage5-containment-recovery",
            TaskSubmission(task_id="task-05-capstone-stage5-containment-recovery", answer="CAPSTONE_STAGE7_CONTAIN_OK")
        )
        assert res5.is_correct is True

        # Stage 6: Final Capstone Report
        chal_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"case_id":"CAPSTONE-IR-FINAL","incident_summary":"CRITICAL_APT_INTRUSION_CONTAINED","all_stages_complete":true}\' '
            f'http://127.0.0.1:8220/challenge'
        )
        out_chal = await runner.execute_command(sess_id, chal_cmd)
        assert "BLUE_TEAM_CAPSTONE_TRIUMPH" in out_chal
        assert info.has_action("capstone_final_verified")

        res6 = validator.validate_submission(
            db_session, test_user, room_id, "task-06-capstone-final-report-assessment",
            TaskSubmission(task_id="task-06-capstone-final-report-assessment", answer="BLUE_TEAM_CAPSTONE_TRIUMPH")
        )
        assert res6.is_correct is True
        assert res6.completed is True

    finally:
        await runner.stop_session(sess_id)
        lab_manager._active_sessions.pop(sess_id, None)


# ============================================================================
# 6. ANTI-FORGERY & DUAL-SESSION ISOLATION AUDIT
# ============================================================================

@pytest.mark.asyncio
async def test_anti_forgery_echo_rejection(db_session: Session, test_user: User):
    """Echoing verification tokens without executing the tool must NOT award action verification."""
    runner = ProcessLabRunner()
    sess_id = f"proc_test_forgery_{test_user.operator_id}"
    info = await runner.start_session(sess_id, "blue-17-digital-forensics", test_user.operator_id)

    try:
        # Attacker tries to fake action via echo
        await runner.execute_command(sess_id, 'echo "FORENSICS_TIMELINE_CONFIRMED"')
        assert not info.has_action("forensics_timeline_confirmed")

        await runner.execute_command(sess_id, 'echo "DIGITAL_FORENSICS_INVESTIGATION_COMPLETE"')
        assert not info.has_action("forensics_challenge_verified")
    finally:
        await runner.stop_session(sess_id)


@pytest.mark.asyncio
async def test_dual_session_cross_session_isolation(db_session: Session, test_user: User, second_user: User):
    """User A completing Room 20 actions must NOT satisfy User B's tasks."""
    runner = ProcessLabRunner()
    sess_a = f"proc_test_dual_a_{test_user.operator_id}"
    sess_b = f"proc_test_dual_b_{second_user.operator_id}"
    room_id = "blue-20-blue-team-capstone"

    info_a = await runner.start_session(sess_a, room_id, test_user.operator_id)
    info_b = await runner.start_session(sess_b, room_id, second_user.operator_id)

    from backend.app.labs.manager import lab_manager
    lab_manager._active_sessions[sess_a] = info_a
    lab_manager._active_sessions[sess_b] = info_b

    try:
        # User A executes Stage 1 Detection
        det_cmd = (
            'curl -s -X POST -H "Content-Type: application/json" '
            '-d \'{"stage":"DETECTION","adversary_ip":"198.51.100.77","compromised_asset":"DB-PROD-01"}\' '
            f'http://127.0.0.1:8220/api/capstone/detect'
        )
        await runner.execute_command(sess_a, det_cmd)

        assert info_a.has_action("capstone_stage1_verified")
        assert not info_b.has_action("capstone_stage1_verified")

        validator = TaskValidator()
        res_a = validator.validate_submission(
            db_session, test_user, room_id, "task-01-capstone-stage1-detection",
            TaskSubmission(task_id="task-01-capstone-stage1-detection", answer="CAPSTONE_STAGE1_DETECT_OK")
        )
        assert res_a.is_correct is True

        res_b = validator.validate_submission(
            db_session, second_user, room_id, "task-01-capstone-stage1-detection",
            TaskSubmission(task_id="task-01-capstone-stage1-detection", answer="CAPSTONE_STAGE1_DETECT_OK")
        )
        assert res_b.is_correct is False
        assert "Investigation incomplete" in res_b.feedback

    finally:
        await runner.stop_session(sess_a)
        await runner.stop_session(sess_b)
        lab_manager._active_sessions.pop(sess_a, None)
        lab_manager._active_sessions.pop(sess_b, None)
