"""
Comprehensive Cross-User Session Isolation, Token Integrity, and Anti-Replay Tests.
Validates:
1. Prerequisite isolation across learners (Learner A cannot unlock Learner B's tasks).
2. Cross-user token theft prevention (Learner B cannot submit Learner A's token).
3. Session replay prevention (Tokens from old sessions cannot be reused in new sessions).
4. Stopped and expired session rejection.
5. Failed command and command forgery rejection (echo, python print, command chaining).
6. Legitimate end-to-end workflow success.
7. Cryptographic HMAC session binding verification.
"""

from datetime import datetime, timedelta
import pytest
from sqlmodel import Session

from backend.app.academy.models import TaskSubmission
from backend.app.academy.validator import task_validator
from backend.app.db.models import User
from backend.app.labs.base import LabSessionInfo
from backend.app.labs.manager import lab_manager
from backend.app.labs.process_runner import ProcessLabRunner
from labs.red_room_09_sqli.target.app import (
    init_target_db,
    reset_target_in_memory_states,
    get_soc_state,
    _SOC_SESSIONS,
)


@pytest.fixture(autouse=True)
def clean_test_environment():
    """Ensure in-memory states are fresh before each test."""
    reset_target_in_memory_states()
    init_target_db()
    lab_manager._active_sessions.clear()
    yield
    reset_target_in_memory_states()
    lab_manager._active_sessions.clear()


@pytest.fixture
def learner_a(session: Session):
    user = User(
        operator_id="OP-LEARNER-ALPHA",
        username="learner_alpha",
        hashed_password="",
        role="operator",
        xp=0,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@pytest.fixture
def learner_b(session: Session):
    user = User(
        operator_id="OP-LEARNER-BRAVO",
        username="learner_bravo",
        hashed_password="",
        role="operator",
        xp=0,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@pytest.mark.asyncio
async def test_cross_user_prerequisite_isolation(session: Session, learner_a: User, learner_b: User):
    """
    Scenario 1:
    Learner A deploys the detection rule prerequisite in Session A.
    Learner B has NOT deployed the rule in Session B.
    Learner B attempts the challenge and MUST be rejected.
    """
    runner = ProcessLabRunner()
    rid = "blue-09-bruteforce-detection"

    sess_a = await runner.start_session("lab_alpha_09_111", rid, learner_a.operator_id)
    sess_b = await runner.start_session("lab_bravo_09_222", rid, learner_b.operator_id)
    lab_manager._active_sessions[sess_a.session_id] = sess_a
    lab_manager._active_sessions[sess_b.session_id] = sess_b

    # Learner A deploys the rule
    rule_cmd_a = (
        'curl -s -X POST http://10.10.14.90:8209/api/auth/rules '
        "-H 'Content-Type: application/json' "
        "-d '{\"rule_name\": \"RULE_SPRAY_ALPHA\", \"threshold\": 5, \"group_by\": \"source_ip\"}'"
    )
    out_a = await runner.execute_command(sess_a.session_id, rule_cmd_a)
    assert "SIEM_SPRAY_CORRELATION_RULE_ACTIVE" in out_a
    assert sess_a.has_action("bruteforce_rule_deployed") is True

    # Learner B has NOT deployed the rule, but attempts to submit challenge directly
    chal_cmd_b = (
        'curl -s -X POST http://10.10.14.90:8209/challenge '
        "-H 'Content-Type: application/json' "
        "-d '{\"source_ip\": \"198.51.100.55\", \"attack_type\": \"PASSWORD_SPRAY\", \"targeted_accounts_count\": 12}'"
    )
    out_b = await runner.execute_command(sess_b.session_id, chal_cmd_b)
    assert "Prerequisite incomplete" in out_b
    assert "BRUTEFORCE_RULE_VERIFIED" not in out_b
    assert sess_b.has_action("bruteforce_challenge_verified") is False

    # Learner B tries to submit task to validator
    sub_b = TaskSubmission(answer="BRUTEFORCE_RULE_VERIFIED")
    res_b = task_validator.validate_submission(session, learner_b, rid, "task-05-bruteforce-correlation-challenge", sub_b)
    assert res_b.is_correct is False
    assert "Investigation incomplete" in res_b.feedback
    assert res_b.earned_xp == 0


@pytest.mark.asyncio
async def test_cross_user_token_theft_rejected(session: Session, learner_a: User, learner_b: User):
    """
    Scenario 2:
    Learner A legitimately completes the challenge and receives an HMAC dynamic token.
    Learner B steals Learner A's dynamic token and submits it.
    Validator MUST reject Learner B.
    """
    runner = ProcessLabRunner()
    rid = "blue-09-bruteforce-detection"

    sess_a = await runner.start_session("lab_alpha_09_333", rid, learner_a.operator_id)
    sess_b = await runner.start_session("lab_bravo_09_444", rid, learner_b.operator_id)
    lab_manager._active_sessions[sess_a.session_id] = sess_a
    lab_manager._active_sessions[sess_b.session_id] = sess_b

    # Learner A executes prerequisite and challenge
    await runner.execute_command(
        sess_a.session_id,
        'curl -s -X POST http://10.10.14.90:8209/api/auth/rules -d \'{"rule_name": "R1", "threshold": 5, "group_by": "source_ip"}\'',
    )
    out_a = await runner.execute_command(
        sess_a.session_id,
        'curl -s -X POST http://10.10.14.90:8209/challenge -d \'{"source_ip": "198.51.100.55", "attack_type": "PASSWORD_SPRAY", "targeted_accounts_count": 12}\'',
    )
    assert "BRUTEFORCE_RULE_VERIFIED" in out_a
    token_a = sess_a.get_action_token("bruteforce_challenge_verified")
    assert token_a is not None
    assert token_a.startswith("VERIFIED-BRUTEFORCE_CHALLENGE-")

    # Learner B tries to submit Learner A's token
    sub_theft = TaskSubmission(answer=token_a)
    res_theft = task_validator.validate_submission(session, learner_b, rid, "task-05-bruteforce-correlation-challenge", sub_theft)
    assert res_theft.is_correct is False
    assert res_theft.earned_xp == 0
    assert learner_b.xp == 0


@pytest.mark.asyncio
async def test_session_replay_in_new_session_rejected(session: Session, learner_a: User):
    """
    Scenario 3:
    Learner A completes challenge in Session 1 and receives token_1.
    Session 1 is stopped and Session 2 is started.
    Learner A submits token_1 in Session 2 without re-doing practical work.
    Must be rejected.
    """
    runner = ProcessLabRunner()
    rid = "blue-09-bruteforce-detection"

    # Session 1
    sess_1 = await runner.start_session("lab_alpha_09_sess1", rid, learner_a.operator_id)
    lab_manager._active_sessions[sess_1.session_id] = sess_1

    await runner.execute_command(
        sess_1.session_id,
        'curl -s -X POST http://10.10.14.90:8209/api/auth/rules -d \'{"rule_name": "R1", "threshold": 5, "group_by": "source_ip"}\'',
    )
    await runner.execute_command(
        sess_1.session_id,
        'curl -s -X POST http://10.10.14.90:8209/challenge -d \'{"source_ip": "198.51.100.55", "attack_type": "PASSWORD_SPRAY", "targeted_accounts_count": 12}\'',
    )
    token_1 = sess_1.get_action_token("bruteforce_challenge_verified")
    assert token_1 is not None

    # Stop Session 1
    await runner.stop_session(sess_1.session_id)
    lab_manager._active_sessions.pop(sess_1.session_id, None)

    # Start Session 2
    sess_2 = await runner.start_session("lab_alpha_09_sess2", rid, learner_a.operator_id)
    lab_manager._active_sessions[sess_2.session_id] = sess_2

    # Attempt replay of token_1 in Session 2
    sub_replay = TaskSubmission(answer=token_1)
    res_replay = task_validator.validate_submission(session, learner_a, rid, "task-05-bruteforce-correlation-challenge", sub_replay)
    assert res_replay.is_correct is False
    assert "Investigation incomplete" in res_replay.feedback or "Invalid or expired verification token" in res_replay.feedback
    assert res_replay.earned_xp == 0


@pytest.mark.asyncio
async def test_stopped_and_expired_session_rejected(session: Session, learner_a: User):
    """
    Scenario 4:
    Submission against a stopped or expired session must be rejected.
    """
    runner = ProcessLabRunner()
    rid = "blue-09-bruteforce-detection"

    sess = await runner.start_session("lab_alpha_09_stop_test", rid, learner_a.operator_id)
    lab_manager._active_sessions[sess.session_id] = sess
    sess.record_action("bruteforce_challenge_verified")
    valid_token = sess.get_action_token("bruteforce_challenge_verified")

    # 1. Stop session
    sess.status = "STOPPED"
    sub_stopped = TaskSubmission(answer=valid_token)
    res_stopped = task_validator.validate_submission(session, learner_a, rid, "task-05-bruteforce-correlation-challenge", sub_stopped)
    assert res_stopped.is_correct is False
    assert "Investigation required" in res_stopped.feedback

    # 2. Expired session
    sess.status = "RUNNING"
    sess.expires_at = datetime.utcnow() - timedelta(minutes=5)
    assert sess.is_expired() is True
    res_expired = task_validator.validate_submission(session, learner_a, rid, "task-05-bruteforce-correlation-challenge", sub_stopped)
    assert res_expired.is_correct is False
    assert "Investigation required" in res_expired.feedback


@pytest.mark.asyncio
async def test_failed_command_and_manual_output_rejected(session: Session, learner_a: User):
    """
    Scenario 5:
    Failed commands, forged output (echo, python print), and command chaining
    must NOT record actions in the session.
    """
    runner = ProcessLabRunner()
    rid = "blue-09-bruteforce-detection"

    sess = await runner.start_session("lab_alpha_09_forge_test", rid, learner_a.operator_id)
    lab_manager._active_sessions[sess.session_id] = sess

    # 1. Direct echo forgery
    echo_out = await runner.execute_command(sess.session_id, 'echo "BRUTEFORCE_RULE_VERIFIED"')
    assert "BRUTEFORCE_RULE_VERIFIED" in echo_out
    assert sess.has_action("bruteforce_challenge_verified") is False

    # 2. Command chaining forgery
    chain_out = await runner.execute_command(sess.session_id, 'false || echo "BRUTEFORCE_RULE_VERIFIED"')
    assert "BRUTEFORCE_RULE_VERIFIED" in chain_out
    assert sess.has_action("bruteforce_challenge_verified") is False

    # 3. Python print forgery
    py_out = await runner.execute_command(sess.session_id, 'python3 -c "print(\'BRUTEFORCE_RULE_VERIFIED\')"')
    assert "BRUTEFORCE_RULE_VERIFIED" in py_out
    assert sess.has_action("bruteforce_challenge_verified") is False

    # 4. Failed curl
    fail_curl = await runner.execute_command(sess.session_id, 'curl -s http://10.10.14.90:9999/invalid')
    assert "Not Found" in fail_curl or "curl:" in fail_curl or "Failed to connect" in fail_curl
    assert sess.has_action("bruteforce_challenge_verified") is False

    # 5. Manual submission without verified action
    sub_fake = TaskSubmission(answer="BRUTEFORCE_RULE_VERIFIED")
    res_fake = task_validator.validate_submission(session, learner_a, rid, "task-05-bruteforce-correlation-challenge", sub_fake)
    assert res_fake.is_correct is False
    assert "Investigation incomplete" in res_fake.feedback


@pytest.mark.asyncio
async def test_legitimate_workflow_succeeds(session: Session, learner_a: User):
    """
    Scenario 6:
    A legitimate command sequence executed in the correct session
    unlocks the challenge, records the action, and allows task completion.
    """
    runner = ProcessLabRunner()
    rid = "blue-09-bruteforce-detection"

    sess = await runner.start_session("lab_alpha_09_legit", rid, learner_a.operator_id)
    lab_manager._active_sessions[sess.session_id] = sess

    # Step 1: Deploy correlation rule via genuine curl
    rule_cmd = (
        'curl -s -X POST http://10.10.14.90:8209/api/auth/rules '
        "-H 'Content-Type: application/json' "
        "-d '{\"rule_name\": \"LEGIT_SPRAY_RULE\", \"threshold\": 4, \"group_by\": \"source_ip\"}'"
    )
    rule_out = await runner.execute_command(sess.session_id, rule_cmd)
    assert "SIEM_SPRAY_CORRELATION_RULE_ACTIVE" in rule_out
    assert sess.has_action("bruteforce_rule_deployed") is True

    # Submit Task 4
    sub4 = TaskSubmission(answer="SIEM_SPRAY_CORRELATION_RULE_ACTIVE")
    res4 = task_validator.validate_submission(session, learner_a, rid, "task-04-siem-threshold-rule-deployment", sub4)
    assert res4.is_correct is True
    assert res4.earned_xp == 70

    # Step 2: Submit findings via genuine curl
    chal_cmd = (
        'curl -s -X POST http://10.10.14.90:8209/challenge '
        "-H 'Content-Type: application/json' "
        "-d '{\"source_ip\": \"198.51.100.55\", \"attack_type\": \"PASSWORD_SPRAY\", \"targeted_accounts_count\": 12}'"
    )
    chal_out = await runner.execute_command(sess.session_id, chal_cmd)
    assert "BRUTEFORCE_RULE_VERIFIED" in chal_out
    assert sess.has_action("bruteforce_challenge_verified") is True

    # Submit Task 5 with dynamic session HMAC token
    dyn_token = sess.get_action_token("bruteforce_challenge_verified")
    assert dyn_token is not None
    assert dyn_token.startswith("VERIFIED-BRUTEFORCE_CHALLENGE-")

    sub5 = TaskSubmission(answer=dyn_token)
    res5 = task_validator.validate_submission(session, learner_a, rid, "task-05-bruteforce-correlation-challenge", sub5)
    assert res5.is_correct is True
    assert res5.earned_xp == 50
    assert learner_a.xp == 120


def test_hmac_token_cryptographic_binding():
    """
    Scenario 7:
    Verify HMAC token generation, nonce uniqueness, and operator binding.
    """
    sess_1 = LabSessionInfo(
        session_id="lab_sess_1",
        room_id="blue-09-bruteforce-detection",
        operator_id="OP-1",
        runner_mode="emulated",
        target_url="http://127.0.0.1:8209",
    )
    sess_2 = LabSessionInfo(
        session_id="lab_sess_2",
        room_id="blue-09-bruteforce-detection",
        operator_id="OP-2",
        runner_mode="emulated",
        target_url="http://127.0.0.1:8209",
    )

    # 1. Nonces must be unique
    assert sess_1.session_nonce != sess_2.session_nonce

    # 2. Generate HMAC tokens for same action
    tok_1 = sess_1.generate_verification_token("bruteforce_challenge_verified")
    tok_2 = sess_2.generate_verification_token("bruteforce_challenge_verified")

    assert tok_1.startswith("VERIFIED-BRUTEFORCE_CHALLENGE-")
    assert tok_2.startswith("VERIFIED-BRUTEFORCE_CHALLENGE-")
    assert tok_1 != tok_2, "Tokens from different sessions must never collide"

    # 3. Verification method checks
    assert sess_1.verify_token("bruteforce_challenge_verified", tok_1) is True
    assert sess_2.verify_token("bruteforce_challenge_verified", tok_2) is True
    assert sess_1.verify_token("bruteforce_challenge_verified", tok_2) is False
    assert sess_2.verify_token("bruteforce_challenge_verified", tok_1) is False
    assert sess_1.verify_token("bruteforce_challenge_verified", tok_1 + "TAMPER") is False
    assert sess_1.verify_token("other_action", tok_1) is False


# ============================================================================
# PROMPT 18C: TRUSTED SESSION IDENTITY & IMPERSONATION AUDIT VECTORS
# ============================================================================

@pytest.mark.asyncio
async def test_vector_1_x_session_id_spoofing_rejected(learner_a: User, learner_b: User):
    """
    Vector 1: Learner A cannot select Learner B's session via X-Session-ID (403 Forbidden).
    """
    runner = ProcessLabRunner()
    rid = "blue-01-foundations"
    sess_a = await runner.start_session("sess_alpha_v1", rid, learner_a.operator_id)
    sess_b = await runner.start_session("sess_bravo_v1", rid, learner_b.operator_id)

    # Learner A executes command attempting to assert Learner B's session ID
    cmd = (
        'curl -s -X POST http://10.10.14.90:8201/api/soc/triage '
        f"-H 'X-Session-ID: {sess_b.session_id}' "
        "-H 'Content-Type: application/json' "
        "-d '{\"event_id\": \"EVT-1003\", \"classification\": \"TRUE_POSITIVE\", \"severity\": \"HIGH\"}'"
    )
    out = await runner.execute_command(sess_a.session_id, cmd)
    assert "FORBIDDEN" in out or "403" in out
    assert "IMPERSONATION_DETECTED" in out

    # Ensure Learner B's state was NOT mutated
    b_state = get_soc_state(sess_b.session_id)
    assert len(b_state.get("triaged_events", [])) == 0
    assert sess_a.has_action("soc_triage_verified") is False
    assert sess_b.has_action("soc_triage_verified") is False


@pytest.mark.asyncio
async def test_vector_2_x_operator_id_spoofing_rejected(learner_a: User, learner_b: User):
    """
    Vector 2: Learner A cannot impersonate Learner B via X-Operator-ID (403 Forbidden).
    """
    runner = ProcessLabRunner()
    rid = "blue-01-foundations"
    sess_a = await runner.start_session("sess_alpha_v2", rid, learner_a.operator_id)

    cmd = (
        'curl -s -X POST http://10.10.14.90:8201/api/soc/triage '
        f"-H 'X-Operator-ID: {learner_b.operator_id}' "
        "-H 'Content-Type: application/json' "
        "-d '{\"event_id\": \"EVT-1003\", \"classification\": \"TRUE_POSITIVE\", \"severity\": \"HIGH\"}'"
    )
    out = await runner.execute_command(sess_a.session_id, cmd)
    assert "FORBIDDEN" in out or "403" in out
    assert "IMPERSONATION_DETECTED" in out
    assert sess_a.has_action("soc_triage_verified") is False


@pytest.mark.asyncio
async def test_vector_3_query_string_identity_manipulation_rejected(learner_a: User, learner_b: User):
    """
    Vector 3: Query-string identity manipulation is rejected (403 Forbidden).
    """
    runner = ProcessLabRunner()
    rid = "blue-01-foundations"
    sess_a = await runner.start_session("sess_alpha_v3", rid, learner_a.operator_id)

    # 1. session_id query param
    cmd_sess = (
        'curl -s -X POST "http://10.10.14.90:8201/api/soc/triage?session_id=spoofed_sess_999" '
        "-H 'Content-Type: application/json' "
        "-d '{\"event_id\": \"EVT-1003\", \"classification\": \"TRUE_POSITIVE\", \"severity\": \"HIGH\"}'"
    )
    out_sess = await runner.execute_command(sess_a.session_id, cmd_sess)
    assert "FORBIDDEN" in out_sess or "403" in out_sess
    assert "IMPERSONATION_DETECTED" in out_sess

    # 2. operator_id query param
    cmd_op = (
        f'curl -s -X POST "http://10.10.14.90:8201/api/soc/triage?operator_id={learner_b.operator_id}" '
        "-H 'Content-Type: application/json' "
        "-d '{\"event_id\": \"EVT-1003\", \"classification\": \"TRUE_POSITIVE\", \"severity\": \"HIGH\"}'"
    )
    out_op = await runner.execute_command(sess_a.session_id, cmd_op)
    assert "FORBIDDEN" in out_op or "403" in out_op
    assert "IMPERSONATION_DETECTED" in out_op


@pytest.mark.asyncio
async def test_vector_4_missing_identity_rejected_401_no_default_fallback():
    """
    Vector 4: Missing identity is rejected with 401 rather than assigned 'default'.
    Never silently creates or accesses a shared default state.
    """
    import httpx
    from labs.red_room_09_sqli.target.app import soc_app

    transport = httpx.ASGITransport(app=soc_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Direct call with no authentication headers
        res = await client.post(
            "/api/soc/triage",
            json={"event_id": "EVT-1003", "classification": "TRUE_POSITIVE", "severity": "HIGH"},
        )
        assert res.status_code == 401
        data = res.json()
        assert data.get("status") == "UNAUTHORIZED"
        assert data.get("error") == "AUTH_REQUIRED"
        assert "default" not in _SOC_SESSIONS, "'default' must never be created or accessed"


@pytest.mark.asyncio
async def test_vector_5_invalid_or_expired_credentials_rejected():
    """
    Vector 5: Invalid or expired credentials cannot mutate state (401 Unauthorized).
    """
    import httpx
    import time
    from labs.red_room_09_sqli.target.app import (
        soc_app,
        generate_trusted_session_signature,
    )

    transport = httpx.ASGITransport(app=soc_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Tampered signature
        headers_tampered = {
            "X-Lab-Session-ID": "fake_sess",
            "X-Lab-Operator-ID": "fake_op",
            "X-Lab-Expires-At": str(int(time.time()) + 3600),
            "X-Lab-Auth-Signature": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        }
        res_tampered = await client.post(
            "/api/soc/triage",
            json={"event_id": "EVT-1003", "classification": "TRUE_POSITIVE", "severity": "HIGH"},
            headers=headers_tampered,
        )
        assert res_tampered.status_code == 401
        assert res_tampered.json().get("error") == "INVALID_OR_EXPIRED_CREDENTIALS"

        # 2. Expired signature (timestamp in the past)
        expired_ts = int(time.time()) - 300
        sig_expired = generate_trusted_session_signature("fake_sess", "fake_op", expired_ts)
        headers_expired = {
            "X-Lab-Session-ID": "fake_sess",
            "X-Lab-Operator-ID": "fake_op",
            "X-Lab-Expires-At": str(expired_ts),
            "X-Lab-Auth-Signature": sig_expired,
        }
        res_expired = await client.post(
            "/api/soc/triage",
            json={"event_id": "EVT-1003", "classification": "TRUE_POSITIVE", "severity": "HIGH"},
            headers=headers_expired,
        )
        assert res_expired.status_code == 401
        assert res_expired.json().get("error") == "INVALID_OR_EXPIRED_CREDENTIALS"
        assert "fake_sess" not in _SOC_SESSIONS


@pytest.mark.asyncio
async def test_vector_6_valid_requests_succeed(learner_a: User):
    """
    Vector 6: Valid requests from correct active session succeed.
    """
    runner = ProcessLabRunner()
    rid = "blue-01-foundations"
    sess = await runner.start_session("sess_alpha_v6", rid, learner_a.operator_id)

    cmd = (
        'curl -s -X POST http://10.10.14.90:8201/api/soc/triage '
        "-H 'Content-Type: application/json' "
        "-d '{\"event_id\": \"EVT-1003\", \"classification\": \"TRUE_POSITIVE\", \"severity\": \"HIGH\"}'"
    )
    out = await runner.execute_command(sess.session_id, cmd)
    assert "TRIAGE_ACCEPTED" in out
    assert "TRIAGE_CONFIRMED_EVT1003_SECURE" in out
    assert sess.has_action("soc_triage_verified") is True


@pytest.mark.asyncio
async def test_vector_7_independent_sessions_isolated_progress(learner_a: User, learner_b: User):
    """
    Vector 7: Independent sessions maintain strictly isolated progress.
    """
    runner = ProcessLabRunner()
    rid = "blue-01-foundations"
    sess_a = await runner.start_session("sess_alpha_v7", rid, learner_a.operator_id)
    sess_b = await runner.start_session("sess_bravo_v7", rid, learner_b.operator_id)

    # Learner A completes triage
    cmd_triage_a = (
        'curl -s -X POST http://10.10.14.90:8201/api/soc/triage '
        "-H 'Content-Type: application/json' "
        "-d '{\"event_id\": \"EVT-1003\", \"classification\": \"TRUE_POSITIVE\", \"severity\": \"HIGH\"}'"
    )
    await runner.execute_command(sess_a.session_id, cmd_triage_a)
    assert len(get_soc_state(sess_a.session_id)["triaged_events"]) == 1

    # Learner B has NOT triaged, attempts timeline challenge
    cmd_chal_b = (
        'curl -s -X POST http://10.10.14.90:8201/challenge '
        "-H 'Content-Type: application/json' "
        "-d '{\"stage\": \"evidence\", \"adversary_ip\": \"198.51.100.42\", \"compromised_host\": \"DC-VOLT01\"}'"
    )
    out_b = await runner.execute_command(sess_b.session_id, cmd_chal_b)
    assert "Prerequisite incomplete" in out_b
    assert "TIMELINE_VERIFIED" not in out_b
    assert sess_b.has_action("soc_timeline_verified") is False

    # Learner A attempts timeline challenge and succeeds
    out_a = await runner.execute_command(sess_a.session_id, cmd_chal_b)
    assert "TIMELINE_VERIFIED" in out_a
    assert sess_a.has_action("soc_timeline_verified") is True


@pytest.mark.asyncio
async def test_vector_8_stopped_session_purges_state(learner_a: User):
    """
    Vector 8: Stopped sessions cannot access or mutate old state.
    State is purged immediately upon session stop.
    """
    runner = ProcessLabRunner()
    rid = "blue-01-foundations"
    sess = await runner.start_session("sess_alpha_v8", rid, learner_a.operator_id)

    # Perform action
    cmd = (
        'curl -s -X POST http://10.10.14.90:8201/api/soc/triage '
        "-H 'Content-Type: application/json' "
        "-d '{\"event_id\": \"EVT-1003\", \"classification\": \"TRUE_POSITIVE\", \"severity\": \"HIGH\"}'"
    )
    await runner.execute_command(sess.session_id, cmd)
    assert len(get_soc_state(sess.session_id)["triaged_events"]) == 1

    # Stop session
    await runner.stop_session(sess.session_id)
    assert sess.session_id not in _SOC_SESSIONS, "Session state must be purged on stop"

    # Attempting to execute commands on stopped session fails
    cmd_after_stop = await runner.execute_command(sess.session_id, cmd)
    assert "Active lab session not found or expired" in cmd_after_stop
