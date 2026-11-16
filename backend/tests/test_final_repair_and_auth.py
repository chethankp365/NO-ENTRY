import pytest
from starlette.testclient import TestClient

def test_registration_and_email_login(client: TestClient):
    # Register new user
    reg_payload = {
        "full_name": "Marcus Kane",
        "email": "marcus.kane@cybercorp.io",
        "password": "SecretPassword123!",
        "confirm_password": "SecretPassword123!",
        "operator_id": "op-kane"
    }
    reg_resp = client.post("/api/auth/register", json=reg_payload)
    assert reg_resp.status_code == 200, reg_resp.text
    data = reg_resp.json()
    assert data["operator_id"] == "op-kane"
    assert data["email"] == "marcus.kane@cybercorp.io"
    assert data["full_name"] == "Marcus Kane"

    # Verify duplicate registration is blocked
    dup_resp = client.post("/api/auth/register", json=reg_payload)
    assert dup_resp.status_code == 400
    assert "already exists" in dup_resp.json()["detail"]

    # Clear cookies by creating a fresh login request with email
    login_resp = client.post("/api/auth/login", json={
        "identifier": "marcus.kane@cybercorp.io",
        "password": "SecretPassword123!"
    })
    assert login_resp.status_code == 200
    assert login_resp.json()["operator_id"] == "op-kane"

    # Test profile endpoint
    prof_resp = client.get("/api/auth/profile")
    assert prof_resp.status_code == 200
    pdata = prof_resp.json()
    assert pdata["operator_id"] == "op-kane"
    assert pdata["email"] == "marcus.kane@cybercorp.io"
    assert "track_stats" in pdata
    assert pdata["track_stats"]["red"]["total"] == 20
    assert pdata["track_stats"]["detection"]["total"] == 20

def test_password_recovery_flow(client: TestClient):
    # Register user
    email = "recovery.tester@noentry.local"
    client.post("/api/auth/register", json={
        "full_name": "Recovery Operator",
        "email": email,
        "password": "OriginalPassword1!",
        "confirm_password": "OriginalPassword1!",
    })

    # Forgot password
    forgot_resp = client.post("/api/auth/forgot-password", json={"email": email})
    assert forgot_resp.status_code == 200
    reset_token = forgot_resp.json().get("reset_token")
    assert reset_token is not None
    assert reset_token.startswith("rst-")

    # Reset password
    reset_resp = client.post("/api/auth/reset-password", json={
        "reset_token": reset_token,
        "new_password": "BrandNewPassword2026!",
        "confirm_password": "BrandNewPassword2026!"
    })
    assert reset_resp.status_code == 200
    assert "successfully updated" in reset_resp.json()["message"]

    # Verify login with new password succeeds and old password fails
    old_fail = client.post("/api/auth/login", json={
        "identifier": email,
        "password": "OriginalPassword1!"
    })
    assert old_fail.status_code == 401

    new_ok = client.post("/api/auth/login", json={
        "identifier": email,
        "password": "BrandNewPassword2026!"
    })
    assert new_ok.status_code == 200

def test_user_a_and_user_b_isolation(client: TestClient):
    # User A
    client.post("/api/auth/register", json={
        "full_name": "User Alpha",
        "email": "user.a@isolation.test",
        "password": "PasswordA123!",
        "confirm_password": "PasswordA123!",
        "operator_id": "op-user-a"
    })
    prof_a = client.get("/api/auth/profile").json()
    assert prof_a["operator_id"] == "op-user-a"

    # User B
    client.post("/api/auth/register", json={
        "full_name": "User Beta",
        "email": "user.b@isolation.test",
        "password": "PasswordB123!",
        "confirm_password": "PasswordB123!",
        "operator_id": "op-user-b"
    })
    prof_b = client.get("/api/auth/profile").json()
    assert prof_b["operator_id"] == "op-user-b"
    assert prof_b["operator_id"] != prof_a["operator_id"]

def test_hunt_presets_and_telemetry_evaluation(client: TestClient):
    # Test Preset 1: Logon Failures
    p1 = client.post("/api/hunt", json={"query": "source.ip: 10.0.2.15 AND event.action: logon_failed"})
    assert p1.status_code == 200
    d1 = p1.json()
    assert d1["hits"] > 0
    assert len(d1["matched_events"]) > 0
    assert any("logon_failed" in e["event"] for e in d1["matched_events"])

    # Test Preset 2: SQL Injection
    p2 = client.post("/api/hunt", json={"query": "target.host: web01 AND event: sqli"})
    assert p2.status_code == 200
    d2 = p2.json()
    assert d2["hits"] > 0
    assert any("sqli" in e["event"] for e in d2["matched_events"])

    # Test Preset 3: Kerberoast
    p3 = client.post("/api/hunt", json={"query": "technique: T1558 AND event.action: ticket_request"})
    assert p3.status_code == 200
    d3 = p3.json()
    assert d3["hits"] > 0
    assert any(e["technique_id"] == "T1558" for e in d3["matched_events"])

    # Test Preset 4: Ransomware Isolation
    p4 = client.post("/api/hunt", json={"query": "state: ISOLATED AND event: ransomware"})
    assert p4.status_code == 200
    d4 = p4.json()
    assert d4["hits"] > 0
    assert any("ransomware" in e["event"] for e in d4["matched_events"])
    assert any(e["state"] == "ISOLATED" for e in d4["matched_events"])

def test_html_routes(client: TestClient):
    # Landing page (without Docs link)
    landing_resp = client.get("/")
    assert landing_resp.status_code == 200
    assert "Docs" not in landing_resp.text or "/playground" not in landing_resp.text

    # Access page
    access_resp = client.get("/access")
    assert access_resp.status_code == 200
    assert "SIGN IN" in access_resp.text
    assert "REGISTER" in access_resp.text

    # Profile page
    profile_resp = client.get("/profile")
    assert profile_resp.status_code == 200
    assert "OPERATOR PROFILE" in profile_resp.text

    # Watch page
    watch_resp = client.get("/watch")
    assert watch_resp.status_code == 200
    assert "WATCH LIVE ATTACK (60s DEMO)" in watch_resp.text

