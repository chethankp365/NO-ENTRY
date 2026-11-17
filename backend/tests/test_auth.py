"""
NO ENTRY - Authentication Test Suite
Tests registration, login, wrong passphrase rejection, guest sessions, and cookie handling.
"""

import pytest
from backend.app.config import settings

def test_jwt_secret_configured():
    assert settings.SECRET_KEY is not None
    assert len(settings.SECRET_KEY) >= 16

def test_operator_auto_registration_and_login(client):
    # First time login auto-registers
    response = client.post("/api/auth/login", json={
        "operator_id": "op-unit-test-1",
        "passphrase": "correct-horse-battery-staple"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["operator_id"] == "op-unit-test-1"
    assert "ne_auth_token" in response.cookies

    # Profile verification with cookie
    me_resp = client.get("/api/auth/me")
    assert me_resp.status_code == 200
    assert me_resp.json()["operator_id"] == "op-unit-test-1"

def test_login_incorrect_passphrase_rejected(client):
    # Register operator
    client.post("/api/auth/login", json={
        "operator_id": "op-defender",
        "passphrase": "super-secure-pass"
    })

    # Try login with wrong passphrase
    bad_resp = client.post("/api/auth/login", json={
        "operator_id": "op-defender",
        "passphrase": "wrong-password-attack"
    })
    assert bad_resp.status_code == 401
    assert "ACCESS DENIED" in bad_resp.json()["detail"]

def test_guest_operator_login(client):
    response = client.post("/api/auth/guest")
    assert response.status_code == 200
    data = response.json()
    assert data["operator_id"].startswith("op-")
    assert data["role"] == "guest"
    assert "ne_auth_token" in response.cookies

    # Check session
    me_resp = client.get("/api/auth/me")
    assert me_resp.status_code == 200
    assert me_resp.json()["operator_id"] == data["operator_id"]

def test_logout(client):
    # Login as guest
    client.post("/api/auth/guest")

    # Logout
    logout_resp = client.post("/api/auth/logout")
    assert logout_resp.status_code == 200

    # Next /me call should be 401
    unauth_resp = client.get("/api/auth/me")
    assert unauth_resp.status_code == 401


def test_password_reset_production_security_no_token_leak(client, monkeypatch):
    """Ensure production password reset never returns reset_token and uses uniform anti-enumeration message."""
    # Test with unregistered email
    resp_unreg = client.post("/api/auth/forgot-password", json={"email": "nonexistent_operator@test.local"})
    assert resp_unreg.status_code == 200
    assert "reset_token" not in resp_unreg.json()
    assert "password recovery instructions have been generated" in resp_unreg.json()["message"]

    # Register an operator first
    reg_resp = client.post("/api/auth/register", json={
        "full_name": "Audit Operator",
        "email": "audit_operator@test.local",
        "password": "InitialPassword123!",
        "confirm_password": "InitialPassword123!"
    })
    assert reg_resp.status_code == 200

    # In production mode:
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "DEBUG", False)

    resp_prod = client.post("/api/auth/forgot-password", json={"email": "audit_operator@test.local"})
    assert resp_prod.status_code == 200
    prod_data = resp_prod.json()
    assert prod_data["status"] == "success"
    assert "reset_token" not in prod_data, "CRITICAL: reset_token must never be returned in production API response!"
    assert prod_data["message"] == resp_unreg.json()["message"], "Message must be uniform to prevent account enumeration!"
