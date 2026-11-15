import pytest

def test_get_trap_status(client):
    res = client.get("/api/trap")
    assert res.status_code == 200
    data = res.json()
    assert "sessions_captured" in data
    assert "unique_countries" in data
    assert "honeytokens_tripped" in data
    assert "honeytokens" in data
    assert "sessions" in data
    assert "attacker_origins" in data

    token_ids = [t["id"] for t in data["honeytokens"]]
    assert "svc_backup" in token_ids
    assert "passwords_xlsx" in token_ids
    assert "aws_key_txt" in token_ids

def test_touch_honeytoken(client):
    # Touch passwords_xlsx
    res = client.post("/api/trap/touch/passwords_xlsx")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "tripped"
    assert data["token"]["id"] == "passwords_xlsx"
    assert data["token"]["status"] == "TRIGGERED"

    # Verify sessions gained a new entry
    state = data["state"]
    assert state["honeytokens_tripped"] >= 2
    assert any("passwords.xlsx" in s["credentials"] for s in state["sessions"])

def test_touch_invalid_honeytoken(client):
    res = client.post("/api/trap/touch/fake_token_99")
    assert res.status_code == 404
