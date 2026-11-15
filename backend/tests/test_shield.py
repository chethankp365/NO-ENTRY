import pytest

def test_get_shield_status(client):
    res = client.get("/api/shield")
    assert res.status_code == 200
    data = res.json()
    assert "before_score" in data
    assert "after_score" in data
    assert "score_gained" in data
    assert "checklist" in data
    assert "areas" in data
    assert data["before_score"] == 38
    assert data["after_score"] >= 38
    assert len(data["checklist"]) >= 7

    # Check known items exist
    items = {item["id"]: item for item in data["checklist"]}
    assert "smb_signing" in items
    assert items["smb_signing"]["status"] == "PASS"
    assert "tiered_admin" in items
    assert "default_creds" in items

def test_apply_shield_fix(client):
    # Apply fix to tiered_admin
    res = client.post("/api/shield/fix/tiered_admin")
    assert res.status_code == 200
    data = res.json()
    items = {item["id"]: item for item in data["checklist"]}
    assert items["tiered_admin"]["status"] == "PASS"
    assert data["score_gained"] > 0

    # Test fix to invalid item
    res_err = client.post("/api/shield/fix/nonexistent_item")
    assert res_err.status_code == 404
