import pytest

def test_get_forensics(client):
    res = client.get("/api/forensics")
    assert res.status_code == 200
    data = res.json()
    assert "timeline" in data
    assert "evidence" in data
    assert len(data["timeline"]) >= 5
    assert len(data["evidence"]) >= 3

def test_verify_forensics_file_real_sha256(client):
    # Verify memory.dmp
    res = client.post("/api/forensics/verify/memory.dmp")
    assert res.status_code == 200
    data = res.json()
    assert data["file"] == "memory.dmp"
    assert data["verified"] is True
    assert "computed_sha256" in data
    assert len(data["computed_sha256"]) == 64
    assert data["computed_sha256"] == data["recorded_sha256"]

def test_verify_nonexistent_file(client):
    res = client.post("/api/forensics/verify/ghost.bin")
    assert res.status_code == 404

def test_forensics_hex_dump(client):
    res = client.get("/api/forensics/hex/memory.dmp?offset=0&limit=64")
    assert res.status_code == 200
    data = res.json()
    assert data["file"] == "memory.dmp"
    assert "rows" in data
    assert len(data["rows"]) > 0
    row0 = data["rows"][0]
    assert "offset" in row0
    assert "hex" in row0
    assert "ascii" in row0
