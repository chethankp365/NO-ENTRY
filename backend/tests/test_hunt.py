import pytest
from backend.app.api.hunt import evaluate_hunt_query, PRESET_QUERIES

def test_hunt_default_evaluation():
    res = evaluate_hunt_query("source.ip: 10.0.2.15 AND event.action: logon_failed")
    assert "hits" in res
    assert res["hits"] > 0
    assert "histogram" in res
    assert len(res["histogram"]) == 10
    assert "hypothesis" in res
    assert "Password spraying" in res["hypothesis"] or "compromised" in res["hypothesis"]

def test_hunt_presets_exist():
    assert len(PRESET_QUERIES) >= 4
    for p in PRESET_QUERIES:
        assert "id" in p
        assert "query" in p
        assert "hypothesis" in p

def test_hunt_api_endpoint(client):
    res = client.post("/api/hunt", json={
        "query": "target.host: web01 AND event: sqli",
        "timeframe_minutes": 10
    })
    assert res.status_code == 200
    data = res.json()
    assert data["hits"] > 0
    assert len(data["histogram"]) == 10
    assert "SQL injection" in data["hypothesis"] or "web" in data["hypothesis"].lower()

def test_hunt_presets_endpoint(client):
    res = client.get("/api/hunt/presets")
    assert res.status_code == 200
    assert len(res.json()) >= 4
