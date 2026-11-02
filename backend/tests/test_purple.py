import pytest
from backend.app.api.purple import get_purple_scenario, PURPLE_SCENARIOS

def test_purple_scenarios_structure():
    assert "brute-force" in PURPLE_SCENARIOS
    assert "sql-injection" in PURPLE_SCENARIOS
    assert "kerberoast" in PURPLE_SCENARIOS

    for sc_id, sc in PURPLE_SCENARIOS.items():
        assert len(sc["pairs"]) >= 5
        for pair in sc["pairs"]:
            assert "link_id" in pair
            assert "stage" in pair
            assert "attacker" in pair
            assert "defender" in pair
            assert "text" in pair["attacker"]
            assert "text" in pair["defender"]

def test_purple_api_endpoint(client):
    res = client.post("/api/purple/run", json={"scenario": "brute-force"})
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == "brute-force"
    assert len(data["pairs"]) >= 5

    # Check for specific expected tokens
    first_pair = data["pairs"][0]
    assert first_pair["link_id"] == "link-1"
    assert "nmap" in first_pair["attacker"]["text"]
    assert "SURICATA" in first_pair["defender"]["text"]

    last_pair = data["pairs"][-1]
    assert "connection refused" in last_pair["attacker"]["text"]

def test_purple_sql_scenario_endpoint(client):
    res = client.post("/api/purple/run", json={"scenario": "sql-injection"})
    assert res.status_code == 200
    data = res.json()
    assert "sql" in data["id"]
    assert any("sqlmap" in p["attacker"]["text"] for p in data["pairs"])
