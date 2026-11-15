import pytest

def test_get_attack_coverage(client):
    res = client.get("/api/attack/coverage")
    assert res.status_code == 200
    data = res.json()
    assert "stats" in data
    assert "tactics" in data

    stats = data["stats"]
    assert stats["detected"] >= 38
    assert stats["gaps"] >= 12
    assert stats["missions"] == 5

    tactics = data["tactics"]
    assert len(tactics) == 12
    for col in tactics:
        assert "tactic_name" in col
        assert "techniques" in col
        assert len(col["techniques"]) == 6
