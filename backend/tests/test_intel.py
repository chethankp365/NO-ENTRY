import pytest

def test_get_intel(client):
    res = client.get("/api/intel")
    assert res.status_code == 200
    data = res.json()
    assert "indicators" in data
    assert "feeds" in data
    assert "graph" in data
    assert len(data["indicators"]) >= 5
    assert len(data["feeds"]) >= 4
    assert "nodes" in data["graph"]
    assert "links" in data["graph"]

def test_ioc_lookup_known(client):
    res = client.get("/api/intel/lookup?ioc=185.220.101.4")
    assert res.status_code == 200
    data = res.json()
    assert data["query"] == "185.220.101.4"
    assert data["score"] == 97
    assert data["verdict"] == "MALICIOUS"
    assert data["campaign"] == "CosmicDuke / APT29"

def test_ioc_lookup_arbitrary_deterministic(client):
    res1 = client.get("/api/intel/lookup?ioc=198.51.100.42")
    assert res1.status_code == 200
    data1 = res1.json()
    assert "verdict" in data1
    assert "score" in data1
    assert "malware" in data1
    assert "campaign" in data1

    # Repeat should return identical deterministic result
    res2 = client.get("/api/intel/lookup?ioc=198.51.100.42")
    assert res2.status_code == 200
    data2 = res2.json()
    assert data1["score"] == data2["score"]
    assert data1["verdict"] == data2["verdict"]
    assert data1["malware"] == data2["malware"]
    assert data1["campaign"] == data2["campaign"]

def test_ioc_lookup_empty(client):
    res = client.get("/api/intel/lookup?ioc=")
    assert res.status_code == 400
