import pytest

def test_debug_page_load(client):
    response = client.get("/debug")
    assert response.status_code == 200
    assert "NO ENTRY" in response.text
    assert "terminalFeed" in response.text

def test_playground_page_load(client):
    response = client.get("/playground")
    assert response.status_code == 200
    assert "NO ENTRY" in response.text
    assert "ne-logo" in response.text
    assert "rainCanvas" in response.text

def test_landing_page_load(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Break in." in response.text
    assert "ENTER THE RANGE" in response.text

def test_boot_page_load(client):
    response = client.get("/boot")
    assert response.status_code == 200
    assert "BOOT SEQUENCE" in response.text
    assert "audioGate" in response.text

def test_access_page_load(client):
    response = client.get("/access")
    assert response.status_code == 200
    assert "ACCESS TERMINAL" in response.text
    assert "REQUEST ACCESS" in response.text

def test_command_center_page_load(client):
    response = client.get("/command-center")
    assert response.status_code == 200

def test_api_state(client):
    response = client.get("/api/state")
    assert response.status_code == 200
    data = response.json()
    assert "metrics" in data
    assert "hosts" in data
    assert "playbooks" in data
    assert "recent_events" in data
    assert "scenarios" in data

def test_api_events_and_filtering(client):
    # Fetch events
    response = client.get("/api/events?limit=10")
    assert response.status_code == 200
    events = response.json()
    assert isinstance(events, list)
    assert len(events) <= 10

    # Filter by state
    response_filt = client.get("/api/events?state=BLOCKED")
    assert response_filt.status_code == 200
    for e in response_filt.json():
        assert e["state"] == "BLOCKED"

def test_api_event_detail_enrichment(client):
    # Get first event
    list_res = client.get("/api/events?limit=1")
    event_id = list_res.json()[0]["id"]

    response = client.get(f"/api/events/{event_id}")
    assert response.status_code == 200
    detail = response.json()
    assert "event" in detail
    assert "mitre_technique" in detail
    assert "enrichment" in detail
    assert "raw_log" in detail
    assert "abuse_confidence_score" in detail["enrichment"]
    # Check deterministic score for known IP 185.220.101.4 if present
    if detail["event"]["source_ip"] == "185.220.101.4":
        assert detail["enrichment"]["abuse_confidence_score"] == 97

def test_api_metrics(client):
    res = client.get("/api/metrics")
    assert res.status_code == 200
    metrics = res.json()
    assert "threat_level" in metrics
    assert "alerts_today" in metrics
    assert "mean_time_to_detect" in metrics
    assert "mean_time_to_respond" in metrics
    assert "module_percentages" in metrics

def test_api_hosts(client):
    res = client.get("/api/hosts")
    assert res.status_code == 200
    hosts = res.json()
    assert "kali" in hosts
    assert "pfsense" in hosts
    assert "web01" in hosts
    assert "ad01" in hosts

def test_api_scenarios_list(client):
    res = client.get("/api/scenarios")
    assert res.status_code == 200
    scenarios = res.json()
    assert len(scenarios) >= 5

def test_api_host_isolate(client):
    res = client.post("/api/hosts/ws-01/isolate")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "isolated"

    # Verify state updated
    hosts_res = client.get("/api/hosts")
    assert hosts_res.json()["ws-01"]["status"] == "isolated"

def test_api_block_ip(client):
    res = client.post("/api/block-ip", json={"ip": "194.26.29.99", "reason": "Test block"})
    assert res.status_code == 200
    assert res.json()["status"] == "blocked"

def test_api_playbooks_toggle(client):
    # Fetch
    pb_res = client.get("/api/reflex/playbooks")
    assert pb_res.status_code == 200

    # Toggle
    toggle_res = client.post("/api/reflex/playbooks", json={
        "playbook_id": "notify_telegram",
        "enabled": True
    })
    assert toggle_res.status_code == 200
    assert toggle_res.json()["enabled"] is True

def test_api_autopilot_toggle(client):
    res = client.post("/api/sim/autopilot", json={"enabled": False})
    assert res.status_code == 200
    assert res.json()["autopilot_enabled"] is False
