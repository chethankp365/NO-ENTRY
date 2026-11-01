import pytest
from backend.app.sim.engine import sim_engine, SimEvent

@pytest.mark.asyncio
async def test_engine_initial_state():
    state = sim_engine.get_full_state()
    assert "metrics" in state
    assert "hosts" in state
    assert "recent_events" in state
    assert len(state["hosts"]) == 9
    assert state["metrics"]["threat_level"] in ["LOW", "ELEVATED", "CRITICAL"]

@pytest.mark.asyncio
async def test_engine_emit_event():
    initial_alerts = sim_engine.metrics.alerts_today
    evt = await sim_engine.emit_event({
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "event": "brute force login attempt",
        "source_ip": "185.220.101.4",
        "target_host": "pfsense",
        "state": "BLOCKED",
        "severity": "HIGH",
        "module": "Watch",
        "breach": False
    })

    assert isinstance(evt, SimEvent)
    assert evt.technique_id == "T1110"
    assert evt.source_ip == "185.220.101.4"
    assert evt.state == "BLOCKED"
    assert sim_engine.metrics.alerts_today == initial_alerts + 1
    assert sim_engine.recent_events[0].id == evt.id

@pytest.mark.asyncio
async def test_engine_breach_event():
    evt = await sim_engine.emit_event({
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "event": "test breach event",
        "source_ip": "10.0.2.16",
        "target_host": "ws-02",
        "state": "ALERT",
        "severity": "CRITICAL",
        "module": "Watch",
        "breach": True
    })

    assert evt.breach is True
    assert sim_engine.metrics.threat_level == "CRITICAL"

@pytest.mark.asyncio
async def test_host_status_update():
    sim_engine.update_host_status("ws-01", "compromised", "T1003 cred dump")
    assert sim_engine.hosts["ws-01"].status == "compromised"
    assert sim_engine.hosts["ws-01"].last_alert == "T1003 cred dump"

    # Reset
    sim_engine.update_host_status("ws-01", "healthy", None)
    assert sim_engine.hosts["ws-01"].status == "healthy"
