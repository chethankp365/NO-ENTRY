import pytest
from backend.app.reflex.engine import ReflexEngine

def test_reflex_playbook_toggle():
    engine = ReflexEngine()
    pb = engine.toggle_playbook("block_ip", False)
    assert pb.enabled is False

    pb = engine.toggle_playbook("block_ip", True)
    assert pb.enabled is True

def test_reflex_block_ip_action():
    engine = ReflexEngine()
    engine.blocked_ips.clear()

    # With block_ip ON
    engine.toggle_playbook("block_ip", True)
    test_event = {
        "technique_id": "T1110",
        "source_ip": "194.26.29.112",
        "target_host": "pfsense",
        "state": "BLOCKED",
        "severity": "HIGH",
        "time": "12:04:14"
    }

    actions = engine.evaluate_event(test_event)
    assert len(actions) >= 1
    assert any("firewall: block 194.26.29.112" in a.action for a in actions)
    assert "194.26.29.112" in engine.blocked_ips
    assert actions[0].response_time == 8.4

def test_reflex_toggle_off_suppresses_action():
    engine = ReflexEngine()
    engine.blocked_ips.clear()

    # Turn block_ip OFF
    engine.toggle_playbook("block_ip", False)
    test_event = {
        "technique_id": "T1110",
        "source_ip": "194.26.29.113",
        "target_host": "pfsense",
        "state": "BLOCKED",
        "severity": "HIGH",
        "time": "12:04:15"
    }

    actions = engine.evaluate_event(test_event)
    # block_ip should NOT trigger because it is disabled
    block_actions = [a for a in actions if a.playbook_id == "block_ip"]
    assert len(block_actions) == 0
    assert "194.26.29.113" not in engine.blocked_ips

def test_reflex_isolate_host():
    engine = ReflexEngine()
    isolated_hosts = []

    def mock_host_updater(host_id, status):
        isolated_hosts.append((host_id, status))

    engine.toggle_playbook("isolate_host", True)
    test_event = {
        "technique_id": "T1021",
        "source_ip": "10.0.2.15",
        "target_host": "ws-02",
        "state": "ISOLATED",
        "severity": "CRITICAL",
        "breach": True,
        "time": "12:03:56"
    }

    actions = engine.evaluate_event(test_event, host_updater=mock_host_updater)
    assert len(actions) >= 1
    isolate_actions = [a for a in actions if a.playbook_id == "isolate_host"]
    assert len(isolate_actions) >= 1
    assert ("ws-02", "isolated") in isolated_hosts
