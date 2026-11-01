from pathlib import Path
import pytest
from backend.app.config import settings
from backend.app.rules.engine import RuleEngine

def test_sqli_rule_detection():
    rule_path = settings.RULES_DIR / "sqli_pattern.yaml"
    with open(rule_path, "r", encoding="utf-8") as f:
        rule = RuleEngine.parse_rule_yaml(f.read())

    test_logs = [
        {"uri": "/products?id=1 UNION SELECT null, username, password FROM users--", "status_code": 200},
        {"uri": "/login?user=admin' OR '1'='1", "status_code": 200},
        {"uri": "/index.html", "status_code": 200},
        {"uri": "/about-us", "status_code": 200},
        {"uri": "/search?q=cybersecurity&order=asc", "status_code": 200},
    ]

    result = RuleEngine.evaluate_rule(rule, test_logs)
    assert result.count == 2
    assert len(result.matched_lines) == 2
    assert "UNION SELECT" in result.matched_lines[0]["uri"]
    assert "admin' OR '1'='1" in result.matched_lines[1]["uri"]

def test_ssh_brute_force_rule_with_filter():
    rule_path = settings.RULES_DIR / "ssh_brute_force.yaml"
    with open(rule_path, "r", encoding="utf-8") as f:
        rule = RuleEngine.parse_rule_yaml(f.read())

    test_logs = [
        # Match: external attacker failed password
        {
            "event": {"action": "logon_failed"},
            "service": "ssh",
            "message": "Failed password for root from 185.220.101.4 port 43212",
            "source_ip": "185.220.101.4"
        },
        # Filtered: internal security scanner 10.0.3.x subnet
        {
            "event": {"action": "logon_failed"},
            "service": "ssh",
            "message": "Failed password for test from 10.0.3.15 port 55122",
            "source_ip": "10.0.3.15"
        },
        # Normal log: accepted password
        {
            "event": {"action": "logon_success"},
            "service": "ssh",
            "message": "Accepted publickey for admin from 10.0.2.10 port 22",
            "source_ip": "10.0.2.10"
        }
    ]

    result = RuleEngine.evaluate_rule(rule, test_logs)
    assert result.count == 1
    assert result.matched_lines[0]["source_ip"] == "185.220.101.4"

def test_kerberoast_rule_detection():
    rule_path = settings.RULES_DIR / "kerberoast.yaml"
    with open(rule_path, "r", encoding="utf-8") as f:
        rule = RuleEngine.parse_rule_yaml(f.read())

    test_logs = [
        # Kerberoast ticket request with RC4 encryption (0x17)
        {
            "event_id": 4769,
            "ticket_encryption": "0x17",
            "service_name": "MSSQLSvc/db01.corp.lan$n",
            "account_name": "attacker@corp.lan"
        },
        # Benign ticket request with AES256 (0x12)
        {
            "event_id": 4769,
            "ticket_encryption": "0x12",
            "service_name": "host/dc01.corp.lan$n",
            "account_name": "admin@corp.lan"
        },
        # Different event id
        {
            "event_id": 4624,
            "ticket_encryption": "0x17",
            "service_name": "krbtgt$n"
        }
    ]

    result = RuleEngine.evaluate_rule(rule, test_logs)
    assert result.count == 1
    assert result.matched_lines[0]["ticket_encryption"] == "0x17"
    assert result.matched_lines[0]["service_name"] == "MSSQLSvc/db01.corp.lan$n"

def test_regex_and_modifiers():
    custom_yaml = '''
    title: Custom Regex Test
    detection:
      selection:
        ip|regex: '^192\\.168\\.1\\.[0-9]+$'
        path|startswith: '/api/v1/'
        file|endswith: '.sh'
      condition: selection
    '''
    rule = RuleEngine.parse_rule_yaml(custom_yaml)

    logs = [
        {"ip": "192.168.1.55", "path": "/api/v1/deploy", "file": "install.sh"},
        {"ip": "10.0.0.1", "path": "/api/v1/deploy", "file": "install.sh"},
        {"ip": "192.168.1.55", "path": "/api/v2/deploy", "file": "install.sh"},
        {"ip": "192.168.1.55", "path": "/api/v1/deploy", "file": "install.exe"},
    ]

    res = RuleEngine.evaluate_rule(rule, logs)
    assert res.count == 1
    assert res.matched_lines[0]["ip"] == "192.168.1.55"
