"""
Purple Team Correlation Engine for NO ENTRY.
Pairs attacker command-line steps with real-time defender SIEM and SOAR logs.
Each pair provides a unique link_id for drawing animated SVG connectors across split screen.
"""

from typing import Dict, List, Any
from pydantic import BaseModel

class PurpleRunRequest(BaseModel):
    scenario: str = "brute-force"

PURPLE_SCENARIOS: Dict[str, Dict[str, Any]] = {
    "brute-force": {
        "id": "brute-force",
        "title": "SSH Credential Brute-Force",
        "technique_id": "T1110",
        "target": "pfsense (10.0.0.1)",
        "pairs": [
            {
                "link_id": "link-1",
                "stage": "Recon",
                "attacker": {
                    "text": "[*] nmap -sV -p 22 10.0.0.1",
                    "type": "info"
                },
                "defender": {
                    "text": "SURICATA: Port scan detected on perimeter interface (TCP SYN)",
                    "technique": "T1595",
                    "rule": "PORT_SCAN_SYN",
                    "time_to_detect": "0.4 s",
                    "action": "logged",
                    "severity": "LOW"
                }
            },
            {
                "link_id": "link-2",
                "stage": "Initial Access",
                "attacker": {
                    "text": "[*] hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.1",
                    "type": "info"
                },
                "defender": {
                    "text": "WAZUH: SSH authentication failures burst (5 attempts in 2s)",
                    "technique": "T1110",
                    "rule": "SSH_BURST_FAILURE",
                    "time_to_detect": "1.8 s",
                    "action": "alerting",
                    "severity": "MEDIUM"
                }
            },
            {
                "link_id": "link-3",
                "stage": "Credential Access",
                "attacker": {
                    "text": "[*] testing candidates: admin123, 123456, Password123...",
                    "type": "info"
                },
                "defender": {
                    "text": "INTEL: IP 185.220.101.4 enriched via AbuseIPDB score 97% (Flyservers / Tor Exit)",
                    "technique": "T1110",
                    "enrichment": "abuseipdb 97",
                    "time_to_detect": "2.2 s",
                    "action": "enriched",
                    "severity": "HIGH"
                }
            },
            {
                "link_id": "link-4",
                "stage": "Defense Evasion / Blocking",
                "attacker": {
                    "text": "[*] hydra worker 4 attempting connection...",
                    "type": "info"
                },
                "defender": {
                    "text": "REFLEX SOAR: Automated firewall drop rule deployed on pfSense: block 185.220.101.4/32",
                    "technique": "T1110",
                    "rule_fired": "yes",
                    "time_to_detect": "3.2 s",
                    "action": "firewall_block_applied",
                    "severity": "CRITICAL"
                }
            },
            {
                "link_id": "link-5",
                "stage": "Impact / Termination",
                "attacker": {
                    "text": "[!] connection refused: ip blocked by perimeter firewall",
                    "type": "alert"
                },
                "defender": {
                    "text": "SIEM: Attack suppressed. Time to detect: 3.2 s | Time to respond: 4.1 s",
                    "technique": "T1110",
                    "rule_fired": "yes",
                    "time_to_detect": "3.2 s",
                    "action": "contained",
                    "severity": "RESOLVED"
                }
            }
        ]
    },
    "sql-injection": {
        "id": "sql-injection",
        "title": "SQL Injection & WAF Blocking",
        "technique_id": "T1190",
        "target": "web01 (10.0.1.10)",
        "pairs": [
            {
                "link_id": "link-1",
                "stage": "Recon",
                "attacker": {
                    "text": "[*] nmap -sV -p 80,443 10.0.1.10",
                    "type": "info"
                },
                "defender": {
                    "text": "ZEEK: HTTP GET /api/v1/search received from 45.9.148.22",
                    "technique": "T1595",
                    "rule": "HTTP_RECON_PROBE",
                    "time_to_detect": "0.3 s",
                    "action": "logged",
                    "severity": "LOW"
                }
            },
            {
                "link_id": "link-2",
                "stage": "Initial Access",
                "attacker": {
                    "text": "[*] sqlmap --batch -u \"http://10.0.1.10/api/v1/search?q=test\"",
                    "type": "info"
                },
                "defender": {
                    "text": "SURICATA: SQL injection UNION SELECT signature matched (SID: 2010992)",
                    "technique": "T1190",
                    "rule": "SQLI_UNION_SELECT",
                    "time_to_detect": "1.2 s",
                    "action": "alerting",
                    "severity": "HIGH"
                }
            },
            {
                "link_id": "link-3",
                "stage": "Execution",
                "attacker": {
                    "text": "[+] injectable parameter: q (Error-based / UNION detected)",
                    "type": "success"
                },
                "defender": {
                    "text": "WAZUH: Anomaly score 15 exceeded WAF threshold on web01",
                    "technique": "T1190",
                    "enrichment": "abuseipdb 84",
                    "time_to_detect": "2.4 s",
                    "action": "analyzed",
                    "severity": "HIGH"
                }
            },
            {
                "link_id": "link-4",
                "stage": "Defense Action",
                "attacker": {
                    "text": "[*] uploading web shell /var/www/uploads/c99.php",
                    "type": "info"
                },
                "defender": {
                    "text": "REFLEX SOAR: ModSecurity WAF rule 949110 applied 403 Forbidden to 45.9.148.22",
                    "technique": "T1190",
                    "rule_fired": "yes",
                    "time_to_detect": "3.1 s",
                    "action": "waf_block_applied",
                    "severity": "CRITICAL"
                }
            },
            {
                "link_id": "link-5",
                "stage": "Impact / Termination",
                "attacker": {
                    "text": "[!] HTTP 403 Forbidden: connection terminated by WAF",
                    "type": "alert"
                },
                "defender": {
                    "text": "SIEM: Web application breach blocked. Host web01 protected. (TTD: 3.1s)",
                    "technique": "T1190",
                    "rule_fired": "yes",
                    "time_to_detect": "3.1 s",
                    "action": "contained",
                    "severity": "RESOLVED"
                }
            }
        ]
    },
    "kerberoast": {
        "id": "kerberoast",
        "title": "Kerberoasting & Account Quarantine",
        "technique_id": "T1558",
        "target": "ad01 (10.0.2.10)",
        "pairs": [
            {
                "link_id": "link-1",
                "stage": "Recon",
                "attacker": {
                    "text": "[*] Rubeus.exe kerberoast /outfile:hashes.txt",
                    "type": "info"
                },
                "defender": {
                    "text": "AD DS: Kerberos TGS request for SPN MSSQLSvc/dc01.corp.internal",
                    "technique": "T1558",
                    "rule": "KERBEROS_SPN_TGS",
                    "time_to_detect": "0.6 s",
                    "action": "logged",
                    "severity": "LOW"
                }
            },
            {
                "link_id": "link-2",
                "stage": "Initial Access",
                "attacker": {
                    "text": "[+] extracted 1 RC4-HMAC ticket for svc_backup",
                    "type": "success"
                },
                "defender": {
                    "text": "WAZUH: Event ID 4769 (A Kerberos service ticket was requested with weak RC4 encryption)",
                    "technique": "T1558",
                    "rule": "WEAK_KERBEROS_CIPHER",
                    "time_to_detect": "1.4 s",
                    "action": "alerting",
                    "severity": "MEDIUM"
                }
            },
            {
                "link_id": "link-3",
                "stage": "Credential Access",
                "attacker": {
                    "text": "[*] hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt",
                    "type": "info"
                },
                "defender": {
                    "text": "SIEM: Anomaly alert: Mass TGS requests from workstation ws-01",
                    "technique": "T1558",
                    "enrichment": "internal 10.0.2.15",
                    "time_to_detect": "2.8 s",
                    "action": "analyzed",
                    "severity": "HIGH"
                }
            },
            {
                "link_id": "link-4",
                "stage": "Defense Action",
                "attacker": {
                    "text": "[*] attempting logon with cracked svc_backup password",
                    "type": "info"
                },
                "defender": {
                    "text": "REFLEX SOAR: Service account svc_backup ticket invalidated & account locked",
                    "technique": "T1558",
                    "rule_fired": "yes",
                    "time_to_detect": "4.2 s",
                    "action": "ticket_revoked_account_locked",
                    "severity": "CRITICAL"
                }
            },
            {
                "link_id": "link-5",
                "stage": "Impact / Termination",
                "attacker": {
                    "text": "[!] RPC server unavailable: account locked out by Domain Controller",
                    "type": "alert"
                },
                "defender": {
                    "text": "DEFENSE: Active Directory secured. Mean time to respond: 4.2 s.",
                    "technique": "T1558",
                    "rule_fired": "yes",
                    "time_to_detect": "4.2 s",
                    "action": "contained",
                    "severity": "RESOLVED"
                }
            }
        ]
    }
}

def get_purple_scenario(scenario_key: str) -> Dict[str, Any]:
    """Retrieve paired scenario data normalized by key."""
    clean_key = scenario_key.lower().replace(" ", "-").replace("_", "")
    if "sql" in clean_key:
        matched = PURPLE_SCENARIOS["sql-injection"]
    elif "kerb" in clean_key:
        matched = PURPLE_SCENARIOS["kerberoast"]
    else:
        matched = PURPLE_SCENARIOS["brute-force"]

    return matched
