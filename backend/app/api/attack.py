"""
NO ENTRY - MITRE ATT&CK Matrix Coverage Service
Calculates 12x6 tactic-technique heatmap coverage, detected techniques vs security gaps,
and dynamically lights up cells when live attack events are recognized.
"""

from typing import Dict, List, Any
from backend.app.sim.mitre import list_techniques

TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance", "short": "Recon"},
    {"id": "TA0001", "name": "Initial Access", "short": "Initial Access"},
    {"id": "TA0002", "name": "Execution", "short": "Execution"},
    {"id": "TA0003", "name": "Persistence", "short": "Persistence"},
    {"id": "TA0004", "name": "Privilege Escalation", "short": "Priv Esc"},
    {"id": "TA0005", "name": "Defense Evasion", "short": "Defense Evasion"},
    {"id": "TA0006", "name": "Credential Access", "short": "Cred Access"},
    {"id": "TA0007", "name": "Discovery", "short": "Discovery"},
    {"id": "TA0008", "name": "Lateral Movement", "short": "Lateral Move"},
    {"id": "TA0009", "name": "Collection", "short": "Collection"},
    {"id": "TA0010", "name": "Exfiltration", "short": "Exfiltration"},
    {"id": "TA0040", "name": "Impact", "short": "Impact"},
]

# 6 representative techniques for each of the 12 tactics
TACTIC_TECHNIQUES = {
    "TA0043": [
        {"id": "T1595", "name": "Active Scanning", "rule": "SIGMA_SCAN_01", "status": "detected"},
        {"id": "T1592", "name": "Gather Host Info", "rule": "ZEEK_HOST_PROBE", "status": "detected"},
        {"id": "T1589", "name": "Gather Identity", "rule": "NONE", "status": "gap"},
        {"id": "T1590", "name": "Gather Net Info", "rule": "SNORT_NET_SURVEY", "status": "detected"},
        {"id": "T1598", "name": "Phishing for Info", "rule": "SURICATA_SPEAR_01", "status": "detected"},
        {"id": "T1594", "name": "Search Victim Sites", "rule": "NONE", "status": "untested"}
    ],
    "TA0001": [
        {"id": "T1190", "name": "Exploit Public App", "rule": "MODSEC_WAF_949", "status": "detected"},
        {"id": "T1566", "name": "Phishing", "rule": "EMAIL_MACRO_ATTACH", "status": "detected"},
        {"id": "T1078", "name": "Valid Accounts", "rule": "WAZUH_ADMIN_BURST", "status": "detected"},
        {"id": "T1133", "name": "External Remote Services", "rule": "NONE", "status": "gap"},
        {"id": "T1200", "name": "Hardware Additions", "rule": "NONE", "status": "untested"},
        {"id": "T1195", "name": "Supply Chain Compromise", "rule": "NONE", "status": "gap"}
    ],
    "TA0002": [
        {"id": "T1059", "name": "Command & Script Interpreter", "rule": "SIGMA_POWERSHELL_ENC", "status": "detected"},
        {"id": "T1204", "name": "User Execution", "rule": "EDR_OFFICE_SPAWN", "status": "detected"},
        {"id": "T1053", "name": "Scheduled Task / Job", "rule": "SCHTASKS_ANOMALY", "status": "detected"},
        {"id": "T1047", "name": "WMI Execution", "rule": "WMI_EXEC_SPAWN", "status": "detected"},
        {"id": "T1569", "name": "System Services", "rule": "SC_SERVICE_CREATE", "status": "detected"},
        {"id": "T1106", "name": "Native API Execution", "rule": "NONE", "status": "gap"}
    ],
    "TA0003": [
        {"id": "T1547", "name": "Boot/Logon Autostart", "rule": "REG_RUN_KEY_CHANGE", "status": "detected"},
        {"id": "T1543", "name": "Create or Modify Service", "rule": "SVC_INSTALL_ALRT", "status": "detected"},
        {"id": "T1136", "name": "Create Account", "rule": "AD_USER_CREATE_01", "status": "detected"},
        {"id": "T1098", "name": "Account Manipulation", "rule": "NONE", "status": "gap"},
        {"id": "T1546", "name": "Event Triggered Execution", "rule": "WMI_EVENT_SUBSCR", "status": "detected"},
        {"id": "T1574", "name": "Hijack Execution Flow", "rule": "NONE", "status": "untested"}
    ],
    "TA0004": [
        {"id": "T1068", "name": "Exploitation for Priv Esc", "rule": "KERNEL_EXPLOIT_SIG", "status": "detected"},
        {"id": "T1548", "name": "Abuse Elevation Control", "rule": "UAC_BYPASS_SIG", "status": "detected"},
        {"id": "T1055", "name": "Process Injection", "rule": "INJECT_REMOTE_THREAD", "status": "detected"},
        {"id": "T1134", "name": "Access Token Manipulation", "rule": "TOKEN_DUPLICATION", "status": "detected"},
        {"id": "T1484", "name": "Domain Policy Modification", "rule": "NONE", "status": "gap"},
        {"id": "T1611", "name": "Escape to Host", "rule": "NONE", "status": "untested"}
    ],
    "TA0005": [
        {"id": "T1070", "name": "Indicator Removal", "rule": "WEVTUTIL_LOG_CLEAR", "status": "detected"},
        {"id": "T1027", "name": "Obfuscated Files", "rule": "HIGH_ENTROPY_PE", "status": "detected"},
        {"id": "T1562", "name": "Impair Defenses", "rule": "AV_TAMPER_ALERT", "status": "detected"},
        {"id": "T1218", "name": "System Binary Proxy (LOLBins)", "rule": "MSHTA_RUNDLL_PROX", "status": "detected"},
        {"id": "T1036", "name": "Masquerading", "rule": "NONE", "status": "gap"},
        {"id": "T1202", "name": "Indirect Command Exec", "rule": "NONE", "status": "untested"}
    ],
    "TA0006": [
        {"id": "T1110", "name": "Brute Force", "rule": "SSH_HYDRA_BURST", "status": "detected"},
        {"id": "T1558", "name": "Steal Kerberos Tickets", "rule": "KERBEROAST_TGS_REQ", "status": "detected"},
        {"id": "T1003", "name": "OS Credential Dumping", "rule": "LSASS_MEM_READ", "status": "detected"},
        {"id": "T1552", "name": "Unsecured Credentials", "rule": "HONEYTOKEN_TRIPPED", "status": "detected"},
        {"id": "T1555", "name": "Credentials from Stores", "rule": "NONE", "status": "gap"},
        {"id": "T1606", "name": "Forge Web Credentials", "rule": "NONE", "status": "untested"}
    ],
    "TA0007": [
        {"id": "T1087", "name": "Account Discovery", "rule": "NET_USER_SURVEY", "status": "detected"},
        {"id": "T1083", "name": "File and Directory Discovery", "rule": "DIR_KDBX_SEARCH", "status": "detected"},
        {"id": "T1046", "name": "Network Service Discovery", "rule": "NMAP_SYN_SWEEP", "status": "detected"},
        {"id": "T1018", "name": "Remote System Discovery", "rule": "PING_SWEEP_ALERT", "status": "detected"},
        {"id": "T1082", "name": "System Information Discovery", "rule": "SYSTEMINFO_QUERY", "status": "detected"},
        {"id": "T1016", "name": "System Network Config", "rule": "IPCONFIG_ROUTE_PROBE", "status": "detected"}
    ],
    "TA0008": [
        {"id": "T1021", "name": "Remote Services (SMB/RDP)", "rule": "PSEXEC_LATERAL_MOVE", "status": "detected"},
        {"id": "T1570", "name": "Lateral Tool Transfer", "rule": "SMB_TRANSFER_PE", "status": "detected"},
        {"id": "T1563", "name": "Remote Service Hijacking", "rule": "NONE", "status": "gap"},
        {"id": "T1080", "name": "Taint Shared Content", "rule": "NONE", "status": "gap"},
        {"id": "T1550", "name": "Use Alternate Authentication", "rule": "PASS_THE_HASH_NTLM", "status": "detected"},
        {"id": "T1091", "name": "Replication Through Media", "rule": "NONE", "status": "untested"}
    ],
    "TA0009": [
        {"id": "T1560", "name": "Archive Collected Data", "rule": "SEVENZIP_ARCHIVE_CMD", "status": "detected"},
        {"id": "T1005", "name": "Data from Local System", "rule": "MASS_DOC_STAGING", "status": "detected"},
        {"id": "T1039", "name": "Data from Network Shared Drive", "rule": "NONE", "status": "gap"},
        {"id": "T1114", "name": "Email Collection", "rule": "OUTLOOK_OST_READ", "status": "detected"},
        {"id": "T1115", "name": "Clipboard Data", "rule": "CLIPBOARD_MONITOR", "status": "detected"},
        {"id": "T1125", "name": "Video Capture", "rule": "NONE", "status": "untested"}
    ],
    "TA0010": [
        {"id": "T1048", "name": "Exfil Over Alternative Protocol", "rule": "DNS_TUNNEL_IODINE", "status": "detected"},
        {"id": "T1041", "name": "Exfil Over C2 Channel", "rule": "HTTP_EXFIL_POST_BURST", "status": "detected"},
        {"id": "T1071", "name": "Application Layer Protocol", "rule": "SURICATA_DNS_ENTROPY", "status": "detected"},
        {"id": "T1567", "name": "Exfil Over Web Service", "rule": "MEGA_UPLOAD_BURST", "status": "detected"},
        {"id": "T1052", "name": "Exfil Over Physical Medium", "rule": "NONE", "status": "gap"},
        {"id": "T1011", "name": "Exfil Over Other Network", "rule": "NONE", "status": "untested"}
    ],
    "TA0040": [
        {"id": "T1486", "name": "Data Encrypted for Impact", "rule": "RANSOM_SHADOW_DELETE", "status": "detected"},
        {"id": "T1489", "name": "Service Stop", "rule": "MSSQL_STOP_BLOCKED", "status": "detected"},
        {"id": "T1490", "name": "Inhibit System Recovery", "rule": "VSSADMIN_DELETE", "status": "detected"},
        {"id": "T1485", "name": "Data Destruction", "rule": "SDELETE_SECURE_WIPE", "status": "detected"},
        {"id": "T1529", "name": "System Shutdown/Reboot", "rule": "NONE", "status": "gap"},
        {"id": "T1499", "name": "Endpoint DoS", "rule": "NONE", "status": "untested"}
    ],
}

class AttackCoverageService:
    def __init__(self):
        self.matrix = TACTIC_TECHNIQUES

    def get_coverage_data(self, sim_engine=None) -> Dict[str, Any]:
        detected_count = 0
        gap_count = 0
        untested_count = 0

        # Collect techniques seen in recent events to mark dynamically
        seen_tech_ids = set()
        if sim_engine:
            seen_tech_ids = {e.technique_id for e in sim_engine.recent_events}

        columns = []
        for tactic in TACTICS:
            t_id = tactic["id"]
            techs = self.matrix.get(t_id, [])
            items = []
            for item in techs:
                status = item["status"]
                # Dynamic mark if seen in live sim events
                if item["id"] in seen_tech_ids:
                    status = "detected"

                if status == "detected":
                    detected_count += 1
                elif status == "gap":
                    gap_count += 1
                else:
                    untested_count += 1

                items.append({
                    "id": item["id"],
                    "name": item["name"],
                    "rule": item["rule"],
                    "status": status
                })

            columns.append({
                "tactic_id": t_id,
                "tactic_name": tactic["name"],
                "short_name": tactic["short"],
                "techniques": items
            })

        return {
            "stats": {
                "detected": detected_count,
                "total": 50,
                "gaps": gap_count,
                "missions": 5,
                "coverage_pct": int((detected_count / 50) * 100)
            },
            "tactics": columns
        }

attack_service = AttackCoverageService()
