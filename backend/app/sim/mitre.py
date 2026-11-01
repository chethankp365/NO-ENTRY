"""
MITRE ATT&CK Catalog for NO ENTRY
Curated catalog of ~35 cyber attack techniques across standard tactics.
Used for detection mapping, heatmap visualization, and event correlation.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel

class MitreTechnique(BaseModel):
    id: str
    name: str
    tactic: str
    description: str

MITRE_CATALOG: Dict[str, MitreTechnique] = {
    # Reconnaissance
    "T1595": MitreTechnique(
        id="T1595",
        name="Active Scanning",
        tactic="Reconnaissance",
        description="Scanning IP blocks, open ports, and vulnerable services to gather pre-attack intelligence."
    ),
    "T1592": MitreTechnique(
        id="T1592",
        name="Gather Victim Host Information",
        tactic="Reconnaissance",
        description="Enumerating host hardware, software versions, network posture, and configuration details."
    ),

    # Resource Development
    "T1587": MitreTechnique(
        id="T1587",
        name="Develop Capabilities",
        tactic="Resource Development",
        description="Crafting custom payloads, malware, webshells, and exploit scripts prior to engagement."
    ),
    "T1588": MitreTechnique(
        id="T1588",
        name="Obtain Capabilities",
        tactic="Resource Development",
        description="Acquiring commercial tools, open-source exploit frameworks, or leaked offensive tradecraft."
    ),

    # Initial Access
    "T1190": MitreTechnique(
        id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        description="Exploiting flaws (SQLi, RCE, auth bypass) in external internet-facing services to compromise systems."
    ),
    "T1566": MitreTechnique(
        id="T1566",
        name="Phishing",
        tactic="Initial Access",
        description="Sending deceptive emails or lures with malicious attachments or links to trick users."
    ),
    "T1078": MitreTechnique(
        id="T1078",
        name="Valid Accounts",
        tactic="Initial Access",
        description="Using stolen, default, or compromised valid credentials to bypass perimeter defenses."
    ),
    "T1133": MitreTechnique(
        id="T1133",
        name="External Remote Services",
        tactic="Initial Access",
        description="Leveraging exposed VPN, SSH, or RDP endpoints without MFA to gain initial entry."
    ),

    # Execution
    "T1059": MitreTechnique(
        id="T1059",
        name="Command and Scripting Interpreter",
        tactic="Execution",
        description="Executing commands via PowerShell, Bash, cmd.exe, or Python to run malicious payloads."
    ),
    "T1204": MitreTechnique(
        id="T1204",
        name="User Execution",
        tactic="Execution",
        description="Relying on target users to double-click an executable, macro-enabled document, or script."
    ),
    "T1047": MitreTechnique(
        id="T1047",
        name="Windows Management Instrumentation",
        tactic="Execution",
        description="Executing malicious commands and queries through WMI infrastructure."
    ),

    # Persistence
    "T1053": MitreTechnique(
        id="T1053",
        name="Scheduled Task/Job",
        tactic="Persistence",
        description="Configuring scheduled tasks or cron jobs to maintain long-term access across reboots."
    ),
    "T1543": MitreTechnique(
        id="T1543",
        name="Create or Modify System Process",
        tactic="Persistence",
        description="Installing rogue Windows services or Linux systemd daemons for persistent execution."
    ),
    "T1547": MitreTechnique(
        id="T1547",
        name="Boot or Logon Autostart Execution",
        tactic="Persistence",
        description="Adding entries to Registry Run keys or startup folders to execute malware on user login."
    ),

    # Privilege Escalation
    "T1068": MitreTechnique(
        id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic="Privilege Escalation",
        description="Abusing kernel bugs or unpatched local vulnerabilities to elevate from user to root/SYSTEM."
    ),
    "T1548": MitreTechnique(
        id="T1548",
        name="Abuse Elevation Control Mechanism",
        tactic="Privilege Escalation",
        description="Bypassing UAC or misconfigured sudo rules to run processes with elevated permissions."
    ),

    # Defense Evasion
    "T1070": MitreTechnique(
        id="T1070",
        name="Indicator Removal",
        tactic="Defense Evasion",
        description="Deleting event logs, clearing bash history, or scrubbing timestamps to conceal intrusion traces."
    ),
    "T1027": MitreTechnique(
        id="T1027",
        name="Obfuscated Files or Information",
        tactic="Defense Evasion",
        description="Encoding strings in base64, packing executables, or encrypting payloads to evade static detection."
    ),
    "T1562": MitreTechnique(
        id="T1562",
        name="Impair Defenses",
        tactic="Defense Evasion",
        description="Disabling security agents, stopping antivirus services, or tampering with firewall rules."
    ),
    "T1036": MitreTechnique(
        id="T1036",
        name="Masquerading",
        tactic="Defense Evasion",
        description="Naming malicious binaries after legitimate system tools (e.g. svchost.exe or update-daemon)."
    ),

    # Credential Access
    "T1110": MitreTechnique(
        id="T1110",
        name="Brute Force",
        tactic="Credential Access",
        description="Automated password guessing, credential stuffing, or password spraying across target accounts."
    ),
    "T1558": MitreTechnique(
        id="T1558",
        name="Steal or Forge Kerberos Tickets (Kerberoasting)",
        tactic="Credential Access",
        description="Requesting service tickets for SPN accounts and cracking the ticket offline to retrieve passwords."
    ),
    "T1003": MitreTechnique(
        id="T1003",
        name="OS Credential Dumping",
        tactic="Credential Access",
        description="Extracting plaintext credentials and hashes from LSASS memory, SAM hive, or /etc/shadow."
    ),
    "T1552": MitreTechnique(
        id="T1552",
        name="Unsecured Credentials",
        tactic="Credential Access",
        description="Searching file shares, configuration files, and scripts for hardcoded plaintext passwords."
    ),
    "T1555": MitreTechnique(
        id="T1555",
        name="Credentials from Password Stores",
        tactic="Credential Access",
        description="Extracting saved credentials from web browsers, credential vaults, or keychains."
    ),

    # Discovery
    "T1087": MitreTechnique(
        id="T1087",
        name="Account Discovery",
        tactic="Discovery",
        description="Listing domain users, local administrators, and group memberships to identify high-value targets."
    ),
    "T1082": MitreTechnique(
        id="T1082",
        name="System Information Discovery",
        tactic="Discovery",
        description="Querying OS version, architecture, patch level, and system environment configurations."
    ),
    "T1046": MitreTechnique(
        id="T1046",
        name="Network Service Discovery",
        tactic="Discovery",
        description="Scanning internal subnets to map accessible internal hosts, open ports, and live services."
    ),
    "T1083": MitreTechnique(
        id="T1083",
        name="File and Directory Discovery",
        tactic="Discovery",
        description="Searching directory trees for sensitive documents, database backups, and source repositories."
    ),

    # Lateral Movement
    "T1021": MitreTechnique(
        id="T1021",
        name="Remote Services",
        tactic="Lateral Movement",
        description="Connecting to other internal systems via SMB/RPC (PsExec), SSH, or RDP using compromised credentials."
    ),
    "T1570": MitreTechnique(
        id="T1570",
        name="Lateral Tool Transfer",
        tactic="Lateral Movement",
        description="Pivoting tools and offensive scripts between compromised hosts across internal network segments."
    ),

    # Collection
    "T1005": MitreTechnique(
        id="T1005",
        name="Data from Local System",
        tactic="Collection",
        description="Searching local disks and connected storage for sensitive files, databases, and trade secrets."
    ),
    "T1114": MitreTechnique(
        id="T1114",
        name="Email Collection",
        tactic="Collection",
        description="Querying Microsoft Exchange, IMAP, or local Outlook PST files to siphon internal communications."
    ),

    # Command and Control
    "T1071": MitreTechnique(
        id="T1071",
        name="Application Layer Protocol",
        tactic="Command and Control",
        description="Tunneling command-and-control communications inside DNS queries, HTTPS requests, or ICMP packets."
    ),
    "T1573": MitreTechnique(
        id="T1573",
        name="Encrypted Channel",
        tactic="Command and Control",
        description="Securing C2 communications with custom asymmetric or symmetric encryption to bypass IDS inspection."
    ),

    # Exfiltration
    "T1048": MitreTechnique(
        id="T1048",
        name="Exfiltration Over Alternative Protocol",
        tactic="Exfiltration",
        description="Exfiltrating stolen data over unusual channels such as DNS tunnels, ICMP payloads, or raw sockets."
    ),
    "T1567": MitreTechnique(
        id="T1567",
        name="Exfiltration Over Web Service",
        tactic="Exfiltration",
        description="Uploading stolen files and archives to external cloud storage providers or public paste sites."
    ),

    # Impact
    "T1486": MitreTechnique(
        id="T1486",
        name="Data Encrypted for Impact",
        tactic="Impact",
        description="Encrypting files, databases, and backup storage using ransomware to disrupt operations and extort victims."
    ),
    "T1489": MitreTechnique(
        id="T1489",
        name="Service Stop",
        tactic="Impact",
        description="Terminating critical system services, databases, and background daemons to inflict downtime."
    ),
    "T1490": MitreTechnique(
        id="T1490",
        name="Inhibit System Recovery",
        tactic="Impact",
        description="Deleting Volume Shadow Copies (vssadmin), disabling Windows recovery, and wiping backup catalogs."
    ),
}

def get_technique(technique_id: str) -> Optional[MitreTechnique]:
    """Retrieve technique metadata by MITRE ID."""
    return MITRE_CATALOG.get(technique_id)

def list_techniques() -> List[MitreTechnique]:
    """List all available MITRE techniques in the catalog."""
    return list(MITRE_CATALOG.values())

def get_technique_dict() -> Dict[str, dict]:
    """Return dictionary representation of all techniques."""
    return {k: v.model_dump() for k, v in MITRE_CATALOG.items()}
