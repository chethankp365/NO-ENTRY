"""
NO ENTRY Academy - Blue Team Rooms 17–20 Definitions.
Completes the 20-room Blue Team track:
- Room 17: Digital Forensics (blue-17-digital-forensics)
- Room 18: Windows and Linux Hardening (blue-18-windows-linux-hardening)
- Room 19: Threat Intelligence (blue-19-threat-intelligence)
- Room 20: Blue Team Capstone (blue-20-blue-team-capstone)
"""

from typing import List
from backend.app.academy.models import (
    QuizQuestion,
    RoomConcept,
    RoomDefinition,
    RoomStatus,
    TaskDefinition,
    TaskType,
    TrackEnum,
)

# ============================================================================
# ROOM 17: DIGITAL FORENSICS
# ============================================================================

ROOM_BLUE_17_TASKS: List[TaskDefinition] = [
    TaskDefinition(
        task_id="task-01-forensics-foundations-evidence",
        order=1,
        title="Digital Forensics & Order of Volatility",
        instructions=(
            "Review digital forensics methodology and RFC 3227 Order of Volatility guidelines. "
            "When responding to a potential workstation intrusion, digital investigators must adhere strictly to "
            "the order of volatility to ensure fleeting evidence is captured before being destroyed. "
            "According to RFC 3227, which component contains the most volatile digital evidence and must be acquired "
            "before shutting down or power-cycling a machine?"
        ),
        task_type=TaskType.QUESTION,
        question="Which component contains the most volatile digital evidence according to RFC 3227?",
        hint="Consider which hardware component loses all its stored data the instant electrical power is cut.",
        accepted_answers=["RAM", "ram", "Memory", "memory", "System RAM", "System Memory", "Volatile Memory"],
        xp_reward=50,
        mistake_explanations={
            "disk": "Disk storage is non-volatile; magnetic and flash media retain data after power-off.",
            "hard drive": "Hard drives preserve data persistently across reboots.",
            "logs": "System event logs on disk survive power cycles, unlike volatile memory.",
        },
    ),
    TaskDefinition(
        task_id="task-02-evidence-integrity-hashing",
        order=2,
        title="Evidence Hashing & Cryptographic Verification",
        instructions=(
            "Examine the forensic evidence artifacts in `/var/log/forensics/` inside your workstation. "
            "To uphold the legal and investigative chain of custody, all captured disk images and memory dumps must be "
            "hashed using cryptographic algorithms (such as SHA-256). "
            "Calculate the SHA-256 hash of `/var/log/forensics/evidence_artifact.bin` using `sha256sum /var/log/forensics/evidence_artifact.bin` "
            "or by executing `python3 /home/operator/tools/forensics_tool.py --hash`. "
            "What is the complete 64-character hexadecimal SHA-256 hash of the evidence file?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the SHA-256 hash of /var/log/forensics/evidence_artifact.bin?",
        hint="Execute 'sha256sum /var/log/forensics/evidence_artifact.bin' in your terminal.",
        accepted_answers=[
            "34049ea3151168bea705f416fabb3c8919ba7563ad650cff2af6e1b7745fc465",
            "8f4c2e6b19a0d3f78b54921b72a912e84c980312fa8901237a35b1d9821811fa",
        ],
        accepted_regex=r"^[a-fA-F0-9]{64}$",
        xp_reward=50,
        mistake_explanations={
            "md5": "MD5 produces a 32-character hash and is cryptographically collision-vulnerable; use SHA-256.",
            "sha1": "SHA-1 produces a 40-character hash; standard forensic procedure mandates SHA-256.",
        },
    ),
    TaskDefinition(
        task_id="task-03-filesystem-metadata-timestamps",
        order=3,
        title="Filesystem Metadata & MACB Timestamps",
        instructions=(
            "Investigate the filesystem metadata for the recovered suspicious staging directory using "
            "`python3 /home/operator/tools/forensics_tool.py --timeline` or by querying `/api/forensics/artifacts`. "
            "Forensic analysts reconstruct timeline events using MACB timestamps: Modified, Accessed, Changed (MFT/Inode metadata), and Born (Creation time). "
            "What is the Master File Table (MFT) record inode number associated with the unauthorized staging folder `C:\\Users\\Public\\Temp_Exfil`?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the MFT inode number for the unauthorized staging folder?",
        hint="Inspect the timeline output from forensics_tool.py or search for Temp_Exfil.",
        accepted_answers=["89104", "inode 89104", "89104 (Inode)", "89104"],
        xp_reward=60,
        mistake_explanations={
            "4820": "PID 4820 was a process ID in the threat hunting room, not the MFT record number.",
            "1044": "Record 1044 corresponds to the legitimate Windows svchost entry.",
        },
    ),
    TaskDefinition(
        task_id="task-04-timeline-reconstruction",
        order=4,
        title="Forensic Timeline Reconstruction & Verification",
        instructions=(
            "Reconstruct the forensic sequence of events and submit the verified timeline data to the lab target. "
            "Execute the following curl command in your terminal workstation: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"inode\":89104,\"event_type\":\"UNAUTHORIZED_STAGING_CREATION\",\"timestamp\":\"2026-11-15T09:12:00Z\"}' http://10.10.14.90:8217/api/forensics/timeline` "
            "Submit the returned verification token below."
        ),
        task_type=TaskType.FLAG,
        question="Submit the timeline reconstruction verification token.",
        hint="Execute the POST request against http://10.10.14.90:8217/api/forensics/timeline.",
        accepted_answers=["FORENSICS_TIMELINE_CONFIRMED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-digital-forensics-challenge",
        order=5,
        title="Digital Forensics Capstone Challenge",
        instructions=(
            "Conclude the digital forensics investigation by validating the root cause artifact and evidence chain of custody. "
            "Execute the challenge submission via POST to http://10.10.14.90:8217/challenge: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"case_id\":\"FOR-2026-091\",\"evidence_hash\":\"34049ea3151168bea705f416fabb3c8919ba7563ad650cff2af6e1b7745fc465\",\"attacker_action\":\"DATA_STAGING_AND_TAMPERING\"}' http://10.10.14.90:8217/challenge` "
            "Submit the resulting verification token."
        ),
        task_type=TaskType.FLAG,
        question="Submit the digital forensics investigation challenge verification token.",
        hint="Ensure task 04 timeline confirmation is completed before submitting the final challenge.",
        accepted_answers=["DIGITAL_FORENSICS_INVESTIGATION_COMPLETE", "FORENSICS_INVESTIGATION_VERIFIED"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-forensics-quiz",
        order=6,
        title="Digital Forensics Technical Assessment",
        instructions="Complete the 4-question technical assessment on digital forensics, file metadata, and evidence integrity.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is calculating cryptographic hashes immediately upon evidence acquisition essential?",
                options=[
                    "To prove that evidence has remained unaltered and guarantee chain of custody integrity",
                    "To compress the evidence file to reduce storage overhead",
                    "To encrypt the evidence so only law enforcement can read it",
                    "To automatically remove any malware contained in the evidence",
                ],
                correct_index=0,
                explanation="Cryptographic hashes (such as SHA-256) provide mathematical proof that digital evidence has not been tampered with or modified since the time of collection.",
            ),
            QuizQuestion(
                id="q2",
                question="In filesystem forensics, what do MACB timestamps represent?",
                options=[
                    "Modified, Accessed, Changed (metadata), Born (Created)",
                    "Memory, Authentication, Certificate, Binary",
                    "Main, Alternative, Compressed, Buffered",
                    "Monitor, Alert, Contain, Block",
                ],
                correct_index=0,
                explanation="MACB timestamps represent Modified (file content altered), Accessed (file read), Changed (MFT or inode metadata modified), and Born (original file creation).",
            ),
            QuizQuestion(
                id="q3",
                question="What is the primary danger of performing forensic analysis directly on an original drive rather than a forensic image?",
                options=[
                    "Mounting and analyzing the drive alters access timestamps and file metadata, contaminating the evidence",
                    "The original drive will overheat and physically melt",
                    "The filesystem will permanently format itself",
                    "The serial number of the drive will change",
                ],
                correct_index=0,
                explanation="Operating directly on original physical media writes access timestamps, swap data, and temporary files, destroying forensic integrity.",
            ),
            QuizQuestion(
                id="q4",
                question="Under RFC 3227, which evidence source is MORE volatile than hard disk data?",
                options=[
                    "Routing tables, ARP cache, and process memory",
                    "Backup tape archives",
                    "Optical CD-ROM discs",
                    "Printed audit logs",
                ],
                correct_index=0,
                explanation="Routing tables, ARP tables, kernel memory, and process memory are highly volatile and disappear immediately when power is lost or the network interface resets.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_BLUE_17_CONCEPT = RoomConcept(
    overview=(
        "Digital Forensics is the scientific identification, preservation, extraction, and analysis of computer evidence "
        "to reconstruct past security incidents. Analysts adhere to RFC 3227 Order of Volatility, ensuring fleeting evidence "
        "(RAM, active network connections, CPU cache) is imaged before non-volatile media (disks, logs, backup tapes). "
        "Filesystem metadata—including NTFS Master File Table (MFT) records and Linux Inodes—provides precise MACB timestamps "
        "to establish exact adversary movements and prove root cause."
    ),
    simple_analogy=(
        "Think of digital forensics like a crime scene investigation: investigators never walk into the room and start moving "
        "furniture. They photograph the scene, dust for fingerprints, seal evidence in tamper-evident bags with unique barcode "
        "hashes, and preserve every footprint so the evidence stands up in court."
    ),
    technical_term="Digital Forensics, Order of Volatility, Cryptographic Hashing & MACB Timestamps (RFC 3227 / ISO 27037)",
    technical_definition=(
        "Digital Forensics is the application of computer science principles to recover and preserve digital artifacts for investigative "
        "and legal purposes. RFC 3227 dictates capturing evidence from highest to lowest volatility: Registers/Cache -> Routing/Process Tables "
        "-> System RAM -> Temporary Filesystems -> Disk -> Archival Media. Cryptographic SHA-256 hashes guarantee uncompromised chain of custody."
    ),
    cybersecurity_context=(
        "When an attacker breaches an endpoint, they frequently attempt anti-forensic techniques: timestomping file creation dates, "
        "clearing event logs, and unlinking malicious staging payloads. Proper digital forensic analysis reconstructs deleted artifacts "
        "from unallocated clusters and MFT records to identify patient zero."
    ),
    why_it_matters=(
        "Without rigorous forensic procedures and chain-of-custody tracking, incident findings cannot be relied upon for regulatory reporting, "
        "law enforcement prosecution, or board-level breach disclosure."
    ),
    demonstration=(
        "Examiners acquire physical memory using write-blocked tools (e.g. WinPmem/LiME), compute SHA-256 hashes, generate timeline bodies "
        "using fls and mactime, and inspect MFT attributes ($STANDARD_INFORMATION and $FILE_NAME) to uncover timestomping anomalies."
    ),
    remediation_guide=(
        "Deploy enterprise EDR agents that continuously stream telemetry to a centralized SIEM, enforce write-once-read-many (WORM) audit "
        "storage, and equip incident responders with standardized hardware write-blockers and validated forensic imaging toolkits."
    ),
)

ROOM_BLUE_17_DEFINITION = RoomDefinition(
    room_id="blue-17-digital-forensics",
    track=TrackEnum.BLUE,
    room_number=17,
    title="Digital Forensics",
    short_description="Reconstruct workstation compromises, extract filesystem metadata and MACB timestamps, calculate SHA-256 hashes, and preserve chain of custody.",
    difficulty="Intermediate",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
    concept=ROOM_BLUE_17_CONCEPT,
    tasks=ROOM_BLUE_17_TASKS,
)


# ============================================================================
# ROOM 18: WINDOWS AND LINUX HARDENING
# ============================================================================

ROOM_BLUE_18_TASKS: List[TaskDefinition] = [
    TaskDefinition(
        task_id="task-01-hardening-principles-defense-in-depth",
        order=1,
        title="Hardening Principles & Attack Surface Reduction",
        instructions=(
            "Examine enterprise defensive hardening fundamentals. Hardening is the systematic reduction of a system's "
            "vulnerabilities by turning off unnecessary services, restricting user privileges, enforcing strong authentication, "
            "and applying defense-in-depth controls. "
            "What security principle dictates that users and processes should operate using only the minimal set of privileges "
            "necessary to perform their legitimate business function?"
        ),
        task_type=TaskType.QUESTION,
        question="What security principle dictates users operate with minimal necessary privileges?",
        hint="Consider the three-word phrase starting with 'Principle of Least...'",
        accepted_answers=[
            "Principle of Least Privilege",
            "Least Privilege",
            "POLP",
            "principle of least privilege",
            "least privilege",
        ],
        xp_reward=50,
        mistake_explanations={
            "defense in depth": "Defense in depth refers to layered defensive controls, not privilege minimalism.",
            "zero trust": "Zero trust is an architectural framework ('never trust, always verify'), while privilege limitation is Least Privilege.",
        },
    ),
    TaskDefinition(
        task_id="task-02-linux-audit-permissions-ssh",
        order=2,
        title="Linux Security Weakness & SSH Posture Audit",
        instructions=(
            "Audit the Linux server posture by executing `python3 /home/operator/tools/hardening_audit.py --linux` "
            "or querying `http://10.10.14.90:8218/api/hardening/posture`. "
            "Inspect the SSH daemon configuration weaknesses in `/etc/ssh/sshd_config`. "
            "Which dangerous SSH configuration parameter currently allows direct administrative root logins over the network?"
        ),
        task_type=TaskType.QUESTION,
        question="Which SSH configuration parameter allows direct root network logins?",
        hint="Look for the directive starting with 'PermitRoot...'.",
        accepted_answers=["PermitRootLogin", "permitrootlogin", "PermitRootLogin yes"],
        xp_reward=50,
        mistake_explanations={
            "passwordauthentication": "PasswordAuthentication controls password vs key logins, not root login authorization.",
            "allowusers": "AllowUsers defines a user whitelist, not the root login directive itself.",
        },
    ),
    TaskDefinition(
        task_id="task-03-windows-security-policy-audit",
        order=3,
        title="Windows Security Policy & Account Audit",
        instructions=(
            "Audit the Windows Domain Member security posture using `python3 /home/operator/tools/hardening_audit.py --windows`. "
            "Review the account lockout and audit logging parameters. "
            "What is the current value of the `AccountLockoutThreshold` setting, which allows attackers to conduct "
            "unrestricted brute-force attacks without locking the account?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the current AccountLockoutThreshold setting allowing unlimited attempts?",
        hint="A threshold of 0 disables account lockout entirely.",
        accepted_answers=["0", "0 attempts", "Disabled", "disabled"],
        xp_reward=60,
        mistake_explanations={
            "5": "5 attempts is the hardened CIS benchmark recommendation, not the current insecure setting.",
            "3": "3 attempts is a common strict policy, not the current audited value.",
        },
    ),
    TaskDefinition(
        task_id="task-04-apply-linux-hardening",
        order=4,
        title="Linux Defensive Control Enforcement",
        instructions=(
            "Apply the required defensive hardening controls to the Linux host via the lab target API. "
            "Execute the following curl command in your terminal workstation: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"disable_root_ssh\":true,\"enforce_key_auth\":true,\"remove_wildcard_sudo\":true}' http://10.10.14.90:8218/api/hardening/linux/apply` "
            "Submit the returned verification token below."
        ),
        task_type=TaskType.FLAG,
        question="Submit the Linux hardening enforcement verification token.",
        hint="Execute the POST request against http://10.10.14.90:8218/api/hardening/linux/apply.",
        accepted_answers=["LINUX_HARDENING_ENFORCED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-hardening-verification-challenge",
        order=5,
        title="Enterprise Hardening Baseline Challenge",
        instructions=(
            "Complete the hardening baseline by enforcing Windows security policies and validating compliance. "
            "First apply Windows hardening: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"lockout_threshold\":5,\"powershell_policy\":\"RemoteSigned\",\"disable_smbv1\":true}' http://10.10.14.90:8218/api/hardening/windows/apply` "
            "Then submit the final hardening challenge verification: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"target_scope\":\"DUAL_OS_ENTERPRISE\",\"linux_remediated\":true,\"windows_remediated\":true}' http://10.10.14.90:8218/challenge` "
            "Submit the resulting verification token."
        ),
        task_type=TaskType.FLAG,
        question="Submit the enterprise hardening baseline challenge verification token.",
        hint="Ensure both Linux and Windows hardening endpoints have been successfully invoked before submitting challenge.",
        accepted_answers=["SYSTEM_HARDENING_BASELINE_VERIFIED", "ENTERPRISE_HARDENING_COMPLETE"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-hardening-quiz",
        order=6,
        title="System Hardening Technical Assessment",
        instructions="Complete the 4-question technical assessment on operating system security baselines and defense controls.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is disabling SMBv1 a critical Windows hardening measure?",
                options=[
                    "SMBv1 lacks modern cryptographic protections and is vulnerable to remote code execution exploits like EternalBlue",
                    "SMBv1 consumes too much memory for modern processors",
                    "SMBv1 only works on Linux machines",
                    "SMBv1 disables Windows Update automatically",
                ],
                correct_index=0,
                explanation="SMBv1 is an insecure, unauthenticated protocol vulnerable to devastating exploits including EternalBlue (MS17-010) and WannaCry ransomware.",
            ),
            QuizQuestion(
                id="q2",
                question="In Linux sudoers policy, what risk does granting NOPASSWD: ALL to a standard user present?",
                options=[
                    "Any compromise of that user's shell allows an adversary to instantly obtain root privileges without authentication",
                    "It causes the system to run out of disk space",
                    "It prevents the user from logging in via SSH",
                    "It disables systemd journal logging",
                ],
                correct_index=0,
                explanation="NOPASSWD: ALL allows any process or attacker executing in the context of that user account to invoke `sudo su` or arbitrary root commands with zero credential challenge.",
            ),
            QuizQuestion(
                id="q3",
                question="What is the primary defensive benefit of setting PowerShell Execution Policy to RemoteSigned or AllSigned?",
                options=[
                    "It prevents users from accidentally executing untrusted downloaded scripts by requiring valid digital signatures",
                    "It completely blocks all PowerShell cmdlets from running",
                    "It encrypts all network traffic on port 443",
                    "It automatically deletes malicious macro files",
                ],
                correct_index=0,
                explanation="Execution policies prevent users from inadvertently launching downloaded, unsigned scripts from the internet, serving as an important baseline safety control.",
            ),
            QuizQuestion(
                id="q4",
                question="Which service should be disabled on internet-facing Linux hosts in favor of SSH key authentication?",
                options=[
                    "Password-based SSH authentication and direct root login",
                    "NTP time synchronization",
                    "Systemd journal daemon",
                    "Iptables packet filtering",
                ],
                correct_index=0,
                explanation="Disabling password authentication and prohibiting direct root login forces all administrators to authenticate via secure public keys as named non-root accounts.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_BLUE_18_CONCEPT = RoomConcept(
    overview=(
        "System hardening is the deliberate process of eliminating attack vectors and closing default security gaps. "
        "Default installations prioritize convenience over defense. In Linux, hardening focuses on least privilege (sudoers), "
        "securing remote access (disabling root SSH, enforcing Ed25519 keys), restricting file permissions (suid/guid audits), "
        "and configuring host-level packet filtering. In Windows environments, hardening enforces CIS Benchmarks: "
        "account lockout thresholds, AppLocker application control, auditing process creation (Event ID 4688 with command lines), "
        "disabling legacy protocols (SMBv1, LLMNR, NBT-NS), and securing PowerShell."
    ),
    simple_analogy=(
        "Building a default computer system is like buying a house with ten doors, single-pane glass windows, and the keys "
        "left under the mat. Hardening means locking nine unused doors, installing deadbolts, setting up motion sensors, and "
        "giving verified residents their own individual keycards."
    ),
    technical_term="System Hardening, Attack Surface Reduction & Security Baselines (CIS Benchmarks / DISA STIGs)",
    technical_definition=(
        "Hardening is the structured process of securing a system by reducing its vulnerability surface through removing unnecessary "
        "features, closing unneeded network ports, tuning kernel parameters, and enforcing restrictive security policies. Standardized "
        "benchmarks (CIS, DISA STIG) provide measurable compliance metrics across operating systems."
    ),
    cybersecurity_context=(
        "Most enterprise ransomware incidents and lateral movement penetrations succeed not through zero-day exploits, but through "
        "unhardened defaults: default administrative credentials, unrestricted SMBv1 broadcasts, missing account lockout limits, "
        "and excessive sudo permissions."
    ),
    why_it_matters=(
        "A hardened system dramatically raises the cost and complexity of an attack, turning trivial automated credential sprays "
        "and public exploits into detectable, high-noise failures."
    ),
    demonstration=(
        "Defenders audit systems using automated compliance scanners, disable PermitRootLogin and PasswordAuthentication in sshd_config, "
        "restrict sudoers to specific administrative commands, and apply Windows Group Policy Objects (GPOs) enforcing 5-attempt lockout."
    ),
    remediation_guide=(
        "Implement Infrastructure-as-Code (Ansible/Puppet) and centralized Group Policy / Intune baselines to continuously audit "
        "and enforce CIS Level 1 benchmarks across all production workloads."
    ),
)

ROOM_BLUE_18_DEFINITION = RoomDefinition(
    room_id="blue-18-windows-linux-hardening",
    track=TrackEnum.BLUE,
    room_number=18,
    title="Windows and Linux Hardening",
    short_description="Audit OS security postures, enforce least privilege, harden SSH configurations, remediate wildcard sudoers, and enforce Windows CIS security policies.",
    difficulty="Intermediate",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
    concept=ROOM_BLUE_18_CONCEPT,
    tasks=ROOM_BLUE_18_TASKS,
)


# ============================================================================
# ROOM 19: THREAT INTELLIGENCE
# ============================================================================

ROOM_BLUE_19_TASKS: List[TaskDefinition] = [
    TaskDefinition(
        task_id="task-01-cti-fundamentals-diamond-model",
        order=1,
        title="Cyber Threat Intelligence Fundamentals & Diamond Model",
        instructions=(
            "Review Cyber Threat Intelligence (CTI) core concepts and the Diamond Model of Intrusion Analysis. "
            "The Diamond Model establishes relationships between four core features of any intrusion: Adversary, "
            "Infrastructure, Capability, and Victim. "
            "Which of the four Diamond Model vertices represents the software tools, malware, or techniques utilized "
            "by the threat actor to compromise the target?"
        ),
        task_type=TaskType.QUESTION,
        question="Which Diamond Model vertex represents the threat actor's tools or malware?",
        hint="The four vertices are: Adversary, Infrastructure, Capability, and Victim.",
        accepted_answers=["Capability", "capability", "Capabilities"],
        xp_reward=50,
        mistake_explanations={
            "infrastructure": "Infrastructure represents the IP addresses, domains, and servers used by the adversary.",
            "adversary": "Adversary represents the threat group or operator behind the intrusion.",
            "victim": "Victim represents the targeted organization or asset.",
        },
    ),
    TaskDefinition(
        task_id="task-02-ioc-extraction-classification",
        order=2,
        title="IOC Extraction & Indicator Classification",
        instructions=(
            "Inspect the threat intelligence files in `/var/log/threat_intel/` or query `http://10.10.14.90:8219/api/intel/stix-feed`. "
            "Run `python3 /home/operator/tools/intel_tool.py --iocs` to extract indicators associated with the suspected campaign. "
            "What is the malicious command and control (C2) IP address identified as active infrastructure in the threat feed?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the malicious C2 IP address identified in the threat feed?",
        hint="Look for the external IPv4 address in the 198.51.100.0/24 documentation subnet.",
        accepted_answers=["198.51.100.77", "198.51.100.77:443", "198.51.100.77"],
        xp_reward=50,
        mistake_explanations={
            "10.10.14.90": "10.10.14.90 is the internal lab target gateway, not external adversary C2 infrastructure.",
            "198.51.100.99": "198.51.100.99 was the port scanner from Room 13, not the campaign C2 IP.",
        },
    ),
    TaskDefinition(
        task_id="task-03-stix-taxonomies-mitre-mapping",
        order=3,
        title="STIX Taxonomies & MITRE ATT&CK Correlation",
        instructions=(
            "Analyze the STIX 2.1 JSON bundle in `/var/log/threat_intel/stix_feed.json` using "
            "`python3 /home/operator/tools/intel_tool.py --attck`. "
            "The threat actor leverages spearphishing attachments containing weaponized macros. "
            "What is the formal MITRE ATT&CK technique ID for Spearphishing Attachment under the Initial Access tactic?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the MITRE ATT&CK technique ID for Spearphishing Attachment?",
        hint="The ID starts with T1566 and has a subtechnique decimal .001.",
        accepted_answers=["T1566.001", "t1566.001", "T1566.001 - Spearphishing Attachment"],
        xp_reward=60,
        mistake_explanations={
            "t1059.001": "T1059.001 is PowerShell Execution, not Spearphishing Attachment.",
            "t1566": "T1566 is the parent technique; the subtechnique for attachments is T1566.001.",
        },
    ),
    TaskDefinition(
        task_id="task-04-indicator-correlation-enrichment",
        order=4,
        title="Threat Indicator Correlation & Enrichment",
        instructions=(
            "Correlate the extracted indicators (IP, domain, hash, threat group) and submit the finding to the lab target. "
            "Execute the correlation request in your workstation: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"threat_actor\":\"APT-VOLT-VIPER\",\"c2_ip\":\"198.51.100.77\",\"c2_domain\":\"update-cdn.voltcorp-support.internal\",\"malware_family\":\"VoltDrop\"}' http://10.10.14.90:8219/api/intel/correlate` "
            "Submit the returned verification token below."
        ),
        task_type=TaskType.FLAG,
        question="Submit the indicator correlation verification token.",
        hint="Execute the POST request against http://10.10.14.90:8219/api/intel/correlate.",
        accepted_answers=["INTEL_CORRELATION_CONFIRMED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-threat-intel-challenge",
        order=5,
        title="Actionable Threat Intelligence Assessment Challenge",
        instructions=(
            "Deliver the actionable threat intelligence assessment by completing MITRE ATT&CK mapping and submitting the challenge dossier. "
            "First map the technique: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"threat_actor\":\"APT-VOLT-VIPER\",\"primary_technique\":\"T1566.001\",\"secondary_technique\":\"T1059.001\"}' http://10.10.14.90:8219/api/intel/attck-map` "
            "Then submit the final intelligence challenge verification: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"campaign_id\":\"CMP-2026-VOLT\",\"confidence_score\":\"HIGH\",\"defensive_recommendation\":\"BLOCK_IP_AND_HASH_ON_PERIMETER\"}' http://10.10.14.90:8219/challenge` "
            "Submit the resulting verification token."
        ),
        task_type=TaskType.FLAG,
        question="Submit the threat intelligence assessment challenge verification token.",
        hint="Ensure correlation and ATT&CK mapping endpoints have both been posted before submitting challenge.",
        accepted_answers=["THREAT_INTEL_ASSESSMENT_DELIVERED", "INTEL_CAMPAIGN_ASSESSMENT_COMPLETE"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-threat-intel-quiz",
        order=6,
        title="Cyber Threat Intelligence Technical Assessment",
        instructions="Complete the 4-question technical assessment on indicator lifecycle, STIX standards, and intelligence-driven defense.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="According to David Bianco's Pyramid of Pain, which indicator is the TOUGHEST for an adversary to change when defenders detect it?",
                options=[
                    "TTPs (Tactics, Techniques, and Procedures)",
                    "IP Addresses",
                    "Domain Names",
                    "Hash Values",
                ],
                correct_index=0,
                explanation="TTPs represent the adversary's behaviors, training, and methodologies. Changing TTPs forces the threat actor to re-train and re-engineer their entire operational model.",
            ),
            QuizQuestion(
                id="q2",
                question="Why are hash values located at the bottom (easiest to change) of the Pyramid of Pain?",
                options=[
                    "Changing a single trivial byte in a binary or script completely alters its cryptographic hash",
                    "Hashes cannot be calculated by defenders",
                    "Hashes expire after 24 hours",
                    "Antivirus engines ignore hashes",
                ],
                correct_index=0,
                explanation="Modifying a single comment, space, or byte in an executable produces an entirely different hash, making hash-only blacklisting trivial for adversaries to bypass.",
            ),
            QuizQuestion(
                id="q3",
                question="What is STIX (Structured Threat Information Expression)?",
                options=[
                    "A standardized JSON-based language for serializing and sharing structured cyber threat intelligence",
                    "A programming language for creating computer viruses",
                    "A proprietary firewall hardware protocol",
                    "A commercial antivirus database",
                ],
                correct_index=0,
                explanation="STIX is an open, standardized XML/JSON language and serialization format used across the cybersecurity industry to share threat indicators, actors, and campaigns.",
            ),
            QuizQuestion(
                id="q4",
                question="What is the primary danger of ingesting uncurated threat intelligence feeds directly into automated blocking rules without tuning?",
                options=[
                    "False positives that block legitimate business traffic, CDNs, or critical partner services",
                    "The firewall will run out of electricity",
                    "The threat feed will delete all database records",
                    "Threat actors will obtain admin access to the SIEM",
                ],
                correct_index=0,
                explanation="Low-confidence or uncurated feeds frequently contain dual-use domains, shared hosting IPs, and legitimate infrastructure, causing severe business disruption from false positives.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_BLUE_19_CONCEPT = RoomConcept(
    overview=(
        "Cyber Threat Intelligence (CTI) is evidence-based knowledge—including context, mechanisms, indicators, and actionable "
        "advice—about an existing or emerging hazard to assets. Analysts operate across three tiers: Strategic (executive risk), "
        "Operational (campaign trends and actor profiles), and Tactical (IOCs, IPs, hashes, signatures). "
        "Frameworks like the Diamond Model, Cyber Kill Chain, and MITRE ATT&CK allow defenders to map isolated technical indicators "
        "to structured adversary behavioral profiles (TTPs), moving defenses from fragile atomic indicators up the Pyramid of Pain."
    ),
    simple_analogy=(
        "Atomic IOCs like IP addresses are like a burglar's license plate—they can easily swap cars. Behavioral threat intelligence "
        "is recognizing the burglar's specific pattern: how they pick deadbolts, which second-story windows they target, and the "
        "unique spray paint they leave behind. You catch them by understanding their habits, not just their license plate."
    ),
    technical_term="Cyber Threat Intelligence, Diamond Model & MITRE ATT&CK Mapping (STIX 2.1 / TAXII)",
    technical_definition=(
        "Cyber Threat Intelligence is structured, context-rich information concerning threat actors, malicious infrastructure, "
        "capabilities, and targeting intents. Standards like STIX 2.1 serialize intelligence as interconnected graph nodes (Threat Actor, "
        "Malware, Indicator, Observed Data, Attack Pattern) shared via TAXII protocols."
    ),
    cybersecurity_context=(
        "Without intelligence correlation, SOC analysts treat every malware alert as an isolated novel incident. CTI connects local alerts "
        "to known adversary campaigns (e.g. APT-VOLT-VIPER), revealing the adversary's ultimate objectives (e.g. database exfiltration) "
        "and enabling preemptive threat hunting."
    ),
    why_it_matters=(
        "Intelligence-driven defense transforms security operations from reactive firefighting into proactive anticipation, hardening "
        "perimeter and endpoint defenses ahead of active intrusion waves."
    ),
    demonstration=(
        "Analysts ingest STIX 2.1 threat bundles, extract verified atomic indicators, correlate command-and-control IPs with DNS passive "
        "records, map execution techniques to MITRE ATT&CK T1566/T1059, and deploy automated IOC watchlists to perimeter firewalls."
    ),
    remediation_guide=(
        "Establish an automated Threat Intelligence Platform (TIP) that normalizes commercial and open-source feeds, enriches alerts with "
        "confidence scores, and programmatically feeds high-confidence indicators to EDR and SIEM detection rules."
    ),
)

ROOM_BLUE_19_DEFINITION = RoomDefinition(
    room_id="blue-19-threat-intelligence",
    track=TrackEnum.BLUE,
    room_number=19,
    title="Threat Intelligence",
    short_description="Extract and classify IOCs, correlate indicators across Diamond Model vertices, map behaviors to MITRE ATT&CK, and generate actionable CTI assessments.",
    difficulty="Intermediate",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
    concept=ROOM_BLUE_19_CONCEPT,
    tasks=ROOM_BLUE_19_TASKS,
)


# ============================================================================
# ROOM 20: BLUE TEAM CAPSTONE
# ============================================================================

ROOM_BLUE_20_TASKS: List[TaskDefinition] = [
    TaskDefinition(
        task_id="task-01-capstone-stage1-detection",
        order=1,
        title="Stage 1 & 2: Intrusion Detection & Timeline Reconstruction",
        instructions=(
            "Welcome to the Blue Team Capstone. You are the Incident Response Lead for VoltCorp Global. "
            "A high-severity security incident is underway across enterprise networks. "
            "Investigate initial telemetry using `python3 /home/operator/tools/capstone_investigator.py --detect` "
            "or querying `http://10.10.14.90:8220/api/capstone/stage-status`. "
            "Correlate NIDS alerts and firewall connection logs. "
            "Submit the initial detection verification by executing: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"stage\":\"DETECTION\",\"adversary_ip\":\"198.51.100.77\",\"compromised_asset\":\"DB-PROD-01\"}' http://10.10.14.90:8220/api/capstone/detect` "
            "Submit the returned verification token below."
        ),
        task_type=TaskType.FLAG,
        question="Submit the Stage 1 & 2 Detection verification token.",
        hint="Execute the POST request against http://10.10.14.90:8220/api/capstone/detect.",
        accepted_answers=["CAPSTONE_STAGE1_DETECT_OK"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-02-capstone-stage2-threat-hunting",
        order=2,
        title="Stage 3: Adversary Hunting & Process Tree Analysis",
        instructions=(
            "Execute Stage 3 Threat Hunting across endpoint process logs. "
            "Run `python3 /home/operator/tools/capstone_investigator.py --hunt` to inspect parent-child execution lineages. "
            "Identify the malicious spawned process and persistence mechanism. "
            "Execute the hunt verification via POST: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"stage\":\"THREAT_HUNTING\",\"malicious_pid\":3912,\"persistence_service\":\"svc_winupdater\",\"technique\":\"T1059.001\"}' http://10.10.14.90:8220/api/capstone/hunt` "
            "Submit the returned verification token below."
        ),
        task_type=TaskType.FLAG,
        question="Submit the Stage 3 Threat Hunting verification token.",
        hint="Execute the POST request against http://10.10.14.90:8220/api/capstone/hunt.",
        accepted_answers=["CAPSTONE_STAGE3_HUNT_OK"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-03-capstone-stage3-forensic-preservation",
        order=3,
        title="Stage 4: Forensic Evidence Acquisition & Integrity",
        instructions=(
            "Preserve volatile forensic evidence from the compromised host `DB-PROD-01`. "
            "Run `python3 /home/operator/tools/capstone_investigator.py --forensics` to inspect memory and disk artifacts. "
            "Submit the forensic integrity verification: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"stage\":\"FORENSICS\",\"sha256_verified\":true,\"ram_hash\":\"7a35b1d9821811faec2984b2382903487f54921b72a912e84c980312fa890123\"}' http://10.10.14.90:8220/api/capstone/forensics` "
            "Submit the returned verification token below."
        ),
        task_type=TaskType.FLAG,
        question="Submit the Stage 4 Forensic Evidence verification token.",
        hint="Execute the POST request against http://10.10.14.90:8220/api/capstone/forensics.",
        accepted_answers=["CAPSTONE_STAGE4_FORENSICS_OK"],
        xp_reward=60,
    ),
    TaskDefinition(
        task_id="task-04-capstone-stage4-intelligence-triage",
        order=4,
        title="Stage 5 & 6: Threat Intelligence & Incident Triage",
        instructions=(
            "Correlate campaign threat intelligence and perform triage severity scoring. "
            "Run `python3 /home/operator/tools/capstone_investigator.py --intel` and `--triage`. "
            "Execute the intelligence and triage validation via POST: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"stage\":\"TRIAGE\",\"incident_severity\":\"CRITICAL\",\"threat_actor\":\"APT-VOLT-VIPER\",\"exfil_volume_mb\":2400}' http://10.10.14.90:8220/api/capstone/triage` "
            "Submit the returned verification token below."
        ),
        task_type=TaskType.FLAG,
        question="Submit the Stage 5 & 6 Threat Intelligence & Triage verification token.",
        hint="Execute the POST request against http://10.10.14.90:8220/api/capstone/triage.",
        accepted_answers=["CAPSTONE_STAGE6_TRIAGE_OK"],
        xp_reward=60,
    ),
    TaskDefinition(
        task_id="task-05-capstone-stage5-containment-recovery",
        order=5,
        title="Stage 7 & 8: Active Containment, Eradication & Recovery",
        instructions=(
            "Execute immediate containment and threat eradication across the enterprise environment. "
            "Isolate compromised host `DB-PROD-01`, terminate backdoor PID `3912`, remove persistence service `svc_winupdater`, "
            "and revoke credential tokens. "
            "Execute the containment request: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"stage\":\"CONTAINMENT\",\"isolate_host\":\"DB-PROD-01\",\"terminate_pid\":3912,\"revoke_token\":\"ST-VOLT-9921\"}' http://10.10.14.90:8220/api/capstone/contain` "
            "Submit the returned verification token below."
        ),
        task_type=TaskType.FLAG,
        question="Submit the Stage 7 & 8 Containment & Recovery verification token.",
        hint="Execute the POST request against http://10.10.14.90:8220/api/capstone/contain.",
        accepted_answers=["CAPSTONE_STAGE7_CONTAIN_OK"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-capstone-final-report-assessment",
        order=6,
        title="Stage 9: Final Master Incident Report & Executive Assessment",
        instructions=(
            "Deliver the comprehensive incident report to conclude the Blue Team Capstone. "
            "Execute the final challenge submission: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"case_id\":\"CAPSTONE-IR-FINAL\",\"incident_summary\":\"CRITICAL_APT_INTRUSION_CONTAINED\",\"all_stages_complete\":true}' http://10.10.14.90:8220/challenge` "
            "Submit the resulting master completion token."
        ),
        task_type=TaskType.FLAG,
        question="Submit the Blue Team Capstone master completion token.",
        hint="Ensure all prior stages (Detect, Hunt, Forensics, Triage, Contain) have been executed before submitting.",
        accepted_answers=["BLUE_TEAM_CAPSTONE_TRIUMPH", "CAPSTONE_INCIDENT_RESOLVED"],
        xp_reward=50,
    ),
]

ROOM_BLUE_20_CONCEPT = RoomConcept(
    overview=(
        "The Blue Team Capstone integrates the full spectrum of defensive cybersecurity disciplines into a cohesive, "
        "high-stakes enterprise simulation. Responding to advanced persistent intrusions requires seamless collaboration "
        "across all phases: rapid perimeter detection, network packet extraction, telemetry correlation, hypothesis-driven "
        "threat hunting, forensically sound memory and disk preservation, intelligence mapping (MITRE ATT&CK), risk-prioritized "
        "triage, aggressive host containment, clean eradication, and executive post-incident documentation."
    ),
    simple_analogy=(
        "The Blue Team Capstone is the ultimate cybersecurity simulation: the emergency room of a major hospital during a crisis. "
        "The team cannot merely take vitals; they must diagnose the pathogen (Detection & Forensics), halt the spread (Containment), "
        "administer the cure (Eradication), verify vital stability (Recovery), and author the medical review (Final Report) "
        "so the hospital is stronger against future outbreaks."
    ),
    technical_term="Enterprise Incident Management, Multi-Stage Threat Containment & Root-Cause Remediation (NIST SP 800-61 / SANS PICERL)",
    technical_definition=(
        "Comprehensive Incident Response combines real-time network and host telemetry with forensic methodologies to mitigate active "
        "enterprise intrusions. Practitioners execute chronological stages: Detection, Initial Scoping, Threat Hunting, Evidence Acquisition, "
        "Intelligence Correlation, Triage Prioritization, Dynamic Network/Identity Containment, Eradication, and Post-Incident Reporting."
    ),
    cybersecurity_context=(
        "In modern enterprise intrusions, adversaries operate with multi-stage playbooks: gaining initial access via phishing or external exploit, "
        "dropping in-memory implants, executing LOLBins, establishing persistent services, and exfiltrating proprietary records. "
        "Defenders must execute integrated, multi-disciplinary responses to neutralize the entire campaign without leaving persistence blind spots."
    ),
    why_it_matters=(
        "Mastering the complete incident lifecycle ensures that security practitioners can coordinate across SOC, Forensics, Threat Intelligence, "
        "and Engineering teams during real-world crises, safeguarding enterprise operations and customer data."
    ),
    demonstration=(
        "The IR Lead correlates NIDS alerts, tracks malicious process trees to find the compromised PID, acquires forensic memory dumps, "
        "enriches C2 indicators via STIX intelligence, scopes data blast radiuses, enforces automated containment, and drafts executive retrospectives."
    ),
    remediation_guide=(
        "Establish unified security operations with integrated SOAR playbooks, enforce automated network isolation, mandate multi-factor "
        "authentication (FIDO2) across all administrative service accounts, and conduct regular cross-functional Purple Team fire drills."
    ),
)

ROOM_BLUE_20_DEFINITION = RoomDefinition(
    room_id="blue-20-blue-team-capstone",
    track=TrackEnum.BLUE,
    room_number=20,
    title="Blue Team Capstone",
    short_description="Lead a 9-stage enterprise incident investigation: detection, timeline reconstruction, hunting, forensics, threat intelligence, triage, containment, and final incident reporting.",
    difficulty="Advanced",
    estimated_duration="60 min",
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
    concept=ROOM_BLUE_20_CONCEPT,
    tasks=ROOM_BLUE_20_TASKS,
)
