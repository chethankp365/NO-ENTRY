"""
Complete curriculum definitions, tasks, concept explanations, and quizzes
for Blue Team Rooms 01–04:
- Room 01: Blue Team Foundations (blue-01-blue-team-foundations)
- Room 02: Windows Security Fundamentals (blue-02-windows-security-fundamentals)
- Room 03: Linux Security Monitoring (blue-03-linux-security-monitoring)
- Room 04: Network Traffic Analysis (blue-04-network-traffic-analysis)
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
# BLUE ROOM 01: BLUE TEAM FOUNDATIONS (FULLY IMPLEMENTED)
# ============================================================================

ROOM_BLUE_01_CONCEPT = RoomConcept(
    overview=(
        "Blue Team operations encompass the defensive capabilities, personnel, technologies, and operational procedures "
        "dedicated to defending an organization's digital assets. Operating primarily within a Security Operations Center (SOC), "
        "defensive engineers maintain the prevention, detection, response, and recovery lifecycle across enterprise infrastructure."
    ),
    simple_analogy=(
        "Imagine a major municipal hospital emergency trauma center and citywide dispatch network. Preventive controls are "
        "building fire sprinklers, sterilized surgical gowns, and biometric access doors. Diagnostic sensors and continuous vital "
        "monitors generate raw clinical telemetry (events). When an irregular heart rate sensor trips, an audible alarm rings "
        "(an alert). The triage nurse immediately evaluates the patient's record: is it a loose monitoring lead (false positive), "
        "or acute myocardial infarction requiring emergency surgical intervention (a confirmed true-positive incident)? If an "
        "incident is confirmed, the medical team initiates the emergency protocol (containment and response), stabilizes the "
        "patient, and later files a clinical post-incident analysis so preventive medical protocols can be improved across the entire hospital."
    ),
    technical_term="Security Operations Center (SOC) Operations & Incident Handling Lifecycle (NIST SP 800-61 / ISO 27035)",
    technical_definition=(
        "Blue Team operations execute the four-phase incident response lifecycle formalized in NIST SP 800-61: "
        "1) Preparation (deploying controls and telemetry sensors), 2) Detection and Analysis (triaging SIEM events, correlating IOCs, "
        "and validating alerts), 3) Containment, Eradication, and Recovery (isolating compromised systems, purging backdoors, and restoring "
        "verified clean states), and 4) Post-Incident Activity (root-cause analysis and detection rule tuning). Central to this is the "
        "Security Information and Event Management (SIEM) pipeline aggregating log events into actionable alert correlations."
    ),
    cybersecurity_context=(
        "While Red Teams focus on identifying and exploiting single paths of resistance, Blue Teams must defend the entire enterprise "
        "perimeter and internal network continuously. In a modern enterprise, Tier 1 SOC analysts triage thousands of daily telemetry "
        "events, Tier 2 incident responders perform deep-dive forensics and host containment, and Tier 3 threat hunters proactively "
        "seek unalerted adversary presence. Key telemetry sources include Endpoint Detection and Response (EDR), authentication gateways, "
        "firewall drop logs, and cloud audit trails."
    ),
    why_it_matters=(
        "Effective Blue Team operations minimize adversary dwell time—the duration an attacker operates inside an enterprise before "
        "being detected. Rapid triage and containment prevent initial credential compromises from escalating into enterprise-wide "
        "ransomware deployment or intellectual property theft."
    ),
    demonstration=(
        "1. SIEM Event Telemetry Stream:\n"
        "   GET /api/soc/events -> Ingest live stream of authentication, cron, and service events from enterprise workstations.\n\n"
        "2. SIEM Alert Correlation & Indicator Extraction:\n"
        "   GET /api/soc/alerts -> Review correlated high-severity alerts highlighting brute-force password spraying and memory access.\n\n"
        "3. Incident Triage Submission:\n"
        "   POST /api/soc/triage -> Submit structured triage ticket classifying confirmed true-positive attack from external IP 198.51.100.42.\n\n"
        "4. Evidence Timeline Reconstruction:\n"
        "   POST /challenge -> Reconstruct chronological sequence of attacker activity across enterprise boundaries.\n\n"
        "5. Perimeter Containment & Remediation:\n"
        "   POST /api/soc/remediate -> Execute automated firewall blacklisting and token invalidation to isolate the threat."
    ),
    remediation_guide=(
        "1. Ingest all security-relevant logs (authentication, process creation, network flow) into a centralized, immutable SIEM.\n"
        "2. Implement automated alert correlation rules based on the MITRE ATT&CK framework to suppress high-volume false positives.\n"
        "3. Define strict Standard Operating Procedures (SOPs) for Tier 1 triage, establishing SLA escalation windows to Tier 2.\n"
        "4. Enforce immediate containment playbooks: host network isolation, active session revocation, and perimeter IP blocking.\n"
        "5. Conduct blameless post-incident reviews (PIR) to turn incident telemetry into new preventive rules and automated detections."
    ),
)

ROOM_BLUE_01_TASKS = [
    TaskDefinition(
        task_id="task-01-soc-fundamentals-lifecycle",
        order=1,
        title="SOC Fundamentals & The Incident Response Lifecycle",
        instructions=(
            "Review the four phases of the NIST SP 800-61 Incident Response Lifecycle:\n"
            "1. Preparation\n"
            "2. Detection and Analysis\n"
            "3. Containment, Eradication, and Recovery\n"
            "4. Post-Incident Activity\n\n"
            "Which critical phase immediately follows 'Detection and Analysis' to stop ongoing damage and isolate threats?"
        ),
        task_type=TaskType.QUESTION,
        question="Which phase of the incident response lifecycle immediately follows Detection and Analysis?",
        hint="It begins with the action of isolating the affected host or blocking malicious traffic.",
        xp_reward=50,
        accepted_answers=["Containment", "containment", "Containment, Eradication, and Recovery", "Containment, Eradication and Recovery"],
        mistake_explanations={
            "preparation": "Preparation is Phase 1 (pre-incident hardening), not the phase following detection.",
            "post-incident": "Post-Incident Activity is Phase 4, conducted after the threat is contained and eradicated.",
            "just recovery": "Recovery is part of Phase 3, but the immediate initial operational step is Containment.",
        },
    ),
    TaskDefinition(
        task_id="task-02-siem-event-stream-investigation",
        order=2,
        title="SIEM Event Stream Investigation",
        instructions=(
            "As a Tier 1 SOC analyst, inspect the live security event stream ingested into the SIEM from enterprise hosts.\n\n"
            "Query the event stream on port 8201:\n"
            "  `curl -s http://10.10.14.90:8201/api/soc/events`\n\n"
            "Or run the analyst helper script:\n"
            "  `python3 /home/operator/tools/soc_query.py`\n\n"
            "Identify the external adversary source IP address conducting the high-severity authentication burst against the gateway."
        ),
        task_type=TaskType.QUESTION,
        question="What is the adversary's source IP address launching the failed authentication burst?",
        hint="Inspect the event with severity HIGH and event_type auth_failed_burst.",
        xp_reward=60,
        accepted_answers=["198.51.100.42"],
        mistake_explanations={
            "EVT-1003": "EVT-1003 is the event identifier. Provide the adversary's IP address.",
            "10.10.14.50": "10.10.14.50 is the internal workstation IP for jdoe.",
            "10.10.14.90": "10.10.14.90 is the internal domain controller IP.",
        },
    ),
    TaskDefinition(
        task_id="task-03-siem-alert-correlation",
        order=3,
        title="SIEM Alert Correlation & Indicator Extraction",
        instructions=(
            "SIEM correlation engines automatically evaluate raw event streams against detection rules and raise high-priority "
            "alerts when suspicious patterns emerge (e.g., repeated authentication failures across multiple accounts).\n\n"
            "Retrieve active SIEM alerts to extract correlated Indicators of Compromise (IOCs):\n"
            "  `curl -s http://10.10.14.90:8201/api/soc/alerts`\n\n"
            "Identify the MITRE ATT&CK technique code (e.g. T1110.003) associated with the password spraying alert ALRT-9102."
        ),
        task_type=TaskType.QUESTION,
        question="What is the MITRE ATT&CK technique code for the correlated password spraying alert?",
        hint="Inspect the alert ALRT-9102 mitre_technique field.",
        xp_reward=70,
        accepted_answers=["T1110.003", "T1110", "T1110.003 - Password Spraying"],
        mistake_explanations={
            "ALRT-9102": "ALRT-9102 is the alert identifier. Provide the MITRE ATT&CK technique code.",
            "T1003.001": "T1003.001 is the OS Credential Dumping technique, not the password spraying technique.",
        },
    ),
    TaskDefinition(
        task_id="task-04-incident-triage-classification",
        order=4,
        title="Incident Triage & Severity Classification",
        instructions=(
            "Once an alert is verified as a True Positive, a SOC analyst must triage the event, assign severity, document "
            "findings, and escalate the incident ticket to Tier 2 for active containment.\n\n"
            "Submit a formal triage verification request to the SOC gateway via POST:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"event_id\":\"EVT-1003\",\"classification\":\"TRUE_POSITIVE\",\"severity\":\"HIGH\"}' http://10.10.14.90:8201/api/soc/triage`\n\n"
            "Submit the verification token returned upon successful ticket escalation."
        ),
        task_type=TaskType.FLAG,
        xp_reward=70,
        accepted_answers=["TRIAGE_CONFIRMED_EVT1003_SECURE", "INC-2026-9901"],
        mistake_explanations={
            "TRUE_POSITIVE": "TRUE_POSITIVE is the classification string. Submit the verification_token returned in the JSON response.",
        },
    ),
    TaskDefinition(
        task_id="task-05-evidence-timeline-challenge",
        order=5,
        title="Independent Challenge: Evidence Timeline Reconstruction",
        instructions=(
            "Correlating disparate log sources allows analysts to reconstruct the chronological attack timeline, establishing "
            "how an adversary moved from initial authentication probing to credential access.\n\n"
            "Verify the reconstructed incident timeline by submitting the investigative findings via POST:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"stage\":\"evidence\",\"adversary_ip\":\"198.51.100.42\",\"compromised_host\":\"DC-VOLT01\"}' http://10.10.14.90:8201/challenge`\n\n"
            "Submit the verification token returned upon timeline verification."
        ),
        task_type=TaskType.FLAG,
        xp_reward=50,
        accepted_answers=["TIMELINE_RECONSTRUCTED_DC_VOLT01", "CONTAINMENT_ENFORCED_IP_BLOCKED"],
        mistake_explanations={
            "TIMELINE_VERIFIED": "TIMELINE_VERIFIED is the status string. Look for the verification_token field.",
        },
    ),
    TaskDefinition(
        task_id="task-06-soc-knowledge-assessment",
        order=6,
        title="Blue Team & SOC Operations Technical Assessment",
        instructions="Complete the 5-question technical quiz to demonstrate comprehensive mastery of SOC analyst operations, SIEM correlation, IOC triaging, and incident containment.",
        task_type=TaskType.QUIZ,
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is the primary operational distinction between an event, an alert, and an incident?",
                options=[
                    "An event is any observable occurrence; an alert is an event flagged by a rule as suspicious; an incident is a confirmed adverse event that threatens security.",
                    "An event is an email message; an alert is a phone call; an incident is a physical security alarm.",
                    "An alert only happens on Linux servers; events only happen in web browsers.",
                    "There is no distinction; all three terms mean identical things.",
                ],
                correct_option_index=0,
                explanation="In SOC terminology, events are all observable log items, alerts are flagged by detection logic, and incidents are verified security breaches requiring containment.",
            ),
            QuizQuestion(
                id="q2",
                question="What is an Indicator of Compromise (IOC)?",
                options=[
                    "A forensic artifact (such as a malicious file hash, IP address, or domain name) indicating an endpoint or network has been breached.",
                    "A certificate verifying that computer hardware is RoHS compliant.",
                    "A metric measuring how many gigabytes of RAM a server uses.",
                    "A software license key required to activate Windows Server.",
                ],
                correct_option_index=0,
                explanation="IOCs are pieces of forensic evidence (file hashes, URLs, IP addresses, registry keys) that identify potential intrusion activity on networks or endpoints.",
            ),
            QuizQuestion(
                id="q3",
                question="In a standard three-tier SOC model, what is the primary responsibility of a Tier 1 Analyst?",
                options=[
                    "Triaging incoming SIEM alerts, validating false positives versus true positives, and escalating verified incidents to Tier 2.",
                    "Rewriting the company's accounting software in C++.",
                    "Physically replacing damaged hard drives in the server rack.",
                    "Managing corporate public relations press releases.",
                ],
                correct_option_index=0,
                explanation="Tier 1 analysts perform front-line triage: monitoring SIEM queues, determining true vs false positives, and escalating confirmed incidents to Tier 2 responders.",
            ),
            QuizQuestion(
                id="q4",
                question="Why is Defense-in-Depth an essential architectural philosophy for Blue Teams?",
                options=[
                    "Layered defensive controls ensure that if a perimeter prevention control fails, secondary detection and containment controls prevent catastrophic compromise.",
                    "It eliminates the need for security log monitoring completely.",
                    "It requires every employee to carry three separate company laptops.",
                    "It guarantees that an organization will never experience a hardware failure.",
                ],
                correct_option_index=0,
                explanation="Defense-in-depth establishes multiple redundant layers of security controls so that the failure of any single component does not compromise the enterprise.",
            ),
            QuizQuestion(
                id="q5",
                question="What is the immediate primary goal during the Containment phase of incident response?",
                options=[
                    "Isolating the compromised systems and blocking malicious traffic to stop lateral movement and prevent further data loss.",
                    "Formatting all servers in the enterprise without creating forensic backups.",
                    "Publicly blaming third-party software vendors on social media.",
                    "Shutting down the entire electric power grid of the city.",
                ],
                correct_option_index=0,
                explanation="Containment focuses on isolating the affected endpoints, revoking session keys, and severing C2 channels to prevent an adversary from spreading laterally.",
            ),
        ],
    ),
]

ROOM_BLUE_01_DEFINITION = RoomDefinition(
    room_id="blue-01-blue-team-foundations",
    room_number=1,
    track=TrackEnum.BLUE,
    title="Blue Team Foundations",
    short_description="Explore Security Operations Center (SOC) workflows, SIEM telemetry triage, incident classification, IOC analysis, and containment response.",
    difficulty="Beginner",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_BLUE_01_CONCEPT,
    tasks=ROOM_BLUE_01_TASKS,
    learning_objectives=[
        "Understand the operational responsibilities of Red, Blue, and Purple teams",
        "Master the 4-phase NIST SP 800-61 Incident Response Lifecycle",
        "Investigate raw event streams and correlate high-priority SIEM alerts",
        "Perform Tier 1 incident triage and classify True Positives vs False Positives",
        "Reconstruct multi-stage attack timelines and execute containment remediation",
    ],
    assessment_criteria=[
        "Identify the correct incident response lifecycle phase following detection",
        "Extract security flags from active SIEM event streams and alert feeds",
        "Submit structured incident triage classification payloads",
        "Reconstruct chronological evidence timelines across enterprise hosts",
        "Execute automated firewall and session containment remediation",
        "Pass the 5-question Blue Team Foundations technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)


# ============================================================================
# BLUE ROOM 02: WINDOWS SECURITY FUNDAMENTALS (FULLY IMPLEMENTED)
# ============================================================================

ROOM_BLUE_02_CONCEPT = RoomConcept(
    overview=(
        "Windows Security Fundamentals focuses on the architecture, access control models, and auditing mechanisms governing "
        "Microsoft Windows enterprise systems. Defending Windows environments requires understanding Security Access Tokens, "
        "the Security Account Manager (SAM), Local Security Authority Subsystem Service (LSASS), and the Windows Security Event Log."
    ),
    simple_analogy=(
        "Imagine an ultra-secure international airport terminal. Entering requires identity verification at the passport control "
        "checkpoint (Windows Logon & LSASS). If your passport is legitimate, the officer stamps a boarding pass specifying your "
        "exact boarding group, seat tier, and lounge clearances (Security Access Token with SIDs for groups and privileges). If an "
        "unauthorized passenger attempts to force open a tarmac security door, computerized gate sensors log the precise turnstile ID, "
        "timestamp, and badge credentials into an immutable airport security ledger (Windows Security Event Log). Standardized event "
        "codes (such as Event ID 4624 for successful boarding, or 4625 for denied entry) allow security personnel across the airport "
        "to instantly recognize routine passenger movements versus unauthorized tarmac breaches."
    ),
    technical_term="Windows Security Subsystem & Security Event Log Auditing (MS-EVEN6 / Win32 Security Architecture)",
    technical_definition=(
        "The Windows security architecture centers on the Local Security Authority (LSA), which authenticates users and generates "
        "Access Tokens containing the user's Security Identifier (SID), group SIDs, and assigned privileges (e.g., SeDebugPrivilege). "
        "Security-relevant events are audited in the Security Event Log (`%SystemRoot%\\System32\\Winevt\\Logs\\Security.evtx`). "
        "Crucial Security Event IDs include: 4624 (Successful Logon with LogonTypes: 2-Interactive, 3-Network, 10-RemoteInteractive), "
        "4625 (Failed Logon with NTSTATUS failure codes), 4672 (Special Privileges assigned), and 4720 (A user account was created)."
    ),
    cybersecurity_context=(
        "Windows endpoints and Active Directory Domain Controllers are the primary targets of advanced persistent threats. Attackers "
        "target LSASS memory to harvest NTLM hashes, abuse privileges like `SeDebugPrivilege` to inject shellcode into legitimate processes, "
        "and establish stealth accounts. SOC analysts must master event ID interpretation to detect unauthorized lateral movement via "
        "RDP (LogonType 10), pass-the-hash network logons (LogonType 3), and off-hours account provisioning (Event 4720)."
    ),
    why_it_matters=(
        "Without rigorous Windows Event Log auditing, stealthy persistence mechanisms (such as dormant administrative accounts or "
        "unauthorized privilege delegation) can remain undetected for months, allowing adversaries to silently maintain access."
    ),
    demonstration=(
        "1. Architectural Realism & Simulation Documentation:\n"
        "   Full Windows Server environments require gigabytes of disk and dedicated hypervisors not packaging natively into "
        "   lightweight container runtimes. The Windows Security event records provided in this lab are synthetic event records "
        "   structured according to the Microsoft MS-EVEN6 schema in JSON format, NOT native binary EVTX files on a live Windows Server OS. "
        "   This authentic Windows Security Telemetry Lab provides realistic event records and inspection tools on port 8202 and in `/home/operator/windows_events/`.\n\n"
        "2. Authentication Auditing (Event 4624 & 4625):\n"
        "   GET /api/windows/events/logon -> Inspect LogonType 2 (Console) vs LogonType 10 (Remote Desktop RDP).\n\n"
        "3. Privileged Activity & Account Creation (Event 4672 & 4720):\n"
        "   GET /api/windows/events/privileged -> Detect rogue administrative account 'backdoor_admin' created outside change windows.\n\n"
        "4. Privilege Delegation & Token Abuse Audit:\n"
        "   POST /challenge -> Verify unauthorized assignment of SeDebugPrivilege.\n\n"
        "5. Defensive Windows Hardening & Remediation:\n"
        "   POST /api/windows/remediate -> Purge rogue accounts, enforce 5-attempt Account Lockout Policies, and revoke token privileges."
    ),
    remediation_guide=(
        "1. Enable comprehensive Advanced Audit Policy Configuration: audit Logon/Logoff, User Account Management, and Privilege Use.\n"
        "2. Configure strict Account Lockout Policies (e.g. lockout duration 30 minutes after 5 failed authentication attempts).\n"
        "3. Restrict administrative privileges: ensure `SeDebugPrivilege` and `SeTcbPrivilege` are never assigned to standard accounts.\n"
        "4. Deploy Windows Defender Credential Guard and enable LSA Protection (`RunAsPPL`) to prevent LSASS memory dumping.\n"
        "5. Forward all Security.evtx events to a centralized SIEM with automated alerting on Event 4720 and Event 4672."
    ),
)

ROOM_BLUE_02_TASKS = [
    TaskDefinition(
        task_id="task-01-windows-logon-types",
        order=1,
        title="Windows Security Architecture & Logon Types",
        instructions=(
            "Windows Security Event 4624 records every successful authentication event on a system. The `LogonType` field "
            "identifies how the user gained access: Type 2 is Interactive (local keyboard/screen), Type 3 is Network (file shares/SMB), "
            "and Type 7 is Workstation Unlock.\n\n"
            "What numerical LogonType value designates a Remote Interactive session established via Remote Desktop Protocol (RDP)?"
        ),
        task_type=TaskType.QUESTION,
        question="Which numerical LogonType in Windows Event 4624 represents Remote Desktop (RDP) connections?",
        hint="It is an integer value between 8 and 12.",
        xp_reward=50,
        accepted_answers=["10", "LogonType 10", "Type 10"],
        mistake_explanations={
            "2": "LogonType 2 is Interactive (direct physical console keyboard), not Remote Desktop.",
            "3": "LogonType 3 is Network logon (such as SMB file sharing or IIS web authentication).",
            "5": "LogonType 5 is Service logon initiated by the Windows Service Control Manager.",
        },
    ),
    TaskDefinition(
        task_id="task-02-windows-logon-audit",
        order=2,
        title="Authentication Auditing: Successful vs Failed Logons (4624 / 4625)",
        instructions=(
            "Inspect the Windows Security event stream to analyze successful and failed logon attempts on domain controller DC-VOLT01.\n\n"
            "Query the logon events endpoint on port 8202:\n"
            "  `curl -s http://10.10.14.90:8202/api/windows/events/logon`\n\n"
            "Or run the local event parser tool:\n"
            "  `python3 /home/operator/tools/parse_evtx.py`\n\n"
            "What is the source IP address (IpAddress) that initiated the Remote Desktop (LogonType 10) connection?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the source IP address that initiated the Remote Desktop (LogonType 10) connection?",
        hint="Look at the Event 4624 entry with LogonType 10.",
        xp_reward=60,
        accepted_answers=["10.10.14.2"],
        mistake_explanations={
            "EventID 4624": "4624 is the Windows Event ID. Provide the source IP address.",
            "127.0.0.1": "127.0.0.1 was the local console logon (LogonType 2). Look for LogonType 10.",
            "198.51.100.42": "198.51.100.42 was a failed logon attempt (Event 4625).",
        },
    ),
    TaskDefinition(
        task_id="task-03-windows-account-creation-audit",
        order=3,
        title="Privileged Activity & Account Provisioning Auditing (4672 / 4720)",
        instructions=(
            "Threat actors frequently establish persistence by creating unauthorized local administrator accounts (Event 4720) "
            "and assigning sensitive privileges such as SeDebugPrivilege (Event 4672).\n\n"
            "Inspect the privileged event stream on port 8202:\n"
            "  `curl -s http://10.10.14.90:8202/api/windows/events/privileged`\n\n"
            "What is the username of the unauthorized rogue account created in Event ID 4720?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the username of the rogue account created in Event ID 4720?",
        hint="Inspect the TargetUserName in the Event 4720 record.",
        xp_reward=70,
        accepted_answers=["backdoor_admin"],
        mistake_explanations={
            "Administrator": "Administrator is the default built-in admin account, not the rogue account created.",
            "compromised_svc": "compromised_svc is the actor account that created the rogue user.",
        },
    ),
    TaskDefinition(
        task_id="task-04-windows-privilege-audit-challenge",
        order=4,
        title="Independent Challenge: Privilege & Token Abuse Investigation",
        instructions=(
            "Audit the sensitive user privileges assigned to accounts across the domain controller to detect unauthorized token elevation.\n\n"
            "Submit the privilege audit investigation payload via POST:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"audit_target\":\"backdoor_admin\",\"abused_privilege\":\"SeDebugPrivilege\"}' http://10.10.14.90:8202/challenge`\n\n"
            "Submit the verification token returned upon confirming the unauthorized privilege assignment."
        ),
        task_type=TaskType.FLAG,
        xp_reward=70,
        accepted_answers=["SEDEBUG_PRIVILEGE_AUDITED_CONFIRMED", "SeDebugPrivilege"],
        mistake_explanations={
            "WINDOWS_AUDIT_VERIFIED": "WINDOWS_AUDIT_VERIFIED is the status. Submit the verification_token value.",
        },
    ),
    TaskDefinition(
        task_id="task-05-windows-remediation-hardening",
        order=5,
        title="Windows Security Hardening & Lockout Policy Enforcement",
        instructions=(
            "Harden the Windows environment by disabling rogue accounts, enforcing a 5-attempt Account Lockout Policy, "
            "and revoking unneeded privileges from non-administrative identities.\n\n"
            "Trigger the defensive Windows remediation routine via POST:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"lockout_threshold\":5,\"reset_duration_mins\":30}' http://10.10.14.90:8202/api/windows/remediate`\n\n"
            "Submit the verification token returned upon policy enforcement."
        ),
        task_type=TaskType.FLAG,
        xp_reward=50,
        accepted_answers=["LOCKOUT_POLICY_ENFORCED_5_ATTEMPTS", "WINDOWS_ENVIRONMENT_HARDENED"],
        mistake_explanations={
            "just status": "Submit the verification_token value rather than generic status.",
        },
    ),
    TaskDefinition(
        task_id="task-06-windows-quiz",
        order=6,
        title="Windows Security Fundamentals Technical Assessment",
        instructions="Complete the 5-question technical quiz to validate comprehensive knowledge of Windows security architecture, event auditing, and account hardening.",
        task_type=TaskType.QUIZ,
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is recorded by Windows Security Event ID 4625?",
                options=[
                    "An account failed to log on, documenting the targeted username and NTSTATUS failure reason.",
                    "A new scheduled task was registered in Task Scheduler.",
                    "A USB flash drive was inserted into the computer.",
                    "An outgoing DNS request was resolved by the resolver cache.",
                ],
                correct_option_index=0,
                explanation="Event ID 4625 documents every failed authentication attempt, including the target username, workstation, caller process, and NTSTATUS error code.",
            ),
            QuizQuestion(
                id="q2",
                question="What security risk is associated with granting a standard user or service account 'SeDebugPrivilege'?",
                options=[
                    "It allows the account to attach to and inspect the memory of any running process, enabling credential extraction from LSASS.",
                    "It automatically changes the user's desktop wallpaper.",
                    "It forces Windows Update to restart the computer without warning.",
                    "It disables physical monitor sleep mode.",
                ],
                correct_option_index=0,
                explanation="SeDebugPrivilege grants the ability to debug and read the virtual memory of any process on the system, including LSASS.exe, enabling tools like Mimikatz to dump plaintext credentials and NTLM hashes.",
            ),
            QuizQuestion(
                id="q3",
                question="What does an Account Lockout Policy achieve in enterprise Windows defense?",
                options=[
                    "It temporarily disables user accounts after a specified number of consecutive failed logon attempts, mitigating online password brute-force attacks.",
                    "It prevents users from locking their screens when walking away from desks.",
                    "It deletes the user's home folder after 30 days of inactivity.",
                    "It forces users to change their username every week.",
                ],
                correct_option_index=0,
                explanation="Account Lockout Policies prevent automated password spraying and brute-force attacks by locking the account for a set duration after threshold failures.",
            ),
            QuizQuestion(
                id="q4",
                question="In NTFS permissions, what is the key difference between a Discretionary Access Control List (DACL) and a System Access Control List (SACL)?",
                options=[
                    "A DACL defines who is permitted or denied access to a file; a SACL defines which access attempts should generate security audit log events.",
                    "A DACL only works on network shares; a SACL only works on local disks.",
                    "A DACL requires an active internet connection; a SACL works offline.",
                    "There is no difference; they are interchangeable terms.",
                ],
                correct_option_index=0,
                explanation="DACLs control access permissions (allow/deny read/write), whereas SACLs configure security auditing to generate event log entries when files are accessed.",
            ),
            QuizQuestion(
                id="q5",
                question="Which Windows Event ID signals that a new user account was created in the local SAM or Active Directory?",
                options=["4720", "4624", "4672", "7045"],
                correct_option_index=0,
                explanation="Event ID 4720 ('A user account was created') is generated whenever a new account is provisioned in the local SAM database or Active Directory domain.",
            ),
        ],
    ),
]

ROOM_BLUE_02_DEFINITION = RoomDefinition(
    room_id="blue-02-windows-security-fundamentals",
    room_number=2,
    track=TrackEnum.BLUE,
    title="Windows Security Fundamentals",
    short_description="Analyze Windows security architecture, investigate Security Event Logs (4624, 4625, 4672, 4720), and harden account lockout policies.",
    difficulty="Beginner",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_BLUE_02_CONCEPT,
    tasks=ROOM_BLUE_02_TASKS,
    learning_objectives=[
        "Understand the Windows Security Subsystem (LSA, SAM, LSASS, and Access Tokens)",
        "Audit logon events and interpret Windows LogonTypes (Console Type 2 vs RDP Type 10)",
        "Analyze Event IDs 4624 (Success), 4625 (Failure), 4672 (Privilege Assigned), and 4720 (Account Created)",
        "Detect unauthorized privilege delegation (`SeDebugPrivilege`) and rogue accounts",
        "Enforce Account Lockout thresholds and Windows security hardening configurations",
    ],
    assessment_criteria=[
        "Identify the correct LogonType integer for Remote Desktop connections",
        "Extract security flags from structured Windows logon and account creation events",
        "Conduct an independent audit challenge of sensitive Windows privileges",
        "Execute automated Windows hardening and lockout policy enforcement",
        "Pass the 5-question Windows Security Fundamentals technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)


# ============================================================================
# BLUE ROOM 03: LINUX SECURITY MONITORING (FULLY IMPLEMENTED)
# ============================================================================

ROOM_BLUE_03_CONCEPT = RoomConcept(
    overview=(
        "Linux Security Monitoring centers on continuous inspection and analysis of authentication records, system activity, "
        "and privilege delegation across Linux servers. SOC analysts must master log locations (`/var/log/auth.log` and `/var/log/secure`), "
        "SSH authentication telemetry, sudo privilege tracking, and defensive host hardening."
    ),
    simple_analogy=(
        "Imagine a residential apartment complex concierge keeping physical visitor logbooks. When someone dials the building intercom "
        "at the front door (an incoming SSH connection request), the concierge writes down the visitor's claimed name, timestamp, and door "
        "intercom number in `/var/log/auth.log`. If the visitor enters the wrong master PIN forty times in two minutes, every failed buzz is "
        "logged as `Failed password for invalid user from [intercom IP]`. If a maintenance technician uses their authorized physical master "
        "key to open an apartment door, that action is recorded in the ledger as `sudo: operator : TTY=pts/0 ; COMMAND=/bin/sh` (elevated "
        "privilege delegation). A security monitor reviews these entries to immediately spot rogue lockpicking attempts and unauthorized "
        "master key usage before an intruder can enter."
    ),
    technical_term="Linux Audit Subsystem, PAM Authentication Telemetry & Syslog Architecture (RFC 5424)",
    technical_definition=(
        "Linux logging is governed by the Pluggable Authentication Modules (PAM) architecture and syslog daemons (rsyslog / systemd-journald). "
        "Authentication events are recorded in `/var/log/auth.log` on Debian/Ubuntu systems and `/var/log/secure` on Red Hat/CentOS/Fedora systems. "
        "Audit records capture SSH daemon authentications (`sshd`), PAM session openings, `sudo` command executions with invoking user and TTY, "
        "and user account modifications. Host defense combines `auditd` kernel rules, `fail2ban` automated iptables jails, and hardened `/etc/ssh/sshd_config`."
    ),
    cybersecurity_context=(
        "Over 80% of internet-facing cloud servers and enterprise web backends run Linux. Consequently, automated adversary botnets "
        "continuously execute distributed SSH dictionary and password spraying attacks against port 22. Once attackers obtain an unprivileged "
        "foothold, they look for permissive `sudo` rules or unmonitored scripts. Defending Linux systems requires analysts who can rapidly parse "
        "log files using `grep`, `awk`, and `journalctl` to attribute malicious source IPs and enforce least-privilege configurations."
    ),
    why_it_matters=(
        "Unmonitored Linux servers can be transformed into persistent command-and-control proxies or cryptominers without outward signs "
        "of malfunction. Proactive log monitoring identifies brute force attacks and privilege escalation attempts before compromise occurs."
    ),
    demonstration=(
        "1. Log File Architecture & Distribution Comparison:\n"
        "   Inspect `/var/log/auth.log` (Debian/Ubuntu) and `/var/log/secure` (RHEL/CentOS) on the live lab filesystem.\n"
        "   Note: The Linux authentication logs in this lab are synthetic pre-seeded log files modeled on standard PAM/syslog telemetry, "
        "   accurately simulating real server log entries without claiming to be records from an aged production enterprise OS.\n\n"
        "2. SSH Brute Force Investigation via grep:\n"
        "   $ grep 'Failed password' /var/log/auth.log | grep '192.0.2.144'\n"
        "   Identify 48+ consecutive authentication failures targeting admin, root, and oracle accounts.\n\n"
        "3. Sudo Execution & Privilege Abuse Triage:\n"
        "   $ grep 'sudo:' /var/log/auth.log\n"
        "   Expose unauthorized root execution of python socket reverse shell.\n\n"
        "4. Threat Actor Attribution Challenge:\n"
        "   POST /challenge -> Verify threat actor source IP and attack pattern.\n\n"
        "5. Defensive Host Hardening:\n"
        "   POST /api/linux/remediate -> Deploy fail2ban jail, set PermitRootLogin no, enforce SSH key authentication, and harden sudoers."
    ),
    remediation_guide=(
        "1. Configure `/etc/ssh/sshd_config`: set `PermitRootLogin no` and `PasswordAuthentication no` (enforce SSH public keys).\n"
        "2. Deploy `fail2ban` or `sshguard` to automatically ban IP addresses exceeding 3 to 5 failed authentication attempts.\n"
        "3. Audit `/etc/sudoers` and `/etc/sudoers.d/*`: eliminate all `NOPASSWD: ALL` directives and enforce least-privilege command lists.\n"
        "4. Enable and configure the Linux Audit Daemon (`auditd`) to log execution of sensitive system binaries (`/usr/bin/passwd`, `/bin/chmod`).\n"
        "5. Forward all syslog and auth events to a centralized SIEM with alerts on repeated SSH failure bursts and sudo session openings."
    ),
)

ROOM_BLUE_03_TASKS = [
    TaskDefinition(
        task_id="task-01-linux-auth-log-paths",
        order=1,
        title="Linux Authentication Log Architecture",
        instructions=(
            "On Linux operating systems, user authentication events (including SSH logins, sudo executions, and password checks) "
            "are handled by PAM and written to standard log files.\n\n"
            "What is the standard absolute file path where authentication events are logged on Debian and Ubuntu systems?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the standard log file path for authentication events on Debian and Ubuntu systems?",
        hint="It is an absolute path starting with /var/log/ followed by auth...",
        xp_reward=50,
        accepted_answers=["/var/log/auth.log", "auth.log", "/var/log/auth"],
        mistake_explanations={
            "/var/log/secure": "/var/log/secure is used on Red Hat and CentOS systems, not Debian/Ubuntu.",
            "/var/log/syslog": "/var/log/syslog contains general system messages; authentication events specifically go to /var/log/auth.log.",
            "/var/log/messages": "/var/log/messages is a general log file used on RHEL-based systems.",
        },
    ),
    TaskDefinition(
        task_id="task-02-ssh-bruteforce-investigation",
        order=2,
        title="SSH Brute Force Attack Investigation",
        instructions=(
            "Inspect the authentication log on your workstation or query the monitoring service on port 8203 to detect "
            "an automated SSH credential brute-force attack:\n\n"
            "  `cat /var/log/auth.log | grep 'Failed password'`\n"
            "  `curl -s http://10.10.14.90:8203/api/linux/logs/auth`\n\n"
            "What is the external adversary's source IP address executing the automated SSH brute-force attack?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the external adversary's source IP address launching the SSH brute-force attack?",
        hint="Inspect the adversary_ip field or the IP in Failed password entries in /var/log/auth.log.",
        xp_reward=60,
        accepted_answers=["192.0.2.144"],
        mistake_explanations={
            "10.10.14.2": "10.10.14.2 is the legitimate internal operator workstation.",
            "127.0.0.1": "127.0.0.1 is the local loopback address.",
        },
    ),
    TaskDefinition(
        task_id="task-03-sudo-privilege-audit",
        order=3,
        title="Sudo Execution & Privilege Escalation Audit",
        instructions=(
            "The `sudo` utility records every command executed with elevated privileges, including the calling user, "
            "terminal, working directory, and target identity (e.g. USER=root).\n\n"
            "Inspect `/var/log/auth.log` or query the sudo audit endpoint:\n"
            "  `grep 'sudo:' /var/log/auth.log`\n"
            "  `curl -s http://10.10.14.90:8203/api/linux/logs/sudo`\n\n"
            "What binary or interpreter command was executed with elevated root privileges via sudo?"
        ),
        task_type=TaskType.QUESTION,
        question="What binary or interpreter was invoked with elevated root privileges?",
        hint="Inspect COMMAND in the sudo log line (e.g. /usr/bin/python3).",
        xp_reward=70,
        accepted_answers=["/usr/bin/python3", "python3", "/usr/bin/python3 -c import socket..."],
        mistake_explanations={
            "operator": "operator is the username that invoked sudo. Provide the binary command.",
            "root": "root is the target user context.",
        },
    ),
    TaskDefinition(
        task_id="task-04-threat-actor-attribution-challenge",
        order=4,
        title="Independent Challenge: Threat Actor IP Attribution",
        instructions=(
            "Verify your forensic attribution by submitting the adversary source IP payload via POST:\n\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"attacker_ip\":\"192.0.2.144\",\"service\":\"sshd\"}' http://10.10.14.90:8203/challenge`\n\n"
            "Submit the verification token returned upon confirming threat actor attribution."
        ),
        task_type=TaskType.FLAG,
        xp_reward=70,
        accepted_answers=["ATTRIBUTION_CONFIRMED_192_0_2_144", "192.0.2.144"],
        mistake_explanations={
            "just attribution": "Submit the full verification_token value rather than generic status.",
        },
    ),
    TaskDefinition(
        task_id="task-05-linux-hardening-remediation",
        order=5,
        title="Defensive Linux Hardening & Remediation",
        instructions=(
            "Deploy defensive host controls: configure `/etc/ssh/sshd_config` to disable direct root logins, enforce SSH key authentication, "
            "activate `fail2ban` automated IP jailing, and revoke permissive sudoer rules.\n\n"
            "Trigger the defensive Linux hardening routine via POST:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"harden_ssh\":true,\"enable_fail2ban\":true}' http://10.10.14.90:8203/api/linux/remediate`\n\n"
            "Submit the verification token returned upon system hardening."
        ),
        task_type=TaskType.FLAG,
        xp_reward=50,
        accepted_answers=["SSHD_HARDENED_FAIL2BAN_ENABLED", "LINUX_HOST_HARDENED"],
        mistake_explanations={
            "just hardened": "Submit the verification_token value rather than generic status.",
        },
    ),
    TaskDefinition(
        task_id="task-06-linux-monitoring-quiz",
        order=6,
        title="Linux Security Monitoring Technical Assessment",
        instructions="Complete the 5-question technical quiz to demonstrate comprehensive mastery of Linux authentication logging, sudo auditing, and host hardening.",
        task_type=TaskType.QUIZ,
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Which log file contains authentication records on Red Hat, CentOS, and Fedora Linux systems?",
                options=["/var/log/secure", "/var/log/auth.log", "/var/log/nginx/access.log", "/var/log/dpkg.log"],
                correct_option_index=0,
                explanation="Red Hat-family distributions write PAM and SSH authentication events to /var/log/secure, whereas Debian-family systems use /var/log/auth.log.",
            ),
            QuizQuestion(
                id="q2",
                question="Why is setting 'PermitRootLogin no' in /etc/ssh/sshd_config considered a security best practice?",
                options=[
                    "It prevents attackers from directly brute-forcing the well-known UID 0 root account, forcing them to authenticate as an unprivileged user first.",
                    "It deletes the root account from the operating system.",
                    "It makes SSH connections 50% faster.",
                    "It prevents root from running administrative commands locally.",
                ],
                correct_option_index=0,
                explanation="Disabling direct root login over SSH prevents automated botnets from targeting the universal root username and enforces accountability by requiring users to log in with named credentials first.",
            ),
            QuizQuestion(
                id="q3",
                question="How does fail2ban protect Linux SSH services from automated brute-force attacks?",
                options=[
                    "It monitors /var/log/auth.log for repeated authentication failures and dynamically adds temporary firewall rules (iptables/nftables) to drop packets from offending IPs.",
                    "It scrambles the SSH port number every 10 seconds.",
                    "It automatically emails the attacker asking them to stop.",
                    "It deletes invalid user accounts created during the attack.",
                ],
                correct_option_index=0,
                explanation="fail2ban scans log files for regular expression patterns indicating authentication failures and adds dynamic firewall rules to block the offending source IP address for a configurable ban duration.",
            ),
            QuizQuestion(
                id="q4",
                question="Which Linux command inspects the binary /var/log/wtmp database to display a history of recently logged-in users and system reboots?",
                options=["last", "whoami", "uname -a", "lsmod"],
                correct_option_index=0,
                explanation="The `last` command parses `/var/log/wtmp` to show user login sessions, terminal points, source IP addresses, and reboot history.",
            ),
            QuizQuestion(
                id="q5",
                question="In an /etc/sudoers file, why is granting 'operator ALL=(ALL) NOPASSWD: ALL' a critical security risk?",
                options=[
                    "It allows the operator user (or any attacker who compromises that account) to execute arbitrary commands as root without authentication, completely defeating privilege boundaries.",
                    "It causes the sudo binary to crash immediately.",
                    "It prevents the operator from running standard bash commands.",
                    "It encrypts the entire filesystem with an unknown key.",
                ],
                correct_option_index=0,
                explanation="A blanket NOPASSWD: ALL rule allows any compromised process running as that user to immediately elevate to full root privileges without password verification, negating all access control.",
            ),
        ],
    ),
]

ROOM_BLUE_03_DEFINITION = RoomDefinition(
    room_id="blue-03-linux-security-monitoring",
    room_number=3,
    track=TrackEnum.BLUE,
    title="Linux Security Monitoring",
    short_description="Inspect Linux authentication telemetry (/var/log/auth.log), detect automated SSH brute-force attacks, audit sudo abuse, and configure fail2ban hardening.",
    difficulty="Beginner",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_BLUE_03_CONCEPT,
    tasks=ROOM_BLUE_03_TASKS,
    learning_objectives=[
        "Differentiate Linux authentication log conventions (/var/log/auth.log vs /var/log/secure)",
        "Investigate SSH authentication failures and identify automated password spraying attacks",
        "Audit sudo execution logs to detect unauthorized root privilege escalations",
        "Attribute threat actor source IPs and construct forensic attack timelines",
        "Implement defensive Linux hardening: SSH key-only auth, PermitRootLogin no, and fail2ban jails",
    ],
    assessment_criteria=[
        "Identify the correct Debian/Ubuntu authentication log path",
        "Extract security flags from SSH failure telemetry and sudo audit logs",
        "Attribute the threat actor source IP address in the forensic challenge",
        "Execute automated Linux system hardening and fail2ban remediation",
        "Pass the 5-question Linux Security Monitoring technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)


# ============================================================================
# BLUE ROOM 04: NETWORK TRAFFIC ANALYSIS (FULLY IMPLEMENTED)
# ============================================================================

ROOM_BLUE_04_CONCEPT = RoomConcept(
    overview=(
        "Network Traffic Analysis is the practice of capturing, decoding, and evaluating communication packets traveling across "
        "digital networks to detect malicious activity, protocol anomalies, and unencrypted sensitive data exposure. Using tools "
        "like `tcpdump` and Wireshark, defensive analysts dissect Ethernet frames, IP packets, and transport flows."
    ),
    simple_analogy=(
        "Imagine an international cargo port customs and postal inspection facility. When packages travel through postal routes, "
        "each shipment has an outer transport container (Ethernet frame with hardware MAC addresses), an inner courier address label "
        "(IP packet with source and destination addresses), a delivery confirmation tracking receipt (TCP 3-way handshake and sequence "
        "tracking), and the actual physical cargo inside (Application Payload). If a shipper sends sensitive documents written on clear "
        "postcards without sealed envelopes (unencrypted HTTP or FTP), any courier along the transit route can read every word. A customs "
        "analyst (Network Traffic Analyst) uses automated x-ray inspection scanners (`tcpdump` and Wireshark) to verify that the cargo "
        "matches the shipping manifest and detect contraband or covert communication channels hidden within ordinary parcels."
    ),
    technical_term="Network Traffic Analysis (NTA), Protocol Decapsulation & PCAP Forensics (IEEE 802.3 / IETF RFC 791 / RFC 793)",
    technical_definition=(
        "Network Traffic Analysis inspects packet captures (`.pcap` / `.pcapng`) at every layer of the OSI model: Layer 2 Data Link "
        "(MAC headers), Layer 3 Network (IPv4/IPv6 addresses, TTL, fragmentation), Layer 4 Transport (TCP flags [SYN, ACK, FIN, RST], "
        "window size, UDP datagrams), and Layer 7 Application (DNS, HTTP, TLS handshake ClientHello/ServerHello). Analysts look for "
        "Network Indicators of Compromise (Network IOCs), cleartext credentials, port scan signatures, and covert tunneling."
    ),
    cybersecurity_context=(
        "Host-based logs can be deleted or tampered with by an adversary who achieves root access, but network packets cannot be retroactively "
        "erased from passive network taps or packet brokers. Traffic analysis allows SOC analysts to detect cleartext credential leaks, "
        "identify suspicious beaconing to external Command-and-Control (C2) servers, and uncover covert DNS tunneling channels used to "
        "exfiltrate proprietary database records."
    ),
    why_it_matters=(
        "Over 90% of malware communicates across network boundaries for command, control, or exfiltration. Network traffic analysis "
        "provides ground truth telemetry that remains trustworthy even if compromised endpoints have their audit logs deleted."
    ),
    demonstration=(
        "1. Packet Capture Inspection via tcpdump:\n"
        "   $ tcpdump -r /home/operator/pcaps/incident_capture.pcap\n"
        "   Inspect captured DNS, TCP, and HTTP traffic recorded inside the isolated lab network.\n"
        "   Note: The PCAP packet capture files in this lab are programmatically constructed packet captures conforming to the standard "
        "   libpcap specification, accurately reflecting real protocol dissections without claiming to be live captures from external network hardware.\n\n"
        "2. Protocol Hierarchy & Traffic Volume:\n"
        "   GET /api/traffic/summary -> Review protocol distribution (65% TCP, 20% HTTP, 30% UDP/DNS).\n\n"
        "3. Cleartext HTTP Credential Interception:\n"
        "   GET /api/traffic/streams/http -> Reconstruct TCP stream 3 showing cleartext credentials submitted to login endpoint.\n\n"
        "4. DNS Covert Exfiltration Detection:\n"
        "   GET /api/traffic/dns -> Identify high-entropy subdomain tunneling queries (`exfil-chunk-data.corp.noentry.internal`).\n\n"
        "5. Traffic Hardening & Remediation:\n"
        "   POST /api/traffic/remediate -> Enforce TLS 1.3 HTTPS redirection, sinkhole covert DNS domains, and deploy Zeek monitoring."
    ),
    remediation_guide=(
        "1. Enforce encryption in transit: disable unencrypted HTTP (port 80) and FTP (port 21); require HTTPS with TLS 1.3 and HSTS.\n"
        "2. Implement DNS Security: configure DNS sinkholing, deploy DNS over HTTPS (DoH) controls, and alert on high-entropy subdomains.\n"
        "3. Deploy Network Security Monitoring (NSM) sensors (such as Zeek or Suricata) to log connection flows and TLS metadata.\n"
        "4. Segment network subnets with internal firewalls to restrict direct traffic flows between workstations and production databases.\n"
        "5. Conduct routine PCAP audits to ensure sensitive customer data or credentials are never transmitted over cleartext channels."
    ),
)

ROOM_BLUE_04_TASKS = [
    TaskDefinition(
        task_id="task-01-network-protocol-hierarchy",
        order=1,
        title="Network Protocols & Transport Layer Mechanics",
        instructions=(
            "Network communications rely on transport layer protocols to move data between endpoints. One protocol establishes "
            "reliable, connection-oriented sessions using a 3-way handshake (SYN, SYN-ACK, ACK) and guarantees packet delivery order.\n\n"
            "Which transport layer protocol (acronym) provides connection-oriented, reliable transmission with packet sequencing?"
        ),
        task_type=TaskType.QUESTION,
        question="Which transport layer protocol provides connection-oriented, reliable packet transmission?",
        hint="It is a 3-letter acronym contrasted with UDP.",
        xp_reward=50,
        accepted_answers=["TCP", "Transmission Control Protocol"],
        mistake_explanations={
            "UDP": "UDP (User Datagram Protocol) is connectionless and does not guarantee packet delivery or order.",
            "IP": "IP (Internet Protocol) operates at Layer 3 (Network), not the transport layer.",
            "HTTP": "HTTP is an Application Layer (Layer 7) protocol running on top of TCP.",
        },
    ),
    TaskDefinition(
        task_id="task-02-pcap-protocol-summary",
        order=2,
        title="Protocol Hierarchy & Packet Capture Inspection",
        instructions=(
            "Examine the packet capture on your workstation (`/home/operator/pcaps/incident_capture.pcap`) using `tcpdump` "
            "or query the traffic summary endpoint on port 8204:\n\n"
            "  `tcpdump -r /home/operator/pcaps/incident_capture.pcap -c 10`\n"
            "  `curl -s http://10.10.14.90:8204/api/traffic/summary`\n\n"
            "How many total network packets are recorded in the incident packet capture (incident_capture.pcap)?"
        ),
        task_type=TaskType.QUESTION,
        question="How many total packets were recorded in the incident packet capture?",
        hint="Inspect the total_packets field in the summary API or count lines in tcpdump.",
        xp_reward=60,
        accepted_answers=["240"],
        mistake_explanations={
            "incident_capture.pcap": "incident_capture.pcap is the file name. Submit the total packet count.",
            "100": "100 is a partial count. Provide the total number of packets.",
        },
    ),
    TaskDefinition(
        task_id="task-03-cleartext-credential-sniffing",
        order=3,
        title="Cleartext Protocol Analysis & Credential Extraction",
        instructions=(
            "Unencrypted application protocols (such as standard HTTP port 80) expose all user credentials and session data to "
            "passive network sniffers along the packet route.\n\n"
            "Reconstruct the intercepted HTTP stream by inspecting packet strings or querying the stream endpoint:\n"
            "  `tcpdump -A -r /home/operator/pcaps/incident_capture.pcap | grep -i 'password'`\n"
            "  `curl -s http://10.10.14.90:8204/api/traffic/streams/http`\n\n"
            "What was the cleartext password intercepted in the unencrypted HTTP login request?"
        ),
        task_type=TaskType.QUESTION,
        question="What was the intercepted cleartext password transmitted over HTTP?",
        hint="Inspect the password parameter in the decoded POST request body.",
        xp_reward=70,
        accepted_answers=["VoltSecret9921!"],
        mistake_explanations={
            "admin": "admin was the username parameter, not the password.",
            "user=admin": "Submit only the password value.",
        },
    ),
    TaskDefinition(
        task_id="task-04-dns-covert-channel-detection",
        order=4,
        title="DNS Anomaly & Covert Exfiltration Investigation",
        instructions=(
            "Adversaries abuse the Domain Name System (DNS) to establish covert channels for data exfiltration by embedding "
            "encoded data into subdomain labels queried against an authoritative nameserver.\n\n"
            "Inspect the captured DNS traffic on port 8204 to detect the covert tunneling query:\n"
            "  `curl -s http://10.10.14.90:8204/api/traffic/dns`\n\n"
            "What is the fully-qualified domain name (FQDN) used for covert DNS tunneling exfiltration?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the fully-qualified domain name used for covert DNS tunneling?",
        hint="Look for the query marked ANOMALOUS_DNS_TUNNELING.",
        xp_reward=70,
        accepted_answers=["exfil-chunk-data.corp.noentry.internal", "exfil-chunk-data"],
        mistake_explanations={
            "target.noentry.internal": "target.noentry.internal is the legitimate target host, not the covert tunneling domain.",
        },
    ),
    TaskDefinition(
        task_id="task-05-pcap-stream-forensic-challenge",
        order=5,
        title="Independent Challenge: PCAP Stream Forensics",
        instructions=(
            "Conduct an in-depth forensic stream analysis to confirm the identification of the covert channel.\n\n"
            "Submit the stream forensic verification payload via POST:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"covert_channel\":\"dns\",\"tunnel_domain\":\"exfil-chunk-data.corp.noentry.internal\"}' http://10.10.14.90:8204/challenge`\n\n"
            "Submit the verification token returned upon stream forensic confirmation."
        ),
        task_type=TaskType.FLAG,
        xp_reward=50,
        accepted_answers=["COVERT_CHANNEL_EXFIL_IDENTIFIED", "TLS_ENFORCED_DNS_SINKHOLED"],
        mistake_explanations={
            "STREAM_FORENSIC_CONFIRMED": "STREAM_FORENSIC_CONFIRMED is the status string. Submit the verification_token value.",
        },
    ),
    TaskDefinition(
        task_id="task-06-network-analysis-quiz",
        order=6,
        title="Network Traffic Analysis Technical Assessment",
        instructions="Complete the 5-question technical quiz to demonstrate comprehensive mastery of network packet dissection, protocol analysis, and traffic hardening.",
        task_type=TaskType.QUIZ,
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is the 3-step TCP packet handshake sequence used to establish a connection?",
                options=[
                    "SYN -> SYN-ACK -> ACK",
                    "ACK -> SYN -> SYN-ACK",
                    "SYN -> ACK -> DATA",
                    "HELLO -> ESTABLISHED -> ACK",
                ],
                correct_option_index=0,
                explanation="TCP initiates connections with a SYN packet from client to server, responds with SYN-ACK from server to client, and completes with an ACK from client to server.",
            ),
            QuizQuestion(
                id="q2",
                question="Why is transmitting sensitive authentication credentials over unencrypted HTTP (port 80) dangerous?",
                options=[
                    "All request headers, form data, and cookies are transmitted in cleartext, allowing any network observer to read passwords with a packet sniffer.",
                    "HTTP automatically deletes user accounts from the database.",
                    "HTTP packets cause physical overheating in network switches.",
                    "Web browsers refuse to display pages loaded over HTTP.",
                ],
                correct_option_index=0,
                explanation="HTTP provides no cryptographic transport confidentiality, meaning packet sniffers like tcpdump or Wireshark can inspect full payloads in cleartext.",
            ),
            QuizQuestion(
                id="q3",
                question="How does DNS tunneling allow an adversary to exfiltrate data from a heavily restricted corporate network?",
                options=[
                    "Data is encoded into subdomain labels (e.g., data.attacker.com) and resolved through legitimate corporate DNS servers that are permitted outbound egress.",
                    "It physically rewires the Ethernet cabling in the server room.",
                    "It converts network packets into radio waves that bypass firewalls.",
                    "It shuts down the DNS server and sends raw files via Bluetooth.",
                ],
                correct_option_index=0,
                explanation="Because internal networks almost always allow queries to internal DNS forwarders, attackers encode stolen data into subdomain queries that reach their attacker-controlled nameserver.",
            ),
            QuizQuestion(
                id="q4",
                question="What command-line utility is standard on Linux systems for capturing and filtering network packets into PCAP files?",
                options=["tcpdump", "ping", "traceroute", "netstat"],
                correct_option_index=0,
                explanation="tcpdump is the standard command-line packet analyzer utilizing libpcap to capture, filter, and inspect raw network packets.",
            ),
            QuizQuestion(
                id="q5",
                question="What is the primary security benefit of enforcing TLS 1.3 encryption across enterprise web services?",
                options=[
                    "It encrypts all application payload data in transit, ensuring confidentiality and integrity against eavesdropping and tampering.",
                    "It eliminates the need for software security patches.",
                    "It guarantees that web applications have zero coding bugs.",
                    "It allows users to log in without needing passwords.",
                ],
                correct_option_index=0,
                explanation="TLS 1.3 provides robust end-to-end cryptographic confidentiality and integrity, preventing passive sniffing and active man-in-the-middle tampering.",
            ),
        ],
    ),
]

ROOM_BLUE_04_DEFINITION = RoomDefinition(
    room_id="blue-04-network-traffic-analysis",
    room_number=4,
    track=TrackEnum.BLUE,
    title="Network Traffic Analysis",
    short_description="Capture and decode network packets with tcpdump, analyze cleartext HTTP credential leaks, detect covert DNS tunneling, and enforce TLS 1.3.",
    difficulty="Beginner",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_BLUE_04_CONCEPT,
    tasks=ROOM_BLUE_04_TASKS,
    learning_objectives=[
        "Understand network protocol encapsulation across Data Link, Network, Transport, and Application layers",
        "Inspect packet captures (.pcap) and filter traffic using tcpdump",
        "Identify cleartext protocol vulnerabilities and extract intercepted credentials",
        "Detect network indicators of compromise (IOCs) and covert DNS tunneling channels",
        "Implement network traffic hardening: TLS 1.3 encryption and DNS sinkholing",
    ],
    assessment_criteria=[
        "Identify the correct transport protocol providing reliable connection-oriented delivery",
        "Extract security flags from packet capture protocol hierarchies and HTTP streams",
        "Detect covert DNS subdomain tunneling in packet captures",
        "Execute automated network traffic hardening and TLS 1.3 remediation",
        "Pass the 5-question Network Traffic Analysis technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)
