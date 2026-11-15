"""
NO ENTRY Academy - Purple Team Rooms 01–04 Definitions.
First four rooms of the Purple Team Track:
- Room 01: Purple Team Foundations (purple-01-purple-team-foundations)
- Room 02: MITRE ATT&CK Fundamentals (purple-02-mitre-attack-fundamentals)
- Room 03: Attack Simulation Planning (purple-03-attack-simulation-planning)
- Room 04: Reconnaissance vs Monitoring (purple-04-reconnaissance-vs-monitoring)
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
# ROOM 01: PURPLE TEAM FOUNDATIONS
# ============================================================================

ROOM_PURPLE_01_TASKS: List[TaskDefinition] = [
    TaskDefinition(
        task_id="task-01-purple-team-mission-collaboration",
        order=1,
        title="Purple Team Mission & Red/Blue Collaboration",
        instructions=(
            "Review the foundational principles of Purple Teaming. Unlike isolated Red Team penetration tests "
            "or isolated Blue Team defensive monitoring, a Purple Team exercise is a collaborative assessment "
            "where offensive and defensive practitioners work together in real-time. "
            "What is the primary operational objective of a Purple Team exercise?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the primary operational objective of a Purple Team exercise?",
        hint="Consider the collaborative improvement of detection capabilities through continuous attack validation.",
        accepted_answers=[
            "Validate and improve defensive detection capabilities",
            "Validate and improve detections",
            "Continuous validation and detection improvement",
            "Improve detection coverage",
            "Detection improvement",
            "Validate and improve defenses",
            "Continuous validation",
        ],
        xp_reward=50,
        mistake_explanations={
            "win": "Purple teaming is not about winning; it is about collaborative defensive uplift.",
            "breach": "Breaching systems without defensive feedback is traditional red teaming, not purple teaming.",
            "compliance": "Compliance audits verify checklists; purple teaming empirically validates live detection logic.",
        },
    ),
    TaskDefinition(
        task_id="task-02-exercise-scope-objective",
        order=2,
        title="Authorised Scope & Attack Objective Identification",
        instructions=(
            "Inspect the authorised exercise scope manifest in your workstation at `/home/operator/purple/scope_manifest.json` "
            "or query the lab target at `http://10.10.14.90:8301/api/purple/scope`. "
            "Run `python3 /home/operator/tools/purple_foundations_tool.py --scope` in your terminal. "
            "What is the authorized exercise identifier assigned to this VoltDefense assessment?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the authorized exercise identifier for this VoltDefense assessment?",
        hint="Look for the identifier starting with 'PT-2026-'.",
        accepted_answers=["PT-2026-001", "pt-2026-001", "PT-2026-001"],
        xp_reward=50,
        mistake_explanations={
            "IR-2026-088": "IR-2026-088 was an incident response ticket from the Blue Team track.",
            "FOR-2026-091": "FOR-2026-091 was the digital forensics case identifier.",
        },
    ),
    TaskDefinition(
        task_id="task-03-attck-technique-selection",
        order=3,
        title="Rules of Engagement & Technique Selection",
        instructions=(
            "Inspect the Rules of Engagement (RoE) section in `/home/operator/purple/scope_manifest.json`. "
            "The engagement focuses on evaluating host telemetry during adversary script execution. "
            "Which MITRE ATT&CK technique ID is authorized to test command and scripting interpreter execution?"
        ),
        task_type=TaskType.QUESTION,
        question="Which MITRE ATT&CK technique ID is authorized to test script execution?",
        hint="Look for the technique ID starting with T1059 for PowerShell execution.",
        accepted_answers=["T1059.001", "t1059.001", "T1059.001 - PowerShell"],
        xp_reward=60,
        mistake_explanations={
            "T1566.001": "T1566.001 is Spearphishing Attachment under Initial Access, not Script Execution.",
            "T1053.005": "T1053.005 is Scheduled Tasks under Persistence.",
        },
    ),
    TaskDefinition(
        task_id="task-04-telemetry-mapping",
        order=4,
        title="Attack Evidence to Defensive Telemetry Mapping",
        instructions=(
            "Connect the authorized offensive attack action with its corresponding defensive telemetry observation. "
            "Execute the telemetry mapping request from your workstation terminal: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"exercise_id\":\"PT-2026-001\",\"attack_technique\":\"T1059.001\",\"expected_telemetry\":\"SYSMON_EVENT_1_PROCESS_CREATION\",\"detection_objective\":\"ALERT_ON_POWERSHELL_SUSPICIOUS_EXECUTION\"}' http://10.10.14.90:8301/api/purple/telemetry-map` "
            "Submit the returned verification token below."
        ),
        task_type=TaskType.FLAG,
        question="Submit the telemetry mapping verification token.",
        hint="Execute the POST request against http://10.10.14.90:8301/api/purple/telemetry-map.",
        accepted_answers=["PURPLE_TELEMETRY_MAP_VERIFIED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-purple-foundations-challenge",
        order=5,
        title="Evidence-Backed Purple Team Exercise Plan Challenge",
        instructions=(
            "Finalize the exercise plan by verifying Rules of Engagement compliance, collaborative alignment, "
            "and detection gap mitigation criteria. "
            "Execute the challenge submission via POST to http://10.10.14.90:8301/challenge: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"exercise_id\":\"PT-2026-001\",\"roe_signed\":true,\"simulation_phase\":\"EXECUTION_AND_VALIDATION\",\"alignment\":\"RED_BLUE_COLLABORATION\"}' http://10.10.14.90:8301/challenge` "
            "Submit the resulting verification token."
        ),
        task_type=TaskType.FLAG,
        question="Submit the Purple Team Foundations exercise plan verification token.",
        hint="Ensure task 04 telemetry mapping is confirmed before submitting the challenge.",
        accepted_answers=["PURPLE_FOUNDATIONS_EXERCISE_APPROVED", "PURPLE_TEAM_FOUNDATIONS_COMPLETE"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-purple-foundations-quiz",
        order=6,
        title="Purple Team Foundations Technical Assessment",
        instructions="Complete the 4-question technical assessment on purple team methodology, detection feedback loops, and collaboration.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What distinguishes a Purple Team exercise from a traditional Red Team engagement?",
                options=[
                    "Red and Blue operators work collaboratively in real-time, sharing offensive execution details to test and tune defensive detections immediately",
                    "The Red Team attacks third-party external vendors without permission",
                    "The Blue Team turns off all antivirus agents before the test begins",
                    "The exercise is conducted exclusively by automated bots without human analysts",
                ],
                correct_index=0,
                explanation="In Purple Teaming, Red and Blue work together synchronously. Red explains what was executed, Blue verifies if logs and alerts fired, and detection engineers tune gaps immediately.",
            ),
            QuizQuestion(
                id="q2",
                question="Why is MITRE ATT&CK essential to Purple Team operations?",
                options=[
                    "It serves as a shared, objective taxonomy and common language that maps offensive actions directly to defensive data sources and detections",
                    "It is a proprietary commercial firewall hardware appliance",
                    "It automatically fixes broken Python scripts",
                    "It replaces the need for security monitoring and SIEM solutions",
                ],
                correct_index=0,
                explanation="ATT&CK provides a structured, common matrix enabling offensive testers and defensive analysts to communicate about specific adversary behaviors with zero ambiguity.",
            ),
            QuizQuestion(
                id="q3",
                question="What is a 'Detection Gap' in the context of security validation?",
                options=[
                    "An adversary technique that successfully executes on an endpoint but fails to generate telemetry, alerts, or correlation in the defensive stack",
                    "A physical hole in a server room wall",
                    "An expired SSL certificate on a public website",
                    "A computer monitor that has been powered down",
                ],
                correct_index=0,
                explanation="A detection gap exists when an authorized or adversary technique runs on an asset without triggering the expected security event logs, EDR telemetry, or SIEM alerts.",
            ),
            QuizQuestion(
                id="q4",
                question="What role do Rules of Engagement (RoE) play in Purple Team exercises?",
                options=[
                    "They define testing boundaries, authorized target systems, safety constraints, emergency stop contacts, and out-of-scope assets",
                    "They determine which team receives a physical trophy at the end of the day",
                    "They mandate that defenders delete all log archives after each test",
                    "They require attackers to use unencrypted plain-text passwords",
                ],
                correct_index=0,
                explanation="The RoE provides strict legal, ethical, and operational boundaries ensuring simulation activities remain safe, controlled, non-destructive, and focused on agreed targets.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_01_CONCEPT = RoomConcept(
    overview=(
        "Purple Teaming represents the convergence of offensive tradecraft and defensive engineering. "
        "Historically, Red Teams conducted opaque assessments producing lengthy post-engagement PDF reports that defenders "
        "struggled to operationalize, while Blue Teams defended perimeters without knowing exact adversary execution nuances. "
        "Purple Team exercises eliminate silos: offensive operators execute specific, controlled adversary behaviors (TTPs) "
        "while defenders observe live telemetry, evaluate EDR/SIEM fidelity, identify visibility blind spots, and engineer "
        "immediate detection improvements in a continuous feedback loop."
    ),
    simple_analogy=(
        "Think of a martial arts dojo: rather than a stranger kicking down the door in the middle of the night (surprise breach), "
        "two sparring partners practice together. The sparring attacker throws a specific punch in slow motion, the defender checks "
        "if their block covers the opening, and the coach adjusts the defender's stance until the defense is airtight."
    ),
    technical_term="Purple Teaming, Continuous Security Validation & Adversary Emulation Feedback Loops",
    technical_definition=(
        "Purple Teaming is a collaborative cybersecurity methodology where offensive (Red) and defensive (Blue) personnel "
        "synchronously simulate specific adversary Tactics, Techniques, and Procedures (TTPs) mapped to the MITRE ATT&CK "
        "framework to empirically measure, tune, and validate defensive monitoring, telemetry pipeline fidelity, and alerting."
    ),
    cybersecurity_context=(
        "Modern enterprise intrusions often bypass perimeter defenses because logging is unconfigured, EDR sensor coverage "
        "has blind spots, or SIEM correlation rules are mis-scoped. Purple Teaming shifts defensive operations from theoretical "
        "readiness to empirical proof by asking: 'If technique X executed right now, would an alert fire within 60 seconds?'"
    ),
    why_it_matters=(
        "Without empirical validation, organizations assume their expensive security toolkits detect attacks. Purple Teaming "
        "exposes that up to 50% of real-world attack techniques bypass default security configurations until tuned."
    ),
    demonstration=(
        "Red and Blue operators gather around a shared console: Red executes an encoded PowerShell command (T1059.001), "
        "Blue queries the Sysmon Event ID 1 index to inspect command-line logging, notes that script block logging was disabled, "
        "deploys a Group Policy update, and re-executes the test to confirm a high-severity alert now fires instantly."
    ),
    remediation_guide=(
        "Establish recurring monthly Purple Team sprints focused on specific threat actor profiles (e.g. FIN7, APT29), "
        "maintain an enterprise detection coverage matrix, and automate regression test suites using atomic testing tools."
    ),
)

ROOM_PURPLE_01_DEFINITION = RoomDefinition(
    room_id="purple-01-purple-team-foundations",
    track=TrackEnum.PURPLE,
    room_number=1,
    title="Purple Team Foundations",
    short_description="Master collaborative offensive and defensive cybersecurity alignment, continuous attack validation, detection feedback loops, and evidence-backed exercise planning.",
    difficulty="Beginner",
    estimated_duration="40 min",
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
    concept=ROOM_PURPLE_01_CONCEPT,
    tasks=ROOM_PURPLE_01_TASKS,
)


# ============================================================================
# ROOM 02: MITRE ATT&CK FUNDAMENTALS
# ============================================================================

ROOM_PURPLE_02_TASKS: List[TaskDefinition] = [
    TaskDefinition(
        task_id="task-01-attck-structure-tactics-techniques",
        order=1,
        title="MITRE ATT&CK Architecture: Tactics vs Techniques",
        instructions=(
            "Review the structural taxonomy of the MITRE ATT&CK Enterprise Matrix. "
            "ATT&CK organizes adversary behavior across three core levels: Tactics (the adversary's technical goal or 'Why'), "
            "Techniques (the method used to accomplish the goal or 'How'), and Sub-techniques (specific implementations). "
            "What structural component represents the adversary's overarching tactical objective (e.g. Initial Access, Persistence, Exfiltration)?"
        ),
        task_type=TaskType.QUESTION,
        question="What structural component represents the adversary's tactical objective ('Why')?",
        hint="Consider the primary columns across the top of the ATT&CK Navigator matrix.",
        accepted_answers=["Tactic", "tactics", "Tactics", "Tactic (Why)", "Tactic column"],
        xp_reward=50,
        mistake_explanations={
            "technique": "Techniques represent the 'How'—the technical method used to accomplish the tactic.",
            "subtechnique": "Sub-techniques describe specific technical variations (e.g., T1059.001 PowerShell).",
            "procedure": "Procedures describe the exact tooling and execution in a specific adversary campaign.",
        },
    ),
    TaskDefinition(
        task_id="task-02-auth-artifact-kerberoasting-mapping",
        order=2,
        title="Authentication Telemetry & Kerberoasting Mapping",
        instructions=(
            "Inspect the authentication logs in `/var/log/attck_evidence/auth_events.json` inside your workstation "
            "or run `python3 /home/operator/tools/attck_mapping_tool.py --auth`. "
            "The logs contain multiple Kerberos Service Ticket requests (Ticket Granting Service / TGS requests with RC4-HMAC encryption). "
            "This pattern indicates an adversary requesting service tickets with weak encryption to perform offline hash cracking. "
            "What is the formal MITRE ATT&CK sub-technique ID for Kerberoasting?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the formal MITRE ATT&CK sub-technique ID for Kerberoasting?",
        hint="The parent technique is Steal or Forge Kerberos Tickets (T1558). Look for sub-technique .003.",
        accepted_answers=["T1558.003", "t1558.003", "T1558.003 - Kerberoasting"],
        xp_reward=50,
        mistake_explanations={
            "t1558": "T1558 is the parent technique (Steal or Forge Kerberos Tickets); Kerberoasting is T1558.003.",
            "t1110": "T1110 is Brute Force, not Kerberoasting ticket harvesting.",
            "t1003": "T1003 is OS Credential Dumping (LSASS/SAM), while Kerberoasting queries domain TGS tickets.",
        },
    ),
    TaskDefinition(
        task_id="task-03-persistence-artifact-registry-mapping",
        order=3,
        title="Registry Persistence Telemetry & Sub-technique Identification",
        instructions=(
            "Examine `/var/log/attck_evidence/persistence_events.json` or run "
            "`python3 /home/operator/tools/attck_mapping_tool.py --persistence`. "
            "An endpoint artifact shows an unauthorized modification adding an executable entry into: "
            "`HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\VoltUpdater`. "
            "What is the MITRE ATT&CK sub-technique ID for Registry Run Keys / Startup Folder under the Persistence tactic?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the sub-technique ID for Registry Run Keys / Startup Folder?",
        hint="The parent technique is Boot or Logon Autostart Execution (T1547). Look for sub-technique .001.",
        accepted_answers=["T1547.001", "t1547.001", "T1547.001 - Registry Run Keys / Startup Folder"],
        xp_reward=60,
        mistake_explanations={
            "t1547": "T1547 is the parent technique; the Registry Run Keys sub-technique is T1547.001.",
            "t1053.005": "T1053.005 is Scheduled Tasks, not Registry Run Keys.",
        },
    ),
    TaskDefinition(
        task_id="task-04-attck-evidence-mapping",
        order=4,
        title="Evidence-Based ATT&CK Mapping Submission",
        instructions=(
            "Submit the validated Kerberoasting evidence mapping to the lab target API. "
            "Execute the following curl command in your workstation: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"evidence_id\":\"EV-AUTH-092\",\"tactic\":\"CREDENTIAL_ACCESS\",\"technique_id\":\"T1558.003\",\"data_source\":\"Active Directory Audit Event 4769\"}' http://10.10.14.90:8302/api/attck/map-evidence` "
            "Submit the returned verification token below."
        ),
        task_type=TaskType.FLAG,
        question="Submit the ATT&CK evidence mapping verification token.",
        hint="Execute the POST request against http://10.10.14.90:8302/api/attck/map-evidence.",
        accepted_answers=["ATTCK_EVIDENCE_MAPPING_VERIFIED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-attck-mapping-challenge",
        order=5,
        title="End-to-End ATT&CK Lifecycle Mapping Challenge",
        instructions=(
            "Conclude the investigation by correlating the complete 5-stage attack lifecycle across tactics: "
            "Initial Access (T1566.001), Execution (T1059.001), Persistence (T1547.001), Credential Access (T1558.003), "
            "and Command and Control (T1071.001), and submitting recommended enterprise mitigations. "
            "Execute the challenge submission via POST to http://10.10.14.90:8302/challenge: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"case_id\":\"ATTCK-MAP-CASE-01\",\"mapped_tactics\":[\"INITIAL_ACCESS\",\"EXECUTION\",\"PERSISTENCE\",\"CREDENTIAL_ACCESS\",\"COMMAND_AND_CONTROL\"],\"primary_mitigation\":\"M1027_PASSWORD_POLICIES_AND_KERBEROS_AES\"}' http://10.10.14.90:8302/challenge` "
            "Submit the resulting verification token."
        ),
        task_type=TaskType.FLAG,
        question="Submit the ATT&CK lifecycle mapping challenge verification token.",
        hint="Ensure task 04 evidence mapping is confirmed before submitting the final lifecycle challenge.",
        accepted_answers=["ATTCK_LIFECYCLE_MAPPING_COMPLETE", "ATTCK_MAPPING_VERIFIED"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-attck-quiz",
        order=6,
        title="MITRE ATT&CK Technical Assessment",
        instructions="Complete the 4-question technical assessment on ATT&CK taxonomy, data sources, and defensive alignment.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="In the MITRE ATT&CK sub-technique notation (e.g. T1059.001), what does the '.001' represent?",
                options=[
                    "A specific sub-technique implementation (e.g. PowerShell) under the broader parent technique (Command and Scripting Interpreter)",
                    "The CVSS severity score of the vulnerability",
                    "The number of times the attack was detected in the wild",
                    "The software release version of the ATT&CK framework",
                ],
                correct_index=0,
                explanation="Sub-techniques (introduced in ATT&CK v7) use a three-digit decimal suffix to represent specific technical variations of a parent technique.",
            ),
            QuizQuestion(
                id="q2",
                question="Which data source is primary for detecting Process Injection (T1055)?",
                options=[
                    "OS API execution telemetry, memory write events (e.g. VirtualAllocEx/WriteProcessMemory), and process access events",
                    "DNS zone transfer audit records",
                    "Printer spooler job history logs",
                    "Physical building access badge entry scans",
                ],
                correct_index=0,
                explanation="Process Injection is identified via kernel and EDR telemetry tracking cross-process memory manipulation APIs like OpenProcess, VirtualAllocEx, and CreateRemoteThread.",
            ),
            QuizQuestion(
                id="q3",
                question="Why is mapping observed behaviors to ATT&CK more resilient than tracking atomic IOCs like IP addresses or file hashes?",
                options=[
                    "Techniques represent adversary behaviors (TTPs at the top of the Pyramid of Pain) which are costly and difficult for an attacker to change, unlike trivial hashes or IPs",
                    "ATT&CK technique IDs never change under any circumstances",
                    "ATT&CK completely prevents computers from being infected by viruses",
                    "IP addresses cannot be extracted from firewall logs",
                ],
                correct_index=0,
                explanation="According to the Pyramid of Pain, adversary TTPs require significant retraining and software re-engineering to alter. Detecting behaviors provides durable defensive advantage.",
            ),
            QuizQuestion(
                id="q4",
                question="What is ATT&CK Navigator commonly used for in security operations?",
                options=[
                    "Visualizing defensive detection coverage, threat actor profiling heatmaps, and identifying matrix gaps",
                    "Directly launching automated DDoS attacks against competitors",
                    "Installing operating system security patches",
                    "Managing firewall hardware power cords",
                ],
                correct_index=0,
                explanation="ATT&CK Navigator is an open-source web visualization tool used to create color-coded heatmaps showing which techniques are covered, partially covered, or blind spots.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_02_CONCEPT = RoomConcept(
    overview=(
        "The MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) framework is the global standard knowledge base "
        "of real-world adversary behaviors. Rather than categorizing threats by malware family or fleeting atomic indicators, ATT&CK "
        "classifies threats by tactical objectives (Why) and operational techniques (How). In Purple Teaming, ATT&CK functions as the "
        "universal coordinate system: every offensive simulation is indexed to a technique ID, allowing defenders to measure exact "
        "telemetry capture rates and build high-fidelity detection rules."
    ),
    simple_analogy=(
        "Think of the Periodic Table in chemistry: instead of describing chemicals by vague brand names ('Drano' or 'bleach'), "
        "chemists reference atomic elements like Chlorine and Sodium. ATT&CK is the Periodic Table of Cyber Tradecraft: instead of saying "
        "'the hacker did something bad to credentials', professionals state precisely that the adversary executed T1558.003 (Kerberoasting)."
    ),
    technical_term="MITRE ATT&CK Enterprise Matrix, Behavioral Taxonomies & Data Source Mapping",
    technical_definition=(
        "MITRE ATT&CK is a curated behavioral model reflecting the phases of an adversary's attack lifecycle. Organized into 14 Enterprise "
        "Tactics containing hundreds of techniques and sub-techniques, each entry identifies technical execution details, associated data sources "
        "(e.g. Process: Process Creation, Logon Session: Logon Session Creation), and verified mitigation controls."
    ),
    cybersecurity_context=(
        "When an incident occurs, raw logs contain thousands of disconnected events. By mapping event sequences to ATT&CK (Event ID 4688 -> T1059.001; "
        "Event ID 4769 -> T1558.003; Registry Run Key -> T1547.001), incident responders and detection engineers transform raw noise into "
        "actionable adversary narrative graphs."
    ),
    why_it_matters=(
        "Mapping defenses to ATT&CK reveals critical visibility gaps. An organization might discover it has 20 detection rules for Command & Control "
        "but zero detection rules for Discovery or Lateral Movement, allowing attackers to navigate undetected."
    ),
    demonstration=(
        "Analysts inspect a Windows Event 4769 ticket audit log, identify Service Name 'MSSQLSvc/db01' requested with ticket encryption 0x17 (RC4), "
        "map it to T1558.003 (Credential Access), and author a Sigma detection rule monitoring high-volume RC4 service ticket requests."
    ),
    remediation_guide=(
        "Enforce Group Policy mandating AES-128/256 Kerberos encryption, configure service accounts with minimum 25-character randomized "
        "passwords, migrate critical services to Group Managed Service Accounts (gMSAs), and continuously monitor Event ID 4769."
    ),
)

ROOM_PURPLE_02_DEFINITION = RoomDefinition(
    room_id="purple-02-mitre-attack-fundamentals",
    track=TrackEnum.PURPLE,
    room_number=2,
    title="MITRE ATT&CK Fundamentals",
    short_description="Analyze authentication events, process trees, and persistence mechanisms; map observed adversary behaviors to MITRE ATT&CK tactics, techniques, and data sources.",
    difficulty="Beginner",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
    concept=ROOM_PURPLE_02_CONCEPT,
    tasks=ROOM_PURPLE_02_TASKS,
)


# ============================================================================
# ROOM 03: ATTACK SIMULATION PLANNING
# ============================================================================

ROOM_PURPLE_03_TASKS: List[TaskDefinition] = [
    TaskDefinition(
        task_id="task-01-simulation-governance-roe",
        order=1,
        title="Simulation Governance & Rules of Engagement",
        instructions=(
            "Review attack simulation planning principles. Controlled adversary simulations require rigorous governance "
            "to ensure safety, avoid unintended operational downtime, and ensure testing produces measurable defensive value. "
            "What binding legal and operational document establishes the simulation boundaries, testing windows, emergency contacts, "
            "and out-of-bounds enterprise assets?"
        ),
        task_type=TaskType.QUESTION,
        question="What document establishes boundaries and safety constraints for a simulation?",
        hint="Consider the three-word standard starting with 'Rules of...'",
        accepted_answers=[
            "Rules of Engagement",
            "Rules of Engagement (RoE)",
            "ROE",
            "roe",
            "rules of engagement",
            "Rules of engagement",
        ],
        xp_reward=50,
        mistake_explanations={
            "sla": "An SLA (Service Level Agreement) governs service delivery uptime, not attack simulation safety.",
            "nda": "An NDA (Non-Disclosure Agreement) protects confidential information, not technical execution scope.",
        },
    ),
    TaskDefinition(
        task_id="task-02-target-identification-scope",
        order=2,
        title="Target Environment & IP Scope Identification",
        instructions=(
            "Inspect `/home/operator/simulation/exercise_spec.json` inside your workstation "
            "or query the simulation gateway at `http://10.10.14.90:8303/api/simulation/scope`. "
            "Execute `python3 /home/operator/tools/simulation_planner.py --scope` in your terminal. "
            "What is the authorized IP address of the dedicated target server designated for controlled testing?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the authorized target IP address for controlled testing?",
        hint="Look for the internal lab target gateway IP in the 10.10.14.0/24 subnet.",
        accepted_answers=["10.10.14.90", "10.10.14.90:8303"],
        xp_reward=50,
        mistake_explanations={
            "198.51.100.77": "198.51.100.77 is external C2 infrastructure, not the internal authorized simulation target.",
            "127.0.0.1": "127.0.0.1 is local loopback; the designated lab target is 10.10.14.90.",
        },
    ),
    TaskDefinition(
        task_id="task-03-cleanup-rollback-planning",
        order=3,
        title="Safety Controls & Rollback Planning",
        instructions=(
            "In attack simulation planning, every offensive action must have a predefined, tested rollback procedure. "
            "Why is the cleanup and rollback phase critical in adversary simulation exercises?"
        ),
        task_type=TaskType.QUESTION,
        question="Why is the rollback and cleanup phase critical in adversary simulation exercises?",
        hint="Consider the danger of leaving test backdoors, artifacts, or elevated accounts behind on assets.",
        accepted_answers=[
            "To prevent leaving systems in an insecure state",
            "Prevent persistent backdoors from remaining",
            "Prevent leaving backdoors or test accounts",
            "To remove test artifacts and restore baseline security",
            "Restore baseline security",
            "Remove backdoors and test artifacts",
        ],
        xp_reward=60,
        mistake_explanations={
            "speed": "Rollback is about system safety and baseline integrity, not execution speed.",
            "cost": "While waste is avoided, the paramount risk is leaving lingering vulnerabilities behind.",
        },
    ),
    TaskDefinition(
        task_id="task-04-register-simulation-step",
        order=4,
        title="Simulation Step Specification & Telemetry Prediction",
        instructions=(
            "Define a controlled simulation test step linking the ATT&CK technique, target host, expected Windows event telemetry, "
            "and safety boundary controls. "
            "Execute the step registration from your workstation: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"step_id\":\"STEP-01\",\"technique\":\"T1059.001\",\"target_host\":\"10.10.14.90\",\"simulation_tool\":\"ATOMIC_TEST\",\"expected_event_id\":4688,\"safety_boundary\":\"NON_DESTRUCTIVE_EXECUTION\"}' http://10.10.14.90:8303/api/simulation/test-step` "
            "Submit the returned verification token below."
        ),
        task_type=TaskType.FLAG,
        question="Submit the simulation test step verification token.",
        hint="Execute the POST request against http://10.10.14.90:8303/api/simulation/test-step.",
        accepted_answers=["SIMULATION_STEP_REGISTERED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-simulation-planning-challenge",
        order=5,
        title="Attack Simulation Master Plan Challenge",
        instructions=(
            "Submit the comprehensive Attack Simulation Plan including RoE sign-off, target scoping, rollback procedures, "
            "and defensive success metrics. "
            "Execute the challenge submission via POST to http://10.10.14.90:8303/challenge: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"plan_id\":\"PLAN-VOLT-2026\",\"scope_validated\":true,\"roe_approved\":true,\"cleanup_procedure_defined\":true,\"defensive_metrics_defined\":true}' http://10.10.14.90:8303/challenge` "
            "Submit the resulting verification token."
        ),
        task_type=TaskType.FLAG,
        question="Submit the Attack Simulation Plan challenge verification token.",
        hint="Ensure task 04 step registration is completed before submitting the challenge.",
        accepted_answers=["ATTACK_SIMULATION_PLAN_APPROVED", "SIMULATION_PLAN_VERIFIED"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-simulation-planning-quiz",
        order=6,
        title="Attack Simulation Planning Technical Assessment",
        instructions="Complete the 4-question technical assessment on simulation methodology, deconfliction, and test design.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is 'Deconfliction' during a cybersecurity simulation exercise?",
                options=[
                    "The process where SOC analysts verify whether an alert was generated by authorized simulation activity or an actual external threat actor",
                    "A physical fight between offensive and defensive teams",
                    "Disabling the internet connection to resolve network latency",
                    "Renaming all computer hostnames to resolve DNS conflicts",
                ],
                correct_index=0,
                explanation="Deconfliction allows defenders who encounter an alert to check timestamps, IPs, and exercise logs with the simulation coordinator to confirm whether it is drill activity or a real breach.",
            ),
            QuizQuestion(
                id="q2",
                question="What is an 'Atomic Test' in adversary emulation?",
                options=[
                    "A tightly focused, non-destructive, single-technique execution test designed to validate one specific detection telemetry pipeline",
                    "A test that detonates physical computer hardware",
                    "A scan that probes all 65,535 TCP ports simultaneously",
                    "An automated script that formats hard drives",
                ],
                correct_index=0,
                explanation="Atomic tests (popularized by Red Canary Atomic Red Team) isolate single ATT&CK techniques into discrete, scriptable units to test specific detection primitives.",
            ),
            QuizQuestion(
                id="q3",
                question="Why is performing blind testing without advance notice to executive sponsors or safety controllers dangerous?",
                options=[
                    "It risks escalating real incident response processes, consuming emergency resources, and potentially causing unapproved system shutdowns",
                    "It makes the test too easy for defenders",
                    "It violates international copyright treaties",
                    "It causes computer memory chips to physically degrade",
                ],
                correct_index=0,
                explanation="While blind testing evaluates real-world SOC response, trusted safety coordinators and exercise leads must maintain awareness to abort the simulation if operational risks arise.",
            ),
            QuizQuestion(
                id="q4",
                question="What metric evaluates the duration between adversary technique execution and defensive detection alert generation?",
                options=[
                    "Time to Detect (TTD) / Mean Time to Detect (MTTD)",
                    "Bandwidth per second",
                    "CPU core utilization clock rate",
                    "Lines of code written per hour",
                ],
                correct_index=0,
                explanation="Time to Detect (TTD) measures how long an attacker operates inside an environment before security monitoring identifies their presence.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_03_CONCEPT = RoomConcept(
    overview=(
        "Adversary simulation planning is the disciplined engineering practice of designing safe, realistic, and measurable "
        "attack scenarios. Rather than randomly running offensive exploits, Purple Teams construct rigorous simulation plans. "
        "Each plan establishes clear objectives, authoritative Rules of Engagement (RoE), target boundary IP whitelists, "
        "hypotheses on expected telemetry, and deterministic rollback/cleanup procedures. This ensures validation is safe for production "
        "and directly translates into actionable detection metrics (TTD, Alert Fidelity, Coverage Score)."
    ),
    simple_analogy=(
        "Think of planning a commercial aviation fire drill: airport emergency teams don't light an uncontrolled bonfire in the main "
        "terminal. They coordinate with air traffic control, schedule a specific non-passenger aircraft, use controlled theatrical smoke, "
        "time the emergency truck arrival with stopwatches, and have fire extinguishers on standby."
    ),
    technical_term="Adversary Emulation Planning, Rules of Engagement & Deconfliction Protocols",
    technical_definition=(
        "Attack Simulation Planning is the structured methodology of designing threat-informed operational security exercises. "
        "Key components include Scope & Boundary Definitions, Threat Profile Selection, Threat-to-Telemetry Mapping, Deconfliction "
        "Procedures, Emergency Abort Triggers, and Post-Execution Cleanup Verification."
    ),
    cybersecurity_context=(
        "Unplanned or uncoordinated security testing risks severe enterprise disruption: accidentally locking out critical service "
        "accounts, triggering false-positive executive escalations, or leaving persistent test implants behind that external hackers "
        "later hijack. Proper simulation planning eliminates these risks while maximizing defensive validation."
    ),
    why_it_matters=(
        "Executive leadership and engineering teams will only authorize ongoing testing if security teams consistently prove that "
        "adversary simulations are safe, strictly controlled, and generate measurable improvements in cyber resilience."
    ),
    demonstration=(
        "The exercise coordinator drafts a simulation spec in JSON, specifies Target 10.10.14.90, technique T1059.001 (Atomic test #2), "
        "predicts Sysmon Event ID 1 creation with Parent CommandLine containing 'winword.exe', sets an abort condition if CPU exceeds 80%, "
        "and schedules an automated cleanup task removing test files 60 seconds post-run."
    ),
    remediation_guide=(
        "Standardize simulation templates using Infrastructure-as-Code, enforce peer-reviewed RoE approvals, establish live out-of-band "
        "communication channels (e.g. dedicated Signal/Slack war rooms), and verify complete artifact removal post-exercise."
    ),
)

ROOM_PURPLE_03_DEFINITION = RoomDefinition(
    room_id="purple-03-attack-simulation-planning",
    track=TrackEnum.PURPLE,
    room_number=3,
    title="Attack Simulation Planning",
    short_description="Design structured, safe adversary emulation plans: define Rules of Engagement, predict telemetry generation, configure safety boundaries, and establish deconfliction criteria.",
    difficulty="Intermediate",
    estimated_duration="50 min",
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
    concept=ROOM_PURPLE_03_CONCEPT,
    tasks=ROOM_PURPLE_03_TASKS,
)


# ============================================================================
# ROOM 04: RECONNAISSANCE VS MONITORING
# ============================================================================

ROOM_PURPLE_04_TASKS: List[TaskDefinition] = [
    TaskDefinition(
        task_id="task-01-recon-mechanics-syn-scan",
        order=1,
        title="Reconnaissance Mechanics: TCP SYN Stealth Scanning",
        instructions=(
            "Analyze the mechanics of network reconnaissance. Offensive operators perform port scanning to identify active hosts, "
            "open listening ports, and running service banners. "
            "In classic port scanning (such as `nmap -sS`), which single TCP flag is transmitted by the scanner to initiate a probe "
            "without establishing a full three-way TCP handshake connection?"
        ),
        task_type=TaskType.QUESTION,
        question="Which TCP flag initiates a half-open port scan probe?",
        hint="Consider the synchronize flag used in the first packet of a TCP handshake.",
        accepted_answers=["SYN", "syn", "TCP SYN", "SYN flag"],
        xp_reward=50,
        mistake_explanations={
            "ack": "ACK packets are used in ACK filtering scans (-sA) to map firewall rule sets, not standard SYN scans.",
            "fin": "FIN packets are used in FIN scans (-sF) to probe RFC 793 compliance, not standard SYN scanning.",
            "rst": "RST (Reset) packets are sent to tear down connections, not initiate probes.",
        },
    ),
    TaskDefinition(
        task_id="task-02-port-enumeration-service-identification",
        order=2,
        title="Active Service Enumeration via Nmap",
        instructions=(
            "Execute an active port scan against the authorized lab target `10.10.14.90` from your workstation: "
            "`nmap -sS -p 8080-8095 10.10.14.90` "
            "or review the captured scan logs in `/var/log/recon/scan_results.txt`. "
            "Which listening port on target 10.10.14.90 hosts the VoltCorp File Storage Gateway service?"
        ),
        task_type=TaskType.QUESTION,
        question="Which port on target 10.10.14.90 hosts the File Storage Gateway?",
        hint="Inspect the open ports between 8090 and 8095.",
        accepted_answers=["8094", "port 8094", "Port 8094", "tcp/8094"],
        xp_reward=50,
        mistake_explanations={
            "8089": "Port 8089 is the main SQLi training target from Red Room 09.",
            "8080": "Port 8080 is the Networking Fundamentals HTTP service.",
            "8090": "Port 8090 is the Reconnaissance target service.",
        },
    ),
    TaskDefinition(
        task_id="task-03-defensive-sensor-telemetry-analysis",
        order=3,
        title="Defensive Telemetry Inspection & Detection Blind Spots",
        instructions=(
            "Inspect the defensive sensor telemetry on port 8304 by querying "
            "`curl -s http://10.10.14.90:8304/api/monitoring/telemetry` "
            "or executing `python3 /home/operator/tools/recon_correlator.py --telemetry`. "
            "The perimeter network sensor detected an aggressive probe burst from your IP (`10.10.14.22`). "
            "What alert classification was assigned to the fast scan burst by the network monitoring sensor?"
        ),
        task_type=TaskType.QUESTION,
        question="What alert classification was assigned to the fast scan burst?",
        hint="Look for the alert string containing 'PORT_SCAN_DETECTED'.",
        accepted_answers=[
            "PORT_SCAN_DETECTED",
            "AGGRESSIVE_PORT_SCAN_DETECTED",
            "port_scan_detected",
            "PORT_SCAN_DETECTED (HIGH_CONFIDENCE)",
        ],
        xp_reward=60,
        mistake_explanations={
            "bruteforce": "The activity was rapid multi-port TCP SYN scanning, not credential brute-force.",
            "dos": "While noisy, port scanning is categorized as Reconnaissance, not Denial of Service.",
        },
    ),
    TaskDefinition(
        task_id="task-04-recon-telemetry-correlation",
        order=4,
        title="Offensive Action to Defensive Telemetry Correlation",
        instructions=(
            "Correlate the offensive port scan events with the defensive sensor detection record. "
            "Submit the correlation finding to the monitoring gateway via POST: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"attacker_ip\":\"10.10.14.22\",\"scan_type\":\"TCP_SYN_SCAN\",\"probed_ports\":[8080,8085,8090,8094],\"sensor_alert\":\"PORT_SCAN_DETECTED\"}' http://10.10.14.90:8304/api/monitoring/correlate` "
            "Submit the returned verification token below."
        ),
        task_type=TaskType.FLAG,
        question="Submit the reconnaissance-to-monitoring correlation verification token.",
        hint="Execute the POST request against http://10.10.14.90:8304/api/monitoring/correlate.",
        accepted_answers=["RECON_MONITORING_CORRELATION_CONFIRMED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-recon-monitoring-challenge",
        order=5,
        title="Detection Blind Spot Remediation & Validation Challenge",
        instructions=(
            "Tune the defensive detection rule to catch stealthy low-and-slow port scans, then validate remediation. "
            "First tune the threshold rule on the sensor: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"sensor_id\":\"SENSOR-VOLT-01\",\"syn_threshold_per_minute\":5,\"alert_action\":\"LOG_AND_ALERT\"}' http://10.10.14.90:8304/api/monitoring/tune-threshold` "
            "Then submit the final reconnaissance remediation challenge: "
            "`curl -s -X POST -H \"Content-Type: application/json\" -d '{\"assessment_id\":\"REC-MON-FINAL\",\"detection_blind_spot_remediated\":true,\"stealth_recon_detectable\":true}' http://10.10.14.90:8304/challenge` "
            "Submit the resulting verification token."
        ),
        task_type=TaskType.FLAG,
        question="Submit the reconnaissance vs monitoring validation challenge verification token.",
        hint="Ensure correlation is confirmed and threshold rule is tuned before submitting challenge.",
        accepted_answers=["RECON_VS_MONITORING_VALIDATED", "RECON_MONITORING_COMPLETE"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-recon-monitoring-quiz",
        order=6,
        title="Reconnaissance vs Monitoring Technical Assessment",
        instructions="Complete the 4-question technical assessment on port scanning mechanics, IDS threshold tuning, and blind spot discovery.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why do attackers use 'low-and-slow' scanning techniques (e.g. nmap -T1 or -T2)?",
                options=[
                    "To evade threshold-based intrusion detection alerts that trigger only when high packet rates occur within a short time window",
                    "To make the scan finish faster",
                    "To bypass physical air gaps in server hardware",
                    "To save electricity on the attacker's laptop",
                ],
                correct_index=0,
                explanation="Threshold rules often count events per second (e.g. >20 SYN packets in 5 seconds). Slowing down packet transmission stays below rate-based trigger thresholds.",
            ),
            QuizQuestion(
                id="q2",
                question="What defensive log source provides visibility into inbound connection attempts blocked by network firewalls?",
                options=[
                    "Firewall drop/deny logs and NetFlow / IPFIX flow records",
                    "Web browser cookie caches",
                    "Operating system sound card drivers",
                    "Email inbox spam folders",
                ],
                correct_index=0,
                explanation="Firewall deny/drop logs record attempted inbound connections that violated security policies, showing source IPs scanning for blocked ports.",
            ),
            QuizQuestion(
                id="q3",
                question="What risk arises when setting network port scan detection thresholds TOO low (e.g. alert on 1 probe)?",
                options=[
                    "Severe false-positive alert fatigue caused by normal network noise, misconfigured client applications, and benign search engine web crawlers",
                    "The firewall will delete all operating system files",
                    "Network cables will experience physical data congestion",
                    "Attacker computers will gain instant domain admin privileges",
                ],
                correct_index=0,
                explanation="Hyper-sensitive thresholds trigger on benign network background traffic, overwhelming SOC analysts with thousands of low-value alerts.",
            ),
            QuizQuestion(
                id="q4",
                question="How does Purple Teaming verify that a newly tuned reconnaissance detection rule actually works?",
                options=[
                    "The offensive operator executes a controlled rescan matching the previously missed pattern, while defenders verify the new alert fires in real-time",
                    "By assuming the documentation is accurate without testing",
                    "By shutting down all external network routers",
                    "By running antivirus on the firewall",
                ],
                correct_index=0,
                explanation="The core Purple Team feedback loop requires empirical re-testing: Red re-runs the evasion technique, and Blue verifies that the newly configured detection logic catches it.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_04_CONCEPT = RoomConcept(
    overview=(
        "Reconnaissance is the initial phase of the cyber attack lifecycle, where adversaries gather intelligence on target network topologies, "
        "live hosts, listening ports, service versions, and perimeter vulnerabilities. Defensive monitoring systems (NIDS, firewalls, SIEMs) "
        "strive to identify reconnaissance before an adversary exploits discovered services. Purple Teaming bridges the gap between offensive "
        "scanning and defensive visibility by directly correlating what the attacker sends with what the sensor records, exposing blind spots "
        "in rate thresholds and tuning rules to catch stealthy tradecraft."
    ),
    simple_analogy=(
        "Imagine a burglar walking down a quiet residential street testing front door handles. A noisy burglar runs from house to house "
        "jiggling 100 handles in 60 seconds—neighborhood watch immediately notices and calls the police. A stealthy burglar tests one handle "
        "every two hours. Purple Teaming teaches defenders how to calibrate their security cameras to catch both the loud and the patient burglar."
    ),
    technical_term="Network Reconnaissance, Port Scanning Telemetry & IDS Threshold Engineering (MITRE ATT&CK T1046 / T1595)",
    technical_definition=(
        "Network Reconnaissance is the systematic probing of network infrastructure to discover active hosts and services (T1046 Network Service "
        "Discovery; T1595 Active Scanning). Defensive monitoring relies on packet inspection (Suricata/Snort), stateful firewall logging, "
        "and flow anomaly detection to identify scanning patterns based on TCP flag distributions, source entropy, and connection frequency."
    ),
    cybersecurity_context=(
        "In modern zero-day campaigns, threat actors conduct low-and-slow reconnaissance over weeks. Default SIEM rules configured with static "
        "high-volume thresholds miss these stealthy probes entirely. Purple Team exercises reveal these blind spots and help engineers deploy "
        "composite rules that correlate slow port scans with DNS lookups and threat intelligence."
    ),
    why_it_matters=(
        "Detecting an adversary during the reconnaissance phase allows defenders to block source infrastructure and remediate exposed "
        "services BEFORE initial access or exploitation occurs, completely preempting a potential breach."
    ),
    demonstration=(
        "An analyst launches an Nmap SYN scan (`nmap -sS -p 8080-8095 10.10.14.90`), queries the target sensor at port 8304, observes "
        "that rapid scans trigger `PORT_SCAN_DETECTED` but slow scans (`-T2`) evade detection, tunes the threshold from 20 to 5 SYN/min, "
        "and validates that subsequent stealth probes now trigger alerts."
    ),
    remediation_guide=(
        "Implement rate-limiting and SYN flood protection on perimeter firewalls, disable unnecessary listening network services, deploy "
        "honeypot ports (canary ports) that trigger alerts upon any connection attempt, and continuously test sensor thresholds using automated scanners."
    ),
)

ROOM_PURPLE_04_DEFINITION = RoomDefinition(
    room_id="purple-04-reconnaissance-vs-monitoring",
    track=TrackEnum.PURPLE,
    room_number=4,
    title="Reconnaissance vs Monitoring",
    short_description="Perform controlled Nmap port scans, inspect network sensor telemetry, correlate offensive scanning with defensive detection alerts, and tune IDS threshold rules to eliminate blind spots.",
    difficulty="Intermediate",
    estimated_duration="50 min",
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
    concept=ROOM_PURPLE_04_CONCEPT,
    tasks=ROOM_PURPLE_04_TASKS,
)

