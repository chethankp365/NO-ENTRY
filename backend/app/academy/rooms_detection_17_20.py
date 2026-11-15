"""
Detection Engineering Rooms 17–20:
- Room 17: Snort / Suricata Network Signatures (detect-17-snort-suricata)
- Room 18: Threat Hunting Hypothesis Formulation (detect-18-threat-hunting-hypothesis)
- Room 19: CI/CD Pipelines for Detection Rules (detect-19-ci-cd-detection-pipelines)
- Room 20: Detection Engineering Capstone: Production Pipeline (detect-20-capstone-detection-pipeline)

Completes the entire 20-room Detection Engineering track and the complete 80-room curriculum.
Follows the standardized NO ENTRY Academy schema:
- 6 tasks per room
- Exactly 350 XP per room (50, 60, 50, 70, 80, 40 = 350 XP)
- 8-field professional concepts (no childish analogies)
- 4-question technical quiz assessment per room (100% threshold)
- Session-bound practical emulation and validation tokens
"""

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
# ROOM 17: SNORT / SURICATA NETWORK SIGNATURES
# ============================================================================

ROOM_DETECTION_17_CONCEPT = RoomConcept(
    technical_term="Packet-Level Network Signature & Deep Packet Inspection (DPI)",
    overview=(
        "Network Intrusion Detection Systems (NIDS) like Snort and Suricata inspect raw IP packets, "
        "TCP streams, and application protocol layers (HTTP, DNS, TLS) in real time. Rules specify header "
        "match filters (protocol, direction, src/dst IPs and ports) and payload inspection options (content, "
        "nocase, offset, depth, distance, within, pcre, flow:to_server,established, classtype, sid, rev). "
        "High-fidelity network signatures inspect protocol anomalies while avoiding catastrophic regex backtracking."
    ),
    simple_analogy=(
        "Imagine an airport customs conveyor belt where every piece of cargo (network packet) is x-rayed. "
        "Normal luggage passes through smoothly, but the automated scanner is configured with strict criteria: "
        "if a crate has an overseas shipping label (flow:to_server), contains metallic rectangular bars (content), "
        "and matches the microscopic density profile of contraband gold (pcre), an immediate diversion alarm triggers "
        "to pull the package aside before it reaches the main terminal."
    ),
    technical_definition=(
        "Suricata captures raw packets via high-performance interfaces (AF_PACKET, DPDK, or libpcap). The engine "
        "decodes Layer 2 through Layer 7, tracks TCP session state, reassembles streams, normalizes protocol buffers "
        "(such as http.uri and http.request_body), and tests packet streams against compiled signature trees. "
        "Multi-pattern search algorithms (Aho-Corasick, Hyperscan) rapidly eliminate non-matching rules before invoking "
        "expensive regular expression (PCRE) clauses."
    ),
    cybersecurity_context=(
        "During CVE-2021-44228 (Log4j / Log4Shell), adversaries injected JNDI exploit strings (${jndi:ldap://...}) "
        "inside HTTP User-Agent and Authorization headers worldwide. Emerging Threats (ET) and the Suricata community "
        "authored perimeter network signatures inspecting HTTP header buffers with wildcard obfuscation handling (sid:2034647), "
        "blocking millions of automated exploit attempts before internal vulnerable Java applications could parse them."
    ),
    why_it_matters=(
        "Endpoint detection (EDR) can be disabled, bypassed, or blinded by kernel rootkits and tampered drivers. Out-of-band "
        "network taps and perimeter Suricata sensors observe unadulterated wire traffic independently, providing an immutable "
        "source of truth for detecting novel network exploits, C2 beaconing, and unauthorized data exfiltration."
    ),
    demonstration=(
        "In this lab, you will analyze network traffic captures, author high-performance Suricata rules with content matching "
        "and PCRE clauses, tune flow options, and validate detection against live packet streams."
    ),
    remediation_guide=(
        "1. Enforce flow:established to eliminate false positives on unacknowledged SYN scans.\n"
        "2. Always pair PCRE expressions with literal content fast-patterns to prevent CPU exhaustion.\n"
        "3. Configure TCP stream reassembly to prevent packet fragmentation evasion.\n"
        "4. Assign canonical SID ranges and increment revision numbers on rule modifications."
    ),
)

ROOM_DETECTION_17_TASKS = [
    TaskDefinition(
        task_id="task-01-snort-rule-header-mechanics",
        title="Snort & Suricata Flow Mechanics",
        order=1,
        instructions=(
            "Examine Snort/Suricata TCP session state tracking. Identify the flow modifier option "
            "that ensures signature inspection occurs only on established two-way TCP sessions "
            "(e.g. following completion of the three-way SYN/ACK handshake). "
            "Enter the keyword ('established')."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["established", "flow:established", "flow:to_server,established"],
        hint="The `flow:established` modifier tells the NIDS engine to only inspect packets belonging to fully negotiated TCP connections, eliminating alerts on rejected or dropped SYN packets.",
    ),
    TaskDefinition(
        task_id="task-02-suricata-sid-mechanics",
        title="Signature Identification Syntax (SID)",
        order=2,
        instructions=(
            "In Snort and Suricata rule authoring, every distinct rule must specify a unique numerical "
            "identifier keyword used for SIEM correlation, alert deduplication, and rule management. "
            "What is this 3-letter keyword? (e.g. 'sid')."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=60,
        accepted_answers=["sid", "SID"],
        hint="The `sid` (Signature ID) uniquely identifies a Snort/Suricata rule. SIDs under 1,000,000 are reserved for official rule sets, while custom enterprise rules start at 1,000,000+.",
    ),
    TaskDefinition(
        task_id="task-03-attck-network-protocol-mapping",
        title="MITRE ATT&CK: Application Layer Protocol",
        order=3,
        instructions=(
            "Adversaries frequently conceal C2 communications and payload delivery within standard application "
            "protocols (HTTP, DNS, TLS) or non-standard ports to blend with legitimate perimeter traffic. "
            "What is the MITRE ATT&CK technique ID for Application Layer Protocol? (e.g. 'T1071')."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["T1071", "t1071"],
        hint="MITRE ATT&CK Technique T1071 covers Application Layer Protocol abuse for Command and Control, including web protocols (T1071.001) and DNS (T1071.004).",
    ),
    TaskDefinition(
        task_id="task-04-snort-suricata-emulation",
        title="NIDS Signature Emulation & Telemetry Inspection",
        order=4,
        instructions=(
            "Inspect `/var/log/detection/suricata_network_events.json` on the attacker workstation. "
            "Execute the Suricata analysis tool with `--emulate-signature` to evaluate candidate signatures "
            "against raw pcap stream decodes and obtain your verification token."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=70,
        accepted_answers=["SURICATA_SIGNATURE_VERIFIED"],
        hint="Evaluating network signatures against raw PCAP streams verifies fast-pattern matches and TCP reassembly without dropping packets under load.",
    ),
    TaskDefinition(
        task_id="task-05-snort-suricata-challenge",
        title="Independent Challenge: Tune PCRE & Validate Signature",
        order=5,
        instructions=(
            "Tune signature regex modifiers and payload depth offsets using `--tune-pcre` to prevent catastrophic "
            "backtracking. Once tuned, submit the challenge with `--challenge` to achieve signature validation."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=80,
        accepted_answers=["SURICATA_SIGNATURE_VALIDATED"],
        hint="Tuning PCRE anchors and fast-pattern offsets ensures that deep packet inspection executes in bounded O(n) time, preventing CPU denial-of-service on high-throughput links.",
    ),
    TaskDefinition(
        task_id="task-06-snort-suricata-quiz",
        title="Snort & Suricata Mastery Assessment",
        order=6,
        instructions="Complete the 4-question technical assessment on NIDS rule architecture, flow tracking, and packet inspection.",
        task_type=TaskType.QUIZ,
        xp_reward=40,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is the 'fast_pattern' modifier used in Suricata rules that contain multiple content options?",
                options=[
                    "It instructs the multi-pattern matching engine (Hyperscan) to use that specific content substring for initial fast triage, skipping unmatching packets.",
                    "It accelerates network transmission by compressing the target packet.",
                    "It bypasses the need for TCP handshakes on the inspected interface.",
                    "It converts Suricata from an intrusion detection system into an unmanaged proxy.",
                ],
                correct_index=0,
                explanation="The `fast_pattern` keyword designates the most unique or longest string to be registered in the multi-pattern matcher, discarding irrelevant packets before evaluating remaining rule options.",
            ),
            QuizQuestion(
                id="q2",
                question="What is the operational purpose of the 'rev' keyword in a Snort/Suricata signature header?",
                options=[
                    "It tracks the revision number of the rule when modifications or performance tunings are published.",
                    "It reverses the source and destination IP addresses in real time.",
                    "It reverts the network interface driver to factory defaults.",
                    "It marks the rule as deprecated and disables alert generation.",
                ],
                correct_index=0,
                explanation="The `rev` keyword specifies the revision number of a signature, enabling SIEMs and rule managers to track changes and audit rule lifecycle updates.",
            ),
            QuizQuestion(
                id="q3",
                question="In packet inspection, what is the key difference between 'depth' and 'offset' keywords?",
                options=[
                    "'offset' specifies how many bytes to skip from the beginning of the payload before searching, while 'depth' specifies how many bytes to search.",
                    "'depth' measures packet latency, while 'offset' sets the destination port.",
                    "'offset' encrypts the signature, while 'depth' stores the packet on disk.",
                    "'depth' is only used for UDP packets, while 'offset' is strictly for ICMP packets.",
                ],
                correct_index=0,
                explanation="`offset` sets the starting byte index in the buffer, and `depth` dictates the maximum number of bytes from the start of the buffer that the engine is permitted to examine.",
            ),
            QuizQuestion(
                id="q4",
                question="What security risk arises if a Snort rule uses an unanchored PCRE with nested greedy quantifiers like `.*`?",
                options=[
                    "Catastrophic regular expression backtracking (ReDoS), consuming 100% CPU on sensor cores and causing packet drops.",
                    "The target server will automatically reboot.",
                    "The SIEM database will delete historical event logs.",
                    "Network switches will drop all VLAN tagging across the enterprise.",
                ],
                correct_index=0,
                explanation="Unanchored regexes with greedy quantifiers cause catastrophic backtracking on non-matching payloads, exhausting CPU cycles and inducing sensor denial of service.",
            ),
        ],
    ),
]

ROOM_DETECTION_17_DEFINITION = RoomDefinition(
    room_id="detect-17-snort-suricata",
    track=TrackEnum.DETECTION,
    room_number=17,
    title="Snort / Suricata Network Signatures",
    short_description="Author packet-level intrusion detection signatures inspecting payload bytes, PCRE, and flow flags.",
    difficulty="Advanced",
    estimated_duration="60 min",
    prerequisites=["detect-05-network-connection-rules", "detect-09-web-detection-rules"],
    required_practical_skills=["Snort Rule Syntax", "Suricata DPI", "PCRE Optimization", "Fast-Pattern Matching"],
    required_lab_type="container_duo",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Master the Snort/Suricata signature syntax and rule header options (action, proto, src, dst, ports)",
        "Configure flow tracking modifiers (flow:to_server,established) to prevent false alerts on invalid TCP states",
        "Implement payload inspection options (content, nocase, offset, depth, distance, within)",
        "Optimize regular expression clauses (pcre) with fast_pattern to eliminate catastrophic backtracking",
        "Validate network signatures against raw PCAP streams with zero dropped packets",
    ],
    assessment_criteria=[
        "Identify flow connection state and SID keywords",
        "Map C2 network communications to MITRE ATT&CK T1071",
        "Emulate signature evaluation and inspect stream decodes",
        "Tune PCRE offsets to prevent regex denial of service",
        "Score 100% on the NIDS architecture and signature optimization quiz",
    ],
    completion_requirements=[
        "Complete all 6 tasks sequentially",
        "Obtain verification and validation tokens from running lab services",
        "Pass the technical assessment quiz with 100%",
    ],
    total_xp=350,
    concept=ROOM_DETECTION_17_CONCEPT,
    tasks=ROOM_DETECTION_17_TASKS,
    default_port=8417,
)

# ============================================================================
# ROOM 18: THREAT HUNTING HYPOTHESIS FORMULATION
# ============================================================================

ROOM_DETECTION_18_CONCEPT = RoomConcept(
    technical_term="Intelligence-Driven Threat Hunting & Hypothesis Development",
    overview=(
        "Threat hunting is the proactive, hypothesis-driven exploration of enterprise telemetry to uncover "
        "advanced persistent threats (APTs) that have bypassed automated detections. Rather than waiting for "
        "alerts, threat hunters formulate structured hypotheses based on cyber threat intelligence (CTI), "
        "threat actor Tactics, Techniques, and Procedures (TTPs), and environmental baseline anomalies. "
        "Hypotheses follow an empirical model: 'If Actor X utilizes Technique Y against Environment Z, we should "
        "observe Evidence Artifacts in Telemetry Source W.'"
    ),
    simple_analogy=(
        "Consider an epidemiologist tracking a silent disease outbreak. Instead of waiting for emergency room "
        "alarms to sound, they formulate a specific hypothesis: 'If an airborne respiratory pathogen is spreading "
        "through city transit hubs, we will observe an anomalous spike in over-the-counter fever medication sales "
        "at subway station pharmacies.' They query point-of-sale datasets, confirm the anomaly, and intervene "
        "before hospital ICUs become overwhelmed."
    ),
    technical_definition=(
        "The threat hunting lifecycle consists of: 1) Hypothesis Formulation (driven by intelligence or environmental "
        "visibility), 2) Investigative Query Construction (SIEM, EDR, data lake), 3) Data Analysis & Baseline Filtering "
        "(separating benign administrative workflows from adversary tradecraft), 4) Threat Identification or Validation, "
        "and 5) Automation & Detection Engineering (converting validated hunt findings into permanent detection rules)."
    ),
    cybersecurity_context=(
        "During the SolarWinds Supply Chain compromise (UNC2452 / Nobelium), threat hunters discovered the breach "
        "not through an automated SIEM alert, but by investigating anomalous multi-factor authentication (MFA) device "
        "registrations associated with employee accounts. Hunters hypothesized that adversaries were establishing persistent "
        "access via secondary token spoofing, leading directly to the discovery of the SUNBURST backdoor."
    ),
    why_it_matters=(
        "Modern threat actors routinely leverage living-off-the-land binaries (LOLBINs), stolen credentials, and zero-day "
        "exploits that generate zero initial SIEM alerts. Proactive threat hunting bridges the detection gap by actively "
        "searching for subtle behavioral indicators of compromise, slashing attacker dwell time from months to hours."
    ),
    demonstration=(
        "In this lab, you will formulate a threat hunting hypothesis targeting living-off-the-land execution, analyze enterprise "
        "telemetry datasets, filter administrative baseline activity, and document validated hunt evidence."
    ),
    remediation_guide=(
        "1. Anchor hunts to testable hypotheses derived from MITRE ATT&CK techniques rather than unstructured data browsing.\n"
        "2. Focus queries on behavioral anomalies (parent-child process lineage, script blocks) rather than fragile static hashes.\n"
        "3. Baseline normal administrative automation to eliminate repeat investigations of known operational patterns.\n"
        "4. Operationalize confirmed hunt findings by writing automated detection rules in production SIEM/EDR."
    ),
)

ROOM_DETECTION_18_TASKS = [
    TaskDefinition(
        task_id="task-01-hypothesis-structure-mechanics",
        title="Hypothesis Formulation Foundations",
        order=1,
        instructions=(
            "In intelligence-driven threat hunting, what testable scientific foundation must be defined "
            "before querying SIEM or EDR data lakes? Enter the term ('hypothesis')."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["hypothesis", "Hypothesis", "threat hypothesis"],
        hint="A structured hypothesis states an expected adversary behavior, target environment, and observable telemetry artifacts, preventing aimless data wandering.",
    ),
    TaskDefinition(
        task_id="task-02-hunt-metrics-dwell-time",
        title="Adversary Dwell Time Reduction",
        order=2,
        instructions=(
            "What critical security metric represents the total elapsed duration between an adversary's "
            "initial network compromise and their active detection by security teams? (Answer: 'dwell time')."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=60,
        accepted_answers=["dwell time", "Dwell Time", "dwell-time"],
        hint="Dwell time measures the window an attacker operates undetected. Mature proactive threat hunting programs systematically reduce dwell time from industry averages of 200+ days down to hours.",
    ),
    TaskDefinition(
        task_id="task-03-attck-lolbin-wmi-mapping",
        title="MITRE ATT&CK: Windows Management Instrumentation",
        order=3,
        instructions=(
            "Threat hunters frequently hypothesize that adversaries abuse native Windows administrative tools "
            "for remote execution and discovery. What is the MITRE ATT&CK technique ID for Windows Management "
            "Instrumentation (WMI)? (e.g. 'T1047')."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["T1047", "t1047"],
        hint="MITRE ATT&CK Technique T1047 covers Windows Management Instrumentation (WMI), often weaponized for stealthy process execution and remote reconnaissance.",
    ),
    TaskDefinition(
        task_id="task-04-threat-hunting-hypothesis-emulation",
        title="Hypothesis Query Emulation & Execution",
        order=4,
        instructions=(
            "Inspect `/var/log/detection/threat_hunting_corpus.json` on the attacker workstation. "
            "Execute the threat hunting tool with `--emulate-hunt` to evaluate your hypothesis against "
            "cross-endpoint telemetry and obtain your verification token."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=70,
        accepted_answers=["THREAT_HUNT_HYPOTHESIS_VERIFIED"],
        hint="Executing hunting queries across normalized EDR process telemetry uncovers covert living-off-the-land execution patterns that bypassed signature-based alerts.",
    ),
    TaskDefinition(
        task_id="task-05-threat-hunting-hypothesis-challenge",
        title="Independent Challenge: Tune Scope & Validate Findings",
        order=5,
        instructions=(
            "Filter benign administrative WMI maintenance tasks using `--tune-hypothesis`, then submit the "
            "challenge with `--challenge` to achieve hunt validation."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=80,
        accepted_answers=["THREAT_HUNT_HYPOTHESIS_VALIDATED"],
        hint="Filtering benign developer and IT maintenance baselines isolates genuine malicious persistence tradecraft, transforming verified hunt queries into production SIEM rules.",
    ),
    TaskDefinition(
        task_id="task-06-threat-hunting-hypothesis-quiz",
        title="Threat Hunting Hypothesis Assessment",
        order=6,
        instructions="Complete the 4-question technical assessment on threat hunting frameworks, dwell time, and hypothesis lifecycle management.",
        task_type=TaskType.QUIZ,
        xp_reward=40,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is the final stage of a successful threat hunting engagement after verifying malicious activity?",
                options=[
                    "Converting the validated hunt query into an automated production detection rule to prevent recurrence.",
                    "Deleting the telemetry logs to free up SIEM storage.",
                    "Disconnecting the entire corporate network permanently.",
                    "Closing the investigation without documenting findings.",
                ],
                correct_index=0,
                explanation="The peak value of threat hunting is feed-forward into detection engineering: every confirmed hunt finding should be automated as a production detection rule.",
            ),
            QuizQuestion(
                id="q2",
                question="Which threat hunting model focuses on analyzing high-prevalence behaviors and outliers in normal enterprise baselines?",
                options=[
                    "Anomaly-based / Baseline-driven hunting (M-Trends / TaHiTI framework).",
                    "Cryptographic brute-forcing.",
                    "Random port scanning.",
                    "Frontend UI regression testing.",
                ],
                correct_index=0,
                explanation="Baseline-driven hunting analyzes statistical distributions across enterprise hosts (e.g. least-frequency-of-occurrence / stacking) to surface anomalous processes.",
            ),
            QuizQuestion(
                id="q3",
                question="Why is 'least-frequency analysis' (stacking) an effective technique in threat hunting?",
                options=[
                    "Legitimate system binaries execute millions of times, while adversary implants typically execute on only one or two hosts, standing out at the bottom of frequency counts.",
                    "It automatically removes all virus files from the network.",
                    "It increases computer processor speeds by 50%.",
                    "It encrypts all outbound network traffic.",
                ],
                correct_index=0,
                explanation="Stacking groups identical command lines or parent-child pairs. Benign software aggregates into massive counts, while attacker tools appear as rare singletons.",
            ),
            QuizQuestion(
                id="q4",
                question="According to threat hunting maturity models, what characterizes a Level 4 (Leading) hunting organization?",
                options=[
                    "High degree of automation where successful hunt patterns are routinely transpiled into permanent CI/CD detection rules.",
                    "Reliance exclusively on third-party commercial antivirus pop-ups.",
                    "Zero collection of endpoint process logs.",
                    "Manual inspection of raw paper printer printouts.",
                ],
                correct_index=0,
                explanation="Level 4 organizations systematically automate the hunt-to-detection lifecycle, publishing validated queries as Detection-as-Code across the enterprise.",
            ),
        ],
    ),
]

ROOM_DETECTION_18_DEFINITION = RoomDefinition(
    room_id="detect-18-threat-hunting-hypothesis",
    track=TrackEnum.DETECTION,
    room_number=18,
    title="Threat Hunting Hypothesis Formulation",
    short_description="Formulate intelligence-driven hypotheses and translate them into investigative queries.",
    difficulty="Intermediate",
    estimated_duration="45 min",
    prerequisites=["detect-04-process-creation-rules", "detect-07-auth-abuse-rules"],
    required_practical_skills=["Threat Hunting Models", "Hypothesis Formulation", "Least-Frequency Stacking", "WMI Analysis"],
    required_lab_type="container_duo",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Understand the structured threat hunting lifecycle (formulate, query, filter, isolate, automate)",
        "Formulate testable hypotheses based on threat intelligence and adversary TTPs",
        "Apply least-frequency analysis (stacking) across endpoint process telemetry",
        "Isolate living-off-the-land techniques (WMI T1047) from legitimate administrative scripts",
        "Translate confirmed hunt findings into permanent production detection rules",
    ],
    assessment_criteria=[
        "Identify hypothesis formulation structure and dwell time metric",
        "Map WMI abuse to MITRE ATT&CK T1047",
        "Emulate threat hunting query across cross-endpoint telemetry",
        "Filter benign IT administration baselines to validate malicious activity",
        "Score 100% on the threat hunting methodology and stacking analysis quiz",
    ],
    completion_requirements=[
        "Complete all 6 tasks sequentially",
        "Obtain verification and validation tokens from running lab services",
        "Pass the technical assessment quiz with 100%",
    ],
    total_xp=350,
    concept=ROOM_DETECTION_18_CONCEPT,
    tasks=ROOM_DETECTION_18_TASKS,
    default_port=8418,
)

# ============================================================================
# ROOM 19: CI/CD PIPELINES FOR DETECTION RULES
# ============================================================================

ROOM_DETECTION_19_CONCEPT = RoomConcept(
    technical_term="Continuous Integration & Deployment (CI/CD) for Detection-as-Code",
    overview=(
        "CI/CD detection pipelines treat security detection rules (Sigma, YARA, Suricata, SIEM queries) "
        "as production code stored in version control (Git). Automated pipelines execute linting (YAML/schema "
        "syntax validation), static security checks, unit testing against synthetic log corpuses, regression testing, "
        "and automated transpilation and deployment into SIEM/EDR clusters via APIs. This ensures zero syntax errors, "
        "guarantees backward compatibility, and enforces peer review before rules reach live production monitoring."
    ),
    simple_analogy=(
        "Think of a high-speed automotive assembly line. Before an engine is mounted into a vehicle, automated "
        "robotic stations verify bolt torque, check fluid pressures, and run diagnostic electrical simulations. "
        "If a single sensor fails or a bolt is loose, the conveyor belt automatically halts and rejects the engine, "
        "preventing a defective vehicle from ever driving out onto the public highway."
    ),
    technical_definition=(
        "When a detection engineer opens a Pull Request in GitLab or GitHub, an automated runner executes pipeline "
        "stages: 1) lint (yamllint, sigma-cli check), 2) test (unit tests against positive and negative synthetic log fixtures), "
        "3) security-review (peer approval requirements), and 4) deploy (API push of transpiled queries into Elasticsearch, "
        "Splunk, or Wazuh). Failed tests block the merge gate automatically."
    ),
    cybersecurity_context=(
        "A major financial institution experienced a 6-hour SIEM outage when an engineer manually committed a malformed "
        "regex directly into a production query interface, causing excessive memory consumption that crashed the SIEM "
        "cluster and blinded security analysts. By implementing a mandatory CI/CD pipeline with automated syntax validation "
        "and ReDoS (regex denial of service) testing, the organization eliminated manual syntax errors completely."
    ),
    why_it_matters=(
        "Manual detection deployment is slow, error-prone, and lacks auditability. Detection-as-Code with automated "
        "CI/CD enables security teams to deploy verified detections in minutes, track every modification via Git commit "
        "history, and prevent catastrophic false-positive floods or SIEM performance degradation."
    ),
    demonstration=(
        "In this lab, you will configure a detection rule CI/CD pipeline, execute automated lint and test stages against "
        "synthetic event fixtures, tune gate thresholds, and deploy validated rules to the monitoring platform."
    ),
    remediation_guide=(
        "1. Enforce automated syntax linting as the fast-fail first stage of all detection CI pipelines.\n"
        "2. Require both positive and negative unit test fixtures for every rule before approving merge requests.\n"
        "3. Protect deployment branches with mandatory code reviews and signed commit verification.\n"
        "4. Automate canary rollouts and instant rollback capabilities to handle unexpected production alert volume."
    ),
)

ROOM_DETECTION_19_TASKS = [
    TaskDefinition(
        task_id="task-01-pipeline-stage-mechanics",
        title="Pipeline Architecture & Initial Stage",
        order=1,
        instructions=(
            "In Detection-as-Code CI/CD pipelines, what initial pipeline stage validates code formatting, "
            "indentation, and YAML schema rules before allocating resources for test execution? (Answer: 'lint')."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["lint", "linting", "Lint"],
        hint="The `lint` stage performs fast static validation of YAML syntax and schema compliance, catching formatting errors in milliseconds before expensive test fixtures run.",
    ),
    TaskDefinition(
        task_id="task-02-git-workflow-branching",
        title="GitOps Peer Review Gates",
        order=2,
        instructions=(
            "In modern GitOps detection workflows, what code collaboration feature allows engineers to propose "
            "rule updates, trigger CI validation, and require peer approval before merging into the main branch? "
            "(Answer: 'pull request')."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=60,
        accepted_answers=["pull request", "Pull Request", "merge request", "PR", "MR"],
        hint="Pull Requests (or Merge Requests) enforce code review, branch protection, and automated CI test gates before new detection logic can enter production branches.",
    ),
    TaskDefinition(
        task_id="task-03-attck-cicd-pipeline-mapping",
        title="MITRE ATT&CK: Compromise Software Supply Chain",
        order=3,
        instructions=(
            "Adversaries increasingly target automated software development and delivery pipelines to tamper with code. "
            "What is the MITRE ATT&CK sub-technique ID for Supply Chain Compromise: Compromise Software Dependencies "
            "or Development Pipeline? (e.g. 'T1195.002')."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["T1195.002", "t1195.002", "T1195"],
        hint="MITRE ATT&CK sub-technique T1195.002 covers adversary tampering with development tools, repositories, and automated CI/CD pipeline infrastructure.",
    ),
    TaskDefinition(
        task_id="task-04-detection-pipeline-emulation",
        title="CI/CD Detection Pipeline Execution",
        order=4,
        instructions=(
            "Inspect `/var/log/detection/ci_cd_pipeline_definition.json` on the attacker workstation. "
            "Execute the pipeline tool with `--emulate-pipeline` to run the automated lint, unit test, "
            "and transpilation stages and obtain your verification token."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=70,
        accepted_answers=["DETECTION_PIPELINE_VERIFIED"],
        hint="Automated CI/CD execution verifies that all rules pass schema validation, synthetic log execution, and SIEM transpilation gates before deployment.",
    ),
    TaskDefinition(
        task_id="task-05-detection-pipeline-challenge",
        title="Independent Challenge: Tune Pipeline Gates & Deploy",
        order=5,
        instructions=(
            "Tune automated pipeline gate thresholds using `--tune-pipeline` to enforce 100% unit test pass rates, "
            "then submit the challenge with `--challenge` to achieve production deployment validation."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=80,
        accepted_answers=["DETECTION_PIPELINE_VALIDATED"],
        hint="Configuring automated merge gates prevents untested or broken detection rules from ever reaching production SIEM clusters.",
    ),
    TaskDefinition(
        task_id="task-06-detection-pipeline-quiz",
        title="CI/CD Detection Engineering Assessment",
        order=6,
        instructions="Complete the 4-question technical assessment on Detection-as-Code CI/CD pipelines, GitOps, and automated deployment.",
        task_type=TaskType.QUIZ,
        xp_reward=40,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why should detection rules be transpiled into SIEM query languages during the CI/CD pipeline rather than authored manually in the SIEM?",
                options=[
                    "It allows rules to remain vendor-agnostic in Git (e.g. Sigma) while automating deployment to multiple target SIEMs simultaneously.",
                    "It permanently disables the need for log storage.",
                    "It makes the detection queries unreadable to security analysts.",
                    "It doubles the CPU clock frequency of target domain controllers.",
                ],
                correct_index=0,
                explanation="Authoring in open formats (Sigma) and transpiling via CI/CD enables vendor-agnostic agility: teams can switch or run multiple SIEMs without rewriting rules from scratch.",
            ),
            QuizQuestion(
                id="q2",
                question="What security control should be enforced on the 'main' branch of a Detection-as-Code repository?",
                options=[
                    "Branch protection requiring passing CI checks and at least one peer code review approval before merging.",
                    "Direct unrestricted commit access for all anonymous users.",
                    "Deleting historical commit logs every 24 hours.",
                    "Disabling all automated pipeline triggers.",
                ],
                correct_index=0,
                explanation="Branch protection rules ensure that no rule enters production without passing automated syntax/unit tests and undergoing mandatory human review.",
            ),
            QuizQuestion(
                id="q3",
                question="How does an automated CI pipeline prevent Regression in Detection Engineering?",
                options=[
                    "By running updated rules against historical synthetic log corpuses to confirm that rule modifications do not break previously working detections.",
                    "By automatically rolling back the operating system to MS-DOS.",
                    "By blocking all user logins during code deployment.",
                    "By deleting all negative test fixtures.",
                ],
                correct_index=0,
                explanation="Regression testing against a library of historical true-positive attack logs ensures that rule tuning does not accidentally introduce blind spots.",
            ),
            QuizQuestion(
                id="q4",
                question="What is the purpose of an automated rollback mechanism in a continuous deployment detection pipeline?",
                options=[
                    "Immediately reverting a newly deployed rule if production telemetry triggers an unexpected alert spike (alert storm) within minutes of deployment.",
                    "Uninstalling the Git client from developer workstations.",
                    "Reverting the SIEM database to zero bytes.",
                    "Switching from Linux to Windows automatically.",
                ],
                correct_index=0,
                explanation="Automated canary deployment and rollback protects SOC analysts by instantly disabling newly deployed rules that generate unexpected false-positive floods.",
            ),
        ],
    ),
]

ROOM_DETECTION_19_DEFINITION = RoomDefinition(
    room_id="detect-19-ci-cd-detection-pipelines",
    track=TrackEnum.DETECTION,
    room_number=19,
    title="CI/CD Pipelines for Detection Rules",
    short_description="Build automated GitHub Actions/GitLab pipelines that validate, lint, test, and deploy Sigma rules.",
    difficulty="Advanced",
    estimated_duration="60 min",
    prerequisites=["detect-01-foundations-as-code", "detect-15-unit-testing-rules"],
    required_practical_skills=["CI/CD Pipeline Design", "Detection-as-Code", "Sigma Transpilation", "GitOps Branching"],
    required_lab_type="container_duo",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Implement Detection-as-Code using Git version control and automated CI/CD runners",
        "Design multi-stage pipelines: lint, synthetic log test, security review, and deploy",
        "Enforce branch protection rules and peer code review gates for detection pull requests",
        "Automate multi-SIEM transpilation from Sigma YAML to native queries (Splunk, Elastic, Wazuh)",
        "Configure automated rollback triggers to protect SOC operations from alert floods",
    ],
    assessment_criteria=[
        "Identify initial pipeline stage and GitOps peer review mechanisms",
        "Map pipeline tampering to MITRE ATT&CK T1195.002",
        "Emulate automated CI/CD pipeline stages and transpilation checks",
        "Tune automated merge gates to enforce 100% unit test pass thresholds",
        "Score 100% on the CI/CD pipeline and GitOps architecture quiz",
    ],
    completion_requirements=[
        "Complete all 6 tasks sequentially",
        "Obtain verification and validation tokens from running lab services",
        "Pass the technical assessment quiz with 100%",
    ],
    total_xp=350,
    concept=ROOM_DETECTION_19_CONCEPT,
    tasks=ROOM_DETECTION_19_TASKS,
    default_port=8419,
)

# ============================================================================
# ROOM 20: DETECTION ENGINEERING CAPSTONE: PRODUCTION PIPELINE
# ============================================================================

ROOM_DETECTION_20_CONCEPT = RoomConcept(
    technical_term="End-to-End Enterprise Detection Engineering Lifecycle & Production Capstone",
    overview=(
        "The Detection Engineering Capstone represents the culmination of the entire track. Learners synthesize "
        "all core disciplines: threat intelligence analysis, data modeling and normalization (ECS/CIM), rule authoring "
        "(Sigma, Suricata, YARA), automated unit testing against positive and negative synthetic logs, false-positive "
        "baseline tuning, and continuous CI/CD deployment into a live multi-tier enterprise monitoring architecture. "
        "The capstone validates that learners can design resilient, high-fidelity detections that protect enterprise "
        "infrastructure from advanced threat actors."
    ),
    simple_analogy=(
        "Think of launching an orbital communications satellite. Aerospace engineers do not simply solder components "
        "together and launch immediately. They design the telemetry bus, test the subassemblies in thermal vacuum "
        "chambers, run synthetic stress simulations, calibrate communication antennas against solar interference, "
        "and pass final countdown launch gates. Once in orbit, the satellite operates autonomously, continuously relaying "
        "critical data with zero failure tolerance."
    ),
    technical_definition=(
        "The capstone exercises an end-to-end production workflow: 1) Threat Scenario Ingestion: analyzing adversary attack "
        "chains (credential dumping via LSASS, lateral movement via WMI, C2 over DNS/HTTPS), 2) Detection Rule Synthesis: "
        "authoring multi-stage detection signatures, 3) Automated Pipeline Testing: validating against mixed benign and attack "
        "telemetry, 4) Production Gate Validation: verifying 100% true positive alert rate and 0% false positives, and "
        "5) Final Deployment to production SIEM."
    ),
    cybersecurity_context=(
        "During the NotPetya global cyber incident, organizations that had deployed mature, automated detection engineering "
        "pipelines were able to detect and contain the wiper within minutes of initial EternalBlue and PsExec lateral "
        "propagation, while organizations relying on unmanaged, ad-hoc rules suffered catastrophic worldwide domain controller outages."
    ),
    why_it_matters=(
        "A security operations center is only as effective as the fidelity of its detection rules. Building an end-to-end "
        "production pipeline ensures that detection engineering operates with software engineering rigor, minimizing alert "
        "fatigue for SOC analysts while maximizing threat detection capabilities across the enterprise."
    ),
    demonstration=(
        "In this capstone lab, you will orchestrate the complete detection engineering lifecycle: ingest complex multi-stage "
        "attack scenarios, author and unit-test detection rules across endpoint and network vectors, tune false-positive baselines, "
        "and deploy a production-grade detection pipeline."
    ),
    remediation_guide=(
        "1. Structure detection development around the full engineering lifecycle: intelligence -> authoring -> testing -> tuning -> deployment.\n"
        "2. Normalize telemetry against common schemas (ECS/CIM) to ensure detection portability across SIEM architectures.\n"
        "3. Pair every detection rule with an actionable analyst triage playbook and documented false-positive scenarios.\n"
        "4. Regularly review and retire obsolete detection rules through continuous detection coverage scoring."
    ),
)

ROOM_DETECTION_20_TASKS = [
    TaskDefinition(
        task_id="task-01-capstone-lifecycle-mechanics",
        title="Production Operational Documentation",
        order=1,
        instructions=(
            "What operational triage documentation must accompany every production detection rule to guide "
            "Tier 1 SOC analysts in investigating and containing confirmed alerts? (Answer: 'playbook')."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["playbook", "runbook", "Playbook", "Runbook", "triage playbook"],
        hint="Every production detection rule requires an associated triage playbook (runbook) detailing investigative steps, asset sensitivity, false-positive indicators, and containment procedures.",
    ),
    TaskDefinition(
        task_id="task-02-capstone-telemetry-taxonomy",
        title="Enterprise Data Model Standardization",
        order=2,
        instructions=(
            "What standardized open-source schema taxonomy defines normalized field names (e.g. `process.parent.name`, "
            "`source.ip`, `destination.port`) across enterprise endpoint and network telemetry? (Answer: 'ECS')."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=60,
        accepted_answers=["ECS", "ecs", "Elastic Common Schema"],
        hint="Elastic Common Schema (ECS) standardizes field naming across heterogeneous security tools, enabling universal detection rules that execute seamlessly across enterprise environments.",
    ),
    TaskDefinition(
        task_id="task-03-attck-lsass-dumping-mapping",
        title="MITRE ATT&CK: OS Credential Dumping (LSASS)",
        order=3,
        instructions=(
            "In enterprise credential access attacks, adversaries commonly target the Local Security Authority "
            "Subsystem Service (LSASS) process to extract plain-text passwords and Kerberos tickets. "
            "What is the MITRE ATT&CK sub-technique ID for LSASS Memory dumping? (e.g. 'T1003.001')."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["T1003.001", "t1003.001"],
        hint="MITRE ATT&CK sub-technique T1003.001 covers OS Credential Dumping via LSASS Memory, commonly executed via procdump, Mimikatz, or MiniDumpWriteDump API abuse.",
    ),
    TaskDefinition(
        task_id="task-04-capstone-pipeline-emulation",
        title="Production Capstone Pipeline Emulation",
        order=4,
        instructions=(
            "Inspect `/var/log/detection/capstone_enterprise_pipeline.json` on the attacker workstation. "
            "Execute the capstone production tool with `--emulate-production` to run the complete end-to-end "
            "lifecycle evaluation across multi-tier telemetry and obtain your verification token."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=70,
        accepted_answers=["CAPSTONE_PIPELINE_VERIFIED"],
        hint="The production capstone evaluation exercises end-to-end detection engineering: ingesting multi-stage attack telemetry, executing correlation logic, and scoring detection coverage.",
    ),
    TaskDefinition(
        task_id="task-05-capstone-pipeline-challenge",
        title="Independent Challenge: Production Deployment & Gate Validation",
        order=5,
        instructions=(
            "Tune production sensitivity thresholds and baseline suppressions with `--tune-production`, "
            "then submit the challenge with `--challenge` to achieve capstone certification validation."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=80,
        accepted_answers=["CAPSTONE_PIPELINE_VALIDATED"],
        hint="Validating the capstone pipeline certifies that your detection engineering architecture achieves 100% true positive detection rate with 0% false positives across production telemetry.",
    ),
    TaskDefinition(
        task_id="task-06-capstone-pipeline-quiz",
        title="Detection Engineering Capstone Assessment",
        order=6,
        instructions="Complete the 4-question technical assessment on enterprise detection architecture, continuous validation, and production governance.",
        task_type=TaskType.QUIZ,
        xp_reward=40,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What metric evaluates the ratio of actionable true-positive security alerts to total alerts generated by a detection rule?",
                options=[
                    "Signal-to-Noise Ratio (SNR) / High-Fidelity Alert Rate.",
                    "Round-Trip Network Ping Time.",
                    "Hard Drive Sector Seek Latency.",
                    "Graphics Processing Unit Core Clock.",
                ],
                correct_index=0,
                explanation="Signal-to-Noise Ratio (SNR) measures the proportion of genuine, actionable security alerts compared to non-actionable noise or benign false alarms.",
            ),
            QuizQuestion(
                id="q2",
                question="How should a mature detection engineering team handle telemetry schema drift when a vendor updates their endpoint log format?",
                options=[
                    "Implement schema normalization layers (ECS/CIM) and automated CI regression tests that alert engineers when field schemas mutate.",
                    "Disable all detection rules indefinitely.",
                    "Switch off security event logging across all domain controllers.",
                    "Ignore the updates and assume queries will continue working.",
                ],
                correct_index=0,
                explanation="Normalization layers decouple rule logic from raw event schemas, and automated CI pipelines catch schema drift before production alerts break.",
            ),
            QuizQuestion(
                id="q3",
                question="What is the role of purple team adversary emulation in the detection engineering lifecycle?",
                options=[
                    "Providing realistic, empirical attack telemetry in controlled environments to validate that detection rules trigger reliably before real incidents occur.",
                    "Replacing all human security analysts with automated scripts.",
                    "Eliminating the need for firewalls and intrusion prevention systems.",
                    "Preventing developers from writing software code.",
                ],
                correct_index=0,
                explanation="Adversary emulation generates verified positive attack telemetry, allowing detection engineers to test and tune rules against authentic attacker tradecraft.",
            ),
            QuizQuestion(
                id="q4",
                question="Which organizational outcome is the primary objective of completing the entire NO ENTRY Detection Engineering track?",
                options=[
                    "Transforming security operations into a proactive, resilient, code-driven discipline that detects advanced adversaries with high fidelity and zero operational downtime.",
                    "Generating maximum alert volume to keep SOC analysts constantly busy.",
                    "Relying entirely on out-of-the-box vendor default rules with no customization.",
                    "Replacing security teams with passive automated antivirus scanners.",
                ],
                correct_index=0,
                explanation="Detection Engineering empowers organizations to author, test, tune, and deploy robust detections-as-code, defeating sophisticated adversaries across the enterprise.",
            ),
        ],
    ),
]

ROOM_DETECTION_20_DEFINITION = RoomDefinition(
    room_id="detect-20-capstone-detection-pipeline",
    track=TrackEnum.DETECTION,
    room_number=20,
    title="Detection Engineering Capstone: Production Pipeline",
    short_description="Design and deploy a complete production detection pipeline: author, test against attack logs, tune, and deploy.",
    difficulty="Advanced",
    estimated_duration="90 min",
    prerequisites=[
        "detect-01-foundations-as-code",
        "detect-03-sigma-syntax",
        "detect-13-threshold-detections",
        "detect-14-correlation-rules",
        "detect-15-unit-testing-rules",
        "detect-19-ci-cd-detection-pipelines",
    ],
    required_practical_skills=[
        "Enterprise Detection Architecture",
        "Adversary Emulation Validation",
        "Schema Drift Mitigation",
        "High-Fidelity Tuning",
        "Production Governance",
    ],
    required_lab_type="container_duo",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Synthesize end-to-end detection engineering: threat intelligence, rule synthesis, unit testing, and deployment",
        "Author high-fidelity detection rules covering multi-stage attack chains (LSASS credential access T1003.001)",
        "Standardize multi-source telemetry using Elastic Common Schema (ECS) to prevent schema drift",
        "Validate detection performance with 100% true positive alert sensitivity and 0% false positives",
        "Publish production rules accompanied by operational SOC triage playbooks and automated rollback gates",
    ],
    assessment_criteria=[
        "Identify operational triage playbook requirements and ECS taxonomy",
        "Map LSASS memory dumping to MITRE ATT&CK T1003.001",
        "Emulate end-to-end production pipeline across enterprise telemetry",
        "Tune production sensitivity and validate capstone certification",
        "Score 100% on the enterprise detection governance and capstone mastery assessment",
    ],
    completion_requirements=[
        "Complete all 6 tasks sequentially",
        "Obtain verification and validation tokens from running lab services",
        "Pass the technical assessment quiz with 100%",
    ],
    total_xp=350,
    concept=ROOM_DETECTION_20_CONCEPT,
    tasks=ROOM_DETECTION_20_TASKS,
    default_port=8420,
)
