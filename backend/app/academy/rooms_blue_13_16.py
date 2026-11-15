"""
Complete curriculum definitions, tasks, concept explanations, and quizzes
for Blue Team Rooms 13–16:
- Room 13: Network Intrusion Detection (blue-13-network-intrusion-detection)
- Room 14: Threat Hunting (blue-14-threat-hunting)
- Room 15: Incident Triage (blue-15-incident-triage)
- Room 16: Incident Response (blue-16-incident-response)
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
# BLUE ROOM 13: NETWORK INTRUSION DETECTION (FULLY IMPLEMENTED)
# ============================================================================

ROOM_BLUE_13_CONCEPT = RoomConcept(
    overview=(
        "Network Intrusion Detection Systems (NIDS) inspect raw network packets across internal subnets and perimeter "
        "boundaries to detect unauthorized scanning, protocol anomalies, and command-and-control (C2) communication. "
        "Defensive analysts learn packet inspection using tcpdump and tshark, examine signature-based detection engines "
        "(Snort/Suricata), identify covert beaconing timing distributions, and deploy custom perimeter filtering rules."
    ),
    simple_analogy=(
        "Think of an international airport security checkpoint. An airport scanner does not open every passenger's sealed "
        "luggage immediately unless anomalous characteristics appear. A Network Intrusion Detection System is like the "
        "automated X-ray screener: it monitors the entire stream of passengers and bags (promiscuous packet capture) in "
        "real time. When an anomalous metallic object or illegal contour matches a threat signature (Snort rule), or "
        "when someone repeatedly walks past restricted doorways testing every locked handle (TCP SYN port scan), the system "
        "immediately alerts the security dispatch center (SOC alert)."
    ),
    technical_term="Network Intrusion Detection (NIDS) vs Prevention (NIPS) & Signature / Anomaly Analysis (MITRE ATT&CK T1046 / T1071.001)",
    technical_definition=(
        "A Network Intrusion Detection System operates in passive (promiscuous / TAP / SPAN port) mode, analyzing mirrored "
        "Ethernet frames, IP headers, TCP/UDP streams, and application payloads against deterministic signature sets (Snort/Suricata rules) "
        "and statistical baseline anomalies without introducing latency or inline single-points-of-failure. NIPS operates inline to block "
        "traffic directly. Key detection techniques include TCP half-open SYN scan tracking (T1046), protocol header malformations, "
        "and low-jitter periodic beaconing over standard web protocols (T1071.001)."
    ),
    cybersecurity_context=(
        "Perimeter firewalls only permit or deny based on IP, port, and protocol headers. Modern adversaries establish covert C2 "
        "channels over standard ports like 80, 443, and 8443 or probe exposed perimeter assets with SYN sweeps. NIDS provides deep packet "
        "visibility to spot abnormal beacon intervals, mismatched protocol handshakes, and reconnaissance before exploitation succeeds."
    ),
    why_it_matters=(
        "Over 90% of advanced persistent threats (APTs) rely on covert network channels for command execution and data exfiltration. "
        "Without deep NIDS telemetry and automated signature tuning, network perimeters remain blind to internal lateral movement."
    ),
    demonstration=(
        "1. Network Packet Capture & Tshark Dissection:\n"
        "   $ tshark -r /var/log/nids_traffic.pcap -c 10\n"
        "   Review mirrored PCAP stream capturing DMZ perimeter ingress and egress.\n\n"
        "2. Reconnaissance & SYN Scan Detection:\n"
        "   $ python3 /home/operator/tools/inspect_nids.py --scan\n"
        "   Correlate half-open SYN packets across multiple destination ports to uncover scanning source IP.\n\n"
        "3. Live NIDS Telemetry & Alert Stream:\n"
        "   GET /api/nids/traffic and GET /api/nids/alerts on port 8213.\n\n"
        "4. Deploy Snort / Suricata Signature Rule:\n"
        "   POST /api/nids/rules -> Deploy rule detecting suspicious C2 beaconing on port 8443.\n\n"
        "5. Intrusion Correlation Challenge:\n"
        "   POST /challenge -> Submit validated scanner IP, C2 beacon IP, and threat classification to receive verification token."
    ),
    remediation_guide=(
        "1. Deploy NIDS sensors on SPAN/TAP ports monitoring all DMZ egress and internal core VLAN switches.\n"
        "2. Keep Snort/Suricata rule sets updated with current threat intelligence feeds (Emerging Threats / ET Open).\n"
        "3. Tune threshold alerts for SYN scans (e.g. alert on >20 SYN packets to closed ports within 10 seconds).\n"
        "4. Enforce strict egress proxy filtering, inspecting TLS SNI headers and blocking unapproved external destination IPs.\n"
        "5. Implement automated firewall blocklist automation via API when NIDS severity reaches high confidence."
    ),
)

ROOM_BLUE_13_TASKS = [
    TaskDefinition(
        task_id="task-01-nids-architecture-dissection",
        order=1,
        title="NIDS Architecture & Monitoring Modes",
        instructions=(
            "Security architects must understand how intrusion detection sensors are integrated into corporate networks.\n\n"
            "What deployment mode allows a NIDS sensor to receive copies of all network packets via a switch SPAN or "
            "network TAP without sitting directly in the transmission path or causing network latency?"
        ),
        task_type=TaskType.QUESTION,
        question="What deployment mode receives copied packets via a SPAN/TAP port without sitting inline in the traffic path?",
        hint="It is also known as passive or promiscuous monitoring mode.",
        xp_reward=50,
        accepted_answers=[
            "Passive",
            "passive",
            "Passive Mode",
            "Promiscuous",
            "promiscuous",
            "Promiscuous Mode",
            "Passive Monitoring",
            "SPAN",
            "TAP",
        ],
        mistake_explanations={
            "inline": "Inline mode is used by NIPS (Intrusion Prevention Systems) or firewalls, where packets physically pass through the device and can introduce latency.",
            "active": "Active mode actively intercepts or drops packets inline; passive/promiscuous mode passively inspects mirrored traffic.",
        },
    ),
    TaskDefinition(
        task_id="task-02-nids-reconnaissance-investigation",
        order=2,
        title="Network Reconnaissance & SYN Scan Investigation",
        instructions=(
            "Inspect the captured network telemetry on your workstation or query the live NIDS sensor API on port 8213:\n"
            "  `tshark -r /var/log/nids_traffic.pcap -Y \"tcp.flags.syn==1 && tcp.flags.ack==0\"`\n"
            "  Or: `curl -s http://10.10.14.90:8213/api/nids/traffic`\n"
            "  Or: `python3 /home/operator/tools/inspect_nids.py --scan`\n\n"
            "Identify the external source IP address conducting a stealthy TCP SYN sweep across multiple DMZ ports."
        ),
        task_type=TaskType.QUESTION,
        question="What is the adversary's source IP address conducting the port scan?",
        hint="Examine which external IP sends SYN packets to ports 21, 22, 80, 443, 8080, and 8443.",
        xp_reward=60,
        accepted_answers=["198.51.100.99"],
        mistake_explanations={
            "203.0.113.88": "203.0.113.88 is the external C2 server destination receiving covert beacon connections, not the scanning IP.",
            "10.10.14.90": "10.10.14.90 is the local sensor host being probed.",
        },
    ),
    TaskDefinition(
        task_id="task-03-covert-beacon-detection",
        order=3,
        title="Covert C2 Beaconing & Protocol Anomaly Identification",
        instructions=(
            "Examine the NIDS alert stream and traffic telemetry for periodic outbound beaconing connections:\n"
            "  `curl -s http://10.10.14.90:8213/api/nids/alerts`\n"
            "  Or: `python3 /home/operator/tools/inspect_nids.py --beacon`\n\n"
            "Identify the external C2 destination IP address receiving regular outbound heartbeat beacons from internal hosts."
        ),
        task_type=TaskType.QUESTION,
        question="What is the external destination IP address receiving covert C2 beacon traffic?",
        hint="Look for periodic outbound connections to port 8443 occurring every 15 seconds.",
        xp_reward=70,
        accepted_answers=["203.0.113.88"],
        mistake_explanations={
            "198.51.100.99": "198.51.100.99 is the port scanner source IP. Look for the external IP receiving repetitive outbound beacon heartbeats.",
            "10.10.20.15": "10.10.20.15 is the internal compromised host initiating the beacon, not the external destination IP.",
        },
    ),
    TaskDefinition(
        task_id="task-04-snort-rule-deployment",
        order=4,
        title="Snort / Suricata NIDS Rule Deployment",
        instructions=(
            "Security engineers author Snort/Suricata signature rules to detect specific traffic patterns.\n\n"
            "Deploy a custom NIDS rule to flag covert C2 egress on port 8443 by submitting a POST request to the sensor:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"rule_name\":\"RULE_NIDS_COVERT_BEACON\",\"protocol\":\"tcp\",\"action\":\"alert\",\"dest_port\":8443,\"content\":\"HEARTBEAT_V2\"}' http://10.10.14.90:8213/api/nids/rules`\n\n"
            "Submit the verification token returned upon successful rule deployment."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned upon deploying the custom NIDS rule.",
        hint="Inspect the verification_token field in the JSON response from /api/nids/rules.",
        xp_reward=70,
        accepted_answers=["NIDS_SNORT_RULE_ACTIVE"],
        mistake_explanations={
            "RULE_DEPLOYED": "RULE_DEPLOYED is the status value. Enter the exact verification_token string.",
        },
    ),
    TaskDefinition(
        task_id="task-05-intrusion-correlation-challenge",
        order=5,
        title="Independent Challenge: Network Intrusion Correlation",
        instructions=(
            "Synthesize your network telemetry findings. Verify the port scanning source IP, covert C2 destination IP, "
            "and threat classification by submitting a POST request to the challenge endpoint on port 8213:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"scanner_ip\":\"198.51.100.99\",\"c2_ip\":\"203.0.113.88\",\"threat_classification\":\"PORT_SCAN_AND_C2_BEACON\"}' http://10.10.14.90:8213/challenge`\n\n"
            "Submit the verification token returned upon successful verification."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned by the NIDS challenge endpoint.",
        hint="Deploy your custom rule first, ensure your lab session is active, and submit scanner_ip (198.51.100.99), c2_ip (203.0.113.88), and threat_classification.",
        xp_reward=50,
        accepted_answers=[
            "NIDS_INTRUSION_DETECTED",
            "NIDS_INTRUSION_CORRELATION_CONFIRMED",
        ],
    ),
    TaskDefinition(
        task_id="task-06-nids-quiz",
        order=6,
        title="Network Intrusion Detection & Traffic Analysis Assessment",
        instructions="Answer the following 5 technical questions to verify comprehensive understanding of NIDS/NIPS architectures, TCP flag analysis, signature engines, and covert communication detection.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question technical assessment.",
        hint="Review passive SPAN port taps, TCP handshake flags, Snort syntax, and beacon jitter.",
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is the primary operational difference between a NIDS and a NIPS?",
                options=[
                    "A NIDS passively inspects mirrored traffic copies without blocking packets, while a NIPS sits inline and can drop malicious traffic in real time.",
                    "A NIDS only inspects encrypted TLS traffic, whereas a NIPS only inspects UDP packets.",
                    "A NIDS is installed directly on endpoints, whereas a NIPS runs exclusively on DNS servers.",
                    "A NIDS cannot read TCP port numbers.",
                ],
                correct_option_index=0,
                explanation="NIDS runs passively on mirrored SPAN/TAP ports to avoid latency, whereas NIPS sits inline to actively drop malicious connections.",
            ),
            QuizQuestion(
                id="q2",
                question="In a stealthy TCP half-open SYN scan (nmap -sS), how does the scanning host respond when the target port replies with SYN-ACK?",
                options=[
                    "The scanning host immediately sends a RST (Reset) packet to close the connection without completing the 3-way handshake.",
                    "The scanning host sends a FIN packet followed by a DHCP request.",
                    "The scanning host sends an HTTP GET request.",
                    "The scanning host waits 30 seconds and completes the connection with an ACK.",
                ],
                correct_option_index=0,
                explanation="In a SYN half-open scan, the scanner responds with RST after receiving SYN-ACK to avoid establishing a full TCP session, minimizing application logging.",
            ),
            QuizQuestion(
                id="q3",
                question="What characteristic in network traffic telemetry strongly differentiates automated adversary C2 beaconing from human web browsing?",
                options=[
                    "C2 beacons typically exhibit highly regular connection intervals with very low timing jitter and fixed payload sizes.",
                    "Human web browsing always occurs over TCP port 23 (Telnet).",
                    "C2 beaconing never uses DNS or HTTP protocols.",
                    "Human browsing always transmits more than 100 gigabytes per second.",
                ],
                correct_option_index=0,
                explanation="Automated malware beacons communicate at predictable, periodic time intervals with low jitter, contrasting with irregular human browsing bursts.",
            ),
            QuizQuestion(
                id="q4",
                question="In standard Snort / Suricata rule syntax, which component specifies what the engine does when a signature match occurs?",
                options=[
                    "The rule action (such as 'alert', 'drop', or 'pass') at the start of the rule header.",
                    "The payload length parameter inside the HTTP cookie.",
                    "The subnet mask in the routing table.",
                    "The TCP sequence number.",
                ],
                correct_option_index=0,
                explanation="The first token in a Snort rule (the rule action) directs the engine on how to react (e.g. alert, drop, log, reject).",
            ),
            QuizQuestion(
                id="q5",
                question="What MITRE ATT&CK technique code corresponds to Network Service Discovery / Port Scanning?",
                options=[
                    "T1046",
                    "T1059",
                    "T1078",
                    "T1003",
                ],
                correct_option_index=0,
                explanation="MITRE ATT&CK T1046 defines Network Service Discovery (scanning hosts and ports across a network).",
            ),
        ],
    ),
]

ROOM_BLUE_13_DEFINITION = RoomDefinition(
    room_id="blue-13-network-intrusion-detection",
    track=TrackEnum.BLUE,
    room_number=13,
    title="Network Intrusion Detection",
    short_description="Analyze mirrored PCAP streams with tshark, detect stealthy SYN scans and covert C2 beaconing, author Snort rules, and correlate intrusion telemetry.",
    difficulty="Intermediate",
    estimated_duration="50 min",
    concept=ROOM_BLUE_13_CONCEPT,
    tasks=ROOM_BLUE_13_TASKS,
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
)


# ============================================================================
# BLUE ROOM 14: THREAT HUNTING (FULLY IMPLEMENTED)
# ============================================================================

ROOM_BLUE_14_CONCEPT = RoomConcept(
    overview=(
        "Hypothesis-Driven Threat Hunting is the proactive, iterative defense discipline of searching through enterprise "
        "telemetry to detect stealthy adversary activity that has evaded automated SIEM and EDR detection rules. Defensive "
        "analysts formulate hunting hypotheses grounded in MITRE ATT&CK tactics, correlate process creation and parent-child "
        "lineage, uncover hidden persistence mechanisms, and convert hunting discoveries into permanent Sigma detection rules."
    ),
    simple_analogy=(
        "Think of a game reserve protected by automated perimeter fences and motion sensors. Automated sensors (SIEM alerts) "
        "ring whenever someone cuts a fence wire. But a skilled poacher who wears camouflage and uses existing game trails "
        "(Living-off-the-Land Binaries) will never trip an automated alarm. A wildlife tracker (Threat Hunter) doesn't wait "
        "for an alarm: they form a hypothesis ('if a poacher came through the north valley, they would leave bent reeds near "
        "the watering hole'), proactively hike into the reserve, inspect subtle footprints (telemetry logs), discover the "
        "hidden camp, and then install a permanent motion sensor at that exact spot (Sigma detection rule)."
    ),
    technical_term="Hypothesis-Driven Threat Hunting & Process Lineage Correlation (MITRE ATT&CK T1059.001 / T1053.005)",
    technical_definition=(
        "Threat hunting is proactive, hypothesis-led inquiry into endpoint and network telemetry. Rather than reacting to alerts, "
        "hunters begin with an intelligence-informed hypothesis (e.g., 'An adversary has gained execution via macro-enabled document and "
        "spawned an obfuscated LOLBIN shell'). Hunters analyze Windows Event ID 4688 / Sysmon Event ID 1 process trees, inspecting ProcessId, "
        "ParentProcessId, CommandLine parameters, and persistence locations like Scheduled Tasks (T1053.005) or Registry Run keys (T1547.001)."
    ),
    cybersecurity_context=(
        "Sophisticated threat actors routinely bypass static antivirus and signature-based SIEM rules using built-in Windows utilities "
        "(PowerShell, WMI, mshta, certutil). Threat hunting is necessary to find dwell time—the median days an attacker remains inside "
        "an enterprise before discovery—and evict them before ransomware deployment or data exfiltration occurs."
    ),
    why_it_matters=(
        "Organizations that rely solely on automated alerting experience an average dwell time of over 20 days. Proactive threat hunting "
        "reduces attacker dwell time to hours and drives continuous hardening of SOC detection rules."
    ),
    demonstration=(
        "1. Interrogate Endpoint Process Telemetry:\n"
        "   $ cat /var/log/threat_hunt_telemetry.json | jq .\n"
        "   Examine endpoint process creation logs and parent-child relationships.\n\n"
        "2. Formulate Hypothesis & Search LOLBIN Spawning:\n"
        "   $ python3 /home/operator/tools/hunt_query.py --parent winword.exe\n"
        "   Trace Microsoft Word spawning an obfuscated powershell.exe subprocess.\n\n"
        "3. Live Hunting Telemetry & Hypotheses API:\n"
        "   GET /api/hunt/telemetry and GET /api/hunt/hypotheses on port 8214.\n\n"
        "4. Author and Deploy Sigma Hunting Query:\n"
        "   POST /api/hunt/queries -> Deploy Sigma rule for abnormal Word parent process execution.\n\n"
        "5. Threat Hunting Validation Challenge:\n"
        "   POST /challenge -> Submit validated MITRE technique, malicious PID, and persistence mechanism to earn verification token."
    ),
    remediation_guide=(
        "1. Enforce Attack Surface Reduction (ASR) rules: block Office applications from creating child processes.\n"
        "2. Implement PowerShell Constrained Language Mode and enable Script Block Logging (Event ID 4104).\n"
        "3. Audit scheduled tasks enterprise-wide using `Get-ScheduledTask` and baseline legitimate administrative tasks.\n"
        "4. Convert verified threat hunting findings into permanent Sigma and SIEM alerting rules.\n"
        "5. Restrict execution of LOLBINs (certutil, mshta, regsvr32) using Windows AppLocker or Windows Defender Application Control (WDAC)."
    ),
)

ROOM_BLUE_14_TASKS = [
    TaskDefinition(
        task_id="task-01-threat-hunting-methodology",
        order=1,
        title="Hypothesis-Driven Threat Hunting Methodology",
        instructions=(
            "Threat hunting differs fundamentally from reactive SOC alert monitoring. Hunters formulate testable hypotheses "
            "based on threat intelligence, attacker techniques, and known organizational blind spots.\n\n"
            "What MITRE ATT&CK technique code describes adversaries abusing the built-in PowerShell command-line "
            "interpreter to execute malicious scripts and commands?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the MITRE ATT&CK technique code for PowerShell execution?",
        hint="It is a sub-technique of Command and Scripting Interpreter (T1059).",
        xp_reward=50,
        accepted_answers=["T1059.001", "T1059.001 - PowerShell", "T1059.001: PowerShell"],
        mistake_explanations={
            "T1059": "T1059 is the parent technique (Command and Scripting Interpreter). Provide the exact sub-technique code for PowerShell: T1059.001.",
            "T1059.003": "T1059.003 is Windows Command Shell (cmd.exe), not PowerShell.",
        },
    ),
    TaskDefinition(
        task_id="task-02-hunting-process-lineage",
        order=2,
        title="Hunting Process Execution & Parent-Child Lineage Anomalies",
        instructions=(
            "Examine the endpoint process creation telemetry on your workstation or query the hunting API on port 8214:\n"
            "  `cat /var/log/threat_hunt_telemetry.json`\n"
            "  Or: `curl -s http://10.10.14.90:8214/api/hunt/telemetry`\n"
            "  Or: `python3 /home/operator/tools/hunt_query.py --parent winword.exe`\n\n"
            "Identify the malicious Process ID (PID) of the obfuscated `powershell.exe` process spawned directly by `winword.exe`."
        ),
        task_type=TaskType.QUESTION,
        question="What is the PID of the suspicious PowerShell process spawned by winword.exe?",
        hint="Find the event where parent_image is winword.exe and image is powershell.exe, then check its pid field.",
        xp_reward=60,
        accepted_answers=["4820"],
        mistake_explanations={
            "2110": "2110 is the Parent Process ID (PPID) of winword.exe. We are looking for the child process ID (PID) of powershell.exe.",
            "1044": "1044 is the PID of svchost.exe.",
        },
    ),
    TaskDefinition(
        task_id="task-03-hunting-persistence-artifacts",
        order=3,
        title="Uncovering Hidden Persistence Artifacts",
        instructions=(
            "Adversaries establish persistence so they can maintain access even if an initial process terminates.\n\n"
            "Analyze the persistence artifacts in the telemetry logs or via the hunting API on port 8214:\n"
            "  `python3 /home/operator/tools/hunt_query.py --persistence`\n\n"
            "What is the name of the hidden scheduled task created by the adversary to execute their encoded payload on a recurring schedule?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the name of the hidden scheduled task used for persistence?",
        hint="Examine the scheduled_tasks section in the telemetry data. Look for a task path under AppID or TelemetrySync.",
        xp_reward=70,
        accepted_answers=[
            "TelemetrySync",
            "telemetrysync",
            "\\Microsoft\\Windows\\AppID\\TelemetrySync",
            "Microsoft\\Windows\\AppID\\TelemetrySync",
        ],
        mistake_explanations={
            "GoogleUpdateTaskMachineUA": "GoogleUpdateTaskMachineUA is a legitimate third-party software update task.",
            "DefenderHealthCheck": "DefenderHealthCheck is a benign operational task.",
        },
    ),
    TaskDefinition(
        task_id="task-04-sigma-query-authoring",
        order=4,
        title="Sigma Hunting Query Authoring & Deployment",
        instructions=(
            "Once a threat hunting hypothesis is confirmed, hunters author detection logic in open Sigma format "
            "so the SOC can deploy it permanently across SIEM and EDR platforms.\n\n"
            "Deploy your correlation query via POST to the hunting gateway:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"query_name\":\"SIGMA_OFFICE_SPAWNS_POWERSHELL\",\"mitre_technique\":\"T1059.001\",\"parent_process\":\"winword.exe\",\"child_process\":\"powershell.exe\"}' http://10.10.14.90:8214/api/hunt/queries`\n\n"
            "Submit the verification token returned upon deploying the query."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned upon deploying the Sigma hunting query.",
        hint="Inspect the verification_token field in the JSON response from /api/hunt/queries.",
        xp_reward=70,
        accepted_answers=["HUNT_SIGMA_QUERY_ACTIVE"],
        mistake_explanations={
            "QUERY_DEPLOYED": "QUERY_DEPLOYED is the status value. Enter the exact verification_token string.",
        },
    ),
    TaskDefinition(
        task_id="task-05-threat-hunting-challenge",
        order=5,
        title="Independent Challenge: Threat Hypothesis Confirmation",
        instructions=(
            "Validate your complete threat hunting findings. Submit the verified MITRE technique code, the malicious child "
            "process PID, and the persistence mechanism type via POST to the challenge endpoint on port 8214:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"mitre_technique\":\"T1059.001\",\"malicious_pid\":4820,\"persistence_mechanism\":\"SCHEDULED_TASK\"}' http://10.10.14.90:8214/challenge`\n\n"
            "Submit the verification token returned upon successful verification."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned by the Threat Hunting challenge endpoint.",
        hint="Deploy your Sigma query first, ensure your lab session is active, and submit mitre_technique (T1059.001), malicious_pid (4820), and persistence_mechanism (SCHEDULED_TASK).",
        xp_reward=50,
        accepted_answers=[
            "THREAT_HUNT_HYPOTHESIS_CONFIRMED",
            "HUNT_CAMPAIGN_VALIDATED",
        ],
    ),
    TaskDefinition(
        task_id="task-06-threat-hunting-quiz",
        order=6,
        title="Threat Hunting Principles & Telemetry Correlation Assessment",
        instructions="Answer the following 5 technical questions to verify comprehensive mastery of hypothesis formulation, process lineage analysis, LOLBIN abuse, and detection engineering.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question technical assessment.",
        hint="Review proactive vs reactive defense, Sysmon Event ID 1, LOLBINs, and Sigma rule format.",
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is the foundational difference between reactive SOC alert monitoring and proactive threat hunting?",
                options=[
                    "Reactive monitoring responds to alerts triggered by known rules, while proactive hunting searches telemetry for unalerted threats based on hypotheses.",
                    "Reactive monitoring only looks at firewalls, while threat hunting only looks at printer logs.",
                    "Threat hunting is performed exclusively by automated bots without human involvement.",
                    "Threat hunting requires shutting down the production network before searching for indicators.",
                ],
                correct_option_index=0,
                explanation="Threat hunting is proactive and hypothesis-driven, designed to discover undetected adversaries that have evaded automated detection systems.",
            ),
            QuizQuestion(
                id="q2",
                question="Which Sysmon / Windows Security Event ID provides the most critical telemetry for analyzing process creation and command-line arguments?",
                options=[
                    "Sysmon Event ID 1 / Windows Security Event ID 4688",
                    "Windows Security Event ID 4624",
                    "Windows System Event ID 7036",
                    "Windows Security Event ID 1102",
                ],
                correct_option_index=0,
                explanation="Sysmon Event ID 1 and Security Event ID 4688 record detailed process creation, including ParentImage, Image, and full CommandLine arguments.",
            ),
            QuizQuestion(
                id="q3",
                question="Why do adversaries frequently utilize Living-off-the-Land Binaries (LOLBINs) such as certutil.exe, powershell.exe, and mshta.exe?",
                options=[
                    "Because LOLBINs are legitimate, trusted system binaries already signed by the OS vendor, blending in with administrative traffic and bypassing simple hash blocklists.",
                    "Because LOLBINs disable hardware encryption on CPU memory chips.",
                    "Because LOLBINs prevent the system from connecting to the internet.",
                    "Because LOLBINs are open-source Python scripts that run without an interpreter.",
                ],
                correct_option_index=0,
                explanation="LOLBINs are native, digitally signed OS utilities that attackers abuse to execute commands and download files while evading signature-based file scanners.",
            ),
            QuizQuestion(
                id="q4",
                question="What is the primary role of the open Sigma rule standard in detection engineering?",
                options=[
                    "It provides a generic, vendor-agnostic YAML signature format that can be converted into queries for Splunk, Elastic, Microsoft Sentinel, and QRadar.",
                    "It replaces the need for operating system kernel updates.",
                    "It automatically deletes infected hard drives across the enterprise.",
                    "It encrypts all outbound email attachments using RSA 4096.",
                ],
                correct_option_index=0,
                explanation="Sigma is a generic YAML-based detection format that enables defenders to share hunting logic and translate it into queries for any SIEM platform.",
            ),
            QuizQuestion(
                id="q5",
                question="When threat hunting in process trees, which pattern represents a severe anomaly indicating client-side exploitation?",
                options=[
                    "An office productivity application (e.g. WINWORD.EXE or EXCEL.EXE) spawning a script interpreter (powershell.exe or cmd.exe).",
                    "explorer.exe spawning chrome.exe when a user double-clicks an icon.",
                    "services.exe managing standard Windows service background threads.",
                    "taskmgr.exe displaying active process lists.",
                ],
                correct_option_index=0,
                explanation="Office applications should never spawn command-line shells under normal business operation; doing so is a hallmark of malicious macro exploitation.",
            ),
        ],
    ),
]

ROOM_BLUE_14_DEFINITION = RoomDefinition(
    room_id="blue-14-threat-hunting",
    track=TrackEnum.BLUE,
    room_number=14,
    title="Threat Hunting",
    short_description="Formulate hypotheses based on MITRE ATT&CK, trace abnormal process lineage (winword spawning powershell), uncover hidden persistence, and author Sigma rules.",
    difficulty="Intermediate",
    estimated_duration="50 min",
    concept=ROOM_BLUE_14_CONCEPT,
    tasks=ROOM_BLUE_14_TASKS,
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
)


# ============================================================================
# BLUE ROOM 15: INCIDENT TRIAGE (FULLY IMPLEMENTED)
# ============================================================================

ROOM_BLUE_15_CONCEPT = RoomConcept(
    overview=(
        "Incident Triage is the critical first-response phase in Security Operations where incoming alerts are vetted, "
        "prioritized, and analyzed to determine scope, severity, and operational impact. SOC analysts learn to distinguish "
        "true positives from benign false positives, evaluate asset criticality, determine the blast radius of compromised "
        "credentials, construct precise chronological timelines, and execute formal incident escalation."
    ),
    simple_analogy=(
        "Think of an emergency hospital trauma center. When thirty people walk into the emergency room, the triage nurse "
        "does not treat patients on a first-come, first-served basis. A patient with a small paper cut (low-severity false "
        "positive alert) is directed to basic care, while a patient with severe chest pain (critical true-positive data breach) "
        "is immediately rushed to the surgical resuscitation unit. In a cybersecurity SOC, Incident Triage is the rigorous "
        "process of examining incoming telemetry, separating benign operational noise from catastrophic breaches, and immediately "
        "routing high-impact incidents to specialized incident response teams."
    ),
    technical_term="Alert Triage, True Positive vs False Positive & Severity Scoring (CVSS / NIST SP 800-61 Rev 2)",
    technical_definition=(
        "Security incident triage evaluates raw security telemetry to categorize events into True Positives (actual malicious "
        "activity), False Positives (benign activity mistakenly flagged as malicious), and Benign True Positives (authorized activity "
        "matching a rule signature, like scheduled penetration tests). Priority and severity are computed based on asset criticality "
        "(Tier 1 domain controllers and production databases vs development workstations), exploit likelihood, and blast radius "
        "(scope of accessible identities, networks, and data volumes)."
    ),
    cybersecurity_context=(
        "Modern enterprise SOCs receive thousands of alerts daily. Alert fatigue causes analysts to overlook legitimate adversary "
        "compromises if triage processes are disorganized or superficial. Structured triage ensures that high-impact threats—such as "
        "database credential dumping and unauthorized cloud data exfiltration—are escalated and contained within minutes."
    ),
    why_it_matters=(
        "The difference between a contained breach and an enterprise catastrophe lies in the first 60 minutes of triage. Rapid, accurate "
        "triage halts adversary lateral movement before data destruction or extortion occurs."
    ),
    demonstration=(
        "1. Ingest SOC Alert Queue:\n"
        "   $ cat /var/log/soc_triage_alerts.json | jq .\n"
        "   Review active alerts in the SOC queue to identify high-priority anomalies.\n\n"
        "2. Interrogate Supporting Telemetry & Asset Criticality:\n"
        "   $ python3 /home/operator/tools/triage_tool.py --alert ALT-8820\n"
        "   Evaluate asset DB-PROD-01 (Tier 1 Production Database) and abnormal off-hours access.\n\n"
        "3. Live Triage API & Evidence Stream:\n"
        "   GET /api/triage/alerts and GET /api/triage/evidence on port 8215.\n\n"
        "4. Submit Formal Triage Classification:\n"
        "   POST /api/triage/classify -> Submit True Positive classification and Critical severity rating.\n\n"
        "5. Incident Escalation & Timeline Challenge:\n"
        "   POST /challenge -> Submit compromised account, exfiltration volume, and external destination IP to earn verification token."
    ),
    remediation_guide=(
        "1. Define clear SLA thresholds for triage: Critical alerts triaged within 15 minutes, High within 30 minutes.\n"
        "2. Maintain an up-to-date Asset Criticality Matrix (Tier 1: Identity/Data, Tier 2: App Servers, Tier 3: Workstations).\n"
        "3. Tune noisy correlation rules to eliminate recurring false positives from authorized scanners and backups.\n"
        "4. Enforce mandatory multi-factor authentication and conditional access for database administrative credentials.\n"
        "5. Implement automated playbooks that immediately collect volatile memory and session artifacts upon critical escalation."
    ),
)

ROOM_BLUE_15_TASKS = [
    TaskDefinition(
        task_id="task-01-triage-severity-matrix",
        order=1,
        title="Alert Triage & Severity Matrix Formulation",
        instructions=(
            "Security analysts must rapidly categorize alerts according to operational impact and evidence veracity.\n\n"
            "What security classification term describes an alert that correctly identifies genuine, unauthorized malicious "
            "adversary activity occurring on an organizational asset?"
        ),
        task_type=TaskType.QUESTION,
        question="What term describes an alert that correctly identifies genuine malicious adversary activity?",
        hint="Distinguish between False Positive, Benign True Positive, and True Positive.",
        xp_reward=50,
        accepted_answers=[
            "True Positive",
            "true positive",
            "True-Positive",
            "true-positive",
            "TP",
        ],
        mistake_explanations={
            "false positive": "A False Positive occurs when benign, harmless activity is mistakenly flagged as malicious.",
            "false negative": "A False Negative occurs when an attack actually happens but no alert is generated at all.",
            "true negative": "A True Negative occurs when normal activity is correctly identified as normal without an alert.",
        },
    ),
    TaskDefinition(
        task_id="task-02-distinguishing-positives",
        order=2,
        title="Distinguishing True Positives from False Positives",
        instructions=(
            "Inspect the SOC alert queue on your workstation or query the triage API on port 8215:\n"
            "  `cat /var/log/soc_triage_alerts.json`\n"
            "  Or: `curl -s http://10.10.14.90:8215/api/triage/alerts`\n"
            "  Or: `python3 /home/operator/tools/triage_tool.py --list`\n\n"
            "Identify the Alert ID (e.g. ALT-XXXX) representing the confirmed Critical True Positive incident "
            "involving unauthorized database credential usage and bulk data egress."
        ),
        task_type=TaskType.QUESTION,
        question="What is the Alert ID of the confirmed critical data exfiltration incident?",
        hint="Review the alerts. ALT-8819 is an internal vulnerability scan; ALT-8821 is routine maintenance.",
        xp_reward=60,
        accepted_answers=["ALT-8820", "alt-8820"],
        mistake_explanations={
            "ALT-8819": "ALT-8819 is a routine automated vulnerability scanner from 10.10.14.5 against a staging server (False Positive).",
            "ALT-8821": "ALT-8821 is an automated nightly backup verification script.",
        },
    ),
    TaskDefinition(
        task_id="task-03-asset-blast-radius",
        order=3,
        title="Asset Impact & Blast Radius Determination",
        instructions=(
            "Investigate the specific evidence and asset records for alert ALT-8820:\n"
            "  `curl -s http://10.10.14.90:8215/api/triage/evidence`\n"
            "  Or: `python3 /home/operator/tools/triage_tool.py --alert ALT-8820`\n\n"
            "What is the service account identity that was compromised and used off-hours to dump database tables?"
        ),
        task_type=TaskType.QUESTION,
        question="What service account identity was compromised in the incident?",
        hint="Examine the username/identity field associated with the database connection on DB-PROD-01.",
        xp_reward=70,
        accepted_answers=["svc_db_sync", "svc_db_sync@voltcorp.internal"],
        mistake_explanations={
            "operator": "Operator is the local analyst account, not the compromised production service account.",
            "admin": "The compromised account is the specific service account `svc_db_sync` used for database synchronization.",
        },
    ),
    TaskDefinition(
        task_id="task-04-formal-triage-classification",
        order=4,
        title="Formal Triage Classification Submission",
        instructions=(
            "Once evidence is validated, the triage analyst must formally classify the alert in the case management system.\n\n"
            "Submit your formal triage classification via POST to the triage API on port 8215:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"alert_id\":\"ALT-8820\",\"classification\":\"TRUE_POSITIVE\",\"severity\":\"CRITICAL\",\"asset_id\":\"DB-PROD-01\"}' http://10.10.14.90:8215/api/triage/classify`\n\n"
            "Submit the verification token returned upon successful classification."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned upon formally classifying the alert.",
        hint="Inspect the verification_token field in the JSON response from /api/triage/classify.",
        xp_reward=70,
        accepted_answers=["TRIAGE_ALERT_CLASSIFIED_CRITICAL"],
        mistake_explanations={
            "ALERT_CLASSIFIED": "ALERT_CLASSIFIED is the status value. Enter the exact verification_token string.",
        },
    ),
    TaskDefinition(
        task_id="task-05-incident-escalation-challenge",
        order=5,
        title="Independent Challenge: Incident Escalation & Timeline Validation",
        instructions=(
            "Construct the full incident parameters and escalate to Incident Response. Submit the incident type, "
            "compromised account, external egress IP destination, and approximate exfiltrated data volume (in MB, e.g. 2400) "
            "via POST to the challenge endpoint on port 8215:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"incident_type\":\"DATA_EXFILTRATION\",\"compromised_account\":\"svc_db_sync\",\"egress_ip\":\"198.51.100.77\",\"exfil_volume_mb\":2400}' http://10.10.14.90:8215/challenge`\n\n"
            "Submit the verification token returned upon successful escalation."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned by the Incident Triage challenge endpoint.",
        hint="Classify the alert first, ensure your lab session is active, and submit incident_type, compromised_account (svc_db_sync), egress_ip (198.51.100.77), and exfil_volume_mb (2400).",
        xp_reward=50,
        accepted_answers=[
            "INCIDENT_TRIAGE_ESCALATION_VALIDATED",
            "TRIAGE_ESCALATION_CONFIRMED",
        ],
    ),
    TaskDefinition(
        task_id="task-06-incident-triage-quiz",
        order=6,
        title="Incident Triage & Escalation Principles Assessment",
        instructions="Answer the following 5 technical questions to verify comprehensive understanding of alert prioritization, blast radius assessment, false positive analysis, and escalation governance.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question technical assessment.",
        hint="Review triage SLAs, asset tiering, CVSS/severity calculation, and evidence verification.",
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is asset criticality considered a foundational factor in calculating incident severity during triage?",
                options=[
                    "Because compromise of a Tier 1 crown-jewel asset (e.g. Domain Controller, Customer Database) poses immediate existential business risk compared to a test lab host.",
                    "Because high-tier assets consume more electrical power in the datacenter.",
                    "Because low-tier assets do not generate Syslog messages.",
                    "Because cloud providers charge double for security incidents on development machines.",
                ],
                correct_option_index=0,
                explanation="Asset criticality directly dictates business impact: compromising core databases or identity infrastructure creates catastrophic risk compared to an isolated test system.",
            ),
            QuizQuestion(
                id="q2",
                question="What is the definition of 'Blast Radius' during security incident triage?",
                options=[
                    "The potential scope of lateral movement, accessible systems, accounts, and data an attacker could compromise from an initial foothold.",
                    "The physical damage radius caused by an overheating server battery.",
                    "The number of SIEM alerts generated per second by a firewall.",
                    "The network cable distance between the router and switch.",
                ],
                correct_option_index=0,
                explanation="Blast radius measures the total potential exposure and lateral movement reach available to an attacker from the compromised asset or credential.",
            ),
            QuizQuestion(
                id="q3",
                question="An authorized vulnerability scanner triggers 500 SQL injection alerts against a staging server during scheduled maintenance. How should these alerts be classified?",
                options=[
                    "Benign True Positive (or Authorized False Positive)",
                    "Catastrophic Zero-Day Breach",
                    "Malicious True Positive requiring immediate law enforcement escalation",
                    "Hardware Failure",
                ],
                correct_option_index=0,
                explanation="Authorized testing correctly matches exploit signatures but is benign and authorized, classifying it as a Benign True Positive.",
            ),
            QuizQuestion(
                id="q4",
                question="What is the primary danger of 'Alert Fatigue' in a Security Operations Center?",
                options=[
                    "Analysts overwhelmed by high volumes of noisy or false-positive alerts become desensitized and overlook genuine critical intrusions.",
                    "Computers run out of hard drive space when storing alert logs.",
                    "The internet bandwidth of the SOC becomes saturated.",
                    "Security analysts forget their passwords.",
                ],
                correct_option_index=0,
                explanation="Alert fatigue causes cognitive overload and desensitization, leading analysts to miss high-severity attacks hidden in high-volume noise.",
            ),
            QuizQuestion(
                id="q5",
                question="Under NIST SP 800-61 Rev 2 guidelines, what action should immediately follow the confirmation of a critical ongoing data exfiltration incident?",
                options=[
                    "Formal escalation to the Incident Response team and immediate activation of containment playbooks.",
                    "Closing the alert ticket and waiting for the weekly review meeting.",
                    "Emailing the adversary to request data deletion.",
                    "Reinstalling Windows on all analyst workstations.",
                ],
                correct_option_index=0,
                explanation="Once a critical ongoing incident is confirmed, triage immediately escalates the incident to the Incident Response team to execute rapid containment.",
            ),
        ],
    ),
]

ROOM_BLUE_15_DEFINITION = RoomDefinition(
    room_id="blue-15-incident-triage",
    track=TrackEnum.BLUE,
    room_number=15,
    title="Incident Triage",
    short_description="Triage incoming SOC alerts, differentiate True Positives from benign noise, evaluate asset blast radius (DB-PROD-01), and execute formal incident escalation.",
    difficulty="Intermediate",
    estimated_duration="45 min",
    concept=ROOM_BLUE_15_CONCEPT,
    tasks=ROOM_BLUE_15_TASKS,
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
)


# ============================================================================
# BLUE ROOM 16: INCIDENT RESPONSE (FULLY IMPLEMENTED)
# ============================================================================

ROOM_BLUE_16_CONCEPT = RoomConcept(
    overview=(
        "Incident Response (IR) is the structured operational methodology executed to contain, eradicate, recover from, "
        "and learn from confirmed cybersecurity incidents. Guided by recognized standards (NIST SP 800-61 Rev 2 and SANS PICERL), "
        "defenders practice rapid host containment, volatile evidence preservation respecting the Order of Volatility (RFC 3227), "
        "root-cause eradication of persistence and C2 sockets, service restoration, and post-incident lessons learned."
    ),
    simple_analogy=(
        "Think of a specialized municipal firefighting squad responding to a multi-story building fire. Firefighters do not "
        "start repainting the walls while the fire is blazing. First, they establish a containment perimeter around the building "
        "so the flames cannot spread to adjacent homes (Containment). Next, they enter with high-pressure hoses to systematically "
        "extinguish every hidden ember inside the walls (Eradication). Then, building engineers inspect the structure and restore "
        "electricity safely (Recovery). Finally, the fire marshal inspects electrical wiring to determine the exact cause and mandates "
        "new fire-code regulations to ensure it never happens again (Lessons Learned / Post-Incident Review)."
    ),
    technical_term="Incident Response Lifecycle, Volatile Evidence Preservation & Containment / Eradication (NIST SP 800-61 / RFC 3227)",
    technical_definition=(
        "The Incident Response lifecycle defines standardized phases: Preparation, Detection & Analysis, Containment, Eradication, "
        "Recovery, and Post-Incident Activity (Lessons Learned). Volatile digital evidence must be acquired adhering strictly to RFC 3227 "
        "Order of Volatility (CPU registers/cache -> routing tables/process tables/memory RAM -> temporary file systems -> disk storage -> "
        "remote logging). Containment isolates compromised hosts at network (802.1X/EDR isolate) and identity (token revocation) layers. "
        "Eradication purges malicious artifacts and closes adversary ingress vectors."
    ),
    cybersecurity_context=(
        "When an enterprise suffers a confirmed breach, ad-hoc or uncoordinated actions often destroy critical forensic evidence "
        "(such as rebooting an infected host and erasing volatile memory) or alert the adversary before containment is enforced, "
        "triggering immediate ransomware detonation. Structured IR frameworks provide a legally defensible, orderly containment sequence."
    ),
    why_it_matters=(
        "Properly executed Incident Response halts an attack, preserves forensic evidence admissible in legal proceedings, minimizes business "
        "downtime, and converts security failures into lasting architectural resilience."
    ),
    demonstration=(
        "1. Inspect Live Incident Status & Compromised Host:\n"
        "   $ python3 /home/operator/tools/ir_manager.py --status\n"
        "   Check active breach telemetry on host DB-PROD-01 (10.10.20.15) with active C2 socket.\n\n"
        "2. Review Order of Volatility & Forensic Artifacts:\n"
        "   GET /api/response/incident-status and GET /api/response/evidence on port 8216.\n\n"
        "3. Enforce Rapid Containment:\n"
        "   POST /api/response/contain -> Isolate DB-PROD-01 and revoke active session tokens.\n\n"
        "4. Eradicate Threat & Neutralize C2 Persistence:\n"
        "   POST /api/response/eradicate -> Terminate rogue process PID 3912 and remove persistence service.\n\n"
        "5. Complete Incident Response Lifecycle Challenge:\n"
        "   POST /challenge -> Submit validated IR incident parameters and standard governance token."
    ),
    remediation_guide=(
        "1. Maintain out-of-band incident response communication channels (signal, separate secure tenant) in case corporate email is compromised.\n"
        "2. Implement automated EDR host isolation capabilities to sever network connectivity while preserving forensic command channels.\n"
        "3. Follow RFC 3227 Order of Volatility: capture RAM memory dumps before shutting down or rebooting any compromised system.\n"
        "4. Conduct comprehensive root-cause analysis during eradication; changing passwords without closing ingress vulnerabilities leads to reinfection.\n"
        "5. Hold a mandatory Post-Incident Review (blameless post-mortem) within 14 days and track all remediation action items to completion."
    ),
)

ROOM_BLUE_16_TASKS = [
    TaskDefinition(
        task_id="task-01-ir-lifecycle-frameworks",
        order=1,
        title="Incident Response Lifecycles: NIST SP 800-61 vs SANS PICERL",
        instructions=(
            "Organizations structure their incident response procedures using established standards such as NIST SP 800-61 Rev 2 "
            "or the SANS 6-phase PICERL framework.\n\n"
            "In both frameworks, what critical phase focuses specifically on stopping the spread of an attack, limiting damage to "
            "organizational assets, and isolating compromised systems?"
        ),
        task_type=TaskType.QUESTION,
        question="What incident response phase focuses on stopping attack spread and isolating affected systems?",
        hint="It is the 'C' in SANS PICERL.",
        xp_reward=50,
        accepted_answers=[
            "Containment",
            "containment",
            "Containment Phase",
            "containment phase",
        ],
        mistake_explanations={
            "eradication": "Eradication comes after containment and focuses on removing malicious files, backdoors, and root causes.",
            "recovery": "Recovery focuses on restoring systems to normal production operation.",
            "preparation": "Preparation involves establishing tools, policies, and training before an incident occurs.",
        },
    ),
    TaskDefinition(
        task_id="task-02-order-of-volatility",
        order=2,
        title="Forensic Order of Volatility & Evidence Preservation",
        instructions=(
            "RFC 3227 defines the Order of Volatility for digital evidence acquisition to ensure volatile information "
            "is not lost when systems are manipulated or powered down.\n\n"
            "Between hard disk storage, system RAM (Random Access Memory), network cabling, and printed paper logs, "
            "which component has the HIGHEST volatility and must be collected first before powering down a machine?"
        ),
        task_type=TaskType.QUESTION,
        question="Which system component has the highest volatility and must be preserved before powering down?",
        hint="Volatile memory disappears when electrical power is disconnected.",
        xp_reward=60,
        accepted_answers=[
            "RAM",
            "ram",
            "Memory",
            "memory",
            "System RAM",
            "system ram",
            "System Memory",
            "volatile memory",
        ],
        mistake_explanations={
            "disk": "Hard disks and non-volatile flash storage persist after power is lost, so they have lower volatility than RAM.",
            "logs": "Remote log servers preserve recorded events persistently.",
        },
    ),
    TaskDefinition(
        task_id="task-03-rapid-containment-execution",
        order=3,
        title="Rapid Host Containment & Token Revocation",
        instructions=(
            "The compromised database host DB-PROD-01 is actively maintaining an external C2 channel.\n\n"
            "Execute immediate containment by issuing a network isolation and credential revocation request to the IR gateway:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"isolate_host\":true,\"revoke_tokens\":true,\"target_host\":\"DB-PROD-01\"}' http://10.10.14.90:8216/api/response/contain`\n\n"
            "Submit the verification token returned upon successful containment."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned upon enforcing host containment.",
        hint="Inspect the verification_token field in the JSON response from /api/response/contain.",
        xp_reward=70,
        accepted_answers=["RESPONSE_CONTAINMENT_ENFORCED"],
        mistake_explanations={
            "HOST_CONTAINED": "HOST_CONTAINED is the status value. Enter the exact verification_token string.",
        },
    ),
    TaskDefinition(
        task_id="task-04-threat-eradication-execution",
        order=4,
        title="Eradication & Persistence Neutralization",
        instructions=(
            "With the host contained, responders must eradicate the adversary's footholds: terminate the backdoor "
            "process (PID 3912), delete the rogue persistence service (`svc_winupdater`), and block egress to `198.51.100.77`.\n\n"
            "Submit the eradication directive via POST to the IR gateway on port 8216:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"terminate_pid\":3912,\"remove_service\":\"svc_winupdater\",\"block_egress_ip\":\"198.51.100.77\"}' http://10.10.14.90:8216/api/response/eradicate`\n\n"
            "Submit the verification token returned upon successful eradication."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned upon executing threat eradication.",
        hint="Inspect the verification_token field in the JSON response from /api/response/eradicate.",
        xp_reward=70,
        accepted_answers=["RESPONSE_ERADICATION_COMPLETE"],
        mistake_explanations={
            "THREAT_ERADICATED": "THREAT_ERADICATED is the status value. Enter the exact verification_token string.",
        },
    ),
    TaskDefinition(
        task_id="task-05-incident-response-challenge",
        order=5,
        title="Independent Challenge: End-to-End IR Lifecycle Verification",
        instructions=(
            "Verify complete execution of the Incident Response lifecycle. Submit the incident ID (`IR-2026-088`), "
            "lifecycle standard (`NIST_SP_800_61`), and containment/eradication verifications via POST to the challenge endpoint on port 8216:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"incident_id\":\"IR-2026-088\",\"lifecycle_standard\":\"NIST_SP_800_61\",\"containment_verified\":true,\"eradication_verified\":true}' http://10.10.14.90:8216/challenge`\n\n"
            "Submit the verification token returned upon completing the incident lifecycle review."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned by the Incident Response challenge endpoint.",
        hint="Complete both containment and eradication first, ensure your lab session is active, and submit incident_id (IR-2026-088), lifecycle_standard (NIST_SP_800_61), containment_verified (true), and eradication_verified (true).",
        xp_reward=50,
        accepted_answers=[
            "INCIDENT_RESPONSE_LIFECYCLE_VERIFIED",
            "IR_LIFECYCLE_COMPLETE",
        ],
    ),
    TaskDefinition(
        task_id="task-06-incident-response-quiz",
        order=6,
        title="Post-Incident Lessons Learned & Incident Governance Assessment",
        instructions="Answer the following 5 technical questions to verify comprehensive understanding of digital forensics evidence handling, root cause analysis, containment strategies, and post-mortem governance.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question technical assessment.",
        hint="Review chain of custody, cryptographic hashes, blameless post-mortems, and eradication verification.",
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is computing cryptographic hashes (e.g. SHA-256) of collected disk images and forensic memory dumps immediately upon acquisition essential?",
                options=[
                    "To establish cryptographic proof of evidence integrity and demonstrate that forensic data has not been modified or corrupted (Chain of Custody).",
                    "To compress the forensic evidence so it fits on a floppy disk.",
                    "To automatically decrypt the adversary's ransomware master key.",
                    "To speed up the network transfer rate across internal switches.",
                ],
                correct_option_index=0,
                explanation="Cryptographic hashes provide mathematical proof of evidence integrity, guaranteeing that data presented in incident analysis or legal proceedings remains identical to the moment of capture.",
            ),
            QuizQuestion(
                id="q2",
                question="During incident containment, why is network isolation via EDR/VLAN preferred over immediately pulling the physical power cord from a live server?",
                options=[
                    "Pulling the power cord destroys all volatile memory (RAM), terminating active network sockets, injected DLLs, and in-memory malware that are critical for root-cause forensics.",
                    "Pulling the power cord causes electrical damage to the wall socket.",
                    "Network isolation permanently deletes all files on the server.",
                    "Pulling the power cord notifies the attacker via SMS.",
                ],
                correct_option_index=0,
                explanation="Cutting power instantly erases volatile RAM, destroying running processes, injected code, encryption keys, and active network connections essential for understanding how the breach occurred.",
            ),
            QuizQuestion(
                id="q3",
                question="What is the primary objective of a 'Lessons Learned' (Post-Incident Review / Post-Mortem) meeting following a major security incident?",
                options=[
                    "Conduct a blameless analysis of what happened, identify systemic architectural weaknesses, evaluate response efficacy, and implement corrective controls to prevent recurrence.",
                    "Assign public blame and immediately terminate the employees involved in the incident.",
                    "Hide the incident details from executive leadership and board members.",
                    "Celebrate the end of the project without documenting technical findings.",
                ],
                correct_option_index=0,
                explanation="The Lessons Learned phase conducts a constructive, blameless review to identify root causes and implement lasting improvements to detection and defense posture.",
            ),
            QuizQuestion(
                id="q4",
                question="In digital forensics and incident response, what document records every person who collected, transferred, analyzed, and stored a piece of physical or digital evidence?",
                options=[
                    "Chain of Custody form",
                    "Certificate of Incorporation",
                    "Non-Disclosure Agreement (NDA)",
                    "Software Bill of Materials (SBOM)",
                ],
                correct_option_index=0,
                explanation="The Chain of Custody rigorously documents the chronological custody, transfer, and disposition of evidence to ensure legal defensibility.",
            ),
            QuizQuestion(
                id="q5",
                question="During the Eradication phase, why must security teams identify and close the initial entry vector in addition to deleting malware binaries?",
                options=[
                    "If the root cause (e.g. unpatched vulnerability or compromised credentials) is not remediated, the adversary will simply reuse the open doorway to regain access immediately.",
                    "Because deleting malware files automatically changes all user passwords.",
                    "Because antivirus software cannot run while servers are connected to a network.",
                    "Because cloud firewalls only permit malware deletion on weekends.",
                ],
                correct_option_index=0,
                explanation="Removing malicious artifacts without fixing the root cause (vulnerability or stolen credential) leaves the organization vulnerable to immediate re-compromise.",
            ),
        ],
    ),
]

ROOM_BLUE_16_DEFINITION = RoomDefinition(
    room_id="blue-16-incident-response",
    track=TrackEnum.BLUE,
    room_number=16,
    title="Incident Response",
    short_description="Execute the complete Incident Response lifecycle (NIST SP 800-61): enforce host containment, preserve volatile RAM evidence, eradicate C2 persistence, and document lessons learned.",
    difficulty="Intermediate",
    estimated_duration="50 min",
    concept=ROOM_BLUE_16_CONCEPT,
    tasks=ROOM_BLUE_16_TASKS,
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
)
