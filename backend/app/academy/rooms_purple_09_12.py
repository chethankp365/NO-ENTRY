"""
NO ENTRY Academy - Purple Team Track: Practical Rooms 09–12 Definitions

Rooms:
- Room 09: Command & Control (C2) Traffic Emulation (purple-09-c2-framework-emulation)
- Room 10: Emulating Data Exfiltration Techniques (purple-10-exfiltration-emulation)
- Room 11: Ransomware Attack Emulation & Readiness (purple-11-ransomware-readiness)
- Room 12: Cloud Identity & IAM Privilege Escalation Emulation (purple-12-cloud-identity-emulation)
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
# ROOM 09: COMMAND & CONTROL (C2) TRAFFIC EMULATION
# ============================================================================

ROOM_PURPLE_09_CONCEPT = RoomConcept(
    overview=(
        "Command and Control (C2) represents the operational communications channel established between an adversary's "
        "implant or agent on a compromised endpoint and their remote infrastructure. Modern C2 frameworks (such as Sliver, "
        "Covenant, and Cobalt Strike) disguise beaconing traffic using standard application layer protocols (HTTP, HTTPS, DNS, "
        "gRPC) and apply randomized sleep intervals known as jitter to defeat frequency-based detection. Purple Teaming "
        "emulates these beacon patterns to evaluate whether proxy logs, flow telemetry (Zeek/Suricata), and behavioral SIEM "
        "algorithms successfully differentiate periodic beaconing from legitimate user web traffic."
    ),
    simple_analogy=(
        "Imagine an undercover agent inside a secured facility who must report back to headquarters without getting caught. "
        "If they send a text message at exactly 12:00:00, 12:05:00, and 12:10:00 every single day, security guards analyzing "
        "tower logs will immediately notice the clockwork transmission. If the agent adds a random pause between 4 and 6 minutes "
        "(jitter), the pattern is disguised, requiring guards to perform advanced statistical interval analysis to spot the secret rhythm."
    ),
    technical_term="Adversary Command & Control (C2) Beaconing & Jitter Telemetry Emulation",
    technical_definition=(
        "The empirical generation and measurement of recurring outbound network callbacks simulating implant beaconing channels "
        "(MITRE ATT&CK T1071.001), evaluated through statistical inter-arrival time clustering (delta-time modeling), URI entropy "
        "inspection, and HTTP User-Agent consistency analysis across web proxy and network flow telemetry."
    ),
    cybersecurity_context=(
        "Once an initial foothold is secured, adversaries maintain command over implants via low-and-slow beaconing. If network "
        "defenders cannot detect beaconing channels, adversaries maintain persistent remote access, pivot deeper into internal "
        "subnets, and stage exfiltration undetected."
    ),
    why_it_matters=(
        "Detecting C2 callbacks is a critical defensive chokepoint. Because an adversary must communicate to execute commands, "
        "identifying beaconing patterns enables the SOC to sever the attacker's connection and isolate compromised systems before data theft occurs."
    ),
    demonstration=(
        "1. Examine prepared proxy and network flow logs containing simulated implant callbacks.\n"
        "2. Analyze beacon interval regularity, average sleep duration, and jitter variance.\n"
        "3. Emulate a live C2 HTTP beaconing callback against target port 8309 using the workstation C2 tool.\n"
        "4. Deploy an automated statistical beacon detection rule to flag low-variance periodic flows.\n"
        "5. Complete the validation challenge to confirm detection efficacy."
    ),
    remediation_guide=(
        "Enforce TLS inspection (decryption) on perimeter egress proxies; implement behavioral flow analysis alerting on recurring "
        "destination IPs with low sleep variance; restrict direct outbound endpoint egress using strict egress firewall filtering; "
        "and maintain centralized reputation threat intelligence feeds for known C2 infrastructure."
    ),
)

ROOM_PURPLE_09_TASKS = [
    TaskDefinition(
        task_id="task-01-c2-beacon-jitter-mechanics",
        order=1,
        title="Understand C2 Beaconing Mechanics & Jitter Randomization",
        instructions=(
            "Review the technical overview for Command and Control (C2) beaconing.\n\n"
            "When C2 implants communicate with their server, they execute a sleep cycle between callbacks to minimize "
            "network noise. To prevent defenders from detecting exact periodic intervals (e.g. exactly every 60 seconds), "
            "implants apply a randomized percentage offset to the sleep duration.\n\n"
            "Identify the technical term used for this randomized percentage variation applied to beacon sleep intervals."
        ),
        task_type=TaskType.QUESTION,
        question="What term refers to the randomized percentage variation added to beacon sleep intervals to evade periodic detection?",
        hint="It is commonly configured in C2 profiles as a percentage (e.g., 20% or 30%) and starts with 'J'.",
        accepted_answers=["Jitter", "jitter", "Jitter percentage", "Sleep jitter"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-02-c2-beacon-traffic-analysis",
        order=2,
        title="Analyze C2 Beaconing Telemetry in Proxy Logs",
        instructions=(
            "Inspect the prepared HTTP beacon telemetry file on your attacker workstation:\n"
            "`cat /var/log/c2/beacon_traffic_events.json`\n\n"
            "Alternatively, retrieve the telemetry via the target C2 service:\n"
            "`curl -s http://10.10.14.90:8309/api/c2/telemetry`\n\n"
            "Analyze the events to determine the exact URI path targeted by the outbound beacon requests."
        ),
        task_type=TaskType.QUESTION,
        question="What is the targeted C2 listener URI path observed in the outbound beacon telemetry?",
        hint="Look for the 'request_path' or 'uri' field in the JSON log (e.g. /api/v1/...).",
        accepted_answers=["/api/v1/ping", "api/v1/ping", "/api/v1/ping/"],
        xp_reward=60,
    ),
    TaskDefinition(
        task_id="task-03-attck-c2-mapping",
        order=3,
        title="Map C2 Communication to MITRE ATT&CK",
        instructions=(
            "Map the observed C2 web beaconing activity to the MITRE ATT&CK framework.\n\n"
            "The implant communicates over standard HTTP/HTTPS channels, disguising its control traffic as legitimate "
            "web browsing requests.\n\n"
            "Identify the sub-technique ID for Command and Control: Application Layer Protocol: Web Protocols."
        ),
        task_type=TaskType.QUESTION,
        question="What is the MITRE ATT&CK sub-technique ID for Application Layer Protocol: Web Protocols?",
        hint="Look under the Command and Control tactic (TA0011) for T1071 sub-techniques.",
        accepted_answers=["T1071.001", "t1071.001", "T1071.001 - Web Protocols"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-04-c2-beacon-emulation",
        order=4,
        title="Emulate C2 Beaconing Channel against Target",
        instructions=(
            "Perform an active C2 beaconing simulation against target port 8309 from your workstation.\n\n"
            "Execute the C2 emulation tool:\n"
            "`python3 /home/operator/tools/c2_emulation_tool.py --emulate-beacon`\n\n"
            "Alternatively, issue an authenticated POST request:\n"
            "`curl -s -X POST -H \"Content-Type: application/json\" \\\n"
            "  -d '{\"channel\":\"HTTP\",\"sleep_interval\":15,\"jitter\":20,\"target_path\":\"/api/v1/ping\"}' \\\n"
            "  http://10.10.14.90:8309/api/c2/emulate`\n\n"
            "Submit the verification token returned by the target."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned after emulating the C2 beaconing channel.",
        hint="Execute c2_emulation_tool.py with --emulate-beacon to capture the verification token.",
        accepted_answers=["C2_BEACON_EMULATION_VERIFIED", "C2_BEACON_EMULATED_OK"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-c2-detection-challenge",
        order=5,
        title="Deploy Statistical Beacon Detection Rule & Verify Challenge",
        instructions=(
            "Deploy a defensive statistical beacon detection rule and finalize the challenge.\n\n"
            "Execute the tool commands:\n"
            "`python3 /home/operator/tools/c2_emulation_tool.py --tune-detection`\n"
            "`python3 /home/operator/tools/c2_emulation_tool.py --challenge`\n\n"
            "Alternatively, POST to the challenge endpoint:\n"
            "`curl -s -X POST -H \"Content-Type: application/json\" \\\n"
            "  -d '{\"action\":\"VALIDATE_C2_DETECTION\"}' \\\n"
            "  http://10.10.14.90:8309/challenge`\n\n"
            "Submit the final verification token."
        ),
        task_type=TaskType.FLAG,
        question="Submit the challenge verification token confirming C2 beacon detection validation.",
        hint="Deploy the detection rule first, then execute the challenge request.",
        accepted_answers=["C2_DETECTION_VALIDATED", "C2_CHALLENGE_COMPLETE"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-c2-quiz",
        order=6,
        title="C2 Traffic Emulation Assessment Quiz",
        instructions="Complete the 4-question technical assessment to solidify Command & Control detection concepts.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why do modern adversary C2 frameworks implement malleable C2 profiles?",
                options=[
                    "To disguise HTTP headers, cookies, and URIs to mimic legitimate web services like Amazon or Microsoft Update",
                    "To compress the host operating system files into a zip archive",
                    "To change the MAC address of the default gateway router",
                    "To bypass local Windows account password length requirements",
                ],
                correct_index=0,
                explanation="Malleable C2 profiles allow operators to reshape HTTP requests/responses so traffic resembles benign business applications.",
            ),
            QuizQuestion(
                id="q2",
                question="What network traffic metric is primarily calculated by statistical detection engines to flag beaconing behavior?",
                options=[
                    "Inter-arrival delta-time variance between consecutive requests to the same external IP",
                    "The color depth of JPEG images downloaded by the web browser",
                    "The number of characters in the user's desktop wallpaper filename",
                    "The CPU temperature of the core layer-3 switch",
                ],
                correct_index=0,
                explanation="Periodic beaconing exhibits tight clustering in inter-arrival delta times compared to human browsing.",
            ),
            QuizQuestion(
                id="q3",
                question="Which protocol is frequently used as a fallback covert C2 channel when all direct outbound HTTP/HTTPS egress is blocked?",
                options=["DNS (Domain Name System)", "BGP (Border Gateway Protocol)", "SNMP (Simple Network Management Protocol)", "ARP (Address Resolution Protocol)"],
                correct_index=0,
                explanation="DNS queries are typically permitted outbound to internal resolvers, enabling DNS tunneling via recursive lookups.",
            ),
            QuizQuestion(
                id="q4",
                question="What defensive inspection capability is mandatory to detect C2 beacons that encrypt their payloads with HTTPS?",
                options=[
                    "TLS/SSL Forward Proxy Decryption (Break and Inspect)",
                    "Disabling TCP keepalive packets on internal workstations",
                    "Installing anti-virus on the external DNS root server",
                    "Replacing all copper ethernet cables with fiber optic links",
                ],
                correct_index=0,
                explanation="Without TLS decryption, proxy and IDS sensors cannot inspect the inner URI, payload, headers, or cookies of HTTPS beacons.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_09_DEFINITION = RoomDefinition(
    room_id="purple-09-c2-framework-emulation",
    track=TrackEnum.PURPLE,
    room_number=9,
    title="Command & Control (C2) Traffic Emulation",
    short_description="Emulate Covenant/Sliver C2 channels and test network egress filtering and beacon detection.",
    difficulty="Advanced",
    estimated_duration="70 min",
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
    concept=ROOM_PURPLE_09_CONCEPT,
    tasks=ROOM_PURPLE_09_TASKS,
)


# ============================================================================
# ROOM 10: EMULATING DATA EXFILTRATION TECHNIQUES
# ============================================================================

ROOM_PURPLE_10_CONCEPT = RoomConcept(
    overview=(
        "Data Exfiltration is the unauthorized transfer of sensitive information from an enterprise network to an "
        "adversary-controlled destination. The exfiltration lifecycle typically consists of local data discovery, staging into "
        "hidden directories, compression and encryption (to evade content inspection and reduce transmission time), followed "
        "by transmission over alternative network channels (HTTPS chunked POST, DNS TXT queries, or cloud storage APIs). "
        "Purple Teaming measures the Mean Time to Detect (MTTD) across each stage, validating Data Loss Prevention (DLP) controls "
        "and egress network anomalies."
    ),
    simple_analogy=(
        "If an intruder attempts to steal file cabinets full of company records, they do not carry the filing cabinets "
        "out the front door. Instead, they photograph the documents, compress the files into small encrypted microfilms, hide them "
        "in an inconspicuous maintenance closet (staging), and slip them out in small postal envelopes over several days. "
        "A Purple Team test verifies whether the office scales, mail inspection scanner, and closet door alarms detect the staged theft."
    ),
    technical_term="Adversary Data Staging, Compression & Covert Channel Exfiltration Emulation",
    technical_definition=(
        "The simulated execution of local data staging (MITRE ATT&CK T1074), archive compression and password encryption (T1560.001), "
        "and covert channel data egress (T1048 / T1041), evaluated against perimeter DLP thresholds, web proxy transfer volumes, "
        "and netflow spike alarms."
    ),
    cybersecurity_context=(
        "In ransomware attacks and cyber espionage campaigns, data exfiltration is the primary leverage for extortion. "
        "Stopping the adversary during the staging and compression phase—before multi-gigabyte transfers leave the network—prevents "
        "catastrophic data breaches."
    ),
    why_it_matters=(
        "Measuring defensive detection lag during data staging and transfer is vital. If alerts only trigger after 50 GB has exited, "
        "the breach is already complete; purple teaming tunes DLP and network anomaly triggers to halt transfers at the initial megabyte threshold."
    ),
    demonstration=(
        "1. Inspect prepared staging and egress telemetry logs detailing compressed archive creation.\n"
        "2. Identify the hidden staging directory and outbound transfer volume.\n"
        "3. Emulate automated archive compression and HTTPS chunked exfiltration against target port 8310.\n"
        "4. Deploy a defensive DLP egress threshold rule to intercept unauthorized archive transfers.\n"
        "5. Complete the validation challenge to verify exfiltration containment."
    ),
    remediation_guide=(
        "Deploy endpoint DLP agents alerting on archive creation of sensitive directory paths; restrict egress bandwidth to unknown "
        "external IP addresses; block unapproved cloud storage and file-sharing domains; and enforce strict outbound proxy authentication."
    ),
)

ROOM_PURPLE_10_TASKS = [
    TaskDefinition(
        task_id="task-01-exfil-staging-mechanics",
        order=1,
        title="Understand Data Staging & Encrypted Compression",
        instructions=(
            "Review the data staging and exfiltration concept.\n\n"
            "Adversaries frequently use command-line archiving tools to package sensitive files into a single password-protected "
            "compressed file before exfiltration, defeating basic keyword inspection.\n\n"
            "Identify the standard Linux archiving utility command flag combination commonly used to create a password-encrypted "
            "archive using the 'zip' utility."
        ),
        task_type=TaskType.QUESTION,
        question="Which flag parameter with the 'zip' command prompts for encryption password protection during archive creation?",
        hint="Type the command option (e.g. zip -e or -e).",
        accepted_answers=["zip -e", "-e", "zip -e filename", "-e flag", "zip"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-02-exfil-telemetry-analysis",
        order=2,
        title="Investigate Data Staging Telemetry in Host Logs",
        instructions=(
            "Inspect the prepared exfiltration telemetry file on your attacker workstation:\n"
            "`cat /var/log/exfil/staging_egress_events.json`\n\n"
            "Alternatively, retrieve the telemetry via the target service:\n"
            "`curl -s http://10.10.14.90:8310/api/exfil/telemetry`\n\n"
            "Identify the hidden staging directory path where the compromised database files were aggregated."
        ),
        task_type=TaskType.QUESTION,
        question="What is the hidden staging directory path where the data was staged before exfiltration?",
        hint="Look for the 'staging_directory' or 'directory' field in the JSON log.",
        accepted_answers=["/tmp/.staging_vault", ".staging_vault", "/tmp/.staging_vault/"],
        xp_reward=60,
    ),
    TaskDefinition(
        task_id="task-03-attck-exfil-mapping",
        order=3,
        title="Map Staging & Compression to MITRE ATT&CK",
        instructions=(
            "Map the data packaging step to the MITRE ATT&CK framework.\n\n"
            "The adversary used command-line utility compression (zip/7z/tar) to assemble collected files into an archive.\n\n"
            "Identify the MITRE ATT&CK sub-technique ID for Archive Collected Data: Archive via Utility."
        ),
        task_type=TaskType.QUESTION,
        question="What is the MITRE ATT&CK sub-technique ID for Archive Collected Data: Archive via Utility?",
        hint="Look under Collection (TA0009) or Exfiltration for technique T1560 sub-techniques.",
        accepted_answers=["T1560.001", "t1560.001", "T1560.001 - Archive via Utility"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-04-exfil-emulation",
        order=4,
        title="Emulate Data Staging & Exfiltration Transfer",
        instructions=(
            "Perform an active exfiltration simulation against target port 8310.\n\n"
            "Execute the exfiltration emulation tool from your workstation:\n"
            "`python3 /home/operator/tools/exfil_emulation_tool.py --emulate-exfil`\n\n"
            "Alternatively, issue an authenticated POST request:\n"
            "`curl -s -X POST -H \"Content-Type: application/json\" \\\n"
            "  -d '{\"staging_dir\":\"/tmp/.staging_vault\",\"archive_name\":\"db_export.7z\",\"transfer_proto\":\"HTTPS_POST\",\"bytes\":48200000}' \\\n"
            "  http://10.10.14.90:8310/api/exfil/emulate`\n\n"
            "Submit the verification token returned by the target."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned after emulating data staging and exfiltration.",
        hint="Run exfil_emulation_tool.py with --emulate-exfil to capture the verification token.",
        accepted_answers=["EXFILTRATION_EMULATION_VERIFIED", "EXFIL_TRANSFER_OK"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-exfil-challenge",
        order=5,
        title="Enforce DLP Threshold Rule & Complete Validation Challenge",
        instructions=(
            "Deploy a defensive egress volume threshold / DLP rule to detect anomalous transfers and complete the challenge.\n\n"
            "Execute the tool commands:\n"
            "`python3 /home/operator/tools/exfil_emulation_tool.py --tune-dlp`\n"
            "`python3 /home/operator/tools/exfil_emulation_tool.py --challenge`\n\n"
            "Alternatively, POST to the challenge endpoint:\n"
            "`curl -s -X POST -H \"Content-Type: application/json\" \\\n"
            "  -d '{\"action\":\"VALIDATE_EXFILTRATION_DETECTION\"}' \\\n"
            "  http://10.10.14.90:8310/challenge`\n\n"
            "Submit the final verification token."
        ),
        task_type=TaskType.FLAG,
        question="Submit the challenge verification token confirming exfiltration detection validation.",
        hint="Deploy the DLP rule first, then execute the challenge request.",
        accepted_answers=["EXFILTRATION_DETECTION_VALIDATED", "EXFIL_CHALLENGE_COMPLETE"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-exfil-quiz",
        order=6,
        title="Data Exfiltration Assessment Quiz",
        instructions="Complete the 4-question technical assessment to solidify exfiltration defense concepts.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why do adversaries split large exfiltration archives into smaller chunks (e.g. 10 MB pieces)?",
                options=[
                    "To evade network bandwidth volume threshold alerts and proxy request size limits",
                    "To increase the processing power of the target CPU",
                    "To change the IP subnet of the source server",
                    "To automatically decrypt SSL certificates on the router",
                ],
                correct_index=0,
                explanation="Chunking large archives prevents triggering high-volume single-connection data transfer alerts in SIEM and DLP systems.",
            ),
            QuizQuestion(
                id="q2",
                question="In DNS tunneling exfiltration, what record type is most commonly abused to return encoded data in query responses?",
                options=["TXT", "PTR", "MX", "SOA"],
                correct_index=0,
                explanation="TXT records can return arbitrary text strings up to 255 bytes per string, making them ideal for carrying encoded data.",
            ),
            QuizQuestion(
                id="q3",
                question="What defensive strategy provides the earliest warning of data staging before network egress begins?",
                options=[
                    "Monitoring filesystem creation of compressed archives in non-standard directories like /tmp, /dev/shm, or C:\\ProgramData",
                    "Blocking ICMP ping requests on external routers",
                    "Setting the Windows screen timeout to 5 minutes",
                    "Formatting USB thumb drives with FAT32 instead of NTFS",
                ],
                correct_index=0,
                explanation="Detecting archive utility execution targeting sensitive directories alerts defenders before network transfer starts.",
            ),
            QuizQuestion(
                id="q4",
                question="What is the primary operational metric measured during a Purple Team exfiltration exercise?",
                options=[
                    "Mean Time to Detect (MTTD) from staging initiation to alert generation",
                    "The number of keyboard strokes typed by the red team operator",
                    "The download speed of public YouTube videos on the corporate LAN",
                    "The resolution of the operator's computer monitor",
                ],
                correct_index=0,
                explanation="MTTD measures how quickly defenders identify unauthorized staging and transfer activity, quantifying detection lag.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_10_DEFINITION = RoomDefinition(
    room_id="purple-10-exfiltration-emulation",
    track=TrackEnum.PURPLE,
    room_number=10,
    title="Emulating Data Exfiltration Techniques",
    short_description="Simulate encrypted staging, archive compression, and DNS/HTTPS exfiltration tunnels to measure detection lag.",
    difficulty="Intermediate",
    estimated_duration="50 min",
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
    concept=ROOM_PURPLE_10_CONCEPT,
    tasks=ROOM_PURPLE_10_TASKS,
)


# ============================================================================
# ROOM 11: RANSOMWARE ATTACK EMULATION & READINESS
# ============================================================================

ROOM_PURPLE_11_CONCEPT = RoomConcept(
    overview=(
        "Ransomware attack emulation tests an organization's detection and automated containment posture against "
        "pre-encryption behaviors without introducing destructive encryption logic. Precursor behaviors include Volume Shadow "
        "Copy deletion (vssadmin delete shadows), backup catalog invalidation (wbadmin delete catalog), service disruption "
        "(stopping antivirus or database services via sc/net stop), and touching canary honeypot files. Purple Teaming measures "
        "how quickly endpoint detection and response (EDR) rules detect precursor indicators and automatically isolate endpoints "
        "before widespread data destruction can occur."
    ),
    simple_analogy=(
        "A fire readiness drill does not set the building on fire; it introduces controlled smoke to test whether the smoke alarms "
        "sound, the sprinkler system valves engage, and fire doors close automatically within seconds. Similarly, ransomware readiness "
        "emulates the smoke (shadow copy deletion and canary file touches) to verify that defensive containment triggers instantly."
    ),
    technical_term="Ransomware Precursor Emulation, Canary Honeypots & Automated Containment",
    technical_definition=(
        "The empirical simulation of pre-ransomware evasion and recovery inhibition behaviors (MITRE ATT&CK T1490 and T1489), "
        "paired with file modification canary decoy tripwires, evaluated against endpoint behavior blocking engines and automated "
        "host isolation pipelines."
    ),
    cybersecurity_context=(
        "Modern human-operated ransomware groups spend days performing discovery and lateral movement before executing their payload. "
        "Immediately before encryption, they launch automated recovery inhibition commands. Detecting these precursor actions "
        "provides the last, critical opportunity to prevent total enterprise lockout."
    ),
    why_it_matters=(
        "Once file encryption begins, high file-write velocity can encrypt thousands of files per minute. Testing canary token triggers "
        "and automated network isolation ensures the infected machine is quarantined before sensitive shares are touched."
    ),
    demonstration=(
        "1. Inspect prepared host precursor logs detailing shadow copy deletion and service stopping attempts.\n"
        "2. Identify the canary decoy file monitored by defensive tripwire sensors.\n"
        "3. Emulate ransomware precursor commands and safe canary access against target port 8311.\n"
        "4. Deploy automated canary alert rules and verify automated containment response.\n"
        "5. Complete the validation challenge to confirm ransomware readiness."
    ),
    remediation_guide=(
        "Restrict vssadmin execution privileges; configure EDR behavioral blocks on processes invoking shadow copy deletion commands; "
        "deploy canary tripwire files across shared network drives; and maintain offline, immutable, write-once-read-many (WORM) backups."
    ),
)

ROOM_PURPLE_11_TASKS = [
    TaskDefinition(
        task_id="task-01-ransomware-inhibiting-recovery",
        order=1,
        title="Understand Recovery Inhibition Mechanics (Shadow Copies)",
        instructions=(
            "Review the ransomware precursor concepts.\n\n"
            "To prevent victims from restoring files from local backups, ransomware operators execute native Windows utilities "
            "to wipe Volume Shadow Copies before launching encryption routines.\n\n"
            "Identify the native Windows command-line utility used to manage and delete Volume Shadow Copies."
        ),
        task_type=TaskType.QUESTION,
        question="What native Windows command-line utility is standardly invoked by ransomware to delete shadow copies?",
        hint="The command name starts with 'vss' and ends with 'admin'.",
        accepted_answers=["vssadmin", "vssadmin.exe", "vssadmin delete shadows"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-02-ransomware-telemetry-analysis",
        order=2,
        title="Analyze Ransomware Precursor & Canary Decoy Telemetry",
        instructions=(
            "Inspect the prepared precursor event log on your attacker workstation:\n"
            "`cat /var/log/ransomware/precursor_events.json`\n\n"
            "Alternatively, retrieve the telemetry via the target service:\n"
            "`curl -s http://10.10.14.90:8311/api/ransomware/telemetry`\n\n"
            "Identify the exact filename of the canary decoy token file that was accessed by the simulated crypto process."
        ),
        task_type=TaskType.QUESTION,
        question="What is the exact filename of the canary decoy token file touched during the simulation?",
        hint="Look for the 'canary_file' or 'decoy_file' field in the JSON log (e.g. ..._canary.xlsx).",
        accepted_answers=["finance_q4_canary.xlsx", "finance_q4_canary", "/home/operator/decoy/finance_q4_canary.xlsx"],
        xp_reward=60,
    ),
    TaskDefinition(
        task_id="task-03-attck-ransomware-mapping",
        order=3,
        title="Map Recovery Inhibition to MITRE ATT&CK",
        instructions=(
            "Map the volume shadow copy deletion behavior to the MITRE ATT&CK framework.\n\n"
            "The adversary executed `vssadmin delete shadows /all /quiet` to prevent disaster recovery.\n\n"
            "Identify the MITRE ATT&CK technique ID for Inhibit System Recovery."
        ),
        task_type=TaskType.QUESTION,
        question="What is the MITRE ATT&CK technique ID for Inhibit System Recovery?",
        hint="Look under the Impact tactic (TA0040) for technique T1490.",
        accepted_answers=["T1490", "t1490", "T1490 - Inhibit System Recovery"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-04-ransomware-emulation",
        order=4,
        title="Emulate Ransomware Precursors & Canary Decoy Touch",
        instructions=(
            "Perform an active safe ransomware readiness emulation against target port 8311.\n\n"
            "Execute the ransomware emulation tool from your workstation:\n"
            "`python3 /home/operator/tools/ransomware_emulation_tool.py --emulate-precursors`\n\n"
            "Alternatively, issue an authenticated POST request:\n"
            "`curl -s -X POST -H \"Content-Type: application/json\" \\\n"
            "  -d '{\"action\":\"PRECURSOR_SIMULATION\",\"vssadmin_executed\":true,\"canary_touched\":\"finance_q4_canary.xlsx\"}' \\\n"
            "  http://10.10.14.90:8311/api/ransomware/emulate`\n\n"
            "Submit the verification token returned by the target."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned after emulating ransomware precursor behaviors.",
        hint="Run ransomware_emulation_tool.py with --emulate-precursors to capture the verification token.",
        accepted_answers=["RANSOMWARE_EMULATION_VERIFIED", "RANSOMWARE_PRECURSORS_OK"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-ransomware-challenge",
        order=5,
        title="Deploy Canary Alerting & Verify Containment Readiness",
        instructions=(
            "Deploy defensive canary tripwire alerting and complete the challenge verification.\n\n"
            "Execute the tool commands:\n"
            "`python3 /home/operator/tools/ransomware_emulation_tool.py --tune-canary`\n"
            "`python3 /home/operator/tools/ransomware_emulation_tool.py --challenge`\n\n"
            "Alternatively, POST to the challenge endpoint:\n"
            "`curl -s -X POST -H \"Content-Type: application/json\" \\\n"
            "  -d '{\"action\":\"VALIDATE_RANSOMWARE_READINESS\"}' \\\n"
            "  http://10.10.14.90:8311/challenge`\n\n"
            "Submit the final verification token."
        ),
        task_type=TaskType.FLAG,
        question="Submit the challenge verification token confirming ransomware readiness validation.",
        hint="Deploy the canary tripwire rule first, then execute the challenge request.",
        accepted_answers=["RANSOMWARE_READINESS_VALIDATED", "RANSOMWARE_CHALLENGE_COMPLETE"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-ransomware-quiz",
        order=6,
        title="Ransomware Readiness Assessment Quiz",
        instructions="Complete the 4-question technical assessment to solidify ransomware defensive readiness concepts.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is a canary decoy file in ransomware defensive engineering?",
                options=[
                    "A benign, bait file placed in common folders monitored by EDR to trigger immediate alarms when modified",
                    "A file used to store the user's Google Chrome passwords",
                    "An audio file that plays a canary chirping sound when an error occurs",
                    "A Windows system DLL that accelerates file encryption performance",
                ],
                correct_index=0,
                explanation="Canary files act as tripwires: legitimate users never open or modify them, so any modification indicates automated ransomware.",
            ),
            QuizQuestion(
                id="q2",
                question="Why is offline, immutable backup storage considered the gold standard protection against ransomware?",
                options=[
                    "Because ransomware operating with Domain Admin credentials cannot delete or encrypt media it cannot write to over the network",
                    "Because immutable backups do not require electricity to run",
                    "Because offline backups double the upload speed of network firewalls",
                    "Because immutable backups eliminate the need to patch software vulnerabilities",
                ],
                correct_index=0,
                explanation="Write-Once-Read-Many (WORM) and air-gapped backups prevent ransomware operators from destroying recovery points.",
            ),
            QuizQuestion(
                id="q3",
                question="Which service deletion or stop command is frequently paired with vssadmin to disable the Windows backup engine?",
                options=[
                    "wbadmin delete catalog -quiet",
                    "ping 127.0.0.1 -n 4",
                    "ipconfig /flushdns",
                    "hostname.exe",
                ],
                correct_index=0,
                explanation="`wbadmin delete catalog` removes the Windows Backup database, ensuring backups cannot be restored via the native GUI.",
            ),
            QuizQuestion(
                id="q4",
                question="What automated defensive capability stops ransomware from spreading laterally across SMB network shares?",
                options=[
                    "Automated host network isolation (quarantine) triggered by EDR upon canary alert detection",
                    "Increasing the computer's screen brightness to maximum",
                    "Disabling the DHCP client service on the local machine",
                    "Renaming all shared folders to begin with an underscore",
                ],
                correct_index=0,
                explanation="Isolating the endpoint's network interface immediately severs SMB connections, preventing spread across file shares.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_11_DEFINITION = RoomDefinition(
    room_id="purple-11-ransomware-readiness",
    track=TrackEnum.PURPLE,
    room_number=11,
    title="Ransomware Attack Emulation & Readiness",
    short_description="Simulate rapid file encryption indicators and canary token touches without damaging assets.",
    difficulty="Advanced",
    estimated_duration="65 min",
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
    concept=ROOM_PURPLE_11_CONCEPT,
    tasks=ROOM_PURPLE_11_TASKS,
)


# ============================================================================
# ROOM 12: CLOUD IDENTITY & IAM PRIVILEGE ESCALATION EMULATION
# ============================================================================

ROOM_PURPLE_12_CONCEPT = RoomConcept(
    overview=(
        "Cloud environments present unique attack surfaces where identity and access management (IAM) represents the "
        "new perimeter. Adversaries targeting cloud compute workloads (EC2, ECS, Azure VMs) frequently query the link-local "
        "Instance Metadata Service (IMDS) at 169.254.169.254 to steal temporary role credentials. Once acquired, attackers abuse "
        "misconfigured trust policies to assume over-privileged administrative roles (sts:AssumeRole). Purple Teaming tests "
        "whether CloudTrail / Azure Activity Logs detect anomalous role assumption chains and whether IMDSv2 protections prevent token theft."
    ),
    simple_analogy=(
        "Imagine an office worker whose lanyard badge is meant only to open the break room. If that employee discovers they can "
        "use an unattended badge machine in the hallway to print an executive director badge and enter the server room, "
        "that is IAM privilege escalation. A Purple Team test checks whether the badge logs flag the sudden leap in authority."
    ),
    technical_term="Cloud IAM Role Assumption Abuse, Metadata Token Exfiltration & Audit Pipeline Emulation",
    technical_definition=(
        "The empirical simulation of Instance Metadata Service (IMDS) credential theft (MITRE ATT&CK T1552.005) and subsequent "
        "cross-role assumption privilege escalation (T1078.004), evaluated against CloudTrail multi-account event streams and "
        "anomaly detection alert pipelines."
    ),
    cybersecurity_context=(
        "In modern cloud infrastructure, server-side request forgery (SSRF) and container escapes allow attackers to query the IMDS. "
        "Enforcing IMDSv2 (session tokens via HTTP PUT) and auditing role assumption patterns stops cloud account takeover."
    ),
    why_it_matters=(
        "IAM misconfigurations represent the single largest cause of cloud security incidents. Purple teaming validates that "
        "security operations receives immediate alerts when an application workload assumes high-privilege administrator roles."
    ),
    demonstration=(
        "1. Inspect prepared cloud audit logs containing simulated IMDS queries and role assumption events.\n"
        "2. Identify the over-privileged role ARN assumed by the workload identity.\n"
        "3. Emulate IMDS credential exfiltration and role assumption against target port 8312.\n"
        "4. Deploy an automated CloudTrail alert rule detecting unexpected AssumeRole calls.\n"
        "5. Complete the validation challenge to confirm cloud identity monitoring."
    ),
    remediation_guide=(
        "Enforce IMDSv2 across all cloud compute instances (disabling IMDSv1); apply the Principle of Least Privilege to IAM roles; "
        "implement Service Control Policies (SCPs) preventing role assumption outside designated organizational units; and enable "
        "GuardDuty / Defender for Cloud anomaly detection."
    ),
)

ROOM_PURPLE_12_TASKS = [
    TaskDefinition(
        task_id="task-01-cloud-imds-mechanics",
        order=1,
        title="Understand Cloud Instance Metadata Service (IMDS) Architecture",
        instructions=(
            "Review the cloud identity emulation concept.\n\n"
            "Cloud compute workloads access temporary instance credentials and metadata via a dedicated non-routable link-local "
            "IPv4 address provided by the hypervisor.\n\n"
            "Identify the standard link-local IP address queried by cloud instances to reach the Instance Metadata Service."
        ),
        task_type=TaskType.QUESTION,
        question="What link-local IP address is used to access the cloud Instance Metadata Service?",
        hint="It is a 169.254.x.x link-local IP address identical across AWS, Azure, and GCP.",
        accepted_answers=["169.254.169.254", "http://169.254.169.254", "http://169.254.169.254/"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-02-cloud-audit-telemetry-analysis",
        order=2,
        title="Investigate CloudTrail Role Assumption Events",
        instructions=(
            "Inspect the prepared cloud audit log on your attacker workstation:\n"
            "`cat /var/log/cloud/cloudtrail_iam_events.json`\n\n"
            "Alternatively, retrieve the telemetry via the target service:\n"
            "`curl -s http://10.10.14.90:8312/api/cloud/telemetry`\n\n"
            "Identify the IAM role name that was assumed by the workload in the CloudTrail audit log."
        ),
        task_type=TaskType.QUESTION,
        question="What is the IAM role name assumed by the adversary in the CloudTrail audit log?",
        hint="Look for the role name in the 'assumed_role' field (e.g. ProdSecOpsAdminRole).",
        accepted_answers=["ProdSecOpsAdminRole", "arn:aws:iam::123456789012:role/ProdSecOpsAdminRole", "role/ProdSecOpsAdminRole"],
        xp_reward=60,
    ),
    TaskDefinition(
        task_id="task-03-attck-cloud-mapping",
        order=3,
        title="Map Cloud Credential Access to MITRE ATT&CK",
        instructions=(
            "Map the instance metadata credential exfiltration technique to MITRE ATT&CK.\n\n"
            "The adversary queried the IMDS endpoint to harvest temporary security credentials from the instance profile.\n\n"
            "Identify the MITRE ATT&CK sub-technique ID for Unsecured Credentials: Cloud Instance Metadata API."
        ),
        task_type=TaskType.QUESTION,
        question="What is the MITRE ATT&CK sub-technique ID for Unsecured Credentials: Cloud Instance Metadata API?",
        hint="Look under Credential Access (TA0006) for technique T1552 sub-techniques.",
        accepted_answers=["T1552.005", "t1552.005", "T1552.005 - Cloud Instance Metadata API", "T1078.004"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-04-cloud-iam-emulation",
        order=4,
        title="Emulate IMDS Query & Role Assumption",
        instructions=(
            "Perform an active cloud identity and role assumption emulation against target port 8312.\n\n"
            "Execute the cloud IAM emulation tool from your workstation:\n"
            "`python3 /home/operator/tools/cloud_iam_emulation_tool.py --emulate-assume-role`\n\n"
            "Alternatively, issue an authenticated POST request:\n"
            "`curl -s -X POST -H \"Content-Type: application/json\" \\\n"
            "  -d '{\"target_role\":\"ProdSecOpsAdminRole\",\"source_identity\":\"app-workload-role\",\"action\":\"sts:AssumeRole\"}' \\\n"
            "  http://10.10.14.90:8312/api/cloud/emulate`\n\n"
            "Submit the verification token returned by the target."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned after emulating the cloud role assumption.",
        hint="Run cloud_iam_emulation_tool.py with --emulate-assume-role to capture the verification token.",
        accepted_answers=["CLOUD_IAM_EMULATION_VERIFIED", "CLOUD_ROLE_ASSUMED_OK"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-cloud-detection-challenge",
        order=5,
        title="Deploy CloudTrail Anomaly Alert Rule & Verify Challenge",
        instructions=(
            "Deploy a defensive CloudTrail alert rule detecting unexpected AssumeRole calls and complete the challenge.\n\n"
            "Execute the tool commands:\n"
            "`python3 /home/operator/tools/cloud_iam_emulation_tool.py --tune-pipeline`\n"
            "`python3 /home/operator/tools/cloud_iam_emulation_tool.py --challenge`\n\n"
            "Alternatively, POST to the challenge endpoint:\n"
            "`curl -s -X POST -H \"Content-Type: application/json\" \\\n"
            "  -d '{\"action\":\"VALIDATE_CLOUD_IDENTITY_DETECTION\"}' \\\n"
            "  http://10.10.14.90:8312/challenge`\n\n"
            "Submit the final verification token."
        ),
        task_type=TaskType.FLAG,
        question="Submit the challenge verification token confirming cloud identity detection validation.",
        hint="Deploy the CloudTrail alert rule first, then execute the challenge request.",
        accepted_answers=["CLOUD_IDENTITY_DETECTION_VALIDATED", "CLOUD_CHALLENGE_COMPLETE"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-cloud-quiz",
        order=6,
        title="Cloud Identity & IAM Assessment Quiz",
        instructions="Complete the 4-question technical assessment to solidify cloud IAM and identity security concepts.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What security enhancement does IMDSv2 introduce over IMDSv1 to prevent SSRF exploitation?",
                options=[
                    "It requires a session token acquired via an HTTP PUT request with a custom header (X-aws-ec2-metadata-token-ttl-seconds)",
                    "It disables IPv4 entirely and only functions over Bluetooth",
                    "It encrypts metadata with a local Windows BitLocker key",
                    "It requires the user to solve a CAPTCHA before every curl command",
                ],
                correct_index=0,
                explanation="IMDSv2 uses session-oriented requests requiring an HTTP PUT method with token headers, neutralizing standard SSRF vectors.",
            ),
            QuizQuestion(
                id="q2",
                question="What AWS STS API call is executed to obtain temporary security credentials for another IAM role?",
                options=["sts:AssumeRole", "sts:DeleteAccount", "iam:CreatePassword", "ec2:RebootInstances"],
                correct_index=0,
                explanation="sts:AssumeRole verifies trust relationships and returns temporary AccessKeyId, SecretAccessKey, and SessionToken.",
            ),
            QuizQuestion(
                id="q3",
                question="What CloudTrail event field records the original ARN or user identity that made an API request?",
                options=["userIdentity.arn", "eventSource.ip", "recipientAccountId", "requestParameters.size"],
                correct_index=0,
                explanation="The userIdentity block in CloudTrail records the principal (IAM user, assumed role, or federated identity) initiating the API call.",
            ),
            QuizQuestion(
                id="q4",
                question="What cloud governance mechanism enforces guardrails across all accounts in an AWS Organization, overriding local IAM permissions?",
                options=[
                    "Service Control Policies (SCPs)",
                    "VPC Peering Connections",
                    "Security Group Inbound Rules",
                    "Route 53 Hosted Zones",
                ],
                correct_index=0,
                explanation="SCPs specify the maximum available permissions for an organization or organizational unit (OU), acting as organizational guardrails.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_12_DEFINITION = RoomDefinition(
    room_id="purple-12-cloud-identity-emulation",
    track=TrackEnum.PURPLE,
    room_number=12,
    title="Cloud Identity & IAM Privilege Escalation Emulation",
    short_description="Emulate AWS/Azure role assumption abuse and verify cloud audit log alert pipelines.",
    difficulty="Intermediate",
    estimated_duration="60 min",
    status=RoomStatus.IMPLEMENTED,
    total_xp=350,
    concept=ROOM_PURPLE_12_CONCEPT,
    tasks=ROOM_PURPLE_12_TASKS,
)

