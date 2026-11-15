"""
Complete curriculum definitions, tasks, concept explanations, and quizzes
for Blue Team Rooms 09–12:
- Room 09: Brute-Force Detection (blue-09-bruteforce-detection)
- Room 10: Malware Behaviour Analysis (blue-10-malware-behaviour-analysis)
- Room 11: Phishing Investigation (blue-11-phishing-investigation)
- Room 12: Endpoint Detection (blue-12-endpoint-detection)
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
# BLUE ROOM 09: BRUTE-FORCE DETECTION (FULLY IMPLEMENTED)
# ============================================================================

ROOM_BLUE_09_CONCEPT = RoomConcept(
    overview=(
        "Brute-Force Detection explores identifying and mitigating automated credential guessing, dictionary attacks, "
        "and password spraying across enterprise identity providers. Defensive analysts learn to parse authentication "
        "event streams, recognize anomalous failure distributions, deploy threshold correlation rules, and enforce "
        "adaptive account containment."
    ),
    simple_analogy=(
        "Imagine an intruder trying to breach an office building. A traditional brute-force attack is like someone "
        "standing at the front door trying 500 keys on one lock in five minutes—the security guard immediately notices "
        "and locks that door (account lockout). A password spray attack is much stealthier: the intruder walks down the "
        "hallway and tests a single common master key ('Password2026!') on 50 different doors once every 10 minutes. "
        "No single door reaches its lockout threshold, but a security analyst looking at the building-wide camera feed "
        "(SIEM correlation) easily spots the single visitor touching dozens of different offices."
    ),
    technical_term="Credential Guessing vs Password Spraying & Threshold Correlation (MITRE ATT&CK T1110.001 / T1110.003)",
    technical_definition=(
        "Authentication telemetry logs record security principals, client IP addresses, target ports, protocols, and "
        "status codes (e.g. Windows Security Event ID 4625 with substatus 0xC000006A for bad password, or Linux PAM "
        "`sshd: Failed password`). Traditional brute-force (T1110.001) exhibits a high volume of attempts against a single "
        "account from one or more IPs. Password spraying (T1110.003) exhibits a low attempt rate per account across a large "
        "cardinality of unique usernames grouped by source IP or subnet within a sliding time window (Δt)."
    ),
    cybersecurity_context=(
        "Adversaries utilize password spraying during initial access and lateral movement specifically to bypass per-user "
        "lockout policies and prevent denial-of-service alerts. Blue Teams must configure SIEM correlation rules that "
        "aggregate authentication failures by source IP and count distinct target usernames rather than tracking individual "
        "account failure counters alone."
    ),
    why_it_matters=(
        "Over 80% of confirmed corporate breaches involve compromised or stolen credentials. Identifying spray patterns "
        "early prevents threat actors from gaining their initial foothold into domain environments."
    ),
    demonstration=(
        "1. Authentication Log Inspection:\n"
        "   $ cat /var/log/auth_bruteforce.log\n"
        "   Review live SSH and web authentication logs recording authentication attempts.\n\n"
        "2. Anomaly Parsing Script:\n"
        "   $ python3 /home/operator/tools/detect_bruteforce.py\n"
        "   Execute automated statistical analysis to count attempts per IP and unique accounts targeted.\n\n"
        "3. SIEM Telemetry & Spray Indicators Query:\n"
        "   GET /api/auth/telemetry and GET /api/auth/spray-indicators on port 8209.\n\n"
        "4. Deploy Detection Rule:\n"
        "   POST /api/auth/rules -> Deploy threshold rule aggregating failures by source IP.\n\n"
        "5. Independent Challenge:\n"
        "   POST /challenge -> Submit validated adversary IP, attack type, and account count to receive flag."
    ),
    remediation_guide=(
        "1. Enforce Multi-Factor Authentication (MFA) across all external and internal authentication gateways.\n"
        "2. Deploy smart lockout policies that evaluate client reputation and IP geolocation rather than locking accounts globally.\n"
        "3. Configure SIEM correlation rules: alert when a single IP generates >= 5 authentication failures across distinct users within 5 minutes.\n"
        "4. Implement automated firewall blocklists that dynamically ban IPs triggering password spray rules.\n"
        "5. Require strong, non-dictionary passwords and screen against publicly disclosed credential dumps."
    ),
)

ROOM_BLUE_09_TASKS = [
    TaskDefinition(
        task_id="task-01-bruteforce-taxonomy",
        order=1,
        title="Authentication Attack Taxonomy: Spraying vs Guessing",
        instructions=(
            "Security analysts must distinguish between credential guessing, dictionary attacks, and password spraying.\n\n"
            "What authentication attack technique tests a small number of commonly used passwords (such as 'Winter2026!') "
            "across a large number of different user accounts to avoid triggering individual account lockout thresholds?"
        ),
        task_type=TaskType.QUESTION,
        question="What authentication attack technique tests common passwords across many accounts to evade lockouts?",
        hint="It is classified as MITRE ATT&CK T1110.003.",
        xp_reward=50,
        accepted_answers=[
            "Password Spraying",
            "password spraying",
            "Password Spray",
            "password spray",
            "T1110.003",
        ],
        mistake_explanations={
            "credential stuffing": "Credential stuffing tests known username/password pairs stolen from third-party breaches. Testing common passwords across many accounts is Password Spraying.",
            "brute force": "Brute force is the overarching category. The specific technique that rotates accounts is Password Spraying.",
            "dictionary attack": "A dictionary attack typically tests a list of passwords against a single target user.",
        },
    ),
    TaskDefinition(
        task_id="task-02-auth-log-stream-investigation",
        order=2,
        title="Authentication Log Stream & Adversary Attribution",
        instructions=(
            "Inspect the authentication logs on your analyst workstation or query the live telemetry endpoint on port 8209:\n"
            "  `cat /var/log/auth_bruteforce.log`\n"
            "  Or: `curl -s http://10.10.14.90:8209/api/auth/telemetry`\n\n"
            "Identify the external source IP address conducting the multi-account password spraying operation against enterprise accounts."
        ),
        task_type=TaskType.QUESTION,
        question="What is the adversary's source IP address conducting the password spray?",
        hint="Examine which IP address generates failed logins across admin, operator, root, svc_backup, etc.",
        xp_reward=60,
        accepted_answers=["198.51.100.55"],
        mistake_explanations={
            "203.0.113.19": "203.0.113.19 is conducting a dictionary attack against a single user (support). Look for the IP spraying multiple accounts.",
            "10.10.14.22": "10.10.14.22 is a legitimate internal host with a successful authentication.",
        },
    ),
    TaskDefinition(
        task_id="task-03-spray-indicator-correlation",
        order=3,
        title="Spray Indicator Correlation & MITRE Mapping",
        instructions=(
            "Query the correlated spray indicator analytics endpoint on port 8209:\n"
            "  `curl -s http://10.10.14.90:8209/api/auth/spray-indicators`\n\n"
            "Or execute the detection helper tool:\n"
            "  `python3 /home/operator/tools/detect_bruteforce.py`\n\n"
            "What is the MITRE ATT&CK sub-technique code (e.g. T1110.003) assigned to the correlated password spray pattern?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the MITRE ATT&CK sub-technique code for the correlated password spray?",
        hint="Inspect the mitre_technique field in the JSON response.",
        xp_reward=70,
        accepted_answers=["T1110.003", "T1110.003 - Password Spraying"],
        mistake_explanations={
            "T1110 (parent)": "T1110 is the parent technique. Provide the exact sub-technique code T1110.003.",
            "T1110.001": "T1110.001 is Password Guessing against a single account, not Password Spraying.",
        },
    ),
    TaskDefinition(
        task_id="task-04-siem-threshold-rule-deployment",
        order=4,
        title="SIEM Correlation Rule Authoring & Deployment",
        instructions=(
            "Defenders must author SIEM correlation rules that aggregate events by source IP rather than individual accounts.\n\n"
            "Deploy a spray detection rule by submitting a POST request to the auth gateway:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"rule_name\":\"RULE_AUTH_BURST_SPRAY\",\"threshold\":5,\"group_by\":\"source_ip\"}' http://10.10.14.90:8209/api/auth/rules`\n\n"
            "Submit the verification token returned upon successful rule deployment."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned upon deploying the correlation rule.",
        hint="Look for the verification_token field in the JSON response.",
        xp_reward=70,
        accepted_answers=["SIEM_SPRAY_CORRELATION_RULE_ACTIVE"],
        mistake_explanations={
            "RULE_DEPLOYED": "RULE_DEPLOYED is the status string. Look for the verification_token field.",
        },
    ),
    TaskDefinition(
        task_id="task-05-bruteforce-correlation-challenge",
        order=5,
        title="Independent Challenge: Brute-Force Telemetry Verification",
        instructions=(
            "Reconstruct the full password spraying campaign parameters from your investigation. Submit the verified "
            "adversary source IP, attack classification, and count of targeted accounts via POST to the challenge endpoint:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"source_ip\":\"198.51.100.55\",\"attack_type\":\"PASSWORD_SPRAY\",\"targeted_accounts_count\":12}' http://10.10.14.90:8209/challenge`\n\n"
            "Submit the verification token returned upon successful verification."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned by the challenge endpoint.",
        hint="Deploy your correlation rule first, ensure your lab session is active, and submit source_ip, attack_type, and targeted_accounts_count (12).",
        xp_reward=50,
        accepted_answers=[
            "BRUTEFORCE_RULE_VERIFIED",
            "BRUTEFORCE_CORRELATION_CONFIRMED",
        ],
    ),
    TaskDefinition(
        task_id="task-06-bruteforce-quiz",
        order=6,
        title="Brute-Force & Credential Defense Technical Assessment",
        instructions="Answer the following 5 technical questions to verify comprehensive mastery of brute-force mechanics, password spraying, telemetry investigation, and SIEM correlation.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question technical assessment.",
        hint="Review authentication telemetry, lockout bypasses, and MITRE T1110 sub-techniques.",
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is password spraying significantly more difficult to detect than traditional password guessing?",
                options=[
                    "It distributes attempts across many accounts at low frequency, avoiding per-user lockout thresholds and individual account alerts.",
                    "It encrypts the network packets so firewalls cannot read TCP port numbers.",
                    "It only targets Linux domain controllers, which do not generate authentication logs.",
                    "It uses compromised digital certificates instead of passwords.",
                ],
                correct_option_index=0,
                explanation="Password spraying intentionally stays below individual account lockout thresholds by testing a small password list against many accounts over time.",
            ),
            QuizQuestion(
                id="q2",
                question="In Windows Security Event Logs, which Event ID indicates an audit failure for an attempted user logon?",
                options=[
                    "Event ID 4625",
                    "Event ID 4624",
                    "Event ID 4688",
                    "Event ID 1102",
                ],
                correct_option_index=0,
                explanation="Event ID 4625 records failed logon attempts. Event ID 4624 records successful logons.",
            ),
            QuizQuestion(
                id="q3",
                question="How should a SIEM correlation rule be configured to reliably detect password spraying?",
                options=[
                    "Group failed logon events by source IP and trigger when the count of distinct target usernames exceeds a threshold within a time window.",
                    "Count how many times a single username fails within 24 hours.",
                    "Alert only when CPU utilization on the domain controller exceeds 95%.",
                    "Block all IP addresses that initiate more than 1 SSH connection per month.",
                ],
                correct_option_index=0,
                explanation="Detecting password spraying requires aggregating events by source IP and counting distinct targeted usernames over a moving time window.",
            ),
            QuizQuestion(
                id="q4",
                question="What security control provides the strongest defense against automated password spraying and credential stuffing?",
                options=[
                    "Multi-Factor Authentication (MFA), especially FIDO2 / WebAuthn phishing-resistant tokens",
                    "Changing user passwords every 15 days",
                    "Hiding the IP address of the company website using DNS CNAME records",
                    "Requiring users to type their passwords in all uppercase letters",
                ],
                correct_option_index=0,
                explanation="MFA prevents adversaries from authenticating even if they successfully guess or obtain a valid password.",
            ),
            QuizQuestion(
                id="q5",
                question="What is the difference between credential stuffing (T1110.004) and password spraying (T1110.003)?",
                options=[
                    "Credential stuffing uses username/password pairs stolen from prior data breaches; password spraying tests common passwords across a known user list.",
                    "Credential stuffing only affects web applications, while password spraying only affects Wi-Fi networks.",
                    "There is no difference; both terms describe the exact same technique.",
                    "Password spraying uses automated bots while credential stuffing is always performed manually.",
                ],
                correct_option_index=0,
                explanation="Credential stuffing leverages breach dumps containing known valid pairs, whereas password spraying guesses common passwords across known organizational usernames.",
            ),
        ],
    ),
]

ROOM_BLUE_09_DEFINITION = RoomDefinition(
    room_id="blue-09-bruteforce-detection",
    track=TrackEnum.BLUE,
    room_number=9,
    title="Brute-Force Detection",
    short_description="Analyze authentication telemetry, identify password spraying vs dictionary attacks, deploy SIEM correlation rules, and enforce containment.",
    difficulty="Intermediate",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Distinguish between credential guessing, dictionary attacks, and password spraying (MITRE T1110)",
        "Parse Linux auth logs and Windows Event ID 4625 telemetry for failure patterns",
        "Author SIEM correlation rules aggregating multi-account failures by source IP",
        "Isolate adversary infrastructure and enforce adaptive account protection",
    ],
    assessment_criteria=[
        "Correctly categorize attack patterns from live log streams",
        "Deploy active SIEM threshold correlation rules",
        "Reconstruct multi-account spray parameters in the live target environment",
        "Pass the technical assessment with 100% accuracy",
    ],
    completion_requirements=["Complete all 6 tasks and validate the challenge flag"],
    concept=ROOM_BLUE_09_CONCEPT,
    tasks=ROOM_BLUE_09_TASKS,
    total_xp=350,
)


# ============================================================================
# BLUE ROOM 10: MALWARE BEHAVIOUR ANALYSIS (FULLY IMPLEMENTED)
# ============================================================================

ROOM_BLUE_10_CONCEPT = RoomConcept(
    overview=(
        "Malware Behaviour Analysis teaches safe static triage, Portable Executable (PE) dissection, cryptographic "
        "hashing, indicator extraction, and YARA signature authoring. Defensive analysts inspect suspicious binaries "
        "in an isolated sandbox to uncover persistence mechanisms, C2 communication domains, and malicious imports "
        "without running untrusted code on production hosts."
    ),
    simple_analogy=(
        "Imagine receiving an unverified suspicious package in the mail. Opening and detonating it on your desk to see "
        "what happens is dangerous and reckless (uncontrolled dynamic execution). Instead, a bomb technician places "
        "the package in a reinforced containment scanner, takes X-ray radiographs of the internal wiring, checks "
        "serial numbers against explosive catalogs, and identifies the detonator mechanism without ever triggering it "
        "(safe static analysis and signature matching). Safe triage extracts threat indicators while keeping the defender "
        "completely protected."
    ),
    technical_term="Portable Executable (PE32+) Dissection, Cryptographic Hashing & YARA Signatures",
    technical_definition=(
        "Static malware triage examines a binary's structure without CPU instruction execution. Analysts compute SHA-256 "
        "hashes for threat intelligence lookup, dissect PE headers (`IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS`, section tables "
        "such as `.text`, `.rdata`, `.data`), calculate section entropy to detect encryption or packing, extract ASCII/UTF-16 "
        "string tables for C2 URLs and registry keys, and inspect the Import Address Table (IAT) for high-risk Win32 APIs "
        "(`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, `RegSetValueEx`). YARA rules formalize these indicators "
        "into detection signatures evaluated across endpoint filesystems."
    ),
    cybersecurity_context=(
        "Live adversaries frequently deliver staged droppers designed to beacon out and download secondary payloads. "
        "Analyzing the initial dropper reveals the adversary's C2 domain, registry persistence keys, and campaign identifiers, "
        "enabling SOC teams to block outbound traffic network-wide before lateral movement begins."
    ),
    why_it_matters=(
        "Rapid, safe triage of suspicious files is essential during endpoint investigations. Extracting IOCs directly from "
        "quarantined files allows defenders to hunt for enterprise-wide infections within minutes."
    ),
    demonstration=(
        "1. Quarantined Sample Catalog:\n"
        "   GET /api/malware/samples on port 8210 -> Review metadata, file sizes, and SHA-256 hashes.\n\n"
        "2. String Extraction & YARA Scanning:\n"
        "   $ python3 /home/operator/tools/yara_scanner.py /home/operator/samples/dropper_sample.bin\n"
        "   Extract indicators including C2 URLs and persistence registry keys.\n\n"
        "3. PE Section & Import Inspection:\n"
        "   GET /api/malware/sample/dropper/headers on port 8210.\n\n"
        "4. YARA Rule Compilation:\n"
        "   POST /api/malware/yara/validate -> Compile custom YARA rule against the mock sample.\n\n"
        "5. Independent Challenge:\n"
        "   POST /challenge -> Submit sample hash, C2 URL, and persistence mechanism to earn security flag."
    ),
    remediation_guide=(
        "1. Never execute unverified attachments or downloads on host machines; perform all triage inside isolated sandboxes.\n"
        "2. Enforce Application Control policies (AppLocker or Windows Defender Application Control) to block untrusted executables.\n"
        "3. Configure EDR agents with YARA and behavioral heuristics to terminate processes attempting unapproved registry Run key modification.\n"
        "4. Immediately sinkhole and block confirmed C2 URLs and domains at perimeter firewalls and recursive DNS resolvers.\n"
        "5. Submit extracted file hashes to enterprise threat intelligence platforms to automate retrospective hunting."
    ),
)

ROOM_BLUE_10_TASKS = [
    TaskDefinition(
        task_id="task-01-static-vs-dynamic-analysis",
        order=1,
        title="Malware Analysis Fundamentals: Static vs Dynamic",
        instructions=(
            "Malware analysis is broadly divided into static analysis and dynamic analysis.\n\n"
            "What is the primary operational advantage of static analysis over dynamic analysis during initial triage?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the primary operational advantage of static analysis over dynamic analysis?",
        hint="Think about the risks of running untrusted code on a host machine.",
        xp_reward=50,
        accepted_answers=[
            "It does not execute the untrusted code",
            "It does not execute the code",
            "Safe analysis without execution",
            "No execution required",
            "Safety",
        ],
        mistake_explanations={
            "it is faster": "While static analysis can be fast, its primary security advantage is that the binary does not need to be executed.",
            "it captures network traffic": "Capturing live network traffic is a feature of dynamic analysis during execution.",
        },
    ),
    TaskDefinition(
        task_id="task-02-sample-hash-verification",
        order=2,
        title="Cryptographic Integrity Hashing & Sample Catalog",
        instructions=(
            "Inspect the quarantined sample catalog on port 8210:\n"
            "  `curl -s http://10.10.14.90:8210/api/malware/samples`\n\n"
            "What is the SHA-256 hash of the quarantined suspicious dropper sample `invoice_dropper.bin`?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the SHA-256 hash of invoice_dropper.bin?",
        hint="Inspect the sha256 field for sample-01 in the JSON response.",
        xp_reward=60,
        accepted_answers=[
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ],
        mistake_explanations={
            "d41d8cd98f00b204e9800998ecf8427e": "That is the MD5 hash. Provide the full 64-character SHA-256 hash.",
            "a8f5b1287c932014f3a09e1e21b83d1c440a831b79f09d2e1189c4a88b438e12": "That is the hash of sample-02 (beacon_stage.bin). Look for sample-01.",
        },
    ),
    TaskDefinition(
        task_id="task-03-pe-imports-persistence",
        order=3,
        title="PE Header Dissection & Persistence Indicator Extraction",
        instructions=(
            "Query the detailed PE structure and extracted strings of the dropper on port 8210:\n"
            "  `curl -s http://10.10.14.90:8210/api/malware/sample/dropper/headers`\n\n"
            "Or run the string scanner on the sample:\n"
            "  `python3 /home/operator/tools/yara_scanner.py /home/operator/samples/dropper_sample.bin`\n\n"
            "What Windows Registry key path does the dropper attempt to write for auto-start persistence?"
        ),
        task_type=TaskType.QUESTION,
        question="What Windows Registry key path is targeted for persistence?",
        hint="Look for the registry key under SOFTWARE\\Microsoft\\Windows\\CurrentVersion.",
        xp_reward=70,
        accepted_answers=[
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "SOFTWARE/Microsoft/Windows/CurrentVersion/Run",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Run",
        ],
        mistake_explanations={
            "VirtualAlloc": "VirtualAlloc is an imported memory allocation API, not a registry persistence key.",
            "gate.php": "gate.php is part of the C2 URL, not the registry persistence key.",
        },
    ),
    TaskDefinition(
        task_id="task-04-yara-rule-syntax-validation",
        order=4,
        title="YARA Rule Syntax Authoring & Validation",
        instructions=(
            "YARA allows analysts to create custom string and regex detection rules.\n\n"
            "Validate a YARA rule for the dropper by submitting a POST request to the analysis engine:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"rule_text\":\"rule Dropper_VoltStage_Win32 { strings: $a = \\\"VoltStage2_Payload\\\" condition: $a }\"}' http://10.10.14.90:8210/api/malware/yara/validate`\n\n"
            "Submit the verification token returned upon successful rule compilation."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned upon YARA rule validation.",
        hint="Look for the verification_token field in the JSON response.",
        xp_reward=70,
        accepted_answers=["YARA_SYNTAX_COMPILED_MATCHED"],
        mistake_explanations={
            "YARA_SYNTAX_VALID": "YARA_SYNTAX_VALID is the status string. Submit the verification_token value.",
        },
    ),
    TaskDefinition(
        task_id="task-05-malware-yara-rule-challenge",
        order=5,
        title="Independent Challenge: Dropper Signature Verification",
        instructions=(
            "Synthesize your static triage findings. Submit the dropper sample hash, the extracted C2 URL, "
            "and the persistence mechanism via POST to the challenge endpoint:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"sample_hash\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"c2_url\":\"http://c2-stage.voltcorp.internal/gate.php\",\"persistence_mechanism\":\"Registry RunKey\"}' http://10.10.14.90:8210/challenge`\n\n"
            "Submit the verification token returned upon signature confirmation."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned by the challenge endpoint.",
        hint="Compile your YARA rule first, ensure your lab session is active, and submit sample_hash, c2_url, and persistence_mechanism.",
        xp_reward=50,
        accepted_answers=[
            "MALWARE_YARA_MATCH_VERIFIED",
            "YARA_DROPPER_MATCHED",
        ],
    ),
    TaskDefinition(
        task_id="task-06-malware-quiz",
        order=6,
        title="Malware Analysis & Triage Technical Assessment",
        instructions="Complete the 5-question technical quiz to demonstrate comprehensive understanding of PE structures, section entropy, hashing, safe sample handling, and YARA authoring.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question technical assessment.",
        hint="Review PE file sections, entropy significance, and safe sandbox operations.",
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What does an unusually high Shannon entropy score (> 7.0) in a PE binary section typically indicate?",
                options=[
                    "The section contains encrypted, compressed, or packed data.",
                    "The file was compiled in debug mode.",
                    "The program is written in pure Python.",
                    "The binary has a valid digital signature.",
                ],
                correct_option_index=0,
                explanation="High entropy indicates randomness, which strongly correlates with encryption or packers used by adversaries to evade signature detection.",
            ),
            QuizQuestion(
                id="q2",
                question="Which Win32 API combination in an Import Address Table (IAT) is commonly associated with process injection?",
                options=[
                    "VirtualAlloc, WriteProcessMemory, and CreateRemoteThread",
                    "MessageBox, GetCommandLine, and ExitProcess",
                    "FindFirstFile, FindNextFile, and CloseHandle",
                    "GetSystemTime, SetTimer, and KillTimer",
                ],
                correct_option_index=0,
                explanation="Adversaries allocate memory in a remote process (VirtualAllocEx), write shellcode (WriteProcessMemory), and execute a new thread (CreateRemoteThread).",
            ),
            QuizQuestion(
                id="q3",
                question="Why is computing a cryptographic hash (e.g. SHA-256) of a suspicious binary critical during incident triage?",
                options=[
                    "It provides a deterministic unique identifier to check against threat intelligence databases without executing the file.",
                    "It automatically removes viruses from the hard drive.",
                    "It decompiles machine code into C source code.",
                    "It resets the file permissions to read-only.",
                ],
                correct_option_index=0,
                explanation="File hashes uniquely identify artifacts for reputation lookups (VirusTotal, internal SIEMs) and chain-of-custody tracking.",
            ),
            QuizQuestion(
                id="q4",
                question="What are the three required sections of a valid YARA rule?",
                options=[
                    "rule name, strings, and condition",
                    "import, export, and main",
                    "header, body, and footer",
                    "ip, port, and protocol",
                ],
                correct_option_index=0,
                explanation="A standard YARA rule requires a rule declaration, a `strings:` section defining patterns, and a `condition:` section defining boolean logic.",
            ),
            QuizQuestion(
                id="q5",
                question="Why should untrusted malware samples NEVER be executed on an analyst's primary workstation?",
                options=[
                    "Execution can infect the local system, compromise organizational credentials, and trigger outbound C2 beacons.",
                    "It will permanently break the Python interpreter.",
                    "Operating systems will automatically delete all source code files.",
                    "Antivirus software is not allowed to run on Windows.",
                ],
                correct_option_index=0,
                explanation="Untrusted malware can establish persistence, steal sensitive data, and propagate across internal subnets if executed outside an isolated sandbox.",
            ),
        ],
    ),
]

ROOM_BLUE_10_DEFINITION = RoomDefinition(
    room_id="blue-10-malware-behaviour-analysis",
    track=TrackEnum.BLUE,
    room_number=10,
    title="Malware Behaviour Analysis",
    short_description="Perform safe static triage of suspicious binaries, inspect PE headers, extract C2 URLs and persistence keys, and author YARA detection rules.",
    difficulty="Intermediate",
    estimated_duration="50 min",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Perform safe static triage of suspicious binaries without live execution",
        "Dissect Portable Executable (PE32+) headers, sections, and import tables",
        "Extract indicators of compromise (C2 domains, persistence keys, and payload hashes)",
        "Author and compile custom YARA rules for automated endpoint detection",
    ],
    assessment_criteria=[
        "Extract valid cryptographic hashes and PE structural metadata",
        "Identify high-risk API imports and persistence registry keys",
        "Compile valid YARA signatures matching target indicators",
        "Pass the technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 6 tasks and validate the challenge flag"],
    concept=ROOM_BLUE_10_CONCEPT,
    tasks=ROOM_BLUE_10_TASKS,
    total_xp=350,
)


# ============================================================================
# BLUE ROOM 11: PHISHING INVESTIGATION (FULLY IMPLEMENTED)
# ============================================================================

ROOM_BLUE_11_CONCEPT = RoomConcept(
    overview=(
        "Phishing Investigation teaches security analysts how to dissect suspicious emails, inspect RFC 5322 headers, "
        "verify email authentication mechanisms (SPF, DKIM, and DMARC), spot lookalike and typosquatted domains, and "
        "remediate spear-phishing and Business Email Compromise (BEC) attacks."
    ),
    simple_analogy=(
        "Imagine receiving a letter in an envelope with an official bank logo stamped on the front. Anyone with a color "
        "printer can forge a logo (display 'From:' header). But looking closely at the post office tracking stamps on the "
        "back of the envelope reveals it was mailed from an unauthorized address, not the bank's central dispatch center "
        "(envelope 'Return-Path:' and SMTP 'Received:' chain). Email authentication protocols like SPF, DKIM, and DMARC "
        "act like cryptographic wax seals and verified dispatch logs: if the sender's IP isn't on the bank's approved list "
        "or the seal is broken, the mail carrier routes the letter directly into the incinerator."
    ),
    technical_term="Email Header Forensics, RFC 7208 (SPF), RFC 6376 (DKIM) & RFC 7489 (DMARC) Alignment",
    technical_definition=(
        "Email forensics inspects the RFC 5322 message structure. Key header fields include `Received` (chronological MTA "
        "routing hops), `Return-Path` (envelope bounce address), `From` (display sender), `Reply-To`, and `Message-ID`. "
        "SPF verifies that the transmitting Mail Transfer Agent (MTA) IP address is authorized in the sender domain's DNS "
        "TXT record. DKIM verifies a public-key cryptographic signature attached in the `DKIM-Signature` header. DMARC "
        "verifies domain alignment: it requires that the domain in the visible `From:` header matches the SPF-validated or "
        "DKIM-validated domain, and specifies policy actions (`none`, `quarantine`, `reject`)."
    ),
    cybersecurity_context=(
        "Phishing remains the primary vector for corporate initial access, ransomware deployment, and credential harvesting. "
        "Adversaries employ lookalike domains (e.g. `v0ltcorp.internal` replacing 'o' with '0') to impersonate executives "
        "and deceive users into submitting SSO credentials to harvesting portals."
    ),
    why_it_matters=(
        "Rapid triage of user-reported phishing emails allows SOC analysts to quarantine malicious messages across all "
        "inboxes, block adversary sender infrastructure, and revoke compromised user credentials before a breach expands."
    ),
    demonstration=(
        "1. Quarantined Email Queue:\n"
        "   GET /api/phishing/emails on port 8211 -> View quarantined message queue.\n\n"
        "2. Header Forensics via Helper Script:\n"
        "   $ python3 /home/operator/tools/inspect_email.py /home/operator/emails/password_reset.eml\n"
        "   Extract Return-Path, SPF, DKIM, and DMARC authentication verdicts.\n\n"
        "3. Header Breakdown API:\n"
        "   GET /api/phishing/headers/EML-2026-02 on port 8211.\n\n"
        "4. Triage Submission:\n"
        "   POST /api/phishing/triage -> Submit threat classification and quarantined lookalike domain.\n\n"
        "5. Independent Challenge:\n"
        "   POST /challenge -> Submit email ID, DMARC result, lookalike domain, and remediation action to earn flag."
    ),
    remediation_guide=(
        "1. Enforce DMARC policy at `p=reject` with strict alignment for all corporate email sending domains.\n"
        "2. Deploy Secure Email Gateways (SEG) that evaluate incoming messages with machine learning for typosquatted lookalikes.\n"
        "3. Implement automated inbox purging (Search-Mailbox / Microsoft Defender for Office 365) to remove phishing messages globally.\n"
        "4. Immediately revoke active session tokens and force password resets for any user who clicked phishing links.\n"
        "5. Register common typosquatting permutations of company domains to prevent adversary acquisition."
    ),
)

ROOM_BLUE_11_TASKS = [
    TaskDefinition(
        task_id="task-01-email-auth-trio",
        order=1,
        title="Email Authentication Trio: SPF, DKIM, and DMARC",
        instructions=(
            "Modern email defense relies on three complementary protocols: SPF, DKIM, and DMARC.\n\n"
            "Which protocol specifically enforces 'Domain Alignment' by ensuring that the domain visible in the "
            "header 'From:' field matches the authenticated domain validated by SPF or DKIM?"
        ),
        task_type=TaskType.QUESTION,
        question="Which protocol enforces domain alignment between the visible From address and SPF/DKIM?",
        hint="It allows domain owners to publish policies like p=quarantine or p=reject.",
        xp_reward=50,
        accepted_answers=["DMARC", "dmarc"],
        mistake_explanations={
            "spf": "SPF only verifies that the sender IP is authorized for the Return-Path envelope domain; it does not check alignment with the visible From: header.",
            "dkim": "DKIM provides cryptographic signature verification for the message body and headers, but does not enforce alignment with the From: header without DMARC.",
        },
    ),
    TaskDefinition(
        task_id="task-02-quarantined-email-triage",
        order=2,
        title="Quarantined Email Queue Inspection",
        instructions=(
            "Query the quarantined mail queue on port 8211:\n"
            "  `curl -s http://10.10.14.90:8211/api/phishing/emails`\n\n"
            "Identify the suspicious phishing email ID exhibiting authentication failures and lookalike domain spoofing."
        ),
        task_type=TaskType.QUESTION,
        question="What is the email ID of the suspicious phishing message in the quarantine queue?",
        hint="Look for the email with classification SUSPICIOUS_PHISHING.",
        xp_reward=60,
        accepted_answers=["EML-2026-02"],
        mistake_explanations={
            "EML-2026-01": "EML-2026-01 is a verified benign vendor invoice with passing SPF, DKIM, and DMARC records.",
        },
    ),
    TaskDefinition(
        task_id="task-03-lookalike-domain-identification",
        order=3,
        title="Header Forensics & Lookalike Domain Detection",
        instructions=(
            "Inspect the parsed headers of the suspicious email on port 8211:\n"
            "  `curl -s http://10.10.14.90:8211/api/phishing/headers/EML-2026-02`\n\n"
            "Or run the analyst helper tool on the raw `.eml` file:\n"
            "  `python3 /home/operator/tools/inspect_email.py /home/operator/emails/password_reset.eml`\n\n"
            "What typosquatted lookalike domain was used in the envelope Return-Path to deceive enterprise recipients?"
        ),
        task_type=TaskType.QUESTION,
        question="What lookalike domain is used in the Return-Path header?",
        hint="Notice the substitution of the digit '0' for the letter 'o'.",
        xp_reward=70,
        accepted_answers=["v0ltcorp.internal"],
        mistake_explanations={
            "voltcorp.internal": "voltcorp.internal is the legitimate corporate domain. Look for the typosquatted lookalike.",
            "198.51.100.99": "198.51.100.99 is the sender IP address. Provide the domain name.",
        },
    ),
    TaskDefinition(
        task_id="task-04-phishing-triage-submission",
        order=4,
        title="Phishing Incident Triage & Domain Quarantine",
        instructions=(
            "Submit a formal phishing incident triage request via POST to the gateway:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"email_id\":\"EML-2026-02\",\"threat_category\":\"SPEAR_PHISHING\",\"spoofed_domain\":\"v0ltcorp.internal\"}' http://10.10.14.90:8211/api/phishing/triage`\n\n"
            "Submit the verification token returned upon triage verification."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned upon triage confirmation.",
        hint="Look for the verification_token field in the JSON response.",
        xp_reward=70,
        accepted_answers=["PHISHING_TRIAGE_VERIFIED_V0LTCORP"],
        mistake_explanations={
            "TRIAGE_ACCEPTED": "TRIAGE_ACCEPTED is the status string. Look for the verification_token field.",
        },
    ),
    TaskDefinition(
        task_id="task-05-phishing-triage-remediation-challenge",
        order=5,
        title="Independent Challenge: Phishing Incident Containment",
        instructions=(
            "Synthesize your email investigation findings. Submit the email ID, the DMARC authentication verdict, "
            "the identified lookalike domain, and the remediation action via POST to the challenge endpoint:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"email_id\":\"EML-2026-02\",\"dmarc_result\":\"FAIL\",\"lookalike_domain\":\"v0ltcorp.internal\",\"remediation_action\":\"PURGE_AND_BLOCK\"}' http://10.10.14.90:8211/challenge`\n\n"
            "Submit the verification token returned upon incident containment."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned by the challenge endpoint.",
        hint="Submit incident triage first, ensure your lab session is active, and submit email_id, dmarc_result, lookalike_domain, and remediation_action.",
        xp_reward=50,
        accepted_answers=[
            "PHISHING_INCIDENT_CONTAINED",
            "PHISHING_SPOOF_CONTAINED",
        ],
    ),
    TaskDefinition(
        task_id="task-06-phishing-quiz",
        order=6,
        title="Email Security & Phishing Forensics Technical Assessment",
        instructions="Answer the following 5 technical questions to verify comprehensive mastery of email header analysis, SPF records, DKIM signatures, DMARC enforcement, and containment workflows.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question technical assessment.",
        hint="Review email headers, DMARC policies, and typosquatting detection.",
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Which email header field provides the most reliable chronological record of every mail server hop the message traversed?",
                options=[
                    "Received",
                    "From",
                    "Subject",
                    "To",
                ],
                correct_option_index=0,
                explanation="Each Mail Transfer Agent (MTA) appends a new `Received:` header line at the top of the message as it handles the email, creating an immutable routing trail.",
            ),
            QuizQuestion(
                id="q2",
                question="What does an SPF record published in DNS actually validate?",
                options=[
                    "The IP addresses authorized to send emails on behalf of that domain.",
                    "The password of the email account.",
                    "Whether the recipient's computer has antivirus installed.",
                    "The credit card information associated with domain registration.",
                ],
                correct_option_index=0,
                explanation="SPF (Sender Policy Framework) is a DNS TXT record listing IP addresses and subnets authorized to dispatch email for that domain.",
            ),
            QuizQuestion(
                id="q3",
                question="If a domain publishes a DMARC policy of 'p=reject', what should a receiving mail server do with an incoming message that fails both SPF and DKIM alignment?",
                options=[
                    "Refuse delivery and drop or bounce the message completely.",
                    "Deliver the message directly into the recipient's primary inbox.",
                    "Forward the email to the police.",
                    "Reply to the sender asking them to resend it.",
                ],
                correct_option_index=0,
                explanation="Under `p=reject`, receiving mail transfer agents must completely block and drop emails failing alignment.",
            ),
            QuizQuestion(
                id="q4",
                question="What attack technique replaces characters in a trusted domain name with visually identical characters (e.g. replacing 'o' with '0' or using Cyrillic characters)?",
                options=[
                    "Typosquatting / IDN Homograph Attack",
                    "SQL Injection",
                    "Buffer Overflow",
                    "SYN Flood",
                ],
                correct_option_index=0,
                explanation="Typosquatting and homograph attacks leverage visually indistinguishable characters to deceive users into trusting fraudulent domain names.",
            ),
            QuizQuestion(
                id="q5",
                question="What is the immediate priority containment action when a user reports having entered their domain credentials on a phishing portal?",
                options=[
                    "Immediately revoke active sessions, reset domain credentials, and audit for suspicious sign-ins or MFA additions.",
                    "Format the domain controller hard drives.",
                    "Send an angry email to the attacker's email address.",
                    "Wait 48 hours to see if any unauthorized logins occur.",
                ],
                correct_option_index=0,
                explanation="Revoking active tokens, resetting passwords, and auditing authentication logs prevents immediate session hijacking and credential re-use.",
            ),
        ],
    ),
]

ROOM_BLUE_11_DEFINITION = RoomDefinition(
    room_id="blue-11-phishing-investigation",
    track=TrackEnum.BLUE,
    room_number=11,
    title="Phishing Investigation",
    short_description="Analyze email headers, evaluate SPF, DKIM, and DMARC alignment, identify lookalike domains, and execute incident containment.",
    difficulty="Beginner",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Dissect RFC 5322 email headers (Received, Return-Path, Authentication-Results)",
        "Evaluate SPF, DKIM, and DMARC records to detect unauthorized spoofing",
        "Identify typosquatted and lookalike domain infrastructure",
        "Execute incident response workflows: quarantine messages, block domains, and reset credentials",
    ],
    assessment_criteria=[
        "Correctly evaluate email header authentication records",
        "Identify lookalike domains used in executive impersonation attacks",
        "Submit validated phishing triage classifications",
        "Pass the technical assessment with 100% accuracy",
    ],
    completion_requirements=["Complete all 6 tasks and validate the challenge flag"],
    concept=ROOM_BLUE_11_CONCEPT,
    tasks=ROOM_BLUE_11_TASKS,
    total_xp=350,
)


# ============================================================================
# BLUE ROOM 12: ENDPOINT DETECTION (FULLY IMPLEMENTED)
# ============================================================================

ROOM_BLUE_12_CONCEPT = RoomConcept(
    overview=(
        "Endpoint Detection teaches defenders how to leverage Endpoint Detection and Response (EDR) telemetry to hunt "
        "for active threats. Security analysts inspect process trees (PID vs PPID), detect Living-off-the-Land Binaries "
        "(LOLBINs), correlate network socket telemetry to active processes, author behavioral detection rules, and "
        "execute emergency host containment."
    ),
    simple_analogy=(
        "Imagine a security guard monitoring access doors at a bank. Perimeter guards verify badges at the entrance. "
        "An EDR agent is like a personal chaperone assigned to every person who enters the building. The chaperone "
        "records not just who enters, but what tools they pick up, who handed them those tools (parent process), and "
        "what doors they open. If a bank teller (Word document) suddenly walks into the basement vault carrying a "
        "crowbar and a high-frequency radio transmitter (PowerShell executing hidden commands to an external IP), "
        "the chaperone immediately sounds the alarm and handcuffs the rogue actor (host isolation)."
    ),
    technical_term="Process Lineage (PPID/PID), LOLBIN Abuse & EDR Host Containment (MITRE ATT&CK T1059.001 / T1218)",
    technical_definition=(
        "EDR telemetry captures operating system kernel and userland events via Event Tracing for Windows (ETW), Microsoft-Windows-Threat-Intelligence, "
        "or Linux eBPF. Critical telemetry includes process execution events (PID, Parent PID/PPID, full command line, user context, image hashes), "
        "file modifications, and TCP/UDP socket connections. Living-off-the-Land Binaries (LOLBINs) are trusted, pre-installed OS utilities "
        "(`powershell.exe`, `certutil.exe`, `mshta.exe`, `rundll32.exe`) abused by adversaries for stealthy execution. EDR rules detect abnormal "
        "process lineage (e.g., `winword.exe` -> `powershell.exe -w hidden -enc`) and enforce endpoint network isolation."
    ),
    cybersecurity_context=(
        "Modern adversaries rarely drop custom uncompiled binaries on disk during initial execution; doing so triggers antivirus signatures. "
        "Instead, they abuse native LOLBINs to execute fileless memory payloads and establish outbound command-and-control beacons. "
        "Hunting based on abnormal process parentage is the most effective technique for detecting living-off-the-land attacks."
    ),
    why_it_matters=(
        "Endpoint telemetry provides ground truth on what executed, how it started, and where it communicated. Rapidly isolating "
        "a compromised endpoint prevents an adversary from dumping LSASS credentials or pivoting laterally across the domain."
    ),
    demonstration=(
        "1. Process Telemetry Query:\n"
        "   GET /api/endpoint/telemetry/processes on port 8212.\n\n"
        "2. Process Tree Inspection via CLI Helper:\n"
        "   $ python3 /home/operator/tools/edr_query.py\n"
        "   Inspect PID vs PPID relationships and highlight anomalous child processes.\n\n"
        "3. Network Socket Telemetry:\n"
        "   GET /api/endpoint/telemetry/network on port 8212 -> Correlate PID 4812 to external C2 IP.\n\n"
        "4. Deploy EDR Behavioral Rule:\n"
        "   POST /api/endpoint/rules -> Deploy rule blocking Word spawning PowerShell.\n\n"
        "5. Independent Challenge & Host Containment:\n"
        "   POST /challenge -> Submit malicious PID, parent process, LOLBIN name, and C2 IP to receive flag."
    ),
    remediation_guide=(
        "1. Deploy Attack Surface Reduction (ASR) rules: 'Block all Office applications from creating child processes'.\n"
        "2. Enforce PowerShell ConstrainedLanguage mode and enable Script Block Logging (Event ID 4104).\n"
        "3. Configure EDR agents to automatically isolate endpoints exhibiting LOLBIN command-and-control beacons.\n"
        "4. Terminate malicious process trees and preserve memory artifacts for memory forensics before rebooting.\n"
        "5. Revoke cached credentials on the compromised host and reset the associated user account password."
    ),
)

ROOM_BLUE_12_TASKS = [
    TaskDefinition(
        task_id="task-01-edr-process-parentage",
        order=1,
        title="Process Lineage & Abnormal Parent-Child Relationships",
        instructions=(
            "In operating system telemetry, every process has a Process Identifier (PID) and a Parent Process Identifier (PPID).\n\n"
            "Under standard enterprise operation, what software application should NEVER legitimately spawn an interactive "
            "command shell or scripting engine (such as `powershell.exe` or `cmd.exe`)?"
        ),
        task_type=TaskType.QUESTION,
        question="What common productivity application should never legitimately spawn PowerShell or CMD?",
        hint="Think of Microsoft Office applications like Microsoft Word or Excel.",
        xp_reward=50,
        accepted_answers=[
            "Microsoft Word",
            "winword.exe",
            "Word",
            "Microsoft Office",
            "Excel",
        ],
        mistake_explanations={
            "explorer.exe": "explorer.exe is the Windows desktop shell; when a user clicks a terminal icon, explorer legitimately spawns it.",
            "services.exe": "services.exe is the Windows Service Control Manager, which starts background system daemons.",
        },
    ),
    TaskDefinition(
        task_id="task-02-edr-telemetry-query",
        order=2,
        title="EDR Process Telemetry & LOLBIN Discovery",
        instructions=(
            "Query the live EDR process telemetry on port 8212:\n"
            "  `curl -s http://10.10.14.90:8212/api/endpoint/telemetry/processes`\n\n"
            "Or run the EDR query tool on your workstation:\n"
            "  `python3 /home/operator/tools/edr_query.py`\n\n"
            "What is the Process ID (PID) of the suspicious hidden PowerShell process spawned by `winword.exe`?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the PID of the suspicious PowerShell process spawned by winword.exe?",
        hint="Inspect the child process with PPID 1204.",
        xp_reward=60,
        accepted_answers=["4812"],
        mistake_explanations={
            "1204": "PID 1204 is the parent process winword.exe. Look for the child process spawned by it.",
            "1120": "PID 1120 is explorer.exe.",
        },
    ),
    TaskDefinition(
        task_id="task-03-lolbin-c2-socket",
        order=3,
        title="Network Socket Correlation & C2 Address Extraction",
        instructions=(
            "Query the active network socket telemetry on port 8212:\n"
            "  `curl -s http://10.10.14.90:8212/api/endpoint/telemetry/network`\n\n"
            "What foreign IP address is the malicious PowerShell process (PID 4812) connected to over port 443?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the foreign C2 IP address connected to PID 4812?",
        hint="Inspect the foreign_addr field associated with PID 4812.",
        xp_reward=70,
        accepted_answers=["198.51.100.88"],
        mistake_explanations={
            "10.10.14.50": "10.10.14.50 is the local endpoint IP address.",
            "10.10.14.90": "10.10.14.90 is the internal domain controller IP.",
        },
    ),
    TaskDefinition(
        task_id="task-04-edr-rule-deployment",
        order=4,
        title="EDR Behavioral Rule Authoring & Deployment",
        instructions=(
            "Deploy a behavioral detection rule to block Office applications from launching script engines.\n\n"
            "Submit a POST request to the EDR rules engine:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"parent_process\":\"winword.exe\",\"child_process\":\"powershell.exe\"}' http://10.10.14.90:8212/api/endpoint/rules`\n\n"
            "Submit the verification token returned upon activating the EDR rule."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned upon EDR rule deployment.",
        hint="Look for the verification_token field in the JSON response.",
        xp_reward=70,
        accepted_answers=["EDR_LOLBIN_RULE_ACTIVE_CONFIRMED"],
        mistake_explanations={
            "EDR_DETECTION_RULE_ACTIVE": "EDR_DETECTION_RULE_ACTIVE is the status string. Look for the verification_token field.",
        },
    ),
    TaskDefinition(
        task_id="task-05-edr-threat-hunting-containment-challenge",
        order=5,
        title="Independent Challenge: EDR Threat Hunting & Host Containment",
        instructions=(
            "Synthesize your endpoint investigation. Submit the malicious PID, the parent process name, "
            "the LOLBIN executable name, and the foreign C2 IP address via POST to the challenge endpoint:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"malicious_pid\":4812,\"parent_process\":\"winword.exe\",\"lolbin\":\"powershell.exe\",\"c2_ip\":\"198.51.100.88\"}' http://10.10.14.90:8212/challenge`\n\n"
            "Submit the verification token returned upon EDR containment verification."
        ),
        task_type=TaskType.FLAG,
        question="Submit the verification token returned by the challenge endpoint.",
        hint="Deploy behavioral LOLBIN rule first, ensure your lab session is active, and submit malicious_pid, parent_process, lolbin, and c2_ip.",
        xp_reward=50,
        accepted_answers=[
            "EDR_CONTAINMENT_VERIFIED",
            "LOLBIN_POWERSHELL_CONTAINED",
        ],
    ),
    TaskDefinition(
        task_id="task-06-endpoint-quiz",
        order=6,
        title="Endpoint Detection & EDR Operations Technical Assessment",
        instructions="Answer the following 5 technical questions to verify comprehensive mastery of EDR telemetry, process trees, LOLBIN exploitation, network socket correlation, and host containment.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question technical assessment.",
        hint="Review process lineage, LOLBINs, Attack Surface Reduction, and endpoint isolation.",
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is a 'Living off the Land Binary' (LOLBIN)?",
                options=[
                    "A legitimate, pre-installed operating system executable abused by adversaries to execute malicious actions without dropping new binaries.",
                    "An open-source Linux kernel module used for farming simulations.",
                    "A virus that only infects computers with solid-state drives.",
                    "A special programming language designed for green energy datacenters.",
                ],
                correct_option_index=0,
                explanation="LOLBINs (e.g. powershell.exe, certutil.exe, mshta.exe) are trusted system utilities abused by threat actors for stealthy post-exploitation.",
            ),
            QuizQuestion(
                id="q2",
                question="Why is inspecting the Parent Process ID (PPID) critical when analyzing an execution of powershell.exe?",
                options=[
                    "PowerShell spawned by a user terminal is normal, but PowerShell spawned by a Word document or web server indicates malicious exploitation.",
                    "PowerShell cannot run unless its PPID is an even number.",
                    "PPID determines what encryption algorithm PowerShell uses.",
                    "The PPID reveals the geographic location of the user.",
                ],
                correct_option_index=0,
                explanation="Process parentage reveals the origin of the execution. Word or web servers spawning shell binaries is a primary indicator of compromise.",
            ),
            QuizQuestion(
                id="q3",
                question="What Windows security feature blocks Microsoft Office applications from creating child processes?",
                options=[
                    "Attack Surface Reduction (ASR) rules",
                    "Windows Media Player Network Sharing Service",
                    "Internet Explorer Compatibility Mode",
                    "BitLocker Drive Encryption",
                ],
                correct_option_index=0,
                explanation="Microsoft Defender Attack Surface Reduction (ASR) rules specifically prevent Office applications from creating child processes.",
            ),
            QuizQuestion(
                id="q4",
                question="What happens when an analyst initiates 'Host Network Isolation' via an EDR console?",
                options=[
                    "The endpoint's network stack is blocked from all communication except for the encrypted management channel to the EDR console.",
                    "The computer is physically powered off and wiped.",
                    "All files on the hard drive are immediately deleted.",
                    "The computer is assigned a public IP address.",
                ],
                correct_option_index=0,
                explanation="Host isolation severs all internal and external network traffic, stopping lateral movement and C2 communication, while preserving EDR analyst access.",
            ),
            QuizQuestion(
                id="q5",
                question="Why should an infected endpoint NOT be immediately rebooted when an active intrusion is detected?",
                options=[
                    "Rebooting destroys volatile RAM evidence, unwritten C2 connection state, and injected memory-only artifacts.",
                    "Rebooting will make the computer catch fire.",
                    "Operating systems permanently lock down if rebooted during an incident.",
                    "Rebooting will send an automated email to the FBI.",
                ],
                correct_option_index=0,
                explanation="Volatile memory (RAM) contains active encryption keys, injected shellcode, process trees, and open socket states that are lost upon reboot.",
            ),
        ],
    ),
]

ROOM_BLUE_12_DEFINITION = RoomDefinition(
    room_id="blue-12-endpoint-detection",
    track=TrackEnum.BLUE,
    room_number=12,
    title="Endpoint Detection",
    short_description="Investigate EDR telemetry, audit abnormal process trees (PID/PPID), identify LOLBIN abuse, deploy behavioral rules, and enforce endpoint containment.",
    difficulty="Intermediate",
    estimated_duration="50 min",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Inspect EDR process telemetry and correlate PID to Parent Process ID (PPID)",
        "Detect Living-off-the-Land Binary (LOLBIN) abuse and fileless PowerShell staging",
        "Correlate active network socket connections directly to executing processes",
        "Author EDR behavioral rules and enforce endpoint network isolation",
    ],
    assessment_criteria=[
        "Identify abnormal process lineages and extract malicious process parameters",
        "Correlate active C2 sockets to malicious PIDs",
        "Deploy active behavioral EDR rules",
        "Pass the technical assessment with 100% accuracy",
    ],
    completion_requirements=["Complete all 6 tasks and validate the challenge flag"],
    concept=ROOM_BLUE_12_CONCEPT,
    tasks=ROOM_BLUE_12_TASKS,
    total_xp=350,
)
