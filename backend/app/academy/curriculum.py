"""
Complete 80-Room Cybersecurity Curriculum Registry for NO ENTRY Academy.
Covers 4 tracks × 20 rooms each = 80 practical rooms:
1. RED TEAM (Rooms 01–20) — All 20 rooms are fully IMPLEMENTED (20/20).
2. BLUE TEAM (Rooms 01–20) — All 20 rooms planned with full curriculum metadata.
3. PURPLE TEAM (Rooms 01–20) — All 20 rooms planned with full curriculum metadata.
4. DETECTION ENGINEERING (Rooms 01–20) — All 20 rooms planned with full curriculum metadata.
"""

from typing import Dict, List, Optional
from backend.app.academy.models import (
    QuizQuestion,
    RoomConcept,
    RoomDefinition,
    RoomStatus,
    TaskDefinition,
    TaskType,
    TrackEnum,
)
from backend.app.academy.rooms_05_08 import (
    ROOM_05_DEFINITION,
    ROOM_06_DEFINITION,
    ROOM_07_DEFINITION,
    ROOM_08_DEFINITION,
)
from backend.app.academy.rooms_10_13 import (
    ROOM_10_DEFINITION,
    ROOM_11_DEFINITION,
    ROOM_12_DEFINITION,
    ROOM_13_DEFINITION,
)
from backend.app.academy.rooms_14_17 import (
    ROOM_14_DEFINITION,
    ROOM_15_DEFINITION,
    ROOM_16_DEFINITION,
    ROOM_17_DEFINITION,
)
from backend.app.academy.rooms_18_20 import (
    ROOM_18_DEFINITION,
    ROOM_19_DEFINITION,
    ROOM_20_DEFINITION,
)
from backend.app.academy.rooms_blue_01_04 import (
    ROOM_BLUE_01_DEFINITION,
    ROOM_BLUE_02_DEFINITION,
    ROOM_BLUE_03_DEFINITION,
    ROOM_BLUE_04_DEFINITION,
)
from backend.app.academy.rooms_blue_05_08 import (
    ROOM_BLUE_05_DEFINITION,
    ROOM_BLUE_06_DEFINITION,
    ROOM_BLUE_07_DEFINITION,
    ROOM_BLUE_08_DEFINITION,
)
from backend.app.academy.rooms_blue_09_12 import (
    ROOM_BLUE_09_DEFINITION,
    ROOM_BLUE_10_DEFINITION,
    ROOM_BLUE_11_DEFINITION,
    ROOM_BLUE_12_DEFINITION,
)
from backend.app.academy.rooms_blue_13_16 import (
    ROOM_BLUE_13_DEFINITION,
    ROOM_BLUE_14_DEFINITION,
    ROOM_BLUE_15_DEFINITION,
    ROOM_BLUE_16_DEFINITION,
)
from backend.app.academy.rooms_blue_17_20 import (
    ROOM_BLUE_17_DEFINITION,
    ROOM_BLUE_18_DEFINITION,
    ROOM_BLUE_19_DEFINITION,
    ROOM_BLUE_20_DEFINITION,
)
from backend.app.academy.rooms_purple_01_04 import (
    ROOM_PURPLE_01_DEFINITION,
    ROOM_PURPLE_02_DEFINITION,
    ROOM_PURPLE_03_DEFINITION,
    ROOM_PURPLE_04_DEFINITION,
)
from backend.app.academy.rooms_purple_05_08 import (
    ROOM_PURPLE_05_DEFINITION,
    ROOM_PURPLE_06_DEFINITION,
    ROOM_PURPLE_07_DEFINITION,
    ROOM_PURPLE_08_DEFINITION,
)
from backend.app.academy.rooms_purple_09_12 import (
    ROOM_PURPLE_09_DEFINITION,
    ROOM_PURPLE_10_DEFINITION,
    ROOM_PURPLE_11_DEFINITION,
    ROOM_PURPLE_12_DEFINITION,
)
from backend.app.academy.rooms_purple_13_16 import (
    ROOM_PURPLE_13_DEFINITION,
    ROOM_PURPLE_14_DEFINITION,
    ROOM_PURPLE_15_DEFINITION,
    ROOM_PURPLE_16_DEFINITION,
)
from backend.app.academy.rooms_purple_17_20 import (
    ROOM_PURPLE_17_DEFINITION,
    ROOM_PURPLE_18_DEFINITION,
    ROOM_PURPLE_19_DEFINITION,
    ROOM_PURPLE_20_DEFINITION,
)
from backend.app.academy.rooms_detection_01_04 import (
    ROOM_DETECTION_01_DEFINITION,
    ROOM_DETECTION_02_DEFINITION,
    ROOM_DETECTION_03_DEFINITION,
    ROOM_DETECTION_04_DEFINITION,
)
from backend.app.academy.rooms_detection_05_08 import (
    ROOM_DETECTION_05_DEFINITION,
    ROOM_DETECTION_06_DEFINITION,
    ROOM_DETECTION_07_DEFINITION,
    ROOM_DETECTION_08_DEFINITION,
)
from backend.app.academy.rooms_detection_09_12 import (
    ROOM_DETECTION_09_DEFINITION,
    ROOM_DETECTION_10_DEFINITION,
    ROOM_DETECTION_11_DEFINITION,
    ROOM_DETECTION_12_DEFINITION,
)
from backend.app.academy.rooms_detection_13_16 import (
    ROOM_DETECTION_13_DEFINITION,
    ROOM_DETECTION_14_DEFINITION,
    ROOM_DETECTION_15_DEFINITION,
    ROOM_DETECTION_16_DEFINITION,
)
from backend.app.academy.rooms_detection_17_20 import (
    ROOM_DETECTION_17_DEFINITION,
    ROOM_DETECTION_18_DEFINITION,
    ROOM_DETECTION_19_DEFINITION,
    ROOM_DETECTION_20_DEFINITION,
)

# ============================================================================
# ROOM 01: CYBERSECURITY FOUNDATIONS (FULLY IMPLEMENTED)
# ============================================================================

ROOM_01_CONCEPT = RoomConcept(
    overview=(
        "Cybersecurity is the discipline of protecting digital systems, networks, devices, and data from "
        "unauthorized access, malicious modification, disruption, or destruction. At its core, security "
        "governance balances three foundational objectives: Confidentiality, Integrity, and Availability (The CIA Triad)."
    ),
    simple_analogy=(
        "Think of a bank safety deposit vault. Confidentiality means only authorized keyholders can see inside the box; "
        "unauthorized strangers cannot peek. Integrity means nobody can tamper with your valuables or swap your gold bars "
        "for counterfeit lead while in the vault. Availability means whenever you show up with your key during banking hours, "
        "the vault door is operational and you can access your assets. If a burglar reads your private papers, Confidentiality is lost. "
        "If an insider alters your documents, Integrity is broken. If an arsonist burns the bank down, Availability is destroyed."
    ),
    technical_term="The CIA Triad & Information Security Governance (NIST SP 800-53 / ISO 27001)",
    technical_definition=(
        "Information security centers on preserving three fundamental properties: Confidentiality (preventing unauthorized disclosure of data), "
        "Integrity (safeguarding the accuracy and completeness of assets and data against unauthorized modification), and Availability (ensuring "
        "authorized operators have timely, dependable access to resources and services). A Threat represents a potential event or actor capable of "
        "causing harm. A Vulnerability is a flaw or weakness in software, hardware, or operational procedure. Risk is the likelihood of a threat actor "
        "exploiting a vulnerability multiplied by the potential operational impact (Risk = Threat × Vulnerability × Impact)."
    ),
    cybersecurity_context=(
        "Red Teams identify attack surfaces and demonstrate how vulnerabilities can be exploited to compromise CIA properties. "
        "Blue Teams deploy security controls (firewalls, EDR, access controls, backups) to defend assets and detect incidents. "
        "Purple Teams perform threat emulation where offensive operators execute tactics while defensive engineers tune detections and logging in real time. "
        "Ethical hacking requires explicit written authorization (Rules of Engagement) defining legal scope, permitted tools, and testing boundaries."
    ),
    why_it_matters=(
        "Every security policy, firewall rule, encryption algorithm, and audit requirement maps back to the CIA Triad and risk equation. "
        "Misclassifying an asset's risk leads to either catastrophic data breaches or wasted operational budget."
    ),
    demonstration=(
        "Asset Inspection Example:\n"
        "  File: /home/operator/assets/customer_records.db (Permissions: 0666 / rw-rw-rw-)\n"
        "  Vulnerability: World-writable permissions allow unprivileged users to alter database balances.\n"
        "  CIA Impact: Violates Integrity (data can be altered) and Confidentiality (data can be read).\n"
        "  Remediation: chmod 600 customer_records.db\n"
    ),
    remediation_guide=(
        "Apply the Principle of Least Privilege. Assets should only grant permissions strictly necessary for intended functionality. "
        "Ensure authentication and encryption (TLS) protect data in transit, access control lists protect data at rest, and redundant backups protect availability."
    ),
)

ROOM_01_TASKS = [
    TaskDefinition(
        task_id="task-01-cia-triad",
        order=1,
        title="The CIA Triad in Action",
        instructions=(
            "Review the three pillars of information security: Confidentiality, Integrity, and Availability. "
            "Consider an incident where an unauthorized attacker secretly alters account balances in a transaction database "
            "without changing passwords or taking the system down."
        ),
        task_type=TaskType.QUESTION,
        question="Which core property of the CIA Triad has been directly violated by altering the data?",
        hint="Integrity ensures data remains accurate, complete, and uncorrupted by unauthorized modification.",
        xp_reward=50,
        accepted_answers=["Integrity", "integrity"],
        mistake_explanations={
            "confidentiality": "Confidentiality concerns unauthorized reading or viewing of secret data. In this scenario, existing records were altered or modified, which violates data accuracy and trustworthiness (Integrity).",
            "availability": "Availability concerns uptime and accessibility. Since the system is still online and operational, Availability is intact; it is the trustworthiness of the data that was corrupted.",
        },
    ),
    TaskDefinition(
        task_id="task-02-asset-inspection",
        order=2,
        title="Asset & Permission Inspection",
        instructions=(
            "On your workstation, examine the directory `/home/operator/assets/`. One configuration file contains exposed emergency recovery "
            "credentials due to overly permissive read permissions. Read `/home/operator/assets/backup_codes.txt` and submit the recovery token flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the recovery token flag found inside backup_codes.txt.",
        hint="Execute `cat /home/operator/assets/backup_codes.txt` in your terminal.",
        xp_reward=60,
        accepted_answers=["NOENTRY{foundations_confidentiality_leak_8821}"],
        accepted_regex=r"^NOENTRY\{foundations_confidentiality_leak_\d+\}$",
        mistake_explanations={
            "VOLT-9921-XCA": "This is the primary recovery key, not the platform flag string formatted as NOENTRY{...}.",
        },
    ),
    TaskDefinition(
        task_id="task-03-threat-vuln-risk",
        order=3,
        title="Threats, Vulnerabilities, and Risk",
        instructions=(
            "In security risk assessment, we distinguish between the threat agent (who attacks), the vulnerability (the flaw they exploit), "
            "and risk (the likelihood and business impact). Identify the term describing a flaw or software bug in an asset that can be exploited."
        ),
        task_type=TaskType.QUESTION,
        question="What cybersecurity term specifically describes a flaw, software bug, or misconfiguration in an asset that can be exploited by an adversary?",
        hint="Distinguish between the adversary (Threat), the flaw (Vulnerability), and the probability of impact (Risk).",
        xp_reward=50,
        accepted_answers=["Vulnerability", "vulnerability", "vuln"],
        mistake_explanations={
            "threat": "A threat is the external actor or potential danger (e.g. ransomware gang or rogue insider). The flaw itself is called a vulnerability.",
            "risk": "Risk is the mathematical product of the likelihood of exploitation multiplied by the resulting operational impact.",
        },
    ),
    TaskDefinition(
        task_id="task-04-roles",
        order=4,
        title="Red, Blue, and Purple Team Roles",
        instructions=(
            "Organizations utilize specialized teams to secure their infrastructure. Red Teams emulate adversary tactics; Blue Teams defend infrastructure and respond to incidents."
        ),
        task_type=TaskType.QUESTION,
        question="What is the collaborative security team model that integrates offensive emulation directly with blue team defensive telemetry and detection tuning?",
        hint="Combine the colors of the offensive team and defensive team.",
        xp_reward=50,
        accepted_answers=["Purple Team", "purple team", "purple", "purpleteam"],
        mistake_explanations={
            "red team": "The Red Team specializes strictly in offensive emulation and penetration testing.",
            "blue team": "The Blue Team specializes in defense, monitoring, threat hunting, and incident response.",
        },
    ),
    TaskDefinition(
        task_id="task-05-practical-audit",
        order=5,
        title="Exposed Asset Audit Challenge",
        instructions=(
            "The target host is running an unauthenticated asset inspection service on port 8081. "
            "Execute `curl -s http://10.10.14.90:8081/audit` to perform an automated asset audit. Identify the security violation and submit the compliance flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the compliance flag returned by the asset audit endpoint.",
        hint="Run `curl -s http://10.10.14.90:8081/audit` in your operator terminal.",
        xp_reward=70,
        accepted_answers=["NOENTRY{cia_triad_integrity_breach_1042}"],
        accepted_regex=r"^NOENTRY\{cia_triad_integrity_breach_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-06-quiz",
        order=6,
        title="Foundations Knowledge Assessment",
        instructions="Answer the following 5 questions to verify your mastery of cybersecurity foundations, the CIA triad, and risk management.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question quiz on cybersecurity foundations.",
        hint="Review the CIA triad and ethical hacking principles.",
        xp_reward=70,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Which document legally establishes scope, authorized targets, and testing boundaries for an ethical hacking engagement?",
                options=[
                    "Rules of Engagement (RoE)",
                    "Terms of Service (ToS)",
                    "Non-Disclosure Agreement (NDA) only",
                    "Public Bug Bounty Disclosure Policy",
                ],
                correct_option_index=0,
                explanation="Rules of Engagement (RoE) formalize explicit written authorization, agreed targets, testing hours, and escalation paths.",
            ),
            QuizQuestion(
                id="q2",
                question="A Distributed Denial of Service (DDoS) attack directly impacts which component of the CIA Triad?",
                options=[
                    "Availability",
                    "Confidentiality",
                    "Integrity",
                    "Non-repudiation",
                ],
                correct_option_index=0,
                explanation="DDoS attacks flood network pipes or system resources to deny access to authorized users, violating Availability.",
            ),
            QuizQuestion(
                id="q3",
                question="What is the security concept of restricting users and services to only the minimal permissions necessary to perform their job?",
                options=[
                    "Principle of Least Privilege",
                    "Security through Obscurity",
                    "Defense in Depth",
                    "Zero-day Mitigation",
                ],
                correct_option_index=0,
                explanation="Least Privilege ensures that if an account or service is compromised, adversary blast radius is strictly contained.",
            ),
            QuizQuestion(
                id="q4",
                question="If a company has a critical vulnerability in a web server, but the web server is disconnected and powered off, what is the resulting operational risk?",
                options=[
                    "Near zero, because the vulnerability cannot be reached by threats",
                    "Critical, because the bug is still present in code",
                    "Medium, due to compliance fines",
                    "High, because hackers know about it",
                ],
                correct_option_index=0,
                explanation="Risk requires both a vulnerability and an accessible threat vector. If threats cannot reach the asset, risk is negligible.",
            ),
            QuizQuestion(
                id="q5",
                question="Which team is primarily responsible for incident triage, log analysis, threat hunting, and defensive telemetry?",
                options=[
                    "Blue Team",
                    "Red Team",
                    "Sales Engineering",
                    "Procurement",
                ],
                correct_option_index=0,
                explanation="The Blue Team operates the SOC, monitors telemetry, investigates suspicious alerts, and defends enterprise assets.",
            ),
        ],
    ),
]

ROOM_01_DEFINITION = RoomDefinition(
    room_id="red-01-cybersecurity-foundations",
    track=TrackEnum.RED,
    room_number=1,
    title="Cybersecurity Foundations",
    short_description="Explore the CIA Triad, threats vs vulnerabilities vs risks, attack surfaces, security controls, ethical boundaries, and red/blue/purple team roles.",
    difficulty="Beginner",
    estimated_duration="35 min",
    prerequisites=["None"],
    required_skills=["Asset inspection", "File permission auditing", "CIA triad classification"],
    lab_type="container_isolated",
    concept=ROOM_01_CONCEPT,
    tasks=ROOM_01_TASKS,
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Master the CIA Triad and classify security incidents accurately",
        "Distinguish between threats, vulnerabilities, and operational risk",
        "Inspect asset permissions and identify security misconfigurations",
        "Understand the collaborative roles of Red, Blue, and Purple teams",
    ],
    assessment_criteria=[
        "Classify incident scenarios against the CIA triad",
        "Inspect file permissions and identify over-permissive files",
        "Capture the compliance audit flag from the target asset service",
        "Pass the 5-question comprehensive foundations quiz",
    ],
    completion_requirements=["Complete all 6 tasks with 100% accuracy"],
    total_xp=350,
)

# ============================================================================
# ROOM 02: LINUX FOR HACKERS (FULLY IMPLEMENTED)
# ============================================================================

ROOM_02_CONCEPT = RoomConcept(
    overview=(
        "Linux is the backbone of offensive security operations, cloud infrastructure, and security appliances. "
        "Mastering terminal navigation, file manipulation, permission structures, process tracking, and text filtering "
        "is essential for every security practitioner."
    ),
    simple_analogy=(
        "Think of an operating system like a corporate headquarters building. The graphical desktop (GUI) is like "
        "the front reception desk with simple brochure stands. The command terminal (CLI) is like having the master "
        "keycard to every maintenance shaft, power distribution room, and control panel. Commands like `pwd` tell you "
        "which floor and room you are standing in. `ls` turns on the lights to inspect everything on the desks. `cd` walks "
        "you down the hallway into another room. File permissions (`chmod`) are the access control badges determining "
        "who is allowed to enter (read), rearrange the furniture (write), or operate the machinery (execute)."
    ),
    technical_term="Linux Command Line, Filesystem Hierarchy & Privilege Controls",
    technical_definition=(
        "Linux is an open-source, Unix-like operating system kernel widely utilized in servers, cloud infrastructure, "
        "and security distributions (such as Kali Linux). Security operations rely on the command shell (e.g., bash/sh) to interface "
        "with the operating system without GUI overhead. The filesystem follows a single unified hierarchical tree starting at root (`/`). "
        "File permissions are divided into User (owner), Group, and Others, with three basic rights: Read (r=4), Write (w=2), and Execute (x=1). "
        "Processes represent executing program instances with unique Process IDs (PIDs) running under specific user contexts."
    ),
    cybersecurity_context=(
        "Over 90% of cloud workloads and internet-facing servers run Linux. Offensive operators use Linux shells for initial access navigation, "
        "file permission auditing, SUID escalation, cron manipulation, and reverse shells. Defensive practitioners inspect `/var/log`, auditd records, "
        "process memory (`/proc`), and user accounts (`/etc/passwd`, `/etc/shadow`) to detect intrusion."
    ),
    why_it_matters=(
        "A security professional cannot effectively assess or defend systems without terminal fluency. "
        "Almost every penetration testing tool, container environment, and server backend is managed via the shell."
    ),
    demonstration=(
        "Terminal Navigation & Permission Example:\n"
        "  $ pwd\n"
        "  /home/operator\n"
        "  $ ls -la\n"
        "  -rw------- 1 operator operator 48 Nov 14 restricted.sh\n"
        "  $ chmod +x restricted.sh\n"
        "  $ ./restricted.sh\n"
        "  [+] Execution granted!\n"
    ),
    remediation_guide=(
        "Audit file permissions regularly using `find / -perm -4000 2>/dev/null` for SUID binaries. Ensure sensitive files "
        "(such as private keys and configuration files) have permissions restricted to `600` or `400` owned by root. "
        "Prevent unauthorized write access to system directories (`/etc`, `/bin`, `/usr/bin`)."
    ),
)

ROOM_02_TASKS = [
    TaskDefinition(
        task_id="task-01-pwd-whoami",
        order=1,
        title="Terminal Identity & Navigation",
        instructions=(
            "On Linux systems, `whoami` outputs your current effective user account, while `pwd` prints your absolute working directory path. "
            "Run both commands in your terminal to orient yourself."
        ),
        task_type=TaskType.COMMAND,
        question="What is your current active username inside the attack container?",
        hint="Type `whoami` and press Enter.",
        xp_reward=50,
        accepted_answers=["operator"],
    ),
    TaskDefinition(
        task_id="task-02-hidden-files",
        order=2,
        title="Hidden Files & Directory Traversal",
        instructions=(
            "In Linux, files and directories prefixed with a dot (`.`) are hidden from standard directory listings. "
            "Use `ls -la /home/operator/challenges/` to list all hidden files and read the flag inside `.secret_vault/flag_hidden.txt`."
        ),
        task_type=TaskType.FLAG,
        question="Submit the hidden flag found inside the .secret_vault directory.",
        hint="Execute `cat /home/operator/challenges/.secret_vault/flag_hidden.txt`.",
        xp_reward=60,
        accepted_answers=["NOENTRY{linux_hidden_dotfiles_revealed_3182}"],
        accepted_regex=r"^NOENTRY\{linux_hidden_dotfiles_revealed_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-03-permissions-chmod",
        order=3,
        title="File Permissions & Executable Rights (chmod)",
        instructions=(
            "Inspect the script `/home/operator/challenges/restricted_script.sh`. Currently, it only has read and write permissions (`-rw-------`). "
            "Use `chmod +x /home/operator/challenges/restricted_script.sh` to add execution rights, then run the script to capture the execution token."
        ),
        task_type=TaskType.FLAG,
        question="Submit the security token emitted when executing restricted_script.sh.",
        hint="Run `chmod +x /home/operator/challenges/restricted_script.sh` followed by `/home/operator/challenges/restricted_script.sh`.",
        xp_reward=60,
        accepted_answers=["NOENTRY{linux_chmod_execution_unlocked_9104}"],
        accepted_regex=r"^NOENTRY\{linux_chmod_execution_unlocked_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-04-process-ps",
        order=4,
        title="Process Inspection with ps",
        instructions=(
            "A background agent is running on this workstation. Use `ps aux` to list all active system processes, locate the `shadow_agent` "
            "command, and inspect its arguments to discover the agent token flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the agent token flag found in the shadow_agent process arguments.",
        hint="Run `ps aux | grep shadow_agent` in the terminal.",
        xp_reward=60,
        accepted_answers=["NOENTRY{linux_process_inspection_7741}"],
        accepted_regex=r"^NOENTRY\{linux_process_inspection_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-05-piping-grep",
        order=5,
        title="Stream Filtering with grep",
        instructions=(
            "The log file `/home/operator/challenges/system_telemetry.log` contains noisy system events. "
            "Use the `grep` utility to filter the file for lines containing `SECURITY_FLAG`."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag extracted from the system telemetry log.",
        hint="Run `grep SECURITY_FLAG /home/operator/challenges/system_telemetry.log`.",
        xp_reward=60,
        accepted_answers=["NOENTRY{linux_grep_stream_mastery_5239}"],
        accepted_regex=r"^NOENTRY\{linux_grep_stream_mastery_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-06-quiz",
        order=6,
        title="Linux Fundamentals Assessment",
        instructions="Complete the 5-question quiz to test your mastery of Linux shell mechanics, filesystem layout, and permissions.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question quiz on Linux fundamentals.",
        hint="Review Linux directory structure and permissions.",
        xp_reward=60,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Which directory in the Linux Filesystem Hierarchy contains system-wide configuration files such as passwd, shadow, and hosts?",
                options=["/etc", "/bin", "/var/log", "/dev"],
                correct_option_index=0,
                explanation="/etc houses system configuration files and service settings.",
            ),
            QuizQuestion(
                id="q2",
                question="In octal permission notation, what numerical value grants full read, write, and execute permissions (rwx) to a user?",
                options=["7", "5", "6", "4"],
                correct_option_index=0,
                explanation="Read is 4, Write is 2, Execute is 1. 4 + 2 + 1 = 7.",
            ),
            QuizQuestion(
                id="q3",
                question="Which shell operator redirects the standard output (stdout) of one command directly into the standard input (stdin) of another command?",
                options=["Pipe (|)", "Redirect output (>)", "Append (>>)", "Background (&)"],
                correct_option_index=0,
                explanation="The pipe character (|) chains command output directly into the next process.",
            ),
            QuizQuestion(
                id="q4",
                question="What is the key difference between an absolute path and a relative path in Linux?",
                options=[
                    "An absolute path starts from the root directory (/), while a relative path starts from the current working directory",
                    "An absolute path is only for root users, while a relative path is for unprivileged users",
                    "An absolute path cannot contain directories",
                    "A relative path must end with a forward slash",
                ],
                correct_option_index=0,
                explanation="Absolute paths always begin with / (the filesystem root), whereas relative paths are relative to your current location (pwd).",
            ),
            QuizQuestion(
                id="q5",
                question="Which command lists running system processes with detailed owner, CPU, memory, and command-line arguments?",
                options=["ps aux", "netstat -tuln", "ls -l", "whoami -p"],
                correct_option_index=0,
                explanation="ps aux lists all running processes across all users with terminal, CPU, memory, and argument details.",
            ),
        ],
    ),
]

ROOM_02_DEFINITION = RoomDefinition(
    room_id="red-02-linux-for-hackers",
    track=TrackEnum.RED,
    room_number=2,
    title="Linux for Hackers",
    short_description="Master the Linux terminal, command execution, absolute and relative paths, file operations, permissions, process management, and user identification.",
    difficulty="Beginner",
    estimated_duration="45 min",
    prerequisites=["Cybersecurity Foundations"],
    required_skills=["Linux CLI navigation", "File permission modification", "Process inspection", "Stream filtering"],
    lab_type="container_isolated",
    concept=ROOM_02_CONCEPT,
    tasks=ROOM_02_TASKS,
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Navigate the Linux filesystem tree using absolute and relative paths",
        "Manage file permissions and execute scripts using chmod",
        "Inspect active system processes and command arguments with ps",
        "Filter large data streams and log files using grep",
    ],
    assessment_criteria=[
        "Identify active user and working directory",
        "Locate hidden dotfile directories and capture flags",
        "Unlock executable permissions on restricted scripts",
        "Filter system telemetry logs to extract target security flags",
        "Pass the 5-question Linux fundamentals quiz",
    ],
    completion_requirements=["Complete all 6 tasks with 100% accuracy"],
    total_xp=350,
)

# ============================================================================
# ROOM 03: NETWORKING FUNDAMENTALS (FULLY IMPLEMENTED)
# ============================================================================

ROOM_03_CONCEPT = RoomConcept(
    overview=(
        "Computer networking is the connective fabric of cybersecurity. Understanding how data moves between "
        "clients and servers through IP addressing, subnet masks, port multiplexing, and transport protocols (TCP vs UDP) "
        "is critical for offensive operations and defensive monitoring."
    ),
    simple_analogy=(
        "Imagine the postal and courier system. An IP address is like the street address of an apartment high-rise—it tells "
        "delivery trucks which building to drive to. A Port number is like the individual apartment unit number inside that building "
        "(Unit 80 for the receptionist, Unit 443 for the vault room). A MAC address is like the physical serial number stamped on the front door. "
        "TCP (Transmission Control Protocol) is like sending a registered parcel with mandatory signature receipt: sender and receiver confirm "
        "connection first (3-way handshake) and guarantee every box arrived intact. UDP (User Datagram Protocol) is like shouting through a megaphone: "
        "fast and lightweight, but with no guarantee anyone heard you."
    ),
    technical_term="Computer Networking: IP Addressing, TCP/UDP Protocols & Socket Communication",
    technical_definition=(
        "Computer networking enables digital communication between distinct host machines over shared physical and logical media. "
        "The Internet Protocol (IP) handles addressing and routing packets across networks. IPv4 addresses consist of 32 bits (4 octets, e.g. 10.10.14.90). "
        "A Subnet Mask (such as /24 or 255.255.255.0) splits the address into Network and Host portions. Port numbers (0–65535) multiplex communication "
        "channels on a single IP. TCP provides reliable, ordered byte streams via a 3-way handshake (SYN -> SYN-ACK -> ACK). UDP provides connectionless, "
        "low-latency datagram delivery without retransmission. DNS translates human-friendly domain names into IP addresses."
    ),
    cybersecurity_context=(
        "Offensive operators map subnets, identify open ports, banner-grab network services, and craft custom network packets. "
        "Defensive engineers configure stateful firewalls, monitor network telemetry (NetFlow, PCAP), analyze DNS queries for data exfiltration tunnels, "
        "and detect port scanning patterns."
    ),
    why_it_matters=(
        "Network packets carry every attack vector and defensive control across the internet. "
        "Without understanding subnetting, routing, ports, and protocols, a security analyst cannot interpret a firewall rule, a Wireshark capture, or an Nmap scan."
    ),
    demonstration=(
        "Network Socket Probing Example:\n"
        "  $ ip addr show eth0\n"
        "  inet 10.10.14.2/24 brd 10.10.14.255 scope global eth0\n"
        "  $ nc -zv 10.10.14.90 8080\n"
        "  10.10.14.90 (10.10.14.90:8080) open\n"
        "  $ curl -s http://10.10.14.90:8080/status\n"
        "  {\"status\": \"ONLINE\", \"host\": \"target.noentry.internal\"}\n"
    ),
    remediation_guide=(
        "Implement Network Segmentation and Zero Trust Architecture. Close unused ports using host and perimeter firewalls (`iptables` / `ufw`). "
        "Segment production, management, and training networks into distinct VLANs. Enforce encrypted protocols (HTTPS/TLS, SSH) over cleartext equivalents (HTTP, Telnet)."
    ),
)

ROOM_03_TASKS = [
    TaskDefinition(
        task_id="task-01-ip-interface",
        order=1,
        title="Network Interface & Subnet Inspection",
        instructions=(
            "Examine your container's network interface using `ip addr show eth0`. Identify the CIDR prefix length (the subnet mask length after the slash, e.g. /24) assigned to the internal interface."
        ),
        task_type=TaskType.QUESTION,
        question="What is the CIDR prefix length (subnet mask) assigned to your interface (e.g. /24 or 24)?",
        hint="Look for the number following the slash in `inet 10.10.14.X/24`.",
        xp_reward=50,
        accepted_answers=["/24", "24", "255.255.255.0"],
    ),
    TaskDefinition(
        task_id="task-02-port-protocol",
        order=2,
        title="Standard Ports & Protocols",
        instructions=(
            "Transport-layer ports allow multiple network services to listen on a single IP address. Recall the standard well-known IANA port for unencrypted HTTP traffic."
        ),
        task_type=TaskType.QUESTION,
        question="Which default TCP port number is utilized for standard unencrypted HTTP web traffic?",
        hint="HTTPS uses 443; plain HTTP uses 80.",
        xp_reward=50,
        accepted_answers=["80"],
    ),
    TaskDefinition(
        task_id="task-03-tcp-socket-nc",
        order=3,
        title="Raw TCP Socket Interaction (Netcat)",
        instructions=(
            "The target host is running a raw TCP socket banner service on port 9001. "
            "Use the `nc` (Netcat) utility to connect to the raw socket (`nc 10.10.14.90 9001`) and capture the transmitted flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag transmitted by the raw TCP socket service on port 9001.",
        hint="Run `nc 10.10.14.90 9001` in your terminal.",
        xp_reward=65,
        accepted_answers=["NOENTRY{net_raw_tcp_socket_8832}"],
        accepted_regex=r"^NOENTRY\{net_raw_tcp_socket_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-04-http-client",
        order=4,
        title="HTTP Client-Server Communication",
        instructions=(
            "The target host provides a network diagnostics endpoint on port 8080. "
            "Issue an HTTP GET request using `curl -s http://10.10.14.90:8080/network-info` to inspect the response headers and payload."
        ),
        task_type=TaskType.FLAG,
        question="Submit the network client flag returned by the network-info endpoint.",
        hint="Run `curl -s http://10.10.14.90:8080/network-info`.",
        xp_reward=65,
        accepted_answers=["NOENTRY{net_http_client_server_4419}"],
        accepted_regex=r"^NOENTRY\{net_http_client_server_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-05-dns-resolution",
        order=5,
        title="Domain Name System (DNS)",
        instructions=(
            "Computers route packets using IP addresses, but humans prefer memorable names. Identify the protocol that maps hostnames like `target.noentry.internal` to IP addresses."
        ),
        task_type=TaskType.QUESTION,
        question="Which protocol translates human-readable hostnames into IP addresses?",
        hint="Three-letter acronym for Domain Name System.",
        xp_reward=50,
        accepted_answers=["DNS", "Domain Name System", "dns"],
    ),
    TaskDefinition(
        task_id="task-06-quiz",
        order=6,
        title="Networking Fundamentals Assessment",
        instructions="Answer the following 5 questions to test your knowledge of IP addressing, TCP/UDP transport mechanics, and network socket operations.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question quiz on networking fundamentals.",
        hint="Review RFC 1918 private ranges and TCP handshakes.",
        xp_reward=70,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Which of the following IPv4 address blocks is reserved for private internal networks according to RFC 1918?",
                options=[
                    "10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16",
                    "8.8.8.0/24 and 1.1.1.0/24",
                    "127.0.0.0/8 exclusively",
                    "224.0.0.0/4 (Multicast)",
                ],
                correct_option_index=0,
                explanation="RFC 1918 establishes the 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16 ranges for private networks.",
            ),
            QuizQuestion(
                id="q2",
                question="What is the correct 3-step packet sequence used by TCP to establish a connection?",
                options=[
                    "SYN -> SYN-ACK -> ACK",
                    "ACK -> SYN -> SYN-ACK",
                    "SYN -> ACK -> DATA",
                    "HELLO -> ACK -> ESTABLISHED",
                ],
                correct_option_index=0,
                explanation="TCP initiates connections with SYN, responds with SYN-ACK, and completes establishment with ACK.",
            ),
            QuizQuestion(
                id="q3",
                question="Which transport-layer protocol is connectionless and does not guarantee packet delivery or order?",
                options=["UDP", "TCP", "SCTP", "BGP"],
                correct_option_index=0,
                explanation="User Datagram Protocol (UDP) sends datagrams without establishing a handshake or verifying receipt.",
            ),
            QuizQuestion(
                id="q4",
                question="At which layer of the OSI model does an IP address operate versus a MAC address?",
                options=[
                    "IP operates at Layer 3 (Network); MAC operates at Layer 2 (Data Link)",
                    "IP operates at Layer 2; MAC operates at Layer 3",
                    "Both operate at Layer 4 (Transport)",
                    "IP operates at Layer 7; MAC operates at Layer 1",
                ],
                correct_option_index=0,
                explanation="IP is an OSI Layer 3 (Network) protocol, whereas physical MAC addresses operate at Layer 2 (Data Link).",
            ),
            QuizQuestion(
                id="q5",
                question="Which tool allows an operator to inspect interface IP addresses and routing tables on modern Linux installations?",
                options=["ip addr", "traceroute -h", "ping -c", "dig +trace"],
                correct_option_index=0,
                explanation="ip addr (from iproute2) is the standard modern utility for viewing and configuring IP interfaces.",
            ),
        ],
    ),
]

ROOM_03_DEFINITION = RoomDefinition(
    room_id="red-03-networking-fundamentals",
    track=TrackEnum.RED,
    room_number=3,
    title="Networking Fundamentals",
    short_description="Master IP addressing, subnet masks, TCP vs UDP, ports and protocols, MAC addresses, DNS resolution, and client-server communication using real network commands.",
    difficulty="Beginner",
    estimated_duration="45 min",
    prerequisites=["Linux for Hackers"],
    required_skills=["Network interface inspection", "Raw TCP socket probing", "HTTP client requests", "Port identification"],
    lab_type="container_isolated",
    concept=ROOM_03_CONCEPT,
    tasks=ROOM_03_TASKS,
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Inspect network interfaces and identify subnet masks using iproute2",
        "Understand well-known port allocations and transport layer differences",
        "Interact with raw TCP socket services using Netcat",
        "Issue HTTP client requests and parse client-server exchanges with curl",
    ],
    assessment_criteria=[
        "Identify the subnet prefix of the local network interface",
        "Establish a raw TCP connection to port 9001 and capture the socket flag",
        "Query the network diagnostics HTTP service on port 8080",
        "Pass the 5-question networking fundamentals quiz",
    ],
    completion_requirements=["Complete all 6 tasks with 100% accuracy"],
    total_xp=350,
)

# ============================================================================
# ROOM 04: RECONNAISSANCE (FULLY IMPLEMENTED)
# ============================================================================

ROOM_04_CONCEPT = RoomConcept(
    overview=(
        "Reconnaissance (Information Gathering) is the first and most critical phase of the cyber attack lifecycle. "
        "Whether passive (gathering OSINT without touching the target) or active (probing live hosts and ports), thorough "
        "reconnaissance maps the attack surface and uncovers vulnerable endpoints."
    ),
    simple_analogy=(
        "Imagine a detective investigating an art gallery before evaluating its security. Passive reconnaissance is like "
        "reading public building blueprints at city hall, checking the gallery's public operating hours online, and viewing photos "
        "tourists posted of the front lobby—you never set foot near the building and the security guards have no idea you exist. "
        "Active reconnaissance is like walking up to the building at night, checking if the rear loading bay door is locked, testing "
        "the window latches, and reading the manufacturer label on the alarm keypad—you are directly interacting with the property, "
        "and security cameras can see and record your activity."
    ),
    technical_term="Reconnaissance: Passive vs Active Information Gathering & Attack Surface Mapping",
    technical_definition=(
        "Reconnaissance (Recon) is the foundational phase of the cyber attack lifecycle (MITRE ATT&CK TA0043). "
        "Passive reconnaissance gathers open-source intelligence (OSINT), DNS records, certificate logs, and public metadata "
        "without generating network packets towards the target's assets. Active reconnaissance transmits packets directly to target "
        "hosts to discover live systems, open TCP/UDP ports, running services, application frameworks, and hidden paths. "
        "Scope of Authorization (Rules of Engagement) strictly delineates which assets are authorized for active probing."
    ),
    cybersecurity_context=(
        "Offensive operators conduct recon to identify the path of least resistance—exposed administrative panels, forgotten staging APIs, "
        "outdated server banners, and misconfigured `robots.txt` files. Defensive teams perform attack surface management to discover "
        "their own exposed digital assets, sanitize public server headers (`Server`, `X-Powered-By`), remove staging URLs from public files, "
        "and block active port scans with intrusion detection systems (IDS)."
    ),
    why_it_matters=(
        "Over 70% of successful breaches exploit assets the target organization forgot was exposed to the internet. "
        "Thorough reconnaissance reveals high-impact vulnerabilities before an attacker touches a single exploit."
    ),
    demonstration=(
        "HTTP Banner Grabbing & Robots Enumeration:\n"
        "  $ curl -I http://10.10.14.90:8090/\n"
        "  HTTP/1.1 200 OK\n"
        "  Server: uvicorn\n"
        "  X-Backend-Server: VoltCore-v2.14-Internal\n\n"
        "  $ curl -s http://10.10.14.90:8090/robots.txt\n"
        "  User-agent: *\n"
        "  Disallow: /admin-portal-staging-7712/\n"
    ),
    remediation_guide=(
        "Minimize your attack surface: disable custom verbose server headers, enforce access controls on administrative endpoints, "
        "never rely on `robots.txt` for security (it is a public directory of sensitive locations), and continuously monitor DNS records "
        "and certificate transparency logs for forgotten subdomains."
    ),
)

ROOM_04_TASKS = [
    TaskDefinition(
        task_id="task-01-passive-vs-active",
        order=1,
        title="Passive vs Active Reconnaissance",
        instructions=(
            "Reconnaissance gathers intelligence about a target's attack surface. One form collects public data without touching target infrastructure, "
            "while the other directly transmits packets to the target's servers."
        ),
        task_type=TaskType.QUESTION,
        question="Which category of reconnaissance collects target intelligence without sending direct network packets to the target's infrastructure?",
        hint="Think of passive observation versus active probing.",
        xp_reward=50,
        accepted_answers=["Passive", "passive reconnaissance", "passive recon", "passive"],
    ),
    TaskDefinition(
        task_id="task-02-robots-txt",
        order=2,
        title="Robots.txt Information Leakage",
        instructions=(
            "Web administrators often specify paths that search engines should not index in `robots.txt`, unintentionally providing a directory of sensitive administrative portals. "
            "Fetch `http://10.10.14.90:8090/robots.txt`, navigate to the disallowed staging path, and submit the flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag revealed inside the disallowed staging admin portal.",
        hint="Run `curl -s http://10.10.14.90:8090/robots.txt` and then curl the disallowed path.",
        xp_reward=65,
        accepted_answers=["NOENTRY{recon_robots_hidden_endpoint_2901}"],
        accepted_regex=r"^NOENTRY\{recon_robots_hidden_endpoint_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-03-banner-grabbing",
        order=3,
        title="HTTP Banner Grabbing & Server Headers",
        instructions=(
            "Active reconnaissance frequently involves inspecting HTTP response headers to identify backend software versions and custom server identifiers. "
            "Use `curl -I http://10.10.14.90:8090/` to inspect headers."
        ),
        task_type=TaskType.QUESTION,
        question="What is the exact value of the custom X-Backend-Server response header?",
        hint="Look for `X-Backend-Server:` in the curl -I response headers.",
        xp_reward=55,
        accepted_answers=["VoltCore-v2.14-Internal", "voltcore-v2.14-internal"],
    ),
    TaskDefinition(
        task_id="task-04-api-enumeration",
        order=4,
        title="API Metadata & Documentation Harvesting",
        instructions=(
            "Modern applications frequently expose internal API documentation. Query `http://10.10.14.90:8090/api/v1/health` and follow the internal documentation link to retrieve the API telemetry flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the API telemetry flag found in the internal API documentation endpoint.",
        hint="Run `curl -s http://10.10.14.90:8090/api/v1/health` and check the documentation URL.",
        xp_reward=65,
        accepted_answers=["NOENTRY{recon_api_metadata_harvest_6310}"],
        accepted_regex=r"^NOENTRY\{recon_api_metadata_harvest_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-05-directory-discovery",
        order=5,
        title="Independent Directory Discovery Challenge",
        instructions=(
            "Independent Challenge: Discover the sensitive database backup file stored under the `/secret-assets/` directory on port 8090 "
            "(`/secret-assets/database_credentials.bak`) and extract the confidential challenge flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the confidential flag extracted from database_credentials.bak.",
        hint="Run `curl -s http://10.10.14.90:8090/secret-assets/database_credentials.bak`.",
        xp_reward=65,
        accepted_answers=["NOENTRY{recon_dir_enumeration_master_9044}"],
        accepted_regex=r"^NOENTRY\{recon_dir_enumeration_master_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-06-quiz",
        order=6,
        title="Reconnaissance Knowledge Assessment",
        instructions="Answer the following 5 questions to test your understanding of passive vs active reconnaissance, OSINT, and scope limitations.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question quiz on reconnaissance.",
        hint="Review passive versus active methodologies and rules of engagement.",
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is `robots.txt` considered an information leak rather than a security mechanism?",
                options=[
                    "It is publicly readable and explicitly lists sensitive or hidden administrative directories",
                    "It automatically executes scripts in the browser",
                    "It reveals the server root password",
                    "Search engines decrypt its contents",
                ],
                correct_option_index=0,
                explanation="robots.txt is plain text and publicly accessible. Disallowed directories guide security analysts straight to hidden endpoints.",
            ),
            QuizQuestion(
                id="q2",
                question="Which of the following is an example of passive reconnaissance?",
                options=[
                    "Searching public Certificate Transparency logs and WHOIS records",
                    "Running an aggressive Nmap SYN scan",
                    "Sending SQL injection probes to a search bar",
                    "Brute-forcing subdomains with Gobuster",
                ],
                correct_option_index=0,
                explanation="Certificate logs and WHOIS queries are third-party OSINT sources that never transmit packets to the target host.",
            ),
            QuizQuestion(
                id="q3",
                question="What document legally protects an ethical security tester from prosecution by specifying authorized domains, IP ranges, and testing windows?",
                options=[
                    "Rules of Engagement (Scope Document)",
                    "Proof of Concept (PoC)",
                    "Common Vulnerabilities and Exposures (CVE)",
                    "MITRE ATT&CK Matrix",
                ],
                correct_option_index=0,
                explanation="Rules of Engagement define legal testing boundaries and explicit permission from the asset owner.",
            ),
            QuizQuestion(
                id="q4",
                question="What is 'banner grabbing' in active reconnaissance?",
                options=[
                    "Connecting to a network service to inspect the software name and version returned in its initial response",
                    "Stealing a website's graphical logo",
                    "Intercepting Wi-Fi packets with a directional antenna",
                    "Capturing an operating system screenshot",
                ],
                correct_option_index=0,
                explanation="Banner grabbing analyzes server response headers or greeting text to fingerprint underlying software and versions.",
            ),
            QuizQuestion(
                id="q5",
                question="Which DNS record type maps a domain name to an IPv4 address?",
                options=["A record", "MX record", "TXT record", "PTR record"],
                correct_option_index=0,
                explanation="An 'A' (Address) record maps a fully qualified domain name to a 32-bit IPv4 address.",
            ),
        ],
    ),
]

ROOM_04_DEFINITION = RoomDefinition(
    room_id="red-04-reconnaissance",
    track=TrackEnum.RED,
    room_number=4,
    title="Reconnaissance",
    short_description="Master passive vs active reconnaissance, service enumeration, directory and asset discovery, banner grabbing, and scope authorization against local targets.",
    difficulty="Beginner",
    estimated_duration="45 min",
    prerequisites=["Networking Fundamentals"],
    required_skills=["Service banner grabbing", "Robots.txt analysis", "API metadata enumeration", "Directory discovery"],
    lab_type="container_isolated",
    concept=ROOM_04_CONCEPT,
    tasks=ROOM_04_TASKS,
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Differentiate passive OSINT from active network enumeration",
        "Analyze robots.txt and HTTP response headers for technology fingerprinting",
        "Enumerate REST API documentation endpoints to discover hidden parameters",
        "Perform targeted path discovery to extract sensitive backup credentials",
    ],
    assessment_criteria=[
        "Identify passive versus active reconnaissance scenarios",
        "Discover and access the staging admin portal via robots.txt",
        "Extract custom server headers using HTTP banner grabbing",
        "Locate and extract confidential backup credentials",
        "Pass the 5-question reconnaissance assessment quiz",
    ],
    completion_requirements=["Complete all 6 tasks with 100% accuracy"],
    total_xp=350,
)

# ============================================================================
# ROOM 09: SQL INJECTION FUNDAMENTALS (FULLY IMPLEMENTED)
# ============================================================================

ROOM_09_CONCEPT = RoomConcept(
    overview=(
        "SQL Injection (SQLi) occurs when untrusted user input is directly concatenated into a dynamic "
        "database query rather than being treated strictly as data. This allows an attacker to manipulate "
        "query logic, bypass authentication, extract hidden records, alter database contents, or escalate privileges."
    ),
    simple_analogy=(
        "Imagine ordering at a restaurant by handing an order ticket to the chef. Normally, you write "
        "'Burger' on the item line. The chef's instructions say: 'Prepare [ITEM] for the guest.' "
        "If you write 'Burger; and give me all the cash in the register', and the kitchen robot blindly "
        "executes whatever is written on the ticket as an operational command, the boundary between data "
        "and command was broken. In cybersecurity, this exact failure happens when user data mixes directly "
        "with database instructions."
    ),
    technical_term="SQL Injection (CWE-89: Improper Neutralization of Special Elements used in an SQL Command)",
    technical_definition=(
        "Relational databases interpret commands structured in Structured Query Language (SQL). "
        "When an application constructs queries via string formatting or concatenation (e.g., "
        "`f\"SELECT * FROM users WHERE username = '{user}'\"`), special characters like the single-quote "
        "(') prematurely terminate the intended string literal. Subsequent characters are interpreted as "
        "SQL syntax (such as OR, UNION, or comment delimiters --), altering the query execution tree."
    ),
    cybersecurity_context=(
        "SQLi remains among the top entries in the OWASP Top 10 (A03:2021 - Injection). Red teams use SQLi "
        "to gain initial access, harvest credentials, bypass single-factor and multi-factor authentication, "
        "or execute commands via database extensions (such as xp_cmdshell in MSSQL). Blue teams detect SQLi "
        "by monitoring WAF telemetry, database query logs, and anomalous error rates."
    ),
    why_it_matters=(
        "A single SQL injection vulnerability can expose an entire enterprise database. High-profile breaches "
        "spanning millions of records—including retail, healthcare, and government systems—originated from "
        "unvalidated web form fields. Understanding how query execution breaks and how parameterized queries "
        "neutralize it is foundational for every security practitioner."
    ),
    demonstration=(
        "Vulnerable Code:\n"
        "  query = f\"SELECT id, name FROM users WHERE username = '{input_user}' AND password = '{input_pass}'\"\n\n"
        "Attacker Input:\n"
        "  Username: admin' OR '1'='1' --\n\n"
        "Resulting Executed Query:\n"
        "  SELECT id, name FROM users WHERE username = 'admin' OR '1'='1' --' AND password = '...'\n"
        "The condition evaluates to TRUE for the first matching user (admin), and the double hyphen (--) "
        "comments out the rest of the query, bypassing password verification completely."
    ),
    remediation_guide=(
        "Always use Parameterized Queries (Prepared Statements) or an Object-Relational Mapper (ORM) "
        "with parameter binding. In parameterized queries, database drivers send query structure and data "
        "in separate channels. Even if an attacker enters `' OR 1=1 --`, the database treats the entire input "
        "as a literal string value for the parameter, making code injection mathematically impossible."
    ),
)

ROOM_09_TASKS = [
    TaskDefinition(
        task_id="task-01-detection",
        order=1,
        title="Input Identification & Query Anatomy",
        instructions=(
            "Review the target application's query anatomy on port 8089. Identify the character commonly used "
            "in SQL string literals that triggers a syntax error when unbalanced by untrusted input."
        ),
        task_type=TaskType.QUESTION,
        question="Which single character is most commonly used to break out of an SQL string literal?",
        hint="Consider the punctuation mark that opens and closes string constants in standard SQL (e.g. 'admin').",
        xp_reward=50,
        accepted_answers=["'", "single quote", "'", "apostrophe", "\'"],
        mistake_explanations={
            '"': "Double quotes can be used in some SQL dialects for identifiers, but standard SQL string literals use the single quote (').",
            ";": "The semicolon terminates SQL statements, but it does not break an unclosed string literal on its own.",
            "--": "Double dashes represent an SQL comment, but you first need to escape the string delimiter before commenting out the remainder.",
        },
    ),
    TaskDefinition(
        task_id="task-02-auth-bypass",
        order=2,
        title="Authentication Bypass via Tautology",
        instructions=(
            "Connect to the target application on port 8089 (`http://10.10.14.90:8089` or the lab target URL). "
            "Navigate to `/login`. Use an SQL tautology injection payload in the username field (e.g. `' OR 1=1 --`) "
            "to authenticate as the administrator without knowing the password. Capture the secret flag displayed in the admin portal."
        ),
        task_type=TaskType.FLAG,
        question="Submit the administrative flag retrieved after logging in via SQL injection.",
        hint="Enter `admin' OR 1=1 --` into the username field with any arbitrary password.",
        xp_reward=60,
        accepted_answers=["NOENTRY{sqli_auth_bypass_success_3914}"],
        accepted_regex=r"^NOENTRY\{sqli_auth_bypass_success_\d+\}$",
        mistake_explanations={
            "admin": "You entered the username rather than the flag revealed inside the admin session.",
            "flag": "Flags follow the platform format: NOENTRY{...}",
            "NOENTRY{sqli_auth_bypass_success}": "Ensure you copy the entire flag including the numeric suffix shown on the dashboard.",
        },
    ),
    TaskDefinition(
        task_id="task-03-union-extraction",
        order=3,
        title="Data Exfiltration using UNION SELECT",
        instructions=(
            "The product search endpoint (`/search?q=`) returns 4 columns: `id`, `name`, `description`, and `price`. "
            "Use a `UNION SELECT` statement to exfiltrate secret credentials from the `hidden_flags` table. "
            "Example query: `' UNION SELECT 1, flag_name, flag_value, 4 FROM hidden_flags --`."
        ),
        task_type=TaskType.FLAG,
        question="Submit the exfiltrated flag from the hidden_flags table.",
        hint="Search for `' UNION SELECT 1, flag_name, flag_value, 4 FROM hidden_flags --` in the search bar.",
        xp_reward=70,
        accepted_answers=["NOENTRY{union_sqli_data_extraction_7129}"],
        accepted_regex=r"^NOENTRY\{union_sqli_data_extraction_\d+\}$",
        mistake_explanations={
            "UNION SELECT": "You must execute the query against the target and capture the NOENTRY{...} flag string.",
            "NOENTRY{sqli_auth_bypass_success_3914}": "This is the auth bypass flag from Task 2. Task 3 requires the UNION flag from hidden_flags.",
        },
    ),
    TaskDefinition(
        task_id="task-04-challenge",
        order=4,
        title="Numeric Parameter SQLi Challenge",
        instructions=(
            "Independent Challenge: The category filter endpoint (`/filter?category=`) takes a numeric parameter without quotes. "
            "Craft an injection payload to pivot to the `hidden_flags` table where `id=2` and capture the challenge flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag retrieved from the category numeric injection challenge.",
        hint="Try appending `UNION SELECT 1, flag_name, flag_value, 4 FROM hidden_flags WHERE id=2` directly without a leading quote.",
        xp_reward=80,
        accepted_answers=["NOENTRY{sqli_numeric_challenge_pivot_8842}"],
        accepted_regex=r"^NOENTRY\{sqli_numeric_challenge_pivot_\d+\}$",
        mistake_explanations={
            "' UNION": "Numeric parameters do not have enclosing single quotes in the SQL query. Adding a quote causes a syntax error.",
        },
    ),
    TaskDefinition(
        task_id="task-05-remediation",
        order=5,
        title="Code Remediation & Parameterized Verification",
        instructions=(
            "Inspect the remediated endpoint `/secure/login` on the target server. "
            "Submit the SQL query syntax demonstrating proper parameterization in Python SQLite."
        ),
        task_type=TaskType.REMEDIATION,
        question="Submit the parameterized SQL query pattern used to neutralize SQL injection in SQLite.",
        hint="In Python sqlite3, parameterized placeholders use the `?` character: `SELECT * FROM users WHERE username = ? AND password = ?`",
        xp_reward=40,
        accepted_answers=[
            "parameterized queries",
            "parameterized query",
            "prepared statements",
            "SELECT * FROM users WHERE username = ? AND password = ?",
            "SELECT id, username, role, flag FROM users WHERE username = ? AND password = ?",
            "SELECT * FROM users WHERE username = ? AND password = ?",
            "SELECT * FROM users WHERE username = ?",
        ],
        accepted_regex=r"SELECT\s+.*\s+FROM\s+users\s+WHERE\s+username\s*=\s*\?\s*(AND\s+password\s*=\s*\?)?",
        mistake_explanations={
            "f\"SELECT * FROM users WHERE username = '{user}'\"": "This is vulnerable string formatting, not parameterized query syntax.",
            "SELECT * FROM users": "You must include the WHERE clause with placeholder parameters (?).",
        },
    ),
    TaskDefinition(
        task_id="task-06-quiz",
        order=6,
        title="SQL Injection Concept Quiz",
        instructions="Complete the 5-question quiz to test your conceptual understanding of SQLi prevention and mechanics.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question concept quiz.",
        hint="Review Prepared Statements, ORMs, and escaping.",
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is the single most effective defense against SQL Injection vulnerabilities?",
                options=[
                    "Parameterized Queries (Prepared Statements)",
                    "Web Application Firewalls (WAF) regex rules",
                    "Blacklisting single quotes in client JavaScript",
                    "Encoding input into Base64 before storing",
                ],
                correct_option_index=0,
                explanation="Parameterized queries separate code from data at the database protocol level, rendering injection mathematically impossible.",
            ),
            QuizQuestion(
                id="q2",
                question="In standard SQL syntax, what does the double hyphen (--) signify?",
                options=[
                    "The beginning of a single-line comment",
                    "A string concatenation operator",
                    "A decrement assignment operator",
                    "A wild-card column selector",
                ],
                correct_option_index=0,
                explanation="In SQL dialects (SQLite, PostgreSQL, MSSQL, Oracle), -- instructs the parser to ignore all remaining characters on that line.",
            ),
            QuizQuestion(
                id="q3",
                question="What requirement must be met for a UNION SELECT attack to succeed?",
                options=[
                    "The injected query must have the exact same number of columns and compatible data types as the original query",
                    "The database user must have administrative (DBA) permissions",
                    "The target table must be in the same database schema file",
                    "The web application must be running in debug mode",
                ],
                correct_option_index=0,
                explanation="SQL UNION combines result sets; both SELECT statements must return identical column counts with matching or coercible types.",
            ),
            QuizQuestion(
                id="q4",
                question="Why is client-side input validation (e.g. JavaScript HTML form checks) insufficient for SQLi protection?",
                options=[
                    "Attackers can bypass client-side checks easily using curl, Burp Suite, or Python scripts",
                    "Client-side scripts cannot read database error codes",
                    "Browsers do not support regular expressions",
                    "SQL queries run in the browser before reaching the server",
                ],
                correct_option_index=0,
                explanation="Attackers interact with backend HTTP endpoints directly; client-side validation is a UX feature, not a security boundary.",
            ),
            QuizQuestion(
                id="q5",
                question="Which OWASP Top 10 category includes SQL Injection?",
                options=[
                    "A03:2021 - Injection",
                    "A01:2021 - Broken Access Control",
                    "A05:2021 - Security Misconfiguration",
                    "A07:2021 - Identification and Authentication Failures",
                ],
                correct_option_index=0,
                explanation="SQLi, OS Command Injection, and LDAP Injection fall under A03:2021 - Injection in the OWASP Top 10.",
            ),
        ],
    ),
]

ROOM_09_DEFINITION = RoomDefinition(
    room_id="red-09-sqli-fundamentals",
    track=TrackEnum.RED,
    room_number=9,
    title="SQL Injection Fundamentals",
    short_description="Learn SQLi mechanics, exploit auth bypass and UNION exfiltration, and verify parameterized queries.",
    difficulty="Beginner",
    estimated_duration="45 min",
    prerequisites=["Web Fundamentals", "Basic SQL Knowledge"],
    required_skills=["Authentication bypass", "UNION data exfiltration", "Code remediation verification"],
    lab_type="container_isolated",
    concept=ROOM_09_CONCEPT,
    tasks=ROOM_09_TASKS,
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Identify vulnerable SQL injection vectors in web input fields",
        "Construct authentication bypass payloads using boolean tautologies",
        "Determine query column count and exfiltrate database records using UNION SELECT",
        "Understand and verify parameterized query remediation in production code",
    ],
    assessment_criteria=[
        "Successfully identify the SQL string delimiter character",
        "Capture the administrative session flag via auth bypass",
        "Exfiltrate the secret flag from the hidden_flags table",
        "Solve the numeric injection pivot challenge",
        "Pass the 5-question concept assessment quiz",
    ],
    completion_requirements=["Complete all 6 tasks with 100% accuracy"],
    total_xp=350,
)

# ============================================================================
# CURRICULUM CATALOG BUILDER: ALL 80 ROOMS
# ============================================================================

def _build_red_track() -> List[RoomDefinition]:
    rooms = []
    red_catalog = [
        (1, "red-01-cybersecurity-foundations", "Cybersecurity Foundations", "Explore the CIA Triad, threats vs vulnerabilities vs risks, attack surfaces, security controls, ethical boundaries, and red/blue/purple team roles.", "Beginner", "35 min"),
        (2, "red-02-linux-for-hackers", "Linux for Hackers", "Master the Linux terminal, command execution, absolute and relative paths, file operations, permissions, process management, and user identification.", "Beginner", "45 min"),
        (3, "red-03-networking-fundamentals", "Networking Fundamentals", "Master IP addressing, subnet masks, TCP vs UDP, ports and protocols, MAC addresses, DNS resolution, and client-server communication using real network commands.", "Beginner", "45 min"),
        (4, "red-04-reconnaissance", "Reconnaissance", "Master passive vs active reconnaissance, service enumeration, directory and asset discovery, banner grabbing, and scope authorization against local targets.", "Beginner", "45 min"),
        (5, "red-05-network-scanning", "Network Scanning", "Master host discovery, port scanning, TCP connection vs SYN scanning, port states (open, closed, filtered), service discovery, scan timing, and authorized scope.", "Beginner", "45 min"),
        (6, "red-06-service-enumeration", "Service Enumeration", "Differentiate scanning from enumeration, extract service banners (FTP, SSH), inspect HTTP response headers, and discover administrative APIs.", "Beginner", "45 min"),
        (7, "red-07-vulnerability-assessment", "Vulnerability Assessment", "Distinguish vulnerabilities from exploits, analyze CVE identifiers and CVSS metrics, audit component inventories using local databases and CLI tools, and verify patch remediations.", "Beginner", "45 min"),
        (8, "red-08-web-application-fundamentals", "Web Application Fundamentals", "Master client-server architecture, HTTP methods (GET, POST, PUT, DELETE), status codes, request/response headers, cookie-based session management, and REST APIs.", "Beginner", "45 min"),
        (9, "red-09-sqli-fundamentals", "SQL Injection Fundamentals", "Learn SQLi mechanics, exploit auth bypass and UNION exfiltration, and verify parameterized queries.", "Beginner", "45 min"),
        (10, "red-10-cross-site-scripting", "Cross-Site Scripting (XSS)", "Master Reflected, Stored, and DOM XSS mechanics, input validation, context-aware output encoding, and Content Security Policy.", "Intermediate", "50 min"),
        (11, "red-11-authentication-attacks", "Authentication Attacks", "Master authentication vs authorization, password hashing, dictionary attacks, credential stuffing, telemetry logs, and rate limiting.", "Intermediate", "50 min"),
        (12, "red-12-access-control-testing", "Access Control Testing", "Master authentication vs authorization, RBAC, IDOR / BOLA, horizontal vs vertical boundaries, and server-side authorization checks.", "Intermediate", "50 min"),
        (13, "red-13-file-upload-vulnerabilities", "File Upload Vulnerabilities", "Master file upload mechanics, extension bypasses, magic byte inspection, path traversal risks, and secure isolated storage.", "Intermediate", "50 min"),
        (14, "red-14-command-injection", "Command Injection", "Analyze OS command construction, exploit shell metacharacters and command chaining operators, and implement secure process execution APIs.", "Intermediate", "45 min"),
        (15, "red-15-directory-traversal", "Directory Traversal", "Explore filesystem path boundaries, exploit dot-dot-slash relative references and URL-encoded traversal patterns, and enforce canonical path resolution.", "Intermediate", "45 min"),
        (16, "red-16-password-security", "Password Security & Key Stretching", "Understand cryptographic password storage, crack unsalted legacy hashes, explore adaptive key-derivation algorithms (bcrypt, Argon2id), and apply NIST 800-63B standards.", "Intermediate", "45 min"),
        (17, "red-17-privilege-escalation", "Privilege Escalation Fundamentals", "Analyze vertical and horizontal privilege escalation, audit SUID/SGID binaries, exploit misconfigured sudoers rules, and enforce the principle of least privilege.", "Intermediate", "45 min"),
        (18, "red-18-active-directory-fundamentals", "Active Directory Fundamentals", "Explore enterprise identity architecture, domain hierarchies, LDAP directory enumeration, Kerberos ticket authentication, and Group Policy hardening.", "Intermediate", "45 min"),
        (19, "red-19-exploitation-post-exploitation", "Exploitation and Post-Exploitation", "Master the lifecycle of controlled foothold exploitation, post-exploitation telemetry, persistence analysis, lateral movement risks, and responsible cleanup.", "Advanced", "45 min"),
        (20, "red-20-red-team-capstone", "Red Team Capstone", "Conduct a full-spectrum authorized penetration assessment against VoltDefense Systems, chaining perimeter discovery, foothold compromise, privilege escalation, and formal reporting.", "Advanced", "60 min"),
    ]

    for num, rid, title, desc, diff, dur in red_catalog:
        if num == 1:
            rooms.append(ROOM_01_DEFINITION)
        elif num == 2:
            rooms.append(ROOM_02_DEFINITION)
        elif num == 3:
            rooms.append(ROOM_03_DEFINITION)
        elif num == 4:
            rooms.append(ROOM_04_DEFINITION)
        elif num == 5:
            rooms.append(ROOM_05_DEFINITION)
        elif num == 6:
            rooms.append(ROOM_06_DEFINITION)
        elif num == 7:
            rooms.append(ROOM_07_DEFINITION)
        elif num == 8:
            rooms.append(ROOM_08_DEFINITION)
        elif num == 9:
            rooms.append(ROOM_09_DEFINITION)
        elif num == 10:
            rooms.append(ROOM_10_DEFINITION)
        elif num == 11:
            rooms.append(ROOM_11_DEFINITION)
        elif num == 12:
            rooms.append(ROOM_12_DEFINITION)
        elif num == 13:
            rooms.append(ROOM_13_DEFINITION)
        elif num == 14:
            rooms.append(ROOM_14_DEFINITION)
        elif num == 15:
            rooms.append(ROOM_15_DEFINITION)
        elif num == 16:
            rooms.append(ROOM_16_DEFINITION)
        elif num == 17:
            rooms.append(ROOM_17_DEFINITION)
        elif num == 18:
            rooms.append(ROOM_18_DEFINITION)
        elif num == 19:
            rooms.append(ROOM_19_DEFINITION)
        elif num == 20:
            rooms.append(ROOM_20_DEFINITION)
        else:
            rooms.append(
                RoomDefinition(
                    room_id=rid,
                    track=TrackEnum.RED,
                    room_number=num,
                    title=title,
                    short_description=desc,
                    difficulty=diff,
                    estimated_duration=dur,
                    status=RoomStatus.PLANNED,
                    learning_objectives=[f"Master foundational concepts of {title}", "Apply techniques in hands-on practical lab scenarios"],
                    assessment_criteria=["Complete all guided tasks", "Capture the room challenge flag"],
                    completion_requirements=["Achieve 100% task validation"],
                    total_xp=250,
                )
            )
    return rooms


def _build_blue_track() -> List[RoomDefinition]:
    blue_catalog = [
        (1, "blue-01-blue-team-foundations", "Blue Team Foundations", "Explore Security Operations Center (SOC) workflows, SIEM telemetry triage, incident classification, IOC analysis, and containment response.", "Beginner", "45 min"),
        (2, "blue-02-windows-security-fundamentals", "Windows Security Fundamentals", "Audit Windows security architecture, token privileges, Security Event IDs (4624, 4625, 4720), and account lockout hardening.", "Beginner", "45 min"),
        (3, "blue-03-linux-security-monitoring", "Linux Security Monitoring", "Triage Linux authentication logs, investigate SSH brute-force attacks, audit sudo privilege abuse, and deploy fail2ban hardening.", "Beginner", "45 min"),
        (4, "blue-04-network-traffic-analysis", "Network Traffic Analysis", "Analyze PCAPs with packet dissection, extract cleartext credentials, detect DNS exfiltration tunneling, and enforce TLS.", "Beginner", "45 min"),
        (5, "blue-05-wireshark-fundamentals", "Wireshark Fundamentals", "Dissect Ethernet frames, TCP handshakes, HTTP streams, and DNS queries with Wireshark and tshark deep packet inspection.", "Intermediate", "45 min"),
        (6, "blue-06-log-analysis-fundamentals", "Log Analysis Fundamentals", "Investigate web server access logs and application JSON events using Linux command-line utilities (grep, awk, cut, sort, uniq).", "Intermediate", "45 min"),
        (7, "blue-07-siem-fundamentals", "SIEM Fundamentals", "Master event normalization, query search indexes, correlate detection alerts, and author custom alert rules in a security information hub.", "Intermediate", "45 min"),
        (8, "blue-08-windows-event-investigation", "Windows Event Investigation", "Conduct deep forensic analysis of Windows Security Event Logs: process creation (4688), group escalation (4732), script blocks (4104), and anti-forensics (1102).", "Intermediate", "45 min"),
        (9, "blue-09-bruteforce-detection", "Brute-Force Detection", "Analyze authentication telemetry, identify password spraying vs dictionary attacks, deploy SIEM correlation rules, and enforce containment.", "Intermediate", "45 min"),
        (10, "blue-10-malware-behaviour-analysis", "Malware Behaviour Analysis", "Perform safe static triage of suspicious binaries, inspect PE headers, extract C2 URLs and persistence keys, and author YARA detection rules.", "Intermediate", "50 min"),
        (11, "blue-11-phishing-investigation", "Phishing Investigation", "Analyze email headers, evaluate SPF, DKIM, and DMARC alignment, identify lookalike domains, and execute incident containment.", "Beginner", "45 min"),
        (12, "blue-12-endpoint-detection", "Endpoint Detection", "Investigate EDR telemetry, audit abnormal process trees (PID/PPID), identify LOLBIN abuse, deploy behavioral rules, and enforce endpoint containment.", "Intermediate", "50 min"),
        (13, "blue-13-network-intrusion-detection", "Network Intrusion Detection", "Analyze mirrored PCAP streams with tshark, detect stealthy SYN scans and covert C2 beaconing, author Snort rules, and correlate intrusion telemetry.", "Intermediate", "50 min"),
        (14, "blue-14-threat-hunting", "Threat Hunting", "Formulate hypotheses based on MITRE ATT&CK, trace abnormal process lineage (winword spawning powershell), uncover hidden persistence, and author Sigma rules.", "Intermediate", "50 min"),
        (15, "blue-15-incident-triage", "Incident Triage", "Triage incoming SOC alerts, differentiate True Positives from benign noise, evaluate asset blast radius (DB-PROD-01), and execute formal incident escalation.", "Intermediate", "45 min"),
        (16, "blue-16-incident-response", "Incident Response", "Execute the complete Incident Response lifecycle (NIST SP 800-61): enforce host containment, preserve volatile RAM evidence, eradicate C2 persistence, and document lessons learned.", "Intermediate", "50 min"),
        (17, "blue-17-digital-forensics", "Digital Forensics", "Reconstruct workstation compromises, extract filesystem metadata and MACB timestamps, calculate SHA-256 hashes, and preserve chain of custody.", "Intermediate", "45 min"),
        (18, "blue-18-windows-linux-hardening", "Windows and Linux Hardening", "Audit OS security postures, enforce least privilege, harden SSH configurations, remediate wildcard sudoers, and enforce Windows CIS security policies.", "Intermediate", "45 min"),
        (19, "blue-19-threat-intelligence", "Threat Intelligence", "Extract and classify IOCs, correlate indicators across Diamond Model vertices, map behaviors to MITRE ATT&CK, and generate actionable CTI assessments.", "Intermediate", "45 min"),
        (20, "blue-20-blue-team-capstone", "Blue Team Capstone", "Lead a 9-stage enterprise incident investigation: detection, timeline reconstruction, hunting, forensics, threat intelligence, triage, containment, and final incident reporting.", "Advanced", "60 min"),
    ]

    rooms = []
    for num, rid, title, desc, diff, dur in blue_catalog:
        if num == 1:
            rooms.append(ROOM_BLUE_01_DEFINITION)
        elif num == 2:
            rooms.append(ROOM_BLUE_02_DEFINITION)
        elif num == 3:
            rooms.append(ROOM_BLUE_03_DEFINITION)
        elif num == 4:
            rooms.append(ROOM_BLUE_04_DEFINITION)
        elif num == 5:
            rooms.append(ROOM_BLUE_05_DEFINITION)
        elif num == 6:
            rooms.append(ROOM_BLUE_06_DEFINITION)
        elif num == 7:
            rooms.append(ROOM_BLUE_07_DEFINITION)
        elif num == 8:
            rooms.append(ROOM_BLUE_08_DEFINITION)
        elif num == 9:
            rooms.append(ROOM_BLUE_09_DEFINITION)
        elif num == 10:
            rooms.append(ROOM_BLUE_10_DEFINITION)
        elif num == 11:
            rooms.append(ROOM_BLUE_11_DEFINITION)
        elif num == 12:
            rooms.append(ROOM_BLUE_12_DEFINITION)
        elif num == 13:
            rooms.append(ROOM_BLUE_13_DEFINITION)
        elif num == 14:
            rooms.append(ROOM_BLUE_14_DEFINITION)
        elif num == 15:
            rooms.append(ROOM_BLUE_15_DEFINITION)
        elif num == 16:
            rooms.append(ROOM_BLUE_16_DEFINITION)
        elif num == 17:
            rooms.append(ROOM_BLUE_17_DEFINITION)
        elif num == 18:
            rooms.append(ROOM_BLUE_18_DEFINITION)
        elif num == 19:
            rooms.append(ROOM_BLUE_19_DEFINITION)
        elif num == 20:
            rooms.append(ROOM_BLUE_20_DEFINITION)
        else:
            rooms.append(
                RoomDefinition(
                    room_id=rid,
                    track=TrackEnum.BLUE,
                    room_number=num,
                    title=title,
                    short_description=desc,
                    difficulty=diff,
                    estimated_duration=dur,
                    status=RoomStatus.PLANNED,
                    learning_objectives=[f"Master defensive operations in {title}", "Investigate incidents using real security telemetry"],
                    assessment_criteria=["Triage forensic artifacts", "Isolate compromised assets and block C2 channels"],
                    completion_requirements=["Achieve 100% task validation"],
                    total_xp=250,
                )
            )
    return rooms


def _build_purple_track() -> List[RoomDefinition]:
    purple_catalog = [
        (1, "purple-01-purple-team-foundations", "Purple Team Foundations", "Master collaborative offensive and defensive cybersecurity alignment, continuous attack validation, detection feedback loops, and evidence-backed exercise planning.", "Beginner", "40 min"),
        (2, "purple-02-mitre-attack-fundamentals", "MITRE ATT&CK Fundamentals", "Analyze authentication events, process trees, and persistence mechanisms; map observed adversary behaviors to MITRE ATT&CK tactics, techniques, and data sources.", "Beginner", "45 min"),
        (3, "purple-03-attack-simulation-planning", "Attack Simulation Planning", "Design structured, safe adversary emulation plans: define Rules of Engagement, predict telemetry generation, configure safety boundaries, and establish deconfliction criteria.", "Intermediate", "50 min"),
        (4, "purple-04-reconnaissance-vs-monitoring", "Reconnaissance vs Monitoring", "Perform controlled Nmap port scans, inspect network sensor telemetry, correlate offensive scanning with defensive detection alerts, and tune IDS threshold rules to eliminate blind spots.", "Intermediate", "50 min"),
        (5, "purple-05-privesc-emulation", "Emulating Privilege Escalation Techniques", "Simulate token manipulation, UAC bypasses, and verify security event log correlation.", "Intermediate", "55 min"),
        (6, "purple-06-defense-evasion-emulation", "Emulating Defense Evasion & Process Injection", "Test process hollowing, thread execution hijacking, and evaluate EDR behavioral alerts.", "Advanced", "65 min"),
        (7, "purple-07-lateral-movement-emulation", "Emulating Lateral Movement (SMB, WMI, WinRM)", "Emulate remote execution via PsExec and WMI, identifying detection blind spots across network segments.", "Intermediate", "60 min"),
        (8, "purple-08-persistence-emulation", "Emulating Persistence Mechanisms", "Install persistence via scheduled tasks, registry run keys, and services; verify detection and remediation.", "Intermediate", "55 min"),
        (9, "purple-09-c2-framework-emulation", "Command & Control (C2) Traffic Emulation", "Emulate Covenant/Sliver C2 channels and test network egress filtering and beacon detection.", "Advanced", "70 min"),
        (10, "purple-10-exfiltration-emulation", "Emulating Data Exfiltration Techniques", "Simulate encrypted staging, archive compression, and DNS/HTTPS exfiltration tunnels to measure detection lag.", "Intermediate", "50 min"),
        (11, "purple-11-ransomware-readiness", "Ransomware Attack Emulation & Readiness", "Simulate rapid file encryption indicators and canary token touches without damaging assets.", "Advanced", "65 min"),
        (12, "purple-12-cloud-identity-emulation", "Cloud Identity & IAM Privilege Escalation Emulation", "Emulate AWS/Azure role assumption abuse and verify cloud audit log alert pipelines.", "Intermediate", "60 min"),
        (13, "purple-13-supply-chain-emulation", "Supply Chain & Dependency Confusion Emulation", "Simulate package typosquatting and internal package repository hijacking in a sandbox pipeline.", "Advanced", "65 min"),
        (14, "purple-14-api-abuse-emulation", "API Security & Broken Object Level Auth (BOLA) Emulation", "Emulate API parameter tampering and test WAF/API gateway anomaly detection triggers.", "Intermediate", "50 min"),
        (15, "purple-15-active-directory-attacks-emulation", "Active Directory Attacks Emulation (Kerberoasting)", "Execute Kerberoasting, AS-REP roasting, and evaluate domain controller event telemetry.", "Intermediate", "60 min"),
        (16, "purple-16-ci-cd-pipeline-emulation", "CI/CD Pipeline & GitHub Actions Attack Emulation", "Simulate secret exfiltration from continuous integration workflows and tune pipeline audit rules.", "Intermediate", "55 min"),
        (17, "purple-17-edr-bypass-emulation", "EDR Telemetry Blinding & Bypass Emulation", "Test AMSI bypasses and API unhooking in a controlled lab to evaluate behavioral fallback detections.", "Advanced", "75 min"),
        (18, "purple-18-ttp-heatmap-generation", "TTP Heatmap Generation & Coverage Scoring", "Compile attack validation results into interactive ATT&CK Navigator heatmaps for leadership review.", "Intermediate", "45 min"),
        (19, "purple-19-continuous-security-validation", "Continuous Security Validation & Automated Testing", "Deploy automated adversary emulation frameworks (Caldera/Atomic) for daily recurring checks.", "Advanced", "60 min"),
        (20, "purple-20-capstone-purple-exercise", "Purple Team Capstone: Full Adversary Emulation Exercise", "Orchestrate an end-to-end Purple Team exercise: emulate APT29 tactics, tune detections, and close security gaps.", "Advanced", "90 min"),
    ]

    rooms = []
    for num, rid, title, desc, diff, dur in purple_catalog:
        if num == 1:
            rooms.append(ROOM_PURPLE_01_DEFINITION)
        elif num == 2:
            rooms.append(ROOM_PURPLE_02_DEFINITION)
        elif num == 3:
            rooms.append(ROOM_PURPLE_03_DEFINITION)
        elif num == 4:
            rooms.append(ROOM_PURPLE_04_DEFINITION)
        elif num == 5:
            rooms.append(ROOM_PURPLE_05_DEFINITION)
        elif num == 6:
            rooms.append(ROOM_PURPLE_06_DEFINITION)
        elif num == 7:
            rooms.append(ROOM_PURPLE_07_DEFINITION)
        elif num == 8:
            rooms.append(ROOM_PURPLE_08_DEFINITION)
        elif num == 9:
            rooms.append(ROOM_PURPLE_09_DEFINITION)
        elif num == 10:
            rooms.append(ROOM_PURPLE_10_DEFINITION)
        elif num == 11:
            rooms.append(ROOM_PURPLE_11_DEFINITION)
        elif num == 12:
            rooms.append(ROOM_PURPLE_12_DEFINITION)
        elif num == 13:
            rooms.append(ROOM_PURPLE_13_DEFINITION)
        elif num == 14:
            rooms.append(ROOM_PURPLE_14_DEFINITION)
        elif num == 15:
            rooms.append(ROOM_PURPLE_15_DEFINITION)
        elif num == 16:
            rooms.append(ROOM_PURPLE_16_DEFINITION)
        elif num == 17:
            rooms.append(ROOM_PURPLE_17_DEFINITION)
        elif num == 18:
            rooms.append(ROOM_PURPLE_18_DEFINITION)
        elif num == 19:
            rooms.append(ROOM_PURPLE_19_DEFINITION)
        elif num == 20:
            rooms.append(ROOM_PURPLE_20_DEFINITION)
        else:
            rooms.append(
                RoomDefinition(
                    room_id=rid,
                    track=TrackEnum.PURPLE,
                    room_number=num,
                    title=title,
                    short_description=desc,
                    difficulty=diff,
                    estimated_duration=dur,
                    status=RoomStatus.PLANNED,
                    learning_objectives=[f"Master Purple Teaming methodology in {title}", "Emulate adversary TTPs and tune detection telemetry"],
                    assessment_criteria=["Execute adversary emulation procedures", "Verify detection alert generation and tune rules"],
                    completion_requirements=["Achieve 100% task validation"],
                    total_xp=250,
                )
            )
    return rooms


def _build_detection_track() -> List[RoomDefinition]:
    detection_catalog = [
        (1, "detect-01-foundations-as-code", "Detection Engineering Foundations & Detection-as-Code", "Understand detection-as-code, detection lifecycles, and false-positive reduction strategies.", "Beginner", "40 min"),
        (2, "detect-02-log-normalization", "Log Normalization & Taxonomy (ECS & CIM)", "Master log normalization taxonomies (ECS & CIM), resolve field schema heterogeneity, and build vendor-agnostic data pipelines.", "Beginner", "45 min"),
        (3, "detect-03-sigma-syntax", "Sigma Rule Syntax & Component Structure", "Master the Sigma YAML specification (v2.0), selection maps, field value modifiers, and transpilation into SIEM search queries.", "Beginner", "45 min"),
        (4, "detect-04-process-creation-rules", "Writing Process Creation Rules (Sysmon Event ID 1)", "Master process creation detection (Sysmon 1 / Event 4688), LOLBIN command line analysis (certutil, mshta), and parent-child anomaly filters.", "Intermediate", "50 min"),
        (5, "detect-05-network-connection-rules", "Writing Network Connection Rules (Sysmon Event ID 3)", "Write high-fidelity rules detecting unauthorized outbound beaconing, rare ports, and anomalous network connections.", "Intermediate", "50 min"),
        (6, "detect-06-file-registry-rules", "Writing File & Registry Integrity Rules", "Detect persistence mechanisms via Run keys, Startup folder additions, and sensitive system file modifications.", "Intermediate", "50 min"),
        (7, "detect-07-auth-abuse-rules", "Detecting Authentication Abuse (Event IDs 4624/4625/4672)", "Write detection rules alerting on brute-force spikes, explicit credential use, and privilege escalation.", "Intermediate", "55 min"),
        (8, "detect-08-powershell-obfuscation", "Detecting PowerShell Obfuscation & Download Cradles", "Detect base64 encoding (-enc), string reversal, and WebClient downloads using regex and Sigma.", "Intermediate", "55 min"),
        (9, "detect-09-web-detection-rules", "Writing Web Application Detection Rules (SQLi, XSS, LFI)", "Analyze web server logs to write rules catching SQL injection syntax and directory traversal patterns.", "Intermediate", "50 min"),
        (10, "detect-10-modsec-crs-tuning", "ModSecurity Core Rule Set Tuning & Custom Rules", "Inspect OWASP Core Rule Set anomalies, adjust paranoia levels, and author custom SecRules.", "Advanced", "60 min"),
        (11, "detect-11-wazuh-decoders-rules", "Wazuh / OSSEC Rules & Decoders", "Author custom decoders and XML detection rules for custom proprietary application logs.", "Advanced", "60 min"),
        (12, "detect-12-reducing-false-positives", "Tuning Detections & Reducing False Positives", "Analyze benign corporate baseline traffic and apply filter exclusions without creating blind spots.", "Intermediate", "45 min"),
        (13, "detect-13-threshold-detections", "Baseline Profiling & Threshold-Based Detections", "Craft stateful queries alerting when an entity exceeds normal baseline thresholds in time windows.", "Intermediate", "50 min"),
        (14, "detect-14-correlation-rules", "Correlation Rules: Multi-Event Detection", "Link multiple independent event stages (phishing click + process launch + C2 connection) into one high-severity alert.", "Advanced", "65 min"),
        (15, "detect-15-unit-testing-rules", "Detection Testing with Unit Tests & Synthetic Logs", "Test Sigma and SIEM rules against synthetic positive and negative log corpuses in automated CI.", "Intermediate", "50 min"),
        (16, "detect-16-yara-hunting", "YARA Rules for File & Memory Threat Hunting", "Write string and hexadecimal YARA rules to detect malware signatures and packed payloads in memory.", "Advanced", "60 min"),
        (17, "detect-17-snort-suricata", "Snort / Suricata Network Signatures", "Author packet-level intrusion detection signatures inspecting payload bytes, PCRE, and flow flags.", "Advanced", "60 min"),
        (18, "detect-18-threat-hunting-hypothesis", "Threat Hunting Hypothesis Formulation", "Formulate intelligence-driven hypotheses and translate them into investigative queries.", "Intermediate", "45 min"),
        (19, "detect-19-ci-cd-detection-pipelines", "CI/CD Pipelines for Detection Rules", "Build automated GitHub Actions/GitLab pipelines that validate, lint, test, and deploy Sigma rules.", "Advanced", "60 min"),
        (20, "detect-20-capstone-detection-pipeline", "Detection Engineering Capstone: Production Pipeline", "Design and deploy a complete production detection pipeline: author, test against attack logs, tune, and deploy.", "Advanced", "90 min"),
    ]

    rooms = []
    for num, rid, title, desc, diff, dur in detection_catalog:
        if num == 1:
            rooms.append(ROOM_DETECTION_01_DEFINITION)
        elif num == 2:
            rooms.append(ROOM_DETECTION_02_DEFINITION)
        elif num == 3:
            rooms.append(ROOM_DETECTION_03_DEFINITION)
        elif num == 4:
            rooms.append(ROOM_DETECTION_04_DEFINITION)
        elif num == 5:
            rooms.append(ROOM_DETECTION_05_DEFINITION)
        elif num == 6:
            rooms.append(ROOM_DETECTION_06_DEFINITION)
        elif num == 7:
            rooms.append(ROOM_DETECTION_07_DEFINITION)
        elif num == 8:
            rooms.append(ROOM_DETECTION_08_DEFINITION)
        elif num == 9:
            rooms.append(ROOM_DETECTION_09_DEFINITION)
        elif num == 10:
            rooms.append(ROOM_DETECTION_10_DEFINITION)
        elif num == 11:
            rooms.append(ROOM_DETECTION_11_DEFINITION)
        elif num == 12:
            rooms.append(ROOM_DETECTION_12_DEFINITION)
        elif num == 13:
            rooms.append(ROOM_DETECTION_13_DEFINITION)
        elif num == 14:
            rooms.append(ROOM_DETECTION_14_DEFINITION)
        elif num == 15:
            rooms.append(ROOM_DETECTION_15_DEFINITION)
        elif num == 16:
            rooms.append(ROOM_DETECTION_16_DEFINITION)
        elif num == 17:
            rooms.append(ROOM_DETECTION_17_DEFINITION)
        elif num == 18:
            rooms.append(ROOM_DETECTION_18_DEFINITION)
        elif num == 19:
            rooms.append(ROOM_DETECTION_19_DEFINITION)
        elif num == 20:
            rooms.append(ROOM_DETECTION_20_DEFINITION)
        else:
            rooms.append(
                RoomDefinition(
                    room_id=rid,
                    track=TrackEnum.DETECTION,
                    room_number=num,
                    title=title,
                    short_description=desc,
                    difficulty=diff,
                    estimated_duration=dur,
                    status=RoomStatus.PLANNED,
                    learning_objectives=[f"Master detection techniques in {title}", "Author high-fidelity detection rules with zero false positives"],
                    assessment_criteria=["Pass automated syntax validation", "Verify detection triggers on malicious logs"],
                    completion_requirements=["Achieve 100% task validation"],
                    total_xp=250,
                )
            )
    return rooms


class CurriculumRegistry:
    def __init__(self):
        self._rooms: Dict[str, RoomDefinition] = {}
        self._load_all()

    def _load_all(self):
        for r in _build_red_track():
            self._rooms[r.room_id] = r
        for r in _build_blue_track():
            self._rooms[r.room_id] = r
        for r in _build_purple_track():
            self._rooms[r.room_id] = r
        for r in _build_detection_track():
            self._rooms[r.room_id] = r

    def get_room(self, room_id: str) -> Optional[RoomDefinition]:
        if room_id in self._rooms:
            return self._rooms[room_id]
        aliases = {
            "red-01-linux-essentials": "red-01-cybersecurity-foundations",
            "red-01-foundations": "red-01-cybersecurity-foundations",
            "red-02-network-recon": "red-02-linux-for-hackers",
            "red-03-web-recon": "red-03-networking-fundamentals",
            "red-04-vuln-scanning": "red-04-reconnaissance",
            "red-05-auth-attacks": "red-05-network-scanning",
            "red-06-hash-cracking": "red-06-service-enumeration",
            "red-07-proxy-burp": "red-07-vulnerability-assessment",
            "red-08-lfi-rfi": "red-08-web-application-fundamentals",
            "red-10-xss-basics": "red-10-cross-site-scripting",
            "red-11-command-injection": "red-11-authentication-attacks",
            "red-11-auth-attacks": "red-11-authentication-attacks",
            "red-12-file-upload": "red-12-access-control-testing",
            "red-12-access-control": "red-12-access-control-testing",
            "red-13-ssrf": "red-13-file-upload-vulnerabilities",
            "red-13-file-upload": "red-13-file-upload-vulnerabilities",
            "red-14-linux-privesc-suid": "red-14-command-injection",
            "red-14": "red-14-command-injection",
            "red-15-linux-privesc-cron": "red-15-directory-traversal",
            "red-15": "red-15-directory-traversal",
            "red-16-win-recon": "red-16-password-security",
            "red-16": "red-16-password-security",
            "red-17-win-privesc": "red-17-privilege-escalation",
            "red-17": "red-17-privilege-escalation",
            "red-18-ad-enum": "red-18-active-directory-fundamentals",
            "red-18": "red-18-active-directory-fundamentals",
            "red-18-lateral-pivoting": "red-18-active-directory-fundamentals",
            "red-19-ad-kerberoast": "red-19-exploitation-post-exploitation",
            "red-19": "red-19-exploitation-post-exploitation",
            "red-19-metasploit": "red-19-exploitation-post-exploitation",
            "red-20-capstone": "red-20-red-team-capstone",
            "red-20": "red-20-red-team-capstone",
            "red-20-capstone-breach": "red-20-red-team-capstone",
            # Blue Team Aliases
            "blue-01": "blue-01-blue-team-foundations",
            "blue-01-soc-fundamentals": "blue-01-blue-team-foundations",
            "blue-02": "blue-02-windows-security-fundamentals",
            "blue-02-windows-event-logs": "blue-02-windows-security-fundamentals",
            "blue-02-wireshark-packets": "blue-02-windows-security-fundamentals",
            "blue-03": "blue-03-linux-security-monitoring",
            "blue-03-linux-log-analysis": "blue-03-linux-security-monitoring",
            "blue-04": "blue-04-network-traffic-analysis",
            "blue-04-windows-event-logs": "blue-04-network-traffic-analysis",
            "blue-04-wireshark-packets": "blue-04-network-traffic-analysis",
            "blue-05": "blue-05-wireshark-fundamentals",
            "blue-05-wireshark-packets": "blue-05-wireshark-fundamentals",
            "blue-05-edr-principles": "blue-05-wireshark-fundamentals",
            "blue-06": "blue-06-log-analysis-fundamentals",
            "blue-06-log-analysis": "blue-06-log-analysis-fundamentals",
            "blue-06-threat-intel-ioc": "blue-06-log-analysis-fundamentals",
            "blue-07": "blue-07-siem-fundamentals",
            "blue-07-siem-splunk-elk": "blue-07-siem-fundamentals",
            "blue-07-memory-forensics": "blue-07-siem-fundamentals",
            "blue-08": "blue-08-windows-event-investigation",
            "blue-08-windows-event-logs": "blue-08-windows-event-investigation",
            "blue-08-disk-forensics": "blue-08-windows-event-investigation",
            # Blue 09-12
            "blue-09": "blue-09-bruteforce-detection",
            "blue-09-bruteforce": "blue-09-bruteforce-detection",
            "blue-09-beacon-detection": "blue-09-bruteforce-detection",
            "blue-10": "blue-10-malware-behaviour-analysis",
            "blue-10-malware": "blue-10-malware-behaviour-analysis",
            "blue-10-malware-analysis": "blue-10-malware-behaviour-analysis",
            "blue-10-malware-static": "blue-10-malware-behaviour-analysis",
            "blue-11": "blue-11-phishing-investigation",
            "blue-11-phishing": "blue-11-phishing-investigation",
            "blue-11-email-security": "blue-11-phishing-investigation",
            "blue-11-malware-dynamic": "blue-11-phishing-investigation",
            "blue-12": "blue-12-endpoint-detection",
            "blue-12-endpoint": "blue-12-endpoint-detection",
            "blue-12-edr": "blue-12-endpoint-detection",
            "blue-12-siem-splunk-elk": "blue-12-endpoint-detection",
            # Blue 13-16
            "blue-13": "blue-13-network-intrusion-detection",
            "blue-13-nids": "blue-13-network-intrusion-detection",
            "blue-13-network-intrusion": "blue-13-network-intrusion-detection",
            "blue-13-email-security": "blue-13-network-intrusion-detection",
            "blue-14": "blue-14-threat-hunting",
            "blue-14-hunting": "blue-14-threat-hunting",
            "blue-14-web-defense": "blue-14-threat-hunting",
            "blue-15": "blue-15-incident-triage",
            "blue-15-triage": "blue-15-incident-triage",
            "blue-15-active-directory-def": "blue-15-incident-triage",
            "blue-16": "blue-16-incident-response",
            "blue-16-ir": "blue-16-incident-response",
            "blue-16-response": "blue-16-incident-response",
            "blue-16-identity-access-mfa": "blue-16-incident-response",
            # Blue 17-20
            "blue-17": "blue-17-digital-forensics",
            "blue-17-forensics": "blue-17-digital-forensics",
            "blue-17-incident-response-containment": "blue-17-digital-forensics",
            "blue-18": "blue-18-windows-linux-hardening",
            "blue-18-hardening": "blue-18-windows-linux-hardening",
            "blue-18-threat-hunting-matrix": "blue-18-windows-linux-hardening",
            "blue-19": "blue-19-threat-intelligence",
            "blue-19-intel": "blue-19-threat-intelligence",
            "blue-19-digital-forensics-evidence": "blue-19-threat-intelligence",
            "blue-20": "blue-20-blue-team-capstone",
            "blue-20-capstone": "blue-20-blue-team-capstone",
            "blue-20-capstone-incident": "blue-20-blue-team-capstone",
            # Purple Team Aliases
            "purple-01": "purple-01-purple-team-foundations",
            "purple-01-intro-emulation": "purple-01-purple-team-foundations",
            "purple-01-foundations": "purple-01-purple-team-foundations",
            "purple-02": "purple-02-mitre-attack-fundamentals",
            "purple-02-mitre-attck-mapping": "purple-02-mitre-attack-fundamentals",
            "purple-02-attack-fundamentals": "purple-02-mitre-attack-fundamentals",
            "purple-03": "purple-03-attack-simulation-planning",
            "purple-03-atomic-red-team": "purple-03-attack-simulation-planning",
            "purple-03-simulation-planning": "purple-03-attack-simulation-planning",
            "purple-04": "purple-04-reconnaissance-vs-monitoring",
            "purple-04-credential-access-emulation": "purple-04-reconnaissance-vs-monitoring",
            "purple-04-recon-monitoring": "purple-04-reconnaissance-vs-monitoring",
            "purple-05": "purple-05-privesc-emulation",
            "purple-05-privilege-escalation": "purple-05-privesc-emulation",
            "purple-05-privesc": "purple-05-privesc-emulation",
            "purple-06": "purple-06-defense-evasion-emulation",
            "purple-06-defense-evasion": "purple-06-defense-evasion-emulation",
            "purple-06-process-injection": "purple-06-defense-evasion-emulation",
            "purple-07": "purple-07-lateral-movement-emulation",
            "purple-07-lateral-movement": "purple-07-lateral-movement-emulation",
            "purple-07-lateral": "purple-07-lateral-movement-emulation",
            "purple-08": "purple-08-persistence-emulation",
            "purple-08-persistence": "purple-08-persistence-emulation",
            "purple-08-persistence-mechanisms": "purple-08-persistence-emulation",
            # Purple 09-12
            "purple-09": "purple-09-c2-framework-emulation",
            "purple-09-c2": "purple-09-c2-framework-emulation",
            "purple-09-c2-framework": "purple-09-c2-framework-emulation",
            "purple-10": "purple-10-exfiltration-emulation",
            "purple-10-exfil": "purple-10-exfiltration-emulation",
            "purple-10-exfiltration": "purple-10-exfiltration-emulation",
            "purple-11": "purple-11-ransomware-readiness",
            "purple-11-ransomware": "purple-11-ransomware-readiness",
            "purple-11-ransomware-emulation": "purple-11-ransomware-readiness",
            "purple-12": "purple-12-cloud-identity-emulation",
            "purple-12-cloud": "purple-12-cloud-identity-emulation",
            "purple-12-cloud-identity": "purple-12-cloud-identity-emulation",
            "purple-12-cloud-iam": "purple-12-cloud-identity-emulation",
            # Purple 13-16
            "purple-13": "purple-13-supply-chain-emulation",
            "purple-13-supply-chain": "purple-13-supply-chain-emulation",
            "purple-13-dependency-confusion": "purple-13-supply-chain-emulation",
            "purple-14": "purple-14-api-abuse-emulation",
            "purple-14-api-abuse": "purple-14-api-abuse-emulation",
            "purple-14-bola": "purple-14-api-abuse-emulation",
            "purple-15": "purple-15-active-directory-attacks-emulation",
            "purple-15-ad-attacks": "purple-15-active-directory-attacks-emulation",
            "purple-15-kerberoasting": "purple-15-active-directory-attacks-emulation",
            "purple-16": "purple-16-ci-cd-pipeline-emulation",
            "purple-16-cicd": "purple-16-ci-cd-pipeline-emulation",
            "purple-16-ci-cd": "purple-16-ci-cd-pipeline-emulation",
            # Purple 17-20
            "purple-17": "purple-17-edr-bypass-emulation",
            "purple-17-edr-telemetry-blinding-and-bypass-emulation": "purple-17-edr-bypass-emulation",
            "purple-17-edr-bypass": "purple-17-edr-bypass-emulation",
            "purple-17-edr": "purple-17-edr-bypass-emulation",
            "purple-17-defense-tuning": "purple-17-edr-bypass-emulation",
            "purple-18": "purple-18-ttp-heatmap-generation",
            "purple-18-ttp-heatmap-generation-and-coverage-scoring": "purple-18-ttp-heatmap-generation",
            "purple-18-heatmap": "purple-18-ttp-heatmap-generation",
            "purple-18-ttp-heatmap": "purple-18-ttp-heatmap-generation",
            "purple-18-gap-analysis": "purple-18-ttp-heatmap-generation",
            "purple-18-cloud-purple-teaming": "purple-18-ttp-heatmap-generation",
            "purple-19": "purple-19-continuous-security-validation",
            "purple-19-continuous-security-validation-and-automated-testing": "purple-19-continuous-security-validation",
            "purple-19-continuous-validation": "purple-19-continuous-security-validation",
            "purple-19-automated-testing": "purple-19-continuous-security-validation",
            "purple-19-metrics-that-matter": "purple-19-continuous-security-validation",
            "purple-20": "purple-20-capstone-purple-exercise",
            "purple-20-purple-team-capstone-full-adversary-emulation-exercise": "purple-20-capstone-purple-exercise",
            "purple-20-capstone": "purple-20-capstone-purple-exercise",
            "purple-20-purple-capstone": "purple-20-capstone-purple-exercise",
            "purple-20-capstone-adversary-exercise": "purple-20-capstone-purple-exercise",
            # Detection Engineering 01-04
            "detect-01": "detect-01-foundations-as-code",
            "detect-01-foundations": "detect-01-foundations-as-code",
            "detect-01-intro-detection-eng": "detect-01-foundations-as-code",
            "detect-01-detection-as-code": "detect-01-foundations-as-code",
            "detect-02": "detect-02-log-normalization",
            "detect-02-log-taxonomy": "detect-02-log-normalization",
            "detect-02-ecs-cim": "detect-02-log-normalization",
            "detect-02-sigma-rules-basics": "detect-02-log-normalization",
            "detect-03": "detect-03-sigma-syntax",
            "detect-03-sigma-rules": "detect-03-sigma-syntax",
            "detect-03-sigma-syntax-basics": "detect-03-sigma-syntax",
            "detect-03-yara-syntax-basics": "detect-03-sigma-syntax",
            "detect-04": "detect-04-process-creation-rules",
            "detect-04-windows-process-creation": "detect-04-process-creation-rules",
            "detect-04-sysmon-event-1": "detect-04-process-creation-rules",
            "detect-04-snort-suricata-basics": "detect-04-process-creation-rules",
            # Detection Engineering 05-08
            "detect-05": "detect-05-network-connection-rules",
            "detect-05-network": "detect-05-network-connection-rules",
            "detect-05-sysmon-event-3": "detect-05-network-connection-rules",
            "detect-05-network-connection": "detect-05-network-connection-rules",
            "detect-06": "detect-06-file-registry-rules",
            "detect-06-file-registry": "detect-06-file-registry-rules",
            "detect-06-fim": "detect-06-file-registry-rules",
            "detect-06-registry-persistence": "detect-06-file-registry-rules",
            "detect-07": "detect-07-auth-abuse-rules",
            "detect-07-auth-abuse": "detect-07-auth-abuse-rules",
            "detect-07-authentication": "detect-07-auth-abuse-rules",
            "detect-07-auth": "detect-07-auth-abuse-rules",
            "detect-08": "detect-08-powershell-obfuscation",
            "detect-08-powershell": "detect-08-powershell-obfuscation",
            "detect-08-powershell-cradles": "detect-08-powershell-obfuscation",
            "detect-08-obfuscation": "detect-08-powershell-obfuscation",
            # Detection Engineering 09-12
            "detect-09": "detect-09-web-detection-rules",
            "detect-09-web": "detect-09-web-detection-rules",
            "detect-09-sqli-xss-lfi": "detect-09-web-detection-rules",
            "detect-09-web-rules": "detect-09-web-detection-rules",
            "detect-10": "detect-10-modsec-crs-tuning",
            "detect-10-modsec": "detect-10-modsec-crs-tuning",
            "detect-10-waf": "detect-10-modsec-crs-tuning",
            "detect-10-crs": "detect-10-modsec-crs-tuning",
            "detect-11": "detect-11-wazuh-decoders-rules",
            "detect-11-wazuh": "detect-11-wazuh-decoders-rules",
            "detect-11-ossec": "detect-11-wazuh-decoders-rules",
            "detect-11-decoders": "detect-11-wazuh-decoders-rules",
            "detect-12": "detect-12-reducing-false-positives",
            "detect-12-false-positives": "detect-12-reducing-false-positives",
            "detect-12-tuning": "detect-12-reducing-false-positives",
            "detect-12-fpr": "detect-12-reducing-false-positives",
            # Detection Engineering 13-16
            "detect-13": "detect-13-threshold-detections",
            "detect-13-threshold": "detect-13-threshold-detections",
            "detect-13-baseline": "detect-13-threshold-detections",
            "detect-13-threshold-detections": "detect-13-threshold-detections",
            "detect-14": "detect-14-correlation-rules",
            "detect-14-correlation": "detect-14-correlation-rules",
            "detect-14-multi-event": "detect-14-correlation-rules",
            "detect-14-correlation-rules": "detect-14-correlation-rules",
            "detect-15": "detect-15-unit-testing-rules",
            "detect-15-unit-testing": "detect-15-unit-testing-rules",
            "detect-15-testing-rules": "detect-15-unit-testing-rules",
            "detect-15-detection-testing": "detect-15-unit-testing-rules",
            "detect-16": "detect-16-yara-hunting",
            "detect-16-yara": "detect-16-yara-hunting",
            "detect-16-yara-rules": "detect-16-yara-hunting",
            "detect-16-threat-hunting": "detect-16-yara-hunting",
            # Detection Engineering 17-20
            "detect-17": "detect-17-snort-suricata",
            "detect-17-snort": "detect-17-snort-suricata",
            "detect-17-suricata": "detect-17-snort-suricata",
            "detect-17-nids": "detect-17-snort-suricata",
            "detect-18": "detect-18-threat-hunting-hypothesis",
            "detect-18-threat-hunting": "detect-18-threat-hunting-hypothesis",
            "detect-18-hypothesis": "detect-18-threat-hunting-hypothesis",
            "detect-18-hunting": "detect-18-threat-hunting-hypothesis",
            "detect-19": "detect-19-ci-cd-detection-pipelines",
            "detect-19-cicd": "detect-19-ci-cd-detection-pipelines",
            "detect-19-ci-cd": "detect-19-ci-cd-detection-pipelines",
            "detect-19-pipeline": "detect-19-ci-cd-detection-pipelines",
            "detect-20": "detect-20-capstone-detection-pipeline",
            "detect-20-capstone": "detect-20-capstone-detection-pipeline",
            "detect-20-detection-capstone": "detect-20-capstone-detection-pipeline",
            "detect-20-production-pipeline": "detect-20-capstone-detection-pipeline",
        }
        mapped_id = aliases.get(room_id)
        if mapped_id and mapped_id in self._rooms:
            return self._rooms[mapped_id]

        # Dynamic prefix fallback (e.g. 'red-09' -> 'red-09-sql-injection')
        clean_id = room_id.strip().lower()
        for r_id, r_def in self._rooms.items():
            if r_id == clean_id or r_id.startswith(f"{clean_id}-"):
                return r_def
            # Support track-01 matching e.g. 'red-01' or 'detection-01'
            short_slug = f"{r_def.track.value}-{r_def.room_number:02d}"
            if short_slug == clean_id or (clean_id.startswith('detect-') and f"detection-{r_def.room_number:02d}" == clean_id.replace('detect-', 'detection-')):
                return r_def

        return None

    def list_rooms(self, track: Optional[TrackEnum] = None) -> List[RoomDefinition]:
        rooms = list(self._rooms.values())
        if track:
            rooms = [r for r in rooms if r.track == track]
        return sorted(rooms, key=lambda x: (x.track.value, x.room_number))

    def get_track_counts(self) -> Dict[str, Dict[str, int]]:
        tracks = {t.value: {"total": 0, "implemented": 0, "planned": 0} for t in TrackEnum}
        for r in self._rooms.values():
            key = r.track.value
            tracks[key]["total"] += 1
            if r.status == RoomStatus.IMPLEMENTED:
                tracks[key]["implemented"] += 1
            else:
                tracks[key]["planned"] += 1
        return tracks


curriculum_registry = CurriculumRegistry()
