"""
Complete curriculum definitions, tasks, concept explanations, and quizzes
for Red Team Rooms 05–08:
- Room 05: Network Scanning (red-05-network-scanning)
- Room 06: Service Enumeration (red-06-service-enumeration)
- Room 07: Vulnerability Assessment (red-07-vulnerability-assessment)
- Room 08: Web Application Fundamentals (red-08-web-application-fundamentals)
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
# ROOM 05: NETWORK SCANNING (FULLY IMPLEMENTED)
# ============================================================================

ROOM_05_CONCEPT = RoomConcept(
    overview=(
        "Network scanning is the active interrogation of target IP addresses and transport ports "
        "to discover live hosts, map open network services, and assess firewall filtering boundaries."
    ),
    simple_analogy=(
        "Think of an investigator walking down an office hallway testing door handles. If a door handle turns "
        "and opens immediately, the room is 'open'. If the door is locked with an active deadbolt and someone "
        "shouts 'Closed!', it is 'closed'. If the hallway has a security checkpoint that drops your request or refuses "
        "to respond, the door is 'filtered'. A port scan systematically checks these numbered doors across an IP address."
    ),
    technical_term="Port Scanning & Transport Layer State Probing (RFC 793 / Nmap TCP Scans)",
    technical_definition=(
        "Network scanning sends structured TCP or UDP probe packets to determine port states: "
        "Open (host responds with SYN-ACK, ready to establish full connection), "
        "Closed (host responds with RST-ACK, port is listening to nothing), or "
        "Filtered (firewall packet drop or ICMP destination unreachable, no response received). "
        "TCP SYN scanning (-sS) performs a half-open probe without completing the 3-way handshake, "
        "while TCP Connect scanning (-sT) completes the full handshake using standard OS system calls."
    ),
    cybersecurity_context=(
        "Offensive operators use network scanners like Nmap to map active attack surfaces within authorized "
        "Rules of Engagement (RoE). Defensive engineers use automated scanning tools and network intrusion detection "
        "systems (NIDS) to detect unauthorized port sweeps and verify firewall ingress policies."
    ),
    why_it_matters=(
        "Unnecessary open ports expand an organization's attack surface and expose internal services to exploitation. "
        "Regular scanning ensures only strictly required services are reachable through network perimeters."
    ),
    demonstration=(
        "Nmap TCP Port Scan Example:\n"
        "  $ nmap -sT -p 8080,8085,9001 10.10.14.90\n"
        "  PORT     STATE SERVICE\n"
        "  8080/tcp open  http\n"
        "  8085/tcp open  http\n"
        "  9001/tcp open  unknown\n"
    ),
    remediation_guide=(
        "Close unnecessary network ports, bind internal services to loopback (127.0.0.1), configure stateful "
        "firewalls (iptables/nftables) with default-deny ingress policies, and implement rate-limiting or port-scan detection."
    ),
)

ROOM_05_TASKS = [
    TaskDefinition(
        task_id="task-01-port-states",
        order=1,
        title="Understanding Port States: Open, Closed, Filtered",
        instructions=(
            "In TCP networking, an operating system responds differently depending on whether a service is actively listening. "
            "When a port receives a TCP SYN packet on an unused port with no listening service, it replies with a TCP Reset (RST) packet. "
            "Which standard port state does Nmap assign to a port that actively resets connection attempts?"
        ),
        task_type=TaskType.QUESTION,
        question="Which standard port state is assigned when the target actively resets the connection?",
        hint="The target actively acknowledges the packet but indicates no service is running (opposite of open).",
        xp_reward=50,
        accepted_answers=["closed", "Closed"],
        mistake_explanations={
            "filtered": "Filtered means the packet was dropped by a firewall without response or blocked by an ICMP rule. An active RST response confirms the port is closed.",
            "open": "Open means the port responded with SYN-ACK and is actively listening.",
        },
    ),
    TaskDefinition(
        task_id="task-02-host-discovery",
        order=2,
        title="Host Discovery on the Internal Subnet",
        instructions=(
            "Run an Nmap ping sweep or host discovery scan (`nmap -sn 10.10.14.0/24`) inside your attacker container. "
            "Identify the reachable target host IP address on the internal lab network."
        ),
        task_type=TaskType.QUESTION,
        question="Submit the IP address of the target host discovered on the 10.10.14.0/24 subnet.",
        hint="Look for the target host configured at 10.10.14.X.",
        xp_reward=50,
        accepted_answers=["10.10.14.90"],
        mistake_explanations={
            "10.10.14.2": "10.10.14.2 is your own workstation container's IP address. Identify the target server IP.",
            "127.0.0.1": "127.0.0.1 is loopback. Discover the target host on the internal 10.10.14.0/24 subnet.",
        },
    ),
    TaskDefinition(
        task_id="task-03-tcp-scan-sweep",
        order=3,
        title="TCP Port Scanning & Discovery",
        instructions=(
            "Perform a TCP port scan against target `10.10.14.90` using `nmap -sT -p- 10.10.14.90` or `nmap -sT -p 1-10000 10.10.14.90`. "
            "Which high port above 9000 is open and actively accepting TCP connections?"
        ),
        task_type=TaskType.QUESTION,
        question="Submit the open port number above 9000 discovered on the target.",
        hint="Scan the port range up to 10000. Look for a socket service listening above 9000.",
        xp_reward=50,
        accepted_answers=["9001"],
        mistake_explanations={
            "8080": "8080 is an open HTTP port, but we are looking for the high port above 9000.",
            "8089": "8089 is open, but we are looking for the high port above 9000.",
        },
    ),
    TaskDefinition(
        task_id="task-04-http-scanning-service",
        order=4,
        title="Interrogating Discovered Port 8085",
        instructions=(
            "Your port scan revealed an active HTTP service on port 8085 (`http://10.10.14.90:8085/scan-status`). "
            "Query this endpoint using `curl -s http://10.10.14.90:8085/scan-status` and submit the port discovery flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the port discovery flag returned by port 8085.",
        hint="Run `curl -s http://10.10.14.90:8085/scan-status` in the operator terminal.",
        xp_reward=60,
        accepted_answers=["NOENTRY{nmap_port_discovery_open_4812}"],
        accepted_regex=r"^NOENTRY\{nmap_port_discovery_open_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-05-challenge",
        order=5,
        title="Independent Challenge: Full Range Port Sweep",
        instructions=(
            "Interrogate the network scanning challenge endpoint on port 8085: `http://10.10.14.90:8085/challenge`. "
            "Submit the scanning challenge completion flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the scanning challenge completion flag.",
        hint="Run `curl -s http://10.10.14.90:8085/challenge`.",
        xp_reward=70,
        accepted_answers=["NOENTRY{net_scan_stealth_recon_7731}"],
        accepted_regex=r"^NOENTRY\{net_scan_stealth_recon_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-06-quiz",
        order=6,
        title="Network Scanning Knowledge Assessment",
        instructions="Complete the 5-question quiz to test your conceptual understanding of port scanning and network reconnaissance.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question assessment quiz on network scanning.",
        hint="Review TCP 3-way handshake states, Nmap flags, and scanning scope.",
        xp_reward=70,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is the primary difference between a TCP SYN scan (-sS) and a TCP Connect scan (-sT)?",
                options=[
                    "A SYN scan does not complete the 3-way handshake, making it less likely to be logged by simple applications",
                    "A Connect scan can only scan UDP ports",
                    "A SYN scan requires administrator/root privileges on Windows only",
                    "A Connect scan sends ICMP echo packets instead of TCP",
                ],
                correct_option_index=0,
                explanation="TCP SYN scanning (-sS) sends a SYN packet and awaits a SYN-ACK, then immediately tears down the connection with RST without completing the 3-way handshake.",
            ),
            QuizQuestion(
                id="q2",
                question="If an Nmap scan reports a port state as 'filtered', what does this indicate?",
                options=[
                    "A firewall or packet filter dropped the probe or returned ICMP unreachable, preventing Nmap from determining if the port is open or closed",
                    "The port is definitely closed and has sent a TCP RST packet",
                    "The port is running an encrypted SSL/TLS tunnel",
                    "The service on the port crashed during the scan",
                ],
                correct_option_index=0,
                explanation="A 'filtered' state means probe packets reached a network boundary device (firewall or filter) that dropped them without response.",
            ),
            QuizQuestion(
                id="q3",
                question="Which Nmap timing template flag provides aggressive, faster scanning without being completely unstable?",
                options=[
                    "-T4",
                    "-T0",
                    "-T1",
                    "-sS",
                ],
                correct_option_index=0,
                explanation="-T4 sets aggressive timing suitable for modern broadband and local lab networks, reducing timeouts and parallelizing probes.",
            ),
            QuizQuestion(
                id="q4",
                question="Why must active port scanning always remain strictly within authorized engagement scope?",
                options=[
                    "Active scanning constitutes unauthorized interrogation of an information system and can destabilize legacy services or trigger legal penalties",
                    "Scanning automatically changes user passwords on the target system",
                    "Port scans immediately format the target server's hard drive",
                    "Scanning reveals the operator's private encryption keys to the target",
                ],
                correct_option_index=0,
                explanation="Scanning without authorization is illegal under computer misuse legislation. Active probes can also overwhelm fragile industrial or embedded equipment.",
            ),
            QuizQuestion(
                id="q5",
                question="Which flag tells Nmap to scan all 65,535 TCP ports instead of just the top 1,000 default ports?",
                options=[
                    "-p-",
                    "-A",
                    "-sV",
                    "-F",
                ],
                correct_option_index=0,
                explanation="-p- is shorthand for -p 1-65535, scanning every possible TCP transport port.",
            ),
        ],
    ),
]

ROOM_05_DEFINITION = RoomDefinition(
    room_id="red-05-network-scanning",
    track=TrackEnum.RED,
    room_number=5,
    title="Network Scanning",
    short_description="Master host discovery, TCP connection & SYN scanning, open/closed/filtered port states, and scanning ethics.",
    difficulty="Beginner",
    estimated_duration="45 min",
    prerequisites=["Cybersecurity Foundations", "Networking Fundamentals"],
    required_skills=["Nmap port scanning", "Host discovery", "Port state triage"],
    lab_type="container_isolated",
    concept=ROOM_05_CONCEPT,
    tasks=ROOM_05_TASKS,
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Perform host discovery across internal subnets using Nmap",
        "Differentiate between open, closed, and filtered port states",
        "Execute TCP port scans to identify listening services",
        "Understand authorized scope and scan timing considerations",
    ],
    assessment_criteria=[
        "Identify the closed port RST response mechanism",
        "Discover the target host IP address on the subnet",
        "Identify the open high-port TCP service",
        "Retrieve the port discovery flag from port 8085",
        "Pass the 5-question network scanning assessment quiz",
    ],
    completion_requirements=["Complete all 6 tasks with 100% accuracy"],
    total_xp=350,
)

# ============================================================================
# ROOM 06: SERVICE ENUMERATION (FULLY IMPLEMENTED)
# ============================================================================

ROOM_06_CONCEPT = RoomConcept(
    overview=(
        "Service enumeration is the detailed inspection of discovered network ports to identify "
        "running application software, specific version numbers, operating system banners, and exposed administrative endpoints."
    ),
    simple_analogy=(
        "If port scanning is finding out that a door is unlocked, service enumeration is peeking inside the room "
        "to see what furniture, computers, and documents are sitting on the desk. You read the labels on the machines "
        "and inspect the badge reader to see exactly what technology is in use."
    ),
    technical_term="Service Version Fingerprinting & Protocol Banner Grabbing",
    technical_definition=(
        "During service enumeration, client probes initiate protocol-specific handshakes (FTP, SSH, HTTP, SMTP) "
        "to elicit service banners, version strings, and capabilities. For instance, connecting to an SSH port elicits "
        "the protocol version string (SSH-2.0-OpenSSH_8.4p1). On HTTP services, web enumeration inspects headers "
        "(Server, X-Powered-By, custom API headers), default paths, and API schemas."
    ),
    cybersecurity_context=(
        "Attackers use service enumeration to find exact software versions with known public exploits (CVEs). "
        "Defenders perform regular enumeration audits to maintain an accurate software bill of materials (SBOM) "
        "and eliminate software running beyond end-of-life (EOL)."
    ),
    why_it_matters=(
        "Knowing that port 21 is open tells you FTP is running; knowing that the version is 'VoltCorp FTP v1.4.2' "
        "tells you the exact feature set and whether known vulnerabilities exist. Version enumeration is the bridge between scanning and exploitation."
    ),
    demonstration=(
        "Grabbing an FTP banner using Netcat:\n"
        "  $ nc 10.10.14.90 2121\n"
        "  220-VoltCorp Embedded Secure FTP Server v1.4.2 ready.\n"
        "  220 Flag: NOENTRY{ftp_banner_service_enumeration_5921}\n"
    ),
    remediation_guide=(
        "Disable verbose banner broadcasting in configuration files (e.g. ServerTokens Prod in Apache, server_tokens off; in Nginx), "
        "remove unnecessary default endpoints, and update services to supported vendor patches."
    ),
)

ROOM_06_TASKS = [
    TaskDefinition(
        task_id="task-01-scanning-vs-enumeration",
        order=1,
        title="Scanning vs Enumeration",
        instructions=(
            "Understand the methodology difference: Port scanning identifies which transport port numbers are open. "
            "What does service enumeration determine about those open ports?"
        ),
        task_type=TaskType.QUESTION,
        question="What core detail does service enumeration identify beyond port open/closed state?",
        hint="Enumeration identifies the specific applications and software versions running on open ports.",
        xp_reward=50,
        accepted_answers=["services", "service versions", "software versions", "versions", "version"],
        mistake_explanations={
            "ip address": "The IP address was already discovered during host discovery. Enumeration discovers the specific software services and versions running on open ports.",
        },
    ),
    TaskDefinition(
        task_id="task-02-ftp-banner",
        order=2,
        title="FTP Banner Grabbing via Netcat",
        instructions=(
            "A legacy FTP service is listening on port 2121 on target host `10.10.14.90`. "
            "Connect to it using Netcat (`nc 10.10.14.90 2121`) and extract the embedded security flag from the welcome banner."
        ),
        task_type=TaskType.FLAG,
        question="Submit the FTP banner enumeration flag.",
        hint="Run `nc 10.10.14.90 2121` in your operator terminal.",
        xp_reward=50,
        accepted_answers=["NOENTRY{ftp_banner_service_enumeration_5921}"],
        accepted_regex=r"^NOENTRY\{ftp_banner_service_enumeration_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-03-ssh-banner",
        order=3,
        title="SSH Protocol Version Exchange",
        instructions=(
            "Connect to the SSH banner service listening on port 2222 (`nc 10.10.14.90 2222`). "
            "Read the protocol version exchange string and submit the base software version identifier (e.g. OpenSSH_8.4p1)."
        ),
        task_type=TaskType.QUESTION,
        question="Submit the OpenSSH version string reported by port 2222.",
        hint="Look for the software version string following 'SSH-2.0-'.",
        xp_reward=50,
        accepted_answers=["OpenSSH_8.4p1", "OpenSSH 8.4p1", "OpenSSH_8.4p1-VoltCorp_Secure_Gateway_v2"],
        mistake_explanations={
            "ssh-2.0": "SSH-2.0 indicates the protocol version, not the software package identifier. Submit the software version (OpenSSH_8.4p1).",
        },
    ),
    TaskDefinition(
        task_id="task-04-http-headers",
        order=4,
        title="HTTP Service Header Enumeration",
        instructions=(
            "Inspect the HTTP response headers on port 8086 using `curl -I -s http://10.10.14.90:8086/`. "
            "Submit the value of the custom `X-Service-Catalog` header."
        ),
        task_type=TaskType.QUESTION,
        question="Submit the value of the X-Service-Catalog header.",
        hint="Look for the header beginning with 'X-Service-Catalog: '.",
        xp_reward=60,
        accepted_answers=["VoltCore-Enum-v3.1", "VoltCorp-Enum-v3.1"],
    ),
    TaskDefinition(
        task_id="task-05-challenge",
        order=5,
        title="Independent Challenge: Service Catalog Enumeration",
        instructions=(
            "Enumerate the internal administrative endpoint discovered in the service API: `http://10.10.14.90:8086/admin-internal/`. "
            "Submit the enumeration completion flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the administrative service catalog enumeration flag.",
        hint="Run `curl -s http://10.10.14.90:8086/admin-internal/`.",
        xp_reward=70,
        accepted_answers=["NOENTRY{service_enumeration_master_3389}"],
        accepted_regex=r"^NOENTRY\{service_enumeration_master_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-06-quiz",
        order=6,
        title="Service Enumeration Knowledge Assessment",
        instructions="Complete the 5-question quiz to test your conceptual understanding of service enumeration and banner analysis.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question assessment quiz on service enumeration.",
        hint="Review banner grabbing, Nmap version detection flags, and service exposure risks.",
        xp_reward=70,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is service version enumeration considered a critical precursor to exploitation?",
                options=[
                    "Knowing the exact software package and version allows an analyst to look up matching vulnerabilities and proof-of-concept exploits",
                    "Version enumeration decrypts target user passwords automatically",
                    "It bypasses network-level firewalls completely",
                    "It changes file permissions on the target server",
                ],
                correct_option_index=0,
                explanation="Exploits target specific flaws in specific software builds. Knowing the exact version eliminates guesswork and enables targeted exploit selection.",
            ),
            QuizQuestion(
                id="q2",
                question="Which Nmap flag performs automated service version detection across probed ports?",
                options=[
                    "-sV",
                    "-sn",
                    "-O",
                    "-Pn",
                ],
                correct_option_index=0,
                explanation="-sV instructs Nmap to interrogate open ports using protocol-specific probes from its nmap-service-probes database.",
            ),
            QuizQuestion(
                id="q3",
                question="What security risk is introduced when a web server returns detailed software stack versions in its Server header?",
                options=[
                    "It accelerates adversary reconnaissance by revealing outdated software without requiring active fuzzing",
                    "It causes the web server to run out of memory",
                    "It allows clients to connect without TCP handshakes",
                    "It exposes the physical geolocation of the datacenter",
                ],
                correct_option_index=0,
                explanation="Verbose banners reveal exact versions, letting adversaries cross-reference public CVE databases and find matching exploits effortlessly.",
            ),
            QuizQuestion(
                id="q4",
                question="What standard port does unencrypted File Transfer Protocol (FTP) command control use by default?",
                options=[
                    "21",
                    "22",
                    "25",
                    "80",
                ],
                correct_option_index=0,
                explanation="Standard unencrypted FTP control traffic listens on TCP port 21 (with data transfer occurring on port 20 in active mode).",
            ),
            QuizQuestion(
                id="q5",
                question="How can organizations prevent unauthorized service enumeration of internal management interfaces?",
                options=[
                    "Restrict management interfaces to dedicated VPN/VLAN segments and configure services to suppress verbose version banners",
                    "Use random port numbers only, without firewalls",
                    "Disable passwords on administrative interfaces",
                    "Run all services on UDP instead of TCP",
                ],
                correct_option_index=0,
                explanation="Defense-in-depth requires network segmentation (placing management ports off public view) and banner suppression (suppressing version disclosure).",
            ),
        ],
    ),
]

ROOM_06_DEFINITION = RoomDefinition(
    room_id="red-06-service-enumeration",
    track=TrackEnum.RED,
    room_number=6,
    title="Service Enumeration",
    short_description="Differentiate scanning from enumeration, extract protocol banners from FTP/SSH, inspect HTTP headers, and discover hidden endpoints.",
    difficulty="Beginner",
    estimated_duration="45 min",
    prerequisites=["Networking Fundamentals", "Network Scanning"],
    required_skills=["Service banner grabbing", "HTTP header enumeration", "Protocol version exchange analysis"],
    lab_type="container_isolated",
    concept=ROOM_06_CONCEPT,
    tasks=ROOM_06_TASKS,
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Distinguish between port scanning and deep service enumeration",
        "Extract raw service banners using Netcat across FTP and SSH",
        "Inspect HTTP response headers for version disclosure",
        "Enumerate administrative service catalog APIs",
    ],
    assessment_criteria=[
        "Identify the primary objective of service enumeration",
        "Extract the embedded security flag from the FTP service banner",
        "Identify the OpenSSH software version string",
        "Capture the administrative service catalog flag",
        "Pass the 5-question service enumeration assessment quiz",
    ],
    completion_requirements=["Complete all 6 tasks with 100% accuracy"],
    total_xp=350,
)

# ============================================================================
# ROOM 07: VULNERABILITY ASSESSMENT (FULLY IMPLEMENTED)
# ============================================================================

ROOM_07_CONCEPT = RoomConcept(
    overview=(
        "Vulnerability assessment is the systematic identification, quantification, and prioritization "
        "of security vulnerabilities in digital assets, applications, and network infrastructure."
    ),
    simple_analogy=(
        "Think of an annual vehicle safety inspection. The mechanic checks brake pad thickness, tire tread depth, "
        "and taillight functionality against legal safety standards. The mechanic documents existing defects and assigns "
        "a severity rating (e.g. worn brakes = immediate critical danger, burnt license plate bulb = low priority fix). "
        "A vulnerability assessment is a vehicle safety inspection for computer systems."
    ),
    technical_term="CVE Identification, CVSS Scoring & Remediation Verification",
    technical_definition=(
        "Vulnerabilities are cataloged using Common Vulnerabilities and Exposures (CVE) identifiers (e.g., CVE-2024-2104). "
        "The Common Vulnerability Scoring System (CVSS) provides an open framework for communicating characteristics and severity "
        "(Base Score from 0.0 to 10.0: None 0.0, Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0–10.0). "
        "A vulnerability assessment differs from a penetration test because it focuses on complete inventory coverage "
        "and remediation guidance rather than achieving deep exploitation."
    ),
    cybersecurity_context=(
        "Security teams run vulnerability scanners (e.g. Nessus, OpenVAS, Trivy) to establish baseline security health, "
        "track Mean Time to Remediate (MTTR), and satisfy compliance frameworks (PCI-DSS, ISO 27001). "
        "Security analysts verify findings to eliminate false positives and coordinate patching with systems engineers."
    ),
    why_it_matters=(
        "Organizations cannot defend what they do not know they have. Prioritizing remediation by CVSS score ensures "
        "limited engineering resources fix critical, internet-facing vulnerabilities before adversaries exploit them."
    ),
    demonstration=(
        "Component inventory check:\n"
        "  $ curl -s http://10.10.14.90:8087/api/components\n"
        "  [{\"name\": \"VoltCore HTTP Engine\", \"version\": \"2.14.0-legacy\", \"status\": \"VULNERABLE\"}]\n"
        "Lookup in local vulnerability database:\n"
        "  $ cat /home/operator/vuln_db/cve_catalog.json\n"
    ),
    remediation_guide=(
        "Establish a regular patch management schedule, prioritize Critical and High CVSS vulnerabilities, "
        "apply vendor updates, test patches in staging environments, and re-scan post-deployment to verify fix efficacy."
    ),
)

ROOM_07_TASKS = [
    TaskDefinition(
        task_id="task-01-cve-definition",
        order=1,
        title="The Common Vulnerabilities and Exposures (CVE) System",
        instructions=(
            "Review the global standardized dictionary of publicly known cybersecurity vulnerabilities. "
            "What is the standard 3-letter acronym used worldwide to identify unique vulnerability entries (such as CVE-2024-2104)?"
        ),
        task_type=TaskType.QUESTION,
        question="Submit the standard 3-letter acronym for public vulnerability identifiers.",
        hint="Common Vulnerabilities and Exposures.",
        xp_reward=50,
        accepted_answers=["CVE", "cve"],
        mistake_explanations={
            "cvss": "CVSS stands for Common Vulnerability Scoring System, which calculates numerical severity scores. The dictionary identifier acronym is CVE.",
        },
    ),
    TaskDefinition(
        task_id="task-02-component-inventory",
        order=2,
        title="Inspecting Target Software Inventory",
        instructions=(
            "Query the target component inventory endpoint on port 8087 (`curl -s http://10.10.14.90:8087/api/components`). "
            "Identify the legacy version of `VoltCore HTTP Engine` currently installed on the host."
        ),
        task_type=TaskType.QUESTION,
        question="Submit the version string of the legacy VoltCore HTTP Engine.",
        hint="Run `curl -s http://10.10.14.90:8087/api/components` in your terminal.",
        xp_reward=50,
        accepted_answers=["2.14.0-legacy", "2.14.0"],
    ),
    TaskDefinition(
        task_id="task-03-cvss-lookup",
        order=3,
        title="CVSS Severity Scoring & Impact",
        instructions=(
            "Examine the local vulnerability catalog on your workstation: `/home/operator/vuln_db/cve_catalog.json` "
            "(or run `python3 /home/operator/tools/vuln_audit.py`). What is the CVSS base score assigned to the critical authentication bypass `CVE-2024-2104`?"
        ),
        task_type=TaskType.QUESTION,
        question="Submit the CVSS score for CVE-2024-2104.",
        hint="Read `/home/operator/vuln_db/cve_catalog.json` and look for the cvss score of CVE-2024-2104.",
        xp_reward=50,
        accepted_answers=["9.8", "9.80"],
        mistake_explanations={
            "8.6": "8.6 is the CVSS score for CVE-2023-9182 (HIGH severity path traversal). Check the score for the critical authentication flaw CVE-2024-2104.",
        },
    ),
    TaskDefinition(
        task_id="task-04-audit-report",
        order=4,
        title="Vulnerability Assessment Finding Report",
        instructions=(
            "Request the official vulnerability assessment findings report from the target system: "
            "`curl -s http://10.10.14.90:8087/audit/report`. Submit the assessment confirmation flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the vulnerability assessment confirmation flag.",
        hint="Run `curl -s http://10.10.14.90:8087/audit/report` in the operator terminal.",
        xp_reward=60,
        accepted_answers=["NOENTRY{cve_vulnerability_assessment_master_8192}"],
        accepted_regex=r"^NOENTRY\{cve_vulnerability_assessment_master_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-05-challenge",
        order=5,
        title="Independent Challenge: Remediation & Patch Verification",
        instructions=(
            "Remediate the critical flaw by dispatching an automated patch application request to `http://10.10.14.90:8087/audit/remediate` "
            "using: `curl -s -X POST http://10.10.14.90:8087/audit/remediate -d 'action=apply_patch&cve=CVE-2024-2104'`. "
            "Submit the remediation verification flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the remediation verification flag.",
        hint="Post the remediation parameters to the /audit/remediate endpoint.",
        xp_reward=70,
        accepted_answers=["NOENTRY{vuln_assessment_remediation_verified_9410}"],
        accepted_regex=r"^NOENTRY\{vuln_assessment_remediation_verified_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-06-quiz",
        order=6,
        title="Vulnerability Assessment Knowledge Assessment",
        instructions="Complete the 5-question quiz to test your conceptual understanding of vulnerability assessment and CVSS metrics.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question assessment quiz on vulnerability assessment.",
        hint="Review vulnerability vs exploit, CVSS severity ranges, and false positive management.",
        xp_reward=70,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is the key distinction between a vulnerability and an exploit?",
                options=[
                    "A vulnerability is a flaw or weakness in code or configuration, while an exploit is software or a technique specifically written to take advantage of that flaw",
                    "A vulnerability is hardware-only, while an exploit is software-only",
                    "An exploit is always defensive, while a vulnerability is always offensive",
                    "There is no difference; the terms are interchangeable",
                ],
                correct_option_index=0,
                explanation="Vulnerability = the weakness or flaw. Exploit = the tool, script, or payload that weaponizes the vulnerability.",
            ),
            QuizQuestion(
                id="q2",
                question="In the CVSS v3 scoring standard, which score range qualifies a vulnerability as 'CRITICAL'?",
                options=[
                    "9.0 to 10.0",
                    "7.0 to 8.9",
                    "4.0 to 6.9",
                    "0.1 to 3.9",
                ],
                correct_option_index=0,
                explanation="CVSS Base Scores 9.0–10.0 represent Critical severity vulnerabilities that typically allow unauthenticated remote code execution or full system takeover.",
            ),
            QuizQuestion(
                id="q3",
                question="What is a 'false positive' in the context of vulnerability scanning?",
                options=[
                    "When a scanner reports a vulnerability that does not actually exist or cannot be exploited in the target's specific configuration",
                    "When a scanner fails to discover a real critical vulnerability",
                    "When an attacker successfully hacks a honeypot",
                    "When a patch breaks application functionality",
                ],
                correct_option_index=0,
                explanation="A false positive occurs when an automated scanner flags a component based on banner version without accounting for backported patches or disabled vulnerable modules.",
            ),
            QuizQuestion(
                id="q4",
                question="Why is post-remediation verification a mandatory step in the vulnerability management lifecycle?",
                options=[
                    "To mathematically verify that the deployed patch was applied correctly and the system is no longer susceptible to the flaw",
                    "To generate billing invoices for the client",
                    "To delete the vulnerability database records permanently",
                    "To enable debug mode on the production server",
                ],
                correct_option_index=0,
                explanation="Deploying a patch does not guarantee success; services may fail to restart or configuration files may override fixes. Verification confirms the attack vector is closed.",
            ),
            QuizQuestion(
                id="q5",
                question="Which factor should take highest priority when scheduling emergency vulnerability remediation?",
                options=[
                    "High CVSS severity combined with exposure on an internet-facing asset and active exploitation in the wild",
                    "The alphabetical order of the vendor name",
                    "Whether the software has a graphical user interface",
                    "The number of lines of code in the patch",
                ],
                correct_option_index=0,
                explanation="Threat exposure, internet reachability, and real-world weaponization dictate operational risk far more than theoretical CVSS scores alone.",
            ),
        ],
    ),
]

ROOM_07_DEFINITION = RoomDefinition(
    room_id="red-07-vulnerability-assessment",
    track=TrackEnum.RED,
    room_number=7,
    title="Vulnerability Assessment",
    short_description="Master CVE identifiers, CVSS severity metrics, component auditing, vulnerability prioritization, and patch verification.",
    difficulty="Beginner",
    estimated_duration="45 min",
    prerequisites=["Service Enumeration", "Linux for Hackers"],
    required_skills=["CVE lookup", "CVSS scoring evaluation", "Patch remediation verification"],
    lab_type="container_isolated",
    concept=ROOM_07_CONCEPT,
    tasks=ROOM_07_TASKS,
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Understand the purpose and structure of CVE identifiers",
        "Evaluate vulnerability severity using CVSS metrics",
        "Audit running software components against local vulnerability databases",
        "Verify successful patch remediation against vulnerable targets",
    ],
    assessment_criteria=[
        "Identify the CVE standard acronym",
        "Discover vulnerable legacy component versions on the target",
        "Look up CVSS scores from the local reference vulnerability catalog",
        "Capture the vulnerability report confirmation flag",
        "Pass the 5-question vulnerability assessment quiz",
    ],
    completion_requirements=["Complete all 6 tasks with 100% accuracy"],
    total_xp=350,
)

# ============================================================================
# ROOM 08: WEB APPLICATION FUNDAMENTALS (FULLY IMPLEMENTED)
# ============================================================================

ROOM_08_CONCEPT = RoomConcept(
    overview=(
        "Web applications are client-server software architectures where users interact with remote "
        "application logic and databases over the Hypertext Transfer Protocol (HTTP/HTTPS)."
    ),
    simple_analogy=(
        "Think of dining at a restaurant. You (the client) review the menu and give an order (HTTP request) "
        "to the waiter (HTTP transport). The waiter carries the ticket to the kitchen (the backend application server). "
        "The chef prepares the meal by pulling ingredients from the pantry (the database). The waiter brings your plate "
        "back to your table (the HTTP response). If you ask for an item not on the menu, the waiter returns an error (404 Not Found). "
        "If you try to walk into the VIP lounge without a reservation ticket, you get turned away (401 Unauthorized)."
    ),
    technical_term="The HTTP Request-Response Lifecycle, Methods & Session State",
    technical_definition=(
        "HTTP is a stateless request-response protocol at Layer 7. A client request contains a Method "
        "(GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS), a Uniform Resource Identifier (URI), HTTP version, "
        "Headers (Host, User-Agent, Cookie, Content-Type), and an optional Body. A server response returns a Status Code "
        "(1xx informational, 2xx success, 3xx redirection, 4xx client error, 5xx server error), Response Headers "
        "(Set-Cookie, Content-Type), and an optional Body. Because HTTP is stateless, session continuity is maintained "
        "using browser cookies (Cookie: session_id=...) or bearer tokens (Authorization: Bearer ...)."
    ),
    cybersecurity_context=(
        "Offensive web application testing explores input fields, parameter tampering, cookie manipulation, and HTTP verb tampering. "
        "Defenders secure web applications using input validation, parameterized queries, CSRF tokens, secure cookie attributes "
        "(HttpOnly, Secure, SameSite), and Web Application Firewalls (WAF)."
    ),
    why_it_matters=(
        "Web applications handle sensitive user data, financial transactions, and authentication credentials. "
        "Understanding core HTTP mechanics is the essential foundation for mastering web attacks like SQL Injection, "
        "Cross-Site Scripting (XSS), and Cross-Site Request Forgery (CSRF)."
    ),
    demonstration=(
        "Authenticate and receive a session cookie:\n"
        "  $ curl -s -X POST http://10.10.14.90:8088/api/auth/login -d \"username=operator&password=voltpass123\"\n"
        "Access profile using session cookie:\n"
        "  $ curl -s -b \"session_id=op_sess_88291a\" http://10.10.14.90:8088/api/profile\n"
    ),
    remediation_guide=(
        "Always enforce server-side authentication checks on protected endpoints, set HttpOnly and Secure flags on session cookies, "
        "validate HTTP methods strictly, and implement proper role-based access control (RBAC)."
    ),
)

ROOM_08_TASKS = [
    TaskDefinition(
        task_id="task-01-http-methods",
        order=1,
        title="HTTP Methods: RESTful Verbs",
        instructions=(
            "HTTP defines distinct methods for resource interactions. GET retrieves data, POST creates resources, "
            "and DELETE removes resources. Which standard HTTP method is specifically intended to update or completely replace an existing resource?"
        ),
        task_type=TaskType.QUESTION,
        question="Which standard HTTP method updates or replaces an existing resource?",
        hint="A 3-letter uppercase HTTP verb beginning with P (idempotent resource replacement).",
        xp_reward=50,
        accepted_answers=["PUT", "put"],
        mistake_explanations={
            "post": "POST is primarily used to submit data or create new resources. PUT is the standard idempotent method for updating or replacing an existing resource.",
        },
    ),
    TaskDefinition(
        task_id="task-02-status-codes",
        order=2,
        title="HTTP Status Code Investigation",
        instructions=(
            "Issue a request using an unpermitted HTTP method against `/api/profile` (for example, `curl -s -i -X DELETE http://10.10.14.90:8088/api/profile`). "
            "What 3-digit HTTP status code is returned when a requested HTTP method is disallowed by the server?"
        ),
        task_type=TaskType.QUESTION,
        question="Submit the 3-digit status code for Method Not Allowed.",
        hint="Method Not Allowed is in the 4xx client error range (405).",
        xp_reward=50,
        accepted_answers=["405"],
        mistake_explanations={
            "404": "404 means Not Found. When an endpoint exists but the requested HTTP verb/method is disallowed, the server returns 405 Method Not Allowed.",
            "403": "403 means Forbidden (permissions issue). Disallowed methods return 405.",
        },
    ),
    TaskDefinition(
        task_id="task-03-session-authentication",
        order=3,
        title="Session Authentication & Token Issuance",
        instructions=(
            "Authenticate to the web API using credentials `operator` / `voltpass123`: "
            "`curl -s -X POST http://10.10.14.90:8088/api/auth/login -d 'username=operator&password=voltpass123'`. "
            "What is the value of the `session_token` returned by the server?"
        ),
        task_type=TaskType.QUESTION,
        question="Submit the session token returned upon successful login.",
        hint="Check the JSON response for the session_token field.",
        xp_reward=50,
        accepted_answers=["op_sess_88291a"],
    ),
    TaskDefinition(
        task_id="task-04-cookie-authorization",
        order=4,
        title="Accessing Protected Endpoints via Cookies",
        instructions=(
            "Query the protected profile endpoint by supplying the session cookie using curl's `-b` flag: "
            "`curl -s -b 'session_id=op_sess_88291a' http://10.10.14.90:8088/api/profile`. "
            "Submit the authorized profile flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the authorized session profile flag.",
        hint="Run `curl -s -b 'session_id=op_sess_88291a' http://10.10.14.90:8088/api/profile`.",
        xp_reward=60,
        accepted_answers=["NOENTRY{web_session_cookie_auth_2841}"],
        accepted_regex=r"^NOENTRY\{web_session_cookie_auth_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-05-challenge",
        order=5,
        title="Independent Challenge: REST API Resource Modification (PUT)",
        instructions=(
            "Inspect item 42 on the store API and update its resource state by issuing an HTTP `PUT` request: "
            "`curl -s -X PUT http://10.10.14.90:8088/api/items/42 -H 'Content-Type: application/json' -d '{\"price\": 0.00}'`. "
            "Submit the PUT modification flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the HTTP PUT resource modification flag.",
        hint="Dispatch a PUT request to /api/items/42.",
        xp_reward=70,
        accepted_answers=["NOENTRY{web_http_put_method_master_7109}"],
        accepted_regex=r"^NOENTRY\{web_http_put_method_master_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-06-quiz",
        order=6,
        title="Web Application Fundamentals Assessment",
        instructions="Complete the 5-question quiz to test your conceptual understanding of HTTP mechanics, status codes, and session state.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question assessment quiz on web application fundamentals.",
        hint="Review HTTP statelessness, cookies, status codes, and methods.",
        xp_reward=70,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is HTTP referred to as a 'stateless' protocol?",
                options=[
                    "Each request from a client to a server is treated as an independent transaction without the server retaining state across requests by default",
                    "HTTP does not support transmitting text data",
                    "Web servers delete all files after each response",
                    "Clients cannot maintain network connections longer than one second",
                ],
                correct_option_index=0,
                explanation="HTTP has no built-in memory of prior requests; each transaction is self-contained unless application mechanisms like cookies or tokens are added.",
            ),
            QuizQuestion(
                id="q2",
                question="Which security attribute should be added to a Set-Cookie header to prevent client-side JavaScript from reading sensitive session cookies via XSS?",
                options=[
                    "HttpOnly",
                    "SameSite=None",
                    "Max-Age=0",
                    "Path=/",
                ],
                correct_option_index=0,
                explanation="The HttpOnly flag prevents client-side scripts (document.cookie) from accessing the cookie, mitigating session theft via Cross-Site Scripting.",
            ),
            QuizQuestion(
                id="q3",
                question="What does an HTTP 401 Unauthorized status code signify?",
                options=[
                    "The request lacks valid authentication credentials for the target resource",
                    "The server crashed while executing database queries",
                    "The requested URL does not exist on the web server",
                    "The client request method was permanently redirected to HTTPS",
                ],
                correct_option_index=0,
                explanation="401 Unauthorized indicates that the client has not provided credentials, or provided invalid credentials, to access the protected endpoint.",
            ),
            QuizQuestion(
                id="q4",
                question="What is the primary difference between a GET request and a POST request?",
                options=[
                    "GET parameters are appended to the URL query string intended for data retrieval, while POST sends data in the request body",
                    "POST can never contain headers",
                    "GET can only be sent by web crawlers, not browsers",
                    "POST requests are always encrypted with TLS by default",
                ],
                correct_option_index=0,
                explanation="GET requests append parameters to the URL query string for safe data retrieval, while POST conveys payloads in the HTTP body for state changes.",
            ),
            QuizQuestion(
                id="q5",
                question="Why is client-side input validation alone never sufficient to secure a web application?",
                options=[
                    "Adversaries can bypass browser validation completely by sending raw HTTP requests directly using curl, proxies, or custom scripts",
                    "Client-side scripts run too slowly to validate characters",
                    "Browsers do not support regular expressions",
                    "Client validation only works on Windows operating systems",
                ],
                correct_option_index=0,
                explanation="Client-side validation is a convenience feature for user experience; all security validation and authorization MUST be enforced on the server.",
            ),
        ],
    ),
]

ROOM_08_DEFINITION = RoomDefinition(
    room_id="red-08-web-application-fundamentals",
    track=TrackEnum.RED,
    room_number=8,
    title="Web Application Fundamentals",
    short_description="Master HTTP methods (GET, POST, PUT, DELETE), status codes, session cookies, REST APIs, and web architecture vulnerabilities.",
    difficulty="Beginner",
    estimated_duration="45 min",
    prerequisites=["Networking Fundamentals", "Linux for Hackers"],
    required_skills=["HTTP request inspection", "Cookie session authentication", "RESTful method manipulation"],
    lab_type="container_isolated",
    concept=ROOM_08_CONCEPT,
    tasks=ROOM_08_TASKS,
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Understand the HTTP request and response lifecycle",
        "Inspect status codes and analyze Method Not Allowed errors (405)",
        "Authenticate and manage session cookies using curl",
        "Perform resource updates using HTTP PUT requests",
    ],
    assessment_criteria=[
        "Identify standard RESTful HTTP methods",
        "Trigger and verify the 405 Method Not Allowed status code",
        "Authenticate and extract session tokens",
        "Capture the authorized cookie session flag",
        "Pass the 5-question web application fundamentals assessment quiz",
    ],
    completion_requirements=["Complete all 6 tasks with 100% accuracy"],
    total_xp=350,
)

