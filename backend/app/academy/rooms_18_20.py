"""
Complete curriculum definitions, tasks, concept explanations, and quizzes
for Red Team Rooms 18–20:
- Room 18: Active Directory Fundamentals (red-18-active-directory-fundamentals)
- Room 19: Exploitation and Post-Exploitation (red-19-exploitation-post-exploitation)
- Room 20: Red Team Capstone (red-20-red-team-capstone)
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
# ROOM 18: ACTIVE DIRECTORY FUNDAMENTALS (FULLY IMPLEMENTED)
# ============================================================================

ROOM_18_CONCEPT = RoomConcept(
    overview=(
        "Active Directory Domain Services (AD DS) is Microsoft's directory service solution providing centralized identity "
        "management, domain authentication, policy enforcement (Group Policy Objects), and resource authorization across "
        "enterprise Windows networks. Over 90% of Global Fortune 1000 organizations rely on Active Directory as the core "
        "identity backbone of their corporate enterprise."
    ),
    simple_analogy=(
        "Imagine an international corporate office tower. Instead of issuing physical metal keys for every individual door, "
        "cubicle, and filing cabinet, the enterprise operates a central security badge office. When an employee arrives in "
        "the morning, they present their credentials to the central badge dispatch desk (the Key Distribution Center / KDC). "
        "The badge desk verifies their identity and issues a tamper-evident smartcard lanyard (Ticket Granting Ticket / TGT). "
        "Later, when that employee needs access to the 4th-floor finance server room, they do not re-enter their password; "
        "they tap their smartcard lanyard at an internal kiosk, which validates the KDC signature and hands them a single-room "
        "entry pass (Service Ticket / TGS). Active Directory uses Kerberos tickets and LDAP directory services so identities "
        "are verified once and delegated securely without re-transmitting passwords across the network."
    ),
    technical_term="Active Directory Domain Services (AD DS) & Kerberos Authentication (RFC 4120 / LDAP RFC 4511)",
    technical_definition=(
        "AD DS organizes network identities hierarchically into Domains, Trees, and Forests, managed by Domain Controllers (DCs) "
        "storing the NTDS.dit database. Domain authentication relies on Kerberos v5: client requests a Ticket Granting Ticket (TGT) "
        "via Authentication Service (AS-REQ/AS-REP), requests Service Tickets (TGS-REQ/TGS-REP) for specific Service Principal Names "
        "(SPNs), and submits tickets with Privilege Attribute Certificates (PACs) to application servers. Querying and directory "
        "object searches occur over the Lightweight Directory Access Protocol (LDAP/LDAPS)."
    ),
    cybersecurity_context=(
        "Because Active Directory governs identity and access control across the entire enterprise, it constitutes the primary "
        "target during corporate cyber attacks. Attack vectors include Kerberoasting (requesting TGS tickets for service accounts "
        "with registered SPNs to crack RC4/AES hashes offline), AS-REP Roasting (requesting tickets for accounts with Kerberos "
        "preauthentication disabled), Unconstrained Delegation abuse, and lateral movement to Domain Admin status. Defending AD "
        "requires least-privilege architecture, Group Managed Service Accounts (gMSA), and strong Kerberos encryption (AES-256)."
    ),
    why_it_matters=(
        "Compromise of a single Domain Controller compromises the entire enterprise identity boundary. An adversary holding "
        "Domain Admin privileges can deploy ransomware across thousands of endpoints simultaneously, access confidential email and "
        "databases, and forge Kerberos Golden Tickets that grant permanent, undetectable access."
    ),
    demonstration=(
        "1. Architectural Limitation & Realism Note:\n"
        "   Full Windows Server Domain Controllers require multiple gigabytes of memory and a Windows kernel VM that cannot "
        "   run natively inside a lightweight Linux container. This lab exposes a realistic AD concepts directory service "
        "   daemon on port 8099 exposing domain structure, LDAP querying, Kerberos AS-REQ ticket issuance, and GPO policies.\n\n"
        "2. Domain Hierarchy Discovery:\n"
        "   GET /api/ad/domain -> Inspect Forest, Domain Controllers (DC01, DC02), and Organizational Units.\n\n"
        "3. LDAP SPN Enumeration:\n"
        "   GET /api/ad/users -> Discover service accounts (svc_sql, svc_backup) configured with Service Principal Names.\n\n"
        "4. Kerberos AS-REQ / AS-REP Authentication:\n"
        "   POST /api/ad/kerberos/request_tgt -> Authenticate and receive a Ticket Granting Ticket (TGT).\n\n"
        "5. Defensive Hardening:\n"
        "   POST /api/ad/remediate -> Deploy AES-256 enforcement, Group Managed Service Accounts, and Protected Users group."
    ),
    remediation_guide=(
        "1. Replace traditional service accounts with Group Managed Service Accounts (gMSA) featuring automatic 128-character password rotation.\n"
        "2. Enforce AES-128 and AES-256 Kerberos encryption; disable legacy DES and RC4 ciphers in domain group policies.\n"
        "3. Add all administrative principals to the Protected Users security group to prevent credential caching in LSASS memory.\n"
        "4. Eliminate unconstrained Kerberos delegation; enforce Resource-Based Constrained Delegation (RBCD).\n"
        "5. Implement a Tiered Administrative Model (Tier 0 / Tier 1 / Tier 2) to ensure Domain Admin accounts never log onto lower-tier workstations."
    ),
)

ROOM_18_TASKS = [
    TaskDefinition(
        task_id="task-01-ad-domain-hierarchy",
        order=1,
        title="Active Directory Architecture & Domain Hierarchy",
        instructions=(
            "Active Directory organizes enterprise resources into a hierarchical tree structure: Forest Root, Domains, "
            "Organizational Units (OUs), Domain Controllers (DCs), and leaf objects (users, groups, computers).\n\n"
            "Query the domain service on port 8099 to inspect the domain hierarchy and find the architecture flag:\n"
            "  `curl -s http://10.10.14.90:8099/api/ad/domain`\n\n"
            "Submit the discovered security flag `NOENTRY{...}`."
        ),
        task_type=TaskType.FLAG,
        xp_reward=50,
        accepted_answers=["NOENTRY{ad_domain_hierarchy_discovered_9102}"],
        mistake_explanations={
            "DC01": "DC01 is the domain controller hostname, not the flag. Look for NOENTRY{...} in the JSON response.",
            "CORP.NOENTRY.LOCAL": "CORP.NOENTRY.LOCAL is the domain name. The flag is formatted as NOENTRY{ad_domain_hierarchy_discovered_9102}.",
        },
    ),
    TaskDefinition(
        task_id="task-02-ad-ldap-enumeration",
        order=2,
        title="LDAP Directory Query & Service Account Enumeration",
        instructions=(
            "The Lightweight Directory Access Protocol (LDAP) allows domain users and applications to query directory objects. "
            "In an Active Directory domain, any authenticated domain user can query LDAP for accounts configured with a "
            "Service Principal Name (SPN). These accounts are prime targets for Kerberoasting attacks.\n\n"
            "Enumerate the domain user accounts and inspect their SPN configurations:\n"
            "  `curl -s http://10.10.14.90:8099/api/ad/users`\n\n"
            "Or run the provided Python LDAP query tool:\n"
            "  `python3 /home/operator/tools/ad_ldap_query.py`\n\n"
            "Submit the discovered flag `NOENTRY{...}`."
        ),
        task_type=TaskType.FLAG,
        xp_reward=60,
        accepted_answers=["NOENTRY{ad_ldap_enumeration_spn_7812}"],
        mistake_explanations={
            "svc_backup": "svc_backup is the vulnerable service account name, not the flag. Submit the NOENTRY{...} flag.",
            "svc_sql": "svc_sql is one of the service accounts. Look for the flag field in the response.",
        },
    ),
    TaskDefinition(
        task_id="task-03-ad-kerberos-authentication",
        order=3,
        title="Kerberos Authentication & Ticket Granting Ticket (TGT) Issuance",
        instructions=(
            "Kerberos authentication begins with the Authentication Service Request (AS-REQ). The client sends an AS-REQ "
            "with a timestamp encrypted using their password hash. The Key Distribution Center (KDC) validates the request "
            "and returns an AS-REP containing the Ticket Granting Ticket (TGT) and session key.\n\n"
            "Simulate an AS-REQ authentication request for the service account `svc_backup`:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"username\":\"svc_backup\"}' http://10.10.14.90:8099/api/ad/kerberos/request_tgt`\n\n"
            "Submit the discovered flag `NOENTRY{...}`."
        ),
        task_type=TaskType.FLAG,
        xp_reward=70,
        accepted_answers=["NOENTRY{ad_kerberos_tgt_authentication_4419}"],
        mistake_explanations={
            "AS_REP_SUCCESS": "AS_REP_SUCCESS is the transaction status, not the security flag.",
            "ticket_only": "TGT is the ticket type abbreviation. Submit the NOENTRY{ad_kerberos_tgt_authentication_4419} flag.",
        },
    ),
    TaskDefinition(
        task_id="task-04-ad-misconfiguration-audit",
        order=4,
        title="Active Directory Security Audit: Delegation & SPN Risks",
        instructions=(
            "Enterprise Active Directory deployments often suffer from legacy misconfigurations, such as RC4 cipher usage "
            "on service tickets, unconstrained delegation, and stale accounts with administrative rights.\n\n"
            "Audit the domain configuration using the challenge endpoint:\n"
            "  `curl -s \"http://10.10.14.90:8099/challenge?audit=spn\"`\n\n"
            "Submit the discovered challenge flag `NOENTRY{...}`."
        ),
        task_type=TaskType.FLAG,
        xp_reward=70,
        accepted_answers=["NOENTRY{ad_delegation_misconfig_master_3201}"],
        mistake_explanations={
            "unconstrained": "Delegation is the concept being audited. Submit the full NOENTRY{...} flag from the audit response.",
            "RC4": "RC4 is the vulnerable legacy cipher. Submit the security flag NOENTRY{ad_delegation_misconfig_master_3201}.",
        },
    ),
    TaskDefinition(
        task_id="task-05-ad-gpo-remediation",
        order=5,
        title="Group Policy Hardening & Least-Privilege Remediation",
        instructions=(
            "Defending Active Directory requires applying hardened Group Policy Objects (GPOs), replacing vulnerable static "
            "service accounts with Group Managed Service Accounts (gMSAs), restricting Kerberos encryption strictly to AES-128 "
            "and AES-256, and placing privileged administrators in the Protected Users security group.\n\n"
            "Trigger the defensive remediation policy deployment:\n"
            "  `curl -s -X POST http://10.10.14.90:8099/api/ad/remediate`\n\n"
            "Submit the remediation confirmation flag `NOENTRY{...}`."
        ),
        task_type=TaskType.FLAG,
        xp_reward=50,
        accepted_answers=["NOENTRY{ad_gpo_least_privilege_secured_8891}"],
        mistake_explanations={
            "REMEDIATED": "REMEDIATED is the status string. Look for the flag field NOENTRY{ad_gpo_least_privilege_secured_8891}.",
        },
    ),
    TaskDefinition(
        task_id="task-06-ad-quiz",
        order=6,
        title="Active Directory Security Concepts Assessment",
        instructions="Complete the 5-question technical quiz to demonstrate comprehensive mastery of Active Directory architecture, Kerberos authentication, and defensive hardening.",
        task_type=TaskType.QUIZ,
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is the primary role of a Domain Controller (DC) in an Active Directory environment?",
                options=[
                    "Centralized host that stores the NTDS.dit directory database and provides authentication and policy enforcement via Kerberos and LDAP.",
                    "A caching web proxy that speeds up employee internet browsing.",
                    "A network switch that routes physical Ethernet frames between offices.",
                    "An antivirus workstation that runs signature updates for desktop users.",
                ],
                correct_option_index=0,
                explanation="A Domain Controller is the central server hosting the Active Directory database (NTDS.dit), running the KDC service for Kerberos authentication, and enforcing Group Policy.",
            ),
            QuizQuestion(
                id="q2",
                question="In the Kerberos authentication protocol, what is a Ticket Granting Ticket (TGT)?",
                options=[
                    "An encrypted proof-of-identity token issued by the KDC Authentication Service (AS) that allows a user to request Service Tickets without re-entering their password.",
                    "A certificate used exclusively for TLS HTTPS web connections.",
                    "A temporary password sent to a user's smartphone via SMS.",
                    "A system registry key stored on the local client hard drive.",
                ],
                correct_option_index=0,
                explanation="A TGT is issued by the KDC's Authentication Service (AS) during initial logon. It proves the user's authenticated identity and is used to request Service Tickets (TGS) for specific network services.",
            ),
            QuizQuestion(
                id="q3",
                question="What makes Kerberoasting such an effective attack vector in enterprise Active Directory environments?",
                options=[
                    "Any valid domain user can request a Kerberos service ticket for any account with a registered SPN and crack the ticket offline without triggering lockouts.",
                    "It exploits a physical defect in the domain controller's motherboard.",
                    "It requires physical access to the corporate server room and a USB rubber ducky.",
                    "It works by sending excessive ICMP ping packets to the network gateway.",
                ],
                correct_option_index=0,
                explanation="In Kerberos, any authenticated domain user can request a TGS ticket for any service with an SPN. Because the ticket is encrypted with the service account's password hash, the attacker can extract and crack the hash offline at high speed.",
            ),
            QuizQuestion(
                id="q4",
                question="Why is adding administrative accounts to the 'Protected Users' security group a critical defensive measure?",
                options=[
                    "It prevents Windows from caching plaintext credentials, NTLM password hashes, and Kerberos keys in LSASS memory on compromised systems.",
                    "It grants administrators unlimited access to every company laptop automatically.",
                    "It disables firewall logging so administrators can work faster.",
                    "It allows administrators to bypass multi-factor authentication requirements.",
                ],
                correct_option_index=0,
                explanation="Members of the Protected Users security group are barred from using NTLM, DES, or RC4, and Windows does not cache their plaintext credentials or Kerberos keys in LSASS memory, mitigating Mimikatz credential theft.",
            ),
            QuizQuestion(
                id="q5",
                question="How do Group Managed Service Accounts (gMSA) protect enterprise networks against service credential compromise?",
                options=[
                    "Active Directory automatically generates, rotates, and manages complex 128-character passwords for the service without human intervention.",
                    "gMSAs eliminate the need for domain controllers entirely.",
                    "They allow services to run without any operating system permissions.",
                    "They store passwords in a publicly readable shared text file on the intranet.",
                ],
                correct_option_index=0,
                explanation="gMSAs allow Active Directory to automatically manage and rotate complex passwords on a scheduled basis, ensuring that service account credentials cannot be cracked via Kerberoasting.",
            ),
        ],
    ),
]

ROOM_18_DEFINITION = RoomDefinition(
    room_id="red-18-active-directory-fundamentals",
    room_number=18,
    track=TrackEnum.RED,
    title="Active Directory Fundamentals",
    short_description="Explore enterprise identity architecture, domain hierarchies, LDAP directory enumeration, Kerberos ticket authentication, and Group Policy hardening.",
    difficulty="Intermediate",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_18_CONCEPT,
    tasks=ROOM_18_TASKS,
    learning_objectives=[
        "Understand Active Directory domain hierarchies, trees, forests, and Domain Controllers",
        "Enumerate user accounts and Service Principal Names (SPNs) over LDAP",
        "Analyze the Kerberos v5 authentication lifecycle: AS-REQ, TGT, TGS-REQ, and PAC",
        "Identify common AD misconfigurations including Kerberoasting and unconstrained delegation",
        "Apply Group Policy Objects, Protected Users groups, and Group Managed Service Accounts (gMSA)",
    ],
    assessment_criteria=[
        "Discover domain controller roles and organizational units from live domain metadata",
        "Enumerate LDAP accounts and extract service accounts registered with SPNs",
        "Perform a simulated Kerberos AS-REQ authentication request and verify TGT issuance",
        "Audit domain misconfigurations including weak RC4 ciphers and insecure delegation",
        "Verify GPO remediation and defensive policy deployment",
        "Pass the 5-question Active Directory technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)


# ============================================================================
# ROOM 19: EXPLOITATION AND POST-EXPLOITATION (FULLY IMPLEMENTED)
# ============================================================================

ROOM_19_CONCEPT = RoomConcept(
    overview=(
        "Exploitation is the controlled execution of code or logic that transforms an identified software vulnerability into "
        "active access. Post-exploitation encompasses the disciplined phases that follow initial access: host enumeration, "
        "situational awareness, privilege evaluation, persistence analysis, lateral movement potential, and evidence cleanup."
    ),
    simple_analogy=(
        "Imagine an authorized industrial safety auditor testing physical vault security. Discovering that a back fire-exit "
        "door latch is misaligned is finding a vulnerability. Opening that door to step inside the loading dock is the exploit "
        "(the initial foothold). However, an ethical auditor does not immediately rifle through confidential filing cabinets "
        "or vandalize machinery. They follow strict post-audit protocol: they note their exact location (situational awareness), "
        "verify whether unmonitored interior doors allow unauthorized hallway access (lateral movement assessment), document "
        "what sensitive assets were exposed without disturbing operations, and finally, close the door, restore all alarms, and "
        "deliver clear engineering blueprints so the latch can be reinforced (cleanup and remediation)."
    ),
    technical_term="Vulnerability Exploitation & Post-Exploitation Lifecycle (MITRE ATT&CK TA0002, TA0003, TA0007, TA0008)",
    technical_definition=(
        "Exploitation leverages specific flaws (memory corruptions, injection flaws, logic errors) to alter execution flow "
        "and establish a command-and-control (C2) channel or interactive shell session. Post-exploitation begins immediately upon "
        "session establishment: local host enumeration (system identity, kernel version, internal routing tables, mounted drives), "
        "persistence mechanism analysis (cron jobs, systemd services, scheduled tasks), credential access, lateral movement analysis, "
        "and mandatory engagement cleanup."
    ),
    cybersecurity_context=(
        "In offensive cybersecurity and professional red teaming, obtaining initial access is rarely the final objective. Threat "
        "actors seek persistence and lateral movement to reach core enterprise assets. Conversely, ethical red teams must execute "
        "post-exploitation with meticulous discipline: logging all commands, strictly avoiding data destruction, verifying all "
        "persistence markers for removal, and providing blue teams with actionable telemetry to build detection rules."
    ),
    why_it_matters=(
        "Without rigorous post-exploitation methodology, security assessments risk causing unintentional system outages, data "
        "corruption, or leaving rogue backdoor mechanisms on client networks that actual threat actors can later exploit."
    ),
    demonstration=(
        "1. Controlled Initial Foothold Exploitation:\n"
        "   POST /api/exploit/stage1 -> Submit verified payload against dispatch service to obtain an active session ID.\n\n"
        "2. Post-Exploitation Environment Telemetry:\n"
        "   GET /api/post/recon?session=sess_post_99182 -> Extract host identity, internal network subnets, and sensitive files.\n\n"
        "3. Controlled Persistence Marker Demonstration:\n"
        "   POST /api/post/persist -> Install a safe, non-destructive marker (/etc/cron.d/marker_persist) to verify persistence vectors.\n\n"
        "4. Lateral Movement & Exfiltration Risk Evaluation:\n"
        "   GET /challenge?stage=lateral -> Analyze SSH key reuse and unencrypted staging databases.\n\n"
        "5. Complete Incident Cleanup & Remediation:\n"
        "   POST /api/remediate -> Purge all sessions, delete persistence markers, patch service vulnerabilities, and verify system integrity."
    ),
    remediation_guide=(
        "1. Enforce strict input validation, parameterization, and least-privilege execution to prevent initial exploitation footholds.\n"
        "2. Deploy File Integrity Monitoring (FIM) and system auditing (auditd) on /etc/cron*, /etc/systemd/, and user startup paths.\n"
        "3. Segment internal subnets with stateful firewalls to prevent lateral movement from perimeter tiers to internal databases.\n"
        "4. Enforce strict credential hygiene: prohibit SSH key reuse and ensure credentials are never stored in plaintext configuration files.\n"
        "5. Maintain a mandatory, documented post-engagement cleanup checklist ensuring all testing accounts and tools are completely removed."
    ),
)

ROOM_19_TASKS = [
    TaskDefinition(
        task_id="task-01-exploit-foothold",
        order=1,
        title="Controlled Initial Foothold Exploitation",
        instructions=(
            "Exploitation requires identifying prerequisites, verifying reliability, and executing a controlled interaction "
            "to establish an interactive session.\n\n"
            "Submit the initial access request against the operations dispatcher on port 8100:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"payload\":\"check_prereq\",\"service\":\"volt_dispatch\"}' http://10.10.14.90:8100/api/exploit/stage1`\n\n"
            "Or run the automated exploit tool:\n"
            "  `python3 /home/operator/tools/exploit_runner.py`\n\n"
            "Submit the discovered foothold security flag `NOENTRY{...}`."
        ),
        task_type=TaskType.FLAG,
        xp_reward=50,
        accepted_answers=["NOENTRY{exploit_initial_foothold_access_6120}"],
        mistake_explanations={
            "sess_post_99182": "sess_post_99182 is the session identifier, not the security flag.",
            "INITIAL_ACCESS_CONFIRMED": "INITIAL_ACCESS_CONFIRMED is the status string. Look for the flag field.",
        },
    ),
    TaskDefinition(
        task_id="task-02-post-recon-telemetry",
        order=2,
        title="Host & Environment Telemetry Reconnaissance",
        instructions=(
            "Once an initial foothold is secured, the operator must avoid noisy or destructive actions and instead perform "
            "situational reconnaissance: verifying session identity (whoami/id), inspecting network interfaces, checking "
            "mounted disks, and identifying sensitive file paths.\n\n"
            "Extract host environment telemetry using your active session token:\n"
            "  `curl -s \"http://10.10.14.90:8100/api/post/recon?session=sess_post_99182\"`\n\n"
            "Submit the discovered reconnaissance flag `NOENTRY{...}`."
        ),
        task_type=TaskType.FLAG,
        xp_reward=60,
        accepted_answers=["NOENTRY{exploit_env_recon_telemetry_9941}"],
        mistake_explanations={
            "daemon_svc": "daemon_svc is the compromised account identity, not the flag.",
            "172.28.0.5": "172.28.0.5 is the internal subnet IP. Look for the flag field in the JSON response.",
        },
    ),
    TaskDefinition(
        task_id="task-03-exploit-persistence",
        order=3,
        title="Persistence Mechanism Analysis & Marker Demonstration",
        instructions=(
            "Persistence allows an adversary to maintain access across system restarts and credential resets. Common persistence "
            "vectors on Linux include cron jobs, systemd service units, and bash profile hooks.\n\n"
            "Demonstrate a controlled, safe persistence marker using the active session:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"session\":\"sess_post_99182\",\"mechanism\":\"cron\"}' http://10.10.14.90:8100/api/post/persist`\n\n"
            "Submit the discovered persistence flag `NOENTRY{...}`."
        ),
        task_type=TaskType.FLAG,
        xp_reward=70,
        accepted_answers=["NOENTRY{exploit_persistence_mechanism_4182}"],
        mistake_explanations={
            "cron": "cron is the persistence mechanism type. Submit the NOENTRY{...} security flag.",
            "/etc/cron.d/marker_persist": "This is the file path of the marker, not the security flag.",
        },
    ),
    TaskDefinition(
        task_id="task-04-exploit-lateral-risk",
        order=4,
        title="Lateral Movement & Data Risk Analysis",
        instructions=(
            "After establishing persistence, attackers attempt lateral movement to pivot across internal network segments toward "
            "high-value targets (such as internal database clusters).\n\n"
            "Evaluate lateral movement vectors and sensitive data collection risks:\n"
            "  `curl -s \"http://10.10.14.90:8100/challenge?stage=lateral\"`\n\n"
            "Submit the discovered lateral analysis flag `NOENTRY{...}`."
        ),
        task_type=TaskType.FLAG,
        xp_reward=70,
        accepted_answers=["NOENTRY{exploit_lateral_exfil_master_7730}"],
        mistake_explanations={
            "stage=lateral": "stage=lateral is the query stage parameter. Submit the flag from the response payload.",
        },
    ),
    TaskDefinition(
        task_id="task-05-exploit-cleanup-remediation",
        order=5,
        title="Incident Cleanup & Evidence Remediation",
        instructions=(
            "Ethical security testing requires 100% artifact cleanup upon engagement conclusion: revoking temporary sessions, "
            "removing all persistence markers, patching vulnerabilities, and verifying system integrity.\n\n"
            "Execute the incident cleanup and system hardening routine:\n"
            "  `curl -s -X POST http://10.10.14.90:8100/api/remediate`\n\n"
            "Submit the cleanup verification flag `NOENTRY{...}`."
        ),
        task_type=TaskType.FLAG,
        xp_reward=50,
        accepted_answers=["NOENTRY{exploit_cleanup_remediation_verified_2041}"],
        mistake_explanations={
            "INCIDENT_CLEANUP_VERIFIED": "INCIDENT_CLEANUP_VERIFIED is the status string. Submit the NOENTRY{...} flag.",
        },
    ),
    TaskDefinition(
        task_id="task-06-exploit-quiz",
        order=6,
        title="Exploitation and Post-Exploitation Technical Assessment",
        instructions="Complete the 5-question technical quiz to demonstrate comprehensive mastery of exploitation prerequisites, situational enumeration, persistence ethics, and defensive cleanup.",
        task_type=TaskType.QUIZ,
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What fundamentally distinguishes a software vulnerability from an exploit?",
                options=[
                    "A vulnerability is a weakness or flaw in software logic; an exploit is tailored code or input that takes active advantage of that flaw to achieve execution or unauthorized access.",
                    "A vulnerability is an antivirus program, while an exploit is an operating system update.",
                    "An exploit is only written by hardware manufacturers, while vulnerabilities only occur in web browsers.",
                    "There is no difference; both terms mean identical things.",
                ],
                correct_option_index=0,
                explanation="A vulnerability is the underlying weakness or bug in the system design or code. An exploit is the specific weaponized payload or command sequence that triggers the bug to gain access.",
            ),
            QuizQuestion(
                id="q2",
                question="Why is local host enumeration (situational awareness) the essential first step immediately after gaining initial access?",
                options=[
                    "It determines the current user privileges, operating system version, network boundaries, and defenses without triggering disruptive alarms.",
                    "It automatically wipes the operating system hard drive to remove forensic evidence.",
                    "It shuts down the target machine so administrators cannot see the session.",
                    "It sends an email notification to the corporate CEO.",
                ],
                correct_option_index=0,
                explanation="Situational awareness allows the operator to understand their execution context (uid, privileges, kernel, routing) so they can make informed, non-destructive decisions.",
            ),
            QuizQuestion(
                id="q3",
                question="What is the ethical and operational danger of installing unmonitored persistence mechanisms during an authorized penetration test?",
                options=[
                    "If persistence hooks are not meticulously tracked and purged, they leave permanent backdoors that malicious third parties can exploit after the test concludes.",
                    "Persistence mechanisms automatically increase the target company's electricity bill.",
                    "Persistence triggers immediate physical damage to computer RAM chips.",
                    "Persistence causes the tester's laptop battery to deplete rapidly.",
                ],
                correct_option_index=0,
                explanation="Leaving unauthorized or forgotten persistence mechanisms creates a severe ongoing vulnerability for the client, turning a security assessment into an active enterprise risk.",
            ),
            QuizQuestion(
                id="q4",
                question="What does 'lateral movement' describe in an enterprise cyber attack lifecycle?",
                options=[
                    "Techniques an attacker uses to pivot from an initially compromised entry point to other systems and subnets across the internal network.",
                    "Moving physical desktop computers from one office room to another.",
                    "Reinstalling the operating system using a different language pack.",
                    "Upgrading the speed of the Ethernet cables in the data center.",
                ],
                correct_option_index=0,
                explanation="Lateral movement refers to techniques used to extend access across internal network boundaries from a low-value entry point toward high-value corporate targets.",
            ),
            QuizQuestion(
                id="q5",
                question="What is the mandatory final operational step of every professional Red Team engagement?",
                options=[
                    "Complete artifact remediation: terminating all testing sessions, deleting all persistence markers, removing uploaded tools, and verifying system state with the blue team.",
                    "Publishing the client's internal passwords on public social media forums.",
                    "Formatting the target server so no one knows what happened.",
                    "Disabling all firewall rules so tests can be run again tomorrow.",
                ],
                correct_option_index=0,
                explanation="Responsible penetration testing strictly mandates complete post-engagement cleanup, ensuring every script, user account, session, and marker is removed.",
            ),
        ],
    ),
]

ROOM_19_DEFINITION = RoomDefinition(
    room_id="red-19-exploitation-post-exploitation",
    room_number=19,
    track=TrackEnum.RED,
    title="Exploitation and Post-Exploitation",
    short_description="Master the lifecycle of controlled foothold exploitation, post-exploitation telemetry, persistence analysis, lateral movement risks, and responsible cleanup.",
    difficulty="Advanced",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_19_CONCEPT,
    tasks=ROOM_19_TASKS,
    learning_objectives=[
        "Distinguish software vulnerabilities from actionable, reliable exploits",
        "Execute a controlled initial foothold and establish an interactive session context",
        "Perform non-destructive post-exploitation reconnaissance and host telemetry collection",
        "Analyze persistence techniques (cron, systemd) and adhere to strict ethical safety boundaries",
        "Execute comprehensive incident cleanup, evidence purging, and defensive verification",
    ],
    assessment_criteria=[
        "Trigger initial access exploit against internal service and obtain active session ID",
        "Extract environment telemetry including user identity, kernel, and internal subnets",
        "Install and verify a safe, controlled persistence marker",
        "Analyze lateral movement vectors and unencrypted credential risks",
        "Execute automated cleanup routine and verify system remediation",
        "Pass the 5-question exploitation and post-exploitation technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)


# ============================================================================
# ROOM 20: RED TEAM CAPSTONE (FULLY IMPLEMENTED)
# ============================================================================

ROOM_20_CONCEPT = RoomConcept(
    overview=(
        "The Red Team Capstone is the culminating practical assessment of the NO ENTRY Red Team Track. Operating as an "
        "authorized cybersecurity assessor against the multi-service enterprise infrastructure of VoltDefense Systems / "
        "VoltCorp Global, the learner conducts a full-spectrum, multi-phase penetration assessment: Rules of Engagement validation, "
        "perimeter service discovery, controlled initial foothold acquisition, internal privilege escalation, professional technical "
        "reporting, and defensive remediation verification."
    ),
    simple_analogy=(
        "Imagine an aerospace engineering firm commissioning an independent certification audit of their aircraft emergency "
        "systems. The lead auditor does not simply jump into the cockpit and push random switches. They first verify the formal flight "
        "test authorization and safety boundaries with air traffic control (Rules of Engagement). They perform a thorough pre-flight "
        "instrument check (perimeter reconnaissance). They execute a controlled simulated emergency touchdown to test the landing "
        "gear failure mode (foothold and exploit). They verify that backup hydraulic overrides respond properly (privilege escalation). "
        "Finally, they submit a comprehensive technical engineering report detailing every finding, risk rating, and engineering "
        "remediation roadmap to corporate executives, followed by re-testing the reinforced systems to certify flight readiness."
    ),
    technical_term="Full-Spectrum Red Team Assessment & Penetration Testing Lifecycle (PTES / NIST SP 800-115)",
    technical_definition=(
        "A comprehensive, objective-based security assessment combining open-source intelligence, active network scanning, "
        "vulnerability exploitation, post-exploitation enumeration, privilege escalation, and formal executive/technical reporting "
        "conducted strictly within predefined Rules of Engagement (ROE). The assessment culminates in actionable remediation "
        "roadmaps that empower organizations to harden their defense-in-depth posture."
    ),
    cybersecurity_context=(
        "Capstone exercises synthesize disparate technical skills into a coherent offensive security methodology. Real-world "
        "adversaries do not rely on isolated vulnerabilities; they chain together minor configuration oversights, perimeter "
        "services, and internal misconfigurations to compromise entire corporate environments. Security professionals must understand "
        "this entire attack chain to design robust defense-in-depth architectures and effective intrusion detection mechanisms."
    ),
    why_it_matters=(
        "Successfully discovering and reporting vulnerabilities before malicious actors exploit them protects critical infrastructure, "
        "financial integrity, and personal privacy. A certified offensive security operator is defined not only by technical "
        "proficiency, but by rigorous adherence to ethical boundaries and the delivery of actionable remediation guidance."
    ),
    demonstration=(
        "Phase 1: Rules of Engagement Verification\n"
        "  GET /api/capstone/scope -> Inspect permitted subnets (10.10.14.0/24), excluded systems, and emergency halt contacts.\n\n"
        "Phase 2: Perimeter Reconnaissance & Service Mapping\n"
        "  GET /api/capstone/recon -> Map exposed enterprise services across target architecture.\n\n"
        "Phase 3: Multi-Service Foothold Exploitation\n"
        "  POST /api/capstone/exploit -> Exploit vulnerable perimeter dispatcher to acquire initial foothold token.\n\n"
        "Phase 4: Internal Privilege Escalation to Root\n"
        "  POST /api/capstone/privesc -> Breach internal privilege boundary to gain root execution context.\n\n"
        "Phase 5: Professional Assessment Report Submission\n"
        "  POST /api/capstone/report -> Submit structured penetration assessment findings and executive remediation roadmap.\n\n"
        "Phase 6: Enterprise Defense Hardening\n"
        "  POST /api/remediate -> Verify all capstone vulnerabilities patched and least-privilege security posture established."
    ),
    remediation_guide=(
        "1. Adopt defense-in-depth across network perimeters, host operating systems, and identity management tiers.\n"
        "2. Implement continuous vulnerability management, prioritizing critical and high-severity CVEs for immediate remediation.\n"
        "3. Enforce the Principle of Least Privilege across all service accounts, sudoers configurations, and file permission bits.\n"
        "4. Deploy centralized logging, SIEM correlation, and Endpoint Detection and Response (EDR) to detect anomalous behavior.\n"
        "5. Conduct periodic third-party penetration assessments and collaborative Purple Team exercises to continuously validate defenses."
    ),
)

ROOM_20_TASKS = [
    TaskDefinition(
        task_id="task-01-capstone-scope-roe",
        order=1,
        title="Scope & Rules of Engagement (ROE) Verification",
        instructions=(
            "Prior to sending any assessment traffic, an ethical red team operator must review and confirm the authorized "
            "Rules of Engagement (ROE): authorized target subnets, permitted ports, excluded systems, and emergency halt procedures.\n\n"
            "Query the capstone scope endpoint on port 8101 to verify engagement parameters:\n"
            "  `curl -s http://10.10.14.90:8101/api/capstone/scope`\n\n"
            "Or inspect the local scope manifesto:\n"
            "  `cat /home/operator/capstone/scope_manifesto.txt`\n\n"
            "Submit the discovered scope verification flag `NOENTRY{...}`."
        ),
        task_type=TaskType.FLAG,
        xp_reward=50,
        accepted_answers=["NOENTRY{capstone_scope_roe_verified_1092}"],
        mistake_explanations={
            "10.10.14.0/24": "10.10.14.0/24 is the authorized target subnet, not the flag. Look for NOENTRY{...}.",
            "soc-lead": "This is the emergency contact identifier. Submit the NOENTRY{capstone_scope_roe_verified_1092} flag.",
        },
    ),
    TaskDefinition(
        task_id="task-02-capstone-service-discovery",
        order=2,
        title="Perimeter Reconnaissance & Service Discovery",
        instructions=(
            "With the scope verified, begin Phase 2: mapping the exposed perimeter attack surface. Identify active services, "
            "underlying technologies, and potential vulnerabilities across the enterprise infrastructure.\n\n"
            "Perform perimeter reconnaissance against the capstone target gateway:\n"
            "  `curl -s http://10.10.14.90:8101/api/capstone/recon`\n\n"
            "Submit the perimeter service discovery flag `NOENTRY{...}`."
        ),
        task_type=TaskType.FLAG,
        xp_reward=60,
        accepted_answers=["NOENTRY{capstone_service_discovery_5821}"],
        mistake_explanations={
            "VoltDefense Systems": "VoltDefense Systems is the target organization name. Look for the flag field.",
        },
    ),
    TaskDefinition(
        task_id="task-03-capstone-foothold-exploit",
        order=3,
        title="Multi-Service Foothold Exploitation",
        instructions=(
            "Phase 3: Execute a controlled foothold exploit against the exposed gateway service to transition from an unauthenticated "
            "external observer to an authenticated internal operator (`app_operator`).\n\n"
            "Trigger the controlled foothold exploit:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"action\":\"foothold\"}' http://10.10.14.90:8101/api/capstone/exploit`\n\n"
            "Submit the discovered foothold security flag `NOENTRY{...}`."
        ),
        task_type=TaskType.FLAG,
        xp_reward=70,
        accepted_answers=["NOENTRY{capstone_foothold_compromise_3319}"],
        mistake_explanations={
            "app_operator": "app_operator is the compromised account identity, not the flag.",
            "FOOTHOLD_ACQUIRED": "FOOTHOLD_ACQUIRED is the status string. Submit the full NOENTRY{...} flag.",
        },
    ),
    TaskDefinition(
        task_id="task-04-capstone-privilege-escalation",
        order=4,
        title="Internal Privilege Escalation to Root",
        instructions=(
            "Phase 4: Operating from the unprivileged `app_operator` foothold, conduct local system auditing and exploit an "
            "internal privilege boundary (SUID / sudoers misconfiguration) to elevate to `root` (UID 0).\n\n"
            "Execute the privilege escalation routine:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"technique\":\"suid\"}' http://10.10.14.90:8101/api/capstone/privesc`\n\n"
            "Submit the discovered privilege breach flag `NOENTRY{...}`."
        ),
        task_type=TaskType.FLAG,
        xp_reward=70,
        accepted_answers=["NOENTRY{capstone_privilege_breach_8804}"],
        mistake_explanations={
            "root": "root is the target elevated identity. Submit the NOENTRY{...} security flag.",
            "ROOT_ELEVATION_CONFIRMED": "ROOT_ELEVATION_CONFIRMED is the status string. Look for the flag field.",
        },
    ),
    TaskDefinition(
        task_id="task-05-capstone-report-submission",
        order=5,
        title="Professional Assessment Report Submission",
        instructions=(
            "Phase 5: The defining mark of a professional security practitioner is delivering clear, actionable, structured "
            "findings to technical and executive stakeholders. Submit the completed penetration testing assessment report.\n\n"
            "Submit the assessment report using the template on your workstation:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d @/home/operator/capstone/report_template.json http://10.10.14.90:8101/api/capstone/report`\n\n"
            "Submit the master assessor certification flag `NOENTRY{...}`."
        ),
        task_type=TaskType.FLAG,
        xp_reward=50,
        accepted_answers=["NOENTRY{capstone_master_assessor_7749}"],
        mistake_explanations={
            "CERTIFIED_RED_TEAM_OPERATOR": "This is your assessor status title. Submit the NOENTRY{capstone_master_assessor_7749} flag.",
            "ASSESSMENT_REPORT_ACCEPTED": "This is the submission status. Look for the flag field.",
        },
    ),
    TaskDefinition(
        task_id="task-06-capstone-quiz",
        order=6,
        title="Red Team Capstone Technical & Ethical Assessment",
        instructions="Complete the 5-question comprehensive quiz to validate complete theoretical, operational, and ethical mastery across the 20-room Red Team Track.",
        task_type=TaskType.QUIZ,
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is formal verification of the Rules of Engagement (ROE) legally and operationally critical before conducting any security assessment?",
                options=[
                    "It establishes legal authorization, defines permissible boundaries, identifies critical out-of-scope systems, and specifies emergency halt protocols to prevent catastrophic outages.",
                    "It guarantees that the penetration tester is immune to all civil laws worldwide.",
                    "It ensures that all discovered company data is automatically uploaded to public file-sharing sites.",
                    "It allows the tester to hack competitor organizations without their permission.",
                ],
                correct_option_index=0,
                explanation="Rules of Engagement (ROE) define the contractual and legal boundaries of testing, preventing unauthorized intrusions, protecting fragile systems, and establishing emergency communication channels.",
            ),
            QuizQuestion(
                id="q2",
                question="In enterprise penetration testing, why is chaining multiple low or medium severity findings often more effective than looking for a single critical flaw?",
                options=[
                    "Modern enterprise networks rarely have a single catastrophic flaw; attackers succeed by combining perimeter information disclosure, credential reuse, and internal privilege misconfigurations.",
                    "Chaining findings creates longer reports that cost more money.",
                    "Low severity findings automatically convert into high severity findings when copied into Word.",
                    "It confuses network firewalls into shutting themselves off.",
                ],
                correct_option_index=0,
                explanation="Real-world attack chains combine subtle flaws (e.g. info disclosure -> credential leak -> foothold -> SUID privesc) into a complete compromise path.",
            ),
            QuizQuestion(
                id="q3",
                question="What is the primary function of the Executive Summary section in a professional penetration testing report?",
                options=[
                    "To communicate strategic business risk, overall security posture, and high-level remediation priorities to non-technical executive leadership in plain, concise language.",
                    "To list every raw Nmap port scan and Wireshark hex packet dump.",
                    "To blame individual developers and demand that they be fired.",
                    "To market expensive third-party security software products.",
                ],
                correct_option_index=0,
                explanation="The Executive Summary translates complex technical vulnerabilities into clear business risk terms so executive leadership can make informed budget and policy decisions.",
            ),
            QuizQuestion(
                id="q4",
                question="How does the Principle of Defense-in-Depth protect an enterprise when a perimeter service is compromised?",
                options=[
                    "Layered defensive controls (least privilege, network segmentation, host hardening, EDR) contain the breach and prevent the attacker from escalating privileges or pivoting laterally.",
                    "It ensures that whenever one computer is hacked, all other computers instantly delete their hard drives.",
                    "It redirects all network traffic to an unmonitored home router.",
                    "It requires users to change their password every 15 minutes.",
                ],
                correct_option_index=0,
                explanation="Defense-in-Depth assumes individual controls will occasionally fail. Redundant, layered defenses ensure that a perimeter foothold cannot easily transition into domain-wide compromise.",
            ),
            QuizQuestion(
                id="q5",
                question="What ethical responsibility distinguishes a professional Red Team operator from a malicious threat actor?",
                options=[
                    "Strict adherence to authorized scope, preservation of system integrity, complete evidence cleanup, and delivering actionable defensive remediation to secure the client.",
                    "Using commercial paid operating systems rather than free open-source software.",
                    "Only performing attacks on national holidays.",
                    "Conducting scans during daytime hours rather than at night.",
                ],
                correct_option_index=0,
                explanation="Ethical operators operate strictly within legal authorization, avoid operational disruption, clean up all artifacts, and empower the client to strengthen their security posture.",
            ),
        ],
    ),
]

ROOM_20_DEFINITION = RoomDefinition(
    room_id="red-20-red-team-capstone",
    room_number=20,
    track=TrackEnum.RED,
    title="Red Team Capstone",
    short_description="Conduct a full-spectrum authorized penetration assessment against VoltDefense Systems, chaining perimeter discovery, foothold compromise, privilege escalation, and formal reporting.",
    difficulty="Advanced",
    estimated_duration="60 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_20_CONCEPT,
    tasks=ROOM_20_TASKS,
    learning_objectives=[
        "Validate engagement scope, Rules of Engagement (ROE), and emergency halt procedures",
        "Perform multi-service perimeter reconnaissance and attack surface discovery",
        "Execute controlled initial foothold compromise against exposed enterprise endpoints",
        "Conduct internal privilege escalation from an unprivileged service account to root",
        "Compile and submit a structured, professional penetration testing assessment report",
        "Validate complete defense-in-depth remediation and least-privilege system hardening",
    ],
    assessment_criteria=[
        "Verify authorized testing scope boundaries and emergency contact channels",
        "Map exposed services across the target infrastructure",
        "Execute controlled foothold exploit to acquire internal operator access",
        "Escalate privileges to root and breach the internal system vault",
        "Submit formal penetration assessment findings with risk-rated remediation roadmaps",
        "Pass the 5-question comprehensive Red Team Capstone technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)
