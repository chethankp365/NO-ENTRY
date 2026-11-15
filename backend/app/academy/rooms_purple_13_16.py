"""
NO ENTRY Academy - Purple Team Track: Practical Rooms 13–16 Definitions

Rooms:
- Room 13: Supply Chain & Dependency Confusion Emulation (purple-13-supply-chain-emulation)
- Room 14: API Security & Broken Object Level Auth (BOLA) Emulation (purple-14-api-abuse-emulation)
- Room 15: Active Directory Attacks Emulation (Kerberoasting) (purple-15-active-directory-attacks-emulation)
- Room 16: CI/CD Pipeline & GitHub Actions Attack Emulation (purple-16-ci-cd-pipeline-emulation)
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
# ROOM 13: SUPPLY CHAIN & DEPENDENCY CONFUSION EMULATION
# ============================================================================

ROOM_PURPLE_13_CONCEPT = RoomConcept(
    overview=(
        "Software supply chain attacks compromise trusted build environments, dependencies, and deployment pipelines to "
        "inject malicious code downstream into production systems. In dependency confusion attacks (MITRE ATT&CK T1195.001), "
        "an adversary identifies internally referenced, unscoped package names in build configurations and registers an identically "
        "named package on public registries (e.g. PyPI, npm) with an artificially higher semantic version. Build managers "
        "defaulting to public feeds automatically download and execute the malicious upstream artifact. Purple Teaming evaluates "
        "registry feed resolution priority, private namespace scoping, and package hash verification to protect modern build systems."
    ),
    simple_analogy=(
        "Imagine a company orders custom proprietary machine parts from an internal on-campus workshop labeled 'volt-bolt-101'. "
        "If a contractor accidentally searches an unverified public commercial catalog instead of the internal supply room, "
        "and finds an external vendor offering 'volt-bolt-101' with 'version 99' priority, the factory inadvertently installs "
        "counterfeit parts into their core machinery because the inventory system trusted the highest version number."
    ),
    technical_term="Software Supply Chain Dependency Confusion & Package Typosquatting Emulation",
    technical_definition=(
        "The empirical simulation of dependency substitution (MITRE ATT&CK T1195.001) where public registry namespace hijacking "
        "exploits build configuration resolution flaws, evaluated through Software Bill of Materials (SBOM) generation, artifact "
        "cryptographic hash pinning, and private registry scope enforcement."
    ),
    cybersecurity_context=(
        "Modern enterprise applications incorporate thousands of third-party open-source components. Adversaries leverage "
        "dependency confusion and typosquatting to bypass traditional perimeter firewalls, executing arbitrary installer code "
        "directly inside secure build runners and developer workstations."
    ),
    why_it_matters=(
        "A single compromised dependency can result in credential theft, source code leakage, and silent backdoor injection "
        "into enterprise customer software without triggering perimeter network alarms."
    ),
    demonstration=(
        "1. Inspect prepared CI/CD build manifests and package resolution logs containing simulated dependency queries.\n"
        "2. Identify the vulnerable, un-scoped internal package name targeted for substitution.\n"
        "3. Emulate a dependency confusion artifact upload against target port 8313 using the workstation supply chain tool.\n"
        "4. Deploy private namespace scope pinning and package checksum integrity verification rules.\n"
        "5. Complete the validation challenge to confirm that unverified public dependencies are blocked."
    ),
    remediation_guide=(
        "Scope private packages under enterprise-owned namespaces (e.g., @voltcorp/); configure build package managers to resolve "
        "internal scopes strictly against authenticated private artifact repositories (Nexus, Artifactory); reserve internal "
        "package names on public registries; and enforce immutable lockfiles with cryptographic SHA-512 integrity hashes."
    ),
)

ROOM_PURPLE_13_TASKS = [
    TaskDefinition(
        task_id="task-01-supply-chain-mechanics",
        order=1,
        title="Understand Dependency Confusion & Resolution Flaws",
        instructions=(
            "Review the technical overview for software supply chain security.\n\n"
            "Dependency confusion occurs when package managers (such as pip or npm) are configured to pull from both an internal "
            "private feed and a public repository. If an internal package name is not reserved on the public registry, an adversary "
            "can publish a package with the same name and a higher version number (e.g., version 99.0.0), causing the package manager "
            "to prioritize the public malicious artifact.\n\n"
            "Identify the technical term used for this attack vector where public package repositories are leveraged to hijack "
            "internal, identically named packages."
        ),
        task_type=TaskType.QUESTION,
        question="What term refers to the attack where public package registries are used to hijack un-scoped internal dependencies?",
        hint="It consists of two words starting with 'D' and 'C' (e.g., Dependency ...).",
        accepted_answers=["Dependency Confusion", "dependency confusion", "Dependency confusion"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-02-supply-chain-telemetry-analysis",
        order=2,
        title="Analyze Build Log & Dependency Resolution Telemetry",
        instructions=(
            "Inspect the prepared build dependency telemetry on your attacker workstation:\n"
            "`cat /var/log/supply_chain/build_dependency_events.json`\n\n"
            "Alternatively, retrieve the telemetry via the target service:\n"
            "`curl -s http://10.10.14.90:8313/api/supply-chain/telemetry`\n\n"
            "Analyze the resolution logs to determine the exact name of the internal private package targeted by the adversary "
            "for dependency substitution."
        ),
        task_type=TaskType.QUESTION,
        question="What is the exact internal package name targeted for substitution in the dependency resolution telemetry?",
        hint="Look for the package name with a public origin mismatch in the JSON events (e.g. voltcorp-internal-...).",
        accepted_answers=["voltcorp-internal-auth", "voltcorp-internal-auth.tar.gz", "voltcorp-internal-auth==99.0.0"],
        xp_reward=60,
    ),
    TaskDefinition(
        task_id="task-03-attck-supply-chain-mapping",
        order=3,
        title="Map Dependency Tampering to MITRE ATT&CK",
        instructions=(
            "Supply chain attacks are classified under the Initial Access tactic in the MITRE ATT&CK framework.\n\n"
            "Specifically, manipulating software dependencies and package managers to execute malicious installer hooks "
            "is cataloged under Supply Chain Compromise: Compromise Software Dependencies.\n\n"
            "Submit the MITRE ATT&CK technique sub-technique ID for Compromise Software Dependencies (e.g. T1195.001)."
        ),
        task_type=TaskType.QUESTION,
        question="What is the MITRE ATT&CK sub-technique ID for Compromise Software Dependencies?",
        hint="The format is T1195.001.",
        accepted_answers=["T1195.001", "t1195.001", "T1195.001 - Compromise Software Dependencies"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-04-supply-chain-emulation",
        order=4,
        title="Emulate Dependency Confusion & Version Precedence",
        instructions=(
            "Use the provided supply chain emulation tool to execute a simulated dependency confusion payload against the "
            "disposable lab service:\n"
            "`python3 /home/operator/tools/supply_chain_tool.py --emulate-confusion`\n\n"
            "This command simulates an upstream package publish with version 99.0.0 and verifies resolution precedence.\n"
            "Upon successful execution, the tool will output a verification token.\n"
            "Submit the verification token to validate practical emulation."
        ),
        task_type=TaskType.COMMAND,
        question="Run the supply chain emulation tool and submit the verification token.",
        hint="Execute 'python3 /home/operator/tools/supply_chain_tool.py --emulate-confusion' in the lab terminal.",
        accepted_answers=["SUPPLY_CHAIN_EMULATION_VERIFIED", "DEPENDENCY_CONFUSION_VERIFIED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-supply-chain-challenge",
        order=5,
        title="Enforce Scope Pinning & Validate Supply Chain Guardrails",
        instructions=(
            "To mitigate dependency confusion, defensive engineers configure repository managers to restrict resolution "
            "for internal scopes strictly to internal feeds, while enforcing SHA-256 package hash verification.\n\n"
            "1. Deploy scope pinning and hash verification using the tool:\n"
            "`python3 /home/operator/tools/supply_chain_tool.py --tune-pinning`\n\n"
            "2. Execute the validation challenge:\n"
            "`python3 /home/operator/tools/supply_chain_tool.py --challenge`\n\n"
            "Submit the returned verification token once scope pinning and hash verification are validated."
        ),
        task_type=TaskType.COMMAND,
        question="Deploy namespace scope pinning, execute the validation challenge, and submit the verification token.",
        hint="Run '--tune-pinning' followed by '--challenge' using the supply chain tool.",
        accepted_answers=["SUPPLY_CHAIN_DETECTION_VALIDATED", "SUPPLY_CHAIN_GUARDRAIL_VALIDATED"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-supply-chain-quiz",
        order=6,
        title="Assess Technical Understanding of Supply Chain Security",
        instructions="Complete the 4-question technical assessment on dependency confusion, namespaces, and SBOM controls.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is the primary root cause of dependency confusion attacks?",
                options=[
                    "Package managers defaulting to the highest version number across multiple untrusted repositories",
                    "SQL injection inside the public package registry database",
                    "Missing TLS certificates on enterprise web proxy gateways",
                    "Failure to use multi-factor authentication on developer laptops",
                ],
                correct_index=0,
                explanation="Dependency confusion relies on package managers picking the highest semantic version across configured repositories when no namespace scoping is enforced.",
            ),
            QuizQuestion(
                id="q2",
                question="Which defensive control best prevents dependency confusion for proprietary packages?",
                options=[
                    "Scoping internal packages under enterprise namespaces and locking resolution to private feeds",
                    "Renaming internal Python files to random numeric identifiers",
                    "Disabling all outbound HTTPS traffic on developer workstations",
                    "Using MD5 hashing on source code files before committing to Git",
                ],
                correct_index=0,
                explanation="Enforcing scoped namespaces (e.g., @company/package) and configuring build clients to resolve those scopes exclusively from private registries eliminates the risk.",
            ),
            QuizQuestion(
                id="q3",
                question="What standard document format details all components, libraries, and dependencies within a build?",
                options=[
                    "Software Bill of Materials (SBOM)",
                    "Certificate Revocation List (CRL)",
                    "Domain Name System Security Extensions (DNSSEC)",
                    "Simple Network Management Protocol MIB (SNMP-MIB)",
                ],
                correct_index=0,
                explanation="An SBOM provides a formal machine-readable inventory of software components and their dependency tree.",
            ),
            QuizQuestion(
                id="q4",
                question="Why is package cryptographic hash pinning (e.g. in requirements.txt or package-lock.json) critical?",
                options=[
                    "It ensures that downloaded packages match the exact byte-for-byte content approved by developers",
                    "It automatically encrypts application traffic between client and server",
                    "It prevents attackers from viewing the application source code in GitHub",
                    "It eliminates the need for software code reviews",
                ],
                correct_index=0,
                explanation="Hash pinning guarantees that a package cannot be silently modified or substituted upstream without triggering a checksum mismatch error.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_13_DEFINITION = RoomDefinition(
    room_id="purple-13-supply-chain-emulation",
    track=TrackEnum.PURPLE,
    room_number=13,
    title="Supply Chain & Dependency Confusion Emulation",
    short_description="Simulate package typosquatting and internal package repository hijacking in a sandbox pipeline.",
    difficulty="Advanced",
    estimated_duration="65 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_PURPLE_13_CONCEPT,
    tasks=ROOM_PURPLE_13_TASKS,
    total_xp=350,
    target_app_type="fastapi",
    default_port=8313,
    learning_objectives=[
        "Analyze software supply chain vulnerabilities, dependency resolution mechanics, and package typosquatting risks.",
        "Inspect build dependency resolution telemetry to detect unauthorized upstream package substitution attempts.",
        "Emulate a dependency confusion attack against an internal build pipeline in an isolated testbed.",
        "Deploy private namespace scoping, repository resolution pinning, and cryptographic checksum validation.",
        "Assess mitigation effectiveness using MITRE ATT&CK T1195.001 mapping and SBOM verification.",
    ],
    assessment_criteria=[
        "Identify the root cause of dependency confusion and package manager resolution priority.",
        "Discover targeted un-scoped internal dependencies in prepared build telemetry logs.",
        "Successfully emulate dependency substitution using the CLI supply chain tool.",
        "Deploy private registry scope enforcement and achieve validation token confirmation.",
        "Attain 100% on the supply chain security assessment quiz.",
    ],
    completion_requirements=[
        "Submit correct technical answers for dependency confusion mechanics and telemetry analysis.",
        "Execute genuine practical emulation and defense tuning commands inside the lab runner.",
        "Validate backend-authoritative challenge tokens bound to the active session.",
        "Pass the technical assessment quiz.",
    ],
)


# ============================================================================
# ROOM 14: API SECURITY & BROKEN OBJECT LEVEL AUTH (BOLA) EMULATION
# ============================================================================

ROOM_PURPLE_14_CONCEPT = RoomConcept(
    overview=(
        "Application Programming Interfaces (APIs) form the backbone of modern web, mobile, and cloud architectures. Broken "
        "Object Level Authorization (BOLA), also known as Insecure Direct Object References (IDOR), consistently ranks as the "
        "#1 vulnerability in the OWASP API Security Top 10. BOLA occurs when an API endpoint takes an object identifier "
        "(such as an account number, user ID, or document UUID) from client input and retrieves the corresponding resource "
        "without verifying whether the authenticated user possesses legitimate authorization to access that specific object. "
        "Purple Teaming emulates parameter manipulation across API calls and evaluates whether WAFs, API gateways, and application "
        "RBAC layers successfully block unauthorized cross-tenant object access."
    ),
    simple_analogy=(
        "Imagine a hotel keycard system where every guest is handed a keycard with their room number printed on the magnetic stripe. "
        "If a guest in Room 101 can reprogram the number on their card to Room 102 and the door reader unlocks without checking "
        "the front-desk guest registry, the hotel suffers from Broken Object Level Authorization: the reader authenticated that "
        "a card existed, but failed to verify if the cardholder was authorized for that specific room."
    ),
    technical_term="API Broken Object Level Authorization (BOLA/IDOR) & RBAC Validation Emulation",
    technical_definition=(
        "The systematic security testing of API endpoints where resource identifiers passed in URLs or request payloads "
        "(MITRE ATT&CK T1190) are altered to access unauthorized data objects, evaluated through API gateway policy enforcement, "
        "context-aware object authorization filters, and anomalous traversal telemetry detection."
    ),
    cybersecurity_context=(
        "Because APIs are designed for automated machine-to-machine consumption, adversaries script high-speed enumeration "
        "attacks altering numerical or predictable object IDs to bulk-scrape confidential customer data, financial records, "
        "and internal documents."
    ),
    why_it_matters=(
        "Unlike memory corruption or SQL injection, BOLA vulnerabilities stem from flawed business logic. Traditional network "
        "firewalls and signature-based WAFs cannot detect BOLA because the HTTP requests appear syntactically valid."
    ),
    demonstration=(
        "1. Inspect API gateway access logs containing client requests targeting user account endpoints.\n"
        "2. Identify unauthorized parameter manipulation targeting account records belonging to another tenant.\n"
        "3. Emulate a live BOLA horizontal privilege escalation attack against target port 8314.\n"
        "4. Deploy context-aware object authorization validation and rate-limiting rules at the API layer.\n"
        "5. Complete the validation challenge to confirm that unauthorized cross-object requests are rejected."
    ),
    remediation_guide=(
        "Implement strict object-level authorization checks in code verifying that the authenticated session principal owns the "
        "requested object; replace sequential integers with cryptographically random UUIDv4 identifiers; and deploy API gateways "
        "that enforce contextual attribute-based access control (ABAC)."
    ),
)

ROOM_PURPLE_14_TASKS = [
    TaskDefinition(
        task_id="task-01-bola-mechanics",
        order=1,
        title="Understand Broken Object Level Authorization (BOLA)",
        instructions=(
            "Review the technical overview for API security.\n\n"
            "In modern RESTful APIs, resources are frequently referenced by ID in the path (e.g. `/api/v1/users/{id}/profile`). "
            "When an application verifies that the user is logged in (Authentication), but fails to verify whether the logged-in user "
            "has permission to view or edit the specific `{id}` requested, an adversary can simply change the ID to access other users' data.\n\n"
            "Identify the standard 4-letter acronym used in the OWASP API Security Top 10 for Broken Object Level Authorization."
        ),
        task_type=TaskType.QUESTION,
        question="What 4-letter acronym designates Broken Object Level Authorization in the OWASP API Security Top 10?",
        hint="It starts with 'B' and ends with 'A' (Broken Object Level Authorization).",
        accepted_answers=["BOLA", "bola", "IDOR", "idor"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-02-api-telemetry-analysis",
        order=2,
        title="Analyze API Access Telemetry for BOLA Indicators",
        instructions=(
            "Inspect the prepared API access log on your attacker workstation:\n"
            "`cat /var/log/api_abuse/api_access_events.json`\n\n"
            "Alternatively, query the telemetry endpoint:\n"
            "`curl -s http://10.10.14.90:8314/api/api-abuse/telemetry`\n\n"
            "Identify the specific account ID (e.g. ACC-...) that was targeted by the adversary using unauthorized parameter tampering."
        ),
        task_type=TaskType.QUESTION,
        question="What account ID was targeted by the unauthorized parameter manipulation in the API telemetry?",
        hint="Look for the 'target_account_id' or 'requested_resource' in the JSON telemetry (e.g. ACC-9...).",
        accepted_answers=["ACC-9042", "acc-9042", "ACC-9042-PROD"],
        xp_reward=60,
    ),
    TaskDefinition(
        task_id="task-03-attck-api-mapping",
        order=3,
        title="Map API Exploitation to MITRE ATT&CK",
        instructions=(
            "Attacking web APIs to exploit authorization logic flaws and access sensitive backend records targets external "
            "application interfaces.\n\n"
            "In the MITRE ATT&CK matrix, targeting vulnerabilities in public-facing web applications and APIs falls under the "
            "Initial Access tactic.\n\n"
            "Submit the MITRE ATT&CK technique ID for Exploit Public-Facing Application (e.g. T1190)."
        ),
        task_type=TaskType.QUESTION,
        question="What is the MITRE ATT&CK technique ID for Exploit Public-Facing Application?",
        hint="The format is T1190.",
        accepted_answers=["T1190", "t1190", "T1190 - Exploit Public-Facing Application"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-04-bola-emulation",
        order=4,
        title="Emulate BOLA Parameter Tampering Across Tenants",
        instructions=(
            "Execute a controlled BOLA emulation test using the provided API abuse tool:\n"
            "`python3 /home/operator/tools/api_abuse_tool.py --emulate-bola`\n\n"
            "This command issues authenticated requests with modified object identifiers to test whether cross-tenant record "
            "retrieval succeeds.\n"
            "Submit the returned verification token to record task completion."
        ),
        task_type=TaskType.COMMAND,
        question="Run the BOLA emulation tool and submit the verification token.",
        hint="Execute 'python3 /home/operator/tools/api_abuse_tool.py --emulate-bola' in the terminal.",
        accepted_answers=["BOLA_EMULATION_VERIFIED", "API_TAMPERING_VERIFIED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-api-detection-challenge",
        order=5,
        title="Tune Gateway Authorization & Complete Challenge",
        instructions=(
            "Remediate the vulnerability and validate defense enforcement:\n"
            "1. Deploy context-aware object validation and anomalous request detection at the API Gateway layer:\n"
            "`python3 /home/operator/tools/api_abuse_tool.py --tune-gateway`\n\n"
            "2. Execute the validation challenge:\n"
            "`python3 /home/operator/tools/api_abuse_tool.py --challenge`\n\n"
            "Submit the resulting verification token once defensive enforcement is confirmed."
        ),
        task_type=TaskType.COMMAND,
        question="Deploy API gateway validation rules, complete the challenge, and submit the verification token.",
        hint="Run '--tune-gateway' followed by '--challenge' using the API abuse tool.",
        accepted_answers=["API_ABUSE_DETECTION_VALIDATED", "BOLA_DEFENSE_VALIDATED"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-api-quiz",
        order=6,
        title="Assess Technical Understanding of API Security",
        instructions="Complete the 4-question technical assessment on BOLA/IDOR, authorization logic, and API gateway controls.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why can traditional signature-based Web Application Firewalls (WAFs) fail to detect BOLA attacks?",
                options=[
                    "Because BOLA requests use completely valid HTTP syntax and legitimate parameters without malicious payloads",
                    "Because WAFs cannot inspect traffic transmitted over HTTPS",
                    "Because BOLA attacks only occur over raw UDP protocols",
                    "Because WAFs only protect against physical network disconnection",
                ],
                correct_index=0,
                explanation="BOLA is a business logic flaw: the HTTP syntax is normal, so signatures looking for SQL injection or XSS strings do not trigger.",
            ),
            QuizQuestion(
                id="q2",
                question="What is the difference between Authentication and Object-Level Authorization?",
                options=[
                    "Authentication verifies who you are; Object-Level Authorization verifies if you have permission to access a specific resource",
                    "Authentication encrypts passwords; Authorization deletes old user accounts",
                    "Authentication runs in the browser; Authorization runs on DNS servers",
                    "There is no difference; the two terms are synonymous in cybersecurity",
                ],
                correct_index=0,
                explanation="Authentication establishes identity; Object-Level Authorization verifies that the authenticated user owns or has legitimate access to the specific data object requested.",
            ),
            QuizQuestion(
                id="q3",
                question="Why is using sequential integers (e.g. /users/1, /users/2) in API endpoints dangerous?",
                options=[
                    "It allows adversaries to easily enumerate and scrape every user record sequentially",
                    "It causes memory corruption inside the API gateway router",
                    "It prevents the server from supporting JSON data format",
                    "It automatically reveals database passwords in HTTP error messages",
                ],
                correct_index=0,
                explanation="Sequential IDs are predictable and trivial to iterate over using simple automated scripts.",
            ),
            QuizQuestion(
                id="q4",
                question="Which architecture pattern provides the strongest defense against BOLA vulnerabilities?",
                options=[
                    "Centralized object authorization checks validating session user ID against object owner ID on every request",
                    "Obfuscating API parameter names using Base64 encoding",
                    "Increasing the web server timeout from 30 seconds to 60 seconds",
                    "Hiding API documentation from external developers",
                ],
                correct_index=0,
                explanation="Enforcing explicit ownership validation checks in data access layers ensures that requests are only fulfilled when the session owner matches the resource owner.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_14_DEFINITION = RoomDefinition(
    room_id="purple-14-api-abuse-emulation",
    track=TrackEnum.PURPLE,
    room_number=14,
    title="API Security & Broken Object Level Auth (BOLA) Emulation",
    short_description="Emulate API parameter tampering and test WAF/API gateway anomaly detection triggers.",
    difficulty="Intermediate",
    estimated_duration="50 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_PURPLE_14_CONCEPT,
    tasks=ROOM_PURPLE_14_TASKS,
    total_xp=350,
    target_app_type="fastapi",
    default_port=8314,
    learning_objectives=[
        "Master the mechanics of Broken Object Level Authorization (BOLA/IDOR) in REST APIs.",
        "Analyze API gateway telemetry to identify parameter manipulation and horizontal privilege escalation.",
        "Emulate unauthorized cross-tenant object access in a safe, isolated API environment.",
        "Deploy context-aware object authorization filters and anomaly detection policies.",
        "Evaluate defensive visibility and logging efficacy using MITRE ATT&CK T1190 mapping.",
    ],
    assessment_criteria=[
        "Differentiate authentication from object-level authorization.",
        "Identify targeted resource identifiers in API request telemetry.",
        "Successfully execute BOLA emulation using the CLI API abuse tool.",
        "Deploy gateway authorization guardrails and complete verification.",
        "Attain 100% on the API security assessment quiz.",
    ],
    completion_requirements=[
        "Submit correct technical answers for BOLA mechanics and telemetry analysis.",
        "Execute genuine practical emulation and defense tuning commands inside the lab runner.",
        "Validate backend-authoritative challenge tokens bound to the active session.",
        "Pass the technical assessment quiz.",
    ],
)


# ============================================================================
# ROOM 15: ACTIVE DIRECTORY ATTACKS EMULATION (KERBEROASTING)
# ============================================================================

ROOM_PURPLE_15_CONCEPT = RoomConcept(
    overview=(
        "Active Directory (AD) serves as the identity and access management backbone of enterprise networks. Kerberos is the "
        "primary authentication protocol in AD environments. In a Kerberoasting attack (MITRE ATT&CK T1558.003), any valid domain "
        "user—regardless of privileges—can request a Kerberos Ticket Granting Service (TGS) ticket for any service account that has "
        "a Service Principal Name (SPN) registered. The returned ticket is encrypted using the password hash of the service account. "
        "Adversaries extract these tickets from memory, exfiltrate them, and crack them offline using tools like Hashcat without "
        "sending further network traffic. Purple Teaming evaluates Domain Controller telemetry (Windows Event ID 4769), legacy "
        "RC4 encryption detection, and automated alerting on mass SPN ticket requests."
    ),
    simple_analogy=(
        "Imagine an office building where any employee can visit the front desk and request a sealed, wax-stamped envelope containing "
        "a voucher for the cafeteria supervisor. The receptionist hands over the envelope without question because employees are "
        "allowed to ask for vouchers. The employee then takes the envelope home and uses chemical solutions to read through the wax "
        "seal at their leisure, discovering the supervisor's private safe combination hidden inside."
    ),
    technical_term="Active Directory Kerberoasting Service Ticket Request Emulation",
    technical_definition=(
        "The controlled execution of Kerberos TGS ticket acquisition (MITRE ATT&CK T1558.003) for domain accounts registered with "
        "Service Principal Names (SPNs), evaluated through Windows Security Event Log ID 4769 audit trails, encryption downgrade "
        "identification (RC4-HMAC vs AES-256), and service account password strength hardening."
    ),
    cybersecurity_context=(
        "Kerberoasting is one of the most reliable privilege escalation techniques in Active Directory because it abuses legitimate "
        "Kerberos protocol design. It requires zero elevated privileges and leaves minimal network footprint on the target host, "
        "making Domain Controller event log monitoring the only reliable detection point."
    ),
    why_it_matters=(
        "Service accounts often possess elevated domain privileges (Domain Admins or local administrator rights across entire server "
        "fleets). Compromising a single service account via Kerberoasting frequently leads to full domain compromise."
    ),
    demonstration=(
        "1. Inspect prepared Domain Controller Kerberos audit telemetry containing Event ID 4769 entries.\n"
        "2. Identify anomalous TGS requests requesting weak RC4 ticket encryption.\n"
        "3. Emulate a controlled Kerberoasting SPN ticket request against target port 8315.\n"
        "4. Deploy a SIEM correlation rule detecting anomalous Kerberos ticket requests with RC4 encryption.\n"
        "5. Complete the validation challenge to confirm detection and remediation efficacy."
    ),
    remediation_guide=(
        "Migrate standard service accounts to Group Managed Service Accounts (gMSA) with automated 120-character random passwords; "
        "enforce AES-256 Kerberos encryption and disable legacy RC4-HMAC; enforce strong 25+ character passwords for legacy service accounts; "
        "and alert on bursts of Event ID 4769 with Ticket Encryption Type 0x17."
    ),
)

ROOM_PURPLE_15_TASKS = [
    TaskDefinition(
        task_id="task-01-kerberoasting-mechanics",
        order=1,
        title="Understand Kerberoasting & Service Principal Names (SPNs)",
        instructions=(
            "Review the technical overview for Active Directory Kerberos security.\n\n"
            "In Active Directory, when an application runs under a domain account, administrators associate an identifier with that "
            "account so clients can request Kerberos tickets to access it. Any authenticated domain user can query Active Directory "
            "for accounts that have this attribute configured, and subsequently request a ticket encrypted with that account's password hash.\n\n"
            "What 3-letter acronym designates the Service Principal Name attribute in Active Directory?"
        ),
        task_type=TaskType.QUESTION,
        question="What 3-letter acronym represents the Service Principal Name attribute in Active Directory?",
        hint="It starts with 'S' and stands for Service Principal Name.",
        accepted_answers=["SPN", "spn", "Service Principal Name", "SPNs"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-02-ad-telemetry-analysis",
        order=2,
        title="Analyze Domain Controller Event ID 4769 Telemetry",
        instructions=(
            "Inspect the prepared Domain Controller Kerberos audit log on your attacker workstation:\n"
            "`cat /var/log/ad_attacks/kerberos_audit_events.json`\n\n"
            "Alternatively, retrieve the telemetry via the target service:\n"
            "`curl -s http://10.10.14.90:8315/api/ad-attacks/telemetry`\n\n"
            "Examine the Event ID 4769 records. Identify the hexadecimal encryption type code (e.g. 0x...) representing legacy "
            "RC4-HMAC encryption requested by the adversary."
        ),
        task_type=TaskType.QUESTION,
        question="What hexadecimal encryption type code in the Event ID 4769 telemetry indicates legacy RC4-HMAC encryption?",
        hint="RC4-HMAC is represented in Windows Kerberos logs as 0x17.",
        accepted_answers=["0x17", "0X17", "0x17 (RC4-HMAC)", "0x17 RC4"],
        xp_reward=60,
    ),
    TaskDefinition(
        task_id="task-03-attck-ad-mapping",
        order=3,
        title="Map Kerberoasting to MITRE ATT&CK",
        instructions=(
            "Kerberoasting is classified under the Credential Access tactic in the MITRE ATT&CK framework.\n\n"
            "Under the primary technique 'Steal or Forge Kerberos Tickets', Kerberoasting has a specific sub-technique identifier.\n\n"
            "Submit the MITRE ATT&CK sub-technique ID for Kerberoasting (e.g. T1558.003)."
        ),
        task_type=TaskType.QUESTION,
        question="What is the MITRE ATT&CK sub-technique ID for Kerberoasting?",
        hint="The format is T1558.003.",
        accepted_answers=["T1558.003", "t1558.003", "T1558.003 - Kerberoasting"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-04-kerberoasting-emulation",
        order=4,
        title="Emulate Kerberos TGS Ticket Acquisition",
        instructions=(
            "Execute a simulated Kerberoasting attack using the provided Active Directory tool:\n"
            "`python3 /home/operator/tools/ad_attacks_tool.py --emulate-kerberoast`\n\n"
            "This command simulates querying the Domain Controller for registered SPNs and requesting a service ticket for "
            "offline password cracking.\n"
            "Submit the returned verification token to record completion."
        ),
        task_type=TaskType.COMMAND,
        question="Run the AD attack tool to emulate Kerberoasting and submit the verification token.",
        hint="Execute 'python3 /home/operator/tools/ad_attacks_tool.py --emulate-kerberoast' in the terminal.",
        accepted_answers=["KERBEROASTING_EMULATION_VERIFIED", "KERBEROAST_TGS_EXTRACTED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-ad-detection-challenge",
        order=5,
        title="Deploy DC Correlation Rule & Complete Challenge",
        instructions=(
            "Configure defensive detection and validate readiness:\n"
            "1. Deploy a Domain Controller SIEM correlation rule detecting anomalous Event ID 4769 ticket requests with RC4 encryption:\n"
            "`python3 /home/operator/tools/ad_attacks_tool.py --tune-dc-rule`\n\n"
            "2. Complete the validation challenge:\n"
            "`python3 /home/operator/tools/ad_attacks_tool.py --challenge`\n\n"
            "Submit the resulting verification token once the defensive rule is validated."
        ),
        task_type=TaskType.COMMAND,
        question="Deploy DC Kerberos detection rules, execute the validation challenge, and submit the verification token.",
        hint="Run '--tune-dc-rule' followed by '--challenge' using the AD attacks tool.",
        accepted_answers=["AD_ATTACK_DETECTION_VALIDATED", "KERBEROASTING_DEFENSE_VALIDATED"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-ad-quiz",
        order=6,
        title="Assess Technical Understanding of Active Directory Security",
        instructions="Complete the 4-question technical assessment on Kerberoasting, SPNs, and Domain Controller auditing.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why can any standard domain user execute a Kerberoasting attack without administrative rights?",
                options=[
                    "Because Kerberos protocol design requires the Domain Controller to grant tickets for any valid SPN to any authenticated user",
                    "Because all domain users have read access to the Domain Controller's SAM database",
                    "Because standard users can remotely execute PowerShell as SYSTEM on Domain Controllers",
                    "Because Kerberos tickets are transmitted in plaintext over UDP port 53",
                ],
                correct_index=0,
                explanation="Active Directory allows any authenticated domain user to request a ticket for any service so legitimate applications can authenticate seamlessly.",
            ),
            QuizQuestion(
                id="q2",
                question="Which Windows Security Event Log Event ID records Kerberos ticket-granting service (TGS) requests?",
                options=[
                    "Event ID 4769",
                    "Event ID 4624",
                    "Event ID 7045",
                    "Event ID 1102",
                ],
                correct_index=0,
                explanation="Event ID 4769 ('A Kerberos service ticket was requested') logs all TGS ticket requests on Domain Controllers.",
            ),
            QuizQuestion(
                id="q3",
                question="Why is Group Managed Service Accounts (gMSA) the premier defense against Kerberoasting?",
                options=[
                    "gMSAs automatically rotate complex 120-character passwords that are mathematically infeasible to crack offline",
                    "gMSAs disable the Kerberos protocol entirely and switch to NTLMv1",
                    "gMSAs prevent users from logging into their desktop computers",
                    "gMSAs encrypt network traffic using DES 56-bit encryption",
                ],
                correct_index=0,
                explanation="gMSAs generate complex, random 120-character passwords that Active Directory manages and rotates automatically, defeating offline dictionary and brute-force cracking.",
            ),
            QuizQuestion(
                id="q4",
                question="Why do adversaries prefer requesting tickets with encryption type 0x17 (RC4-HMAC) over 0x12 (AES-256)?",
                options=[
                    "RC4-HMAC is significantly faster to crack offline using GPU clusters than modern AES algorithms",
                    "RC4-HMAC tickets contain cleartext plaintext passwords",
                    "AES-256 tickets automatically trigger Windows Defender alert popups",
                    "0x17 encryption is the only format supported by Domain Controllers",
                ],
                correct_index=0,
                explanation="RC4-HMAC hashing is computationally much simpler, allowing offline cracking tools like Hashcat to test billions of password candidates per second compared to computationally heavy AES.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_15_DEFINITION = RoomDefinition(
    room_id="purple-15-active-directory-attacks-emulation",
    track=TrackEnum.PURPLE,
    room_number=15,
    title="Active Directory Attacks Emulation (Kerberoasting)",
    short_description="Execute Kerberoasting, AS-REP roasting, and evaluate domain controller event telemetry.",
    difficulty="Intermediate",
    estimated_duration="60 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_PURPLE_15_CONCEPT,
    tasks=ROOM_PURPLE_15_TASKS,
    total_xp=350,
    target_app_type="fastapi",
    default_port=8315,
    learning_objectives=[
        "Understand Active Directory Kerberos authentication, SPN registrations, and Kerberoasting mechanics.",
        "Analyze Domain Controller Windows Security Event Log 4769 telemetry to detect anomalous ticket requests.",
        "Emulate controlled Kerberos TGS ticket acquisition and encryption downgrade identification.",
        "Deploy SIEM detection rules targeting bursts of RC4-HMAC ticket requests on Domain Controllers.",
        "Assess mitigation strategies including Group Managed Service Accounts (gMSA) and AES-256 enforcement.",
    ],
    assessment_criteria=[
        "Explain the role of Service Principal Names in Kerberoasting attacks.",
        "Identify anomalous encryption types (0x17) in Event ID 4769 audit telemetry.",
        "Successfully execute Kerberoasting emulation using the CLI AD attacks tool.",
        "Deploy Domain Controller SIEM correlation rules and validate defense status.",
        "Attain 100% on the Active Directory security assessment quiz.",
    ],
    completion_requirements=[
        "Submit correct technical answers for Kerberoasting mechanics and telemetry analysis.",
        "Execute genuine practical emulation and defense tuning commands inside the lab runner.",
        "Validate backend-authoritative challenge tokens bound to the active session.",
        "Pass the technical assessment quiz.",
    ],
)


# ============================================================================
# ROOM 16: CI/CD PIPELINE & GITHUB ACTIONS ATTACK EMULATION
# ============================================================================

ROOM_PURPLE_16_CONCEPT = RoomConcept(
    overview=(
        "Continuous Integration and Continuous Deployment (CI/CD) pipelines automate building, testing, and shipping code. Modern "
        "pipeline engines (such as GitHub Actions, GitLab CI, and Jenkins) operate with high-privilege access tokens, cloud "
        "deployment credentials, and production release permissions. Adversaries target vulnerable workflow trigger configurations "
        "(such as `pull_request_target` in GitHub Actions) to run untrusted code from forked repositories inside the context of the "
        "base repository, exfiltrating encrypted secrets (`GITHUB_TOKEN`, cloud API keys, signing certificates) or poisoning release "
        "artifacts (MITRE ATT&CK T1195.002). Purple Teaming emulates pipeline injection, evaluates audit webhook telemetry, and "
        "deploys OpenID Connect (OIDC) identity federation and pipeline step isolation."
    ),
    simple_analogy=(
        "Imagine an automated automated mail sorting machine inside a corporate headquarters that scans incoming customer envelopes. "
        "If the machine has a rule saying 'automatically open any package labeled urgent and run the executable code inside using "
        "the CEO's master executive access badge', an outside attacker can mail an envelope that tells the machine to photocopy all "
        "executive safe keys and fax them to an external number."
    ),
    technical_term="CI/CD Pipeline Workflow Poisoning & Secret Exfiltration Emulation",
    technical_definition=(
        "The empirical simulation of automated CI/CD pipeline subversion (MITRE ATT&CK T1195.002 & T1552) exploiting untrusted "
        "trigger contexts (`pull_request_target`), evaluated through runner audit telemetry, secret masking verification, and "
        "OpenID Connect (OIDC) short-lived token enforcement."
    ),
    cybersecurity_context=(
        "DevOps pipelines are prime targets for sophisticated threat actors (e.g. SolarWinds, Codecov). Compromising the build "
        "pipeline provides adversaries with signed, trusted distribution channels to deliver malware directly to end users."
    ),
    why_it_matters=(
        "Pipelines frequently hold long-lived static secrets with administrative cloud permissions. If an adversary compromises "
        "the runner, they inherit those cloud credentials, pivoting directly into production infrastructure."
    ),
    demonstration=(
        "1. Inspect prepared GitHub Actions workflow execution logs containing simulated pipeline runs.\n"
        "2. Identify the exfiltrated cloud deployment secret key exposed through an insecure workflow step.\n"
        "3. Emulate a pipeline attack extracting environment variables against target port 8316.\n"
        "4. Deploy pipeline secret masking and OIDC short-lived credential exchange policies.\n"
        "5. Complete the validation challenge to confirm pipeline hardening."
    ),
    remediation_guide=(
        "Avoid using `pull_request_target` with untrusted PR checkouts; adopt OpenID Connect (OIDC) to eliminate long-lived static "
        "AWS/Azure credentials; enforce explicit minimal permissions on `GITHUB_TOKEN`; run builds on ephemeral, single-use container "
        "runners; and implement required review approvals for any workflow modifications."
    ),
)

ROOM_PURPLE_16_TASKS = [
    TaskDefinition(
        task_id="task-01-cicd-mechanics",
        order=1,
        title="Understand CI/CD Workflow Triggers & Fork Abuse",
        instructions=(
            "Review the technical overview for CI/CD pipeline security.\n\n"
            "In GitHub Actions, the standard `pull_request` trigger runs with read-only permissions and no access to repository secrets "
            "when handling pull requests from forks. However, workflows configured with a specific privileged trigger run in the context "
            "of the base repository with full access to secrets, creating severe vulnerabilities if they checkout and run untrusted fork code.\n\n"
            "Identify the GitHub Actions trigger event that grants access to base repository secrets during pull request workflows."
        ),
        task_type=TaskType.QUESTION,
        question="Which GitHub Actions trigger event runs with base repository permissions and access to secrets?",
        hint="It is named 'pull_request_target'.",
        accepted_answers=["pull_request_target", "pull_request_target event", "pull_request_target:"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-02-cicd-telemetry-analysis",
        order=2,
        title="Analyze Workflow Run Audit Logs for Leaked Secrets",
        instructions=(
            "Inspect the prepared workflow execution log on your attacker workstation:\n"
            "`cat /var/log/cicd/workflow_run_events.json`\n\n"
            "Alternatively, retrieve the telemetry via the target service:\n"
            "`curl -s http://10.10.14.90:8316/api/cicd/telemetry`\n\n"
            "Identify the exact name of the cloud credential secret variable (e.g. DEPLOY_...) that was exfiltrated during the compromised workflow run."
        ),
        task_type=TaskType.QUESTION,
        question="What is the name of the cloud secret environment variable exfiltrated in the workflow run telemetry?",
        hint="Look for the environment variable name in the JSON log (e.g. DEPLOY_AWS_...).",
        accepted_answers=["DEPLOY_AWS_SECRET_KEY", "deploy_aws_secret_key", "DEPLOY_AWS_SECRET_KEY_PROD"],
        xp_reward=60,
    ),
    TaskDefinition(
        task_id="task-03-attck-cicd-mapping",
        order=3,
        title="Map CI/CD Pipeline Attacks to MITRE ATT&CK",
        instructions=(
            "Compromising deployment pipelines and continuous integration infrastructure to inject malicious code or steal secrets "
            "falls under the Supply Chain Compromise technique in the MITRE ATT&CK matrix.\n\n"
            "Specifically, subverting the software development environment or build process is cataloged under Compromise Software Supply Chain.\n\n"
            "Submit the MITRE ATT&CK sub-technique ID for Compromise Software Supply Chain (e.g. T1195.002)."
        ),
        task_type=TaskType.QUESTION,
        question="What is the MITRE ATT&CK sub-technique ID for Compromise Software Supply Chain?",
        hint="The format is T1195.002.",
        accepted_answers=["T1195.002", "t1195.002", "T1195.002 - Compromise Software Supply Chain"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-04-cicd-emulation",
        order=4,
        title="Emulate CI/CD Secret Extraction from Workflow",
        instructions=(
            "Execute a controlled CI/CD pipeline secret extraction simulation using the provided pipeline tool:\n"
            "`python3 /home/operator/tools/cicd_pipeline_tool.py --emulate-pipeline-attack`\n\n"
            "This command simulates executing untrusted script commands inside a workflow runner to dump environment variables.\n"
            "Submit the returned verification token to record completion."
        ),
        task_type=TaskType.COMMAND,
        question="Run the CI/CD pipeline tool to emulate secret exfiltration and submit the verification token.",
        hint="Execute 'python3 /home/operator/tools/cicd_pipeline_tool.py --emulate-pipeline-attack' in the terminal.",
        accepted_answers=["CICD_PIPELINE_EMULATION_VERIFIED", "WORKFLOW_SECRET_EXFIL_VERIFIED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-cicd-detection-challenge",
        order=5,
        title="Deploy OIDC Policies & Complete Challenge",
        instructions=(
            "Configure defensive controls to harden the pipeline:\n"
            "1. Deploy OpenID Connect (OIDC) short-lived token policies and pipeline secret masking:\n"
            "`python3 /home/operator/tools/cicd_pipeline_tool.py --tune-pipeline-audit`\n\n"
            "2. Complete the validation challenge:\n"
            "`python3 /home/operator/tools/cicd_pipeline_tool.py --challenge`\n\n"
            "Submit the resulting verification token once the defensive policy is validated."
        ),
        task_type=TaskType.COMMAND,
        question="Deploy pipeline audit rules and OIDC controls, complete the challenge, and submit the verification token.",
        hint="Run '--tune-pipeline-audit' followed by '--challenge' using the CI/CD pipeline tool.",
        accepted_answers=["CICD_PIPELINE_DETECTION_VALIDATED", "PIPELINE_HARDENED_VALIDATED"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-cicd-quiz",
        order=6,
        title="Assess Technical Understanding of CI/CD Pipeline Security",
        instructions="Complete the 4-question technical assessment on GitHub Actions, OIDC tokens, and pipeline isolation.",
        task_type=TaskType.QUIZ,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is OpenID Connect (OIDC) superior to storing static cloud access keys in CI/CD secrets?",
                options=[
                    "OIDC issues temporary, short-lived credentials scoped to specific repositories without storing static keys",
                    "OIDC completely disables user authentication to make builds run faster",
                    "OIDC encrypts all Git commits with SHA-1 hashing",
                    "OIDC eliminates the need for unit testing in the pipeline",
                ],
                correct_index=0,
                explanation="OIDC uses cryptographic identity tokens exchanged for short-lived cloud credentials (typically 15-60 minutes), eliminating persistent static secret keys that can leak.",
            ),
            QuizQuestion(
                id="q2",
                question="What security risk is created when combining `pull_request_target` with `actions/checkout` of the head ref?",
                options=[
                    "It allows an external attacker to execute arbitrary malicious code from their fork with access to repository secrets",
                    "It prevents the workflow from sending emails on build failure",
                    "It forces GitHub to charge extra billing minutes for the repository",
                    "It automatically creates a release tag in the Git repository",
                ],
                correct_index=0,
                explanation="Checking out the untrusted fork PR code while running under `pull_request_target` executes attacker-controlled code inside a runner that has full access to repository secrets.",
            ),
            QuizQuestion(
                id="q3",
                question="What is an 'ephemeral runner' in CI/CD environments?",
                options=[
                    "A single-use build runner created for one specific job and destroyed immediately after completion",
                    "A runner that runs continuously on a developer's desktop indefinitely",
                    "A runner that does not have internet access or network cards",
                    "A software testing tool that only tests CSS styling files",
                ],
                correct_index=0,
                explanation="Ephemeral runners ensure clean state isolation: any persistence or artifacts left by a malicious job are discarded when the runner container is destroyed.",
            ),
            QuizQuestion(
                id="q4",
                question="Which permission model should be applied by default to the `GITHUB_TOKEN` in workflow definitions?",
                options=[
                    "Principle of Least Privilege: read-all or individual explicit read permissions with write disabled by default",
                    "Full administrative permissions to all repository and organization assets",
                    "No permissions allowed whatsoever, preventing the repository from compiling code",
                    "Public anonymous read-write access to all branches",
                ],
                correct_index=0,
                explanation="Workflows should default to minimal read-only permissions and only request write permissions for specific scopes (e.g. `contents: read`, `issues: write`) where explicitly required.",
            ),
        ],
        xp_reward=40,
    ),
]

ROOM_PURPLE_16_DEFINITION = RoomDefinition(
    room_id="purple-16-ci-cd-pipeline-emulation",
    track=TrackEnum.PURPLE,
    room_number=16,
    title="CI/CD Pipeline & GitHub Actions Attack Emulation",
    short_description="Simulate secret exfiltration from continuous integration workflows and tune pipeline audit rules.",
    difficulty="Intermediate",
    estimated_duration="55 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_PURPLE_16_CONCEPT,
    tasks=ROOM_PURPLE_16_TASKS,
    total_xp=350,
    target_app_type="fastapi",
    default_port=8316,
    learning_objectives=[
        "Analyze modern CI/CD pipeline attack surfaces, workflow triggers, and runner execution contexts.",
        "Inspect workflow execution audit logs to detect secret exfiltration and unauthorized script injections.",
        "Emulate a pipeline secret extraction attack in a controlled sandbox environment.",
        "Deploy OpenID Connect (OIDC) identity federation and secret masking guardrails.",
        "Evaluate pipeline hardening and defense-in-depth using MITRE ATT&CK T1195.002 mapping.",
    ],
    assessment_criteria=[
        "Identify vulnerable GitHub Actions triggers including pull_request_target.",
        "Locate exfiltrated cloud credentials in CI/CD workflow telemetry.",
        "Successfully execute pipeline attack emulation using the CLI CI/CD tool.",
        "Deploy OIDC policies and achieve validation challenge token confirmation.",
        "Attain 100% on the CI/CD pipeline security assessment quiz.",
    ],
    completion_requirements=[
        "Submit correct technical answers for CI/CD mechanics and telemetry analysis.",
        "Execute genuine practical emulation and defense tuning commands inside the lab runner.",
        "Validate backend-authoritative challenge tokens bound to the active session.",
        "Pass the technical assessment quiz.",
    ],
)
