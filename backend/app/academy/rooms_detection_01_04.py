"""
NO ENTRY Cybersecurity Academy - Detection Engineering Track: Rooms 01–04
Canonical Implementation of:
- Room 01: Detection Engineering Foundations & Detection-as-Code (detect-01-foundations-as-code)
- Room 02: Log Normalization & Taxonomy (ECS & CIM) (detect-02-log-normalization)
- Room 03: Sigma Rule Syntax & Component Structure (detect-03-sigma-syntax)
- Room 04: Writing Process Creation Rules (Sysmon Event ID 1) (detect-04-process-creation-rules)

Each room provides deep technical concepts, 6 tasks (350 XP per room),
session-bound validation, anti-forgery guards, and 4-question technical quizzes.
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
# ROOM 01: DETECTION ENGINEERING FOUNDATIONS & DETECTION-AS-CODE (PORT 8401)
# ============================================================================

ROOM_DETECTION_01_CONCEPT = RoomConcept(
    overview=(
        "Detection Engineering transforms threat detection from reactive, ad-hoc alerting into a structured software "
        "engineering discipline. Rather than manually clicking through SIEM dashboards to create fragile alert filters, "
        "Detection-as-Code (DaC) applies software lifecycle principles: authoring rules in standard formats (e.g., Sigma), "
        "storing them in version control (Git), linting syntax, running automated unit tests against positive/negative telemetry, "
        "deploying via CI/CD pipelines, measuring Signal-to-Noise Ratio (SNR), and retiring deprecated signatures. "
        "According to David Bianco's Pyramid of Pain, detection engineers prioritize TTPs over trivial indicators like hashes or IPs, "
        "ensuring that defensive controls impose maximum cost upon adversaries."
    ),
    simple_analogy=(
        "Like modern continuous integration pipelines where application code is verified against unit tests and security linting "
        "in pull requests before reaching production servers, Detection-as-Code treats threat detection rules as software "
        "that must pass automated linting and replay tests before deployment to live SIEM indexers."
    ),
    technical_term="Detection-as-Code (DaC) & Detection Development Lifecycle (DDLC)",
    technical_definition=(
        "Detection-as-Code (DaC) is an architectural approach treating security detection logic as source code. Rules are authored "
        "in declarative formats (e.g. Sigma, YARA, Splunk SPL), managed in Git repositories, and validated through CI/CD pipelines. "
        "The Detection Development Lifecycle (DDLC) encompasses eight systematic phases: Threat Identification, Data Source Research, "
        "Detection Logic Authoring, Unit Testing (Positive/Negative validation), CI/CD Linting, Staging Deployment, False Positive Tuning, "
        "and Deprecation/Retirement. By optimizing Signal-to-Noise Ratio (SNR = True Positives / (True Positives + False Positives)), "
        "detection engineering eliminates alert fatigue and maintains operational SOC fidelity."
    ),
    cybersecurity_context=(
        "Modern enterprise SOCs face overwhelming alert volumes, with up to 70% of alerts representing benign false positives. "
        "Detection-as-Code eliminates ad-hoc GUI rule tampering, enforces peer code review, and guarantees that every detection is "
        "validated against historical and synthetic baselines before reaching production analysts."
    ),
    why_it_matters=(
        "Manual alert creation produces unversioned, undocumented, and brittle rules that trigger alert fatigue in the SOC. "
        "By enforcing the Detection Development Lifecycle (DDLC), security operations teams maintain high detection fidelity, "
        "test resilience against evasion, and systematically close coverage gaps across the MITRE ATT&CK matrix."
    ),
    demonstration=(
        "1. Inspect synthetic CI/CD rule validation pipeline logs in `/var/log/detection/ddlc_pipeline_events.json`.\n"
        "2. Identify the misconfigured rule causing false positive build failures on legitimate developer scripts.\n"
        "3. Emulate the automated Detection-as-Code linting and unit test suite via workstation CLI.\n"
        "4. Tune the rule's SNR threshold and path exclusions to eliminate false positives.\n"
        "5. Finalize the Detection Foundations challenge and extract the verification token."
    ),
    remediation_guide=(
        "Adopt a Git-centric repository for all detection rules; establish automated GitHub Actions / GitLab CI pipelines running "
        "linter checks and test datasets; enforce mandatory peer reviews for rule modifications; require positive and negative test "
        "cases for every rule; track rule performance metrics in production; and retire low-fidelity or obsolete signatures quarterly."
    ),
)

ROOM_DETECTION_01_TASKS = [
    TaskDefinition(
        task_id="task-01-dac-mechanics",
        order=1,
        title="Detection Lifecycle & The Pyramid of Pain",
        instructions=(
            "Review the Detection Development Lifecycle (DDLC) and David Bianco's Pyramid of Pain.\n\n"
            "Defenders traditionally spent immense resources detecting trivial atomic indicators (MD5 hashes, IP addresses) "
            "that adversaries can alter with negligible cost. Detection engineering focuses on detecting adversary behaviors.\n\n"
            "Identify the apex tier of the Pyramid of Pain that detection engineers prioritize to force adversaries "
            "to reinvent their operational behaviors rather than merely rotating infrastructure."
        ),
        task_type=TaskType.QUESTION,
        question="What is the top tier of the Pyramid of Pain (abbreviation or full phrase)?",
        hint="The top tier represents adversary behavioral methods: TTPs (Tactics, Techniques, and Procedures).",
        accepted_answers=["TTPs", "ttps", "TTP", "Tactics, Techniques, and Procedures", "Tactics, Techniques, & Procedures"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-02-ddlc-telemetry-analysis",
        order=2,
        title="Analyze Detection CI/CD Pipeline Telemetry",
        instructions=(
            "Inspect the prepared synthetic CI/CD pipeline validation report on your workstation:\n"
            "`cat /var/log/detection/ddlc_pipeline_events.json`\n\n"
            "Alternatively, query the telemetry endpoint:\n"
            "`curl -s http://10.10.14.90:8401/api/detection/foundations/telemetry`\n\n"
            "Identify the specific Rule ID that triggered an excessive false-positive rate on benign developer activity."
        ),
        task_type=TaskType.QUESTION,
        question="What Rule ID failed pipeline validation due to an unacceptable false positive rate?",
        hint="Inspect the JSON report: look for the rule record where validation_status is 'FAILED_HIGH_FALSE_POSITIVES'.",
        accepted_answers=["RULE-DAC-104", "rule-dac-104", "RULE-104"],
        xp_reward=60,
    ),
    TaskDefinition(
        task_id="task-03-attck-detection-mapping",
        order=3,
        title="Enterprise Detection Coverage Mapping",
        instructions=(
            "Review enterprise detection mapping methodologies.\n\n"
            "Identify the standard global knowledge base of adversary tactics and techniques used by detection engineers "
            "to assess organization-wide visibility and prioritize detection engineering backlogs."
        ),
        task_type=TaskType.QUESTION,
        question="What globally recognized taxonomy defines adversary tactics, techniques, and procedures?",
        hint="The framework maintained by MITRE categorizing adversary actions across 14 tactical phases.",
        accepted_answers=["MITRE ATT&CK", "mitre att&ck", "ATT&CK", "mitre attack", "MITRE ATTACK"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-04-dac-pipeline-emulation",
        order=4,
        title="Execute Detection-as-Code Pipeline Validation",
        instructions=(
            "Use the operator detection workstation tool to execute an automated linting and unit-testing run "
            "against the staged rule bundle:\n\n"
            "`python3 /home/operator/tools/detection_foundations_tool.py --emulate-pipeline`\n\n"
            "Submit the verification token returned upon successful completion."
        ),
        task_type=TaskType.COMMAND,
        question="Run the detection foundations pipeline tool and submit the verification token.",
        hint="Execute 'python3 /home/operator/tools/detection_foundations_tool.py --emulate-pipeline' in the lab terminal.",
        accepted_answers=["DETECTION_FOUNDATIONS_VERIFIED", "DAC_PIPELINE_VERIFIED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-dac-challenge",
        order=5,
        title="Tune Signal-to-Noise Ratio & Finalize DaC Challenge",
        instructions=(
            "To deploy the rule bundle into production, false-positive noise must be suppressed:\n\n"
            "1. Tune the detection rule filter to suppress benign developer noise:\n"
            "`python3 /home/operator/tools/detection_foundations_tool.py --tune-snr`\n\n"
            "2. Finalize the Detection Foundations challenge:\n"
            "`python3 /home/operator/tools/detection_foundations_tool.py --challenge`\n\n"
            "Submit the challenge completion verification token."
        ),
        task_type=TaskType.COMMAND,
        question="Tune SNR threshold filter, complete the challenge, and submit the verification token.",
        hint="Execute '--tune-snr' followed by '--challenge' using detection_foundations_tool.py.",
        accepted_answers=["DETECTION_FOUNDATIONS_VALIDATED", "DAC_CHALLENGE_VALIDATED"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-detection-foundations-quiz",
        order=6,
        title="Detection Engineering Foundations Assessment",
        instructions="Complete the 4-question technical quiz to demonstrate mastery of DaC, DDLC, and SNR concepts.",
        task_type=TaskType.QUIZ,
        xp_reward=40,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is the primary benefit of Detection-as-Code (DaC) over manual SIEM alert creation?",
                options=[
                    "Rules are version-controlled, automated in CI/CD, peer-reviewed, and tested before production",
                    "It eliminates the need for security log sources by predicting attacks mathematically",
                    "It allows raw malware samples to execute without generating telemetry",
                    "It replaces all SIEM indexers with unencrypted text files on student laptops",
                ],
                correct_index=0,
                explanation="Detection-as-Code brings software engineering rigor: version control, peer review, CI/CD linting, and automated unit testing.",
            ),
            QuizQuestion(
                id="q2",
                question="According to David Bianco's Pyramid of Pain, which indicator tier is hardest for defenders to detect but most painful for attackers when detected?",
                options=[
                    "TTPs (Tactics, Techniques, and Procedures)",
                    "IP Addresses",
                    "Hash Values (MD5, SHA-256)",
                    "Domain Names",
                ],
                correct_index=0,
                explanation="TTPs sit at the apex of the Pyramid of Pain; evading TTP detections forces the adversary to re-engineer their entire tradecraft.",
            ),
            QuizQuestion(
                id="q3",
                question="What does Signal-to-Noise Ratio (SNR) measure in a detection engineering context?",
                options=[
                    "The ratio of actionable true-positive alerts relative to benign false-positive noise",
                    "The Wi-Fi antenna frequency of the SIEM collector appliance",
                    "The number of characters in a Sigma YAML rule title",
                    "The bitrate of VoIP phone conversations recorded by network sensors",
                ],
                correct_index=0,
                explanation="High SNR means a rule generates high-confidence, actionable alerts while minimizing false-positive interruptions for SOC analysts.",
            ),
            QuizQuestion(
                id="q4",
                question="Which stage of the Detection Development Lifecycle (DDLC) directly follows detection logic development and precedes production rollout?",
                options=[
                    "Positive and negative testing against synthetic or replayed telemetry",
                    "Immediate unmonitored production deployment across all endpoints",
                    "Permanent rule deprecation and archiving",
                    "Manual deletion of all past incident tickets",
                ],
                correct_index=0,
                explanation="Before deployment, new rules must be tested against both positive exploit cases and negative benign baselines to verify recall and precision.",
            ),
        ],
    ),
]

ROOM_DETECTION_01_DEFINITION = RoomDefinition(
    room_id="detect-01-foundations-as-code",
    track=TrackEnum.DETECTION,
    room_number=1,
    title="Detection Engineering Foundations & Detection-as-Code",
    short_description="Master the Detection Development Lifecycle (DDLC), Detection-as-Code (DaC) CI/CD workflows, the Pyramid of Pain, and SNR tuning.",
    difficulty="Beginner",
    estimated_duration="40 min",
    prerequisites=[],
    required_practical_skills=["Git workflows", "Log analysis", "CI/CD concepts", "ATT&CK taxonomy"],
    required_lab_type="container_duo",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Implement the stages of the Detection Development Lifecycle (DDLC)",
        "Differentiate atomic indicators from behavioral TTPs using the Pyramid of Pain",
        "Author, lint, and test detection rules within an automated Detection-as-Code pipeline",
        "Calculate and optimize Signal-to-Noise Ratio (SNR) to eliminate alert fatigue",
    ],
    assessment_criteria=[
        "Correctly identify TTPs and Pyramid of Pain tiering",
        "Diagnose high-false-positive rules in CI/CD pipeline telemetry",
        "Execute automated rule validation and verify output tokens",
        "Tune false positive exclusions and score 100% on the foundations quiz",
    ],
    completion_requirements=["Complete all 5 practical investigation/emulation tasks", "Score 100% on technical quiz"],
    total_xp=350,
    concept=ROOM_DETECTION_01_CONCEPT,
    tasks=ROOM_DETECTION_01_TASKS,
    default_port=8401,
)


# ============================================================================
# ROOM 02: LOG NORMALIZATION & TAXONOMY (ECS & CIM) (PORT 8402)
# ============================================================================

ROOM_DETECTION_02_CONCEPT = RoomConcept(
    overview=(
        "Enterprise security telemetry originates from disparate operating systems, cloud providers, and network devices, "
        "each using idiosyncratic field names. Windows Security Event 4688 records `NewProcessName`, Sysmon Event 1 logs `Image`, "
        "Linux auditd records `exe`, and cloud containers log `container.image.name`. Without schema normalization, defenders "
        "must author distinct detection queries for every vendor dialect. Universal schemas like the Elastic Common Schema (ECS) "
        "and Splunk Common Information Model (CIM) normalize disparate fields into standard taxonomies (e.g., `process.executable`, "
        "`source.ip`, `destination.port`). Normalization enables portable detection rules, reliable correlation, and unified incident triage."
    ),
    simple_analogy=(
        "Like an international financial exchange that converts pounds, yen, and euros into standard SDR units so that global ledgers "
        "reconcile consistently, log normalization maps divergent vendor field formats into a unified schema so a single detection logic "
        "works across all data sources."
    ),
    technical_term="Log Normalization, Common Information Model (CIM) & Elastic Common Schema (ECS)",
    technical_definition=(
        "Log Normalization transforms heterogeneous semi-structured or unstructured event streams into a consistent, strongly-typed "
        "schema. Elastic Common Schema (ECS) organizes fields into standardized hierarchical namespaces (e.g., `process.*`, `user.*`, "
        "`source.*`, `destination.*`, `event.*`). Splunk Common Information Model (CIM) provides domain-specific data models "
        "(Endpoint, Authentication, Network Traffic). Ingestion pipelines use parsers, grok filters, and field aliases to map raw "
        "vendor fields (e.g. Sysmon `ParentImage` -> ECS `process.parent.executable` / CIM `parent_process_path`), ensuring semantic "
        "consistency across log pipelines."
    ),
    cybersecurity_context=(
        "In modern multi-cloud hybrid enterprises, attacks traverse Windows endpoints, Linux bastion hosts, and AWS VPCs. "
        "Without schema normalization, a detection engineer must write three separate rules for process execution. "
        "Normalized data models allow generic rules to correlate activities seamlessly across platforms."
    ),
    why_it_matters=(
        "Schema fragmentation creates dangerous blind spots. If a detection rule searches for `ProcessName` while an endpoint agent "
        "outputs `process_path`, the attack goes undetected. Log normalization establishes semantic consistency across the enterprise."
    ),
    demonstration=(
        "1. Inspect raw unnormalized heterogeneous event records in `/var/log/detection/raw_event_schema.json`.\n"
        "2. Analyze field discrepancies between Windows Security 4688, Sysmon Event 1, and Linux auditd.\n"
        "3. Emulate the schema normalization pipeline to transform raw telemetry into ECS and CIM models.\n"
        "4. Tune taxonomy field aliases to resolve unmapped parent process metadata.\n"
        "5. Complete the normalization challenge to confirm cross-platform schema fidelity."
    ),
    remediation_guide=(
        "Enforce standard schemas (ECS or CIM) at ingestion time via Logstash, Cribl Stream, or Vector; maintain a centralized "
        "field mapping dictionary; validate event types against strict JSON schemas before indexing; and audit data pipelines "
        "regularly to catch unmapped vendor field changes following software updates."
    ),
)

ROOM_DETECTION_02_TASKS = [
    TaskDefinition(
        task_id="task-01-normalization-foundations",
        order=1,
        title="Universal Log Schemas & Taxonomies",
        instructions=(
            "Review log normalization standards.\n\n"
            "Identify the open source specification developed by Elastic that defines a common set of fields "
            "for storing event data in Elasticsearch, OpenSearch, and Logstash."
        ),
        task_type=TaskType.QUESTION,
        question="What is the name or acronym of the Elastic log normalization schema?",
        hint="The 3-letter acronym developed by Elastic: Elastic Common Schema.",
        accepted_answers=["Elastic Common Schema", "ECS", "ecs", "elastic common schema"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-02-schema-mapping-analysis",
        order=2,
        title="Process Path Normalization Mapping",
        instructions=(
            "Inspect the raw unnormalized telemetry on your workstation:\n"
            "`cat /var/log/detection/raw_event_schema.json`\n\n"
            "Alternatively, query the telemetry endpoint:\n"
            "`curl -s http://10.10.14.90:8402/api/detection/normalization/telemetry`\n\n"
            "When normalizing Windows Security 4688 (`NewProcessName`) and Sysmon Event 1 (`Image`) into the Elastic Common Schema, "
            "what is the canonical field name for the process binary path?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the canonical ECS field name for an executable binary path?",
        hint="In ECS, process attributes reside in the 'process.*' namespace. The full binary path field is 'process.executable'.",
        accepted_answers=["process.executable", "process_executable", "process.path"],
        xp_reward=60,
    ),
    TaskDefinition(
        task_id="task-03-splunk-cim-mapping",
        order=3,
        title="Splunk Common Information Model Standard",
        instructions=(
            "Review SIEM data model architectures.\n\n"
            "Identify the standard Splunk framework that organizes field names and event types into normalized "
            "data models such as Endpoint, Network Traffic, and Authentication."
        ),
        task_type=TaskType.QUESTION,
        question="What Splunk framework acronym stands for Common Information Model?",
        hint="The framework acronym is CIM (Common Information Model).",
        accepted_answers=["Common Information Model", "CIM", "cim", "Splunk CIM", "splunk cim"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-04-normalization-emulation",
        order=4,
        title="Execute Schema Normalization Pipeline",
        instructions=(
            "Run the normalization engine on your workstation to transform raw heterogeneous logs into normalized ECS and CIM JSON records:\n\n"
            "`python3 /home/operator/tools/log_normalization_tool.py --emulate-normalization`\n\n"
            "Submit the verification token returned."
        ),
        task_type=TaskType.COMMAND,
        question="Run the log normalization emulation tool and submit the verification token.",
        hint="Execute 'python3 /home/operator/tools/log_normalization_tool.py --emulate-normalization' in the terminal.",
        accepted_answers=["LOG_NORMALIZATION_VERIFIED", "SCHEMA_NORMALIZATION_VERIFIED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-normalization-challenge",
        order=5,
        title="Tune Taxonomy Aliases & Finalize Normalization",
        instructions=(
            "To complete schema alignment across the heterogeneous estate:\n\n"
            "1. Configure the field alias dictionary to resolve unmapped parent process fields:\n"
            "`python3 /home/operator/tools/log_normalization_tool.py --tune-taxonomy`\n\n"
            "2. Complete the normalization challenge:\n"
            "`python3 /home/operator/tools/log_normalization_tool.py --challenge`\n\n"
            "Submit the completion verification token."
        ),
        task_type=TaskType.COMMAND,
        question="Tune taxonomy aliases, complete the challenge, and submit the verification token.",
        hint="Execute '--tune-taxonomy' followed by '--challenge' using log_normalization_tool.py.",
        accepted_answers=["LOG_NORMALIZATION_VALIDATED", "TAXONOMY_CHALLENGE_VALIDATED"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-normalization-quiz",
        order=6,
        title="Log Normalization & Taxonomy Assessment",
        instructions="Complete the 4-question technical quiz to demonstrate mastery of ECS, CIM, and log parsing.",
        task_type=TaskType.QUIZ,
        xp_reward=40,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is log normalization essential for enterprise detection engineering?",
                options=[
                    "It allows detection rules written against standard fields to run across multi-vendor log sources",
                    "It compresses log files by deleting all IP addresses and timestamps",
                    "It converts text files into proprietary compiled binary executables",
                    "It encrypts audit logs so incident responders cannot read them",
                ],
                correct_index=0,
                explanation="Normalization decouples detection logic from vendor-specific schemas, making rules portable across diverse environments.",
            ),
            QuizQuestion(
                id="q2",
                question="In the Elastic Common Schema (ECS), which field category represents network connection endpoints and IP addresses?",
                options=[
                    "source.* and destination.*",
                    "user.agent.os.*",
                    "file.pe.imphash.*",
                    "registry.key.hive.*",
                ],
                correct_index=0,
                explanation="ECS uses the `source.*` and `destination.*` namespaces (e.g., `source.ip`, `destination.port`) for network connection telemetry.",
            ),
            QuizQuestion(
                id="q3",
                question="What risk arises when a log forwarder maps the same source field to two conflicting data types (e.g., string vs integer)?",
                options=[
                    "Schema collision / index mapping explosion leading to dropped or unindexed logs",
                    "The operating system automatically reboots in safe mode",
                    "The client computer generates a hardware interrupt storm",
                    "Network interface cards permanently downgrade to 10 Mbps speed",
                ],
                correct_index=0,
                explanation="Mapping conflicts (type mismatch) cause SIEM indexing errors, resulting in unindexed logs and severe detection gaps.",
            ),
            QuizQuestion(
                id="q4",
                question="In the Splunk Common Information Model (CIM), which data model is queried to detect unauthorized account creations across Active Directory, Linux, and Cloud?",
                options=[
                    "Authentication / Change (Account Management)",
                    "Web / Proxy Traffic",
                    "Interprocess Communication (IPC)",
                    "Database Query Audit",
                ],
                correct_index=0,
                explanation="Splunk CIM's Change and Authentication data models normalize identity and account management actions across heterogeneous platforms.",
            ),
        ],
    ),
]

ROOM_DETECTION_02_DEFINITION = RoomDefinition(
    room_id="detect-02-log-normalization",
    track=TrackEnum.DETECTION,
    room_number=2,
    title="Log Normalization & Taxonomy (ECS & CIM)",
    short_description="Master log normalization taxonomies (ECS & CIM), resolve field schema heterogeneity, and build vendor-agnostic data pipelines.",
    difficulty="Beginner",
    estimated_duration="45 min",
    prerequisites=["detect-01-foundations-as-code"],
    required_practical_skills=["JSON parsing", "Log schema analysis", "Elastic Common Schema", "Splunk CIM"],
    required_lab_type="container_duo",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Identify field fragmentation issues across Windows, Linux, and Cloud telemetry",
        "Map raw event attributes to Elastic Common Schema (ECS) standard namespaces",
        "Normalize multi-vendor events into Splunk Common Information Model (CIM) data models",
        "Resolve schema collisions and build portable detection pipelines",
    ],
    assessment_criteria=[
        "Correctly identify canonical ECS and CIM field names",
        "Analyze heterogeneous raw event records and determine normalized paths",
        "Execute normalization transformations via CLI and extract verification tokens",
        "Tune taxonomy alias mappings and pass the quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 practical investigation/emulation tasks", "Score 100% on technical quiz"],
    total_xp=350,
    concept=ROOM_DETECTION_02_CONCEPT,
    tasks=ROOM_DETECTION_02_TASKS,
    default_port=8402,
)


# ============================================================================
# ROOM 03: SIGMA RULE SYNTAX & COMPONENT STRUCTURE (PORT 8403)
# ============================================================================

ROOM_DETECTION_03_CONCEPT = RoomConcept(
    overview=(
        "Sigma is the de-facto open standard for authoring generic, vendor-agnostic detection rules. Instead of writing proprietary "
        "queries locked into Splunk SPL, Elastic KQL, or Microsoft Sentinel KQL, detection engineers write Sigma YAML definitions. "
        "A valid Sigma rule specifies top-level metadata (`title`, `id`, `status`, `description`), a target `logsource` "
        "(`category`, `product`, `service`), and a `detection` block containing named search identifiers (selections), value modifiers "
        "(`|contains`, `|startswith`, `|endswith`, `|re`, `|all`), and a boolean `condition` expression (e.g., `selection and not filter`). "
        "Transpilers (pySigma / sigmac) then compile generic Sigma definitions into target query dialects automatically."
    ),
    simple_analogy=(
        "Like intermediate representation (IR) in software compilers (such as LLVM bytecode) that compiles high-level code into "
        "disparate machine architectures (x86, ARM, RISC-V), Sigma acts as an intermediate detection language compiling generic "
        "rules into target SIEM search dialects."
    ),
    technical_term="Sigma Specification (v2.0) & Generic Rule Architecture",
    technical_definition=(
        "The Sigma Specification defines an open YAML schema for expressing log event signatures. Key components include: "
        "1) Metadata: `title`, `id` (UUIDv4), `status` (experimental, test, stable, deprecated), `level` (informational, low, medium, high, critical); "
        "2) `logsource`: defines telemetry scope (`category: process_creation`, `product: windows`, `service: sysmon`); "
        "3) `detection`: maps search identifiers to field-value pairs with modifiers (`|contains`, `|startswith`, `|endswith`, `|re`, `|all`, `|base64offset`); "
        "4) `condition`: boolean logic connecting selections (`selection and not filter`, `1 of selection_*`). "
        "pySigma backends transpile the AST into platform-specific syntax (e.g., Splunk SPL, Elasticsearch Lucene/KQL, Azure KQL, Snowflake SQL)."
    ),
    cybersecurity_context=(
        "Community threat intelligence and CISA advisories publish detection signatures in Sigma format. By mastering Sigma syntax, "
        "detection engineers can ingest community threat hunting rules immediately, test them internally, and transpile them to their "
        "production SIEM without vendor dependency."
    ),
    why_it_matters=(
        "Sigma decouples detection knowledge from proprietary SIEM vendors. When organizations migrate SIEM platforms, "
        "Sigma rules convert instantly without manual re-authoring, preserving years of detection engineering investment."
    ),
    demonstration=(
        "1. Inspect candidate Sigma rule in `/var/log/detection/sample_sigma_rule.yaml` and test dataset in `/var/log/detection/sigma_eval_dataset.json`.\n"
        "2. Identify the string value modifier required for robust substring detection.\n"
        "3. Emulate Sigma compilation and evaluation against positive and negative test cases.\n"
        "4. Tune the boolean condition expression (`selection and not filter`) to suppress benign matches.\n"
        "5. Finalize the challenge and confirm 100% precision and recall."
    ),
    remediation_guide=(
        "Store all internal detection rules in Sigma YAML format; utilize automated linter tools (sigma-cli, pySigma) in CI pipelines; "
        "always include UUID identifiers and MITRE ATT&CK tags; specify granular log sources; and thoroughly test selection modifiers "
        "against benign baseline data before promoting rules to `status: stable`."
    ),
)

ROOM_DETECTION_03_TASKS = [
    TaskDefinition(
        task_id="task-01-sigma-structure-foundations",
        order=1,
        title="Sigma YAML Top-Level Sections",
        instructions=(
            "Review the Sigma rule specification.\n\n"
            "What top-level YAML key defines the target telemetry context (such as product, service, or category) "
            "that a SIEM query must search against?"
        ),
        task_type=TaskType.QUESTION,
        question="What top-level YAML key defines product, service, and category in a Sigma rule?",
        hint="The key that groups product, category, and service specifications: logsource.",
        accepted_answers=["logsource", "logsource:", "log source", "Logsource"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-02-sigma-modifier-analysis",
        order=2,
        title="String Value Modifiers",
        instructions=(
            "Inspect the candidate Sigma rule on your workstation:\n"
            "`cat /var/log/detection/sample_sigma_rule.yaml`\n\n"
            "Alternatively, query the telemetry endpoint:\n"
            "`curl -s http://10.10.14.90:8403/api/detection/sigma/telemetry`\n\n"
            "Identify the field value modifier appended to a field name (e.g., `CommandLine|...`) to indicate a case-insensitive substring search."
        ),
        task_type=TaskType.QUESTION,
        question="What field modifier specifies case-insensitive substring searching?",
        hint="The modifier is written after a pipe character: CommandLine|contains.",
        accepted_answers=["contains", "|contains", "contains modifier"],
        xp_reward=60,
    ),
    TaskDefinition(
        task_id="task-03-sigma-condition-logic",
        order=3,
        title="Condition Expression Syntax",
        instructions=(
            "Review Sigma boolean logic.\n\n"
            "In a Sigma rule containing a primary match block named `selection` and an exclusion block named `filter`, "
            "what is the standard boolean condition expression that matches malicious activity while excluding benign noise?"
        ),
        task_type=TaskType.QUESTION,
        question="What boolean condition combines a selection while excluding a filter block?",
        hint="The syntax combines the selection with an inverted filter: selection and not filter.",
        accepted_answers=["selection and not filter", "selection and not 1 of filter*", "selection AND NOT filter"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-04-sigma-syntax-emulation",
        order=4,
        title="Execute Sigma Syntax Parser & Evaluator",
        instructions=(
            "Run the operator Sigma tool to parse, compile, and evaluate the candidate rule against the synthetic event dataset:\n\n"
            "`python3 /home/operator/tools/sigma_syntax_tool.py --emulate-parser`\n\n"
            "Submit the verification token returned."
        ),
        task_type=TaskType.COMMAND,
        question="Run the Sigma syntax evaluator tool and submit the verification token.",
        hint="Execute 'python3 /home/operator/tools/sigma_syntax_tool.py --emulate-parser' in the terminal.",
        accepted_answers=["SIGMA_SYNTAX_VERIFIED", "SIGMA_PARSER_VERIFIED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-sigma-syntax-challenge",
        order=5,
        title="Tune Condition Logic & Finalize Sigma Challenge",
        instructions=(
            "To deploy the generic rule without triggering false positives on administrative maintenance:\n\n"
            "1. Update the condition expression to properly filter out legitimate administrative processes:\n"
            "`python3 /home/operator/tools/sigma_syntax_tool.py --tune-condition`\n\n"
            "2. Complete the Sigma Syntax challenge:\n"
            "`python3 /home/operator/tools/sigma_syntax_tool.py --challenge`\n\n"
            "Submit the completion verification token."
        ),
        task_type=TaskType.COMMAND,
        question="Tune condition logic, complete the challenge, and submit the verification token.",
        hint="Execute '--tune-condition' followed by '--challenge' using sigma_syntax_tool.py.",
        accepted_answers=["SIGMA_SYNTAX_VALIDATED", "SIGMA_CHALLENGE_VALIDATED"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-sigma-syntax-quiz",
        order=6,
        title="Sigma Rule Architecture Assessment",
        instructions="Complete the 4-question technical quiz to demonstrate mastery of Sigma YAML specifications.",
        task_type=TaskType.QUIZ,
        xp_reward=40,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is the purpose of the 'id' field in a standard Sigma rule definition?",
                options=[
                    "A globally unique UUIDv4 identifier used to track the rule across versions and translations",
                    "The IP address of the server running the SIEM",
                    "The number of times the rule has triggered in the last 24 hours",
                    "The operating system build number required to execute the signature",
                ],
                correct_index=0,
                explanation="The `id` field holds a unique UUIDv4 ensuring rules can be reliably tracked, updated, and referenced globally.",
            ),
            QuizQuestion(
                id="q2",
                question="What does the '|all' modifier specify when applied to a list of values in a Sigma field (e.g., CommandLine|contains|all)?",
                options=[
                    "All items in the value list must be present in the matched log field",
                    "At least one item in the list must match",
                    "The field must match all log sources in the database",
                    "The rule applies to all users in the active directory domain",
                ],
                correct_index=0,
                explanation="By default, lists in Sigma selections evaluate as OR; appending `|all` requires every item in the list to be present.",
            ),
            QuizQuestion(
                id="q3",
                question="Which Sigma rule status level indicates a detection is verified, battle-tested, and suitable for production alerting?",
                options=[
                    "stable",
                    "experimental",
                    "test",
                    "deprecated",
                ],
                correct_index=0,
                explanation="`stable` indicates a thoroughly tested rule with verified low false-positive rates ready for production SOC alerting.",
            ),
            QuizQuestion(
                id="q4",
                question="What is pySigma (formerly sigmac)?",
                options=[
                    "A compiler library that converts generic Sigma rules into target SIEM query dialects (SPL, KQL, etc.)",
                    "A malware payload generator used by ransomware operators",
                    "A kernel driver that hooks Windows system calls",
                    "A hardware network tap for 10Gbps fiber connections",
                ],
                correct_index=0,
                explanation="pySigma is the official transpiler framework that compiles Sigma rules into specific SIEM query formats.",
            ),
        ],
    ),
]

ROOM_DETECTION_03_DEFINITION = RoomDefinition(
    room_id="detect-03-sigma-syntax",
    track=TrackEnum.DETECTION,
    room_number=3,
    title="Sigma Rule Syntax & Component Structure",
    short_description="Master the Sigma YAML specification (v2.0), selection maps, field value modifiers, and transpilation into SIEM search queries.",
    difficulty="Beginner",
    estimated_duration="45 min",
    prerequisites=["detect-01-foundations-as-code", "detect-02-log-normalization"],
    required_practical_skills=["YAML authoring", "Sigma syntax", "Boolean logic", "SIEM transpilation"],
    required_lab_type="container_duo",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Author compliant Sigma rules adhering to the v2.0 specification",
        "Utilize field value modifiers (|contains, |startswith, |endswith, |all)",
        "Construct robust boolean condition expressions combining selections and filters",
        "Evaluate Sigma rules against synthetic telemetry and compile queries",
    ],
    assessment_criteria=[
        "Identify core Sigma top-level keys and string value modifiers",
        "Formulate valid boolean selection/filter conditions",
        "Compile and execute Sigma evaluation tests via CLI tools",
        "Tune condition filters and pass the quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 practical investigation/emulation tasks", "Score 100% on technical quiz"],
    total_xp=350,
    concept=ROOM_DETECTION_03_CONCEPT,
    tasks=ROOM_DETECTION_03_TASKS,
    default_port=8403,
)


# ============================================================================
# ROOM 04: WRITING PROCESS CREATION RULES (SYSMON EVENT ID 1) (PORT 8404)
# ============================================================================

ROOM_DETECTION_04_CONCEPT = RoomConcept(
    overview=(
        "Process Creation telemetry is the bedrock of host-based threat detection. Windows Security Event 4688 and Sysmon Event ID 1 "
        "record critical execution metadata: the target binary path (`Image`), command line flags (`CommandLine`), the initiating "
        "process (`ParentImage`), parent command line (`ParentCommandLine`), current working directory, authenticating user, and file hashes. "
        "Adversaries frequently employ Living-off-the-Land Binaries (LOLBINs) like `certutil.exe`, `bitsadmin.exe`, or `mshta.exe` "
        "to download remote payloads or execute code without dropping new binaries. High-fidelity process creation rules do not simply "
        "alert on binary execution; they inspect specific argument combinations (e.g. `certutil -urlcache -split -f`), detect anomalous "
        "parent-child relationships (e.g., `winword.exe` spawning `powershell.exe`), and establish strict negative filters to eliminate "
        "legitimate administrative operations."
    ),
    simple_analogy=(
        "Like an airport security checkpoint log that records not only the passenger's name, but which gate they departed from, "
        "who accompanied them through transit, and the exact contents of their carry-on luggage, Sysmon Event ID 1 records the full "
        "ancestry, command arguments, and cryptographic hash of every launched program."
    ),
    technical_term="Sysmon Event ID 1 (Process Creation) & Living-off-the-Land Binaries (LOLBINs)",
    technical_definition=(
        "Sysmon Event ID 1 captures detailed process creation metadata on Windows systems. Key telemetry attributes include: "
        "`Image` (target executable path), `CommandLine` (full execution arguments), `ParentImage` (parent executable), "
        "`ParentCommandLine` (parent execution arguments), `OriginalFileName` (internal PE header name), `CurrentDirectory`, "
        "`User`, `IntegrityLevel`, and `Hashes` (SHA256, IMPHASH). Living-off-the-Land Binaries (LOLBINs) leverage trusted Microsoft-signed "
        "executables to perform malicious tasks (e.g., `certutil.exe -urlcache -split -f` for file downloading, `mshta.exe` for remote script execution). "
        "Detection rules must match specific argument patterns while using `OriginalFileName` to catch renamed binaries and parent process "
        "heuristics to detect exploitation."
    ),
    cybersecurity_context=(
        "Threat actors heavily favor LOLBINs because application control systems (AppLocker, Windows Defender Application Control) "
        "frequently whitelist Microsoft-signed binaries. Detecting LOLBIN execution requires deep inspection of command line arguments "
        "and process ancestry rather than relying on binary presence."
    ),
    why_it_matters=(
        "Process creation events provide direct attribution of adversary actions on endpoints. By writing precise Sigma rules for Event ID 1, "
        "defenders catch living-off-the-land techniques (T1105, T1059) while filtering out normal administrative background noise."
    ),
    demonstration=(
        "1. Inspect Sysmon Event ID 1 telemetry in `/var/log/detection/sysmon_event_1_dataset.json`.\n"
        "2. Identify the malicious `certutil.exe -urlcache -split` download cradle arguments.\n"
        "3. Emulate process creation detection matching against positive attack and negative benign events.\n"
        "4. Tune the exclusion filter to distinguish malicious download cradles from benign certificate verifications.\n"
        "5. Finalize the challenge and verify zero false-positive alerts."
    ),
    remediation_guide=(
        "Enable Sysmon Event ID 1 or Windows Security Event 4688 with Command Line Process Auditing enabled via Group Policy; "
        "block unauthorized LOLBIN execution using WDAC or AppLocker policy rules; author Sigma detections inspecting `CommandLine` arguments "
        "and `OriginalFileName`; and alert on anomalous parent processes (e.g., Office, Acrobat, or web servers launching shells)."
    ),
)

ROOM_DETECTION_04_TASKS = [
    TaskDefinition(
        task_id="task-01-sysmon-event1-mechanics",
        order=1,
        title="Sysmon Process Creation Telemetry",
        instructions=(
            "Review Windows host monitoring telemetry.\n\n"
            "What Sysmon Event ID records new process creation events, providing command lines, parent processes, and cryptographic hashes?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the numeric Event ID for Sysmon Process Creation?",
        hint="Enter the numeric Event ID for Sysmon Process Creation (single digit 1).",
        accepted_answers=["1", "Event ID 1", "Sysmon 1", "Event 1"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-02-lolbin-telemetry-analysis",
        order=2,
        title="Analyze LOLBIN Command Line Arguments",
        instructions=(
            "Inspect the Sysmon Event ID 1 dataset on your workstation:\n"
            "`cat /var/log/detection/sysmon_event_1_dataset.json`\n\n"
            "Alternatively, query the telemetry endpoint:\n"
            "`curl -s http://10.10.14.90:8404/api/detection/process-creation/telemetry`\n\n"
            "Identify the specific command-line argument used with `certutil.exe` in the malicious event record "
            "to download remote payloads via HTTP/HTTPS."
        ),
        task_type=TaskType.QUESTION,
        question="What command-line parameter in certutil.exe was used to download a remote file?",
        hint="Look for the certutil command downloading a payload from an external URL: -urlcache.",
        accepted_answers=["-urlcache", "-split", "-f", "-urlcache -split", "urlcache"],
        xp_reward=60,
    ),
    TaskDefinition(
        task_id="task-03-attck-lolbin-mapping",
        order=3,
        title="ATT&CK Ingress Tool Transfer Mapping",
        instructions=(
            "Review MITRE ATT&CK techniques.\n\n"
            "Identify the MITRE ATT&CK technique ID associated with adversaries using utilities like certutil, bitsadmin, or curl "
            "to transfer malicious tools from external infrastructure into the compromised environment."
        ),
        task_type=TaskType.QUESTION,
        question="What is the MITRE ATT&CK technique ID for Ingress Tool Transfer?",
        hint="Technique T1105: Ingress Tool Transfer under the Command and Control / Lateral Movement tactics.",
        accepted_answers=["T1105", "t1105", "T1105 - Ingress Tool Transfer"],
        xp_reward=50,
    ),
    TaskDefinition(
        task_id="task-04-process-creation-emulation",
        order=4,
        title="Evaluate Process Creation Rule Against Telemetry",
        instructions=(
            "Execute the process creation detection tool on your workstation to evaluate the rule against the dataset "
            "of positive exploits and benign baseline logs:\n\n"
            "`python3 /home/operator/tools/process_creation_tool.py --emulate-detection`\n\n"
            "Submit the verification token returned."
        ),
        task_type=TaskType.COMMAND,
        question="Run the process creation detection tool and submit the verification token.",
        hint="Execute 'python3 /home/operator/tools/process_creation_tool.py --emulate-detection' in the terminal.",
        accepted_answers=["PROCESS_CREATION_VERIFIED", "SYSMON1_DETECTION_VERIFIED"],
        xp_reward=70,
    ),
    TaskDefinition(
        task_id="task-05-process-creation-challenge",
        order=5,
        title="Tune Benign LOLBIN Filter & Finalize Challenge",
        instructions=(
            "To deploy the LOLBIN process creation rule into production without false positives on legitimate certificate admin operations:\n\n"
            "1. Tune the exclusion filter to eliminate false positives on legitimate administrative certutil usage (`certutil -verify`):\n"
            "`python3 /home/operator/tools/process_creation_tool.py --tune-lolbin-filter`\n\n"
            "2. Complete the Process Creation detection challenge:\n"
            "`python3 /home/operator/tools/process_creation_tool.py --challenge`\n\n"
            "Submit the completion verification token."
        ),
        task_type=TaskType.COMMAND,
        question="Tune LOLBIN filters, complete the challenge, and submit the verification token.",
        hint="Execute '--tune-lolbin-filter' followed by '--challenge' using process_creation_tool.py.",
        accepted_answers=["PROCESS_CREATION_VALIDATED", "SYSMON1_CHALLENGE_VALIDATED"],
        xp_reward=80,
    ),
    TaskDefinition(
        task_id="task-06-process-creation-quiz",
        order=6,
        title="Process Creation Detection Assessment",
        instructions="Complete the 4-question technical quiz to demonstrate mastery of Sysmon Event ID 1 and LOLBIN detection.",
        task_type=TaskType.QUIZ,
        xp_reward=40,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is detecting a LOLBIN solely by its file name (e.g., Image|endswith: 'certutil.exe') considered poor practice?",
                options=[
                    "It causes high false-positive rates on legitimate administrative tasks and is easily bypassed if the adversary renames the binary",
                    "LOLBINs can only execute if the system has no network connectivity",
                    "Windows automatically prevents any binary named certutil.exe from executing",
                    "Security event logs never record binary file names",
                ],
                correct_index=0,
                explanation="Detecting solely on file names triggers false positives on benign admin work and fails when attackers rename the binary.",
            ),
            QuizQuestion(
                id="q2",
                question="Which Sysmon Event ID 1 field allows detection engineers to identify a binary even if an attacker renames certutil.exe to svchost.exe?",
                options=[
                    "OriginalFileName (extracted from PE Version Info)",
                    "CurrentDirectory",
                    "IntegrityLevel",
                    "TerminalSessionId",
                ],
                correct_index=0,
                explanation="`OriginalFileName` is extracted from the PE header's version resource, persisting even if the file on disk is renamed.",
            ),
            QuizQuestion(
                id="q3",
                question="Which parent-child process relationship represents an immediate high-fidelity anomaly indicative of macro or exploit execution?",
                options=[
                    "winword.exe spawning cmd.exe or powershell.exe",
                    "services.exe spawning svchost.exe",
                    "explorer.exe spawning chrome.exe",
                    "system spawning smss.exe",
                ],
                correct_index=0,
                explanation="Office productivity applications like Word or Excel should virtually never spawn command interpreters like cmd or PowerShell.",
            ),
            QuizQuestion(
                id="q4",
                question="In Sysmon Event ID 1, what does the ParentCommandLine field provide to the detection engineer?",
                options=[
                    "The exact arguments used to launch the parent process that created the current process",
                    "The parent process's motherboard serial number",
                    "The Wi-Fi SSID connected to the parent process",
                    "The DNS server address used by the operating system kernel",
                ],
                correct_index=0,
                explanation="`ParentCommandLine` reveals the full execution arguments of the parent process, providing crucial contextual ancestry.",
            ),
        ],
    ),
]

ROOM_DETECTION_04_DEFINITION = RoomDefinition(
    room_id="detect-04-process-creation-rules",
    track=TrackEnum.DETECTION,
    room_number=4,
    title="Writing Process Creation Rules (Sysmon Event ID 1)",
    short_description="Master process creation detection (Sysmon 1 / Event 4688), LOLBIN command line analysis (certutil, mshta), and parent-child anomaly filters.",
    difficulty="Intermediate",
    estimated_duration="50 min",
    prerequisites=["detect-01-foundations-as-code", "detect-02-log-normalization", "detect-03-sigma-syntax"],
    required_practical_skills=["Sysmon Event ID 1", "LOLBIN analysis", "Parent-child correlation", "False positive tuning"],
    required_lab_type="container_duo",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Inspect critical Sysmon Event ID 1 fields: Image, CommandLine, ParentImage, OriginalFileName",
        "Author Sigma rules detecting Living-off-the-Land (LOLBIN) download cradles (T1105)",
        "Identify anomalous parent-child execution patterns (Office spawning shell interpreters)",
        "Tune exclusion filters against benign administrative activity to achieve high signal-to-noise ratio",
    ],
    assessment_criteria=[
        "Identify Sysmon Event ID 1 and LOLBIN command line arguments",
        "Map download cradle techniques to ATT&CK T1105",
        "Evaluate process creation Sigma detections against positive/negative datasets",
        "Tune administrative filters and pass the quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 practical investigation/emulation tasks", "Score 100% on technical quiz"],
    total_xp=350,
    concept=ROOM_DETECTION_04_CONCEPT,
    tasks=ROOM_DETECTION_04_TASKS,
    default_port=8404,
)
