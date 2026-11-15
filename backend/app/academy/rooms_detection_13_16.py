"""
NO ENTRY Academy - Detection Engineering Track: Rooms 13-16
Room 13: Baseline Profiling & Threshold-Based Detections (detect-13-threshold-detections)
Room 14: Correlation Rules: Multi-Event Detection (detect-14-correlation-rules)
Room 15: Detection Testing with Unit Tests & Synthetic Logs (detect-15-unit-testing-rules)
Room 16: YARA Rules for File & Memory Threat Hunting (detect-16-yara-hunting)
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
# ROOM 13: BASELINE PROFILING & THRESHOLD-BASED DETECTIONS
# ============================================================================

ROOM_DETECTION_13_CONCEPT = RoomConcept(
    technical_term="Baseline Profiling & Statistical Threshold Detections",
    overview=(
        "Threshold-based detection identifies anomalous enterprise activity by establishing statistical baselines "
        "of normal volume, frequency, and distribution over historical windows, alerting when behavior deviates "
        "beyond calculated confidence boundaries (such as 3 standard deviations or quantile limits). In detection engineering, "
        "stateful aggregation queries monitor metric spikes—including failed authentication bursts, mass file encryption/staging, "
        "and rapid DNS query surges—while dynamically accommodating cyclical diurnal patterns and maintenance schedules."
    ),
    simple_analogy=(
        "Like an intelligent municipal water meter monitoring flow: steady kitchen and bathroom usage follows predictable "
        "hourly patterns. If flow abruptly surges to 200 gallons per minute at 3:00 AM, the system detects a catastrophic burst "
        "pipe rather than normal household consumption."
    ),
    technical_definition=(
        "A detection methodology that aggregates discrete event telemetry into stateful metric counters over defined rolling "
        "or tumbling time windows (e.g., sliding 5-minute intervals), comparing observed values against static limits or "
        "dynamic baselines computed from parametric statistics (mean ± n*sigma) or non-parametric percentiles."
    ),
    cybersecurity_context=(
        "Attackers executing password spraying (T1110.003), data staging (T1074), or ransomware file traversal (T1486) "
        "naturally generate high-frequency event clusters. Static threshold alerts often suffer from false positives during "
        "peak business hours or false negatives during night shifts. Modern detection pipelines profile entity-specific "
        "baselines (by user, host, or subnet) to pinpoint volumetric outliers with minimal operational noise."
    ),
    why_it_matters=(
        "Without threshold aggregation, single events like one failed login appear indistinguishable from benign user typos. "
        "Threshold detections provide the critical temporal context required to distinguish malicious high-volume attacks "
        "from routine administrative operations."
    ),
    demonstration=(
        "In this lab, you will analyze corporate authentication and file staging telemetry. You will calculate statistical "
        "deviations, configure stateful rolling window parameters, and deploy a threshold detection rule alerting on abnormal "
        "burst frequencies while filtering out expected batch automation."
    ),
    remediation_guide=(
        "1. Establish rolling baseline windows that account for 24-hour diurnal rhythms and weekend activity drops.\n"
        "2. Group metrics by entity keys (SubjectUserName, WorkstationName, ClientIP) rather than global counters.\n"
        "3. Incorporate sliding windows with variance checks to prevent threshold bypass via low-and-slow distribution.\n"
        "4. Implement dynamic exclusion lists for authorized scheduled backup tasks and administrative scripts."
    ),
)

ROOM_DETECTION_13_TASKS = [
    TaskDefinition(
        task_id="task-01-threshold-metric-mechanics",
        order=1,
        title="Statistical Baseline Profiling & Variance Mechanics",
        instructions=(
            "Review statistical anomaly detection principles. In parametric baseline profiling, identify the standard "
            "statistical measure of dispersion (often abbreviated 'sigma' or calculated as the square root of variance) "
            "used to define upper anomaly thresholds (e.g., mean + 3*sigma)."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["standard deviation", "Standard Deviation", "std dev", "stddev", "sigma"],
        hint="Consider the square root of variance, commonly called standard deviation or sigma.",
    ),
    TaskDefinition(
        task_id="task-02-sliding-window-analysis",
        order=2,
        title="Analyze Rolling Window Telemetry Corpus",
        instructions=(
            "Inspect the baseline telemetry dataset on your workstation:\n"
            "`cat /var/log/detection/threshold_baseline_events.json`\n\n"
            "Identify the burst threshold value (number of failed authentication attempts within a 5-minute sliding window) "
            "that definitively separates adversary password spray attempts from benign administrative retries."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=60,
        accepted_answers=["50", "50 attempts", "50 events", "50/5min"],
        hint="Inspect the threshold_baseline_events.json file for the attack burst count (50).",
    ),
    TaskDefinition(
        task_id="task-03-attck-threshold-mapping",
        order=3,
        title="MITRE ATT&CK Password Spraying Mapping",
        instructions=(
            "Review MITRE ATT&CK Credential Access techniques.\n\n"
            "Adversaries cycle passwords across numerous user accounts in bursts to gain initial access without locking out accounts.\n\n"
            "What MITRE ATT&CK sub-technique ID corresponds to Password Spraying?"
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["T1110.003", "t1110.003", "T1110.003 - Password Spraying"],
        hint="Technique T1110 (Brute Force), Sub-technique .003 (Password Spraying).",
    ),
    TaskDefinition(
        task_id="task-04-threshold-emulation",
        order=4,
        title="Emulate Threshold Detection Telemetry",
        instructions=(
            "Launch the interactive threshold analysis tool on your workstation:\n"
            "`python3 /home/operator/tools/threshold_tool.py --emulate-detection`\n\n"
            "Verify that the threshold detection engine analyzes the rolling window event stream and confirms threshold breach."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=70,
        accepted_answers=["THRESHOLD_DETECTION_VERIFIED"],
        hint="Run threshold_tool.py with --emulate-detection to capture the verification token.",
    ),
    TaskDefinition(
        task_id="task-05-threshold-challenge",
        order=5,
        title="Tune Rolling Window & Validate Threshold Challenge",
        instructions=(
            "Apply the rolling window aggregation parameter to exclude isolated failed logins:\n"
            "`python3 /home/operator/tools/threshold_tool.py --tune-window`\n\n"
            "Then submit the final threshold challenge to validate stateful detection:\n"
            "`python3 /home/operator/tools/threshold_tool.py --challenge`"
        ),
        task_type=TaskType.COMMAND,
        xp_reward=80,
        accepted_answers=["THRESHOLD_DETECTION_VALIDATED"],
        hint="Tune the window parameter with --tune-window, then finalize with --challenge.",
    ),
    TaskDefinition(
        task_id="task-06-threshold-quiz",
        order=6,
        title="Threshold-Based Detection Technical Assessment",
        instructions="Complete the 4-question technical assessment on statistical baselining and window aggregation.",
        task_type=TaskType.QUIZ,
        xp_reward=40,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is the critical difference between a tumbling time window and a sliding (rolling) time window in threshold detection?",
                options=[
                    "A tumbling window evaluates non-overlapping contiguous blocks of time, whereas a sliding window continuously evaluates events over a moving interval of fixed length.",
                    "Tumbling windows run on client browsers, while sliding windows run only on server firewalls.",
                    "Tumbling windows require root privileges, whereas sliding windows are completely unprivileged.",
                    "Sliding windows can only process text logs, while tumbling windows only process PCAP traffic.",
                ],
                correct_index=0,
                explanation="Tumbling windows evaluate non-overlapping intervals (e.g. 12:00-12:05, 12:05-12:10), which can miss attacks straddling the window boundary. Sliding windows move continuously with time.",
            ),
            QuizQuestion(
                id="q2",
                question="Why can static threshold rules (e.g., alert if failed logins > 20) lead to severe false negatives during off-peak hours?",
                options=[
                    "Because an attacker generating 15 failed logins at 3:00 AM represents a massive anomaly compared to normal zero nighttime logins, but remains hidden below the global threshold.",
                    "Because static thresholds automatically shut down when servers enter sleep mode.",
                    "Because static rules only work on HTTP traffic and ignore Windows Security events.",
                    "Because database indexes become fragmented during non-business hours.",
                ],
                correct_index=0,
                explanation="Static thresholds fail to adjust for diurnal traffic curves: 15 failed logins at 3:00 AM is highly suspicious, yet undetectable if the threshold is set for daytime peak volumes.",
            ),
            QuizQuestion(
                id="q3",
                question="How do sophisticated adversaries evade simple threshold-based detection rules?",
                options=[
                    "By executing 'low-and-slow' operations, spacing actions out over long time intervals below the detection window threshold.",
                    "By encrypting the network card firmware.",
                    "By changing their local screen resolution.",
                    "By submitting valid Kerberos tickets for guest accounts.",
                ],
                correct_index=0,
                explanation="Low-and-slow attack techniques distribute requests across time windows or multiple source IPs to stay below single-entity detection thresholds.",
            ),
            QuizQuestion(
                id="q4",
                question="When calculating statistical baselines for authentication events, why is it essential to group metrics by entity (e.g., username or workstation)?",
                options=[
                    "To prevent enterprise-wide legitimate traffic spikes from masking localized account takeover attempts or conversely triggering false alarms across the entire organization.",
                    "Because entity grouping compresses log files by 90% in disk storage.",
                    "Because Microsoft Windows refuses to generate Event ID 4625 without entity groups.",
                    "Because SQL databases cannot sort numbers without alphabetical usernames.",
                ],
                correct_index=0,
                explanation="Entity grouping isolates individual user and host behavior, ensuring alerts trigger on specific anomalous entities rather than diluting counts into enterprise-wide averages.",
            ),
        ],
    ),
]

ROOM_DETECTION_13_DEFINITION = RoomDefinition(
    room_id="detect-13-threshold-detections",
    track=TrackEnum.DETECTION,
    room_number=13,
    title="Baseline Profiling & Threshold-Based Detections",
    short_description="Craft stateful queries alerting when an entity exceeds normal baseline thresholds in time windows.",
    difficulty="Intermediate",
    estimated_duration="50 min",
    prerequisites=["detect-01-foundations-as-code", "detect-07-auth-abuse-rules"],
    required_practical_skills=["Statistical baselining", "Sliding window aggregation", "Threshold tuning"],
    required_lab_type="container_duo",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Master the mathematical principles of baseline profiling and statistical thresholding",
        "Implement rolling vs tumbling time windows to capture stateful attack patterns",
        "Differentiate normal business-hour volume from low-frequency off-hours anomalies",
        "Prevent threshold evasion from low-and-slow attack campaigns",
        "Tune stateful thresholds to eliminate false positives from batch administrative scripts",
    ],
    assessment_criteria=[
        "Identify statistical variance metrics for anomaly boundary definition",
        "Extract burst threshold parameters from simulated authentication datasets",
        "Map volumetric attacks to MITRE ATT&CK Password Spraying",
        "Execute threshold evaluation tool to verify burst trigger",
        "Configure sliding window filters and validate challenge",
        "Pass the technical assessment quiz with 100% accuracy",
    ],
    completion_requirements=["Achieve 100% validation on all 6 tasks"],
    total_xp=350,
    concept=ROOM_DETECTION_13_CONCEPT,
    tasks=ROOM_DETECTION_13_TASKS,
    default_port=8413,
)


# ============================================================================
# ROOM 14: CORRELATION RULES: MULTI-EVENT DETECTION
# ============================================================================

ROOM_DETECTION_14_CONCEPT = RoomConcept(
    technical_term="Multi-Event Temporal Correlation Rules",
    overview=(
        "Multi-event correlation rules link disparate, low-severity security events occurring across different telemetry "
        "sources into a unified, high-confidence alert. Rather than alarming on an isolated email delivery, office document "
        "launch, or single outbound network connection, correlation engines track composite attack chains across time, "
        "verifying that event B followed event A within a shared entity context (such as the same host or user session)."
    ),
    simple_analogy=(
        "Like an airport security tracking system: purchasing a ticket is routine; checking luggage is normal; sprinting "
        "toward an emergency exit door is concerning. However, purchasing a one-way international ticket with cash, abandoning "
        "luggage, and immediately breaching the secure perimeter in sequence triggers an instant emergency lockdown."
    ),
    technical_definition=(
        "A composite detection logic model that evaluates temporal and causal relationships across heterogeneous event streams "
        "(e.g., Sysmon 1 -> Sysmon 3 -> Sysmon 13) sharing primary entity keys (ComputerName, User, ProcessGuid) within "
        "a bounded time constraint (t_delta <= threshold)."
    ),
    cybersecurity_context=(
        "Modern adversary intrusion operations rarely consist of a single catastrophic command. Threat actors leverage multi-stage "
        "attack lifecycles: spearphishing attachment execution (T1566.001) followed by child process spawning (T1059.001), "
        "outbound C2 connection (T1071.001), and registry run key persistence (T1547.001). Individual events frequently resemble "
        "benign activity; correlating the entire chain produces near-zero false positive detections."
    ),
    why_it_matters=(
        "Isolated alert triage overwhelms Security Operations Centers with fragmented, low-context alerts. Multi-event correlation "
        "reconstructs the kill chain automatically, presenting analysts with a cohesive narrative that cuts mean time to respond (MTTR)."
    ),
    demonstration=(
        "In this lab, you will analyze a multi-stage intrusion dataset. You will configure entity join keys, define temporal "
        "sequencing constraints, and deploy a multi-event correlation rule linking macro execution to outbound beaconing."
    ),
    remediation_guide=(
        "1. Define reliable entity join keys (e.g., host.name, user.name, process.entity_id) across all normalized logs.\n"
        "2. Enforce explicit temporal ordering (Event A MUST precede Event B by less than N minutes).\n"
        "3. Configure state memory expiration to purge incomplete chains and prevent memory exhaustion in the SIEM.\n"
        "4. Assign composite severity scores that elevate correlated alerts to Critical/High priority."
    ),
)

ROOM_DETECTION_14_TASKS = [
    TaskDefinition(
        task_id="task-01-correlation-entity-keys",
        order=1,
        title="Entity Join Keys & Correlation Schema Mechanics",
        instructions=(
            "Review multi-source correlation fundamentals. In normalized schemas (like ECS or CIM), identify the universal "
            "hostname field (often `host.name` or `ComputerName`) used as the primary entity join key to correlate "
            "process execution events with local network connection events occurring on the same endpoint."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["host.name", "ComputerName", "hostname", "host", "Computer"],
        hint="Consider the ECS field for endpoint hostname: host.name (or Windows ComputerName).",
    ),
    TaskDefinition(
        task_id="task-02-attack-chain-analysis",
        order=2,
        title="Analyze Multi-Stage Intrusion Sequence",
        instructions=(
            "Inspect the multi-event correlation dataset on your workstation:\n"
            "`cat /var/log/detection/multi_event_correlation_stream.json`\n\n"
            "Trace the chronological sequence of events. Identify the initial Office executable (e.g. `winword.exe` or `excel.exe`) "
            "that spawned the malicious command interpreter child process."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=60,
        accepted_answers=["winword.exe", "winword", "WINWORD.EXE"],
        hint="Look for the parent process of cmd.exe or powershell.exe in the correlation dataset (winword.exe).",
    ),
    TaskDefinition(
        task_id="task-03-attck-phishing-macro-mapping",
        order=3,
        title="MITRE ATT&CK Spearphishing Attachment Mapping",
        instructions=(
            "Review MITRE ATT&CK Initial Access techniques.\n\n"
            "Adversaries send emails with weaponized attachments (such as macro-enabled Word or Excel documents) to execute code on victim endpoints.\n\n"
            "What MITRE ATT&CK sub-technique ID corresponds to Spearphishing Attachment?"
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["T1566.001", "t1566.001", "T1566.001 - Spearphishing Attachment"],
        hint="Technique T1566 (Phishing), Sub-technique .001 (Spearphishing Attachment).",
    ),
    TaskDefinition(
        task_id="task-04-correlation-emulation",
        order=4,
        title="Emulate Multi-Event Correlation Engine",
        instructions=(
            "Execute the correlation rule engine on your workstation:\n"
            "`python3 /home/operator/tools/correlation_rule_tool.py --emulate-detection`\n\n"
            "Verify that the correlation engine evaluates the event stream and identifies the linked kill chain sequence."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=70,
        accepted_answers=["CORRELATION_RULE_VERIFIED"],
        hint="Run correlation_rule_tool.py with --emulate-detection to verify correlation logic.",
    ),
    TaskDefinition(
        task_id="task-05-correlation-challenge",
        order=5,
        title="Tune Temporal Sequence & Validate Challenge",
        instructions=(
            "Configure the temporal sequence ordering and maximum latency threshold:\n"
            "`python3 /home/operator/tools/correlation_rule_tool.py --tune-sequence`\n\n"
            "Then submit the final correlation challenge to validate multi-event detection:\n"
            "`python3 /home/operator/tools/correlation_rule_tool.py --challenge`"
        ),
        task_type=TaskType.COMMAND,
        xp_reward=80,
        accepted_answers=["CORRELATION_RULE_VALIDATED"],
        hint="Tune the sequence with --tune-sequence, then finalize with --challenge.",
    ),
    TaskDefinition(
        task_id="task-06-correlation-quiz",
        order=6,
        title="Multi-Event Correlation Rules Technical Assessment",
        instructions="Complete the 4-question technical assessment on correlation engines and temporal state tracking.",
        task_type=TaskType.QUIZ,
        xp_reward=40,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is it necessary to enforce a maximum time window (TTL) on partial state matches in a SIEM correlation engine?",
                options=[
                    "To prevent unbounded memory growth and avoid correlating unrelated events that occurred days or weeks apart.",
                    "Because SIEM network cards disconnect if state is kept for more than 60 seconds.",
                    "Because SSL certificates expire if an event sequence lasts longer than 15 minutes.",
                    "To comply with GDPR requirement that all logs be deleted immediately upon ingestion.",
                ],
                correct_index=0,
                explanation="If partial state matches never expire, the correlation engine will consume massive RAM holding pending states, and risk correlating unrelated benign events across weeks.",
            ),
            QuizQuestion(
                id="q2",
                question="In a composite rule correlating an email delivery, process launch, and outbound network connection, what is the best entity join key to link the process launch to the network connection?",
                options=[
                    "Process GUID / PID combined with Hostname",
                    "Public IP address of the email sender",
                    "Operating system version number",
                    "CPU core utilization percentage",
                ],
                correct_index=0,
                explanation="On an endpoint, binding the unique Process GUID/PID and Hostname ensures the outbound socket connection is accurately attributed to the exact spawned child process.",
            ),
            QuizQuestion(
                id="q3",
                question="What is the primary advantage of multi-event correlation over standalone single-event alerts?",
                options=[
                    "Significantly higher signal-to-noise ratio and dramatic reduction in false positives by requiring multiple stages of the attack chain to coincide.",
                    "It eliminates the need to install endpoint detection agents.",
                    "It guarantees that attackers can never encrypt files.",
                    "It runs 10 times faster than simple grep commands.",
                ],
                correct_index=0,
                explanation="Requiring multiple distinct phases (e.g. macro launch -> shell spawn -> network beacon) to coincide within minutes reduces false alarms by orders of magnitude.",
            ),
            QuizQuestion(
                id="q4",
                question="If an adversary delays their secondary action (e.g. waits 48 hours after macro execution before launching network beaconing), how should detection engineering respond?",
                options=[
                    "Complement short-window correlation with standalone persistence and LOLBIN execution rules, and extend long-term hunting queries.",
                    "Increase the short-window correlation timer to 1 year for all rules.",
                    "Ignore the intrusion because delayed attacks are harmless.",
                    "Disable correlation engines completely.",
                ],
                correct_index=0,
                explanation="Defense-in-depth requires layers: short temporal correlation catches rapid automated exploits, while standalone behavior rules and threat hunting catch delayed, human-operated attacks.",
            ),
        ],
    ),
]

ROOM_DETECTION_14_DEFINITION = RoomDefinition(
    room_id="detect-14-correlation-rules",
    track=TrackEnum.DETECTION,
    room_number=14,
    title="Correlation Rules: Multi-Event Detection",
    short_description="Link multiple independent event stages (phishing click + process launch + C2 connection) into one high-severity alert.",
    difficulty="Advanced",
    estimated_duration="65 min",
    prerequisites=["detect-04-process-creation-rules", "detect-05-network-connection-rules", "detect-13-threshold-detections"],
    required_practical_skills=["Multi-event correlation", "Stateful event sequencing", "Entity key join analysis"],
    required_lab_type="container_duo",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Understand the architecture of stateful SIEM and CEP (Complex Event Processing) correlation engines",
        "Define primary entity join keys across heterogeneous network and host telemetry",
        "Construct multi-event temporal sequences with strict ordering and duration constraints",
        "Synthesize fragmented, low-fidelity event streams into high-fidelity composite alerts",
        "Mitigate state memory saturation through proper time-to-live (TTL) expiration policies",
    ],
    assessment_criteria=[
        "Identify standard entity join keys for host-network log correlation",
        "Trace multi-stage attack chains in chronological event corpora",
        "Map weaponized macro execution to MITRE ATT&CK Spearphishing Attachment",
        "Execute correlation engine emulation verifying composite sequence detection",
        "Tune temporal latency parameters and validate challenge",
        "Pass the technical assessment quiz with 100% accuracy",
    ],
    completion_requirements=["Achieve 100% validation on all 6 tasks"],
    total_xp=350,
    concept=ROOM_DETECTION_14_CONCEPT,
    tasks=ROOM_DETECTION_14_TASKS,
    default_port=8414,
)


# ============================================================================
# ROOM 15: DETECTION TESTING WITH UNIT TESTS & SYNTHETIC LOGS
# ============================================================================

ROOM_DETECTION_15_CONCEPT = RoomConcept(
    technical_term="Detection-as-Code Unit Testing & Synthetic Telemetry Fixtures",
    overview=(
        "Detection testing treats detection rules as production software artifacts subject to rigorous automated verification. "
        "Just as software engineers write unit tests to validate application code, detection engineers maintain test suites "
        "combining synthetic positive log fixtures (confirming true positives trigger as expected) and negative log fixtures "
        "(verifying benign corporate operations do not cause false alarms). Automated CI pipelines run these tests on every "
        "commit, preventing rule regressions and syntax errors before deployment to production SIEMs."
    ),
    simple_analogy=(
        "Like automated smoke testing in automobile manufacturing: before a new vehicle model enters the assembly line, "
        "engineers run crash simulations and sensor diagnostics on computer-generated collision models to verify the airbag "
        "deploys on actual impacts but never deploys when the car merely hits a speed bump."
    ),
    technical_definition=(
        "An automated quality assurance methodology for detection logic, utilizing structured synthetic event corpuses "
        "and unit testing frameworks (e.g. pytest, sigma-test) to assert expected matching behavior (Assert True for positive cases, "
        "Assert False for negative cases) across rule revisions."
    ),
    cybersecurity_context=(
        "Production detection pipelines frequently fail silently when vendor log schemas change or when an engineer edits a regex "
        "without realizing they introduced catastrophic backtracking or over-filtered legitimate alerts. Establishing automated "
        "unit test suites with synthetic test logs ensures rules remain robust, testable, and reliable over their entire lifecycle."
    ),
    why_it_matters=(
        "Deploying untested detection rules directly to production SIEMs results in alert storms that blind SOC analysts, or "
        "broken syntax that silently leaves enterprise systems completely unprotected against active adversary campaigns."
    ),
    demonstration=(
        "In this lab, you will inspect synthetic test fixtures containing positive attack samples and negative baseline samples. "
        "You will run an automated detection test runner, diagnose a failing negative test case, tune the rule fixture assertion, "
        "and validate 100% test pass rate."
    ),
    remediation_guide=(
        "1. Maintain pairs of positive and negative synthetic log fixtures for every authored detection rule.\n"
        "2. Integrate automated testing tools (such as pytest or sigma-test) into git pre-commit hooks and CI pipelines.\n"
        "3. Explicitly test schema edge cases, including null fields, variable case sensitivity, and unusual character encoding.\n"
        "4. Enforce strict build failure policies: no detection rule may be deployed to production if any unit test fails."
    ),
)

ROOM_DETECTION_15_TASKS = [
    TaskDefinition(
        task_id="task-01-testing-principles-mechanics",
        order=1,
        title="Detection Unit Testing Principles & Test Fixtures",
        instructions=(
            "Review software engineering and detection-as-code principles. In automated testing frameworks, identify the term "
            "used for a test case specifically designed to verify that benign baseline activity does NOT trigger an alert "
            "(commonly referred to as a 'negative' test case)."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["negative", "negative test", "negative test case", "Negative"],
        hint="Consider the counterpart to a positive test case: a negative test case.",
    ),
    TaskDefinition(
        task_id="task-02-synthetic-fixture-analysis",
        order=2,
        title="Analyze Synthetic Log Test Fixtures",
        instructions=(
            "Inspect the synthetic test fixture suite on your workstation:\n"
            "`cat /var/log/detection/synthetic_test_fixtures.json`\n\n"
            "Identify the standard test runner assertion keyword (such as `PASSED` or `assert`) evaluated when all positive "
            "and negative test cases execute successfully without unexpected matches."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=60,
        accepted_answers=["PASSED", "assert", "passed", "PASS"],
        hint="Review the expected status keyword in synthetic_test_fixtures.json (PASSED).",
    ),
    TaskDefinition(
        task_id="task-03-attck-scripting-interpreter-mapping",
        order=3,
        title="MITRE ATT&CK Command and Scripting Mapping",
        instructions=(
            "Review MITRE ATT&CK Execution techniques.\n\n"
            "Adversaries abuse command and script interpreters (such as PowerShell, Bash, and Python) to execute arbitrary code.\n\n"
            "What MITRE ATT&CK technique ID corresponds to Command and Scripting Interpreter?"
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["T1059", "t1059", "T1059 - Command and Scripting Interpreter"],
        hint="Technique T1059 under the Execution tactic.",
    ),
    TaskDefinition(
        task_id="task-04-testing-unit-emulation",
        order=4,
        title="Execute Automated Detection Test Suite",
        instructions=(
            "Execute the automated detection unit test harness on your workstation:\n"
            "`python3 /home/operator/tools/detection_testing_tool.py --emulate-detection`\n\n"
            "Observe test execution against positive and negative test fixtures, verifying unit test runner execution."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=70,
        accepted_answers=["DETECTION_UNIT_TEST_VERIFIED"],
        hint="Run detection_testing_tool.py with --emulate-detection to execute unit test suite.",
    ),
    TaskDefinition(
        task_id="task-05-testing-unit-challenge",
        order=5,
        title="Tune Test Fixtures & Validate Challenge",
        instructions=(
            "Resolve the failing negative test fixture assertion by tuning boundary conditions:\n"
            "`python3 /home/operator/tools/detection_testing_tool.py --tune-fixtures`\n\n"
            "Then execute the test suite challenge to validate 100% passing detection tests:\n"
            "`python3 /home/operator/tools/detection_testing_tool.py --challenge`"
        ),
        task_type=TaskType.COMMAND,
        xp_reward=80,
        accepted_answers=["DETECTION_UNIT_TEST_VALIDATED"],
        hint="Tune fixture assertions with --tune-fixtures, then finalize with --challenge.",
    ),
    TaskDefinition(
        task_id="task-06-testing-quiz",
        order=6,
        title="Detection Unit Testing Technical Assessment",
        instructions="Complete the 4-question technical assessment on synthetic log testing and CI test harnesses.",
        task_type=TaskType.QUIZ,
        xp_reward=40,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is it critical to test detection rules against negative test cases in addition to positive attack cases?",
                options=[
                    "To verify that benign normal business activity matching similar keywords does not cause false positives.",
                    "Because positive test cases can damage database hardware.",
                    "To ensure the detection engineer's computer runs faster.",
                    "Because negative test cases are required to renew SIEM vendor licenses.",
                ],
                correct_index=0,
                explanation="Testing against negative cases ensures the rule is sufficiently specific to ignore benign administrative commands, preventing costly alert fatigue.",
            ),
            QuizQuestion(
                id="q2",
                question="What is a major advantage of using synthetic log fixtures over replaying raw production logs in automated testing?",
                options=[
                    "Synthetic logs can be deterministically crafted to isolate specific edge cases and contain zero sensitive PII or confidential company data.",
                    "Synthetic logs never take up any disk space.",
                    "Raw production logs cannot be parsed by python scripts.",
                    "Synthetic logs automatically patch vulnerabilities on remote endpoints.",
                ],
                correct_index=0,
                explanation="Synthetic logs provide clean, deterministic test fixtures with predictable timestamps and values while avoiding PII privacy violations.",
            ),
            QuizQuestion(
                id="q3",
                question="In a Continuous Integration (CI) pipeline for Detection-as-Code, what should happen if a modified rule fails a unit test?",
                options=[
                    "The CI pipeline must block the merge request, preventing the broken rule from being deployed to production.",
                    "The pipeline should silently ignore the failure and delete the test.",
                    "The pipeline should email all employees asking for help.",
                    "The rule should be automatically published with high severity.",
                ],
                correct_index=0,
                explanation="In modern Detection-as-Code pipelines, CI gates prevent regressions by blocking merges and deployments when any unit test fails.",
            ),
            QuizQuestion(
                id="q4",
                question="What type of error occurs when a detection rule's regular expression contains catastrophic backtracking?",
                options=[
                    "The regex engine consumes 100% CPU on certain inputs, potentially freezing the log parsing pipeline (ReDoS).",
                    "The SIEM deletes all log files permanently.",
                    "The computer monitor turns off.",
                    "The operating system reverts to factory settings.",
                ],
                correct_index=0,
                explanation="Catastrophic backtracking in poorly structured regular expressions causes exponential execution time on specific strings, causing Denial of Service in log ingest pipelines.",
            ),
        ],
    ),
]

ROOM_DETECTION_15_DEFINITION = RoomDefinition(
    room_id="detect-15-unit-testing-rules",
    track=TrackEnum.DETECTION,
    room_number=15,
    title="Detection Testing with Unit Tests & Synthetic Logs",
    short_description="Test Sigma and SIEM rules against synthetic positive and negative log corpuses in automated CI.",
    difficulty="Intermediate",
    estimated_duration="50 min",
    prerequisites=["detect-01-foundations-as-code", "detect-03-sigma-syntax"],
    required_practical_skills=["Unit testing methodologies", "Synthetic log generation", "CI pipeline test automation"],
    required_lab_type="container_duo",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Implement Detection-as-Code automated testing harnesses using structured fixtures",
        "Author synthetic positive log events confirming true positive rule activation",
        "Author synthetic negative log events confirming false positive resistance",
        "Diagnose and resolve rule regression bugs before production deployment",
        "Integrate automated test execution gates into Continuous Integration pipelines",
    ],
    assessment_criteria=[
        "Identify core principles of positive vs negative test case design",
        "Analyze synthetic test fixture suites and verify assertion mechanics",
        "Map script abuse to MITRE ATT&CK Command and Scripting Interpreter",
        "Execute automated detection test runner against synthetic corpus",
        "Tune fixture assertions to eliminate false positive failures and validate challenge",
        "Pass the technical assessment quiz with 100% accuracy",
    ],
    completion_requirements=["Achieve 100% validation on all 6 tasks"],
    total_xp=350,
    concept=ROOM_DETECTION_15_CONCEPT,
    tasks=ROOM_DETECTION_15_TASKS,
    default_port=8415,
)


# ============================================================================
# ROOM 16: YARA RULES FOR FILE & MEMORY THREAT HUNTING
# ============================================================================

ROOM_DETECTION_16_CONCEPT = RoomConcept(
    technical_term="YARA Signatures for File System & Process Memory Threat Hunting",
    overview=(
        "YARA is the de facto standard pattern-matching engine for malware researchers, detection engineers, and threat hunters. "
        "YARA rules describe malware families and threat actor artifacts using combinations of text strings, wildcards, "
        "regular expressions, and hexadecimal byte sequences. Crucially, YARA operates both statically against files on disk "
        "and dynamically across volatile process memory, allowing hunters to detect unpacked shellcode, injected payloads, "
        "and in-memory beacon configurations that never touch the file system."
    ),
    simple_analogy=(
        "Like genetic DNA profiling in forensic biology: rather than identifying a suspect solely by their clothing (which can be "
        "easily swapped like an executable file name or hash), forensic scientists sequence immutable DNA markers. Even if malware "
        "changes its name or compile time, unique byte sequences and functional strings remain exposed in memory."
    ),
    technical_definition=(
        "A declarative rule syntax consisting of metadata, string definitions (text, hex, or regex with modifiers like `ascii`, `wide`, "
        "`nocase`), and a boolean condition expression evaluating match counts, offsets, and header characteristics (`uint16(0) == 0x5A4D`)."
    ),
    cybersecurity_context=(
        "Threat actors frequently utilize packers, crypters, and in-memory execution (such as reflective DLL loading or process hollowing) "
        "to evade traditional disk antivirus. Once loaded into memory, however, the executable sections must deobfuscate into plaintext "
        "machine code and configuration strings. YARA rules scanning endpoint process memory catch malware at its most vulnerable moment."
    ),
    why_it_matters=(
        "Hashes (MD5, SHA256) are brittle and change with a single byte modification. YARA rules target core functionality, "
        "unique cryptographic constants, and C2 communication protocols, creating resilient detections that withstand polymorphic variants."
    ),
    demonstration=(
        "In this lab, you will inspect suspicious process memory dumps and disk artifacts. You will author a YARA rule combining "
        "hexadecimal shellcode patterns with ASCII/wide strings, apply PE header constraints, and scan target memory to isolate an active threat."
    ),
    remediation_guide=(
        "1. Combine string signatures with binary header conditions (`uint16(0) == 0x5A4D` for Windows PE binaries).\n"
        "2. Use both `ascii` and `wide` modifiers to catch strings stored in UTF-16 Unicode format.\n"
        "3. Incorporate wildcard hex sequences (`??`) to accommodate variable memory addresses and offsets.\n"
        "4. Enforce `filesize` boundaries to prevent scanning engines from wasting memory on massive log archives."
    ),
)

ROOM_DETECTION_16_TASKS = [
    TaskDefinition(
        task_id="task-01-yara-pe-header-mechanics",
        order=1,
        title="YARA PE Header & Magic Byte Conditions",
        instructions=(
            "Review YARA condition syntax and Windows PE file structure. In YARA conditions, identify the 2-byte hexadecimal "
            "integer value (representing the ASCII characters 'MZ') commonly asserted at offset 0 (`uint16(0) == 0x5A4D`) "
            "to ensure the rule only evaluates Windows Portable Executables."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["0x5A4D", "0x5a4d", "5A4D", "5a4d", "MZ"],
        hint="Consider the hexadecimal representation of the 'MZ' magic bytes: 0x5A4D.",
    ),
    TaskDefinition(
        task_id="task-02-yara-hex-wildcard-analysis",
        order=2,
        title="Analyze In-Memory Hex Pattern with Wildcards",
        instructions=(
            "Inspect the YARA target memory sample dataset on your workstation:\n"
            "`cat /var/log/detection/yara_target_memory_samples.json`\n\n"
            "Review the suspicious in-memory shellcode pattern. Count how many consecutive wildcard nibbles/bytes "
            "(represented by `??`) are used in the call instruction `{ E8 ?? ?? ?? ?? 85 C0 }` to accommodate relative offsets."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=60,
        accepted_answers=["4", "4 bytes", "four", "4 wildcards"],
        hint="Count the ?? pairs between E8 and 85: there are four wildcard bytes (4).",
    ),
    TaskDefinition(
        task_id="task-03-attck-obfuscation-mapping",
        order=3,
        title="MITRE ATT&CK Obfuscated Files Mapping",
        instructions=(
            "Review MITRE ATT&CK Defense Evasion techniques.\n\n"
            "Adversaries obfuscate executable code and payloads in files and memory to evade signature-based security controls.\n\n"
            "What MITRE ATT&CK technique ID corresponds to Obfuscated Files or Information?"
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["T1027", "t1027", "T1027 - Obfuscated Files or Information"],
        hint="Technique T1027 under Defense Evasion.",
    ),
    TaskDefinition(
        task_id="task-04-yara-hunting-emulation",
        order=4,
        title="Scan Process Memory with YARA Engine",
        instructions=(
            "Execute the YARA memory scanning tool on your workstation:\n"
            "`python3 /home/operator/tools/yara_hunting_tool.py --emulate-detection`\n\n"
            "Verify that the YARA engine compiles rule signatures and scans the target process memory space."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=70,
        accepted_answers=["YARA_HUNTING_VERIFIED"],
        hint="Run yara_hunting_tool.py with --emulate-detection to execute in-memory scan.",
    ),
    TaskDefinition(
        task_id="task-05-yara-hunting-challenge",
        order=5,
        title="Tune Condition Optimization & Validate Challenge",
        instructions=(
            "Optimize the YARA condition with PE magic byte verification and filesize limits:\n"
            "`python3 /home/operator/tools/yara_hunting_tool.py --tune-condition`\n\n"
            "Then execute the final threat hunting challenge to validate YARA detection:\n"
            "`python3 /home/operator/tools/yara_hunting_tool.py --challenge`"
        ),
        task_type=TaskType.COMMAND,
        xp_reward=80,
        accepted_answers=["YARA_HUNTING_VALIDATED"],
        hint="Tune condition with --tune-condition, then finalize with --challenge.",
    ),
    TaskDefinition(
        task_id="task-06-yara-quiz",
        order=6,
        title="YARA Rules & Threat Hunting Technical Assessment",
        instructions="Complete the 4-question technical assessment on YARA rule structure and memory threat hunting.",
        task_type=TaskType.QUIZ,
        xp_reward=40,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is it crucial to specify the 'wide' modifier alongside 'ascii' when searching for string indicators in Windows executables?",
                options=[
                    "Because Windows internal APIs and binaries frequently store strings encoded as 2-byte UTF-16 LE (Unicode), which ASCII-only rules miss.",
                    "Because 'wide' increases the font size of the text output in the terminal.",
                    "Because 'wide' allows the YARA rule to run across 64-bit operating systems.",
                    "Because 'ascii' rules only work on Linux ELF files.",
                ],
                correct_index=0,
                explanation="Windows binaries heavily utilize UTF-16 Little Endian encoding (2 bytes per character). The `wide` modifier instructs YARA to match characters separated by null bytes.",
            ),
            QuizQuestion(
                id="q2",
                question="What is the performance hazard of defining extremely short string atoms (e.g. $s = 'http') in a YARA rule scanned across gigabytes of memory?",
                options=[
                    "YARA must evaluate condition logic on millions of common string matches, causing massive CPU spikes and severe memory scanner slowdowns.",
                    "The operating system will crash with a Blue Screen of Death.",
                    "Short strings automatically corrupt the target process memory.",
                    "YARA rules with short strings are rejected by compiler syntax rules.",
                ],
                correct_index=0,
                explanation="Short strings appear ubiquitously across memory and files, generating millions of match candidates that overwhelm YARA's Aho-Corasick matching engine and degrade performance.",
            ),
            QuizQuestion(
                id="q3",
                question="How does in-memory YARA threat hunting detect packed or reflective malware that evades static disk scanning?",
                options=[
                    "In order to execute, packed binaries must unpack their payload into virtual memory, exposing unencrypted shellcode and C2 strings to memory scanners.",
                    "Memory scanners rewrite the malware's assembly instructions to print out the password.",
                    "By blocking network ports before the file is downloaded.",
                    "By replacing the Windows kernel with an emulated sandbox.",
                ],
                correct_index=0,
                explanation="Packers and crypters disguise disk payloads, but at execution time the CPU must read plaintext machine instructions in RAM, where memory YARA scans can detect them.",
            ),
            QuizQuestion(
                id="q4",
                question="In YARA rule condition syntax, what does the expression '2 of ($str_*)' specify?",
                options=[
                    "At least two strings whose variable names begin with '$str_' must match in the target sample.",
                    "The string '$str_' must occur exactly twice in the first 100 bytes of the file.",
                    "The rule must be compiled two consecutive times before scanning.",
                    "Only the second process thread in memory will be inspected.",
                ],
                correct_index=0,
                explanation="Wildcard string sets with quantifiers like `2 of ($str_*)` require that at least 2 distinct strings from the named set match anywhere in the inspected target.",
            ),
        ],
    ),
]

ROOM_DETECTION_16_DEFINITION = RoomDefinition(
    room_id="detect-16-yara-hunting",
    track=TrackEnum.DETECTION,
    room_number=16,
    title="YARA Rules for File & Memory Threat Hunting",
    short_description="Write string and hexadecimal YARA rules to detect malware signatures and packed payloads in memory.",
    difficulty="Advanced",
    estimated_duration="60 min",
    prerequisites=["detect-01-foundations-as-code", "detect-03-sigma-syntax"],
    required_practical_skills=["YARA rule authoring", "Hexadecimal pattern matching with wildcards", "In-memory threat hunting"],
    required_lab_type="container_duo",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Master the YARA rule specification including meta, strings, and condition blocks",
        "Author resilient hexadecimal byte patterns utilizing single- and multi-byte wildcards",
        "Apply string modifiers (ascii, wide, nocase) to match Unicode payloads in memory",
        "Construct performant condition expressions leveraging PE header checks and filesize limits",
        "Perform in-memory threat hunting against injected shellcode and unpacked C2 beacons",
    ],
    assessment_criteria=[
        "Identify Windows PE magic byte condition assertions (0x5A4D)",
        "Analyze wildcard sequences in hexadecimal shellcode patterns",
        "Map obfuscated payloads to MITRE ATT&CK Obfuscated Files or Information",
        "Execute YARA memory scanner emulation against target memory dump",
        "Tune condition optimizations with filesize guards and validate challenge",
        "Pass the technical assessment quiz with 100% accuracy",
    ],
    completion_requirements=["Achieve 100% validation on all 6 tasks"],
    total_xp=350,
    concept=ROOM_DETECTION_16_CONCEPT,
    tasks=ROOM_DETECTION_16_TASKS,
    default_port=8416,
)

