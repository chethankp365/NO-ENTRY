"""
Detection Engineering Rooms 09–12 Room Definitions for NO ENTRY Cybersecurity Academy:
- Room 09: Writing Web Application Detection Rules (SQLi, XSS, LFI) (detect-09-web-detection-rules)
- Room 10: ModSecurity Core Rule Set Tuning & Custom Rules (detect-10-modsec-crs-tuning)
- Room 11: Wazuh / OSSEC Rules & Decoders (detect-11-wazuh-decoders-rules)
- Room 12: Tuning Detections & Reducing False Positives (detect-12-reducing-false-positives)

Provides deep technical concepts, 6 tasks (350 XP per room; 1,400 XP total),
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
# DETECTION ROOM 09: WRITING WEB APPLICATION DETECTION RULES (SQLi, XSS, LFI)
# ============================================================================

ROOM_DETECTION_09_CONCEPT = RoomConcept(
    overview=(
        "Web application attack detection focuses on inspecting HTTP transaction logs, reverse proxy streams, and web "
        "application firewall events to identify exploitation attempts targeting server-side and client-side vulnerabilities. "
        "Unlike endpoint process creation auditing, web detection requires evaluating URL query parameters, HTTP headers, request bodies, "
        "and server response codes across high-volume access logs. Detection engineers must author rules that recognize SQL injection (SQLi) "
        "tautologies and UNION clauses, Cross-Site Scripting (XSS) script injections, and Local File Inclusion (LFI) directory traversals, "
        "while implementing recursive URL-decoding to defeat obfuscation and encoding evasion."
    ),
    simple_analogy=(
        "Think of an international customs border control checkpoint inspecting cargo manifests and baggage slips. "
        "Most travelers submit standard declarations in plain English (normal HTTP requests). An attacker attempts to smuggle prohibited "
        "goods by disguising the cargo description using code words or foreign ciphers (URL encoding `%27%20OR%201=1`). "
        "If the customs officer only checks for literal English words without translating the ciphers (URL decoding), the contraband passes through. "
        "A well-engineered inspection protocol automatically decodes all layers of packaging before comparing contents against the contraband registry."
    ),
    technical_term="Web Access Telemetry Analysis & HTTP Payload Deobfuscation (W3C / Nginx JSON / Apache Combined)",
    technical_definition=(
        "Web application attack detection analyzes structured HTTP telemetry records capturing fields such as `cs-method` (HTTP verb), "
        "`cs-uri-stem` (target path), `cs-uri-query` (query parameters), `cs-headers` (User-Agent, Cookie, Referer), and `sc-status` (HTTP status code). "
        "High-fidelity detection rules combine pattern-matching logic (Sigma `category: webserver`) with string transformation pipelines that perform "
        "recursive percentage-decoding, null-byte stripping, and delimiter normalization prior to evaluating attack regular expressions."
    ),
    cybersecurity_context=(
        "In enterprise environments, public-facing web applications are subjected to continuous automated scanning and manual exploitation attempts. "
        "According to MITRE ATT&CK T1190 (Exploit Public-Facing Application), web vulnerabilities represent the leading initial access vector. "
        "Detection engineers write Sigma and SIEM rules targeting WAF and reverse-proxy logs to alert SOC analysts when an anomalous parameter matches "
        "SQL comment syntax (`--`, `/* */`), XSS event handlers (`onerror=`, `<script>`), or directory traversal sequences (`../`, `..%2f`)."
    ),
    why_it_matters=(
        "Relying solely on backend error logs creates massive defensive blind spots. Successful SQL injections and LFI reads often return HTTP 200 OK, "
        "meaning an intrusion can succeed without throwing unhandled application exceptions. Furthermore, sophisticated adversaries use double "
        "URL-encoding (`%2527`) or UTF-8 overlong encodings to slip past naive pattern matchers. Detection rules must enforce canonicalization "
        "to ensure consistent threat visibility."
    ),
    demonstration=(
        "1. Inspect incoming HTTP access telemetry record:\n"
        "   GET /catalog/products?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1\n"
        "2. Apply URL decoding transformation to normalize query string:\n"
        "   `id=1' UNION SELECT username,password FROM users--`\n"
        "3. Match against Sigma web detection selection:\n"
        "   `cs-uri-query|contains: ['UNION SELECT', 'UNION ALL SELECT', '\' OR \'1\'=\'1']`\n"
        "4. Trigger high-severity security alert: `SQL Injection Attack Detected Against Catalog API`."
    ),
    remediation_guide=(
        "1. Developers must implement parameterized prepared statements (SQLi), context-aware output encoding (XSS), and strict file path whitelists (LFI).\n"
        "2. Detection engineers must configure log collectors to record decoded query strings and request bodies wherever feasible.\n"
        "3. Implement normalization preprocessors in SIEM ingestion pipelines to resolve `%2e%2e%2f` and `%2527` before rule evaluation.\n"
        "4. Maintain exclusion lists for legitimate developer administrative tools and authorized penetration testing source IP addresses."
    ),
)

ROOM_DETECTION_09_TASKS = [
    TaskDefinition(
        task_id="task-01-web-log-schema-mechanics",
        order=1,
        title="Web Log Schema & HTTP Telemetry Mechanics",
        instructions=(
            "Review the web server access log specifications and HTTP request mechanics. "
            "Identify the standard HTTP method most frequently observed when adversaries pass SQL injection payloads inside URL query strings."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["GET"],
        hint="Consider which HTTP verb appends key-value parameters directly to the target URL path.",
    ),
    TaskDefinition(
        task_id="task-02-sqli-signature-analysis",
        order=2,
        title="SQL Injection Delimiter & Syntax Analysis",
        instructions=(
            "Inspect the web application attack dataset. Identify the standard SQL comment delimiter sequence "
            "(consisting of two consecutive punctuation symbols) commonly used by attackers to truncate the remainder of a backend query."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=60,
        accepted_answers=["--"],
        hint="In ANSI SQL and SQLite, two consecutive hyphens signify an inline comment.",
    ),
    TaskDefinition(
        task_id="task-03-attck-web-exploit-mapping",
        order=3,
        title="MITRE ATT&CK Mapping: Exploit Public-Facing Application",
        instructions=(
            "Identify the enterprise MITRE ATT&CK technique ID corresponding to adversary exploitation of public-facing web applications "
            "and APIs (e.g., SQLi, XSS, and command injection attacks against web servers)."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["T1190"],
        hint="Format: T1xxx. This is a foundational Initial Access technique in MITRE ATT&CK.",
    ),
    TaskDefinition(
        task_id="task-04-web-detection-emulation",
        order=4,
        title="Web Application Attack Rule Emulation",
        instructions=(
            "Launch your isolated lab environment. Execute the web detection CLI tool with `--emulate-detection` to evaluate "
            "your Sigma detection rule against synthetic web server access logs containing SQL injection and path traversal attempts."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=70,
        accepted_answers=["WEB_DETECTION_VERIFIED"],
        hint="Execute: `python3 /home/operator/tools/web_detection_tool.py --emulate-detection`",
    ),
    TaskDefinition(
        task_id="task-05-web-detection-challenge",
        order=5,
        title="URL Normalization & Multi-Attack Validation Challenge",
        instructions=(
            "Adversaries employ URL-encoding (`%27`, `%20`, `%2e%2e%2f`) to evade simplistic pattern matchers. "
            "Tune your detection pipeline with `--tune-urldecode` to enforce automated URL-decoding prior to inspection, "
            "then submit `--challenge` to validate detection accuracy across SQLi, XSS, and LFI attacks with zero false positives."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=80,
        accepted_answers=["WEB_DETECTION_VALIDATED"],
        hint="Execute `--tune-urldecode` followed by `--challenge` using `/home/operator/tools/web_detection_tool.py`.",
    ),
    TaskDefinition(
        task_id="task-06-web-detection-quiz",
        order=6,
        title="Web Application Detection Technical Assessment",
        instructions="Complete the 4-question technical assessment to verify mastery of web application detection engineering.",
        task_type=TaskType.QUIZ,
        xp_reward=40,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is URL canonicalization and decoding essential before evaluating web detection rules?",
                options=[
                    "Because adversaries use URL-encoding like `%27` and `%2e%2e%2f` to bypass plain-text string signatures",
                    "Because web servers automatically discard any log entries containing encoded characters",
                    "Because Sigma rules cannot parse files larger than 10 kilobytes without decompression",
                    "Because HTTP/2 and HTTP/3 protocols forbid the transmission of hexadecimal percent signs",
                ],
                correct_index=0,
                correct_option_index=0,
                explanation="Attackers frequently encode sensitive characters (e.g. quotes as `%27`, slashes as `%2f`) to bypass basic pattern matching. Normalizing input before signature evaluation is essential to close evasion gaps.",
            ),
            QuizQuestion(
                id="q2",
                question="In a Sigma rule designed for web server access logs, what logsource category is typically specified?",
                options=[
                    "category: webserver",
                    "category: kernel_memory",
                    "category: process_creation",
                    "category: active_directory",
                ],
                correct_index=0,
                correct_option_index=0,
                explanation="Sigma specifies `category: webserver` for rules targeting reverse proxies and HTTP daemon access telemetry like Nginx, Apache, or IIS.",
            ),
            QuizQuestion(
                id="q3",
                question="Which pattern in an HTTP request URI most strongly indicates a Local File Inclusion (LFI) or path traversal attack?",
                options=[
                    "../..//etc/passwd",
                    "SELECT COUNT(*) FROM information_schema",
                    "<script>alert(document.cookie)</script>",
                    "certutil.exe -urlcache -split",
                ],
                correct_index=0,
                correct_option_index=0,
                explanation="Directory traversal sequences like `../../` combined with sensitive operating system paths like `/etc/passwd` or `win.ini` are hallmarks of LFI exploitation.",
            ),
            QuizQuestion(
                id="q4",
                question="Why is inspecting HTTP response status codes (`sc-status`) alone insufficient for detecting successful web exploitation?",
                options=[
                    "Because successful SQL injection or file inclusion attacks frequently return HTTP 200 OK with the exfiltrated data",
                    "Because web application firewalls always rewrite all status codes to HTTP 500 Internal Error",
                    "Because HTTP status codes are only recorded in browser debug logs, not server access logs",
                    "Because web servers randomly select HTTP status codes when responding to unauthorized clients",
                ],
                correct_index=0,
                correct_option_index=0,
                explanation="An attacker who successfully exploits a SQL injection or LFI vulnerability receives the requested data within a standard HTTP 200 OK response; the server does not register an error.",
            ),
        ],
    ),
]

ROOM_DETECTION_09_DEFINITION = RoomDefinition(
    room_id="detect-09-web-detection-rules",
    track=TrackEnum.DETECTION,
    room_number=9,
    title="Writing Web Application Detection Rules (SQLi, XSS, LFI)",
    short_description="Analyze web server access logs and author Sigma rules detecting SQL injection, Cross-Site Scripting, and Local File Inclusion while implementing automated URL deobfuscation.",
    difficulty="Intermediate",
    estimated_duration="50 min",
    prerequisites=["detect-01-foundations-as-code", "detect-03-sigma-syntax"],
    required_practical_skills=["Web access log analysis", "Regular expression rule authoring", "SQLi/XSS/LFI signature identification", "URL deobfuscation"],
    required_lab_type="container_duo",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Author high-fidelity Sigma rules for web server access telemetry (category: webserver)",
        "Identify signatures for SQL injection (UNION SELECT, tautologies), XSS (<script>, event handlers), and LFI (../)",
        "Implement automated URL-decoding normalization to defeat evasion via percent-encoding",
        "Correlate request URI parameters and HTTP response codes to detect exploitation success",
    ],
    assessment_criteria=[
        "Identify standard web access telemetry fields and attack delimiters",
        "Map web application attacks to MITRE ATT&CK T1190",
        "Verify Sigma rule against simulated SQLi, XSS, and LFI log corpuses",
        "Tune URL-decoding preprocessors and score 100% on web detection quiz",
    ],
    completion_requirements=["Complete all 5 practical investigation/emulation tasks", "Score 100% on technical quiz"],
    total_xp=350,
    concept=ROOM_DETECTION_09_CONCEPT,
    tasks=ROOM_DETECTION_09_TASKS,
    default_port=8409,
)


# ============================================================================
# DETECTION ROOM 10: MODSECURITY CORE RULE SET TUNING & CUSTOM RULES
# ============================================================================

ROOM_DETECTION_10_CONCEPT = RoomConcept(
    overview=(
        "ModSecurity (libmodsecurity) is the industry-standard open-source Web Application Firewall (WAF) engine. "
        "Paired with the OWASP ModSecurity Core Rule Set (CRS), it provides generic, signature-based protection against the "
        "OWASP Top 10 web application vulnerabilities. Understanding ModSecurity requires mastering the `SecRule` declarative language, "
        "the five HTTP inspection phases, the collaborative anomaly scoring architecture, Paranoia Levels (PL 1 through PL 4), "
        "and rule exclusion tuning to eliminate false positives in enterprise environments."
    ),
    simple_analogy=(
        "Consider an airport baggage scanner configured with adjustable sensitivity dials. At Paranoia Level 1, the scanner only flags obvious "
        "weapons like firearms and large blades (high-confidence attacks, zero false alarms). At Paranoia Level 4, the scanner alerts on any dense object, "
        "pocket knife, or liquid container over 50ml (maximum security, but many false alarms on legitimate travelers with toiletries). "
        "Instead of immediately arresting someone who has a small bottle of lotion, the scanner tallies an 'anomaly score'. "
        "Only when the total risk score across all items exceeds the threshold (e.g. score >= 5) is the traveler stopped and searched."
    ),
    technical_term="Web Application Firewall (WAF) Anomaly Scoring & SecRule Directive Engineering",
    technical_definition=(
        "ModSecurity processes HTTP transactions across discrete phases (Phase 1: Request Headers, Phase 2: Request Body, Phase 3: Response Headers, "
        "Phase 4: Response Body, Phase 5: Logging). The OWASP CRS operates via Collaborative Anomaly Scoring: rules do not block immediately; "
        "instead, matched rules contribute anomaly points (Critical: 5, Error: 4, Warning: 3, Notice: 2) to a cumulative transaction score (`tx.anomaly_score`). "
        "At the end of Phase 2 or Phase 4, a threshold rule (`SecRule TX:ANOMALY_SCORE '@ge %{tx.inbound_anomaly_score_threshold}'`) decides whether to block."
    ),
    cybersecurity_context=(
        "WAF deployments protect web applications from zero-day exploits and known vulnerabilities prior to application code patching. "
        "However, out-of-the-box WAF deployments often disrupt legitimate business transactions due to overly aggressive generic rules. "
        "Detection engineers write custom `SecRule` directives and author targeted rule exclusions using `ctl:ruleRemoveById` or "
        "`SecRuleUpdateTargetById` to protect legacy or bespoke application endpoints without disabling core WAF protections."
    ),
    why_it_matters=(
        "Simply disabling a WAF rule entirely (`SecRuleRemoveById`) creates dangerous blind spots that attackers can exploit across the whole site. "
        "Precision tuning requires scoping exclusions to specific URI endpoints and parameter targets. Mastery of ModSecurity syntax and anomaly scoring "
        "enables organizations to deploy strict security baselines (PL 2 or PL 3) while maintaining seamless user experience."
    ),
    demonstration=(
        "1. Author custom ModSecurity directive blocking command injection in User-Agent header:\n"
        "   `SecRule REQUEST_HEADERS:User-Agent \"@rx (?:\\b(?:bash|sh|cmd|powershell)\\b|[;&|`])\" \\\n"
        "       \"id:100001,phase:1,deny,status:403,log,msg:'Command Injection Pattern in User-Agent'\"`\n"
        "2. Evaluate incoming HTTP request with suspicious User-Agent:\n"
        "   `User-Agent: Mozilla/5.0; /bin/sh -c whoami`\n"
        "3. ModSecurity Phase 1 inspection triggers `id:100001`.\n"
        "4. Client receives immediate `HTTP/1.1 403 Forbidden` response."
    ),
    remediation_guide=(
        "1. Never disable whole rule families globally when resolving a single false positive.\n"
        "2. Use `SecRuleUpdateTargetById` to remove specific parameters (e.g. `ARGS:comment`) from rule inspection on trusted endpoints.\n"
        "3. Maintain development environments operating under the same Paranoia Level as production to catch false positives before release.\n"
        "4. Audit ModSecurity audit log (`modsec_audit.log`) regularly to identify recurring benign triggers."
    ),
)

ROOM_DETECTION_10_TASKS = [
    TaskDefinition(
        task_id="task-01-modsec-syntax-mechanics",
        order=1,
        title="ModSecurity Inspection Phases & Directive Mechanics",
        instructions=(
            "Review ModSecurity transaction processing phases. Identify the numerical phase (1 through 5) in which "
            "request bodies and POST arguments are decoded and evaluated."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["2"],
        hint="Phase 1 inspects Request Headers; Phase 2 inspects Request Body.",
    ),
    TaskDefinition(
        task_id="task-02-crs-anomaly-scoring-analysis",
        order=2,
        title="OWASP CRS Anomaly Score Severity Weighting",
        instructions=(
            "In the OWASP ModSecurity Core Rule Set anomaly scoring model, what numerical point value is contributed "
            "to the cumulative transaction score by a CRITICAL severity rule match?"
        ),
        task_type=TaskType.QUESTION,
        xp_reward=60,
        accepted_answers=["5"],
        hint="Critical = 5, Error = 4, Warning = 3, Notice = 2.",
    ),
    TaskDefinition(
        task_id="task-03-attck-waf-evasion-mapping",
        order=3,
        title="MITRE ATT&CK Mapping: Web Shell Persistence",
        instructions=(
            "Identify the sub-technique ID under Server Software Component (T1505) corresponding to adversary deployment "
            "of Web Shells (which WAFs specifically inspect and block during file upload processing)."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["T1505.003"],
        hint="Format: T1505.00x. This sub-technique represents Web Shells.",
    ),
    TaskDefinition(
        task_id="task-04-modsec-crs-emulation",
        order=4,
        title="ModSecurity Anomaly Evaluation Emulation",
        instructions=(
            "Launch your isolated lab environment. Run the ModSecurity tuning tool with `--emulate-inspection` to inspect "
            "incoming HTTP transactions against the OWASP Core Rule Set engine and verify anomaly scoring calculations."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=70,
        accepted_answers=["MODSEC_CRS_VERIFIED"],
        hint="Execute: `python3 /home/operator/tools/modsec_tuning_tool.py --emulate-inspection`",
    ),
    TaskDefinition(
        task_id="task-05-modsec-crs-challenge",
        order=5,
        title="Paranoia Level Calibration & Target Exclusion Challenge",
        instructions=(
            "A benign administrative markdown upload endpoint is triggering false-positive alerts on rule 941100 (XSS). "
            "Tune your ModSecurity configuration using `--tune-paranoia` to deploy a parameter-specific exclusion target, "
            "then submit `--challenge` to validate blocking malicious web payloads while permitting legitimate traffic."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=80,
        accepted_answers=["MODSEC_CRS_VALIDATED"],
        hint="Execute `--tune-paranoia` followed by `--challenge` using `/home/operator/tools/modsec_tuning_tool.py`.",
    ),
    TaskDefinition(
        task_id="task-06-modsec-crs-quiz",
        order=6,
        title="ModSecurity & CRS Technical Assessment",
        instructions="Complete the 4-question technical assessment to verify mastery of ModSecurity directives and CRS tuning.",
        task_type=TaskType.QUIZ,
        xp_reward=40,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="How does the OWASP ModSecurity Core Rule Set anomaly scoring model differ from traditional WAF blocking?",
                options=[
                    "It calculates a cumulative threat score across all matched rules and blocks only if the total exceeds a threshold",
                    "It immediately blocks and terminates the connection on the very first pattern match regardless of severity",
                    "It forwards all HTTP traffic to a sandbox container before allowing any packets through to the server",
                    "It requires manual human authorization from a SOC analyst before responding to any client request",
                ],
                correct_index=0,
                correct_option_index=0,
                explanation="Collaborative anomaly scoring aggregates points from multiple matching rules across inspection phases, providing superior contextual accuracy compared to immediate single-rule blocking.",
            ),
            QuizQuestion(
                id="q2",
                question="What is the operational consequence of raising the OWASP CRS Paranoia Level from PL 1 to PL 4?",
                options=[
                    "Detection coverage increases to catch advanced evasions, but the risk of false positives on legitimate traffic also rises",
                    "The WAF completely disables regex evaluation and relies solely on client IP reputation lists",
                    "ModSecurity switches from Phase 2 body inspection to hardware packet header inspection",
                    "All server response codes are automatically converted into encrypted TLS tokens",
                ],
                correct_index=0,
                correct_option_index=0,
                explanation="Higher paranoia levels activate increasingly sensitive and aggressive rules, maximizing security against sophisticated attackers at the cost of requiring more tuning to eliminate false alarms.",
            ),
            QuizQuestion(
                id="q3",
                question="Which ModSecurity action allows detection engineers to exclude a specific parameter from being inspected by a rule?",
                options=[
                    "SecRuleUpdateTargetById 941100 \"!ARGS:description\"",
                    "SecRuleEngine Off",
                    "ctl:ruleRemoveTargetAll",
                    "SecComponentDisable",
                ],
                correct_index=0,
                correct_option_index=0,
                explanation="`SecRuleUpdateTargetById` with `!ARGS:target` surgically removes a specific argument from inspection for a specified rule ID, preserving protection across all other fields.",
            ),
            QuizQuestion(
                id="q4",
                question="In ModSecurity directive syntax, which operator performs case-insensitive regular expression pattern matching?",
                options=[
                    "@rx",
                    "@streq",
                    "@ipMatch",
                    "@contains",
                ],
                correct_index=0,
                correct_option_index=0,
                explanation="The `@rx` operator invokes the PCRE regular expression engine against the selected variable targets.",
            ),
        ],
    ),
]

ROOM_DETECTION_10_DEFINITION = RoomDefinition(
    room_id="detect-10-modsec-crs-tuning",
    track=TrackEnum.DETECTION,
    room_number=10,
    title="ModSecurity Core Rule Set Tuning & Custom Rules",
    short_description="Inspect OWASP Core Rule Set anomaly scores, adjust Paranoia Levels, author custom SecRule directives, and configure surgical exclusions to eliminate false positives.",
    difficulty="Advanced",
    estimated_duration="60 min",
    prerequisites=["detect-01-foundations-as-code", "detect-09-web-detection-rules"],
    required_practical_skills=["WAF architecture", "ModSecurity SecRule syntax", "CRS anomaly scoring", "Paranoia Level tuning", "Target exclusion authoring"],
    required_lab_type="container_duo",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Master ModSecurity declarative syntax (SecRule, variables, operators, transformations, actions)",
        "Understand OWASP CRS collaborative anomaly scoring and threshold evaluation",
        "Calibrate Paranoia Levels (PL 1 through PL 4) to balance detection depth and false alarm rates",
        "Author surgical parameter exclusions using SecRuleUpdateTargetById without creating security blind spots",
    ],
    assessment_criteria=[
        "Identify ModSecurity inspection phases and anomaly scoring points",
        "Map Web Shell and WAF exploitation to MITRE ATT&CK T1505.003",
        "Verify custom SecRule directives against attack payloads",
        "Tune paranoia levels, apply surgical exclusions, and score 100% on ModSecurity quiz",
    ],
    completion_requirements=["Complete all 5 practical investigation/emulation tasks", "Score 100% on technical quiz"],
    total_xp=350,
    concept=ROOM_DETECTION_10_CONCEPT,
    tasks=ROOM_DETECTION_10_TASKS,
    default_port=8410,
)


# ============================================================================
# DETECTION ROOM 11: WAZUH / OSSEC RULES & DECODERS
# ============================================================================

ROOM_DETECTION_11_CONCEPT = RoomConcept(
    overview=(
        "Wazuh (derived from OSSEC) is an open-source security monitoring and Host Intrusion Detection System (HIDS). "
        "At its core lies a high-performance two-stage log analysis pipeline: Decoders and Rules. Decoders parse unstructured, "
        "heterogeneous text logs (syslog, application logs, auditd) into structured XML key-value fields. Rules then evaluate conditional "
        "logic, frequency thresholds, and hierarchy relationships across those structured fields to generate alerts ranked from Level 0 to 16. "
        "Detection engineers author custom decoders to extract proprietary application attributes and write composite rules that detect "
        "adversary activity across Linux and Windows hosts."
    ),
    simple_analogy=(
        "Think of a forensic translation bureau receiving handwritten police witness statements from various countries. "
        "Stage 1 is the Translator (The Decoder): it reads the unstructured foreign text, identifies who was involved, where it happened, "
        "and what time, and fills out a standardized English intake form with specific labeled boxes (Caller, Location, Action). "
        "Stage 2 is the Lead Detective (The Rule Engine): they review the standardized form, check against historical case files "
        "(e.g. 'Has this caller filed 3 failed reports in 5 minutes?'), and assign a priority rank from 1 (routine) to 15 (urgent felony)."
    ),
    technical_term="HIDS Log Parsing Pipelines & Hierarchical XML Rule Evaluation (Wazuh / OSSEC Engine)",
    technical_definition=(
        "Wazuh's analysis engine operates sequentially: 1) Pre-decoding extracts static metadata (hostname, program_name, timestamp). "
        "2) Sibling and child decoders match `<prematch>` and `<regex>` expressions to populate dynamic attributes (`srcip`, `dstuser`, `action`, `id`). "
        "3) Rules evaluate `<if_sid>` (rule inheritance), `<if_group>`, `<match>`, `<regex>`, and `<frequency>` over a sliding `<timeframe>`. "
        "Rules produce alert levels ranging from 0 (ignored/logging only) to 16 (maximum severity / automated active response)."
    ),
    cybersecurity_context=(
        "Modern cloud workloads generate vast quantities of proprietary JSON, syslog, and container logs that commercial SIEMs cannot "
        "interpret out-of-the-box. Detection engineers write custom Wazuh decoders to extract authentication failures, privilege escalations, "
        "and command executions from proprietary microservices, integrating host-level telemetry directly into SOC alerting."
    ),
    why_it_matters=(
        "If a decoder fails to extract a field like `srcip` or `dstuser`, downstream detection rules cannot trigger on specific entities or "
        "track brute-force thresholds. Authoring robust regex patterns in decoders and linking child rules through `<if_sid>` enables "
        "sophisticated multi-stage detection logic without overwhelming SIEM storage."
    ),
    demonstration=(
        "1. Unstructured proprietary application log arrives:\n"
        "   `2026-11-15 12:00:01 volt-auth: FAILED_LOGIN user=admin src=198.51.100.22 reason=bad_token`\n"
        "2. Custom Wazuh decoder parses fields:\n"
        "   `<decoder name=\"volt-auth\"><prematch>volt-auth:</prematch><regex>user=(\\S+) src=(\\S+)</regex><order>dstuser, srcip</order></decoder>`\n"
        "3. Custom rule matches on failed login:\n"
        "   `<rule id=\"100201\" level=\"7\"><decoded_as>volt-auth</decoded_as><match>FAILED_LOGIN</match><description>VoltCorp Failed Login</description></rule>`\n"
        "4. Correlated child rule triggers on brute force:\n"
        "   `<rule id=\"100202\" level=\"10\" frequency=\"5\" timeframe=\"60\"><if_matched_sid>100201</if_matched_sid><same_srcip/><description>VoltCorp Brute Force Attempt</description></rule>`."
    ),
    remediation_guide=(
        "1. Test custom decoders and rules using `wazuh-logtest` before committing to `/var/ossec/etc/decoders/local_decoder.xml`.\n"
        "2. Always define `<parent>` and `<prematch>` to prevent decoder evaluation over unrelated logs and maintain engine performance.\n"
        "3. Assign alert levels logically: 3 for informational successes, 7 for single security anomalies, 10+ for correlated attacks.\n"
        "4. Use `<same_srcip>` or `<same_user>` to constrain frequency-based rules to specific entities."
    ),
)

ROOM_DETECTION_11_TASKS = [
    TaskDefinition(
        task_id="task-01-wazuh-pipeline-mechanics",
        order=1,
        title="Wazuh Two-Stage Processing Pipeline Mechanics",
        instructions=(
            "Review Wazuh log processing architecture. Identify the component in the analysis engine that parses "
            "raw log strings into structured XML attributes before rules are evaluated (Answer: decoder)."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["decoder", "decoders"],
        hint="Decoders parse the logs; Rules evaluate the extracted fields.",
    ),
    TaskDefinition(
        task_id="task-02-wazuh-severity-analysis",
        order=2,
        title="Wazuh Alert Level Severity Threshold",
        instructions=(
            "In default Wazuh / OSSEC configurations, what is the standard minimum alert level (1 through 16) "
            "frequently configured as the threshold to send email notifications or trigger SIEM alerts for security anomalies?"
        ),
        task_type=TaskType.QUESTION,
        xp_reward=60,
        accepted_answers=["7"],
        hint="Level 7 represents bad words or first-time security failures like failed logons.",
    ),
    TaskDefinition(
        task_id="task-03-attck-hids-telemetry-mapping",
        order=3,
        title="MITRE ATT&CK Mapping: Valid Accounts Abuse",
        instructions=(
            "Identify the MITRE ATT&CK technique ID for Valid Accounts, representing compromise and abuse of legitimate "
            "system and service credentials monitored by HIDS authentication decoders."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["T1078"],
        hint="Format: T1078. This covers Default, Domain, Local, and Cloud accounts.",
    ),
    TaskDefinition(
        task_id="task-04-wazuh-decoders-emulation",
        order=4,
        title="Wazuh Decoder & Rule Pipeline Emulation",
        instructions=(
            "Launch your isolated lab environment. Run the Wazuh decoders tool with `--emulate-decoder` to execute "
            "unstructured proprietary application logs through custom XML decoders and verify field extraction into structured attributes."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=70,
        accepted_answers=["WAZUH_RULES_VERIFIED"],
        hint="Execute: `python3 /home/operator/tools/wazuh_decoders_tool.py --emulate-decoder`",
    ),
    TaskDefinition(
        task_id="task-05-wazuh-decoders-challenge",
        order=5,
        title="Composite Rule Correlation & Regex Calibration Challenge",
        instructions=(
            "The custom decoder is currently dropping source IP addresses containing IPv6 representations. "
            "Tune your XML decoder regex using `--tune-regex` to support both IPv4 and IPv6 patterns, "
            "then submit `--challenge` to validate child rule correlation (`<if_sid>`) across multi-stage attack logs."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=80,
        accepted_answers=["WAZUH_RULES_VALIDATED"],
        hint="Execute `--tune-regex` followed by `--challenge` using `/home/operator/tools/wazuh_decoders_tool.py`.",
    ),
    TaskDefinition(
        task_id="task-06-wazuh-rules-quiz",
        order=6,
        title="Wazuh Decoders & Rules Technical Assessment",
        instructions="Complete the 4-question technical assessment to verify mastery of Wazuh HIDS XML decoders and rule hierarchies.",
        task_type=TaskType.QUIZ,
        xp_reward=40,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is the role of `<if_sid>` in Wazuh rule definition syntax?",
                options=[
                    "It establishes rule inheritance, causing the rule to evaluate only if a specific parent rule ID previously matched",
                    "It disables the rule whenever the server experiences high CPU utilization",
                    "It forwards the raw log to an external syslog server without parsing",
                    "It converts Windows Event IDs directly into Linux auditd syscall numbers",
                ],
                correct_index=0,
                correct_option_index=0,
                explanation="`<if_sid>` links child rules to parent rule IDs, enabling hierarchical classification (e.g. Rule 100201 matches failed login, and Rule 100202 triggers on 5 occurrences of Rule 100201).",
            ),
            QuizQuestion(
                id="q2",
                question="Why is the `<prematch>` tag critical when authoring sibling decoders in Wazuh?",
                options=[
                    "It acts as a fast filter, ensuring expensive regular expressions run only on logs matching a distinctive header or prefix",
                    "It encrypts the log payload before storing it in the database",
                    "It overwrites the system timestamp with UTC network time",
                    "It automatically creates a local user account on the monitored agent",
                ],
                correct_index=0,
                correct_option_index=0,
                explanation="`<prematch>` quickly evaluates whether a log line belongs to this decoder family before executing full regular expression capture groups, significantly optimizing processing performance.",
            ),
            QuizQuestion(
                id="q3",
                question="Which tag in a frequency-based Wazuh rule ensures that threshold counts apply only to repeated events from the exact same source IP?",
                options=[
                    "<same_srcip />",
                    "<group_ip_all />",
                    "<global_threshold />",
                    "<unique_event />",
                ],
                correct_index=0,
                correct_option_index=0,
                explanation="`<same_srcip />` constrains the frequency counter so that the rule triggers only when the designated number of events originate from one identical source IP address.",
            ),
            QuizQuestion(
                id="q4",
                question="What tool included with Wazuh allows detection engineers to interactively test and debug decoders and rules in real-time?",
                options=[
                    "wazuh-logtest",
                    "ossec-wireshark",
                    "sigma-transpiler",
                    "sysmon-test",
                ],
                correct_index=0,
                correct_option_index=0,
                explanation="`wazuh-logtest` (formerly `ossec-logtest`) accepts sample log lines from standard input and displays step-by-step decoder extraction, field parsing, and matching rule outputs.",
            ),
        ],
    ),
]

ROOM_DETECTION_11_DEFINITION = RoomDefinition(
    room_id="detect-11-wazuh-decoders-rules",
    track=TrackEnum.DETECTION,
    room_number=11,
    title="Wazuh / OSSEC Rules & Decoders",
    short_description="Author custom XML decoders to parse unstructured application logs, configure field extractions, and build hierarchical composite detection rules in Wazuh.",
    difficulty="Advanced",
    estimated_duration="60 min",
    prerequisites=["detect-01-foundations-as-code", "detect-02-log-normalization"],
    required_practical_skills=["HIDS architecture", "Wazuh XML decoder authoring", "Regular expression field parsing", "Rule inheritance (<if_sid>)", "Frequency thresholding"],
    required_lab_type="container_duo",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Author custom Wazuh XML decoders using <prematch>, <regex>, and <order>",
        "Extract dynamic attributes (srcip, dstuser, action, status) from proprietary application logs",
        "Build composite child rules using <if_sid>, <same_srcip>, <frequency>, and <timeframe>",
        "Verify decoder parsing and rule evaluation pipelines using wazuh-logtest methodology",
    ],
    assessment_criteria=[
        "Identify Wazuh pipeline components and alert severity levels",
        "Map HIDS credential access to MITRE ATT&CK T1078",
        "Verify custom XML decoder parsing against unstructured application logs",
        "Calibrate regex capture groups, validate composite rules, and score 100% on Wazuh quiz",
    ],
    completion_requirements=["Complete all 5 practical investigation/emulation tasks", "Score 100% on technical quiz"],
    total_xp=350,
    concept=ROOM_DETECTION_11_CONCEPT,
    tasks=ROOM_DETECTION_11_TASKS,
    default_port=8411,
)


# ============================================================================
# DETECTION ROOM 12: TUNING DETECTIONS & REDUCING FALSE POSITIVES
# ============================================================================

ROOM_DETECTION_12_CONCEPT = RoomConcept(
    overview=(
        "Writing detection rules is only half the engineering discipline; tuning detections to achieve an optimal Signal-to-Noise Ratio (SNR) "
        "is what differentiates production-grade detection programs from noisy, neglected alerting backlogs. Alert fatigue caused by false positives "
        "leads to genuine attacks being overlooked by overworked analysts. Detection engineers must systematically evaluate baseline telemetry, "
        "measure False Positive Rate (FPR) and False Discovery Rate (FDR), implement multi-attribute scoped exclusion filters, and test rules in "
        "canary/shadow mode before moving them to active blocking or page-level alerting."
    ),
    simple_analogy=(
        "Imagine installing a sensitive smoke detector in a commercial bakery. If the alarm sounds whenever flour is sifted or bread crust browns, "
        "the bakers will quickly disconnect the battery or ignore the siren (alert fatigue). An amateur might 'fix' this by wrapping plastic over the sensor "
        "(disabling the rule, creating a blind spot). A detection engineer tunes the detector: they calibrate the sensor to recognize real smoke particles "
        "versus flour dust, and position heat sensors that cross-correlate high temperatures before sounding the building alarm."
    ),
    technical_term="Detection Tuning Methodology, Statistical Validation & Scoped Exclusion Filters",
    technical_definition=(
        "Detection tuning is the systematic process of refining detection logic to maximize precision (True Positives / (True Positives + False Positives)) "
        "while maintaining high recall. It leverages multi-attribute boolean exclusions (`selection and not filter`) where exclusion filters are tightly scoped "
        "across multiple high-entropy attributes (e.g. `Image` + `ParentImage` + `User` + `CommandLine` + `Signer`) rather than single malleable fields."
    ),
    cybersecurity_context=(
        "In enterprise SOC operations, the average analyst handles dozens of alerts daily. When a poorly tuned rule triggers hundreds of times a day on "
        "benign administrative maintenance (e.g. backup scripts, software deployment agents), analysts develop confirmation bias and instinctively close "
        "the alerts as benign. Attackers exploit this by masquerading malicious binaries as benign administrative tools (MITRE ATT&CK T1036). "
        "Rigorous tuning ensures that legitimate tools are excluded only when operating in their exact validated operational contexts."
    ),
    why_it_matters=(
        "A common anti-pattern is creating exclusion rules based solely on binary filename (e.g., `filter: Image|endswith: '\\updater.exe'`). "
        "This creates an immediate trivial bypass: an attacker simply renames their malware to `updater.exe` to operate completely undetected. "
        "High-fidelity tuning requires coupling binary path, digital signature validity, parent process lineage, and specific command-line arguments."
    ),
    demonstration=(
        "1. Broad rule matches legitimate SCCM software deployment agent, causing 4,000 false alerts per day:\n"
        "   `selection: Image|endswith: '\\powershell.exe' and CommandLine|contains: '-ExecutionPolicy Bypass'`\n"
        "2. Analyze benign baseline telemetry to extract invariant administrative attributes:\n"
        "   `ParentImage: C:\\Windows\\CCM\\CcmExec.exe`\n"
        "   `User: NT AUTHORITY\\SYSTEM`\n"
        "   `CommandLine|contains: '\\Packages\\DeployScript.ps1'`\n"
        "3. Author scoped exclusion filter:\n"
        "   `filter_sccm:`\n"
        "   `  ParentImage: 'C:\\Windows\\CCM\\CcmExec.exe'`\n"
        "   `  User: 'NT AUTHORITY\\SYSTEM'`\n"
        "   `  CommandLine|contains: '\\Packages\\'`\n"
        "4. Deploy updated logic: `condition: selection and not filter_sccm`.\n"
        "5. False positive rate drops to 0.0%, while adversary PowerShell executions continue alerting."
    ),
    remediation_guide=(
        "1. Never exclude by filename or path alone; require parent process, user identity, or cryptographic signer verification.\n"
        "2. Establish a canary testing phase: run new rules in 'silent/test' status for 7 to 14 days against live telemetry.\n"
        "3. Track FDR (False Discovery Rate) metrics weekly and retire or tune any rule generating > 15% false positives.\n"
        "4. Document the exact business justification, author, and review date inside the rule metadata for every exclusion filter."
    ),
)

ROOM_DETECTION_12_TASKS = [
    TaskDefinition(
        task_id="task-01-tuning-metric-mechanics",
        order=1,
        title="Detection Metrics & False Discovery Rate (FDR)",
        instructions=(
            "Review statistical metrics in detection engineering. Identify the three-letter acronym for the metric representing "
            "the ratio of false positive alerts to all triggered alerts: False Positives / (True Positives + False Positives)."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["FDR"],
        hint="False Discovery Rate. Complement of Precision (1 - Precision).",
    ),
    TaskDefinition(
        task_id="task-02-blind-spot-vulnerability-analysis",
        order=2,
        title="Insecure Exclusion Anti-Pattern Analysis",
        instructions=(
            "Identify the single Sysmon/Windows telemetry field name (e.g. Image, User, ProcessId) that should NEVER be used alone "
            "as an exclusion filter because adversaries can trivially rename their malicious executable to match it."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=60,
        accepted_answers=["Image", "image"],
        hint="Excluding by executable file name/path alone allows attackers to rename malware.",
    ),
    TaskDefinition(
        task_id="task-03-attck-masquerading-mapping",
        order=3,
        title="MITRE ATT&CK Mapping: Masquerading",
        instructions=(
            "Identify the MITRE ATT&CK Defense Evasion technique ID for Masquerading, where adversaries manipulate "
            "executable names, icons, or paths to mimic legitimate system software and evade poorly tuned detections."
        ),
        task_type=TaskType.QUESTION,
        xp_reward=50,
        accepted_answers=["T1036"],
        hint="Format: T1036. Covers Match Legitimate Name or Location, Masquerade Task or Service.",
    ),
    TaskDefinition(
        task_id="task-04-false-positive-emulation",
        order=4,
        title="Baseline Telemetry Profiling & Noise Emulation",
        instructions=(
            "Launch your isolated lab environment. Run the false positive tuning tool with `--emulate-baseline` to profile "
            "benign enterprise telemetry against an uncalibrated rule and identify the volume of false alerts generated."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=70,
        accepted_answers=["FALSE_POSITIVE_TUNING_VERIFIED"],
        hint="Execute: `python3 /home/operator/tools/false_positive_tool.py --emulate-baseline`",
    ),
    TaskDefinition(
        task_id="task-05-false-positive-challenge",
        order=5,
        title="Multi-Attribute Scoped Exclusion Challenge",
        instructions=(
            "The broad detection rule is flooding the SOC with alerts on legitimate scheduled backup operations. "
            "Tune your rule logic using `--tune-baseline` to deploy a multi-attribute exclusion filter (combining User, ParentImage, and Path), "
            "then submit `--challenge` to achieve a 0% false positive rate while maintaining 100% detection of real attacks."
        ),
        task_type=TaskType.COMMAND,
        xp_reward=80,
        accepted_answers=["FALSE_POSITIVE_TUNING_VALIDATED"],
        hint="Execute `--tune-baseline` followed by `--challenge` using `/home/operator/tools/false_positive_tool.py`.",
    ),
    TaskDefinition(
        task_id="task-06-tuning-quiz",
        order=6,
        title="Detection Tuning & Precision Technical Assessment",
        instructions="Complete the 4-question technical assessment to verify mastery of detection tuning, alert fatigue mitigation, and exclusion scoping.",
        task_type=TaskType.QUIZ,
        xp_reward=40,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is filtering an alert solely by `Image: C:\\Windows\\System32\\calc.exe` considered an insecure detection engineering practice?",
                options=[
                    "Because an attacker can name any malicious payload `calc.exe` and execute it completely undetected",
                    "Because Windows automatically blocks any process named `calc.exe` from accessing the network",
                    "Because Sysmon cannot record Event ID 1 for executables located inside System32",
                    "Because regular expressions cannot match paths containing single backslashes",
                ],
                correct_index=0,
                correct_option_index=0,
                explanation="Excluding based solely on filename or binary path introduces an immediate masquerading vulnerability (T1036). Adversaries name their malware after excluded binaries to blind the detection.",
            ),
            QuizQuestion(
                id="q2",
                question="What is the recommended multi-attribute approach for authoring high-integrity exclusion filters?",
                options=[
                    "Combine binary path, parent process executable, user security context, and specific command-line arguments",
                    "Exclude all activities performed by users in the local Administrators group",
                    "Disable the rule during business hours and activate it only on weekends",
                    "Delete all log records originating from production database servers",
                ],
                correct_index=0,
                correct_option_index=0,
                explanation="Safe exclusions require multiple correlated attributes (e.g. legitimate parent process + specific service account + explicit command argument) to ensure malware mimicking one attribute is still caught.",
            ),
            QuizQuestion(
                id="q3",
                question="What is the purpose of running a detection rule in 'shadow' or 'canary' mode before production deployment?",
                options=[
                    "To measure false-positive volume and evaluate baseline noise against live telemetry without alerting analysts",
                    "To test whether the server's graphics card supports GPU-accelerated pattern matching",
                    "To ensure the rule can automatically shut down the enterprise domain controller",
                    "To generate synthetic attack logs using deep learning models",
                ],
                correct_index=0,
                correct_option_index=0,
                explanation="Shadow or canary deployment allows detection engineers to evaluate alert frequency, identify benign business triggers, and tune exclusions without generating false alarm noise for frontline SOC analysts.",
            ),
            QuizQuestion(
                id="q4",
                question="How does alert fatigue directly degrade enterprise cybersecurity posture?",
                options=[
                    "Analysts become overwhelmed by noise, leading them to reflexively close alerts and overlook genuine security breaches",
                    "It causes the SIEM database hard drives to run out of disk sectors within seconds",
                    "It forces operating systems to disable all security logging agents automatically",
                    "It increases network latency across wide area network routers",
                ],
                correct_index=0,
                correct_option_index=0,
                explanation="When analysts are bombarded with false positives, human vigilance drops, triage becomes superficial, and real intrusion signals are dismissed as more benign noise.",
            ),
        ],
    ),
]

ROOM_DETECTION_12_DEFINITION = RoomDefinition(
    room_id="detect-12-reducing-false-positives",
    track=TrackEnum.DETECTION,
    room_number=12,
    title="Tuning Detections & Reducing False Positives",
    short_description="Analyze benign corporate baseline traffic, calculate False Discovery Rates, and engineer multi-attribute scoped exclusion filters to eliminate alert fatigue without creating blind spots.",
    difficulty="Intermediate",
    estimated_duration="45 min",
    prerequisites=["detect-01-foundations-as-code", "detect-03-sigma-syntax", "detect-04-process-creation-rules"],
    required_practical_skills=["False positive analysis", "Precision vs recall optimization", "Multi-attribute exclusion scoping", "Baseline profiling", "Canary testing"],
    required_lab_type="container_duo",
    status=RoomStatus.IMPLEMENTED,
    learning_objectives=[
        "Measure and optimize False Discovery Rate (FDR) and Signal-to-Noise Ratio (SNR)",
        "Identify and remediate insecure exclusion anti-patterns that create masquerading blind spots (T1036)",
        "Author robust multi-attribute boolean exclusion filters (Image + ParentImage + User + CommandLine)",
        "Implement canary deployment strategies to safely validate detection rules against live enterprise noise",
    ],
    assessment_criteria=[
        "Calculate detection accuracy metrics and identify insecure exclusion filters",
        "Map masquerading and evasion to MITRE ATT&CK T1036",
        "Verify baseline noise profiling in simulated enterprise telemetry",
        "Tune multi-attribute exclusions to achieve zero false positives and score 100% on tuning quiz",
    ],
    completion_requirements=["Complete all 5 practical investigation/emulation tasks", "Score 100% on technical quiz"],
    total_xp=350,
    concept=ROOM_DETECTION_12_CONCEPT,
    tasks=ROOM_DETECTION_12_TASKS,
    default_port=8412,
)
