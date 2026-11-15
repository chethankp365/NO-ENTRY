"""
Complete curriculum definitions, tasks, concept explanations, and quizzes
for Red Team Rooms 10–13:
- Room 10: Cross-Site Scripting (red-10-cross-site-scripting)
- Room 11: Authentication Attacks (red-11-authentication-attacks)
- Room 12: Access Control Testing (red-12-access-control-testing)
- Room 13: File Upload Vulnerabilities (red-13-file-upload-vulnerabilities)
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
# ROOM 10: CROSS-SITE SCRIPTING (FULLY IMPLEMENTED)
# ============================================================================

ROOM_10_CONCEPT = RoomConcept(
    overview=(
        "Cross-Site Scripting (XSS) is a client-side code injection vulnerability occurring when untrusted data "
        "is included in a web application response without sufficient context-aware escaping or validation. "
        "This tricks the victim's browser into executing malicious JavaScript within the trusted domain context."
    ),
    simple_analogy=(
        "Imagine an office bulletin board where employees pin announcements. If an unauthorized stranger pins an "
        "official-looking notice stating 'Security memo: deposit your desk keys into mailbox 4B', and the board moderator "
        "fails to inspect or verify submissions, coworkers obey the forged directive because it appears on the company's "
        "legitimate bulletin board. Similarly, XSS occurs when a web application prints unverified input directly into HTML, "
        "causing victim browsers to execute injected instructions under the web application's legitimate authority."
    ),
    technical_term="Cross-Site Scripting (OWASP Top 10 A03:2021 — Injection / CWE-79)",
    technical_definition=(
        "XSS vulnerabilities permit adversaries to execute arbitrary JavaScript in victim browser sessions. "
        "Reflected XSS occurs when payload input is echoed immediately in an HTTP response (such as search queries or error messages). "
        "Stored XSS occurs when payload input is persisted in a database or server file and later served to multiple users. "
        "DOM-based XSS occurs when client-side script code reads untrusted sources (e.g. location.search) and passes data to dangerous sinks (e.g. eval, innerHTML). "
        "Mitigation requires context-aware output encoding (HTML, attribute, JavaScript contexts), Content Security Policy (CSP), and HttpOnly cookie flags."
    ),
    cybersecurity_context=(
        "Adversaries leverage XSS to capture session cookies, harvest credentials via in-page keyloggers, forge actions on behalf "
        "of authenticated operators, or redirect users to malicious infrastructure. Defensive engineers implement strict Content "
        "Security Policy headers, use automated HTML sanitization libraries (DOMPurify), and mark all session cookies as HttpOnly."
    ),
    why_it_matters=(
        "Even when servers enforce strong transport encryption (TLS) and perimeter firewalls, an XSS flaw bypasses perimeter "
        "controls entirely by attacking user sessions directly inside the browser viewport."
    ),
    demonstration=(
        "Reflected XSS Execution Vector:\n"
        "  Target Endpoint: http://10.10.14.90:8091/reflected?q=<script>alert(1)</script>\n"
        "  Vulnerable Response: <h2>Search Results</h2><p>Query: <script>alert(1)</script></p>\n"
        "  Browser Execution: Injected script runs with access to document.cookie.\n"
        "  Remediated Response: <h2>Search Results</h2><p>Query: &lt;script&gt;alert(1)&lt;/script&gt;</p>\n"
        "  Header Defense: Content-Security-Policy: default-src 'self'\n"
    ),
    remediation_guide=(
        "1. Never insert untrusted data directly into HTML bodies, attributes, or script blocks without context-aware escaping.\n"
        "2. Apply html.escape() or template engine auto-escaping for HTML body contexts.\n"
        "3. Deploy Content Security Policy headers (Content-Security-Policy: default-src 'self').\n"
        "4. Enforce HttpOnly and SameSite=Lax flags on all authentication and session cookies."
    ),
)

ROOM_10_TASKS = [
    TaskDefinition(
        task_id="task-01-xss-fundamentals",
        order=1,
        title="Classifications of Cross-Site Scripting",
        instructions=(
            "Review the three standard classifications of Cross-Site Scripting (Reflected, Stored, and DOM-based). "
            "Consider an attack where an adversary submits a malicious script inside a customer support ticket or forum comment. "
            "The script is saved to the backend database and subsequently executes in the browser of every administrator who reviews the ticket."
        ),
        task_type=TaskType.QUESTION,
        question="Which classification of XSS persists user-supplied payloads on the server to impact subsequent visitors?",
        hint="The payload is stored on the server.",
        xp_reward=50,
        accepted_answers=["stored", "Stored", "stored xss", "Stored XSS"],
        mistake_explanations={
            "reflected": "Reflected XSS echoes input immediately within a single request-response cycle; it is not persisted in the database.",
            "dom": "DOM-based XSS executes entirely on the client side without necessarily saving data on the backend.",
        },
    ),
    TaskDefinition(
        task_id="task-02-reflected-xss",
        order=2,
        title="Reflected XSS Identification",
        instructions=(
            "The search portal on port 8091 (`http://10.10.14.90:8091/reflected`) reflects user query parameters directly into the HTML response. "
            "Submit a test payload (`curl -s 'http://10.10.14.90:8091/reflected?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'`) "
            "and submit the reflected script execution flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the reflected XSS execution flag returned by port 8091.",
        hint="Query the /reflected endpoint with a script tag parameter using curl.",
        xp_reward=50,
        accepted_answers=["NOENTRY{xss_reflected_script_execution_4821}"],
        accepted_regex=r"^NOENTRY\{xss_reflected_script_execution_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-03-stored-xss",
        order=3,
        title="Stored XSS in Discussion Comments",
        instructions=(
            "The community comments endpoint stores submissions in memory and renders them to subsequent users. "
            "Post a script comment using: `curl -s -X POST http://10.10.14.90:8091/comments -d 'author=tester&comment=<script>alert(1)</script>'`. "
            "Submit the stored XSS payload flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the stored comment payload flag.",
        hint="Dispatch a POST request to /comments containing an unescaped script tag.",
        xp_reward=50,
        accepted_answers=["NOENTRY{xss_stored_comment_payload_9104}"],
        accepted_regex=r"^NOENTRY\{xss_stored_comment_payload_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-04-context-encoding-challenge",
        order=4,
        title="Attribute Context Escaping Challenge",
        instructions=(
            "When user input is reflected inside an HTML attribute (e.g. `<div class=\"USER_INPUT\">`), attackers inject quote delimiters "
            "and event handlers (e.g. `\" onmouseover=\"alert(1)`). Query the challenge endpoint on port 8091: "
            "`curl -s 'http://10.10.14.90:8091/challenge?theme=%22+onmouseover%3D%22alert(1)'`. Submit the context encoding flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the attribute injection challenge flag.",
        hint="Escape the attribute boundary using quote and event handler delimiters.",
        xp_reward=60,
        accepted_answers=["NOENTRY{xss_context_encoding_defense_6623}"],
        accepted_regex=r"^NOENTRY\{xss_context_encoding_defense_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-05-remediation-defense",
        order=5,
        title="Remediation: Output Encoding & CSP",
        instructions=(
            "Remediate the vulnerability by triggering the defense hardening endpoint: "
            "`curl -s -X POST http://10.10.14.90:8091/remediate`. This activates context-aware HTML escaping and Content Security Policy. "
            "Submit the remediation verification flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the output encoding remediation verification flag.",
        hint="Post to /remediate on port 8091.",
        xp_reward=70,
        accepted_answers=["NOENTRY{xss_output_encoding_remediation_7812}"],
        accepted_regex=r"^NOENTRY\{xss_output_encoding_remediation_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-06-quiz",
        order=6,
        title="Cross-Site Scripting Knowledge Assessment",
        instructions="Complete the 5-question quiz to test your conceptual understanding of XSS mechanics, contexts, and defensive engineering.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question assessment quiz on XSS.",
        hint="Review cookie security flags, CSP, and output encoding.",
        xp_reward=70,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Which cookie flag prevents client-side JavaScript from accessing session tokens via document.cookie?",
                options=[
                    "HttpOnly",
                    "Secure",
                    "SameSite",
                    "NoScript",
                ],
                correct_option_index=0,
                explanation="The HttpOnly flag directs browsers to disallow client-side scripts from accessing document.cookie, mitigating session theft via XSS.",
            ),
            QuizQuestion(
                id="q2",
                question="Why is client-side input validation alone insufficient to prevent Cross-Site Scripting?",
                options=[
                    "Attackers can bypass browser controls by dispatching raw HTTP requests via curl, proxies, or scripts",
                    "Client-side validation only operates on HTTPS connections",
                    "Web browsers automatically disable input validation for form fields",
                    "JavaScript validation can only detect SQL injection characters",
                ],
                correct_option_index=0,
                explanation="Client-side validation occurs entirely within user-controlled execution space and is easily bypassed using raw HTTP requests, proxies, or curl.",
            ),
            QuizQuestion(
                id="q3",
                question="What is the primary defensive function of a Content Security Policy (CSP) header?",
                options=[
                    "Restricting the origins and sources from which scripts, styles, and resources may execute",
                    "Encrypting local browser storage and cookie values",
                    "Blocking unauthorized IP addresses at the network transport layer",
                    "Replacing server-side database authentication checks",
                ],
                correct_option_index=0,
                explanation="Content Security Policy (CSP) defines approved origins and cryptographic nonces for script execution, blocking unauthorized inline scripts and exfiltration domains.",
            ),
            QuizQuestion(
                id="q4",
                question="What distinguishes Reflected XSS from Stored XSS?",
                options=[
                    "Reflected is echoed immediately in a single response, whereas Stored persists on the server for multiple victims",
                    "Reflected executes in the server memory, while Stored executes in the browser",
                    "Reflected requires root operating system privileges on the target",
                    "Stored XSS can only impact desktop operating systems",
                ],
                correct_option_index=0,
                explanation="Reflected XSS immediately bounces an unescaped input back to the specific requester, while Stored XSS stores malicious payloads in a database or file to impact subsequent users.",
            ),
            QuizQuestion(
                id="q5",
                question="What is the most effective primary architectural defense against Cross-Site Scripting?",
                options=[
                    "Context-aware output encoding and escaping before data is rendered into the browser DOM",
                    "Blacklisting specific keywords like 'script' and 'alert'",
                    "Disabling all HTTP POST requests on the web server",
                    "Enforcing 16-character minimum passwords for user accounts",
                ],
                correct_option_index=0,
                explanation="Context-aware output encoding (such as HTML entity escaping, JavaScript attribute encoding, URL escaping) renders untrusted data as literal characters rather than executable markup.",
            ),
        ],
    ),
]

ROOM_10_DEFINITION = RoomDefinition(
    room_id="red-10-cross-site-scripting",
    track=TrackEnum.RED,
    room_number=10,
    title="Cross-Site Scripting (XSS)",
    short_description="Master Reflected, Stored, and DOM XSS mechanics, input validation, context-aware output encoding, and Content Security Policy.",
    difficulty="Intermediate",
    estimated_duration="50 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_10_CONCEPT,
    tasks=ROOM_10_TASKS,
    learning_objectives=[
        "Differentiate Reflected, Stored, and DOM-based Cross-Site Scripting vectors",
        "Exploit unsafe output rendering in browser contexts safely",
        "Implement context-aware HTML output encoding and escaping",
        "Configure Content Security Policy (CSP) and HttpOnly cookie protections",
    ],
    assessment_criteria=[
        "Identify XSS classification categories",
        "Extract reflected and stored execution flags via CLI and browser interaction",
        "Verify defensive remediation using output encoding and CSP",
        "Pass the 5-question XSS technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)


# ============================================================================
# ROOM 11: AUTHENTICATION ATTACKS (FULLY IMPLEMENTED)
# ============================================================================

ROOM_11_CONCEPT = RoomConcept(
    overview=(
        "Authentication is the gatekeeping process verifying that an entity is who they claim to be. "
        "Authentication attacks exploit weaknesses in credential verification: predictable credentials, "
        "missing rate limiting, unsalted password hashes, and the absence of multi-factor authentication."
    ),
    simple_analogy=(
        "Think of an electronic keycard lock on an office suite. Authentication asks 'Who are you?' and validates "
        "your digital keycard or PIN code. If the reader allows a stranger to stand outside trying thousands of random 4-digit PINs "
        "without triggering an alarm or locking the keypad, the intruder will eventually guess the code. Authorization asks "
        "'What rooms are you allowed into?' once your identity is confirmed. If the building stores all employee PINs on an unencrypted "
        "paper ledger, any insider who glances at the paper compromises every room."
    ),
    technical_term="Identification and Authentication Failures (OWASP Top 10 A07:2021 / CWE-287)",
    technical_definition=(
        "Authentication flaws encompass weaknesses in identity confirmation mechanisms. "
        "A brute-force attack systematically generates candidates across the keyspace. "
        "A dictionary attack tests targeted high-probability passwords against known accounts. "
        "Credential stuffing tests leaked username/password combos from external breaches against target systems. "
        "Defensive architectures enforce server-side rate limiting (HTTP 429), progressive account lockout, "
        "cryptographic key stretching with unique salts (bcrypt, Argon2id), and Multi-Factor Authentication (MFA)."
    ),
    cybersecurity_context=(
        "Offensive operators utilize wordlists (like RockYou) and automated login fuzzers to identify weak credentials. "
        "Defensive SOC analysts inspect authentication telemetry logs for failed logon bursts (Event ID 4625 / syslog auth.log) "
        "and configure web application firewalls (WAFs) to enforce IP and account rate limits."
    ),
    why_it_matters=(
        "Compromising a valid account grants attackers immediate legitimate access, bypassing perimeter firewalls "
        "and signature-based detection systems without deploying noisy exploits."
    ),
    demonstration=(
        "Controlled Dictionary Attack:\n"
        "  Target Endpoint: POST http://10.10.14.90:8092/api/login\n"
        "  Dictionary List: /home/operator/wordlists/passwords.txt (voltcorp2024)\n"
        "  Vulnerable State: No rate limiting; accepts unlimited attempts until valid credentials hit.\n"
        "  Hardened State: HTTP 429 Too Many Requests after 3 failed attempts; bcrypt salted password storage.\n"
    ),
    remediation_guide=(
        "1. Enforce server-side rate limiting (e.g. maximum 5 attempts per minute per IP/account).\n"
        "2. Store credentials using adaptive, salted hashing functions: Argon2id or bcrypt (cost factor >= 12).\n"
        "3. Require Multi-Factor Authentication (MFA) via TOTP or FIDO2 hardware tokens.\n"
        "4. Log and monitor authentication telemetry for brute-force and stuffing patterns."
    ),
)

ROOM_11_TASKS = [
    TaskDefinition(
        task_id="task-01-auth-vs-authz",
        order=1,
        title="Authentication vs Authorization",
        instructions=(
            "In identity and access governance, security engineers strictly distinguish between identity verification "
            "and permission evaluation. Which fundamental concept verifies *who you are* (identity claim validation) "
            "prior to checking what resources you are allowed to access?"
        ),
        task_type=TaskType.QUESTION,
        question="Which concept validates a user's identity claims before permission evaluation?",
        hint="Authentication validates identity; authorization determines privileges.",
        xp_reward=50,
        accepted_answers=["authentication", "Authentication", "authn", "AuthN"],
        mistake_explanations={
            "authorization": "Authorization evaluates permissions and access rights after identity has already been established. Authentication validates the identity claim itself.",
        },
    ),
    TaskDefinition(
        task_id="task-02-dictionary-attack",
        order=2,
        title="Controlled Password Guessing",
        instructions=(
            "The synthetic service account `support` on port 8092 has a weak password included in your operator wordlist "
            "(`/home/operator/wordlists/passwords.txt`). Test the credentials against `http://10.10.14.90:8092/api/login` "
            "using `curl -s -X POST http://10.10.14.90:8092/api/login -d 'username=support&password=voltcorp2024'`. "
            "Submit the authentication success flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the dictionary attack authentication flag.",
        hint="Log in with username support and password voltcorp2024.",
        xp_reward=50,
        accepted_answers=["NOENTRY{auth_brute_force_dictionary_7190}"],
        accepted_regex=r"^NOENTRY\{auth_brute_force_dictionary_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-03-telemetry-audit",
        order=3,
        title="Authentication Audit Telemetry",
        instructions=(
            "SOC analysts investigate authentication logs to identify brute-force patterns. Query the audit telemetry endpoint: "
            "`curl -s http://10.10.14.90:8092/api/logs`. Submit the log analysis flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the authentication audit log analysis flag.",
        hint="Query /api/logs on port 8092.",
        xp_reward=50,
        accepted_answers=["NOENTRY{auth_log_analysis_telemetry_3481}"],
        accepted_regex=r"^NOENTRY\{auth_log_analysis_telemetry_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-04-lockout-challenge",
        order=4,
        title="Lockout Policy Verification Challenge",
        instructions=(
            "Interrogate the password policy challenge endpoint to verify lockout thresholds: "
            "`curl -s 'http://10.10.14.90:8092/challenge?action=verify_policy'`. Submit the policy verification flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the lockout policy defense flag.",
        hint="Pass action=verify_policy to the /challenge endpoint on port 8092.",
        xp_reward=60,
        accepted_answers=["NOENTRY{auth_lockout_policy_defense_5514}"],
        accepted_regex=r"^NOENTRY\{auth_lockout_policy_defense_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-05-remediation-hardening",
        order=5,
        title="Remediation: Rate Limiting & Bcrypt Hardening",
        instructions=(
            "Harden the authentication endpoint by enforcing server-side rate limiting and upgraded bcrypt hashing: "
            "`curl -s -X POST http://10.10.14.90:8092/api/remediate`. Submit the remediation verification flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the rate limiting and bcrypt hardening flag.",
        hint="Post to /api/remediate on port 8092.",
        xp_reward=70,
        accepted_answers=["NOENTRY{auth_rate_limiting_bcrypt_hardened_9205}"],
        accepted_regex=r"^NOENTRY\{auth_rate_limiting_bcrypt_hardened_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-06-quiz",
        order=6,
        title="Authentication Security Knowledge Assessment",
        instructions="Complete the 5-question quiz to test your conceptual understanding of authentication protocols, hashing, and rate limiting.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question assessment quiz on authentication.",
        hint="Review salting, bcrypt properties, rate limit status codes, and credential stuffing.",
        xp_reward=70,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is adding a unique cryptographic salt to password hashes before hashing essential?",
                options=[
                    "It ensures identical passwords produce distinct hash digests, neutralizing precomputed rainbow table lookups",
                    "It encrypts the password so it can be decrypted by administrators",
                    "It automatically forces the user to reset their password every 90 days",
                    "It compresses the hash string to reduce database storage space",
                ],
                correct_option_index=0,
                explanation="A cryptographic salt ensures identical plaintext passwords produce entirely different hash outputs, defeating offline dictionary precomputation and rainbow tables.",
            ),
            QuizQuestion(
                id="q2",
                question="Which password hashing algorithm is intentionally computationally intensive to resist GPU-based cracking?",
                options=[
                    "bcrypt",
                    "MD5",
                    "SHA-1",
                    "CRC32",
                ],
                correct_option_index=0,
                explanation="bcrypt utilizes a configurable work factor and memory/CPU intensive operations to make parallelized GPU-based brute-force cracking prohibitively slow.",
            ),
            QuizQuestion(
                id="q3",
                question="What distinguishes a credential stuffing attack from a standard brute-force attack?",
                options=[
                    "Credential stuffing tests leaked username/password pairs across many services, while brute-force guesses passwords against one target",
                    "Credential stuffing requires root administrative access to domain controllers",
                    "Credential stuffing only operates against unencrypted FTP connections",
                    "Brute-force attacks always utilize dictionary wordlists while credential stuffing generates random hashes",
                ],
                correct_option_index=0,
                explanation="Credential stuffing leverages database dumps from previous breaches to test known email/password combinations across multiple unrelated websites.",
            ),
            QuizQuestion(
                id="q4",
                question="Which standard HTTP status code should an API return when an IP exceeds permitted login attempt thresholds?",
                options=[
                    "429 Too Many Requests",
                    "401 Unauthorized",
                    "403 Forbidden",
                    "503 Service Unavailable",
                ],
                correct_option_index=0,
                explanation="HTTP 429 Too Many Requests communicates rate limit throttling or temporary lockout, typically accompanied by a Retry-After header.",
            ),
            QuizQuestion(
                id="q5",
                question="Why is hashing passwords exclusively on the client side before transmission ineffective as a security control?",
                options=[
                    "The client hash becomes the effective password, allowing attackers to replay it directly to authenticate",
                    "Web browsers do not support cryptographic hashing functions",
                    "Client hashing causes database corruption during user lookups",
                    "Client hashing disables transport layer encryption (TLS)",
                ],
                correct_option_index=0,
                explanation="If the server treats a client-side hash as the secret, the hash itself becomes the effective credential (pass-the-hash over HTTP). Servers must salt and hash server-side.",
            ),
        ],
    ),
]

ROOM_11_DEFINITION = RoomDefinition(
    room_id="red-11-authentication-attacks",
    track=TrackEnum.RED,
    room_number=11,
    title="Authentication Attacks",
    short_description="Master authentication vs authorization, password hashing, dictionary attacks, credential stuffing, telemetry logs, and rate limiting.",
    difficulty="Intermediate",
    estimated_duration="50 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_11_CONCEPT,
    tasks=ROOM_11_TASKS,
    learning_objectives=[
        "Differentiate authentication (identity verification) from authorization (permission checks)",
        "Execute controlled dictionary attacks against un-rate-limited endpoints safely",
        "Inspect authentication telemetry logs for failed logon bursts",
        "Implement rate limiting (HTTP 429) and bcrypt salted password storage",
    ],
    assessment_criteria=[
        "Identify core authentication concepts and difference from authorization",
        "Capture dictionary attack flag and audit telemetry flag",
        "Verify rate limiting and salted bcrypt remediation",
        "Pass the 5-question authentication technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)


# ============================================================================
# ROOM 12: ACCESS CONTROL TESTING (FULLY IMPLEMENTED)
# ============================================================================

ROOM_12_CONCEPT = RoomConcept(
    overview=(
        "Access control ensures that authenticated users act only within their authorized permission boundaries. "
        "Broken access control is the leading web security vulnerability, allowing adversaries to view peer records "
        "(Horizontal IDOR) or elevate to administrative functions (Vertical Privilege Escalation)."
    ),
    simple_analogy=(
        "Consider a corporate storage vault with individual numbered lockers. Alice owns locker 101; Bob owns locker 102. "
        "If Bob alters his request slip from 102 to 101, and the security guard hands over Alice's confidential documents "
        "without verifying whether Bob actually owns locker 101, that is a Horizontal Privilege Violation (IDOR). "
        "If Bob pushes open a door marked 'Executive Boardroom Only' and the lock fails to verify his credentials, "
        "allowing him to access executive controls, that is a Vertical Privilege Escalation."
    ),
    technical_term="Broken Access Control (OWASP Top 10 A01:2021 / CWE-639 / CWE-284)",
    technical_definition=(
        "Access control weaknesses occur when server-side applications fail to enforce authorization policies on requests. "
        "Insecure Direct Object References (IDOR / BOLA) occur when an application exposes a reference to an internal object "
        "(like database IDs or filenames) without verifying that the requesting session owns the referenced object. "
        "Vertical escalation occurs when standard users invoke endpoints reserved for higher privilege tiers (e.g. /api/admin/*). "
        "Mitigation mandates server-side ownership validation (doc.owner_id == session.user_id) and strict Role-Based Access Control (RBAC)."
    ),
    cybersecurity_context=(
        "Attackers enumerate API endpoints using proxy interception tools (like Burp Suite) to alter parameter IDs (e.g. /api/invoices/1042). "
        "Defenders implement centralized authorization interceptors, role-checking decorators, and enforce the Principle of Least Privilege."
    ),
    why_it_matters=(
        "Broken access control is currently the most prevalent and impactful web application vulnerability, "
        "routinely leading to mass unauthorized data exposure and full administrative takeover."
    ),
    demonstration=(
        "Horizontal IDOR Vulnerability:\n"
        "  Attacker Session: Bob (User ID: 102)\n"
        "  Target Endpoint: GET /api/documents/101 (Alice's Confidential Document)\n"
        "  Vulnerable Server: Returns Document 101 directly without checking owner_id.\n"
        "  Remediated Server: Evaluates 'if doc.owner_id != session.user_id: 403 Forbidden'.\n"
    ),
    remediation_guide=(
        "1. Never rely on client-side controls, hidden form fields, or obfuscated URLs for authorization.\n"
        "2. Enforce server-side record ownership checks on every request: verify session user matches object owner.\n"
        "3. Implement Role-Based Access Control (RBAC) middleware verifying administrative role on sensitive paths.\n"
        "4. Deny access by default: grant privileges explicitly rather than attempting to blacklist unauthorized actions."
    ),
)

ROOM_12_TASKS = [
    TaskDefinition(
        task_id="task-01-access-control-boundaries",
        order=1,
        title="Access Control Concepts: IDOR & BOLA",
        instructions=(
            "Review access control failure classifications. What standard 4-letter cybersecurity acronym identifies "
            "an Insecure Direct Object Reference, where altering a database key or object parameter accesses unauthorized peer data?"
        ),
        task_type=TaskType.QUESTION,
        question="Submit the standard 4-letter acronym for Insecure Direct Object References.",
        hint="Insecure Direct Object Reference.",
        xp_reward=50,
        accepted_answers=["IDOR", "idor", "BOLA", "bola"],
    ),
    TaskDefinition(
        task_id="task-02-horizontal-idor",
        order=2,
        title="Horizontal Privilege Violation (IDOR)",
        instructions=(
            "As user Bob (`token=bob_token`), query Alice's private financial document on port 8093: "
            "`curl -s -H 'Authorization: Bearer bob_token' http://10.10.14.90:8093/api/documents/101`. "
            "Submit the horizontal IDOR flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the horizontal IDOR access flag.",
        hint="Query document 101 with Bob's bearer token on port 8093.",
        xp_reward=50,
        accepted_answers=["NOENTRY{idor_horizontal_privilege_access_8321}"],
        accepted_regex=r"^NOENTRY\{idor_horizontal_privilege_access_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-03-vertical-privilege-escalation",
        order=3,
        title="Vertical Privilege Boundary Breach",
        instructions=(
            "Vertical privilege escalation occurs when an unprivileged user accesses administrative functions. "
            "Using Bob's standard user token, request the administrative user database: "
            "`curl -s -H 'Authorization: Bearer bob_token' http://10.10.14.90:8093/api/admin/users`. "
            "Submit the vertical escalation flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the vertical privilege escalation breach flag.",
        hint="Request /api/admin/users using Bob's token.",
        xp_reward=50,
        accepted_answers=["NOENTRY{vertical_privilege_escalation_breach_4490}"],
        accepted_regex=r"^NOENTRY\{vertical_privilege_escalation_breach_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-04-parameter-tampering-challenge",
        order=4,
        title="Parameter Tampering Challenge",
        instructions=(
            "Interrogate the challenge endpoint by tampering with the account_id parameter: "
            "`curl -s 'http://10.10.14.90:8093/challenge?account_id=101'`. Submit the parameter tampering flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the BOLA parameter tampering challenge flag.",
        hint="Supply account_id=101 to /challenge on port 8093.",
        xp_reward=60,
        accepted_answers=["NOENTRY{bola_access_control_master_2951}"],
        accepted_regex=r"^NOENTRY\{bola_access_control_master_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-05-server-side-authorization-fix",
        order=5,
        title="Remediation: Server-Side Authorization Enforcement",
        instructions=(
            "Remediate the access control flaws by enforcing server-side object ownership and RBAC role checks: "
            "`curl -s -X POST http://10.10.14.90:8093/api/remediate`. Submit the remediation flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the server-side authorization remediation flag.",
        hint="Post to /api/remediate on port 8093.",
        xp_reward=70,
        accepted_answers=["NOENTRY{rbac_server_side_authorization_fixed_7134}"],
        accepted_regex=r"^NOENTRY\{rbac_server_side_authorization_fixed_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-06-quiz",
        order=6,
        title="Access Control Knowledge Assessment",
        instructions="Complete the 5-question quiz to test your conceptual understanding of RBAC, IDOR, and authorization enforcement.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question assessment quiz on access control.",
        hint="Review horizontal vs vertical escalation, Least Privilege, and HTTP 403.",
        xp_reward=70,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is the core distinction between horizontal and vertical privilege escalation?",
                options=[
                    "Horizontal accesses peer resources at the same permission level, while vertical elevates to higher administrative tiers",
                    "Horizontal occurs on mobile devices, while vertical occurs on desktop browsers",
                    "Horizontal requires encrypted traffic, while vertical occurs only over cleartext HTTP",
                    "Horizontal is a network routing error, while vertical is a database error",
                ],
                correct_option_index=0,
                explanation="Horizontal escalation occurs between users with equal privilege tiers (e.g. user A viewing user B's documents), while vertical escalation breaches hierarchy boundaries to gain administrative powers.",
            ),
            QuizQuestion(
                id="q2",
                question="Why can access control checks never be safely implemented solely on the client side?",
                options=[
                    "Clients can bypass frontend checks by modifying JavaScript, tampering with parameters, or issuing direct HTTP requests",
                    "Web browsers do not support conditional logic",
                    "Client-side checks increase server memory usage excessively",
                    "Client-side validation requires root operating system access",
                ],
                correct_option_index=0,
                explanation="Any check that executes on the client can be bypassed by an adversary modifying client-side scripts, intercepted request parameters, or issuing requests via curl/scripts.",
            ),
            QuizQuestion(
                id="q3",
                question="Which HTTP status code should an API return when an authenticated user attempts to access an unauthorized resource?",
                options=[
                    "403 Forbidden",
                    "401 Unauthorized",
                    "404 Not Found",
                    "500 Internal Server Error",
                ],
                correct_option_index=0,
                explanation="HTTP 403 Forbidden is used when the client's identity is authenticated, but their credentials lack authorization to access the specific resource.",
            ),
            QuizQuestion(
                id="q4",
                question="What is the core principle of Least Privilege?",
                options=[
                    "Users and systems should be granted only the minimum permissions necessary to perform their legitimate tasks",
                    "All users should be granted administrative access by default to avoid permission friction",
                    "Permissions should be validated once at login and never checked on subsequent requests",
                    "Access control policies should be documented publicly for all users",
                ],
                correct_option_index=0,
                explanation="Least Privilege ensures accounts and service processes possess only the minimal privileges required to complete their assigned functions, constraining potential breach impact.",
            ),
            QuizQuestion(
                id="q5",
                question="What is the most effective architectural defense against Insecure Direct Object References (IDOR)?",
                options=[
                    "Enforcing server-side authorization checks that verify the session user owns the requested object",
                    "Using Base64 encoding on database primary keys in URL parameters",
                    "Limiting API requests to desktop operating systems",
                    "Disabling all HTTP GET methods across the application",
                ],
                correct_option_index=0,
                explanation="Robust access control verifies on every request that the authenticated session ID matches the owner_id or authorized role for the requested object before returning data.",
            ),
        ],
    ),
]

ROOM_12_DEFINITION = RoomDefinition(
    room_id="red-12-access-control-testing",
    track=TrackEnum.RED,
    room_number=12,
    title="Access Control Testing",
    short_description="Master authentication vs authorization, RBAC, IDOR / BOLA, horizontal vs vertical boundaries, and server-side authorization checks.",
    difficulty="Intermediate",
    estimated_duration="50 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_12_CONCEPT,
    tasks=ROOM_12_TASKS,
    learning_objectives=[
        "Differentiate horizontal privilege violations (IDOR) from vertical privilege escalation",
        "Inspect and tamper with object identifiers to access unauthorized records",
        "Test administrative endpoints for missing role-based access checks",
        "Implement robust server-side ownership and RBAC enforcement",
    ],
    assessment_criteria=[
        "Identify core access control acronyms and privilege boundary concepts",
        "Capture horizontal IDOR flag and vertical escalation flag",
        "Verify server-side authorization remediation (HTTP 403 Forbidden)",
        "Pass the 5-question access control technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)


# ============================================================================
# ROOM 13: FILE UPLOAD VULNERABILITIES (FULLY IMPLEMENTED)
# ============================================================================

ROOM_13_CONCEPT = RoomConcept(
    overview=(
        "File upload functionality allows users to transfer files to a server filesystem. "
        "Unrestricted or poorly validated file uploads represent critical vulnerabilities that allow "
        "adversaries to upload executable scripts, overwrite arbitrary files via path traversal, or execute code."
    ),
    simple_analogy=(
        "Imagine a corporate mailroom receiving package deliveries. Company policy specifies: 'Only flat paper resumes "
        "in envelopes may be accepted.' If the mail clerk inspects only the label sticker on the envelope ('Resume.pdf') "
        "without inspecting the actual physical contents, an adversary can ship a hazardous mechanical device inside an envelope "
        "labeled 'Resume.pdf'. Once delivered into the building's server room, the device causes severe damage. "
        "A secure mailroom inspects physical dimensions, verifies actual contents with an X-ray scanner (magic bytes inspection), "
        "and stores incoming mail in an isolated quarantine depot outside the executive floor."
    ),
    technical_term="Unrestricted Upload of File with Dangerous Type (OWASP Top 10 A04:2021 / CWE-434)",
    technical_definition=(
        "File upload vulnerabilities occur when an application accepts user-uploaded files without adequate verification "
        "of file extension, MIME type, file headers (magic bytes), and filename paths. "
        "Attackers exploit weak validation to upload server-executable files (.php, .jsp, .phtml) into web-accessible directories, "
        "or utilize directory traversal filenames (../../etc/cron.d/job) to overwrite system files. "
        "Remediation requires: validating file signatures (magic bytes), enforcing strict extension allowlists, generating random UUID filenames, "
        "and storing uploads in non-executable storage locations outside the web root."
    ),
    cybersecurity_context=(
        "Offensive operators bypass client-side file pickers using curl or proxies, disguise extensions (e.g. avatar.php.png), "
        "or tamper with Content-Type headers to deploy webshells. Defenders inspect magic byte signatures, strip directory traversal characters, "
        "and serve files exclusively as download attachments (`Content-Disposition: attachment`)."
    ),
    why_it_matters=(
        "Successful file upload exploitation typically results in immediate Remote Code Execution (RCE) on the backend server, "
        "completely compromising the hosting infrastructure."
    ),
    demonstration=(
        "Unrestricted Upload Vector:\n"
        "  Target Endpoint: POST http://10.10.14.90:8094/api/upload\n"
        "  Malicious Filename: poc.php.png or test_script.php\n"
        "  Vulnerable State: Server accepts .php extensions based purely on client Content-Type.\n"
        "  Hardened State: Rejects unapproved extensions; validates PNG/JPEG magic byte header; renames to UUID.\n"
    ),
    remediation_guide=(
        "1. Implement strict extension allowlists (e.g. only .png, .jpg, .pdf) rather than blocklists.\n"
        "2. Verify magic bytes / file signatures to ensure file content matches the declared format.\n"
        "3. Sanitize filenames using os.path.basename and replace original names with server-generated random UUIDs.\n"
        "4. Store uploaded files outside the public web root in directories mounted with the 'noexec' flag."
    ),
)

ROOM_13_TASKS = [
    TaskDefinition(
        task_id="task-01-file-signatures-magic-bytes",
        order=1,
        title="File Signatures & Magic Bytes",
        instructions=(
            "File extension names can be altered easily, but legitimate binary formats contain fixed leading bytes "
            "called magic bytes (or file signatures). In hexadecimal notation, what 4-byte sequence identifies the header "
            "of a valid PNG image file (`89 50 4E 47` / `\\x89PNG`)?"
        ),
        task_type=TaskType.QUESTION,
        question="Submit the 4-byte hexadecimal sequence identifying a valid PNG file.",
        hint="89 50 4E 47 (spelling \\x89PNG).",
        xp_reward=50,
        accepted_answers=["89 50 4E 47", "89504E47", "89 50 4e 47", "89504e47", "\\x89PNG"],
        mistake_explanations={
            "ffd8ff": "FF D8 FF is the magic byte sequence for JPEG images. PNG headers begin with 89 50 4E 47.",
            "%pdf": "%PDF (25 50 44 46) is the magic byte sequence for PDF documents.",
        },
    ),
    TaskDefinition(
        task_id="task-02-extension-bypass",
        order=2,
        title="Extension Verification Bypass",
        instructions=(
            "The upload gateway on port 8094 does not inspect file contents. Upload the test script file "
            "(`/home/operator/uploads/poc.php.png`) to `http://10.10.14.90:8094/api/upload` using: "
            "`curl -s -F 'file=@/home/operator/uploads/poc.php.png' http://10.10.14.90:8094/api/upload`. "
            "Submit the extension bypass flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the file upload extension bypass flag.",
        hint="Upload poc.php.png using curl -F on port 8094.",
        xp_reward=50,
        accepted_answers=["NOENTRY{file_upload_extension_bypass_1892}"],
        accepted_regex=r"^NOENTRY\{file_upload_extension_bypass_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-03-path-traversal-upload",
        order=3,
        title="Path Traversal in Upload Filenames",
        instructions=(
            "When applications trust client-supplied filenames without sanitization, directory traversal sequences (`../`) "
            "allow files to be written into arbitrary directories. Submit an upload with traversal in the filename: "
            "`curl -s -F 'file=@/home/operator/uploads/avatar.png;filename=../../uploads/poc.txt' http://10.10.14.90:8094/api/upload`. "
            "Submit the path traversal flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the upload path traversal flag.",
        hint="Pass a filename parameter containing ../ in the multipart upload.",
        xp_reward=50,
        accepted_answers=["NOENTRY{file_upload_path_traversal_flag_6301}"],
        accepted_regex=r"^NOENTRY\{file_upload_path_traversal_flag_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-04-mime-spoofing-challenge",
        order=4,
        title="MIME Type Spoofing Challenge",
        instructions=(
            "Interrogate the MIME type validation challenge endpoint: "
            "`curl -s 'http://10.10.14.90:8094/challenge?mime=application/x-php'`. Submit the challenge flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the MIME spoofing challenge flag.",
        hint="Query /challenge with mime=application/x-php on port 8094.",
        xp_reward=60,
        accepted_answers=["NOENTRY{upload_validation_defense_master_4029}"],
        accepted_regex=r"^NOENTRY\{upload_validation_defense_master_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-05-upload-hardening-remediation",
        order=5,
        title="Remediation: Magic Bytes & Storage Hardening",
        instructions=(
            "Harden the upload gateway by enabling extension allowlists, magic byte validation, and UUID renaming: "
            "`curl -s -X POST http://10.10.14.90:8094/api/remediate`. Submit the remediation flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the file upload remediation verification flag.",
        hint="Post to /api/remediate on port 8094.",
        xp_reward=70,
        accepted_answers=["NOENTRY{file_upload_magic_bytes_secured_8832}"],
        accepted_regex=r"^NOENTRY\{file_upload_magic_bytes_secured_\d+\}$",
    ),
    TaskDefinition(
        task_id="task-06-quiz",
        order=6,
        title="File Upload Security Knowledge Assessment",
        instructions="Complete the 5-question quiz to test your conceptual understanding of upload validation, magic bytes, and secure storage.",
        task_type=TaskType.QUIZ,
        question="Complete the 5-question assessment quiz on file uploads.",
        hint="Review MIME spoofing, magic bytes, path traversal, and execution prevention.",
        xp_reward=70,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is checking the client-provided Content-Type header insufficient to ensure file safety?",
                options=[
                    "The Content-Type header is completely controlled by the client and can be spoofed arbitrarily",
                    "Content-Type headers are stripped by network firewalls",
                    "HTTP/1.1 does not support Content-Type headers for file uploads",
                    "Content-Type validation can only be executed by root users",
                ],
                correct_option_index=0,
                explanation="The Content-Type header is an arbitrary MIME string submitted by the user's browser or tool (e.g. curl -F) and provides zero guarantee of actual file contents.",
            ),
            QuizQuestion(
                id="q2",
                question="What security risk is created when saving uploaded files under their original user-supplied filenames?",
                options=[
                    "Directory traversal characters (../) can overwrite arbitrary system files or write outside the intended upload directory",
                    "Original filenames slow down database search performance",
                    "Original filenames prevent browser caching from operating",
                    "Original filenames automatically disable TLS transport encryption",
                ],
                correct_option_index=0,
                explanation="Unsanitized filenames containing traversal sequences (like ../../etc/cron.d/job) permit adversaries to write files outside the target upload root or overwrite critical operating system files.",
            ),
            QuizQuestion(
                id="q3",
                question="What are magic bytes in file validation architecture?",
                options=[
                    "Fixed byte sequences at the beginning of a file that uniquely identify its true format regardless of extension",
                    "Cryptographic signatures added by antivirus software",
                    "Random nonces generated by web application firewalls",
                    "Database primary keys associated with the file upload",
                ],
                correct_option_index=0,
                explanation="Magic bytes (file signatures) are standardized hex bytes at the beginning of binary files (e.g. 89 50 4E 47 for PNG, FF D8 FF for JPEG, %PDF for PDF) identifying the authentic file type.",
            ),
            QuizQuestion(
                id="q4",
                question="Where should uploaded user files be stored to minimize server-side execution risks?",
                options=[
                    "In dedicated object storage or outside the web root on a filesystem mounted with the noexec flag",
                    "Directly inside the web root alongside index.php",
                    "Inside the operating system /etc/ directory",
                    "In the browser local storage of the uploading user",
                ],
                correct_option_index=0,
                explanation="Storing uploads outside web roots on partitions mounted with 'noexec' prevents the web server or underlying operating system from executing uploaded scripts even if an attacker manages to store them.",
            ),
            QuizQuestion(
                id="q5",
                question="Which file extension validation strategy is secure?",
                options=[
                    "A strict allowlist of explicitly permitted safe extensions (e.g. .png, .jpg), rejecting all others",
                    "A blacklist that checks only for '.exe' and '.bat'",
                    "Allowing any extension as long as the filename is longer than 5 characters",
                    "Renaming all uploaded files to end in '.sh'",
                ],
                correct_option_index=0,
                explanation="A strict allowlist explicitly permits known, harmless extensions (e.g. .png, .jpg, .pdf) and rejects all others by default, eliminating bypasses with alternative executable formats (.phtml, .php5, .phar).",
            ),
        ],
    ),
]

ROOM_13_DEFINITION = RoomDefinition(
    room_id="red-13-file-upload-vulnerabilities",
    track=TrackEnum.RED,
    room_number=13,
    title="File Upload Vulnerabilities",
    short_description="Master file upload mechanics, extension bypasses, magic byte inspection, path traversal risks, and secure isolated storage.",
    difficulty="Intermediate",
    estimated_duration="50 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_13_CONCEPT,
    tasks=ROOM_13_TASKS,
    learning_objectives=[
        "Understand the file upload lifecycle and multipart/form-data transport",
        "Inspect and bypass naive extension and MIME-type validation",
        "Demonstrate path traversal risks in unsanitized filenames",
        "Implement strict magic byte validation, extension allowlists, and UUID renaming",
    ],
    assessment_criteria=[
        "Identify file signatures and magic bytes for standard media formats",
        "Capture extension bypass flag and path traversal upload flag",
        "Verify upload remediation enforcing magic byte validation and allowlists",
        "Pass the 5-question file upload technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)
