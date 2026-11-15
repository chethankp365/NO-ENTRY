"""
Complete curriculum definitions, tasks, concept explanations, and quizzes
for Red Team Rooms 14–17:
- Room 14: Command Injection (red-14-command-injection)
- Room 15: Directory Traversal (red-15-directory-traversal)
- Room 16: Password Security & Key Stretching (red-16-password-security)
- Room 17: Privilege Escalation Fundamentals (red-17-privilege-escalation)
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
# ROOM 14: COMMAND INJECTION (FULLY IMPLEMENTED)
# ============================================================================

ROOM_14_CONCEPT = RoomConcept(
    overview=(
        "Command Injection (OS Command Injection) is a critical security vulnerability occurring when an application "
        "concatenates untrusted user input directly into system commands executed by a shell (such as bash, sh, or cmd.exe). "
        "This allows an adversary to execute arbitrary operating-system commands with the privileges of the hosting web service."
    ),
    simple_analogy=(
        "Imagine an office manager who delegates tasks to couriers by writing work orders on cards. "
        "If a work order says 'Deliver package to address: [user address]', and a malicious customer submits: "
        "'42 Market Street; then open the company safe and photocopy the master ledger', a negligent courier who simply "
        "reads the entire sentence aloud to the office staff executes both the legitimate delivery and the unauthorized theft. "
        "In command injection, the application passes unvalidated user input directly to the shell interpreter, allowing command "
        "chaining operators like semicolons or pipes to trigger secondary operating-system commands."
    ),
    technical_term="OS Command Injection (OWASP Top 10 A03:2021 — Injection / CWE-78)",
    technical_definition=(
        "Command injection takes place when user-supplied input is embedded into a command line string executed via system "
        "interfaces such as system(), popen(), or subprocess.Popen(..., shell=True). Because the shell treats metacharacters "
        "(;, |, &, &&, ||, $(), `, \n) as command separators, pipeline operators, or command substitution constructs, "
        "an attacker can append or substitute arbitrary executable commands. Mitigation requires avoiding shell invocation entirely "
        "by utilizing parameterized APIs (e.g. execve argument arrays where shell=False) and validating input against strict allowlists."
    ),
    cybersecurity_context=(
        "Command injection represents an immediate transition from web application compromise to host-level operating system "
        "takeover. Once an attacker obtains command execution, they can deploy web shells, dump system credentials (/etc/shadow), "
        "pivot into internal network subnets, and establish persistent backdoors. Modern security architecture requires that web "
        "runtimes execute as minimally privileged service accounts inside ephemeral containers with immutable root filesystems."
    ),
    why_it_matters=(
        "Unlike SQL injection, which is confined to the relational database engine, command injection directly yields arbitrary "
        "process execution on the underlying host kernel, rendering all application sandboxing and perimeter firewalls ineffective "
        "if the service process has access to local sockets or sensitive storage."
    ),
    demonstration=(
        "Vulnerable Command Construction:\n"
        "  Target Code: subprocess.run(f'ping -c 1 {host}', shell=True, capture_output=True)\n"
        "  Attacker Input: 127.0.0.1; cat /etc/passwd\n"
        "  Executed Shell Command: ping -c 1 127.0.0.1; cat /etc/passwd\n"
        "  Impact: Shell runs ping, then runs cat, dumping sensitive password file.\n\n"
        "Remediated Safe Execution:\n"
        "  Safe Code: subprocess.run(['ping', '-c', '1', validated_host], shell=False, capture_output=True)\n"
        "  Input: 127.0.0.1; cat /etc/passwd\n"
        "  Result: ping binary receives the exact literal string as an IP argument and fails safely without invoking a shell."
    ),
    remediation_guide=(
        "1. Avoid invoking system shells entirely. Never pass user input to os.system() or subprocess.run(..., shell=True).\n"
        "2. Utilize direct execve-based argument vectors (e.g., subprocess.run(['/bin/ping', '-c', '1', host], shell=False)).\n"
        "3. Validate all input strictly against allowlists (e.g., standard regex ^[a-zA-Z0-9.-]+$ for hostnames/IPs).\n"
        "4. Enforce strict character allowlists, rejecting metacharacters (;, |, &, $, `, \\n, <, >).\n"
        "5. Run the web service as an unprivileged service account with no sudo rights and minimal filesystem write permissions."
    ),
)

ROOM_14_TASKS = [
    TaskDefinition(
        task_id="task-01-cmd-injection-mechanics",
        order=1,
        title="Application Input vs OS Command Execution",
        instructions=(
            "Review the architectural difference between passing structured arguments directly to an executable binary "
            "versus passing an unparsed command string to a shell interpreter (sh, bash, cmd.exe). "
            "In Python's `subprocess` module, one configuration parameter instructs the runtime to launch an intermediate "
            "system shell to parse and execute the command string, rendering it vulnerable to metacharacter injection."
        ),
        task_type=TaskType.QUESTION,
        question="Which Python subprocess keyword argument enables shell interpretation of command strings?",
        hint="It is a boolean keyword argument passed to subprocess.run or Popen.",
        xp_reward=50,
        accepted_answers=["shell=True", "shell=true", "shell = True", "shell"],
        mistake_explanations={
            "capture_output": "capture_output captures standard output and error, but does not invoke a shell.",
            "check=True": "check=True raises an exception on non-zero exit codes; it does not control shell invocation.",
            "text=True": "text=True sets string encoding for I/O streams.",
        },
    ),
    TaskDefinition(
        task_id="task-02-ping-diagnostics-probing",
        order=2,
        title="Shell Metacharacters & Diagnostic Probing",
        instructions=(
            "The diagnostic service on port 8095 exposes a network latency probe at `/api/diagnostics/ping`. "
            "The backend unsafely concatenates the `host` parameter into a shell execution string: `ping -c 1 {host}`. "
            "Use the terminal to issue an HTTP request injecting the semicolon `;` command separator to chain an arbitrary command: "
            "`curl -s 'http://10.10.14.90:8095/api/diagnostics/ping?host=127.0.0.1%3Bid'` and submit the diagnostic execution flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag returned from the semicolon command injection probe.",
        hint="Use curl to target http://10.10.14.90:8095/api/diagnostics/ping?host=127.0.0.1;id or URL-encode the semicolon as %3B.",
        xp_reward=60,
        accepted_answers=["NOENTRY{cmd_injection_shell_metachars_8192}"],
        mistake_explanations={
            "NOENTRY{cmd_injection_command_chain_3391}": "That flag belongs to the DNS pipeline operator task.",
            "NOENTRY{cmd_injection_operator_master_7140}": "That flag belongs to the breakout challenge task.",
        },
    ),
    TaskDefinition(
        task_id="task-03-command-chaining-operators",
        order=3,
        title="Command Chaining with Logical and Pipeline Operators",
        instructions=(
            "In addition to semicolons, shell interpreters support pipeline (`|`) and boolean operators (`&&`, `||`). "
            "The DNS resolution probe at `/api/diagnostics/dns?domain=` concatenates input into `nslookup {domain}`. "
            "Execute a probe using the logical AND operator `&&` (URL-encoded as `%26%26`) or pipe `|`: "
            "`curl -s 'http://10.10.14.90:8095/api/diagnostics/dns?domain=target.noentry.internal%26%26whoami'` "
            "and submit the command chaining flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag returned by exploiting command chaining on the DNS diagnostic endpoint.",
        hint="Inject && (URL-encoded as %26%26) or | into the domain query parameter.",
        xp_reward=60,
        accepted_answers=["NOENTRY{cmd_injection_command_chain_3391}"],
        mistake_explanations={
            "NOENTRY{cmd_injection_shell_metachars_8192}": "That flag belongs to the ping diagnostics task.",
        },
    ),
    TaskDefinition(
        task_id="task-04-operator-breakout-challenge",
        order=4,
        title="Command Substitution & Metacharacter Breakout Challenge",
        instructions=(
            "Command substitution constructs (`$(...)` and backticks) allow attackers to embed command output directly into "
            "command arguments. The diagnostic gateway provides an advanced probe verification endpoint at `/challenge?probe=`. "
            "Submit a probe query utilizing command substitution or metacharacters (`curl -s 'http://10.10.14.90:8095/challenge?probe=127.0.0.1%24(whoami)'`) "
            "and capture the breakout mastery flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag returned from the command substitution breakout challenge.",
        hint="Pass $(whoami) or backticks or | in the probe parameter.",
        xp_reward=60,
        accepted_answers=["NOENTRY{cmd_injection_operator_master_7140}"],
        mistake_explanations={
            "NOENTRY{cmd_injection_safe_api_remediated_5521}": "That flag is awarded upon successful remediation.",
        },
    ),
    TaskDefinition(
        task_id="task-05-safe-api-remediation",
        order=5,
        title="Safe API Architecture & Input Hardening",
        instructions=(
            "True defense against OS command injection requires replacing shell invocation with direct process execution "
            "(argument vector lists) and enforcing strict regex allowlists. "
            "Trigger the service remediation endpoint via `curl -s -X POST http://10.10.14.90:8095/api/remediate`. "
            "Verify that shell execution is disabled, metacharacters are rejected with HTTP 400 Bad Request, "
            "and submit the remediation verification flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag received upon applying safe API parameterization.",
        hint="POST to http://10.10.14.90:8095/api/remediate.",
        xp_reward=60,
        accepted_answers=["NOENTRY{cmd_injection_safe_api_remediated_5521}"],
        mistake_explanations={
            "NOENTRY{cmd_injection_operator_master_7140}": "That flag is for the breakout challenge.",
        },
    ),
    TaskDefinition(
        task_id="task-06-room-quiz",
        order=6,
        title="Room 14 Knowledge Assessment",
        instructions=(
            "Demonstrate your mastery of command injection vectors, shell metacharacters, and safe programming APIs "
            "by completing this 5-question technical quiz."
        ),
        task_type=TaskType.QUIZ,
        xp_reward=60,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is passing an array of arguments to subprocess.run(['ping', host], shell=False) immune to command injection?",
                options=[
                    "The operating system executes the ping binary directly via execve, treating host as a literal data argument without invoking a shell interpreter.",
                    "The operating system automatically removes all semicolons and ampersands before passing data to the shell.",
                    "Python automatically encrypts user input before passing it to the operating system kernel.",
                    "The Linux kernel blocks all network commands executed without root privileges.",
                ],
                correct_option_index=0,
                explanation="When shell=False, the kernel invokes execve directly. Arguments are passed as individual memory strings, eliminating shell parsing and metacharacter execution entirely.",
            ),
            QuizQuestion(
                id="q2",
                question="Which shell operator executes a second command ONLY if the first command succeeds (exit code 0)?",
                options=[
                    "&& (Logical AND)",
                    "|| (Logical OR)",
                    "; (Semicolon sequence)",
                    "| (Standard Pipeline)",
                ],
                correct_option_index=0,
                explanation="In POSIX shells, && executes the subsequent command only if the preceding command returns exit status 0 (success).",
            ),
            QuizQuestion(
                id="q3",
                question="What security impact differentiates Command Injection from Cross-Site Scripting (XSS)?",
                options=[
                    "Command injection executes arbitrary operating system commands on the hosting server, whereas XSS executes JavaScript in victim client browsers.",
                    "Command injection only affects databases, whereas XSS affects web servers.",
                    "XSS gives root access to the hosting server, while command injection is limited to HTML formatting.",
                    "Command injection is an unfixable hardware bug in Intel and AMD microprocessors.",
                ],
                correct_option_index=0,
                explanation="Command injection is a host-side attack executing commands on the server OS, whereas XSS is a client-side attack executing within user web browsers.",
            ),
            QuizQuestion(
                id="q4",
                question="Which input validation strategy is recommended to defend against command injection when an argument must be accepted?",
                options=[
                    "Strict allowlisting using regular expressions matching only expected alphanumeric formats (e.g. ^[0-9a-f:.]+$).",
                    "Blacklisting only the semicolon character while leaving all other characters uninspected.",
                    "Replacing all spaces with tabs so the shell does not detect arguments.",
                    "Base64 encoding the input before concatenating it into a shell string.",
                ],
                correct_option_index=0,
                explanation="Allowlisting ensures only legitimate characters matching strict syntactic constraints are permitted, avoiding the pitfalls of incomplete blacklists.",
            ),
            QuizQuestion(
                id="q5",
                question="If an application must generate a hash or archive a file, what is the most secure software architecture?",
                options=[
                    "Use native programming language libraries (e.g., hashlib, zipfile) rather than spawning external shell commands.",
                    "Spawn bash with sudo privileges to ensure commands do not encounter permission errors.",
                    "Write user inputs directly to /tmp/script.sh and execute it with chmod 777.",
                    "Concatenate inputs into os.system() calls because os.system() is memory-safe.",
                ],
                correct_option_index=0,
                explanation="Using built-in, native language libraries avoids process invocation entirely and eliminates all possibility of OS command injection.",
            ),
        ],
    ),
]

ROOM_14_DEFINITION = RoomDefinition(
    room_id="red-14-command-injection",
    room_number=14,
    track=TrackEnum.RED,
    title="Command Injection",
    short_description="Analyze OS command construction, exploit shell metacharacters and command chaining operators, and implement secure process execution APIs.",
    difficulty="Intermediate",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_14_CONCEPT,
    tasks=ROOM_14_TASKS,
    learning_objectives=[
        "Differentiate structured API process invocation from shell command string parsing",
        "Identify and exploit shell metacharacters and command separators (; and |)",
        "Construct multi-stage command execution chains using boolean operators (&& and ||)",
        "Implement secure process execution using argument vector arrays and allowlists",
    ],
    assessment_criteria=[
        "Identify the subprocess configuration argument enabling shell interpretation",
        "Capture diagnostic flags via semicolon and command chaining operators",
        "Solve the command substitution breakout challenge",
        "Verify defensive remediation using argument vector arrays",
        "Pass the 5-question command injection technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)


# ============================================================================
# ROOM 15: DIRECTORY TRAVERSAL (FULLY IMPLEMENTED)
# ============================================================================

ROOM_15_CONCEPT = RoomConcept(
    overview=(
        "Directory Traversal (also known as Path Traversal or Arbitrary File Disclosure) is an authorization and input validation "
        "vulnerability allowing an adversary to read or manipulate arbitrary files on the web server filesystem outside the intended "
        "document root directory by manipulating file path references."
    ),
    simple_analogy=(
        "Consider a corporate archival library where visitors may request documents by filling out a slip with a folder name "
        "located inside the Public Documents room. If an unauthorized researcher writes 'Public/../../Executive/Confidential_Memos', "
        "and the librarian naively follows the directions step-by-step—stepping into Public, backing out to the corridor, "
        "backing out to the building lobby, and walking into the restricted Executive suite—the researcher accesses classified "
        "records outside the permitted reading room. In directory traversal, dot-dot-slash (../) sequences instruct the operating "
        "system to step up into parent directories beyond the authorized file boundary."
    ),
    technical_term="Path Traversal (OWASP Top 10 A01:2021 — Broken Access Control / CWE-22)",
    technical_definition=(
        "Directory traversal occurs when an application accepts user input representing file or folder names and passes that input "
        "to filesystem APIs (such as open(), readfile(), or FileOutputStream) without canonicalization and boundary verification. "
        "By utilizing dot-dot-slash (../ or ..\\) sequences, absolute path prefixes (/etc/passwd, C:\\Windows\\System32), or "
        "URL-encoded variants (%2e%2e%2f), an attacker traverses beyond the intended base directory to access sensitive configuration "
        "files, application source code, and cryptographic credentials."
    ),
    cybersecurity_context=(
        "Directory traversal is frequently combined with other attack vectors. Reading database configuration files (e.g. .env, "
        "database.yml) yields credentials for secondary exploitation. Reading /etc/passwd or Windows registry hives discloses user "
        "inventories, and reading web application source code allows attackers to discover zero-day logic flaws. In severe scenarios, "
        "path traversal in upload or archive extraction endpoints (Zip Slip) enables arbitrary remote code execution."
    ),
    why_it_matters=(
        "Even when web services implement strong authentication tokens, an unauthenticated directory traversal vulnerability "
        "allows adversaries to extract the private cryptographic keys used to sign those tokens, collapsing the entire security model."
    ),
    demonstration=(
        "Vulnerable File Access Endpoint:\n"
        "  Target URL: http://10.10.14.90:8096/api/files/view?file=../../vault/recovery.key\n"
        "  Underlying Call: open('/app/public_docs/' + request.args.get('file'))\n"
        "  Resolved Filesystem Path: /app/vault/recovery.key\n"
        "  Result: Application returns secret recovery credentials to the attacker.\n\n"
        "Secure Canonical Path Resolution:\n"
        "  Safe Code:\n"
        "    base_dir = Path('/app/public_docs').resolve()\n"
        "    target_file = (base_dir / user_input).resolve()\n"
        "    if not target_file.is_relative_to(base_dir):\n"
        "        raise PermissionError('Directory traversal prohibited')\n"
        "  Result: Traversal attempt resolves outside base_dir and is immediately rejected with HTTP 403 Forbidden."
    ),
    remediation_guide=(
        "1. Avoid accepting direct filesystem paths from client input. Prefer indirect object identifiers (e.g., file IDs mapped in a database).\n"
        "2. Canonicalize all target paths using Path.resolve() or os.path.realpath() before opening files.\n"
        "3. Verify that the resolved canonical path begins with the canonical base directory using path.is_relative_to(base_dir).\n"
        "4. Enforce strict allowlists on filenames (e.g., ^[a-zA-Z0-9_.-]+$) and reject all paths containing slashes or dots.\n"
        "5. Restrict web server process filesystem permissions with chroot or container isolation."
    ),
)

ROOM_15_TASKS = [
    TaskDefinition(
        task_id="task-01-path-traversal-mechanics",
        order=1,
        title="Relative Path Navigation Mechanics",
        instructions=(
            "Understand how operating systems resolve relative path navigation sequences. "
            "In hierarchical filesystems adhering to POSIX standards or Windows conventions, a specific two-character "
            "directory reference represents the parent of the current working directory."
        ),
        task_type=TaskType.QUESTION,
        question="Which relative directory sequence ascends one level upward to the parent directory in hierarchical filesystems?",
        hint="Two dots and an optional slash.",
        xp_reward=50,
        accepted_answers=["../", "..", "..\\"],
        mistake_explanations={
            "current": "A single dot or current directory reference refers to the current directory, not the parent directory.",
            "root": "A forward slash or root directory refers to the root directory, not a relative parent step.",
            "home": "A tilde or home directory represents the user's home directory.",
        },
    ),
    TaskDefinition(
        task_id="task-02-relative-traversal-probing",
        order=2,
        title="Relative Path Traversal to Sensitive Assets",
        instructions=(
            "The document viewer service on port 8096 exposes a public document reader at `/api/files/view?file=`. "
            "The backend naively opens files relative to its public folder. "
            "Use `curl` to traverse out of the public folder into the private vault directory: "
            "`curl -s 'http://10.10.14.90:8096/api/files/view?file=../../vault/recovery.key'` "
            "and submit the confidential vault recovery flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag disclosed by reading the restricted recovery key file via relative path traversal.",
        hint="Target http://10.10.14.90:8096/api/files/view?file=../../vault/recovery.key",
        xp_reward=60,
        accepted_answers=["NOENTRY{dir_traversal_dot_dot_slash_4102}"],
        mistake_explanations={
            "NOENTRY{dir_traversal_arbitrary_file_read_9318}": "That flag belongs to the arbitrary file download task.",
            "NOENTRY{dir_traversal_encoding_bypass_7749}": "That flag belongs to the encoded challenge task.",
        },
    ),
    TaskDefinition(
        task_id="task-03-arbitrary-file-disclosure",
        order=3,
        title="Arbitrary File Read & System Disclosure",
        instructions=(
            "In addition to viewing document text, the service exposes a file download handler at `/api/files/download?file=`. "
            "If an application fails to restrict file downloads to an authorized repository, an adversary can extract system-level telemetry and credentials. "
            "Probe the download endpoint with an absolute or deep traversal path: "
            "`curl -s 'http://10.10.14.90:8096/api/files/download?file=/etc/telemetry.log'` "
            "and submit the arbitrary file disclosure flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag returned from the arbitrary file download endpoint.",
        hint="Curl http://10.10.14.90:8096/api/files/download?file=/etc/telemetry.log or use ../../ sequences.",
        xp_reward=60,
        accepted_answers=["NOENTRY{dir_traversal_arbitrary_file_read_9318}"],
        mistake_explanations={
            "NOENTRY{dir_traversal_dot_dot_slash_4102}": "That flag belongs to the relative vault reading task.",
        },
    ),
    TaskDefinition(
        task_id="task-04-encoding-bypass-challenge",
        order=4,
        title="URL-Encoded Traversal Sequence Challenge",
        instructions=(
            "Web application firewalls (WAFs) and poorly implemented input filters often attempt to block literal `../` strings, "
            "yet vulnerable web frameworks decode URL hex sequences (%2e for dot, %2f for slash) after filter evaluation. "
            "The verification endpoint at `/challenge?doc=` tests your ability to supply encoded traversal patterns. "
            "Submit an encoded traversal query: `curl -s 'http://10.10.14.90:8096/challenge?doc=%2e%2e%2fsecret'` "
            "and capture the encoding mastery flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag returned by supplying URL-encoded path traversal characters.",
        hint="Use %2e%2e%2f or ..%2f in the doc query parameter.",
        xp_reward=60,
        accepted_answers=["NOENTRY{dir_traversal_encoding_bypass_7749}"],
        mistake_explanations={
            "NOENTRY{dir_traversal_canonical_path_secured_2810}": "That flag is awarded upon completing remediation.",
        },
    ),
    TaskDefinition(
        task_id="task-05-canonical-path-remediation",
        order=5,
        title="Canonical Path Resolution & Boundary Hardening",
        instructions=(
            "To definitively prevent directory traversal, software must resolve symbolic links and relative references into "
            "absolute canonical paths (`Path.resolve()`) and confirm that the target path remains within the base directory. "
            "Trigger the service remediation endpoint: `curl -s -X POST http://10.10.14.90:8096/api/remediate`. "
            "Verify that traversal attempts are blocked with HTTP 403 Forbidden, and submit the remediation flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag received after applying canonical path verification and directory boundary checks.",
        hint="POST to http://10.10.14.90:8096/api/remediate.",
        xp_reward=60,
        accepted_answers=["NOENTRY{dir_traversal_canonical_path_secured_2810}"],
        mistake_explanations={
            "NOENTRY{dir_traversal_encoding_bypass_7749}": "That flag belongs to the encoding bypass challenge.",
        },
    ),
    TaskDefinition(
        task_id="task-06-room-quiz",
        order=6,
        title="Room 15 Knowledge Assessment",
        instructions=(
            "Test your understanding of filesystem boundaries, path traversal mechanics, URL encoding evasion, "
            "and canonicalization defenses."
        ),
        task_type=TaskType.QUIZ,
        xp_reward=60,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is filtering literal '../' strings by replacing them with empty strings ('') dangerous and ineffective?",
                options=[
                    "Adversaries can supply nested patterns like '....//', which after a single pass of '../' removal collapse into '../'.",
                    "The operating system automatically restores the deleted characters upon saving the file.",
                    "Web browsers will crash if an HTTP request does not contain dots.",
                    "Filtering strings causes CPU memory leaks in Linux kernels.",
                ],
                correct_option_index=0,
                explanation="Incomplete recursive string replacement leaves attackers able to bypass filters using constructs like '....//' or '..././', which transform into '../' after one pass.",
            ),
            QuizQuestion(
                id="q2",
                question="What is the definition of path 'canonicalization' in operating systems and secure coding?",
                options=[
                    "Resolving all relative references (such as '.' and '..') and symbolic links to determine the unique, absolute filesystem location.",
                    "Encrypting the file path using AES-256 before accessing it on the disk.",
                    "Compressing file paths into MD5 hashes to conserve database index storage.",
                    "Converting all uppercase letters in a path into lowercase letters.",
                ],
                correct_option_index=0,
                explanation="Canonicalization resolves relative directory segments, symbolic links, and redundant separators into a single normalized, unambiguous absolute path.",
            ),
            QuizQuestion(
                id="q3",
                question="In Python 3.9+, which method securely checks whether a resolved Path object resides within a designated base directory?",
                options=[
                    "target_path.is_relative_to(base_directory)",
                    "target_path.startswith(base_directory)",
                    "base_directory.contains(target_path)",
                    "os.path.samefile(target_path, base_directory)",
                ],
                correct_option_index=0,
                explanation="Path.is_relative_to(base) checks whether the path is relative to the given base path, correctly handling directory boundaries without string prefix vulnerabilities.",
            ),
            QuizQuestion(
                id="q4",
                question="What security risk arises if a string prefix check (e.g., path.startswith('/app/data')) is used instead of a directory-boundary check?",
                options=[
                    "An attacker accessing '/app/data_confidential' satisfies the startswith condition even though it is a different directory.",
                    "The startswith method throws an unhandled exception whenever a path contains an underscore.",
                    "The web server automatically redirects the user to the login screen.",
                    "String methods fail on Linux because Linux paths use backslashes.",
                ],
                correct_option_index=0,
                explanation="Without enforcing a trailing directory separator, '/app/data' matches sibling directories like '/app/data_private' or '/app/database'.",
            ),
            QuizQuestion(
                id="q5",
                question="Which architecture offers the strongest defense against arbitrary file downloads in a web service?",
                options=[
                    "Store files using random UUID keys in object storage (or database IDs) and never expose raw filesystem paths to clients.",
                    "Permit clients to specify absolute paths as long as they provide a valid session cookie.",
                    "Store all application files in /tmp so they are deleted upon system reboot.",
                    "Disable HTTPS so network firewalls can inspect file download parameters in plaintext.",
                ],
                correct_option_index=0,
                explanation="Using indirect identifiers (UUIDs/IDs) decouples client requests completely from the underlying filesystem hierarchy, eliminating path traversal risks.",
            ),
        ],
    ),
]

ROOM_15_DEFINITION = RoomDefinition(
    room_id="red-15-directory-traversal",
    room_number=15,
    track=TrackEnum.RED,
    title="Directory Traversal",
    short_description="Explore filesystem path boundaries, exploit dot-dot-slash relative references and URL-encoded traversal patterns, and enforce canonical path resolution.",
    difficulty="Intermediate",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_15_CONCEPT,
    tasks=ROOM_15_TASKS,
    learning_objectives=[
        "Understand filesystem path resolution and relative path mechanics",
        "Exploit dot-dot-slash (../) sequences to read sensitive files outside document roots",
        "Bypass naive string filters using URL encoding (%2e%2e%2f) and path variations",
        "Implement secure file-serving with path canonicalization and directory boundary verification",
    ],
    assessment_criteria=[
        "Identify relative path navigation tokens",
        "Disclose restricted vault files via relative directory traversal",
        "Extract arbitrary system files via file download endpoints",
        "Solve the encoded path traversal evasion challenge",
        "Verify path canonicalization and boundary remediation",
        "Pass the 5-question directory traversal technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)


# ============================================================================
# ROOM 16: PASSWORD SECURITY (FULLY IMPLEMENTED)
# ============================================================================

ROOM_16_CONCEPT = RoomConcept(
    overview=(
        "Password Security & Key Stretching encompasses the cryptographic principles, storage architectures, and policy standards "
        "required to protect user credentials against offline credential cracking, rainbow table lookups, and brute-force attacks."
    ),
    simple_analogy=(
        "Imagine a hotel that protects guest safety deposit boxes. If the hotel writes every guest's combination lock code "
        "on a whiteboard in the lobby (plaintext storage), any passerby can open every box immediately. If the hotel instead "
        "uses a basic photocopy of the code (fast hash like MD5), a thief with a digital database of common photocopies (rainbow tables) "
        "can look up the original code in microseconds. But if the hotel stamps each guest's code with a unique, unrepeatable wax seal (salt) "
        "and places the slip inside a mechanical lockbox that takes three seconds of manual crank turning to open (adaptive key stretching like bcrypt), "
        "a thief who steals the lockboxes would require hundreds of years of crank turning to test millions of passwords."
    ),
    technical_term="Cryptographic Password Hashing & Key Stretching (OWASP Top 10 A02:2021 — Cryptographic Failures / CWE-916)",
    technical_definition=(
        "Passwords must never be stored in plaintext or reversible encryption. Instead, passwords must be transformed using "
        "cryptographically secure, adaptive one-way key-derivation functions (KDFs) such as Argon2id, bcrypt, or PBKDF2. "
        "Every credential entry must incorporate a cryptographically strong, unique per-user salt (at least 16 random bytes) "
        "to defeat precomputed lookup structures (rainbow tables). Adaptive algorithms introduce a configurable work factor "
        "(cost factor / iterations) that can be scaled over time as hardware speeds increase, deliberately constraining offline "
        "GPU/ASIC cracking throughput."
    ),
    cybersecurity_context=(
        "Credential database breaches occur routinely. When an attacker dumps a backend database, the security of user accounts "
        "rests entirely on the cryptographic strength of the password storage scheme. Fast general-purpose hashing algorithms "
        "(MD5, SHA-1, SHA-256) were designed for message integrity verification, allowing modern GPUs to compute billions of hashes "
        "per second. In contrast, memory-hard algorithms like Argon2id and computationally intensive functions like bcrypt restrict "
        "adversary throughput to a few thousand attempts per second, rendering offline dictionary attacks unfeasible."
    ),
    why_it_matters=(
        "Because users frequently reuse credentials across corporate and personal services, a compromised unsalted hash database "
        "fuels widespread credential stuffing campaigns against enterprise infrastructure, virtual private networks (VPNs), "
        "and single sign-on (SSO) identity providers."
    ),
    demonstration=(
        "Vulnerable Legacy Storage:\n"
        "  Algorithm: MD5 (Unsalted)\n"
        "  Stored Hash: 5f4dcc3b5aa765d61d8327deb882cf99\n"
        "  Cracking Velocity: Over 10,000,000,000 hashes/sec on modern GPU.\n"
        "  Result: Precomputed rainbow tables or dictionary attacks reverse hash to 'password' instantaneously.\n\n"
        "Modern Hardened Storage:\n"
        "  Algorithm: bcrypt (Salted, Work Factor 12)\n"
        "  Stored String: $2b$12$e8ukV.yCg3vC9B1yq3vCDe6x8F7K9L2M3N4O5P6Q7R8S9T0U1V2W3\n"
        "  Properties: Unique per-user 128-bit salt embedded; 4,096 cryptographic rounds.\n"
        "  Cracking Velocity: Limited to ~5,000 guesses/sec per GPU, neutralizing dictionary attacks."
    ),
    remediation_guide=(
        "1. Never store passwords in plaintext or using reversible symmetric encryption.\n"
        "2. Never use fast cryptographic hashes (MD5, SHA-1, SHA-256, SHA-512) for password storage.\n"
        "3. Implement modern adaptive key-derivation algorithms: Argon2id (preferred) or bcrypt (minimum work factor 12).\n"
        "4. Enforce unique, cryptographically random salts generated by the KDF for every individual password.\n"
        "5. Align password policies with NIST SP 800-63B: require at least 8–12 characters, screen against known breached wordlists, and avoid arbitrary periodic expiration."
    ),
)

ROOM_16_TASKS = [
    TaskDefinition(
        task_id="task-01-salting-principles",
        order=1,
        title="Cryptographic Salts & Rainbow Table Neutralization",
        instructions=(
            "Examine how cryptographic salts function in password storage. "
            "A rainbow table is a precomputed lookup table mapping common plaintext passwords to their respective cryptographic hash digests. "
            "To prevent an adversary from checking multiple users simultaneously or using precomputed tables, the authentication engine "
            "appends a unique, cryptographically random value to each password prior to hashing."
        ),
        task_type=TaskType.QUESTION,
        question="What unique random value is concatenated with a password before hashing to defeat precomputed rainbow tables?",
        hint="A four-letter culinary seasoning term.",
        xp_reward=50,
        accepted_answers=["salt", "Salt", "cryptographic salt", "a salt"],
        mistake_explanations={
            "pepper": "A pepper is a secret application-wide key, not a unique per-user value.",
            "nonce": "A nonce is a number used once for freshness in protocols, whereas salts ensure hash diversity.",
            "iv": "An Initialization Vector (IV) is used in symmetric block cipher encryption modes.",
        },
    ),
    TaskDefinition(
        task_id="task-02-dump-unsalted-hashes",
        order=2,
        title="Legacy Unsalted Hash Disclosure",
        instructions=(
            "The identity gateway on port 8097 contains an administrative debugging endpoint at `/api/users/dump`. "
            "Query the endpoint using `curl -s http://10.10.14.90:8097/api/users/dump`. "
            "Inspect the disclosed database records to observe unsalted MD5 hashes and submit the exposed database flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag returned by querying the exposed legacy user database dump.",
        hint="Curl http://10.10.14.90:8097/api/users/dump",
        xp_reward=60,
        accepted_answers=["NOENTRY{pwd_sec_plaintext_md5_cracked_8912}"],
        mistake_explanations={
            "NOENTRY{pwd_sec_hash_collision_breach_3419}": "That flag is obtained after authenticating with cracked credentials.",
            "NOENTRY{pwd_sec_key_stretching_master_6601}": "That flag belongs to the key stretching challenge.",
        },
    ),
    TaskDefinition(
        task_id="task-03-hash-cracking-verification",
        order=3,
        title="Hash Cracking & Credential Verification",
        instructions=(
            "In the user dump, Alice's password hash is `5f4dcc3b5aa765d61d8327deb882cf99`. "
            "Because this is an unsalted MD5 digest of a common password, it cracks immediately to the plaintext string `password`. "
            "Authenticate against the login endpoint via `POST /api/verify` with Alice's credentials: "
            "`curl -s -X POST http://10.10.14.90:8097/api/verify -H 'Content-Type: application/json' -d '{\"username\":\"alice\",\"password\":\"password\"}'` "
            "and submit the hash verification flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag received upon authenticating with the cracked password.",
        hint="POST username=alice and password=password to http://10.10.14.90:8097/api/verify",
        xp_reward=60,
        accepted_answers=["NOENTRY{pwd_sec_hash_collision_breach_3419}"],
        mistake_explanations={
            "NOENTRY{pwd_sec_plaintext_md5_cracked_8912}": "That flag belongs to the hash dump task.",
        },
    ),
    TaskDefinition(
        task_id="task-04-key-stretching-challenge",
        order=4,
        title="Adaptive Key Stretching Verification",
        instructions=(
            "General-purpose hashing algorithms execute in fractions of a microsecond, enabling rapid GPU cracking. "
            "Modern security requires adaptive key-derivation algorithms that allow administrators to configure cost factors. "
            "Probe the key-stretching verification endpoint specifying a recommended algorithm: "
            "`curl -s 'http://10.10.14.90:8097/challenge?algorithm=bcrypt'` "
            "and capture the key-stretching mastery flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag returned from the key stretching algorithm challenge.",
        hint="Target http://10.10.14.90:8097/challenge?algorithm=bcrypt or argon2",
        xp_reward=60,
        accepted_answers=["NOENTRY{pwd_sec_key_stretching_master_6601}"],
        mistake_explanations={
            "NOENTRY{pwd_sec_salted_bcrypt_hardened_4418}": "That flag is awarded upon applying remediation.",
        },
    ),
    TaskDefinition(
        task_id="task-05-password-remediation",
        order=5,
        title="Password Storage Hardening & NIST 800-63B Remediation",
        instructions=(
            "Enforce production-grade credential security by activating salted bcrypt key stretching and aligning with NIST SP 800-63B guidelines. "
            "Trigger remediation via `curl -s -X POST http://10.10.14.90:8097/api/remediate`. "
            "Verify that unsalted hashes are rejected, work factor 12 is enforced, and submit the remediation verification flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag received after applying salted bcrypt key stretching and NIST 800-63B hardening.",
        hint="POST to http://10.10.14.90:8097/api/remediate.",
        xp_reward=60,
        accepted_answers=["NOENTRY{pwd_sec_salted_bcrypt_hardened_4418}"],
        mistake_explanations={
            "NOENTRY{pwd_sec_key_stretching_master_6601}": "That flag belongs to the key stretching challenge.",
        },
    ),
    TaskDefinition(
        task_id="task-06-room-quiz",
        order=6,
        title="Room 16 Knowledge Assessment",
        instructions=(
            "Assess your technical understanding of cryptographic password hashing, salts, key stretching, and modern NIST policy standards."
        ),
        task_type=TaskType.QUIZ,
        xp_reward=60,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is SHA-256 without a key-derivation function unsuitable for password storage, even if it is cryptographically unbroken?",
                options=[
                    "SHA-256 was designed for fast streaming integrity verification; a modern GPU cluster can compute billions of SHA-256 hashes per second, making offline dictionary attacks trivial.",
                    "SHA-256 produces output that can be reversed using basic algebraic factoring formulas.",
                    "SHA-256 cannot process passwords longer than 8 characters.",
                    "SHA-256 is a symmetric block cipher that requires sharing secret keys with clients.",
                ],
                correct_option_index=0,
                explanation="General-purpose hash functions prioritize high speed and throughput, which is fatal for password storage because attackers can test billions of candidate passwords per second.",
            ),
            QuizQuestion(
                id="q2",
                question="What primary advantage does Argon2id provide over legacy key-stretching functions like PBKDF2?",
                options=[
                    "Argon2id is memory-hard, requiring configurable amounts of RAM that prevent cost-effective scaling on custom GPU and ASIC cracking rigs.",
                    "Argon2id produces hashes that can be decoded by authorized administrators without a password.",
                    "Argon2id eliminates the requirement to store any salt values in the database.",
                    "Argon2id runs entirely in hardware inside the motherboard BIOS.",
                ],
                correct_option_index=0,
                explanation="Argon2id combines data-dependent and data-independent memory access, creating memory-hardness that makes dedicated hardware (ASICs and GPUs) inefficient at brute-forcing.",
            ),
            QuizQuestion(
                id="q3",
                question="Under NIST Special Publication 800-63B guidelines, which traditional password policy is officially discouraged?",
                options=[
                    "Arbitrary periodic password expiration (e.g. forcing password resets every 90 days) without evidence of compromise.",
                    "Allowing passwords longer than 16 characters.",
                    "Checking candidate passwords against lists of breached credentials.",
                    "Permitting spaces and emoji characters in user passwords.",
                ],
                correct_option_index=0,
                explanation="NIST SP 800-63B advises against arbitrary periodic expiration because users predictably choose weaker, minor variations of existing passwords unless an actual breach has occurred.",
            ),
            QuizQuestion(
                id="q4",
                question="Where should the unique cryptographic salt for a user's password be stored?",
                options=[
                    "Together with the password hash in the database (e.g. as part of the standard modular crypt format string).",
                    "Stored exclusively in the user's browser local storage.",
                    "Hardcoded in the server source code repository.",
                    "Sent in plaintext to the user via SMS message.",
                ],
                correct_option_index=0,
                explanation="Salts are not secrets; their purpose is to ensure hash uniqueness. Storing the salt alongside the hash (as in standard bcrypt/Argon2 string formats) is secure and necessary for verification.",
            ),
            QuizQuestion(
                id="q5",
                question="What security attack occurs when an adversary uses millions of username/password pairs breached from one website to access accounts on other unrelated websites?",
                options=[
                    "Credential Stuffing",
                    "Man-in-the-Middle (MitM)",
                    "Cross-Site Request Forgery (CSRF)",
                    "SYN Flood Denial of Service",
                ],
                correct_option_index=0,
                explanation="Credential stuffing exploits widespread password reuse by automating login attempts against multiple web platforms using breached credential databases.",
            ),
        ],
    ),
]

ROOM_16_DEFINITION = RoomDefinition(
    room_id="red-16-password-security",
    room_number=16,
    track=TrackEnum.RED,
    title="Password Security & Key Stretching",
    short_description="Understand cryptographic password storage, crack unsalted legacy hashes, explore adaptive key-derivation algorithms (bcrypt, Argon2id), and apply NIST 800-63B standards.",
    difficulty="Intermediate",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_16_CONCEPT,
    tasks=ROOM_16_TASKS,
    learning_objectives=[
        "Differentiate plaintext storage, fast cryptographic hashes, and adaptive slow key stretching",
        "Understand the role of per-user unique cryptographic salts in defeating rainbow table lookups",
        "Crack unsalted legacy hash digests using wordlists and dictionary attacks",
        "Implement modern adaptive key derivation functions (Argon2id and bcrypt) and NIST 800-63B policies",
    ],
    assessment_criteria=[
        "Identify the purpose and operation of cryptographic salts",
        "Extract unsalted hashes from an exposed user database export",
        "Crack candidate hashes and authenticate against verification gateways",
        "Solve the key stretching algorithm challenge",
        "Verify salted bcrypt password storage remediation",
        "Pass the 5-question password security technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)


# ============================================================================
# ROOM 17: PRIVILEGE ESCALATION (FULLY IMPLEMENTED)
# ============================================================================

ROOM_17_CONCEPT = RoomConcept(
    overview=(
        "Privilege Escalation is the phase of a security assessment wherein an adversary leverages software vulnerabilities, "
        "permission misconfigurations, or architectural oversights to acquire privileges beyond those originally granted, "
        "culminating in root (superuser) control on Linux or SYSTEM/Domain Admin control on Windows."
    ),
    simple_analogy=(
        "Imagine an office building where contractors are issued blue visitor badges that only unlock the first-floor cafeteria. "
        "If a contractor discovers that the building's emergency fire alarm key (SUID binary) was accidentally left hanging unlocked "
        "beside a mechanical room, and turning the key automatically triggers the master security console to unlock every executive suite "
        "in the tower (vertical privilege escalation), the contractor transitions from an unprivileged visitor to complete facility control. "
        "In operating systems, privilege escalation occurs when an unprivileged account leverages misconfigured permissions or administrative "
        "tools to assume superuser status."
    ),
    technical_term="Privilege Escalation (OWASP Top 10 A01:2021 — Broken Access Control / CWE-250 / CWE-269)",
    technical_definition=(
        "Privilege escalation is categorized into vertical escalation (where a low-privilege account elevates to a higher privilege level, "
        "such as standard user to root/UID 0) and horizontal escalation (where a user assumes identity and data access belonging to a peer user). "
        "Common Linux vertical escalation vectors include binaries with the Set User ID (SUID) bit enabled (octal 4755) executing with owner privileges, "
        "overly permissive sudoers configurations allowing execution without password verification (NOPASSWD), vulnerable kernel drivers, "
        "and world-writable cron jobs or configuration files."
    ),
    cybersecurity_context=(
        "Initial access into an enterprise environment typically lands within a low-privilege context (such as an unprivileged service account, "
        "a phishing victim's workstation, or a restricted web application container). To dump credentials, disable security monitoring (EDR/SIEM), "
        "and establish long-term persistence, the adversary must escalate privileges to root or Administrator. Defensive engineering enforces "
        "the Principle of Least Privilege, regular SUID audits, and hardened sudoers rules."
    ),
    why_it_matters=(
        "Without privilege escalation, an attacker's blast radius is strictly confined to the compromised user's directory. "
        "A successful vertical escalation breaks all operating system isolation boundaries, exposing all tenants and data on the machine."
    ),
    demonstration=(
        "Vulnerable SUID Misconfiguration:\n"
        "  Inspected Binary: /usr/local/bin/backup_helper (Permissions: -rwsr-xr-x / 4755, Owner: root)\n"
        "  Flaw: Binary executes user-supplied commands or invokes /bin/sh without dropping elevated privileges.\n"
        "  Exploitation: Low-privilege operator executes binary; process retains effective UID 0 (root).\n\n"
        "Vulnerable Sudoers Configuration:\n"
        "  Configuration (/etc/sudoers): backup_svc ALL=(ALL) NOPASSWD: /usr/bin/find\n"
        "  Breakout Command: sudo find . -exec /bin/sh \\; -quit\n"
        "  Result: find launches an interactive root shell without requiring a password.\n\n"
        "Remediation:\n"
        "  1. Remove SUID bit: chmod u-s /usr/local/bin/backup_helper\n"
        "  2. Remove NOPASSWD wildcard rules and require explicit commands and authentication."
    ),
    remediation_guide=(
        "1. Adhere strictly to the Principle of Least Privilege across all service and human accounts.\n"
        "2. Audit all SUID/SGID binaries across filesystems using find / -perm -4000 and strip unnecessary SUID bits (chmod u-s).\n"
        "3. Avoid wildcards and NOPASSWD rules in /etc/sudoers. Never grant sudo execution rights on binaries with shell escapes (vi, less, find, nmap).\n"
        "4. Enforce strict permissions on system configuration files (chmod 644 /etc/passwd, chmod 600 /etc/shadow).\n"
        "5. Implement Linux capabilities (setcap) instead of blanket SUID root execution for binaries requiring limited privileges."
    ),
)

ROOM_17_TASKS = [
    TaskDefinition(
        task_id="task-01-privesc-taxonomies",
        order=1,
        title="Vertical vs Horizontal Privilege Escalation",
        instructions=(
            "Review the core taxonomies of privilege escalation. "
            "In cybersecurity, when an adversary with low-privilege access elevates their security context to that of a superuser, "
            "system administrator, or root (UID 0), what direction of privilege escalation has occurred?"
        ),
        task_type=TaskType.QUESTION,
        question="Which form of privilege escalation involves ascending from standard user permissions to superuser or root authority?",
        hint="The opposite of horizontal.",
        xp_reward=50,
        accepted_answers=["vertical", "Vertical", "vertical privilege escalation", "Vertical Privilege Escalation"],
        mistake_explanations={
            "horizontal": "Horizontal escalation involves accessing accounts at the same privilege tier (e.g., Alice accessing Bob's files).",
            "lateral": "Lateral movement describes pivoting between different hosts across an internal network.",
        },
    ),
    TaskDefinition(
        task_id="task-02-system-permission-audit",
        order=2,
        title="System Permission & SUID Binary Audit",
        instructions=(
            "The system security daemon on port 8098 exposes a system audit diagnostic endpoint at `/api/system/audit`. "
            "Query the audit report via `curl -s http://10.10.14.90:8098/api/system/audit`. "
            "Inspect the disclosed SUID binaries (permissions 4755) to identify the misconfigured executable "
            "and submit the system audit discovery flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag disclosed by querying the system audit endpoint.",
        hint="Curl http://10.10.14.90:8098/api/system/audit",
        xp_reward=60,
        accepted_answers=["NOENTRY{privesc_permission_audit_discovered_9012}"],
        mistake_explanations={
            "NOENTRY{privesc_sudo_nopasswd_misconfig_7821}": "That flag belongs to the sudo permissions task.",
            "NOENTRY{privesc_suid_boundary_breach_5194}": "That flag belongs to the elevated execution simulation task.",
        },
    ),
    TaskDefinition(
        task_id="task-03-sudo-nopasswd-misconfiguration",
        order=3,
        title="Sudo Permissions & NOPASSWD Misconfiguration",
        instructions=(
            "System administrators sometimes configure `/etc/sudoers` with `NOPASSWD` directives to facilitate automated backup jobs. "
            "The security daemon exposes a sudo rights verification endpoint at `/api/sudo/check?user=backup_svc`. "
            "Query the endpoint using `curl -s 'http://10.10.14.90:8098/api/sudo/check?user=backup_svc'` "
            "and submit the sudoers misconfiguration flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag returned by checking the sudo permissions for the backup service account.",
        hint="Curl http://10.10.14.90:8098/api/sudo/check?user=backup_svc",
        xp_reward=60,
        accepted_answers=["NOENTRY{privesc_sudo_nopasswd_misconfig_7821}"],
        mistake_explanations={
            "NOENTRY{privesc_permission_audit_discovered_9012}": "That flag belongs to the system audit task.",
        },
    ),
    TaskDefinition(
        task_id="task-04-suid-execution-simulation",
        order=4,
        title="SUID Privilege Boundary Breach Simulation",
        instructions=(
            "When an SUID root binary executes, its effective user ID (EUID) is 0, granting full administrative authority. "
            "The security daemon provides an execution simulation endpoint at `/api/escalate/simulate`. "
            "Trigger elevated command execution by issuing: "
            "`curl -s -X POST http://10.10.14.90:8098/api/escalate/simulate -H 'Content-Type: application/json' -d '{\"command\":\"whoami\"}'` "
            "and submit the root confidential key flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the flag received upon executing an elevated command through the SUID boundary.",
        hint="POST command=whoami to http://10.10.14.90:8098/api/escalate/simulate",
        xp_reward=60,
        accepted_answers=["NOENTRY{privesc_suid_boundary_breach_5194}"],
        mistake_explanations={
            "NOENTRY{privesc_least_privilege_master_3218}": "That flag belongs to the vector triage challenge.",
        },
    ),
    TaskDefinition(
        task_id="task-05-least-privilege-remediation",
        order=5,
        title="Principle of Least Privilege & System Remediation",
        instructions=(
            "Remediation of privilege escalation vectors involves stripping unnecessary SUID bits and enforcing strict sudo authentication. "
            "First, verify vector comprehension by querying `curl -s 'http://10.10.14.90:8098/challenge?vector=suid'` to earn the challenge token (`NOENTRY{privesc_least_privilege_master_3218}`). "
            "Then, trigger system hardening via `curl -s -X POST http://10.10.14.90:8098/api/remediate` to lock down permissions, drop SUID bits, "
            "and submit the hardened sudoers remediation flag."
        ),
        task_type=TaskType.FLAG,
        question="Submit the remediation flag received after stripping SUID bits and hardening the sudoers configuration.",
        hint="POST to http://10.10.14.90:8098/api/remediate. (Challenge flag NOENTRY{privesc_least_privilege_master_3218} is also accepted).",
        xp_reward=60,
        accepted_answers=[
            "NOENTRY{privesc_sudoers_hardened_secured_8892}",
            "NOENTRY{privesc_least_privilege_master_3218}",
        ],
        mistake_explanations={
            "NOENTRY{privesc_suid_boundary_breach_5194}": "That flag belongs to the elevated execution simulation task.",
        },
    ),
    TaskDefinition(
        task_id="task-06-room-quiz",
        order=6,
        title="Room 17 Knowledge Assessment",
        instructions=(
            "Test your knowledge of Linux permissions, SUID bits, sudoers security configurations, and least privilege hardening."
        ),
        task_type=TaskType.QUIZ,
        xp_reward=60,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What security effect does setting the SUID bit on an executable binary owned by root have when run by an unprivileged user?",
                options=[
                    "The process runs with the file owner's permissions (root / UID 0) rather than the executing user's permissions.",
                    "The process is terminated immediately by the operating system kernel.",
                    "The executing user is prompted to enter their personal password.",
                    "The binary is copied into the /tmp directory and deleted upon completion.",
                ],
                correct_option_index=0,
                explanation="SUID (Set User ID) causes the operating system to set the effective UID (EUID) of the running process to the file owner's UID (typically root).",
            ),
            QuizQuestion(
                id="q2",
                question="Which standard Linux command checks the current user's permitted sudo privileges?",
                options=[
                    "sudo -l",
                    "sudo --status",
                    "id -sudo",
                    "cat /etc/shadow",
                ],
                correct_option_index=0,
                explanation="The 'sudo -l' command lists the allowed (and forbidden) commands for the invoking user as specified in /etc/sudoers.",
            ),
            QuizQuestion(
                id="q3",
                question="Why is granting NOPASSWD sudo access to interactive binaries like /usr/bin/find, /usr/bin/vi, or /usr/bin/less dangerous?",
                options=[
                    "These binaries feature built-in shell escape mechanisms (such as -exec or :!sh) that spawn an unconstrained root shell.",
                    "These binaries automatically delete all log files on the system.",
                    "Interactive binaries corrupt the terminal screen and crash the desktop manager.",
                    "These binaries only work when connected to the internet.",
                ],
                correct_option_index=0,
                explanation="Binaries with shell escape mechanisms (documented on GTFOBins) allow users to spawn subshells, bypassing application restrictions and yielding full root shells.",
            ),
            QuizQuestion(
                id="q4",
                question="Which permission command removes the SUID bit from a binary named /usr/local/bin/custom_tool?",
                options=[
                    "chmod u-s /usr/local/bin/custom_tool",
                    "chmod 777 /usr/local/bin/custom_tool",
                    "chown root:root /usr/local/bin/custom_tool",
                    "chmod +x /usr/local/bin/custom_tool",
                ],
                correct_option_index=0,
                explanation="'chmod u-s' strips the SetUID permission bit from the user (owner) permission set.",
            ),
            QuizQuestion(
                id="q5",
                question="What does the Principle of Least Privilege dictate regarding service account configurations?",
                options=[
                    "Accounts, processes, and systems should be granted only the minimum permissions necessary to perform their legitimate business function.",
                    "Every user on a server must be granted root access to avoid permission denial tickets.",
                    "All services must run as UID 0 in development environments.",
                    "Password lengths should be kept as short as possible to prevent forgetting credentials.",
                ],
                correct_option_index=0,
                explanation="The Principle of Least Privilege requires that entities operate with only the minimum privileges required to accomplish their assigned duties.",
            ),
        ],
    ),
]

ROOM_17_DEFINITION = RoomDefinition(
    room_id="red-17-privilege-escalation",
    room_number=17,
    track=TrackEnum.RED,
    title="Privilege Escalation Fundamentals",
    short_description="Analyze vertical and horizontal privilege escalation, audit SUID/SGID binaries, exploit misconfigured sudoers rules, and enforce the principle of least privilege.",
    difficulty="Intermediate",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_17_CONCEPT,
    tasks=ROOM_17_TASKS,
    learning_objectives=[
        "Differentiate horizontal and vertical privilege escalation vectors",
        "Audit Linux user identities, file permission bits (rwx / octal 4755), and SUID executables",
        "Identify and exploit misconfigured sudoers rules with NOPASSWD directives",
        "Enforce the Principle of Least Privilege and harden Linux system permissions",
    ],
    assessment_criteria=[
        "Identify privilege escalation classifications",
        "Discover vulnerable SUID binaries in system audit reports",
        "Extract sudo rights misconfigurations for service accounts",
        "Simulate elevated execution through the SUID boundary",
        "Verify system remediation dropping SUID bits and hardening sudoers",
        "Pass the 5-question privilege escalation technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)
