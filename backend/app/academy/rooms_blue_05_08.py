"""
Complete curriculum definitions, tasks, concept explanations, and quizzes
for Blue Team Rooms 05–08:
- Room 05: Wireshark Fundamentals (blue-05-wireshark-fundamentals)
- Room 06: Log Analysis Fundamentals (blue-06-log-analysis-fundamentals)
- Room 07: SIEM Fundamentals (blue-07-siem-fundamentals)
- Room 08: Windows Event Investigation (blue-08-windows-event-investigation)
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
# BLUE ROOM 05: WIRESHARK FUNDAMENTALS (FULLY IMPLEMENTED)
# ============================================================================

ROOM_BLUE_05_CONCEPT = RoomConcept(
    overview=(
        "Wireshark Fundamentals introduces deep packet inspection, network protocol dissection, and traffic filtering using "
        "the world's most widely adopted network protocol analyzer. Security analysts dissect Ethernet frames, IP packets, and "
        "transport layer streams to detect unauthorized command-and-control beacons, cleartext data leaks, and protocol anomalies."
    ),
    simple_analogy=(
        "Imagine an international air-freight logistics hub. Every shipping parcel has an exterior barcode label (Layer 2 Ethernet "
        "and MAC addresses), a postal routing slip (Layer 3 IP source and destination addresses), a delivery sequence checklist "
        "(Layer 4 TCP sequence and acknowledgment numbers), and the physical cargo container (Layer 7 Application Payload). "
        "A customs inspector with an optical scanning rig (Wireshark) can inspect every layer of the package. If a parcel claims to "
        "be ordinary office supplies but contains undeclared electronic transmitters (such as covert C2 beacon traffic concealed inside "
        "HTTP requests), display filters allow the inspector to instantly isolate every parcel matching that suspicious signature."
    ),
    technical_term="Deep Packet Inspection (DPI), Display Filter Logic & Protocol Decapsulation (IETF RFC 791 / RFC 793 / RFC 1035)",
    technical_definition=(
        "Wireshark utilizes the libpcap/Npcap packet capture library to intercept raw network interface traffic into `.pcap` or "
        "`.pcapng` format. Packet dissection resolves nested protocol layers: Data Link (IEEE 802.3), Network (IPv4/IPv6, TTL, flags), "
        "Transport (TCP port multiplexing, 3-way handshake SYN/ACK flags, sliding window flow control; UDP datagrams), and Application "
        "(HTTP, DNS, TLS ClientHello). Wireshark's display filter engine allows analysts to execute boolean queries (`tcp.flags.syn == 1 && tcp.flags.ack == 0`, "
        "`http.request.method == \"POST\"`, `dns.qry.name contains \"beacon\"`) without altering underlying packet buffers."
    ),
    cybersecurity_context=(
        "Endpoint logs can be manipulated or deleted by an adversary who obtains root or SYSTEM privileges, but network packets "
        "captured on an out-of-band network tap or span port provide tamper-resistant ground truth. Analysts use Wireshark to "
        "reconstruct TCP streams, detect unencrypted authentication credentials, and identify Command-and-Control (C2) domains "
        "communicating on anomalous ports."
    ),
    why_it_matters=(
        "Over 90% of modern cyber attacks generate network telemetry during initial access, lateral movement, or data staging. "
        "Mastering packet filtering and dissection enables rapid root-cause analysis during live incident response."
    ),
    demonstration=(
        "1. Packet Capture Inspection via tshark & tcpdump:\n"
        "   $ tshark -r /home/operator/pcaps/suspicious_http_dns.pcap -c 10\n"
        "   Dissect genuine PCAP traffic containing TCP handshakes, HTTP POST telemetry, and DNS queries.\n\n"
        "2. Display Filter Syntax & Protocol Summaries:\n"
        "   GET /api/wireshark/summary -> Review protocol distribution and filter recommendations on port 8205.\n\n"
        "3. HTTP Stream Reconstruction:\n"
        "   GET /api/wireshark/http -> Reconstruct cleartext HTTP telemetry request and extract target Host headers.\n\n"
        "4. DNS Query Dissection:\n"
        "   GET /api/wireshark/dns -> Identify anomalous C2 domain queries (`c2-beacon.corp.noentry.internal`).\n\n"
        "5. Filter Verification Challenge:\n"
        "   POST /challenge -> Submit validated display filter and domain findings to receive confirmation token."
    ),
    remediation_guide=(
        "1. Deprecate all cleartext application protocols; enforce TLS 1.3 encryption across all internal and external services.\n"
        "2. Implement DNS sinkholing and monitor recursive DNS resolvers for repetitive high-frequency beaconing queries.\n"
        "3. Deploy Network Security Monitoring (NSM) sensors (Zeek / Suricata) to continuously evaluate packet streams against known signatures.\n"
        "4. Segment enterprise networks with internal firewalls to block unauthorized lateral traffic between subnets.\n"
        "5. Conduct routine PCAP audits to ensure sensitive credentials or API keys are never transmitted without cryptographic encapsulation."
    ),
)

ROOM_BLUE_05_TASKS = [
    TaskDefinition(
        task_id="task-01-wireshark-syn-filter",
        order=1,
        title="Wireshark Display Filter Syntax & TCP Flags",
        instructions=(
            "In Wireshark, display filters allow analysts to isolate specific packet types from massive captures without "
            "modifying the raw capture file. The TCP header flags field indicates connection states: SYN initiates sessions, "
            "ACK acknowledges received octets, FIN cleanly terminates, and RST aborts connections.\n\n"
            "What Wireshark display filter expression isolates TCP connection initiation packets (SYN flag set to 1 and ACK flag set to 0)?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the Wireshark display filter expression for TCP SYN initiation packets?",
        hint="Use tcp.flags.syn == 1 && tcp.flags.ack == 0.",
        xp_reward=50,
        accepted_answers=[
            "tcp.flags.syn == 1 && tcp.flags.ack == 0",
            "tcp.flags.syn==1 && tcp.flags.ack==0",
            "tcp.flags.syn == 1 and tcp.flags.ack == 0",
            "tcp.flags.syn==1 and tcp.flags.ack==0",
        ],
        mistake_explanations={
            "just tcp.flags.syn": "tcp.flags.syn == 1 matches both initial SYN packets and SYN-ACK responses. You must also check tcp.flags.ack == 0.",
            "tcp.flags.ack == 1": "tcp.flags.ack == 1 matches acknowledgment packets, not initial connection requests.",
        },
    ),
    TaskDefinition(
        task_id="task-02-http-stream-host-header",
        order=2,
        title="HTTP Stream Reconstruction & Host Header Analysis",
        instructions=(
            "Inspect the captured HTTP traffic in `/home/operator/pcaps/suspicious_http_dns.pcap` using `tshark` or query the "
            "HTTP stream endpoint on port 8205:\n\n"
            "  `tshark -r /home/operator/pcaps/suspicious_http_dns.pcap -Y http`\n"
            "  `curl -s http://10.10.14.90:8205/api/wireshark/http`\n\n"
            "What is the destination Host header domain requested in the HTTP POST telemetry beacon?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the Host header domain requested in the HTTP POST beacon?",
        hint="Inspect the request host field in the HTTP stream payload.",
        xp_reward=60,
        accepted_answers=["telemetry.corp.noentry.internal"],
        mistake_explanations={
            "target.noentry.internal": "target.noentry.internal is the local target address, not the telemetry host header domain.",
            "c2-beacon": "c2-beacon is the DNS query domain, not the HTTP Host header.",
        },
    ),
    TaskDefinition(
        task_id="task-03-dns-c2-query-analysis",
        order=3,
        title="DNS Query Dissection & Threat Intelligence Correlation",
        instructions=(
            "Adversary malware frequently resolves external Command-and-Control domains via standard DNS before establishing "
            "HTTP/TCP communication.\n\n"
            "Dissect DNS queries in `suspicious_http_dns.pcap` or query the DNS telemetry endpoint:\n"
            "  `tshark -r /home/operator/pcaps/suspicious_http_dns.pcap -Y dns`\n"
            "  `curl -s http://10.10.14.90:8205/api/wireshark/dns`\n\n"
            "What anomalous C2 beaconing domain was resolved by the client?"
        ),
        task_type=TaskType.QUESTION,
        question="What anomalous C2 domain name was resolved in the captured DNS queries?",
        hint="Look for the domain beginning with c2-beacon...",
        xp_reward=70,
        accepted_answers=["c2-beacon.corp.noentry.internal"],
        mistake_explanations={
            "target.noentry.internal": "target.noentry.internal is the legitimate lab server, not the anomalous C2 domain.",
        },
    ),
    TaskDefinition(
        task_id="task-04-tcp-handshake-client-port",
        order=4,
        title="TCP 3-Way Handshake & Port Analysis",
        instructions=(
            "The TCP 3-way handshake synchronizes sequence numbers between a client's ephemeral source port and a server's well-known service port.\n\n"
            "Evaluate the TCP handshake in `suspicious_http_dns.pcap` or query the handshake endpoint on port 8205:\n"
            "  `curl -s http://10.10.14.90:8205/api/wireshark/handshake`\n\n"
            "What client ephemeral source port (src port) initiated the TCP connection to port 80?"
        ),
        task_type=TaskType.QUESTION,
        question="What client source port initiated the TCP connection?",
        hint="Inspect the client source port in packet 1 (SYN).",
        xp_reward=70,
        accepted_answers=["51420"],
        mistake_explanations={
            "80": "Port 80 is the destination web server port, not the client source port.",
            "53": "Port 53 is the DNS server port.",
        },
    ),
    TaskDefinition(
        task_id="task-05-wireshark-challenge",
        order=5,
        title="Independent Challenge: Wireshark Display Filter Validation",
        instructions=(
            "Confirm your packet analysis findings by submitting the identified C2 domain and display filter to the challenge endpoint via POST:\n\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"suspicious_domain\":\"c2-beacon.corp.noentry.internal\",\"filter\":\"dns.qry.name contains \\\"c2-beacon\\\"\"}' http://10.10.14.90:8205/challenge`\n\n"
            "Submit the verification token returned upon confirmation."
        ),
        task_type=TaskType.FLAG,
        xp_reward=50,
        accepted_answers=["WIRESHARK_DISPLAY_FILTER_VALIDATED"],
        mistake_explanations={
            "just verified": "Submit the full verification_token value rather than generic status.",
        },
    ),
    TaskDefinition(
        task_id="task-06-wireshark-quiz",
        order=6,
        title="Wireshark Fundamentals Technical Assessment",
        instructions="Complete the 5-question technical quiz to validate comprehensive mastery of packet capture dissection, display filters, protocol layers, and TCP flags.",
        task_type=TaskType.QUIZ,
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is the operational difference between a capture filter (BPF) and a display filter in Wireshark?",
                options=[
                    "Capture filters restrict which packets are written to disk during live capture; display filters dynamically filter already-captured packets in the GUI without altering the file.",
                    "Capture filters only work on Windows; display filters only work on macOS.",
                    "Capture filters decrypt HTTPS traffic; display filters delete corrupted packets.",
                    "There is no difference; both use identical syntax and operate identically.",
                ],
                correct_option_index=0,
                explanation="Capture filters use Berkeley Packet Filter (BPF) syntax at capture time to discard unneeded packets, while display filters evaluate packets in memory during post-capture analysis.",
            ),
            QuizQuestion(
                id="q2",
                question="Which Wireshark display filter will display only HTTP POST requests?",
                options=[
                    'http.request.method == "POST"',
                    "post.http == true",
                    "tcp.payload == post",
                    "ip.proto == http-post",
                ],
                correct_option_index=0,
                explanation='The filter `http.request.method == "POST"` evaluates the HTTP request method string extracted by Wireshark\'s HTTP protocol dissector.',
            ),
            QuizQuestion(
                id="q3",
                question="Why does inspecting an encrypted TLS 1.3 session in Wireshark prevent an analyst from reading cleartext HTTP request bodies?",
                options=[
                    "TLS encrypts Application Layer data using ephemeral symmetric keys, rendering the payload indistinguishable from random bytes to passive observers.",
                    "Wireshark automatically crashes when opening any file containing TLS traffic.",
                    "TLS converts IP packets into analog telephone signals that cannot be parsed by network cards.",
                    "Encrypted packets contain no IP headers or TCP ports.",
                ],
                correct_option_index=0,
                explanation="TLS 1.3 provides end-to-end cryptographic confidentiality. Without the session private key or SSLKEYLOGFILE, application payloads remain encrypted.",
            ),
            QuizQuestion(
                id="q4",
                question="In a standard TCP 3-way handshake, which flags are set in the second packet (sent from server to client)?",
                options=[
                    "SYN and ACK",
                    "SYN only",
                    "ACK only",
                    "FIN and RST",
                ],
                correct_option_index=0,
                explanation="The server responds to the initial SYN with a packet having both the SYN (synchronize sequence) and ACK (acknowledge client sequence) flags set.",
            ),
            QuizQuestion(
                id="q5",
                question="Which command-line utility from the Wireshark suite is designed for scriptable, terminal-based packet analysis without a graphical interface?",
                options=["tshark", "ping", "traceroute", "netcat"],
                correct_option_index=0,
                explanation="tshark is the terminal-oriented version of Wireshark, sharing its protocol dissectors and display filter engine for automated CLI analysis.",
            ),
        ],
    ),
]

ROOM_BLUE_05_DEFINITION = RoomDefinition(
    room_id="blue-05-wireshark-fundamentals",
    room_number=5,
    track=TrackEnum.BLUE,
    title="Wireshark Fundamentals",
    short_description="Master packet capture dissection with Wireshark and tshark, analyze TCP 3-way handshakes, inspect cleartext HTTP telemetry, and detect C2 beaconing.",
    difficulty="Intermediate",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_BLUE_05_CONCEPT,
    tasks=ROOM_BLUE_05_TASKS,
    learning_objectives=[
        "Understand packet decapsulation across Data Link, Network, Transport, and Application layers",
        "Construct complex Wireshark display filters using boolean operators",
        "Dissect TCP 3-way handshake flags and ephemeral port allocations",
        "Reconstruct cleartext HTTP streams and extract application headers",
        "Identify anomalous DNS queries correlating with Command-and-Control infrastructure",
    ],
    assessment_criteria=[
        "Identify the correct Wireshark display filter for TCP SYN initiation packets",
        "Extract the Host header domain from captured HTTP streams",
        "Identify anomalous C2 beaconing domains in DNS telemetry",
        "Verify ephemeral client port allocations in TCP handshakes",
        "Submit validated display filter findings in the challenge task",
        "Pass the 5-question Wireshark Fundamentals technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)


# ============================================================================
# BLUE ROOM 06: LOG ANALYSIS FUNDAMENTALS (FULLY IMPLEMENTED)
# ============================================================================

ROOM_BLUE_06_CONCEPT = RoomConcept(
    overview=(
        "Log Analysis Fundamentals trains defensive engineers to inspect, parse, normalize, and correlate system, application, "
        "and web server logs. Operating with command-line tools like `grep`, `awk`, `cut`, `sort`, and `uniq`, analysts transform "
        "voluminous raw text streams into high-fidelity forensic timelines to identify attacker reconnaissance and exploitation."
    ),
    simple_analogy=(
        "Imagine an automated access monitoring system for a high-rise office complex. Front-door badge readers log every entry, "
        "elevator sensors record floor destinations, and server room biometrics track rack access. If a rogue visitor wanders the "
        "building trying door handles (scanning for vulnerabilities), individual door logs might show 404 access denied errors. "
        "By aggregating and sorting the records chronologically across all sensors, a security auditor sees the exact progression: "
        "the visitor arrived at the loading dock, tested three locked storage closets, forced open a maintenance door, and entered "
        "the main server room. Correlating timestamps and visitor IDs across separate logs reveals the full scope of the breach."
    ),
    technical_term="Log Parsing, Field Extraction & Forensic Timestamp Correlation (IETF RFC 5424 / W3C Combined Log Format)",
    technical_definition=(
        "Security log analysis evaluates machine-generated audit records structured according to standard conventions: Syslog "
        "(RFC 5424 with PRI, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID), W3C Combined Log Format (`$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"`), "
        "and structured JSON application streams. Standard severity levels range from DEBUG and INFO to WARNING, ERROR, and CRITICAL. "
        "Analysts construct shell pipelines to extract delimiters, compute frequency counts, and trace adversary dwell time."
    ),
    cybersecurity_context=(
        "Web servers and API gateways are subjected to continuous automated scanning by adversary reconnaissance tools searching for "
        "environment files (`/.env`), admin consoles (`/admin`), and injection flaws. In-depth log analysis allows SOC teams to identify "
        "source IPs conducting vulnerability probing, verify whether attacks resulted in HTTP 200 success or HTTP 500 crashes, and extract "
        "adversary payloads directly from query parameters."
    ),
    why_it_matters=(
        "Incident responders cannot determine whether an intrusion occurred without analyzing log trails. Rigorous log analysis "
        "confirms root-cause vulnerability exploitation and validates the effectiveness of defensive remediations."
    ),
    demonstration=(
        "1. Web Access Log Triage via awk & uniq:\n"
        "   $ awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr\n"
        "   Identify external scanner IP addresses generating abnormal volumes of 404 error codes.\n\n"
        "2. Nginx Access Summary & Scanned URIs:\n"
        "   GET /api/logs/nginx/summary -> Inspect request distributions and top scanned endpoints on port 8206.\n\n"
        "3. SQL Injection Status Code Extraction:\n"
        "   Identify HTTP 500 internal server errors caused by unhandled SQL syntax exceptions.\n\n"
        "4. Structured Application Log Triage:\n"
        "   GET /api/logs/app/critical -> Inspect JSON-formatted application records for CRITICAL database connection errors.\n\n"
        "5. Multi-Source Log Correlation Challenge:\n"
        "   POST /challenge -> Correlate adversary IP and error severity to verify the attack timeline."
    ),
    remediation_guide=(
        "1. Centralize all application and web access logs into an immutable, write-once-read-many (WORM) storage architecture.\n"
        "2. Enforce strict UTC timestamp synchronization across all enterprise servers using Network Time Protocol (NTP).\n"
        "3. Configure automated threshold alerts on web servers to flag clients generating over 20 HTTP 404/403 errors within 60 seconds.\n"
        "4. Ensure application exceptions are caught and sanitized, preventing database query errors from leaking internal syntax.\n"
        "5. Retain security-critical authentication and access logs for a minimum of 12 months to support retrospective investigations."
    ),
)

ROOM_BLUE_06_TASKS = [
    TaskDefinition(
        task_id="task-01-log-pipeline-frequency",
        order=1,
        title="Command-Line Log Pipelines: Frequency Counting",
        instructions=(
            "When analyzing raw log files on Linux servers, analysts use standard shell pipelines to extract fields, sort records, "
            "and compute frequency counts to identify outliers.\n\n"
            "Which standard Linux command sequence counts the occurrence of unique lines and sorts the results in descending numerical order?"
        ),
        task_type=TaskType.QUESTION,
        question="What command pipeline counts unique lines and sorts them in descending numerical order?",
        hint="Combine sort, uniq with the count flag -c, and sort with numerical reverse flags -nr.",
        xp_reward=50,
        accepted_answers=[
            "sort | uniq -c | sort -nr",
            "sort | uniq -c | sort -rn",
            "uniq -c | sort -nr",
            "uniq -c | sort -rn",
        ],
        mistake_explanations={
            "just sort": "Running sort alone only arranges lines alphabetically without counting frequencies.",
            "just uniq": "uniq requires sorted input to group duplicate lines and requires -c to display counts.",
        },
    ),
    TaskDefinition(
        task_id="task-02-nginx-recon-ip",
        order=2,
        title="Web Server Reconnaissance Triage: Malicious IP Identification",
        instructions=(
            "Inspect the Nginx access log `/var/log/nginx/access.log` using shell tools or query the summary endpoint on port 8206:\n\n"
            "  `awk '{print $1, $7, $9}' /var/log/nginx/access.log`\n"
            "  `curl -s http://10.10.14.90:8206/api/logs/nginx/summary`\n\n"
            "What external adversary IP address is probing sensitive paths (such as `/.env` and `/admin`) and generating 404 errors?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the external adversary IP address probing sensitive web paths?",
        hint="Look for the IP generating 404 Not Found responses.",
        xp_reward=60,
        accepted_answers=["203.0.113.88"],
        mistake_explanations={
            "10.10.14.50": "10.10.14.50 is internal staff workstation traffic generating legitimate 200 OK responses.",
            "10.10.14.22": "10.10.14.22 is the automated backup runner.",
        },
    ),
    TaskDefinition(
        task_id="task-03-sqli-status-code",
        order=3,
        title="Web Attack Analysis: Status Code & SQL Injection Extraction",
        instructions=(
            "Adversaries often test query parameters for SQL injection vulnerabilities by supplying syntax-breaking characters "
            "like quotes and boolean expressions.\n\n"
            "Inspect `/var/log/nginx/access.log` or query the summary endpoint to analyze the probe against `/api/users`:\n"
            "  `grep '/api/users' /var/log/nginx/access.log`\n\n"
            "What HTTP response status code (3-digit integer) was returned by the web server when the unhandled SQL syntax error was triggered?"
        ),
        task_type=TaskType.QUESTION,
        question="What HTTP status code was returned when the SQL injection query caused an unhandled error?",
        hint="Server error status codes are in the 5xx range.",
        xp_reward=70,
        accepted_answers=["500"],
        mistake_explanations={
            "200": "HTTP 200 represents success. The database error generated an Internal Server Error.",
            "404": "HTTP 404 indicates Not Found. The endpoint existed but failed during execution.",
        },
    ),
    TaskDefinition(
        task_id="task-04-structured-log-level",
        order=4,
        title="Structured JSON Application Log Triage: Log Level Identification",
        instructions=(
            "Modern microservices emit structured JSON log entries capturing granular telemetry, service identifiers, and severity levels.\n\n"
            "Inspect `/var/log/app/app.log` or query the critical logs endpoint on port 8206:\n"
            "  `curl -s http://10.10.14.90:8206/api/logs/app/critical`\n\n"
            "What standard log level (in ALL CAPS) was assigned to the unhandled database syntax error event?"
        ),
        task_type=TaskType.QUESTION,
        question="What log level was assigned to the unhandled database syntax error in the structured application log?",
        hint="Standard levels include DEBUG, INFO, WARNING, ERROR, and CRITICAL.",
        xp_reward=70,
        accepted_answers=["CRITICAL"],
        mistake_explanations={
            "ERROR": "While it was an error, the log specifically recorded it at the highest severity level.",
            "WARNING": "WARNING is used for non-critical conditions like probe attempts on missing routes.",
        },
    ),
    TaskDefinition(
        task_id="task-05-log-analysis-challenge",
        order=5,
        title="Independent Challenge: Multi-Source Log Correlation",
        instructions=(
            "Confirm your multi-source log investigation by submitting the attacker IP and correlated critical log level via POST:\n\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"attacker_ip\":\"203.0.113.88\",\"log_level\":\"CRITICAL\"}' http://10.10.14.90:8206/challenge`\n\n"
            "Submit the verification token returned upon successful correlation."
        ),
        task_type=TaskType.FLAG,
        xp_reward=50,
        accepted_answers=["LOG_TRIAGE_INCIDENT_CORRELATED_SECURE"],
        mistake_explanations={
            "just correlated": "Submit the full verification_token value rather than generic status.",
        },
    ),
    TaskDefinition(
        task_id="task-06-log-analysis-quiz",
        order=6,
        title="Log Analysis Fundamentals Technical Assessment",
        instructions="Complete the 5-question technical quiz to validate comprehensive mastery of log levels, web server access logging, timestamp normalization, and command-line filtering.",
        task_type=TaskType.QUIZ,
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="In standard Syslog (RFC 5424) and application logging, which log level represents the most severe system failure requiring immediate intervention?",
                options=["CRITICAL / EMERGENCY", "WARNING", "INFO", "DEBUG"],
                correct_option_index=0,
                explanation="EMERGENCY (Level 0) and CRITICAL (Level 2) designate catastrophic failures where the system or critical services are unusable, contrasted with INFO or DEBUG.",
            ),
            QuizQuestion(
                id="q2",
                question="Why is NTP (Network Time Protocol) clock synchronization essential for cross-server log analysis during an incident?",
                options=[
                    "Without synchronized timestamps, analysts cannot accurately reconstruct the chronological order of adversary actions across disparate servers.",
                    "NTP encryption prevents log files from being read by unauthorized users.",
                    "NTP automatically translates Chinese and Russian hacker scripts into English.",
                    "NTP compresses log files to save hard drive space.",
                ],
                correct_option_index=0,
                explanation="Accurate chronological reconstruction requires uniform clock synchronization; clock skew of even a few seconds can confuse causal relationships in attack kill chains.",
            ),
            QuizQuestion(
                id="q3",
                question="In W3C Combined Log Format, what does an HTTP status code in the 4xx range (such as 401 or 403) indicate?",
                options=[
                    "A client-side error, such as unauthorized access or forbidden resource request.",
                    "A server-side fatal database crash.",
                    "A successful file download.",
                    "A permanent network cable disconnection.",
                ],
                correct_option_index=0,
                explanation="HTTP status codes in the 400–499 range designate client errors (e.g. 401 Unauthorized, 403 Forbidden, 404 Not Found), while 5xx designates server errors.",
            ),
            QuizQuestion(
                id="q4",
                question="Why are structured logs (such as JSON or Key-Value format) preferred over unstructured raw text in modern Security Operations Centers?",
                options=[
                    "Structured logs provide standardized field names that can be parsed and indexed natively by SIEM ingestion engines without brittle regular expressions.",
                    "JSON logs are physically impossible for hackers to view.",
                    "Structured logs eliminate the need for server hard drives.",
                    "JSON logs run 100 times faster in web browsers.",
                ],
                correct_option_index=0,
                explanation="Structured logs allow automated ingest pipelines to query fields (like `src_ip`, `user`, `event_type`) directly without relying on complex, fragile regex parsing.",
            ),
            QuizQuestion(
                id="q5",
                question="Which Linux command extracts specific columnar delimited fields (such as extracting only the 1st and 7th columns of a space-separated log)?",
                options=["awk (or cut)", "cat", "tail", "chmod"],
                correct_option_index=0,
                explanation="`awk '{print $1, $7}'` and `cut -d' ' -f1,7` are standard Linux tools for columnar field extraction from text logs.",
            ),
        ],
    ),
]

ROOM_BLUE_06_DEFINITION = RoomDefinition(
    room_id="blue-06-log-analysis-fundamentals",
    room_number=6,
    track=TrackEnum.BLUE,
    title="Log Analysis Fundamentals",
    short_description="Analyze web server access logs, investigate structured application telemetry, filter logs with shell pipelines, and correlate multi-source incident timelines.",
    difficulty="Intermediate",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_BLUE_06_CONCEPT,
    tasks=ROOM_BLUE_06_TASKS,
    learning_objectives=[
        "Understand syslog, W3C combined, and structured JSON log architectures",
        "Construct command-line text processing pipelines with grep, awk, sort, and uniq",
        "Identify web application reconnaissance probes and analyze HTTP error distributions",
        "Distinguish between client-side errors (4xx) and server-side syntax crashes (5xx)",
        "Correlate events across heterogeneous log files to reconstruct adversary intrusion timelines",
    ],
    assessment_criteria=[
        "Identify the correct Linux command pipeline for sorting frequency counts",
        "Extract the adversary reconnaissance IP from Nginx web server access logs",
        "Identify the HTTP status code triggered by SQL injection syntax errors",
        "Extract the severity log level from structured application JSON logs",
        "Execute multi-source incident correlation in the challenge task",
        "Pass the 5-question Log Analysis Fundamentals technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)


# ============================================================================
# BLUE ROOM 07: SIEM FUNDAMENTALS (FULLY IMPLEMENTED)
# ============================================================================

ROOM_BLUE_07_CONCEPT = RoomConcept(
    overview=(
        "SIEM Fundamentals focuses on the architecture, data ingestion pipelines, event normalization, and correlation logic "
        "that power modern Security Information and Event Management (SIEM) platforms. Defensive engineers configure ingestion "
        "rules, query normalized indexes, evaluate automated alert triggers, and prioritize true positive security incidents."
    ),
    simple_analogy=(
        "Imagine an air traffic control radar integration and emergency dispatch center. Incoming flights generate data from "
        "dozens of independent sources: onboard transponders, ground radar dishes, meteorological weather stations, and voice radio "
        "chatter. If raw data were displayed without translation, controllers would be overwhelmed by incompatible units (feet vs "
        "meters, knots vs mph). A central computer ingests and normalizes all data into a uniform display coordinate grid. "
        "Automated collision-warning algorithms continuously correlate vectors across all aircraft; if two planes converge onto an "
        "identical altitude corridor, an immediate high-priority proximity alert flashes on the controller's console, prompting "
        "swift evasive vectoring before a catastrophic incident occurs."
    ),
    technical_term="SIEM Architecture, Common Information Model (CIM) Normalization & Correlation Engines (NIST SP 800-92)",
    technical_definition=(
        "A SIEM system provides centralized log aggregation, event parsing, normalization, real-time correlation, alerting, and "
        "long-term compliance storage. Heterogeneous logs (Windows EVTX, Linux syslog, firewall netflow, cloud API audit trails) "
        "are parsed into a standardized taxonomy (such as the Elastic Common Schema [ECS] or Splunk Common Information Model [CIM]). "
        "Correlation rules evaluate boolean and temporal thresholds (e.g. `count(event.type=AUTH_FAIL) > 50 WITHIN 5m FOLLOWED BY bytes_out > 10MB`). "
        "Analysts query normalized indexes to investigate alerts, validate True Positives versus False Positives, and manage incident SLAs."
    ),
    cybersecurity_context=(
        "Modern enterprises generate millions of daily events. Without a SIEM, SOC analysts suffer severe alert fatigue and miss "
        "subtle Indicators of Compromise (IOCs). By correlating events across disparate boundaries—such as linking a firewall drop "
        "at 10:00 to three failed Active Directory logons at 10:05 and an outbound data transfer spike at 10:07—the SIEM enables analysts "
        "to detect multi-stage intrusions before full data exfiltration occurs."
    ),
    why_it_matters=(
        "The SIEM is the operational nervous system of the SOC. Effective correlation rules reduce adversary dwell time from "
        "months to minutes, transforming noisy raw data into actionable threat intelligence."
    ),
    demonstration=(
        "1. Architectural Authenticity & Lab Realism:\n"
        "   Commercial enterprise SIEMs (Splunk, Microsoft Sentinel) require multi-gigabyte cloud infrastructures. This room provides "
        "   a functional lightweight SIEM lab service simulating standard normalized ingestion, search index querying, and rule-based "
        "   correlation on port 8207.\n\n"
        "2. Normalized Index Search:\n"
        "   GET /api/siem/search?severity=HIGH -> Query normalized event index across perimeter firewall and Windows audit sources.\n\n"
        "3. Multi-Source Alert Correlation:\n"
        "   GET /api/siem/alerts -> Inspect correlated alerts detecting brute force followed by large egress transfer.\n\n"
        "4. Custom Detection Rule Deployment:\n"
        "   POST /api/siem/rules -> Register a custom detection rule to monitor anomalous outbound traffic.\n\n"
        "5. Incident Prioritization & Escalation:\n"
        "   POST /challenge -> Submit incident prioritization payload to escalate critical multi-stage intrusion to Tier 2."
    ),
    remediation_guide=(
        "1. Map all SIEM correlation rules directly to the MITRE ATT&CK framework to ensure comprehensive defensive coverage.\n"
        "2. Implement automated data parsing and field normalization using standardized schemas (ECS or CIM).\n"
        "3. Routinely tune alert correlation thresholds to suppress benign False Positives and preserve analyst operational focus.\n"
        "4. Establish strict incident classification playbooks (P1 Critical through P4 Low) with defined response SLAs.\n"
        "5. Conduct weekly log ingestion validation tests to confirm that all enterprise telemetry forwarders are actively transmitting."
    ),
)

ROOM_BLUE_07_TASKS = [
    TaskDefinition(
        task_id="task-01-siem-false-positive-concept",
        order=1,
        title="SIEM Fundamentals: Alert Classification & False Positives",
        instructions=(
            "In SIEM operations, correlation rules evaluate telemetry against detection logic. When a rule triggers on benign, "
            "authorized activity (such as an administrative backup script that resembles an exfiltration burst), analysts must "
            "classify the alert accurately to tune detection rules.\n\n"
            "What term describes a benign, harmless activity that was incorrectly flagged as malicious by a security detection rule?"
        ),
        task_type=TaskType.QUESTION,
        question="What term describes benign activity incorrectly flagged as an alert by a detection rule?",
        hint="It is a 2-word phrase contrasting with False Negative.",
        xp_reward=50,
        accepted_answers=["False Positive", "false positive", "False positive", "False-Positive"],
        mistake_explanations={
            "false negative": "A False Negative occurs when a genuine attack occurs but the detection system fails to alert on it.",
            "true positive": "A True Positive occurs when a genuine malicious attack is correctly flagged by an alert.",
        },
    ),
    TaskDefinition(
        task_id="task-02-siem-search-index-query",
        order=2,
        title="Normalized Event Index Search: High-Severity Triage",
        instructions=(
            "Query the normalized SIEM search index on port 8207 to investigate high-severity security events across enterprise hosts:\n\n"
            "  `curl -s 'http://10.10.14.90:8207/api/siem/search?severity=HIGH'`\n"
            "  `python3 /home/operator/tools/siem_query.py search HIGH`\n\n"
            "What is the source IP address (src_ip) responsible for the high-severity authentication failures?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the source IP address responsible for the high-severity authentication failures?",
        hint="Inspect the src_ip field in the returned SIEM search results.",
        xp_reward=60,
        accepted_answers=["198.51.100.77"],
        mistake_explanations={
            "10.10.14.90": "10.10.14.90 is the internal target domain controller destination IP.",
            "SIEM-002": "SIEM-002 is the event record identifier, not the source IP.",
        },
    ),
    TaskDefinition(
        task_id="task-03-siem-correlated-alert-rule",
        order=3,
        title="SIEM Multi-Source Correlation: Alert Rule Identification",
        instructions=(
            "SIEM correlation engines link multiple events across distinct telemetry feeds over time to uncover multi-stage attacks.\n\n"
            "Interrogate active correlated alerts on port 8207:\n"
            "  `curl -s http://10.10.14.90:8207/api/siem/alerts`\n"
            "  `python3 /home/operator/tools/siem_query.py alerts`\n\n"
            "What is the exact name of the detection rule that triggered on consecutive failed authentications followed by high-volume egress?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the name of the correlated detection rule that triggered?",
        hint="Look for the rule_name attribute beginning with RULE_...",
        xp_reward=70,
        accepted_answers=["RULE_BRUTE_FORCE_EXFIL"],
        mistake_explanations={
            "ALRT-701": "ALRT-701 is the alert identifier. Provide the rule name.",
            "T1048": "T1048 is the MITRE ATT&CK technique code.",
        },
    ),
    TaskDefinition(
        task_id="task-04-siem-custom-rule-deployment",
        order=4,
        title="Custom Detection Rule Engineering: Ingestion Configuration",
        instructions=(
            "Detection engineers author custom rules in the SIEM to flag novel attack patterns and enforce zero-trust egress policies.\n\n"
            "Deploy a custom detection rule to the SIEM engine via POST:\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"rule_name\":\"RULE_ANOMALOUS_EGRESS\",\"condition\":\"bytes_out > 10000000\",\"severity\":\"HIGH\"}' http://10.10.14.90:8207/api/siem/rules`\n\n"
            "Submit the verification token returned upon registering the detection rule."
        ),
        task_type=TaskType.FLAG,
        xp_reward=70,
        accepted_answers=["SIEM_CUSTOM_DETECTION_RULE_ACTIVE"],
        mistake_explanations={
            "RULE_REGISTERED": "RULE_REGISTERED is the status string. Submit the verification_token value.",
        },
    ),
    TaskDefinition(
        task_id="task-05-siem-incident-prioritization-challenge",
        order=5,
        title="Independent Challenge: Incident Prioritization & Escalation",
        instructions=(
            "Escalate the confirmed multi-stage intrusion to Tier 2 by submitting your incident prioritization triage payload via POST:\n\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"alert_id\":\"ALRT-701\",\"rule_name\":\"RULE_BRUTE_FORCE_EXFIL\",\"priority\":\"CRITICAL\"}' http://10.10.14.90:8207/challenge`\n\n"
            "Submit the verification token returned upon incident escalation."
        ),
        task_type=TaskType.FLAG,
        xp_reward=50,
        accepted_answers=["SIEM_TRIAGE_PRIORITIZATION_VALIDATED"],
        mistake_explanations={
            "just prioritized": "Submit the full verification_token value rather than generic status.",
        },
    ),
    TaskDefinition(
        task_id="task-06-siem-quiz",
        order=6,
        title="SIEM Fundamentals Technical Assessment",
        instructions="Complete the 5-question technical quiz to validate comprehensive mastery of SIEM architecture, event normalization, correlation logic, and alert triage.",
        task_type=TaskType.QUIZ,
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="What is the primary function of event normalization in a SIEM architecture?",
                options=[
                    "Transforming heterogeneous logs from disparate vendors into a uniform schema with standardized field names for unified search and correlation.",
                    "Deleting all security logs older than 24 hours to conserve storage.",
                    "Encrypting server hard drives with BitLocker.",
                    "Automatically restarting network switches when packet drops occur.",
                ],
                correct_option_index=0,
                explanation="Normalization parses disparate log formats into a common taxonomy (e.g. mapping Windows 'IpAddress' and Linux 'src_ip' to a single standardized field).",
            ),
            QuizQuestion(
                id="q2",
                question="What is the operational risk of setting a SIEM alert threshold too low (overly sensitive)?",
                options=[
                    "It causes alert fatigue by flooding analysts with high volumes of False Positives, increasing the likelihood that real attacks will be ignored.",
                    "It physically damages the server's CPU cooling fans.",
                    "It prevents the network card from transmitting TCP packets.",
                    "It automatically revokes the CEO's email password.",
                ],
                correct_option_index=0,
                explanation="Overly sensitive correlation rules generate excessive False Positives, leading to alert fatigue where analysts burn out or fail to spot critical incidents.",
            ),
            QuizQuestion(
                id="q3",
                question="In SIEM terminology, what is a correlation rule?",
                options=[
                    "A predefined logic condition that evaluates relationships between multiple events across time and data sources to identify composite threat patterns.",
                    "A mathematical algorithm that calculates the physical weight of server racks.",
                    "A software patch applied to the Windows kernel.",
                    "A firewall cable color standard.",
                ],
                correct_option_index=0,
                explanation="Correlation rules evaluate multiple disparate events (e.g. authentication failures followed by unusual outbound network spikes) within a specified time window.",
            ),
            QuizQuestion(
                id="q4",
                question="Why is mapping SIEM detection rules to the MITRE ATT&CK framework considered an industry best practice?",
                options=[
                    "It provides a structured methodology to visualize defensive detection coverage and identify gaps across known adversary tactics and techniques.",
                    "It eliminates the need for security analysts in the SOC.",
                    "It makes internet connections 100 times faster.",
                    "It guarantees that an organization will never experience a hardware failure.",
                ],
                correct_option_index=0,
                explanation="Mapping detection rules to MITRE ATT&CK allows security leaders to assess defensive posture against real-world adversary behaviors and identify unmonitored blind spots.",
            ),
            QuizQuestion(
                id="q5",
                question="In incident response, what is meant by Mean Time to Detect (MTTD)?",
                options=[
                    "The average duration of time that elapses between an adversary's initial breach and the security team's discovery of the incident.",
                    "The amount of time it takes to purchase a new server.",
                    "The time required to install Windows updates.",
                    "The total battery life of a corporate laptop.",
                ],
                correct_option_index=0,
                explanation="MTTD measures how quickly defensive controls and SOC analysts detect unauthorized adversary presence, a key metric for measuring security program maturity.",
            ),
        ],
    ),
]

ROOM_BLUE_07_DEFINITION = RoomDefinition(
    room_id="blue-07-siem-fundamentals",
    room_number=7,
    track=TrackEnum.BLUE,
    title="SIEM Fundamentals",
    short_description="Explore SIEM architecture, query normalized event indexes across disparate log sources, investigate multi-source correlation rules, and engineer custom detections.",
    difficulty="Intermediate",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_BLUE_07_CONCEPT,
    tasks=ROOM_BLUE_07_TASKS,
    learning_objectives=[
        "Understand the multi-tier SIEM architecture: ingestion, parsing, normalization, and correlation",
        "Query normalized event indices using field-based search filters",
        "Analyze multi-source correlation rules combining endpoint and network telemetry",
        "Engineer and register custom detection rules to catch anomalous network egress",
        "Perform incident triage, evaluate False Positives vs True Positives, and prioritize incidents",
    ],
    assessment_criteria=[
        "Identify the operational definition of a False Positive in SIEM alerting",
        "Extract the adversary source IP from normalized high-severity event search results",
        "Identify the correlated detection rule triggered by multi-source attack telemetry",
        "Deploy a custom detection rule to the SIEM engine via POST",
        "Submit incident prioritization triage payloads in the challenge task",
        "Pass the 5-question SIEM Fundamentals technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)


# ============================================================================
# BLUE ROOM 08: WINDOWS EVENT INVESTIGATION (FULLY IMPLEMENTED)
# ============================================================================

ROOM_BLUE_08_CONCEPT = RoomConcept(
    overview=(
        "Windows Event Investigation immerses defenders in forensic analysis of Microsoft Windows Security Event Logs. "
        "Analysts investigate high-fidelity event IDs covering process creation with command-line auditing (4688), privileged "
        "group membership modifications (4732), PowerShell script block execution (4104), and anti-forensic audit log tampering (1102)."
    ),
    simple_analogy=(
        "Imagine a forensic detective investigating a sophisticated corporate headquarters burglary. The building has specialized "
        "security ledgers: the master badge system records every door unlocked (logon events), security cameras record which room "
        "someone enters with specialized tools (Process Creation 4688), keycard management logs when an unauthorized key is granted "
        "executive vault privileges (Group Member Added 4732), and hidden audio recorders transcribe conversations behind closed doors "
        "(PowerShell Script Block Logging 4104). Before escaping, the intruder attempts to spray paint over the security camera and pull "
        "the main recording tape (Audit Log Cleared 1102). Even though the intruder attempted to erase their tracks, the very act of "
        "destroying the ledger generates an immutable tamper alarm that identifies the exact timestamp and badge used during the sabotage."
    ),
    technical_term="Windows Security Auditing Subsystem, Process Tracking & Anti-Forensic Telemetry (MS-EVEN6 / Win32 SecAuth)",
    technical_definition=(
        "Windows Security Event Log auditing operates via the Local Security Authority Subsystem Service (LSASS) and Windows "
        "Event Log service (`eventlog`). High-fidelity event IDs include: Event 4688 (A new process has been created, capturing "
        "Creator/Parent Process and full CommandLine arguments when enabled via Group Policy), Event 4732 (A member was added to a "
        "security-enabled local group like Administrators), Event 4104 (Microsoft-Windows-PowerShell Script Block Logging, capturing "
        "the full un-obfuscated script code executed in memory), and Event 1102 (The audit log was cleared, documenting the user principal "
        "and session ID responsible for anti-forensic log deletion)."
    ),
    cybersecurity_context=(
        "Adversaries operating in Windows environments utilize LOLBins (Living Off the Land Binaries) such as `powershell.exe`, "
        "`wmic.exe`, and `certutil.exe` to execute memory-resident payloads without touching disk. Once elevation is achieved, "
        "they assign backdoor accounts to high-privilege groups (Administrators or Domain Admins) and attempt anti-forensics "
        "(`wevtutil cl Security`) to hinder incident response. Master defenders look for the sequence: 4688 -> 4104 -> 4732 -> 1102."
    ),
    why_it_matters=(
        "Windows Event Logs provide the essential forensic evidence required to prove adversary attribution, reconstruct lateral movement, "
        "and determine whether sensitive data was accessed or exfiltrated during an intrusion."
    ),
    demonstration=(
        "1. Architectural Realism & Lab Authenticity:\n"
        "   The Windows event telemetry in this lab provides authentic JSON-serialized records structured according to Microsoft MS-EVEN6 "
        "   schemas, processed via a dedicated Python investigation tool (`investigate_win_events.py`) on port 8208.\n\n"
        "2. Process Creation Tracking (Event ID 4688):\n"
        "   GET /api/winevent/process -> Inspect process creation telemetry capturing base64-encoded PowerShell execution.\n\n"
        "3. Security Group Escalation (Event ID 4732):\n"
        "   GET /api/winevent/groups -> Detect rogue account 'backdoor_admin' added to the Administrators local group.\n\n"
        "4. PowerShell Script Block Logging (Event ID 4104):\n"
        "   GET /api/winevent/scriptblock -> Inspect decoded ScriptBlockText revealing remote payload download.\n\n"
        "5. Anti-Forensic Audit Log Cleared (Event ID 1102):\n"
        "   GET /api/winevent/antiforensics -> Detect tamper event logging intentional erasure of the Security event log.\n\n"
        "6. Full Attack Chain Reconstruction Challenge:\n"
        "   POST /challenge -> Submit complete reconstructed intrusion kill-chain to verify incident timeline."
    ),
    remediation_guide=(
        "1. Enable Advanced Audit Policy: turn on 'Audit Process Creation' and enable 'Include command line in process creation events' via GPO.\n"
        "2. Enable PowerShell Script Block Logging (Event ID 4104) and PowerShell Transcription across all enterprise workstations.\n"
        "3. Forward all Windows Security event logs in real-time to a centralized SIEM to preserve evidence before Event 1102 log-clearing occurs.\n"
        "4. Configure immediate high-priority alerts on Event ID 1102 (Audit log cleared) and Event ID 4732 (Admin group member added).\n"
        "5. Restrict local and domain administrative rights, enforcing Privileged Access Workstations (PAWs) and Just-in-Time administration."
    ),
)

ROOM_BLUE_08_TASKS = [
    TaskDefinition(
        task_id="task-01-windows-event-log-tamper-id",
        order=1,
        title="Anti-Forensics & Audit Log Tampering Event ID",
        instructions=(
            "When an adversary achieves local administrative privileges, they frequently execute anti-forensic commands "
            "(such as `wevtutil cl Security` or `Clear-EventLog -LogName Security`) to erase forensic footprints.\n\n"
            "Which Windows Security Event ID is generated by the operating system when the Security audit log is cleared?"
        ),
        task_type=TaskType.QUESTION,
        question="Which Windows Event ID signals that the Security audit log was cleared?",
        hint="It is a 4-digit Event ID starting with 11...",
        xp_reward=50,
        accepted_answers=["1102", "Event ID 1102", "EventID 1102"],
        mistake_explanations={
            "4624": "Event ID 4624 records successful logons, not audit log clearing.",
            "4720": "Event ID 4720 records user account creation.",
            "4688": "Event ID 4688 records process creation.",
        },
    ),
    TaskDefinition(
        task_id="task-02-process-creation-powershell",
        order=2,
        title="Process Creation Auditing: Obfuscated PowerShell Execution (4688)",
        instructions=(
            "Inspect the process creation events in `/home/operator/windows_events/Security_investigation.json` using the investigation "
            "tool or query the process telemetry endpoint on port 8208:\n\n"
            "  `python3 /home/operator/tools/investigate_win_events.py 4688`\n"
            "  `curl -s http://10.10.14.90:8208/api/winevent/process`\n\n"
            "What is the name of the executable (with extension) launched by explorer.exe with an obfuscated encoded command line?"
        ),
        task_type=TaskType.QUESTION,
        question="What is the name of the process executable launched with an encoded command line?",
        hint="Look for the NewProcessName attribute (e.g. powershell.exe).",
        xp_reward=60,
        accepted_answers=["powershell.exe", "powershell"],
        mistake_explanations={
            "explorer.exe": "explorer.exe was the parent process (ParentProcessName), not the newly created process.",
            "cmd.exe": "The command line shows powershell.exe was invoked.",
        },
    ),
    TaskDefinition(
        task_id="task-03-security-group-escalation",
        order=3,
        title="Privilege Escalation Auditing: Group Membership Modifications (4732)",
        instructions=(
            "Adversaries add backdoor user accounts to high-privilege local or domain groups to establish persistent administrative access.\n\n"
            "Inspect the group modification events on port 8208:\n"
            "  `python3 /home/operator/tools/investigate_win_events.py 4732`\n"
            "  `curl -s http://10.10.14.90:8208/api/winevent/groups`\n\n"
            "What privileged security group (TargetUserName) was rogue account 'backdoor_admin' added to?"
        ),
        task_type=TaskType.QUESTION,
        question="What security group was rogue account backdoor_admin added to in Event ID 4732?",
        hint="Inspect the TargetUserName attribute in the Event 4732 record.",
        xp_reward=70,
        accepted_answers=["Administrators", "administrators"],
        mistake_explanations={
            "backdoor_admin": "backdoor_admin was the member added (MemberName), not the target security group.",
            "SYSTEM": "SYSTEM was the subject user that executed the change.",
        },
    ),
    TaskDefinition(
        task_id="task-04-powershell-scriptblock-logging",
        order=4,
        title="PowerShell Script Block Logging: Payload Analysis (4104)",
        instructions=(
            "PowerShell Script Block Logging (Event ID 4104) captures the full decoded code executed by the PowerShell engine, "
            "completely defeating command-line base64 obfuscation.\n\n"
            "Inspect the script block telemetry on port 8208:\n"
            "  `curl -s http://10.10.14.90:8208/api/winevent/scriptblock`\n\n"
            "What remote payload script filename was requested in the `DownloadString` web client call?"
        ),
        task_type=TaskType.QUESTION,
        question="What remote payload filename was requested in the DownloadString call?",
        hint="Look for the script filename ending in .ps1.",
        xp_reward=70,
        accepted_answers=["payload.ps1"],
        mistake_explanations={
            "198.51.100.77": "198.51.100.77 is the web server IP address hosting the payload.",
        },
    ),
    TaskDefinition(
        task_id="task-05-windows-event-investigation-challenge",
        order=5,
        title="Independent Challenge: Intrusion Kill-Chain Reconstruction",
        instructions=(
            "Reconstruct the attacker's complete intrusion sequence across Event IDs 4688, 4732, and 1102. Submit your findings via POST:\n\n"
            "  `curl -s -X POST -H \"Content-Type: application/json\" -d '{\"tamper_event_id\":1102,\"malicious_process\":\"powershell.exe\",\"added_group\":\"Administrators\"}' http://10.10.14.90:8208/challenge`\n\n"
            "Submit the verification token returned upon intrusion chain validation."
        ),
        task_type=TaskType.FLAG,
        xp_reward=50,
        accepted_answers=["WIN_EVENT_CHAIN_RECONSTRUCTED_CONFIRMED"],
        mistake_explanations={
            "just reconstructed": "Submit the full verification_token value rather than generic status.",
        },
    ),
    TaskDefinition(
        task_id="task-06-windows-event-quiz",
        order=6,
        title="Windows Event Investigation Technical Assessment",
        instructions="Complete the 5-question technical quiz to validate comprehensive mastery of Windows Event IDs, process creation logging, script block logging, and anti-forensics auditing.",
        task_type=TaskType.QUIZ,
        xp_reward=50,
        quiz_questions=[
            QuizQuestion(
                id="q1",
                question="Why is enabling 'Include command line in process creation events' for Event ID 4688 crucial for security monitoring?",
                options=[
                    "It logs the full command-line arguments passed to executables, revealing parameters, flags, scripts, and download URLs used by attackers.",
                    "It automatically prevents malware from running on the system.",
                    "It compresses process memory to prevent RAM exhaustion.",
                    "It notifies end users whenever a new window opens.",
                ],
                correct_option_index=0,
                explanation="Standard 4688 only logs the executable path; enabling command-line auditing captures the exact flags and commands (such as encoded PowerShell scripts).",
            ),
            QuizQuestion(
                id="q2",
                question="What security capability is provided by PowerShell Script Block Logging (Event ID 4104)?",
                options=[
                    "It records the full, un-obfuscated script code executed by the PowerShell engine, capturing payloads even if passed via base64 encoding or dynamic invocation.",
                    "It permanently blocks all PowerShell scripts from running.",
                    "It encrypts all .ps1 files on the hard drive.",
                    "It converts PowerShell scripts into C++ source code.",
                ],
                correct_option_index=0,
                explanation="Script block logging captures script contents as they are parsed by the runtime engine immediately prior to execution, neutralizing obfuscation techniques.",
            ),
            QuizQuestion(
                id="q3",
                question="Which Windows Event ID records that a member was added to a security-enabled global or local group?",
                options=["4728 / 4732", "4624", "4672", "7045"],
                correct_option_index=0,
                explanation="Event ID 4728 (global group) and 4732 (local group) document when a user account is granted membership in security groups like Administrators.",
            ),
            QuizQuestion(
                id="q4",
                question="When an attacker executes 'wevtutil cl Security', what immediate indicator remains in the event log?",
                options=[
                    "Event ID 1102 is recorded in the new log, documenting that the audit log was cleared along with the user account responsible.",
                    "The entire computer hard drive is wiped.",
                    "A blue screen of death (BSOD) is permanently triggered.",
                    "The Windows license key is revoked.",
                ],
                correct_option_index=0,
                explanation="The Windows Event Log service automatically records Event ID 1102 whenever the Security log is cleared, establishing a tamper record.",
            ),
            QuizQuestion(
                id="q5",
                question="Why should security event logs be forwarded in real time to an external SIEM rather than stored exclusively on local disks?",
                options=[
                    "If an attacker gains local root/SYSTEM access and clears local logs (Event 1102), the external SIEM retains an immutable copy of all preceding evidence.",
                    "Local disks cannot store more than 100 log entries.",
                    "Windows Event Viewer only operates when connected to the internet.",
                    "Local event logs are deleted automatically every hour.",
                ],
                correct_option_index=0,
                explanation="Real-time forwarding ensures that even if an attacker erases local logs or wipes the machine, the central SIEM preserves historical telemetry.",
            ),
        ],
    ),
]

ROOM_BLUE_08_DEFINITION = RoomDefinition(
    room_id="blue-08-windows-event-investigation",
    room_number=8,
    track=TrackEnum.BLUE,
    title="Windows Event Investigation",
    short_description="Conduct deep forensic analysis of Windows Security Event Logs: process creation (4688), group escalation (4732), script blocks (4104), and anti-forensics (1102).",
    difficulty="Intermediate",
    estimated_duration="45 min",
    status=RoomStatus.IMPLEMENTED,
    concept=ROOM_BLUE_08_CONCEPT,
    tasks=ROOM_BLUE_08_TASKS,
    learning_objectives=[
        "Master high-fidelity Windows Security Event IDs: 4624, 4625, 4688, 4720, 4732, 4104, and 1102",
        "Inspect process creation events and analyze obfuscated command-line arguments",
        "Audit privileged security group modifications and detect rogue account persistence",
        "Analyze PowerShell Script Block Logging telemetry to reveal in-memory payload execution",
        "Detect anti-forensic audit log tampering and reconstruct multi-stage intrusion chains",
    ],
    assessment_criteria=[
        "Identify Windows Event ID 1102 for audit log clearing",
        "Extract the malicious executable name from process creation telemetry",
        "Identify the elevated security group in membership modification events",
        "Extract the remote payload filename from PowerShell Script Block logs",
        "Reconstruct the full intrusion kill-chain in the challenge task",
        "Pass the 5-question Windows Event Investigation technical quiz with 100% accuracy",
    ],
    completion_requirements=["Complete all 5 guided challenge tasks", "Achieve 100% on the room knowledge quiz"],
    total_xp=350,
)

