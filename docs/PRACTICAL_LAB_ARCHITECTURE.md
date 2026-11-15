# NO ENTRY Practical Lab Engine Architecture

## 1. High-Level System Architecture

The NO ENTRY Practical Lab Engine provides a genuine hands-on cybersecurity learning environment inspired by TryHackMe. It isolates disposable target applications and attacker workstations inside dedicated container sandboxes while streaming terminal and web interfaces to the operator's browser.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        BROWSER CLIENT (OPERATOR)                       │
│  ┌─────────────────────────┐          ┌─────────────────────────────┐  │
│  │  Jinja2 / ES Module UI  │          │      xterm.js Terminal      │  │
│  │  (Concept + Task Form)  │          │   (ANSI VT100 Streaming)    │  │
│  └───────────┬─────────────┘          └──────────────┬──────────────┘  │
└──────────────┼───────────────────────────────────────┼─────────────────┘
               │ HTTP REST                             │ WebSocket
               ▼                                       ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        FASTAPI BACKEND CORE                            │
│  ┌─────────────────────────┐          ┌─────────────────────────────┐  │
│  │    Academy API Router   │          │   Academy Terminal Handler  │  │
│  │    (/api/academy/...)   │          │  (/ws/academy/.../terminal) │  │
│  └───────────┬─────────────┘          └──────────────┬──────────────┘  │
│              │                                       │                 │
│              ▼                                       ▼                 │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    LAB SESSION MANAGER                           │  │
│  │      • Session Ownership & Authentication Verification           │  │
│  │      • 60-Minute Expiration Enforcement                          │  │
│  │      • 5-State Docker Status Lifecycle Management                │  │
│  │      • Dynamic Subnet Allocation & Port Isolation                │  │
│  └───────────┬───────────────────────────────────────┬──────────────┘  │
└──────────────┼───────────────────────────────────────┼─────────────────┘
               │                                       │
      ┌────────┴────────┐                     ┌────────┴────────┐
      │ DOCKER_AVAILABLE│                     │ (Test Fallback) │
      ▼                 ▼                     ▼                 ▼
┌─────────────────────────────┐         ┌─────────────────────────────┐
│     DOCKER LAB RUNNER       │         │    PROCESS LAB RUNNER       │
│                             │         │                             │
│ Internal Bridge Network:    │         │ Local Process Mode:         │
│ • --internal (No Internet)  │         │ • Explicit Test Fallback    │
│ • Subnet: 10.10.14.0/24     │         │ • Loopback Target Port      │
│                             │         │ • Authentic SQLite Storage  │
│ Disposable Containers:      │         │                             │
│ • Target (VoltGear Store)   │         │                             │
│   IP: 10.10.14.90:8089      │         │                             │
│   User: targetuser (1001)   │         │                             │
│ • Attacker (Alpine Shell)   │         │                             │
│   User: operator (1000)     │         │                             │
│ Limits: 256MB RAM, 0.5 CPU, │         │                             │
│         64 PIDs, no-new-priv│         │                             │
└─────────────────────────────┘         └─────────────────────────────┘
```

---

## 2. Docker Status State Machine

NO ENTRY implements a 5-state Docker runtime lifecycle:

1. **`DOCKER_AVAILABLE`**: Docker daemon is active and responsive. Lab containers launch in full isolation.
2. **`DOCKER_UNAVAILABLE`**: Docker daemon is stopped or CLI is not found. Clear diagnostic guidance is reported.
3. **`DOCKER_STARTING`**: Docker engine is currently booting up. Operator is guided to wait 10-30 seconds.
4. **`LAB_BUILD_FAILED`**: An image build failure occurred. Detailed build failure logs and guidance are returned.
5. **`LAB_START_FAILED`**: Container or network startup failed. Partial resources are cleaned up and diagnostics provided.

---

## 3. Security and Isolation Principles

### 3.1 Network Isolation
- **Dedicated Bridge Network**: Each session provisions a distinct bridge network named `noentry_net_<session_id>` with a dedicated subnet (default `10.10.14.0/24`).
- **Zero Internet Egress (`--internal`)**: The bridge network is configured with `--internal`. Target and attacker containers cannot route traffic out to the internet, public APIs, or internal host LANs.
- **Zero Public Port Mapping**: The vulnerable target application does **not** map ports to host (`-p` is omitted). The target is reachable exclusively from the attacker container across the private network at `http://10.10.14.90:8089/`.

### 3.2 Resource Constraints
To protect the host against Denial-of-Service, runaway scripts, or fork bombs:
- **Memory Cap**: Hard limit of `256m` per container (`--memory=256m`).
- **CPU Quota**: Maximum `0.5` CPU cores (`--cpus=0.5`).
- **PID Limit**: Maximum `64` processes (`--pids-limit=64`).
- **No New Privileges**: Containers execute with `--security-opt=no-new-privileges:true`.
- **Non-Root Execution**: Both target and attacker containers run as unprivileged users (`targetuser` UID 1001, `operator` UID 1000).
- **Filesystem Isolation**: No host filesystem directories or Docker sockets are mounted.

### 3.3 Session Lifecycle & Ownership
- **Session Auto-Expiration**: Every lab session has a hard deadline of 60 minutes (`expires_at = datetime.utcnow() + timedelta(minutes=60)`). Expired containers and networks are automatically pruned.
- **Ownership Verification**: All API calls and WebSocket connections verify `operator_id`. An operator cannot execute commands, inspect logs, or terminate another operator's lab session.

---

## 4. WebSocket Terminal Communication

The browser terminal connects via WebSocket to `/ws/academy/{room_id}/terminal`:
- **Protocol**: JSON text messages with ANSI escape codes.
- **Command Dispatch**: User keystrokes and quick-probe commands are sent to FastAPI, which dispatches them via `docker exec -i <attacker_container> /bin/sh -c "<command>"`.
- **Execution Timeout**: Commands enforce a 15-second execution timeout to prevent runaway commands from hanging the session.
- **ANSI Output**: Full VT100/ANSI terminal responses are streamed back to xterm.js in the browser.

---

## 5. Multi-Service Container Architecture (Rooms 01–20)

The Docker target container (`noentry/target-sqli:latest`) and attacker container (`noentry/attacker:latest`) are designed with multi-service support, providing dedicated services for each room without container bloat:

### 5.1 Target Container Multi-Service Layout (`10.10.14.90`)
| Port | Protocol | Service | Room | Purpose & Vulnerabilities |
| :---: | :---: | :--- | :---: | :--- |
| **8081** | HTTP | `foundations_app` | Room 01 | Asset inventory system, unauthenticated audit endpoint (`/audit`) |
| **8089** | HTTP | `target_app` | Rooms 02, 09 | VoltGear Store: SQLi in search, login, category filter; secure login |
| **8080** | HTTP | `network_app` | Room 03 | Network diagnostics gateway (`/network-info`, `/status`) |
| **9001** | Raw TCP | Socket Server | Rooms 03, 05 | Layer 4 TCP connection, banner and flag delivery on 3-way handshake |
| **8090** | HTTP | `recon_app` | Room 04 | Web infrastructure: `robots.txt`, `/admin-portal-staging-7712/`, custom `X-Backend-Server` header banner, `/api/v1/health`, `/secret-assets/database_credentials.bak` |
| **8085** | HTTP | `scanning_app` | Room 05 | Network scanning target: open/closed port mapping, `/scan-status`, full range sweep `/challenge` |
| **2121** | Raw TCP | FTP Banner Server | Room 06 | Legacy FTP service delivering banner flag `NOENTRY{ftp_banner_service_enumeration_5921}` |
| **2222** | Raw TCP | SSH Banner Server | Room 06 | SSH service returning protocol version `SSH-2.0-OpenSSH_8.4p1-VoltCorp_Secure_Gateway_v2` |
| **8086** | HTTP | `enum_app` | Room 06 | Service enumeration gateway: `X-Service-Catalog` header, `/admin-internal/` catalog flag |
| **8087** | HTTP | `vuln_app` | Room 07 | Vulnerability assessment: `/api/components` inventory, `/audit/report`, `/audit/remediate` patch verification |
| **8088** | HTTP | `webapp_app` | Room 08 | Web application mechanics: `POST /api/auth/login` session token issuance, `GET /api/profile` cookie auth, `PUT /api/items/{id}` resource replace, `DELETE` 405 |
| **8091** | HTTP | `xss_app` | Room 10 | Cross-Site Scripting: `/reflected?q=`, `/comments` stored XSS, `/challenge` attribute context escape, `/remediate` CSP & escaping |
| **8092** | HTTP | `auth_app` | Room 11 | Authentication Portal: `POST /api/login` dictionary attack, `/api/logs` telemetry analysis, `/challenge` lockout policy, `/api/remediate` rate limiting (429) & bcrypt |
| **8093** | HTTP | `access_app` | Room 12 | Access Control: `GET /api/documents/101` horizontal IDOR, `GET /api/admin/users` vertical escalation, `/challenge` BOLA parameter tampering, `/api/remediate` server-side authorization (403) |
| **8094** | HTTP | `upload_app` | Room 13 | File Storage Gateway: `POST /api/upload` executable extension bypass & path traversal, `/challenge` MIME spoofing, `/api/remediate` magic byte inspection & UUID storage |
| **8095** | HTTP | `cmd_app` | Room 14 | Network Diagnostics: `/api/diagnostics/ping?host=` semicolon injection, `/api/diagnostics/dns` logical AND command chaining, `/challenge` breakout, `/api/remediate` argument vectors |
| **8096** | HTTP | `traversal_app` | Room 15 | Document Viewer: `/api/files/view?file=` relative `../` traversal, `/api/files/download` arbitrary file read, `/challenge` URL-encoded traversal (%2e%2e%2f), `/api/remediate` canonicalization (Path.resolve()) & boundary checks |
| **8097** | HTTP | `password_app` | Room 16 | Identity Gateway: `/api/users/dump` legacy unsalted MD5 disclosure, `POST /api/verify` cracked credential authentication, `/challenge` adaptive key stretching (bcrypt/Argon2id), `/api/remediate` salted bcrypt (work factor 12) & NIST 800-63B |
| **8098** | HTTP | `privesc_app` | Room 17 | Security Daemon: `/api/system/audit` SUID binary discovery (`/usr/local/bin/backup_helper`), `/api/sudo/check` wildcard NOPASSWD misconfiguration, `/api/escalate/simulate` UID 0 root execution, `/challenge` vector triage, `/api/remediate` sudoers hardening & SUID revocation |
| **8099** | HTTP | `ad_app` | Room 18 | Active Directory: `/api/ad/domain` hierarchy discovery, `/api/ad/users` LDAP SPN enumeration, `/api/ad/kerberos/request_tgt` AS-REQ / TGT issuance, `/challenge` delegation audit, `/api/ad/remediate` GPO hardening |
| **8100** | HTTP | `exploit_app` | Room 19 | Operations Dispatcher: `/api/exploit/stage1` controlled foothold exploit, `/api/post/recon` environment telemetry, `/api/post/persist` safe persistence marker, `/challenge` lateral movement analysis, `/api/remediate` incident cleanup |
| **8101** | HTTP | `capstone_app` | Room 20 | Capstone Gateway: `/api/capstone/scope` ROE verification, `/api/capstone/recon` perimeter discovery, `/api/capstone/exploit` foothold compromise, `/api/capstone/privesc` root elevation, `/api/capstone/report` formal reporting, `/api/remediate` enterprise defense |
| **8201** | HTTP | `soc_app` | Blue Room 01 | Security Operations Center: `/api/soc/events` live SIEM event telemetry, `/api/soc/alerts` correlated alerts, `POST /api/soc/triage` incident triage classification, `/challenge?stage=evidence` evidence timeline reconstruction, `POST /api/soc/remediate` session containment |
| **8202** | HTTP | `win_security_app` | Blue Room 02 | Windows Security Telemetry: `/api/windows/events/logon` Event 4624/4625 triage, `/api/windows/events/privileged` Event 4720/4672 audit, `/challenge?audit=privilege` SeDebugPrivilege audit, `POST /api/windows/remediate` lockout policy hardening |
| **8203** | HTTP | `linux_monitoring_app` | Blue Room 03 | Linux Security Monitoring: `/api/linux/logs/auth` SSH brute-force analysis, `/api/linux/logs/sudo` privilege abuse, `/challenge?audit=source_ip&ip=192.0.2.144` attribution challenge, `POST /api/linux/remediate` sshd/fail2ban hardening |
| **8204** | HTTP | `traffic_app` | Blue Room 04 | Network Traffic Analysis: `/api/traffic/summary` PCAP protocol hierarchy, `/api/traffic/streams/http` cleartext credential leak, `/api/traffic/dns` covert tunneling, `/challenge?stream=exfil` stream forensics, `POST /api/traffic/remediate` TLS enforcement |
| **8205** | HTTP | `wireshark_lab_app` | Blue Room 05 | Wireshark Fundamentals: `/api/wireshark/summary` packet distribution, `/api/wireshark/http` beacon dissection, `/api/wireshark/dns` C2 resolution, `/api/wireshark/handshake` TCP flags, `POST /challenge` display filter validation |
| **8206** | HTTP | `log_analysis_app` | Blue Room 06 | Log Analysis Fundamentals: `/api/logs/nginx/summary` web probe extraction (404/500 errors), `/api/logs/app/critical` structured JSON critical events, `POST /challenge` adversary IP attribution |
| **8207** | HTTP | `siem_lab_app` | Blue Room 07 | SIEM Fundamentals: `/api/siem/search` normalized event index query, `/api/siem/alerts` correlated alerts (RULE_BRUTE_FORCE_EXFIL), `POST /api/siem/rules` custom rule registration, `POST /challenge` incident escalation triage |
| **8208** | HTTP | `win_event_app` | Blue Room 08 | Windows Event Investigation: `/api/winevent/process` Event 4688 process creation, `/api/winevent/groups` Event 4732 group escalation, `/api/winevent/scriptblock` Event 4104 script block logging, `/api/winevent/antiforensics` Event 1102 log tampering, `POST /challenge` kill-chain validation |
| **8209** | HTTP | `bruteforce_app` | Blue Room 09 | Brute-Force & Password Spray Detection: `/api/auth/telemetry` authentication telemetry, `/api/auth/spray-indicators` spraying indicators, `POST /api/auth/rules` correlation rules, `POST /challenge` spray pattern validation |
| **8210** | HTTP | `malware_analysis_app` | Blue Room 10 | Malware Behaviour Analysis: `/api/malware/samples` catalog, `/api/malware/sample/dropper/headers` PE header telemetry, `POST /api/malware/yara/validate` YARA compilation, `POST /challenge` dropper capability verification |
| **8211** | HTTP | `phishing_app` | Blue Room 11 | Phishing Investigation: `/api/phishing/emails` quarantined mail queue, `/api/phishing/headers/{id}` forensic headers, `POST /api/phishing/triage` categorization, `POST /challenge` spoof containment verification |
| **8212** | HTTP | `endpoint_app` | Blue Room 12 | Endpoint Detection (EDR): `/api/endpoint/telemetry/processes` process tree hierarchy, `/api/endpoint/telemetry/network` socket telemetry, `POST /api/endpoint/rules` LOLBIN detection rules, `POST /challenge` C2 containment verification |

> **Architectural Limitation & Simulation Note (Room 18 Active Directory & Blue Room 02 Windows Security)**:
> Full Active Directory Domain Services and native Windows Event Viewer require a dedicated Microsoft Windows Server VM running `NTDS.dit` and Kerberos KDC services. Such a VM cannot be packaged natively inside an unprivileged Linux container on Docker Desktop. To provide an authentic, hands-on learning experience without requiring multi-gigabyte Windows VM hypervisors, NO ENTRY implements high-fidelity local AD directory services on port 8099 and Windows security event telemetry daemons on port 8202, coupled with authentic structured EVTX/JSON datasets and local parsing utilities (`parse_evtx.py`).

### 5.2 Attacker Workstation Filesystem & Process Layout
- **Wordlists & Dictionaries** (`/home/operator/wordlists/`):
  - `passwords.txt` (Targeted operator credential dictionary containing `voltcorp2024`)
  - `users.txt` (Common synthetic user roster for enumeration)
- **Active Directory Assets & Notes** (`/home/operator/ad/`):
  - `domain_users.txt` (Domain user list for enumeration)
- **Password Hashes & Cracking Targets** (`/home/operator/hashes/`):
  - `hashes.txt` (Contains unsalted MD5 and SHA-256 digests for Alice, Bob, operator, and secadmin)
- **Security Audit Scripts & Tools** (`/home/operator/tools/`):
  - `ad_ldap_query.py` (LDAP directory query tool enumerating domain users and SPNs)
  - `exploit_runner.py` (Exploit client executing controlled foothold verification on port 8100)
  - `privesc_audit.sh` (Linux privilege escalation audit utility checking `id`, `sudo -l`, and SUID binaries `find / -perm -4000`)
  - `vuln_audit.py` (CLI vulnerability assessment audit script for local component interrogation)
  - `soc_query.py` (Blue Team SIEM event query script for Room 01)
  - `parse_evtx.py` (Windows Security Event parser for Room 02)
  - `siem_query.py` (SIEM search and alert CLI tool for Room 07)
  - `investigate_win_events.py` (Windows Security Event investigation tool for Room 08)
  - `detect_bruteforce.py` (Authentication log analyzer and password spraying detector for Room 09)
  - `yara_scanner.py` (Static binary signature scanner matching dropper patterns for Room 10)
  - `inspect_email.py` (RFC 5322 email header forensic inspector for Room 11)
  - `edr_query.py` (Process tree and LOLBIN parent-child relationship query utility for Room 12)
- **Blue Team SOC & Telemetry Assets**:
  - `/home/operator/soc/raw_events.json` (Raw SIEM events ingested from enterprise hosts)
  - `/home/operator/soc/triage_guide.md` (Standard Operating Procedure for Tier 1 triage)
  - `/home/operator/windows_events/Security_logon_events.json` (Structured Windows logon records for Room 02)
  - `/home/operator/windows_events/Security_investigation.json` (Comprehensive Windows security dataset with Events 4688, 4732, 4104, 1102 for Room 08)
  - `/var/log/auth.log`, `/var/log/secure`, `/var/log/syslog` (Live Linux authentication and sudo logs with active SSH brute-force records for Room 03)
  - `/var/log/nginx/access.log` (Web access log with scanner probes, 404s, and SQLi 500 errors for Room 06)
  - `/var/log/app/app.log` (Structured JSON application log with CRITICAL database syntax exceptions for Room 06)
  - `/var/log/auth_bruteforce.log` (Simulated enterprise SSH and web authentication failure stream with password spraying clusters for Room 09)
  - `/home/operator/samples/dropper_sample.bin` (Mock inert PE32 binary sample with embedded C2 URLs and Run key persistence for Room 10)
  - `/home/operator/emails/password_reset.eml` (Synthetic raw phishing email RFC 5322 format with typosquatted lookalike domain headers for Room 11)
  - `/home/operator/endpoint_telemetry/endpoint_events.json` (Structured JSON process tree dataset capturing Word spawning hidden PowerShell for Room 12)
  - `/home/operator/pcaps/incident_capture.pcap` (Capture holding HTTP credentials and DNS exfiltration packets for Room 04)
  - `/home/operator/pcaps/suspicious_http_dns.pcap`, `/home/operator/pcaps/lab_traffic.pcap` (Packet captures with TCP handshakes, HTTP POST telemetry, and C2 DNS queries for Room 05)
- **Capstone Engagement Assets** (`/home/operator/capstone/`):
  - `scope_manifesto.txt` (Formal Rules of Engagement and scope boundaries for VoltDefense Systems assessment)
  - `report_template.json` (Structured JSON template for penetration testing assessment report submission)
- **Upload Payloads & Test Media** (`/home/operator/uploads/`):
  - `avatar.png` (Valid 1x1 PNG image with authentic `89 50 4E 47` magic bytes)
  - `document.txt` (Plaintext document for safe payload testing)
  - `poc.php.png` (Disguised PHP script testing extension allowlist bypass)
  - `test_script.php` (Raw PHP test script for execution boundary testing)
- **Vulnerability Database**:
  - `/home/operator/vuln_db/cve_catalog.json` (Local vulnerability intelligence database mapping components to CVEs and CVSS base scores)
- **Installed Offensive Tools**:
  - `nmap` & `nmap-scripts` (Network port scanning, host discovery, service probing)
  - `netcat-openbsd` (Raw TCP/UDP socket connections and banner grabbing)
  - `curl` (HTTP requests, header inspection `-I`, cookies `-b`, custom methods `-X PUT/-X DELETE`, multipart uploads `-F`)
  - `python3`, `jq`, `iproute2` (Scripting, JSON stream parsing, network interface diagnostics)
- **Asset Directory** (`/home/operator/assets/`):
  - `customer_records.db` (Permissions `0666` world-writable asset demonstrating integrity flaw)
  - `backup_codes.txt` (Contains emergency recovery token `NOENTRY{foundations_confidentiality_leak_8821}`)
  - `cia_scenario.txt` (CIA Triad incident scenario review)
- **Challenge Directory** (`/home/operator/challenges/`):
  - `.secret_vault/flag_hidden.txt` (Hidden dotfile containing dotfile flag)
  - `restricted_script.sh` (Unexecutable `0600` script requiring `chmod +x` to unlock execution flag)
  - `system_telemetry.log` (Raw log containing `SECURITY_FLAG` discoverable with `grep`)
- **Background Daemon**:
  - `python3 shadow_agent --token NOENTRY{linux_process_inspection_7741}` (Active background process discoverable via `ps aux`)

---

## 6. Server-Side Session-Bound Practical Task Validation Engine

To prevent credential and flag leakage, token replay, and premature task bypass:

1. **Zero Flag Exposure on GET Requests**: All challenge endpoints reject GET requests or return generic operational status messages without exposing task completion tokens or flags.
2. **Strict Multi-Parameter Conjunctions**: Challenge endpoints require complete, genuine investigative artifacts submitted via POST (e.g. source IP, attack pattern, targeted account counts, parent-child process pairs, DMARC statuses). Partial submissions or missing keys fail with HTTP 400 without revealing the expected values.
3. **Active Lab Session Enforcement**: Submitting an answer for a practical challenge task requires an active, running lab session owned by the authenticated operator (`status == "RUNNING"`). Submissions made without starting the lab are rejected.
4. **Session Action Verification**: Successful execution of challenge commands inside the container sandbox records an authenticated action flag in the session metadata (`info.record_action(...)`). The backend task validator verifies that the required action flag is present on the operator's active session before granting task completion and awarding XP.
5. **Cross-Session & Cross-Operator Isolation**: Actions are bound strictly to the `session_id` and `operator_id` that initiated the command. Replaying tokens across different sessions or user accounts is impossible.


