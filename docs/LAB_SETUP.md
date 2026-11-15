# NO ENTRY Lab Setup & Environment Guide

This document details how NO ENTRY configures and operates the genuine Docker-based practical lab runtime for hands-on cybersecurity training, along with environment detection and troubleshooting.

---

## 1. Docker Environment Detection & Status Lifecycle

When an operator launches a practical cybersecurity room (such as **Red Team Room 09: SQL Injection Fundamentals**), NO ENTRY inspects the host environment via `find_docker_binary()` and `docker info`.

The system explicitly distinguishes five operational states:

| Status Code | Description | User Action / Guidance |
|-------------|-------------|-------------------------|
| `DOCKER_AVAILABLE` | Docker Engine (WSL 2 backend) is healthy and responsive. | Full containerized lab launches automatically. |
| `DOCKER_UNAVAILABLE` | Docker CLI not found or Docker Desktop daemon is not running. | Start Docker Desktop on Windows and verify the engine is running. |
| `DOCKER_STARTING` | Docker daemon is actively initializing or booting up. | Wait 10–30 seconds for the engine to complete startup. |
| `LAB_BUILD_FAILED` | Target or attacker container image build encountered an error. | Check Dockerfile syntax and package dependencies. |
| `LAB_START_FAILED` | Docker container or bridge network failed to instantiate. | Check container limits or Docker daemon memory allocation. |

**No silent fake terminal fallbacks**: When Docker is offline or starting, NO ENTRY reports the exact error and guidance in both the web workspace and the terminal banner.

---

## 2. Docker Desktop Setup Instructions (Windows with WSL 2)

NO ENTRY is optimized for Docker Desktop running on Windows 10/11 with the WSL 2 backend:

1. **Verify WSL 2 Installation**:
   In PowerShell (Administrator):
   ```powershell
   wsl --status
   wsl --update
   ```
2. **Install Docker Desktop**:
   Download and install from [Docker Desktop Official Site](https://www.docker.com/products/docker-desktop/).
   Ensure **"Use WSL 2 instead of Hyper-V (recommended)"** is selected.
3. **Verify Docker Daemon**:
   In PowerShell:
   ```powershell
   docker --version
   docker run hello-world
   ```
4. **Auto-Discovery by NO ENTRY**:
   NO ENTRY automatically discovers `docker.exe` across standard PATH and per-user install locations:
   - `%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin\docker.exe`
   - `C:\Program Files\Docker\Docker\resources\bin\docker.exe`

---

## 3. Container Images & Lab Architecture

### 3.1 Container Images
- **Vulnerable Target**: `noentry/target-sqli:latest`
  - Python 3.11-slim, FastAPI, SQLite3, `python-multipart`.
  - Runs multi-service engine for Red Team rooms:
    - Port `8081`: Asset inventory system with unauthenticated audit endpoint (Room 01)
    - Port `8089`: VoltGear Equipment Store with SQL injection vulnerabilities (Rooms 02, 09)
    - Port `8080`: Network diagnostic gateway with CIDR / interface status (Room 03)
    - Port `9001`: Raw TCP socket service with 3-way handshake banner (Rooms 03, 05)
    - Port `8090`: Web infrastructure with `robots.txt`, staging gateway, custom server banner header, API documentation, and backup files (Room 04)
    - Port `8085`: Network scanning target with open/closed port mapping and `/scan-status` discovery (Room 05)
    - Port `2121`: Raw TCP FTP service with protocol banner information disclosure (Room 06)
    - Port `2222`: Raw TCP SSH service with protocol version exchange string (Room 06)
    - Port `8086`: HTTP service enumeration API with custom `X-Service-Catalog` header and internal administrative catalog (Room 06)
    - Port `8087`: Vulnerability assessment component inventory (`/api/components`), findings report (`/audit/report`), and patch verification endpoint (`/audit/remediate`) (Room 07)
    - Port `8088`: Web application fundamentals API with session login (`/api/auth/login`), cookie-authenticated profile (`/api/profile`), and REST resource modification (`PUT /api/items/{id}`) (Room 08)
    - Port `8091`: Cross-Site Scripting portal with reflected XSS (`/reflected?q=`), stored forum comments (`/comments`), attribute context injection (`/challenge`), and CSP / output encoding remediation (`/remediate`) (Room 10)
    - Port `8092`: Authentication gateway with dictionary brute-force target (`POST /api/login`), logon telemetry audit logs (`/api/logs`), lockout policy verification (`/challenge`), and rate-limiting / bcrypt remediation (`POST /api/remediate`) (Room 11)
    - Port `8093`: Document management portal with horizontal IDOR (`GET /api/documents/101`), vertical administrative escalation (`GET /api/admin/users`), BOLA parameter challenge (`/challenge`), and server-side RBAC remediation (`POST /api/remediate`) (Room 12)
    - Port `8094`: File storage gateway with executable extension bypass and path traversal (`POST /api/upload`), MIME type spoofing challenge (`/challenge`), and magic byte / UUID storage remediation (`POST /api/remediate`) (Room 13)
    - Port `8095`: Network diagnostics gateway with OS command injection (`/api/diagnostics/ping`), logical AND/pipe command chaining (`/api/diagnostics/dns`), breakout challenge (`/challenge`), and safe argument vector remediation (`POST /api/remediate`) (Room 14)
    - Port `8096`: Document viewer with relative path traversal (`/api/files/view`), arbitrary file disclosure (`/api/files/download`), URL-encoded traversal challenge (`/challenge`), and canonical path boundary remediation (`POST /api/remediate`) (Room 15)
    - Port `8097`: Identity management gateway with unsalted MD5 hash dump (`/api/users/dump`), cracked credential verification (`POST /api/verify`), adaptive key stretching challenge (`/challenge`), and salted bcrypt / NIST 800-63B remediation (`POST /api/remediate`) (Room 16)
    - Port `8098`: System security daemon with SUID binary auditing (`/api/system/audit`), wildcard NOPASSWD sudoers check (`/api/sudo/check`), elevated root execution simulation (`POST /api/escalate/simulate`), and least privilege remediation (`POST /api/remediate`) (Room 17)
    - Port `8099`: Active Directory concepts directory service daemon with domain hierarchy (`/api/ad/domain`), LDAP SPN enumeration (`/api/ad/users`), Kerberos AS-REQ / TGT issuance (`/api/ad/kerberos/request_tgt`), and GPO remediation (Room 18)
    - Port `8100`: Operations Dispatcher with controlled initial foothold exploit (`/api/exploit/stage1`), environment telemetry (`/api/post/recon`), safe persistence marker (`/api/post/persist`), and cleanup remediation (Room 19)
    - Port `8101`: Enterprise Capstone Gateway with Rules of Engagement verification (`/api/capstone/scope`), perimeter reconnaissance (`/api/capstone/recon`), foothold compromise (`/api/capstone/exploit`), root privilege escalation (`/api/capstone/privesc`), and formal assessment reporting (`/api/capstone/report`) (Room 20)
    - Port `8201`: Security Operations Center with live SIEM telemetry stream (`/api/soc/events`), correlated alerts (`/api/soc/alerts`), incident triage classification (`POST /api/soc/triage`), evidence timeline reconstruction (`/challenge?stage=evidence`), and session containment remediation (`POST /api/soc/remediate`) (Blue Room 01)
    - Port `8202`: Windows Security Telemetry Lab with logon event auditing (`/api/windows/events/logon`), privileged account creation events (`/api/windows/events/privileged`), privilege audit challenge (`/challenge?audit=privilege`), and lockout policy hardening (`POST /api/windows/remediate`) (Blue Room 02)
    - Port `8203`: Linux Security Monitoring with SSH brute-force analysis (`/api/linux/logs/auth`), sudo privilege abuse logs (`/api/linux/logs/sudo`), source IP attribution challenge (`/challenge?audit=source_ip&ip=192.0.2.144`), and sshd/fail2ban hardening (`POST /api/linux/remediate`) (Blue Room 03)
    - Port `8204`: Network Traffic Analysis with PCAP capture summary (`/api/traffic/summary`), cleartext HTTP credential sniffing (`/api/traffic/streams/http`), DNS covert tunneling telemetry (`/api/traffic/dns`), stream forensics challenge (`/challenge?stream=exfil`), and TLS enforcement (`POST /api/traffic/remediate`) (Blue Room 04)
    - Port `8205`: Wireshark Fundamentals with PCAP protocol dissection (`/api/wireshark/summary`), HTTP POST telemetry beaconing (`/api/wireshark/http`), DNS C2 domain resolution (`/api/wireshark/dns`), TCP 3-way handshake flag analysis (`/api/wireshark/handshake`), and display filter validation (`POST /challenge`) (Blue Room 05)
    - Port `8206`: Log Analysis Fundamentals with Nginx request and 404/500 code distribution (`/api/logs/nginx/summary`), structured JSON application errors (`/api/logs/app/critical`), and adversary IP attribution (`POST /challenge`) (Blue Room 06)
    - Port `8207`: SIEM Fundamentals with normalized event search index (`/api/siem/search`), correlated alert stream (`/api/siem/alerts`), custom detection rule creation (`POST /api/siem/rules`), and incident escalation triage (`POST /challenge`) (Blue Room 07)
    - Port `8208`: Windows Event Investigation with process creation auditing (`/api/winevent/process`), security group escalation (`/api/winevent/groups`), PowerShell script block logging (`/api/winevent/scriptblock`), audit log tampering (`/api/winevent/antiforensics`), and kill-chain validation (`POST /challenge`) (Blue Room 08)
    - Port `8209`: Brute-Force Detection with authentication telemetry (`/api/auth/telemetry`), spraying indicator matrix (`/api/auth/spray-indicators`), correlation rule deployment (`POST /api/auth/rules`), and spray pattern challenge validation (`POST /challenge`) (Blue Room 09)
    - Port `8210`: Malware Behaviour Analysis with sample catalog (`/api/malware/samples`), PE header inspection (`/api/malware/sample/dropper/headers`), YARA rule compiler and validator (`POST /api/malware/yara/validate`), and dropper capability triage challenge (`POST /challenge`) (Blue Room 10)
    - Port `8211`: Phishing Investigation with quarantined email queue (`/api/phishing/emails`), RFC 5322 header forensics (`/api/phishing/headers/{id}`), email triage workflow (`POST /api/phishing/triage`), and domain spoof containment challenge (`POST /challenge`) (Blue Room 11)
    - Port `8212`: Endpoint Detection with process tree telemetry (`/api/endpoint/telemetry/processes`), socket connection telemetry (`/api/endpoint/telemetry/network`), LOLBIN detection rule authoring (`POST /api/endpoint/rules`), and C2 beacon containment challenge (`POST /challenge`) (Blue Room 12)
  - Runs as non-root user `targetuser` (UID 1001).
- **Attacker Workstation**: `noentry/attacker:latest`
  - Alpine Linux 3.19 with `tshark`, `tcpdump`, `nmap`, `nmap-scripts`, `curl`, `python3`, `jq`, `netcat`, `bind-tools`, `iproute2`.
  - Populated with practical challenge assets:
    - `/home/operator/wordlists/` (`passwords.txt` containing target password `voltcorp2024`, `users.txt`)
    - `/home/operator/hashes/` (`hashes.txt` containing unsalted MD5 hashes for Alice and Bob)
    - `/home/operator/ad/` (`domain_users.txt` domain accounts list)
    - `/home/operator/soc/` (`raw_events.json` SIEM events, `triage_guide.md` SOP guide)
    - `/home/operator/windows_events/` (`Security_logon_events.json` Windows EVTX records, `Security_investigation.json` Event IDs 4688, 4732, 4104, 1102)
    - `/var/log/` (`auth.log`, `secure`, `syslog`, `/var/log/nginx/access.log`, `/var/log/app/app.log`, `/var/log/auth_bruteforce.log`)
    - `/home/operator/samples/` (`dropper_sample.bin` mock PE32 dropper artifact)
    - `/home/operator/emails/` (`password_reset.eml` RFC 5322 phishing email)
    - `/home/operator/endpoint_telemetry/` (`endpoint_events.json` EDR process telemetry)
    - `/home/operator/pcaps/` (`incident_capture.pcap`, `suspicious_http_dns.pcap`, `lab_traffic.pcap`)
    - `/home/operator/capstone/` (`scope_manifesto.txt` engagement boundaries, `report_template.json` formal assessment report template)
    - `/home/operator/uploads/` (`avatar.png`, `document.txt`, `poc.php.png`, `test_script.php`)
    - `/home/operator/assets/` (`customer_records.db`, `backup_codes.txt`, `cia_scenario.txt`)
    - `/home/operator/challenges/` (`.secret_vault/flag_hidden.txt`, `restricted_script.sh`, `system_telemetry.log`)
    - `/home/operator/vuln_db/` (`cve_catalog.json` - local vulnerability database with CVSS metrics)
    - `/home/operator/tools/` (`privesc_audit.sh`, `ad_ldap_query.py`, `exploit_runner.py`, `vuln_audit.py`, `soc_query.py`, `parse_evtx.py`, `siem_query.py`, `investigate_win_events.py`, `detect_bruteforce.py`, `yara_scanner.py`, `inspect_email.py`, `edr_query.py`)
    - Background process `shadow_agent` with security token.
  - Runs as unprivileged operator `operator` (UID 1000) member of groups `operator` and `wireshark`.

### 3.2 Security Constraints
- **Private Internal Bridge Network**: Created with `--internal --subnet=10.10.14.0/24`. All outbound internet egress is blocked at the bridge driver.
- **Resource Constraints**:
  - Memory: `256m` (`--memory=256m`)
  - CPU Quota: `0.5` (`--cpus=0.5`)
  - PID Limit: `64` (`--pids-limit=64`)
  - Security Options: `--security-opt=no-new-privileges:true`
- **Zero Public Exposure**: The vulnerable target container does **not** map ports to host (`-p` is omitted). It is accessible exclusively from the attacker workstation over the internal bridge network at `http://10.10.14.90:8089/`.
- **Zero Host Volume Mounts**: Containers run in complete isolation with no host filesystems or Docker sockets mounted.
- **Automatic 60-Minute Expiration**: Sessions automatically expire and are purged after 60 minutes.

---

## 4. Manual Pre-Build of Lab Images (Optional)

NO ENTRY automatically builds lab images if they are not already cached. You can also pre-build them manually:

```powershell
# Prepend Docker path if needed
$env:Path = "C:\Users\$env:USERNAME\AppData\Local\Programs\DockerDesktop\resources\bin;$env:Path"

# Build Target Image
docker build -t noentry/target-sqli:latest labs/red_room_09_sqli/target/

# Build Attacker Image
docker build -t noentry/attacker:latest labs/red_room_09_sqli/attacker/
```

---

## 5. Verification & Testing

Tests are cleanly separated:
- **Unit & Concept Validation**:
  - `backend/tests/test_academy.py`: Tests 80-room curriculum integrity, task schemas, answer scrubbing, mistake explanations, quizzes, and process emulation fallback.
  - `backend/tests/test_rooms_01_04.py`: Unit and task validation for Rooms 01–04.
  - `backend/tests/test_rooms_05_08.py`: Unit and task validation for Rooms 05–08.
  - `backend/tests/test_rooms_10_13.py`: Unit and task validation for Rooms 10–13.
  - `backend/tests/test_rooms_14_17.py`: Unit and task validation for Rooms 14–17.
  - `backend/tests/test_rooms_18_20.py`: Unit and task validation for Rooms 18–20.
- **Docker Lab Unit Tests**: `backend/tests/test_labs.py`
  - Tests database persistence, process emulation fallback, safe Docker availability checks, and WebSocket terminal communications.
- **Real Docker Integration Tests**:
  - `backend/tests/test_docker_real.py`: Tests genuine Docker container duo, security limits, network isolation, and SQLi exploitation.
  - `backend/tests/test_docker_rooms_01_04.py`: Tests genuine Docker container execution for Rooms 01–04 (asset auditing, Linux dotfiles, chmod, ps/grep, raw TCP sockets on port 9001, robots.txt, header banners, API endpoints, and backup discovery).
  - `backend/tests/test_docker_rooms_05_08.py`: Tests genuine Docker container execution for Rooms 05–08 (Nmap port scanning, FTP/SSH service enumeration, vulnerability assessment CVE catalog, and RESTful web app interactions).
  - `backend/tests/test_docker_rooms_10_13.py`: Tests genuine Docker container execution for Rooms 10–13 (reflected/stored XSS and CSP, dictionary login and rate limiting, horizontal IDOR and vertical RBAC escalation, multipart file uploads, path traversal, and magic byte validation).
  - `backend/tests/test_docker_rooms_14_17.py`: Tests genuine Docker container execution for Rooms 14–17 (OS command injection & command chaining, relative directory traversal & arbitrary file disclosure, unsalted MD5 cracking & adaptive key stretching, Linux SUID auditing & sudo NOPASSWD privilege escalation).
  - `backend/tests/test_docker_rooms_18_20.py`: Tests genuine Docker container execution for Rooms 18–20 (Active Directory domain discovery & LDAP SPN query & Kerberos TGT issuance, foothold exploit & post-recon telemetry & persistence marker & incident cleanup, Red Team Capstone full attack chain & ROE & formal reporting).
