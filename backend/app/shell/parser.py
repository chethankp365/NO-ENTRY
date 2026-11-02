"""
Simulated shell parser and command executor for NO ENTRY.
Pure simulation - zero real command execution, zero subprocesses, zero network traffic.
Generates authentic penetration testing and sysadmin output formatted for xterm.js with ANSI colors.
"""

import shlex
from typing import List, Dict, Any, Optional

# ANSI Color Codes for terminal styling
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_RED = "\033[38;2;255;31;61m"
C_GREEN = "\033[38;2;0;255;106m"
C_CYAN = "\033[38;2;0;229;255m"
C_YELLOW = "\033[38;2;255;184;0m"
C_GRAY = "\033[38;2;138;147;163m"

# Simulated Lab Hosts Port and Service Directory
HOST_PROFILES: Dict[str, Dict[str, Any]] = {
    "web01": {
        "ip": "10.0.1.10",
        "os": "Linux 5.15.0-88-generic Ubuntu 22.04 LTS",
        "hostname": "web01.corp.internal",
        "latency": "0.42 ms",
        "ports": [
            ("22/tcp", "open", "ssh", "OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)"),
            ("80/tcp", "open", "http", "nginx 1.18.0 (Ubuntu)"),
            ("443/tcp", "open", "ssl/http", "nginx 1.18.0 (Ubuntu) [ModSecurity v3.0.8 active]"),
            ("8080/tcp", "open", "http-proxy", "Apache Tomcat/9.0.58"),
        ]
    },
    "mail01": {
        "ip": "10.0.1.20",
        "os": "Debian GNU/Linux 12 (bookworm)",
        "hostname": "mail01.corp.internal",
        "latency": "0.68 ms",
        "ports": [
            ("22/tcp", "open", "ssh", "OpenSSH 9.2p1 Debian 2+deb12u1"),
            ("25/tcp", "open", "smtp", "Postfix smtpd"),
            ("110/tcp", "open", "pop3", "Dovecot pop3d"),
            ("143/tcp", "open", "imap", "Dovecot imapd"),
            ("993/tcp", "open", "imaps", "Dovecot imapd (SSL)"),
        ]
    },
    "pfsense": {
        "ip": "10.0.0.1",
        "os": "FreeBSD 14.0-CURRENT (pfSense-CE 2.7.2)",
        "hostname": "firewall.corp.internal",
        "latency": "0.19 ms",
        "ports": [
            ("22/tcp", "open", "ssh", "OpenSSH 9.5 (FreeBSD 20231004)"),
            ("53/tcp", "open", "domain", "Unbound 1.19.0"),
            ("80/tcp", "open", "http", "lighttpd 1.4.69 (pfSense WebGUI redirect)"),
            ("443/tcp", "open", "ssl/https", "lighttpd 1.4.69 (pfSense Management Console)"),
        ]
    },
    "ad01": {
        "ip": "10.0.2.10",
        "os": "Windows Server 2022 Standard 20348",
        "hostname": "dc01.corp.internal",
        "latency": "1.12 ms",
        "ports": [
            ("53/tcp", "open", "domain", "Microsoft DNS 6.1.7601 (17763)"),
            ("88/tcp", "open", "kerberos-sec", "Microsoft Windows Kerberos (server time: 2026-11-02 04:12:00Z)"),
            ("135/tcp", "open", "msrpc", "Microsoft Windows RPC"),
            ("389/tcp", "open", "ldap", "Microsoft Windows Active Directory LDAP"),
            ("445/tcp", "open", "microsoft-ds", "Windows Server 2022 Standard SMBv2/v3"),
            ("3389/tcp", "open", "ms-wbt-server", "Microsoft Terminal Services RDP"),
        ]
    },
    "ws-01": {
        "ip": "10.0.2.15",
        "os": "Windows 11 Enterprise 22H2 22621",
        "hostname": "ws-finance-01.corp.internal",
        "latency": "0.85 ms",
        "ports": [
            ("135/tcp", "open", "msrpc", "Microsoft Windows RPC"),
            ("139/tcp", "open", "netbios-ssn", "Microsoft Windows netbios-ssn"),
            ("445/tcp", "open", "microsoft-ds", "Windows 11 SMB"),
            ("3389/tcp", "open", "ms-wbt-server", "Microsoft RDP (NLA enabled)"),
        ]
    },
    "ws-02": {
        "ip": "10.0.2.16",
        "os": "Windows 11 Enterprise 22H2 22621",
        "hostname": "ws-eng-02.corp.internal",
        "latency": "0.91 ms",
        "ports": [
            ("135/tcp", "open", "msrpc", "Microsoft Windows RPC"),
            ("445/tcp", "open", "microsoft-ds", "Windows 11 SMB"),
            ("5985/tcp", "open", "wsman", "Microsoft HTTP WinRM 3.0"),
        ]
    },
    "switch": {
        "ip": "10.0.0.2",
        "os": "Cumulus Linux 5.4.0 (Debian based NOS)",
        "hostname": "core-sw01.corp.internal",
        "latency": "0.15 ms",
        "ports": [
            ("22/tcp", "open", "ssh", "OpenSSH 8.4p1 Debian"),
            ("161/udp", "open", "snmp", "NET-SNMP v5.9"),
        ]
    },
    "siem": {
        "ip": "10.0.3.10",
        "os": "Linux 5.15.0-91-generic Ubuntu 22.04 LTS",
        "hostname": "wazuh-siem.corp.internal",
        "latency": "0.55 ms",
        "ports": [
            ("22/tcp", "open", "ssh", "OpenSSH 8.9p1 Ubuntu"),
            ("1514/tcp", "open", "wazuh-agent", "Wazuh Agent Communication Gateway"),
            ("9200/tcp", "open", "elasticsearch", "OpenSearch 2.11.0 (REST API)"),
            ("55000/tcp", "open", "wazuh-api", "Wazuh Central Manager API"),
        ]
    }
}

# Simulated Filesystem Content
SIMULATED_FILES: Dict[str, str] = {
    "recon_results.txt": """# NO ENTRY RANGE RECONNAISSANCE LOG
Scope: 10.0.0.0/16 Virtual Target Environment
- 10.0.0.1  : pfSense Perimeter Firewall & WAN Gateway
- 10.0.1.10 : web01 (Nginx Public Portal, CRM api)
- 10.0.1.20 : mail01 (Postfix / Dovecot Gateway)
- 10.0.2.10 : ad01 (Windows Server 2022 Active Directory DC)
- 10.0.2.15 : ws-01 (Finance Workstation, user j.doe)
- 10.0.2.16 : ws-02 (Engineering Workstation, user a.turing)
Notice: Lab is isolated. All attacks remain strictly within the simulated range.
""",
    "/etc/passwd": """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
kali:x:1000:1000:Kali Linux Operator,,,:/home/kali:/bin/zsh
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
wazuh:x:999:999:Wazuh Agent:/var/ossec:/bin/false
""",
    "notes.txt": """Target notes:
- web01 runs a vulnerable search endpoint: /api/v1/search?q=
- ad01 has Kerberos pre-authentication enabled for SPN svc_backup
- pfSense rate-limits brute force attempts after 10 requests.
"""
}

class ShellParser:
    """Parser and virtual evaluator for simulated shell commands."""

    def __init__(self):
        self.current_user = "kali"
        self.hostname = "kali-offensive"
        self.cwd = "~/range"

    def parse_command(self, raw_cmd: str) -> List[str]:
        """Parse raw command string and return believable terminal output lines."""
        stripped = raw_cmd.strip()
        if not stripped:
            return []

        try:
            tokens = shlex.split(stripped)
        except Exception:
            tokens = stripped.split()

        cmd = tokens[0].lower()
        args = tokens[1:]

        if cmd in ("help", "?"):
            return self._cmd_help()
        elif cmd == "clear":
            return ["\033[2J\033[H"]
        elif cmd == "whoami":
            return [self.current_user]
        elif cmd == "id":
            return ["uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),122(docker)"]
        elif cmd in ("ls", "dir"):
            return self._cmd_ls(args)
        elif cmd == "cat":
            return self._cmd_cat(args)
        elif cmd == "pwd":
            return [self.cwd]
        elif cmd == "uname":
            return ["Linux kali-offensive 6.5.0-kali3-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.5.6-1kali1 (2023-10-09) x86_64 GNU/Linux"]
        elif cmd == "nmap":
            return self._cmd_nmap(args)
        elif cmd == "sqlmap":
            return self._cmd_sqlmap(args)
        elif cmd == "hydra":
            return self._cmd_hydra(args)
        elif cmd == "status":
            return self._cmd_status()
        elif cmd == "scope":
            return [f"{C_YELLOW}[!] Lab is isolated. Attacks stay inside the range.{C_RESET}"]
        else:
            return [
                f"{C_RED}zsh: command not found: {tokens[0]}{C_RESET}",
                f"{C_GRAY}Type 'help' for available simulated range tools.{C_RESET}"
            ]


    def _cmd_help(self) -> List[str]:
        return [
            f"{C_BOLD}{C_CYAN}NO ENTRY // SIMULATED OFFENSIVE TERMINAL ENVIRONMENT{C_RESET}",
            f"{C_GRAY}Simulated range commands (completely safe, zero real network activity):{C_RESET}",
            "",
            f"  {C_BOLD}nmap -sV <target>{C_RESET}               Scan open ports and service versions on lab hosts",
            f"  {C_BOLD}sqlmap -u <url> --batch{C_RESET}         Automated SQL injection audit against web targets",
            f"  {C_BOLD}hydra -l <user> -P <pass> <url>{C_RESET} Fast network logon brute-force simulator",
            f"  {C_BOLD}whoami | id | pwd | uname{C_RESET}       Inspect simulated operator identity & system",
            f"  {C_BOLD}ls [-la] / cat <filename>{C_RESET}        Explore local reconnaissance files and notes",
            f"  {C_BOLD}status{C_RESET}                          Check range connectivity and sensor telemetry",
            f"  {C_BOLD}clear{C_RESET}                           Clear terminal screen buffer",
            "",
            f"{C_YELLOW}[!] Lab is isolated. Attacks stay inside the range.{C_RESET}"
        ]

    def _cmd_ls(self, args: List[str]) -> List[str]:
        show_hidden = "-a" in args or "-la" in args or "-al" in args
        files = ["recon_results.txt", "notes.txt", "wordlists/", "tools/", "scenarios/", "payloads/"]
        if show_hidden:
            files = [".", "..", ".bash_history", ".zshrc"] + files

        if "-l" in args or "-la" in args or "-al" in args:
            lines = [f"total {len(files) * 4}"]
            for f in files:
                is_dir = f.endswith("/")
                perm = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                size = "4096" if is_dir else "1842"
                color = C_CYAN if is_dir else C_RESET
                lines.append(f"{perm} 1 kali kali {size:>5} Nov  2 04:00 {color}{f}{C_RESET}")
            return lines

        return ["  ".join(files)]

    def _cmd_cat(self, args: List[str]) -> List[str]:
        if not args:
            return ["cat: missing file operand. Usage: cat <filename>"]

        filename = args[0]
        # Clean relative path prefixes
        clean_name = filename.replace("./", "").strip()

        if clean_name in SIMULATED_FILES:
            return SIMULATED_FILES[clean_name].strip().split("\n")
        elif filename in SIMULATED_FILES:
            return SIMULATED_FILES[filename].strip().split("\n")
        else:
            return [f"cat: {filename}: No such file or directory"]

    def _resolve_target(self, token: str) -> Optional[str]:
        """Map target IP, hostname, or shorthand to HOST_PROFILES key."""
        token_clean = token.lower().strip().replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        for host_id, profile in HOST_PROFILES.items():
            if token_clean in (host_id, profile["ip"], profile["hostname"]):
                return host_id
        return None

    def _cmd_nmap(self, args: List[str]) -> List[str]:
        if not args:
            return [
                "Nmap 7.94 ( https://nmap.org )",
                "Usage: nmap -sV [Target IP or Hostname]",
                "Example: nmap -sV 10.0.1.10   (or: nmap -sV web01)"
            ]

        # Extract target argument (last non-flag argument)
        target_token = None
        for arg in reversed(args):
            if not arg.startswith("-"):
                target_token = arg
                break

        if not target_token:
            target_token = "web01"

        host_id = self._resolve_target(target_token)

        lines = [
            f"{C_GRAY}Starting Nmap 7.94 ( https://nmap.org ) at 2026-11-02 04:15 UTC{C_RESET}",
        ]

        if not host_id:
            # Target not found in virtual range
            lines.extend([
                f"Note: Host {target_token} seems down or outside isolated range.",
                f"{C_RED}Nmap done: 0 IP addresses (0 hosts up) scanned in 1.20 seconds{C_RESET}"
            ])
            return lines

        profile = HOST_PROFILES[host_id]
        lines.extend([
            f"Nmap scan report for {profile['hostname']} ({profile['ip']})",
            f"Host is up ({profile['latency']} latency).",
            f"rDNS record for {profile['ip']}: {profile['hostname']}",
            "",
            f"{C_BOLD}{'PORT':<10} {'STATE':<8} {'SERVICE':<16} {'VERSION'}{C_RESET}",
        ])

        for port, state, srv, ver in profile["ports"]:
            port_colored = f"{C_GREEN}{port:<10}{C_RESET}"
            state_colored = f"{C_GREEN}{state:<8}{C_RESET}"
            lines.append(f"{port_colored} {state_colored} {srv:<16} {ver}")

        lines.extend([
            "",
            f"Service Info: OS: {profile['os']}; CPE: cpe:/o:linux:linux_kernel",
            "",
            f"{C_GREEN}Nmap done: 1 IP address (1 host up) scanned in 0.88 seconds{C_RESET}"
        ])
        return lines

    def _cmd_sqlmap(self, args: List[str]) -> List[str]:
        return [
            f"{C_BOLD}{C_CYAN}    ___     _{C_RESET}",
            f"{C_BOLD}{C_CYAN}___/___\\_[)]  |___ ___ ___ --batch{C_RESET}",
            f"{C_GRAY}http://sqlmap.org (NO ENTRY Range Simulation){C_RESET}",
            "",
            f"{C_GRAY}[*] testing connection to the target URL...{C_RESET}",
            f"{C_GREEN}[+] target URL is active (HTTP 200 OK){C_RESET}",
            f"{C_GRAY}[*] testing if the target parameter is dynamic...{C_RESET}",
            f"{C_GRAY}[*] confirming target parameter 'q' is vulnerable...{C_RESET}",
            f"{C_GREEN}[+] Parameter: q (GET / POST){C_RESET}",
            f"    Type: boolean-based blind",
            f"    Title: AND boolean-based blind - WHERE or HAVING clause",
            f"    Type: error-based",
            f"    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING clause",
            f"    Type: UNION query",
            f"    Title: Generic UNION query (NULL) - 4 columns",
            f"{C_GRAY}[*] identifying back-end DBMS: MySQL >= 8.0.33{C_RESET}",
            f"{C_GREEN}[+] available databases [4]:{C_RESET}",
            f"    [*] information_schema",
            f"    [*] mysql",
            f"    [*] performance_schema",
            f"    [*] {C_BOLD}corp_crm{C_RESET}",
            "",
            f"{C_GREEN}[*] fetched data logged to ~/.local/share/sqlmap/output/{C_RESET}"
        ]

    def _cmd_hydra(self, args: List[str]) -> List[str]:
        target = "10.0.0.1"
        for a in args:
            if "10.0." in a or "web" in a or "pfsense" in a:
                target = a
                break

        return [
            f"{C_BOLD}Hydra v9.5 (c) 2023 by van Hauser / THC & David Maciejak{C_RESET}",
            f"{C_GRAY}[DATA] max 16 tasks per target, 1 login try per task, 16 tasks in total{C_RESET}",
            f"[*] Attacking ssh://{target}:22/",
            f"{C_GRAY}[ATTEMPT] target: {target} | user: admin | pass: admin123{C_RESET}",
            f"{C_GRAY}[ATTEMPT] target: {target} | user: admin | pass: 123456{C_RESET}",
            f"{C_GRAY}[ATTEMPT] target: {target} | user: admin | pass: password{C_RESET}",
            f"{C_RED}[!] Alert: 10 authentication failures in 5 seconds (Suricata SID 2001219){C_RESET}",
            f"{C_RED}[!] Connection refused: IP blocked by pfSense firewall rate limit rule.{C_RESET}",
            f"{C_YELLOW}[*] 1 of 1 target completed, 0 valid passwords found (Host isolated){C_RESET}"
        ]

    def _cmd_status(self) -> List[str]:
        return [
            f"{C_BOLD}{C_CYAN}RANGE TELEMETRY STATUS // NO ENTRY LAB{C_RESET}",
            f"Range Perimeter: {C_GREEN}ARMED & ISOLATED{C_RESET}",
            f"Target Nodes   : 9 Hosts Active (DMZ, Corp LAN, Security Zone)",
            f"SIEM Monitoring: {C_GREEN}ONLINE (Wazuh 4.7.2 + Suricata NIDS){C_RESET}",
            f"Reflex SOAR    : {C_GREEN}READY (Auto-quarantine active){C_RESET}",
            f"Attacks Routing: {C_YELLOW}STRICTLY CONTAINED TO RANGE{C_RESET}"
        ]

shell_parser = ShellParser()
