"""
Docker-based Lab Runner for NO ENTRY Academy.
Spins up disposable target and attacker containers connected via an internal-only bridge network.
Applies memory limits, CPU caps, PID limits, and disabled outbound internet.
"""

import asyncio
import hashlib
import os
import re
import shutil
import subprocess
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from backend.app.labs.base import DockerRuntimeError, DockerStatus, LabRunner, LabSessionInfo


def find_docker_binary() -> Optional[str]:
    """Locate docker executable across PATH and standard Docker Desktop install paths."""
    which_path = shutil.which("docker")
    if which_path:
        return which_path

    candidates = [
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin\docker.exe"),
        r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
        r"C:\Program Files\Docker\Docker\resources\docker.exe",
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


def get_docker_env() -> Dict[str, str]:
    """Construct environment with Docker binary directory prepended to PATH."""
    env = os.environ.copy()
    docker_bin = find_docker_binary()
    if docker_bin:
        bin_dir = os.path.dirname(docker_bin)
        curr_path = env.get("PATH", "")
        if bin_dir.lower() not in curr_path.lower():
            env["PATH"] = bin_dir + os.pathsep + curr_path
    return env


class DockerLabRunner(LabRunner):
    def __init__(self):
        self._active_sessions: Dict[str, LabSessionInfo] = {}

    def check_docker_status(self) -> Tuple[DockerStatus, str, str]:
        """
        Check Docker daemon status and return (DockerStatus, message, guidance).
        Distinguishes DOCKER_AVAILABLE, DOCKER_UNAVAILABLE, and DOCKER_STARTING.
        """
        docker_bin = find_docker_binary()
        if not docker_bin:
            return (
                DockerStatus.DOCKER_UNAVAILABLE,
                "Docker CLI not found on system PATH or standard install paths.",
                "Please install Docker Desktop for Windows (with WSL 2 backend) and restart the application.",
            )

        env = get_docker_env()
        try:
            res = subprocess.run(
                [docker_bin, "info"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                timeout=6,
            )
            if res.returncode == 0:
                return (
                    DockerStatus.DOCKER_AVAILABLE,
                    "Docker Desktop daemon is operational.",
                    "",
                )

            err_text = (res.stderr or b"").decode("utf-8", errors="replace").lower()
            if "starting" in err_text or "is starting" in err_text:
                return (
                    DockerStatus.DOCKER_STARTING,
                    "Docker Desktop engine is currently starting up.",
                    "Please wait 10-30 seconds for the Docker daemon to reach 'Engine running' status.",
                )

            return (
                DockerStatus.DOCKER_UNAVAILABLE,
                f"Docker daemon is not running ({err_text.strip()[:160]}).",
                "Start Docker Desktop on Windows and verify that WSL 2 integration is active.",
            )
        except subprocess.TimeoutExpired:
            return (
                DockerStatus.DOCKER_STARTING,
                "Docker daemon status check timed out.",
                "Docker Desktop may still be booting up. Please wait a moment and retry.",
            )
        except Exception as exc:
            return (
                DockerStatus.DOCKER_UNAVAILABLE,
                f"Failed to query Docker daemon: {str(exc)}",
                "Ensure the Docker Desktop background service is running.",
            )

    def is_available(self) -> bool:
        """Return True if Docker daemon is responsive."""
        status, _, _ = self.check_docker_status()
        return status == DockerStatus.DOCKER_AVAILABLE

    async def _spawn_cmd(self, cmd_args: List[str]):
        """Helper to spawn an async subprocess with Docker binary and environment resolved."""
        docker_bin = find_docker_binary() or "docker"
        exec_args = list(cmd_args)
        if exec_args and exec_args[0] == "docker":
            exec_args[0] = docker_bin

        return await asyncio.create_subprocess_exec(
            *exec_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=get_docker_env(),
        )

    async def _run_cmd(self, cmd_args: List[str], ignore_errors: bool = False) -> Tuple[int, str]:
        """Execute a Docker command asynchronously and return (exit_code, output)."""
        proc = await self._spawn_cmd(cmd_args)
        stdout, _ = await proc.communicate()
        out_text = (stdout or b"").decode("utf-8", errors="replace")
        if proc.returncode != 0 and not ignore_errors:
            raise RuntimeError(f"Docker command failed ({proc.returncode}): {' '.join(cmd_args)}\n{out_text}")
        return proc.returncode, out_text

    async def ensure_images_available(self):
        """Verify that target and attacker Docker images exist; build them if missing."""
        code_t, _ = await self._run_cmd(["docker", "image", "inspect", "noentry/target-sqli:latest"], ignore_errors=True)
        if code_t != 0:
            code_b, out_b = await self._run_cmd(
                ["docker", "build", "-t", "noentry/target-sqli:latest", "labs/red_room_09_sqli/target/"],
                ignore_errors=True,
            )
            if code_b != 0:
                raise DockerRuntimeError(
                    DockerStatus.LAB_BUILD_FAILED,
                    f"Target image build failed: {out_b[:200]}",
                    "Inspect labs/red_room_09_sqli/target/Dockerfile and ensure requirements can be resolved.",
                )

        code_a, _ = await self._run_cmd(["docker", "image", "inspect", "noentry/attacker:latest"], ignore_errors=True)
        if code_a != 0:
            code_b, out_b = await self._run_cmd(
                ["docker", "build", "-t", "noentry/attacker:latest", "labs/red_room_09_sqli/attacker/"],
                ignore_errors=True,
            )
            if code_b != 0:
                raise DockerRuntimeError(
                    DockerStatus.LAB_BUILD_FAILED,
                    f"Attacker image build failed: {out_b[:200]}",
                    "Inspect labs/red_room_09_sqli/attacker/Dockerfile and ensure packages can be installed.",
                )

    async def start_session(
        self, session_id: str, room_id: str, operator_id: str
    ) -> LabSessionInfo:
        status, msg, guidance = self.check_docker_status()
        if status != DockerStatus.DOCKER_AVAILABLE:
            raise DockerRuntimeError(status, msg, guidance)

        await self.ensure_images_available()

        # Clean up any preexisting session with the same ID
        await self.stop_session(session_id)

        clean_id = f"{session_id.replace('-', '_')[:8]}_{hashlib.sha256(session_id.encode('utf-8')).hexdigest()[:8]}"
        net_name = f"noentry_net_{clean_id}"
        target_name = f"noentry_target_{clean_id}"
        attacker_name = f"noentry_attacker_{clean_id}"

        # 1. Create dedicated internal bridge network (no internet egress)
        net_created = False
        attacker_ip = "10.10.14.10"
        target_ip = "10.10.14.90"
        port_map = {
            "red-01-cybersecurity-foundations": 8081,
            "red-01-foundations": 8081,
            "red-01-linux-essentials": 8081,
            "red-02-linux-for-hackers": 8089,
            "red-02-network-recon": 8089,
            "red-03-networking-fundamentals": 8080,
            "red-03-web-recon": 8080,
            "red-04-reconnaissance": 8090,
            "red-04-vuln-scanning": 8090,
            "red-05-network-scanning": 8085,
            "red-05-auth-attacks": 8085,
            "red-06-service-enumeration": 8086,
            "red-06-hash-cracking": 8086,
            "red-07-vulnerability-assessment": 8087,
            "red-07-proxy-burp": 8087,
            "red-08-web-application-fundamentals": 8088,
            "red-08-lfi-rfi": 8088,
            "red-09-sqli-fundamentals": 8089,
            "red-10-cross-site-scripting": 8091,
            "red-10-xss-basics": 8091,
            "red-11-authentication-attacks": 8092,
            "red-11-auth-attacks": 8092,
            "red-11-command-injection": 8092,
            "red-12-access-control-testing": 8093,
            "red-12-access-control": 8093,
            "red-12-file-upload": 8093,
            "red-13-file-upload-vulnerabilities": 8094,
            "red-13-file-upload": 8094,
            "red-13-ssrf": 8094,
            "red-14-command-injection": 8095,
            "red-14": 8095,
            "red-14-linux-privesc-suid": 8095,
            "red-15-directory-traversal": 8096,
            "red-15": 8096,
            "red-15-linux-privesc-cron": 8096,
            "red-16-password-security": 8097,
            "red-16": 8097,
            "red-16-win-recon": 8097,
            "red-17-privilege-escalation": 8098,
            "red-17": 8098,
            "red-17-win-privesc": 8098,
            "red-18-active-directory-fundamentals": 8099,
            "red-18": 8099,
            "red-18-ad-enum": 8099,
            "red-19-exploitation-post-exploitation": 8100,
            "red-19": 8100,
            "red-19-ad-kerberoast": 8100,
            "red-20-red-team-capstone": 8101,
            "red-20": 8101,
            "red-20-capstone": 8101,
            # Blue Team Rooms 01-08
            "blue-01-blue-team-foundations": 8201,
            "blue-01": 8201,
            "blue-01-soc-fundamentals": 8201,
            "blue-02-windows-security-fundamentals": 8202,
            "blue-02": 8202,
            "blue-02-windows-event-logs": 8202,
            "blue-03-linux-security-monitoring": 8203,
            "blue-03": 8203,
            "blue-03-linux-log-analysis": 8203,
            "blue-04-network-traffic-analysis": 8204,
            "blue-04": 8204,
            "blue-04-traffic-analysis": 8204,
            "blue-05-wireshark-fundamentals": 8205,
            "blue-05": 8205,
            "blue-05-wireshark-packets": 8205,
            "blue-06-log-analysis-fundamentals": 8206,
            "blue-06": 8206,
            "blue-06-log-analysis": 8206,
            "blue-07-siem-fundamentals": 8207,
            "blue-07": 8207,
            "blue-07-siem-splunk-elk": 8207,
            "blue-08-windows-event-investigation": 8208,
            "blue-08": 8208,
            "blue-08-windows-event-logs": 8208,
            # Blue Team Rooms 09-12
            "blue-09-bruteforce-detection": 8209,
            "blue-09": 8209,
            "blue-09-bruteforce": 8209,
            "blue-10-malware-behaviour-analysis": 8210,
            "blue-10": 8210,
            "blue-10-malware": 8210,
            "blue-10-malware-analysis": 8210,
            "blue-11-phishing-investigation": 8211,
            "blue-11": 8211,
            "blue-11-phishing": 8211,
            "blue-12-endpoint-detection": 8212,
            "blue-12": 8212,
            "blue-12-endpoint": 8212,
            # Blue Team Rooms 13-16
            "blue-13-network-intrusion-detection": 8213,
            "blue-13": 8213,
            "blue-13-nids": 8213,
            "blue-14-threat-hunting": 8214,
            "blue-14": 8214,
            "blue-14-hunting": 8214,
            "blue-15-incident-triage": 8215,
            "blue-15": 8215,
            "blue-15-triage": 8215,
            "blue-16-incident-response": 8216,
            "blue-16": 8216,
            "blue-16-ir": 8216,
            # Blue Team Rooms 17-20
            "blue-17-digital-forensics": 8217,
            "blue-17": 8217,
            "blue-17-forensics": 8217,
            "blue-18-windows-linux-hardening": 8218,
            "blue-18": 8218,
            "blue-18-hardening": 8218,
            "blue-19-threat-intelligence": 8219,
            "blue-19": 8219,
            "blue-19-intel": 8219,
            "blue-19-threat-intel": 8219,
            "blue-20-blue-team-capstone": 8220,
            "blue-20": 8220,
            "blue-20-capstone": 8220,
            # Purple Team Rooms 01-04
            "purple-01-purple-team-foundations": 8301,
            "purple-01": 8301,
            "purple-01-foundations": 8301,
            "purple-02-mitre-attack-fundamentals": 8302,
            "purple-02": 8302,
            "purple-02-attck": 8302,
            "purple-03-attack-simulation-planning": 8303,
            "purple-03": 8303,
            "purple-03-simulation": 8303,
            "purple-04-reconnaissance-vs-monitoring": 8304,
            "purple-04": 8304,
            "purple-04-recon-monitoring": 8304,
            # Purple Team Rooms 05-08
            "purple-05-privesc-emulation": 8305,
            "purple-05": 8305,
            "purple-05-privesc": 8305,
            "purple-06-defense-evasion-emulation": 8306,
            "purple-06": 8306,
            "purple-06-defense-evasion": 8306,
            "purple-07-lateral-movement-emulation": 8307,
            "purple-07": 8307,
            "purple-07-lateral-movement": 8307,
            "purple-08-persistence-emulation": 8308,
            "purple-08": 8308,
            "purple-08-persistence": 8308,
            # Purple Team Rooms 09-12
            "purple-09-c2-framework-emulation": 8309,
            "purple-09": 8309,
            "purple-09-c2": 8309,
            "purple-10-exfiltration-emulation": 8310,
            "purple-10": 8310,
            "purple-10-exfil": 8310,
            "purple-11-ransomware-readiness": 8311,
            "purple-11": 8311,
            "purple-11-ransomware": 8311,
            "purple-12-cloud-identity-emulation": 8312,
            "purple-12": 8312,
            "purple-12-cloud-identity": 8312,
            # Purple Team Rooms 13-16
            "purple-13-supply-chain-emulation": 8313,
            "purple-13": 8313,
            "purple-13-supply-chain": 8313,
            "purple-14-api-abuse-emulation": 8314,
            "purple-14": 8314,
            "purple-14-api-abuse": 8314,
            "purple-14-bola": 8314,
            "purple-15-active-directory-attacks-emulation": 8315,
            "purple-15": 8315,
            "purple-15-ad-attacks": 8315,
            "purple-15-kerberoasting": 8315,
            "purple-16-ci-cd-pipeline-emulation": 8316,
            "purple-16": 8316,
            "purple-16-cicd": 8316,
            "purple-16-ci-cd": 8316,
            "purple-17-edr-telemetry-blinding-and-bypass-emulation": 8317,
            "purple-17-edr-bypass-emulation": 8317,
            "purple-17": 8317,
            "purple-17-edr-bypass": 8317,
            "purple-17-edr": 8317,
            "purple-18-ttp-heatmap-generation-and-coverage-scoring": 8318,
            "purple-18-ttp-heatmap-generation": 8318,
            "purple-18": 8318,
            "purple-18-heatmap": 8318,
            "purple-19-continuous-security-validation-and-automated-testing": 8319,
            "purple-19-continuous-security-validation": 8319,
            "purple-19": 8319,
            "purple-19-continuous-validation": 8319,
            "purple-20-purple-team-capstone-full-adversary-emulation-exercise": 8320,
            "purple-20-capstone-purple-exercise": 8320,
            "purple-20": 8320,
            "purple-20-capstone": 8320,
            # Detection Engineering Rooms 01-04
            "detect-01-foundations-as-code": 8401,
            "detect-01-detection-engineering-foundations-and-detection-as-code": 8401,
            "detect-01": 8401,
            "detect-01-foundations": 8401,
            "detect-02-log-normalization-and-taxonomy-ecs-and-cim": 8402,
            "detect-02-log-normalization": 8402,
            "detect-02": 8402,
            "detect-02-normalization": 8402,
            "detect-03-sigma-rule-syntax-and-component-structure": 8403,
            "detect-03-sigma-syntax": 8403,
            "detect-03": 8403,
            "detect-03-sigma": 8403,
            "detect-04-writing-process-creation-rules-sysmon-event-id-1": 8404,
            "detect-04-process-creation-rules": 8404,
            "detect-04": 8404,
            "detect-04-process-creation": 8404,
            # Detection Engineering Rooms 05-08
            "detect-05-writing-network-connection-rules-sysmon-event-id-3": 8405,
            "detect-05-network-connection-rules": 8405,
            "detect-05": 8405,
            "detect-05-network": 8405,
            "detect-06-writing-file-and-registry-integrity-rules": 8406,
            "detect-06-file-registry-rules": 8406,
            "detect-06": 8406,
            "detect-06-file-registry": 8406,
            "detect-07-detecting-authentication-abuse-event-ids-4624-4625-4672": 8407,
            "detect-07-auth-abuse-rules": 8407,
            "detect-07": 8407,
            "detect-07-auth-abuse": 8407,
            "detect-08-detecting-powershell-obfuscation-and-download-cradles": 8408,
            "detect-08-powershell-obfuscation": 8408,
            "detect-08": 8408,
            "detect-08-powershell": 8408,
            # Detection Engineering Rooms 09-12
            "detect-09-web-detection-rules": 8409,
            "detect-09-writing-web-application-detection-rules-sqli-xss-lfi": 8409,
            "detect-09": 8409,
            "detect-09-web-rules": 8409,
            "detect-10-modsec-crs-tuning": 8410,
            "detect-10-modsecurity-core-rule-set-tuning-and-custom-rules": 8410,
            "detect-10": 8410,
            "detect-10-modsec": 8410,
            "detect-11-wazuh-decoders-rules": 8411,
            "detect-11-wazuh-ossec-rules-and-decoders": 8411,
            "detect-11": 8411,
            "detect-11-wazuh": 8411,
            "detect-12-reducing-false-positives": 8412,
            "detect-12-tuning-detections-and-reducing-false-positives": 8412,
            "detect-12": 8412,
            "detect-12-tuning": 8412,
            # Detection Engineering Rooms 13-16
            "detect-13-threshold-detections": 8413,
            "detect-13-baseline-profiling-and-threshold-based-detections": 8413,
            "detect-13": 8413,
            "detect-13-threshold": 8413,
            "detect-14-correlation-rules": 8414,
            "detect-14-correlation-rules-multi-event-detection": 8414,
            "detect-14": 8414,
            "detect-14-correlation": 8414,
            "detect-15-unit-testing-rules": 8415,
            "detect-15-detection-testing-with-unit-tests-and-synthetic-logs": 8415,
            "detect-15": 8415,
            "detect-15-unit-testing": 8415,
            "detect-16-yara-hunting": 8416,
            "detect-16-yara-rules-for-file-and-memory-threat-hunting": 8416,
            "detect-16": 8416,
            "detect-16-yara": 8416,
            # Detection Engineering Rooms 17-20
            "detect-17-snort-suricata": 8417,
            "detect-17": 8417,
            "detect-17-suricata": 8417,
            "detect-17-snort": 8417,
            "detect-18-threat-hunting-hypothesis": 8418,
            "detect-18": 8418,
            "detect-18-threat-hunting": 8418,
            "detect-19-ci-cd-detection-pipelines": 8419,
            "detect-19": 8419,
            "detect-19-cicd": 8419,
            "detect-19-ci-cd": 8419,
            "detect-20-capstone-detection-pipeline": 8420,
            "detect-20": 8420,
            "detect-20-capstone": 8420,
        }
        target_port = port_map.get(room_id, 8089)

        for octet in [14, 15, 16, 17, 18, 19, 20]:
            candidate_subnet = f"10.10.{octet}.0/24"
            candidate_target_ip = f"10.10.{octet}.90"
            candidate_attacker_ip = f"10.10.{octet}.10"
            code, out = await self._run_cmd(
                ["docker", "network", "create", "--internal", f"--subnet={candidate_subnet}", net_name],
                ignore_errors=True,
            )
            if code == 0:
                target_ip = candidate_target_ip
                attacker_ip = candidate_attacker_ip
                net_created = True
                break

        if not net_created:
            # Fallback to standard internal bridge network without explicit static subnet
            code, out = await self._run_cmd(
                ["docker", "network", "create", "--internal", net_name],
                ignore_errors=True,
            )
            if code != 0:
                raise DockerRuntimeError(
                    DockerStatus.LAB_START_FAILED,
                    f"Failed to create isolated lab network: {out.strip()}",
                    "Verify Docker bridge network driver configuration in Docker Desktop settings.",
                )

        try:
            # 2. Run target container (Vulnerable VoltGear web application)
            # Memory: 256MB, CPU quota: 0.5 cores, PID limit: 64, no-new-privileges
            target_cmd = [
                "docker", "run", "-d",
                "--name", target_name,
                "--hostname", "target",
                "--network", net_name,
                "--network-alias", "target",
                "--network-alias", "target.noentry.internal",
                "--network-alias", "voltgear",
                "--network-alias", "voltgear.noentry.internal",
                "--memory=256m",
                "--cpus=0.5",
                "--pids-limit=64",
                "--security-opt=no-new-privileges:true",
                "-e", f"NOENTRY_SESSION_ID={session_id}",
                "-e", f"NOENTRY_OPERATOR_ID={operator_id}",
                "--restart=no",
            ]
            if net_created:
                target_cmd.extend(["--ip", target_ip])
            target_cmd.append("noentry/target-sqli:latest")

            code, out = await self._run_cmd(target_cmd, ignore_errors=True)
            if code != 0:
                raise DockerRuntimeError(
                    DockerStatus.LAB_START_FAILED,
                    f"Failed to start target container: {out.strip()}",
                    "Check memory and CPU quota availability in Docker Desktop WSL 2 settings.",
                )

            # 3. Run attacker container (Operator workstation with curl, python, jq)
            attacker_cmd = [
                "docker", "run", "-d",
                "--name", attacker_name,
                "--hostname", "attacker",
                "--network", net_name,
                "--network-alias", "attacker",
                "--network-alias", "attacker.noentry.internal",
                "--memory=256m",
                "--cpus=0.5",
                "--pids-limit=64",
                "--security-opt=no-new-privileges:true",
                "-e", f"TARGET_HOST={target_ip}",
                "-e", f"TARGET_PORT={target_port}",
                "-e", f"NOENTRY_SESSION_ID={session_id}",
                "-e", f"NOENTRY_OPERATOR_ID={operator_id}",
                "--restart=no",
            ]
            if net_created:
                attacker_cmd.extend(["--ip", attacker_ip])
            attacker_cmd.extend(["noentry/attacker:latest", "tail", "-f", "/dev/null"])

            code, out = await self._run_cmd(attacker_cmd, ignore_errors=True)
            if code != 0:
                raise DockerRuntimeError(
                    DockerStatus.LAB_START_FAILED,
                    f"Failed to start attacker container: {out.strip()}",
                    "Check container execution permissions in Docker Desktop.",
                )

            # Query authoritative assigned IPs from Docker inspect
            c_code, c_out = await self._run_cmd(
                ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", target_name],
                ignore_errors=True,
            )
            if c_code == 0 and c_out.strip():
                target_ip = c_out.strip()

            c_code, c_out = await self._run_cmd(
                ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", attacker_name],
                ignore_errors=True,
            )
            if c_code == 0 and c_out.strip():
                attacker_ip = c_out.strip()

            # 4. Wait briefly for target application readiness inside the network
            for _ in range(12):
                await asyncio.sleep(0.5)
                c_code, c_out = await self._run_cmd(
                    ["docker", "exec", attacker_name, "curl", "-s", "-m", "1", f"http://{target_ip}:8089/"],
                    ignore_errors=True,
                )
                if c_code == 0 and "VoltGear" in c_out:
                    break

        except Exception as exc:
            # Tear down any partially allocated containers/network on failure
            await self._run_cmd(["docker", "rm", "-f", attacker_name], ignore_errors=True)
            await self._run_cmd(["docker", "rm", "-f", target_name], ignore_errors=True)
            await self._run_cmd(["docker", "network", "rm", net_name], ignore_errors=True)
            if isinstance(exc, DockerRuntimeError):
                raise
            raise DockerRuntimeError(
                DockerStatus.LAB_START_FAILED,
                f"Unexpected failure while starting lab containers: {str(exc)}",
                "Check Docker daemon resource utilization and container logs.",
            )

        open_ports = [22, 80]
        if target_port not in open_ports:
            open_ports.append(target_port)
        open_ports.sort()

        info = LabSessionInfo(
            session_id=session_id,
            room_id=room_id,
            operator_id=operator_id,
            runner_mode="docker",
            docker_available=True,
            docker_status=DockerStatus.DOCKER_AVAILABLE,
            status="RUNNING",
            target_url=f"http://{target_ip}:{target_port}",
            target_ip=target_ip,
            target_port=target_port,
            target_hostname="target",
            attacker_ip=attacker_ip,
            attacker_hostname="attacker",
            open_ports=open_ports,
            active_sessions_count=1,
            network_id=net_name,
            attacker_container_id=attacker_name,
            target_container_id=target_name,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(minutes=60),
        )
        self._active_sessions[session_id] = info
        return info

    async def stop_session(self, session_id: str) -> bool:
        clean_id = f"{session_id.replace('-', '_')[:8]}_{hashlib.sha256(session_id.encode('utf-8')).hexdigest()[:8]}"
        attacker_name = f"noentry_attacker_{clean_id}"
        target_name = f"noentry_target_{clean_id}"
        net_name = f"noentry_net_{clean_id}"

        info = self._active_sessions.pop(session_id, None)
        if info:
            info.status = "STOPPED"

        # Force remove containers and network
        await self._run_cmd(["docker", "rm", "-f", attacker_name], ignore_errors=True)
        await self._run_cmd(["docker", "rm", "-f", target_name], ignore_errors=True)
        await self._run_cmd(["docker", "network", "rm", net_name], ignore_errors=True)

        return True

    async def reset_session(self, session_id: str) -> LabSessionInfo:
        info = self._active_sessions.get(session_id)
        if not info:
            raise KeyError(f"Session {session_id} not found.")

        # Re-initialize target database inside container
        await self._run_cmd(
            [
                "docker", "exec", info.target_container_id,
                "python", "-c", "from app import init_target_db; init_target_db()",
            ],
            ignore_errors=True,
        )
        if info.attacker_container_id:
            await self._run_cmd(
                [
                    "docker", "exec", "-u", "operator", "-w", "/home/operator", info.attacker_container_id,
                    "/bin/sh", "-c", "rm -f /home/operator/loot/* /home/operator/*.tmp /home/operator/*.log 2>/dev/null || true",
                ],
                ignore_errors=True,
            )
        return info

    @staticmethod
    def _is_forged_command(command: str) -> bool:
        cmd = command.strip().lower()
        if re.search(r"(^|[;&|`$()])\s*(echo|printf)\s+", cmd):
            return True
        if re.search(r"python[23]?\s+-c\s+.*(print|stdout\.write)", cmd):
            return True
        if re.search(r"cat\s*<<\s*['\"]?eof['\"]?", cmd):
            return True
        if re.search(r"<\(\s*(echo|printf)", cmd):
            return True
        if cmd.startswith("alias "):
            return True
        return False

    def _record_command_actions(self, info: LabSessionInfo, command: str, output: str) -> None:
        if not info:
            return
        if self._is_forged_command(command):
            return

        # Ensure command is actually invoking a legitimate HTTP client, shell tool, or script
        has_client = any(
            tool in command.lower()
            for tool in [
                "curl", "wget", "python", "tshark", "tcpdump", "edr_query",
                "yara_scanner", "detect_bruteforce", "inspect_email", "soc_query", "parse_evtx",
                "inspect_nids", "hunt_query", "triage_tool", "ir_manager",
                "privesc_emulation_tool", "injection_emulation_tool", "lateral_emulation_tool", "persistence_emulation_tool",
                "c2_emulation_tool", "exfil_emulation_tool", "ransomware_emulation_tool", "cloud_iam_emulation_tool",
                "supply_chain_tool", "api_abuse_tool", "ad_attacks_tool", "cicd_pipeline_tool",
                "edr_bypass_tool", "heatmap_tool", "continuous_validation_tool", "purple_capstone_tool",
                "detection_foundations_tool", "log_normalization_tool", "sigma_syntax_tool", "process_creation_tool",
                "network_connection_tool", "file_registry_tool", "auth_abuse_tool", "powershell_obfuscation_tool",
                "web_detection_tool", "modsec_tuning_tool", "wazuh_decoders_tool", "false_positive_tool",
                "threshold_tool", "correlation_rule_tool", "detection_testing_tool", "yara_hunting_tool",
                "suricata_tool", "threat_hunting_tool", "pipeline_tool", "capstone_pipeline_tool"
            ]
        )
        if not has_client:
            return

        # Blue Team Room 01
        if "TRIAGE_CONFIRMED_EVT1003_SECURE" in output:
            info.record_action("soc_triage_verified")
        if "TIMELINE_RECONSTRUCTED_DC_VOLT01" in output:
            info.record_action("soc_timeline_verified")
        if "CONTAINMENT_ENFORCED_IP_BLOCKED" in output:
            info.record_action("soc_remediation_verified")
        # Blue Team Room 02
        if "SEDEBUG_PRIVILEGE_AUDITED_CONFIRMED" in output:
            info.record_action("win_privilege_audited")
        if "LOCKOUT_POLICY_ENFORCED_5_ATTEMPTS" in output:
            info.record_action("win_audit_remediation_verified")
        # Blue Team Room 03
        if "ATTRIBUTION_CONFIRMED_192_0_2_144" in output:
            info.record_action("linux_attribution_verified")
        if "SSHD_HARDENED_FAIL2BAN_ENABLED" in output:
            info.record_action("linux_incident_verified")
        # Blue Team Room 04
        if "COVERT_CHANNEL_EXFIL_IDENTIFIED" in output:
            info.record_action("traffic_investigation_verified")
        if "TLS_ENFORCED_DNS_SINKHOLED" in output:
            info.record_action("traffic_remediation_verified")
        # Blue Team Room 05
        if "WIRESHARK_DISPLAY_FILTER_VALIDATED" in output:
            info.record_action("wireshark_challenge_verified")
        # Blue Team Room 06
        if "LOG_TRIAGE_INCIDENT_CORRELATED_SECURE" in output:
            info.record_action("log_analysis_challenge_verified")
        # Blue Team Room 07
        if "SIEM_CUSTOM_DETECTION_RULE_ACTIVE" in output:
            info.record_action("siem_rule_deployed")
        if "SIEM_TRIAGE_PRIORITIZATION_VALIDATED" in output:
            info.record_action("siem_challenge_verified")
        # Blue Team Room 08
        if "WIN_EVENT_CHAIN_RECONSTRUCTED_CONFIRMED" in output:
            info.record_action("win_event_challenge_verified")
        # Blue Team Room 09
        if "SIEM_SPRAY_CORRELATION_RULE_ACTIVE" in output:
            info.record_action("bruteforce_rule_deployed")
        if "BRUTEFORCE_RULE_VERIFIED" in output:
            info.record_action("bruteforce_challenge_verified")
        # Blue Team Room 10
        if "YARA_SYNTAX_COMPILED_MATCHED" in output:
            info.record_action("malware_yara_validated")
        if "MALWARE_YARA_MATCH_VERIFIED" in output:
            info.record_action("malware_challenge_verified")
        # Blue Team Room 11
        if "PHISHING_TRIAGE_VERIFIED_V0LTCORP" in output:
            info.record_action("phishing_triage_verified")
        if "PHISHING_INCIDENT_CONTAINED" in output:
            info.record_action("phishing_challenge_verified")
        # Blue Team Room 12
        if "EDR_LOLBIN_RULE_ACTIVE_CONFIRMED" in output:
            info.record_action("endpoint_rule_deployed")
        if "EDR_CONTAINMENT_VERIFIED" in output:
            info.record_action("endpoint_challenge_verified")
        # Blue Team Room 13
        if "NIDS_SNORT_RULE_ACTIVE" in output:
            info.record_action("nids_rule_deployed")
        if "NIDS_INTRUSION_DETECTED" in output:
            info.record_action("nids_challenge_verified")
        # Blue Team Room 14
        if "HUNT_SIGMA_QUERY_ACTIVE" in output:
            info.record_action("hunt_query_deployed")
        if "THREAT_HUNT_HYPOTHESIS_CONFIRMED" in output:
            info.record_action("hunt_challenge_verified")
        # Blue Team Room 15
        if "TRIAGE_ALERT_CLASSIFIED_CRITICAL" in output:
            info.record_action("triage_alert_classified")
        if "INCIDENT_TRIAGE_ESCALATION_VALIDATED" in output:
            info.record_action("triage_challenge_verified")
        # Blue Team Room 16
        if "RESPONSE_CONTAINMENT_ENFORCED" in output:
            info.record_action("response_containment_enforced")
        if "RESPONSE_ERADICATION_COMPLETE" in output:
            info.record_action("response_eradication_complete")
        if "INCIDENT_RESPONSE_LIFECYCLE_VERIFIED" in output:
            info.record_action("response_challenge_verified")
        # Blue Team Room 17
        if "FORENSICS_TIMELINE_CONFIRMED" in output:
            info.record_action("forensics_timeline_confirmed")
        if "DIGITAL_FORENSICS_INVESTIGATION_COMPLETE" in output:
            info.record_action("forensics_challenge_verified")
        # Blue Team Room 18
        if "LINUX_HARDENING_ENFORCED" in output:
            info.record_action("linux_hardening_enforced")
        if "SYSTEM_HARDENING_BASELINE_VERIFIED" in output:
            info.record_action("hardening_challenge_verified")
        # Blue Team Room 19
        if "INTEL_CORRELATION_CONFIRMED" in output:
            info.record_action("intel_correlation_confirmed")
        if "THREAT_INTEL_ASSESSMENT_DELIVERED" in output:
            info.record_action("intel_challenge_verified")
        # Blue Team Room 20
        if "CAPSTONE_STAGE1_DETECT_OK" in output:
            info.record_action("capstone_stage1_verified")
        if "CAPSTONE_STAGE3_HUNT_OK" in output:
            info.record_action("capstone_stage2_verified")
        if "CAPSTONE_STAGE4_FORENSICS_OK" in output:
            info.record_action("capstone_stage3_verified")
        if "CAPSTONE_STAGE6_TRIAGE_OK" in output:
            info.record_action("capstone_stage4_verified")
        if "CAPSTONE_STAGE7_CONTAIN_OK" in output:
            info.record_action("capstone_stage5_verified")
        if "BLUE_TEAM_CAPSTONE_TRIUMPH" in output:
            info.record_action("capstone_final_verified")
        # Purple Team Room 01
        if "PURPLE_TELEMETRY_MAP_VERIFIED" in output:
            info.record_action("purple_telemetry_mapped")
        if "PURPLE_FOUNDATIONS_EXERCISE_APPROVED" in output:
            info.record_action("purple_foundations_approved")
        # Purple Team Room 02
        if "ATTCK_EVIDENCE_MAPPING_VERIFIED" in output:
            info.record_action("attck_evidence_mapped")
        if "ATTCK_LIFECYCLE_MAPPING_COMPLETE" in output:
            info.record_action("attck_lifecycle_complete")
        # Purple Team Room 03
        if "SIMULATION_STEP_REGISTERED" in output:
            info.record_action("simulation_step_registered")
        if "ATTACK_SIMULATION_PLAN_APPROVED" in output:
            info.record_action("simulation_plan_approved")
        # Purple Team Room 04
        if "RECON_MONITORING_CORRELATION_CONFIRMED" in output:
            info.record_action("recon_correlation_confirmed")
        if "RECON_VS_MONITORING_VALIDATED" in output:
            info.record_action("recon_monitoring_validated")
        # Purple Team Room 05
        if "PRIVESC_EMULATION_VERIFIED" in output:
            info.record_action("privesc_emulated")
        if "PRIVESC_DETECTION_VALIDATED" in output:
            info.record_action("privesc_detection_validated")
        # Purple Team Room 06
        if "INJECTION_EMULATION_VERIFIED" in output:
            info.record_action("injection_emulated")
        if "DEFENSE_EVASION_DETECTION_VALIDATED" in output:
            info.record_action("defense_evasion_detection_validated")
        # Purple Team Room 07
        if "LATERAL_EMULATION_VERIFIED" in output:
            info.record_action("lateral_emulated")
        if "LATERAL_MOVEMENT_DETECTION_VALIDATED" in output:
            info.record_action("lateral_movement_detection_validated")
        # Purple Team Room 08
        if "PERSISTENCE_EMULATION_VERIFIED" in output:
            info.record_action("persistence_emulated")
        if "PERSISTENCE_REMEDIATION_VALIDATED" in output:
            info.record_action("persistence_remediation_validated")
        # Purple Team Room 09
        if "C2_BEACON_EMULATION_VERIFIED" in output:
            info.record_action("c2_beacon_emulated")
        if "C2_DETECTION_VALIDATED" in output:
            info.record_action("c2_detection_validated")
        # Purple Team Room 10
        if "EXFILTRATION_EMULATION_VERIFIED" in output:
            info.record_action("exfil_emulated")
        if "EXFILTRATION_DETECTION_VALIDATED" in output:
            info.record_action("exfil_detection_validated")
        # Purple Team Room 11
        if "RANSOMWARE_EMULATION_VERIFIED" in output:
            info.record_action("ransomware_emulated")
        if "RANSOMWARE_READINESS_VALIDATED" in output:
            info.record_action("ransomware_readiness_validated")
        # Purple Team Room 12
        if "CLOUD_IAM_EMULATION_VERIFIED" in output:
            info.record_action("cloud_iam_emulated")
        if "CLOUD_IDENTITY_DETECTION_VALIDATED" in output:
            info.record_action("cloud_identity_detection_validated")
        # Purple Team Room 13
        if "SUPPLY_CHAIN_EMULATION_VERIFIED" in output:
            info.record_action("supply_chain_emulated")
        if "SUPPLY_CHAIN_DETECTION_VALIDATED" in output:
            info.record_action("supply_chain_detection_validated")
        # Purple Team Room 14
        if "BOLA_EMULATION_VERIFIED" in output:
            info.record_action("bola_emulated")
        if "API_ABUSE_DETECTION_VALIDATED" in output:
            info.record_action("api_abuse_detection_validated")
        # Purple Team Room 15
        if "KERBEROASTING_EMULATION_VERIFIED" in output:
            info.record_action("kerberoasting_emulated")
        if "AD_ATTACK_DETECTION_VALIDATED" in output:
            info.record_action("ad_attack_detection_validated")
        # Purple Team Room 16
        if "CICD_PIPELINE_EMULATION_VERIFIED" in output:
            info.record_action("cicd_pipeline_emulated")
        if "CICD_PIPELINE_DETECTION_VALIDATED" in output:
            info.record_action("cicd_pipeline_detection_validated")
        # Purple Team Room 17
        if "EDR_BYPASS_EMULATION_VERIFIED" in output:
            info.record_action("edr_bypass_emulated")
        if "EDR_BYPASS_DETECTION_VALIDATED" in output:
            info.record_action("edr_bypass_detection_validated")
        # Purple Team Room 18
        if "HEATMAP_EMULATION_VERIFIED" in output:
            info.record_action("heatmap_emulated")
        if "HEATMAP_COVERAGE_VALIDATED" in output:
            info.record_action("heatmap_coverage_validated")
        # Purple Team Room 19
        if "CONTINUOUS_VALIDATION_EMULATION_VERIFIED" in output:
            info.record_action("continuous_validation_emulated")
        if "CONTINUOUS_VALIDATION_DETECTION_VALIDATED" in output:
            info.record_action("continuous_validation_detection_validated")
        # Purple Team Room 20
        if "PURPLE_CAPSTONE_EMULATION_VERIFIED" in output:
            info.record_action("purple_capstone_emulated")
        if "PURPLE_CAPSTONE_DETECTION_VALIDATED" in output:
            info.record_action("purple_capstone_detection_validated")
        # Detection Engineering Room 01
        if "DETECTION_FOUNDATIONS_VERIFIED" in output:
            info.record_action("detection_foundations_verified")
        if "DETECTION_FOUNDATIONS_VALIDATED" in output:
            info.record_action("detection_foundations_validated")
        # Detection Engineering Room 02
        if "LOG_NORMALIZATION_VERIFIED" in output:
            info.record_action("log_normalization_verified")
        if "LOG_NORMALIZATION_VALIDATED" in output:
            info.record_action("log_normalization_validated")
        # Detection Engineering Room 03
        if "SIGMA_SYNTAX_VERIFIED" in output:
            info.record_action("sigma_syntax_verified")
        if "SIGMA_SYNTAX_VALIDATED" in output:
            info.record_action("sigma_syntax_validated")
        # Detection Engineering Room 04
        if "PROCESS_CREATION_VERIFIED" in output:
            info.record_action("process_creation_verified")
        if "PROCESS_CREATION_VALIDATED" in output:
            info.record_action("process_creation_validated")
        # Detection Engineering Room 05
        if "NETWORK_DETECTION_VERIFIED" in output:
            info.record_action("network_connection_verified")
        if "NETWORK_DETECTION_VALIDATED" in output:
            info.record_action("network_connection_validated")
        # Detection Engineering Room 06
        if "FILE_REGISTRY_VERIFIED" in output:
            info.record_action("file_registry_verified")
        if "FILE_REGISTRY_VALIDATED" in output:
            info.record_action("file_registry_validated")
        # Detection Engineering Room 07
        if "AUTH_ABUSE_VERIFIED" in output:
            info.record_action("auth_abuse_verified")
        if "AUTH_ABUSE_VALIDATED" in output:
            info.record_action("auth_abuse_validated")
        # Detection Engineering Room 08
        if "POWERSHELL_DETECTION_VERIFIED" in output:
            info.record_action("powershell_obfuscation_verified")
        if "POWERSHELL_DETECTION_VALIDATED" in output:
            info.record_action("powershell_obfuscation_validated")
        # Detection Engineering Room 09
        if "WEB_DETECTION_VERIFIED" in output:
            info.record_action("web_detection_verified")
        if "WEB_DETECTION_VALIDATED" in output:
            info.record_action("web_detection_validated")
        # Detection Engineering Room 10
        if "MODSEC_CRS_VERIFIED" in output:
            info.record_action("modsec_crs_verified")
        if "MODSEC_CRS_VALIDATED" in output:
            info.record_action("modsec_crs_validated")
        # Detection Engineering Room 11
        if "WAZUH_RULES_VERIFIED" in output:
            info.record_action("wazuh_rules_verified")
        if "WAZUH_RULES_VALIDATED" in output:
            info.record_action("wazuh_rules_validated")
        # Detection Engineering Room 12
        if "FALSE_POSITIVE_TUNING_VERIFIED" in output:
            info.record_action("false_positive_tuning_verified")
        if "FALSE_POSITIVE_TUNING_VALIDATED" in output:
            info.record_action("false_positive_tuning_validated")
        # Detection Engineering Room 13
        if "THRESHOLD_DETECTION_VERIFIED" in output:
            info.record_action("threshold_detection_verified")
        if "THRESHOLD_DETECTION_VALIDATED" in output:
            info.record_action("threshold_detection_validated")
        # Detection Engineering Room 14
        if "CORRELATION_RULE_VERIFIED" in output:
            info.record_action("correlation_rule_verified")
        if "CORRELATION_RULE_VALIDATED" in output:
            info.record_action("correlation_rule_validated")
        # Detection Engineering Room 15
        if "DETECTION_UNIT_TEST_VERIFIED" in output:
            info.record_action("detection_unit_test_verified")
        if "DETECTION_UNIT_TEST_VALIDATED" in output:
            info.record_action("detection_unit_test_validated")
        # Detection Engineering Room 16
        if "YARA_HUNTING_VERIFIED" in output:
            info.record_action("yara_hunting_verified")
        if "YARA_HUNTING_VALIDATED" in output:
            info.record_action("yara_hunting_validated")
        # Detection Engineering Room 17
        if "SURICATA_SIGNATURE_VERIFIED" in output:
            info.record_action("suricata_signature_verified")
        if "SURICATA_SIGNATURE_VALIDATED" in output:
            info.record_action("suricata_signature_validated")
        # Detection Engineering Room 18
        if "THREAT_HUNT_HYPOTHESIS_VERIFIED" in output:
            info.record_action("threat_hunt_hypothesis_verified")
        if "THREAT_HUNT_HYPOTHESIS_VALIDATED" in output:
            info.record_action("threat_hunt_hypothesis_validated")
        # Detection Engineering Room 19
        if "DETECTION_PIPELINE_VERIFIED" in output:
            info.record_action("detection_pipeline_verified")
        if "DETECTION_PIPELINE_VALIDATED" in output:
            info.record_action("detection_pipeline_validated")
        # Detection Engineering Room 20
        if "CAPSTONE_PIPELINE_VERIFIED" in output:
            info.record_action("capstone_pipeline_verified")
        if "CAPSTONE_PIPELINE_VALIDATED" in output:
            info.record_action("capstone_pipeline_validated")

    async def execute_command(self, session_id: str, command: str) -> str:
        info = self._active_sessions.get(session_id)
        if not info or not info.attacker_container_id:
            raise KeyError(f"Active container for session {session_id} not found.")

        cmd_args = [
            "docker", "exec", "-i",
            "-u", "operator",
            "-w", "/home/operator",
            info.attacker_container_id,
            "/bin/sh", "-c", command,
        ]
        try:
            proc = await self._spawn_cmd(cmd_args)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15.0)
            out_text = (stdout or b"").decode("utf-8", errors="replace")
            if proc.returncode == 0:
                self._record_command_actions(info, command, out_text)
            return out_text
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return "\x1b[31m[-] Command execution timed out after 15 seconds.\x1b[0m\n"
        except Exception as exc:
            return f"\x1b[31m[-] Execution error: {str(exc)}\x1b[0m\n"
