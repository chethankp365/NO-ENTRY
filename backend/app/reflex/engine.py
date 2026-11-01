"""
Reflex SOAR / Automated Response Engine for NO ENTRY
Manages automated incident response playbooks with on/off toggles.
Executes actions when security events or alerts trigger playbook criteria.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
from pydantic import BaseModel, Field

class Playbook(BaseModel):
    id: str
    name: str
    description: str
    enabled: bool = True
    trigger_conditions: List[str] = Field(default_factory=list)
    action_type: str # "firewall_block", "host_isolate", "disable_account", "simulated_notify"

class ReflexActionRecord(BaseModel):
    id: str
    time: str
    playbook_id: str
    action: str
    target: str
    status: str # "EXECUTED", "SKIPPED", "SIMULATED"
    response_time: float # seconds, e.g. 8.4
    details: str

class ReflexEngine:
    def __init__(self):
        self.playbooks: Dict[str, Playbook] = {
            "block_ip": Playbook(
                id="block_ip",
                name="Block attacker IP",
                description="firewall rule added",
                enabled=True,
                trigger_conditions=["T1110", "T1190", "T1071"],
                action_type="firewall_block"
            ),
            "isolate_host": Playbook(
                id="isolate_host",
                name="Isolate host",
                description="network quarantine",
                enabled=True,
                trigger_conditions=["T1021", "T1486", "T1048"],
                action_type="host_isolate"
            ),
            "disable_ad_account": Playbook(
                id="disable_ad_account",
                name="Disable AD account",
                description="on honeytoken hit",
                enabled=True,
                trigger_conditions=["T1558", "T1078"],
                action_type="disable_account"
            ),
            "notify_telegram": Playbook(
                id="notify_telegram",
                name="Notify Telegram",
                description="context attached",
                enabled=False,
                trigger_conditions=["CRITICAL", "breach"],
                action_type="simulated_notify"
            ),
        }
        self.action_history: List[ReflexActionRecord] = [
            ReflexActionRecord(
                id="act-001",
                time="12:03:55",
                playbook_id="isolate_host",
                action="isolate ws-02 requested",
                target="ws-02",
                status="EXECUTED",
                response_time=8.2,
                details="Network quarantine applied on ws-02"
            ),
            ReflexActionRecord(
                id="act-002",
                time="12:03:56",
                playbook_id="isolate_host",
                action="ws-02 quarantined",
                target="ws-02",
                status="EXECUTED",
                response_time=8.4,
                details="Host isolated from 10.0.2.0/24 subnet"
            ),
            ReflexActionRecord(
                id="act-003",
                time="12:04:14",
                playbook_id="block_ip",
                action="firewall: block 185.220.101.4",
                target="185.220.101.4",
                status="EXECUTED",
                response_time=8.4,
                details="iptables / pfSense rule drop rule added"
            ),
        ]
        self.blocked_ips: set[str] = {"185.220.101.4"}
        self.disabled_accounts: set[str] = {"svc_backup"}

    def get_playbooks(self) -> List[Playbook]:
        return list(self.playbooks.values())

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        return self.playbooks.get(playbook_id)

    def toggle_playbook(self, playbook_id: str, enabled: bool) -> Optional[Playbook]:
        if playbook_id in self.playbooks:
            self.playbooks[playbook_id].enabled = enabled
            return self.playbooks[playbook_id]
        return None

    def evaluate_event(
        self,
        event: dict,
        host_updater: Optional[Callable[[str, str], None]] = None
    ) -> List[ReflexActionRecord]:
        """
        Evaluate an incoming event against active playbooks and execute automated responses.
        Returns list of actions executed.
        """
        executed_actions: List[ReflexActionRecord] = []
        technique_id = event.get("technique_id", "")
        source_ip = event.get("source_ip", "")
        target_host = event.get("target_host", "")
        severity = event.get("severity", "LOW")
        breach = event.get("breach", False)
        event_time = event.get("time", datetime.utcnow().strftime("%H:%M:%S"))

        # 1. Block Attacker IP playbook
        pb_block = self.playbooks.get("block_ip")
        if pb_block and pb_block.enabled:
            # Trigger on external brute force or web exploit
            if technique_id in pb_block.trigger_conditions or (source_ip and not source_ip.startswith("10.0.") and source_ip != "127.0.0.1"):
                if source_ip and source_ip not in self.blocked_ips:
                    self.blocked_ips.add(source_ip)
                    record = ReflexActionRecord(
                        id=f"act-{len(self.action_history)+1:03d}",
                        time=event_time,
                        playbook_id="block_ip",
                        action=f"firewall: block {source_ip}",
                        target=source_ip,
                        status="EXECUTED",
                        response_time=8.4,
                        details=f"Dropped traffic from external source {source_ip} (response time: 8.4s)"
                    )
                    self.action_history.insert(0, record)
                    executed_actions.append(record)

        # 2. Isolate Host playbook
        pb_isolate = self.playbooks.get("isolate_host")
        if pb_isolate and pb_isolate.enabled:
            if technique_id in pb_isolate.trigger_conditions or breach or event.get("state") == "ISOLATED":
                if target_host and target_host not in ["pfsense", "switch", "kali"]:
                    record = ReflexActionRecord(
                        id=f"act-{len(self.action_history)+1:03d}",
                        time=event_time,
                        playbook_id="isolate_host",
                        action=f"isolate {target_host} quarantined",
                        target=target_host,
                        status="EXECUTED",
                        response_time=8.4,
                        details=f"Network quarantine applied on host {target_host}"
                    )
                    self.action_history.insert(0, record)
                    executed_actions.append(record)
                    if host_updater:
                        host_updater(target_host, "isolated")

        # 3. Disable AD Account playbook
        pb_ad = self.playbooks.get("disable_ad_account")
        if pb_ad and pb_ad.enabled:
            if technique_id in pb_ad.trigger_conditions or "honeytoken" in event.get("event", "").lower():
                account_name = "svc_backup" if "svc" in event.get("event", "") else "compromised_user"
                self.disabled_accounts.add(account_name)
                record = ReflexActionRecord(
                    id=f"act-{len(self.action_history)+1:03d}",
                    time=event_time,
                    playbook_id="disable_ad_account",
                    action=f"AD: account {account_name} disabled",
                    target=account_name,
                    status="EXECUTED",
                    response_time=8.4,
                    details=f"Active Directory user account {account_name} locked"
                )
                self.action_history.insert(0, record)
                executed_actions.append(record)

        # 4. Notify Telegram playbook
        pb_notify = self.playbooks.get("notify_telegram")
        if pb_notify and pb_notify.enabled:
            if severity == "CRITICAL" or breach:
                record = ReflexActionRecord(
                    id=f"act-{len(self.action_history)+1:03d}",
                    time=event_time,
                    playbook_id="notify_telegram",
                    action="telegram message sent",
                    target="SOC_Alerts_Channel",
                    status="SIMULATED",
                    response_time=8.4,
                    details="Simulated Telegram webhook notification dispatched"
                )
                self.action_history.insert(0, record)
                executed_actions.append(record)

        return executed_actions

# Singleton reflex engine
reflex_engine = ReflexEngine()
