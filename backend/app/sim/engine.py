"""
Simulation Engine for NO ENTRY
Drives simulated cyber attacks, host state machines, real-time metrics,
and background scenario execution with zero real attacks.
"""

import asyncio
from datetime import datetime
import json
import random
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
import yaml
from pydantic import BaseModel, Field

from backend.app.config import settings
from backend.app.sim.mitre import MITRE_CATALOG, get_technique
from backend.app.reflex.engine import reflex_engine

class SimEvent(BaseModel):
    id: str
    time: str
    technique_id: str
    technique_name: str
    event: str
    source_ip: str
    target_host: str
    state: str # DETECTED | BLOCKED | ALERT | ISOLATED
    severity: str # LOW | MEDIUM | HIGH | CRITICAL
    module: str # Watch | Trap | Reflex | Intel | Red | Shield
    breach: bool = False
    raw_log: Optional[Dict[str, Any]] = None

class HostState(BaseModel):
    id: str
    name: str
    role: str
    os: str
    status: str # healthy | suspicious | compromised | isolated
    agent: str
    last_alert: Optional[str] = None
    ip: str

class Metrics(BaseModel):
    threat_level: str = "ELEVATED"
    alerts_today: int = 128
    mean_time_to_detect: float = 3.2
    mean_time_to_respond: float = 8.4
    module_percentages: Dict[str, int] = {
        "Watch": 78,
        "Trap": 42,
        "Reflex": 64,
        "Intel": 35
    }
    top_techniques: List[Dict[str, Any]] = [
        {"technique": "T1110 brute force", "percentage": 82},
        {"technique": "T1190 exploit public app", "percentage": 61},
        {"technique": "T1558 kerberoast", "percentage": 44},
        {"technique": "T1071 dns tunnel", "percentage": 27}
    ]
    events_per_second: float = 0.8

class ScenarioStep(BaseModel):
    stage: str
    delay: float
    event: Dict[str, Any]
    host_update: Optional[Dict[str, Any]] = None

class Scenario(BaseModel):
    id: str
    name: str
    technique_id: str
    description: str
    steps: List[ScenarioStep]
    status: str = "idle" # idle | running | completed | stopped
    current_step: int = 0

# Realistic event templates matching project brief and reference screenshots
EVENT_TEMPLATES = [
    # Required exact examples from prompt and screenshots
    {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "event": "brute force",
        "source_ip": "185.220.101.4",
        "target_host": "web01",
        "state": "BLOCKED",
        "severity": "HIGH",
        "module": "Watch",
        "breach": False
    },
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "event": "sqli on web01",
        "source_ip": "45.9.148.22",
        "target_host": "web01",
        "state": "DETECTED",
        "severity": "HIGH",
        "module": "Watch",
        "breach": False
    },
    {
        "technique_id": "T1558",
        "technique_name": "Steal or Forge Kerberos Tickets (Kerberoasting)",
        "event": "kerberoast",
        "source_ip": "10.0.2.15",
        "target_host": "ad01",
        "state": "ALERT",
        "severity": "CRITICAL",
        "module": "Watch",
        "breach": True
    },
    {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "event": "smb lateral move",
        "source_ip": "10.0.2.15",
        "target_host": "ws-02",
        "state": "ISOLATED",
        "severity": "CRITICAL",
        "module": "Watch",
        "breach": True
    },
    {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "event": "dns tunnel",
        "source_ip": "10.0.2.31",
        "target_host": "switch",
        "state": "DETECTED",
        "severity": "MEDIUM",
        "module": "Watch",
        "breach": False
    },

    # ~25 additional realistic cyber range events
    {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "event": "phishing attachment opened on ws-01",
        "source_ip": "185.220.101.4",
        "target_host": "ws-01",
        "state": "DETECTED",
        "severity": "MEDIUM",
        "module": "Watch",
        "breach": False
    },
    {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "event": "macro spawns powershell.exe -enc",
        "source_ip": "10.0.2.15",
        "target_host": "ws-01",
        "state": "ALERT",
        "severity": "HIGH",
        "module": "Watch",
        "breach": True
    },
    {
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "event": "lsass.exe memory dump attempt (mimikatz)",
        "source_ip": "10.0.2.15",
        "target_host": "ws-01",
        "state": "ALERT",
        "severity": "CRITICAL",
        "module": "Watch",
        "breach": True
    },
    {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "event": "ransomware mass file renaming detected (.lockbit)",
        "source_ip": "10.0.2.16",
        "target_host": "ws-02",
        "state": "ALERT",
        "severity": "CRITICAL",
        "module": "Watch",
        "breach": True
    },
    {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "event": "svc_backup (fake AD account) logon from unapproved IP",
        "source_ip": "10.0.2.15",
        "target_host": "ad01",
        "state": "ALERT",
        "severity": "HIGH",
        "module": "Trap",
        "breach": False
    },
    {
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "event": "passwords.xlsx (decoy file) honeytoken tripped",
        "source_ip": "10.0.2.15",
        "target_host": "ws-01",
        "state": "ALERT",
        "severity": "HIGH",
        "module": "Trap",
        "breach": False
    },
    {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "event": "cowrie ssh honeypot: root:123456 attempted",
        "source_ip": "185.220.101.4",
        "target_host": "kali",
        "state": "BLOCKED",
        "severity": "LOW",
        "module": "Trap",
        "breach": False
    },
    {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "event": "nmap SYN stealth scan against dmz subnets",
        "source_ip": "185.220.101.4",
        "target_host": "pfsense",
        "state": "DETECTED",
        "severity": "LOW",
        "module": "Watch",
        "breach": False
    },
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "event": "ModSecurity WAF rule 949110 anomaly limit blocked",
        "source_ip": "45.9.148.22",
        "target_host": "web01",
        "state": "BLOCKED",
        "severity": "HIGH",
        "module": "Shield",
        "breach": False
    },
    {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "event": "high entropy TXT query burst (exfil channel)",
        "source_ip": "10.0.2.31",
        "target_host": "switch",
        "state": "ALERT",
        "severity": "CRITICAL",
        "module": "Watch",
        "breach": True
    },
    {
        "technique_id": "T1087",
        "technique_name": "Account Discovery",
        "event": "domain admin account enumeration via LDAP",
        "source_ip": "10.0.2.15",
        "target_host": "ad01",
        "state": "DETECTED",
        "severity": "LOW",
        "module": "Watch",
        "breach": False
    },
    {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "event": "internal port scan against corp lan 10.0.2.0/24",
        "source_ip": "10.0.1.10",
        "target_host": "switch",
        "state": "DETECTED",
        "severity": "LOW",
        "module": "Watch",
        "breach": False
    },
    {
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job",
        "event": "crontab backdoor added /etc/cron.hourly/sync.sh",
        "source_ip": "10.0.1.10",
        "target_host": "web01",
        "state": "ALERT",
        "severity": "HIGH",
        "module": "Watch",
        "breach": True
    },
    {
        "technique_id": "T1070",
        "technique_name": "Indicator Removal",
        "event": "cleared security eventlog (EventID 1102)",
        "source_ip": "10.0.2.15",
        "target_host": "ws-01",
        "state": "ALERT",
        "severity": "HIGH",
        "module": "Watch",
        "breach": True
    },
    {
        "technique_id": "T1562",
        "technique_name": "Impair Defenses",
        "event": "wazuh-agent service stop attempted",
        "source_ip": "10.0.1.10",
        "target_host": "web01",
        "state": "BLOCKED",
        "severity": "CRITICAL",
        "module": "Shield",
        "breach": False
    },
    {
        "technique_id": "T1505",
        "technique_name": "Server Software Component",
        "event": "c99.php web shell execution detected by auditd",
        "source_ip": "45.9.148.22",
        "target_host": "web01",
        "state": "ALERT",
        "severity": "CRITICAL",
        "module": "Watch",
        "breach": True
    },
    {
        "technique_id": "T1570",
        "technique_name": "Lateral Tool Transfer",
        "event": "nc.exe copied over SMB admin share",
        "source_ip": "10.0.2.15",
        "target_host": "ws-02",
        "state": "DETECTED",
        "severity": "MEDIUM",
        "module": "Watch",
        "breach": False
    },
    {
        "technique_id": "T1573",
        "technique_name": "Encrypted Channel",
        "event": "outbound TLS handshake with untrusted self-signed cert",
        "source_ip": "10.0.2.16",
        "target_host": "pfsense",
        "state": "ALERT",
        "severity": "HIGH",
        "module": "Watch",
        "breach": False
    },
    {
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "event": "sudoers privilege escalation attempt /bin/su",
        "source_ip": "10.0.1.10",
        "target_host": "web01",
        "state": "BLOCKED",
        "severity": "HIGH",
        "module": "Shield",
        "breach": False
    },
    {
        "technique_id": "T1490",
        "technique_name": "Inhibit System Recovery",
        "event": "vssadmin delete shadows command intercepted",
        "source_ip": "10.0.2.16",
        "target_host": "ws-02",
        "state": "BLOCKED",
        "severity": "CRITICAL",
        "module": "Shield",
        "breach": False
    },
    {
        "technique_id": "T1133",
        "technique_name": "External Remote Services",
        "event": "rdp connection request from high-risk Tor exit node",
        "source_ip": "185.220.101.4",
        "target_host": "pfsense",
        "state": "BLOCKED",
        "severity": "MEDIUM",
        "module": "Reflex",
        "breach": False
    },
    {
        "technique_id": "T1567",
        "technique_name": "Exfiltration Over Web Service",
        "event": "upload to anonfiles.me intercepted by proxy",
        "source_ip": "10.0.2.15",
        "target_host": "switch",
        "state": "BLOCKED",
        "severity": "HIGH",
        "module": "Reflex",
        "breach": False
    },
    {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "event": "dir /s *.kdbx search query executed",
        "source_ip": "10.0.2.15",
        "target_host": "ws-01",
        "state": "DETECTED",
        "severity": "LOW",
        "module": "Watch",
        "breach": False
    },
    {
        "technique_id": "T1489",
        "technique_name": "Service Stop",
        "event": "net stop mssqlserver command blocked by policy",
        "source_ip": "10.0.2.10",
        "target_host": "ad01",
        "state": "BLOCKED",
        "severity": "HIGH",
        "module": "Shield",
        "breach": False
    }
]

class SimulationEngine:
    def __init__(self):
        self.autopilot_enabled: bool = settings.AUTOPILOT_ENABLED
        self.metrics: Metrics = Metrics()
        self.recent_events: List[SimEvent] = []
        self.active_scenarios: Dict[str, Scenario] = {}
        self.running_scenario_tasks: Dict[str, asyncio.Task] = {}
        self.background_task: Optional[asyncio.Task] = None
        self._subscribers: Set[asyncio.Queue] = set()

        # Initialize Lab State hosts matching reference designs
        self.hosts: Dict[str, HostState] = {
            "kali": HostState(
                id="kali",
                name="Kali + C2",
                role="attacker zone",
                os="kali linux",
                status="healthy",
                agent="offline",
                last_alert=None,
                ip="185.220.101.4"
            ),
            "pfsense": HostState(
                id="pfsense",
                name="pfSense",
                role="perimeter",
                os="freebsd",
                status="healthy",
                agent="suricata online",
                last_alert=None,
                ip="10.0.0.1"
            ),
            "switch": HostState(
                id="switch",
                name="Switch",
                role="10.0.0.0/24",
                os="cumulus linux",
                status="healthy",
                agent="zeek online",
                last_alert=None,
                ip="10.0.0.2"
            ),
            "web01": HostState(
                id="web01",
                name="web01",
                role="dmz web server",
                os="ubuntu 22.04",
                status="compromised",
                agent="wazuh online",
                last_alert="T1190 sqli",
                ip="10.0.1.10"
            ),
            "mail01": HostState(
                id="mail01",
                name="mail01",
                role="dmz",
                os="debian 12",
                status="healthy",
                agent="wazuh online",
                last_alert=None,
                ip="10.0.1.20"
            ),
            "ad01": HostState(
                id="ad01",
                name="AD server",
                role="corp lan",
                os="windows server 2022",
                status="suspicious",
                agent="wazuh online",
                last_alert="T1558 kerberoast",
                ip="10.0.2.10"
            ),
            "ws-01": HostState(
                id="ws-01",
                name="Workstations",
                role="corp lan x2",
                os="windows 11",
                status="healthy",
                agent="wazuh online",
                last_alert=None,
                ip="10.0.2.15"
            ),
            "ws-02": HostState(
                id="ws-02",
                name="Workstation 02",
                role="corp lan workstation",
                os="windows 11",
                status="healthy",
                agent="wazuh online",
                last_alert=None,
                ip="10.0.2.16"
            ),
            "siem": HostState(
                id="siem",
                name="Wazuh + Suricata + MISP",
                role="security zone",
                os="ubuntu 22.04",
                status="healthy",
                agent="core engine",
                last_alert=None,
                ip="10.0.3.10"
            ),
        }

        # Seed initial events matching reference screenshots
        initial_events = [
            ("12:01:09", "T1071", "Application Layer Protocol", "dns tunnel", "10.0.2.31", "switch", "DETECTED", "MEDIUM", "Watch", False),
            ("12:02:47", "T1021", "Remote Services", "smb lateral move", "10.0.2.15", "ws-02", "ISOLATED", "CRITICAL", "Watch", True),
            ("12:03:20", "T1558", "Steal or Forge Kerberos Tickets", "kerberoast", "10.0.2.15", "ad01", "ALERT", "CRITICAL", "Watch", True),
            ("12:03:52", "T1190", "Exploit Public-Facing Application", "sqli on web01", "45.9.148.22", "web01", "DETECTED", "HIGH", "Watch", False),
            ("12:04:11", "T1110", "Brute Force", "brute force", "185.220.101.4", "pfsense", "BLOCKED", "HIGH", "Watch", False),
        ]
        for t, tech_id, tech_name, ev_txt, src_ip, tgt, st, sev, mod, br in initial_events:
            self.recent_events.append(SimEvent(
                id=f"evt-{uuid.uuid4().hex[:8]}",
                time=t,
                technique_id=tech_id,
                technique_name=tech_name,
                event=ev_txt,
                source_ip=src_ip,
                target_host=tgt,
                state=st,
                severity=sev,
                module=mod,
                breach=br,
                raw_log={
                    "timestamp": t,
                    "action": ev_txt,
                    "src_ip": src_ip,
                    "target": tgt,
                    "technique": tech_id
                }
            ))

        self.load_scenarios()

    def load_scenarios(self):
        """Load all scenario YAML definitions from scenarios directory."""
        scenarios_dir = settings.SCENARIOS_DIR
        if not scenarios_dir.exists():
            return

        for yml_path in scenarios_dir.glob("*.yaml"):
            try:
                with open(yml_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    steps = [ScenarioStep(**step) for step in data.get("steps", [])]
                    scenario = Scenario(
                        id=data["id"],
                        name=data["name"],
                        technique_id=data["technique_id"],
                        description=data.get("description", ""),
                        steps=steps,
                        status="idle",
                        current_step=0
                    )
                    self.active_scenarios[scenario.id] = scenario
            except Exception as e:
                print(f"Error loading scenario {yml_path}: {e}")

    def update_host_status(self, host_id: str, new_status: str, last_alert: Optional[str] = None):
        """Update host health status and broadcast changes."""
        if host_id in self.hosts:
            host = self.hosts[host_id]
            host.status = new_status
            if last_alert:
                host.last_alert = last_alert
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self.broadcast({"type": "host", "data": host.model_dump()}))
            except RuntimeError:
                pass

    def subscribe(self) -> asyncio.Queue:
        """Subscribe to engine event broadcast queue."""
        q = asyncio.Queue()
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        """Unsubscribe from event broadcast queue."""
        self._subscribers.discard(q)

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all active WebSocket clients/subscribers."""
        dead_queues = []
        for q in list(self._subscribers):
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                dead_queues.append(q)
        for dq in dead_queues:
            self._subscribers.discard(dq)

    def create_sim_event(
        self,
        technique_id: str,
        technique_name: str,
        event: str,
        source_ip: str,
        target_host: str,
        state: str,
        severity: str,
        module: str,
        breach: bool = False,
        raw_log: Optional[Dict[str, Any]] = None
    ) -> SimEvent:
        curr_time = datetime.now().strftime("%H:%M:%S")
        evt_id = f"evt-{uuid.uuid4().hex[:8]}"

        if not raw_log:
            raw_log = {
                "id": evt_id,
                "timestamp": curr_time,
                "technique": technique_id,
                "event_name": event,
                "source_ip": source_ip,
                "target_host": target_host,
                "state": state,
                "severity": severity,
                "module": module,
                "breach": breach
            }

        sim_evt = SimEvent(
            id=evt_id,
            time=curr_time,
            technique_id=technique_id,
            technique_name=technique_name,
            event=event,
            source_ip=source_ip,
            target_host=target_host,
            state=state,
            severity=severity,
            module=module,
            breach=breach,
            raw_log=raw_log
        )

        # Store in recent events (cap at 200)
        self.recent_events.insert(0, sim_evt)
        if len(self.recent_events) > 200:
            self.recent_events.pop()

        # Update metrics
        self.metrics.alerts_today += 1
        if breach:
            self.metrics.threat_level = "CRITICAL"
        elif self.metrics.threat_level != "CRITICAL":
            self.metrics.threat_level = "ELEVATED"

        return sim_evt

    async def emit_event(self, event_spec: Dict[str, Any]) -> SimEvent:
        """Create event, evaluate reflex playbooks, and broadcast."""
        tech_id = event_spec.get("technique_id", "T1110")
        tech_meta = get_technique(tech_id)
        tech_name = event_spec.get("technique_name", tech_meta.name if tech_meta else "Simulated Attack")

        evt = self.create_sim_event(
            technique_id=tech_id,
            technique_name=tech_name,
            event=event_spec.get("event", "simulated security event"),
            source_ip=event_spec.get("source_ip", "185.220.101.4"),
            target_host=event_spec.get("target_host", "web01"),
            state=event_spec.get("state", "DETECTED"),
            severity=event_spec.get("severity", "MEDIUM"),
            module=event_spec.get("module", "Watch"),
            breach=event_spec.get("breach", False),
            raw_log=event_spec.get("raw_log")
        )

        # Broadcast event
        await self.broadcast({"type": "event", "data": evt.model_dump()})

        # If breach, broadcast breach alert
        if evt.breach:
            await self.broadcast({"type": "breach", "data": evt.model_dump()})

        # Evaluate Reflex automated responses
        actions = reflex_engine.evaluate_event(
            evt.model_dump(),
            host_updater=self.update_host_status
        )
        for act in actions:
            await self.broadcast({"type": "reflex_action", "data": act.model_dump()})

        # Broadcast updated metrics
        await self.broadcast({"type": "metrics", "data": self.metrics.model_dump()})

        return evt

    async def start_scenario(self, scenario_id: str) -> bool:
        """Start playing a scenario step-by-step asynchronously."""
        scenario = self.active_scenarios.get(scenario_id)
        if not scenario:
            return False

        # If already running, don't restart
        if scenario.id in self.running_scenario_tasks and not self.running_scenario_tasks[scenario.id].done():
            return True

        scenario.status = "running"
        scenario.current_step = 0

        async def _run_scenario():
            try:
                for idx, step in enumerate(scenario.steps):
                    scenario.current_step = idx + 1
                    await self.broadcast({
                        "type": "scenario_step",
                        "data": {
                            "scenario_id": scenario.id,
                            "scenario_name": scenario.name,
                            "stage": step.stage,
                            "step_index": idx + 1,
                            "total_steps": len(scenario.steps)
                        }
                    })

                    # Wait configured step delay
                    await asyncio.sleep(step.delay)

                    # Emit step event
                    await self.emit_event(step.event)

                    # Update host state if defined
                    if step.host_update:
                        h_id = step.host_update.get("host")
                        h_st = step.host_update.get("status")
                        h_al = step.host_update.get("last_alert")
                        if h_id and h_st:
                            self.update_host_status(h_id, h_st, h_al)

                scenario.status = "completed"
                await self.broadcast({
                    "type": "scenario_step",
                    "data": {
                        "scenario_id": scenario.id,
                        "status": "completed",
                        "message": f"Scenario {scenario.name} finished successfully."
                    }
                })
            except asyncio.CancelledError:
                scenario.status = "stopped"
                await self.broadcast({
                    "type": "scenario_step",
                    "data": {"scenario_id": scenario.id, "status": "stopped"}
                })
            finally:
                if scenario.id in self.running_scenario_tasks:
                    del self.running_scenario_tasks[scenario.id]

        task = asyncio.create_task(_run_scenario())
        self.running_scenario_tasks[scenario.id] = task
        return True

    def stop_scenario(self, scenario_id: str) -> bool:
        """Stop an active scenario run."""
        task = self.running_scenario_tasks.get(scenario_id)
        if task and not task.done():
            task.cancel()
        if scenario_id in self.active_scenarios:
            self.active_scenarios[scenario_id].status = "stopped"
            return True
        return False

    async def _autopilot_loop(self):
        """Continuous background task generating realistic activity every 1-4 seconds."""
        while True:
            try:
                delay = random.uniform(settings.EVENT_INTERVAL_MIN, settings.EVENT_INTERVAL_MAX)
                await asyncio.sleep(delay)

                if self.autopilot_enabled:
                    template = random.choice(EVENT_TEMPLATES)
                    # Randomize occasionally to keep metrics dynamic
                    event_data = dict(template)
                    # Small random variance in IP or host occasionally
                    if random.random() < 0.2 and event_data["state"] == "ALERT":
                        event_data["breach"] = True
                    await self.emit_event(event_data)

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in simulation autopilot loop: {e}")
                await asyncio.sleep(2)

    def start_background_loop(self):
        """Start the autopilot asyncio task."""
        if self.background_task is None or self.background_task.done():
            self.background_task = asyncio.create_task(self._autopilot_loop())

    def stop_background_loop(self):
        """Stop the autopilot asyncio task."""
        if self.background_task and not self.background_task.done():
            self.background_task.cancel()

    def get_full_state(self) -> Dict[str, Any]:
        """Return full lab state snapshot."""
        return {
            "metrics": self.metrics.model_dump(),
            "hosts": {k: v.model_dump() for k, v in self.hosts.items()},
            "playbooks": [p.model_dump() for p in reflex_engine.get_playbooks()],
            "reflex_actions": [a.model_dump() for a in reflex_engine.action_history[:15]],
            "recent_events": [e.model_dump() for e in self.recent_events[:50]],
            "scenarios": [s.model_dump() for s in self.active_scenarios.values()],
            "autopilot_enabled": self.autopilot_enabled
        }

# Global singleton simulation engine
sim_engine = SimulationEngine()
