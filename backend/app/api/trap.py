"""
NO ENTRY - Trap Deception & Honeypot Service
Manages honeypot activity, decoys, honeytokens, and triggers automated Reflex SOAR reactions.
"""

from datetime import datetime
from typing import Dict, List, Any, Optional
from pydantic import BaseModel
import uuid

class Honeytoken(BaseModel):
    id: str
    name: str
    type: str
    target_host: str
    status: str # "ARMED" or "TRIGGERED"
    last_tripped: Optional[str] = None
    technique_id: str
    description: str

class HoneypotSession(BaseModel):
    id: str
    time: str
    honeypot: str
    credentials: str
    source_ip: str
    country: str
    country_code: str
    action: str

class TrapService:
    def __init__(self):
        self.sessions_captured: int = 37
        self.unique_countries: int = 9
        self.honeytokens_tripped: int = 1

        self.tokens: Dict[str, Honeytoken] = {
            "svc_backup": Honeytoken(
                id="svc_backup",
                name="svc_backup fake AD account",
                type="Active Directory Account",
                target_host="ad01",
                status="TRIGGERED",
                last_tripped="12:03:20",
                technique_id="T1558",
                description="Decoy service account with high-privilege SPN configured for Kerberoast bait"
            ),
            "passwords_xlsx": Honeytoken(
                id="passwords_xlsx",
                name="passwords.xlsx decoy",
                type="Decoy Document",
                target_host="ws-01",
                status="ARMED",
                last_tripped=None,
                technique_id="T1552",
                description="Seeded Excel spreadsheet on workstation desktop containing canary credentials"
            ),
            "aws_key_txt": Honeytoken(
                id="aws_key_txt",
                name="aws_key.txt canary",
                type="Cloud Credential Canary",
                target_host="web01",
                status="ARMED",
                last_tripped=None,
                technique_id="T1078",
                description="Mock AWS API access key configured to alert on any access in /root/.aws/credentials"
            ),
        }

        self.sessions: List[HoneypotSession] = [
            HoneypotSession(
                id="sess-01",
                time="12:01:14",
                honeypot="cowrie ssh",
                credentials="root:123456",
                source_ip="185.220.101.4",
                country="Romania",
                country_code="RO",
                action="BLOCKED"
            ),
            HoneypotSession(
                id="sess-02",
                time="12:02:40",
                honeypot="cowrie ssh",
                credentials="admin:admin",
                source_ip="45.9.148.22",
                country="Netherlands",
                country_code="NL",
                action="BLOCKED"
            ),
            HoneypotSession(
                id="sess-03",
                time="12:03:19",
                honeypot="dionaea smb",
                credentials="exploit probe (MS17-010)",
                source_ip="91.92.240.7",
                country="United States",
                country_code="US",
                action="ALERT"
            ),
            HoneypotSession(
                id="sess-04",
                time="12:03:48",
                honeypot="cowrie ssh",
                credentials="support:P@ssword2026",
                source_ip="194.26.29.112",
                country="Russia",
                country_code="RU",
                action="BLOCKED"
            ),
            HoneypotSession(
                id="sess-05",
                time="12:04:02",
                honeypot="dionaea smb",
                credentials="IPC$ anonymous bind",
                source_ip="185.220.101.4",
                country="Romania",
                country_code="RO",
                action="DETECTED"
            ),
        ]

        self.attacker_origins: List[Dict[str, Any]] = [
            {"country": "Romania", "code": "RO", "lat": 44.43, "lon": 26.10, "count": 14},
            {"country": "Netherlands", "code": "NL", "lat": 52.37, "lon": 4.90, "count": 11},
            {"country": "United States", "code": "US", "lat": 38.89, "lon": -77.03, "count": 7},
            {"country": "Germany", "code": "DE", "lat": 52.52, "lon": 13.40, "count": 5},
            {"country": "Russia", "code": "RU", "lat": 55.75, "lon": 37.61, "count": 4},
            {"country": "Bulgaria", "code": "BG", "lat": 42.69, "lon": 23.32, "count": 3},
            {"country": "Brazil", "code": "BR", "lat": -15.78, "lon": -47.92, "count": 2},
            {"country": "Singapore", "code": "SG", "lat": 1.35, "lon": 103.81, "count": 2},
            {"country": "Sweden", "code": "SE", "lat": 59.32, "lon": 18.06, "count": 1},
        ]

    def get_state(self) -> Dict[str, Any]:
        return {
            "sessions_captured": self.sessions_captured,
            "unique_countries": self.unique_countries,
            "honeytokens_tripped": self.honeytokens_tripped,
            "honeytokens": [t.model_dump() for t in self.tokens.values()],
            "sessions": [s.model_dump() for s in self.sessions],
            "attacker_origins": self.attacker_origins
        }

    async def touch_token(self, token_id: str, sim_engine) -> Dict[str, Any]:
        clean_id = token_id.lower().replace("-", "_").replace(".", "_")
        token = self.tokens.get(clean_id) or self.tokens.get(token_id)

        if not token:
            return {"error": f"Token '{token_id}' not found"}

        now_str = datetime.now().strftime("%H:%M:%S")
        token.status = "TRIGGERED"
        token.last_tripped = now_str
        self.honeytokens_tripped += 1

        # Emit simulated alert into the live cyber engine
        event_payload = {
            "technique_id": token.technique_id,
            "technique_name": "Deception Canary Tripped",
            "event": f"TRAP ALERT: Honeytoken {token.name} tripped on {token.target_host}!",
            "source_ip": "10.0.2.15" if token.target_host != "web01" else "185.220.101.4",
            "target_host": token.target_host,
            "state": "ALERT",
            "severity": "CRITICAL",
            "module": "Trap",
            "breach": True
        }

        await sim_engine.emit_event(event_payload)

        # Append honeypot session entry
        new_sess = HoneypotSession(
            id=f"sess-{uuid.uuid4().hex[:4]}",
            time=now_str,
            honeypot="canary monitor",
            credentials=f"trip: {token.name}",
            source_ip=event_payload["source_ip"],
            country="Internal / Pivot" if event_payload["source_ip"].startswith("10.") else "Romania",
            country_code="INT" if event_payload["source_ip"].startswith("10.") else "RO",
            action="ALERT"
        )
        self.sessions.insert(0, new_sess)
        self.sessions_captured += 1

        return {
            "status": "tripped",
            "token": token.model_dump(),
            "state": self.get_state()
        }

trap_service = TrapService()
