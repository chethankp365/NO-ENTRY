"""
NO ENTRY - Shield Hardening API Service
Manages baseline vs hardened posture scores, system hardening checklists,
and interactive remediation fixes that recalculate posture live.
"""

from typing import Dict, List, Any
from pydantic import BaseModel

class ChecklistItem(BaseModel):
    id: str
    name: str
    status: str # "PASS" or "OPEN"
    area: str   # "Active Directory", "Web server", "Linux hosts", "Network"
    impact: int
    description: str

class ShieldState:
    def __init__(self):
        self.before_score: int = 38
        self.checklist: Dict[str, ChecklistItem] = {
            "smb_signing": ChecklistItem(
                id="smb_signing",
                name="SMB signing enforced",
                status="PASS",
                area="Active Directory",
                impact=12,
                description="GPO enforces SMBv3 packet signing across all domain controllers and member servers"
            ),
            "laps": ChecklistItem(
                id="laps",
                name="LAPS deployed",
                status="PASS",
                area="Active Directory",
                impact=14,
                description="Local Administrator Password Solution rotates unique passwords on local accounts"
            ),
            "ntlm_disabled": ChecklistItem(
                id="ntlm_disabled",
                name="NTLM disabled",
                status="PASS",
                area="Active Directory",
                impact=10,
                description="Kerberos-only authentication strictly required for domain RPC and SMB"
            ),
            "waf": ChecklistItem(
                id="waf",
                name="ModSecurity WAF on",
                status="PASS",
                area="Web server",
                impact=16,
                description="OWASP Core Rule Set active on nginx reverse proxy inspecting ingress traffic"
            ),
            "tiered_admin": ChecklistItem(
                id="tiered_admin",
                name="Tiered admin model",
                status="OPEN",
                area="Active Directory",
                impact=18,
                description="Domain Admin accounts prevented from logging into Tier 1 and Tier 2 workstations"
            ),
            "tls_modern": ChecklistItem(
                id="tls_modern",
                name="TLS 1.0 and 1.1 off",
                status="PASS",
                area="Network",
                impact=10,
                description="Perimeter load balancer and gateway enforce TLS 1.2 and TLS 1.3 only"
            ),
            "default_creds": ChecklistItem(
                id="default_creds",
                name="Default creds removed",
                status="OPEN",
                area="Linux hosts",
                impact=16,
                description="Factory default SSH credentials on auxiliary switches and appliances disabled"
            ),
        }
        self.areas: Dict[str, int] = {
            "Active Directory": 82,
            "Web server": 91,
            "Linux hosts": 74,
            "Network": 88
        }

    def get_state(self) -> Dict[str, Any]:
        # Compute after score dynamically based on passed items
        base = self.before_score
        total_possible = sum(item.impact for item in self.checklist.values())
        passed_points = sum(item.impact for item in self.checklist.values() if item.status == "PASS")
        after = base + int((passed_points / total_possible) * (100 - base))
        after = max(base, min(100, after))

        return {
            "before_score": self.before_score,
            "after_score": after,
            "score_gained": after - self.before_score,
            "checklist": [item.model_dump() for item in self.checklist.values()],
            "areas": self.areas
        }

    def apply_fix(self, item_id: str) -> Dict[str, Any]:
        clean_id = item_id.lower().replace("-", "_")
        if clean_id not in self.checklist:
            return {"error": f"Item '{item_id}' not found"}

        item = self.checklist[clean_id]
        item.status = "PASS"

        # Boost area score
        if item.area in self.areas:
            self.areas[item.area] = min(99, self.areas[item.area] + 12)

        return self.get_state()

shield_service = ShieldState()
