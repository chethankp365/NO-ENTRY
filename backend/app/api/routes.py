"""
REST API Router for NO ENTRY
Exposes endpoints for lab state, events, MITRE mapping, metrics,
scenarios, Reflex automation, and host operations.
"""

import hashlib
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from backend.app.sim.engine import sim_engine
from backend.app.sim.mitre import get_technique, list_techniques
from backend.app.reflex.engine import reflex_engine

api_router = APIRouter(prefix="/api")

class BlockIPRequest(BaseModel):
    ip: str
    reason: Optional[str] = "Manual operator ban"

class PlaybookToggleRequest(BaseModel):
    playbook_id: str
    enabled: bool

class AutopilotToggleRequest(BaseModel):
    enabled: bool

def compute_fake_abuseipdb(ip: str) -> Dict[str, Any]:
    """Deterministic simulated IP threat intelligence enrichment."""
    # Exact values from reference screenshots
    known_scores = {
        "185.220.101.4": 97,
        "45.9.148.22": 84,
        "91.92.240.7": 89,
        "194.26.29.112": 92
    }
    if ip in known_scores:
        score = known_scores[ip]
    elif ip.startswith("10.0.") or ip.startswith("192.168.") or ip == "127.0.0.1":
        score = 0
    else:
        # Deterministic hash to range 65 - 98
        h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
        score = 65 + (h % 34)

    is_malicious = score > 50
    return {
        "ip": ip,
        "abuse_confidence_score": score,
        "is_public": not (ip.startswith("10.0.") or ip == "127.0.0.1"),
        "country_code": "RO" if "185.220" in ip else ("NL" if "45.9" in ip else "US"),
        "country_name": "Romania" if "185.220" in ip else ("Netherlands" if "45.9" in ip else "United States"),
        "usage_type": "Data Center/Web Hosting/Transit" if is_malicious else "Internal Network",
        "isp": "Flyservers S.A." if "185.220" in ip else "Mevspace sp. z o.o.",
        "total_reports": (score * 12) if score > 0 else 0,
        "last_reported_at": "2026-11-01T20:45:00Z" if score > 0 else None,
        "threat_tags": ["brute-force", "ssh-scanner", "botnet"] if score > 80 else ["suspicious"]
    }

@api_router.get("/state")
def get_lab_state():
    """Retrieve complete snapshot of lab hosts, metrics, reflex playbooks, and events."""
    return sim_engine.get_full_state()

@api_router.get("/events")
def get_events(
    limit: int = Query(50, ge=1, le=200),
    state: Optional[str] = Query(None, description="Filter by state (DETECTED, BLOCKED, ALERT, ISOLATED)"),
    technique: Optional[str] = Query(None, description="Filter by MITRE technique ID (e.g. T1110)")
):
    """List recent simulation events with optional filtering."""
    events = sim_engine.recent_events
    if state:
        events = [e for e in events if e.state.upper() == state.upper()]
    if technique:
        events = [e for e in events if e.technique_id.upper() == technique.upper()]
    return [e.model_dump() for e in events[:limit]]

@api_router.get("/events/{event_id}")
def get_event_detail(event_id: str):
    """Retrieve full detail for a single event: raw log, MITRE technique card, and IP enrichment."""
    event = next((e for e in sim_engine.recent_events if e.id == event_id), None)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    mitre_info = get_technique(event.technique_id)
    enrichment = compute_fake_abuseipdb(event.source_ip)

    return {
        "event": event.model_dump(),
        "mitre_technique": mitre_info.model_dump() if mitre_info else None,
        "enrichment": enrichment,
        "raw_log": event.raw_log or {
            "timestamp": event.time,
            "event_id": event.id,
            "technique": event.technique_id,
            "message": event.event,
            "source_ip": event.source_ip,
            "target": event.target_host,
            "status": event.state
        }
    }

@api_router.get("/metrics")
def get_metrics():
    """Get real-time operational and detection metrics."""
    return sim_engine.metrics.model_dump()

@api_router.get("/hosts")
def get_hosts():
    """Get list and status of all simulated lab network hosts."""
    return {k: v.model_dump() for k, v in sim_engine.hosts.items()}

@api_router.get("/mitre")
def get_mitre_catalog():
    """Get the full MITRE ATT&CK technique catalog."""
    return [t.model_dump() for t in list_techniques()]

@api_router.get("/scenarios")
def get_scenarios():
    """List all available attack scenarios and their current execution status."""
    return [s.model_dump() for s in sim_engine.active_scenarios.values()]

@api_router.post("/scenarios/{scenario_id}/start")
async def start_scenario(scenario_id: str):
    """Start executing a simulated attack scenario."""
    success = await sim_engine.start_scenario(scenario_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found or invalid.")
    return {"status": "started", "scenario_id": scenario_id}

@api_router.post("/scenarios/{scenario_id}/stop")
def stop_scenario(scenario_id: str):
    """Stop/cancel a currently running attack scenario."""
    success = sim_engine.stop_scenario(scenario_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")
    return {"status": "stopped", "scenario_id": scenario_id}

@api_router.post("/hosts/{host_id}/isolate")
async def isolate_host(host_id: str):
    """Manually apply network quarantine to a host."""
    if host_id not in sim_engine.hosts:
        raise HTTPException(status_code=404, detail=f"Host '{host_id}' not found.")
    sim_engine.update_host_status(host_id, "isolated", "Manual operator quarantine")
    await sim_engine.broadcast({"type": "host", "data": sim_engine.hosts[host_id].model_dump()})
    return {"status": "isolated", "host_id": host_id}

@api_router.post("/block-ip")
async def block_ip(req: BlockIPRequest):
    """Manually block an IP address across perimeter defenses."""
    reflex_engine.blocked_ips.add(req.ip)
    # Emit a simulated firewall block event
    await sim_engine.emit_event({
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "event": f"operator firewall rule: block {req.ip}",
        "source_ip": req.ip,
        "target_host": "pfsense",
        "state": "BLOCKED",
        "severity": "MEDIUM",
        "module": "Reflex",
        "breach": False
    })
    return {"status": "blocked", "ip": req.ip}

@api_router.get("/reflex/playbooks")
def get_playbooks():
    """Get list of automated response playbooks."""
    return [p.model_dump() for p in reflex_engine.get_playbooks()]

@api_router.post("/reflex/playbooks")
def toggle_playbook(req: PlaybookToggleRequest):
    """Enable or disable an automated response playbook."""
    pb = reflex_engine.toggle_playbook(req.playbook_id, req.enabled)
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook '{req.playbook_id}' not found.")
    return pb.model_dump()

@api_router.post("/sim/autopilot")
def toggle_autopilot(req: AutopilotToggleRequest):
    """Toggle background autopilot simulation loop."""
    sim_engine.autopilot_enabled = req.enabled
    return {"autopilot_enabled": sim_engine.autopilot_enabled}

from backend.app.api.hunt import evaluate_hunt_query, HuntQueryRequest, PRESET_QUERIES
from backend.app.api.purple import get_purple_scenario, PurpleRunRequest

@api_router.post("/hunt")
def run_threat_hunt(req: HuntQueryRequest):
    """Evaluate threat hunting query over simulated event corpus."""
    return evaluate_hunt_query(req.query, req.timeframe_minutes)

@api_router.get("/hunt/presets")
def get_hunt_presets():
    """Retrieve curated threat hunting preset queries."""
    return PRESET_QUERIES

@api_router.post("/purple/run")
def run_purple_scenario(req: PurpleRunRequest):
    """Execute paired purple team scenario returning synchronized attacker and defender actions."""
    return get_purple_scenario(req.scenario)

