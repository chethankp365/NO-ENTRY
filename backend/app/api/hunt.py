"""
Threat Hunting Query Evaluator for NO ENTRY.
Evaluates lucene/KQL-style threat hunting queries over simulated range events.
Returns matching hits, per-minute bucketed histogram, and intelligence hypotheses.
"""

from datetime import datetime, timedelta
import random
import re
from typing import Dict, List, Any, Optional
from pydantic import BaseModel

from backend.app.sim.engine import sim_engine

PRESET_QUERIES = [
    {
        "id": "preset-1",
        "title": "Internal Logon Failures",
        "query": "source.ip: 10.0.2.15 AND event.action: logon_failed",
        "hypothesis": "Password spraying or credential brute-force originating from compromised internal workstation ws-01 targeting Domain Controller."
    },
    {
        "id": "preset-2",
        "title": "Web Application SQL Injection",
        "query": "target.host: web01 AND event: sqli",
        "hypothesis": "External adversary scanning and attempting SQL injection exploitation against public-facing customer portal."
    },
    {
        "id": "preset-3",
        "title": "Kerberoasting SPN Ticket Requests",
        "query": "technique: T1558 AND event.action: ticket_request",
        "hypothesis": "Active Directory credential theft via Kerberos Service Ticket extraction with weak encryption types (RC4-HMAC)."
    },
    {
        "id": "preset-4",
        "title": "Reflex Host Quarantine Actions",
        "query": "state: ISOLATED AND event: ransomware",
        "hypothesis": "Automated incident response playbook execution isolating endpoint ws-02 following volume shadow copy tampering."
    }
]

class HuntQueryRequest(BaseModel):
    query: str
    timeframe_minutes: int = 10

def evaluate_hunt_query(raw_query: str, timeframe_minutes: int = 10) -> Dict[str, Any]:
    """
    Evaluates hunt query string across active events and synthetic telemetry.
    Supports queries like: 'source.ip: 10.0.2.15 AND event.action: logon_failed'
    """
    q = raw_query.strip()
    if not q:
        q = PRESET_QUERIES[0]["query"]

    # Parse key-value tokens from query (e.g. source.ip: 10.0.2.15 AND event.action: logon_failed)
    tokens = re.findall(r'(\w+(?:\.\w+)?)\s*:\s*([^\s\)]+)', q, re.IGNORECASE)
    field_filters: Dict[str, str] = {k.lower(): v.strip("\"'").lower() for k, v in tokens}

    # Extract free-text keywords if no field tokens
    free_words = []
    if not field_filters:
        clean_words = re.sub(r'[\(\)]', ' ', q).split()
        free_words = [w.lower() for w in clean_words if w.upper() not in ("AND", "OR", "NOT")]

    # Match against preset hypotheses if matching
    matched_hypothesis = None
    for p in PRESET_QUERIES:
        if p["query"].lower() in q.lower() or q.lower() in p["query"].lower():
            matched_hypothesis = p["hypothesis"]
            break

    if not matched_hypothesis:
        if "10.0.2.15" in q or "ws-01" in q:
            matched_hypothesis = "Suspicious lateral movement or credential activity originating from corporate host ws-01."
        elif "sqli" in q or "web01" in q or "t1190" in q:
            matched_hypothesis = "Web application probing and exploitation against DMZ web services."
        elif "ransomware" in q or "t1486" in q or "isolated" in q:
            matched_hypothesis = "Endpoint compromise and ransomware file encryption requiring immediate isolation."
        elif "t1110" in q or "brute" in q or "hydra" in q:
            matched_hypothesis = "Distributed authentication brute-force attempt against perimeter SSH/RDP services."
        else:
            matched_hypothesis = f"Threat hunting telemetry evaluation for pattern '{q}'."

    # Search existing events in sim_engine
    matched_events = []
    for evt in sim_engine.recent_events:
        matches = True
        evt_dict = {
            "source.ip": evt.source_ip.lower(),
            "source_ip": evt.source_ip.lower(),
            "src_ip": evt.source_ip.lower(),
            "src": evt.source_ip.lower(),
            "target.host": evt.target_host.lower(),
            "target_host": evt.target_host.lower(),
            "target": evt.target_host.lower(),
            "host": evt.target_host.lower(),
            "technique": evt.technique_id.lower(),
            "technique_id": evt.technique_id.lower(),
            "technique.id": evt.technique_id.lower(),
            "mitre": evt.technique_id.lower(),
            "state": evt.state.lower(),
            "status": evt.state.lower(),
            "severity": evt.severity.lower(),
            "module": evt.module.lower(),
            "event": evt.event.lower(),
            "event.action": evt.event.lower(),
            "action": evt.event.lower()
        }

        if field_filters:
            for k, v in field_filters.items():
                if k in evt_dict:
                    if v not in evt_dict[k]:
                        matches = False
                        break
                else:
                    # Fallback full-text match in event text
                    if v not in evt.event.lower() and v not in evt.source_ip.lower() and v not in evt.target_host.lower():
                        matches = False
                        break
        elif free_words:
            # Free-text search matching across all event attributes
            combined_text = f"{evt.event} {evt.source_ip} {evt.target_host} {evt.technique_id} {evt.technique_name} {evt.state} {evt.severity}".lower()
            for w in free_words:
                if w not in combined_text:
                    matches = False
                    break

        if matches:
            matched_events.append({
                "id": evt.id,
                "time": evt.time,
                "technique_id": evt.technique_id,
                "technique_name": evt.technique_name,
                "event": evt.event,
                "source_ip": evt.source_ip,
                "target_host": evt.target_host,
                "state": evt.state,
                "severity": evt.severity
            })

    # Realistic scaled hit count
    base_hits = len(matched_events)
    if base_hits == 0:
        total_hits = 0
    else:
        multiplier = 6 if "10.0.2.15" in q else (8 if "sqli" in q else 4)
        total_hits = max(base_hits, base_hits * multiplier + (abs(hash(q)) % 15))

    # Build 10-minute bucketed histogram
    now = datetime.now()
    histogram = []
    if total_hits == 0:
        for i in range(10):
            minute_time = (now - timedelta(minutes=9 - i)).strftime("%H:%M")
            histogram.append({"minute": minute_time, "count": 0})
    else:
        for i in range(10):
            minute_time = (now - timedelta(minutes=9 - i)).strftime("%H:%M")
            factor = 1.0 + (0.8 if i in (5, 6, 7) else 0.2) * (random.random() * 0.4 + 0.8)
            bucket_count = int((total_hits / 10.0) * factor)
            histogram.append({
                "minute": minute_time,
                "count": max(1, bucket_count)
            })
        histogram[-1]["count"] = max(1, total_hits - sum(b["count"] for b in histogram[:-1]))

    return {
        "query": q,
        "hits": total_hits,
        "timeframe": f"last {timeframe_minutes} min",
        "hypothesis": matched_hypothesis,
        "histogram": histogram,
        "matched_events": matched_events[:20],
        "presets": PRESET_QUERIES
    }
