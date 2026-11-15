"""
NO ENTRY - Threat Intelligence Service
Provides IOC indicator table, feed health metrics, deterministic IOC lookup evaluation,
and node-link relationship graph connecting IPs, domains, and hashes to threat campaigns.
"""

import hashlib
from typing import Dict, List, Any, Optional

DEFAULT_INDICATORS = [
    {
        "id": "ioc-1",
        "value": "185.220.101.4",
        "type": "IP",
        "score": 97,
        "source": "AbuseIPDB",
        "campaign": "CosmicDuke / APT29",
        "malware": "Cobalt Strike Beacon",
        "country": "Romania (RO)",
        "last_seen": "12:04:11",
        "tags": ["tor-exit", "ssh-spray", "c2"]
    },
    {
        "id": "ioc-2",
        "value": "evil-update.net",
        "type": "Domain",
        "score": 91,
        "source": "AlienVault OTX",
        "campaign": "Lazarus FakeUpdate",
        "malware": "RedLine Stealer",
        "country": "Russia (RU)",
        "last_seen": "12:02:47",
        "tags": ["phishing", "fast-flux", "payload-delivery"]
    },
    {
        "id": "ioc-3",
        "value": "44d88612fea8a8f3b29c118",
        "type": "Hash",
        "score": 88,
        "source": "VirusTotal",
        "campaign": "LockBit 3.0",
        "malware": "LockBit Ransomware",
        "country": "Global",
        "last_seen": "12:03:20",
        "tags": ["ransomware", "shadow-copy-killer"]
    },
    {
        "id": "ioc-4",
        "value": "45.9.148.22",
        "type": "IP",
        "score": 84,
        "source": "MISP",
        "campaign": "FIN7 Cobalt",
        "malware": "SQLi Scanner / Pivoter",
        "country": "Netherlands (NL)",
        "last_seen": "12:03:52",
        "tags": ["exploit-probe", "web-scanner"]
    },
    {
        "id": "ioc-5",
        "value": "91.92.240.7",
        "type": "IP",
        "score": 89,
        "source": "AbuseIPDB",
        "campaign": "Volt Typhoon Proxy",
        "malware": "Iodine DNS Exfil Agent",
        "country": "United States (US)",
        "last_seen": "12:01:09",
        "tags": ["dns-tunnel", "covert-channel"]
    }
]

FEEDS = [
    {"name": "AbuseIPDB", "score": 100, "status": "ONLINE", "latency": "24 ms", "records": "4.2M", "color": "var(--color-green)"},
    {"name": "AlienVault OTX", "score": 100, "status": "ONLINE", "latency": "62 ms", "records": "19.8M", "color": "var(--color-green)"},
    {"name": "VirusTotal API", "score": 72, "status": "THROTTLED", "latency": "140 ms", "records": "1.1B", "color": "#FFB800"},
    {"name": "MISP Threat Sharing", "score": 100, "status": "ONLINE", "latency": "18 ms", "records": "880K", "color": "var(--color-green)"}
]

GRAPH_DATA = {
    "nodes": [
        {"id": "camp_apt29", "name": "APT29 (CosmicDuke)", "group": "campaign", "radius": 14, "color": "#FF1F3D"},
        {"id": "camp_lockbit", "name": "LockBit Syndicate", "group": "campaign", "radius": 14, "color": "#FF1F3D"},
        {"id": "camp_fin7", "name": "FIN7 Group", "group": "campaign", "radius": 14, "color": "#FF1F3D"},
        {"id": "ip_185", "name": "185.220.101.4", "group": "ip", "radius": 9, "color": "#00E5FF"},
        {"id": "ip_45", "name": "45.9.148.22", "group": "ip", "radius": 9, "color": "#00E5FF"},
        {"id": "ip_91", "name": "91.92.240.7", "group": "ip", "radius": 9, "color": "#00E5FF"},
        {"id": "dom_evil", "name": "evil-update.net", "group": "domain", "radius": 8, "color": "#FFB800"},
        {"id": "dom_cdn", "name": "cdn-cdn7.org", "group": "domain", "radius": 8, "color": "#FFB800"},
        {"id": "hash_44d", "name": "44d88612f... (LockBit)", "group": "hash", "radius": 8, "color": "#D500F9"},
        {"id": "hash_e9a", "name": "e9a04b11c... (Cobalt)", "group": "hash", "radius": 8, "color": "#D500F9"},
    ],
    "links": [
        {"source": "camp_apt29", "target": "ip_185"},
        {"source": "camp_apt29", "target": "dom_evil"},
        {"source": "camp_apt29", "target": "hash_e9a"},
        {"source": "camp_lockbit", "target": "hash_44d"},
        {"source": "camp_lockbit", "target": "ip_185"},
        {"source": "camp_fin7", "target": "ip_45"},
        {"source": "camp_fin7", "target": "dom_cdn"},
        {"source": "ip_91", "target": "camp_apt29"}
    ]
}

def lookup_ioc(ioc_val: str) -> Dict[str, Any]:
    """Deterministic, believable verdict derived from hashing IOC value."""
    clean = ioc_val.strip()
    if not clean:
        return {"error": "Empty IOC query"}

    # Check known matches
    known = next((item for item in DEFAULT_INDICATORS if item["value"].lower() == clean.lower()), None)
    if known:
        return {
            "query": clean,
            "score": known["score"],
            "verdict": "MALICIOUS" if known["score"] > 80 else "SUSPICIOUS",
            "campaign": known["campaign"],
            "malware": known["malware"],
            "country": known["country"],
            "category": known["type"],
            "source": known["source"],
            "tags": known["tags"],
            "asn": "AS49981 Flyservers S.A.",
            "first_seen": "2026-10-14",
            "last_seen": "2026-11-02",
            "confidence": 98
        }

    # Deterministic calculation for arbitrary inputs
    digest = hashlib.sha256(clean.encode()).hexdigest()
    num = int(digest[:6], 16)
    score = 65 + (num % 34) # 65 - 98

    families = ["AgentTesla", "RedLine Stealer", "Cobalt Strike", "LockBit 3.0", "Qakbot", "Sliver C2", "AsyncRAT"]
    campaigns = ["Operation NightWatch", "Financially Motivated 7", "DarkSide Affiliate", "Storm-0558", "APT28 FancyBear"]
    countries = ["Romania (RO)", "Netherlands (NL)", "Germany (DE)", "Russian Federation (RU)", "Seychelles (SC)", "Panama (PA)"]

    family = families[num % len(families)]
    campaign = campaigns[(num >> 3) % len(campaigns)]
    country = countries[(num >> 5) % len(countries)]

    ioc_type = "IP" if clean.replace(".", "").isdigit() else ("Domain" if "." in clean else "Hash")

    return {
        "query": clean,
        "score": score,
        "verdict": "MALICIOUS" if score >= 80 else "SUSPICIOUS",
        "campaign": campaign,
        "malware": family,
        "country": country,
        "category": ioc_type,
        "source": "Enriched Intelligence Cluster",
        "tags": ["command-and-control", "high-confidence", "active-threat"],
        "asn": f"AS{(num % 60000) + 10000} Threat Transit Networks",
        "first_seen": "2026-09-18",
        "last_seen": "2026-11-02",
        "confidence": score
    }

def get_intel_state() -> Dict[str, Any]:
    return {
        "indicators": DEFAULT_INDICATORS,
        "feeds": FEEDS,
        "graph": GRAPH_DATA
    }
