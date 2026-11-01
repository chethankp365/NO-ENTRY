# NO ENTRY

> **"Open-source attack simulation and automated threat detection."**
> *"We break in, so no one else can."*

NO ENTRY is an open-source simulated cyber range and detection engineering platform. Everything is 100% simulated (scripted shell, virtual company topology, synthesized logs, and automated SOAR responses). No real scans, exploits, or network attacks are ever run.

---

## Architecture & Technology Stack

- **Backend**: Python 3.11+, FastAPI, Uvicorn, WebSockets, SQLModel (SQLite), PyYAML, pydantic-settings
- **Simulation**: Asyncio event bus emitting telemetry every 1–4 seconds with full MITRE ATT&CK mapping
- **Reflex SOAR**: Automated playbooks (`block_ip`, `isolate_host`, `disable_ad_account`, `notify_telegram`)
- **Detection Rules**: Sigma-style rule engine supporting `|contains`, `|startswith`, `|endswith`, and `|regex`
- **Frontend / Debug Layer**: Jinja2 templates, native ES modules, vanilla CSS, and real-time WebSockets

---

## Quickstart

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment
Copy the example environment file:
```bash
cp .env.example .env
```

### 3. Run the Development Server
```bash
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```
Then visit [http://127.0.0.1:8000/debug](http://127.0.0.1:8000/debug) to open the live cyber range debug console.

### 4. Run the Test Suite
```bash
pytest -v
```

---

## Core Endpoints

- `GET /debug`: Monospace live event stream and interactive scenario controller
- `GET /ws/events`: WebSocket stream broadcasting snapshots, live events, metrics, and reflex actions
- `GET /api/state`: Full lab snapshot (hosts, metrics, playbooks, recent events, active scenarios)
- `GET /api/events`: Event bus log with state & technique filters
- `GET /api/events/{id}`: Detailed log with MITRE card & deterministic AbuseIPDB threat intelligence
- `GET /api/metrics`: Real-time operational metrics (threat level, MTTD, MTTR, sensor coverage)
- `GET /api/hosts`: Status of all 9 lab network hosts
- `GET /api/scenarios`: Attack scenarios (`ransomware`, `web-breach`, `insider`, `credential`, `exfiltration`)
- `POST /api/scenarios/{id}/start`: Launch timed attack scenario
- `POST /api/scenarios/{id}/stop`: Halt active attack scenario
- `POST /api/hosts/{id}/isolate`: Network quarantine host
- `POST /api/block-ip`: Firewall drop IP rule
- `GET /api/reflex/playbooks` & `POST /api/reflex/playbooks`: SOAR playbook toggle
