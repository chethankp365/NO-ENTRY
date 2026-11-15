# NO ENTRY // EXECUTIVE & TECHNICAL PRESENTATION SCRIPT
## Demonstration Playbooks for Recruiters, Stakeholders, and Technical Audits

This document provides structured demonstration flows for showcasing the **NO ENTRY** cybersecurity training platform across three time formats:
1. **[5-Minute Executive Walkthrough](#1-the-5-minute-executive-walkthrough)** — High-impact visual overview & 60-second attack replay.
2. **[15-Minute Technical Deep-Dive](#2-the-15-minute-technical-deep-dive)** — Hands-on room workflow, Docker isolation, GHOST AI mentor, and Detection-as-Code.
3. **[30-Minute Comprehensive Architecture Audit](#3-the-30-minute-comprehensive-architecture-audit)** — Complete 80-room curriculum verification, SIEM hunting, SOAR automation, and code inspection.

---

## 1. The 5-Minute Executive Walkthrough
**Target Audience**: Engineering Managers, Recruiters, Executive Stakeholders  
**Goal**: Demonstrate immediate visual polish, platform breadth, and the core value proposition.

### Step 1: Command Center & Real-Time Threat Posture (1:00)
1. Navigate to `http://127.0.0.1:8000/command-center`.
2. **Talking Points**:
   - *"NO ENTRY is a unified cybersecurity training platform combining a real-time SOC simulation range with an 80-room hands-on academy."*
   - Point out the 4 primary StatCards: `THREAT LEVEL: ELEVATED`, `ALERTS TODAY`, `MTTD: 3.2s`, `MTTR: 8.4s`.
   - Point out the rotating 3D attack globe and continuous WebSockets telemetry pulse.
   - Mention the tactile WebAudio engine: all alert blips, hums, and chimes are synthesized via the Web Audio API with zero external audio files.

### Step 2: 60-Second Full-Spectrum Live Cyber Attack (2:30)
1. Click the top button **`[⚡ 60s LIVE ATTACK DEMO]`** or visit `/watch?demo=1`.
2. **Talking Points**:
   - *"Here we see an automated, safe 8-stage cyber engagement that illustrates the complete attack-to-detection lifecycle in 60 seconds."*
   - Direct attention to the **Dual Stream**:
     - **Left Terminal (Red Team)**: Attacker Kali terminal showing reconnaissance (`nmap`), initial foothold RCE, and SUID root privilege escalation.
     - **Right Terminal (Blue Team)**: Defender SIEM stream ingesting Sysmon Event ID 1, triggering Sigma detection rules, and displaying analyst triage.
   - Show the **Network Topology Diagram (SVG)**: Observe the packet trail traversing the Perimeter Firewall into DMZ Web01, and ultimately being blocked when SOAR quarantine isolates the host.
   - Demonstrate the interactive scrubber: pause, toggle `2x SPEED`, or jump directly to **Stage 4 (PrivEsc)** or **Stage 8 (Containment)**.

### Step 3: 80-Room Academy Overview (1:30)
1. Navigate to `/academy`.
2. **Talking Points**:
   - *"The academy features 80 complete rooms spanning four distinct disciplines: Red Team (Offensive), Blue Team (Defensive SOC), Purple Team (Adversary Emulation), and Detection Engineering (Detection-as-Code)."*
   - Show the completion counters: `80 / 80 Rooms Active (100% Operational)`.
   - Briefly explain how every room includes concept theory, analogies, practical demonstrations, and interactive task assessments.

---

## 2. The 15-Minute Technical Deep-Dive
**Target Audience**: Senior Security Engineers, Staff Software Architects, Technical Interviewers  
**Goal**: Prove architectural maturity, security isolation, AI integration, and practical task execution.

### Step 1: Enter a Hands-On Room Workspace (4:00)
1. Open Room `red-09` (`http://127.0.0.1:8000/academy/red-09` — SQL Injection) or `detect-03` (`detect-03` — Sigma Rule Fundamentals).
2. **Observe Room Initialization**:
   - Point out the holographic **Mission Briefing Modal**: shows classification, objectives list, XP bounty, and target vector. Click **`INITIALIZE OPERATION // COMMENCE MISSION`**.
   - Notice the track dynamic theme (Crimson red for offensive, Emerald green for detection, Neon cyan for SOC, Purple for emulation).
3. **Inspect the Dual Pane Interface**:
   - Left pane: Learn the concept (everyday analogy, technical definition, mitigation), followed by guided TryHackMe-style tasks.
   - Right pane: Lab lifecycle controls (`START LAB`, `RESET DB`, `STOP`) and the live **xterm.js terminal workstation**.

### Step 2: Target Service & Docker Zero-Trust Isolation (3:00)
1. Click **`START LAB`**.
2. **Talking Points**:
   - *"The backend provisions an isolated lab container connected through an internal-only Docker bridge network."*
   - *"Outbound WAN traffic is strictly disabled to prevent external pivot attacks; CPU and RAM limits are enforced at the cgroup level."*
   - *"If Docker is not installed on the host, NO ENTRY automatically falls back to high-speed in-process microservice emulators without breaking the operator experience."*
3. Click a **Quick Probe** button (e.g. `test quote injection` or `curl target`).
4. Watch the command execute and return formatted JSON in the terminal.

### Step 3: Interactive Task Submission & XP Feedback (3:00)
1. Complete a task in the left pane (e.g., enter an injection string or submit quiz options).
2. Click **`SUBMIT`**.
3. **Observe System Response**:
   - Instant backend validation via SQLModel and targeted regex/action validators.
   - WebAudio synthesized XP chime (`xpBurst()`).
   - Floating holographic toast: `+70 XP EARNED`.
   - Card transitions to green solved state with live progress bar update.

### Step 4: GHOST AI Cognitive Mentor (3:00)
1. Click the floating **GHOST** icon in the bottom-right corner.
2. Click **`GIVE ME A HINT`** or type a query: *"Why did the single quote cause an error?"*.
3. **Talking Points**:
   - *"GHOST is an autonomous multi-provider mentor that inspects the current room ID, operator steps, and terminal logs."*
   - *"It routes across Groq (Llama-3 70B), Google Gemini 1.5, and OpenRouter, with built-in prompt-injection defenses and secret scrubbing."*
   - *"If all LLM providers are unreachable, GHOST gracefully degrades to offline YAML-scripted pedagogical hints."*

### Step 5: Easter Eggs & Terminal Interactivity (2:00)
1. In the terminal, type `matrix` and press Enter: observe the falling green digital rain.
2. Type `ghost --whoami`: observe the encrypted AI agent clearance banner.
3. Press `↑ ↑ ↓ ↓ ← → ← → B A`: observe the Konami code CRT scanline flicker and achievement unlock toast.

---

## 3. The 30-Minute Comprehensive Architecture Audit
**Target Audience**: Security Assessors, Lead Evaluators, Portfolio Review Committees  
**Goal**: Rigorous verification of full stack code quality, testing rigor, detection engineering pipelines, and security controls.

### Part A: Curriculum & Engine Verification (10:00)
1. **Verification of All 80 Rooms**:
   - Walk through the curriculum registry in `backend/app/academy/curriculum.py`.
   - Demonstrate that all 80 rooms exist with valid slugs (`red-01`..`20`, `blue-01`..`20`, `purple-01`..`20`, `detect-01`..`20`).
2. **Automated Test Suite Demonstration**:
   - In terminal, execute:
     ```bash
     pytest backend/tests/ -k "not docker" -q
     ```
   - Show all 279+ tests passing with zero failures.
   - Point out unit tests verifying task progression, validation logic, API contracts, and room integrity.

### Part B: Detection-as-Code & Rule Testing Pipeline (8:00)
1. Navigate to `/academy/detect-09` (Detection-as-Code & GitOps Pipelines) or `/academy/detect-17` (Metrics & Health).
2. Open the **Evidence Drawer** by clicking **`[📂 EVIDENCE]`** in the HUD.
3. Show the real-time Sigma YAML configuration.
4. Explain the CI/CD gating methodology:
   - Rules are linted for syntax and schema conformity.
   - Atomic unit test events are evaluated against the rule logic.
   - False positive thresholds gate deployment to the active SIEM.

### Part C: Threat Hunting & SOAR Response (7:00)
1. Navigate to `/watch`.
2. Enter a threat hunt query in the HUNT panel:
   ```
   source.ip: 10.0.2.15 AND event.action: logon_failed
   ```
3. Click **`RUN HUNT`**: observe the real-time histogram calculation and matched hits.
4. Click an event in the Alert Stream to open the Slide-in Inspection Drawer.
5. Demonstrate MITRE technique mapping, AbuseIPDB reputation score, and raw JSON logs.
6. Click **`BLOCK IP`** or **`ISOLATE HOST`**: show automated SOAR reflex containment dispatching network quarantine.

### Part D: Code Review & Security Hardening (5:00)
1. Review `backend/app/labs/docker_runner.py`:
   - Inspect internal bridge network creation (`no-entry-internal-net`).
   - Review memory limits (`mem_limit="256m"`) and CPU quotas (`cpus=0.5`).
2. Review `backend/app/ai/safety.py`:
   - Inspect regex patterns detecting prompt injection attempts and system prompt extraction attacks.
3. Review `Dockerfile` and `render.yaml`:
   - Non-root `operator` user enforcement, minimal slim base image, and automated health checks.

---

## 🎯 Summary Checklist for Presenters

- [ ] Backend running on `http://127.0.0.1:8000`.
- [ ] Browser window sized to 1920x1080 or 1366x768 with audio enabled.
- [ ] Start on Command Center (`/command-center`).
- [ ] Trigger 60s Live Attack Replay (`/watch?demo=1`).
- [ ] Demonstrate at least one room from each track (e.g. `red-09`, `blue-05`, `purple-03`, `detect-09`).
- [ ] Show GHOST AI mentor responding to context.
- [ ] Trigger Konami Code (`↑↑↓↓←→←→ba`) for visual delight.
- [ ] Conclude with the passing 279-test regression suite.
