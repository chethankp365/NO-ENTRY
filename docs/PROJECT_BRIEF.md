PROJECT
NO ENTRY is an open-source cyber range and cybersecurity learning platform. Tagline: "Open-source attack
simulation and automated threat detection." Banner line: "We break in, so no one else can." A learner
attacks a virtual company inside the app, watches the defenders' SIEM catch it live, writes a detection
rule, patches the hole, and re-runs the attack to prove it is blocked. Core loop: attack, detect, fix,
verify.
Everything is SIMULATED (scripted shell, fake network, generated logs). The code must NEVER run real
scans, exploits, or network attacks against anything. This keeps it safe, free and instant.

EXPERIENCE GOAL (most important, no compromise)
Every second must feel like a hacker movie: dark, tense, cinematic, alive. Nothing is static. Real 3D
(Three.js/WebGL) with post-processing (bloom, chromatic aberration, glitch, film grain, vignette),
particle systems, animated data, decrypting text, glitch transitions, camera fly-throughs, screen shake on
breaches, pulsing alerts, radar sweeps, typing terminals and WebAudio sound effects. The user should get
goosebumps in the first 10 seconds and never see a flat, empty page.

LANGUAGE AND STACK (all free) - PYTHON FIRST
BACKEND, 100% Python 3.11+: FastAPI + Uvicorn, WebSockets, Pydantic, SQLModel + SQLite (Postgres via
DATABASE_URL optional), PyYAML, PyJWT + bcrypt for auth, reportlab for PDF reports, google-genai for the
Gemini AI mentor, python-dotenv, pytest. ALL real logic lives in Python: the simulation engine (asyncio),
event bus, MITRE ATT&CK catalog, simulated shell/terminal gateway, mission engine + grader, Sigma-style
detection-rule engine, Reflex playbook engine, XP/ranks/badges/leaderboard, report generation, AI mentor
proxy.
FRONTEND, rendering layer only: Jinja2 templates served by FastAPI + plain JavaScript ES modules +
hand-written CSS with CSS variables. NO TypeScript, NO React, NO Node build step (use an import map;
vendor three.js, GSAP and xterm.js into frontend/static/vendor so it also works offline). 3D uses Three.js
with EffectComposer (UnrealBloomPass, GlitchPass, RGB-shift, film pass) from three/examples/jsm. WebGL
only runs JavaScript, so this thin JS layer is the one unavoidable non-Python part. It contains no
business logic.
Deploy as one Docker container (FastAPI serves API, WebSockets and the static frontend).

FOLDERS
backend/app/{main.py, config.py, api/, sim/, shell/, missions/(+data/*.yaml), rules/, reflex/, ai/,
reports/, db/}, backend/tests/, frontend/templates/, frontend/static/{css, js/{core,fx,three,screens},
vendor}, docs/, reference/, Dockerfile, requirements.txt, .env.example, README.md.

DESIGN SYSTEM (matches my reference designs in /reference)
Background #04060A, surface #080B10, border #1A1F29, text #E6E9EF, muted #8A93A3.
Red #FF1F3D (attack, danger, primary buttons). Cyan #00E5FF (detection, info). Green #00FF6A (success,
blocked, ok).
Fonts (Google Fonts, or vendored): Orbitron for big display titles, Rajdhani for UI and nav, JetBrains
Mono for terminals, logs and tags.
Look: near-black, thin 1px borders, red corner brackets on full-screen views, faint grid background,
uppercase letter-spaced labels, glowing neon edges, sharp corners (no rounded cards).

Logo: a red circle with a diagonal prohibition slash and a white keyhole in the middle, recreated as an
inline SVG. Secondary assets: wordmark "N(slashed-O) ENTRY" for README and landing, "NE" monogram for
favicon, octagonal stop sign for ACCESS DENIED and 404 stamps.

SCREENS
Boot sequence, Landing, Access terminal (login), Command center, Lab map, Red, Watch, Shield, Trap,
Reflex, Intel, Forensics, Missions, ATT&CK coverage, Reports, Learn (rank, XP, badges, leaderboard),
Docs/Settings/Ethics, Purple team. Learning layer: mission briefing, guided step view with hints,
in-browser attacker terminal, flag submission, rule editor with test button, fix and verify, quiz.
Inner screens share a left sidebar (Command center, Lab map, Red, Watch, Shield, Trap, Reflex, Intel,
Forensics, Missions, ATT&CK, Reports, Learn, Purple team, Docs), a header with the page title in Orbitron,
a "THREAT: ELEVATED" tag and an operator id chip, and a bottom status line "> lab armed. 5 sensors online.
waiting for operator" with a blinking red cursor.

WORKING RULES
1. Build only what each prompt asks, in order. After each prompt: `pytest` passes, `uvicorn app.main:app
--reload` starts without errors, the pages load with no console errors. Fix problems yourself, then commit
with a clear message.
2. Python decides, JavaScript displays. Every number, event, score and grade comes from the Python API or
WebSocket.
3. Performance: cap devicePixelRatio at 1.5, instance repeated geometry, lazy-load heavy 3D modules with
dynamic import(), pause animation when the tab is hidden, provide "Performance mode" and "Reduce motion"
toggles.
4. Desktop first, must work on a 1366x768 laptop. Mobile just must not break.
5. Plain ASCII punctuation in UI copy. Realistic, specific copy. Never lorem ipsum.
6. Never hardcode secrets. Read them from environment variables via config.py and keep .env.example
current. The browser never sees a secret.
7. Every attack-related screen shows: "Lab is isolated. Attacks stay inside the range."
