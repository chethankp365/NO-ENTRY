"""
NO ENTRY - Core FastAPI Application
Cyber Range and Threat Simulation Platform
"""

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.app.config import settings
from backend.app.db.database import init_db
from backend.app.sim.engine import sim_engine
from backend.app.api.routes import api_router
from backend.app.api.auth import auth_router
from backend.app.api.missions import missions_router
from backend.app.api.ghost import ghost_router
from backend.app.api.academy import academy_router, academy_terminal_handler
from backend.app.api.auth import resolve_operator
from backend.app.db.database import get_session

# Lifespan event handler for startup and shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database tables
    init_db()

    # Start simulation engine background autopilot
    sim_engine.start_background_loop()
    print(">>> NO ENTRY simulation engine armed. Background autopilot running.")

    yield

    # Graceful shutdown
    sim_engine.stop_background_loop()
    print(">>> NO ENTRY simulation engine disarmed.")

app = FastAPI(
    title=settings.APP_NAME,
    description="Open-source attack simulation and automated threat detection.",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Include REST API routes (no CORS middleware needed - same origin)
app.include_router(api_router)
app.include_router(auth_router)
app.include_router(missions_router)
app.include_router(ghost_router)
app.include_router(academy_router)

@app.get("/api/health")
@app.get("/health")
def health_check():
    """Service healthcheck probe for Docker and cloud monitoring."""
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "env": settings.APP_ENV,
        "sensors_online": 5,
        "rooms_total": 80
    }

# Mount static files and templates
settings.STATIC_DIR.mkdir(parents=True, exist_ok=True)
settings.TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(settings.STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(settings.TEMPLATES_DIR))

@app.get("/", response_class=HTMLResponse)
def landing_page(request: Request):
    """Screen 2: Landing page."""
    return templates.TemplateResponse(
        request=request,
        name="landing.html",
        context={"app_name": settings.APP_NAME}
    )

@app.get("/boot", response_class=HTMLResponse)
def boot_page(request: Request):
    """Screen 1: Boot sequence page."""
    return templates.TemplateResponse(
        request=request,
        name="boot.html",
        context={"app_name": settings.APP_NAME}
    )

@app.get("/access", response_class=HTMLResponse)
def access_page(request: Request):
    """Screen 3: Access terminal login page."""
    return templates.TemplateResponse(
        request=request,
        name="access.html",
        context={"app_name": settings.APP_NAME}
    )

@app.get("/command-center", response_class=HTMLResponse)
def command_center_page(request: Request):
    """Screen 4: Command Center."""
    return templates.TemplateResponse(
        request=request,
        name="command_center.html",
        context={"app_name": settings.APP_NAME}
    )

@app.get("/lab-map", response_class=HTMLResponse)
def lab_map_page(request: Request):
    """Screen 5: 3D Hero Lab Map."""
    return templates.TemplateResponse(
        request=request,
        name="lab_map.html",
        context={"app_name": settings.APP_NAME}
    )

@app.get("/red", response_class=HTMLResponse)
def red_page(request: Request):
    """Screen 6: Red Team attack launcher and scenario console."""
    return templates.TemplateResponse(
        request=request,
        name="red.html",
        context={"app_name": settings.APP_NAME}
    )

@app.get("/watch", response_class=HTMLResponse)
def watch_page(request: Request):
    """Screen 7: Watch SIEM alerts and threat hunting."""
    return templates.TemplateResponse(
        request=request,
        name="watch.html",
        context={"app_name": settings.APP_NAME}
    )

@app.get("/purple", response_class=HTMLResponse)
@app.get("/purple-team", response_class=HTMLResponse)
def purple_page(request: Request):
    """Screen 18: Purple Team correlation view."""
    return templates.TemplateResponse(
        request=request,
        name="purple.html",
        context={"app_name": settings.APP_NAME}
    )

@app.get("/shield", response_class=HTMLResponse)
def shield_page(request: Request):
    """Screen 8: Shield Hardening & Posture."""
    return templates.TemplateResponse(
        request=request,
        name="shield.html",
        context={"app_name": settings.APP_NAME}
    )

@app.get("/trap", response_class=HTMLResponse)
def trap_page(request: Request):
    """Screen 9: Trap Deception & Honeypots."""
    return templates.TemplateResponse(
        request=request,
        name="trap.html",
        context={"app_name": settings.APP_NAME}
    )

@app.get("/reflex", response_class=HTMLResponse)
def reflex_page(request: Request):
    """Screen 10: Reflex SOAR Playbooks & Actions."""
    return templates.TemplateResponse(
        request=request,
        name="reflex.html",
        context={"app_name": settings.APP_NAME}
    )

@app.get("/intel", response_class=HTMLResponse)
def intel_page(request: Request):
    """Screen 11: Threat Intelligence & IOC Graph."""
    return templates.TemplateResponse(
        request=request,
        name="intel.html",
        context={"app_name": settings.APP_NAME}
    )

@app.get("/forensics", response_class=HTMLResponse)
def forensics_page(request: Request):
    """Screen 12: Digital Forensics & Evidence Chain."""
    return templates.TemplateResponse(
        request=request,
        name="forensics.html",
        context={"app_name": settings.APP_NAME}
    )

@app.get("/attack", response_class=HTMLResponse)
def attack_page(request: Request):
    """Screen 14: MITRE ATT&CK Matrix Heatmap."""
    return templates.TemplateResponse(
        request=request,
        name="attack.html",
        context={"app_name": settings.APP_NAME}
    )

@app.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request):
    """Screen 15: Incident Reports & PDF Generation."""
    return templates.TemplateResponse(
        request=request,
        name="reports.html",
        context={"app_name": settings.APP_NAME}
    )


@app.get("/missions", response_class=HTMLResponse)
def missions_page(request: Request):
    """Missions Hub: 5 cyber scenarios + XP/cleared progress."""
    return templates.TemplateResponse(
        request=request,
        name="missions.html",
        context={"app_name": settings.APP_NAME}
    )


@app.get("/missions/{mission_id}", response_class=HTMLResponse)
def mission_player_page(request: Request, mission_id: str):
    """8-stage interactive Attack -> Defend Mission Player."""
    return templates.TemplateResponse(
        request=request,
        name="mission_player.html",
        context={"app_name": settings.APP_NAME, "mission_id": mission_id}
    )


@app.get("/learn", response_class=HTMLResponse)
def learn_page(request: Request):
    """Learn Academy: Ranks, Badges, Leaderboard, Streaks, Cheat-Sheet."""
    return templates.TemplateResponse(
        request=request,
        name="learn.html",
        context={"app_name": settings.APP_NAME}
    )


@app.get("/docs", response_class=HTMLResponse)
def docs_page(request: Request):
    """Docs, Lab Settings & Mandatory 3-Question Ethics Gate."""
    return templates.TemplateResponse(
        request=request,
        name="docs.html",
        context={"app_name": settings.APP_NAME}
    )


@app.get("/academy", response_class=HTMLResponse)
def academy_catalog_page(request: Request):
    """Hands-on Cybersecurity Academy 80-Room Curriculum Catalog."""
    return templates.TemplateResponse(
        request=request,
        name="academy.html",
        context={"app_name": settings.APP_NAME}
    )


@app.get("/academy/rooms/{room_id}", response_class=HTMLResponse)
@app.get("/academy/{room_id}", response_class=HTMLResponse)
def academy_room_page(request: Request, room_id: str):
    """TryHackMe-style Hands-On Practical Room Workspace."""
    return templates.TemplateResponse(
        request=request,
        name="room_workspace.html",
        context={"app_name": settings.APP_NAME, "room_id": room_id}
    )


@app.websocket("/ws/academy/{room_id}/terminal")
async def academy_terminal_direct_ws(
    websocket: WebSocket,
    room_id: str,
    session = Depends(get_session),
):
    """Direct WebSocket endpoint for xterm.js terminal connection."""
    user = resolve_operator(websocket, session)
    await academy_terminal_handler.handle_connection(websocket, room_id, user)



@app.get("/debug", response_class=HTMLResponse)
def debug_page(request: Request):
    """Monospace live debug console proving end-to-end WebSocket stream & API."""
    return templates.TemplateResponse(
        request=request,
        name="debug.html",
        context={"app_name": settings.APP_NAME}
    )

@app.get("/playground", response_class=HTMLResponse)
def playground_page(request: Request):
    """Interactive Design System & WebGL FX Playground."""
    return templates.TemplateResponse(
        request=request,
        name="playground.html",
        context={"app_name": settings.APP_NAME}
    )

@app.websocket("/ws/events")
async def websocket_events_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time cyber range event streaming.
    Sends a full state snapshot immediately upon connection, then pushes
    live events, metrics, host state changes, and reflex actions.
    """
    await websocket.accept()
    queue = sim_engine.subscribe()

    try:
        # Send full snapshot on connect
        snapshot = {
            "type": "snapshot",
            "data": sim_engine.get_full_state()
        }
        await websocket.send_json(snapshot)

        # Stream real-time events as they occur
        while True:
            # Check for incoming client messages (e.g. ping/heartbeat or commands)
            receive_task = asyncio.create_task(websocket.receive_text())
            queue_task = asyncio.create_task(queue.get())

            done, pending = await asyncio.wait(
                [receive_task, queue_task],
                return_when=asyncio.FIRST_COMPLETED
            )

            for task in pending:
                task.cancel()

            if receive_task in done:
                try:
                    data = receive_task.result()
                    # Client can send simple ping or action triggers
                    if data == "ping":
                        await websocket.send_text("pong")
                except WebSocketDisconnect:
                    break

            if queue_task in done:
                msg = queue_task.result()
                await websocket.send_json(msg)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"WebSocket client error: {e}")
    finally:
        sim_engine.unsubscribe(queue)

from backend.app.sim.terminal_service import handle_terminal_ws

@app.websocket("/ws/terminal")
async def websocket_terminal_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for simulated offensive terminal streaming.
    Streams interactive command output line-by-line and executes Red scenario scripts.
    """
    await handle_terminal_ws(websocket)


# Placeholder routes for remaining sidebar items to prevent 404s
@app.get("/{screen_path:path}", response_class=HTMLResponse)
def app_screen_fallback(request: Request, screen_path: str):
    valid_screens = {
        "red": ("RED TEAM OPS", "automated adversarial simulation"),
        "watch": ("WATCH // SIEM", "real-time rule matching & event logs"),
        "shield": ("SHIELD // DEFENSE", "automated perimeter & firewall rules"),
        "trap": ("TRAP // HONEYPOTS", "deception technology & decoys"),
        "reflex": ("REFLEX // SOAR", "automated response playbooks"),
        "intel": ("INTEL // THREAT ENRICHMENT", "live IP reputation & IOC feeds"),
        "forensics": ("FORENSICS", "packet analysis & artifact timeline"),
        "attack": ("MITRE ATT&CK MATRIX", "tactics, techniques & procedures"),
        "reports": ("EXECUTIVE REPORTS", "incident timelines & compliance metrics"),
        "purple-team": ("PURPLE TEAM WORKSPACE", "collaborative attack-defense exercises")
    }
    clean_path = screen_path.strip("/")
    if clean_path in valid_screens:
        title, subtitle = valid_screens[clean_path]
        return templates.TemplateResponse(
            request=request,
            name="base_app.html",
            context={
                "app_name": settings.APP_NAME,
                "screen_title": title,
                "screen_subtitle": subtitle,
                "active_nav": clean_path.replace("-", "_")
            }
        )
    raise HTTPException(status_code=404, detail="Page not found")
