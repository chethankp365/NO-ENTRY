"""
NO ENTRY - Core FastAPI Application
Cyber Range and Threat Simulation Platform
"""

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.app.config import settings
from backend.app.db.database import init_db
from backend.app.sim.engine import sim_engine
from backend.app.api.routes import api_router
from backend.app.api.auth import auth_router

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
    lifespan=lifespan
)

# Include REST API routes (no CORS middleware needed - same origin)
app.include_router(api_router)
app.include_router(auth_router)

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
        "missions": ("MISSIONS // SCENARIOS", "curated cyber defense challenges"),
        "attack": ("MITRE ATT&CK MATRIX", "tactics, techniques & procedures"),
        "reports": ("EXECUTIVE REPORTS", "incident timelines & compliance metrics"),
        "learn": ("CYBER LAB ACADEMY", "interactive threat simulation tutorials"),
        "purple-team": ("PURPLE TEAM WORKSPACE", "collaborative attack-defense exercises"),
        "docs": ("DOCUMENTATION", "cyber range architecture & developer guide")
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
