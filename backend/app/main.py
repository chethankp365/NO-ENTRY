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

# Mount static files and templates
settings.STATIC_DIR.mkdir(parents=True, exist_ok=True)
settings.TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(settings.STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(settings.TEMPLATES_DIR))

@app.get("/", response_class=HTMLResponse)
def index_redirect():
    """Redirect root to /debug in development core phase."""
    return RedirectResponse(url="/debug")

@app.get("/debug", response_class=HTMLResponse)
def debug_page(request: Request):
    """Monospace live debug console proving end-to-end WebSocket stream & API."""
    return templates.TemplateResponse(
        request=request,
        name="debug.html",
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
