"""
REST and WebSocket API endpoints for NO ENTRY Academy.
Handles track listings, room details, answer validation, lab lifecycle, and browser terminal.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket
from sqlmodel import Session

from backend.app.academy.models import TaskSubmission, TaskSubmissionResult
from backend.app.academy.service import academy_service
from backend.app.academy.validator import task_validator
from backend.app.api.auth import resolve_operator
from backend.app.db.database import get_session
from backend.app.db.models import User
from backend.app.labs.base import DockerRuntimeError, DockerStatus
from backend.app.labs.manager import lab_manager
from backend.app.labs.terminal import academy_terminal_handler

academy_router = APIRouter(prefix="/api/academy", tags=["Academy"])


@academy_router.get("/tracks")
def get_tracks(
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    """Retrieve curriculum track stats, completed counts, and XP totals."""
    return academy_service.get_tracks_summary(session, user.operator_id)


@academy_router.get("/rooms")
def list_rooms(
    track: Optional[str] = Query(default=None),
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    """List curriculum rooms with learner progress status and badges."""
    return academy_service.list_rooms_for_user(session, user.operator_id, track=track)


@academy_router.get("/rooms/{room_id}")
def get_room(
    room_id: str,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    """Get full room details, tasks (without leaked answers), and concept guide."""
    detail = academy_service.get_room_detail_for_user(session, user.operator_id, room_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Room '{room_id}' not found.")
    return detail


@academy_router.post("/rooms/{room_id}/start")
def start_room(
    room_id: str,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    """Initialize room progression for the operator."""
    try:
        return academy_service.start_room(session, user, room_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@academy_router.post("/rooms/{room_id}/tasks/{task_id}/submit", response_model=TaskSubmissionResult)
def submit_task(
    room_id: str,
    task_id: str,
    submission: TaskSubmission,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    """Validate submitted flag, query fix, command answer, or quiz."""
    return task_validator.validate_submission(session, user, room_id, task_id, submission)


@academy_router.post("/labs/{room_id}/start")
async def start_lab(
    room_id: str,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    """Spawn isolated target application and attacker workstation."""
    try:
        info = await lab_manager.start_lab(session, user, room_id)
        return info.client_dict()
    except DockerRuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "error": exc.status.value,
                "message": exc.message,
                "guidance": exc.guidance,
            },
        )


@academy_router.post("/labs/{room_id}/stop")
async def stop_lab(
    room_id: str,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    """Shut down and release isolated lab resources."""
    stopped = await lab_manager.stop_lab(session, user.operator_id, room_id)
    return {"room_id": room_id, "stopped": stopped}


@academy_router.post("/labs/{room_id}/reset")
async def reset_lab(
    room_id: str,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    """Reset target database and state to initial configuration."""
    info = await lab_manager.reset_lab(session, user.operator_id, room_id)
    return info.client_dict()


@academy_router.get("/labs/{room_id}/status")
def get_lab_status(
    room_id: str,
    user: User = Depends(resolve_operator),
):
    """Query live lab session status, IP/port, countdown timer, and runner mode."""
    info = lab_manager.get_user_session(user.operator_id, room_id)
    d_status, d_msg, d_guidance = lab_manager.get_docker_status()
    if not info:
        return {
            "session_id": None,
            "room_id": room_id,
            "status": "STOPPED",
            "runner_mode": "docker" if d_status == DockerStatus.DOCKER_AVAILABLE else "emulated",
            "docker_available": d_status == DockerStatus.DOCKER_AVAILABLE,
            "docker_status": d_status.value,
            "target_url": None,
            "target_ip": "10.10.14.90",
            "target_port": 8089,
            "remaining_seconds": 0,
            "error_message": d_msg if d_status != DockerStatus.DOCKER_AVAILABLE else None,
            "guidance": d_guidance if d_status != DockerStatus.DOCKER_AVAILABLE else None,
        }
    return info.client_dict()


@academy_router.websocket("/ws/{room_id}/terminal")
async def academy_terminal_ws(
    websocket: WebSocket,
    room_id: str,
    session: Session = Depends(get_session),
):
    """Interactive WebSocket terminal for xterm.js connection."""
    token = websocket.cookies.get("ne_auth_token")
    user = resolve_operator(token, session)
    await academy_terminal_handler.handle_connection(websocket, room_id, user)

