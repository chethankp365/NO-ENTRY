"""
REST & SSE API router for Ghost AI Mentor and Deepgram Voice Integration.
"""

import json
import re
from typing import Any, Dict, List, Literal, Optional
from fastapi import APIRouter, Depends, File, HTTPException, Query, Response, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlmodel import Session

from backend.app.api.auth import resolve_operator
from backend.app.config import settings
from backend.app.db.database import get_session
from backend.app.db.models import User
from backend.app.ai.ghost import check_rate_limit, ghost_service, record_rate_limit_hit
from backend.app.ai.safety import MAX_MESSAGE_CHARS, MAX_RULE_CHARS, MAX_TTS_CHARS, scrub_secrets, validate_learner_input
from backend.app.ai.voice import VoiceServiceError, voice_service

ghost_router = APIRouter(prefix="/api/ghost", tags=["ghost"])


class GhostChatRequest(BaseModel):
    message: str = Field(default="")
    action: Literal["auto", "hint", "explain_log", "why_it_worked", "review_rule", "chat"] = "auto"
    mission_id: Optional[str] = Field(default=None, max_length=64)
    stage: Optional[str] = Field(default=None, max_length=64)
    screen: Optional[str] = Field(default=None, max_length=64)
    terminal_output: List[str] = Field(default_factory=list, max_length=25)
    logs: List[str] = Field(default_factory=list, max_length=25)
    rule_yaml: Optional[str] = Field(default=None, max_length=MAX_RULE_CHARS)
    selected_mitre_id: Optional[str] = Field(default=None, max_length=32)
    rule_test_result: Optional[Dict[str, Any]] = None


class GhostTtsRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=MAX_TTS_CHARS)


@ghost_router.get("/status")
def api_ghost_status(
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    """Return safe Ghost AI, voice, intent, and local-inference status without exposing keys."""
    return ghost_service.get_status(session, user.operator_id)


@ghost_router.post("")
async def api_ghost_chat(
    req: GhostChatRequest,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    """Stream Ghost AI Mentor response over Server-Sent Events (SSE)."""
    allow_empty = req.action in ("hint", "explain_log", "why_it_worked", "review_rule")
    try:
        validate_learner_input(req.message, allow_empty=allow_empty, max_chars=MAX_MESSAGE_CHARS)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    payload = req.model_dump()

    async def event_stream():
        try:
            async for evt in ghost_service.stream_mentor_reply(session, user, payload):
                yield f"data: {json.dumps(evt, ensure_ascii=True)}\n\n"
        except Exception as exc:
            err_evt = {"type": "error", "message": scrub_secrets(str(exc))}
            yield f"data: {json.dumps(err_evt, ensure_ascii=True)}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@ghost_router.post("/voice/stt")
async def api_ghost_voice_stt(
    audio: UploadFile = File(...),
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    """Convert uploaded learner microphone audio into text via Deepgram (in-memory only)."""
    allowed, used, limit = check_rate_limit(session, user.operator_id, "voice_stt")
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Voice STT rate limit exceeded ({used}/{limit} per hour). Type your question instead.",
        )

    audio_bytes = await audio.read()
    content_type = audio.content_type or "audio/webm"

    try:
        record_rate_limit_hit(session, user.operator_id, "voice_stt")
        result = await voice_service.transcribe_audio(audio_bytes, content_type)
        return result
    except VoiceServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc


@ghost_router.post("/voice/tts")
async def api_ghost_voice_tts(
    req: GhostTtsRequest,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    """Synthesize Ghost reply text into audio/mpeg bytes via Deepgram."""
    allowed, used, limit = check_rate_limit(session, user.operator_id, "voice_tts")
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Voice TTS rate limit exceeded ({used}/{limit} per hour). Text output remains active.",
        )

    try:
        record_rate_limit_hit(session, user.operator_id, "voice_tts")
        audio_bytes = await voice_service.synthesize_speech(req.text)
        return Response(
            content=audio_bytes,
            media_type="audio/mpeg",
            headers={
                "Cache-Control": "no-store",
                "X-Voice-Provider": "deepgram",
                "X-Voice-Model": (settings.DEEPGRAM_TTS_MODEL or "").strip() or "provider-default",
            },
        )
    except VoiceServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc


class GhostRoomAskRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=1000)
    current_step: Optional[int] = 1


def _academy_room_context(room_id: str, user: User, session: Session, task_id: Optional[str] = None):
    from backend.app.academy.curriculum import curriculum_registry
    from backend.app.academy.service import academy_service
    from backend.app.labs.manager import lab_manager

    room = curriculum_registry.get_room(room_id)
    if not room:
        raise HTTPException(status_code=404, detail=f"Room '{room_id}' not found.")

    detail = academy_service.get_room_detail_for_user(session, user.operator_id, room_id)
    tasks = detail["tasks"] if detail else []
    selected_task = next((item for item in tasks if item["task_id"] == task_id), None) if task_id else None
    if not selected_task:
        selected_task = next((item for item in tasks if not item.get("is_completed")), tasks[-1] if tasks else None)

    session_info = lab_manager.get_user_session(user.operator_id, room_id)
    active_session = (
        session_info
        if session_info and session_info.status == "RUNNING" and session_info.runner_mode == "docker"
        else None
    )
    lab_status = (
        "EMULATED"
        if session_info and session_info.status == "RUNNING" and session_info.runner_mode != "docker"
        else session_info.status if session_info else "STOPPED"
    )
    target_ip = active_session.target_ip if active_session and active_session.target_ip else None
    target_port = active_session.target_port if active_session else room.default_port
    task = next((item for item in room.tasks if selected_task and item.task_id == selected_task["task_id"]), None)
    task_hint = task.hint if task else None
    target_reference = target_ip or "<target-ip>"

    def resolve_target(value: str) -> str:
        return value.replace("10.10.14.90", target_reference)

    command = None
    if task_hint:
        candidates = re.findall(r"`([^`]+)`", task_hint)
        executable = re.compile(
            r"^(?:curl|wget|nmap|python3?|tcpdump|tshark|dig|nslookup|whois|nc|"
            r"cat|grep|awk|jq|ip|whoami|id|hostname|ls|file|strings|sha256sum|"
            r"git|yara|pytest|sqlite3|find|sed|openssl)\b"
        )
        for raw_candidate in candidates:
            candidate = resolve_target(raw_candidate.strip())
            if executable.match(candidate) and (target_ip or "<target-ip>" not in candidate):
                command = candidate
                break

    verified_actions = set(session_info.recorded_actions) if active_session else set()
    display_hint = resolve_target(task_hint) if task_hint else None
    if not target_ip and display_hint and "<target-ip>" in display_hint:
        display_hint = None
    return {
        "room": room,
        "detail": detail or room.client_detail(),
        "task": selected_task,
        "task_hint": display_hint,
        "task_command": command,
        "session": active_session,
        "lab_status": lab_status,
        "target_ip": target_ip,
        "target_port": target_port,
        "verified_actions": verified_actions,
    }


@ghost_router.get("/room/{room_id}/guide")
def api_ghost_room_guide(
    room_id: str,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    """Return curriculum-led steps and completion based only on backend evidence."""
    ctx = _academy_room_context(room_id, user, session)
    room, task = ctx["room"], ctx["task"]
    target_ip, target_port = ctx["target_ip"], ctx["target_port"]
    completed_task = bool(task and task.get("is_completed"))
    task_title = task["title"] if task else room.title
    task_goal = task["instructions"] if task else room.short_description
    task_tools = ", ".join(room.required_practical_skills) or "the tools described in this room"
    target_status = (
        f"Backend assigned {target_ip}:{target_port} on the running isolated lab."
        if target_ip
        else "Start the lab to receive the actual target address; no address is assigned while stopped."
    )
    environment_verified = "ghost_environment_verified" in ctx["verified_actions"]
    target_verified = "ghost_target_reachable" in ctx["verified_actions"]
    services_verified = "ghost_services_enumerated" in ctx["verified_actions"]
    steps = [
        {
            "step": 1,
            "title": "Verify Environment: Operator Workstation",
            "goal": "Confirm the current user, host, and interface from inside the isolated attacker container.",
            "tool": "whoami, id, hostname, ip",
            "command": "whoami && id && hostname && ip -br addr" if ctx["session"] else None,
            "explanation": "This proves the terminal is attached to the provisioned operator container rather than the application host.",
            "completed": environment_verified,
        },
        {
            "step": 2,
            "title": "Identify Network & Target",
            "goal": target_status,
            "tool": "Lab Intelligence",
            "command": (
                f"curl -sS -o /dev/null -w 'HTTP %{{http_code}}\\n' http://{target_ip}:{target_port}/"
                if target_ip
                else None
            ),
            "explanation": "The address comes from Docker inspection; the backend also checks the target service is reachable from the attacker container before reporting the lab online.",
            "completed": target_verified,
        },
        {
            "step": 3,
            "title": "Enumerate Room Service",
            "goal": f"Check the service provisioned for {room.title} and record its actual response.",
            "tool": "nmap",
            "command": (
                f"nmap -sV --version-light -T4 --max-retries 1 -p {target_port} {target_ip}"
                if target_ip
                else None
            ),
            "explanation": "Use the assigned IP and room port only; the range does not claim unrelated SSH or HTTP ports are open.",
            "completed": services_verified,
        },
        {
            "step": 4,
            "title": f"Practise: {task_title}",
            "goal": task_goal,
            "tool": task_tools,
            "command": ctx["task_command"],
            "explanation": ctx["task_hint"] or "Follow the task procedure in the room and compare your result with its stated objective.",
            "completed": completed_task,
        },
        {
            "step": 5,
            "title": "Interpret the Evidence",
            "goal": "Compare the observed result with the room's assessment criteria.",
            "tool": "Room assessment criteria",
            "command": None,
            "explanation": "GHOST marks this step complete only after the backend records the task as completed.",
            "completed": completed_task,
        },
        {
            "step": 6,
            "title": "Submit and Verify",
            "goal": "Submit the evidence required by this room's task for backend validation.",
            "tool": "Room task validator",
            "command": None,
            "explanation": "Only the server-side validator updates task progress and completion.",
            "completed": completed_task,
        },
    ]

    active_step = next((item["step"] for item in steps if not item["completed"]), 6)
    return {
        "room_id": room.room_id,
        "title": room.title,
        "track": room.track.value if hasattr(room.track, "value") else str(room.track),
        "difficulty": room.difficulty,
        "target_ip": target_ip,
        "target_port": target_port,
        "lab_status": ctx["lab_status"],
        "active_task_id": task["task_id"] if task else None,
        "active_step": active_step,
        "steps": steps,
    }


@ghost_router.get("/room/{room_id}/hint")
def api_ghost_room_hint(
    room_id: str,
    level: int = Query(default=1, ge=1, le=4),
    task_id: Optional[str] = Query(default=None),
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    """Return progressive hints derived from the current room task and backend lab state."""
    ctx = _academy_room_context(room_id, user, session, task_id)
    room, task = ctx["room"], ctx["task"]
    task_title = task["title"] if task else room.title
    task_instructions = task["instructions"] if task else room.short_description
    tools = ", ".join(room.required_practical_skills) or "the practical tools described in this room"
    criteria = room.assessment_criteria or room.completion_requirements
    hint_text = ctx["task_hint"] or (
        "Start the lab to receive the assigned target and a usable room-specific procedure."
        if not ctx["session"]
        else None
    )
    hints = {
        1: {
            "label": "Objective: Understand the Task",
            "hint": f"{task_title}: {task_instructions}",
            "command": None,
        },
        2: {
            "label": "Tool Selection",
            "hint": (
                f"Use this room's practical tools and skills: {tools}. "
                + (
                    f"The isolated target is {ctx['target_ip']}:{ctx['target_port']}."
                    if ctx["target_ip"]
                    else "Start the lab first to obtain its actual target address."
                )
            ),
            "command": None,
        },
        3: {
            "label": "Command: Actionable Task Hint",
            "hint": hint_text or "Use the task instructions to plan a procedure; this task has no additional command hint.",
            "command": ctx["task_command"],
        },
        4: {
            "label": "Interpretation: Check the Evidence",
            "hint": (
                "Compare your result with: " + "; ".join(criteria)
                if criteria
                else f"Compare your evidence with the task requirement: {task_instructions}"
            ),
            "command": None,
        },
    }

    selected = hints.get(level, hints[1])
    return {
        "room_id": room_id,
        "task_id": task["task_id"] if task else None,
        "lab_status": ctx["lab_status"],
        "target_ip": ctx["target_ip"],
        "target_port": ctx["target_port"],
        "task_completed": bool(task and task.get("is_completed")),
        "level": level,
        "label": selected["label"],
        "hint": selected["hint"],
        "command": selected["command"],
    }


@ghost_router.post("/room/{room_id}/ask")
async def api_ghost_room_ask(
    room_id: str,
    req: GhostRoomAskRequest,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    """Use the existing multi-provider GHOST service with server-verified room context."""
    ctx = _academy_room_context(room_id, user, session)
    q = req.question.strip()
    q_lower = q.lower()
    if "next" in q_lower or "step-by-step" in q_lower:
        actions = ctx["verified_actions"]
        if not ctx["session"]:
            answer = (
                "The next step is to start this room's Docker lab. The backend has not assigned a target "
                "address while the lab is stopped."
            )
        elif "ghost_environment_verified" not in actions:
            answer = (
                "First verify the isolated operator workstation with "
                "`whoami && id && hostname && ip -br addr`. GHOST advances after that output is observed "
                "from the active container."
            )
        elif "ghost_services_enumerated" not in actions:
            answer = (
                f"The backend-confirmed target service is {ctx['target_ip']}:{ctx['target_port']}. "
                "Enumerate that room port with "
                f"`nmap -sV --version-light -T4 --max-retries 1 -p "
                f"{ctx['target_port']} {ctx['target_ip']}`."
            )
        elif ctx["task"]:
            answer = (
                f"Continue with the current backend-tracked task, “{ctx['task']['title']}”: "
                f"{ctx['task']['instructions']} "
                + (f"Try `{ctx['task_command']}`." if ctx["task_command"] else "")
            )
        else:
            answer = "All curriculum tasks are complete according to backend progress. Review the room's assessment criteria."
        return {
            "room_id": room_id,
            "question": q,
            "answer": answer,
            "mentor": "GHOST AI MENTOR",
            "provider": "backend-context",
            "ai_generated": False,
            "lab_status": ctx["lab_status"],
            "active_task_id": ctx["task"]["task_id"] if ctx["task"] else None,
        }
    if any(term in q_lower for term in ("target ip", "target address", "target host", "scan it", "scan the target")):
        if not ctx["target_ip"]:
            answer = (
                "The lab is not running, so Docker has not assigned a target IP yet. "
                "Start the lab first; GHOST will then use the address reported by the backend."
            )
        else:
            answer = (
                f"The active Docker lab reports target {ctx['target_ip']} on room service port "
                f"{ctx['target_port']}. "
            )
            if "nmap" in [tool.lower() for tool in ctx["room"].required_practical_skills]:
                answer += (
                    "To inspect that assigned service, run "
                    f"`nmap -sV --version-light -T4 --max-retries 1 -p "
                    f"{ctx['target_port']} {ctx['target_ip']}`."
                )
            else:
                answer += f"Use the room's listed tools against `{ctx['target_ip']}:{ctx['target_port']}`."
        return {
            "room_id": room_id,
            "question": q,
            "answer": answer,
            "mentor": "GHOST AI MENTOR",
            "provider": "backend-context",
            "ai_generated": False,
            "lab_status": ctx["lab_status"],
            "active_task_id": ctx["task"]["task_id"] if ctx["task"] else None,
        }
    try:
        from backend.app.labs.terminal import academy_terminal_handler

        terminal_session = (
            academy_terminal_handler._sessions.get(ctx["session"].session_id)
            if ctx["session"]
            else None
        )
        terminal_output = terminal_session.recent_output if terminal_session else []
        events = []
        async for event in ghost_service.stream_mentor_reply(
            session,
            user,
            {
                "message": q,
                "action": "auto",
                "mission_id": room_id,
                "stage": f"academy_step_{req.current_step or 1}",
                "screen": "academy_room",
                "terminal_output": terminal_output,
            },
        ):
            events.append(event)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    answer = "".join(event.get("text", "") for event in events if event.get("type") == "token")
    done = next((event for event in reversed(events) if event.get("type") == "done"), {})
    return {
        "room_id": room_id,
        "question": q,
        "answer": answer,
        "mentor": "GHOST AI MENTOR",
        "provider": done.get("provider"),
        "ai_generated": done.get("ai_generated", False),
        "lab_status": ctx["lab_status"],
        "active_task_id": ctx["task"]["task_id"] if ctx["task"] else None,
    }
