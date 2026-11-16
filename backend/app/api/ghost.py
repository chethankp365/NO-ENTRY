"""
REST & SSE API router for Ghost AI Mentor and Deepgram Voice Integration.
"""

import json
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


@ghost_router.get("/room/{room_id}/guide")
def api_ghost_room_guide(
    room_id: str,
    user: User = Depends(resolve_operator),
    session: Session = Depends(get_session),
):
    """Retrieve structured 6-step guided path for the given room."""
    from backend.app.academy.curriculum import curriculum_registry
    from backend.app.labs.manager import lab_manager

    room = curriculum_registry.get_room(room_id)
    if not room:
        raise HTTPException(status_code=404, detail=f"Room '{room_id}' not found.")

    session_info = lab_manager.get_user_session(user.operator_id, room_id)
    target_ip = session_info.target_ip if session_info else "10.10.14.90"
    target_port = session_info.target_port if session_info else (room.default_port or 8089)

    first_task = room.tasks[0] if room.tasks else None
    task_desc = first_task.instructions if first_task else room.short_description
    primary_tool = room.required_practical_skills[0] if room.required_practical_skills else "curl"

    steps = [
        {
            "step": 1,
            "title": "Understand Environment",
            "goal": "Verify operator identity and local workstation privileges.",
            "tool": "whoami / id",
            "command": "whoami && id && pwd",
            "explanation": "Confirms you are executing as the unprivileged 'operator' user on the isolated attacker workstation.",
        },
        {
            "step": 2,
            "title": "Identify Network & Target",
            "goal": f"Verify interface addressing and reachability to target host ({target_ip}).",
            "tool": "ip / ping",
            "command": f"ip -br addr && ping -c 2 {target_ip}",
            "explanation": f"Checks your attacker IP (10.10.x.10) and confirms low-latency IP routing to the target ({target_ip}) on the zero-trust bridge.",
        },
        {
            "step": 3,
            "title": "Enumerate Target Services",
            "goal": f"Scan target ports and identify running services and versions.",
            "tool": "nmap",
            "command": f"nmap -sV -p 22,80,{target_port} {target_ip}",
            "explanation": f"Discovers open ports (SSH 22, HTTP 80, App {target_port}) and fingerprints service daemon versions.",
        },
        {
            "step": 4,
            "title": "Execute Practical Exercise Probe",
            "goal": f"Test the target service according to the room objective: {room.title}",
            "tool": primary_tool,
            "command": f"curl -s -i http://{target_ip}:{target_port}/",
            "explanation": f"Interacts directly with the target endpoint to gather HTTP headers, application state, and security banners.",
        },
        {
            "step": 5,
            "title": "Analyze Results & Formulate Solution",
            "goal": f"Examine response data and apply security techniques: {task_desc[:80]}...",
            "tool": "analysis",
            "command": f"curl -s http://{target_ip}:{target_port}/ | grep -iE 'error|voltgear|version|admin|user'",
            "explanation": "Filters output for vulnerable parameters, sensitive keywords, or telemetry signatures required to complete the mission.",
        },
        {
            "step": 6,
            "title": "Verify Remediation & Complete Task",
            "goal": "Submit task answer or flag to validate completion.",
            "tool": "validator",
            "command": "cat /home/operator/loot/* 2>/dev/null || echo 'Review task instructions on the left pane.'",
            "explanation": "Confirm successful exploit, rule detection, or log analysis and submit the solution into the task verification box.",
        },
    ]

    return {
        "room_id": room.room_id,
        "title": room.title,
        "track": room.track.value if hasattr(room.track, "value") else str(room.track),
        "difficulty": room.difficulty,
        "target_ip": target_ip,
        "target_port": target_port,
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
    """Return progressive, actionable hint (Levels 1 to 4) for the active room task."""
    from backend.app.academy.curriculum import curriculum_registry
    from backend.app.labs.manager import lab_manager

    room = curriculum_registry.get_room(room_id)
    if not room:
        raise HTTPException(status_code=404, detail=f"Room '{room_id}' not found.")

    session_info = lab_manager.get_user_session(user.operator_id, room_id)
    target_ip = session_info.target_ip if session_info else "10.10.14.90"
    target_port = session_info.target_port if session_info else (room.default_port or 8089)

    active_task = None
    if task_id:
        for t in room.tasks:
            if t.task_id == task_id:
                active_task = t
                break
    if not active_task and room.tasks:
        active_task = room.tasks[0]

    title = active_task.title if active_task else room.title
    primary_tool = room.required_practical_skills[0] if room.required_practical_skills else "curl"

    hints = {
        1: {
            "level": 1,
            "label": "Conceptual Objective",
            "hint": f"Objective: {title}. Focus on understanding how the system behaves under standard operation versus attack conditions.",
            "command": None,
        },
        2: {
            "level": 2,
            "label": "Tool Selection & Syntax",
            "hint": f"Recommended tool: {primary_tool}. Target address is {target_ip}:{target_port}. Inspect service responses and parameters.",
            "command": None,
        },
        3: {
            "level": 3,
            "label": "Actionable Command",
            "hint": "Execute this command in the terminal to probe the target directly:",
            "command": f"curl -s -i http://{target_ip}:{target_port}/",
        },
        4: {
            "level": 4,
            "label": "Result Interpretation",
            "hint": f"Look at the HTTP response or logs. Once confirmed, enter your answer or flag into the task box on the left pane.",
            "command": f"nmap -sV -p {target_port} {target_ip}",
        },
    }

    selected = hints.get(level, hints[1])
    return {
        "room_id": room_id,
        "task_id": active_task.task_id if active_task else None,
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
    """Answer learner's question with room and lab context, utilizing AI or deterministic curriculum knowledge."""
    from backend.app.academy.curriculum import curriculum_registry
    from backend.app.labs.manager import lab_manager

    room = curriculum_registry.get_room(room_id)
    if not room:
        raise HTTPException(status_code=404, detail=f"Room '{room_id}' not found.")

    session_info = lab_manager.get_user_session(user.operator_id, room_id)
    target_ip = session_info.target_ip if session_info else "10.10.14.90"
    target_port = session_info.target_port if session_info else (room.default_port or 8089)

    q = req.question.strip()

    answer = None
    try:
        from backend.app.ai.orchestrator import orchestrator
        prompt = (
            f"You are GHOST, the elite cybersecurity AI mentor for NO ENTRY Academy. "
            f"The learner is in Room: '{room.title}' ({room_id}), Track: {room.track.value if hasattr(room.track, 'value') else room.track}. "
            f"Target IP: {target_ip}, Port: {target_port}. "
            f"Learner question: {q}\n"
            f"Provide a concise, practical, technical answer with a suggested terminal command if appropriate."
        )
        reply = await orchestrator.generate_text(prompt, max_tokens=350)
        if reply and reply.strip():
            answer = reply.strip()
    except Exception:
        pass

    if not answer:
        q_lower = q.lower()
        if "target" in q_lower or "ip" in q_lower or "address" in q_lower:
            answer = f"The target machine is hosted at `{target_ip}` on port `{target_port}`. You can probe it with `curl -s http://{target_ip}:{target_port}/` or scan it with `nmap -sV -p 22,80,{target_port} {target_ip}`."
        elif "tool" in q_lower or "command" in q_lower or "how" in q_lower:
            tools_str = ", ".join(room.required_practical_skills) if room.required_practical_skills else "curl, nmap, python3"
            answer = f"For {room.title}, the recommended tools are: {tools_str}. Start by probing `{target_ip}:{target_port}`."
        elif "flag" in q_lower or "answer" in q_lower:
            answer = "Examine the output of your exploit or inspection command. Look for key values or tokens produced by the target service, then paste into the task submission box."
        else:
            answer = f"GHOST MENTOR // {room.title}: Ensure your lab is RUNNING (click 'START LAB'). Verify connectivity with `ping -c 2 {target_ip}`, then run `nmap -sV -p 22,80,{target_port} {target_ip}` to discover service details."

    return {
        "room_id": room_id,
        "question": q,
        "answer": answer,
        "mentor": "GHOST AI MENTOR",
    }

