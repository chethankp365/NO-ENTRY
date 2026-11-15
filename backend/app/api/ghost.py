"""
REST & SSE API router for Ghost AI Mentor and Deepgram Voice Integration.
"""

import json
from typing import Any, Dict, List, Literal, Optional
from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile
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

