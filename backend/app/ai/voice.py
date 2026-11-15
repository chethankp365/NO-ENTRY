"""
Deepgram Voice integration for Ghost:
- Speech-to-Text (`/v1/listen`)
- Text-to-Speech (`/v1/speak`)
Uses Deepgram's built-in provider defaults unless optionally overridden.
Validates MIME type & size, never persists audio bytes to disk, never leaks API keys.
"""

from typing import Any, Dict
import httpx

from backend.app.config import settings
from backend.app.ai.safety import MAX_TTS_CHARS, normalize_control_chars, scrub_secrets

DEEPGRAM_STT_URL = "https://api.deepgram.com/v1/listen"
DEEPGRAM_TTS_URL = "https://api.deepgram.com/v1/speak"

MAX_AUDIO_BYTES = 5 * 1024 * 1024  # 5 MB strict ceiling

ALLOWED_AUDIO_TYPES = {
    "audio/webm",
    "audio/wav",
    "audio/x-wav",
    "audio/wave",
    "audio/ogg",
    "audio/mpeg",
    "audio/mp3",
    "audio/mp4",
    "audio/aac",
}


class VoiceServiceError(Exception):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = scrub_secrets(message)


def normalize_audio_mime(content_type: str) -> str:
    raw = (content_type or "audio/webm").split(";")[0].strip().lower()
    if raw not in ALLOWED_AUDIO_TYPES:
        raise VoiceServiceError(
            400,
            f"Unsupported audio format '{raw}'. Allowed types: webm, wav, ogg, mp3, mp4.",
        )
    return raw


class DeepgramVoiceService:
    def is_configured(self) -> bool:
        return bool((settings.DEEPGRAM_API_KEY or "").strip())

    def get_status(self) -> Dict[str, Any]:
        configured = self.is_configured()
        return {
            "configured": configured,
            "provider": "deepgram",
            "stt_model": (settings.DEEPGRAM_STT_MODEL or "").strip() or "provider-default",
            "tts_model": (settings.DEEPGRAM_TTS_MODEL or "").strip() or "provider-default",
            "status": "ready" if configured else "unconfigured",
        }

    async def transcribe_audio(self, audio_bytes: bytes, content_type: str) -> Dict[str, Any]:
        api_key = (settings.DEEPGRAM_API_KEY or "").strip()
        if not api_key:
            raise VoiceServiceError(503, "Deepgram STT unavailable: DEEPGRAM_API_KEY is not configured.")

        if not audio_bytes:
            raise VoiceServiceError(400, "Uploaded audio recording is empty.")
        if len(audio_bytes) > MAX_AUDIO_BYTES:
            raise VoiceServiceError(413, "Audio file exceeds maximum size of 5 MB.")

        mime = normalize_audio_mime(content_type)
        opt_model = (settings.DEEPGRAM_STT_MODEL or "").strip()
        headers = {
            "Authorization": f"Token {api_key}",
            "Content-Type": mime,
        }
        params: Dict[str, str] = {"smart_format": "true"}
        if opt_model:
            params["model"] = opt_model

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(DEEPGRAM_STT_URL, params=params, headers=headers, content=audio_bytes)
        except httpx.TimeoutException as exc:
            raise VoiceServiceError(504, "Deepgram STT request timed out.") from exc
        except Exception as exc:
            raise VoiceServiceError(502, f"Deepgram STT network error: {scrub_secrets(str(exc))}") from exc

        if resp.status_code >= 400:
            raise VoiceServiceError(
                502 if resp.status_code >= 500 else resp.status_code,
                f"Deepgram STT error (HTTP {resp.status_code}).",
            )

        try:
            payload = resp.json()
            alt = payload["results"]["channels"][0]["alternatives"][0]
            transcript = str(alt.get("transcript") or "").strip()
            confidence = float(alt.get("confidence") or 0.0)
        except Exception as exc:
            raise VoiceServiceError(502, "Deepgram STT returned malformed transcript payload.") from exc

        if not transcript:
            raise VoiceServiceError(422, "No clear speech detected in microphone audio.")

        return {
            "transcript": transcript,
            "confidence": round(confidence, 3),
            "provider": "deepgram",
            "model": opt_model or "provider-default",
        }

    async def synthesize_speech(self, text: str) -> bytes:
        api_key = (settings.DEEPGRAM_API_KEY or "").strip()
        if not api_key:
            raise VoiceServiceError(503, "Deepgram TTS unavailable: DEEPGRAM_API_KEY is not configured.")

        cleaned = normalize_control_chars(text or "").strip()
        if not cleaned:
            raise VoiceServiceError(400, "TTS text cannot be empty.")
        if len(cleaned) > MAX_TTS_CHARS:
            cleaned = cleaned[:MAX_TTS_CHARS]

        opt_model = (settings.DEEPGRAM_TTS_MODEL or "").strip()
        headers = {
            "Authorization": f"Token {api_key}",
            "Content-Type": "application/json",
        }
        params: Dict[str, str] = {"model": opt_model} if opt_model else {}

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(DEEPGRAM_TTS_URL, params=params, headers=headers, json={"text": cleaned})
        except httpx.TimeoutException as exc:
            raise VoiceServiceError(504, "Deepgram TTS request timed out.") from exc
        except Exception as exc:
            raise VoiceServiceError(502, f"Deepgram TTS network error: {scrub_secrets(str(exc))}") from exc

        if resp.status_code >= 400 or not resp.content:
            raise VoiceServiceError(503, f"Deepgram TTS unavailable (HTTP {resp.status_code}).")

        return resp.content


voice_service = DeepgramVoiceService()

