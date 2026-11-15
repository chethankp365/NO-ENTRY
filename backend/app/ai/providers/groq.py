"""
Groq LLM adapter using official `groq` AsyncGroq Python SDK.
Dynamically discovers active chat models from the Groq account when GROQ_MODEL is not explicitly overridden.
"""

import asyncio
from typing import Any, AsyncIterator, List, Optional
from groq import AsyncGroq

from backend.app.config import settings
from backend.app.ai.safety import scrub_secrets
from backend.app.ai.providers.base import AIProviderAdapter, ProviderError

_EXCLUDED_TOKENS = ("whisper", "orpheus", "guard", "safeguard", "tts", "moderation", "embed")


def _select_chat_candidates(models: List[Any]) -> List[str]:
    scored = []
    for m in models or []:
        mid = str(getattr(m, "id", "") or "").strip()
        if not mid:
            continue
        if getattr(m, "active", True) is False:
            continue
        low = mid.lower()
        if any(tok in low for tok in _EXCLUDED_TOKENS):
            continue
        ctx_window = int(getattr(m, "context_window", 0) or 0)
        if ctx_window and ctx_window < 8192:
            continue
        general_pref = 0 if "allam" in low else 1
        scored.append((general_pref, ctx_window, mid))
    scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [item[2] for item in scored]


class GroqProvider(AIProviderAdapter):
    name = "groq"

    def __init__(self):
        self._resolved_model: Optional[str] = None
        self._cached_candidates: List[str] = []

    def is_configured(self) -> bool:
        return bool((settings.GROQ_API_KEY or "").strip())

    def model_name(self) -> str:
        override = (settings.GROQ_MODEL or "").strip()
        return override or self._resolved_model or "auto"

    async def _get_candidates(self, client: AsyncGroq, timeout: float) -> List[str]:
        override = (settings.GROQ_MODEL or "").strip()
        if override:
            return [override]
        if self._cached_candidates:
            return list(self._cached_candidates)

        listing = await asyncio.wait_for(client.models.list(), timeout=min(10.0, timeout))
        candidates = _select_chat_candidates(getattr(listing, "data", []) or [])
        if not candidates:
            raise ProviderError(self.name, "No active chat models available on Groq account.", retryable=False)
        self._cached_candidates = candidates
        return list(candidates)

    async def stream_chat(
        self,
        system_prompt: str,
        user_prompt: str,
        timeout: float,
    ) -> AsyncIterator[str]:
        api_key = (settings.GROQ_API_KEY or "").strip()
        if not api_key:
            raise ProviderError(self.name, "GROQ_API_KEY is not configured.", retryable=False)

        client = AsyncGroq(api_key=api_key, timeout=timeout)
        emitted = False

        try:
            candidates = await self._get_candidates(client, timeout)
            last_error: Optional[ProviderError] = None

            for model in candidates[:3]:
                try:
                    stream = await asyncio.wait_for(
                        client.chat.completions.create(
                            model=model,
                            messages=[
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": user_prompt},
                            ],
                            temperature=0.35,
                            max_tokens=500,
                            stream=True,
                        ),
                        timeout=timeout,
                    )
                    async for chunk in stream:
                        choices = getattr(chunk, "choices", None) or []
                        if not choices:
                            continue
                        delta = getattr(choices[0], "delta", None)
                        text = getattr(delta, "content", None) if delta else None
                        if text:
                            if not emitted:
                                self._resolved_model = model
                            emitted = True
                            yield text

                    if emitted:
                        return
                    last_error = ProviderError(self.name, "Groq returned an empty completion stream.", retryable=True)
                except ProviderError as exc:
                    last_error = exc
                    if emitted:
                        raise
                except asyncio.TimeoutError as exc:
                    raise ProviderError(self.name, "Groq request timed out.", retryable=True) from exc
                except Exception as exc:
                    status_code = getattr(exc, "status_code", None)
                    msg = scrub_secrets(str(exc))
                    if status_code in (400, 404) and not (settings.GROQ_MODEL or "").strip():
                        # Try next discovered model when auto-resolving
                        self._cached_candidates = [c for c in self._cached_candidates if c != model]
                        if self._resolved_model == model:
                            self._resolved_model = None
                        last_error = ProviderError(self.name, msg, retryable=True)
                        continue
                    retryable = status_code not in (400, 401, 403, 404)
                    raise ProviderError(self.name, msg, retryable=retryable) from exc

            if last_error:
                raise last_error
        finally:
            try:
                await client.close()
            except Exception:
                pass
