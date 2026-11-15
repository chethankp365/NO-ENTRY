"""
OpenRouter LLM adapter using official HTTPS Server-Sent Events API via httpx.
Dynamically discovers zero-cost/router endpoints from OpenRouter's catalog when OPENROUTER_MODEL is not explicitly overridden.
"""

import json
from typing import AsyncIterator, List, Optional
import httpx

from backend.app.config import settings
from backend.app.ai.safety import scrub_secrets
from backend.app.ai.providers.base import AIProviderAdapter, ProviderError

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models"


class OpenRouterProvider(AIProviderAdapter):
    name = "openrouter"

    def __init__(self):
        self._resolved_model: Optional[str] = None
        self._cached_candidates: List[str] = []

    def is_configured(self) -> bool:
        return bool((settings.OPENROUTER_API_KEY or "").strip())

    def model_name(self) -> str:
        override = (settings.OPENROUTER_MODEL or "").strip()
        return override or self._resolved_model or "auto"

    async def _get_candidates(self, client: httpx.AsyncClient, api_key: str) -> List[str]:
        override = (settings.OPENROUTER_MODEL or "").strip()
        if override:
            return [override]
        if self._cached_candidates:
            return list(self._cached_candidates)

        resp = await client.get(
            OPENROUTER_MODELS_URL,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10.0,
        )
        if resp.status_code >= 400:
            raise ProviderError(self.name, f"OpenRouter model discovery HTTP {resp.status_code}.", retryable=True)

        data = resp.json().get("data") or []
        routers: List[str] = []
        free_models: List[str] = []
        for item in data:
            mid = str(item.get("id") or "").strip()
            if not mid:
                continue
            pricing = item.get("pricing") or {}
            is_zero = str(pricing.get("prompt", "")) == "0" and str(pricing.get("completion", "")) == "0"
            if not is_zero:
                continue
            low = mid.lower()
            if any(skip in low for skip in ("embed", "whisper", "tts", "audio")):
                continue
            if low.startswith("openrouter/") and "free" in low:
                routers.append(mid)
            else:
                free_models.append(mid)

        candidates = routers + free_models[:4]
        if not candidates:
            raise ProviderError(self.name, "No free/default models returned by OpenRouter catalog.", retryable=False)
        self._cached_candidates = candidates
        return list(candidates)

    async def stream_chat(
        self,
        system_prompt: str,
        user_prompt: str,
        timeout: float,
    ) -> AsyncIterator[str]:
        api_key = (settings.OPENROUTER_API_KEY or "").strip()
        if not api_key:
            raise ProviderError(self.name, "OPENROUTER_API_KEY is not configured.", retryable=False)

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://127.0.0.1:8000",
            "X-Title": "NO ENTRY Cyber Range",
        }

        emitted = False
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                candidates = await self._get_candidates(client, api_key)
                last_error: Optional[ProviderError] = None

                for model in candidates[:3]:
                    payload = {
                        "model": model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        "temperature": 0.35,
                        "max_tokens": 500,
                        "stream": True,
                    }

                    async with client.stream("POST", OPENROUTER_API_URL, headers=headers, json=payload) as resp:
                        if resp.status_code >= 400:
                            raw_body = (await resp.aread()).decode("utf-8", errors="replace")[:200]
                            retryable = resp.status_code in (408, 429) or resp.status_code >= 500
                            err = ProviderError(
                                self.name,
                                f"OpenRouter HTTP {resp.status_code}: {scrub_secrets(raw_body)}",
                                retryable=retryable,
                            )
                            if not (settings.OPENROUTER_MODEL or "").strip() and resp.status_code in (400, 404, 429):
                                self._cached_candidates = [c for c in self._cached_candidates if c != model]
                                last_error = err
                                continue
                            raise err

                        async for line in resp.aiter_lines():
                            if not line or not line.startswith("data: "):
                                continue
                            data_str = line[6:].strip()
                            if data_str == "[DONE]":
                                break
                            try:
                                chunk = json.loads(data_str)
                            except json.JSONDecodeError:
                                continue
                            routed_model = chunk.get("model")
                            if routed_model and not emitted:
                                self._resolved_model = str(routed_model)
                            choices = chunk.get("choices") or []
                            if not choices:
                                continue
                            delta = choices[0].get("delta") or {}
                            content = delta.get("content")
                            if content:
                                if not emitted and not self._resolved_model:
                                    self._resolved_model = model
                                emitted = True
                                yield content

                    if emitted:
                        return
                    last_error = ProviderError(self.name, "OpenRouter returned an empty completion stream.", retryable=True)

                if last_error:
                    raise last_error
        except ProviderError:
            raise
        except httpx.TimeoutException as exc:
            raise ProviderError(self.name, "OpenRouter request timed out.", retryable=True) from exc
        except Exception as exc:
            raise ProviderError(self.name, scrub_secrets(str(exc)), retryable=True) from exc
