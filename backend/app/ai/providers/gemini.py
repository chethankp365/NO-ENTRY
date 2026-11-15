"""
Google Gemini LLM adapter using official `google-genai` Python SDK.
Dynamically discovers `generateContent`-capable models when GEMINI_MODEL is not explicitly overridden.
"""

import asyncio
import inspect
import re
from typing import Any, AsyncIterator, List, Optional, Tuple
from google import genai
from google.genai import types

from backend.app.config import settings
from backend.app.ai.safety import scrub_secrets
from backend.app.ai.providers.base import AIProviderAdapter, ProviderError

_EXCLUDED_TOKENS = ("image", "banana", "tts", "audio", "research", "embedding", "robotics", "computer-use", "customtools", "gemma")


def _extract_version(model_id: str) -> Tuple[int, int]:
    m = re.search(r"(\d+)(?:\.(\d+))?", model_id)
    if not m:
        return (0, 0)
    return (int(m.group(1)), int(m.group(2) or 0))


def _rank_gemini_candidates(models: List[Any]) -> List[str]:
    scored = []
    for m in models or []:
        actions = getattr(m, "supported_actions", None) or []
        if "generateContent" not in actions:
            continue
        raw_name = str(getattr(m, "name", "") or "").strip()
        model_id = raw_name[7:] if raw_name.startswith("models/") else raw_name
        if not model_id:
            continue
        low = model_id.lower()
        if not low.startswith("gemini-"):
            continue
        if any(tok in low for tok in _EXCLUDED_TOKENS):
            continue
        major, minor = _extract_version(low)
        is_flash = 1 if "flash" in low else 0
        is_lite = 1 if "lite" in low else 0
        is_preview = 0 if "preview" in low or "exp" in low else 1
        scored.append((major, is_preview, is_flash, is_lite, minor, model_id))
    scored.sort(key=lambda item: item[:5], reverse=True)
    return [item[5] for item in scored]


class GeminiProvider(AIProviderAdapter):
    name = "gemini"

    def __init__(self):
        self._resolved_model: Optional[str] = None
        self._cached_candidates: List[str] = []

    def is_configured(self) -> bool:
        return bool((settings.GEMINI_API_KEY or "").strip())

    def model_name(self) -> str:
        override = (settings.GEMINI_MODEL or "").strip()
        return override or self._resolved_model or "auto"

    async def _get_candidates(self, client: genai.Client, timeout: float) -> List[str]:
        override = (settings.GEMINI_MODEL or "").strip()
        if override:
            return [override]
        if self._cached_candidates:
            return list(self._cached_candidates)

        pager = await asyncio.wait_for(client.aio.models.list(), timeout=min(10.0, timeout))
        items = []
        if hasattr(pager, "__aiter__"):
            async for m in pager:
                items.append(m)
        else:
            items = list(pager or [])
        candidates = _rank_gemini_candidates(items)
        if not candidates:
            raise ProviderError(self.name, "No generateContent models available on Gemini account.", retryable=False)
        self._cached_candidates = candidates
        return list(candidates)

    async def stream_chat(
        self,
        system_prompt: str,
        user_prompt: str,
        timeout: float,
    ) -> AsyncIterator[str]:
        api_key = (settings.GEMINI_API_KEY or "").strip()
        if not api_key:
            raise ProviderError(self.name, "GEMINI_API_KEY is not configured.", retryable=False)

        client = genai.Client(
            api_key=api_key,
            http_options=types.HttpOptions(
                api_version="v1beta",
                timeout=int(max(5.0, timeout) * 1000),
            ),
        )
        config = types.GenerateContentConfig(
            system_instruction=system_prompt,
            temperature=0.35,
            max_output_tokens=500,
        )
        emitted = False

        try:
            candidates = await self._get_candidates(client, timeout)
            last_error: Optional[ProviderError] = None

            for model in candidates[:4]:
                try:
                    stream_call = client.aio.models.generate_content_stream(
                        model=model,
                        contents=user_prompt,
                        config=config,
                    )
                    stream = await asyncio.wait_for(stream_call, timeout=timeout) if inspect.isawaitable(stream_call) else stream_call

                    async for chunk in stream:
                        text = getattr(chunk, "text", None)
                        if text:
                            if not emitted:
                                self._resolved_model = model
                            emitted = True
                            yield text

                    if emitted:
                        return
                    last_error = ProviderError(self.name, "Gemini returned an empty completion stream.", retryable=True)
                except ProviderError as exc:
                    last_error = exc
                    if emitted:
                        raise
                except asyncio.TimeoutError as exc:
                    if emitted:
                        return
                    last_error = ProviderError(self.name, "Gemini request timed out.", retryable=True)
                    if (settings.GEMINI_MODEL or "").strip():
                        raise last_error from exc
                except Exception as exc:
                    msg = scrub_secrets(str(exc))
                    low = msg.lower()
                    if not (settings.GEMINI_MODEL or "").strip() and (
                        "404" in low
                        or "not_found" in low
                        or "developer instruction" in low
                        or "invalid_argument" in low
                        or "429" in low
                        or "resource_exhausted" in low
                        or "quota" in low
                        or "503" in low
                        or "unavailable" in low
                        or "high demand" in low
                    ):
                        self._cached_candidates = [c for c in self._cached_candidates if c != model]
                        if self._resolved_model == model:
                            self._resolved_model = None
                        last_error = ProviderError(self.name, msg, retryable=True)
                        continue
                    retryable = not ("api_key" in low or "permission_denied" in low or "401" in low or "403" in low)
                    raise ProviderError(self.name, msg, retryable=retryable) from exc

            if last_error:
                raise last_error
        except ProviderError:
            raise
        except Exception as exc:
            msg = scrub_secrets(str(exc))
            low = msg.lower()
            retryable = not ("api_key" in low or "permission_denied" in low or "401" in low or "403" in low)
            raise ProviderError(self.name, msg, retryable=retryable) from exc
