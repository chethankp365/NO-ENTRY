"""
Multi-provider AI orchestrator for Ghost.
Selects providers strictly by configured priority (default: Groq -> Gemini -> OpenRouter),
handles timeouts, bounded retries, automatic failover, and clear non-fabricated status reporting.
"""

import time
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

from backend.app.config import settings
from backend.app.ai.safety import scrub_secrets
from backend.app.ai.providers.base import AIProviderAdapter, ProviderError
from backend.app.ai.providers.groq import GroqProvider
from backend.app.ai.providers.gemini import GeminiProvider
from backend.app.ai.providers.openrouter import OpenRouterProvider


class AllProvidersUnavailableError(Exception):
    """Raised when no LLM provider is configured or all configured providers failed."""

    def __init__(self, reason: str, errors: Optional[Dict[str, str]] = None):
        super().__init__(reason)
        self.reason = reason
        self.errors = errors or {}


class AIOrchestrator:
    """Coordinates provider priority, retry limits, failover, and telemetry without secret leakage."""

    def __init__(self):
        self.adapters: Dict[str, AIProviderAdapter] = {
            "groq": GroqProvider(),
            "gemini": GeminiProvider(),
            "openrouter": OpenRouterProvider(),
        }
        self._last_errors: Dict[str, str] = {}
        self._last_latency_ms: Dict[str, float] = {}

    def get_priority(self) -> List[str]:
        return settings.provider_priority_list

    def any_llm_configured(self) -> bool:
        return any(self.adapters[name].is_configured() for name in self.get_priority() if name in self.adapters)

    def get_status(self) -> Dict[str, Any]:
        priority = self.get_priority()
        providers_info = []
        any_ready = False
        for name in priority:
            adapter = self.adapters.get(name)
            if not adapter:
                continue
            configured = adapter.is_configured()
            if configured:
                any_ready = True
            providers_info.append({
                "name": name,
                "configured": configured,
                "model": adapter.model_name(),
                "status": "ready" if configured else "unconfigured",
                "last_error": self._last_errors.get(name),
                "last_latency_ms": self._last_latency_ms.get(name),
            })

        return {
            "ai_online": any_ready,
            "priority": priority,
            "providers": providers_info,
            "local_inference": {
                "tflite_configured": False,
                "note": "No TensorFlow Lite (.tflite) model exists in project; optional local inference is disabled.",
            },
        }

    async def stream_with_fallback(
        self,
        system_prompt: str,
        user_prompt: str,
        timeout: Optional[float] = None,
        max_retries: Optional[int] = None,
    ) -> AsyncIterator[Tuple[str, str, str]]:
        """
        Yields tuples of `(provider_name, model_name, token_chunk)` from the highest-priority
        working provider. Stops immediately after that provider succeeds (never calls multiple
        providers redundantly on success). Raises AllProvidersUnavailableError if none succeed.
        """
        eff_timeout = float(timeout or settings.AI_REQUEST_TIMEOUT_SEC or 20.0)
        eff_retries = max(0, int(settings.AI_MAX_RETRIES if max_retries is None else max_retries))
        priority = self.get_priority()

        configured_names = [p for p in priority if p in self.adapters and self.adapters[p].is_configured()]
        if not configured_names:
            raise AllProvidersUnavailableError("No LLM API keys configured.")

        attempt_errors: Dict[str, str] = {}

        for provider_name in configured_names:
            adapter = self.adapters[provider_name]

            for attempt in range(eff_retries + 1):
                t0 = time.perf_counter()
                emitted_any = False
                try:
                    async for chunk in adapter.stream_chat(system_prompt, user_prompt, eff_timeout):
                        if chunk:
                            emitted_any = True
                            yield (provider_name, adapter.model_name(), chunk)

                    if emitted_any:
                        self._last_latency_ms[provider_name] = round((time.perf_counter() - t0) * 1000.0, 1)
                        self._last_errors.pop(provider_name, None)
                        return
                except ProviderError as exc:
                    err_clean = scrub_secrets(exc.message)
                    attempt_errors[provider_name] = err_clean
                    self._last_errors[provider_name] = err_clean
                    if emitted_any:
                        # Stream already started delivering real content to user; avoid duplicating with another provider
                        self._last_latency_ms[provider_name] = round((time.perf_counter() - t0) * 1000.0, 1)
                        return
                    if not exc.retryable or attempt >= eff_retries:
                        break
                except Exception as exc:
                    err_clean = scrub_secrets(str(exc))
                    attempt_errors[provider_name] = err_clean
                    self._last_errors[provider_name] = err_clean
                    if emitted_any:
                        return
                    if attempt >= eff_retries:
                        break

        raise AllProvidersUnavailableError(
            "All configured AI providers failed or timed out.",
            errors=attempt_errors,
        )


orchestrator = AIOrchestrator()

