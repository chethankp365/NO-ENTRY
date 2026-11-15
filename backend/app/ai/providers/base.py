"""
Common provider-independent interface for Ghost AI LLM backends.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import AsyncIterator, Optional


class ProviderError(Exception):
    """Raised when an upstream AI provider fails, times out, or rejects a request."""

    def __init__(self, provider: str, message: str, retryable: bool = True):
        super().__init__(message)
        self.provider = provider
        self.message = message
        self.retryable = retryable


@dataclass
class ProviderResult:
    text: str
    provider: str
    model: str
    ai_generated: bool
    latency_ms: float = 0.0
    fallback_reason: Optional[str] = None


class AIProviderAdapter(ABC):
    """Base adapter implemented by Groq, Gemini, and OpenRouter backends."""

    name: str = "base"

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True iff the required API key is non-empty."""

    @abstractmethod
    def model_name(self) -> str:
        """Return configured model identifier for this provider."""

    @abstractmethod
    async def stream_chat(
        self,
        system_prompt: str,
        user_prompt: str,
        timeout: float,
    ) -> AsyncIterator[str]:
        """Yield streamed response text chunks cleanly."""
        if False:
            yield ""

