"""Base LLM provider interface.

NEUROTRACE supports any OpenAI-compatible chat-completions endpoint.
AkashML is shipped as the first preset, but the provider layer is
provider-agnostic so OpenAI, Anthropic (via gateway), Ollama, and any
other OpenAI-compatible service can be added with a one-line registration.
"""
from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, List, Optional

logger = logging.getLogger("neurotrace.llm")


class LLMError(RuntimeError):
    """Raised when an LLM provider cannot complete a request."""


@dataclass
class LLMUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: Optional[float] = None


@dataclass
class LLMRequest:
    system: str
    user: str
    model: Optional[str] = None
    temperature: float = 0.2
    max_tokens: int = 2048
    json_mode: bool = False
    response_schema_hint: Optional[str] = None  # human-readable JSON schema
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMResponse:
    text: str
    parsed: Optional[Dict[str, Any]] = None  # populated when json_mode=True
    model: str = ""
    usage: LLMUsage = field(default_factory=LLMUsage)
    raw: Any = None


class LLMProvider(abc.ABC):
    """Abstract base for OpenAI-compatible chat providers."""

    name: str = "base"

    def __init__(self, api_key: str, base_url: str, default_model: str):
        if not api_key:
            raise LLMError(f"Provider {self.name} requires an API key.")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model

    @abc.abstractmethod
    async def chat(self, request: LLMRequest) -> LLMResponse:
        """Send a chat-completions request and return the response."""

    def _resolve_model(self, request: LLMRequest) -> str:
        return request.model or self.default_model


def strip_markdown_fences(text: str) -> str:
    """Some providers wrap JSON in ```json ... ```. Strip the fences."""
    s = text.strip()
    if s.startswith("```"):
        # remove first fence line
        parts = s.split("```", 2)
        if len(parts) >= 2:
            s = parts[1]
        if s.startswith("json"):
            s = s[4:]
        if s.endswith("```"):
            s = s[:-3]
    return s.strip()


def safe_json_loads(text: str) -> Dict[str, Any]:
    import json
    cleaned = strip_markdown_fences(text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        # Try to find the first {...} block
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(cleaned[start:end + 1])
        raise
