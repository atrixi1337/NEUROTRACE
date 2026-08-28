"""OpenAI-compatible provider.

Works with any service that exposes /v1/chat/completions in the OpenAI format:
- AkashML (https://akashml.com) — decentralized GPU inference
- OpenAI
- OpenRouter
- Ollama (http://host:11434/v1)
- vLLM, LM Studio, llama.cpp server, etc.

The official `openai` SDK is reused so retries, streaming, and tool calls
are all inherited for free.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from openai import AsyncOpenAI

from .base import (
    LLMError,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    LLMUsage,
    safe_json_loads,
)

logger = logging.getLogger("neurotrace.llm")


class OpenAICompatProvider(LLMProvider):
    """Generic OpenAI-compatible provider.

    Subclasses just set `name` and a sensible default model. Everything
    else (auth, transport, JSON-mode handling) is inherited.

    JSON-mode handling is provider-aware: we *try* the strict
    ``response_format={"type": "json_object"}`` first, and if the
    provider silently returns empty (AkashML does this), we retry
    without the flag and rely on the parser + system prompt to
    elicit valid JSON.
    """

    name: str = "openai-compat"

    def __init__(
        self,
        api_key: str,
        base_url: str,
        default_model: str,
        name: str = "openai-compat",
    ):
        super().__init__(api_key, base_url, default_model)
        self.name = name
        self._client = AsyncOpenAI(api_key=api_key, base_url=base_url)

    async def chat(self, request: LLMRequest) -> LLMResponse:
        model = self._resolve_model(request)
        messages = [
            {"role": "system", "content": request.system},
            {"role": "user", "content": request.user},
        ]

        base_kwargs: Dict[str, Any] = dict(
            model=model,
            messages=messages,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
        )
        base_kwargs.update(request.extra)

        text: str = ""
        usage = LLMUsage()
        last_exc: Optional[Exception] = None

        if request.json_mode:
            # Different providers behave very differently wrt the
            # strict JSON flag. AkashML's `openai/gpt-oss-20b` for example
            # currently returns empty content WITHOUT the flag but works
            # WITH it, while other models do the opposite. We try both
            # in turn and keep the first non-empty result.
            for label, use_flag in (("strict-JSON", True), ("plain", False)):
                try:
                    kwargs = dict(base_kwargs)
                    if use_flag:
                        kwargs["response_format"] = {"type": "json_object"}
                    resp = await self._client.chat.completions.create(**kwargs)
                    text = (resp.choices[0].message.content or "") if resp.choices else ""
                    usage = LLMUsage(
                        prompt_tokens=getattr(resp.usage, "prompt_tokens", 0) or 0,
                        completion_tokens=getattr(resp.usage, "completion_tokens", 0) or 0,
                        total_tokens=getattr(resp.usage, "total_tokens", 0) or 0,
                    )
                    if text.strip():
                        logger.debug("%s: JSON mode succeeded via %s path.", self.name, label)
                        break
                except Exception as exc:  # noqa: BLE001
                    last_exc = exc
                    logger.debug("%s: JSON mode %s path failed (%s).", self.name, label, exc)
        else:
            try:
                resp = await self._client.chat.completions.create(**base_kwargs)
                text = (resp.choices[0].message.content or "") if resp.choices else ""
                usage = LLMUsage(
                    prompt_tokens=getattr(resp.usage, "prompt_tokens", 0) or 0,
                    completion_tokens=getattr(resp.usage, "completion_tokens", 0) or 0,
                    total_tokens=getattr(resp.usage, "total_tokens", 0) or 0,
                )
            except Exception as exc:  # noqa: BLE001
                last_exc = exc

        if not text.strip():
            raise LLMError(
                f"{self.name} returned empty response "
                f"(last error: {last_exc})"
            )

        parsed: Optional[Dict[str, Any]] = None
        if request.json_mode:
            try:
                parsed = safe_json_loads(text)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "%s: JSON parse failed (%s); returning raw text.", self.name, exc
                )
        return LLMResponse(
            text=text,
            parsed=parsed,
            model=model,
            usage=usage,
            raw=text,
        )


class AkashMLProvider(OpenAICompatProvider):
    """AkashML — decentralized GPU inference, OpenAI-compatible.

    Docs: https://akashml.com/docs/getting-started/introduction
    Auth:  bearer `akml-...` key
    Base:  https://api.akashml.com/v1
    """

    name: str = "akashml"

    def __init__(self, api_key: str, model: str = "openai/gpt-oss-20b"):
        super().__init__(
            api_key=api_key,
            base_url="https://api.akashml.com/v1",
            default_model=model,
            name="akashml",
        )


class OpenAIProvider(OpenAICompatProvider):
    """OpenAI's own API."""

    name: str = "openai"

    def __init__(self, api_key: str, model: str = "openai/gpt-oss-20b"):
        super().__init__(
            api_key=api_key,
            base_url="https://api.openai.com/v1",
            default_model=model,
            name="openai",
        )


class OpenRouterProvider(OpenAICompatProvider):
    """OpenRouter — federated model catalog."""

    name: str = "openrouter"

    def __init__(self, api_key: str, model: str = "openai/gpt-oss-20b"):
        super().__init__(
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
            default_model=model,
            name="openrouter",
        )


class OllamaProvider(OpenAICompatProvider):
    """Ollama local server (no auth)."""

    name: str = "ollama"

    def __init__(self, base_url: str = "http://localhost:11434/v1",
                 model: str = "llama3.1:8b", api_key: str = "ollama"):
        super().__init__(
            api_key=api_key,
            base_url=base_url,
            default_model=model,
            name="ollama",
        )
