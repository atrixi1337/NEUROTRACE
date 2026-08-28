"""Provider registry and factory.

The engine calls ``get_provider(...)`` and the right implementation
is selected from ``.env``. Adding a new provider is a one-liner —
import its class and call ``register_provider`` once, or override
the auto-selected one with ``NEUROTRACE_LLM_PROVIDER=akashml``.
"""
from __future__ import annotations

import logging
import os
from typing import Dict, Type

from dotenv import load_dotenv

# Make sure the .env file is honoured regardless of import order.
load_dotenv(override=False)

from .base import LLMProvider, LLMError

logger = logging.getLogger("neurotrace.llm")

_REGISTRY: Dict[str, Type[LLMProvider]] = {}


def register_provider(name: str, cls: Type[LLMProvider]) -> None:
    """Register a provider class under a string key."""
    _REGISTRY[name] = cls
    logger.debug("Registered LLM provider: %s -> %s", name, cls.__name__)


def list_providers() -> Dict[str, Type[LLMProvider]]:
    return dict(_REGISTRY)


def get_provider(
    provider: str | None = None,
    model: str | None = None,
) -> LLMProvider:
    """Resolve and instantiate a provider from the registry.

    Selection order:
      1. Explicit `provider=` argument.
      2. ``NEUROTRACE_LLM_PROVIDER`` env var.
      3. Auto-detect: ``AKASHML_API_KEY`` → akashml, ``OPENAI_API_KEY`` → openai,
         ``OPENROUTER_API_KEY`` → openrouter, ``OLLAMA_BASE_URL`` → ollama.
    """
    # Lazy imports so missing optional deps don't break the registry.
    from .openai_compat import (
        AkashMLProvider,
        OpenAIProvider,
        OpenRouterProvider,
        OllamaProvider,
    )
    from .stub import StubProvider
    register_provider("akashml", AkashMLProvider)
    register_provider("openai", OpenAIProvider)
    register_provider("openrouter", OpenRouterProvider)
    register_provider("ollama", OllamaProvider)
    register_provider("stub", StubProvider)

    name = (provider or os.getenv("NEUROTRACE_LLM_PROVIDER") or "").lower().strip()
    if not name:
        if os.getenv("AKASHML_API_KEY"):
            name = "akashml"
        elif os.getenv("OPENROUTER_API_KEY"):
            name = "openrouter"
        elif os.getenv("OPENAI_API_KEY"):
            name = "openai"
        elif os.getenv("OLLAMA_BASE_URL") or os.getenv("NEUROTRACE_OLLAMA_URL"):
            name = "ollama"
        else:
            raise LLMError(
                "No LLM provider configured. Set one of:\n"
                "  AKASHML_API_KEY / OPENAI_API_KEY / OPENROUTER_API_KEY\n"
                "  OLLAMA_BASE_URL / NEUROTRACE_LLM_PROVIDER=<name>"
            )

    if name not in _REGISTRY:
        raise LLMError(
            f"Unknown LLM provider '{name}'. "
            f"Known: {sorted(_REGISTRY.keys())}"
        )

    cls = _REGISTRY[name]
    default_model = model or os.getenv("NEUROTRACE_LLM_MODEL") or "openai/gpt-oss-20b"

    if name == "akashml":
        api_key = os.getenv("AKASHML_API_KEY")
        return cls(api_key=api_key, model=default_model)  # type: ignore[arg-type]
    if name == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        return cls(api_key=api_key, model=default_model)  # type: ignore[arg-type]
    if name == "openrouter":
        api_key = os.getenv("OPENROUTER_API_KEY")
        return cls(api_key=api_key, model=default_model)  # type: ignore[arg-type]
    if name == "ollama":
        base = os.getenv("OLLAMA_BASE_URL") or os.getenv("NEUROTRACE_OLLAMA_URL") \
            or "http://localhost:11434/v1"
        return cls(base_url=base, model=default_model)  # type: ignore[arg-type]
    if name == "stub":
        # No API key required.
        return cls(model=default_model)  # type: ignore[arg-type]

    raise LLMError(f"Provider '{name}' has no factory branch (bug).")
