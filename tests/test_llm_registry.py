"""LLM provider tests.

Smoke-tests the registry and stub provider. The AkashML live call
is exercised in the integration test only when a real key is present.
"""
from __future__ import annotations

import asyncio
import pytest

from neurotrace.llm import get_provider
from neurotrace.llm.base import LLMError, LLMRequest


def test_stub_provider_returns_consistent_score():
    """The stub provider should return a deterministic threat score."""
    from neurotrace.llm.stub import StubProvider

    p = StubProvider()
    r1 = asyncio.run(p.chat(LLMRequest(
        system="x", user="cobalt injection beacon", json_mode=True,
    )))
    r2 = asyncio.run(p.chat(LLMRequest(
        system="x", user="cobalt injection beacon", json_mode=True,
    )))
    assert r1.parsed is not None
    assert r2.parsed is not None
    assert r1.parsed["calculated_risk_score"] == r2.parsed["calculated_risk_score"]


def test_stub_yara_is_valid_minimal_form():
    from neurotrace.llm.stub import StubProvider
    p = StubProvider()
    r = asyncio.run(p.chat(LLMRequest(
        system="x", user="mimikatz credential", json_mode=True,
    )))
    rule = r.parsed["yara_rule"]
    assert rule.startswith("rule ")
    assert "condition:" in rule
    assert "strings:" in rule


def test_registry_returns_provider_by_name():
    p = get_provider("stub")
    assert p.name == "stub"
    assert p.default_model  # not empty


def test_registry_auto_selects_with_key(monkeypatch):
    monkeypatch.setenv("NEUROTRACE_LLM_PROVIDER", "akashml")
    monkeypatch.setenv("AKASHML_API_KEY", "fake")
    p = get_provider()
    assert p.name == "akashml"
    assert p.default_model == "openai/gpt-oss-20b"


def test_registry_raises_when_nothing_configured(monkeypatch):
    for k in ("NEUROTRACE_LLM_PROVIDER", "AKASHML_API_KEY", "OPENAI_API_KEY",
              "OPENROUTER_API_KEY", "OLLAMA_BASE_URL", "NEUROTRACE_OLLAMA_URL"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(LLMError):
        get_provider()
