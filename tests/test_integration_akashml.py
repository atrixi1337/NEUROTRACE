"""Live integration test — only runs when a real AkashML key is present.

The CI runner doesn't have the key, so this is skipped unless
``NEUROTRACE_FORCE_LIVE=1`` and ``AKASHML_API_KEY`` are both set.
"""
from __future__ import annotations

import asyncio
import os

import pytest

from neurotrace.ai.analyst import ForensicAIAnalyst
from neurotrace.llm import get_provider
from neurotrace.llm.base import LLMError, LLMRequest


@pytest.mark.skipif(
    os.getenv("NEUROTRACE_FORCE_LIVE") != "1" or not os.getenv("AKASHML_API_KEY"),
    reason="set NEUROTRACE_FORCE_LIVE=1 and AKASHML_API_KEY to run live tests",
)
def test_akashml_live_json_call():
    p = get_provider("akashml")
    r = asyncio.run(p.chat(LLMRequest(
        system="Reply with strict JSON only.",
        user='Emit: {"status": "ok", "n": 1}',
        max_tokens=60,
        json_mode=True,
    )))
    assert r.parsed is not None
    assert r.parsed.get("status") == "ok"
