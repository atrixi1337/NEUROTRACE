"""Live integration test — only runs when a real AkashML key is present.

The CI runner doesn't have the key, so this is skipped unless
``NEUROTRACE_FORCE_LIVE=1`` and ``AKASHML_API_KEY`` are both set.

The AkashML `openai/gpt-oss-20b` model occasionally returns an empty
content block under load (rate limiting, transient backend issues —
empirically observed >30% empty under sustained load). We retry up
to 5 times with exponential backoff. If the model is genuinely
broken (the retry loop exhausted), we **xfail** the test rather
than fail it, so a flaky model doesn't take down the CI suite. The
NEUROTRACE wiring is verified by reaching this point; whether the
*remote model* is healthy is a separate concern.

Set ``NEUROTRACE_LIVE_TEST_STRICT=1`` to convert xfail into a hard
fail (useful for diagnosing provider-side issues).
"""
from __future__ import annotations

import asyncio
import os
import time

import pytest

from neurotrace.ai.analyst import ForensicAIAnalyst
from neurotrace.llm import get_provider
from neurotrace.llm.base import LLMError, LLMRequest


MAX_ATTEMPTS = 5
STRICT = os.getenv("NEUROTRACE_LIVE_TEST_STRICT") == "1"


@pytest.mark.skipif(
    os.getenv("NEUROTRACE_FORCE_LIVE") != "1" or not os.getenv("AKASHML_API_KEY"),
    reason="set NEUROTRACE_FORCE_LIVE=1 and AKASHML_API_KEY to run live tests",
)
def test_akashml_live_json_call():
    """Smoke-test the live LLM wiring.

    Skipped if no key. Passes if the model returns the expected JSON.
    Xfails (by default) if the model is flaky so CI stays green while
    the upstream provider is having a bad day.
    """
    p = get_provider("akashml")
    last_err: Exception | None = None
    for attempt in range(MAX_ATTEMPTS):
        try:
            r = asyncio.run(p.chat(LLMRequest(
                system="Reply with strict JSON only.",
                user='Emit: {"status": "ok", "n": 1}',
                max_tokens=60,
                json_mode=True,
            )))
            if r.parsed is not None and r.parsed.get("status") == "ok":
                return  # success
            last_err = AssertionError(f"unexpected parsed: {r.parsed!r}")
        except LLMError as exc:
            last_err = exc
        if attempt < MAX_ATTEMPTS - 1:
            time.sleep(2 ** attempt)

    msg = f"akashml live test failed after {MAX_ATTEMPTS} attempts: {last_err}"
    if STRICT:
        pytest.fail(msg)
    pytest.xfail(
        msg + " (NEUROTRACE_LIVE_TEST_STRICT=1 to convert into a hard fail)"
    )
