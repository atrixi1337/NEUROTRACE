"""Test fixtures: shared pytest configuration and helper utilities."""
from __future__ import annotations

import os
from pathlib import Path

import pytest


# When no AkashML key is available (CI), fall back to the stub provider
# so tests don't hit the network. The user can override by exporting
# ``NEUROTRACE_FORCE_LIVE=1`` and setting the real key.
@pytest.fixture(autouse=True)
def _force_stub_provider(monkeypatch):
    if os.getenv("NEUROTRACE_FORCE_LIVE") == "1":
        return
    monkeypatch.setenv("NEUROTRACE_LLM_PROVIDER", "stub")


@pytest.fixture
def samples_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture
def corpus_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "corpora"


@pytest.fixture
def fixture_dir() -> Path:
    return Path(__file__).resolve().parent / "fixtures"
