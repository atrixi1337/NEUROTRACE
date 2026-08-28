"""End-to-end engine pipeline tests.

These tests verify the full pipeline (Vol3 → analyzers → AI → report)
with deterministic inputs. They use the mock Vol3 backend, the
mock Velociraptor, and the stub LLM — all of which are deterministic
and offline. A separate integration test exercises the real AkashML
provider when the API key is present.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from neurotrace.ai.analyst import ForensicAIAnalyst
from neurotrace.core.engine import NeurotraceEngine
from neurotrace.velociraptor.client import MockVelociraptorClient
from neurotrace.volatility import VolatilityMode, VolatilityWrapper


def _make_test_engine() -> NeurotraceEngine:
    return NeurotraceEngine(
        vol3=VolatilityWrapper(force_mode=VolatilityMode.MOCK),
        velo=MockVelociraptorClient(),
        ai=ForensicAIAnalyst(provider_name="stub"),
    )


def test_analyze_memory_file_produces_report(tmp_path):
    f = tmp_path / "case.dmp"
    f.write_bytes(b"\x00" * 1024)
    e = _make_test_engine()
    r = asyncio.run(e.analyze_memory_file(f, sample_name="case.dmp"))
    assert r.analysis_id.startswith("NT-")
    assert r.target_name == "case.dmp"
    assert r.total_processes >= 5
    assert len(r.injections) >= 1
    assert len(r.beacons) >= 1
    assert r.vol3_mode == "mock"
    assert r.ai_storyline  # non-empty
    assert r.generated_yara_rule  # non-empty
    assert "T1055" in " ".join(r.mitre_techniques)


def test_analyze_via_velociraptor_no_memory_dump():
    """When Velociraptor memory acquisition isn't available, the engine
    should still produce a report from artifact rows."""
    e = _make_test_engine()
    r = asyncio.run(e.analyze_via_velociraptor("C.0011223344556677"))
    assert r.analysis_id.startswith("NT-")
    # Either the mock produced a dump (then vol3 ran) or we fell back
    # to artifacts-only analysis; both paths must yield findings.
    assert len(r.findings) >= 1
    assert any(
        "Handle" in f.title or "Established" in f.title or "Injection" in f.title
        for f in r.findings
    )


def test_stream_velociraptor_artifact():
    e = _make_test_engine()
    r = asyncio.run(e.stream_velociraptor_artifact(
        "C.0011223344556677", "Generic.System.Pslist",
    ))
    assert r["artifact"] == "Generic.System.Pslist"
    assert r["completed"] is True
    assert len(r["rows"]) >= 1


def test_report_is_serializable(tmp_path):
    f = tmp_path / "case.dmp"
    f.write_bytes(b"\x00" * 1024)
    e = _make_test_engine()
    r = asyncio.run(e.analyze_memory_file(f, sample_name="case.dmp"))
    # Round-trip through JSON to catch serialization issues
    j = r.model_dump_json()
    parsed = json.loads(j)
    assert parsed["analysis_id"] == r.analysis_id
    assert "coverage_notes" in parsed
    assert "vol3_mode" in parsed


def test_coverage_notes_populated(tmp_path):
    f = tmp_path / "case.dmp"
    f.write_bytes(b"\x00" * 1024)
    e = _make_test_engine()
    r = asyncio.run(e.analyze_memory_file(f, sample_name="case.dmp"))
    assert r.coverage_notes  # non-empty
    # Must explain the vol3 mode
    assert any("Volatility3" in n or "mock" in n for n in r.coverage_notes)
