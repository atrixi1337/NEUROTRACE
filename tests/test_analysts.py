"""Golden-output regression test for the existing sample dump.

This test pins the output of the engine against the existing 2 KB
synthetic sample. If the output drifts (a refactor accidentally
removes a field, an analyzer starts reporting false positives, etc.)
the test fails. This is the most important safety net in the suite.
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import pytest

from neurotrace.ai.analyst import ForensicAIAnalyst
from neurotrace.core.engine import NeurotraceEngine
from neurotrace.velociraptor.client import MockVelociraptorClient
from neurotrace.volatility import VolatilityMode, VolatilityWrapper


GOLDEN_PATH = Path(__file__).resolve().parent / "fixtures" / "engine_golden.json"


def _make_engine() -> NeurotraceEngine:
    return NeurotraceEngine(
        vol3=VolatilityWrapper(force_mode=VolatilityMode.MOCK),
        velo=MockVelociraptorClient(),
        ai=ForensicAIAnalyst(provider_name="stub"),
    )


def test_engine_golden_output(tmp_path, samples_dir):
    dump = samples_dir / "sample_cobaltstrike_dump.dmp"
    if not dump.exists():
        pytest.skip("sample dump not present")
    e = _make_engine()
    report = asyncio.run(e.analyze_memory_file(dump, sample_name=dump.name))

    # Pull only the fields that should be stable across runs.
    # LLM output and timestamps are deliberately excluded.
    stable = {
        "vol3_mode": report.vol3_mode,
        "total_processes": report.total_processes,
        "compromised_processes": report.compromised_processes,
        "n_injections": len(report.injections),
        "n_beacons": len(report.beacons),
        "n_credentials": len(report.credentials),
        "n_findings": len(report.findings),
        "injection_pids": sorted({i.pid for i in report.injections}),
        "beacon_servers": sorted({s for b in report.beacons for s in b.c2_servers}),
        "beacon_watermark": sorted({(b.watermark_or_id or "") for b in report.beacons}),
        "mitre_techniques": sorted(report.mitre_techniques),
    }

    if not GOLDEN_PATH.exists():
        # First run: write the golden file and skip the comparison.
        GOLDEN_PATH.write_text(json.dumps(stable, indent=2, sort_keys=True))
        pytest.skip("wrote golden output, please re-run to verify")

    expected = json.loads(GOLDEN_PATH.read_text())
    assert stable == expected, (
        "Engine output drifted from golden. If intentional, delete "
        f"{GOLDEN_PATH.name} and rerun."
    )


def test_storyline_includes_anchored_pids(samples_dir):
    dump = samples_dir / "sample_cobaltstrike_dump.dmp"
    if not dump.exists():
        pytest.skip("sample dump not present")
    e = _make_engine()
    report = asyncio.run(e.analyze_memory_file(dump, sample_name=dump.name))
    # The narrative must reference at least one compromised PID
    pids = {str(p.pid) for p in report.processes if p.is_compromised}
    if pids:
        assert any(p in (report.ai_storyline or "") for p in pids)
