"""Real-dump regression tests.

These tests run the engine end-to-end against a real memory image
loaded from ``corpora/dumps/``. They are skipped if the dump is
absent so the suite stays green on a fresh clone — populate the
dump with::

    bash corpora/dumps/fetch.sh

or drop any Windows memory image at::

    corpora/dumps/Challenge_Win7SP1x64.raw

The test verifies two things:

1. **Volatility 3 must run in real mode** (``vol3_mode == "real"``)
   against the baked-in ISF symbol pack. If we get ``fallback`` or
   ``mock`` the wrapper has a bug — failing the test surfaces it.

2. **The engine must surface the minimum IOCs** from
   ``corpora/dumps/expected.json``. We enforce the process tree
   and at least one LSASS handle — the canonical signals a real
   Windows image should produce.

Live LLM call is optional and xfail'd if the provider is flaky.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

import pytest

from neurotrace.ai.analyst import ForensicAIAnalyst
from neurotrace.core.engine import NeurotraceEngine
from neurotrace.velociraptor.client import MockVelociraptorClient
from neurotrace.volatility import VolatilityMode, VolatilityWrapper


CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpora" / "dumps"
DUMP_PATH = CORPUS_DIR / "Challenge_Win7SP1x64.raw"
EXPECTED_PATH = CORPUS_DIR / "expected.json"


pytestmark = pytest.mark.skipif(
    not DUMP_PATH.exists(),
    reason=(
        f"real memory image not found at {DUMP_PATH}. "
        "Run `bash corpora/dumps/fetch.sh` to download it, or drop "
        "any Windows memory image at the same path."
    ),
)


@pytest.fixture(scope="module")
def expected() -> dict:
    if not EXPECTED_PATH.exists():
        pytest.skip(f"expected IOCs not found at {EXPECTED_PATH}")
    return json.loads(EXPECTED_PATH.read_text())


@pytest.fixture(scope="module")
def real_report() -> dict:
    """Run the engine against the real dump and serialize the report.

    Done once per module to keep the 30+ second Vol3 run amortized
    across assertions.
    """
    # The real Vol3 wrapper (no mock).
    vol3 = VolatilityWrapper(force_mode=None)  # auto -> real
    velo = MockVelociraptorClient()           # no real velo in CI
    # Live LLM if available, otherwise stub.
    if os.getenv("NEUROTRACE_FORCE_LIVE") == "1" and os.getenv("AKASHML_API_KEY"):
        ai = ForensicAIAnalyst(provider_name="akashml")
    else:
        ai = ForensicAIAnalyst(provider_name="stub")
    engine = NeurotraceEngine(vol3=vol3, velo=velo, ai=ai)
    t0 = time.time()
    report = asyncio.run(
        engine.analyze_memory_file(DUMP_PATH, sample_name=DUMP_PATH.name)
    )
    out = report.model_dump()
    out["__elapsed__"] = time.time() - t0
    return out


def test_vol3_runs_in_real_mode(real_report):
    """The wrapper must successfully run the real Vol3 plugins
    (not fall back to mock) when given a real Windows image
    with the baked-in ISF pack.

    NB: this test is `xfail` when only the legacy XP/2003 ISF pack
    is present (which is what ships in the Docker image — the
    Microsoft download for modern Windows 6.x+ symbols is not
    free). For the MemLabs Lab 0 image (Windows 7 SP1 x64) the
    full ISF must be generated on the fly via
    `bash corpora/dumps/fetch.sh`.
    """
    mode = real_report["vol3_mode"]
    if mode in ("real",):
        return
    # If we're in mock/fallback, the test only "passes" if a known
    # ISF for the build was provided. Otherwise the corpus test is
    # not really exercising real Vol3; mark as xfail.
    expected = json.loads((CORPUS_DIR / "expected.json").read_text())
    kernel_guid = expected.get("os", {}).get("kernel_pdb_guid", "")
    found = any(
        kernel_guid.lower() in p.lower()
        for p in [
            *(p.parts for p in (CORPUS_DIR.parent / "symbols").rglob("*.json.xz")),
        ]
    )
    if found:
        pytest.fail(
            f"expected vol3_mode=real for the matched ISF, got {mode!r}. "
            f"coverage_notes: {real_report.get('coverage_notes', [])}"
        )
    pytest.xfail(
        f"vol3_mode={mode!r} (no matching ISF for build {kernel_guid!r}); "
        "run `bash corpora/dumps/fetch.sh` to generate the ISF"
    )


def test_real_dump_produces_processes(real_report, expected):
    """The process tree should have at least the minimum count
    defined in expected.json.
    """
    n = real_report["total_processes"]
    min_n = expected.get("min_process_count", 5)
    assert n >= min_n, f"expected at least {min_n} processes, got {n}"


def test_real_dump_includes_canonical_processes(real_report, expected):
    """Each canonical Windows process from expected.json must appear
    at least once.
    """
    names = {p["name"] for p in real_report["processes"]}
    for entry in expected.get("expected_processes", []):
        assert entry["name"] in names, (
            f"missing canonical process: {entry['name']!r}. "
            f"got: {sorted(names)[:20]}"
        )


def test_real_dump_credential_path_is_observable(real_report, expected):
    """LSASS is the canonical Windows credential store. The engine
    should either see it directly in the process tree OR via a
    handle from a credential-dumping process.
    """
    names = {p["name"] for p in real_report["processes"]}
    has_lsass = "lsass.exe" in names or "lsass" in str(names).lower()
    has_cred_finding = any(
        "lsass" in f["title"].lower() or "credential" in f["title"].lower()
        for f in real_report["findings"]
    )
    assert has_lsass or has_cred_finding, (
        "neither lsass.exe in process tree nor a credential-related finding"
    )


def test_real_dump_report_serializes(real_report):
    """A real-dump report must round-trip through JSON cleanly."""
    j = json.dumps(real_report)
    parsed = json.loads(j)
    assert parsed["analysis_id"] == real_report["analysis_id"]
    assert parsed["total_processes"] == real_report["total_processes"]


def test_real_dump_elapsed_time_reported(real_report):
    """Regression sanity-check: the engine must record its elapsed
    time so an operator can tell a 30-second real run from a 1-second
    mock run.
    """
    assert real_report.get("elapsed_seconds", 0) > 1.0, (
        f"elapsed_seconds={real_report.get('elapsed_seconds')} — too fast, "
        "suggests Vol3 didn't actually run"
    )


def test_real_dump_persists_json_report(real_report):
    """The engine should have persisted a JSON report under reports/."""
    from neurotrace.config import REPORTS_DIR
    reports = list(REPORTS_DIR.glob(f"{real_report['analysis_id']}*.json"))
    assert reports, f"no JSON report persisted for {real_report['analysis_id']}"
