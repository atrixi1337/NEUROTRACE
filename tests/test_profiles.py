"""Scan profile + parallel wrapper tests."""
from __future__ import annotations

import asyncio

from neurotrace.volatility import VolatilityMode, VolatilityWrapper
from neurotrace.volatility.wrapper import SCAN_PROFILES, plugins_for_profile


def test_profiles_defined():
    for name in ("quick", "normal", "malware", "network", "deep"):
        assert name in SCAN_PROFILES
        assert len(SCAN_PROFILES[name]) >= 2
    assert "windows.malfind" in SCAN_PROFILES["quick"]
    assert "windows.vadinfo" in SCAN_PROFILES["deep"]
    assert "windows.vadinfo" not in SCAN_PROFILES["normal"]


def test_plugins_for_profile_unknown_falls_back():
    p = plugins_for_profile("nope")
    assert p == SCAN_PROFILES["normal"]


def test_wrapper_accepts_profile():
    w = VolatilityWrapper(force_mode=VolatilityMode.MOCK, profile="quick")
    assert w.profile == "quick"
    assert w.plugins == SCAN_PROFILES["quick"]
    w.apply_profile("deep")
    assert w.plugins == SCAN_PROFILES["deep"]


def test_mock_run_with_profile(tmp_path):
    f = tmp_path / "x.raw"
    f.write_bytes(b"\x00" * 64)
    w = VolatilityWrapper(force_mode=VolatilityMode.MOCK, profile="quick", max_parallel=2)
    r = asyncio.run(w.run(f))
    assert r.mode == VolatilityMode.MOCK
    assert w.max_parallel == 2


def test_max_parallel_capped():
    w = VolatilityWrapper(force_mode=VolatilityMode.MOCK, max_parallel=99)
    assert w.max_parallel == 4
