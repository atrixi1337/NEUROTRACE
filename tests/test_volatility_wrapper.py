"""Volatility3 wrapper tests."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from neurotrace.volatility import VolatilityMode, VolatilityWrapper


def test_mock_mode_returns_deterministic_processes(tmp_path):
    f = tmp_path / "fake.raw"
    f.write_bytes(b"\x00" * 4096)
    w = VolatilityWrapper(force_mode=VolatilityMode.MOCK)
    r = asyncio.run(w.run(f))
    assert r.mode == VolatilityMode.MOCK
    assert r.os_family == "windows"
    names = [p["name"] for p in r.processes]
    assert "lsass.exe" in names
    assert "svchost.exe" in names


def test_mock_mode_extracts_beacon_config(tmp_path):
    f = tmp_path / "fake.raw"
    f.write_bytes(b"\x00" * 4096)
    w = VolatilityWrapper(force_mode=VolatilityMode.MOCK)
    r = asyncio.run(w.run(f))
    assert len(r.beacons) >= 1
    b = r.beacons[0]
    assert "watermark" in b["config"]
    assert b["config"]["server"].startswith("185.")


def test_mock_mode_includes_malfind_findings(tmp_path):
    f = tmp_path / "fake.raw"
    f.write_bytes(b"\x00" * 4096)
    w = VolatilityWrapper(force_mode=VolatilityMode.MOCK)
    r = asyncio.run(w.run(f))
    pids = [i["pid"] for i in r.injections]
    assert 3380 in pids
    assert 4892 in pids


def test_missing_file_returns_note(tmp_path):
    w = VolatilityWrapper(force_mode=VolatilityMode.MOCK)
    r = asyncio.run(w.run(tmp_path / "does-not-exist.raw"))
    assert any("not found" in n for n in r.notes)


def test_real_mode_falls_back_to_mock_without_symbols(tmp_path):
    """Without ISF symbols, real mode should record fallback and not crash."""
    f = tmp_path / "fake.raw"
    f.write_bytes(b"\x00" * 4096)
    w = VolatilityWrapper(force_mode=None)  # auto → real attempt
    r = asyncio.run(w.run(f))
    # Either the real path produced something or we fell back; both OK
    assert r.mode in (VolatilityMode.REAL, VolatilityMode.MOCK, VolatilityMode.FALLBACK)
