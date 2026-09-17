"""Volatility3 wrapper tests.

Covers three contracts:

1. Forced-mock path stays deterministic (offline/CI).
2. Missing vol CLI → MOCK with an explicit reason (never silent).
3. When a vol command IS provided, empty/error output becomes FALLBACK,
   never a silent MOCK. Real mode is reserved for actual rows.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, List

import pytest

from neurotrace.volatility import VolatilityMode, VolatilityWrapper
from neurotrace.volatility.wrapper import (
    DEFAULT_PLUGINS,
    HEAVY_PLUGINS,
    _extract_json_from_mixed,
    _find_vol_command,
    _try_parse_json_rows,
)


# ---------------------------------------------------------------- helpers
class _FakeProc:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _pslist_rows() -> List[dict]:
    return [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},  # fine, vol emits one
        {"PID": 990, "PPID": 890, "ImageFileName": "lsass.exe"},
        {"PID": 3380, "PPID": 940, "ImageFileName": "svchost.exe"},
    ]


# ----------------------------------------------------------------- contracts
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


def test_missing_vol_cli_returns_mock_not_silent(tmp_path, monkeypatch):
    """No vol on PATH → MOCK, and the reason must be explicit."""
    f = tmp_path / "fake.raw"
    f.write_bytes(b"\x00" * 4096)
    w = VolatilityWrapper(force_mode=None, vol_command=None)
    # Simulate "vol not found"
    w._vol_command = None
    w._vol3_available = False
    r = asyncio.run(w.run(f))
    assert r.mode == VolatilityMode.MOCK
    assert any("CLI not found" in n or "vol CLI not found" in n for n in r.notes)


def test_real_mode_empty_output_is_fallback_not_mock(tmp_path, monkeypatch):
    """When vol runs but produces nothing, mode must be FALLBACK (loud)."""
    f = tmp_path / "fake.raw"
    f.write_bytes(b"\x00" * 4096)

    w = VolatilityWrapper(
        force_mode=None,
        vol_command=["fake-vol"],
        plugins=["windows.pslist"],
    )

    def _fake_run(argv, **kwargs):
        return _FakeProc(returncode=0, stdout="[]", stderr="")

    monkeypatch.setattr(
        "neurotrace.volatility.wrapper.subprocess.run",
        _fake_run,
    )
    r = asyncio.run(w.run(f))
    assert r.mode == VolatilityMode.FALLBACK, (
        f"expected FALLBACK, got {r.mode}; notes={r.notes}"
    )
    assert any("ISF" in n or "symbol" in n.lower() or "fallback" in n.lower() for n in r.notes)


def test_real_mode_plugin_error_is_recorded_not_silent_mock(tmp_path, monkeypatch):
    """A crashing plugin must appear in plugins_failed; if ALL crash → FALLBACK."""
    f = tmp_path / "fake.raw"
    f.write_bytes(b"\x00" * 4096)

    w = VolatilityWrapper(
        force_mode=None,
        vol_command=["fake-vol"],
        plugins=["windows.pslist", "windows.malfind"],
    )

    def _fake_run(argv, **kwargs):
        return _FakeProc(returncode=1, stdout="", stderr="unknown plugin")

    monkeypatch.setattr(
        "neurotrace.volatility.wrapper.subprocess.run",
        _fake_run,
    )
    r = asyncio.run(w.run(f))
    assert r.mode == VolatilityMode.FALLBACK
    assert len(r.plugins_failed) >= 1, (
        f"plugins_failed should record the crash, got {r.plugins_failed!r}"
    )


def test_real_mode_with_rows_is_real(tmp_path, monkeypatch):
    """Happy path: vol emits JSON rows → mode is REAL and data is absorbed."""
    f = tmp_path / "fake.raw"
    f.write_bytes(b"\x00" * 4096)

    w = VolatilityWrapper(
        force_mode=None,
        vol_command=["fake-vol"],
        plugins=["windows.pslist"],
    )

    payload = json.dumps(_pslist_rows())

    def _fake_run(argv, **kwargs):
        return _FakeProc(returncode=0, stdout=payload, stderr="")

    monkeypatch.setattr(
        "neurotrace.volatility.wrapper.subprocess.run",
        _fake_run,
    )
    r = asyncio.run(w.run(f))
    assert r.mode == VolatilityMode.REAL
    names = {p["name"] for p in r.processes}
    assert "lsass.exe" in names
    assert "windows.pslist" in r.plugins_run


def test_real_mode_argv_includes_symbol_dir_and_json(tmp_path, monkeypatch):
    """CLI argv must carry -f, -s (when set), -r json, and the plugin name."""
    f = tmp_path / "fake.raw"
    f.write_bytes(b"\x00" * 4096)
    captured: dict[str, Any] = {}

    w = VolatilityWrapper(
        force_mode=None,
        vol_command=["fake-vol"],
        plugins=["windows.pslist"],
        symbol_dir=str(tmp_path / "symbols"),
    )

    def _fake_run(argv, **kwargs):
        captured["argv"] = list(argv)
        return _FakeProc(returncode=0, stdout=json.dumps(_pslist_rows()), stderr="")

    monkeypatch.setattr(
        "neurotrace.volatility.wrapper.subprocess.run",
        _fake_run,
    )
    asyncio.run(w.run(f))
    argv = captured["argv"]
    assert argv[0] == "fake-vol"
    assert "-f" in argv and str(f) in argv
    assert "-r" in argv and "json" in argv
    assert "-s" in argv
    assert "windows.pslist" in argv


def test_heavy_plugins_are_opt_in():
    """vadinfo/dlllist/modules must not be in the default set (huge output)."""
    assert "windows.vadinfo" not in DEFAULT_PLUGINS
    assert "windows.dlllist" not in DEFAULT_PLUGINS
    assert "windows.vadinfo" in HEAVY_PLUGINS


# ------------------------------------------------------------- JSON helpers
def test_try_parse_json_rows_accepts_bare_list():
    rows = _try_parse_json_rows('[{"PID": 1}, {"PID": 2}]')
    assert rows == [{"PID": 1}, {"PID": 2}]


def test_try_parse_json_rows_wrapped_key():
    rows = _try_parse_json_rows('{"rows": [{"PID": 9}]}')
    assert rows == [{"PID": 9}]


def test_try_parse_json_rows_rejects_garbage():
    assert _try_parse_json_rows("not json at all") is None


def test_extract_json_from_mixed_stdout():
    mixed = "Loading plugins...\n[{\"PID\": 4}]\n"
    rows = _extract_json_from_mixed(mixed)
    assert rows == [{"PID": 4}]


def test_find_vol_command_returns_list_or_none():
    cmd = _find_vol_command()
    assert cmd is None or (isinstance(cmd, list) and cmd)


def test_wrapper_marks_vol_available_when_cli_exists():
    """If volatility3 is installed, the wrapper must see it — no silent mock."""
    w = VolatilityWrapper()
    if _find_vol_command() is not None:
        assert w._vol3_available is True
        assert w.vol_command and len(w.vol_command) >= 1
