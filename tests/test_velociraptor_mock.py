"""Velociraptor mock tests."""
from __future__ import annotations

import asyncio

from neurotrace.velociraptor import make_client
from neurotrace.velociraptor.factory import make_client as make_client_factory


def test_factory_returns_mock_by_default(monkeypatch):
    monkeypatch.setenv("VELO_API_URL", "")
    monkeypatch.setenv("VELO_API_KEY", "")
    c = make_client_factory()
    assert c.__class__.__name__ == "MockVelociraptorClient"


def test_health_reports_ok():
    c = make_client()
    h = asyncio.run(c.health())
    assert h["status"] == "ok"
    assert h["backend"] == "mock"


def test_list_clients_returns_three():
    c = make_client()
    clients = asyncio.run(c.list_clients())
    assert len(clients) == 3
    assert all(c.client_id.startswith("C.") for c in clients)


def test_collect_artifact_pslist():
    c = make_client()
    r = asyncio.run(c.collect_artifact("C.0011223344556677", "Generic.System.Pslist"))
    assert r.completed is True
    names = [row["Name"] for row in r.rows]
    assert "lsass.exe" in names
    assert "svchost.exe" in names


def test_collect_artifact_handles_to_lsass():
    c = make_client()
    r = asyncio.run(c.collect_artifact("C.0011223344556677", "Windows.System.HandleSnapshots"))
    assert any("lsass.exe" in str(row.get("TargetName", "")).lower() for row in r.rows)


def test_run_hunt_completes():
    c = make_client()
    h = asyncio.run(c.run_hunt("Generic.System.Pslist"))
    assert h.hunt_id.startswith("H.")
    assert h.status.value == "completed"
    assert h.stats["clients_completed"] == 3


def test_acquire_memory_dump_writes_placeholder(tmp_path):
    c = make_client()
    dest = tmp_path / "dump.raw"
    out = asyncio.run(c.acquire_memory_dump("C.0011223344556677", dest))
    assert out.exists()
    assert out.stat().st_size == 1024
