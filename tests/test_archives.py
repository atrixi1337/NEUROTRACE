"""Tests for archive intake."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from neurotrace.core.archives import (
    extract_archive,
    is_archive,
    looks_like_dump,
    resolve_analyzable,
)


def test_is_archive_detects_7z(tmp_path):
    p = tmp_path / "dump.7z"
    p.write_bytes(b"7z\xbc\xaf'\x1c")
    assert is_archive(p)
    assert not is_archive(tmp_path / "dump.raw")


def test_looks_like_dump():
    assert looks_like_dump(Path("a.raw"))
    assert looks_like_dump(Path("a.DMP"))
    assert not looks_like_dump(Path("a.7z"))


def test_resolve_non_archive_passthrough(tmp_path):
    p = tmp_path / "mem.raw"
    p.write_bytes(b"\x00" * 16)
    out, notes = resolve_analyzable(p)
    assert out == p
    assert notes == []


def test_zip_slip_is_rejected(tmp_path):
    import zipfile
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../escape.raw", b"nope")
    extracted, notes = extract_archive(archive, dest_dir=tmp_path / "out")
    # Either raised (caught → None) or did not write outside dest.
    outside = (tmp_path / "escape.raw").exists()
    assert not outside
    assert extracted is None or extracted.is_file()


def test_zip_extracts_dump(tmp_path):
    import zipfile
    archive = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("nested/mem.raw", b"\x00" * 128)
        zf.writestr("readme.txt", b"ignore me")
    extracted, notes = extract_archive(archive, dest_dir=tmp_path / "out")
    assert extracted is not None
    assert extracted.name == "mem.raw"
    assert extracted.read_bytes() == b"\x00" * 128
