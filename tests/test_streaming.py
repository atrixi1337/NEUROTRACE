"""Tests for the streaming chunk reader and scanner."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from neurotrace.core.scanner import (
    CREDENTIAL_RULES,
    BEACON_RULES,
    stream_scan,
)
from neurotrace.core.streaming import iter_chunks


def test_iter_chunks_yields_full_file(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"A" * 10_000)
    chunks = list(iter_chunks(p, chunk_size=2048, overlap=128))
    total = sum(len(c) for c in chunks)
    # Each boundary chunk re-emits `overlap` bytes, so the total is
    # at least file_size and at most file_size + n_chunks * overlap.
    n = len(chunks)
    assert n >= 5
    assert total >= 10_000
    assert total <= 10_000 + n * 128


def test_iter_chunks_handles_empty_file(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    assert list(iter_chunks(p)) == []


def test_stream_scan_finds_aws_key_across_boundary(tmp_path):
    p = tmp_path / "dump.bin"
    # AWS access key: exactly 20 bytes, AKIA + 16 chars in [0-9A-Z].
    full_key = b"AKIAIOSFODNN7EXAMPLE"  # canonical example from AWS docs
    pad1 = b"q" * 50
    pad2 = b"q" * 50
    body = pad1 + full_key + pad2
    p.write_bytes(body)
    # chunk_size=60 means the key (offset 50..70) straddles the
    # 60-byte boundary, so the overlap window must catch the suffix.
    hits = stream_scan(p, CREDENTIAL_RULES, chunk_size=60, overlap=30)
    aws = [h for h in hits if h.rule == "aws_access_key"]
    assert len(aws) == 1
    assert aws[0].match == full_key
    assert len(aws[0].match) == 20


def test_stream_scan_finds_beacons(tmp_path):
    p = tmp_path / "dump.bin"
    p.write_bytes(b"junk https://185.220.101.44:443/api/v2/telemetry.php more junk")
    hits = stream_scan(p, BEACON_RULES, chunk_size=128, overlap=32)
    cs = [h for h in hits if h.rule == "cs_url"]
    assert cs and b"185.220.101.44" in cs[0].match


def test_stream_scan_does_not_double_count(tmp_path):
    p = tmp_path / "dump.bin"
    p.write_bytes(b"AKIAIOSFODNN7EXAMPLE" * 5)
    hits = stream_scan(p, CREDENTIAL_RULES, chunk_size=128, overlap=0)
    aws = [h for h in hits if h.rule == "aws_access_key"]
    assert len(aws) == 5
