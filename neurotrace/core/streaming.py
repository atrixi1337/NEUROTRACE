"""Streaming / chunked byte readers for large memory dumps.

Volatility3 handles its own mmap'd layers, but NEUROTRACE's regex
analyzers (credential miner, beacon parser) historically read the
whole dump into memory. For an 8 GB workstation dump that's not
viable on a small server. This module provides a tiny helper that
yields overlapping chunks to regex scanners so a dump can be
scanned with constant memory.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator


def iter_chunks(
    path: Path,
    chunk_size: int = 8 * 1024 * 1024,
    overlap: int = 4096,
) -> Iterator[bytes]:
    """Yield chunks of ``path`` with ``overlap`` bytes shared between
    adjacent chunks so a pattern that straddles a chunk boundary is
    still found.

    The default 8 MB chunk + 4 KB overlap is enough for almost any
    string or regex match (Windows URLs, AWS keys, etc.) while
    keeping peak RAM to a few MB.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if overlap < 0 or overlap >= chunk_size:
        raise ValueError("overlap must be in [0, chunk_size)")

    file_size = path.stat().st_size
    if file_size == 0:
        return

    with path.open("rb") as f:
        carry = b""
        offset = 0
        while True:
            buf = f.read(chunk_size - len(carry))
            if not buf:
                if carry:
                    yield carry
                return
            chunk = carry + buf
            if len(buf) < chunk_size - len(carry):
                # Final chunk
                yield chunk
                return
            yield chunk
            carry = chunk[-overlap:]
            offset += len(chunk) - overlap
            if offset >= file_size:
                return
