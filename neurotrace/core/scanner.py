"""Streaming regex scanner for credential/secret patterns.

A drop-in replacement for the regex-passes in
``neurotrace.analyzers.credential_miner`` and
``neurotrace.analyzers.beacon_parser`` that uses
:func:`iter_chunks` to keep memory constant regardless of dump size.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Pattern, Set, Tuple

from .streaming import iter_chunks


@dataclass
class StreamHit:
    """One match found by the streaming scanner."""
    rule: str
    start: int  # absolute offset in the dump
    match: bytes


def stream_scan(
    path: Path,
    rules: Iterable[Tuple[str, Pattern[bytes]]],
    chunk_size: int = 8 * 1024 * 1024,
    overlap: int = 4096,
    progress: Callable[[int, int], None] | None = None,
) -> List[StreamHit]:
    """Scan ``path`` with each ``(name, regex)`` rule, streaming chunks.

    Returns every match. The same hit may be reported once per
    overlap window it crosses; callers should de-duplicate by
    ``(rule, start)`` if that matters.
    """
    rules = list(rules)
    if not rules:
        return []

    file_size = max(path.stat().st_size, 1)
    hits: List[StreamHit] = []
    abs_offset = 0
    seen: Set[Tuple[str, int]] = set()

    for chunk in iter_chunks(path, chunk_size=chunk_size, overlap=overlap):
        for name, pat in rules:
            for m in pat.finditer(chunk):
                start = abs_offset + m.start()
                key = (name, start)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(StreamHit(rule=name, start=start, match=m.group()))
        abs_offset += len(chunk) - overlap
        if progress is not None:
            progress(min(abs_offset, file_size), file_size)

    return hits


# Convenience rule presets for the credential miner
CREDENTIAL_RULES: List[Tuple[str, Pattern[bytes]]] = [
    ("aws_access_key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("bearer_token",   re.compile(rb"Bearer\s+[a-zA-Z0-9_\-\.]{30,}")),
    ("ntlm_hash",      re.compile(rb"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}")),
    ("github_token",   re.compile(rb"ghp_[a-zA-Z0-9]{36}")),
    ("slack_token",    re.compile(rb"xox[abpr]-[a-zA-Z0-9-]{10,}")),
    ("private_key",    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]


# Convenience rule presets for the beacon parser
BEACON_RULES: List[Tuple[str, Pattern[bytes]]] = [
    ("cs_url",        re.compile(rb"https?://[a-zA-Z0-9.\-_]+(?::[0-9]{2,5})?/[a-zA-Z0-9_\-\.\?=/]+")),
    ("cs_useragent",  re.compile(rb"Mozilla/5\.0\s+\(Windows\s+NT\s+10\.0;[^\x00]+")),
    ("msf_marker",    re.compile(rb"metsrv\.x64\.dll|metsrv\.dll|stdapi\.dll")),
    ("msf_tcp",       re.compile(rb"tcp://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{2,5}")),
    ("sliver_marker", re.compile(rb"sliver\.pb\.BeaconConfig|api/v1/session")),
]
