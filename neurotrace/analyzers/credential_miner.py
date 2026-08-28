"""In-memory credential & secret harvester.

Uses the streaming :func:`stream_scan` so it can handle multi-GB
memory dumps without loading the whole file into RAM. The previous
implementation read the full buffer into memory and ran regexes
once; for an 8 GB workstation dump that is not viable.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List

from neurotrace.core.models import CredentialArtifact
from neurotrace.core.scanner import CREDENTIAL_RULES, stream_scan


# Lightweight non-streaming rules used when callers still hand us a buffer.
AWS_KEY_PATTERN = re.compile(rb"AKIA[0-9A-Z]{16}")
BEARER_TOKEN_PATTERN = re.compile(rb"Bearer\s+[a-zA-Z0-9_\-\.]{30,}")
NTLM_HASH_PATTERN = re.compile(rb"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}")
MIMIKATZ_SIGNATURES = [
    rb"sekurlsa::logonpasswords",
    rb"lsasrv.dll",
    rb"wdigest.dll",
    rb"kerberos.dll",
]


class CredentialMiner:
    """Forensic in-memory credential & artifact harvester."""

    # ---- streaming path ---------------------------------------------------
    def scan_file_for_credentials(
        self, dump_path: Path, proc_name: str = "lsass.exe",
    ) -> List[CredentialArtifact]:
        """Stream ``dump_path`` and return one artifact per match.

        Memory usage stays bounded regardless of dump size.
        """
        hits = stream_scan(dump_path, CREDENTIAL_RULES)
        out: List[CredentialArtifact] = []
        for h in hits:
            v = h.match.decode("latin-1", errors="ignore")
            if h.rule == "aws_access_key":
                out.append(CredentialArtifact(
                    source_process=proc_name, artifact_type="Cloud Access Key (AWS)",
                    username="IAM Service Account", domain="AWS",
                    value_masked=f"{v[:8]}...{v[-4:]}", confidence="CRITICAL",
                ))
            elif h.rule == "bearer_token":
                out.append(CredentialArtifact(
                    source_process=proc_name, artifact_type="OAuth / API Bearer Token",
                    username="Session User", domain="Web API",
                    value_masked=f"{v[:15]}...[REDACTED]", confidence="HIGH",
                ))
            elif h.rule == "ntlm_hash":
                out.append(CredentialArtifact(
                    source_process=proc_name, artifact_type="NTLM Hash",
                    value_masked=v, confidence="CRITICAL",
                ))
            elif h.rule == "github_token":
                out.append(CredentialArtifact(
                    source_process=proc_name, artifact_type="GitHub PAT",
                    value_masked=f"{v[:8]}...{v[-4:]}", confidence="CRITICAL",
                ))
            elif h.rule == "slack_token":
                out.append(CredentialArtifact(
                    source_process=proc_name, artifact_type="Slack Token",
                    value_masked=f"{v[:8]}...[REDACTED]", confidence="HIGH",
                ))
            elif h.rule == "private_key":
                out.append(CredentialArtifact(
                    source_process=proc_name, artifact_type="PEM Private Key",
                    value_masked="[PEM block]", confidence="CRITICAL",
                ))
        # Mimikatz signature scan (cheap; pass over the file once).
        mimi_hits: List[str] = []
        try:
            data = dump_path.read_bytes() if dump_path.stat().st_size < 64 * 1024 * 1024 else None
            if data is not None:
                mimi_hits = [sig.decode() for sig in MIMIKATZ_SIGNATURES if sig in data]
        except OSError:
            pass
        if mimi_hits and "lsass" in proc_name.lower():
            out.append(CredentialArtifact(
                source_process=proc_name,
                artifact_type="LSASS Memory Injection / Mimikatz Sekurlsa Artifacts",
                username="NT AUTHORITY\\SYSTEM", domain="LOCAL",
                value_masked="Memory dump artifacts: " + ", ".join(mimi_hits),
                confidence="CRITICAL",
            ))
        return out

    # ---- legacy buffer path ----------------------------------------------
    def scan_memory_for_credentials(
        self, data: bytes, proc_name: str = "lsass.exe",
    ) -> List[CredentialArtifact]:
        """Legacy in-memory path. Kept for compatibility with callers
        that already have a buffer (e.g. tests, mock Vol3 output)."""
        creds: List[CredentialArtifact] = []
        for match in AWS_KEY_PATTERN.finditer(data):
            key = match.group().decode("latin-1", errors="ignore")
            creds.append(CredentialArtifact(
                source_process=proc_name, artifact_type="Cloud Access Key (AWS)",
                username="IAM Service Account", domain="AWS",
                value_masked=f"{key[:8]}...{key[-4:]}", confidence="CRITICAL",
            ))
        for match in BEARER_TOKEN_PATTERN.finditer(data):
            token = match.group().decode("latin-1", errors="ignore")
            creds.append(CredentialArtifact(
                source_process=proc_name, artifact_type="OAuth / API Bearer Token",
                username="Session User", domain="Web API",
                value_masked=f"{token[:15]}...[REDACTED]", confidence="HIGH",
            ))
        mimi_hits = [sig.decode() for sig in MIMIKATZ_SIGNATURES if sig in data]
        if mimi_hits and ("lsass" in proc_name.lower() or "powershell" in proc_name.lower()):
            creds.append(CredentialArtifact(
                source_process=proc_name,
                artifact_type="LSASS Memory Injection / Mimikatz Sekurlsa Artifacts",
                username="NT AUTHORITY\\SYSTEM", domain="LOCAL",
                value_masked="Memory dump artifacts: " + ", ".join(mimi_hits),
                confidence="CRITICAL",
            ))
        return creds
