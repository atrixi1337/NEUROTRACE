"""Extract structured IOCs from a ForensicReport / report dict."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set

_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

_PRIVATE_PREFIXES = (
    "10.", "127.", "192.168.", "169.254.",
)
_PRIVATE_172 = re.compile(r"^172\.(1[6-9]|2\d|3[01])\.")


def _is_public_ip(ip: str) -> bool:
    if any(ip.startswith(p) for p in _PRIVATE_PREFIXES):
        return False
    if _PRIVATE_172.match(ip):
        return False
    if ip.startswith("0.") or ip.startswith("255."):
        return False
    return True


def _is_noise_domain(d: str) -> bool:
    low = d.lower()
    # Process / dump filenames mis-detected as domains
    if low.endswith((
        ".exe", ".dll", ".sys", ".pdb", ".raw", ".dmp", ".mem",
        ".zip", ".7z", ".bin", ".php",
    )):
        return True
    skip = (
        "microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com",
        "azure.com", "office.com", "office.net", "live.com", "msn.com",
        "digicert.com", "verisign.com", "sectigo.com", "example.com",
        "localhost", "w3.org", "apache.org", "github.com", "githubusercontent.com",
    )
    return any(low.endswith(s) for s in skip)


def extract_iocs(report: Dict[str, Any]) -> Dict[str, List[str]]:
    """Pull IPs, domains, hashes from a report dict."""
    ips: Set[str] = set()
    domains: Set[str] = set()
    md5s: Set[str] = set()
    sha1s: Set[str] = set()
    sha256s: Set[str] = set()

    def scan_text(s: str) -> None:
        if not s:
            return
        for m in _IPV4.findall(s):
            if _is_public_ip(m):
                ips.add(m)
        for m in _DOMAIN.findall(s):
            if not _is_noise_domain(m) and "." in m:
                domains.add(m.lower())
        for m in _SHA256.findall(s):
            sha256s.add(m.lower())
        for m in _SHA1.findall(s):
            sha1s.add(m.lower())
        for m in _MD5.findall(s):
            md5s.add(m.lower())

    for b in report.get("beacons") or []:
        for srv in b.get("c2_servers") or []:
            scan_text(str(srv))
        raw = b.get("raw_config_keys") or {}
        scan_text(str(raw.get("server") or ""))
        scan_text(str(raw.get("uri") or ""))
        scan_text(str(b.get("user_agent") or ""))

    for f in report.get("findings") or []:
        scan_text(f.get("title") or "")
        scan_text(f.get("description") or "")
        ev = f.get("evidence") or {}
        scan_text(str(ev.get("remote") or ""))
        scan_text(str(ev))

    scan_text(report.get("ai_storyline") or "")
    scan_text(report.get("generated_yara_rule") or "")

    # Process command lines often carry C2 URLs / IPs
    for p in report.get("processes") or []:
        scan_text(p.get("command_line") or "")
        scan_text(p.get("path") or "")

    for inj in report.get("injections") or []:
        scan_text(str(inj.get("extracted_strings") or ""))

    return {
        "ips": sorted(ips),
        "domains": sorted(domains),
        "md5": sorted(md5s),
        "sha1": sorted(sha1s),
        "sha256": sorted(sha256s),
    }


def ioc_summary(iocs: Dict[str, List[str]]) -> Dict[str, int]:
    return {k: len(v) for k, v in iocs.items()}
