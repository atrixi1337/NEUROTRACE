"""Correlate reports into campaigns by shared IOCs."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from neurotrace.intel.iocs import extract_iocs


def _load_reports(reports_dir: Path, limit: int = 200) -> List[Dict[str, Any]]:
    out = []
    if not reports_dir.exists():
        return out
    for p in sorted(reports_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception:  # noqa: BLE001
            continue
    return out


def build_campaigns(reports_dir: Path, min_shared: int = 1) -> Dict[str, Any]:
    """Group reports that share C2 IPs / domains / hashes."""
    reports = _load_reports(reports_dir)
    per_report = []
    ioc_to_reports: Dict[str, List[str]] = defaultdict(list)

    for r in reports:
        iocs = extract_iocs(r)
        rid = r.get("analysis_id") or "?"
        per_report.append({
            "analysis_id": rid,
            "target_name": r.get("target_name"),
            "timestamp": r.get("timestamp"),
            "threat_level": r.get("overall_threat_level"),
            "threat_score": r.get("threat_score"),
            "vol3_mode": r.get("vol3_mode"),
            "iocs": iocs,
        })
        seen = set()
        for typ in ("ips", "domains", "sha256", "md5"):
            for v in iocs.get(typ) or []:
                key = f"{typ}:{v}"
                if key in seen:
                    continue
                seen.add(key)
                ioc_to_reports[key].append(rid)

    # Shared IOCs across 2+ reports
    shared = []
    for key, rids in sorted(ioc_to_reports.items(), key=lambda kv: -len(set(kv[1]))):
        uniq = list(dict.fromkeys(rids))
        if len(uniq) < 2:
            continue
        typ, _, val = key.partition(":")
        shared.append({
            "ioc": val,
            "type": typ,
            "report_count": len(uniq),
            "reports": uniq,
        })

    # Simple campaign clusters: union-find over shared IOCs
    parent: Dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    ids = [p["analysis_id"] for p in per_report]
    for rid in ids:
        find(rid)
    for s in shared:
        rs = s["reports"]
        for other in rs[1:]:
            union(rs[0], other)

    clusters: Dict[str, List[str]] = defaultdict(list)
    for rid in ids:
        clusters[find(rid)].append(rid)

    by_id = {p["analysis_id"]: p for p in per_report}
    campaigns = []
    for root, members in clusters.items():
        if len(members) < 2:
            continue
        shared_in = [
            s for s in shared
            if any(m in s["reports"] for m in members)
        ]
        # Top shared IOCs
        top = sorted(shared_in, key=lambda s: -s["report_count"])[:8]
        max_score = max((by_id[m].get("threat_score") or 0) for m in members)
        campaigns.append({
            "id": f"camp-{root[:12]}",
            "report_count": len(members),
            "reports": [by_id[m] for m in members if m in by_id],
            "shared_iocs": top,
            "max_threat_score": max_score,
            "targets": sorted({by_id[m].get("target_name") or m for m in members if m in by_id}),
        })
    campaigns.sort(key=lambda c: (-c["report_count"], -c["max_threat_score"]))

    return {
        "reports_analyzed": len(per_report),
        "shared_iocs": shared[:50],
        "campaigns": campaigns,
        "standalone": [
            p for p in per_report
            if p["analysis_id"]
            not in {r.get("analysis_id") for c in campaigns for r in c["reports"]}
        ],
    }


def hunt_ioc_across_history(reports_dir: Path, needle: str) -> Dict[str, Any]:
    """Find every report that mentions a given IOC."""
    needle = (needle or "").strip().lower()
    hits = []
    if not needle:
        return {"query": needle, "hits": []}
    for r in _load_reports(reports_dir):
        iocs = extract_iocs(r)
        matched = []
        for typ, vals in iocs.items():
            for v in vals:
                if needle in v.lower():
                    matched.append({"type": typ, "value": v})
        # Also search narrative / raw dump textually
        blob = json.dumps(r, default=str).lower()
        if needle in blob and not matched:
            matched.append({"type": "text", "value": needle})
        if matched:
            hits.append({
                "analysis_id": r.get("analysis_id"),
                "target_name": r.get("target_name"),
                "threat_level": r.get("overall_threat_level"),
                "threat_score": r.get("threat_score"),
                "matched": matched[:10],
            })
    return {"query": needle, "hit_count": len(hits), "hits": hits}
