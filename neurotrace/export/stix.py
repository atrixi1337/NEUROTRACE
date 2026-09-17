"""Minimal STIX 2.1 bundle export from a NEUROTRACE report."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from neurotrace.intel.iocs import extract_iocs


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def report_to_stix(report: Dict[str, Any]) -> Dict[str, Any]:
    """Emit a STIX 2.1 bundle: identity, observed-data, indicators."""
    now = _ts()
    sid = f"identity--{uuid.uuid4()}"
    objects: List[Dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": sid,
            "created": now,
            "modified": now,
            "name": "NEUROTRACE",
            "identity_class": "system",
        }
    ]

    iocs = extract_iocs(report)
    observed: List[Dict[str, Any]] = []
    for ip in iocs.get("ips") or []:
        observed.append({"type": "ipv4-addr", "value": ip})
    for d in iocs.get("domains") or []:
        observed.append({"type": "domain-name", "value": d})
    for h in iocs.get("sha256") or []:
        observed.append({"type": "file", "hashes": {"SHA-256": h}})

    if observed:
        objects.append({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": f"observed-data--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "first_observed": now,
            "last_observed": now,
            "number_observed": len(observed),
            "x_neurotrace_objects": observed,
            "created_by_ref": sid,
            "x_neurotrace_analysis": report.get("analysis_id"),
        })

    for ip in iocs.get("ips") or []:
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": f"NEUROTRACE C2 IP {ip}",
            "description": f"Observed in memory analysis {report.get('analysis_id')}",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": now,
            "created_by_ref": sid,
        })
    for d in iocs.get("domains") or []:
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": f"NEUROTRACE domain {d}",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[domain-name:value = '{d}']",
            "pattern_type": "stix",
            "valid_from": now,
            "created_by_ref": sid,
        })

    for tech in report.get("mitre_techniques") or []:
        objects.append({
            "type": "x-neurotrace-technique",
            "spec_version": "2.1",
            "id": f"x-neurotrace-technique--{uuid.uuid4()}",
            "created": now,
            "technique": tech,
            "analysis_id": report.get("analysis_id"),
        })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
