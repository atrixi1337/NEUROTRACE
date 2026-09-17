"""YARAKIN bridge — submit carved artifacts / request YARA forge."""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger("neurotrace.yarakin")


def yarakin_base() -> Optional[str]:
    return (os.getenv("YARAKIN_URL") or "").strip().rstrip("/") or None


def yarakin_key() -> Optional[str]:
    return (os.getenv("YARAKIN_API_KEY") or "").strip() or None


async def yarakin_health() -> Dict[str, Any]:
    base = yarakin_base()
    if not base:
        return {"configured": False, "status": "YARAKIN_URL not set"}
    try:
        headers = {}
        key = yarakin_key()
        if key:
            headers["X-Yarakin-Key"] = key
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{base}/api/history", headers=headers)
            return {
                "configured": True,
                "url": base,
                "status": r.status_code,
                "ok": r.status_code == 200,
            }
    except Exception as exc:  # noqa: BLE001
        return {"configured": True, "url": base, "ok": False, "error": str(exc)}


async def submit_sample(
    file_path: Path,
    callback_url: Optional[str] = None,
    wait: int = 0,
) -> Dict[str, Any]:
    """POST a binary to YARAKIN /api/webhook/analyze."""
    base = yarakin_base()
    if not base:
        raise RuntimeError("YARAKIN_URL is not configured")
    headers = {}
    key = yarakin_key()
    if key:
        headers["X-Yarakin-Key"] = key

    url = f"{base}/api/webhook/analyze"
    params: Dict[str, Any] = {}
    if callback_url:
        params["callback_url"] = callback_url
    if wait:
        params["wait"] = wait

    data = file_path.read_bytes()
    async with httpx.AsyncClient(timeout=120) as c:
        r = await c.post(
            url,
            params=params,
            content=data,
            headers={**headers, "Content-Type": "application/octet-stream"},
        )
        r.raise_for_status()
        return r.json()


async def get_job(job_id: str) -> Dict[str, Any]:
    base = yarakin_base()
    if not base:
        raise RuntimeError("YARAKIN_URL is not configured")
    headers = {}
    key = yarakin_key()
    if key:
        headers["X-Yarakin-Key"] = key
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.get(f"{base}/api/jobs/{job_id}/result", headers=headers)
        r.raise_for_status()
        return r.json()


def attach_yarakin_to_report(report: Dict[str, Any], yara_result: Dict[str, Any]) -> Dict[str, Any]:
    """Merge a YARAKIN webhook result into a NEUROTRACE report dict."""
    results = yara_result.get("results") or []
    rules = yara_result.get("rules") or []
    report = dict(report)
    report["yarakin"] = {
        "job": yara_result.get("job"),
        "status": yara_result.get("status"),
        "model": yara_result.get("model"),
        "totals": yara_result.get("totals"),
        "results": results,
        "rules": rules,
    }
    if rules and not report.get("generated_yara_rule"):
        report["generated_yara_rule"] = rules[0].get("yara")
    # Boost confidence when YARAKIN says malicious with a validated rule.
    if results:
        verdict = (results[0] or {}).get("verdict")
        if verdict == "malicious" and rules:
            report.setdefault("coverage_notes", []).append(
                "YARAKIN validated a YARA rule for this sample family."
            )
    return report
