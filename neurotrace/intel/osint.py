"""OSINT enrichment agent.

Fans out extracted IOCs to free/open intel sources. Degrades gracefully:
missing API keys are skipped, not fatal. Optional OSINT_HUB_URL reuses
your existing osint-hub service when it is running.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("neurotrace.osint")

TIMEOUT = 15.0


def _env(name: str) -> str:
    return (os.getenv(name) or "").strip()


async def _get(
    client: httpx.AsyncClient,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    try:
        r = await client.get(url, headers=headers, params=params, timeout=TIMEOUT)
        if r.status_code == 200:
            try:
                return r.json()
            except Exception:  # noqa: BLE001
                return {"_raw": r.text[:2000], "_status": r.status_code}
        return {"_error": f"HTTP {r.status_code}", "_body": r.text[:300]}
    except Exception as exc:  # noqa: BLE001
        return {"_error": str(exc)}


async def enrich_ip(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ioc": ip, "type": "ip", "sources": {}}

    # VirusTotal (free key)
    vt = _env("VIRUSTOTAL_API_KEY")
    if vt:
        data = await _get(
            client,
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": vt},
        )
        if data and "data" in data:
            attrs = (data.get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
            out["sources"]["virustotal"] = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "reputation": attrs.get("reputation"),
                "country": (attrs.get("country") or None),
                "as_owner": attrs.get("as_owner"),
            }
        elif data:
            out["sources"]["virustotal"] = data

    # AbuseIPDB (free key)
    ab = _env("ABUSEIPDB_API_KEY")
    if ab:
        data = await _get(
            client,
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ab, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
        )
        if data and "data" in data:
            d = data["data"]
            out["sources"]["abuseipdb"] = {
                "abuseConfidenceScore": d.get("abuseConfidenceScore"),
                "totalReports": d.get("totalReports"),
                "countryCode": d.get("countryCode"),
                "isp": d.get("isp"),
                "usageType": d.get("usageType"),
            }
        elif data:
            out["sources"]["abuseipdb"] = data

    # GreyNoise community (free key)
    gn = _env("GREYNOISE_API_KEY")
    if gn:
        data = await _get(
            client,
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": gn},
        )
        if data:
            out["sources"]["greynoise"] = {
                k: data.get(k)
                for k in ("noise", "riot", "classification", "name", "link")
                if k in data
            }

    # Shodan InternetDB — keyless
    data = await _get(client, f"https://internetdb.shodan.io/{ip}")
    if data and "detail" not in data:
        out["sources"]["shodan_internetdb"] = {
            "ports": data.get("ports"),
            "hostnames": data.get("hostnames"),
            "cpes": data.get("cpes"),
            "vulns": (data.get("vulns") or [])[:10],
            "tags": data.get("tags"),
        }
    elif data:
        out["sources"]["shodan_internetdb"] = data

    # AlienVault OTX (optional key)
    otx = _env("OTX_API_KEY")
    headers = {"X-OTX-API-KEY": otx} if otx else None
    data = await _get(
        client,
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
        headers=headers,
    )
    if data and "pulse_info" in data:
        pulses = data.get("pulse_info") or {}
        out["sources"]["otx"] = {
            "pulse_count": pulses.get("count"),
            "reputation": data.get("reputation"),
            "country": (data.get("country") or {}).get("name") if isinstance(data.get("country"), dict) else None,
            "asn": data.get("asn"),
        }
    elif data:
        out["sources"]["otx"] = data

    out["score"] = _score_ip(out["sources"])
    out["summary"] = _summarize_ip(ip, out["sources"])
    return out


async def enrich_domain(client: httpx.AsyncClient, domain: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ioc": domain, "type": "domain", "sources": {}}

    vt = _env("VIRUSTOTAL_API_KEY")
    if vt:
        data = await _get(
            client,
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": vt},
        )
        if data and "data" in data:
            attrs = (data["data"] or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
            out["sources"]["virustotal"] = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "reputation": attrs.get("reputation"),
            }

    # URLhaus host lookup — keyless
    try:
        r = await client.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            j = r.json()
            if j.get("query_status") == "ok":
                urls = j.get("urls") or []
                out["sources"]["urlhaus"] = {
                    "url_count": len(urls),
                    "threats": list({(u.get("threat") or "") for u in urls})[:5],
                    "blacklists": j.get("blacklists"),
                }
            else:
                out["sources"]["urlhaus"] = {"query_status": j.get("query_status")}
    except Exception as exc:  # noqa: BLE001
        out["sources"]["urlhaus"] = {"_error": str(exc)}

    otx = _env("OTX_API_KEY")
    headers = {"X-OTX-API-KEY": otx} if otx else None
    data = await _get(
        client,
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
        headers=headers,
    )
    if data and "pulse_info" in data:
        out["sources"]["otx"] = {"pulse_count": (data.get("pulse_info") or {}).get("count")}

    out["score"] = _score_generic(out["sources"])
    out["summary"] = _summarize_generic(domain, out["sources"])
    return out


async def enrich_hash(client: httpx.AsyncClient, h: str, htype: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ioc": h, "type": f"hash_{htype}", "sources": {}}
    vt = _env("VIRUSTOTAL_API_KEY")
    if vt:
        data = await _get(
            client,
            f"https://www.virustotal.com/api/v3/files/{h}",
            headers={"x-apikey": vt},
        )
        if data and "data" in data:
            attrs = (data["data"] or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
            out["sources"]["virustotal"] = {
                "malicious": stats.get("malicious", 0),
                "total": sum(stats.values()) if stats else 0,
                "names": (attrs.get("names") or [])[:3],
                "type_description": attrs.get("type_description"),
            }

    # MalwareBazaar — keyless with optional ABUSECH_API_KEY
    ab = _env("ABUSECH_API_KEY")
    headers = {"Auth-Key": ab} if ab else None
    try:
        r = await client.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": h},
            headers=headers,
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            j = r.json()
            if j.get("query_status") == "ok":
                info = (j.get("data") or [{}])[0]
                out["sources"]["malwarebazaar"] = {
                    "signature": info.get("signature"),
                    "file_type": info.get("file_type"),
                    "vendor_intel": bool(info.get("vendor_intel")),
                }
            else:
                out["sources"]["malwarebazaar"] = {"query_status": j.get("query_status")}
    except Exception as exc:  # noqa: BLE001
        out["sources"]["malwarebazaar"] = {"_error": str(exc)}

    out["score"] = _score_generic(out["sources"])
    out["summary"] = _summarize_generic(h[:16] + "…", out["sources"])
    return out


def _score_ip(sources: Dict[str, Any]) -> int:
    score = 0
    vt = sources.get("virustotal") or {}
    if isinstance(vt, dict) and "malicious" in vt:
        score += min(50, int(vt.get("malicious") or 0) * 5)
    ab = sources.get("abuseipdb") or {}
    if isinstance(ab, dict) and ab.get("abuseConfidenceScore") is not None:
        score += int(ab.get("abuseConfidenceScore") or 0) // 2
    gn = sources.get("greynoise") or {}
    if isinstance(gn, dict):
        if gn.get("classification") == "malicious":
            score += 30
        if gn.get("noise"):
            score += 10
    otx = sources.get("otx") or {}
    if isinstance(otx, dict) and otx.get("pulse_count"):
        score += min(25, int(otx["pulse_count"]) * 3)
    return max(0, min(100, score))


def _score_generic(sources: Dict[str, Any]) -> int:
    score = 0
    vt = sources.get("virustotal") or {}
    if isinstance(vt, dict) and "malicious" in vt:
        score += min(70, int(vt.get("malicious") or 0) * 5)
    uh = sources.get("urlhaus") or {}
    if isinstance(uh, dict) and uh.get("url_count"):
        score += min(40, int(uh["url_count"]) * 8)
    mb = sources.get("malwarebazaar") or {}
    if isinstance(mb, dict) and mb.get("signature"):
        score += 50
    otx = sources.get("otx") or {}
    if isinstance(otx, dict) and otx.get("pulse_count"):
        score += min(30, int(otx["pulse_count"]) * 4)
    return max(0, min(100, score))


def _summarize_ip(ip: str, sources: Dict[str, Any]) -> str:
    bits = []
    vt = sources.get("virustotal") or {}
    if isinstance(vt, dict) and "malicious" in vt:
        bits.append(f"VT {vt.get('malicious', 0)} malicious")
        if vt.get("as_owner"):
            bits.append(str(vt["as_owner"]))
    ab = sources.get("abuseipdb") or {}
    if isinstance(ab, dict) and ab.get("abuseConfidenceScore") is not None:
        bits.append(f"AbuseIPDB {ab['abuseConfidenceScore']}%")
    gn = sources.get("greynoise") or {}
    if isinstance(gn, dict) and gn.get("classification"):
        bits.append(f"GreyNoise {gn['classification']}")
    uh = sources.get("shodan_internetdb") or {}
    if isinstance(uh, dict) and uh.get("ports"):
        bits.append(f"ports {uh['ports'][:6]}")
    otx = sources.get("otx") or {}
    if isinstance(otx, dict) and otx.get("pulse_count"):
        bits.append(f"OTX {otx['pulse_count']} pulses")
    return "; ".join(bits) if bits else "no strong intel signals"


def _summarize_generic(ioc: str, sources: Dict[str, Any]) -> str:
    bits = []
    vt = sources.get("virustotal") or {}
    if isinstance(vt, dict) and "malicious" in vt:
        bits.append(f"VT {vt.get('malicious', 0)} malicious")
    uh = sources.get("urlhaus") or {}
    if isinstance(uh, dict) and uh.get("url_count"):
        bits.append(f"URLhaus {uh['url_count']} urls")
    mb = sources.get("malwarebazaar") or {}
    if isinstance(mb, dict) and mb.get("signature"):
        bits.append(f"MB {mb['signature']}")
    otx = sources.get("otx") or {}
    if isinstance(otx, dict) and otx.get("pulse_count"):
        bits.append(f"OTX {otx['pulse_count']} pulses")
    return "; ".join(bits) if bits else "no strong intel signals"


async def enrich_iocs(
    iocs: Dict[str, List[str]],
    max_per_type: int = 8,
) -> Dict[str, Any]:
    """Enrich a batch of IOCs. Optionally prefers OSINT_HUB_URL."""
    hub = _env("OSINT_HUB_URL").rstrip("/")
    results: List[Dict[str, Any]] = []
    providers_used: List[str] = []

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        tasks = []
        meta = []
        for ip in (iocs.get("ips") or [])[:max_per_type]:
            if hub:
                tasks.append(_hub_lookup(client, hub, ip))
            else:
                tasks.append(enrich_ip(client, ip))
            meta.append(("ip", ip))
        for dom in (iocs.get("domains") or [])[:max_per_type]:
            if hub:
                tasks.append(_hub_lookup(client, hub, dom))
            else:
                tasks.append(enrich_domain(client, dom))
            meta.append(("domain", dom))
        for h in (iocs.get("sha256") or [])[:max_per_type]:
            tasks.append(enrich_hash(client, h, "sha256"))
            meta.append(("sha256", h))
        for h in (iocs.get("md5") or [])[:max_per_type]:
            tasks.append(enrich_hash(client, h, "md5"))
            meta.append(("md5", h))

        if not tasks:
            return {"enriched": [], "providers": [], "hub": bool(hub)}

        done = await asyncio.gather(*tasks, return_exceptions=True)
        for (typ, val), res in zip(meta, done):
            if isinstance(res, Exception):
                results.append({"ioc": val, "type": typ, "error": str(res)})
                continue
            results.append(res)
            for src in (res.get("sources") or {}):
                if src not in providers_used:
                    providers_used.append(src)

    results.sort(key=lambda r: r.get("score") or 0, reverse=True)
    return {
        "enriched": results,
        "providers": providers_used,
        "hub": bool(hub),
        "enriched_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
    }


async def _hub_lookup(client: httpx.AsyncClient, hub: str, value: str) -> Dict[str, Any]:
    """Delegate to an osint-hub instance if configured."""
    try:
        r = await client.post(f"{hub}/api/lookup", json={"input": value}, timeout=60)
        r.raise_for_status()
        data = r.json()
        return {
            "ioc": value,
            "type": data.get("type") or "auto",
            "sources": data.get("results") or data.get("providers") or {"osint_hub": data},
            "score": data.get("score") or 0,
            "summary": data.get("brief") or data.get("summary") or "osint-hub brief",
            "hub": True,
        }
    except Exception as exc:  # noqa: BLE001
        return {"ioc": value, "type": "auto", "error": f"osint-hub: {exc}", "sources": {}}
