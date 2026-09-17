import asyncio
import json
import os
import httpx

API = "https://openrouter.ai/api/v1/chat/completions"
KEY = os.environ.get("OPENROUTER_API_KEY", "")
MODEL = os.environ.get("NEUROTRACE_LLM_MODEL", "nvidia/nemotron-3.5-lightning:free")

SYSTEM = (
    "You are a DFIR analyst. Reply with ONLY a JSON object, no markdown, no prose.\n"
    'Required keys: attack_narrative (string), threat_level (CRITICAL|HIGH|ELEVATED|LOW), '
    "calculated_risk_score (int 0-100), key_findings (array of strings)."
)
USER = (
    "Evidence: 11 in-memory injections in MsMpEng.exe, SearchUI.exe, smartscreen.exe. "
    "2 established outbound connections to 205.185.216.10 and 40.67.254.36. "
    "70 processes total, 3 compromised. Emit the JSON."
)

async def main():
    async with httpx.AsyncClient(timeout=60) as c:
        for label, body in (
            ("json_object", {
                "model": MODEL,
                "messages": [{"role":"system","content":SYSTEM},{"role":"user","content":USER}],
                "temperature": 0.2,
                "max_tokens": 800,
                "response_format": {"type": "json_object"},
            }),
            ("plain", {
                "model": MODEL,
                "messages": [{"role":"system","content":SYSTEM},{"role":"user","content":USER}],
                "temperature": 0.2,
                "max_tokens": 800,
            }),
        ):
            r = await c.post(API, json=body, headers={"Authorization": f"Bearer {KEY}"})
            print("===", label, "status", r.status_code)
            if r.status_code != 200:
                print(r.text[:400])
                continue
            data = r.json()
            text = (data.get("choices") or [{}])[0].get("message", {}).get("content") or ""
            print("raw_repr=", repr(text[:500]))
            print("len=", len(text))
            try:
                print("parsed=", json.loads(text))
            except Exception as e:
                print("parse_fail", e)

asyncio.run(main())
