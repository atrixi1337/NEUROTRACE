import asyncio, json, os, httpx

MODELS = [
    "nvidia/nemotron-3.5-lightning:free",
    "google/gemma-4-31b-it:free",
    "cohere/north-mini-code:free",
    "poolside/laguna-s-2.1:free",
]

SYSTEM = (
    "You are NEUROTRACE AI, a DFIR memory-forensics investigator.\n"
    "OUTPUT RULE: Your entire reply must be one JSON object and nothing else.\n"
    "Do not explain. Do not use markdown. Do not print a thinking process.\n"
    "If you need to reason, reason inside the attack_narrative string.\n"
    'Schema: {"attack_narrative": str, "primary_threat_actor_or_malware": str, '
    '"threat_level": "CRITICAL"|"HIGH"|"ELEVATED"|"LOW", "calculated_risk_score": int, '
    '"key_findings": [str], "mitre_techniques": [str], '
    '"incident_response_recommendations": [str], "yara_rule": str}'
)
USER = json.dumps({
    "processes_total": 70,
    "processes_compromised": 3,
    "injections": [
        {"pid": 1988, "process_name": "MsMpEng.exe", "injection_type": "Reflective DLL",
         "target_address": "0xB2C00000", "payload_size": 4096, "confidence": "CRITICAL"},
        {"pid": 3672, "process_name": "SearchUI.exe", "injection_type": "Reflective DLL",
         "confidence": "CRITICAL"},
        {"pid": 1516, "process_name": "smartscreen.exe", "injection_type": "Reflective DLL",
         "confidence": "CRITICAL"},
    ],
    "beacons": [{"c2_framework": "session", "c2_servers": ["205.185.216.10", "40.67.254.36"]}],
})

async def try_model(c, key, model):
    r = await c.post(
        "https://openrouter.ai/api/v1/chat/completions",
        json={
            "model": model,
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": USER}],
            "temperature": 0.1,
            "max_tokens": 2000,
            "response_format": {"type": "json_object"},
        },
        headers={"Authorization": f"Bearer {key}"},
    )
    if r.status_code != 200:
        return model, None, f"http {r.status_code}: {r.text[:120]}"
    text = (r.json().get("choices") or [{}])[0].get("message", {}).get("content") or ""
    try:
        obj = json.loads(text)
        return model, obj, "OK"
    except Exception as e:
        # try extract
        from neurotrace.llm.base import safe_json_loads
        try:
            return model, safe_json_loads(text), "recovered"
        except Exception:
            return model, None, f"fail {e}; head={text[:80]!r}"

async def main():
    key = os.environ["OPENROUTER_API_KEY"]
    async with httpx.AsyncClient(timeout=90) as c:
        for m in MODELS:
            model, obj, note = await try_model(c, key, m)
            print(f"{model}: {note}")
            if obj:
                print("  narrative:", (obj.get("attack_narrative") or "")[:180])
                print("  level:", obj.get("threat_level"), "score:", obj.get("calculated_risk_score"))
                return
    print("NONE_WORKED")

asyncio.run(main())
