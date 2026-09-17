import asyncio, json, os, httpx
from neurotrace.ai.analyst import ForensicAIAnalyst
from neurotrace.llm import LLMRequest

async def main():
    ai = ForensicAIAnalyst()
    evidence = {
        "analysis_id": "NT-TEST",
        "target": "imagery.raw",
        "vol3_mode": "real",
        "processes_total": 70,
        "processes_compromised": 3,
        "injections": [
            {"pid": 1988, "process_name": "MsMpEng.exe", "injection_type": "Reflective DLL",
             "target_address": "0xB2C00000", "payload_size": 4096, "confidence": "CRITICAL"}
            for _ in range(5)
        ],
        "beacons": [{"c2_framework": "session", "c2_servers": ["205.185.216.10", "40.67.254.36"]}],
        "credentials": [],
        "findings": [{"title": "In-Memory Code Injection Detected", "severity": "CRITICAL",
                      "mitre_attack_id": "T1055"}],
        "mitre_attiques": ["T1055"],
        "processes": [
            {"pid": 1988, "name": "MsMpEng.exe", "is_compromised": True},
            {"pid": 3672, "name": "SearchUI.exe", "is_compromised": True},
        ],
    }
    compact = ai._compact_evidence(evidence)
    user = (
        "Examine the following Memory Dump Forensic Analysis Data and emit ONLY the JSON object.\n"
        "Do not include a thinking process. Do not wrap in markdown.\n\n"
        + json.dumps(compact, indent=2, default=str)
    )
    resp = await ai._provider.chat(LLMRequest(
        system=ai.SYSTEM_PROMPT,
        user=user,
        temperature=0.1,
        max_tokens=3000,
        json_mode=True,
    ))
    print("parsed?", bool(resp.parsed), "text_len", len(resp.text or ""))
    print("TEXT_HEAD:")
    print((resp.text or "")[:2000])
    print("TEXT_TAIL:")
    print((resp.text or "")[-1500:])

asyncio.run(main())
