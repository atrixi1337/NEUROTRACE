"""Re-run AI analyst on an existing report and patch the narrative in place."""
import asyncio
import json
import sys
from pathlib import Path

from neurotrace.ai.analyst import ForensicAIAnalyst


async def main(report_path: str):
    path = Path(report_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    print("loaded", path.name, "threat=", data.get("overall_threat_level"),
          "injections=", len(data.get("injections") or []))

    evidence = {
        "analysis_id": data.get("analysis_id"),
        "target": data.get("target_name"),
        "source": "file",
        "vol3_mode": data.get("vol3_mode"),
        "processes_total": data.get("total_processes"),
        "processes_compromised": data.get("compromised_processes"),
        "injections": data.get("injections") or [],
        "beacons": data.get("beacons") or [],
        "credentials": data.get("credentials") or [],
        "findings": data.get("findings") or [],
        "mitre_attiques": data.get("mitre_techniques") or [],
        "processes": data.get("processes") or [],
        "coverage_notes": data.get("coverage_notes") or [],
        "velociraptor": {"external_connections": data.get("beacons") or []},
    }

    ai = ForensicAIAnalyst()
    print("provider=", ai._provider.name if ai._provider else None,
          "model=", getattr(ai._provider, "default_model", None),
          "live=", ai.is_live)
    result = await ai.generate_forensic_investigation(evidence)

    print("--- AI RESULT ---")
    print("threat_level=", result.get("threat_level"))
    print("score=", result.get("calculated_risk_score"))
    print("actor=", result.get("primary_threat_actor_or_malware"))
    print("narrative=")
    print(result.get("attack_narrative", "")[:1500])
    print("key_findings=", result.get("key_findings"))
    print("mitre=", result.get("mitre_techniques"))
    print("yara_head=")
    print((result.get("yara_rule") or "")[:400])

    offline = "offline rule-based synthesis" in (result.get("attack_narrative") or "")
    print("IS_FALLBACK=", offline)

    # Patch the report so the dashboard History shows the live AI narrative.
    data["ai_storyline"] = result.get("attack_narrative", data.get("ai_storyline"))
    data["ai_recommendations"] = result.get("incident_response_recommendations") or data.get("ai_recommendations")
    data["generated_yara_rule"] = result.get("yara_rule") or data.get("generated_yara_rule")
    if result.get("mitre_techniques"):
        merged = list(dict.fromkeys((data.get("mitre_techniques") or []) + result["mitre_techniques"]))
        data["mitre_techniques"] = merged
    data["ai_meta"] = {
        "provider": ai._provider.name if ai._provider else None,
        "model": getattr(ai._provider, "default_model", None),
        "live": ai.is_live,
        "fallback": offline,
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print("patched", path)


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "/opt/neurotrace/reports/NT-F98DA524-imagery.raw.json"))
