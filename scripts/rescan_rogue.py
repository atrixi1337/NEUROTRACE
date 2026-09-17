import asyncio
import json
import time
from pathlib import Path

from neurotrace.core.engine import NeurotraceEngine
from neurotrace.volatility import VolatilityWrapper

DUMP = Path("/opt/neurotrace/uploads/1789048996-RogueOne_extracted/20230810.mem")
REPORT_GLOB = "NT-*RogueOne*.json"

async def main():
    print("dump", DUMP, "size", DUMP.stat().st_size)
    w = VolatilityWrapper()
    print("plugin_timeout", w._effective_plugin_timeout(DUMP))
    print("symbol_dir", w.symbol_dir, "writable", end=" ")
    try:
        p = Path(w.symbol_dir) / ".probe"
        p.write_text("1"); p.unlink()
        print(True)
    except Exception as e:
        print(False, e)

    engine = NeurotraceEngine(vol3=w)
    t0 = time.time()
    report = await engine.analyze_memory_file(DUMP, sample_name="RogueOne.zip")
    print(f"elapsed={time.time()-t0:.1f}s")
    print("analysis_id", report.analysis_id)
    print("mode", getattr(report, "vol3_mode", "?"))
    print("processes", report.total_processes, "compromised", report.compromised_processes)
    print("injections", len(report.injections), "beacons", len(report.beacons))
    print("threat", report.overall_threat_level, report.threat_score)
    print("plugins_run", getattr(report, "plugins_run", []))
    print("plugins_failed", getattr(report, "plugins_failed", []))
    print("ai_fallback", "offline" in (report.ai_storyline or ""))
    print("ai_head", (report.ai_storyline or "")[:500])
    print("notes", getattr(report, "coverage_notes", [])[:6])

    # Overwrite the latest failed RogueOne report so History shows real data.
    from neurotrace.config import REPORTS_DIR
    cands = sorted(REPORTS_DIR.glob("*RogueOne*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if cands:
        target = cands[0]
        data = json.loads(target.read_text(encoding="utf-8"))
        new = json.loads(report.model_dump_json())
        new["analysis_id"] = data.get("analysis_id", new["analysis_id"])
        new["target_name"] = "RogueOne.zip"
        target.write_text(json.dumps(new, indent=2), encoding="utf-8")
        print("updated", target)

asyncio.run(main())
