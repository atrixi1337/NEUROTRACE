import asyncio
import json
import time
from pathlib import Path

from neurotrace.core.engine import NeurotraceEngine
from neurotrace.volatility import VolatilityWrapper

DUMP = Path("/opt/neurotrace/uploads/1789041268-imagery_extracted/imagery.raw")
REPORT = Path("/opt/neurotrace/reports/NT-9B34C8CD-imagery.7z.json")

async def main():
    print("dump", DUMP, "size", DUMP.stat().st_size)
    w = VolatilityWrapper()
    print("plugin_timeout would be", w._effective_plugin_timeout(DUMP))
    engine = NeurotraceEngine(vol3=w)
    t0 = time.time()
    report = await engine.analyze_memory_file(DUMP, sample_name="imagery.7z")
    print(f"elapsed={time.time()-t0:.1f}s")
    print("analysis_id", report.analysis_id)
    print("mode", getattr(report, "vol3_mode", "?"))
    print("processes", report.total_processes, "compromised", report.compromised_processes)
    print("injections", len(report.injections), "beacons", len(report.beacons))
    print("threat", report.overall_threat_level, report.threat_score)
    print("plugins_run", getattr(report, "plugins_run", []))
    print("plugins_failed", getattr(report, "plugins_failed", []))
    print("ai_fallback", "offline" in (report.ai_storyline or ""))
    print("ai_head", (report.ai_storyline or "")[:400])

    # Overwrite the bad fallback report so History shows the good one.
    if REPORT.exists():
        data = json.loads(REPORT.read_text(encoding="utf-8"))
        # Keep the new analysis id in a copy too; replace the old file body
        # with the successful report so History click reloads real data.
        new = json.loads(report.model_dump_json())
        new["analysis_id"] = data.get("analysis_id", new["analysis_id"])
        new["target_name"] = "imagery.7z"
        REPORT.write_text(json.dumps(new, indent=2), encoding="utf-8")
        print("updated", REPORT)

asyncio.run(main())
