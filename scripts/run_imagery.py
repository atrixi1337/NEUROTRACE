import asyncio
import time
from pathlib import Path

from neurotrace.core.archives import resolve_analyzable
from neurotrace.core.engine import NeurotraceEngine
from neurotrace.volatility import VolatilityWrapper

archive = Path("/opt/neurotrace/uploads/imagery.7z")
print("resolving", archive)
t0 = time.time()
dump, notes = resolve_analyzable(archive, dest_dir=Path("/opt/neurotrace/uploads/extracted"))
for n in notes:
    print(" intake:", n)
print(f"dump={dump} size={dump.stat().st_size} elapsed={time.time()-t0:.1f}s")

print("building engine...")
engine = NeurotraceEngine(vol3=VolatilityWrapper(), ai=None)
print("starting analysis (Vol3 can take several minutes on a 2GB dump)...")
t1 = time.time()
report = asyncio.run(engine.analyze_memory_file(dump, sample_name="imagery.raw"))
print(f"analysis elapsed={time.time()-t1:.1f}s")
print("analysis_id=", report.analysis_id)
print("vol3_mode=", getattr(report, "vol3_mode", "?"))
print("processes=", report.total_processes)
print("compromised=", report.compromised_processes)
print("threat_level=", report.overall_threat_level)
print("threat_score=", report.threat_score)
print("injections=", len(report.injections))
print("beacons=", len(report.beacons))
print("credentials=", len(report.credentials))
print("findings=", len(report.findings))
print("plugins_run=", getattr(report, "plugins_run", []))
print("plugins_failed=", getattr(report, "plugins_failed", []))
print("coverage_notes=")
for n in getattr(report, "coverage_notes", []):
    print("  -", n)
print("ai_storyline_head=")
print((report.ai_storyline or "")[:500])
