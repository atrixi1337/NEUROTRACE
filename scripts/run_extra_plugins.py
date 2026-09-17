"""Quick follow-up: run hollowprocesses + netscan on the extracted dump."""
import asyncio
import json
from pathlib import Path

from neurotrace.volatility import VolatilityWrapper

async def main():
    w = VolatilityWrapper(plugins=[
        "windows.hollowprocesses",
        "windows.netscan",
    ], per_plugin_timeout=240)
    dump = Path("/opt/neurotrace/uploads/extracted/imagery.raw")
    r = await w.run(dump)
    print("mode=", r.mode.value)
    print("plugins_run=", r.plugins_run)
    print("plugins_failed=", r.plugins_failed)
    print("injections=", len(r.injections))
    for i in r.injections[:10]:
        print("  inj", i)
    print("beacons=", len(r.beacons))
    for b in r.beacons[:10]:
        print("  beacon", b)
    print("notes:")
    for n in r.notes[:15]:
        print("  -", n)

asyncio.run(main())
