import os
import lzma
import json
from pathlib import Path
from urllib.request import pathname2url

from volatility3.framework import contexts
from volatility3.framework.symbols.windows import pdbconv

# Kernel PDB for RogueOne / 20230810.mem
GUID = "3789767E34B7A48A3FC80CE12DE18E65"
AGE = "1"
PDB = "ntkrnlmp.pdb"
OUT_DIR = Path("/opt/neurotrace/symbols/windows/ntkrnlmp.pdb")
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT = OUT_DIR / f"{GUID}-{AGE}.json.xz"

if OUT.exists():
    print("already present", OUT, OUT.stat().st_size)
    raise SystemExit(0)

print("downloading", PDB, GUID, AGE)
ctx = contexts.Context()
filename = pdbconv.PdbRetreiver().retreive_pdb(GUID + AGE, file_name=PDB)
print("retrieved", filename)
if not filename:
    raise SystemExit("download failed")
if os.path.exists(filename):
    location = "file:" + pathname2url(os.path.abspath(filename))
else:
    location = filename
print("converting...")
js = pdbconv.PdbReader(ctx, location, PDB).get_json()
print("meta", js.get("metadata", {}).get("windows"))
with lzma.open(OUT, "w") as of:
    of.write(json.dumps(js, indent=2, sort_keys=True).encode())
print("wrote", OUT, OUT.stat().st_size)
if os.path.exists(filename):
    os.remove(filename)
print("DONE")
