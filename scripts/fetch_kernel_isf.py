"""Download ntkrnlmp.pdb for the dump and convert it to Vol3 ISF."""
import os
import lzma
import json
from pathlib import Path

from volatility3.framework import contexts
from volatility3.framework.symbols.windows import pdbconv

GUID = "8B11040A5928757B11390AC78F6B6925"
AGE = "1"
PDB = "ntkrnlmp.pdb"
OUT_DIR = Path("/opt/neurotrace/symbols/windows/ntkrnlmp.pdb")
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT = OUT_DIR / f"{GUID}-{AGE}.json.xz"

print("downloading", PDB, GUID, AGE)
ctx = contexts.Context()
filename = pdbconv.PdbRetreiver().retreive_pdb(
    GUID + AGE, file_name=PDB, progress_callback=None
)
print("retrieved", filename)
if not filename:
    raise SystemExit("download failed")

location = "file:" + filename if not filename.startswith("http") else filename
# On Linux, pathname2url style
from urllib.request import pathname2url
if os.path.exists(filename):
    location = "file:" + pathname2url(os.path.abspath(filename))

print("converting", location)
reader = pdbconv.PdbReader(ctx, location, PDB, None)
js = reader.get_json()
print("json keys", list(js)[:8], "tables", js.get("metadata", {}))
with lzma.open(OUT, "w") as of:
    of.write(json.dumps(js, indent=2, sort_keys=True).encode())
print("wrote", OUT, "size", OUT.stat().st_size)
os.remove(filename)
print("done")
