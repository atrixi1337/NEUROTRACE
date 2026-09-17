import re
from pathlib import Path

p = Path("/opt/neurotrace/uploads/1789041268-imagery_extracted/imagery.raw")
print("exists", p.exists(), "size", p.stat().st_size if p.exists() else None)
data = p.read_bytes()[:128 * 1024 * 1024]

pat = re.compile(rb"RSDS.{16}(.{4})([^\x00]{5,200}\.pdb)", re.S)
hits = []
allp = []
for m in pat.finditer(data):
    age = int.from_bytes(m.group(1), "little")
    path = m.group(2).decode("ascii", "ignore")
    g = m.group(0)[4:20]
    guid_s = (
        f"{g[0:4][::-1].hex()}-{g[4:6][::-1].hex()}-{g[6:8][::-1].hex()}-"
        f"{g[8:10].hex()}-{g[10:16].hex()}"
    )
    if path not in allp:
        allp.append(path)
    if "ntkrnl" in path.lower() or "ntoskrnl" in path.lower():
        hits.append((guid_s, age, path))

print("nt kernel PDB hits:")
for h in hits[:10]:
    print(" ", h)
print("unique pdb paths:")
for pth in allp[:25]:
    print(" ", pth)
