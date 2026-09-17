import pkgutil
import volatility3.plugins

found = []
for m in pkgutil.walk_packages(volatility3.plugins.__path__, "volatility3.plugins."):
    found.append(m.name)

print("=== cobalt/beacon/sliver/yara/impscan ===")
for n in sorted(found):
    low = n.lower()
    if any(k in low for k in ("cobalt", "beacon", "sliver", "yara", "impscan", "svcscan", "netscan")):
        print(n)

print("=== windows.malware.* ===")
for n in sorted(found):
    if n.startswith("volatility3.plugins.windows.malware"):
        print(n)
