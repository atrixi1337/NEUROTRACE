import json, urllib.request

def post(path, body):
    req = urllib.request.Request(
        "http://127.0.0.1:8010" + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.loads(r.read())

def get(path):
    with urllib.request.urlopen("http://127.0.0.1:8010" + path, timeout=30) as r:
        return json.loads(r.read())

print("=== chat ===")
try:
    print(post("/api/chat", {
        "analysis_id": "NT-6DEF313D",
        "message": "What IPs did this host talk to? Keep it short.",
    }).get("answer", "")[:600])
except Exception as e:
    print("FAIL", e)

print("=== stix types ===")
try:
    b = get("/api/reports/NT-6DEF313D/stix")
    types = {}
    for o in b.get("objects", []):
        types[o.get("type")] = types.get(o.get("type"), 0) + 1
    print(types)
except Exception as e:
    print("FAIL", e)
