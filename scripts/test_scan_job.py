import json
import time
import urllib.request
import uuid

# tiny fake dump — should fail/fallback quickly, NOT hang
boundary = "----nt" + uuid.uuid4().hex
data = b"\x00" * 4096
filename = "tiny-test.raw"
body = (
    f"--{boundary}\r\n"
    f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
    f"Content-Type: application/octet-stream\r\n\r\n"
).encode() + data + f"\r\n--{boundary}--\r\n".encode()

req = urllib.request.Request(
    "http://127.0.0.1:8010/api/scan",
    data=body,
    headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=30) as resp:
    print("POST /api/scan", resp.status)
    start = json.loads(resp.read())
    print(start)

job_id = start["job_id"]
for i in range(40):
    time.sleep(1)
    with urllib.request.urlopen(f"http://127.0.0.1:8010/api/jobs/{job_id}", timeout=10) as resp:
        job = json.loads(resp.read())
    print(f"[{i}s] status={job['status']} stage={job['stage']} err={job.get('error')}")
    if job["status"] in ("completed", "failed"):
        print("logs:")
        for line in job.get("logs", [])[-15:]:
            print(" ", line)
        if job.get("error"):
            print("ERROR:", job["error"])
        if job.get("result"):
            r = job["result"]
            print("result: mode=", r.get("vol3_mode"), "procs=", r.get("total_processes"),
                  "threat=", r.get("overall_threat_level"))
        break
else:
    print("TIMEOUT — job still running after 40s (BAD)")
