# NEUROTRACE Lab — malware-safe drop zone

**Nothing in this tree should ever be opened or executed on the host.**

All analysis happens inside Docker. The host only stores bytes.

## Layout

| Path | Purpose | Mount |
|---|---|---|
| `lab/dumps/` | RAM images (`.raw` `.dmp` `.vmem`) | `:ro` into app/lab |
| `lab/samples/` | Suspicious binaries for intake | `:ro` into app/lab |
| `lab/out/` | Generated reports you export from the lab | rw, lab only |

## Rules

1. Drop files in with your file manager or `cp`. Never double-click.
2. Analyze only via the container:
   ```bash
   docker compose --profile lab run --rm lab
   # inside the container:
   python -m neurotrace.cli analyze /opt/neurotrace/lab/dumps/your.dmp
   ```
3. The **lab** profile has `network_mode: none` — no exfil, no C2 callback.
4. The **app** profile can reach the internet only if you give it an LLM key.
   Leave `NEUROTRACE_LLM_PROVIDER=stub` (default) for fully offline triage.
5. Git ignores everything under `lab/dumps/` and `lab/samples/` except this README.

## Safe sample sources (for testing)

- EICAR test file: https://www.eicar.org/download-anti-malware-testfile/
- MemLabs: `bash corpora/dumps/fetch.sh` (puts the image in `corpora/`, copy into `lab/dumps/` if you want it here)
- Your own captures, legally obtained

## Wipe

```bash
docker compose down -v          # drops named volumes (reports/uploads/workspace)
rm -f lab/dumps/* lab/samples/*
```
