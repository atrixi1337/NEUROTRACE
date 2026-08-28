# 🧠 NEUROTRACE — AI Volatile Memory Forensics Engine v2.0

**Autonomous In-Memory DFIR, Fileless Threat Hunter & C2 Extractor**
*Powered by Volatility3, Velociraptor, and a multi-provider LLM analyst.*

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![LLM: openai/gpt-oss-20b](https://img.shields.io/badge/LLM-openai%2Fgpt--oss--20b-4CC9F0)]()
[![Volatility3](https://img.shields.io/badge/Volatility3-required-red)]()
[![Velociraptor](https://img.shields.io/badge/Velociraptor-optional-yellow)]()
[![Tests](https://img.shields.io/badge/tests-30%20passing-brightgreen)](tests/)

NEUROTRACE ingests volatile RAM dumps (`.raw`, `.dmp`, `.vmem`, `.bin`) —
either uploaded directly or acquired from a Velociraptor-managed endpoint —
walks the process tree with **Volatility3** (real plugins, not custom heuristics),
cross-references with **Velociraptor** artifact rows, and synthesizes a full
multi-stage attack narrative + YARA rule with an AI co-pilot.

> **Status:** v2.0 — pipeline works end-to-end. The bottleneck for
> "real DFIR" use is symbol availability and live Velociraptor;
> see [TODO.md](TODO.md) for the production-readiness roadmap.

---

## ⚡ Core Capabilities

- 🧬 **Volatility3-backed Fileless & Process Injection Hunting** — real `windows.malfind`,
  `windows.hollowfind`, `windows.cobaltstrikebeacon`, `windows.pslist`. No more custom
  VAD walker guesses.
- 🎯 **C2 Beacon Configuration Parser** — extracts endpoints, watermarks, sleep,
  jitter for Cobalt Strike, Sliver, Metasploit. Vol3's `cobaltstrikebeacon` plugin
  is the ground truth; we only normalize the output.
- 🔑 **Volatile Credential & Token Miner** — AWS keys, GitHub PATs, Slack tokens,
  NTLM hashes, private keys. **Streams the dump** (8 MB chunks) so 8 GB+
  workstation images don't OOM.
- 🌐 **Velociraptor Integration** — trigger a hunt from NEUROTRACE, stream
  `Generic.System.Pslist` / `Windows.Network.Netstat` / `Windows.System.HandleSnapshots`
  rows directly into the analysis. Acquire a memory dump from a chosen client
  and pipe it back to Vol3 in one call.
- 🤖 **Multi-Provider AI Co-Pilot** — AkashML (default), OpenAI, OpenRouter, Ollama,
  or any OpenAI-compatible endpoint. Default model: **`openai/gpt-oss-20b`**.
  Stub mode for offline testing.
- 🩺 **Coverage Notes** — every report records *what was scanned*, *what fell
  back to mock*, and *what was skipped* (e.g. missing ISF symbols). No
  silent failure mode.
- 🧪 **Real Test Suite** — 30 unit + integration tests, golden-output regression,
  streaming-chunk boundary test, live AkashML round-trip.

---

## 🚀 Quickstart

### 1. Install
```bash
cd NEUROTRACE
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### 2. Configure
```bash
cp .env.example .env
# Put your AkashML key in .env (or OPENAI_API_KEY, OPENROUTER_API_KEY, OLLAMA_BASE_URL)
```

NEUROTRACE auto-selects the first configured provider. To force a specific
one, set `NEUROTRACE_LLM_PROVIDER` in `.env`.

### 3. CLI
```bash
# Analyze a memory dump file
python -m neurotrace.cli analyze samples/sample_cobaltstrike_dump.dmp

# Analyze a Velociraptor client (acquires dump + runs Vol3)
python -m neurotrace.cli velo C.0011223344556677

# Stream a single Velociraptor artifact
python -m neurotrace.cli velo-artifact C.0011223344556677 Generic.System.Pslist

# Engine + LLM health
python -m neurotrace.cli health
```

### 4. Web UI
```bash
python app.py
# Open http://localhost:8010
```

### 5. API
| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/scan` | Upload a memory dump and analyze |
| `POST` | `/api/velociraptor/analyze?client_id=...` | Acquire + analyze a Velociraptor client |
| `GET`  | `/api/velociraptor/artifact?client_id=...&artifact=...` | Stream a single artifact's rows |
| `GET`  | `/api/llm` | Show LLM provider + model |
| `GET`  | `/api/health` | Engine health |

Set `NEUROTRACE_API_KEY` to enable `X-NT-Key` header auth on the API.

---

## 🏗️ Architecture

```
   memory dump / Velociraptor client
            │
            ▼
   ┌──────────────────┐
   │  Velociraptor    │  Generic.System.Pslist, HandleSnapshots, Netstat
   │  (artifacts)     │  → enriches process tree + network findings
   └────────┬─────────┘
            │
            ▼
   ┌──────────────────┐
   │   Volatility3    │  windows.pslist, malfind, hollowfind,
   │   (real plugins) │  cobaltstrikebeacon, vadinfo, handles
   └────────┬─────────┘
            │
            ▼
   ┌──────────────────┐
   │  NEUROTRACE      │  credential miner (streaming),
   │  Analyzers       │  beacon parser, MITRE mapping,
   │                  │  process tree correlation
   └────────┬─────────┘
            │
            ▼
   ┌──────────────────┐
   │   AI Co-Pilot    │  AkashML / OpenAI / OpenRouter / Ollama
   │   (LLM registry) │  → narrative + YARA rule
   └────────┬─────────┘
            │
            ▼
       ForensicReport
       (JSON + persisted to reports/)
```

### Key packages

```
neurotrace/
├── core/
│   ├── engine.py            # Orchestrator
│   ├── models.py            # Pydantic DFIR models
│   ├── streaming.py         # Constant-memory chunk reader
│   └── scanner.py           # Streaming regex scanner
├── analyzers/
│   ├── beacon_parser.py     # C2 framework config extraction
│   ├── credential_miner.py  # AWS/GitHub/Slack/NTLM/PEM
│   ├── entropy_vad.py       # VAD heuristics (enrichment layer)
│   └── injection_hunter.py  # Capstone disassembly preview
├── ai/
│   └── analyst.py           # Provider-agnostic forensic analyst
├── llm/                     # Multi-provider LLM client
│   ├── base.py
│   ├── openai_compat.py     # AkashML, OpenAI, OpenRouter, Ollama
│   ├── stub.py              # Deterministic offline provider
│   └── registry.py          # Auto-detect + factory
├── volatility/
│   └── wrapper.py           # Vol3 invocation + normalization + mock
├── velociraptor/
│   ├── client.py            # Real HTTP + Mock backends
│   └── factory.py           # Auto-detect from .env
├── cli.py                   # Rich-based CLI
└── app.py                   # FastAPI web server
```

---

## 🔌 LLM Providers

NEUROTRACE auto-detects the first available key in this order:

| Priority | Provider | Env var | Default base URL | Default model |
|---|---|---|---|---|
| 1 | **AkashML** | `AKASHML_API_KEY` | `https://api.akashml.com/v1` | `openai/gpt-oss-20b` |
| 2 | OpenRouter | `OPENROUTER_API_KEY` | `https://openrouter.ai/api/v1` | `openai/gpt-oss-20b` |
| 3 | OpenAI | `OPENAI_API_KEY` | `https://api.openai.com/v1` | `openai/gpt-oss-20b` |
| 4 | Ollama | `OLLAMA_BASE_URL` | `http://localhost:11434/v1` | `llama3.1:8b` |
| 5 | **Stub** (offline) | _(no key needed)_ | — | `stub/forensic-v1` |

**Adding a new provider** = one line in `neurotrace/llm/openai_compat.py`
(subclass `OpenAICompatProvider`, override `name`) + one line in
`neurotrace/llm/registry.py` to register it. Everything else (auth,
JSON-mode handling, retry, streaming) is inherited.

---

## 🦖 Velociraptor Integration

Set `VELO_API_URL` and `VELO_API_KEY` in `.env` to point at a live
Velociraptor server. With no URL set, NEUROTRACE uses a deterministic
in-memory mock so the entire pipeline can be tested offline.

```bash
# .env
VELO_API_URL=https://velo.lab:8001/
VELO_API_KEY=...your-key...
```

The mock backend ships 3 clients and canned artifact responses; it's
used by every test in `tests/test_velociraptor_mock.py`.

---

## 🧪 Tests

```bash
# Offline tests (no API key required)
venv/bin/pytest

# Live AkashML integration test
NEUROTRACE_FORCE_LIVE=1 venv/bin/pytest tests/test_integration_akashml.py
```

The test suite is the safety net that lets us refactor aggressively:
- **Golden-output regression** — pins the engine's output shape against
  the sample dump, so a refactor that accidentally drops a field fails CI
- **Streaming boundary test** — proves that the credential scanner catches
  an AWS key that straddles an 8 MB chunk boundary
- **Mock Velociraptor** — exercises the full hunt + artifact streaming
  flow without a live server
- **Provider fallback** — verifies that strict-JSON-mode failure
  retries gracefully (AkashML behaviour)

---

## ⚠️ Coverage & Limitations

NEUROTRACE's report includes a `coverage_notes` array that tells you
*exactly* what was scanned, what was mocked, and what was skipped. Typical
entries:

- `"Volatility3 ran in fallback mode — see vol.notes for details."`
  → Real Vol3 attempt failed (no ISF symbols for this build); the
  mock fixture was used. The user is told explicitly.
- `"Vol3 mock mode active (no plugins importable). For real analysis,
  install ISF symbols via \`vol --symbol-dirs <path>\` and rerun."`
- `"Velociraptor enrichment failed: <reason>"` — if a Velo call failed
  mid-pipeline, the report continues with the data it has.

To get **real** Vol3 output, install an ISF symbol pack:
```bash
# Linux: ships in the volatility3 package
# Windows: download from https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
# or use community packs like the "windows-symbols" pack
export VOLATILITY_SYMBOL_DIR=/path/to/symbols
```

---

## 📋 Roadmap to Production

This is v2.0. The full backlog of work needed to make NEUROTRACE a
production-grade DFIR tool is in **[TODO.md](TODO.md)**. Highlights:

- **ISF symbol pack bootstrap** — automate download on first run
- **Real CTF/malware memory dump corpus** with golden-output regression
- **gRPC Velociraptor client** for binary file acquisition
- **PDF report rendering** for management hand-off
- **YARA rule validation loop** — test every generated rule against a
  goodware corpus before the analyst sees it
- **STIX 2.1 IOC export** for SIEM ingestion
- **Auth + per-user rate limiting** on the API
- **Job queue** for long-running scans
- **Container image** (Docker) for one-command deployment
- **YARAKIN integration** — combine static-binary detection with runtime detection

---

## 🛠️ Development

```bash
# Run with stub LLM + mock Velo (default for tests)
pytest

# Run with real AkashML
NEUROTRACE_FORCE_LIVE=1 python -m neurotrace.cli analyze samples/sample_cobaltstrike_dump.dmp

# Format / lint
black neurotrace/ tests/
ruff check neurotrace/ tests/
```

---

## 🔗 Related Projects

NEUROTRACE sits in the same DFIR/RE lineage as:
- **[MALAI](https://github.com/atrixi1337/MALAI)**
- **[agentic-soc](https://github.com/atrixi1337/agentic-soc)**
- **[osint-hub](https://github.com/atrixi1337/osint-hub)**
- **[YARAKIN](https://github.com/atrixi1337/yarakin)** — static-binary
  analysis with a validated YARA-rule forge loop. Pairs naturally with
  NEUROTRACE for static + dynamic analysis in one suite.

---

## License

MIT — see [LICENSE](LICENSE).
