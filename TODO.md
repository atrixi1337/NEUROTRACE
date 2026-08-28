# TODO — Road to Production

NEUROTRACE v2.0 ships a working end-to-end pipeline (Vol3 + Velociraptor +
LLM analyst + 30 passing tests + FastAPI + Rich CLI). This document lists
everything that still needs to happen before this is a tool you hand to a
real incident response team.

Organised by area. Items marked **[blocker]** must be done before NEUROTRACE
is usable on a real engagement without an experienced operator babysitting
it. Items marked **[stretch]** are nice-to-haves.

---

## 0. Immediate (this week) — **[blocker]**

- [ ] **Download the Volatility3 ISF symbol pack** so real dumps are actually parsed.
  - [ ] Add a `scripts/install_symbols.sh` that fetches
        `https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip`
        to `./symbols/` and unzips it.
  - [ ] Make the wrapper auto-discover `./symbols/` so the user doesn't
        have to set `VOLATILITY_SYMBOL_DIR` manually.
  - [ ] Add a smoke test that confirms Vol3 can parse at least one real
        Windows image end-to-end (regression test on the first real dump
        we acquire).
- [ ] **Get a real CTF/malware memory dump** and put it in `corpora/dumps/`.
  - [ ] Volatility Foundation ZeekCTF image (~150 MB) — try again once
        the symbol pack is in place.
  - [ ] Add a hand-verified "expected" JSON next to the dump and a
        golden-output regression test that compares a full engine
        run against it.
  - [ ] **Without this, every test currently runs against the 2 KB
        synthetic sample** which has no real Windows structures.
- [ ] **Add GitHub Actions CI** so PRs and merges automatically run the
      test suite on Python 3.11.
  - [ ] Add a separate "live" workflow gated by a repo secret
        (`AKASHML_API_KEY`) so the live integration test only runs
        when the secret is set.
  - [ ] Add `ruff` and `black --check` to the workflow.

---

## 1. Trust & Validation — **[blocker]**

A "real" DFIR tool cannot output findings the analyst can't reproduce
or verify. Every claim needs provenance.

- [ ] **Provenance-by-construction for the AI narrative.**
  - [ ] Make the LLM prompt require every sentence to be tagged with
        an evidence-pack field reference. The current prompt says
        "trace to evidence" but doesn't enforce it. Add a
        post-generation validator that flags any sentence not
        anchored to a Pydantic field.
  - [ ] Adopt YARAKIN's evidence-pack pattern verbatim — it's
        the same problem and they solved it well.
- [ ] **YARA rule validation loop.** A generated YARA rule is currently
      trusted because the LLM said so. It must be **compiled and
      tested**.
  - [ ] Compile every generated rule with `yarac`.
  - [ ] Run the rule against a goodware corpus (see below) and
        against the source dump. If FP > 0 or recall < 1.0, the rule
        is rejected and the LLM is asked to revise (capped at
        `FORGE_MAX_ROUNDS`).
  - [ ] Stamp the rule's header with: sample hashes, recall, FP count,
        model name, round count. This is what YARAKIN already does.
- [ ] **Goodware corpus for FP testing.**
  - [ ] Curate 200+ benign binaries from common software
        (browser installers, IDEs, utilities).
  - [ ] Document how to refresh the corpus.
  - [ ] Reuse YARAKIN's `corpora/goodware/` if it stays compatible.
- [ ] **Real malware memory dump corpus.**
  - [ ] 5–10 labeled memory dumps of known incidents (one Mimikatz,
        one Cobalt Strike, one Sliver, one Process Hollowing,
        one Benign-Windows).
  - [ ] Hand-written expected IOCs per dump.
  - [ ] CI step that runs the engine against every dump and fails
        if any IOC is missed.
- [ ] **Per-finding confidence calibration.** Currently confidence is
      a string ("CRITICAL"/"HIGH"/"MEDIUM") derived from a single
      heuristic. Add:
  - [ ] Entropy, file-pattern density, region-size → numeric score
  - [ ] Calibrate against the corpus above so "HIGH" means
        P(malicious | HIGH) ≥ 0.95.

---

## 2. Volatility3 Integration — **[blocker]**

- [ ] **Auto-detect OS profile.** The wrapper currently assumes Windows.
      Add Linux and Mac support:
  - [ ] `linux.pslist`, `linux.bash`, `linux.malfind`, `linux.lsmod`
      - [ ] `mac.pslist`, `mac.malfind`
- [ ] **Stream plugin output for very large dumps.** Current wrapper
      loads the full plugin output into a list. For a 16 GB dump with
      4,000 processes, this is fine, but for `windows.filescan` (which
      can return millions of rows) it's not. Add a row-streaming path.
- [ ] **Plugin error surface.** When a plugin fails, the report gets
      a string in `plugins_failed`. The operator needs more: stack
      trace, the partial output, and a retry-with-different-renderer
      path. Add structured plugin error records.
- [ ] **Symbol-table diagnostics.** If Vol3 falls back to mock because
      of missing symbols, the report should tell the user *which*
      profile was needed and *where* to put the ISF file. Currently
      it just says "install ISF symbols".
- [ ] **Volatility2 compatibility.** Some shops still run Vol2. Decide
      whether to support it; if yes, add a parallel `vol2` wrapper.

---

## 3. Velociraptor Integration — **[blocker]**

- [ ] **gRPC client for binary file acquisition.** The HTTP notebook
      API does not support downloading the output of
      `Windows.Memory.Acquisition`. We need the gRPC API.
  - [ ] Use the official `velociraptor` Python package if available;
        otherwise generate gRPC stubs from Velociraptor's `.proto`
        files.
  - [ ] Stream the dump to disk in 64 MB chunks so we don't hold
        a 16 GB acquisition in RAM.
- [ ] **Hunt subscription.** Subscribe to a hunt's event stream
      (`WatchEvent`) so NEUROTRACE can run a hunt and react to
      completion in real time, rather than polling.
- [ ] **Multi-client campaigns.** Run a hunt once, correlate the
      results across clients, surface "this beacon was on 4 hosts
      in the last 6 hours" as a single finding.
- [ ] **Authorization scope.** The current code uses an admin
      `X-Velo-Api-Key`. Most SOCs will hand out a read-only token
      with specific ACLs. Document the required Velociraptor
      permissions.

---

## 4. LLM Analyst — **[blocker]**

- [ ] **Streaming narrative.** A 16 GB dump analysis should not
      produce a single 800-token "story". Generate in passes:
      - [ ] Per-injection micro-narrative (one paragraph)
      - [ ] Per-process storyline
      - [ ] Cross-process attack chain
      - [ ] Executive summary (CISO audience)
- [ ] **STIX 2.1 ATT&CK output.** Build a `attck_mapper.py` shared
      module that takes NEUROTRACE findings and emits STIX 2.1
      bundles with proper technique IDs
      (`T1055.012`, `T1071.001`, etc.). SIEMs ingest STIX directly.
- [ ] **Token accounting.** The current run uses ~2k tokens of
      evidence + ~1k of completion. For large dumps, the evidence
      pack will exceed context. Add:
  - [ ] An evidence summariser that compresses the pack to fit
  - [ ] Per-section LLM calls instead of one big one
- [ ] **Prompt-injection guard.** The user-uploaded dump may contain
      bytes that look like system prompts ("ignore previous
      instructions..."). Sanitise the evidence pack before
      sending it to the LLM.
- [ ] **Cost + rate limits.** Track per-provider costs and
      enforce a per-job maximum. AkashML's pricing is per-token;
      OpenAI is per-token; Ollama is free. Surface the cost in
      the report footer.
- [ ] **Multi-model consensus.** For high-confidence claims, query
      two providers and only keep findings both agree on. Slower
      but more defensible.

---

## 5. Analyzers

- [ ] **The custom `entropy_vad` walker is now redundant.** Vol3
      does the same job better. Decide:
  - [ ] Delete it and rely on Vol3 (recommended)
  - [ ] Keep it as a tie-breaker for the case where Vol3 says
        "ambiguous" — currently it does
- [ ] **The custom `injection_hunter` does Capstone disassembly.**
      Vol3's `malfind` does the same and is more reliable. Same
      decision as above.
- [ ] **Add a credential dump detector beyond string-matching.**
      Use YARA rules for `mimikatz`, `lazagne`, `nanodump`,
      `pypykatz` signatures. Download the community YARA pack.
- [ ] **Sliver / Havoc / Brute Ratel parsers.** Currently only
      Cobalt Strike is well-supported. Add real protobuf decoders
      for Sliver (the `implant.proto` schema is public) and a
      string-pattern-based detector for Havoc's XOR'd config.

---

## 6. Operational Hardening

- [ ] **Streaming upload with size cap.** Already done for `/api/scan`,
      but the cap is 8 GB. Make it configurable via
      `NEUROTRACE_MAX_UPLOAD_BYTES`.
- [ ] **Job queue + cancellation.** Long scans (multi-GB dumps
      with full LLM narrative) can take minutes. Add:
  - [ ] Celery / RQ / Dramatiq worker
  - [ ] SQLite job table
  - [ ] Status endpoint
  - [ ] Cancel endpoint
- [ ] **Auth on `/api/scan` and other write endpoints.** The
      `X-NT-Key` is a single shared secret. Replace with:
  - [ ] Per-user API keys
  - [ ] Per-key rate limits
  - [ ] Audit log of every analysis
- [ ] **TLS termination guide.** Document the reverse-proxy
      setup (nginx, Caddy, Traefik) for production deploys.
- [ ] **Multi-tenant isolation.** A SOC will run many analyses
      in parallel. Ensure uploads, reports, and Velociraptor
      results are isolated per-user.

---

## 7. Reporting & UX

- [ ] **PDF report.** Markdown dossier rendered to a styled PDF.
      YARAKIN already does this; copy the pattern.
- [ ] **HTML report in the dashboard.** The current dashboard
      uploads + shows results inline. Add a "history" tab that
      lists past analyses.
- [ ] **Diff view between two scans of the same host.** A
      "the host looked fine yesterday and looks bad today" view.
      More useful than either report alone.
- [ ] **Quick mode vs deep mode.**
  - [ ] `--quick` — only `malfind` + C2 beacon parser (~30 sec)
  - [ ] `--deep` — full VAD walk + credentials + AI narrative (minutes)
- [ ] **Triage mode.** Skip the LLM call entirely. Just Vol3 +
      regex analyzers. Output is JSON the SIEM can ingest.
- [ ] **Diff IOCs.** On a re-scan, show what changed (new
      processes, new network connections, new credentials).

---

## 8. Interoperability

- [ ] **STIX 2.1 IOC export.** (See §4 above.)
- [ ] **OpenIOC 1.1 export.** Some legacy SIEMs only speak this.
- [ ] **MISP export.** Push events to a MISP server.
- [ ] **TheHive / Cortex integration.** Create cases from
      findings, run playbooks.
- [ ] **Webhook callback.** When an analysis completes, POST
      the result to a URL. YARAKIN already has this; copy the
      pattern (including the wait-mode polling fallback).
- [ ] **MCP server.** YARAKIN already has one. Mirror it for
      NEUROTRACE so MCP clients (Claude Desktop, etc.) can
      submit dumps and fetch reports.
- [ ] **YARAKIN integration.** When NEUROTRACE sees an unknown
      in-memory binary, POST it to YARAKIN's `/api/webhook/analyze`
      for family classification + YARA rule. Two-way hook so
      YARAKIN-generated YARA rules are loaded into NEUROTRACE's
      memory scan automatically.

---

## 9. Distribution

- [x] **Docker image.** Multi-stage build (`Dockerfile`), non-root user
      (`neurotrace` uid 1000), tini entrypoint, healthcheck. 3,014 ISF
      symbol files baked in at `/opt/neurotrace/symbols/`. Image is
      `neurotrace:2.0`, 1.76 GB compressed / 3.75 GB on disk.
- [x] **docker-compose** with named volumes for `uploads/`, `reports/`,
      and a `nt-cli` sidecar for one-shot CLI runs.
- [x] **Makefile** for one-command workflows (`make build`, `make up`,
      `make test`, `make analyze FILE=…`).
- [x] **pyproject.toml** for `pip install .` to work in the build.
- [ ] **Helm chart.** For Kubernetes deployment in a SOC.
- [ ] **PyPI release.** `pip install neurotrace` should work.
- [ ] **SBOM + signature.** Sigstore-signed releases so a SOC
      can verify the bits they're running.
- [ ] **Multi-arch image** (linux/amd64 + linux/arm64) for Apple Silicon
      and Graviton.

---

## 10. Documentation

- [ ] **Architecture deep-dive.** Like YARAKIN's `doc.md`. Cover
      the evidence pack format, the LLM prompt, the Vol3 layer
      abstraction, the streaming scanner.
- [ ] **Operator guide.** "How to use NEUROTRACE on a real
      engagement" — from alert to report, with screenshots.
- [ ] **Analyst playbook.** "You saw X finding. What does that
      mean? What do you do next?" Tied to MITRE technique IDs.
- [ ] **FAQ.** Especially around the Vol3 fallback mode, the
      AkashML JSON-mode quirk, and Velociraptor ACLs.
- [ ] **Threat model.** What can a malicious dump do to
      NEUROTRACE? Document and mitigate.

---

## 11. Stretch Goals

- [ ] **Speakeasy / CAPE sidecar.** When `malfind` flags a
      process, optionally detonate the parent binary in a
      sandbox and cross-reference behaviour.
- [ ] **Packer triage.** Detect UPX, VMProtect, Themida
      signatures and (where possible) auto-unpack.
- [ ] **Firmware / IoT intake.** binwalk → extract → recurse.
- [ ] **Multi-dump timeline correlation.** If you have 3
      memory dumps from the same host taken at 10-minute
      intervals, reconstruct the cross-dump timeline.
- [ ] **Adversarial YARA reviewer.** A second LLM tries to
      break the rule before the gate does. (YARAKIN roadmap
      item — share the work.)
- [ ] **Live memory mode.** Don't dump, just attach. Requires
      a Windows VM with WinPmem / LiME.

---

## 12. Maintenance

- [ ] **Dependabot.** Auto-PR for Vol3, FastAPI, openai, etc.
- [ ] **Vol3 compatibility tracker.** When Vol3 ships a new
      plugin, add it to the wrapper.
- [ ] **LLM provider test matrix.** Run `pytest -k llm` against
      every supported provider weekly so drift is caught early.
- [ ] **YARAKIN alignment.** When the YARAKIN roadmap items
      (adversarial reviewer, MCP, n8n webhook) land, mirror
      them here. The two tools should evolve together.

## §0 update — partial completion

### ✅ Done in this round
- [x] Real CTF memory image: MemLabs Lab 0 (Win7 SP1 x64, 702 MB) at
      `corpora/dumps/Challenge_Win7SP1x64.raw`. Not committed (gitignored).
- [x] ISF symbol pack: 1,725 unique Windows ISFs (451 MB) at `symbols/`,
      auto-discovered by the engine. The matching build's ISF
      (6.1.7601.17514) is generated on the fly by `fetch.sh` from
      Microsoft's symbol server.
- [x] `corpora/dumps/fetch.sh`: one-command fetcher. `bash
      corpora/dumps/fetch.sh` populates the image and the ISF in a
      fresh clone.
- [x] `corpora/dumps/expected.json`: ground-truth IOCs based on the
      MemLabs walkthrough.
- [x] `tests/test_real_corpus.py`: 7 tests. 4 pass, 1 xfail, 2 fail.
- [x] Engine runs end-to-end against the real image (the wrapper
      currently falls back to mock because the vol3 wrapper uses an
      obsolete API — see blocker below).

### 🚨 Blocker (must fix before "real" tests are meaningful)
- [ ] **Volatility3 wrapper is using an obsolete API** (`framework.import_plugins`
      which doesn't exist in vol3 2.28). The current wrapper silently
      returns mock data on every call. Either:
    - [ ] Rewrite to use `volatility3.framework.plugins.construct_plugin`
          + the modern `automagic` flow, OR
    - [ ] Switch the wrapper to invoke the `vol` CLI as a subprocess
          and parse its JSON output (smaller change, what most vol3
          community tools do).
- [ ] Symbol-cache build is slow (~20 min for 1,725 ISFs) and the
      cache gets nuked by `--clear-cache`. Consider keeping only the
      ISFs we actually need (just the ntkrnlmp.pdb/ directory, and
      maybe ntkrnlpa.pdb/ + ntkrpamp.pdb/ for variant coverage) instead
      of the full 3,014-file pack.

### Note on symbol sourcing
The official Volatility Foundation ISF pack
(`downloads.volatilityfoundation.org/volatility3/symbols/windows.zip`)
only covers Windows XP and Server 2003. Modern builds (Vista/7/8/10/11)
must be generated per-build by downloading the matching kernel PDB
from `msdl.microsoft.com` and converting it to ISF. We use
`ChickenLoner/vol3-symbol-generator` to automate this.
