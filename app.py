"""NEUROTRACE — FastAPI web server.

Live, job-based dashboard:
  POST /api/scan                 — upload + start background scan (returns job_id)
  GET  /api/jobs                 — list jobs
  GET  /api/jobs/{job_id}        — job status + live logs + result/error
  GET  /api/reports              — past report history
  GET  /api/reports/{analysis_id}
  POST /api/velociraptor/analyze
  GET  /api/health
  GET  /                         — dashboard
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

# Path setup so the package works both via `python app.py` and `uvicorn app:app`.
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from neurotrace.config import REPORTS_DIR, UPLOAD_DIR
from neurotrace.core.archives import PasswordRequiredError, archive_is_encrypted, is_archive
from neurotrace.core.engine import NeurotraceEngine
from neurotrace.core.jobs import STORE, JobLogHandler, JobStatus, ScanJob
from neurotrace.llm import LLMError, get_provider

logging.basicConfig(level=os.getenv("NEUROTRACE_LOG_LEVEL", "INFO"))
logger = logging.getLogger("neurotrace.web")

app = FastAPI(
    title="NEUROTRACE — AI Memory Forensics & Incident Response",
    description="Volatile Memory Analysis, Fileless Malware Hunter & C2 Extractor",
    version="2.1.0",
)

API_KEY = os.getenv("NEUROTRACE_API_KEY", "").strip() or None


def _check_auth(request: Request) -> None:
    if not API_KEY:
        return
    provided = request.headers.get("X-NT-Key", "")
    if provided != API_KEY:
        raise HTTPException(status_code=401, detail="invalid or missing X-NT-Key")


app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="static")

try:
    engine = NeurotraceEngine()
    logger.info(
        "NEUROTRACE engine ready (vol3=%s, velo=%s, llm=%s)",
        type(engine.vol3).__name__,
        type(engine.velo).__name__,
        type(engine.ai._provider).__name__ if engine.ai._provider else "fallback",
    )
except Exception as exc:  # noqa: BLE001
    logger.exception("Failed to build engine: %s", exc)
    engine = None


# ============================================================ helpers
def _safe_name(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)[:128]


async def _save_upload(file: UploadFile, dest: Path, max_bytes: int) -> int:
    written = 0
    with dest.open("wb") as buffer:
        while True:
            chunk = await file.read(8 * 1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > max_bytes:
                buffer.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail=f"file exceeds {max_bytes} bytes")
            buffer.write(chunk)
    return written


async def _run_scan_job(
    job: ScanJob,
    file_path: Path,
    password: Optional[str] = None,
    profile: str = "normal",
) -> None:
    """Background task: extract → Vol3 → AI → report. Never raises to caller."""
    handler = JobLogHandler(job)
    handler.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    job.status = JobStatus.RUNNING
    job.started_at = time.time()
    job.stage = "starting"
    job.file_path = str(file_path)
    job.log(f"scan started for {job.filename} (profile={profile})")

    # Hard ceiling so the UI never waits forever. Scale with file size.
    try:
        size = file_path.stat().st_size
    except OSError:
        size = 0
    max_seconds = float(os.getenv("NEUROTRACE_SCAN_TIMEOUT", "0") or 0)
    if max_seconds <= 0:
        # ~1s per MB, floor 90s, ceiling 45 min
        max_seconds = min(2700, max(90.0, size / (1024 * 1024) + 60))

    try:
        if engine is None:
            raise RuntimeError("engine unavailable")

        job.stage = "intake"
        job.log(f"file on disk: {file_path} ({size} bytes)")

        if is_archive(file_path):
            job.stage = "extracting archive"
            job.log(f"archive detected ({file_path.suffix}) — extracting before Vol3")
            if password:
                job.log("archive password provided")
            elif archive_is_encrypted(file_path):
                job.log("archive appears encrypted and no password was supplied")
        else:
            job.log("raw image — no extraction needed")

        job.stage = "volatility3"
        job.log(f"running Volatility3 plugin suite (timeout budget {int(max_seconds)}s)")

        report = await asyncio.wait_for(
            engine.analyze_memory_file(
                file_path,
                sample_name=job.filename,
                password=password,
                profile=profile,
            ),
            timeout=max_seconds,
        )

        job.stage = "finalizing"
        job.analysis_id = report.analysis_id
        job.result = report.model_dump()
        job.status = JobStatus.COMPLETED
        job.finished_at = time.time()
        job.stage = "done"
        mode = getattr(report, "vol3_mode", "?")
        job.log(
            f"done: {report.analysis_id} mode={mode} "
            f"processes={report.total_processes} "
            f"injections={len(report.injections)} "
            f"threat={report.overall_threat_level}/{report.threat_score}"
        )

        # Post-process: YARA gate, optional OSINT, webhook.
        try:
            await _post_process_report(job, report.model_dump())
        except Exception as exc:  # noqa: BLE001
            job.log(f"post-process warning: {exc}")
    except PasswordRequiredError as exc:
        # Not a hard failure — pause and wait for the operator.
        job.status = JobStatus.NEEDS_PASSWORD
        job.finished_at = None
        job.stage = "needs_password"
        job.error = str(exc)
        job.log(f"PASSWORD REQUIRED: {exc}")
        job.log("Submit the archive password to continue this scan (file is still on disk).")
    except asyncio.CancelledError:
        job.status = JobStatus.CANCELLED
        job.finished_at = time.time()
        job.stage = "cancelled"
        job.error = "cancelled by operator"
        job.log("scan cancelled")
    except asyncio.TimeoutError:
        job.status = JobStatus.FAILED
        job.finished_at = time.time()
        job.stage = "error"
        job.error = (
            f"Scan timed out after {int(max_seconds)}s. "
            "The dump may be too large, symbols may be missing, or Vol3 is stuck."
        )
        job.log(f"ERROR: {job.error}")
        logger.error("scan job %s timed out", job.job_id)
    except Exception as exc:  # noqa: BLE001
        job.status = JobStatus.FAILED
        job.finished_at = time.time()
        job.stage = "error"
        job.error = f"{type(exc).__name__}: {exc}"
        job.log(f"ERROR: {job.error}")
        logger.exception("scan job %s failed", job.job_id)
    finally:
        root.removeHandler(handler)


def _persist_report_patch(analysis_id: str, report: Dict[str, Any]) -> None:
    try:
        for p in REPORTS_DIR.glob(f"{analysis_id}*.json"):
            p.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
            return
    except Exception as exc:  # noqa: BLE001
        logger.warning("failed to patch report %s: %s", analysis_id, exc)


async def _post_process_report(job: ScanJob, report: Dict[str, Any]) -> None:
    """YARA gate + optional auto-OSINT + webhook. Best-effort."""
    from neurotrace.forge.yara_gate import validate_yara
    from neurotrace.intel.iocs import extract_iocs
    from neurotrace.intel.osint import enrich_iocs

    yara = report.get("generated_yara_rule") or ""
    if yara:
        gate = validate_yara(yara)
        report["yara_gate"] = gate
        job.log(
            f"yara gate: passed={gate.get('passed')} score={gate.get('score')} "
            f"compiler={gate.get('compiler')}"
            + (f" errors={gate.get('errors')}" if gate.get("errors") else "")
        )
        _persist_report_patch(report.get("analysis_id") or "", report)

    # Auto OSINT — default on; set NEUROTRACE_AUTO_OSINT=0 to disable
    if os.getenv("NEUROTRACE_AUTO_OSINT", "1").lower() not in ("0", "false", "no"):
        job.stage = "osint"
        job.log("auto-OSINT enrichment starting")
        iocs = extract_iocs(report)
        intel = await enrich_iocs(iocs)
        report["iocs"] = iocs
        report["osint"] = intel
        job.result = report
        counts = {k: len(v) for k, v in iocs.items()}
        job.log(
            f"osint done: iocs={counts} providers={intel.get('providers')}"
        )
        _persist_report_patch(report.get("analysis_id") or "", report)

    # Webhook on complete
    hook = (os.getenv("NEUROTRACE_WEBHOOK_URL") or "").strip()
    if hook:
        job.stage = "webhook"
        job.log(f"POST webhook {hook}")
        try:
            import httpx
            async with httpx.AsyncClient(timeout=20) as c:
                r = await c.post(hook, json={
                    "event": "scan.completed",
                    "analysis_id": report.get("analysis_id"),
                    "job_id": job.job_id,
                    "target": report.get("target_name"),
                    "threat_level": report.get("overall_threat_level"),
                    "threat_score": report.get("threat_score"),
                    "iocs": report.get("iocs"),
                    "report": report,
                })
                job.log(f"webhook HTTP {r.status_code}")
        except Exception as exc:  # noqa: BLE001
            job.log(f"webhook failed: {exc}")

    # Webhook
    hook = os.getenv("NEUROTRACE_WEBHOOK_URL", "").strip()
    if hook:
        job.log(f"firing webhook {hook[:60]}…")
        try:
            import httpx
            async with httpx.AsyncClient(timeout=15.0) as client:
                await client.post(hook, json={
                    "event": "scan.completed",
                    "analysis_id": report.get("analysis_id"),
                    "target": report.get("target_name"),
                    "threat_level": report.get("overall_threat_level"),
                    "threat_score": report.get("threat_score"),
                    "vol3_mode": report.get("vol3_mode"),
                    "report": report,
                })
            job.log("webhook delivered")
        except Exception as exc:  # noqa: BLE001
            job.log(f"webhook failed: {exc}")


# ============================================================ routes
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"request": request})


@app.get("/api/health")
async def health_check():
    info: Dict[str, Any] = {
        "status": "operational",
        "engine": "NEUROTRACE AI Forensics v2.1.0",
        "jobs_active": sum(
            1 for j in STORE.list() if j.status in (JobStatus.QUEUED, JobStatus.RUNNING)
        ),
    }
    if engine is not None:
        info["vol3_mode"] = engine.vol3.__class__.__name__
        info["velo_backend"] = type(engine.velo).__name__
        if engine.ai._provider is not None:
            info["llm"] = {
                "provider": engine.ai._provider.name,
                "model": engine.ai._provider.default_model,
                "live": engine.ai.is_live,
            }
        else:
            info["llm"] = {"provider": "fallback", "live": False}
    return info


@app.post("/api/scan")
async def scan_memory_dump(
    request: Request,
    file: UploadFile = File(...),
    password: Optional[str] = Form(default=None),
    profile: Optional[str] = Form(default="normal"),
):
    """Upload a dump/archive and start a background scan. Returns job_id immediately.

    ``profile``: quick | normal | malware | network | deep
    Optional ``password`` decrypts password-protected .zip/.7z archives.
    """
    _check_auth(request)
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file selected.")
    if engine is None:
        raise HTTPException(status_code=503, detail="engine unavailable")

    MAX_UPLOAD = int(os.getenv("NEUROTRACE_MAX_UPLOAD_BYTES", 8 * 1024 ** 3))
    safe = _safe_name(file.filename)
    file_path = UPLOAD_DIR / f"{int(time.time())}-{safe}"
    pwd = password.strip() if password and password.strip() else None
    prof = (profile or "normal").strip().lower() or "normal"
    from neurotrace.volatility.wrapper import SCAN_PROFILES
    if prof not in SCAN_PROFILES:
        raise HTTPException(status_code=400, detail=f"unknown profile {prof!r}")

    job = STORE.create(filename=file.filename)
    try:
        written = await _save_upload(file, file_path, MAX_UPLOAD)
    except HTTPException as exc:
        job.status = JobStatus.FAILED
        job.error = str(exc.detail)
        job.finished_at = time.time()
        job.log(f"upload failed: {exc.detail}")
        raise
    job.file_path = str(file_path)
    job.log(f"uploaded {written} bytes → {file_path.name}")
    job.log(f"scan profile: {prof}")
    if pwd:
        job.log("archive password supplied with upload")

    task = asyncio.create_task(
        _run_scan_job(job, file_path, password=pwd, profile=prof)
    )
    job._task = task
    return JSONResponse(status_code=202, content={"job_id": job.job_id, "status": job.status.value, "profile": prof})


@app.get("/api/profiles")
async def list_profiles(request: Request):
    _check_auth(request)
    from neurotrace.volatility.wrapper import SCAN_PROFILES
    return {
        "default": "normal",
        "profiles": {k: {"plugins": v, "count": len(v)} for k, v in SCAN_PROFILES.items()},
        "parallel": int(os.getenv("NEUROTRACE_VOL_PARALLEL", "2") or 2),
    }


class PasswordBody(BaseModel):
    password: str


@app.post("/api/jobs/{job_id}/password")
async def submit_job_password(request: Request, job_id: str, body: PasswordBody):
    """Continue a paused ``needs_password`` job with the archive password."""
    _check_auth(request)
    job = STORE.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"unknown job {job_id}")
    if job.status != JobStatus.NEEDS_PASSWORD:
        raise HTTPException(
            status_code=409,
            detail=f"job {job_id} is {job.status.value}, not waiting for a password",
        )
    if not job.file_path or not Path(job.file_path).exists():
        raise HTTPException(status_code=410, detail="uploaded file is no longer on disk")

    pwd = body.password
    if not pwd:
        raise HTTPException(status_code=400, detail="password is empty")

    job.log("retrying scan with operator-supplied password")
    job.error = None
    job.status = JobStatus.QUEUED
    job.stage = "queued"
    task = asyncio.create_task(
        _run_scan_job(job, Path(job.file_path), password=pwd)
    )
    job._task = task
    return JSONResponse(
        status_code=202,
        content={"job_id": job.job_id, "status": job.status.value},
    )


@app.get("/api/jobs")
async def list_jobs(request: Request):
    _check_auth(request)
    return {"jobs": [j.to_dict(include_result=False) for j in STORE.list()]}


@app.get("/api/jobs/{job_id}")
async def get_job(request: Request, job_id: str):
    _check_auth(request)
    job = STORE.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"unknown job {job_id}")
    return job.to_dict(include_result=True)


def _list_report_files() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    if not REPORTS_DIR.exists():
        return items
    for path in sorted(REPORTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            items.append({
                "analysis_id": path.stem,
                "filename": path.name,
                "error": "unreadable report JSON",
                "mtime": path.stat().st_mtime,
            })
            continue
        items.append({
            "analysis_id": data.get("analysis_id", path.stem),
            "filename": path.name,
            "target_name": data.get("target_name"),
            "timestamp": data.get("timestamp"),
            "overall_threat_level": data.get("overall_threat_level"),
            "threat_score": data.get("threat_score"),
            "total_processes": data.get("total_processes"),
            "compromised_processes": data.get("compromised_processes"),
            "injection_count": len(data.get("injections") or []),
            "beacon_count": len(data.get("beacons") or []),
            "vol3_mode": data.get("vol3_mode"),
            "elapsed_seconds": data.get("elapsed_seconds"),
            "mtime": path.stat().st_mtime,
        })
    return items


@app.get("/api/reports")
async def list_reports(request: Request):
    _check_auth(request)
    return {"reports": _list_report_files()}


@app.get("/api/reports/{analysis_id}")
async def get_report(request: Request, analysis_id: str):
    _check_auth(request)
    if not REPORTS_DIR.exists():
        raise HTTPException(status_code=404, detail="no reports directory")
    matches = list(REPORTS_DIR.glob(f"{analysis_id}*.json"))
    if not matches:
        raise HTTPException(status_code=404, detail=f"report {analysis_id} not found")
    path = matches[0]
    try:
        return JSONResponse(content=json.loads(path.read_text(encoding="utf-8")))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"failed to read report: {exc}")


@app.post("/api/velociraptor/analyze")
async def analyze_via_velociraptor(
    request: Request,
    client_id: str = Query(..., description="Velociraptor client_id (e.g. C.1234...)"),
    artifact: str = Query("Windows.Memory.Acquisition"),
):
    _check_auth(request)
    if engine is None:
        raise HTTPException(status_code=503, detail="engine unavailable")
    try:
        report = await engine.analyze_via_velociraptor(client_id, artifact=artifact)
    except Exception as exc:  # noqa: BLE001
        logger.exception("velo analyze failed")
        raise HTTPException(status_code=500, detail=f"velociraptor analyze error: {exc}")
    return JSONResponse(content=report.model_dump())


@app.get("/api/velociraptor/artifact")
async def get_artifact(
    request: Request,
    client_id: str = Query(...),
    artifact: str = Query("Generic.System.Pslist"),
):
    _check_auth(request)
    if engine is None:
        raise HTTPException(status_code=503, detail="engine unavailable")
    try:
        return JSONResponse(content=await engine.stream_velociraptor_artifact(client_id, artifact))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"velociraptor artifact error: {exc}")


@app.get("/api/llm")
async def llm_info():
    if engine is None or engine.ai._provider is None:
        return {"provider": None, "live": False, "model": None}
    p = engine.ai._provider
    return {
        "provider": p.name,
        "live": engine.ai.is_live,
        "model": p.default_model,
        "base_url": getattr(p, "base_url", None),
    }


# ============================================================ storage
def _dir_size(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for p in path.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            continue
    return total


def _active_job_paths() -> set[str]:
    """Paths that belong to queued/running jobs — never delete those."""
    active: set[str] = set()
    for j in STORE.list():
        if j.status in (JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.NEEDS_PASSWORD):
            if j.file_path:
                active.add(str(Path(j.file_path).resolve()))
                parent = Path(j.file_path).resolve().parent
                # extracted sibling dirs like uploads/xxx_extracted
                stem = Path(j.file_path).name
                # strip timestamp prefix if present
                active.add(str((parent / f"{Path(stem).stem}_extracted").resolve()))
    return active


def _storage_snapshot() -> Dict[str, Any]:
    uploads = _dir_size(UPLOAD_DIR)
    reports = _dir_size(REPORTS_DIR)
    extracted = 0
    upload_files = 0
    extract_dirs = 0
    if UPLOAD_DIR.exists():
        for p in UPLOAD_DIR.iterdir():
            if p.is_file():
                upload_files += 1
            elif p.is_dir():
                extract_dirs += 1
                extracted += _dir_size(p)
    return {
        "uploads_bytes": uploads,
        "reports_bytes": reports,
        "extracted_bytes": extracted,
        "upload_files": upload_files,
        "extract_dirs": extract_dirs,
        "reports_count": len(list(REPORTS_DIR.glob("*.json"))) if REPORTS_DIR.exists() else 0,
        "jobs_active": sum(
            1 for j in STORE.list()
            if j.status in (JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.NEEDS_PASSWORD)
        ),
    }


@app.get("/api/storage")
async def storage_info(request: Request):
    """Disk usage for uploads/extracts vs reports."""
    _check_auth(request)
    return _storage_snapshot()


class CleanupBody(BaseModel):
    confirm: bool = False
    keep_reports: bool = True


@app.post("/api/storage/cleanup")
async def storage_cleanup(request: Request, body: CleanupBody):
    """Delete uploaded archives/dumps and extracted copies. Keep History reports.

    Skips files still in use by queued/running/needs_password jobs.
    """
    _check_auth(request)
    if not body.confirm:
        raise HTTPException(
            status_code=400,
            detail="set confirm=true to delete uploads/extracts (reports are kept)",
        )

    protected = _active_job_paths()
    deleted_files: List[str] = []
    deleted_dirs: List[str] = []
    skipped: List[str] = []
    freed = 0

    if not UPLOAD_DIR.exists():
        return {"deleted_files": [], "deleted_dirs": [], "skipped": [], "freed_bytes": 0, **_storage_snapshot()}

    for p in sorted(UPLOAD_DIR.iterdir()):
        resolved = str(p.resolve())
        # Never delete anything an active job is using.
        if resolved in protected or any(resolved.startswith(pr) for pr in protected):
            skipped.append(p.name)
            continue
        try:
            if p.is_file():
                size = p.stat().st_size
                p.unlink()
                freed += size
                deleted_files.append(p.name)
            elif p.is_dir():
                size = _dir_size(p)
                import shutil as _shutil
                _shutil.rmtree(p)
                freed += size
                deleted_dirs.append(p.name)
        except OSError as exc:
            skipped.append(f"{p.name}: {exc}")

    logger.info(
        "storage cleanup: freed=%d files=%d dirs=%d skipped=%d",
        freed, len(deleted_files), len(deleted_dirs), len(skipped),
    )
    return {
        "deleted_files": deleted_files,
        "deleted_dirs": deleted_dirs,
        "skipped": skipped,
        "freed_bytes": freed,
        **_storage_snapshot(),
    }


# ============================================================ OSINT / intel
@app.get("/api/reports/{analysis_id}/iocs")
async def report_iocs(request: Request, analysis_id: str):
    """Extract IOCs from a saved report (no network)."""
    _check_auth(request)
    data = _load_report(analysis_id)
    from neurotrace.osint import extract_iocs
    return {"analysis_id": analysis_id, "iocs": extract_iocs(data)}


@app.post("/api/reports/{analysis_id}/osint")
async def report_osint(request: Request, analysis_id: str):
    """Enrich IOCs from a report via keyless/optional OSINT providers."""
    _check_auth(request)
    data = _load_report(analysis_id)
    from neurotrace.osint import enrich_iocs, extract_iocs
    iocs = extract_iocs(data)
    intel = await enrich_iocs(iocs)
    data["iocs"] = iocs
    data["osint"] = intel
    _save_report(analysis_id, data)
    return {"analysis_id": analysis_id, "iocs": iocs, "osint": intel}


@app.get("/api/correlate")
async def correlate(request: Request):
    """Campaign view: IOCs shared across History reports."""
    _check_auth(request)
    from neurotrace.correlate import build_campaign_index
    return build_campaign_index()


@app.get("/api/iocs/search")
async def search_iocs_api(request: Request, q: str = Query(..., min_length=1)):
    """Find every report that mentioned an IOC."""
    _check_auth(request)
    from neurotrace.correlate import search_iocs
    return search_iocs(q)


@app.get("/api/reports/{analysis_id}/export/stix")
async def export_stix(request: Request, analysis_id: str):
    _check_auth(request)
    data = _load_report(analysis_id)
    from neurotrace.export import report_to_stix
    return JSONResponse(content=report_to_stix(data))


class AskBody(BaseModel):
    question: str


@app.post("/api/reports/{analysis_id}/ask")
async def ask_case(request: Request, analysis_id: str, body: AskBody):
    """Chat with a case: LLM answers grounded in the report evidence."""
    _check_auth(request)
    if not body.question.strip():
        raise HTTPException(status_code=400, detail="question is empty")
    data = _load_report(analysis_id)
    if engine is None or engine.ai is None:
        raise HTTPException(status_code=503, detail="AI analyst unavailable")

    from neurotrace.llm import LLMRequest
    from neurotrace.osint import extract_iocs

    iocs = extract_iocs(data)
    context = {
        "analysis_id": data.get("analysis_id"),
        "target": data.get("target_name"),
        "threat_level": data.get("overall_threat_level"),
        "threat_score": data.get("threat_score"),
        "vol3_mode": data.get("vol3_mode"),
        "processes_total": data.get("total_processes"),
        "compromised": data.get("compromised_processes"),
        "injections": (data.get("injections") or [])[:12],
        "beacons": (data.get("beacons") or [])[:8],
        "findings": (data.get("findings") or [])[:12],
        "mitre": data.get("mitre_techniques"),
        "iocs": {k: [i["value"] for i in (v or [])[:12]] for k, v in iocs.items()},
        "narrative": (data.get("ai_storyline") or "")[:2500],
        "coverage_notes": (data.get("coverage_notes") or [])[:12],
    }
    system = (
        "You are NEUROTRACE, a DFIR memory-forensics assistant. "
        "Answer ONLY from the provided case JSON. "
        "If the case does not contain the answer, say so. "
        "Be concise and technical. Cite PIDs / IPs when relevant."
    )
    user = (
        f"CASE DATA:\n{json.dumps(context, indent=2, default=str)}\n\n"
        f"QUESTION: {body.question.strip()}"
    )
    provider = engine.ai._provider
    resp = await provider.chat(LLMRequest(
        system=system,
        user=user,
        temperature=0.2,
        max_tokens=1200,
        json_mode=False,
    ))
    return {
        "analysis_id": analysis_id,
        "question": body.question,
        "answer": resp.text or "",
        "model": getattr(provider, "default_model", None),
    }


def _load_report(analysis_id: str) -> Dict[str, Any]:
    if not REPORTS_DIR.exists():
        raise HTTPException(status_code=404, detail="no reports")
    matches = list(REPORTS_DIR.glob(f"{analysis_id}*.json"))
    if not matches:
        raise HTTPException(status_code=404, detail=f"report {analysis_id} not found")
    try:
        return json.loads(matches[0].read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"unreadable report: {exc}")


def _save_report(analysis_id: str, data: Dict[str, Any]) -> None:
    matches = list(REPORTS_DIR.glob(f"{analysis_id}*.json")) if REPORTS_DIR.exists() else []
    if matches:
        matches[0].write_text(json.dumps(data, indent=2), encoding="utf-8")


# ============================================================ intel / ops API
@app.post("/api/jobs/{job_id}/cancel")
async def cancel_job(request: Request, job_id: str):
    _check_auth(request)
    job = STORE.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"unknown job {job_id}")
    if not job.cancel():
        raise HTTPException(status_code=409, detail=f"job is {job.status.value}, cannot cancel")
    return {"job_id": job_id, "status": job.status.value}


def _load_report_dict(analysis_id: str) -> Dict[str, Any]:
    matches = list(REPORTS_DIR.glob(f"{analysis_id}*.json")) if REPORTS_DIR.exists() else []
    if not matches:
        raise HTTPException(status_code=404, detail=f"report {analysis_id} not found")
    return json.loads(matches[0].read_text(encoding="utf-8"))


@app.get("/api/reports/{analysis_id}/iocs")
async def report_iocs(request: Request, analysis_id: str):
    _check_auth(request)
    from neurotrace.intel.iocs import extract_iocs
    report = _load_report_dict(analysis_id)
    return {"analysis_id": analysis_id, "iocs": extract_iocs(report)}


@app.post("/api/reports/{analysis_id}/enrich")
async def report_enrich(request: Request, analysis_id: str):
    """Run OSINT enrichment on a stored report and persist the result."""
    _check_auth(request)
    from neurotrace.intel.iocs import extract_iocs
    from neurotrace.intel.osint import enrich_iocs
    report = _load_report_dict(analysis_id)
    iocs = extract_iocs(report)
    intel = await enrich_iocs(iocs)
    report["iocs"] = iocs
    report["osint"] = intel
    _persist_report_patch(analysis_id, report)
    return {"analysis_id": analysis_id, "iocs": iocs, "osint": intel}


@app.post("/api/reports/{analysis_id}/yara-validate")
async def report_yara_validate(request: Request, analysis_id: str):
    _check_auth(request)
    from neurotrace.forge.yara_gate import validate_yara
    report = _load_report_dict(analysis_id)
    gate = validate_yara(report.get("generated_yara_rule") or "")
    report["yara_gate"] = gate
    _persist_report_patch(analysis_id, report)
    return gate


@app.get("/api/reports/{analysis_id}/stix")
async def report_stix(request: Request, analysis_id: str):
    _check_auth(request)
    from neurotrace.export.stix import report_to_stix
    report = _load_report_dict(analysis_id)
    return JSONResponse(content=report_to_stix(report))


@app.get("/api/campaign")
async def campaign_view(request: Request, min_shared: int = Query(1)):
    """Shared-IOC campaign clusters across History."""
    _check_auth(request)
    from neurotrace.intel.correlate import build_campaigns
    return build_campaigns(REPORTS_DIR, min_shared=min_shared)


@app.get("/api/hunt")
async def hunt_ioc(request: Request, q: str = Query(..., min_length=2)):
    """Find reports that mention an IOC (IP/domain/hash)."""
    _check_auth(request)
    from neurotrace.intel.correlate import hunt_ioc_across_history
    return hunt_ioc_across_history(REPORTS_DIR, q)


class ChatBody(BaseModel):
    analysis_id: str
    message: str


@app.post("/api/chat")
async def chat_about_case(request: Request, body: ChatBody):
    """Ask the LLM about a specific case (uses live provider or stub)."""
    _check_auth(request)
    if engine is None or engine.ai._provider is None:
        raise HTTPException(status_code=503, detail="LLM provider unavailable")
    report = _load_report_dict(body.analysis_id)
    from neurotrace.llm import LLMRequest

    # Compact context so free models don't blow up
    context = {
        "analysis_id": report.get("analysis_id"),
        "target": report.get("target_name"),
        "threat_level": report.get("overall_threat_level"),
        "threat_score": report.get("threat_score"),
        "processes_total": report.get("total_processes"),
        "compromised": report.get("compromised_processes"),
        "injection_count": len(report.get("injections") or []),
        "beacons": report.get("beacons"),
        "iocs": report.get("iocs"),
        "osint_summary": [
            {"ioc": e.get("ioc"), "score": e.get("score"), "summary": e.get("summary")}
            for e in (report.get("osint") or {}).get("enriched") or []
        ][:12],
        "yara_gate": report.get("yara_gate"),
        "mitre": report.get("mitre_techniques"),
        "ai_storyline": (report.get("ai_storyline") or "")[:1500],
        "notable_processes": [
            {k: p.get(k) for k in ("pid", "name", "command_line", "is_compromised")}
            for p in (report.get("processes") or [])[:40]
        ],
    }
    system = (
        "You are NEUROTRACE AI, a DFIR co-pilot. Answer the analyst's question "
        "about THIS memory-forensics case only. Be concise, cite PIDs/IPs from "
        "the context, and say when you don't know. Plain text, no markdown fences."
    )
    user = f"CASE CONTEXT:\n{json.dumps(context, default=str)[:8000]}\n\nQUESTION: {body.message}"
    try:
        resp = await engine.ai._provider.chat(LLMRequest(
            system=system,
            user=user,
            temperature=0.2,
            max_tokens=800,
            json_mode=False,
        ))
        answer = (resp.text or "").strip()
        # Strip accidental thinking preambles for free models
        if "thinking" in answer[:80].lower() and "}" in answer:
            pass
        return {
            "analysis_id": body.analysis_id,
            "answer": answer,
            "model": getattr(engine.ai._provider, "default_model", None),
        }
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"LLM error: {exc}")


@app.get("/api/integrations")
async def integrations_status(request: Request):
    _check_auth(request)
    from neurotrace.intel.yarakin import yarakin_health
    return {
        "osint_hub": (os.getenv("OSINT_HUB_URL") or None),
        "webhook": (os.getenv("NEUROTRACE_WEBHOOK_URL") or None),
        "auto_osint": os.getenv("NEUROTRACE_AUTO_OSINT", "1").lower() not in ("0", "false", "no"),
        "yarakin": await yarakin_health(),
        "vt_key": bool(os.getenv("VIRUSTOTAL_API_KEY")),
        "abuseipdb_key": bool(os.getenv("ABUSEIPDB_API_KEY")),
    }


class YarakinSubmitBody(BaseModel):
    analysis_id: Optional[str] = None
    # If no file_path, operator can pass a path already on disk
    file_path: Optional[str] = None


@app.post("/api/yarakin/submit")
async def yarakin_submit(request: Request, body: YarakinSubmitBody):
    """Send a sample path to YARAKIN for family classification + YARA forge."""
    _check_auth(request)
    from neurotrace.intel.yarakin import attach_yarakin_to_report, submit_sample
    src = body.file_path
    if not src:
        raise HTTPException(status_code=400, detail="file_path is required (sample on disk)")
    path = Path(src)
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"file not found: {src}")
    try:
        result = await submit_sample(path)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"YARAKIN error: {exc}")
    if body.analysis_id:
        try:
            report = _load_report_dict(body.analysis_id)
            report = attach_yarakin_to_report(report, result)
            _persist_report_patch(body.analysis_id, report)
        except HTTPException:
            pass
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8010, reload=False)
