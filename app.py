"""NEUROTRACE — FastAPI web server.

Three entry points:
  POST /api/scan                       — upload + analyze a memory dump
  POST /api/velociraptor/analyze       — analyze a client via Velociraptor
  GET  /api/velociraptor/artifact      — stream a Velociraptor artifact
  GET  /api/health                     — health check
  GET  /                                — dashboard
"""
from __future__ import annotations

import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Path setup so the package works both via `python app.py` and `uvicorn app:app`.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from neurotrace.config import UPLOAD_DIR
from neurotrace.core.engine import NeurotraceEngine
from neurotrace.llm import LLMError, get_provider

logging.basicConfig(level=os.getenv("NEUROTRACE_LOG_LEVEL", "INFO"))
logger = logging.getLogger("neurotrace.web")

app = FastAPI(
    title="NEUROTRACE — AI Memory Forensics & Incident Response",
    description="Volatile Memory Analysis, Fileless Malware Hunter & C2 Extractor",
    version="2.0.0",
)

# Optional API-key auth. Set NEUROTRACE_API_KEY to enable.
API_KEY = os.getenv("NEUROTRACE_API_KEY", "").strip() or None


def _check_auth(request: Request) -> None:
    if not API_KEY:
        return
    provided = request.headers.get("X-NT-Key", "")
    if provided != API_KEY:
        raise HTTPException(status_code=401, detail="invalid or missing X-NT-Key")


# Static & Templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="static")

# Build the engine once at startup
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


# ============================================================ ROUTES
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"request": request})


@app.get("/api/health")
async def health_check():
    info: Dict[str, Any] = {"status": "operational", "engine": "NEUROTRACE AI Forensics v2.0.0"}
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
async def scan_memory_dump(request: Request, file: UploadFile = File(...)):
    """Upload a memory dump and run the full forensic pipeline."""
    _check_auth(request)
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file selected.")
    if engine is None:
        raise HTTPException(status_code=503, detail="engine unavailable")

    # Bound the upload to a sane size; streaming via spooled file
    MAX_UPLOAD = int(os.getenv("NEUROTRACE_MAX_UPLOAD_BYTES", 8 * 1024 ** 3))  # 8 GB
    file_path = UPLOAD_DIR / file.filename
    written = 0
    try:
        with file_path.open("wb") as buffer:
            while True:
                chunk = await file.read(8 * 1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_UPLOAD:
                    buffer.close()
                    file_path.unlink(missing_ok=True)
                    raise HTTPException(status_code=413, detail=f"file exceeds {MAX_UPLOAD} bytes")
                buffer.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"upload failed: {exc}")

    try:
        report = await engine.analyze_memory_file(file_path, sample_name=file.filename)
    except Exception as exc:  # noqa: BLE001
        logger.exception("scan failed")
        raise HTTPException(status_code=500, detail=f"forensic triage error: {exc}")

    return JSONResponse(content=report.model_dump())


@app.post("/api/velociraptor/analyze")
async def analyze_via_velociraptor(
    request: Request,
    client_id: str = Query(..., description="Velociraptor client_id (e.g. C.1234...)"),
    artifact: str = Query("Windows.Memory.Acquisition"),
):
    """Acquire a memory dump from a Velociraptor client and analyze."""
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
    """Stream a single Velociraptor artifact's rows."""
    _check_auth(request)
    if engine is None:
        raise HTTPException(status_code=503, detail="engine unavailable")
    try:
        return JSONResponse(content=await engine.stream_velociraptor_artifact(client_id, artifact))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"velociraptor artifact error: {exc}")


@app.get("/api/llm")
async def llm_info():
    """Inspect the LLM configuration the engine is actually using."""
    if engine is None or engine.ai._provider is None:
        return {"provider": None, "live": False, "model": None}
    p = engine.ai._provider
    return {
        "provider": p.name,
        "live": engine.ai.is_live,
        "model": p.default_model,
        "base_url": getattr(p, "base_url", None),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8010, reload=False)
