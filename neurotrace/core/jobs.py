"""In-process scan job store.

The web UI must never hang on a multi-minute Vol3 run. Scans are started
as background jobs; the UI polls status and streams log lines. Errors are
captured on the job instead of freezing the HTTP request.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("neurotrace.jobs")


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    NEEDS_PASSWORD = "needs_password"
    CANCELLED = "cancelled"


@dataclass
class ScanJob:
    job_id: str
    filename: str
    status: JobStatus = JobStatus.QUEUED
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    stage: str = "queued"
    logs: List[str] = field(default_factory=list)
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    analysis_id: Optional[str] = None
    file_path: Optional[str] = None
    _task: Optional[asyncio.Task] = field(default=None, repr=False)

    def log(self, line: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        entry = f"[{stamp}] {line}"
        self.logs.append(entry)
        # Cap memory: keep last 500 lines.
        if len(self.logs) > 500:
            self.logs = self.logs[-500:]
        # Do NOT emit through the root logger while a JobLogHandler is
        # attached — that re-enters the handler and floods the buffer.

    def to_dict(self, include_result: bool = True) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "job_id": self.job_id,
            "filename": self.filename,
            "status": self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_seconds": (
                round((self.finished_at or time.time()) - (self.started_at or self.created_at), 2)
            ),
            "stage": self.stage,
            "logs": self.logs[-100:],  # last 100 for the terminal view
            "log_count": len(self.logs),
            "error": self.error,
            "analysis_id": self.analysis_id,
            "needs_password": self.status == JobStatus.NEEDS_PASSWORD,
        }
        if include_result and self.result is not None:
            d["result"] = self.result
        return d

    def cancel(self) -> bool:
        if self.status not in (JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.NEEDS_PASSWORD):
            return False
        if self._task and not self._task.done():
            self._task.cancel()
        self.status = JobStatus.CANCELLED
        self.finished_at = time.time()
        self.stage = "cancelled"
        self.error = "cancelled by operator"
        self.log("CANCELLED by operator")
        return True


class JobStore:
    def __init__(self, max_jobs: int = 50):
        self._jobs: Dict[str, ScanJob] = {}
        self.max_jobs = max_jobs

    def create(self, filename: str) -> ScanJob:
        job_id = f"job-{uuid.uuid4().hex[:10]}"
        job = ScanJob(job_id=job_id, filename=filename)
        self._jobs[job_id] = job
        self._evict()
        return job

    def get(self, job_id: str) -> Optional[ScanJob]:
        return self._jobs.get(job_id)

    def list(self) -> List[ScanJob]:
        return sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)

    def _evict(self) -> None:
        if len(self._jobs) <= self.max_jobs:
            return
        # Drop oldest finished jobs first.
        finished = sorted(
            (j for j in self._jobs.values() if j.status in (JobStatus.COMPLETED, JobStatus.FAILED)),
            key=lambda j: j.finished_at or j.created_at,
        )
        while len(self._jobs) > self.max_jobs and finished:
            old = finished.pop(0)
            self._jobs.pop(old.job_id, None)


# Process-wide store.
STORE = JobStore()


class JobLogHandler(logging.Handler):
    """Forward logger records into the active scan job's log buffer.

    Ignores neurotrace.jobs records and guards re-entrancy so job.log()
    cannot loop back through the root logger.
    """

    def __init__(self, job: ScanJob):
        super().__init__(level=logging.INFO)
        self.job = job
        self._in_emit = False

    def emit(self, record: logging.LogRecord) -> None:
        if self._in_emit or record.name == "neurotrace.jobs":
            return
        self._in_emit = True
        try:
            self.job.log(f"{record.name}: {record.getMessage()}")
        except Exception:  # noqa: BLE001
            pass
        finally:
            self._in_emit = False
