"""Velociraptor client interfaces and the mock backend."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Protocol

logger = logging.getLogger("neurotrace.velociraptor")


class VeloHuntStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class VeloClient:
    """A Velociraptor-managed endpoint."""
    client_id: str
    hostname: str
    os_info: str
    last_seen: str


@dataclass
class VeloArtifactResult:
    """Rows of a single artifact run on a single client."""
    artifact: str
    client_id: str
    rows: List[Dict[str, Any]] = field(default_factory=list)
    completed: bool = False
    notes: List[str] = field(default_factory=list)


@dataclass
class VeloHunt:
    """A hunt is a long-running artifact collection across many clients."""
    hunt_id: str
    artifact: str
    status: VeloHuntStatus
    created_at: str
    finished_at: Optional[str] = None
    stats: Dict[str, int] = field(default_factory=dict)
    params: Dict[str, Any] = field(default_factory=dict)


class VelociraptorClient(Protocol):
    """Backend interface — both real HTTP and mock implement this."""

    async def health(self) -> Dict[str, Any]: ...
    async def list_clients(self) -> List[VeloClient]: ...
    async def collect_artifact(
        self, client_id: str, artifact: str, params: Optional[Dict[str, Any]] = None,
    ) -> VeloArtifactResult: ...
    async def acquire_memory_dump(
        self, client_id: str, dest_path: Path, artifact: str = "Windows.Memory.Acquisition",
    ) -> Path: ...
    async def run_hunt(
        self, artifact: str, params: Optional[Dict[str, Any]] = None,
    ) -> VeloHunt: ...
    async def get_hunt(self, hunt_id: str) -> VeloHunt: ...


# =============================================================== MOCK BACKEND
class MockVelociraptorClient:
    """In-memory Velociraptor mock for development and tests.

    Simulates 2-3 clients and a fixed set of artifacts. The data
    is deterministic given the seed, so golden-report tests can
    compare outputs without flakiness.
    """

    def __init__(self, seed: int = 0xC0FFEE):
        self.seed = seed
        rng = random.Random(seed)
        clients: List[VeloClient] = [
            VeloClient(
                client_id="C.0011223344556677",
                hostname="WS-FINANCE-01",
                os_info="windows",
                last_seen=datetime(2026, 8, 22, 8, 30, tzinfo=timezone.utc).isoformat(),
            ),
            VeloClient(
                client_id="C.8899aabbccddeeff",
                hostname="WS-DEV-04",
                os_info="windows",
                last_seen=datetime(2026, 8, 22, 9, 1, tzinfo=timezone.utc).isoformat(),
            ),
            VeloClient(
                client_id="C.fedcba9876543210",
                hostname="SRV-DC-01",
                os_info="windows",
                last_seen=datetime(2026, 8, 22, 7, 55, tzinfo=timezone.utc).isoformat(),
            ),
        ]
        self._clients = clients
        self._hunts: Dict[str, VeloHunt] = {}
        self._rng = rng

    async def health(self) -> Dict[str, Any]:
        return {
            "status": "ok",
            "backend": "mock",
            "version": "velociraptor-mock-1.0",
            "client_count": len(self._clients),
        }

    async def list_clients(self) -> List[VeloClient]:
        return list(self._clients)

    async def collect_artifact(
        self,
        client_id: str,
        artifact: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> VeloArtifactResult:
        if not any(c.client_id == client_id for c in self._clients):
            return VeloArtifactResult(
                artifact=artifact, client_id=client_id, completed=False,
                notes=[f"unknown client_id: {client_id}"],
            )

        # Built-in canned responses for the most useful artifacts.
        if artifact == "Generic.System.Pslist":
            return VeloArtifactResult(
                artifact=artifact, client_id=client_id, completed=True,
                rows=_mock_pslist(self._rng),
            )
        if artifact == "Windows.Network.Netstat":
            return VeloArtifactResult(
                artifact=artifact, client_id=client_id, completed=True,
                rows=_mock_netstat(),
            )
        if artifact == "Windows.System.HandleSnapshots":
            return VeloArtifactResult(
                artifact=artifact, client_id=client_id, completed=True,
                rows=_mock_handles_to_lsass(),
            )
        if artifact == "Windows.Memory.Acquisition":
            # The mock doesn't actually produce a file; callers should
            # use a real Velociraptor server for memory acquisition.
            return VeloArtifactResult(
                artifact=artifact, client_id=client_id, completed=True,
                notes=["mock backend: use a real Velociraptor for memory acquisition"],
                rows=[{"Note": "Memory acquisition requires a live server."}],
            )
        # Default empty result.
        return VeloArtifactResult(artifact=artifact, client_id=client_id, completed=True)

    async def acquire_memory_dump(
        self,
        client_id: str,
        dest_path: Path,
        artifact: str = "Windows.Memory.Acquisition",
    ) -> Path:
        # Mock writes a tiny placeholder so the rest of the pipeline can run.
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_bytes(b"\x00" * 1024)
        logger.warning(
            "MockVelociraptor wrote a 1KB placeholder to %s. "
            "Connect a real Velociraptor server for actual memory dumps.",
            dest_path,
        )
        return dest_path

    async def run_hunt(
        self, artifact: str, params: Optional[Dict[str, Any]] = None,
    ) -> VeloHunt:
        hunt_id = "H." + uuid.uuid4().hex[:16]
        now = datetime.now(timezone.utc).isoformat()
        hunt = VeloHunt(
            hunt_id=hunt_id, artifact=artifact, status=VeloHuntStatus.RUNNING,
            created_at=now, params=params or {},
        )
        self._hunts[hunt_id] = hunt
        # Simulate progress: in real life we'd poll; for tests, mark complete.
        await asyncio.sleep(0.05)
        hunt.status = VeloHuntStatus.COMPLETED
        hunt.finished_at = datetime.now(timezone.utc).isoformat()
        hunt.stats = {
            "clients_scheduled": len(self._clients),
            "clients_completed": len(self._clients),
        }
        return hunt

    async def get_hunt(self, hunt_id: str) -> VeloHunt:
        if hunt_id not in self._hunts:
            return VeloHunt(
                hunt_id=hunt_id, artifact="(unknown)", status=VeloHuntStatus.FAILED,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
        return self._hunts[hunt_id]


# --------------------------------------------------------------------- helpers
def _mock_pslist(rng: random.Random) -> List[Dict[str, Any]]:
    return [
        {"Pid": 4, "Name": "System", "CommandLine": "", "Username": "NT AUTHORITY\\SYSTEM"},
        {"Pid": 640, "Name": "smss.exe", "CommandLine": "\\SystemRoot\\System32\\smss.exe"},
        {"Pid": 990, "Name": "lsass.exe", "CommandLine": "C:\\Windows\\System32\\lsass.exe",
         "Username": "NT AUTHORITY\\SYSTEM"},
        {"Pid": 3380, "Name": "svchost.exe", "CommandLine": "svchost.exe -k netsvcs -p",
         "Username": "NT AUTHORITY\\SYSTEM"},
        {"Pid": 4892, "Name": "powershell.exe",
         "CommandLine": "powershell.exe -nop -w hidden -enc JABz...",
         "Username": "WS-FINANCE-01\\alice"},
    ]


def _mock_netstat() -> List[Dict[str, Any]]:
    return [
        {"Pid": 3380, "Status": "ESTABLISHED", "LocalAddress": "10.0.0.21:49213",
         "RemoteAddress": "185.220.101.44:443"},
        {"Pid": 4892, "Status": "ESTABLISHED", "LocalAddress": "10.0.0.21:49214",
         "RemoteAddress": "185.220.101.44:443"},
    ]


def _mock_handles_to_lsass() -> List[Dict[str, Any]]:
    return [
        {"SourcePid": 3380, "TargetPid": 990, "GrantedAccess": "0x1010",
         "HandleType": "Process", "TargetName": "lsass.exe"},
    ]


# ============================================================== REAL BACKEND
class RealVelociraptorClient:
    """HTTP/JSON client for the Velociraptor notebook API.

    Authentication uses the standard ``X-Velo-Api-Key`` header
    issued from the Velociraptor GUI (Settings → API key).
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        verify_tls: bool = True,
        client_id: str = "neurotrace",
    ):
        import httpx
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.verify_tls = verify_tls
        self.client_id = client_id
        self._http = httpx.AsyncClient(
            verify=verify_tls,
            headers={"X-Velo-Api-Key": api_key, "User-Agent": f"NEUROTRACE/1.0 ({client_id})"},
            timeout=httpx.Timeout(60.0, connect=10.0),
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def health(self) -> Dict[str, Any]:
        r = await self._http.get(f"{self.api_url}/api/v1/ping")
        r.raise_for_status()
        return r.json() if r.content else {"status": "ok"}

    async def list_clients(self) -> List[VeloClient]:
        # Notebook API: POST /api/v1/GetTable with a VQL query.
        vql = "SELECT client_id, os_info.hostname AS hostname, os_info.system AS os, last_seen_at FROM clients()"
        r = await self._http.post(
            f"{self.api_url}/api/v1/GetTable",
            json={"query": vql, "limit": 500},
        )
        r.raise_for_status()
        data = r.json()
        return [
            VeloClient(
                client_id=row.get("client_id", ""),
                hostname=row.get("hostname", ""),
                os_info=row.get("os", "unknown"),
                last_seen=str(row.get("last_seen_at", "")),
            )
            for row in data.get("response", [])
        ]

    async def collect_artifact(
        self,
        client_id: str,
        artifact: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> VeloArtifactResult:
        vql = f"SELECT * FROM artifact(artifact='{artifact}', client_id='{client_id}')"
        r = await self._http.post(
            f"{self.api_url}/api/v1/GetTable",
            json={"query": vql, "limit": 1000},
        )
        r.raise_for_status()
        data = r.json()
        return VeloArtifactResult(
            artifact=artifact, client_id=client_id,
            rows=data.get("response", []), completed=True,
        )

    async def acquire_memory_dump(
        self,
        client_id: str,
        dest_path: Path,
        artifact: str = "Windows.Memory.Acquisition",
    ) -> Path:
        # Start the artifact collection server-side, then poll for completion.
        # Full flow:
        #   1. POST /api/v1/CollectArtifact with the artifact spec
        #   2. POST /api/v1/GetTable polling the resulting flow's status
        #   3. GET the file from /api/v1/DownloadFile
        # We deliberately don't implement step 3 here — a production
        # deployment should use the gRPC API for binary downloads.
        # For the HTTP-only path, the caller is expected to manually
        # trigger the artifact in the Velociraptor GUI and point the
        # resulting file path to NEUROTRACE.
        raise NotImplementedError(
            "Memory acquisition via the notebook API requires gRPC; "
            "use the Velociraptor GUI to run Windows.Memory.Acquisition "
            "and pass the resulting file to NEUROTRACE."
        )

    async def run_hunt(
        self, artifact: str, params: Optional[Dict[str, Any]] = None,
    ) -> VeloHunt:
        # Use the CreateHunt notebook API
        body = {
            "description": f"NEUROTRACE triggered hunt for {artifact}",
            "artifacts": [artifact],
            "specs": [{"artifact": artifact, "parameters": params or {}}],
        }
        r = await self._http.post(f"{self.api_url}/api/v1/CreateHunt", json=body)
        r.raise_for_status()
        hunt_id = r.json().get("hunt_id", "")
        return VeloHunt(
            hunt_id=hunt_id, artifact=artifact,
            status=VeloHuntStatus.RUNNING,
            created_at=datetime.now(timezone.utc).isoformat(),
            params=params or {},
        )

    async def get_hunt(self, hunt_id: str) -> VeloHunt:
        vql = f"SELECT * FROM hunts(hunt_id='{hunt_id}')"
        r = await self._http.post(
            f"{self.api_url}/api/v1/GetTable",
            json={"query": vql, "limit": 1},
        )
        r.raise_for_status()
        rows = r.json().get("response", [])
        if not rows:
            return VeloHunt(
                hunt_id=hunt_id, artifact="(unknown)", status=VeloHuntStatus.FAILED,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
        row = rows[0]
        stats = {
            "total_clients_scheduled": int(row.get("total_clients_scheduled") or 0),
            "total_clients_completed": int(row.get("total_clients_completed") or 0),
        }
        return VeloHunt(
            hunt_id=hunt_id,
            artifact=row.get("artifacts", [artifact_placeholder(hunt_id)])[0]
            if row.get("artifacts") else artifact_placeholder(hunt_id),
            status=VeloHuntStatus(row.get("state", "RUNNING").lower()),
            created_at=str(row.get("create_time", "")),
            finished_at=str(row.get("finished_time", "")) or None,
            stats=stats,
        )


def artifact_placeholder(hunt_id: str) -> str:
    return f"unknown:{hunt_id}"
