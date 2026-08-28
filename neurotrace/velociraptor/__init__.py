"""Velociraptor integration.

NEUROTRACE can drive a Velociraptor server to:
  * trigger hunts (Generic.System.Pslist, Windows.Memory.Acquisition, etc.),
  * stream artifact results (process list, handles, netstat) directly
    into the analysis pipeline,
  * acquire a memory dump from a chosen client and feed it back into
    Volatility3.

The Velociraptor gRPC API is JSON-over-HTTP for notebook API calls and
real gRPC for everything else. We hit the JSON HTTP endpoints with
``httpx`` (no extra deps), and document the gRPC migration path in
the README for the next iteration.

The package ships with a :class:`MockVelociraptorClient` that returns
a deterministic fixture so the entire engine can be exercised without
a live server. The wrapper picks the right backend based on
``VELO_API_URL`` in config — see :func:`make_client`.
"""
from __future__ import annotations

from .client import (
    VelociraptorClient,
    VeloArtifactResult,
    VeloHunt,
    VeloHuntStatus,
    VeloClient,
)
from .factory import make_client

__all__ = [
    "VelociraptorClient",
    "VeloArtifactResult",
    "VeloHunt",
    "VeloHuntStatus",
    "VeloClient",
    "make_client",
]
