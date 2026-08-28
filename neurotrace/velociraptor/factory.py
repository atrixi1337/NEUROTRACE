"""Factory for the right Velociraptor backend.

Selection:
  * If ``VELO_API_URL`` is set and the URL is reachable → real backend.
  * Otherwise → mock backend (deterministic, in-memory).
"""
from __future__ import annotations

import logging
from typing import Union

from neurotrace.config import VELO_API_URL, VELO_API_KEY, VELO_VERIFY_TLS, VELO_MOCK

from .client import MockVelociraptorClient, RealVelociraptorClient

logger = logging.getLogger("neurotrace.velociraptor")


def make_client() -> Union[MockVelociraptorClient, RealVelociraptorClient]:
    if VELO_MOCK or not VELO_API_URL:
        logger.info("Using MOCK Velociraptor backend (no VELO_API_URL set).")
        return MockVelociraptorClient()

    if not VELO_API_KEY:
        logger.warning(
            "VELO_API_URL set but no VELO_API_KEY; falling back to mock backend."
        )
        return MockVelociraptorClient()

    logger.info("Using REAL Velociraptor backend at %s", VELO_API_URL)
    return RealVelociraptorClient(
        api_url=VELO_API_URL,
        api_key=VELO_API_KEY,
        verify_tls=VELO_VERIFY_TLS,
    )
