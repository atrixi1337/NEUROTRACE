"""NEUROTRACE runtime configuration.

Reads from .env (or process environment). All analyzers and the engine
read their tunables from this module — no scattered os.getenv calls.
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
RULES_DIR = BASE_DIR / "neurotrace" / "rules"
SAMPLES_DIR = BASE_DIR / "samples"
REPORTS_DIR = BASE_DIR / "reports"
CORPORA_DIR = BASE_DIR / "corpora"
FIXTURES_DIR = BASE_DIR / "tests" / "fixtures"
CACHE_DIR = BASE_DIR / "workspace" / "cache"

for _d in (UPLOAD_DIR, RULES_DIR, SAMPLES_DIR, REPORTS_DIR,
          CORPORA_DIR, FIXTURES_DIR, CACHE_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ---- LLM -------------------------------------------------------------------
LLM_PROVIDER = os.getenv("NEUROTRACE_LLM_PROVIDER", "").strip().lower() or None
LLM_MODEL = os.getenv("NEUROTRACE_LLM_MODEL", "openai/gpt-oss-20b").strip()

# ---- Volatility3 ------------------------------------------------------------
VOLATILITY_SYMBOL_DIR = os.getenv("VOLATILITY_SYMBOL_DIR", "").strip() or None

# ---- Velociraptor -----------------------------------------------------------
VELO_API_URL = os.getenv("VELO_API_URL", "").strip() or None
VELO_API_KEY = os.getenv("VELO_API_KEY", "").strip() or None
VELO_VERIFY_TLS = os.getenv("VELO_VERIFY_TLS", "false").lower() in ("1", "true", "yes")
VELO_CLIENT_ID = os.getenv("VELO_CLIENT_ID", "neurotrace").strip()
VELO_MOCK = not bool(VELO_API_URL)  # If no URL → use mock client

# ---- Engine tunables --------------------------------------------------------
MAX_SCAN_BYTES = int(os.getenv("MAX_SCAN_BYTES", 1024 * 1024 * 1024))  # 1 GB
RWX_PAGE_SUSPICIOUS_ENTROPY = float(os.getenv("RWX_PAGE_SUSPICIOUS_ENTROPY", "6.2"))
ENTROPY_WINDOW = int(os.getenv("ENTROPY_WINDOW", "4096"))  # bytes per entropy window
