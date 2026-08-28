"""Volatility3 integration package.

NEUROTRACE delegates to Volatility3 for the heavy lifting (process
enumeration, VAD walking, hollowed-process detection, beacon
extraction) and treats the result as ground truth. The custom
entropy/VAD walkers in ``neurotrace.analyzers`` are kept as a
lightweight enrichment layer for analyst triage and for cases
where Volatility3 cannot parse a dump (corrupt headers, unsupported
profile, etc.).

Two execution modes:

* **real**   — runs the actual Volatility3 plugin against the file.
* **mock**   — returns a deterministic fixture (used in tests and
  when the dump cannot be parsed).

Mode selection is automatic: if Volatility3 can be imported and the
file looks parseable, ``real`` is used. If parsing fails on the
real path, the wrapper falls back to ``mock`` and the report
records a coverage note explaining why.
"""
from __future__ import annotations

import logging

from .wrapper import VolatilityWrapper, VolatilityResult, VolatilityMode

logger = logging.getLogger("neurotrace.volatility")

__all__ = ["VolatilityWrapper", "VolatilityResult", "VolatilityMode"]
