"""YARA quality gate — compile + basic hygiene before we trust a rule."""
from __future__ import annotations

import logging
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("neurotrace.yara_gate")


def _extract_rule_text(yara: str) -> str:
    if not yara:
        return ""
    s = yara.strip()
    if s.startswith("```"):
        parts = s.split("```")
        if len(parts) >= 2:
            s = parts[1]
        if s.startswith("yara"):
            s = s[4:]
    return s.strip()


def _which(name: str) -> Optional[str]:
    import shutil
    return shutil.which(name)


def validate_yara(rule_text: str) -> Dict[str, Any]:
    """Compile-check a YARA rule and score basic quality."""
    text = _extract_rule_text(rule_text)
    result: Dict[str, Any] = {
        "input_len": len(rule_text or ""),
        "rule_text": text,
        "compiled": False,
        "compiler": None,
        "errors": [],
        "warnings": [],
        "score": 0,
        "passed": False,
    }
    if not text:
        result["errors"].append("empty rule")
        return result

    if not re.search(r"\brule\s+\w+", text):
        result["errors"].append("no `rule <name>` declaration found")
    if "condition:" not in text:
        result["errors"].append("missing `condition:` block")
    if "strings:" not in text and "$" not in text:
        result["warnings"].append("no strings section — rule may be too generic")

    for tool in ("yarac", "yara"):
        path = _which(tool)
        if not path:
            continue
        try:
            if tool == "yarac":
                with tempfile.TemporaryDirectory() as td:
                    src = Path(td) / "rule.yar"
                    out = Path(td) / "rule.yac"
                    src.write_text(text, encoding="utf-8")
                    proc = subprocess.run(
                        [path, str(src), str(out)],
                        capture_output=True, text=True, timeout=15,
                    )
            else:
                with tempfile.TemporaryDirectory() as td:
                    src = Path(td) / "rule.yar"
                    dummy = Path(td) / "dummy.bin"
                    src.write_text(text, encoding="utf-8")
                    dummy.write_bytes(b"MZ\x00\x00")
                    proc = subprocess.run(
                        [path, str(dummy), str(src)],
                        capture_output=True, text=True, timeout=15,
                    )
            result["compiler"] = tool
            if proc.returncode == 0:
                result["compiled"] = True
                result["compiler_output"] = (proc.stdout or "")[:500]
                break
            err = (proc.stderr or proc.stdout or "").strip()
            result["errors"].append(f"{tool}: {err[:400]}")
        except Exception as exc:  # noqa: BLE001
            result["warnings"].append(f"{tool} failed to run: {exc}")

    if result["compiler"] is None:
        result["warnings"].append("yara/yarac not installed — structural check only")
        if not result["errors"]:
            result["compiled"] = True
            result["compiler"] = "structural"

    score = 0
    if result["compiled"] and not result["errors"]:
        score += 40
    n_strings = len(re.findall(r"\$\w+\s*=", text))
    if n_strings >= 2:
        score += 20
    elif n_strings == 1:
        score += 10
    if re.search(r"filesize\s*<", text):
        score += 10
    if re.search(r"\bany of\b|\ball of\b|\bthem\b", text):
        score += 10
    if re.search(r"\bMZ\b|\{ ?4[Dd] ?5[Aa]", text):
        score += 10
    if "meta:" in text:
        score += 5
    if n_strings == 0:
        score -= 30
        result["warnings"].append("no string definitions — high FP risk")
    if re.search(r"condition:\s*true\s*$", text, re.M):
        score -= 50
        result["warnings"].append("condition: true — always fires")
    result["score"] = max(0, min(100, score))
    result["passed"] = bool(result["compiled"] and not result["errors"] and result["score"] >= 50)
    result["quality_notes"] = result["warnings"]
    return result
