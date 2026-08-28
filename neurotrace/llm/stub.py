"""Deterministic stub LLM provider for tests and offline operation.

Returns canned narratives based on the keywords in the user prompt,
so the rest of the pipeline can be exercised end-to-end without any
network call or API key.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from .base import LLMProvider, LLMRequest, LLMResponse, LLMUsage


class StubProvider(LLMProvider):
    name: str = "stub"

    def __init__(self, model: str = "stub/forensic-v1", api_key: str = "stub", **kwargs):
        # No API key required for stub. Extra kwargs are ignored for API compatibility
        # with the registry factory (which passes the same args as real providers).
        self.api_key = api_key
        self.base_url = "stub://"
        self.default_model = model

    async def chat(self, request: LLMRequest) -> LLMResponse:
        # Deterministic seed from prompt so the same dump → same narrative.
        seed = hashlib.sha256(request.user.encode("utf-8")).hexdigest()[:8]
        score = self._score_from_prompt(request.user)
        level = "CRITICAL" if score >= 70 else "HIGH" if score >= 40 else "ELEVATED" if score >= 20 else "LOW"

        if request.json_mode:
            # Try to extract PIDs from the evidence pack so the stub
            # narrative anchors to specific processes (like the real LLM
            # is asked to do).
            pids = self._extract_pids(request.user)
            injections = self._extract_injections(request.user)
            beacons = self._extract_beacons(request.user)
            parts = [
                f"[stub:{seed}] Forensic engine identified {score}-risk anomalies across "
                f"the process tree, memory regions, and credential artifacts."
            ]
            if pids:
                parts.append(
                    f" Compromised/anomalous PIDs observed: {', '.join(map(str, pids[:6]))}."
                )
            if injections:
                addrs = ", ".join(i.get("target_address", "?") for i in injections[:3] if i.get("target_address"))
                if addrs:
                    parts.append(f" In-memory implants located at: {addrs}.")
            fws: List[str] = []
            if beacons:
                fws = sorted({b.get("c2_framework", "?") for b in beacons if b.get("c2_framework")})
                if fws:
                    parts.append(f" C2 frameworks identified: {', '.join(fws)}.")

            parsed: Dict[str, Any] = {
                "attack_narrative": "".join(parts),
                "primary_threat_actor_or_malware": (
                    fws[0] if (fws and fws[0] != "?") else "Unknown (stub mode)"
                ),
                "threat_level": level,
                "calculated_risk_score": score,
                "key_findings": [
                    "Unbacked memory regions flagged by Volatility malfind (if present)",
                    "C2 indicators extracted from process heaps",
                    "Credential residue recovered from session handles",
                ],
                "mitre_techniques": [
                    "T1055 Process Injection",
                    "T1071.001 Web Protocols",
                    "T1003 OS Credential Dumping",
                ],
                "incident_response_recommendations": [
                    "Isolate the host and preserve volatile memory.",
                    "Block extracted C2 indicators at the perimeter.",
                    "Rotate credentials observed in memory.",
                ],
                "yara_rule": (
                    "rule NT_Stub_Detection_v1 {\n"
                    "  meta: author=\"NEUROTRACE stub\", model=\"stub/forensic-v1\"\n"
                    "  strings:\n"
                    "    $mz = { 4D 5A }\n"
                    "  condition:\n"
                    "    $mz at 0 and filesize < 5MB\n"
                    "}"
                ),
            }
            return LLMResponse(
                text="", parsed=parsed, model=self.default_model,
                usage=LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2),
            )

        return LLMResponse(
            text=f"[stub:{seed}] Stub analyst — no LLM configured. Score {level} ({score}/100).",
            model=self.default_model,
            usage=LLMUsage(),
        )

    @staticmethod
    def _score_from_prompt(user_prompt: str) -> int:
        # Cheap heuristic: count high-signal keywords.
        s = user_prompt.lower()
        score = 0
        for kw, w in [
            ("injection", 25),
            ("cobalt", 20),
            ("mimikatz", 25),
            ("rwx", 15),
            ("beacon", 20),
            ("c2", 15),
            ("credential", 15),
            ("api key", 10),
            ("hollow", 20),
        ]:
            if kw in s:
                score += w
        return min(score, 100)

    @staticmethod
    def _extract_pids(prompt: str) -> List[int]:
        """Pull PID numbers out of the evidence-pack text."""
        import re
        # Look for `"pid": <int>` or `"Pid": <int>` patterns.
        out: List[int] = []
        for m in re.finditer(r'"[Pp]id"\s*:\s*(\d+)', prompt):
            try:
                out.append(int(m.group(1)))
            except ValueError:
                pass
        return sorted(set(out))[:6]

    @staticmethod
    def _extract_injections(prompt: str) -> List[Dict[str, Any]]:
        """Recover a few injection dicts from the prompt's JSON blob."""
        import json
        try:
            data = json.loads(prompt[prompt.find("{"): prompt.rfind("}") + 1])
        except Exception:
            return []
        return list(data.get("injections", []) or [])[:3]

    @staticmethod
    def _extract_beacons(prompt: str) -> List[Dict[str, Any]]:
        import json
        try:
            data = json.loads(prompt[prompt.find("{"): prompt.rfind("}") + 1])
        except Exception:
            return []
        return list(data.get("beacons", []) or [])[:3]
