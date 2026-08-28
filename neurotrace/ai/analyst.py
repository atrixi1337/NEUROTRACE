"""AI forensic analyst.

Provider-agnostic. Talks to whatever LLM is configured via
``neurotrace.llm.registry``. Falls back to a deterministic
rule-based synthesis when no provider is configured.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from neurotrace.llm import LLMRequest, get_provider
from neurotrace.llm.base import LLMError

logger = logging.getLogger("neurotrace.ai")


class ForensicAIAnalyst:
    """Forensic AI Co-Pilot.

    Synthesizes a memory-forensic evidence pack into:
      - a coherent attack narrative,
      - MITRE ATT&CK technique mapping,
      - an incident response checklist,
      - a targeted YARA rule.
    """

    SYSTEM_PROMPT = """You are NEUROTRACE AI, an elite DFIR memory-forensics investigator.
You receive a structured *evidence pack* of memory findings (processes, VADs, injections,
C2 configs, credentials, MITRE techniques) extracted by Volatility3 and other analyzers.

Your job: synthesize a *coherent attack narrative* and emit a JSON object with EXACTLY these keys:

{
  "attack_narrative": "Step-by-step reconstruction tied to specific PIDs, VAD regions, and beacon params",
  "primary_threat_actor_or_malware": "Family or 'Unknown'",
  "threat_level": "CRITICAL" | "HIGH" | "ELEVATED" | "LOW",
  "calculated_risk_score": <integer 0-100>,
  "key_findings": ["short finding 1", "..."],
  "mitre_techniques": ["T1055.012 Process Hollowing", "T1071.001 Web Protocols", "..."],
  "incident_response_recommendations": ["immediate action", "containment", "eradication"],
  "yara_rule": "rule NT_<short> { ... }  -- syntactically valid YARA12+"
}

Rules:
- Every claim MUST trace to a field in the evidence pack. If you cannot anchor a claim, omit it.
- Prefer specific MITRE technique IDs (T1055.012, T1071.001, T1003.001, etc.).
- The YARA rule must be compilable. Use the most distinctive strings/byte patterns from the evidence.
- Output STRICT JSON. No prose, no markdown fences.
"""

    def __init__(self, provider_name: str | None = None, model: str | None = None):
        self.provider_name = provider_name
        self.model = model
        self._provider = None
        try:
            self._provider = get_provider(provider_name, model)
            logger.info(
                "ForensicAIAnalyst using %s (%s)",
                self._provider.name, self._provider.default_model,
            )
        except LLMError as exc:
            logger.warning(
                "No LLM provider available (%s). AI analyst will use rule-based fallback.",
                exc,
            )

    @property
    def is_live(self) -> bool:
        return self._provider is not None and self._provider.name != "stub"

    async def generate_forensic_investigation(
        self, evidence_pack: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Call the configured LLM with the evidence pack.

        Returns a dict matching the schema in ``SYSTEM_PROMPT``.
        Falls back to a deterministic synthesis on any error.
        """
        if self._provider is not None:
            try:
                user = (
                    "Examine the following Memory Dump Forensic Analysis Data and emit the JSON.\n\n"
                    + json.dumps(evidence_pack, indent=2, default=str)
                )
                resp = await self._provider.chat(LLMRequest(
                    system=self.SYSTEM_PROMPT,
                    user=user,
                    model=self.model,
                    temperature=0.2,
                    max_tokens=2400,
                    json_mode=True,
                ))
                if resp.parsed:
                    return self._normalize(resp.parsed)
                logger.warning("LLM returned no parsed JSON; using fallback.")
            except Exception as exc:  # noqa: BLE001
                logger.error("AI investigation query error: %s", exc)

        return self._fallback_investigation(evidence_pack)

    # ---------------------------------------------------------------- helpers
    def _normalize(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        out = {
            "attack_narrative": str(parsed.get("attack_narrative", "")).strip(),
            "primary_threat_actor_or_malware": str(
                parsed.get("primary_threat_actor_or_malware", "Unknown")
            ).strip(),
            "threat_level": self._coerce_level(parsed.get("threat_level")),
            "calculated_risk_score": self._coerce_score(parsed.get("calculated_risk_score")),
            "key_findings": list(parsed.get("key_findings", []) or []),
            "mitre_techniques": list(parsed.get("mitre_techniques", []) or []),
            "incident_response_recommendations": list(
                parsed.get("incident_response_recommendations", []) or []
            ),
            "yara_rule": str(parsed.get("yara_rule", "")).strip(),
        }
        return out

    @staticmethod
    def _coerce_level(v: Any) -> str:
        v = str(v).upper().strip() if v else "ELEVATED"
        return v if v in {"CRITICAL", "HIGH", "ELEVATED", "LOW"} else "ELEVATED"

    @staticmethod
    def _coerce_score(v: Any) -> int:
        try:
            n = int(v)
        except (TypeError, ValueError):
            n = 0
        return max(0, min(100, n))

    def _fallback_investigation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Deterministic offline synthesis when no LLM is available."""
        injections = data.get("injections", [])
        beacons = data.get("beacons", [])
        creds = data.get("credentials", [])
        compromised = data.get("compromised_processes", 0)

        score = min(
            100,
            (len(injections) * 30) + (len(beacons) * 35) + (len(creds) * 10) + (compromised * 12),
        )
        level = "CRITICAL" if score >= 70 else "HIGH" if score >= 40 else "ELEVATED" if score >= 15 else "LOW"

        narrative_parts = [
            f"Automated forensic engine detected {len(injections)} in-memory injection(s) "
            f"across {compromised} process(es)."
        ]
        if beacons:
            b = beacons[0]
            narrative_parts.append(
                f" Active C2 beacon ({b.get('c2_framework', 'C2')}) → "
                f"{', '.join(b.get('c2_servers', []))}."
            )
        if creds:
            narrative_parts.append(f" Recovered {len(creds)} credential artifact(s).")

        return {
            "attack_narrative": "".join(narrative_parts) + " (offline rule-based synthesis)",
            "primary_threat_actor_or_malware": (
                beacons[0].get("c2_framework") if beacons else "In-Memory Implant"
            ),
            "threat_level": level,
            "calculated_risk_score": max(20, score),
            "key_findings": [
                f"{len(injections)} unbacked memory region(s) flagged",
                f"{len(beacons)} C2 channel(s) extracted",
                f"{compromised} process tree node(s) compromised",
            ],
            "mitre_techniques": [
                "T1055 Process Injection",
                "T1055.012 Process Hollowing",
                "T1071.001 Application Layer Protocol: Web Protocols",
                "T1003 OS Credential Dumping",
            ],
            "incident_response_recommendations": [
                "Isolate the host from the network immediately.",
                "Block extracted C2 indicators at the perimeter.",
                "Preserve a fresh RAM image and acquire disk for secondary review.",
                "Rotate any credentials observed in memory.",
            ],
            "yara_rule": (
                "rule NT_Generic_Implant_v1 {\n"
                "    meta:\n"
                "        description = \"Auto-generated by NEUROTRACE fallback\"\n"
                "        author = \"NEUROTRACE AI Forensics\"\n"
                "    strings:\n"
                "        $s1 = \"VirtualAllocEx\" ascii wide\n"
                "        $s2 = \"CreateRemoteThread\" ascii wide\n"
                "        $mz = { 4D 5A }\n"
                "    condition:\n"
                "        $mz at 0 and ($s1 or $s2)\n"
                "}"
            ),
        }
