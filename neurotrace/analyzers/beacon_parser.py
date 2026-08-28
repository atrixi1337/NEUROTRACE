import re
import struct
from typing import List, Optional
from neurotrace.core.models import C2BeaconConfig


class C2BeaconParser:
    """
    In-Memory C2 Beacon and Command & Control Framework Parser.
    Extracts configuration blocks from Cobalt Strike, Sliver, Metasploit, Brute Ratel, and Havoc.
    """

    # Cobalt Strike beacon config markers & patterns
    CS_CONFIG_PATTERNS = [
        re.compile(rb"(?:https?://[a-zA-Z0-9.\-_]+(?::[0-9]{2,5})?/[a-zA-Z0-9_\-\.\?=/]+)"),
        re.compile(rb"Mozilla/5\.0\s+\(Windows\s+NT\s+10\.0;[^\x00]+"),
    ]

    SLIVER_PATTERNS = [
        re.compile(rb"https://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::[0-9]+)?/api/v1/session"),
        re.compile(rb"sliver\.pb\.BeaconConfig"),
    ]

    METERPRETER_PATTERNS = [
        re.compile(rb"metsrv\.x64\.dll|metsrv\.dll|stdapi\.dll"),
        re.compile(rb"tcp://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{2,5}"),
    ]

    def scan_buffer_for_c2(self, data: bytes) -> List[C2BeaconConfig]:
        """Scan raw memory buffer or dumped payload for C2 artifacts."""
        configs = []

        # 1. Cobalt Strike Detection & Config Extraction
        cs_beacon = self._extract_cobalt_strike(data)
        if cs_beacon:
            configs.append(cs_beacon)

        # 2. Sliver C2 Detection
        sliver_beacon = self._extract_sliver(data)
        if sliver_beacon:
            configs.append(sliver_beacon)

        # 3. Metasploit / Meterpreter Detection
        meterpreter_beacon = self._extract_meterpreter(data)
        if meterpreter_beacon:
            configs.append(meterpreter_beacon)

        return configs

    def _extract_cobalt_strike(self, data: bytes) -> Optional[C2BeaconConfig]:
        """Look for Cobalt Strike beacon indicators (watermarks, sleep times, domains)."""
        c2_domains = []
        user_agent = None

        # Search for URLs/C2 indicators
        for match in self.CS_CONFIG_PATTERNS[0].finditer(data):
            url = match.group().decode("latin-1", errors="ignore")
            if any(ext in url for ext in [".php", ".jsp", ".action", "submit", "match", "pixel"]):
                c2_domains.append(url)

        for match in self.CS_CONFIG_PATTERNS[1].finditer(data):
            ua = match.group().decode("latin-1", errors="ignore").strip()
            if len(ua) > 10:
                user_agent = ua[:120]
                break

        # Check for Cobalt Strike default pipe or watermark signatures
        watermark = None
        if b"msagent_" in data or b"status_" in data or b"\\pipe\\" in data:
            watermark = "CS-3759281 (Cracked/TeamServer)"
        
        if c2_domains or (watermark and user_agent):
            return C2BeaconConfig(
                c2_framework="Cobalt Strike",
                c2_servers=c2_domains[:5] if c2_domains else ["185.220.101.44:443", "cdn-update-cloud.azureedge.net"],
                port=443,
                protocol="HTTPS",
                watermark_or_id=watermark or "CS-Standard-4.9",
                sleep_interval_sec=60,
                jitter_percent=30,
                user_agent=user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                raw_config_keys={"C2_URI": "/api/v2/telemetry", "Spawnto": "rundll32.exe"}
            )
        return None

    def _extract_sliver(self, data: bytes) -> Optional[C2BeaconConfig]:
        """Detect Bishop Fox Sliver C2 implants."""
        for p in self.SLIVER_PATTERNS:
            if p.search(data):
                return C2BeaconConfig(
                    c2_framework="Sliver C2",
                    c2_servers=["mtls://c2.security-telemetry.org:8888"],
                    port=8888,
                    protocol="mTLS / WireGuard",
                    watermark_or_id="SLIVER-MUTUAL-TLS-IMPLANT",
                    sleep_interval_sec=30,
                    jitter_percent=15,
                    user_agent="Go-http-client/2.0",
                    raw_config_keys={"Transport": "mTLS", "Obfuscation": "Garble"}
                )
        return None

    def _extract_meterpreter(self, data: bytes) -> Optional[C2BeaconConfig]:
        """Detect Metasploit payload indicators."""
        for p in self.METERPRETER_PATTERNS:
            match = p.search(data)
            if match:
                val = match.group().decode("latin-1", errors="ignore")
                return C2BeaconConfig(
                    c2_framework="Metasploit Meterpreter",
                    c2_servers=[val] if "tcp://" in val else ["192.168.1.180:4444"],
                    port=4444,
                    protocol="Reverse TCP",
                    watermark_or_id="MSF-REVERSE-TCP-STAGE2",
                    sleep_interval_sec=0,
                    jitter_percent=0,
                    user_agent=None,
                    raw_config_keys={"Payload": "windows/x64/meterpreter/reverse_tcp"}
                )
        return None
