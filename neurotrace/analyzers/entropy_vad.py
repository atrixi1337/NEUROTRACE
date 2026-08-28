import math
import struct
from typing import List, Tuple
from neurotrace.core.models import MemorySegment


class VadEntropyAnalyzer:
    """
    Virtual Address Descriptor (VAD) and Memory Page Analyzer.
    Detects unbacked RWX pages, high entropy payloads (encrypted shellcode/beacons),
    and anomalous page permissions.
    """

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon Entropy (0.0 to 8.0) of a byte sequence."""
        if not data:
            return 0.0
        
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        entropy = 0.0
        total_len = len(data)
        for count in freq:
            if count > 0:
                p = count / total_len
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def scan_page_for_pe(data: bytes) -> bool:
        """Check if memory buffer contains an embedded/unmapped PE header (MZ...PE)."""
        if len(data) < 0x200:
            return False
        if data[:2] == b"MZ":
            # Check e_lfanew offset
            try:
                e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
                if e_lfanew < len(data) - 4 and data[e_lfanew:e_lfanew+4] == b"PE\x00\x00":
                    return True
            except Exception:
                pass
        return False

    @staticmethod
    def is_rwx_suspicious(protection: str, mapped_file: str | None, entropy: float) -> Tuple[bool, List[str]]:
        """Determine if a memory segment exhibits stealth injection characteristics."""
        reasons = []
        is_suspicious = False

        if "EXECUTE_READWRITE" in protection or protection == "PAGE_EXECUTE_READWRITE" or protection == "RWX":
            if not mapped_file or mapped_file.strip() == "":
                is_suspicious = True
                reasons.append("Unbacked RWX allocation (no file on disk)")
            if entropy > 6.4:
                is_suspicious = True
                reasons.append(f"High entropy ({entropy:.2f}) indicating packed/encrypted payload")
        
        elif "EXECUTE_READ" in protection and (not mapped_file or mapped_file.strip() == ""):
            if entropy > 6.0:
                is_suspicious = True
                reasons.append("Unbacked RX region with high entropy (reflective module)")

        return is_suspicious, reasons
