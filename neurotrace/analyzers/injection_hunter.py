import re
from typing import List, Dict, Any
from neurotrace.core.models import InjectedCodeArtifact, ProcessNode
from neurotrace.analyzers.entropy_vad import VadEntropyAnalyzer

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


class ProcessInjectionHunter:
    """
    Detects advanced in-memory injection techniques:
    - Process Hollowing / Doppelganging
    - Reflective DLL Injection (unbacked PE memory)
    - Shellcode / Beacon Stagers in RWX heaps
    - EarlyBird / APC Queue Injections
    """

    def __init__(self):
        if HAS_CAPSTONE:
            self.disassembler_x64 = Cs(CS_ARCH_X86, CS_MODE_64)
            self.disassembler_x86 = Cs(CS_ARCH_X86, CS_MODE_32)
        else:
            self.disassembler_x64 = None
            self.disassembler_x86 = None

    def disassemble_snippet(self, code_bytes: bytes, max_instructions: int = 8, is_64bit: bool = True) -> List[str]:
        """Disassemble injected shellcode snippet for forensic proof."""
        if not HAS_CAPSTONE or not code_bytes:
            # Fallback simple hex view if capstone is missing
            return [f"0x{i:04x}: {code_bytes[i:i+4].hex()}" for i in range(0, min(len(code_bytes), 32), 4)]
        
        disasm = self.disassembler_x64 if is_64bit else self.disassembler_x86
        instructions = []
        try:
            for instr in disasm.disasm(code_bytes[:128], 0x0):
                instructions.append(f"0x{instr.address:04x}: {instr.mnemonic} {instr.op_str}")
                if len(instructions) >= max_instructions:
                    break
        except Exception:
            pass
        return instructions

    def scan_process_memory(
        self,
        pid: int,
        proc_name: str,
        memory_segments: List[Dict[str, Any]],
        raw_buffers: Dict[str, bytes]
    ) -> List[InjectedCodeArtifact]:
        """Examine process VAD segments and memory buffers for injection artifacts."""
        artifacts = []

        for seg in memory_segments:
            addr = seg.get("start_address", "0x0")
            prot = seg.get("protection", "")
            mapped_file = seg.get("mapped_file", "")
            buf = raw_buffers.get(addr, b"")

            entropy = VadEntropyAnalyzer.calculate_entropy(buf) if buf else seg.get("entropy", 0.0)
            is_pe = VadEntropyAnalyzer.scan_page_for_pe(buf) if buf else False

            # Check for Process Hollowing / Reflective DLL
            if is_pe and (not mapped_file or "svchost" in proc_name.lower() or "explorer" in proc_name.lower() or "calc" in proc_name.lower() or "notepad" in proc_name.lower()):
                # Embedded PE inside standard process unbacked or in heap/stack
                disasm = self.disassemble_snippet(buf[0x100:], max_instructions=6) if buf else []
                artifacts.append(InjectedCodeArtifact(
                    pid=pid,
                    process_name=proc_name,
                    injection_type="Reflective DLL / Process Hollowing",
                    target_address=addr,
                    payload_size=len(buf) if buf else seg.get("size", 4096),
                    entropy=entropy,
                    disassembly_preview=disasm,
                    pe_header_found=True,
                    extracted_strings=self._extract_strings(buf, min_len=5),
                    confidence="CRITICAL"
                ))

            # Check for Raw Shellcode / RWX Injection
            elif ("RWX" in prot or "PAGE_EXECUTE_READWRITE" in prot) and (not mapped_file or mapped_file == ""):
                if entropy > 5.5 or len(buf) > 500:
                    disasm = self.disassemble_snippet(buf, max_instructions=6) if buf else []
                    artifacts.append(InjectedCodeArtifact(
                        pid=pid,
                        process_name=proc_name,
                        injection_type="Unbacked Shellcode Injection (RWX Memory)",
                        target_address=addr,
                        payload_size=len(buf) if buf else seg.get("size", 4096),
                        entropy=entropy,
                        disassembly_preview=disasm,
                        pe_header_found=False,
                        extracted_strings=self._extract_strings(buf, min_len=5),
                        confidence="HIGH" if entropy > 6.2 else "MEDIUM"
                    ))

        return artifacts

    def _extract_strings(self, data: bytes, min_len: int = 5, max_strings: int = 10) -> List[str]:
        """Extract ASCII strings from raw payload buffer."""
        if not data:
            return []
        pattern = re.compile(rb"[\x20-\x7E]{" + str(min_len).encode() + rb",}")
        matches = [m.group().decode("latin-1", errors="ignore") for m in pattern.finditer(data[:4096])]
        return matches[:max_strings]
