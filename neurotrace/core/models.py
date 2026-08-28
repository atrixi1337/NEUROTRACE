from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class MemorySegment(BaseModel):
    start_address: str
    end_address: str
    size: int
    protection: str  # e.g., PAGE_EXECUTE_READWRITE (RWX)
    state: str       # MEM_COMMIT, MEM_RESERVE
    entropy: float
    mapped_file: Optional[str] = None
    is_suspicious: bool = False
    reasons: List[str] = []


class InjectedCodeArtifact(BaseModel):
    pid: int
    process_name: str
    injection_type: str  # "Process Hollowing", "Reflective DLL", "Shellcode Injection", "Hooking"
    target_address: str
    payload_size: int
    entropy: float
    disassembly_preview: List[str] = []
    pe_header_found: bool = False
    extracted_strings: List[str] = []
    confidence: str  # "CRITICAL", "HIGH", "MEDIUM"


class C2BeaconConfig(BaseModel):
    c2_framework: str  # "Cobalt Strike", "Sliver", "Metasploit", "Brute Ratel", "Havoc", "Custom"
    c2_servers: List[str] = []
    port: Optional[int] = None
    protocol: Optional[str] = "HTTPS"
    watermark_or_id: Optional[str] = None
    sleep_interval_sec: Optional[int] = None
    jitter_percent: Optional[int] = None
    user_agent: Optional[str] = None
    raw_config_keys: Dict[str, Any] = {}


class CredentialArtifact(BaseModel):
    source_process: str
    artifact_type: str  # "Kerberos Ticket", "NTLM Hash", "Plaintext Credential", "Vault/SAM", "API Key"
    username: Optional[str] = None
    domain: Optional[str] = None
    value_masked: str
    confidence: str


class ProcessNode(BaseModel):
    pid: int
    ppid: int
    name: str
    path: Optional[str] = None
    command_line: Optional[str] = None
    create_time: Optional[str] = None
    threads_count: int = 0
    handles_count: int = 0
    is_hidden: bool = False  # DKOM unlinked
    is_compromised: bool = False
    injections: List[InjectedCodeArtifact] = []
    suspicious_vad_count: int = 0


class ForensicFinding(BaseModel):
    title: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    category: str  # "Execution", "Persistence", "Credential Access", "Defense Evasion", "C2"
    mitre_attack_id: Optional[str] = None
    description: str
    evidence: Dict[str, Any] = {}


class ForensicReport(BaseModel):
    analysis_id: str
    target_name: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    os_detected: str = "Windows 10/11 x64 (NT Kernel 10.0)"
    total_processes: int = 0
    compromised_processes: int = 0
    overall_threat_level: str = "BENIGN"  # "CRITICAL", "HIGH", "ELEVATED", "CLEAN"
    threat_score: int = 0  # 0 to 100
    processes: List[ProcessNode] = []
    injections: List[InjectedCodeArtifact] = []
    beacons: List[C2BeaconConfig] = []
    credentials: List[CredentialArtifact] = []
    findings: List[ForensicFinding] = []
    mitre_techniques: List[str] = []
    attack_timeline: List[Dict[str, str]] = []
    ai_storyline: Optional[str] = None
    ai_recommendations: List[str] = []
    generated_yara_rule: Optional[str] = None
    # New fields: provenance + coverage
    coverage_notes: List[str] = Field(default_factory=list)
    vol3_mode: str = "unknown"  # "real" | "mock" | "fallback" | "n/a"
    plugins_run: List[str] = Field(default_factory=list)
    plugins_failed: List[Dict[str, str]] = Field(default_factory=list)
    elapsed_seconds: float = 0.0
