import struct

# Create a realistic test memory sample simulating an injected Cobalt Strike memory region
sample_path = "sample_cobaltstrike_dump.dmp"

header = b"\x7fMEMDUMP\x00\x00\x01\x00\x00\x00"
pe_stub = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80) + b"\x00" * 60 + b"PE\x00\x00"
beacon_indicators = (
    b"powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBt..."
    b"\x00\x00"
    b"https://185.220.101.44:443/api/v2/telemetry.php"
    b"\x00"
    b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0"
    b"\x00"
    b"msagent_status_pipe_3819"
    b"\x00"
    b"AKIAIOSFODNN7EXAMPLE"
    b"\x00"
    b"sekurlsa::logonpasswords lsasrv.dll"
)

with open(sample_path, "wb") as f:
    f.write(header)
    f.write(pe_stub)
    f.write(b"\x90\x48\x31\xc0\x48\xff\xc0\xc3" * 100)  # Shellcode NOP sled & x64 instructions
    f.write(beacon_indicators)
    f.write(b"\xCC" * 1024)

print(f"Generated sample test memory dump: {sample_path}")
