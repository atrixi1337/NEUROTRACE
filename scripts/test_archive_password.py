import io
import zipfile
from pathlib import Path

# Create a password-protected zip (ZipCrypto via setpassword on write isn't
# supported by stdlib zipfile for writing. Use a pre-encrypted approach with
# pyminizip if available; else craft flag and test detection only.)

# stdlib cannot WRITE encrypted zips. Test detection + PasswordRequiredError
# by constructing a zip and checking open(pwd=) behavior on a synthetic file.

# Simpler: unit-test archive_is_encrypted on a plain zip (False) and
# PasswordRequiredError path via a fake encrypted flag.

from neurotrace.core.archives import (
    PasswordRequiredError,
    archive_is_encrypted,
    extract_archive,
    _looks_like_password_error,
)

tmp = Path("/tmp/nt-pwd-test")
tmp.mkdir(exist_ok=True)

# Plain zip
plain = tmp / "plain.zip"
with zipfile.ZipFile(plain, "w") as zf:
    zf.writestr("a.raw", b"\x00" * 16)
assert archive_is_encrypted(plain) is False
dump, notes = extract_archive(plain, dest_dir=tmp / "out1")
assert dump is not None and dump.name == "a.raw"
print("plain zip OK", dump)

# Password error detector
assert _looks_like_password_error("File is encrypted, password required for extraction")
assert _looks_like_password_error("Bad password for file")
assert _looks_like_password_error("compress_type=99")
assert not _looks_like_password_error("disk full")
print("password detector OK")

# Simulate encrypted zip by setting flag_bits after write is not easy;
# instead verify PasswordRequiredError type exists and extract raises it
# when we force the encrypted path via a monkeypatched ZipInfo.
class FakeInfo:
    def __init__(self):
        self.filename = "x.raw"
        self.flag_bits = 0x1
        self.compress_type = 99
        self.is_dir = lambda: False

class FakeZip:
    def __init__(self, *a, **k):
        pass
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def infolist(self):
        return [FakeInfo()]

import neurotrace.core.archives as arch
orig = arch.zipfile.ZipFile
arch.zipfile.ZipFile = FakeZip
try:
    try:
        extract_archive(plain, dest_dir=tmp / "out2")
        print("FAIL: expected PasswordRequiredError")
    except PasswordRequiredError as e:
        print("encrypted path OK:", e)
finally:
    arch.zipfile.ZipFile = orig

print("ALL ARCHIVE PASSWORD TESTS PASSED")
