"""Archive intake helpers.

Memory dumps often arrive as .7z / .zip / .tar / .gz. Volatility3 only
understands raw images, so NEUROTRACE expands supported archives before
analysis. Extraction is size-bounded and path-safe (zip-slip guarded).
"""
from __future__ import annotations

import logging
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Iterable, List, Optional, Tuple

logger = logging.getLogger("neurotrace.archives")


class PasswordRequiredError(RuntimeError):
    """Archive is encrypted and no (or wrong) password was supplied."""

    def __init__(self, message: str, archive_name: str = ""):
        super().__init__(message)
        self.archive_name = archive_name

# Extensions we will attempt to unpack.
ARCHIVE_SUFFIXES = {
    ".7z",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".tar.gz",
    ".bz2",
    ".xz",
}

# Memory-image extensions worth analyzing after unpack.
DUMP_SUFFIXES = {
    ".raw",
    ".dmp",
    ".vmem",
    ".mem",
    ".bin",
    ".lime",
    ".core",
    ".elf",
}

# Hard caps so a malicious archive can't fill the disk.
MAX_TOTAL_BYTES = 16 * 1024 ** 3  # 16 GB extracted
MAX_MEMBERS = 32


def is_archive(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(s) for s in ARCHIVE_SUFFIXES)


def looks_like_dump(path: Path) -> bool:
    return path.suffix.lower() in DUMP_SUFFIXES


def _safe_join(dest: Path, member_name: str) -> Path:
    """Resolve member path under dest; reject zip-slip."""
    # Normalize separators; reject absolute paths and parent traversal.
    name = member_name.replace("\\", "/").lstrip("/")
    target = (dest / name).resolve()
    dest_resolved = dest.resolve()
    if not str(target).startswith(str(dest_resolved)):
        raise ValueError(f"unsafe archive member path: {member_name!r}")
    return target


def _pick_best_dump(files: Iterable[Path]) -> Optional[Path]:
    """Prefer the largest memory-image file."""
    dumps = [p for p in files if p.is_file() and looks_like_dump(p)]
    if not dumps:
        # Fall back to the largest regular file.
        dumps = [p for p in files if p.is_file()]
    if not dumps:
        return None
    return max(dumps, key=lambda p: p.stat().st_size)


def extract_archive(
    archive_path: Path,
    dest_dir: Optional[Path] = None,
    password: Optional[str] = None,
) -> Tuple[Optional[Path], List[str]]:
    """Unpack ``archive_path`` and return (best_dump_path, notes).

    Returns ``(None, notes)`` when nothing analyzable is found.
    Raises :class:`PasswordRequiredError` when the archive is encrypted
    and no valid password was supplied.
    """
    notes: List[str] = []
    dest = dest_dir or (archive_path.parent / f"{archive_path.stem}_extracted")
    dest.mkdir(parents=True, exist_ok=True)
    notes.append(f"extracting {archive_path.name} → {dest}")
    if password:
        notes.append("archive password supplied")

    extracted: List[Path] = []
    try:
        if archive_path.name.lower().endswith(".7z"):
            extracted = _extract_7z(archive_path, dest, notes, password=password)
        elif archive_path.name.lower().endswith(".zip"):
            extracted = _extract_zip(archive_path, dest, notes, password=password)
        elif archive_path.name.lower().endswith((".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz")):
            extracted = _extract_tar(archive_path, dest, notes)
        elif archive_path.name.lower().endswith((".gz", ".bz2", ".xz")):
            extracted = _extract_single_compress(archive_path, dest, notes)
        else:
            notes.append(f"unsupported archive type: {archive_path.suffix}")
            return None, notes
    except PasswordRequiredError:
        raise
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        if _looks_like_password_error(msg):
            raise PasswordRequiredError(
                f"archive is encrypted and the password is missing or wrong: {msg}",
                archive_name=archive_path.name,
            ) from exc
        logger.warning("archive extraction failed: %s", exc)
        notes.append(f"extraction failed: {exc}")
        return None, notes

    best = _pick_best_dump(extracted)
    if best is None:
        notes.append("archive extracted but no files found")
        return None, notes
    notes.append(f"selected dump: {best.name} ({best.stat().st_size} bytes)")
    return best, notes


def _looks_like_password_error(msg: str) -> bool:
    m = msg.lower()
    needles = (
        "password",
        "encrypted",
        "bad password",
        "wrong password",
        "requires a password",
        "compression method 99",
        "compress_type=99",
        "that compression method is not supported",
    )
    return any(n in m for n in needles)


def archive_is_encrypted(archive_path: Path) -> bool:
    """Cheap pre-check so the UI can prompt before a long extract."""
    name = archive_path.name.lower()
    try:
        if name.endswith(".zip"):
            with zipfile.ZipFile(archive_path, "r") as zf:
                for info in zf.infolist():
                    # Bit 0 of general purpose flag = encrypted.
                    if info.flag_bits & 0x1:
                        return True
                    # WinZip AES uses compress_type 99.
                    if getattr(info, "compress_type", None) == 99:
                        return True
            return False
        if name.endswith(".7z"):
            try:
                import py7zr
            except ImportError:
                return False
            with py7zr.SevenZipFile(archive_path, "r") as zf:
                return bool(getattr(zf, "needs_password", lambda: False)())
    except Exception:  # noqa: BLE001
        return False
    return False


def _extract_7z(
    archive_path: Path,
    dest: Path,
    notes: List[str],
    password: Optional[str] = None,
) -> List[Path]:
    try:
        import py7zr
    except ImportError as exc:
        raise RuntimeError(
            "py7zr not installed — `pip install py7zr` to handle .7z dumps"
        ) from exc

    try:
        zf = py7zr.SevenZipFile(archive_path, "r", password=password)
    except Exception as exc:  # noqa: BLE001
        if _looks_like_password_error(str(exc)) or not password:
            raise PasswordRequiredError(
                f"7z archive requires a password ({exc})",
                archive_name=archive_path.name,
            ) from exc
        raise

    with zf:
        if getattr(zf, "needs_password", lambda: False)() and not password:
            raise PasswordRequiredError(
                "7z archive is encrypted — password required",
                archive_name=archive_path.name,
            )
        names = zf.getnames()
        if len(names) > MAX_MEMBERS:
            notes.append(f"archive has {len(names)} members; truncating to {MAX_MEMBERS}")
        targets = []
        for name in names[:MAX_MEMBERS]:
            if name.endswith("/"):
                continue
            _safe_join(dest, name)  # raises on zip-slip
            targets.append(name)
        try:
            zf.extract(path=dest, targets=targets)
        except Exception as exc:  # noqa: BLE001
            if password is None or _looks_like_password_error(str(exc)):
                raise PasswordRequiredError(
                    f"7z extract failed (password missing/wrong): {exc}",
                    archive_name=archive_path.name,
                ) from exc
            raise

    files = [p for p in dest.rglob("*") if p.is_file()]
    total = sum(p.stat().st_size for p in files)
    if total > MAX_TOTAL_BYTES:
        raise RuntimeError(f"extracted size {total} exceeds cap {MAX_TOTAL_BYTES}")
    notes.append(f"extracted {len(files)} file(s), {total} bytes")
    return files


def _zip_uses_aes(zf: Any) -> bool:
    for info in zf.infolist():
        if getattr(info, "compress_type", None) == 99:
            return True
        # Extra field 0x9901 = AE-x AES marker (WinZip).
        extra = getattr(info, "extra", b"") or b""
        if b"\x01\x99" in extra or b"\x99\x01" in extra:
            return True
    return False


def _extract_zip(
    archive_path: Path,
    dest: Path,
    notes: List[str],
    password: Optional[str] = None,
) -> List[Path]:
    """Extract .zip including WinZip AES (compress_type=99).

    stdlib zipfile cannot decrypt AES — use pyzipper when present,
    then fall back to the 7z CLI.
    """
    pwd = password.encode("utf-8") if password else None

    # Inspect encryption type with stdlib first.
    with zipfile.ZipFile(archive_path, "r") as probe:
        members = [m for m in probe.infolist() if not m.is_dir()][:MAX_MEMBERS]
        encrypted = any(
            (m.flag_bits & 0x1) or getattr(m, "compress_type", None) == 99
            for m in members
        )
        uses_aes = _zip_uses_aes(probe)

    if encrypted and not pwd:
        raise PasswordRequiredError(
            "zip archive is encrypted — password required",
            archive_name=archive_path.name,
        )

    if uses_aes:
        notes.append("WinZip AES encryption detected (compress_type=99)")
        if password and _extract_zip_aes_pyzipper(archive_path, dest, members, password, notes):
            files = [p for p in dest.rglob("*") if p.is_file()]
            notes.append(f"extracted {len(files)} file(s) via pyzipper/AES")
            return files
        if password and _extract_zip_aes_7z(archive_path, dest, password, notes):
            files = [p for p in dest.rglob("*") if p.is_file()]
            notes.append(f"extracted {len(files)} file(s) via 7z AES")
            return files
        raise RuntimeError(
            "WinZip AES zip requires pyzipper or the 7z CLI to decrypt. "
            "Neither could extract this archive. Install pyzipper "
            "(`pip install pyzipper`) or p7zip-full."
        )

    # Traditional ZipCrypto / unencrypted — stdlib is fine.
    with zipfile.ZipFile(archive_path, "r") as zf:
        for m in members:
            target = _safe_join(dest, m.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with zf.open(m, pwd=pwd) as src, target.open("wb") as out:
                    shutil.copyfileobj(src, out)
            except RuntimeError as exc:
                if pwd is None or _looks_like_password_error(str(exc)):
                    raise PasswordRequiredError(
                        f"zip extract failed (password missing/wrong): {exc}",
                        archive_name=archive_path.name,
                    ) from exc
                raise
    files = [p for p in dest.rglob("*") if p.is_file()]
    notes.append(f"extracted {len(files)} file(s)")
    return files


def _extract_zip_aes_pyzipper(
    archive_path: Path,
    dest: Path,
    members: List[Any],
    password: str,
    notes: List[str],
) -> bool:
    try:
        import pyzipper
    except ImportError:
        notes.append("pyzipper not installed — cannot decrypt WinZip AES via Python")
        return False
    try:
        with pyzipper.AESZipFile(archive_path, "r") as zf:
            zf.setpassword(password.encode("utf-8"))
            for m in members[:MAX_MEMBERS]:
                name = m.filename
                if name.endswith("/"):
                    continue
                target = _safe_join(dest, name)
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(name) as src, target.open("wb") as out:
                    # Stream in chunks so a 5GB dump does not blow RAM.
                    while True:
                        chunk = src.read(8 * 1024 * 1024)
                        if not chunk:
                            break
                        out.write(chunk)
        return True
    except Exception as exc:  # noqa: BLE001
        if _looks_like_password_error(str(exc)):
            raise PasswordRequiredError(
                f"AES zip password missing/wrong: {exc}",
                archive_name=archive_path.name,
            ) from exc
        notes.append(f"pyzipper AES extract failed: {exc}")
        return False


def _extract_zip_aes_7z(
    archive_path: Path,
    dest: Path,
    password: str,
    notes: List[str],
) -> bool:
    import shutil as _shutil
    import subprocess

    seven = _shutil.which("7z") or _shutil.which("7za") or _shutil.which("7zr")
    if not seven:
        notes.append("7z CLI not found — cannot decrypt WinZip AES via 7z")
        return False
    try:
        # -p must be attached with no space; empty would mean prompt.
        proc = subprocess.run(
            [seven, "x", "-y", f"-o{dest}", f"-p{password}", str(archive_path)],
            capture_output=True,
            text=True,
            timeout=1800,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            if _looks_like_password_error(err) or "Wrong password" in err:
                raise PasswordRequiredError(
                    f"7z AES extract failed (password missing/wrong): {err[:300]}",
                    archive_name=archive_path.name,
                )
            notes.append(f"7z AES extract failed: {err[:300]}")
            return False
        return True
    except PasswordRequiredError:
        raise
    except Exception as exc:  # noqa: BLE001
        notes.append(f"7z AES extract error: {exc}")
        return False


def _extract_tar(archive_path: Path, dest: Path, notes: List[str]) -> List[Path]:
    mode = "r:*"
    count = 0
    with tarfile.open(archive_path, mode) as tf:
        for member in tf.getmembers():
            if not member.isfile() or count >= MAX_MEMBERS:
                continue
            target = _safe_join(dest, member.name)
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, target.open("wb") as out:
                shutil.copyfileobj(src, out)
            count += 1
    files = [p for p in dest.rglob("*") if p.is_file()]
    notes.append(f"extracted {len(files)} file(s)")
    return files


def _extract_single_compress(archive_path: Path, dest: Path, notes: List[str]) -> List[Path]:
    import gzip
    import bz2
    import lzma

    name = archive_path.name.lower()
    if name.endswith(".gz"):
        opener = gzip.open
        out_name = archive_path.name[:-3]
    elif name.endswith(".bz2"):
        opener = bz2.open
        out_name = archive_path.name[:-4]
    elif name.endswith(".xz"):
        opener = lzma.open
        out_name = archive_path.name[:-3]
    else:
        return []

    out_path = dest / out_name
    with opener(archive_path, "rb") as src, out_path.open("wb") as out:
        shutil.copyfileobj(src, out)
    notes.append(f"decompressed → {out_path.name}")
    return [out_path]


def resolve_analyzable(
    path: Path,
    dest_dir: Optional[Path] = None,
    password: Optional[str] = None,
) -> Tuple[Path, List[str]]:
    """Return a raw dump path, extracting archives when needed.

    Non-archives are returned unchanged.
    Raises :class:`PasswordRequiredError` for encrypted archives.
    """
    notes: List[str] = []
    if not is_archive(path):
        return path, notes

    extracted, xnotes = extract_archive(path, dest_dir=dest_dir, password=password)
    notes.extend(xnotes)
    if extracted is None:
        raise RuntimeError(
            f"could not extract an analyzable dump from {path.name}: {'; '.join(notes)}"
        )
    return extracted, notes
