"""Volatility3 wrapper — CLI subprocess path.

The previous in-process implementation used ``framework.import_plugins``,
which no longer exists in volatility3 >= 2.5. Every "real" run therefore
silently fell back to the mock. This rewrite shells out to the ``vol`` CLI
(the approach most community tools take) and parses its JSON renderer.

Mode semantics (never silent):

* ``REAL``     — vol ran and produced at least one structured row.
* ``FALLBACK`` — vol was invoked but produced nothing useful (missing ISF,
                 unknown image, plugin crash). Mock data is attached so the
                 pipeline can still emit a report, but the mode is loud.
* ``MOCK``     — explicitly forced, or the ``vol`` CLI is not installed.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger("neurotrace.volatility")


class VolatilityMode(str, Enum):
    """How a Vol3 run was executed."""
    REAL = "real"
    MOCK = "mock"
    FALLBACK = "fallback"  # real attempt failed, returned mock output


@dataclass
class VolatilityResult:
    """Normalized output of one or more Volatility3 plugins."""
    mode: VolatilityMode = VolatilityMode.REAL
    os_family: str = "unknown"
    processes: List[Dict[str, Any]] = field(default_factory=list)
    injections: List[Dict[str, Any]] = field(default_factory=list)
    beacons: List[Dict[str, Any]] = field(default_factory=list)
    credentials: List[Dict[str, Any]] = field(default_factory=list)
    plugins_run: List[str] = field(default_factory=list)
    plugins_failed: List[Dict[str, str]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "os_family": self.os_family,
            "processes": self.processes,
            "injections": self.injections,
            "beacons": self.beacons,
            "credentials": self.credentials,
            "plugins_run": self.plugins_run,
            "plugins_failed": self.plugins_failed,
            "notes": self.notes,
        }


# Core plugins the engine actually consumes. Heavy plugins (vadinfo,
# dlllist, modules) produce multi-million-row output on real dumps and
# are opt-in via ``plugins=``.
#
# Names updated for volatility3 2.28:
#   windows.hollowfind        → windows.hollowprocesses (also under malware/)
#   windows.cobaltstrikebeacon → removed upstream; netscan/svcscan kept
DEFAULT_PLUGINS = [
    "windows.pslist",              # process list
    "windows.psscan",              # pool-scanning fallback (hidden/DKOM)
    "windows.cmdline",             # command lines
    "windows.malfind",             # injected/RX regions
    "windows.hollowprocesses",     # hollowed processes (was hollowfind)
    "windows.netscan",             # network connections (was part of CS hunt)
    "windows.handles",             # handles (incl. process handles to LSASS)
]

# Scan profiles (inspired by autoVolatility3). "normal" = DEFAULT_PLUGINS.
SCAN_PROFILES: Dict[str, List[str]] = {
    "quick": [
        "windows.pslist",
        "windows.malfind",
        "windows.netscan",
    ],
    "normal": list(DEFAULT_PLUGINS),
    "malware": [
        "windows.pslist",
        "windows.psscan",
        "windows.malfind",
        "windows.hollowprocesses",
        "windows.malware.psxview",
        "windows.malware.suspicious_threads",
        "windows.netscan",
        "windows.handles",
    ],
    "network": [
        "windows.pslist",
        "windows.netscan",
    ],
    "deep": list(DEFAULT_PLUGINS) + [
        "windows.dlllist",
        "windows.modules",
        "windows.vadinfo",
        "windows.svcscan",
    ],
}


def plugins_for_profile(profile: str) -> List[str]:
    key = (profile or "normal").strip().lower()
    if key not in SCAN_PROFILES:
        logger.warning("unknown scan profile %r — using normal", profile)
        key = "normal"
    return list(SCAN_PROFILES[key])

# Logical name → candidate vol plugin paths. First that imports wins.
PLUGIN_ALIASES = {
    "windows.hollowprocesses": [
        "windows.hollowprocesses",
        "windows.malware.hollowprocesses",
        "windows.hollowfind",  # vol3 < 2.11
    ],
    "windows.malfind": [
        "windows.malfind",
        "windows.malware.malfind",
    ],
    "windows.cobaltstrikebeacon": [
        "windows.cobaltstrikebeacon",
        "windows.malware.cobaltstrikebeacon",
    ],
}

# Opt-in heavy plugins — useful for deep analysis, brutal on large dumps.
HEAVY_PLUGINS = [
    "windows.dlllist",
    "windows.modules",
    "windows.vadinfo",
    "windows.vadyarascan",
]


def _resolve_plugin_name(name: str) -> str:
    """Map a logical plugin name to one that exists in this vol3 build."""
    candidates = PLUGIN_ALIASES.get(name, [name])
    try:
        import volatility3.plugins as vplugins
        import importlib
    except Exception:  # noqa: BLE001
        return candidates[0]
    for cand in candidates:
        try:
            importlib.import_module(f"volatility3.plugins.{cand}")
            return cand
        except Exception:  # noqa: BLE001
            continue
    return candidates[0]


def _discover_symbol_dir() -> Optional[str]:
    """Resolve the ISF symbol directory.

    Priority:
      1. VOLATILITY_SYMBOL_DIR env
      2. NEUROTRACE config (which itself auto-discovers ./symbols/)
      3. ./symbols/ relative to the repo root
      4. /opt/neurotrace/symbols (Docker image)
    """
    env = os.getenv("VOLATILITY_SYMBOL_DIR", "").strip()
    if env:
        return env
    try:
        from neurotrace.config import VOLATILITY_SYMBOL_DIR as CFG_DIR
        if CFG_DIR:
            return str(CFG_DIR)
    except Exception:  # noqa: BLE001
        pass
    here = Path(__file__).resolve().parents[2]
    for candidate in (here / "symbols", Path("/opt/neurotrace/symbols")):
        if candidate.is_dir():
            return str(candidate)
    return None


def _find_vol_command() -> Optional[List[str]]:
    """Locate an executable Volatility3 CLI.

    Returns an argv prefix that can be extended with plugin/renderer
    arguments, or None if nothing is available.

    Search order:
      1. ``vol`` on PATH
      2. ``vol.exe`` (or ``vol``) in the same Scripts/ dir as the
         running interpreter — covers ``pip install --user`` and
         portable Windows embeds where Scripts isn't on PATH
      3. ``python -c "from volatility3.cli import main; ..."``
         launcher (works after ``pip install volatility3`` even when
         the console script isn't linked)
    """
    # 1. PATH
    vol_bin = shutil.which("vol")
    if vol_bin:
        return [vol_bin]

    # 2. Scripts/ next to this interpreter (Windows portable / venv)
    exe = Path(sys.executable)
    candidates = [
        exe.parent / "Scripts" / "vol.exe",
        exe.parent / "Scripts" / "vol",
        exe.parent / "vol.exe",  # rare layouts
    ]
    # Also honour a virtualenv's bin/ on Unix-like paths under Windows.
    if os.name != "nt":
        candidates.extend([
            exe.parent / "vol",
            exe.parent / "bin" / "vol",
        ])
    for cand in candidates:
        if cand.is_file():
            return [str(cand)]

    # 3. In-process entry point via a tiny launcher. sys.argv[0] must be
    #    something other than "-c" or argparse treats it as the --config flag.
    launcher = (
        "import sys; sys.argv[0] = 'vol'; "
        "from volatility3.cli import main; sys.exit(main())"
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-c", launcher, "--help"],
            capture_output=True,
            timeout=20,
            text=True,
        )
        if proc.returncode == 0 and "volatility" in (proc.stdout + proc.stderr).lower():
            return [sys.executable, "-c", launcher]
    except Exception:  # noqa: BLE001
        pass
    return None


class VolatilityWrapper:
    """Run Volatility3 via its CLI and normalize the JSON output.

    Construct with no arguments for default behavior. Inject
    ``force_mode=VolatilityMode.MOCK`` to bypass real execution
    (used in tests).
    """

    def __init__(
        self,
        force_mode: Optional[VolatilityMode] = None,
        plugins: Optional[List[str]] = None,
        profile: str = "normal",
        symbol_dir: Optional[str] = None,
        per_plugin_timeout: float = 90.0,
        vol_command: Optional[Sequence[str]] = None,
        max_parallel: Optional[int] = None,
    ):
        self.force_mode = force_mode
        self.profile = (profile or "normal").strip().lower()
        self.plugins = list(plugins) if plugins else plugins_for_profile(self.profile)
        self.symbol_dir = symbol_dir if symbol_dir is not None else _discover_symbol_dir()
        self.per_plugin_timeout = per_plugin_timeout
        # Cap parallelism: each vol process is RAM-heavy on multi-GB dumps.
        default_par = int(os.getenv("NEUROTRACE_VOL_PARALLEL", "2") or 2)
        self.max_parallel = max(1, min(int(max_parallel or default_par), 4))
        self._vol_command: Optional[List[str]] = (
            list(vol_command) if vol_command else _find_vol_command()
        )
        self._vol3_available = self._vol_command is not None

    @property
    def vol_command(self) -> Optional[List[str]]:
        return self._vol_command

    def apply_profile(self, profile: str) -> None:
        self.profile = (profile or "normal").strip().lower()
        self.plugins = plugins_for_profile(self.profile)

    async def detect_os(self, dump_path: Path) -> str:
        """Best-effort OS family via vol *.info plugins (short timeout)."""
        if not self._vol3_available:
            return "unknown"
        argv_prefix = self._build_base_argv(dump_path)
        probes = (
            ("windows", "windows.info"),
            ("linux", "linux.info"),
            ("mac", "mac.info"),
        )
        for family, plugin in probes:
            try:
                rows = await asyncio.to_thread(
                    self._run_plugin, argv_prefix, plugin, timeout=25.0
                )
            except Exception:  # noqa: BLE001
                continue
            if rows:
                return family
        return "unknown"

    async def run(
        self,
        dump_path: Path,
        profile: Optional[str] = None,
    ) -> VolatilityResult:
        """Run the configured plugin set against ``dump_path``.

        Never raises — failures are recorded in the result's
        ``plugins_failed`` and ``notes`` fields so the engine can
        still produce a partial report.
        """
        if profile:
            self.apply_profile(profile)

        if not dump_path.exists():
            return VolatilityResult(
                mode=VolatilityMode.MOCK,
                notes=[f"dump not found: {dump_path}"],
            )

        if self.force_mode == VolatilityMode.MOCK:
            return self._mock_result(dump_path, reason="forced")

        if not self._vol3_available:
            logger.warning(
                "volatility3 CLI not found; returning MOCK. "
                "Install with `pip install volatility3` or ensure `vol` is on PATH."
            )
            return self._mock_result(dump_path, reason="vol CLI not found")

        try:
            return await self._run_real(dump_path)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Vol3 real execution failed: %s; falling back to mock.", exc)
            return self._mock_result(
                dump_path,
                reason=f"vol3 error: {exc}",
                mode=VolatilityMode.FALLBACK,
            )

    # ---------------------------------------------------------- real execution
    async def _run_real(self, dump_path: Path) -> VolatilityResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._run_real_sync, dump_path)

    def _build_base_argv(self, dump_path: Path) -> List[str]:
        assert self._vol_command is not None
        argv = list(self._vol_command)
        argv += ["-q"]  # quiet: less stdout noise, slightly faster startup
        argv += ["-f", str(dump_path)]
        if self.symbol_dir:
            # volatility3 accepts repeated -s / --symbol-dirs
            argv += ["-s", self.symbol_dir]
        # Persist identifier.cache on a native volume — rebuilding 3k ISF
        # indexes from a Windows bind mount takes minutes every run.
        cache_dir = os.getenv("VOLATILITY_CACHE_PATH", "/opt/neurotrace/workspace/volcache")
        try:
            Path(cache_dir).mkdir(parents=True, exist_ok=True)
            argv += ["--cache-path", cache_dir]
        except OSError:
            pass
        argv += ["-r", "json"]
        return argv

    def _effective_plugin_timeout(self, dump_path: Path) -> float:
        """Scale the per-plugin timeout by dump size.

        Tiny garbage files must fail in seconds. Real multi-GB Windows
        dumps need minutes per plugin, especially on the first run while
        Vol3 builds its symbol cache from a bind-mounted ISF pack.
        """
        try:
            size = dump_path.stat().st_size
        except OSError:
            return self.per_plugin_timeout
        if size < 1024 * 1024:  # < 1 MB
            return min(self.per_plugin_timeout, 20.0)
        if size < 100 * 1024 * 1024:  # < 100 MB
            return min(self.per_plugin_timeout, 60.0)
        if size < 1024 * 1024 * 1024:  # < 1 GB
            return max(self.per_plugin_timeout, 120.0)
        # >= 1 GB: give Vol3 real room.
        return max(self.per_plugin_timeout, 240.0)

    def _run_real_sync(self, dump_path: Path) -> VolatilityResult:
        result = VolatilityResult(mode=VolatilityMode.REAL)
        argv_prefix = self._build_base_argv(dump_path)
        result.raw["vol_command"] = list(argv_prefix)
        result.raw["symbol_dir"] = self.symbol_dir
        result.raw["profile"] = self.profile
        result.raw["max_parallel"] = self.max_parallel
        plugin_timeout = self._effective_plugin_timeout(dump_path)
        try:
            dump_size = dump_path.stat().st_size
        except OSError:
            dump_size = 0
        abort_on_consecutive_timeouts = dump_size < 100 * 1024 * 1024
        overall_deadline = time.time() + (
            plugin_timeout * max(1, (len(self.plugins) + self.max_parallel - 1) // self.max_parallel)
            + 60
        )
        result.raw["plugin_timeout"] = plugin_timeout

        if self.symbol_dir:
            result.notes.append(f"ISF symbol dir: {self.symbol_dir}")
            # Vol3 auto-downloads missing kernel ISFs; that requires a writable dir.
            try:
                Path(self.symbol_dir).mkdir(parents=True, exist_ok=True)
                probe = Path(self.symbol_dir) / ".neurotrace-write-probe"
                probe.write_text("ok")
                probe.unlink(missing_ok=True)
                result.notes.append("symbol dir is writable (Vol3 may auto-download missing ISFs)")
            except OSError as exc:
                result.notes.append(
                    f"symbol dir is read-only ({exc}) — Vol3 cannot auto-download "
                    "missing kernel ISFs for this dump's build"
                )
        else:
            result.notes.append(
                "No ISF symbol directory configured. Set VOLATILITY_SYMBOL_DIR "
                "or place symbols in ./symbols/ for real Windows analysis."
            )

        any_success = False
        consecutive_timeouts = 0
        abort_all = False

        def _one(plugin: str):
            resolved = _resolve_plugin_name(plugin)
            t0 = time.time()
            logger.info(
                "vol start %s (timeout=%.0fs) parallel=%d",
                resolved, plugin_timeout, self.max_parallel,
            )
            try:
                rows = self._run_plugin(argv_prefix, resolved, timeout=plugin_timeout)
            except subprocess.TimeoutExpired:
                return plugin, resolved, None, f"timeout after {plugin_timeout:.0f}s", time.time() - t0
            except Exception as exc:  # noqa: BLE001
                return plugin, resolved, None, str(exc), time.time() - t0
            return plugin, resolved, rows, None, time.time() - t0

        # Capped parallel fan-out (autoVolatility3-style, but bounded).
        from concurrent.futures import ThreadPoolExecutor, as_completed
        pending = list(self.plugins)
        idx = 0
        with ThreadPoolExecutor(max_workers=self.max_parallel) as pool:
            while idx < len(pending) and not abort_all:
                if time.time() > overall_deadline:
                    for leftover in pending[idx:]:
                        result.plugins_failed.append({
                            "plugin": leftover,
                            "error": "skipped: overall deadline exceeded",
                        })
                    result.notes.append("Stopped early: overall deadline exceeded.")
                    break
                batch = pending[idx:idx + self.max_parallel]
                idx += self.max_parallel
                futs = {pool.submit(_one, p): p for p in batch}
                for fut in as_completed(futs):
                    plugin, resolved, rows, err, elapsed = fut.result()
                    if err:
                        result.plugins_failed.append({"plugin": plugin, "error": err})
                        logger.warning("vol %s failed: %s", resolved, err)
                        if "timeout" in err:
                            consecutive_timeouts += 1
                            if abort_on_consecutive_timeouts and consecutive_timeouts >= 2:
                                result.notes.append(
                                    "Aborting remaining plugins after 2 consecutive "
                                    "timeouts (small/corrupt input)."
                                )
                                abort_all = True
                        continue
                    consecutive_timeouts = 0
                    if rows is None:
                        continue
                    if rows:
                        any_success = True
                        self._absorb(result, resolved, rows)
                        result.plugins_run.append(resolved)
                        logger.info(
                            "vol %s → %d rows in %.1fs", resolved, len(rows), elapsed
                        )
                    else:
                        result.plugins_run.append(resolved)
                        logger.info("vol %s → 0 rows in %.1fs", resolved, elapsed)

        if not any_success and not result.plugins_run:
            # Every plugin blew up before producing output.
            fallback = self._mock_result(
                dump_path,
                reason="all plugins failed",
                mode=VolatilityMode.FALLBACK,
                extra_notes=result.notes,
            )
            fallback.plugins_failed = list(result.plugins_failed)
            return fallback

        if not any_success:
            # Plugins "ran" but everything is empty — classic missing-symbol
            # symptom. Keep mode REAL (vol did execute) but surface loudly.
            result.notes.append(
                "Vol3 CLI ran but produced no structured rows. This almost "
                "always means the dump's ISF symbols are missing. Generate "
                "them via `bash corpora/dumps/fetch.sh` or point "
                "VOLATILITY_SYMBOL_DIR at a directory of Windows ISF .json.xz "
                "files matching the target build."
            )
            # Downgrade to FALLBACK so the engine's coverage note is unmissable
            # and test_real_dump_runs_in_real_mode fails when symbols ARE present.
            result.mode = VolatilityMode.FALLBACK
            result.notes.append(
                "Mode downgraded to fallback because no plugin produced rows."
            )

        return result

    def _run_plugin(
        self,
        argv_prefix: List[str],
        plugin: str,
        timeout: Optional[float] = None,
    ) -> Optional[List[Dict[str, Any]]]:
        """Execute one plugin and return its JSON rows (list of dicts).

        Returns None when the subprocess/JSON layer itself failed; the
        caller records that in plugins_failed.
        """
        argv = list(argv_prefix) + [plugin]
        env = os.environ.copy()
        if self.symbol_dir:
            # Some Vol3 builds also honour these env vars.
            env.setdefault("VOLATILITY_SYMBOL_DIR", self.symbol_dir)
            env.setdefault("VOLATILITY3_SYMBOL_DIR", self.symbol_dir)

        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout if timeout is not None else self.per_plugin_timeout,
            env=env,
        )
        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()

        if proc.returncode != 0:
            # Vol3 sometimes still emits partial JSON on non-zero; try it.
            rows = _try_parse_json_rows(stdout)
            if rows:
                return rows
            raise RuntimeError(
                f"exit={proc.returncode}: {stderr[:500] or stdout[:500] or 'no output'}"
            )

        if not stdout:
            return []

        rows = _try_parse_json_rows(stdout)
        if rows is None:
            # Vol3 occasionally prints progress/log lines before the JSON
            # document. Try to find the first JSON array/object.
            rows = _extract_json_from_mixed(stdout)
        if rows is None:
            raise RuntimeError(f"unparseable JSON ({len(stdout)} bytes)")
        return rows

    # --------------------------------------------------------- normalization
    @staticmethod
    def _absorb(result: VolatilityResult, plugin_name: str, rows: List[Dict[str, Any]]) -> None:
        """Pull fields out of a single plugin's JSON output into the result."""
        short = plugin_name.split(".")[-1]

        if short == "pslist":
            for row in rows:
                result.processes.append({
                    "pid": row.get("PID"),
                    "ppid": row.get("PPID"),
                    "name": row.get("ImageFileName") or row.get("Name") or "",
                    "create_time": row.get("CreateTime") or row.get("Created"),
                    "exit_time": row.get("ExitTime"),
                })
            if rows:
                result.os_family = "windows"

        elif short == "psscan":
            for row in rows:
                result.processes.append({
                    "pid": row.get("PID"),
                    "ppid": row.get("PPID"),
                    "name": row.get("ImageFileName") or row.get("Name") or "",
                    "create_time": row.get("CreateTime"),
                    "source": "psscan",
                })

        elif short == "cmdline":
            for row in rows:
                for p in result.processes:
                    if p.get("pid") == row.get("PID"):
                        p["command_line"] = row.get("CommandLine") or row.get("Args")
                        break

        elif short == "malfind":
            for row in rows:
                result.injections.append({
                    "pid": row.get("PID"),
                    "process": row.get("Process") or row.get("ImageFileName") or "",
                    "address": row.get("Start VPN") or row.get("Address") or "",
                    "end_address": row.get("End VPN") or row.get("EndAddress") or "",
                    "protection": row.get("Protection") or "",
                    "hexdump": row.get("Hexdump") or row.get("HexDump") or "",
                    "source": "vol3.malfind",
                })

        elif short in ("hollowfind", "hollowprocesses"):
            for row in rows:
                result.injections.append({
                    "pid": row.get("PID"),
                    "process": row.get("Process") or row.get("ImageFileName") or "",
                    "address": row.get("Start VPN") or row.get("Address") or "",
                    "end_address": row.get("End VPN") or "",
                    "note": row.get("Reason") or row.get("Note") or "hollowed",
                    "source": "vol3.hollowprocesses",
                })

        elif short == "netscan":
            for row in rows:
                # Surface established outbound connections as beacon candidates.
                state = str(row.get("State") or "").upper()
                remote = str(row.get("ForeignAddr") or row.get("RemoteAddress") or "")
                if state == "ESTABLISHED" and remote and not remote.startswith("0.0.0.0"):
                    result.beacons.append({
                        "pid": row.get("PID") or row.get("Owner"),
                        "process": row.get("Process") or "",
                        "config": {"server": remote, "state": state},
                        "source": "vol3.netscan",
                    })

        elif short == "cobaltstrikebeacon":
            for row in rows:
                result.beacons.append({
                    "pid": row.get("PID"),
                    "process": row.get("Process") or "",
                    "version": row.get("Version") or "",
                    "config": row.get("BeaconConfig") or row.get("Config") or {},
                    "source": "vol3.cobaltstrikebeacon",
                })

        elif short in ("vadinfo", "vadwalk"):
            for row in rows:
                for p in result.processes:
                    if p.get("pid") == row.get("PID"):
                        p.setdefault("vad_count", 0)
                        p["vad_count"] += 1
                        break

        elif short == "handles":
            for row in rows:
                name = str(row.get("Name") or row.get("ObjectName") or "")
                if "lsass" in name.lower():
                    result.notes.append(
                        f"PID {row.get('PID')} has a handle to {name} — "
                        f"potential credential dumping (T1003)"
                    )

        elif short == "dlllist":
            for row in rows:
                for p in result.processes:
                    if p.get("pid") == row.get("PID"):
                        p.setdefault("dll_count", 0)
                        p["dll_count"] += 1
                        break

    # ------------------------------------------------------------------ mock
    def _mock_result(
        self,
        dump_path: Path,
        reason: str = "no real engine",
        mode: VolatilityMode = VolatilityMode.MOCK,
        extra_notes: Optional[List[str]] = None,
    ) -> VolatilityResult:
        """Deterministic mock output, used for tests and offline mode.

        Returns a small but realistic Windows process tree with a
        couple of injected regions and one C2 beacon so the rest of
        the pipeline can be exercised end-to-end.
        """
        result = VolatilityResult(mode=mode, os_family="windows")
        result.notes.append(
            f"Vol3 {mode.value} mode active ({reason}). For real analysis, install "
            "volatility3 (`pip install volatility3`) and ISF symbols via "
            "`bash corpora/dumps/fetch.sh`, then rerun."
        )
        if extra_notes:
            result.notes.extend(extra_notes)
        if self._vol_command:
            result.notes.append(f"vol command: {' '.join(self._vol_command)}")
        if self.symbol_dir:
            result.notes.append(f"symbol dir: {self.symbol_dir}")

        result.plugins_run = ["pslist", "malfind", "cobaltstrikebeacon", "cmdline"]
        result.processes = [
            {"pid": 4, "ppid": 0, "name": "System", "create_time": "2026-08-22T08:00:00Z", "vad_count": 0},
            {"pid": 640, "ppid": 4, "name": "smss.exe", "create_time": "2026-08-22T08:00:01Z"},
            {"pid": 780, "ppid": 640, "name": "csrss.exe"},
            {"pid": 890, "ppid": 640, "name": "wininit.exe"},
            {"pid": 940, "ppid": 890, "name": "services.exe"},
            {"pid": 990, "ppid": 890, "name": "lsass.exe"},
            {"pid": 2104, "ppid": 940, "name": "explorer.exe"},
            {"pid": 3380, "ppid": 940, "name": "svchost.exe",
             "command_line": "svchost.exe -k netsvcs -p"},
            {"pid": 4892, "ppid": 2104, "name": "powershell.exe",
             "command_line": "powershell.exe -nop -w hidden -enc JABz..."},
        ]
        result.injections = [
            {
                "pid": 3380,
                "process": "svchost.exe",
                "address": "0x00007FF7A0000000",
                "end_address": "0x00007FF7A0002000",
                "protection": "PAGE_EXECUTE_READWRITE",
                "hexdump": "4d 5a 90 00 03 00 00 00 ...",
                "source": "vol3.malfind",
            },
            {
                "pid": 4892,
                "process": "powershell.exe",
                "address": "0x0000024A00000000",
                "end_address": "0x0000024A00001000",
                "protection": "PAGE_EXECUTE_READ",
                "source": "vol3.malfind",
            },
        ]
        result.beacons = [
            {
                "pid": 3380,
                "process": "svchost.exe",
                "version": "4.9",
                "config": {
                    "server": "185.220.101.44:443",
                    "useragent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "watermark": 3819,
                    "sleeptime": 60000,
                    "jitter": 30,
                    "spawnto": "rundll32.exe",
                    "uri": "/api/v2/telemetry.php",
                },
                "source": "vol3.cobaltstrikebeacon",
            }
        ]
        result.raw = {"dump": str(dump_path), "mock": True}
        return result


def _try_parse_json_rows(stdout: str) -> Optional[List[Dict[str, Any]]]:
    """Parse vol -r json output into a list of row dicts.

    Vol3 JSON renderer emits either:
      - a bare list of objects, or
      - a list of objects (the common case)
    Returns None if the text is not parseable JSON.
    """
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, list):
        return [row for row in parsed if isinstance(row, dict)]
    if isinstance(parsed, dict):
        # Some renderers wrap rows under a key.
        for key in ("rows", "data", "output", "Results"):
            if isinstance(parsed.get(key), list):
                return [row for row in parsed[key] if isinstance(row, dict)]
        return [parsed]
    return None


def _extract_json_from_mixed(text: str) -> Optional[List[Dict[str, Any]]]:
    """Best-effort: find a JSON array in a stream that has log lines mixed in."""
    # Try each line from the end — the JSON document is usually last.
    lines = text.splitlines()
    for i in range(len(lines), 0, -1):
        chunk = "\n".join(lines[:i]).strip()
        if not chunk:
            continue
        rows = _try_parse_json_rows(chunk)
        if rows is not None:
            return rows
    # Try from the first line that looks like JSON start.
    for i, line in enumerate(lines):
        if line.strip().startswith(("[", "{")):
            chunk = "\n".join(lines[i:]).strip()
            rows = _try_parse_json_rows(chunk)
            if rows is not None:
                return rows
    return None
