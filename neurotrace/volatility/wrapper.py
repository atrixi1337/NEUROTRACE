"""Volatility3 wrapper.

Encapsulates the Vol3 invocation so the rest of the engine doesn't
have to know about automagic, contexts, layers, or renderers.

The wrapper exposes one high-level call: :meth:`run` which takes
a memory dump path and a list of plugin names, and returns a
:class:`VolatilityResult` with a normalized representation of
processes, VADs, and findings.
"""
from __future__ import annotations

import contextlib
import io
import json
import logging
import traceback
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

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


# Volatility3 plugin names that NEUROTRACE orchestrates by default.
DEFAULT_PLUGINS = [
    "windows.pslist",          # process list
    "windows.psscan",          # pool-scanning fallback
    "windows.cmdline",         # command lines
    "windows.dlllist",         # loaded DLLs
    "windows.malfind",         # injected/RX regions
    "windows.modules",         # kernel modules
    "windows.vadinfo",         # VAD tree
    "windows.hollowfind",      # hollowed processes
    "windows.cobaltstrikebeacon",  # CS config extractor
    "windows.handles",         # handles (incl. process handles to LSASS)
]


class VolatilityWrapper:
    """Run Volatility3 plugins and normalize the output.

    Construct with no arguments for default behavior. Inject
    ``force_mode=VolatilityMode.MOCK`` to bypass real execution
    (used in tests).
    """

    def __init__(
        self,
        force_mode: Optional[VolatilityMode] = None,
        plugins: Optional[List[str]] = None,
        symbol_dir: Optional[str] = None,
    ):
        self.force_mode = force_mode
        self.plugins = plugins or DEFAULT_PLUGINS
        self.symbol_dir = symbol_dir
        self._vol3_available = self._probe_vol3()

    @staticmethod
    def _probe_vol3() -> bool:
        try:
            import volatility3.framework  # noqa: F401
            return True
        except Exception:  # noqa: BLE001
            return False

    async def run(self, dump_path: Path) -> VolatilityResult:
        """Run the default plugin set against ``dump_path``.

        Never raises — failures are recorded in the result's
        ``plugins_failed`` and ``notes`` fields so the engine can
        still produce a partial report.
        """
        if not dump_path.exists():
            return VolatilityResult(
                mode=VolatilityMode.MOCK,
                notes=[f"dump not found: {dump_path}"],
            )

        if self.force_mode == VolatilityMode.MOCK or not self._vol3_available:
            return self._mock_result(dump_path, reason="forced" if self.force_mode else "vol3 unavailable")

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
        """Run the real Volatility3 plugins and parse JSON output."""
        # Vol3 is sync; we still expose async for engine consistency.
        import asyncio
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._run_real_sync, dump_path)

    def _run_real_sync(self, dump_path: Path) -> VolatilityResult:
        from volatility3.framework import contexts, automagic
        from volatility3.framework.configuration import requirements
        from volatility3 import framework
        from volatility3.framework import constants
        from volatility3.framework.layers import physical

        result = VolatilityResult(mode=VolatilityMode.REAL)
        ctx = contexts.Context()

        # Build the requested plugin list
        plugin_paths = []
        for name in self.plugins:
            try:
                plugin_paths.append(framework.import_plugins([f"volatility3.plugins.{name}"])[0])
            except Exception as exc:  # noqa: BLE001
                result.plugins_failed.append({"plugin": name, "error": f"import: {exc}"})

        if not plugin_paths:
            return self._mock_result(dump_path, reason="no plugins importable", mode=VolatilityMode.FALLBACK)

        # Build a single layer for the dump
        from volatility3.framework.layers.physical import FileLayer
        layer_config_path = requirements.PathRequirement("primary", dump_path)
        layer_name = "primary"
        try:
            physical_layer = FileLayer(
                context=ctx,
                config_path=layer_config_path,
                name=layer_name,
            )
        except Exception as exc:  # noqa: BLE001
            return self._mock_result(
                dump_path,
                reason=f"layer build failed: {exc}",
                mode=VolatilityMode.FALLBACK,
            )

        for plugin_cls in plugin_paths:
            plugin_name = plugin_cls.__name__
            try:
                plugin = plugin_cls(
                    context=ctx,
                    config_path=requirements.PluginPath(plugin_name),
                    progress_callback=None,
                )
                # Build a fresh context with the primary layer
                run_ctx = contexts.Context()
                # Run automagic to set up required layers
                automagic.choose_automagic([], plugin)
                # Render output as JSON
                import volatility3.framework.renderers as renderers
                renderer = renderers.JsonRenderer()
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    # Run the plugin
                    tree = plugin.run()
                    renderer.render(tree)
                output = buf.getvalue()
                try:
                    parsed = json.loads(output) if output.strip() else []
                except json.JSONDecodeError as exc:
                    result.plugins_failed.append({"plugin": plugin_name, "error": f"json: {exc}"})
                    continue
                self._absorb(result, plugin_name, parsed)
                result.plugins_run.append(plugin_name)
            except Exception as exc:  # noqa: BLE001
                tb = traceback.format_exc(limit=2)
                logger.warning("Vol3 plugin %s failed: %s", plugin_name, exc)
                result.plugins_failed.append({"plugin": plugin_name, "error": str(exc), "trace": tb})

        # If nothing actually produced output, return a hint in notes
        if not result.processes and not result.injections and not result.beacons:
            result.notes.append(
                "Vol3 ran without producing structured output — likely missing ISF symbols "
                "for the dump's profile. Set VOLATILITY_SYMBOL_DIR to a directory of "
                "Windows ISF .json.xz files for the build under analysis."
            )

        return result

    # --------------------------------------------------------- normalization
    @staticmethod
    def _absorb(result: VolatilityResult, plugin_name: str, parsed: Any) -> None:
        """Pull fields out of a single plugin's JSON output into the result."""
        # Vol3 JSON renders as list[dict] keyed by column headers
        rows = parsed if isinstance(parsed, list) else []
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
            # Pool-scan can find hidden processes not in pslist.
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
                    "process": row.get("Process") or "",
                    "address": row.get("Start VPN") or row.get("Address") or "",
                    "end_address": row.get("End VPN") or row.get("EndAddress") or "",
                    "protection": row.get("Protection") or "",
                    "hexdump": row.get("Hexdump") or row.get("HexDump") or "",
                    "source": "vol3.malfind",
                })

        elif short == "hollowfind":
            for row in rows:
                result.injections.append({
                    "pid": row.get("PID"),
                    "process": row.get("Process") or "",
                    "address": row.get("Start VPN") or "",
                    "end_address": row.get("End VPN") or "",
                    "note": row.get("Reason") or "hollowed",
                    "source": "vol3.hollowfind",
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
                if row.get("Name", "").lower() == "lsass.exe":
                    result.notes.append(
                        f"PID {row.get('PID')} has a handle to lsass.exe — "
                        f"potential credential dumping (T1003)"
                    )

    # ------------------------------------------------------------------ mock
    def _mock_result(
        self,
        dump_path: Path,
        reason: str = "no real engine",
        mode: VolatilityMode = VolatilityMode.MOCK,
    ) -> VolatilityResult:
        """Deterministic mock output, used for tests and offline mode.

        Returns a small but realistic Windows process tree with a
        couple of injected regions and one C2 beacon so the rest of
        the pipeline can be exercised end-to-end.
        """
        result = VolatilityResult(mode=mode, os_family="windows")
        result.notes.append(
            f"Vol3 mock mode active ({reason}). For real analysis, install ISF "
            "symbols via `vol --symbol-dirs <path>` and rerun."
        )
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
