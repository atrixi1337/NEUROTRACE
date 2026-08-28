"""NEUROTRACE — Rich-based CLI for memory dump analysis.

Usage:
    python -m neurotrace.cli analyze <path-to-dump>
    python -m neurotrace.cli velo <client_id> [--artifact=Windows.Memory.Acquisition]
    python -m neurotrace.cli velo-artifact <client_id> <artifact>
    python -m neurotrace.cli health
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from neurotrace.core.engine import NeurotraceEngine

console = Console()


# ---------------------------------------------------------- analyze (file)
async def cmd_analyze(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        console.print(f"[red]Error: file {path} does not exist.[/red]")
        return 1

    console.print(Panel(
        f"[bold cyan]NEUROTRACE Memory Forensics Scanner[/bold cyan]\n"
        f"Target: [yellow]{path.name}[/yellow]",
        border_style="cyan",
    ))

    engine = NeurotraceEngine()
    with console.status("[bold green]Triage in progress (Vol3 → injections → C2 → AI narrative)..."):
        report = await engine.analyze_memory_file(path, sample_name=path.name)

    _render_report(report)
    if args.output:
        Path(args.output).write_text(report.model_dump_json(indent=2))
        console.print(f"[dim]Wrote JSON report → {args.output}[/dim]")
    return 0


# ---------------------------------------------------------- velo (analyze)
async def cmd_velo(args: argparse.Namespace) -> int:
    engine = NeurotraceEngine()
    with console.status(f"[bold green]Acquiring dump from Velociraptor client {args.client_id}..."):
        report = await engine.analyze_via_velociraptor(
            args.client_id, artifact=args.artifact,
        )
    _render_report(report)
    return 0


# ---------------------------------------------------------- velo artifact
async def cmd_velo_artifact(args: argparse.Namespace) -> int:
    engine = NeurotraceEngine()
    out = await engine.stream_velociraptor_artifact(
        args.client_id, args.artifact,
    )
    console.print_json(data=out)
    return 0


# ---------------------------------------------------------- health
async def cmd_health(_: argparse.Namespace) -> int:
    engine = NeurotraceEngine()
    info: Dict[str, Any] = {
        "vol3_backend": type(engine.vol3).__name__,
        "velo_backend": type(engine.velo).__name__,
        "llm_provider": engine.ai._provider.name if engine.ai._provider else None,
        "llm_model": engine.ai._provider.default_model if engine.ai._provider else None,
        "llm_live": engine.ai.is_live,
    }
    console.print_json(data=info)
    return 0


# ---------------------------------------------------------- renderer
def _render_report(report) -> None:
    score_color = "red" if report.threat_score >= 70 else \
                  "yellow" if report.threat_score >= 40 else "green"
    console.print(
        f"\n[bold]Threat Level:[/bold] [{score_color}]{report.overall_threat_level} "
        f"(Score: {report.threat_score}/100)[/{score_color}]"
    )
    console.print(
        f"[bold]Total Processes Scanned:[/bold] {report.total_processes} | "
        f"[bold red]Compromised:[/bold red] {report.compromised_processes} | "
        f"[bold]Vol3 mode:[/bold] {report.vol3_mode} | "
        f"[bold]Elapsed:[/bold] {report.elapsed_seconds}s"
    )

    if report.injections:
        t = Table(title="\nDetected In-Memory Injections", border_style="red")
        t.add_column("PID", style="cyan", justify="right")
        t.add_column("Process", style="bold white")
        t.add_column("Type", style="red")
        t.add_column("Address", style="yellow")
        t.add_column("Confidence", style="bold red")
        for inj in report.injections:
            t.add_row(str(inj.pid), inj.process_name, inj.injection_type,
                       inj.target_address, inj.confidence)
        console.print(t)

    if report.beacons:
        t = Table(title="\nExtracted Command & Control (C2) Configurations", border_style="magenta")
        t.add_column("Framework", style="bold magenta")
        t.add_column("C2 Endpoints", style="yellow")
        t.add_column("Port/Proto", style="cyan")
        t.add_column("Watermark / ID", style="green")
        for b in report.beacons:
            t.add_row(
                b.c2_framework,
                ", ".join(b.c2_servers),
                f"{b.port}/{b.protocol}",
                b.watermark_or_id or "N/A",
            )
        console.print(t)

    if report.credentials:
        t = Table(title="\nRecovered In-Memory Credentials & Artifacts", border_style="purple")
        t.add_column("Source", style="cyan")
        t.add_column("Type", style="bold purple")
        t.add_column("User / Principal", style="white")
        t.add_column("Masked Value", style="yellow")
        for c in report.credentials:
            t.add_row(
                c.source_process, c.artifact_type,
                c.username or "N/A", c.value_masked,
            )
        console.print(t)

    if report.mitre_techniques:
        console.print(f"\n[bold]MITRE ATT&CK:[/bold] {', '.join(report.mitre_techniques)}")

    if report.findings:
        t = Table(title="\nForensic Findings", border_style="red")
        t.add_column("Severity", style="bold")
        t.add_column("Category", style="cyan")
        t.add_column("Title", style="white")
        t.add_column("MITRE", style="yellow")
        for f in report.findings:
            t.add_row(f.severity, f.category, f.title, f.mitre_attack_id or "—")
        console.print(t)

    if report.ai_storyline:
        console.print("\n", Panel(
            Markdown(f"### 🤖 AI Incident Storyline\n{report.ai_storyline}"),
            title="[bold green]AI Forensic Reconstruction[/bold green]",
            border_style="green",
        ))

    if report.ai_recommendations:
        console.print(Panel(
            "\n".join(f"• {r}" for r in report.ai_recommendations),
            title="[bold yellow]IR Recommendations[/bold yellow]",
            border_style="yellow",
        ))

    if report.generated_yara_rule:
        console.print("\n", Panel(
            f"[cyan]{report.generated_yara_rule}[/cyan]",
            title="[bold yellow]Auto-Generated YARA Rule[/bold yellow]",
            border_style="yellow",
        ))

    if report.coverage_notes:
        console.print(Panel(
            "\n".join(f"• {n}" for n in report.coverage_notes),
            title="[bold]Coverage / Limitations[/bold]",
            border_style="blue",
        ))


# ---------------------------------------------------------- main
def main() -> int:
    parser = argparse.ArgumentParser(
        prog="neurotrace",
        description="NEUROTRACE — AI memory forensics & incident response",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_analyze = sub.add_parser("analyze", help="Analyze a memory dump file")
    p_analyze.add_argument("path")
    p_analyze.add_argument("--output", "-o", help="Write JSON report to this path")

    p_velo = sub.add_parser("velo", help="Analyze a Velociraptor client")
    p_velo.add_argument("client_id")
    p_velo.add_argument("--artifact", default="Windows.Memory.Acquisition")

    p_va = sub.add_parser("velo-artifact", help="Stream a Velociraptor artifact")
    p_va.add_argument("client_id")
    p_va.add_argument("artifact")

    sub.add_parser("health", help="Print engine + LLM health info")

    args = parser.parse_args()
    if args.cmd == "analyze":
        return asyncio.run(cmd_analyze(args))
    if args.cmd == "velo":
        return asyncio.run(cmd_velo(args))
    if args.cmd == "velo-artifact":
        return asyncio.run(cmd_velo_artifact(args))
    if args.cmd == "health":
        return asyncio.run(cmd_health(args))
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
