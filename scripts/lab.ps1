#!/usr/bin/env pwsh
# =============================================================================
# NEUROTRACE lab controller — Windows / PowerShell first.
#
# All analysis runs inside Linux containers. Nothing on this host ever
# executes a dump or sample.
#
#   .\scripts\lab.ps1 build          # build image (fast, no ISF symbols)
#   .\scripts\lab.ps1 build-full     # build image with ISF symbol pack
#   .\scripts\lab.ps1 up             # start dashboard on :8010
#   .\scripts\lab.ps1 test           # run pytest inside the image
#   .\scripts\lab.ps1 dev            # interactive shell, source mounted
#   .\scripts\lab.ps1 lab            # AIR-GAPPED shell (network_mode:none)
#   .\scripts\lab.ps1 analyze <file> # analyze a dump already in lab/dumps
#   .\scripts\lab.ps1 down           # stop everything
#   .\scripts\lab.ps1 clean          # stop + wipe volumes/image
# =============================================================================
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet(
        "build", "build-full", "up", "down", "logs", "health",
        "test", "test-dev", "dev", "lab", "cli", "analyze", "shell", "clean", "status", "help"
    )]
    [string]$Command = "help",

    [Parameter(Position = 1)]
    [string]$Arg1 = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
Set-Location $RootDir

# Prefer the compose plugin; fall back to the standalone docker-compose.exe
# that ships with Docker Desktop on Windows.
function Get-Compose {
    try {
        $null = docker compose version 2>$null
        if ($LASTEXITCODE -eq 0) { return @("docker", "compose") }
    } catch {}
    $dc = Get-Command docker-compose -ErrorAction SilentlyContinue
    if ($dc) { return @($dc.Source) }
    throw "Neither 'docker compose' nor 'docker-compose' found. Install Docker Desktop."
}

function Invoke-Compose {
    $cmd = Get-Compose
    & $cmd[0] $cmd[1..($cmd.Length)] @args
}

function Write-Header($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
}

switch ($Command) {
    "build" {
        Write-Header "Building neurotrace:2.0 (fast — no ISF symbols)"
        Invoke-Compose build --build-arg NEUROTRACE_SKIP_SYMBOLS=1 app
    }
    "build-full" {
        Write-Header "Building neurotrace:2.0 (with ISF symbols — slower)"
        Invoke-Compose build app
    }
    "up" {
        Write-Header "Starting dashboard"
        Invoke-Compose up -d app
        Write-Host "  Dashboard : http://localhost:8010"
        Write-Host "  Health    : http://localhost:8010/api/health"
    }
    "down" {
        Write-Header "Stopping"
        Invoke-Compose down --remove-orphans
    }
    "logs" {
        Invoke-Compose logs -f app
    }
    "health" {
        Invoke-Compose exec app curl -s http://127.0.0.1:8010/api/health
        Write-Host ""
    }
    "test" {
        Write-Header "Running pytest inside container (baked-in package)"
        Invoke-Compose --profile test run --rm --no-deps test
    }
    "test-dev" {
        Write-Header "Running pytest against bind-mounted working tree"
        Invoke-Compose --profile dev run --rm --no-deps test-dev
    }
    "dev" {
        Write-Header "Dev shell (source bind-mounted, LLM stubbed by default)"
        Write-Host "  Mount: $RootDir -> /workspace"
        Write-Host "  Exit with 'exit' or Ctrl+D"
        Invoke-Compose --profile dev run --rm dev
    }
    "lab" {
        Write-Header "AIR-GAPPED lab shell (network_mode: none)"
        Write-Host "  samples -> /opt/neurotrace/lab/samples (ro)"
        Write-Host "  dumps   -> /opt/neurotrace/lab/dumps   (ro)"
        Write-Host "  out     -> /opt/neurotrace/lab/out     (rw)"
        Write-Host "  NO outbound network. Safe for live malware."
        Invoke-Compose --profile lab run --rm lab
    }
    "cli" {
        if (-not $Arg1) {
            Write-Header "CLI help"
            Invoke-Compose --profile cli run --rm nt-cli --help
        } else {
            Write-Header "CLI: $Arg1"
            Invoke-Compose --profile cli run --rm nt-cli $Arg1.Split(" ")
        }
    }
    "analyze" {
        if (-not $Arg1) {
            Write-Host "usage: .\scripts\lab.ps1 analyze <path-in-lab/dumps>"
            Write-Host "  e.g. copy a dump into lab\dumps\ then:"
            Write-Host "       .\scripts\lab.ps1 analyze Challenge_Win7SP1x64.raw"
            exit 1
        }
        Write-Header "Analyzing $Arg1 (inside container)"
        Invoke-Compose --profile lab run --rm lab python -m neurotrace.cli analyze "/opt/neurotrace/lab/dumps/$Arg1"
    }
    "shell" {
        Write-Header "Shell into running app container"
        Invoke-Compose exec app bash
    }
    "status" {
        Write-Header "Container status"
        Invoke-Compose ps -a
    }
    "clean" {
        Write-Header "Removing containers, volumes, image"
        Invoke-Compose down -v --remove-orphans
        docker rmi -f neurotrace:2.0 2>$null
        Write-Host "  Clean."
    }
    default {
        Write-Host @"
NEUROTRACE lab — malware-safe Docker workflow

  build         Build image (fast, no ISF symbols)
  build-full    Build image with ISF symbol pack
  up            Start dashboard on :8010
  down          Stop containers
  logs          Tail app logs
  health        Hit /api/health
  test          Run pytest inside the image
  test-dev      Run pytest against your working tree (no rebuild)
  dev           Interactive dev shell (source mounted)
  lab           AIR-GAPPED shell (no network) — use for real malware
  cli [args]    One-shot neurotrace CLI
  analyze FILE  Analyze a dump from lab/dumps (runs in air-gapped lab)
  shell         Bash into the running app container
  status        Show compose services
  clean         Wipe containers + volumes + image

Safety model:
  - Host never executes samples or dumps
  - lab/samples and lab/dumps are mounted :ro
  - lab profile uses network_mode: none
  - Reports land in lab/out or the named docker volumes
"@
    }
}
