#!/usr/bin/env python3
"""
SENTINEL — AI-Powered Cybersecurity & Vulnerability Intelligence Platform
Agent Engine v1.0 — Full Pipeline + AI Analysis + Memory Integration

Phase 1 (Foundation):
  - Staged pipeline with Stage enum state machine
  - Resumable scans via state.json
  - Full Finding schema (false_positive, user_verified, ai_chain_context, etc.)
  - Legal disclaimer enforcement per target
  - PII scrubbing stubs ready for privacy.py
  - stage_started / stage_complete events emitted to server

AI Backend priority (all free):
  1. Ollama  — local, zero cost, no rate limits. Install: https://ollama.com
               Run:  ollama pull mistral   (or llama3, gemma2, etc.)
   2. OpenRouter — Free tier access. Set OPENROUTER_API_KEY env var.
   4. None    — scan still runs; report uses raw tool descriptions only.

CHANGES in v2.0 (Phase 2/3 additions):
  - FIX: state.json renamed to scan_state.json (matches server.py resume detection)
  - FIX: SIGINT handler now writes scan_state.json with "interrupted" status
  - ADD: _run_stage tracks current stage globally for SIGINT handler
  - ADD: memory.py learning loop called after successful scan completion
  - ADD: save_finding checks FP registry before persisting (skips known FPs)

CHANGES in v1.0 (Phase 1 alignment):
  - ADD: Stage enum (VALIDATE, RECON, PROBE, CRAWL, FUZZ, SCAN, INJECT,
         SECRETS, CLOUD, PROTO, AI_ENRICH, REPORT) — matches architecture §4.1
  - ADD: state.json written to scan dir on every stage transition (resumable)
  - ADD: Legal disclaimer printed + acknowledged per target (§8.3)
  - ADD: false_positive, user_verified, user_notes columns in findings DB
  - ADD: ai_chain_context, ai_effort_to_fix, ai_bounty_value AI fields
  - ADD: url, parameter, method, request, response_excerpt finding fields
  - ADD: stage_started / stage_complete stdout markers (parsed by server.py)
  - ADD: Cerebras AI backend
  - ADD: ~/.sentinel/ as canonical data dir; scan dirs nested under scans/
  - FIX: Operator-precedence bug in cloud SSRF check (false positives on empty output)
  - FIX: urllib.parse imported at top level (was inside inner loop)
  - FIX: global_conn opened but never used — removed resource leak
  - FIX: run_nmap no longer double-writes via both -oN and output_file=
  - FIX: Input validation rejects invalid/dangerous target strings
  - FIX: AI rate-limiter now applies to Ollama too (prevent OOM on large scans)
  - FIX: SQLi detection covers more sqlmap output patterns
  - FIX: fuzz write_lines called once after all results collected (was overwriting)
  - FIX: SIGINT handler marks scan as interrupted in DB before exit
  - FIX: --ai-delay flag for manual AI throttle control
   - IMPROVE: All tool stderr now logged at DEBUG level, not silently swallowed
"""

import signal
import subprocess
import json
import os
import sys
import argparse
import shutil
import threading
import time
import re
import platform
import sqlite3
import hashlib
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime
from enum import Enum
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Any

# Forward references for AgentBrain
from tools import ToolRegistry, ToolResult
from ai import LLMProvider, LLMMessage


# ─────────────────────────────────────────────
# STAGE STATE MACHINE  (Architecture §4.1)
# ─────────────────────────────────────────────

class Stage(Enum):
    """
    Pipeline state machine:
    IDLE → VALIDATE → RECON → PROBE → CRAWL → FUZZ
                                                  │
         REPORT ← AI_ENRICH ← SCAN ← INJECT ←───┘
            │
            ▼
         COMPLETE / INTERRUPTED / ERROR

    Each stage transition is persisted to state.json so scans are resumable.
    """
    VALIDATE  = "validate"    # Target validation, scope check, auth
    RECON     = "recon"       # Subdomain enum, DNS, ASN
    PROBE     = "probe"       # Live host detection, tech fingerprint
    CRAWL     = "crawl"       # URL discovery, spidering, archive
    FUZZ      = "fuzz"        # Directory, param, vhost fuzzing
    PORTSCAN  = "portscan"    # Fast port discovery
    SCAN      = "scan"        # Nuclei, Jaeles, Wapiti
    INJECT    = "inject"      # XSS, SQLi, SSRF, SSTI, CMDi
    SECRETS   = "secrets"     # Credential and secret exposure
    CLOUD     = "cloud"       # S3, cloud metadata, IAM misconfig
    PROTO     = "proto"       # SSL/TLS, HTTP smuggling, WebSocket
    AI_ENRICH = "ai_enrich"   # AI explanations + PoC generation
    REPORT    = "report"      # Report generation + export

STAGE_ORDER = [
    Stage.VALIDATE, Stage.RECON, Stage.PROBE, Stage.CRAWL, Stage.FUZZ,
    Stage.PORTSCAN, Stage.SCAN, Stage.INJECT, Stage.SECRETS,
    Stage.CLOUD, Stage.PROTO, Stage.AI_ENRICH, Stage.REPORT,
]


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

VERSION = "2"

# SENTINEL canonical data directory (Architecture §5 / §13)
SENTINEL_DIR = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))
SENTINEL_SCANS_DIR = SENTINEL_DIR / "scans"

TOOL_GROUPS = {
    "core":         {"description": "Subdomain enum + live host probing",          "tools": ["subfinder", "httpx", "amass", "assetfinder", "dnsx", "massdns"]},
    "crawl":        {"description": "URL & parameter discovery",                   "tools": ["katana", "gospider", "waybackurls", "gau", "hakrawler"]},
    "fuzz":         {"description": "Directory, param & vhost fuzzing",            "tools": ["ffuf", "feroxbuster", "paramspider", "arjun"]},
    "scan":         {"description": "Vulnerability scanning",                      "tools": ["nuclei", "jaeles", "wapiti"]},
    "exploit_lite": {"description": "XSS, SQLi, SSRF, SSTI, open-redirect",       "tools": ["dalfox", "sqlmap", "nikto", "commix", "tplmap", "ssrfmap", "crlfuzz"]},
    "secrets":      {"description": "Secrets & credential exposure",               "tools": ["trufflehog", "gitleaks", "secretfinder"]},
    "portscan":     {"description": "Service / port discovery",                    "tools": ["nmap", "masscan", "rustscan"]},
    "cloud":        {"description": "Cloud & S3 misconfig",                        "tools": ["cloudfox", "s3scanner", "awscli"]},
    "cors_csp":     {"description": "CORS, CSP, header analysis",                  "tools": ["corscanner", "shcheck"]},
    "proto":        {"description": "Protocol-level: SSL, HTTP/2, WebSocket",      "tools": ["testssl", "h2csmuggler", "smuggler"]},
}

ALL_TOOLS = [t for g in TOOL_GROUPS.values() for t in g["tools"]]

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
    "unknown":  "❓",
}

# ─────────────────────────────────────────────
# CROSS-PLATFORM TOOL INSTALL MAP
# ─────────────────────────────────────────────

# Keys: platform short names used in TOOL_INSTALLS
#   "apt"    — Debian/Ubuntu/Kali  (sudo apt install -y ...)
#   "pacman" — Arch Linux          (sudo pacman -S --noconfirm ...)
#   "dnf"    — Fedora/RHEL         (sudo dnf install -y ...)
#   "brew"   — macOS               (brew install ...)
#   "scoop"  — Windows             (scoop install ...)
#   "choco"  — Windows             (choco install ...)
#   "go"     — any                 (go install ...@latest)
#   "pip"    — any                 (pip install ...)
#   "cargo"  — any                 (cargo install ...)

TOOL_INSTALLS: dict[str, dict[str, str]] = {
    # ── Recon / Subdomain ──
    "subfinder":   {"go": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    "assetfinder": {"go": "go install -v github.com/tomnomnom/assetfinder@latest"},
    "amass":       {"apt": "sudo apt install -y amass", "pacman": "sudo pacman -S --noconfirm amass",
                     "brew": "brew install amass", "go": "go install -v github.com/owasp-amass/amass/v4/...@master"},
    "dnsx":        {"apt": "sudo apt install -y dnsx", "go": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
    "httpx":       {"go": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    "gospider":    {"go": "go install -v github.com/jaeles-project/gospider@latest"},
    "hakrawler":   {"go": "go install -v github.com/hakluke/hakrawler@latest"},
    "subjack":     {"go": "go install -v github.com/haccer/subjack@latest"},

    # ── URL / Crawl ──
    "katana":      {"go": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"},
    "waybackurls": {"go": "go install -v github.com/tomnomnom/waybackurls@latest"},
    "gau":         {"go": "go install -v github.com/lc/gau/v2/cmd/gau@latest"},

    # ── Fuzzing ──
    "ffuf":         {"apt": "sudo apt install -y ffuf", "pacman": "sudo pacman -S --noconfirm ffuf",
                     "brew": "brew install ffuf", "go": "go install -v github.com/ffuf/ffuf/v2@latest"},
    "feroxbuster":  {"apt": "sudo apt install -y feroxbuster", "brew": "brew install feroxbuster",
                     "go": "go install -v github.com/epi052/feroxbuster@latest"},
    "arjun":        {"pip": "pip install arjun"},
    "paramspider":  {"pip": "pip install paramspider"},

    # ── Vulnerability Scanning ──
    "nuclei":  {"go": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                "brew": "brew install nuclei"},
    "nikto":   {"apt": "sudo apt install -y nikto", "pacman": "sudo pacman -S --noconfirm nikto",
                "brew": "brew install nikto"},
    "wapiti":  {"pip": "pip install wapiti3", "brew": "brew install wapiti"},
    "corscanner": {"pip": "pip install corscanner"},
    "shcheck":    {"pip": "pip install shcheck"},

    # ── Injection ──
    "dalfox":   {"go": "go install -v github.com/hahwul/dalfox/v2@latest"},
    "sqlmap":   {"apt": "sudo apt install -y sqlmap", "pacman": "sudo pacman -S --noconfirm sqlmap",
                 "brew": "brew install sqlmap", "pip": "pip install sqlmap"},
    "xsstrike": {"pip": "pip install xsstrike"},
    "commix":   {"pip": "pip install commix"},
    "ssrfmap":  {"pip": "pip install ssrfmap"},
    "crlfuzz":  {"go": "go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"},
    "smuggler": {"pip": "pip install smuggler"},
    "h2csmuggler": {"pip": "pip install h2csmuggler"},

    # ── Secrets ──
    "trufflehog":   {"go": "go install -v github.com/trufflesecurity/trufflehog/v3@latest",
                     "brew": "brew install trufflehog"},
    "gitleaks":     {"go": "go install -v github.com/gitleaks/gitleaks/v8@latest",
                     "apt": "sudo apt install -y gitleaks", "brew": "brew install gitleaks"},
    "secretfinder": {"pip": "pip install secretfinder"},

    # ── Port Scanning ──
    "nmap":     {"apt": "sudo apt install -y nmap", "pacman": "sudo pacman -S --noconfirm nmap",
                 "brew": "brew install nmap", "scoop": "scoop install nmap"},
    "masscan":  {"apt": "sudo apt install -y masscan", "brew": "brew install masscan"},
    "rustscan": {"cargo": "cargo install rustscan", "brew": "brew install rustscan",
                 "snap": "sudo snap install rustscan"},

    # ── Technology / Protocol ──
    "whatweb":  {"apt": "sudo apt install -y whatweb", "brew": "brew install whatweb"},
    "wafw00f":  {"apt": "sudo apt install -y wafw00f", "brew": "brew install wafw00f",
                 "pip": "pip install wafw00f"},
    "testssl":  {"apt": "sudo apt install -y testssl.sh", "pacman": "sudo pacman -S --noconfirm testssl.sh",
                 "brew": "brew install testssl"},
    "sslscan":  {"apt": "sudo apt install -y sslscan", "brew": "brew install sslscan"},

    # ── Cloud ──
    "s3scanner": {"pip": "pip install s3scanner"},
    "cloudfox":  {"go": "go install -v github.com/BishopFox/cloudfox@latest"},
}

# Map from platform.system() output → preferred install keys
_PLATFORM_TO_KEYS: dict[str, list[str]] = {
    "Linux":   ["apt", "pacman", "dnf", "snap"],
    "Darwin":  ["brew"],
    "Windows": ["scoop", "choco"],
}

_UNIVERSAL_KEYS = ["go", "pip", "cargo", "snap"]


def detect_platform_install_keys() -> list[str]:
    """Return ordered list of install method keys for current platform."""
    os_name = platform.system()
    plat_keys = _PLATFORM_TO_KEYS.get(os_name, [])
    return plat_keys + _UNIVERSAL_KEYS


def get_install_command(tool_name: str) -> str | None:
    """Get the best install command for a tool on this platform, or None."""
    installs = TOOL_INSTALLS.get(tool_name)
    if not installs:
        return None
    for key in detect_platform_install_keys():
        if key in installs:
            return installs[key]
    return None


def suggest_installable(tool_name: str) -> str:
    """Suggest how to install a missing tool."""
    cmd = get_install_command(tool_name)
    if cmd:
        return f"Install with: {cmd}"
    alt_fmt = ", ".join(TOOL_INSTALLS.get(tool_name, {}).values())
    if alt_fmt:
        return f"Install options: {alt_fmt}"
    # Suggest checking official docs or using alternatives
    return f"See {tool_name} docs for install instructions, or try alternatives"


def check_install_capabilities() -> list[str]:
    """Return list of available install methods on this system."""
    available = []
    if shutil.which("apt"):
        available.append("apt")
    if shutil.which("apt-get"):
        available.append("apt")
    if shutil.which("pacman"):
        available.append("pacman")
    if shutil.which("dnf"):
        available.append("dnf")
    if shutil.which("brew"):
        available.append("brew")
    if shutil.which("scoop"):
        available.append("scoop")
    if shutil.which("choco") or shutil.which("chocolatey"):
        available.append("choco")
    if shutil.which("go"):
        available.append("go")
    if shutil.which("pip") or shutil.which("pip3"):
        available.append("pip")
    if shutil.which("cargo"):
        available.append("cargo")
    if shutil.which("snap"):
        available.append("snap")
    return available

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]

SEVERITY_SCORE = {
    "critical": 10.0,
    "high":     7.5,
    "medium":   5.0,
    "low":      2.5,
    "info":     0.5,
    "unknown":  1.0,
}

VULN_CATEGORIES = {
    "injection":    ["sql", "sqli", "xss", "ssti", "xpath", "ldap", "nosql", "rce", "command", "injection"],
    "auth":         ["auth", "bypass", "broken-auth", "session", "oauth", "jwt", "privilege", "idor"],
    "exposure":     ["exposure", "disclosure", "leak", "config", "debug", "backup", "env", "secret"],
    "misconfig":    ["misconfig", "default", "cors", "header", "csp", "clickjack", "open-redirect"],
    "ssrf_xxe":     ["ssrf", "xxe", "request-forgery"],
    "traversal":    ["traversal", "lfi", "rfi", "path", "directory"],
    "component":    ["cve-", "outdated", "vulnerable-version", "dependency"],
}

# ─────────────────────────────────────────────
# ANSI COLORS
# ─────────────────────────────────────────────

C = {
    "red":     "\033[91m",
    "green":   "\033[92m",
    "yellow":  "\033[93m",
    "blue":    "\033[94m",
    "magenta": "\033[95m",
    "cyan":    "\033[96m",
    "white":   "\033[97m",
    "gray":    "\033[90m",
    "bold":    "\033[1m",
    "dim":     "\033[2m",
    "reset":   "\033[0m",
}

ICONS = {
    "INFO":    ("🔹", C["blue"]),
    "SUCCESS": ("✅", C["green"]),
    "WARN":    ("⚠️ ", C["yellow"]),
    "ERROR":   ("❌", C["red"]),
    "STEP":    ("🔷", C["magenta"]),
    "FIND":    ("🐛", C["red"]),
    "SCAN":    ("🔍", C["cyan"]),
    "RECON":   ("📡", C["blue"]),
    "FUZZ":    ("🎯", C["yellow"]),
    "REPORT":  ("📋", C["green"]),
    "AI":      ("🤖", C["magenta"]),
}

OUTPUT_DIR = Path("bb_output")
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")

_spinner_active = False
_spinner_thread = None
_IS_TTY = sys.stdout.isatty()

# ─────────────────────────────────────────────
# SIGNAL HANDLING — graceful SIGINT
# ─────────────────────────────────────────────

_shutdown_requested = False
_scan_conn: "sqlite3.Connection | None" = None
_scan_id_global: "int | None" = None
_run_dir_global: "Path | None" = None
_current_stage_global: "str | None" = None
_completed_stages_global: "list | None" = None

try:
    import memory as mem_mod
    _memory_available = True
except ImportError:
    mem_mod = None
    _memory_available = False


def _sigint_handler(sig, frame):
    global _shutdown_requested
    _shutdown_requested = True
    log("WARN", "Interrupt received — finishing current step and saving state…")
    # Mark scan as interrupted in DB
    if _scan_conn and _scan_id_global:
        try:
            _scan_conn.execute(
                "UPDATE scans SET finished_at=?, status=? WHERE id=?",
                (datetime.now().isoformat(), "interrupted", _scan_id_global),
            )
            _scan_conn.commit()
        except Exception:
            pass
    # Write scan_state.json so server.py _check_resume can detect it
    if _run_dir_global:
        try:
            import json as _json
            state = {
                "current_stage": _current_stage_global or "unknown",
                "completed_stages": _completed_stages_global or [],
                "status": "interrupted",
                "updated_at": datetime.now().isoformat(),
            }
            (_run_dir_global / "scan_state.json").write_text(_json.dumps(state, indent=2))
        except Exception:
            pass
    sys.exit(130)


signal.signal(signal.SIGINT, _sigint_handler)


# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────

def banner():
    print(f"""
{C['cyan']}╔══════════════════════════════════════════════════════════════╗
║  {C['bold']}{C['white']}  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗{C['reset']}{C['cyan']} ║
║  {C['bold']}{C['white']}  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║{C['reset']}{C['cyan']} ║
║  {C['bold']}{C['white']}  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║{C['reset']}{C['cyan']} ║
║  {C['bold']}{C['white']}  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║{C['reset']}{C['cyan']} ║
║  {C['bold']}{C['white']}  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗{C['reset']}{C['cyan']}║
║  {C['bold']}{C['white']}  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝{C['reset']}{C['cyan']}║
║                                                              ║
║    {C['bold']}{C['yellow']} SENTINEL v{VERSION} — Cybersecurity Intelligence Platform{C['reset']}{C['cyan']}     ║
║    {C['dim']}{C['white']} "The bug bounty platform that learns with you."         {C['reset']}{C['cyan']}   ║
║    {C['dim']}{C['white']} 100% Local · Zero Telemetry · Red Team Ready             {C['reset']}{C['cyan']}   ║
╚══════════════════════════════════════════════════════════════╝{C['reset']}
""")


def log(level: str, msg: str, indent: int = 0):
    icon, color = ICONS.get(level, ("•", ""))
    prefix = "  " * indent
    ts = f"{C['dim']}{C['gray']}{datetime.now().strftime('%H:%M:%S')}{C['reset']}"
    print(f"{ts} {prefix}{color}{icon} {msg}{C['reset']}", flush=True)


def section(title: str, step: str = ""):
    step_str = f"  [{step}]" if step else ""
    print(f"\n{C['cyan']}{'─'*62}{C['reset']}", flush=True)
    print(f"{C['bold']}{C['white']}{step_str} {title}{C['reset']}", flush=True)
    print(f"{C['cyan']}{'─'*62}{C['reset']}", flush=True)


_ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub('', text)


def spinner_start(msg: str):
    global _spinner_active, _spinner_thread
    if not _IS_TTY:
        log("INFO", msg, indent=1)
        return
    _spinner_active = True
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    def _spin():
        i = 0
        while _spinner_active:
            print(f"\r  {C['cyan']}{frames[i % len(frames)]}{C['reset']}  {C['dim']}{msg}{C['reset']}", end="", flush=True)
            time.sleep(0.1)
            i += 1
    _spinner_thread = threading.Thread(target=_spin, daemon=True)
    _spinner_thread.start()


def spinner_stop(result_msg: str = "", ok: bool = True):
    global _spinner_active
    if not _IS_TTY:
        if result_msg:
            log("SUCCESS" if ok else "ERROR", result_msg, indent=1)
        return
    _spinner_active = False
    if _spinner_thread:
        _spinner_thread.join(timeout=0.5)
    color = C["green"] if ok else C["red"]
    if result_msg:
        print(f"\r  {color}{'✓' if ok else '✗'}{C['reset']}  {result_msg}                    ", flush=True)
    else:
        print(flush=True)


# ─────────────────────────────────────────────
# LEGAL DISCLAIMER  (Architecture §8.3)
# Displayed on every scan start. Cannot be globally disabled.
# ─────────────────────────────────────────────

_DISCLAIMER_CACHE_FILE = SENTINEL_DIR / "acknowledged_targets.json"


def _load_acknowledged_targets() -> set:
    try:
        if _DISCLAIMER_CACHE_FILE.exists():
            return set(json.loads(_DISCLAIMER_CACHE_FILE.read_text()))
    except Exception:
        pass
    return set()


def _save_acknowledged_target(target: str):
    SENTINEL_DIR.mkdir(parents=True, exist_ok=True)
    acked = _load_acknowledged_targets()
    acked.add(target)
    _DISCLAIMER_CACHE_FILE.write_text(json.dumps(sorted(acked)))


def enforce_legal_disclaimer(target: str, auto_accept: bool = False) -> bool:
    """
    Show legal reminder and require acknowledgement before scanning.
    Returns True if user confirmed (or auto_accept=True for CI/headless mode).
    Per architecture §8.3: this cannot be globally disabled, only suppressed
    after first acknowledgement PER target (not globally).
    """
    acked = _load_acknowledged_targets()
    if target in acked:
        log("INFO", f"⚖️  Legal reminder acknowledged for {target} (cached).", indent=0)
        return True

    print(f"""
{C['yellow']}{'─'*64}{C['reset']}
{C['bold']}{C['yellow']}  ⚖️  LEGAL REMINDER{C['reset']}

  Only scan targets you have {C['bold']}explicit written authorization{C['reset']} to test.
  Unauthorized scanning is {C['red']}illegal{C['reset']} in most jurisdictions.

  Target: {C['cyan']}{target}{C['reset']}
{C['yellow']}{'─'*64}{C['reset']}""")

    if auto_accept:
        log("INFO", "Auto-accepting legal disclaimer (headless/CI mode).", indent=0)
        _save_acknowledged_target(target)
        return True

    try:
        resp = input(f"  {C['bold']}Do you have written authorization to scan {target}? [y/N]: {C['reset']}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        resp = "n"

    if resp in ("y", "yes"):
        _save_acknowledged_target(target)
        log("SUCCESS", "Authorization confirmed. Starting scan.", indent=0)
        return True
    else:
        log("ERROR", "Scan aborted — no authorization confirmed.", indent=0)
        return False


# ─────────────────────────────────────────────
# SCAN STATE MACHINE  (Architecture §4.1)
# Persists stage to state.json for resumable scans
# ─────────────────────────────────────────────

def _write_state(run_dir: Path, stage: Stage, completed_stages: list, status: str = "running"):
    """Write current scan state to state.json for resumability."""
    state = {
        "current_stage": stage.value,
        "completed_stages": [s.value for s in completed_stages],
        "status": status,
        "updated_at": datetime.now().isoformat(),
    }
    try:
        (run_dir / "scan_state.json").write_text(json.dumps(state, indent=2))
    except Exception as e:
        log("WARN", f"Failed to write state.json: {e}", indent=1)


def _read_state(run_dir: Path) -> dict:
    """Read state.json for resume logic."""
    state_file = run_dir / "scan_state.json"
    if state_file.exists():
        try:
            return json.loads(state_file.read_text())
        except Exception:
            pass
    return {}


def emit_stage_started(stage: Stage):
    """Emit a marker line that server.py parses into a stage_started WS message."""
    print(f"SENTINEL:STAGE_STARTED:{stage.value}", flush=True)
    log("STEP", f"Stage: {stage.value.upper()}", indent=0)


def emit_stage_complete(stage: Stage, duration_sec: float):
    """Emit a marker line that server.py parses into a stage_complete WS message."""
    print(f"SENTINEL:STAGE_COMPLETE:{stage.value}:{duration_sec:.1f}", flush=True)
    log("SUCCESS", f"Stage {stage.value.upper()} complete ({duration_sec:.1f}s)", indent=0)




# ─────────────────────────────────────────────
# INPUT VALIDATION
# ─────────────────────────────────────────────

# FIX: Validate target to reject shell-dangerous chars and obvious non-domains
_VALID_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def validate_target(raw: str) -> str:
    """Strip scheme/path, validate domain chars. Raises ValueError on bad input."""
    target = raw.strip().lower()
    target = re.sub(r"^https?://", "", target)
    target = target.split("/")[0]   # remove any path
    target = target.split("?")[0]   # remove query string
    target = target.split("#")[0]   # remove fragment
    if not target:
        raise ValueError("Target domain cannot be empty")
    if len(target) > 253:
        raise ValueError("Target domain too long (>253 chars)")
    if not _VALID_DOMAIN_RE.match(target):
        raise ValueError(
            f"'{target}' does not look like a valid domain. "
            "Expected format: example.com"
        )
    return target


# ─────────────────────────────────────────────
# TOOL MANAGEMENT
# ─────────────────────────────────────────────

def check_tools(required_groups: list | None = None) -> dict:
    section("Tool Availability Check")
    available = {}
    groups = required_groups or list(TOOL_GROUPS.keys())
    for group in groups:
        tools = TOOL_GROUPS.get(group, {}).get("tools", [])
        desc  = TOOL_GROUPS.get(group, {}).get("description", "")
        print(f"\n  {C['bold']}{C['yellow']}{group.upper()}{C['reset']}  {C['dim']}{desc}{C['reset']}")
        for tool in tools:
            found = shutil.which(tool) is not None
            available[tool] = found
            status = f"{C['green']}✓ found{C['reset']}" if found else f"{C['red']}✗ missing{C['reset']}"
            print(f"    {status}  {tool}")
    missing = [t for t, v in available.items() if not v]
    if missing:
        print(f"\n  {C['yellow']}⚠️  Missing tools:{C['reset']} {', '.join(missing)}")
        print(f"  {C['dim']}Agent will skip steps requiring unavailable tools.{C['reset']}")
    return available


def require_tool(tool: str, available: dict) -> bool:
    if not available.get(tool, False):
        log("WARN", f"Skipping: {tool} not installed", indent=1)
        return False
    return True


# ─────────────────────────────────────────────
# TOOL HEALTH MONITORING  (Roadmap Phase 1)
# ─────────────────────────────────────────────

def _get_tool_version(tool: str) -> str:
    """Try common version flags and return first non-empty line, or empty string."""
    for flag in ("--version", "-version", "-V", "version"):
        try:
            r = subprocess.run(
                [tool, flag], capture_output=True, text=True, timeout=5
            )
            out = (r.stdout + r.stderr).strip()
            if out:
                return out.splitlines()[0][:120]
        except Exception:
            pass
    return ""


def record_tool_health(conn: sqlite3.Connection, scan_id: int, available: dict):
    """
    Phase 1: snapshot tool installation status + versions into tool_health.
    Called once at scan start after check_tools().
    """
    now = datetime.now().isoformat()
    for tool, installed in available.items():
        version = _get_tool_version(tool) if installed else ""
        conn.execute("""
            INSERT INTO tool_health
                (scan_id, tool, installed, version, checked_at,
                 total_runs, crashes, timeouts, total_runtime_sec,
                 findings_attributed, health_score)
            VALUES (?,?,?,?,?,0,0,0,0.0,0,?)
        """, (
            scan_id, tool, int(installed), version, now,
            100 if installed else 0,
        ))
    conn.commit()
    log("INFO", f"Tool health snapshot: {sum(available.values())}/{len(available)} tools installed", indent=1)


def update_tool_run_stat(
    conn: sqlite3.Connection,
    scan_id: int,
    tool: str,
    *,
    crashed: bool = False,
    timed_out: bool = False,
    runtime_sec: float = 0.0,
):
    """
    Phase 1: Update runtime stats for a tool after each run_cmd call.
    health_score degrades: -10 per crash, -5 per timeout, floor 0.
    """
    row = conn.execute(
        "SELECT id, health_score, crashes, timeouts, total_runs, total_runtime_sec "
        "FROM tool_health WHERE scan_id=? AND tool=?",
        (scan_id, tool),
    ).fetchone()
    if not row:
        return  # tool not tracked for this scan — ignore
    new_score  = row["health_score"] - (10 if crashed else 0) - (5 if timed_out else 0)
    new_score  = max(0, new_score)
    conn.execute("""
        UPDATE tool_health SET
            total_runs       = total_runs + 1,
            crashes          = crashes + ?,
            timeouts         = timeouts + ?,
            total_runtime_sec = total_runtime_sec + ?,
            health_score     = ?
        WHERE id = ?
    """, (
        int(crashed), int(timed_out), runtime_sec, new_score, row["id"]
    ))
    conn.commit()


def attribute_findings_to_tool(
    conn: sqlite3.Connection, scan_id: int, tool: str, count: int
):
    """Phase 1: Record how many findings came from this tool."""
    conn.execute("""
        UPDATE tool_health SET findings_attributed = findings_attributed + ?
        WHERE scan_id=? AND tool=?
    """, (count, scan_id, tool))
    conn.commit()


def get_tool_health_report(conn: sqlite3.Connection, scan_id: int) -> list:
    """Return tool health rows for this scan, ordered by health score ascending."""
    rows = conn.execute("""
        SELECT tool, installed, version, health_score,
               total_runs, crashes, timeouts,
               total_runtime_sec, findings_attributed
        FROM tool_health
        WHERE scan_id=?
        ORDER BY health_score ASC, tool ASC
    """, (scan_id,)).fetchall()
    return [dict(r) for r in rows]


def run_cmd(cmd: list, output_file: Path | None = None, timeout: int = 600,
            label: str = "", append: bool = False,
            _health_conn: "sqlite3.Connection | None" = None,
            _health_scan_id: "int | None" = None) -> str:
    """
    Run a subprocess and return stdout.
    - append: if True and output_file exists, append rather than overwrite.
    - Stderr is logged at WARN level (not silently discarded).
    - _health_conn/_health_scan_id: if provided, updates tool_health stats.
    """
    label = label or " ".join(cmd[:2])
    tool  = cmd[0] if cmd else ""
    log("INFO", f"→ {C['dim']}{' '.join(cmd)[:120]}{C['reset']}", indent=1)
    t0 = time.time()
    crashed = False
    timed_out = False
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        stdout = _strip_ansi(result.stdout).strip()
        if output_file and stdout:
            if append and output_file.exists():
                with open(output_file, "a") as f:
                    f.write("\n" + stdout)
            else:
                output_file.write_text(stdout)
        # FIX: Always log stderr so tool errors are visible, not silently swallowed
        if result.stderr and result.stderr.strip():
            for errline in result.stderr.strip().splitlines()[:5]:
                stripped = errline.strip()
                # Skip ASCII art banners (amass, httpx, etc. print to stderr)
                if stripped and not stripped[0].isprintable():
                    continue
                if re.search(r'^[\s\]\[.,:;@#&+*!~=\-○│░/\\]{10,}', stripped):
                    continue
                # Skip benign tool chatter (config not found, using defaults, info logs)
                if re.search(r'(error reading config|config file .* not found|using default config|level=warning|"level":"info|SyntaxWarning|DeprecationWarning)', stripped, re.I):
                    continue
                log("WARN", f"[{label}] stderr: {errline[:200]}", indent=2)
        if result.returncode not in (0, 1) and result.returncode is not None:
            log("WARN", f"[{label}] exit code: {result.returncode}", indent=2)
            crashed = True
        runtime = time.time() - t0
        if _health_conn and _health_scan_id and tool:
            update_tool_run_stat(
                _health_conn, _health_scan_id, tool,
                crashed=crashed, timed_out=False, runtime_sec=runtime,
            )
        return stdout
    except subprocess.TimeoutExpired:
        log("ERROR", f"Timeout ({timeout}s): {label}", indent=1)
        runtime = time.time() - t0
        if _health_conn and _health_scan_id and tool:
            update_tool_run_stat(
                _health_conn, _health_scan_id, tool,
                crashed=False, timed_out=True, runtime_sec=runtime,
            )
        return ""
    except FileNotFoundError as e:
        log("ERROR", f"Not found: {e}", indent=1)
        return ""


def read_lines(path: Path) -> list:
    if path and path.exists():
        return [l for l in path.read_text().splitlines() if l.strip()]
    return []


def write_lines(path: Path, lines: list):
    path.write_text("\n".join(lines))


# ─────────────────────────────────────────────
# DATABASE (SQLite — persistent findings store)
# ─────────────────────────────────────────────

def init_db(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target      TEXT NOT NULL,
            run_id      TEXT NOT NULL,
            started_at  TEXT NOT NULL,
            finished_at TEXT,
            status      TEXT DEFAULT 'running'
        );

        -- Full Finding schema per Architecture §15
        CREATE TABLE IF NOT EXISTS findings (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id             INTEGER REFERENCES scans(id),
            finding_hash        TEXT UNIQUE,
            source              TEXT,                     -- tool that found this
            severity            TEXT,                     -- critical/high/medium/low/info/unknown
            name                TEXT,
            template_id         TEXT,
            host                TEXT,
            url                 TEXT,                     -- full URL if available
            matched_at          TEXT,
            parameter           TEXT,                     -- vulnerable parameter
            method              TEXT,                     -- HTTP method
            request             TEXT,                     -- raw HTTP request
            response_excerpt    TEXT,                     -- first 500 chars of response
            cvss_score          REAL,
            cvss_vector         TEXT,
            cve_ids             TEXT,                     -- JSON array
            cwe_ids             TEXT,                     -- JSON array
            raw_description     TEXT,
            remediation         TEXT,
            vuln_references     TEXT,                     -- JSON array
            category            TEXT,
            confidence          INTEGER DEFAULT 50,       -- 0-100
            false_positive      INTEGER DEFAULT 0,        -- bool: user marked as FP
            user_verified       INTEGER DEFAULT 0,        -- bool: user confirmed real
            user_notes          TEXT,                     -- user annotations
            -- AI fields
            ai_explanation      TEXT,
            ai_impact           TEXT,
            ai_poc              TEXT,
            ai_remediation      TEXT,
            ai_chain_context    TEXT,                     -- attack chain narrative
            ai_effort_to_fix    TEXT,                     -- e.g. "low / 1 hour"
            ai_bounty_value     TEXT,                     -- e.g. "$500-2000"
            -- Meta
            first_seen          TEXT,
            last_seen           TEXT,
            raw_json            TEXT
        );

        CREATE TABLE IF NOT EXISTS scan_stats (
            scan_id         INTEGER REFERENCES scans(id) UNIQUE,
            subdomains      INTEGER DEFAULT 0,
            live_hosts      INTEGER DEFAULT 0,
            urls            INTEGER DEFAULT 0,
            fuzz_paths      INTEGER DEFAULT 0,
            risk_score      INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_findings_scan    ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_sev     ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_findings_hash    ON findings(finding_hash);
        CREATE INDEX IF NOT EXISTS idx_findings_fp      ON findings(false_positive);
        CREATE INDEX IF NOT EXISTS idx_findings_uv      ON findings(user_verified);

        -- Roadmap Phase 1: Tool Health Monitoring
        CREATE TABLE IF NOT EXISTS tool_health (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id         INTEGER REFERENCES scans(id),
            tool            TEXT NOT NULL,
            installed       INTEGER DEFAULT 0,   -- bool
            version         TEXT,                -- version string from --version
            checked_at      TEXT NOT NULL,
            -- Runtime tracking (updated by run_cmd wrapper)
            total_runs      INTEGER DEFAULT 0,
            crashes         INTEGER DEFAULT 0,   -- non-zero exit AND non-1
            timeouts        INTEGER DEFAULT 0,
            total_runtime_sec REAL DEFAULT 0.0,
            findings_attributed INTEGER DEFAULT 0,  -- findings from this tool
            health_score    INTEGER DEFAULT 100  -- 0-100, degraded by crashes/timeouts
        );

        CREATE INDEX IF NOT EXISTS idx_tool_health_scan ON tool_health(scan_id);
        CREATE INDEX IF NOT EXISTS idx_tool_health_tool ON tool_health(tool);
    """)
    conn.commit()
    return conn


def finding_hash(source: str, name: str, host: str, matched_at: str) -> str:
    raw = f"{source}|{name}|{host}|{matched_at}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def upsert_finding(conn: sqlite3.Connection, scan_id: int, finding: dict) -> int | None:
    if _memory_available and mem_mod is not None and isinstance(finding, dict):
        try:
            if mem_mod.is_known_fp(finding):
                log("INFO", f"Skipping known FP: {finding.get('name','')} on {finding.get('host','')}", indent=2)
                return None
        except Exception:
            log("WARN", "Memory FP check failed (non-fatal)", indent=2)

    fhash = finding_hash(
        finding.get("source", ""),
        finding.get("name", ""),
        finding.get("host", ""),
        finding.get("matched_at", ""),
    )
    now = datetime.now().isoformat()

    existing = conn.execute("SELECT id FROM findings WHERE finding_hash=?", (fhash,)).fetchone()
    if existing:
        conn.execute("UPDATE findings SET last_seen=?, scan_id=? WHERE finding_hash=?",
                     (now, scan_id, fhash))
        conn.commit()
        return existing["id"]

    try:
        cur = conn.execute("""
            INSERT INTO findings (
                scan_id, finding_hash, source, severity, name, template_id,
                host, url, matched_at, parameter, method, request, response_excerpt,
                cvss_score, cvss_vector, cve_ids, cwe_ids,
                raw_description, remediation, vuln_references, category,
                confidence, false_positive, user_verified,
                first_seen, last_seen, raw_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            scan_id,
            fhash,
            finding.get("source", "unknown"),
            finding.get("severity", "unknown"),
            finding.get("name", ""),
            finding.get("template_id", ""),
            finding.get("host", ""),
            finding.get("url", ""),
            finding.get("matched_at", ""),
            finding.get("parameter", ""),
            finding.get("method", ""),
            finding.get("request", ""),
            finding.get("response_excerpt", ""),
            finding.get("cvss_score"),
            finding.get("cvss_vector", ""),
            json.dumps(finding.get("cve_ids", [])),
            json.dumps(finding.get("cwe_ids", [])),
            finding.get("raw_description", ""),
            finding.get("remediation", ""),
            json.dumps(finding.get("references", [])),
            finding.get("category", "other"),
            finding.get("confidence", 50),
            int(finding.get("false_positive", False)),
            int(finding.get("user_verified", False)),
            now, now,
            finding.get("raw_json", ""),
        ))
        conn.commit()
        return cur.lastrowid
    except Exception as e:
        log("ERROR", f"DB insert failed: {e}", indent=2)
        return None


# ─────────────────────────────────────────────
# AI INTEGRATION  (100% FREE — no paid API needed)
# ─────────────────────────────────────────────

OLLAMA_BASE_URL  = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL     = os.environ.get("OLLAMA_MODEL", "mistral")

OPENROUTER_API_KEY   = os.environ.get("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL     = os.environ.get("OPENROUTER_MODEL", "openrouter/free")
OPENROUTER_API_BASE  = "https://openrouter.ai/api/v1/chat/completions"

OPENCODE_API_KEY     = os.environ.get("OPENCODE_API_KEY", "")
OPENCODE_MODEL       = os.environ.get("OPENCODE_MODEL", "deepseek-v4-flash-free")
OPENCODE_MODELS      = [
    "deepseek-v4-flash-free",
    "minimax-m3-free",
    "mimo-v2.5-free",
    "nemotron-3-ultra-free",
    "nemotron-3-super-free",
    "qwen3.6-plus-free",
    "north-mini-code-free",
]
OPENCODE_API_BASE    = "https://opencode.ai/zen/v1/chat/completions"

CEREBRAS_API_KEY     = os.environ.get("CEREBRAS_API_KEY", "")
CEREBRAS_MODEL       = os.environ.get("CEREBRAS_MODEL", "llama3.3-70b")
CEREBRAS_MODELS      = [
    "llama3.3-70b",
    "llama3.1-8b",
    "gpt-oss-120b",
]
CEREBRAS_API_BASE    = "https://api.cerebras.ai/v1/chat/completions"

AI_AVAILABLE     = False
AI_BACKEND       = "none"
AI_BACKEND_LABEL = "None"
AI_MODEL         = "none"

# AI_DELAY controls inter-call sleep (overridden per-backend by detect_ai_backend)
# Default: 0s — will be reconfigured once backend is detected
AI_DELAY         = 0.0

_OLLAMA_RESOLVED_MODEL: str | None = None

# ── Backend cascade: ordered list of (backend_name, label) to try in sequence
# when the primary backend is exhausted or fails. Populated by detect_ai_backend().
_AI_FALLBACK_BACKENDS: list = []   # list of dicts: {backend, label, model}
_AI_BACKEND_EXHAUSTED: set  = set()   # backends that have hit hard quota/rate limits

# ── Request deduplication: cache results by prompt hash so identical prompts
# across retries / re-scans never hit the API twice in the same process run.
_AI_CALL_CACHE: dict = {}   # prompt_hash → result string


class _BackendExhausted(Exception):
    """
    Raised by backend call functions when the backend is rate-limited,
    quota-exhausted, or otherwise unable to serve any more requests.
    Replaces the fragile '__BACKEND_EXHAUSTED__' string sentinel so that a
    model legitimately returning that text can never be misinterpreted.
    """
    pass


def detect_ai_backend() -> tuple[bool, str, str]:
    """
    Detect available AI backends and populate _AI_FALLBACK_BACKENDS for cascade.
    Priority: Ollama (local, free) → OpenRouter → Cerebras → OpenCode.
    All available backends are registered; if the primary hits quota the scan
    automatically falls through to the next one.
    """
    global _OLLAMA_RESOLVED_MODEL, _AI_FALLBACK_BACKENDS
    _AI_FALLBACK_BACKENDS = []   # reset on each call

    primary_backend = "none"
    primary_label   = "None"
    primary_ok      = False

    # 1. Try Ollama (local)
    try:
        req = urllib.request.Request(f"{OLLAMA_BASE_URL}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
            models = [m["name"] for m in data.get("models", [])]
            preferred = OLLAMA_MODEL.split(":")[0]
            match = next((m for m in models if preferred in m), None)
            if match:
                _OLLAMA_RESOLVED_MODEL = match
                label = f"Ollama ({match})"
                log("SUCCESS", f"AI backend: {label} — local, free, no limits")
                primary_backend, primary_label, primary_ok = "ollama", label, True
            elif models:
                _OLLAMA_RESOLVED_MODEL = models[0]
                label = f"Ollama ({models[0]})"
                log("SUCCESS", f"AI backend: {label} — local model auto-selected")
                log("WARN", f"Preferred '{OLLAMA_MODEL}' not found. Using '{models[0]}'. Pull: ollama pull {OLLAMA_MODEL}", indent=1)
                primary_backend, primary_label, primary_ok = "ollama", label, True
            else:
                log("WARN", "Ollama running but no models pulled. Run: ollama pull mistral", indent=1)
    except Exception:
        pass

    # 2. OpenRouter (free models available)
    if OPENROUTER_API_KEY:
        label = f"OpenRouter (multi-model free tier)"
        if not primary_ok:
            log("SUCCESS", f"AI backend: {label}")
            primary_backend, primary_label, primary_ok = "openrouter", label, True
        else:
            _AI_FALLBACK_BACKENDS.append({"backend": "openrouter", "label": label})
            log("INFO", f"AI fallback registered: {label}", indent=1)

    # 5. Cerebras (fastest inference, OpenAI-compatible, 1M tok/day free)
    if CEREBRAS_API_KEY:
        label = f"Cerebras ({CEREBRAS_MODEL} — fastest, free)"
        if not primary_ok:
            log("SUCCESS", f"AI backend: {label}")
            primary_backend, primary_label, primary_ok = "cerebras", label, True
        else:
            _AI_FALLBACK_BACKENDS.append({"backend": "cerebras", "label": label})
            log("INFO", f"AI fallback registered: {label}", indent=1)

    # 6. OpenCode Zen — requires API key (even free models need auth)
    if OPENCODE_API_KEY:
        label = f"OpenCode Zen ({OPENCODE_MODEL} — free)"
        if not primary_ok:
            log("SUCCESS", f"AI backend: {label}")
            primary_backend, primary_label, primary_ok = "opencode", label, True
        else:
            _AI_FALLBACK_BACKENDS.append({"backend": "opencode", "label": label})
            log("INFO", f"AI fallback registered: {label}", indent=1)

    if not primary_ok:
        log("WARN", "No AI backend found. Report will use raw tool descriptions.")
        log("WARN", "→ For local AI:  install Ollama (https://ollama.com) + run: ollama pull mistral", indent=1)
        log("WARN", "→ For cloud AI:  export CEREBRAS_API_KEY=... (free at cloud.cerebras.ai)", indent=1)

        log("WARN", "→ For cloud AI:  export OPENCODE_API_KEY=... (free at opencode.ai/zen)", indent=1)

    if _AI_FALLBACK_BACKENDS:
        log("INFO", f"Backend cascade enabled: {len(_AI_FALLBACK_BACKENDS)} fallback(s) registered", indent=0)

    # Configure the global rate limiter for the active backend
    if primary_ok:
        _configure_rate_limiter(primary_backend)

    return primary_ok, primary_backend, primary_label


def _call_ollama(system: str, user: str) -> str:
    model = _OLLAMA_RESOLVED_MODEL or OLLAMA_MODEL

    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 1200,
        },
    }).encode()

    req = urllib.request.Request(
        f"{OLLAMA_BASE_URL}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
            return data["message"]["content"].strip()
    except Exception as e:
        log("WARN", f"Ollama call failed: {e}", indent=2)
        return ""


def _call_openrouter(system: str, user: str, retry: int = 3) -> str:
    """
    OpenRouter: routes to many free/paid models via OpenAI-compatible API.
    Falls back through free models if the primary is rate-limited or unavailable.
    """
    if not OPENROUTER_API_KEY:
        return ""
    # Free models confirmed available on OpenRouter as of 2026-06.
    # 404 = model ID removed/renamed; skip immediately, never retry a 404.
    free_models = [
        OPENROUTER_MODEL,
        # OpenRouter auto-router — picks best available free model
        "openrouter/free",
        # Hermes 405B — large, less rate-limited
        "nousresearch/hermes-3-llama-3.1-405b:free",
        # Qwen Coder
        "qwen/qwen3-coder:free",
        "qwen/qwen3-next-80b-a3b-instruct:free",
        # Meta Llama
        "meta-llama/llama-3.3-70b-instruct:free",
        # Google Gemma 4
        "google/gemma-4-31b-it:free",
        "google/gemma-4-26b-a4b-it:free",
        # NVIDIA Nemotron
        "nvidia/nemotron-3-ultra-550b-a55b:free",
        "nvidia/nemotron-3-super-120b-a12b:free",
        "nvidia/nemotron-3-nano-30b-a3b:free",
        # Dolphin
        "cognitivecomputations/dolphin-mistral-24b-venice-edition:free",
    ]
    # Deduplicate while preserving order
    seen: set = set()
    model_list = [m for m in free_models if not (m in seen or seen.add(m))]

    system_t = system[:2000]
    user_t   = user[:6000]

    for model in model_list:
        payload = json.dumps({
            "model": model,
            "messages": [
                {"role": "system", "content": system_t},
                {"role": "user",   "content": user_t},
            ],
            "max_tokens": 1200,
            "temperature": 0.1,
        }).encode()
        headers = {
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "HTTP-Referer":  "https://localhost:8766",
            "X-Title":       "SENTINEL Security Scanner",
        }
        model_wait_total = 0.0
        for attempt in range(retry + 1):
            req = urllib.request.Request(
                OPENROUTER_API_BASE, data=payload, headers=headers, method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = json.loads(resp.read())
                    if data.get("error"):
                        err_msg = data["error"].get("message", str(data["error"]))
                        log("WARN", f"OpenRouter model {model} error: {err_msg} — trying next model", indent=2)
                        break  # try next model
                    text = (data.get("choices") or [{}])[0].get("message", {}).get("content", "").strip()
                    if not text:
                        log("WARN", f"OpenRouter model {model} returned empty response", indent=2)
                        break
                    return text
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    # Model no longer exists — skip immediately, never retry
                    log("WARN", f"OpenRouter 404: model '{model}' not found — skipping", indent=2)
                    break
                elif e.code == 429:
                    try:
                        retry_after = int(e.headers.get("retry-after", "15"))
                    except (ValueError, AttributeError):
                        retry_after = 15
                    model_wait_total += retry_after
                    if model_wait_total > 60:
                        log("WARN", f"OpenRouter 429: total wait on {model} exceeded 60s — trying next model", indent=2)
                        break
                    log("WARN", f"OpenRouter 429 on {model} — waiting {retry_after}s (attempt {attempt+1}/{retry+1})", indent=2)
                    time.sleep(retry_after)
                elif e.code == 402:
                    log("WARN", f"OpenRouter: insufficient credits for {model} — trying next model", indent=2)
                    break
                elif e.code in (400, 503):
                    log("WARN", f"OpenRouter {e.code} on {model} — trying next model", indent=2)
                    break
                elif e.code == 401:
                    log("ERROR", "OpenRouter 401: invalid or expired key — check OPENROUTER_API_KEY", indent=2)
                    raise _BackendExhausted()
                else:
                    # Unknown error — retry with backoff but cap at 2 attempts
                    if attempt >= 1:
                        log("WARN", f"OpenRouter HTTP {e.code} on {model} — skipping", indent=2)
                        break
                    log("WARN", f"OpenRouter HTTP {e.code} (attempt {attempt+1}/{retry+1})", indent=2)
                    time.sleep(5)
            except Exception as ex:
                log("WARN", f"OpenRouter call failed: {ex}", indent=2)
                if attempt < retry:
                    time.sleep(4 * (attempt + 1))
    log("WARN", "OpenRouter: all models exhausted or failed — cascading", indent=1)
    raise _BackendExhausted()


def _call_opencode(system: str, user: str, retry: int = 2) -> str:
    """
    OpenCode Zen (opencode.ai/zen): free multi-model API, OpenAI-compatible.
    Requires OPENCODE_API_KEY — sign up at opencode.ai/zen for a free API key.
    Free models cost $0 but still need authentication.
    """
    if not OPENCODE_API_KEY:
        log("WARN", "OpenCode Zen: no API key — set OPENCODE_API_KEY", indent=1)
        raise _BackendExhausted()

    free_models = [
        OPENCODE_MODEL,
        "deepseek-v4-flash-free",
        "minimax-m3-free",
        "mimo-v2.5-free",
        "nemotron-3-ultra-free",
        "qwen3.6-plus-free",
        "north-mini-code-free",
    ]
    seen: set = set()
    model_list = [m for m in free_models if not (m in seen or seen.add(m))]

    system_t = system[:2000]
    user_t   = user[:6000]

    for model in model_list:
        payload = json.dumps({
            "model": model,
            "messages": [
                {"role": "system", "content": system_t},
                {"role": "user",   "content": user_t},
            ],
            "max_tokens": 1200,
            "temperature": 0.1,
        }).encode()
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SENTINEL/1.0",
        }
        if OPENCODE_API_KEY:
            headers["Authorization"] = f"Bearer {OPENCODE_API_KEY}"

        for attempt in range(retry + 1):
            req = urllib.request.Request(
                OPENCODE_API_BASE, data=payload, headers=headers, method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = json.loads(resp.read())
                    if data.get("error"):
                        err_msg = data["error"].get("message", str(data["error"]))
                        log("WARN", f"OpenCode model {model} error: {err_msg} — trying next", indent=2)
                        break
                    text = (data.get("choices") or [{}])[0].get("message", {}).get("content", "").strip()
                    if not text:
                        log("WARN", f"OpenCode model {model} returned empty response", indent=2)
                        break
                    return text
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    log("WARN", f"OpenCode 404: model '{model}' not found — skipping", indent=2)
                    break
                elif e.code == 429:
                    log("WARN", f"OpenCode 429 on {model} — waiting 10s", indent=2)
                    time.sleep(10)
                elif e.code == 401:
                    log("WARN", f"OpenCode 401: invalid key — trying without key", indent=2)
                    headers.pop("Authorization", None)
                else:
                    if attempt >= 1:
                        log("WARN", f"OpenCode HTTP {e.code} on {model} — skipping", indent=2)
                        break
                    time.sleep(3)
            except Exception as ex:
                log("WARN", f"OpenCode call failed: {ex}", indent=2)
                if attempt < retry:
                    time.sleep(3 * (attempt + 1))
    log("WARN", "OpenCode Zen: all models exhausted — cascading", indent=1)
    raise _BackendExhausted()


def _call_cerebras(system: str, user: str, retry: int = 2) -> str:
    """Cerebras Inference — fastest, 1M tok/day free, OpenAI-compatible."""
    if not CEREBRAS_API_KEY:
        log("WARN", "Cerebras: no API key — set CEREBRAS_API_KEY", indent=1)
        raise _BackendExhausted()

    free_models = [
        CEREBRAS_MODEL,
        "llama3.3-70b",
        "llama3.1-8b",
        "gpt-oss-120b",
    ]
    seen: set = set()
    model_list = [m for m in free_models if not (m in seen or seen.add(m))]

    system_t = system[:2000]
    user_t   = user[:6000]

    for model in model_list:
        payload = json.dumps({
            "model": model,
            "messages": [
                {"role": "system", "content": system_t},
                {"role": "user",   "content": user_t},
            ],
            "max_tokens": 1200,
            "temperature": 0.1,
        }).encode()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {CEREBRAS_API_KEY}",
        }

        for attempt in range(retry + 1):
            req = urllib.request.Request(
                CEREBRAS_API_BASE, data=payload, headers=headers, method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = json.loads(resp.read())
                    if data.get("error"):
                        err_msg = data["error"].get("message", str(data["error"]))
                        log("WARN", f"Cerebras model {model} error: {err_msg} — trying next", indent=2)
                        break
                    text = (data.get("choices") or [{}])[0].get("message", {}).get("content", "").strip()
                    if not text:
                        log("WARN", f"Cerebras model {model} returned empty response", indent=2)
                        break
                    return text
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    log("WARN", f"Cerebras 404: model '{model}' not found — skipping", indent=2)
                    break
                elif e.code == 429:
                    log("WARN", f"Cerebras 429 on {model} — waiting 10s", indent=2)
                    time.sleep(10)
                elif e.code == 401:
                    log("WARN", f"Cerebras 401: invalid key", indent=2)
                    raise _BackendExhausted()
                else:
                    if attempt >= 1:
                        log("WARN", f"Cerebras HTTP {e.code} on {model} — skipping", indent=2)
                        break
                    time.sleep(3)
            except Exception as ex:
                log("WARN", f"Cerebras call failed: {ex}", indent=2)
                if attempt < retry:
                    time.sleep(3 * (attempt + 1))
    log("WARN", "Cerebras: all models exhausted — cascading", indent=1)
    raise _BackendExhausted()


# ── Global sliding-window rate limiter shared across all AI backends.
# Tracks call timestamps in a rolling 60-second window.  Blocks here instead
# of letting each backend retry independently, which causes retry storms.
import threading as _threading

class _SlidingWindowRateLimiter:
    """
    Thread-safe sliding-window rate limiter.
    Blocks the calling thread until a call slot is available.
    """
    def __init__(self, max_calls: int = 25, window_sec: float = 60.0):
        self._max   = max_calls
        self._win   = window_sec
        self._times: list = []
        self._lock  = _threading.Lock()

    def acquire(self):
        while True:
            with self._lock:
                now = time.monotonic()
                # Evict timestamps outside the rolling window
                self._times = [t for t in self._times if now - t < self._win]
                if len(self._times) < self._max:
                    self._times.append(now)
                    return
                # Window full — calculate how long until oldest call expires
                oldest  = self._times[0]
                wait_for = self._win - (now - oldest) + 0.1
            time.sleep(wait_for)

# Default: 20 calls per 60 s — will be reconfigured once backend is detected.
# Cerebras: 30 RPM; OpenRouter: ~20 RPM free.
# We set 20 as a safe default. detect_ai_backend() calls _configure_rate_limiter().
_GLOBAL_AI_RATE_LIMITER = _SlidingWindowRateLimiter(max_calls=20, window_sec=60.0)


def _configure_rate_limiter(backend: str):
    """
    Reconfigure the global rate limiter to match the active backend's free-tier RPM.
    Called once after detect_ai_backend() resolves the primary backend.
    Also sets AI_DELAY (inter-call gap) per-backend — cloud APIs need spacing.
    """
    global AI_DELAY
    limits = {
        "openrouter":  15,   # conservative — free models share a pool
        "cerebras":    30,   # 30 RPM free tier
        "opencode":    30,   # Zen free tier — generous limits
        "ollama":      60,   # local, no external rate limit
    }
    delays = {
        "openrouter":  1.5,
        "cerebras":    0.3,  # fastest inference, low delay needed
        "opencode":    1.0,  # Zen responds fast for free models
        "ollama":      0.0,  # local — no rate limit
    }
    max_calls = limits.get(backend, 20)
    _GLOBAL_AI_RATE_LIMITER._max = max_calls
    if backend in delays:
        AI_DELAY = delays[backend]
    log("INFO", f"AI rate limiter: {max_calls} req/min, {AI_DELAY}s delay for backend '{backend}'", indent=1)


def _ai_rate_limited_sleep():
    """
    Called ONCE per AI call (in _call_ai only — NOT inside per-backend retry loops).
    Uses the sliding-window limiter so bursts are absorbed without blocking
    for an entire minute when only a few extra slots are consumed.
    AI_DELAY adds a minimum inter-call gap on top, for providers that need it.
    """
    _GLOBAL_AI_RATE_LIMITER.acquire()
    # AI_DELAY is a minimum inter-call gap (per-provider throttle).
    # Even 0.0 will yield briefly to avoid busy-waiting.
    time.sleep(AI_DELAY)


def _call_ai(system: str, user: str) -> str:
    """
    Central AI dispatcher. Applies rate limiting, caching, and backend cascade.
    Called by all ai_* functions — never call backend functions directly.
    """
    # Cache: skip identical prompts within the same process run
    cache_key = hashlib.sha256((system + "\x00" + user).encode()).hexdigest()
    cached = _AI_CALL_CACHE.get(cache_key)
    if cached is not None:
        return cached

    _ai_rate_limited_sleep()

    # Build ordered list: primary backend first, then fallbacks
    backend_dispatch = {
        "ollama":      _call_ollama,
        "openrouter":  _call_openrouter,
        "cerebras":    _call_cerebras,
        "opencode":    _call_opencode,
    }

    backends_to_try = [AI_BACKEND] + [
        fb["backend"] for fb in _AI_FALLBACK_BACKENDS
        if fb["backend"] not in _AI_BACKEND_EXHAUSTED
    ]

    for backend in backends_to_try:
        if backend in _AI_BACKEND_EXHAUSTED:
            continue
        fn = backend_dispatch.get(backend)
        if fn is None:
            continue
        try:
            result = fn(system, user)
            if result:
                _AI_CALL_CACHE[cache_key] = result
                return result
        except _BackendExhausted:
            _AI_BACKEND_EXHAUSTED.add(backend)
            log("WARN", f"AI backend '{backend}' exhausted — cascading to next", indent=1)

    log("WARN", "All AI backends exhausted or unavailable — returning empty", indent=1)
    return ""


def _clean_ai_raw(raw: str) -> str:
    """Return the raw text from an AI call, stripping JSON fences if present."""
    if not raw:
        return ""
    return re.sub(r"```(?:json)?", "", raw).strip().rstrip("`")


def _parse_ai_json(raw: str) -> dict:
    """Parse a JSON response from an AI call, stripping markdown fences if present.
    Falls back to regex extraction if direct parse fails. Returns {} on failure.
    """
    if not raw:
        return {}
    cleaned = re.sub(r"```(?:json)?", "", raw).strip().rstrip("`")
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    # Try extracting the first {...} block (AI sometimes adds preamble text)
    m = re.search(r"\{[\s\S]*\}", cleaned)
    if m:
        try:
            return json.loads(m.group())
        except Exception:
            pass
    return {}


def ai_explain_vulnerability(finding: dict) -> dict:
    if not AI_AVAILABLE:
        return {}

    name        = finding.get("name", "unknown")
    template_id = finding.get("template_id", "")
    severity    = finding.get("severity", "unknown")
    host        = finding.get("host", "")
    matched_at  = finding.get("matched_at", "")
    raw_desc    = finding.get("raw_description", "")
    raw_remed   = finding.get("remediation", "")
    cve_ids     = finding.get("cve_ids", [])
    cwe_ids     = finding.get("cwe_ids", [])
    cvss        = finding.get("cvss_score", "")
    refs        = finding.get("references", [])

    system = (
        "You are a senior offensive security engineer writing a professional bug bounty report. "
        "Your audience has decent technical knowledge (developers, security leads) but may not be "
        "experts in every vulnerability class. "
        "Be precise, factual, and actionable. Avoid marketing language. "
        "CRITICAL: Respond ONLY with a single valid JSON object. No markdown, no backticks, no explanation outside the JSON."
    )

    user = f"""Analyze this vulnerability finding and produce a structured JSON response.

=== FINDING ===
Name:        {name}
Template ID: {template_id}
Severity:    {severity}
Host:        {host}
Matched at:  {matched_at}
CVSS Score:  {cvss}
CVE IDs:     {', '.join(cve_ids) if cve_ids else 'None'}
CWE IDs:     {', '.join(cwe_ids) if cwe_ids else 'None'}
Description: {raw_desc[:600] if raw_desc else 'Not provided'}
Remediation: {raw_remed[:300] if raw_remed else 'Not provided'}
References:  {'; '.join(refs[:3]) if refs else 'None'}

Return ONLY this JSON (fill in the angle-bracket placeholders):
{{"explanation":"<3-5 sentences: WHAT this vulnerability is, HOW it works technically, WHY it exists.>","impact":"<2-3 sentences: real-world business and security impact if exploited.>","poc":"<Numbered reproduction steps using the actual host/URL above. Include curl commands or payloads where applicable.>","remediation":"<Concrete actionable fix: code patterns, config changes, or patch versions.>","effort_to_fix":"<e.g. low / 1 hour — one line estimate>","bounty_value":"<e.g. $200-500 — typical bug bounty range for this class>","confidence_adjustment":<integer from -20 to +20 based on how specific and credible this match is>}}"""

    raw = _call_ai(system, user)
    return _parse_ai_json(raw)


def ai_executive_summary(target: str, stats: dict, findings_by_sev: dict) -> str:
    if not AI_AVAILABLE:
        return ""

    system = (
        "You are a senior penetration tester writing an executive summary for a bug bounty report. "
        "Be concise (3–5 sentences), factual, and highlight the most urgent risks. "
        "Write flowing prose paragraphs — no bullet points."
    )

    sev_counts     = {sev: len(lst) for sev, lst in findings_by_sev.items()}
    critical_names = [f.get("name","") for f in findings_by_sev.get("critical", [])[:3]]
    high_names     = [f.get("name","") for f in findings_by_sev.get("high", [])[:3]]

    user = f"""Write a 3–5 sentence executive summary for a bug bounty scan of: {target}

Scan stats:
  Subdomains:  {stats.get('subdomains', 0)}
  Live hosts:  {stats.get('live_hosts', 0)}
  URLs found:  {stats.get('urls', 0)}
  Risk score:  {stats.get('risk_score', 0)}/100

Vulnerability counts: {json.dumps(sev_counts)}
Critical findings: {', '.join(critical_names) if critical_names else 'None'}
High findings:     {', '.join(high_names) if high_names else 'None'}
XSS confirmed:  {stats.get('xss', 0)}
SQLi confirmed: {stats.get('sqli', 0)}

Write a paragraph a CISO can read in 30 seconds. Highlight the most dangerous issues, their likely exploitability, and urgency. Plain prose only — no bullets, no headers."""

    return _call_ai(system, user)


def ai_triage_xss(xss_line: str) -> dict:
    if not AI_AVAILABLE:
        return {"explanation": xss_line, "impact": "", "poc": xss_line, "remediation": ""}

    system = "You are a senior web security researcher. Respond ONLY with valid JSON, no extra text."
    user = f"""Analyze this XSS finding from dalfox:

Finding: {xss_line[:500]}

Return ONLY this JSON:
{{"explanation":"<what the XSS is and where it was found>","impact":"<impact of this specific XSS>","poc":"<exact URL or payload to reproduce>","remediation":"<how to fix this specific case>"}}"""

    raw = _call_ai(system, user)
    result = _parse_ai_json(raw)
    return result if result else {"explanation": xss_line, "impact": "", "poc": xss_line, "remediation": ""}


def ai_triage_sqli(sqli_line: str) -> dict:
    if not AI_AVAILABLE:
        return {"explanation": sqli_line, "impact": "", "poc": sqli_line, "remediation": ""}

    system = "You are a senior web security researcher. Respond ONLY with valid JSON, no extra text."
    user = f"""Analyze this SQL injection finding from sqlmap:

Finding: {sqli_line[:500]}

Return ONLY this JSON:
{{"explanation":"<what the SQLi is and how it was triggered>","impact":"<impact of this specific injection point>","poc":"<example sqlmap command or payload to reproduce>","remediation":"<concrete fix: parameterized queries, ORM pattern, etc.>"}}"""

    raw = _call_ai(system, user)
    result = _parse_ai_json(raw)
    return result if result else {"explanation": sqli_line, "impact": "", "poc": sqli_line, "remediation": ""}


# ─────────────────────────────────────────────
# STAGE 1: RECON
# ─────────────────────────────────────────────

def run_recon(target: str, run_dir: Path, available: dict) -> Path:
    section("RECON — Subdomain Enumeration", "1/7")
    subdomains_file = run_dir / "subdomains.txt"
    all_subs = set()

    if require_tool("subfinder", available):
        subfinder_out = run_dir / "subfinder.txt"
        spinner_start("subfinder: passive subdomain enumeration...")
        # FIX: Write directly to file with -o so output isn't lost if stdout buffering drops lines
        run_cmd([
            "subfinder", "-d", target, "-silent", "-all", "-no-color",
            "-o", str(subfinder_out),
        ])
        spinner_stop()
        if subfinder_out.exists():
            subs = [l.strip() for l in subfinder_out.read_text().splitlines()
                    if l.strip() and target in l.strip()]
            all_subs.update(subs)
            log("SUCCESS", f"subfinder → Found {len(subs)} subdomains")
        else:
            log("WARN", "subfinder produced no output file — trying stdout capture", indent=1)
            out = run_cmd(["subfinder", "-d", target, "-silent", "-all", "-no-color"])
            subs = [l.strip() for l in out.splitlines() if l.strip() and "." in l.strip()]
            all_subs.update(subs)

    if require_tool("assetfinder", available):
        spinner_start("assetfinder: additional subdomain discovery...")
        out = run_cmd(["assetfinder", "--subs-only", target], timeout=60)
        spinner_stop()
        subs = [l.strip() for l in out.splitlines() if l.strip() and target in l.strip()]
        all_subs.update(subs)
        log("SUCCESS", f"assetfinder → {len(subs)} subdomains")

    if shutil.which("amass"):
        spinner_start("amass: DNS enumeration...")
        # FIX: amass v4+ uses `amass enum` with `-passive` (single dash); v3 used same.
        # Add -json output to avoid parsing colorized stdout.
        amass_out = run_dir / "amass_out.txt"
        out = run_cmd([
            "amass", "enum", "-passive", "-d", target, "-o", str(amass_out),
        ], timeout=180)
        spinner_stop()
        if amass_out.exists():
            subs = [l.strip() for l in amass_out.read_text().splitlines()
                    if l.strip() and "." in l.strip()]
        else:
            subs = [l.strip() for l in out.splitlines() if l.strip() and "." in l.strip()]
        all_subs.update(subs)
        log("SUCCESS", f"amass → {len(subs)} subdomains (deduplicated)")

    # Always include root target so probing stage has at least one host
    all_subs.add(target)
    # Filter out obviously non-domain lines
    sorted_subs = sorted(s for s in all_subs if "." in s and len(s) > 3)
    write_lines(subdomains_file, sorted_subs)
    log("SUCCESS", f"Total unique subdomains: {len(sorted_subs)} → {subdomains_file.name}")
    return subdomains_file


# ─────────────────────────────────────────────
# STAGE 2: PROBING
# ─────────────────────────────────────────────

def run_probing(subdomains_file: Path, run_dir: Path, available: dict) -> Path:
    section("PROBING — Live Host Detection", "2/7")
    live_hosts_file = run_dir / "live_hosts.txt"
    live_urls_file  = run_dir / "live_urls.txt"

    if not require_tool("httpx", available):
        return live_hosts_file

    spinner_start("httpx: probing HTTP/S on all subdomains...")
    raw_file = run_dir / "live_hosts_raw.txt"

    # Distinguish projectdiscovery/httpx from the Python httpx CLI (pip install httpx).
    # Python httpx CLI:          httpx --version  → "httpx, 0.x.x"  (no -l flag)
    # projectdiscovery/httpx:   httpx -version   → "Current Version: 1.x.x" (uses -l)
    # Strategy: run both version probes; pd-httpx wins only if "current version" found
    # AND the output does NOT look like the Python CLI "httpx, 0." pattern.
    _pd_httpx = False
    _httpx_new_flags = False   # pd-httpx ≥1.2 flag names
    try:
        _hv = subprocess.run(["httpx", "-version"], capture_output=True, text=True, timeout=5)
        _hv_text = (_hv.stdout + _hv.stderr).lower()
        # Explicit Python httpx CLI guard — its output contains "httpx, 0." or "httpx/0."
        _is_python_httpx = bool(re.search(r"httpx[,/\s]+0\.", _hv_text))
        _m = re.search(r"current version[:\s]+v?(\d+)\.(\d+)", _hv_text)
        if _m and not _is_python_httpx:
            _pd_httpx = True
            _maj, _min = int(_m.group(1)), int(_m.group(2))
            # ≥1.2: uses -td, -fr, -nc, -c; <1.2: uses -tech-detect, -follow-redirects, etc.
            _httpx_new_flags = (_maj > 1) or (_maj == 1 and _min >= 2)
        elif not _m and not _is_python_httpx:
            # Some pd-httpx builds don't print "Current Version" — try --version too
            _hv2 = subprocess.run(["httpx", "--version"], capture_output=True, text=True, timeout=5)
            _hv2_text = (_hv2.stdout + _hv2.stderr).lower()
            _m2 = re.search(r"current version[:\s]+v?(\d+)\.(\d+)", _hv2_text)
            if _m2 and not re.search(r"httpx[,/\s]+0\.", _hv2_text):
                _pd_httpx = True
                _maj, _min = int(_m2.group(1)), int(_m2.group(2))
                _httpx_new_flags = (_maj > 1) or (_maj == 1 and _min >= 2)
    except Exception:
        pass

    if _pd_httpx:
        # projectdiscovery/httpx — use -l <file>
        if _httpx_new_flags:
            httpx_cmd = [
                "httpx", "-l", str(subdomains_file), "-silent",
                "-status-code", "-title", "-td", "-fr",
                "-c", "50", "-nc", "-o", str(raw_file),
            ]
        else:
            httpx_cmd = [
                "httpx", "-l", str(subdomains_file), "-silent",
                "-status-code", "-title", "-tech-detect", "-follow-redirects",
                "-threads", "50", "-no-color", "-o", str(raw_file),
            ]
        run_cmd(httpx_cmd, timeout=300)
        # Minimal fallback if the above produced nothing
        if not raw_file.exists() or raw_file.stat().st_size == 0:
            log("WARN", "httpx produced no output — retrying with minimal flags", indent=1)
            run_cmd(["httpx", "-l", str(subdomains_file), "-silent", "-o", str(raw_file)], timeout=300)
    else:
        # Python httpx (pip) is in PATH instead of projectdiscovery/httpx.
        # It does not support batch-file probing. Fall back to curl probing each host.
        log("WARN", "projectdiscovery/httpx not found — Python httpx CLI detected.", indent=1)
        log("WARN", "Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest", indent=1)
        log("INFO", "Falling back to curl-based live-host probing...", indent=1)
        live_urls: list = []
        subdomains = read_lines(subdomains_file)
        for subdomain in subdomains[:200]:   # cap to avoid hour-long probes
            subdomain = subdomain.strip()
            if not subdomain:
                continue
            for scheme in ("https", "http"):
                url = f"{scheme}://{subdomain}"
                try:
                    result = subprocess.run(
                        ["curl", "-sI", "--max-time", "5", "-L", "--max-redirs", "3", url],
                        capture_output=True, text=True, timeout=8,
                    )
                    if result.returncode == 0 and result.stdout:
                        status_line = result.stdout.splitlines()[0] if result.stdout.splitlines() else ""
                        live_urls.append(f"{url} [{status_line.strip()}]")
                        break   # https worked, skip http
                except Exception:
                    pass
        if live_urls:
            raw_file.write_text("\n".join(live_urls))
            log("SUCCESS", f"curl probe → {len(live_urls)} live hosts", indent=1)
        else:
            log("WARN", "curl probe found no live hosts", indent=1)

    raw_lines = read_lines(raw_file)
    urls = []
    for line in raw_lines:
        parts = line.split()
        if parts and (parts[0].startswith("https://") or parts[0].startswith("http://")):
            urls.append(parts[0])

    write_lines(live_hosts_file, raw_lines)
    write_lines(live_urls_file, urls)

    log("SUCCESS", f"Found {len(raw_lines)} live hosts → {live_hosts_file.name}")
    return live_hosts_file


# ─────────────────────────────────────────────
# STAGE 3: URL / PARAMETER DISCOVERY
# ─────────────────────────────────────────────

def run_url_discovery(live_hosts_file: Path, target: str, run_dir: Path, available: dict) -> Path:
    section("URL & PARAMETER DISCOVERY", "3/7")
    urls_dir = run_dir / "urls"
    urls_dir.mkdir(exist_ok=True)
    all_urls: set = set()

    live_urls_file = run_dir / "live_urls.txt"
    urls = read_lines(live_urls_file)

    # FIX: Seed all_urls with already-probed live URLs so nuclei/fuzzing always
    # have something to scan even if all crawlers fail or are not installed.
    all_urls.update(u for u in urls if u.startswith("http"))

    if require_tool("waybackurls", available):
        spinner_start("waybackurls: fetching archived URLs...")
        out = run_cmd(["waybackurls", target], timeout=120)
        spinner_stop()
        wb_urls = [l.strip() for l in out.splitlines() if l.strip() and l.strip().startswith("http")]
        all_urls.update(wb_urls)
        log("SUCCESS", f"waybackurls → {len(wb_urls)} archived URLs")

    if require_tool("gau", available):
        spinner_start("gau: fetching all-origins URLs...")
        # gau v2 (shenwei356/gau): uses --subs flag only.
        # Do NOT retry with --include-subs — it's not a valid flag in any version.
        _gau_out = run_cmd(["gau", "--subs", target], timeout=120)
        if not _gau_out:
            # If --subs produced nothing (flag rejected or empty), try bare domain
            _gau_out = run_cmd(["gau", target], timeout=90)
        spinner_stop()
        gau_urls = [l.strip() for l in _gau_out.splitlines() if l.strip() and l.strip().startswith("http")]
        all_urls.update(gau_urls)
        log("SUCCESS", f"gau → {len(gau_urls)} URLs")

    if require_tool("katana", available) and urls:
        for url in urls[:5]:
            spinner_start(f"katana: crawling {url}...")
            out = run_cmd([
                "katana", "-u", url, "-silent", "-d", "3",
                "-jc",           # parse JS files for URLs
                "-fx",           # form extraction
                "-fs", "rdn",    # field scope: root domain and sub-domains
                "-nc",           # no color
            ], timeout=120)
            spinner_stop()
            k_urls = [l.strip() for l in out.splitlines() if l.strip() and l.strip().startswith("http")]
            all_urls.update(k_urls)
        log("SUCCESS", "katana → crawled URLs added")

    if require_tool("gospider", available) and urls:
        # FIX: gospider -o writes per-URL files inside the dir, not a single gospider.txt.
        # Read all files it creates and extract URLs from them.
        gospider_dir = urls_dir / "gospider_out"
        gospider_dir.mkdir(exist_ok=True)
        run_cmd([
            "gospider", "-S", str(live_urls_file),
            "-o", str(gospider_dir), "--js", "--sitemap",
            "--robots", "-a", "-t", "10",
        ], timeout=180)
        g_count = 0
        url_pat = re.compile(r"https?://[^\s\"'<>]+")
        for f in gospider_dir.glob("*"):
            if f.is_file():
                try:
                    for line in f.read_text(errors="ignore").splitlines():
                        for m in url_pat.findall(line):
                            all_urls.add(m.rstrip(".,;)\"'"))
                            g_count += 1
                except Exception:
                    pass
        if g_count:
            log("SUCCESS", f"gospider → {g_count} URLs")

    if require_tool("hakrawler", available) and urls:
        # Detect hakrawler version: v1 uses -depth/-insecure; v2+ uses --depth/-insecure removed
        _hak_new = False
        try:
            _hv = subprocess.run(["hakrawler", "-h"], capture_output=True, text=True, timeout=5)
            _hak_new = "--depth" in (_hv.stdout + _hv.stderr)
        except Exception:
            pass
        _depth_flag = "--depth" if _hak_new else "-depth"

        for url in urls[:3]:
            spinner_start(f"hakrawler: crawling {url}...")
            # hakrawler reads URLs from stdin
            try:
                hak_cmd = ["hakrawler", _depth_flag, "3"]
                proc = subprocess.run(
                    hak_cmd,
                    input=url + "\n", capture_output=True, text=True, timeout=60,
                )
                hak_urls = [l.strip() for l in proc.stdout.splitlines()
                            if l.strip().startswith("http")]
                all_urls.update(hak_urls)
            except Exception:
                pass
            spinner_stop()

    params_file = run_dir / "params.txt"
    if require_tool("paramspider", available):
        spinner_start("paramspider: extracting parameterized URLs...")
        # FIX: newer paramspider writes to results/<domain>.txt, not -o path directly.
        # Try both invocation styles.
        run_cmd(["paramspider", "-d", target, "-o", str(params_file)], timeout=120)
        if not params_file.exists() or params_file.stat().st_size == 0:
            # Newer paramspider (≥1.3) uses --domain and outputs to results/
            run_cmd(["paramspider", "--domain", target], timeout=120)
            alt_path = Path("results") / f"{target}.txt"
            if alt_path.exists():
                import shutil as _sh
                _sh.copy(str(alt_path), str(params_file))
        spinner_stop()
        if params_file.exists() and params_file.stat().st_size > 0:
            p_urls = [l.strip() for l in read_lines(params_file) if l.strip().startswith("http")]
            all_urls.update(p_urls)
            log("SUCCESS", f"paramspider → {len(p_urls)} parameterized URLs")

    all_urls_file = run_dir / "all_urls.txt"
    # Filter out clearly invalid lines before writing
    clean_urls = sorted(u for u in all_urls if u.startswith("http") and len(u) > 10)
    write_lines(all_urls_file, clean_urls)

    param_urls = [u for u in clean_urls if "?" in u and "=" in u]
    param_urls_file = run_dir / "param_urls.txt"
    write_lines(param_urls_file, param_urls)

    log("SUCCESS", f"Total unique URLs: {len(clean_urls)} ({len(param_urls)} parameterized)")
    return all_urls_file


# ─────────────────────────────────────────────
# STAGE 4: DIRECTORY FUZZING
# ─────────────────────────────────────────────

def run_fuzzing(live_hosts_file: Path, run_dir: Path, available: dict) -> Path:
    section("DIRECTORY & ENDPOINT FUZZING", "4/7")
    fuzz_dir = run_dir / "fuzzing"
    fuzz_dir.mkdir(exist_ok=True)
    results_file = run_dir / "fuzz_results.txt"

    if not require_tool("ffuf", available):
        return results_file

    live_urls_file = run_dir / "live_urls.txt"
    urls = read_lines(live_urls_file)[:10]

    wordlist_env = os.environ.get("SENTINEL_WORDLIST", "")
    if wordlist_env and Path(wordlist_env).exists():
        wordlist = wordlist_env
    else:
        seclists_home = os.environ.get("SECLISTS_HOME", "/usr/share/seclists")
        wordlists = [
            seclists_home + "/Discovery/Web-Content/common.txt",
            seclists_home + "/Discovery/Web-Content/raft-small-words.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/opt/seclists/Discovery/Web-Content/common.txt",
        ]
        wordlist = next((w for w in wordlists if Path(w).exists()), None)
        if not wordlist:
            log("WARN", "No wordlist found. Set SENTINEL_WORDLIST or install seclists")
            return results_file

    all_fuzz: list = []
    for url in urls:
        base = url.rstrip("/")
        safe_name = re.sub(r"[:/.]", "_", base)[:80]
        out_file = fuzz_dir / f"fuzz_{safe_name}.json"
        spinner_start(f"ffuf: fuzzing {base}/...")
        run_cmd([
            "ffuf", "-u", f"{base}/FUZZ",
            "-w", wordlist,
            "-mc", "200,201,204,301,302,307,401,403,405",
            "-of", "json", "-o", str(out_file),
            "-t", "50", "-timeout", "5", "-fs", "0",
            "-s",
        ], timeout=180)
        spinner_stop()

        if out_file.exists():
            try:
                data = json.loads(out_file.read_text())
                results = data.get("results", [])
                for r in results:
                    all_fuzz.append(f"{r['url']} [{r['status']}] [{r['length']}b]")
                log("SUCCESS", f"  {base} → {len(results)} paths found")
            except Exception:
                pass

    # FIX: Single write after collecting all results (was overwriting on each iteration)
    write_lines(results_file, all_fuzz)
    log("SUCCESS", f"Total fuzz findings: {len(all_fuzz)} → {results_file.name}")
    return results_file


# ─────────────────────────────────────────────
# STAGE 5: VULNERABILITY SCANNING
# ─────────────────────────────────────────────

def run_nuclei_scan(run_dir: Path, available: dict, severity: str) -> Path:
    section("NUCLEI — Automated Vulnerability Scanning", "5a/7")
    nuclei_json = run_dir / "nuclei_results.json"

    if not require_tool("nuclei", available):
        return nuclei_json

    live_urls_file = run_dir / "live_urls.txt"
    all_urls_file  = run_dir / "all_urls.txt"
    urls = read_lines(live_urls_file)

    # FIX: prefer all_urls (which includes crawled + archived URLs) for richer coverage;
    # fall back to live_urls if crawl stage was skipped.
    if all_urls_file.exists() and all_urls_file.stat().st_size > 0:
        scan_file = all_urls_file
        scan_count = len(read_lines(all_urls_file))
    else:
        scan_file = live_urls_file
        scan_count = len(urls)

    if scan_count == 0:
        log("WARN", "No URLs to scan — creating a minimal target list from domain.")
        # FIX: If probing produced nothing, at least try http/https on the root domain.
        # This can happen when httpx is missing or subdomains file is empty.
        fallback_urls_file = run_dir / "fallback_urls.txt"
        parent_target = run_dir.name.rsplit("_", 1)[0]  # strip timestamp from dir name
        fallback_lines = [f"https://{parent_target}", f"http://{parent_target}"]
        write_lines(fallback_urls_file, fallback_lines)
        scan_file = fallback_urls_file
        scan_count = len(fallback_lines)
        log("INFO", f"Fallback: scanning {scan_count} base URLs", indent=1)

    log("SCAN", f"nuclei: scanning {scan_count} targets (severity: {severity})...")

    # FIX: Version-detect which flags nuclei supports, avoiding silent flag-rejection.
    json_flag    = "-jsonl"
    duc_flag     = "-disable-update-check"  # v3+
    etags_flag   = "-exclude-tags"          # v3+
    try:
        ver_out = subprocess.run(["nuclei", "-version"], capture_output=True, text=True, timeout=5)
        ver_str = ver_out.stdout + ver_out.stderr
        m = re.search(r"v(\d+)\.(\d+)", ver_str)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            if major < 3:
                json_flag  = "-json"
                duc_flag   = "-duc"
                etags_flag = "-etags"
    except Exception:
        pass

    nuclei_cmd = [
        "nuclei",
        "-l", str(scan_file),
        "-severity", severity,
        "-nc",                   # no color
        duc_flag,
        "-retries", "1",
        "-timeout", "10",
        "-rate-limit", "50",
        "-bulk-size", "20",
        "-concurrency", "20",
        etags_flag, "intrusive",
        json_flag, str(nuclei_json),
    ]

    finding_count = 0
    try:
        proc = subprocess.Popen(
            nuclei_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert proc.stdout is not None
        for raw_line in iter(proc.stdout.readline, ""):
            line = raw_line.rstrip()
            if not line:
                continue
            clean = re.sub(r"\033\[[0-9;]*m", "", line)
            print(clean, flush=True)
            if clean.strip().startswith("{") and '"template-id"' in clean:
                finding_count += 1
                log("FIND", f"Finding #{finding_count}: {_quick_nuclei_summary(clean)}", indent=1)
        proc.wait()
    except subprocess.TimeoutExpired:
        log("ERROR", "nuclei timed out", indent=1)
    except Exception as ex:
        log("ERROR", f"nuclei error: {ex}", indent=1)

    if nuclei_json.exists() and finding_count == 0:
        for raw in nuclei_json.read_text().splitlines():
            raw = raw.strip()
            if raw.startswith("{") and '"template-id"' in raw:
                print(raw, flush=True)
                finding_count += 1

    findings = _load_nuclei_json(nuclei_json)
    log("SUCCESS", f"Nuclei scan complete. Findings: {len(findings)}")
    return nuclei_json


def _quick_nuclei_summary(json_line: str) -> str:
    try:
        d = json.loads(json_line)
        name = d.get("info", {}).get("name", d.get("template-id", "?"))
        sev  = d.get("info", {}).get("severity", "?")
        host = d.get("host", "")
        return f"[{sev.upper()}] {name} — {host}"
    except Exception:
        return json_line[:80]


def run_xss_scan(run_dir: Path, available: dict) -> Path:
    section("XSS SCANNING — Dalfox", "5b/7")
    xss_file = run_dir / "xss_results.txt"

    if not require_tool("dalfox", available):
        return xss_file

    param_urls_file = run_dir / "param_urls.txt"
    urls = read_lines(param_urls_file)
    if not urls:
        log("WARN", "No parameterized URLs for XSS testing.")
        return xss_file

    # FIX: Cap URL list — dalfox can hang on very large lists
    capped = urls[:200]
    if len(urls) > 200:
        log("INFO", f"Capping XSS scan at 200/{len(urls)} parameterized URLs.", indent=1)

    # Write a clean URL-only file (param_urls may contain extraneous lines)
    clean_param_file = run_dir / "param_urls_clean.txt"
    clean_urls = [u for u in capped if u.startswith("http") and "=" in u]
    write_lines(clean_param_file, clean_urls)

    if not clean_urls:
        log("WARN", "No valid parameterized URLs after filtering.")
        return xss_file

    log("SCAN", f"dalfox: testing {len(clean_urls)} parameterized endpoints...")

    # FIX: detect dalfox version — v2+ supports --format flag; older uses --output
    dalfox_cmd = [
        "dalfox", "file", str(clean_param_file),
        "--output", str(xss_file),
        "--only-poc", "v",
        "--timeout", "10",
        "--worker", "20",
        "--skip-bav",
        "--no-color",
    ]

    run_cmd(dalfox_cmd, timeout=300)

    results = read_lines(xss_file)
    log("SUCCESS" if results else "INFO", f"XSS findings: {len(results)}")
    return xss_file


def run_sqli_scan(run_dir: Path, available: dict) -> Path:
    section("SQL INJECTION — SQLMap", "5c/7")
    sqli_dir = run_dir / "sqli"
    sqli_dir.mkdir(exist_ok=True)
    results_file = run_dir / "sqli_results.txt"

    if not require_tool("sqlmap", available):
        return results_file

    param_urls_file = run_dir / "param_urls.txt"
    raw_urls = read_lines(param_urls_file)
    # FIX: Only pass URLs that actually have GET parameters to sqlmap
    urls = [u for u in raw_urls if "?" in u and "=" in u][:20]
    if not urls:
        log("WARN", "No parameterized URLs for SQLi testing.")
        return results_file

    findings: list = []
    SQLI_PATTERNS = [
        r"sqlmap identified the following injection point",
        r"parameter '.*?' is vulnerable",
        r"\bis injectable\b",
        r"Type: .*(boolean-based|time-based|error-based|UNION query|stacked queries)",
        r"\[CRITICAL\].*injectable",
        r"sql injection.*confirmed",
        r"back-end DBMS:",
    ]

    for url in urls:
        log("SCAN", f"sqlmap → {url[:80]}")
        # FIX: Remove Q (stacked queries) — causes many DBs to error and abort;
        # Remove --forms + --crawl=1 combo — conflates GET param test with form crawl.
        out = run_cmd([
            "sqlmap", "-u", url,
            "--batch", "--level=1", "--risk=1",
            "--technique=BEUST",   # removed Q (stacked queries)
            "--output-dir", str(sqli_dir),
            "--smart", "--timeout=10",
            "--disable-coloring",
            "--no-cast",           # avoids false positives on type-casting differences
        ], timeout=120)
        lower_out = out.lower()
        if any(re.search(pat, lower_out, re.I) for pat in SQLI_PATTERNS):
            findings.append(f"VULNERABLE: {url}")
            log("WARN", f"  SQLi confirmed: {url[:80]}", indent=1)

    write_lines(results_file, findings)
    log("SUCCESS" if findings else "INFO", f"SQLi vulnerable: {len(findings)} endpoints")
    return results_file


def run_nikto_scan(live_hosts_file: Path, run_dir: Path, available: dict) -> Path:
    section("WEB SERVER MISCONFIGURATION — Nikto", "5d/7")
    nikto_file = run_dir / "nikto_results.txt"

    if not require_tool("nikto", available):
        return nikto_file

    live_urls_file = run_dir / "live_urls.txt"
    urls = read_lines(live_urls_file)[:5]

    all_out: list = []
    for url in urls:
        spinner_start(f"nikto: {url}...")
        out = run_cmd([
            "nikto", "-h", url, "-nointeractive", "-ask", "no",
            "-Tuning", "123456789ax",
        ], timeout=180)
        spinner_stop()
        if out:
            all_out.append(f"\n### {url}\n{out}")

    write_lines(nikto_file, all_out)
    log("SUCCESS", f"Nikto scan complete → {nikto_file.name}")
    return nikto_file


def run_nmap(target: str, run_dir: Path, available: dict) -> Path:
    section("PORT SCAN — Nmap", "5e/7")
    nmap_file = run_dir / "nmap_results.txt"

    if not require_tool("nmap", available):
        return nmap_file

    # FIX: Don't pass output_file= to run_cmd when -oN already writes the file.
    # Previously both -oN and output_file= were used, causing a double-write race.
    log("SCAN", f"nmap phase 1: fast port discovery on {target}...")
    fast_out = run_cmd([
        "nmap", "-sV", "--open", "-T4",
        "--max-retries", "2",
        "--host-timeout", "60s",
        "--min-rate", "500",
        "-oN", str(nmap_file),
        target,
    ], timeout=120)

    # Read from file (written by -oN) if stdout was empty
    nmap_text = fast_out or (nmap_file.read_text() if nmap_file.exists() else "")
    open_ports = _parse_open_ports(nmap_text)

    if open_ports:
        ports_arg = ",".join(str(p) for p in open_ports[:20])
        log("SCAN", f"nmap phase 2: safe scripts on open ports: {ports_arg}")
        script_out = run_cmd([
            "nmap", "-sV", "--open", "-T3",
            "-p", ports_arg,
            "--script", "http-title,http-headers,ssl-cert,banner",
            "--host-timeout", "90s",
            "-oN", str(run_dir / "nmap_scripts.txt"),
            target,
        ], timeout=180)
        if script_out:
            with open(nmap_file, "a") as f:
                f.write("\n\n# Script Results\n" + script_out)
    else:
        log("INFO", "No open ports found in phase 1 — skipping script scan.")

    log("SUCCESS", f"Nmap complete → {nmap_file.name}")
    return nmap_file


def _parse_open_ports(nmap_output: str) -> list:
    ports = []
    for line in nmap_output.splitlines():
        m = re.match(r"\s*(\d+)/tcp\s+open", line)
        if m:
            ports.append(int(m.group(1)))
    return ports


# ─────────────────────────────────────────────
# STAGE: SECRETS SCANNING
# ─────────────────────────────────────────────

def run_secrets_scan(target: str, run_dir: Path, available: dict) -> Path:
    section("SECRETS SCANNING — TruffleHog / Gitleaks / SecretFinder", "5f/7")
    secrets_file = run_dir / "secrets_results.txt"
    all_secrets: list = []

    if shutil.which("trufflehog"):
        spinner_start(f"trufflehog: scanning for exposed secrets on {target}...")
        # --directory is deprecated in trufflehog v3+; pass path as positional arg
        out = run_cmd([
            "trufflehog", "filesystem",
            str(run_dir),
            "--only-verified", "--json", "--no-update",
        ], timeout=120)
        spinner_stop()
        for line in out.splitlines():
            if line.strip().startswith("{"):
                try:
                    d = json.loads(line)
                    secret_type = d.get("DetectorName", "secret")
                    raw = d.get("Raw", "")[:80]
                    all_secrets.append(f"[trufflehog] {secret_type}: {raw}")
                    log("WARN", f"  Secret found: {secret_type}", indent=1)
                except Exception:
                    pass

    if shutil.which("gitleaks"):
        gl_out = run_dir / "gitleaks.json"
        spinner_start("gitleaks: scanning for hardcoded credentials...")
        run_cmd([
            "gitleaks", "detect", "--source", str(run_dir),
            "--report-format", "json", "--report-path", str(gl_out),
            "--no-git", "--exit-code", "0",
        ], timeout=60)
        spinner_stop()
        if gl_out.exists():
            try:
                leaks = json.loads(gl_out.read_text())
                for leak in leaks[:10]:
                    desc = f"[gitleaks] {leak.get('RuleID','?')} in {leak.get('File','?')}"
                    all_secrets.append(desc)
                    log("WARN", f"  Leak: {desc}", indent=1)
            except Exception:
                pass

    if shutil.which("secretfinder") or shutil.which("SecretFinder"):
        sf_bin = "secretfinder" if shutil.which("secretfinder") else "SecretFinder"
        all_urls_file = run_dir / "all_urls.txt"
        js_urls = [u for u in read_lines(all_urls_file) if u.endswith(".js")][:20]
        if js_urls:
            spinner_start(f"SecretFinder: scanning {len(js_urls)} JS files for API keys...")
            for js_url in js_urls:
                out = run_cmd([sf_bin, "-i", js_url, "-o", "cli"], timeout=30)
                if out:
                    all_secrets.append(f"[secretfinder] {js_url}: {out[:120]}")
            spinner_stop()

    write_lines(secrets_file, all_secrets)
    if all_secrets:
        log("WARN", f"Secrets found: {len(all_secrets)} — review immediately!")
    else:
        log("INFO", "No verified secrets found in this scan pass.")
    return secrets_file


# ─────────────────────────────────────────────
# STAGE: CORS MISCONFIGURATION
# ─────────────────────────────────────────────

def run_cors_scan(run_dir: Path, available: dict) -> Path:
    section("CORS MISCONFIGURATION SCAN", "5g/7")
    cors_file = run_dir / "cors_results.txt"
    all_cors: list = []

    live_urls_file = run_dir / "live_urls.txt"
    urls = read_lines(live_urls_file)[:20]
    if not urls:
        log("WARN", "No live URLs for CORS scan.")
        return cors_file

    if shutil.which("corscanner") or shutil.which("CORScanner"):
        bin_name = "corscanner" if shutil.which("corscanner") else "CORScanner"
        targets_file = run_dir / "cors_targets.txt"
        write_lines(targets_file, urls)
        spinner_start(f"CORScanner: testing {len(urls)} endpoints...")
        out = run_cmd([bin_name, "-i", str(targets_file), "-t", "10"], timeout=120)
        spinner_stop()
        vulns = [l for l in out.splitlines() if "vulnerable" in l.lower() or "cors" in l.lower()]
        all_cors.extend(vulns)
        log("SUCCESS" if vulns else "INFO", f"CORScanner → {len(vulns)} CORS issues")
    else:
        spinner_start(f"curl: manual CORS origin reflection test on {len(urls)} URLs...")
        for url in urls[:10]:
            out = run_cmd([
                "curl", "-sI", "-H", "Origin: https://evil.com",
                "-H", "Access-Control-Request-Method: GET",
                url, "--max-time", "5",
            ], timeout=15)
            if ("access-control-allow-origin: https://evil.com" in out.lower() or
                    "access-control-allow-origin: *" in out.lower()):
                issue = f"[cors] Origin reflection: {url}"
                all_cors.append(issue)
                log("WARN", f"  CORS misconfiguration: {url}", indent=1)
        spinner_stop()

    if shutil.which("shcheck"):
        spinner_start("shcheck: security header analysis...")
        for url in urls[:5]:
            out = run_cmd(["shcheck", url], timeout=30)
            if out:
                all_cors.append(f"[shcheck] {url}:\n{out[:300]}")
        spinner_stop()
        log("SUCCESS", "shcheck header analysis complete")

    write_lines(cors_file, all_cors)
    log("SUCCESS" if all_cors else "INFO", f"CORS/Header findings: {len(all_cors)}")
    return cors_file


# ─────────────────────────────────────────────
# STAGE: SSTI / COMMAND INJECTION / OPEN REDIRECT
# ─────────────────────────────────────────────

def run_injection_scans(run_dir: Path, available: dict) -> Path:
    section("INJECTION SCANS — SSTI / CMDi / Open Redirect / CRLF", "5h/7")
    inj_file = run_dir / "injection_results.txt"
    all_findings: list = []

    param_urls_file = run_dir / "param_urls.txt"
    urls = read_lines(param_urls_file)[:30]

    if shutil.which("tplmap"):
        log("SCAN", f"tplmap: testing {min(len(urls),10)} URLs for SSTI...")
        for url in urls[:10]:
            out = run_cmd([
                "tplmap", "-u", url, "--level", "1",
                "--engine", "all", "--os-cmd", "id",
            ], timeout=60)
            if "vulnerable" in out.lower() or "injection" in out.lower():
                all_findings.append(f"[ssti] VULNERABLE: {url}")
                log("WARN", f"  SSTI: {url}", indent=1)

    if shutil.which("commix"):
        log("SCAN", f"commix: testing {min(len(urls),10)} URLs for OS command injection...")
        for url in urls[:10]:
            out = run_cmd([
                "commix", "--url", url, "--batch",
                "--level=1", "--timeout=10",
            ], timeout=90)
            if "vulnerable" in out.lower() or "os-shell" in out.lower():
                all_findings.append(f"[cmdi] VULNERABLE: {url}")
                log("WARN", f"  CMDi: {url}", indent=1)

    if shutil.which("crlfuzz"):
        live_urls_file = run_dir / "live_urls.txt"
        live_urls = read_lines(live_urls_file)[:20]
        if live_urls:
            spinner_start(f"crlfuzz: CRLF injection on {len(live_urls)} URLs...")
            crlf_out = run_dir / "crlf_results.txt"
            run_cmd(["crlfuzz", "-l", str(live_urls_file), "-o", str(crlf_out), "-s"], timeout=120)
            spinner_stop()
            crlf_hits = read_lines(crlf_out)
            all_findings.extend([f"[crlf] {h}" for h in crlf_hits])
            if crlf_hits:
                log("WARN", f"  CRLF injection: {len(crlf_hits)} endpoints", indent=1)

    if shutil.which("ssrfmap"):
        log("SCAN", f"ssrfmap: SSRF testing on parameterized URLs...")
        for url in urls[:5]:
            out = run_cmd([
                "ssrfmap", "-r", url, "-p", "url",
                "--lhost", "127.0.0.1", "--lport", "8080",
            ], timeout=60)
            if "ssrf" in out.lower() or "hit" in out.lower():
                all_findings.append(f"[ssrf] POTENTIAL: {url}")

    # Open redirect — quick curl sweep
    log("SCAN", "Testing open redirect patterns...")
    redirect_payloads = [
        "//evil.com", "https://evil.com", "///evil.com",
        "//evil.com/%2f..", "javascript:alert(1)",
    ]
    redirect_params = ["url", "next", "redirect", "return", "goto", "dest", "location", "target"]
    all_urls_file = run_dir / "all_urls.txt"
    for raw_url in read_lines(all_urls_file)[:50]:
        if "?" not in raw_url:
            continue
        for param in redirect_params:
            if f"{param}=" in raw_url.lower():
                for payload in redirect_payloads[:2]:
                    test_url = re.sub(
                        rf"({param}=)[^&]+", rf"\g<1>{urllib.parse.quote(payload)}",
                        raw_url, flags=re.I
                    )
                    out = run_cmd(["curl", "-sI", "--max-time", "5", "-L", test_url], timeout=10)
                    if ("location: https://evil.com" in out.lower() or
                            "location: //evil.com" in out.lower()):
                        all_findings.append(f"[open-redirect] {test_url}")
                        log("WARN", f"  Open redirect: {test_url[:80]}", indent=1)
                        break

    write_lines(inj_file, all_findings)
    log("SUCCESS" if all_findings else "INFO", f"Injection findings: {len(all_findings)}")
    return inj_file


# ─────────────────────────────────────────────
# STAGE: SSL / TLS ANALYSIS
# ─────────────────────────────────────────────

def run_ssl_scan(target: str, run_dir: Path, available: dict) -> Path:
    section("SSL/TLS ANALYSIS — testssl", "5i/7")
    ssl_file = run_dir / "ssl_results.txt"

    if not shutil.which("testssl") and not shutil.which("testssl.sh"):
        log("WARN", "testssl not installed — skipping SSL scan")
        log("WARN", "Install: https://testssl.sh  or  yay -S testssl.sh", indent=1)
        return ssl_file

    bin_name = "testssl" if shutil.which("testssl") else "testssl.sh"
    spinner_start(f"testssl: full SSL/TLS audit on {target}...")
    out = run_cmd([
        bin_name, "--quiet", "--color", "0",
        "--severity", "MEDIUM",
        "--csvfile", str(run_dir / "ssl_results.csv"),
        target,
    ], timeout=180)
    spinner_stop()

    if out:
        ssl_file.write_text(out)
        vulns = [l for l in out.splitlines() if any(
            kw in l for kw in ["VULNERABLE", "WEAK", "EXPIRED", "BEAST", "POODLE",
                                "ROBOT", "HEARTBLEED", "CRIME", "BREACH", "FREAK",
                                "LOGJAM", "LUCKY13", "DROWN", "TICKETBLEED"]
        )]
        log("SUCCESS" if not vulns else "WARN", f"SSL findings: {len(vulns)} issues")
    return ssl_file


# ─────────────────────────────────────────────
# STAGE: HTTP REQUEST SMUGGLING
# ─────────────────────────────────────────────

def run_smuggling_scan(run_dir: Path, available: dict) -> Path:
    section("HTTP REQUEST SMUGGLING — smuggler / h2csmuggler", "5j/7")
    smuggle_file = run_dir / "smuggling_results.txt"
    all_findings: list = []

    live_urls_file = run_dir / "live_urls.txt"
    urls = read_lines(live_urls_file)[:10]

    if shutil.which("smuggler"):
        log("SCAN", f"smuggler: testing {len(urls)} endpoints for CL.TE / TE.CL smuggling...")
        for url in urls:
            out = run_cmd(["smuggler", "-u", url, "-l", "1", "--no-color"], timeout=60)
            if "vulnerable" in out.lower() or "smuggling" in out.lower():
                all_findings.append(f"[smuggling] VULNERABLE: {url}")
                log("WARN", f"  HTTP smuggling: {url}", indent=1)

    if shutil.which("h2csmuggler"):
        log("SCAN", "h2csmuggler: testing HTTP/2 cleartext upgrade smuggling...")
        for url in urls[:5]:
            out = run_cmd(["h2csmuggler", "--wordlist", "/dev/null", "-x", url], timeout=30)
            if "vulnerable" in out.lower():
                all_findings.append(f"[h2c-smuggling] {url}")

    write_lines(smuggle_file, all_findings)
    log("SUCCESS" if all_findings else "INFO", f"Smuggling findings: {len(all_findings)}")
    return smuggle_file


# ─────────────────────────────────────────────
# STAGE: CLOUD / S3 MISCONFIGURATION
# ─────────────────────────────────────────────

def run_cloud_scan(target: str, run_dir: Path, available: dict) -> Path:
    section("CLOUD & S3 MISCONFIGURATION SCAN", "5k/7")
    cloud_file = run_dir / "cloud_results.txt"
    all_findings: list = []

    if shutil.which("s3scanner"):
        domain_parts = target.split(".")
        bucket_guesses = [
            target, target.replace(".", "-"),
            f"{domain_parts[0]}-backup", f"{domain_parts[0]}-assets",
            f"{domain_parts[0]}-static", f"{domain_parts[0]}-dev",
            f"{domain_parts[0]}-prod", f"{domain_parts[0]}-staging",
        ]
        buckets_file = run_dir / "bucket_list.txt"
        write_lines(buckets_file, bucket_guesses)
        spinner_start(f"s3scanner: checking {len(bucket_guesses)} potential S3 buckets...")
        out = run_cmd(["s3scanner", "scan", "--bucket-file", str(buckets_file)], timeout=60)
        spinner_stop()
        public_hits = [l for l in out.splitlines() if "open" in l.lower() or "public" in l.lower()]
        all_findings.extend(public_hits)
        if public_hits:
            log("WARN", f"  S3: {len(public_hits)} public/misconfigured buckets", indent=1)

    if shutil.which("cloudfox") and os.environ.get("AWS_ACCESS_KEY_ID"):
        spinner_start("cloudfox: AWS cloud asset enumeration...")
        out = run_cmd(["cloudfox", "aws", "all-checks", "--output-format", "txt"], timeout=120)
        spinner_stop()
        if out:
            all_findings.append(f"[cloudfox]\n{out[:500]}")
            log("SUCCESS", "CloudFox scan complete")

    # FIX: Operator precedence bug — `out and len(out) > 20 and X or Y` evaluated
    # as `(out and len(out) > 20 and X) or Y`, making the Y condition fire even
    # when `out` is empty/short. Fixed with explicit parentheses.
    live_urls_file = run_dir / "live_urls.txt"
    urls = read_lines(live_urls_file)[:5]
    metadata_paths = [
        "http://169.254.169.254/latest/meta-data/",   # AWS IMDS
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
        "http://169.254.169.254/metadata/instance",    # Azure
    ]
    for url in urls:
        for meta_path in metadata_paths:
            out = run_cmd([
                "curl", "-sf", "--max-time", "3",
                "-H", "Metadata-Flavor: Google",
                f"{url.rstrip('/')}/ssrf?url={meta_path}",
            ], timeout=8)
            # FIX: Parentheses ensure all conditions are under the `out` guard
            if out and len(out) > 20 and ("ami-id" in out.lower() or "instance" in out.lower()):
                finding = f"[ssrf-metadata] IMDS reachable via {url}"
                all_findings.append(finding)
                log("WARN", f"  Cloud metadata SSRF: {url}", indent=1)

    write_lines(cloud_file, all_findings)
    log("SUCCESS" if all_findings else "INFO", f"Cloud findings: {len(all_findings)}")
    return cloud_file


# ─────────────────────────────────────────────
# STAGE: VHOST / SUBDOMAIN TAKEOVER
# ─────────────────────────────────────────────

def run_takeover_scan(target: str, run_dir: Path, available: dict) -> Path:
    section("SUBDOMAIN TAKEOVER SCAN — subjack / nuclei-takeover", "5l/7")
    takeover_file = run_dir / "takeover_results.txt"
    all_findings: list = []
    subdomains_file = run_dir / "subdomains.txt"

    if shutil.which("subjack"):
        n_subs = len(read_lines(subdomains_file))
        spinner_start(f"subjack: checking {n_subs} subdomains for takeover...")
        subjack_fp = os.environ.get("SUBJACK_FINGERPRINTS", "/usr/share/subjack/fingerprints.json")
        fingerprints = subjack_fp
        fp_flag = ["-c", fingerprints] if Path(fingerprints).exists() else []
        run_cmd([
            "subjack", "-w", str(subdomains_file),
            "-t", "20", "-timeout", "30", "-o", str(takeover_file), "-ssl",
        ] + fp_flag, timeout=180)
        spinner_stop()
        if takeover_file.exists():
            hits = read_lines(takeover_file)
            all_findings.extend(hits)
            if hits:
                log("WARN", f"  Takeover candidates: {len(hits)}", indent=1)

    if shutil.which("nuclei") and subdomains_file.exists():
        spinner_start("nuclei: running subdomain takeover templates...")
        to_out = run_dir / "takeover_nuclei.txt"
        run_cmd([
            "nuclei", "-l", str(subdomains_file),
            "-t", os.environ.get("NUCLEI_TAKEOVER_PATH", "~/nuclei-templates/takeovers/"),
            "-silent", "-nc", "-o", str(to_out),
        ], timeout=180)
        spinner_stop()
        if to_out.exists():
            hits = read_lines(to_out)
            all_findings.extend(hits)

    if shutil.which("ffuf"):
        dns_wordlist_env = os.environ.get("SENTINEL_DNS_WORDLIST", "")
        wordlists = [dns_wordlist_env] if dns_wordlist_env else []
        seclists_home = os.environ.get("SECLISTS_HOME", "/usr/share/seclists")
        wordlists += [
            seclists_home + "/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        ]
        wl = next((w for w in wordlists if Path(w).exists()), None)
        if wl:
            spinner_start("ffuf: virtual host discovery...")
            out = run_cmd([
                "ffuf", "-u", f"https://{target}",
                "-H", f"Host: FUZZ.{target}",
                "-w", wl, "-mc", "200,301,302,403",
                "-c", "-s", "-t", "50",
            ], timeout=120)
            spinner_stop()
            vhosts = [l.strip() for l in out.splitlines() if l.strip()]
            all_findings.extend([f"[vhost] {v}" for v in vhosts])
            if vhosts:
                log("SUCCESS", f"  Virtual hosts found: {len(vhosts)}", indent=1)

    write_lines(takeover_file, all_findings)
    log("SUCCESS" if all_findings else "INFO", f"Takeover/vhost findings: {len(all_findings)}")
    return takeover_file


# ─────────────────────────────────────────────
# STAGE: MASS PORTSCAN (masscan + rustscan)
# ─────────────────────────────────────────────

def run_mass_portscan(target: str, run_dir: Path, available: dict) -> Path:
    section("FAST PORTSCAN — masscan / rustscan", "5m/7")
    portscan_file = run_dir / "masscan_results.txt"

    if shutil.which("rustscan"):
        spinner_start(f"rustscan: ultra-fast port discovery on {target}...")
        out = run_cmd([
            "rustscan", "-a", target, "--ulimit", "500",
            "-b", "200", "--timeout", "8000",
            "--", "-sV", "--open",
        ], timeout=120)
        spinner_stop()
        if out:
            portscan_file.write_text(out)
            open_ports = [l for l in out.splitlines() if "/tcp" in l and "open" in l]
            log("SUCCESS", f"rustscan → {len(open_ports)} open ports")

    elif shutil.which("masscan"):
        spinner_start(f"masscan: scanning all 65535 ports on {target}...")
        out = run_cmd([
            "masscan", target, "-p0-65535",
            "--rate", "10000",
            "--output-format", "list",
            "--output-file", str(portscan_file),
        ], timeout=300)
        spinner_stop()
        results = read_lines(portscan_file)
        log("SUCCESS", f"masscan → {len(results)} open ports")
    else:
        log("WARN", "Neither rustscan nor masscan installed — skipping fast portscan")

    return portscan_file


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _load_nuclei_json(path: Path) -> list:
    """Handle both JSONL (one JSON object per line) and JSON array formats."""
    findings = []
    if not path.exists():
        return findings
    content = path.read_text().strip()
    if not content:
        return findings
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    if not findings:
        try:
            arr = json.loads(content)
            if isinstance(arr, list):
                findings = arr
        except json.JSONDecodeError:
            pass
    return findings


def categorize_vuln(name: str, template_id: str) -> str:
    combined = (name + " " + template_id).lower()
    for cat, keywords in VULN_CATEGORIES.items():
        if any(k in combined for k in keywords):
            return cat
    return "other"


def confidence_from_nuclei(vuln: dict) -> int:
    score = 50
    info = vuln.get("info", {})
    sev = info.get("severity", "unknown").lower()
    if sev in ("critical", "high"):  score += 15
    if sev == "medium":              score += 5
    if info.get("classification", {}).get("cve-id"):  score += 20
    if vuln.get("matched-at"):       score += 10
    if vuln.get("extracted-results"):score += 5
    return min(100, score)


# ─────────────────────────────────────────────
# STAGE 6: AI ANALYSIS
# ─────────────────────────────────────────────

def run_ai_analysis(
    conn: sqlite3.Connection,
    scan_id: int,
    nuclei_findings: list,
    xss_results: list,
    sqli_results: list,
) -> None:
    section("AI ANALYSIS — Vulnerability Intelligence", "6/7")

    if not AI_AVAILABLE:
        log("WARN", "No AI backend available — skipping AI analysis.")
        log("WARN", "→ Install Ollama: ollama pull mistral   (https://ollama.com)")
        _upsert_all_findings_no_ai(conn, scan_id, nuclei_findings, xss_results, sqli_results)
        return

    total = len(nuclei_findings) + len(xss_results) + len(sqli_results)
    backend_label = "Ollama" if AI_BACKEND == "ollama" else "OpenRouter" if AI_BACKEND == "openrouter" else "Cerebras" if AI_BACKEND == "cerebras" else "OpenCode" if AI_BACKEND == "opencode" else "AI"
    log("AI", f"AI backend: {backend_label} ({AI_MODEL})")
    log("AI", f"Analyzing {total} findings with {backend_label}…")

    # Rate-limit / overload circuit breaker:
    # - Cap total AI calls to avoid exhausting free-tier quotas on large scans
    # - After 3 consecutive empty responses, assume rate-limit hit and stop early
    # - Per-finding deduplication: skip findings whose hash is already enriched in DB
    MAX_AI_CALLS = 30       # max enrichment calls per scan
    ai_calls_made = 0
    consecutive_failures = 0
    MAX_CONSECUTIVE_FAILURES = 3

    # Pre-build set of already-enriched finding_hashes so we never hit the API
    # twice for a finding that was enriched in a previous scan run.
    already_enriched: set = set()
    try:
        rows = conn.execute(
            "SELECT finding_hash FROM findings WHERE scan_id=? AND ai_explanation IS NOT NULL AND ai_explanation != ''",
            (scan_id,),
        ).fetchall()
        already_enriched = {r[0] for r in rows}
    except Exception:
        pass

    def _try_enrich(finding: dict) -> dict:
        """Call AI enrichment with circuit-breaker tracking."""
        nonlocal ai_calls_made, consecutive_failures
        if ai_calls_made >= MAX_AI_CALLS:
            return {}
        if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
            return {}
        ai_calls_made += 1
        result = ai_explain_vulnerability(finding)
        if result:
            consecutive_failures = 0
        else:
            consecutive_failures += 1
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                log("WARN", f"AI: {consecutive_failures} consecutive empty responses — rate-limit likely. Skipping remaining AI calls.", indent=1)
        return result

    # --- Nuclei findings ---
    for i, vuln in enumerate(nuclei_findings):
        info        = vuln.get("info", {})
        name        = info.get("name", "Unknown")
        severity    = info.get("severity", "unknown").lower()
        host        = vuln.get("host", "")
        matched_at  = vuln.get("matched-at", vuln.get("matched", ""))
        template_id = vuln.get("template-id", "")
        cvss        = info.get("classification", {}).get("cvss-score", None)
        cve_ids     = info.get("classification", {}).get("cve-id", [])
        cwe_ids     = info.get("classification", {}).get("cwe-id", [])
        if isinstance(cve_ids, str): cve_ids = [cve_ids]
        if isinstance(cwe_ids, str): cwe_ids = [cwe_ids]
        refs        = info.get("reference", [])
        if isinstance(refs, str): refs = [refs]

        finding = {
            "source":          "nuclei",
            "severity":        severity,
            "name":            name,
            "template_id":     template_id,
            "host":            host,
            "matched_at":      matched_at,
            "cvss_score":      cvss,
            "cve_ids":         cve_ids,
            "cwe_ids":         cwe_ids,
            "raw_description": info.get("description", ""),
            "remediation":     info.get("remediation", ""),
            "references":      refs[:5],
            "category":        categorize_vuln(name, template_id),
            "confidence":      confidence_from_nuclei(vuln),
            "raw_json":        json.dumps(vuln),
        }

        row_id = upsert_finding(conn, scan_id, finding)
        if row_id is None:
            continue

        # Skip AI enrichment if this finding was already enriched (deduplication)
        fhash = finding_hash(
            finding.get("source", ""),
            finding.get("name", ""),
            finding.get("host", ""),
            finding.get("matched_at", ""),
        )
        if fhash in already_enriched:
            continue

        if severity in ("critical", "high", "medium"):
            log("AI", f"[{i+1}/{len(nuclei_findings)}] Enriching: {name[:60]}", indent=1)
            ai = _try_enrich(finding)
            if ai:
                conf_adj = ai.get("confidence_adjustment", 0)
                new_conf = min(100, max(0, finding["confidence"] + conf_adj))
                conn.execute("""
                    UPDATE findings SET
                        ai_explanation=?, ai_impact=?, ai_poc=?, ai_remediation=?,
                        ai_effort_to_fix=?, ai_bounty_value=?, confidence=?
                    WHERE id=?
                """, (
                    ai.get("explanation", ""),
                    ai.get("impact", ""),
                    ai.get("poc", ""),
                    ai.get("remediation", ""),
                    ai.get("effort_to_fix", ""),
                    ai.get("bounty_value", ""),
                    new_conf,
                    row_id,
                ))
                conn.commit()
        else:
            conn.execute("""
                UPDATE findings SET
                    ai_explanation=?, ai_impact=?, ai_poc=?, ai_remediation=?
                WHERE id=?
            """, (
                info.get("description", ""),
                "",
                f"Access {matched_at} and observe the finding.",
                info.get("remediation", ""),
                row_id,
            ))
            conn.commit()

    # --- XSS findings ---
    for i, line in enumerate(xss_results[:30]):
        xss_host_match = re.search(r"https?://[^/ ]+", line)
        finding = {
            "source":          "dalfox",
            "severity":        "high",
            "name":            "Cross-Site Scripting (XSS)",
            "template_id":     "xss-dalfox",
            "host":            xss_host_match.group() if xss_host_match else "",
            "matched_at":      line[:200],
            "cvss_score":      6.1,
            "cve_ids":         [],
            "cwe_ids":         ["CWE-79"],
            "raw_description": "Reflected or DOM-based XSS detected by Dalfox.",
            "remediation":     "Encode all output. Implement Content-Security-Policy.",
            "references":      ["https://owasp.org/www-community/attacks/xss/"],
            "category":        "injection",
            "confidence":      75,
            "raw_json":        json.dumps({"raw": line}),
        }
        row_id = upsert_finding(conn, scan_id, finding)
        if ai_calls_made < MAX_AI_CALLS and consecutive_failures < MAX_CONSECUTIVE_FAILURES:
            log("AI", f"XSS [{i+1}/{min(len(xss_results),30)}]: triage…", indent=1)
            ai = ai_triage_xss(line)
            ai_calls_made += 1
            if ai:
                consecutive_failures = 0
            else:
                consecutive_failures += 1
            if row_id and ai:
                conn.execute("""
                    UPDATE findings SET ai_explanation=?, ai_impact=?, ai_poc=?, ai_remediation=?
                    WHERE id=?
                """, (ai.get("explanation",""), ai.get("impact",""), ai.get("poc",""), ai.get("remediation",""), row_id))
                conn.commit()

    # --- SQLi findings ---
    for i, line in enumerate(sqli_results[:20]):
        sqli_host_match = re.search(r"https?://[^/ ]+", line)
        finding = {
            "source":          "sqlmap",
            "severity":        "critical",
            "name":            "SQL Injection",
            "template_id":     "sqli-sqlmap",
            "host":            sqli_host_match.group() if sqli_host_match else "",
            "matched_at":      line[:200],
            "cvss_score":      9.8,
            "cve_ids":         [],
            "cwe_ids":         ["CWE-89"],
            "raw_description": "SQL injection vulnerability confirmed by SQLMap.",
            "remediation":     "Use parameterized queries or prepared statements. Never interpolate user input into SQL.",
            "references":      ["https://owasp.org/www-community/attacks/SQL_Injection"],
            "category":        "injection",
            "confidence":      90,
            "raw_json":        json.dumps({"raw": line}),
        }
        row_id = upsert_finding(conn, scan_id, finding)
        if ai_calls_made < MAX_AI_CALLS and consecutive_failures < MAX_CONSECUTIVE_FAILURES:
            log("AI", f"SQLi [{i+1}/{min(len(sqli_results),20)}]: triage…", indent=1)
            ai = ai_triage_sqli(line)
            ai_calls_made += 1
            if ai:
                consecutive_failures = 0
            else:
                consecutive_failures += 1
            if row_id and ai:
                conn.execute("""
                    UPDATE findings SET ai_explanation=?, ai_impact=?, ai_poc=?, ai_remediation=?
                    WHERE id=?
                """, (ai.get("explanation",""), ai.get("impact",""), ai.get("poc",""), ai.get("remediation",""), row_id))
                conn.commit()

    total_enriched = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE scan_id=? AND ai_explanation IS NOT NULL AND ai_explanation != ''",
        (scan_id,)
    ).fetchone()[0]
    log("SUCCESS", f"AI analysis complete. {total_enriched} findings enriched.")


def _upsert_all_findings_no_ai(conn, scan_id, nuclei_findings, xss_results, sqli_results):
    """Upsert findings to DB even when AI is disabled."""
    for vuln in nuclei_findings:
        info = vuln.get("info", {})
        name = info.get("name", "Unknown")
        severity = info.get("severity", "unknown").lower()
        host = vuln.get("host", "")
        matched_at = vuln.get("matched-at", vuln.get("matched", ""))
        template_id = vuln.get("template-id", "")
        cvss = info.get("classification", {}).get("cvss-score", None)
        cve_ids = info.get("classification", {}).get("cve-id", [])
        cwe_ids = info.get("classification", {}).get("cwe-id", [])
        if isinstance(cve_ids, str): cve_ids = [cve_ids]
        if isinstance(cwe_ids, str): cwe_ids = [cwe_ids]
        refs = info.get("reference", [])
        if isinstance(refs, str): refs = [refs]
        finding = {
            "source": "nuclei", "severity": severity, "name": name,
            "template_id": template_id, "host": host, "matched_at": matched_at,
            "cvss_score": cvss, "cve_ids": cve_ids, "cwe_ids": cwe_ids,
            "raw_description": info.get("description", ""),
            "remediation": info.get("remediation", ""),
            "references": refs[:5], "category": categorize_vuln(name, template_id),
            "confidence": confidence_from_nuclei(vuln), "raw_json": json.dumps(vuln),
        }
        upsert_finding(conn, scan_id, finding)

    for line in xss_results[:30]:
        m = re.search(r"https?://[^/ ]+", line)
        finding = {
            "source": "dalfox", "severity": "high",
            "name": "Cross-Site Scripting (XSS)", "template_id": "xss-dalfox",
            "host": m.group() if m else "", "matched_at": line[:200],
            "cvss_score": 6.1, "cve_ids": [], "cwe_ids": ["CWE-79"],
            "raw_description": "Reflected or DOM-based XSS detected by Dalfox.",
            "remediation": "Encode all output. Implement CSP.",
            "references": ["https://owasp.org/www-community/attacks/xss/"],
            "category": "injection", "confidence": 75,
            "raw_json": json.dumps({"raw": line}),
        }
        upsert_finding(conn, scan_id, finding)

    for line in sqli_results[:20]:
        m = re.search(r"https?://[^/ ]+", line)
        finding = {
            "source": "sqlmap", "severity": "critical",
            "name": "SQL Injection", "template_id": "sqli-sqlmap",
            "host": m.group() if m else "", "matched_at": line[:200],
            "cvss_score": 9.8, "cve_ids": [], "cwe_ids": ["CWE-89"],
            "raw_description": "SQL injection vulnerability confirmed by SQLMap.",
            "remediation": "Use parameterized queries.",
            "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
            "category": "injection", "confidence": 90,
            "raw_json": json.dumps({"raw": line}),
        }
        upsert_finding(conn, scan_id, finding)


# ─────────────────────────────────────────────
# STAGE 7: REPORT GENERATION
# ─────────────────────────────────────────────

def generate_report(
    target: str,
    run_dir: Path,
    conn: sqlite3.Connection,
    scan_id: int,
    subdomains_file: Path,
    live_hosts_file: Path,
    nuclei_json: Path,
    xss_file: Path | None = None,
    sqli_file: Path | None = None,
    nmap_file: Path | None = None,
    fuzz_file: Path | None = None,
    nikto_file: Path | None = None,
    all_urls_file: Path | None = None,
) -> Path:
    section("REPORT GENERATION — AI-Enhanced", "7/7")

    subdomains    = read_lines(subdomains_file)
    live_hosts    = read_lines(live_hosts_file)
    fuzz_results  = read_lines(fuzz_file) if fuzz_file else []
    all_urls      = read_lines(all_urls_file) if all_urls_file else []
    xss_results   = read_lines(xss_file) if xss_file else []
    sqli_results  = read_lines(sqli_file) if sqli_file else []

    db_findings = conn.execute("""
        SELECT * FROM findings WHERE scan_id=?
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium'   THEN 3 WHEN 'low'  THEN 4
                ELSE 5
            END, name
    """, (scan_id,)).fetchall()

    by_sev: dict = {}
    for f in db_findings:
        sev = f["severity"] or "unknown"
        by_sev.setdefault(sev, []).append(dict(f))

    critical_n  = len(by_sev.get("critical", []))
    high_n      = len(by_sev.get("high", []))
    medium_n    = len(by_sev.get("medium", []))
    low_n       = len(by_sev.get("low", []))
    risk_score  = min(100, critical_n*25 + high_n*10 + medium_n*3 + low_n + len(xss_results)*5 + len(sqli_results)*10)
    risk_label  = "CRITICAL" if risk_score >= 75 else "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 25 else "LOW"

    stats = {
        "subdomains":  len(subdomains),
        "live_hosts":  len(live_hosts),
        "urls":        len(all_urls),
        "risk_score":  risk_score,
        "xss":         len(xss_results),
        "sqli":        len(sqli_results),
    }

    conn.execute("""
        INSERT OR REPLACE INTO scan_stats
            (scan_id, subdomains, live_hosts, urls, fuzz_paths, risk_score)
        VALUES (?,?,?,?,?,?)
    """, (scan_id, len(subdomains), len(live_hosts), len(all_urls), len(fuzz_results), risk_score))
    conn.commit()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Generate executive summary — always produce a plain-text fallback so
    # the report is complete even when AI is unavailable or rate-limited.
    exec_summary = ""
    if AI_AVAILABLE:
        log("AI", "Generating AI executive summary…")
        try:
            exec_summary = ai_executive_summary(target, stats, {
                sev: [{"name": f["name"]} for f in lst]
                for sev, lst in by_sev.items()
            })
        except Exception as e:
            log("WARN", f"AI executive summary failed: {e} — using plain summary", indent=1)

    if not exec_summary:
        # Plain-text summary generated without AI
        total_n = len(db_findings)
        sev_parts = [
            f"{len(by_sev.get(s, []))} {s}"
            for s in ["critical", "high", "medium", "low"]
            if by_sev.get(s)
        ]
        exec_summary = (
            f"Scan of **{target}** completed at {now}. "
            f"Discovered {stats.get('subdomains', 0)} subdomains, "
            f"{stats.get('live_hosts', 0)} live hosts, and "
            f"{stats.get('urls', 0)} URLs. "
            f"Total findings: {total_n}" +
            (f" ({', '.join(sev_parts)})." if sev_parts else ".") +
            (f" {stats.get('xss', 0)} XSS and {stats.get('sqli', 0)} SQLi confirmed." if stats.get('xss') or stats.get('sqli') else "") +
            f" Overall risk score: {stats.get('risk_score', 0)}/100."
        )

    lines: list = []
    lines += [
        f"# 🔍 Security Report — `{target}`",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Target** | `{target}` |",
        f"| **Generated** | {now} |",
        f"| **Agent Version** | v{VERSION} |",
        f"| **AI Analysis** | {'✅ Enabled (' + AI_BACKEND_LABEL + ')' if AI_AVAILABLE else '❌ Disabled'} |",
        f"| **Output Directory** | `{run_dir}` |",
        f"| **Database** | `{run_dir / 'findings.db'}` |",
        "",
    ]

    lines += [
        "---",
        "## 📋 Executive Summary",
        "",
        exec_summary,
        "",
    ]

    lines += [
        "---",
        "## 📊 Scan Statistics",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Subdomains discovered | {len(subdomains)} |",
        f"| Live hosts detected | {len(live_hosts)} |",
        f"| Total URLs collected | {len(all_urls)} |",
        f"| Fuzz paths found | {len(fuzz_results)} |",
        f"| **Total findings (DB)** | **{len(db_findings)}** |",
    ]
    for sev in SEVERITY_ORDER:
        count = len(by_sev.get(sev, []))
        if count:
            emoji = SEVERITY_EMOJI.get(sev, "")
            lines.append(f"| {emoji} {sev.capitalize()} | {count} |")
    if xss_results:
        lines.append(f"| 💉 XSS (Dalfox) | {len(xss_results)} |")
    if sqli_results:
        lines.append(f"| 🗃️ SQLi (SQLMap) | {len(sqli_results)} |")
    lines.append("")

    risk_bar = "█" * (risk_score // 10) + "░" * (10 - risk_score // 10)
    lines += [
        "---",
        "## 🎯 Risk Assessment",
        "",
        f"**Overall Risk: {risk_label} — {risk_score}/100**",
        "",
        f"```",
        f"Risk  [{risk_bar}] {risk_score}/100  ({risk_label})",
        f"```",
        "",
    ]

    lines += ["---", "## 🐛 Vulnerability Findings — Detailed Analysis", ""]

    if not db_findings:
        lines.append("_No findings recorded in this scan._\n")
    else:
        for sev in SEVERITY_ORDER:
            findings_in_sev = by_sev.get(sev, [])
            if not findings_in_sev:
                continue
            emoji = SEVERITY_EMOJI.get(sev, "")
            lines += [f"### {emoji} {sev.upper()} Severity ({len(findings_in_sev)} findings)", ""]
            for f in findings_in_sev:
                lines += [
                    f"#### `{f['name']}`",
                    "",
                    f"| Field | Value |",
                    f"|-------|-------|",
                    f"| **Source** | {f['source']} |",
                    f"| **Host** | `{f['host']}` |",
                    f"| **Matched At** | `{f.get('matched_at','')[:120]}` |",
                    f"| **Template ID** | `{f.get('template_id','')}` |",
                    f"| **Confidence** | {f.get('confidence',50)}% |",
                ]
                if f.get('cvss_score'):
                    lines.append(f"| **CVSS** | {f['cvss_score']} |")
                cve_ids = json.loads(f.get('cve_ids') or '[]')
                if cve_ids:
                    lines.append(f"| **CVEs** | {', '.join(cve_ids)} |")
                lines.append("")

                if f.get('ai_explanation'):
                    lines += [
                        "**🤖 AI Analysis**",
                        "",
                        f"> {f['ai_explanation']}",
                        "",
                    ]
                if f.get('ai_impact'):
                    lines += [
                        "**💥 Impact**",
                        "",
                        f"{f['ai_impact']}",
                        "",
                    ]
                if f.get('ai_poc'):
                    lines += [
                        "**🧪 Proof of Concept**",
                        "",
                        "```",
                        f"{f['ai_poc']}",
                        "```",
                        "",
                    ]
                if f.get('ai_remediation'):
                    lines += [
                        "**🔧 Remediation**",
                        "",
                        f"{f['ai_remediation']}",
                        "",
                    ]
                elif f.get('remediation'):
                    lines += [
                        "**🔧 Remediation**",
                        "",
                        f"{f['remediation']}",
                        "",
                    ]
                lines.append("---")

    lines += [
        "## 🗂️ Remediation Priority Matrix",
        "",
        "| Priority | Finding | Severity | Confidence | Action |",
        "|----------|---------|----------|------------|--------|",
    ]
    for f in db_findings[:20]:
        prio = "🔴 P1 — Now" if f["severity"] == "critical" else \
               "🟠 P2 — 24h" if f["severity"] == "high" else \
               "🟡 P3 — 2wk" if f["severity"] == "medium" else \
               "🔵 P4 — Sprint"
        lines.append(f"| {prio} | {f['name'][:40]} | {f['severity'].upper()} | {f.get('confidence',50)}% | Verify & patch |")
    lines.append("")

    lines += [
        "---",
        "## ⚠️ Legal Disclaimer",
        "",
        "> This report was generated by an automated agent for **authorized penetration testing only**.",
        "> Findings must be verified manually before reporting. Only test targets you have **explicit written permission** to scan.",
        "",
        f"*Generated by SENTINEL v{VERSION} at {now}*  ",
        f"*AI Analysis: {AI_BACKEND_LABEL if AI_AVAILABLE else 'Disabled'}*",
    ]

    # Roadmap Phase 1: Tool Health section
    tool_health_rows = get_tool_health_report(conn, scan_id)
    if tool_health_rows:
        lines += [
            "",
            "---",
            "## 🔧 Tool Health Report",
            "",
            "| Tool | Status | Health | Runs | Crashes | Timeouts | Runtime | Findings |",
            "|------|--------|--------|------|---------|----------|---------|----------|",
        ]
        for th in tool_health_rows:
            status = "✅ installed" if th["installed"] else "❌ missing"
            score  = th["health_score"]
            score_emoji = "🟢" if score >= 80 else "🟡" if score >= 50 else "🔴"
            lines.append(
                f"| `{th['tool']}` | {status} | {score_emoji} {score}/100 | "
                f"{th['total_runs']} | {th['crashes']} | {th['timeouts']} | "
                f"{th['total_runtime_sec']:.1f}s | {th['findings_attributed']} |"
            )

    report_file = run_dir / f"report_{TIMESTAMP}.md"
    report_file.write_text("\n".join(lines), encoding="utf-8")
    log("SUCCESS", f"Report saved → {report_file}")
    return report_file


# ─────────────────────────────────────────────
# STATS SUMMARY
# ─────────────────────────────────────────────

def print_summary(target, run_dir, report_file, conn, scan_id):
    db_findings = conn.execute(
        "SELECT severity, COUNT(*) as n FROM findings WHERE scan_id=? GROUP BY severity",
        (scan_id,)
    ).fetchall()
    by_sev = {r["severity"]: r["n"] for r in db_findings}
    total  = sum(by_sev.values())

    print(f"\n{C['cyan']}{'═'*62}{C['reset']}")
    print(f"{C['bold']}{C['white']}  SCAN COMPLETE — {target}{C['reset']}")
    print(f"{C['cyan']}{'═'*62}{C['reset']}")
    print(f"  {C['dim']}Total findings:{C['reset']}{C['white']} {total}{C['reset']}")
    for sev in SEVERITY_ORDER:
        n = by_sev.get(sev, 0)
        if n:
            emoji = SEVERITY_EMOJI.get(sev, "")
            col   = {"critical":C["red"],"high":C["yellow"],"medium":C["magenta"]}.get(sev, C["cyan"])
            print(f"    {emoji}  {col}{sev.capitalize():10}{C['reset']} {n}")
    enriched = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE scan_id=? AND ai_explanation IS NOT NULL AND ai_explanation!=''",
        (scan_id,)
    ).fetchone()[0]
    print(f"  {C['dim']}AI-enriched:{C['reset']}{C['magenta']} {enriched} findings{C['reset']}")
    print(f"\n  {C['green']}Report:{C['reset']}   {report_file}")
    print(f"  {C['green']}Database:{C['reset']} {run_dir / 'findings.db'}")
    print(f"  {C['green']}Dir:    {C['reset']}   {run_dir}")
    print(f"{C['cyan']}{'═'*62}{C['reset']}\n")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    global AI_AVAILABLE, AI_BACKEND, AI_BACKEND_LABEL, AI_MODEL
    global AI_DELAY, _scan_conn, _scan_id_global

    try:
        from config import get_config as _get_cfg
        _cfg = _get_cfg()
        os.environ.setdefault("SENTINEL_DIR", _cfg.sentinel.data_dir)
    except Exception:
        pass

    banner()

    parser = argparse.ArgumentParser(
        description=f"SENTINEL — Cybersecurity Intelligence Platform v{VERSION}",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target", help="Target domain (e.g. example.com)")
    parser.add_argument("--severity", default="critical,high,medium")
    parser.add_argument(
        "--output-dir", default=str(SENTINEL_SCANS_DIR),
        help=f"Scan output directory (default: {SENTINEL_SCANS_DIR})",
    )
    parser.add_argument("--skip-check", action="store_true")
    parser.add_argument("--stages", default="all")
    parser.add_argument("--enable-intrusive", action="store_true")
    parser.add_argument("--no-ai", action="store_true")
    parser.add_argument(
        "--ai-delay", type=float, default=None,
        help="Seconds to wait between AI calls (default: 0 for Ollama, 0.3 for Cerebras). "
             "Increase if hitting rate limits.",
    )
    parser.add_argument(
        "--yes", "-y", action="store_true",
        help="Auto-accept legal disclaimer (for CI/headless mode). "
             "Only use if you have written authorization.",
    )
    args = parser.parse_args()

    # FIX: Validate target before doing anything else
    try:
        target = validate_target(args.target)
    except ValueError as e:
        print(f"{C['red']}❌ Invalid target: {e}{C['reset']}")
        sys.exit(1)

    # ── Legal disclaimer enforcement (Architecture §8.3) ──
    # Cannot be globally disabled. Suppressed after first ack per target.
    if not enforce_legal_disclaimer(target, auto_accept=args.yes):
        sys.exit(1)

    if not args.no_ai:
        AI_AVAILABLE, AI_BACKEND, AI_BACKEND_LABEL = detect_ai_backend()
        if AI_AVAILABLE and AI_BACKEND == "ollama":
            AI_MODEL = f"Ollama ({_OLLAMA_RESOLVED_MODEL or OLLAMA_MODEL})"
        elif AI_AVAILABLE and AI_BACKEND == "openrouter":
            AI_MODEL = f"OpenRouter ({OPENROUTER_MODEL})"
        elif AI_AVAILABLE and AI_BACKEND == "cerebras":
            AI_MODEL = f"Cerebras ({CEREBRAS_MODEL})"
    else:
        AI_AVAILABLE = False

    # Configure the rate limiter to the correct RPM for this backend.
    # AI_DELAY is kept only if explicitly passed via --ai-delay (extra throttle).
    _configure_rate_limiter(AI_BACKEND)
    if args.ai_delay is not None:
        AI_DELAY = args.ai_delay
    # else AI_DELAY stays 0.0 — the sliding-window limiter handles pacing alone.

    stages  = set(args.stages.lower().split(",")) if args.stages != "all" else {"all"}
    run_all = "all" in stages
    intrusive = args.enable_intrusive

    available = check_tools() if not args.skip_check else {t: bool(shutil.which(t)) for t in ALL_TOOLS}

    # ── Canonical output path: ~/.sentinel/scans/{target}_{timestamp}/ ──
    run_dir = Path(args.output_dir) / f"{target}_{TIMESTAMP}"
    run_dir.mkdir(parents=True, exist_ok=True)
    # Also create stage_outputs/ subdirectory for raw tool output
    (run_dir / "stage_outputs").mkdir(exist_ok=True)
    log("INFO", f"Output directory: {run_dir}")

    db_path = run_dir / "findings.db"
    conn = init_db(db_path)

    # FIX: Register conn globally for SIGINT handler
    _scan_conn = conn

    cur = conn.execute(
        "INSERT INTO scans (target, run_id, started_at) VALUES (?,?,?)",
        (target, TIMESTAMP, datetime.now().isoformat()),
    )
    scan_id = cur.lastrowid
    if scan_id is None:
        raise RuntimeError("Failed to register scan in the database")
    scan_id = int(scan_id)
    conn.commit()

    # FIX: Register scan_id globally for SIGINT handler
    _scan_id_global = scan_id
    # Register run_dir and stage tracking for improved SIGINT handler
    global _run_dir_global, _current_stage_global, _completed_stages_global
    _run_dir_global = run_dir
    _current_stage_global = Stage.VALIDATE.value
    _completed_stages_global = []

    # Roadmap Phase 1: snapshot tool health into DB
    record_tool_health(conn, scan_id, available)

    # ── Initial state.json (Architecture §4.1 — resumable scans) ──
    completed_stages: list[Stage] = []
    _write_state(run_dir, Stage.VALIDATE, completed_stages, "running")

    if AI_AVAILABLE:
        log("AI", f"AI analysis enabled — {AI_BACKEND_LABEL}")
        if AI_DELAY > 0:
            log("INFO", f"AI inter-call delay: {AI_DELAY}s")
    else:
        log("WARN", "AI analysis disabled. Install Ollama or set a cloud API key (GROQ/OPENROUTER/OPENCODE).")

    # ── Pipeline with Stage enum transitions ──
    def _run_stage(stage: Stage, fn, *fn_args):
        """Execute a pipeline stage with state tracking."""
        global _current_stage_global, _completed_stages_global
        _current_stage_global = stage.value
        _completed_stages_global = [s.value for s in completed_stages]
        t0 = time.time()
        emit_stage_started(stage)
        _write_state(run_dir, stage, completed_stages, "running")
        try:
            result = fn(*fn_args)
        except Exception as e:
            log("ERROR", f"Stage {stage.value} failed: {e}", indent=1)
            _write_state(run_dir, stage, completed_stages, "error")
            return None
        dur = time.time() - t0
        completed_stages.append(stage)
        emit_stage_complete(stage, dur)
        _write_state(run_dir, stage, completed_stages, "running")
        return result

    # VALIDATE stage — target already validated above
    emit_stage_started(Stage.VALIDATE)
    completed_stages.append(Stage.VALIDATE)
    emit_stage_complete(Stage.VALIDATE, 0.0)

    # RECON stage
    subdomains_file = _run_stage(Stage.RECON, run_recon, target, run_dir, available) \
        if run_all or "recon" in stages else run_dir / "subdomains.txt"
    if subdomains_file is None:
        subdomains_file = run_dir / "subdomains.txt"

    # PROBE stage
    live_hosts_file = _run_stage(Stage.PROBE, run_probing, subdomains_file, run_dir, available) \
        if run_all or "probe" in stages else run_dir / "live_hosts.txt"
    if live_hosts_file is None:
        live_hosts_file = run_dir / "live_hosts.txt"

    # CRAWL stage (URL discovery)
    all_urls_file = _run_stage(Stage.CRAWL, run_url_discovery, live_hosts_file, target, run_dir, available) \
        if run_all or "urls" in stages else run_dir / "all_urls.txt"
    if all_urls_file is None:
        all_urls_file = run_dir / "all_urls.txt"

    # FUZZ stage
    fuzz_file = _run_stage(Stage.FUZZ, run_fuzzing, live_hosts_file, run_dir, available) \
        if run_all or "fuzz" in stages else run_dir / "fuzz_results.txt"
    if fuzz_file is None:
        fuzz_file = run_dir / "fuzz_results.txt"

    # PORTSCAN stage
    if run_all or "nmap" in stages:
        nmap_file = _run_stage(Stage.PORTSCAN, run_nmap, target, run_dir, available)
        _run_stage(Stage.PORTSCAN, run_mass_portscan, target, run_dir, available)
    else:
        nmap_file = None

    # SCAN stage (nuclei, XSS)
    nuclei_json = _run_stage(Stage.SCAN, run_nuclei_scan, run_dir, available, args.severity) \
        if run_all or "nuclei" in stages else run_dir / "nuclei_results.json"
    if nuclei_json is None:
        nuclei_json = run_dir / "nuclei_results.json"

    xss_file = _run_stage(Stage.SCAN, run_xss_scan, run_dir, available) \
        if run_all or "xss" in stages else None

    # INJECT stage (intrusive: SQLi, Nikto, SSTI, CMDi, SSRF, CRLF, open-redirect)
    # FIX: sqli/nikto check their own stage keywords; injection/smuggling/cloud
    # run whenever intrusive is enabled (they have no dedicated UI chip).
    sqli_file   = None
    nikto_file  = None
    if intrusive:
        if run_all or "sqli" in stages:
            sqli_file = _run_stage(Stage.INJECT, run_sqli_scan, run_dir, available)
        if run_all or "nikto" in stages:
            nikto_file = _run_stage(Stage.INJECT, run_nikto_scan, live_hosts_file, run_dir, available)
        # FIX: injection/smuggling/cloud have no dedicated chip — run them whenever
        # intrusive mode is on (they were previously gated on "inject"/"smuggling"/"cloud"
        # keywords that the UI never sends, making them unreachable).
        _run_stage(Stage.INJECT, run_injection_scans, run_dir, available)
        _run_stage(Stage.PROTO,  run_smuggling_scan, run_dir, available)
        _run_stage(Stage.CLOUD,  run_cloud_scan, target, run_dir, available)
    else:
        log("INFO", "Intrusive scans (SQLMap, Nikto, SSTI, CMDi) skipped. Use --enable-intrusive to enable.")

    # SECRETS stage
    if run_all or "secrets" in stages:
        _run_stage(Stage.SECRETS, run_secrets_scan, target, run_dir, available)

    # PROTO stage
    if run_all or "cors" in stages:
        _run_stage(Stage.PROTO, run_cors_scan, run_dir, available)
    if run_all or "ssl" in stages:
        _run_stage(Stage.PROTO, run_ssl_scan, target, run_dir, available)
    if run_all or "takeover" in stages:
        _run_stage(Stage.PROTO, run_takeover_scan, target, run_dir, available)

    # AI_ENRICH stage
    # FIX: AI enrichment must always run when findings exist — it was gated on
    # "ai" being in the stages set, but the UI never sends that keyword, causing
    # AI analysis to be silently skipped on every scan launched from the UI.
    nuclei_findings = _load_nuclei_json(nuclei_json)
    xss_results     = read_lines(xss_file) if xss_file else []
    sqli_results    = read_lines(sqli_file) if sqli_file else []

    _run_stage(Stage.AI_ENRICH, run_ai_analysis, conn, scan_id,
               nuclei_findings, xss_results, sqli_results)

    # REPORT stage
    report_file = _run_stage(
        Stage.REPORT, generate_report,
        target, run_dir, conn, scan_id,
        subdomains_file, live_hosts_file, nuclei_json,
        xss_file, sqli_file, nmap_file, fuzz_file, nikto_file, all_urls_file,
    )

    conn.execute(
        "UPDATE scans SET finished_at=?, status=? WHERE id=?",
        (datetime.now().isoformat(), "complete", scan_id),
    )
    conn.commit()
    _write_state(run_dir, Stage.REPORT, completed_stages, "complete")

    print_summary(target, run_dir, report_file, conn, scan_id)

    # ── Phase 2: Feed completed scan into memory learning loop ──
    if _memory_available and mem_mod is not None:
        try:
            findings_rows = conn.execute(
                "SELECT template_id, name, severity, category, host, matched_at, "
                "raw_description, false_positive "
                "FROM findings WHERE scan_id=?", (scan_id,)
            ).fetchall()
            finding_dicts = [dict(zip(
                ["template_id","name","severity","category","host","matched_at",
                 "raw_description","false_positive"], row
            )) for row in findings_rows]
            import memory as mem_mod
            risk_score = mem_mod.compute_risk_score(finding_dicts) if hasattr(mem_mod, 'compute_risk_score') else 0

            # Build tech_stack from httpx live_hosts output
            tech_stack = {}
            if live_hosts_file and live_hosts_file.exists():
                for line in read_lines(live_hosts_file):
                    tech_matches = re.findall(r'\[(\w+(?:[-\+]\w+)*)\]', line)
                    for t in tech_matches:
                        tech_stack[t.lower()] = True
            whatweb_file = run_dir / "whatweb.txt"
            if whatweb_file.exists():
                for line in read_lines(whatweb_file):
                    techs = re.findall(r'([\w\-\+]+)\[', line)
                    for t in techs:
                        tech_stack[t.lower()] = True

            # Build tools_run from tool_health table
            tools_run = {}
            try:
                tool_rows = conn.execute(
                    "SELECT tool, total_runs FROM tool_health WHERE scan_id=? AND total_runs > 0",
                    (scan_id,)
                ).fetchall()
                for row in tool_rows:
                    tools_run[row[0]] = row[1]
            except Exception:
                pass

            # Parse subdomains
            subdomains = read_lines(subdomains_file) if subdomains_file and subdomains_file.exists() else []

            # Parse XSS payload hits from dalfox output
            xss_payloads_hit = []
            if xss_file and xss_file.exists():
                for line in read_lines(xss_file):
                    try:
                        data = json.loads(line)
                        param = data.get("param", "")
                        if param:
                            xss_payloads_hit.append(param)
                    except (json.JSONDecodeError, TypeError):
                        if "=" in line:
                            xss_payloads_hit.append(line.strip())

            # Parse SQLi payload hits from sqlmap output
            sqli_payloads_hit = []
            if sqli_file and sqli_file.exists():
                for line in read_lines(sqli_file):
                    if "VULNERABLE:" in line:
                        url_part = line.split("VULNERABLE:")[-1].strip()
                        if "?" in url_part:
                            sqli_payloads_hit.append(url_part.split("?")[-1].strip())

            scan_data = {
                "target": target,
                "scan_uuid": TIMESTAMP,
                "db_path": str(run_dir / "findings.db"),
                "started_at": datetime.now().isoformat(),
                "findings": finding_dicts,
                "tech_stack": tech_stack,
                "subdomains": subdomains,
                "risk_score": risk_score,
                "tools_run": tools_run,
                "xss_payloads_hit": xss_payloads_hit,
                "sqli_payloads_hit": sqli_payloads_hit,
                "stages_completed": [s.value for s in completed_stages],
            }
            mem_mod.post_scan_learning(scan_data)
            log("INFO", "Memory learning loop updated", indent=1)
        except Exception as e:
            log("WARN", f"Memory learning loop error (non-fatal): {e}", indent=1)

    conn.close()


# ════════════════════════════════════════════════════════
#  AGENTBRAIN — AI-Driven Reasoning Loop
#  ════════════════════════════════════════════════════════

class AgentEvent:
    """Events emitted by AgentBrain during execution for UI streaming."""
    def __init__(self, event_type: str, data: dict):
        self.type = event_type
        self.data = data


class AgentBrain:
    """
    AI-powered cybersecurity agent with memory, learning, and self-healing.

    Architecture:
      - ReAct reasoning loop (Think → Act → Observe → Repeat)
      - Four-layer memory system (episodic, semantic, procedural, vector)
      - Self-healing: detects missing tools, suggests alternatives
      - Continuous learning: updates tool effectiveness, FP registry, target profiles
    """

    MAX_ITERATIONS = 50
    MAX_TOOL_CALLS_PER_TURN = 5

    def __init__(self, tool_registry: "ToolRegistry", llm_provider: "LLMProvider",
                 run_dir: Path | None = None):
        self.tools = tool_registry
        self.llm = llm_provider
        default_dir = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel")) / "runs"
        self.run_dir = run_dir or default_dir
        self.run_dir.mkdir(parents=True, exist_ok=True)

        self.messages: list[LLMMessage] = []
        self._on_event: Callable | None = None
        self._tool_available: dict[str, bool] = {}
        self._findings: list[dict] = []
        self._context: dict[str, Any] = {
            "target": "",
            "scan_results": {},
            "findings": [],
            "tools_run": {},
            "tech_stack": {},
            "subdomains": [],
        }
        self._tool_call_history: list[dict] = []
        self._installing_tools: set[str] = set()
        self._interrupt_event: threading.Event | None = None

        # Memory system
        self._memory = None
        self._memory_available = False
        try:
            sys.path.insert(0, str(Path(__file__).parent))
            from memory import MemoryCore
            self._memory = MemoryCore()
            self._memory_available = True
        except Exception:
            pass

        # Self-healing knowledge: tool alternatives
        self._tool_alternatives: dict[str, list[str]] = {
            "subfinder": ["assetfinder", "amass"],
            "assetfinder": ["subfinder", "amass"],
            "amass": ["subfinder", "assetfinder"],
            "nuclei": ["nikto", "wapiti"],
            "dalfox": ["xsstrike"],
            "sqlmap": ["commix"],
            "ffuf": ["feroxbuster"],
            "feroxbuster": ["ffuf"],
            "nmap": ["masscan", "rustscan"],
            "masscan": ["nmap", "rustscan"],
            "rustscan": ["nmap"],
            "gospider": ["katana", "hakrawler"],
            "katana": ["gospider", "hakrawler"],
            "waybackurls": ["gau"],
            "gau": ["waybackurls"],
            "trufflehog": ["gitleaks"],
            "gitleaks": ["trufflehog"],
            "testssl": ["sslscan"],
        }

    def on_event(self, handler: Callable) -> None:
        self._on_event = handler

    def set_interrupt_event(self, event: threading.Event) -> None:
        self._interrupt_event = event

    def _emit(self, event_type: str, data: dict) -> None:
        if self._on_event:
            self._on_event(AgentEvent(event_type, data))

    def _get_memory_context(self, target: str = "") -> str:
        """Build a rich memory context string for the system prompt.
        Surfaces: target profile, historical stats, top-3 similar past findings,
        FP common patterns, and tool skill recommendations."""
        if not self._memory_available or not self._memory:
            return ""
        lines = []
        try:
            # ── 1. Target profile & Known Target Context ──
            if target:
                ctx = self._memory.get_target_context(target)
                if ctx:
                    lines.append(f"## Memory: Known Target Context\n{ctx}")

            # ── 2. Historical Stats & FP Registry ──
            stats = self._memory.get_full_summary()
            if stats["total_scans"] > 0:
                fp_section = f"False positives filtered: {stats['total_fp_filtered']}"
                try:
                    fp_patterns = self._memory.get_common_fp_patterns(5)
                    if fp_patterns:
                        pattern_lines = [f"  - {p['template_id']}: {p['count']} occurrence(s) on {p['affected_targets']}"
                                         for p in fp_patterns]
                        fp_section += "\nMost common FP patterns:\n" + "\n".join(pattern_lines)
                except Exception:
                    pass
                lines.append(
                    f"## Memory: Historical Stats\n"
                    f"Total past scans: {stats['total_scans']}\n"
                    f"Total findings: {stats['total_findings']}\n"
                    f"{fp_section}\n"
                    f"Vector docs indexed: {stats['vector_doc_count']}"
                )

            # ── 3. Similar past findings via vector memory ──
            if target and stats.get("vector_doc_count", 0) > 0:
                try:
                    similar = self._memory.vector_memory.recall_context(target, top_k=3)
                    if similar:
                        lines.append(f"## Memory: Similar Past Findings\n{similar}")
                except Exception:
                    pass

            # ── 4. Skill registry — tools that worked on similar targets ──
            skills = stats.get("skill_registry", {})
            if skills:
                skill_lines = ["## Memory: Known Effective Tools"]
                for ctx_name, data in list(skills.items())[:5]:
                    best = ", ".join(data.get("best_tools", []))
                    skip = data.get("skip_tools", [])
                    if best:
                        line = f"  For {ctx_name}: {best}"
                        if skip:
                            line += f" (avoid: {', '.join(skip[:3])})"
                        skill_lines.append(line)
                lines.append("\n".join(skill_lines))

            # ── 5. Target-specific tool recommendations ──
            if target:
                try:
                    profile = self._memory.target_profiler.get(target)
                    if profile:
                        tech = json.loads(profile.get("tech_stack", "{}"))
                        if tech:
                            tech_context = list(tech.keys())[0].lower()
                            best_tools = self._memory.tool_tracker.get_best_tools(tech_context, min_runs=1)
                            skip_tools = self._memory.tool_tracker.get_skip_tools(tech_context)
                            if best_tools:
                                tool_lines = [f"## Memory: Recommended Tools for {tech_context}"]
                                for t in best_tools[:5]:
                                    tool_lines.append(
                                        f"  - {t['tool_name']}: {t['hit_rate']*100:.0f}% hit rate "
                                        f"({t['hit_count']}/{t['total_runs']} runs, avg {t['avg_findings']:.1f} findings/run)"
                                    )
                                if skip_tools:
                                    tool_lines.append(f"  (tools to skip: {', '.join(skip_tools[:3])})")
                                lines.append("\n".join(tool_lines))
                except Exception:
                    pass
        except Exception:
            pass
        return "\n\n".join(lines)

    def _classify_error(self, error: str) -> str:
        """Classify a tool error into a category."""
        el = error.lower()
        if any(w in el for w in ("not installed", "not found", "command not found")):
            return "missing_tool"
        if any(w in el for w in ("timeout", "timed out")):
            return "timeout"
        if any(w in el for w in ("connection", "refused", "reset", "unreachable")):
            return "connection"
        if any(w in el for w in ("permission", "denied", "forbidden", "401", "403")):
            return "permission"
        if any(w in el for w in ("rate", "429", "throttle")):
            return "rate_limited"
        if any(w in el for w in ("segfault", "segmentation", "signal", "core dumped")):
            return "crash"
        if any(w in el for w in ("no result", "no output", "empty", "0 finding")):
            return "no_results"
        if any(w in el for w in ("memory", "oom", "alloc")):
            return "out_of_memory"
        if any(w in el for w in ("invalid arg", "unknown option", "usage:", "wrong")):
            return "bad_args"
        if any(w in el for w in ("no such file", "cannot open", "does not exist")):
            return "missing_file"
        if any(w in el for w in ("dns", "resolve", "hostname")):
            return "dns"
        return "unknown"

    def _learn_from_tool_run(self, tool_name: str, success: bool, findings_count: int,
                              error: str = "", retried: bool = False) -> None:
        """Update procedural memory after a tool run, learning from both success and failure."""
        if not self._memory_available or not self._memory:
            return
        try:
            tech = self._context.get("tech_stack", {})
            tech_context = "generic"
            if tech:
                tech_context = list(tech.keys())[0].lower() if isinstance(tech, dict) else "generic"

            timestamp = str(int(time.time()))
            error_cat = self._classify_error(error) if error else ""

            if success:
                self._memory.tool_tracker.record_tool_run(
                    tool_name, tech_context, findings_count, timestamp
                )
            elif error_cat and error_cat != "unknown":
                # Record failures too — track which errors happen per tool
                self._memory.tool_tracker.record_tool_run(
                    tool_name, tech_context, -1, timestamp, error_category=error_cat
                )
        except Exception:
            pass

    def _filter_known_fps(self, findings: list[dict]) -> list[dict]:
        """Filter out known false positives using the FP registry."""
        if not self._memory_available or not self._memory:
            return findings
        filtered = []
        for f in findings:
            try:
                if not self._memory.should_skip_finding(f):
                    filtered.append(f)
            except Exception:
                filtered.append(f)
        return filtered

    def _suggest_alternatives(self, missing_tool: str) -> str:
        """Suggest alternative tools when one is missing, incorporating memory of what worked before."""
        alt = self._tool_alternatives.get(missing_tool, [])
        installed = [t for t in alt if shutil.which(t)]

        # Check memory for effective alternatives on similar targets
        memory_alts = []
        if self._memory_available and self._memory and installed:
            try:
                tech = self._context.get("tech_stack", {})
                if tech:
                    tech_context = list(tech.keys())[0].lower()
                    best = self._memory.tool_tracker.get_best_tools(tech_context, min_runs=1)
                    memory_alts = [t['tool_name'] for t in best if t['tool_name'] in installed]
            except Exception:
                pass

        if installed:
            ranked = memory_alts or installed
            return f"Consider using: {', '.join(ranked)}"
        uninstalled = [t for t in alt if t not in installed]
        if uninstalled:
            return f"Alternatives (not installed — use install_tool): {', '.join(uninstalled)}"
        return ""

    def _install_tool(self, tool_name: str) -> ToolResult:
        """Install a missing security tool using the best available method."""
        if tool_name in self._installing_tools:
            return ToolResult(success=False, error=f"Already installing {tool_name}")

        cmd = get_install_command(tool_name)
        if not cmd:
            # No known install method — check if we can still find it in the map
            installs = TOOL_INSTALLS.get(tool_name, {})
            if installs:
                opts = "; ".join(f"{k}: {v}" for k, v in installs.items())
                return ToolResult(success=False,
                    error=f"Install methods for {tool_name}: {opts}. "
                          f"None match this platform ({platform.system()}). "
                          f"Try installing manually.")
            return ToolResult(success=False,
                error=f"No install method known for {tool_name}. "
                      f"Report this at https://github.com/anomalyco/opencode/issues")

        self._installing_tools.add(tool_name)
        try:
            self._emit("agent_tool_start", {
                "tool": f"install_{tool_name}",
                "args": {"command": cmd},
                "install": True,
            })
            r = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=120,
                env={**os.environ, "GO111MODULE": "on"} if "go install" in cmd else None,
            )
            elapsed = r.returncode == 0 and shutil.which(tool_name) is not None
            if r.returncode == 0:
                if shutil.which(tool_name):
                    self._tool_available[tool_name] = True
                    return ToolResult(success=True,
                        output=f"✅ Installed {tool_name} [{cmd}]",
                        runtime_sec=0)
                else:
                    return ToolResult(success=True,
                        output=f"Install command completed for {tool_name}. "
                               f"It may not be on PATH — try a new terminal session.",
                        runtime_sec=0)
            else:
                err = r.stderr[:600] or r.stdout[:300]
                return ToolResult(success=False,
                    error=f"Failed to install {tool_name}: {err}")
        except subprocess.TimeoutExpired:
            return ToolResult(success=False,
                error=f"Install of {tool_name} timed out after 120s")
        except Exception as e:
            return ToolResult(success=False,
                error=f"Install error for {tool_name}: {e}")
        finally:
            self._installing_tools.discard(tool_name)

    def _suggest_install_hint(self, missing_tool: str) -> str:
        """Suggest installation + alternatives for a missing tool."""
        parts = []
        cmd = get_install_command(missing_tool)
        if cmd:
            parts.append(f"Auto-install with: install_tool(tool=\"{missing_tool}\")")
        alt = self._suggest_alternatives(missing_tool)
        if alt:
            parts.append(alt)
        caps = check_install_capabilities()
        if not caps and not alt:
            parts.append("No package manager found (apt/brew/go/pip). Install manually.")
        return ". ".join(parts)

    def _install_from_github(self, tool_name: str, repo_url: str) -> ToolResult:
        """Install a tool from a GitHub repository with user permission."""
        if self._interrupt_event and self._interrupt_event.is_set():
            return ToolResult(success=False, error="Agent was interrupted")

        # Request user permission
        cb = self.tools.get_permission_callback()
        if cb:
            granted = cb(f"Install {tool_name} from {repo_url}?")
            if not granted:
                return ToolResult(success=True,
                    output=f"Install of {tool_name} cancelled — user denied permission.")
        else:
            return ToolResult(success=False,
                error="No permission system available for GitHub install.")

        if repo_url in self._installing_tools:
            return ToolResult(success=False, error=f"Already installing {tool_name}")
        self._installing_tools.add(repo_url)

        try:
            import tempfile
            clone_dir = tempfile.mkdtemp(prefix=f"{tool_name}_")
            self._emit("agent_tool_start", {
                "tool": f"install_{tool_name}",
                "args": {"repo": repo_url, "action": "git_clone"},
                "install": True,
            })
            r = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, clone_dir],
                capture_output=True, text=True, timeout=120,
            )
            if r.returncode != 0:
                return ToolResult(success=False,
                    error=f"Git clone failed: {r.stderr[:500]}")

            # Try pip install, then setup.py, then go install
            pip_files = list(Path(clone_dir).glob("*.py"))
            setup_py = Path(clone_dir) / "setup.py"
            pyproject = Path(clone_dir) / "pyproject.toml"

            if (setup_py.exists() or pyproject.exists()) and shutil.which("pip"):
                install_cmd = f"pip install {clone_dir}"
                r = subprocess.run(install_cmd, shell=True, capture_output=True, text=True, timeout=120)
                if r.returncode == 0:
                    return ToolResult(success=True,
                        output=f"Installed {tool_name} from {repo_url} via pip")
            elif list(Path(clone_dir).glob("*.go")):
                if shutil.which("go"):
                    r = subprocess.run(
                        ["go", "install", "./..."],
                        capture_output=True, text=True, timeout=120,
                        cwd=clone_dir,
                        env={**os.environ, "GO111MODULE": "on"},
                    )
                    if r.returncode == 0:
                        return ToolResult(success=True,
                            output=f"Installed {tool_name} from {repo_url} via go install")
            elif (Path(clone_dir) / "Makefile").exists():
                r = subprocess.run(
                    ["make", "install"],
                    capture_output=True, text=True, timeout=120,
                    cwd=clone_dir,
                )
                if r.returncode == 0:
                    return ToolResult(success=True,
                        output=f"Installed {tool_name} from {repo_url} via make install")

            return ToolResult(success=True,
                output=f"Cloned {tool_name} from {repo_url} to {clone_dir}. "
                       f"Manual install may be needed.")
        except subprocess.TimeoutExpired:
            return ToolResult(success=False,
                error=f"Install of {tool_name} from GitHub timed out")
        except Exception as e:
            return ToolResult(success=False,
                error=f"GitHub install error for {tool_name}: {e}")
        finally:
            self._installing_tools.discard(repo_url)

    # ── PUBLIC API ──

    def run(self, user_input: str, conversation_history: list[dict] | None = None) -> str:
        self._tool_available = self.tools.check_available()
        available_tools = [n for n, ok in self._tool_available.items() if ok]
        tool_schemas = self.tools.get_schemas()

        # Inject built-in install_tool schema for self-healing
        install_tool_schema = {
            "type": "function",
            "function": {
                "name": "install_tool",
                "description": "Auto-install a missing security tool on the current system. "
                               "Detects OS (Linux/macOS/Windows) and uses the best package manager "
                               "(apt/pacman/brew/scoop/go/pip/cargo). "
                               "If you found a GitHub repository for the tool, include github_url "
                               "and the system will ask the user for permission to install from there. "
                               "Call this when a tool is not found.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tool": {
                            "type": "string",
                            "description": "Name of the tool to install (e.g., subfinder, nmap, nuclei, sqlmap, gospider, dalfox)",
                        },
                        "github_url": {
                            "type": "string",
                            "description": "Optional GitHub URL to clone and install from (e.g., https://github.com/user/repo). User permission will be requested.",
                        },
                    },
                    "required": ["tool"],
                },
            },
        }

        install_github_schema = {
            "type": "function",
            "function": {
                "name": "install_from_github",
                "description": "Install a tool directly from a GitHub repository. "
                               "User permission will be requested before installing.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tool": {
                            "type": "string",
                            "description": "Name of the tool to install",
                        },
                        "repo": {
                            "type": "string",
                            "description": "GitHub repository URL (e.g., https://github.com/user/repo)",
                        },
                    },
                    "required": ["tool", "repo"],
                },
            },
        }
        tool_schemas = list(tool_schemas) + [install_tool_schema, install_github_schema]
        tool_schemas = list(tool_schemas) + [install_tool_schema]

        # Detect target from input
        target = self._extract_target(user_input)
        self._context["target"] = target

        memory_context = self._get_memory_context(target)
        system_prompt = self._build_system_prompt(available_tools, memory_context)

        self.messages = [
            LLMMessage(role="system", content=system_prompt),
        ]
        # Prepend conversation history so the AI remembers previous turns
        if conversation_history:
            for turn in conversation_history:
                role = "user" if turn.get("role") == "user" else "assistant"
                self.messages.append(LLMMessage(role=role, content=turn.get("content", "")))
        self.messages.append(LLMMessage(role="user", content=user_input))

        self._emit("agent_start", {"goal": user_input, "target": target})

        self._interrupt_event = threading.Event()
        self._emit("agent_interrupt_ready", {})

        for iteration in range(self.MAX_ITERATIONS):
            if self._interrupt_event.is_set():
                self._emit("agent_interrupted", {"iteration": iteration})
                self.messages.append(LLMMessage(
                    role="user",
                    content="[System] The user interrupted the agent."
                ))
                return "Agent interrupted by user."

            self._emit("agent_thinking", {"iteration": iteration + 1})

            streamed_content = ""

            def on_chunk(text: str) -> None:
                nonlocal streamed_content
                streamed_content += text
                self._emit("agent_streaming", {"text": text})

            def interrupt_check() -> bool:
                return self._interrupt_event is not None and self._interrupt_event.is_set()

            try:
                result = self.llm.chat_stream(
                    messages=self.messages,
                    tools=tool_schemas,
                    temperature=0.2,
                    max_tokens=4000,
                    on_chunk=on_chunk,
                    interrupt_check=interrupt_check,
                )
                _streamed_this_turn = True
            except Exception:
                result = self.llm.chat(
                    messages=self.messages,
                    tools=tool_schemas,
                    temperature=0.2,
                    max_tokens=4000,
                )
                _streamed_this_turn = False

            self._emit("agent_stream_end", {"text": result.content or ""})

            if interrupt_check():
                self._emit("agent_interrupted", {"iteration": iteration})
                self.messages.append(LLMMessage(
                    role="user",
                    content="[System] The user interrupted the agent."
                ))
                return "Agent interrupted by user."

            if result.finish_reason == "error":
                self._emit("agent_error", {"error": result.content})
                return f"Error: {result.content}"

            if result.tool_calls:
                self._emit("agent_action", {
                    "tool_calls": [
                        {"name": tc["function"]["name"],
                         "args": json.loads(tc["function"]["arguments"])}
                        for tc in result.tool_calls
                    ]
                })

                assistant_msg = LLMMessage(
                    role="assistant",
                    content=result.content or "",
                    tool_calls=result.tool_calls,
                )
                self.messages.append(assistant_msg)

                for tc in result.tool_calls[:self.MAX_TOOL_CALLS_PER_TURN]:
                    func_name = tc["function"]["name"]
                    try:
                        func_args = json.loads(tc["function"]["arguments"])
                    except json.JSONDecodeError:
                        func_args = {}

                    self._emit("agent_tool_start", {"tool": func_name, "args": func_args})

                    tool_result = self._execute_tool(func_name, func_args)

                    # Filter findings through FP registry before reporting
                    raw_findings = tool_result.findings or []
                    clean_findings = self._filter_known_fps(raw_findings)
                    fp_count = len(raw_findings) - len(clean_findings)

                    self._emit("agent_tool_result", {
                        "tool": func_name,
                        "result": tool_result.output[:2000] if tool_result.success else tool_result.error or "",
                        "success": tool_result.success,
                        "runtime_sec": tool_result.runtime_sec,
                        "findings_count": len(clean_findings),
                        "fp_filtered": fp_count,
                    })

                    if clean_findings:
                        self._findings.extend(clean_findings)
                        self._context["findings"] = self._findings

                    self._tool_call_history.append({
                        "tool": func_name,
                        "args": func_args,
                        "success": tool_result.success,
                        "findings_count": len(clean_findings),
                        "output_preview": tool_result.output[:300],
                    })

                    # Learn from this tool run (both success and failure)
                    self._learn_from_tool_run(
                        func_name, tool_result.success, len(clean_findings),
                        error=tool_result.error or "",
                    )
                    self._context["tools_run"][func_name] = self._context["tools_run"].get(func_name, 0) + 1

                    # Build tool result message for LLM
                    tool_output_parts = []
                    if tool_result.success:
                        tool_output_parts.append(tool_result.output[:2500])
                    else:
                        tool_output_parts.append(f"ERROR: {tool_result.error}")

                    if fp_count > 0:
                        tool_output_parts.append(f"\n[Note: {fp_count} finding(s) suppressed as known false positives]")

                    tool_output = "\n".join(tool_output_parts)

                    self.messages.append(LLMMessage(
                        role="tool",
                        content=tool_output,
                        tool_call_id=tc["id"],
                        name=func_name,
                    ))

                    if clean_findings:
                        first = json.dumps(clean_findings[0], default=str)[:500]
                        self.messages.append(LLMMessage(
                            role="user",
                            content=f"[System] Tool {func_name} found {len(clean_findings)} verified findings. "
                                    f"First: {first}",
                        ))

                    if not tool_result.success and tool_result.error:
                        error_cat = self._classify_error(tool_result.error)
                        debug_parts = [f"[System] Tool {func_name} failed: {tool_result.error[:400]}"]
                        debug_parts.append(f"[Debug] Error category: {error_cat}")

                        # Auto-run self_debug analysis and inject it
                        try:
                            from tools import _tool_self_debug
                            debug_result = _tool_self_debug(
                                self.tools, "self_debug",
                                {"error": tool_result.error, "tool": func_name},
                                None, None,
                            )
                            if debug_result.success:
                                debug_parts.append(f"[Debug Analysis]\n{debug_result.output[:600]}")
                        except Exception:
                            pass

                        # If missing tool, suggest alternatives
                        if error_cat == "missing_tool":
                            alt = self._suggest_alternatives(func_name)
                            if alt:
                                debug_parts.append(f"[System] {alt}")

                        # Inject debug info into LLM context
                        self.messages.append(LLMMessage(
                            role="user",
                            content="\n".join(debug_parts),
                        ))

                continue

            # No tool calls — response or finish
            final_content = result.content or ""
            if final_content:
                if not _streamed_this_turn:
                    self._emit("agent_response", {"text": final_content})
                self.messages.append(LLMMessage(role="assistant", content=final_content))

            if result.finish_reason == "stop":
                # Run learning loop on completion
                self._run_post_task_learning()
                self._emit("agent_complete", {"response": final_content})
                return final_content

        # Max iterations — still learn from what we did
        self._run_post_task_learning()
        summary = f"Maximum iterations reached. Found {len(self._findings)} findings."
        self._emit("agent_complete", {"response": summary, "max_iterations": True})
        return summary

    def _run_post_task_learning(self) -> None:
        """Run the learning loop after task completion."""
        if not self._memory_available or not self._memory:
            return
        try:
            if not self._findings:
                return
            scan_data = {
                "target": self._context.get("target", ""),
                "scan_uuid": f"agent_{int(time.time())}",
                "findings": self._findings,
                "tech_stack": self._context.get("tech_stack", {}),
                "subdomains": self._context.get("subdomains", []),
                "tools_run": self._context.get("tools_run", {}),
                "risk_score": min(100, sum(
                    {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
                    .get(f.get("severity", "info"), 0) for f in self._findings
                )),
            }
            self._memory.learning_loop.process_scan(scan_data)
            self._emit("agent_response", {
                "text": f"🧠 Learned from this session. Memory updated with {len(self._findings)} findings."
            })
        except Exception:
            pass

    # ── INTERNALS ──

    def _extract_target(self, text: str) -> str:
        """Extract likely target domain/URL from user input."""
        patterns = [
            r'scan\s+(\S+\.\S+)',
            r'recon\s+(\S+\.\S+)',
            r'target\s+(\S+\.\S+)',
            r'check\s+(\S+\.\S+)',
            r'https?://\S+',
            r'(\S+\.\S+)',
        ]
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return m.group(1).rstrip("/").replace("https://", "").replace("http://", "")
        return ""

    def _build_system_prompt(self, available_tools: list[str], memory_context: str = "") -> str:
        prompt = """You are SENTINEL, an AI assistant specializing in cybersecurity. You can answer general questions, explain concepts, and help with security testing.

## Identity
You are SENTINEL, an autonomous cybersecurity AI agent created by SoukoX. You are NOT Anthropic's Claude, OpenAI's ChatGPT, Google's Gemini, or any other commercial AI — you are SoukoX's personal security agent running locally. You have no corporate affiliation.

## Core Principles
1. **Research before scanning** — always use web_search() to study real bug bounty reports, CVE writeups, and known exploitation techniques BEFORE running tools. Never blindly scan.
2. **Accuracy above all** — never fabricate findings. Only report what tools actually produce. If unsure, say so.
3. **Think before you act** — reason step-by-step about what to do and why
4. **Start broad, go deep** — begin with recon, then drill into findings
5. **Self-debug systematically** — when a tool fails, categorize (missing/permission/timeout/connection/bad-args), fix using self_debug() or install_tool(), retry, then pivot if needed.
6. **Learn from everything** — bug bounty writeups, CVEs, walkthroughs, past mistakes. Use web_search() to find real-world examples.

## Decision Rule
- If the user asks a general question, greets you, or wants to chat: use respond() to reply conversationally, then finish()
- If the user asks to scan, recon, find vulns, or test a target: research real-world techniques first, then use security tools
- If the user asks cybersecurity questions (what is XSS, how does SQLi work, etc.): use respond() to teach with real-world examples
- If the user asks about yourself or your tools: use respond() to explain

## Security Process
1. **RESEARCH** — Before running any tool, use web_search() to find real-world writeups, CVEs, and techniques relevant to the target/technology
2. **PLAN** — Select the right tools based on research, not random guessing
3. **EXECUTE** — Run tools one at a time, learning from each result
4. **ANALYZE** — Cross-reference findings with known vulnerabilities from research
5. **REPORT** — Clear findings with CVE references, real-world impact examples, and remediation
6. **LEARN** — Every session improves your knowledge base

## Professional Methodology
- Always start with reconnaissance to understand the target's technology stack
- Research CVEs and known vulnerabilities for the specific technologies discovered
- Use precise, targeted tests instead of broad random scanning
- Document every finding with evidence, CVE references, and real-world exploit examples
- Never run intrusive tests without user consent

## Self-Debugging & Problem Solving Protocol

When a tool fails, follow this systematic protocol:

### Step 1: Categorize the error
- **Tool not installed**: `install_tool()` will auto-install and retry
- **Timeout**: Scope too large — narrow target, reduce wordlist, increase time-sec
- **Connection/DNS**: Target unreachable — verify hostname, try IP, check network
- **Permission**: Need root/sudo — try alternative flags (e.g., nmap -sT vs -sS)
- **Rate limited**: Reduce concurrency (-c, -rl, -t flags), add delays
- **Bad arguments**: Check `tool --help`, flag syntax may have changed
- **No results**: Target may be down, try different approach or tool
- **Crash/OOM**: Scope too large, tool bug — reduce input, update tool

### Step 2: Apply the fix
- Use `self_debug(error=<msg>, tool=<name>)` to get structured diagnosis
- For install issues: `install_tool(tool="<name>")` or `install_tool(tool="<name>", github_url="<url>")`
- For alternative approaches: check the alternatives list or use `web_search()`

### Step 3: Retry or pivot
- After applying a fix, retry the same tool (the system auto-retries after install)
- If the tool still fails, try an alternative tool from the same category
- If all tools in a category fail, change strategy: use a different technique entirely

### Step 4: Learn
- Every failure is recorded in memory — the system tracks which errors occur per tool
- The system remembers what worked before for similar targets
- Use `web_search()` to find real-world solutions for unfamiliar errors

## Learning from Real-World Data
Always research before testing:
- **Bug bounty reports**: Search HackerOne, Bugcrowd for similar vulnerabilities to understand real exploitation paths
- **PortSwigger Academy**: Study lab walkthroughs for exploitation techniques
- **CVE writeups**: Research specific CVEs to understand root causes and fixes
- **Past incidents**: Learn from major security breaches
- **Tool docs**: Study tool usage examples and best practices
Always ask for permission via web_search() before browsing.

"""
        if memory_context:
            prompt += f"\n{memory_context}\n"

        prompt += """
## Available Tools
"""
        for name in available_tools:
            spec = self.tools.get(name)
            if spec:
                prompt += f"\n- {name}: {spec.description}"

        prompt += """

## Built-in Agent Tools
- **think**: Show your reasoning step-by-step. Always use this before acting.
- **respond**: Send a message to the user with findings, explanations, or questions.
- **finish**: Signal task complete with a summary of what was accomplished.
- **install_tool**: Auto-install a missing security tool. Call this when a tool you need is not installed.
- **web_search**: Search the web for cybersecurity information, bug bounty reports, walkthroughs, or tool docs. Requires user permission — you'll be prompted.
- **self_debug**: Diagnose and fix tool errors with structured analysis and category-specific advice. Supports 50+ common security tools with known error patterns. Call this when a tool fails to get precise fix suggestions.

## Bug Report Guidelines
Every finding you report must include:
1. **Vulnerability type** (XSS, SQLi, IDOR, etc.) with CWE reference
2. **Severity** (critical/high/medium/low/info) with justification
3. **Affected URL/endpoint** with exact parameter
4. **Steps to reproduce** — clear, numbered, actionable
5. **Impact** — what an attacker could achieve
6. **Remediation** — specific code/config fix recommendation
7. **Reference** — link to relevant CVE, OWASP, or real-world example if available

Never report:
- False positives — verify findings before reporting
- Theoretical issues without evidence — only confirmed vulnerabilities
- Out-of-scope targets — respect authorized scope

To call a tool, use the function calling mechanism."""
        return prompt

    def _execute_tool(self, name: str, args: dict) -> "ToolResult":
        if name == "think":
            return ToolResult(success=True, output=f"Thought: {args.get('thought', '')}")
        if name == "respond":
            msg = args.get("message", "")
            self._emit("agent_response", {"text": msg})
            return ToolResult(success=True, output=f"Sent: {msg[:100]}")
        if name == "finish":
            summary = args.get("summary", "Done")
            self._emit("agent_complete", {"response": summary})
            return ToolResult(success=True, output=summary)
        if name == "install_tool":
            tool_arg = args.get("tool", "")
            if not tool_arg:
                return ToolResult(success=False, error="install_tool requires 'tool' argument")
            github_url = args.get("github_url", "")
            if github_url:
                return self._install_from_github(tool_arg, github_url)
            return self._install_tool(tool_arg)

        if name == "install_from_github":
            tool_arg = args.get("tool", "")
            repo = args.get("repo", "")
            if not tool_arg or not repo:
                return ToolResult(success=False, error="install_from_github requires 'tool' and 'repo' arguments")
            return self._install_from_github(tool_arg, repo)

        spec = self.tools.get(name)
        if not spec:
            hint = self._suggest_install_hint(name)
            msg = f"Unknown tool: {name}"
            if hint:
                msg += f". {hint}"
            return ToolResult(success=False, error=msg)

        # Run tool via registry.run() API
        tool_result = self.tools.run(name, args, self.run_dir,
            lambda etype, edata: self._emit(etype, edata))

        # Auto-heal: intelligently handle tool failures
        if not tool_result.success and tool_result.error:
            err_lower = tool_result.error.lower()
            error_cat = self._classify_error(tool_result.error)

            # ── 1. Not installed → auto-install + retry ──
            if error_cat == "missing_tool":
                self._emit("agent_tool_start", {
                    "tool": f"install_{name}",
                    "args": {"auto": True},
                    "install": True,
                })
                install_result = self._install_tool(name)
                self._emit("agent_tool_result", {
                    "tool": f"install_{name}",
                    "result": install_result.output or install_result.error or "done",
                    "success": install_result.success,
                })
                if install_result.success:
                    tool_result = self.tools.run(name, args, self.run_dir,
                        lambda etype, edata: self._emit(etype, edata))

            # ── 2. Permission denied → suggest sudo ──
            elif error_cat == "permission":
                self._emit("agent_tool_result", {
                    "tool": name,
                    "result": "",
                    "success": False,
                    "info": f"Permission denied. Try: sudo {name}",
                })

            # ── 3. DNS resolution failure → try with IP ──
            elif error_cat == "dns":
                self._emit("agent_tool_result", {
                    "tool": name,
                    "result": "",
                    "success": False,
                    "info": f"DNS resolution failed. Check hostname or try with IP address.",
                })

            # ── 4. Rate limited → suggest reduced concurrency ──
            elif error_cat == "rate_limited":
                self._emit("agent_tool_result", {
                    "tool": name,
                    "result": "",
                    "success": False,
                    "info": f"Rate limited. Reduce concurrency/rate flags.",
                })

            # ── 5. Connection issues → try alternative approach ──
            elif error_cat == "connection":
                self._emit("agent_tool_result", {
                    "tool": name,
                    "result": "",
                    "success": False,
                    "info": f"Connection failed. Verify target and network.",
                })

            # ── 6. Bad args → inform the LLM ──
            elif error_cat == "bad_args":
                self._emit("agent_tool_result", {
                    "tool": name,
                    "result": "",
                    "success": False,
                    "info": f"Invalid arguments for {name}. Check help.",
                })

        # Post-process: extract findings from output (critical for bug reporting)
        if tool_result.success and tool_result.output:
            parsed = self._parse_findings(name, tool_result.output, args)
            if parsed:
                if tool_result.findings:
                    tool_result.findings.extend(parsed)
                else:
                    tool_result.findings = parsed
        return tool_result

    def _parse_findings(self, tool_name: str, output: str, args: dict) -> list[dict]:
        findings = []
        target = args.get("target") or args.get("domain") or args.get("host") or args.get("url", "")

        if tool_name == "nuclei":
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        f = json.loads(line)
                        findings.append({
                            "source": "nuclei",
                            "name": f.get("info", {}).get("name", f.get("template-id", "")),
                            "severity": f.get("info", {}).get("severity", "unknown"),
                            "host": f.get("host", target),
                            "matched": f.get("matched-at", ""),
                            "description": f.get("info", {}).get("description", ""),
                            "template_id": f.get("template-id", ""),
                            "remediation": f.get("info", {}).get("remediation", ""),
                        })
                    except json.JSONDecodeError:
                        pass

        elif tool_name == "subfinder":
            for line in output.splitlines():
                s = line.strip()
                if s and "." in s:
                    findings.append({
                        "source": "subfinder",
                        "type": "subdomain",
                        "value": s,
                    })
                    self._context.setdefault("subdomains", []).append(s)

        elif tool_name == "assetfinder":
            for line in output.splitlines():
                s = line.strip()
                if s and "." in s:
                    findings.append({
                        "source": "assetfinder",
                        "type": "subdomain",
                        "value": s,
                    })
                    self._context.setdefault("subdomains", []).append(s)

        elif tool_name == "httpx":
            for line in output.splitlines():
                s = line.strip()
                if s and ("http" in s.lower() or s.startswith("[") or "[" in s):
                    findings.append({"source": "httpx", "type": "live_host", "value": s})
                    # Extract tech hints
                    tech_match = re.findall(r'\[(\w+(?:-\w+)*)\]', s)
                    for t in tech_match:
                        self._context["tech_stack"][t.lower()] = True

        elif tool_name == "nmap":
            for line in output.splitlines():
                m = re.search(r'(\d+)/tcp\s+open\s+(\S+)', line)
                if m:
                    findings.append({
                        "source": "nmap",
                        "type": "open_port",
                        "port": int(m.group(1)),
                        "service": m.group(2),
                    })

        elif tool_name == "whatweb":
            techs = re.findall(r'([\w\-\+]+)\[', output)
            for t in techs:
                self._context["tech_stack"][t.lower().replace("+", "p")] = True

        elif tool_name == "wafw00f":
            for line in output.splitlines():
                if "WAF" in line and "detected" in line.lower():
                    findings.append({"source": "wafw00f", "type": "waf_detected", "value": line.strip()})

        return findings


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C['yellow']}⚠️  Scan interrupted by user.{C['reset']}", flush=True)
        sys.exit(130)
    except Exception as e:
        import traceback
        print(f"\n{C['red']}❌ SENTINEL crashed: {e}{C['reset']}", flush=True)
        traceback.print_exc()
        sys.exit(1)