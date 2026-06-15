#!/usr/bin/env python3
"""
SENTINEL — WebSocket/HTTP Daemon
Architecture Phase 2 — Production Server

Provides:
  - WebSocket endpoint for real-time UI integration
  - Static file serving for the HTML UI
  - AI backend key validation and configuration
  - Agent lifecycle management
  - Scan result browsing

 files are at /home/ac/agent/server.py, agent at /home/ac/agent/agent.py. Use .opencode/NEXT_SESSION.md for the quick-start and verification steps.



Run: python3 server.py
Then open http://localhost:8766/ui.html

Requires: pip install websockets

Phase 1 changes (Architecture alignment):
  Phase 2/3 additions:
  - ADD: get_fp_list, clear_fp, get_payload_stats, get_audit_log
  - ADD: get_disk_usage, purge_target, update_target_notes, get_config
  - ADD: check_resume (interrupted scan detection)
  - ADD: find_similar (vector/text similarity search via memory.py)
  Phase 1 changes (Architecture alignment):
  - ADD: Parses SENTINEL:STAGE_STARTED / SENTINEL:STAGE_COMPLETE markers from
         agent.py stdout → emits stage_started / stage_complete WS messages
  - ADD: get_findings action (per API contract §15)
  - ADD: get_memory_summary action stub (returns scan summary from DB)
  - ADD: validate_key supports "groq" backend (matches agent.py v1.0)
  - ADD: start_scan passes --yes flag for auto-accept in headless mode
  - ADD: Reads new Finding fields: url, parameter, method, false_positive,
         user_verified, ai_chain_context, ai_effort_to_fix, ai_bounty_value
  - FIX: _active_proc made per-connection — two WS clients no longer share state
  - FIX: stop_scan calls proc.wait() after terminate() to reap zombie
  - FIX: find_latest_run_dir uses exact target prefix match only
  - FIX: send_queue bounded to 4096 messages to prevent unbounded growth
  - FIX: HTTP server no longer emits ACAO: * — returns restrictive header
  - FIX: WebSocket server binds to 127.0.0.1 only (not 0.0.0.0) by default
  - IMPROVE: Added /health HTTP endpoint for monitoring
  - IMPROVE: Consistent VERSION constant across all files
"""

import asyncio
import json
import logging
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

try:
    import websockets
    from websockets import serve as ws_serve
    from websockets.http11 import Response
except ImportError:
    print("Install websockets:  pip install websockets")
    sys.exit(1)

try:
    from http.server import HTTPServer, SimpleHTTPRequestHandler, BaseHTTPRequestHandler
except ImportError:
    sys.exit(1)

# AgentBrain imports
sys.path.insert(0, str(Path(__file__).parent))
from tools import ToolRegistry, ToolResult
from ai import LLMProvider, LLMMessage, detect_available_backends
from agent import AgentBrain, AgentEvent

VERSION    = "2"
WS_PORT    = 8765
HTTP_PORT  = 8766
# FIX: Bind to loopback only by default — set WS_HOST=0.0.0.0 to expose on LAN
WS_HOST    = os.environ.get("WS_HOST", "127.0.0.1")
_IS_FROZEN = getattr(sys, 'frozen', False)
AGENT_PATH = Path(__file__).parent / "agent.py"
# Canonical SENTINEL data dir — matches agent.py
SENTINEL_DIR = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))

# FIX: No longer a global — each connection gets its own proc slot (see handle_connection)
_active_proc_lock = threading.Lock()

# ── Global scan-idempotency registry ──────────────────────────────────────
# Maps target → start_time so concurrent WS clients cannot launch duplicate
# scans for the same target within the dedup window.
_SCAN_REGISTRY: dict = {}          # target → start_epoch_float
_SCAN_REGISTRY_LOCK = threading.Lock()
_SCAN_DEDUP_WINDOW_SEC = 10.0      # ignore duplicate start_scan within 10s

# ── Agent permission request system ──────────────────────────
import uuid as _uuid
_pending_permissions: dict[str, dict] = {}

def build_permission_callback(q_send):
    def request_permission(query: str) -> bool:
        try:
            request_id = _uuid.uuid4().hex[:12]
            event = threading.Event()
            _pending_permissions[request_id] = {"event": event, "granted": False, "query": query}
            q_send("agent_ask_permission", request_id=request_id, query=query)
            event.wait(timeout=120)
            result = _pending_permissions.pop(request_id, {}).get("granted", False)
            return result
        except Exception:
            return False
    return request_permission


# ─────────────────────────────────────────────
# TOOL CHECKER
# ─────────────────────────────────────────────

TOOL_GROUPS = {
    "core":         {"description": "Subdomain enum + live host probing",
                     "tools": ["subfinder","httpx","amass","assetfinder","dnsx","massdns"]},
    "crawl":        {"description": "URL & parameter discovery",
                     "tools": ["katana","gospider","waybackurls","gau","hakrawler","paramspider"]},
    "fuzz":         {"description": "Directory, param & vhost fuzzing",
                     "tools": ["ffuf","feroxbuster","arjun"]},
    "scan":         {"description": "Vulnerability scanning",
                     "tools": ["nuclei","jaeles","wapiti"]},
    "exploit_lite": {"description": "XSS, SQLi, SSRF, SSTI, open-redirect",
                     "tools": ["dalfox","sqlmap","nikto","commix","tplmap","ssrfmap","crlfuzz"]},
    "secrets":      {"description": "Secrets & credential exposure",
                     "tools": ["trufflehog","gitleaks","secretfinder"]},
    "portscan":     {"description": "Service / port discovery",
                     "tools": ["nmap","masscan","rustscan"]},
    "cloud":        {"description": "Cloud & S3 misconfig",
                     "tools": ["cloudfox","s3scanner","awscli"]},
    "cors_csp":     {"description": "CORS, CSP, header analysis",
                     "tools": ["corscanner","shcheck"]},
    "proto":        {"description": "Protocol-level: SSL, HTTP/2, WebSocket",
                     "tools": ["testssl","h2csmuggler","smuggler"]},
    "webserver":    {"description": "Web server fingerprinting & WAF detection",
                     "tools": ["whatweb","wafw00f"]},
    "takeover":     {"description": "Subdomain takeover detection",
                     "tools": ["subjack"]},
    "deps":         {"description": "Agent dependencies",
                     "tools": ["gf","uro","interactsh-client","curl","jq","git"]},
}

ALL_TOOLS = [t for g in TOOL_GROUPS.values() for t in g["tools"]]


def check_tools() -> dict:
    return {t: bool(shutil.which(t)) for t in ALL_TOOLS}


def check_ollama() -> dict:
    installed = bool(shutil.which("ollama"))
    running   = False
    models    = []
    if installed:
        try:
            req = urllib.request.Request("http://localhost:11434/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                data   = json.loads(resp.read())
                models = [m["name"] for m in data.get("models", [])]
                running = True
        except Exception:
            pass
    return {"installed": installed, "running": running, "models": models}


# ─────────────────────────────────────────────
# KEY VALIDATORS
# ─────────────────────────────────────────────





def validate_openrouter_key(api_key: str) -> tuple[bool, str]:
    """
    Real validation: hits /api/v1/auth/key which returns 401 for invalid/expired keys.
    /api/v1/models is public and always returns 200 — never use that for validation.
    Also checks for empty credits and malformed key format.
    """
    if not api_key:
        return False, "API key is empty"
    api_key = api_key.strip()
    if len(api_key) < 10:
        return False, "API key is too short to be valid"
    # OpenRouter keys always start with "sk-or-"
    if not api_key.startswith("sk-or-"):
        return False, "Malformed OpenRouter key — must start with 'sk-or-'"

    last_err = ""
    for attempt in range(3):
        req = urllib.request.Request(
            "https://openrouter.ai/api/v1/auth/key",
            headers={"Authorization": f"Bearer {api_key}"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                data = json.loads(body)
                # Valid response: {"data": {"label": ..., "limit": ..., "usage": ...}}
                kdata = data.get("data", {})
                if not kdata:
                    return False, "OpenRouter key rejected — no data returned (check openrouter.ai/keys)"
                label  = kdata.get("label", "")
                limit  = kdata.get("limit")   # None = unlimited, number = credit limit
                usage  = kdata.get("usage", 0)
                is_free = kdata.get("is_free_tier", False)
                # Check for exhausted credits
                if limit is not None and usage is not None:
                    remaining = limit - usage
                    if remaining <= 0:
                        return False, f"OpenRouter key has no remaining credits (used ${usage:.4f} of ${limit:.4f})"
                    return True, f"OpenRouter key valid ✓ ({label or 'authenticated'}) — ${remaining:.4f} remaining"
                return True, f"OpenRouter key valid ✓ ({label or 'authenticated'}{'  [free tier]' if is_free else ''})"
        except urllib.error.HTTPError as e:
            body_text = ""
            try:
                body_text = e.read().decode("utf-8", errors="replace")[:120]
            except Exception:
                pass
            if e.code == 401:
                return False, "Invalid or expired OpenRouter key (401) — get one at openrouter.ai/keys"
            if e.code == 403:
                return False, "OpenRouter key forbidden (403) — key may be revoked"
            if e.code == 429:
                return True, "OpenRouter key valid but rate-limited (429) — OK for scans"
            return False, f"OpenRouter HTTP {e.code}: {body_text}"
        except (TimeoutError, OSError) as ex:
            last_err = f"Timeout/connection error attempt {attempt+1}/3: {ex}"
            time.sleep(1)
        except Exception as ex:
            return False, f"Unexpected error: {str(ex)[:80]}"
    return False, f"Connection error after 3 attempts: {last_err}"


# ─────────────────────────────────────────────
# DB READER
# ─────────────────────────────────────────────

def validate_opencode_key(api_key: str) -> tuple[bool, str]:
    """
    Validate OpenCode Zen key by making a minimal test request to the chat endpoint.
    The /zen/v1/models endpoint is public (no auth required) so it can't validate keys.
    We send a tiny chat completion with the key — 401 means invalid key.
    """
    api_key = api_key.strip() if api_key else ""
    if not api_key:
        return False, "OpenCode Zen: no API key provided — set an OpenCode key for authenticated access"

    if len(api_key) < 8:
        return False, "OpenCode Zen: API key is too short to be valid"

    payload = json.dumps({
        "model": "deepseek-v4-flash-free",
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 1,
    }).encode()
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "SENTINEL/1.0",
        "Authorization": f"Bearer {api_key}",
    }

    req = urllib.request.Request(
        "https://opencode.ai/zen/v1/chat/completions",
        data=payload, headers=headers, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return True, "OpenCode Zen ✓ key accepted"
    except urllib.error.HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode("utf-8", errors="replace")[:200]
        except Exception:
            pass
        if e.code == 401:
            return False, "OpenCode Zen 401: invalid or expired API key"
        if e.code == 403 and "1010" in body_text:
            return False, "OpenCode Zen 403/1010: access denied by Cloudflare — check your network or try without a VPN"
        return False, f"OpenCode Zen HTTP {e.code}: {body_text or 'unknown error'}"
    except TimeoutError:
        return False, "OpenCode Zen unreachable (timeout)"
    except Exception as ex:
        return False, f"OpenCode Zen connection error: {str(ex)[:120]}"


def validate_cerebras_key(api_key: str) -> tuple[bool, str]:
    """
    Validate a Cerebras API key via the chat completions endpoint.
    Cerebras keys start with 'csk-'.  The /v1/models endpoint often returns
    403 even with valid keys, so we use the same endpoint that the actual
    inference call uses.
    """
    api_key = api_key.strip() if api_key else ""
    if not api_key:
        return False, "Cerebras: no API key provided"
    if len(api_key) < 8:
        return False, "Cerebras: API key is too short to be valid"
    if not api_key.startswith("csk-"):
        return False, "Malformed Cerebras key — must start with 'csk-'"

    payload = json.dumps({
        "model": "llama3.3-70b",
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 1,
    }).encode()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    req = urllib.request.Request(
        "https://api.cerebras.ai/v1/chat/completions",
        data=payload, headers=headers, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            return True, "Cerebras key valid ✓"
    except urllib.error.HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode("utf-8", errors="replace")[:200]
        except Exception:
            pass
        if e.code == 401:
            return False, "Invalid or expired Cerebras key (401) — get one at cloud.cerebras.ai"
        if e.code == 403:
            return False, "Cerebras key forbidden (403) — key may be revoked"
        return False, f"Cerebras HTTP {e.code}: {body_text or 'unknown error'}"
    except TimeoutError:
        return False, "Cerebras unreachable (timeout)"
    except Exception as ex:
        return False, f"Cerebras connection error: {str(ex)[:120]}"


def read_all_findings(run_dir: Path) -> list[dict]:
    db_path = run_dir / "findings.db"
    if not db_path.exists():
        candidates = list(run_dir.glob("*/findings.db"))
        if candidates:
            db_path = max(candidates, key=lambda p: p.stat().st_mtime)
    if not db_path.exists():
        return []
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT name, severity, host, url, matched_at, template_id,
                   parameter, method,
                   cvss_score, cvss_vector, cve_ids, cwe_ids, category,
                   confidence, false_positive, user_verified, user_notes,
                   ai_explanation, ai_impact, ai_poc, ai_remediation,
                   ai_chain_context, ai_effort_to_fix, ai_bounty_value,
                   raw_description, remediation, source,
                   finding_hash, first_seen, last_seen
            FROM findings
            ORDER BY CASE severity
                WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium'   THEN 3 WHEN 'low'  THEN 4
                ELSE 5 END
        """).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as ex:
        print(f"[server] DB read error: {ex}", flush=True)
        return []


def read_ai_findings(run_dir: Path) -> list[dict]:
    db_path = run_dir / "findings.db"
    if not db_path.exists():
        candidates = list(run_dir.glob("*/findings.db"))
        if candidates:
            db_path = max(candidates, key=lambda p: p.stat().st_mtime)
    if not db_path.exists():
        return []
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT name, severity, host, url, matched_at, template_id,
                   parameter, cvss_score, cve_ids, cwe_ids, category,
                   confidence, false_positive, user_verified,
                   ai_explanation, ai_impact, ai_poc, ai_remediation,
                   ai_chain_context, ai_effort_to_fix, ai_bounty_value,
                   raw_description, remediation, finding_hash
            FROM findings
            WHERE ai_explanation IS NOT NULL AND ai_explanation != ''
            ORDER BY CASE severity
                WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                WHEN 'medium'   THEN 3 WHEN 'low'  THEN 4
                ELSE 5 END
        """).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as ex:
        print(f"[server] DB read error: {ex}", flush=True)
        return []


def find_latest_run_dir(outdir: str, target: str) -> "Path | None":
    # Expand ~ and resolve any env vars
    base = Path(os.path.expanduser(outdir))
    if not base.exists():
        # Also try SENTINEL canonical dir
        alt = SENTINEL_DIR / "scans"
        if alt.exists():
            base = alt
        else:
            # Last resort: try common locations
            for fallback in [Path.home() / ".sentinel" / "scans", Path("bb_output")]:
                if fallback.exists():
                    base = fallback
                    break
            else:
                return None
    # FIX: Only exact prefix match — no fuzzy root-domain matching that could
    # return results from a different target with a similar name.
    safe = target.replace("https://","").replace("http://","").rstrip("/")
    candidates = [d for d in base.iterdir() if d.is_dir() and d.name.startswith(safe + "_")]
    return max(candidates, key=lambda d: d.stat().st_mtime) if candidates else None


def _build_memory_summary(target_filter: "str | None" = None) -> dict:
    """
    Phase 1 memory summary: aggregate stats from all scan DBs.
    Returns MemorySummary shape per Architecture §15.
    Full memory.py (semantic/vector layers) is Phase 2.
    """
    scans_dir = SENTINEL_DIR / "scans"
    if not scans_dir.exists():
        return {"total_scans": 0, "targets": [], "total_findings": 0}

    targets: dict = {}
    total_findings = 0
    total_scans = 0

    for db_path in sorted(scans_dir.rglob("findings.db")):
        try:
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            scans = conn.execute("SELECT target, started_at, status FROM scans").fetchall()
            for scan in scans:
                t = scan["target"]
                if target_filter and t != target_filter:
                    continue
                total_scans += 1
                counts = conn.execute(
                    "SELECT severity, COUNT(*) as n FROM findings GROUP BY severity"
                ).fetchall()
                by_sev = {r["severity"]: r["n"] for r in counts}
                n = sum(by_sev.values())
                total_findings += n
                if t not in targets:
                    targets[t] = {"target": t, "scan_count": 0, "total_vulns": 0,
                                  "by_severity": {}, "last_seen": scan["started_at"]}
                targets[t]["scan_count"] += 1
                targets[t]["total_vulns"] += n
                for sev, cnt in by_sev.items():
                    targets[t]["by_severity"][sev] = targets[t]["by_severity"].get(sev, 0) + cnt
                if scan["started_at"] > targets[t]["last_seen"]:
                    targets[t]["last_seen"] = scan["started_at"]
            conn.close()
        except Exception:
            pass

    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "targets": list(targets.values()),
    }



def _get_fp_list(target=None) -> list:
    """Return false positive entries from memory DB."""
    fps = []
    try:
        mem_db = SENTINEL_DIR / "db" / "memory.db"
        if mem_db.exists():
            conn = sqlite3.connect(str(mem_db))
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM false_positives ORDER BY noted_at DESC"
            ).fetchall()
            for r in rows:
                d = dict(r)
                if target is None or d.get("target") == target:
                    fps.append(d)
            conn.close()
    except Exception:
        pass
    return fps


def _clear_fp(fp_hash: str) -> bool:
    """Remove a false positive entry by hash from memory DB."""
    try:
        mem_db = SENTINEL_DIR / "db" / "memory.db"
        if mem_db.exists():
            conn = sqlite3.connect(str(mem_db))
            conn.execute("DELETE FROM false_positives WHERE fp_hash=?", (fp_hash,))
            conn.commit()
            conn.close()
            return True
    except Exception:
        pass
    return False


def _get_payload_stats() -> dict:
    """Aggregate payload effectiveness stats from memory DBs."""
    stats: dict = {}
    scans_dir = SENTINEL_DIR / "scans"
    if not scans_dir.exists():
        return stats
    for db_path in sorted(scans_dir.rglob("findings.db")):
        try:
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute(
                    "SELECT vuln_type, SUM(hit_count) as total_hits, "
                    "SUM(miss_count) as total_misses, COUNT(DISTINCT payload) as unique_payloads "
                    "FROM payload_stats GROUP BY vuln_type"
                ).fetchall()
                for r in rows:
                    pt = r["vuln_type"]
                    if pt not in stats:
                        stats[pt] = {"total_hits": 0, "total_misses": 0, "unique_payloads": 0}
                    stats[pt]["total_hits"] += r["total_hits"] or 0
                    stats[pt]["total_misses"] += r["total_misses"] or 0
                    stats[pt]["unique_payloads"] += r["unique_payloads"] or 0
            except sqlite3.OperationalError:
                pass
            conn.close()
        except Exception:
            pass
    # If no payload_stats table yet, derive from findings categories
    if not stats:
        for db_path in sorted(scans_dir.rglob("findings.db")):
            try:
                conn = sqlite3.connect(str(db_path))
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT category, COUNT(*) as n FROM findings GROUP BY category"
                ).fetchall()
                for r in rows:
                    cat = r["category"] or "unknown"
                    stats[cat] = {
                        "total_hits": r["n"], "total_misses": 0, "unique_payloads": r["n"]
                    }
                conn.close()
            except Exception:
                pass
    return stats


def _get_audit_log(limit=100, action_filter=None) -> list:
    """Return recent audit log entries from SENTINEL DB."""
    entries = []
    audit_db = SENTINEL_DIR / "audit.db"
    if not audit_db.exists():
        return entries
    try:
        conn = sqlite3.connect(str(audit_db))
        conn.row_factory = sqlite3.Row
        if action_filter:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE action=? ORDER BY timestamp DESC LIMIT ?",
                (action_filter, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        for r in rows:
            d = dict(r)
            # details may be JSON string
            if isinstance(d.get("details"), str):
                try:
                    d["details"] = json.loads(d["details"])
                except Exception:
                    pass
            entries.append(d)
        conn.close()
    except Exception:
        pass
    return entries


def _get_disk_usage() -> dict:
    """Return disk usage stats for SENTINEL data directory."""
    scans_dir = SENTINEL_DIR / "scans"
    by_target: dict = {}
    scan_count = 0
    total_bytes = 0
    if scans_dir.exists():
        for run_dir in scans_dir.iterdir():
            if not run_dir.is_dir():
                continue
            scan_count += 1
            # run dir name is typically target_YYYYMMDD_HHMMSS
            target = run_dir.name.rsplit("_", 2)[0] if run_dir.name.count("_") >= 2 else run_dir.name
            size = sum(f.stat().st_size for f in run_dir.rglob("*") if f.is_file())
            total_bytes += size
            by_target[target] = by_target.get(target, 0) + size
    return {
        "total_mb": round(total_bytes / 1024 / 1024, 1),
        "scan_count": scan_count,
        "by_target_mb": {k: round(v / 1024 / 1024, 1) for k, v in sorted(
            by_target.items(), key=lambda x: x[1], reverse=True
        )[:20]},
    }


def _purge_target(target: str) -> int:
    """Delete all scan run directories for a target. Returns count deleted."""
    scans_dir = SENTINEL_DIR / "scans"
    deleted = 0
    if not scans_dir.exists():
        return deleted
    for run_dir in list(scans_dir.iterdir()):
        if not run_dir.is_dir():
            continue
        dir_target = run_dir.name.rsplit("_", 2)[0] if run_dir.name.count("_") >= 2 else run_dir.name
        if dir_target == target or dir_target == target.replace(".", "_"):
            try:
                shutil.rmtree(run_dir)
                deleted += 1
            except Exception:
                pass
    return deleted


def _check_resume(target: str) -> dict | None:
    """Check if there is an interrupted scan state file for this target."""
    scans_dir = SENTINEL_DIR / "scans"
    if not scans_dir.exists():
        return None
    clean = target.replace(".", "_").replace("/", "_")
    # Look for most recent run dir for this target
    candidates = []
    for run_dir in scans_dir.iterdir():
        if not run_dir.is_dir():
            continue
        if run_dir.name.startswith(clean + "_") or run_dir.name.startswith(target + "_"):
            state_file = run_dir / "scan_state.json"
            if state_file.exists():
                try:
                    state = json.loads(state_file.read_text())
                    if state.get("status") == "interrupted":
                        candidates.append((run_dir, state))
                except Exception:
                    pass
    if not candidates:
        return None
    # Most recent interrupted run
    candidates.sort(key=lambda x: x[0].name, reverse=True)
    run_dir, state = candidates[0]
    return {"run_dir": str(run_dir), "state": state}


def _update_target_notes(target: str, notes: str, program: str) -> bool:
    """Persist target notes/program to SENTINEL DB."""
    notes_dir = SENTINEL_DIR / "notes"
    notes_dir.mkdir(parents=True, exist_ok=True)
    note_file = notes_dir / f"{target.replace('/', '_')}.json"
    try:
        existing = {}
        if note_file.exists():
            existing = json.loads(note_file.read_text())
        existing.update({"target": target, "notes": notes, "program": program,
                         "updated_at": datetime.now(timezone.utc).isoformat()})
        note_file.write_text(json.dumps(existing, indent=2))
        return True
    except Exception:
        return False


def _get_config_flat() -> dict:
    """Return a flat key=value dict of the active config for the UI."""
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from config import get_config
        cfg = get_config()
        flat = {}
        for section_name in ["sentinel", "ai", "scan", "privacy", "ui", "memory", "notifications"]:
            section = getattr(cfg, section_name, None)
            if section:
                from dataclasses import asdict
                for k, v in asdict(section).items():
                    flat[f"{section_name}.{k}"] = v
        return flat
    except Exception as e:
        return {"error": str(e)}


def find_latest_report(run_dir: Path) -> Path | None:
    reports = list(run_dir.glob("report_*.md"))
    return max(reports, key=lambda p: p.stat().st_mtime) if reports else None


# ─────────────────────────────────────────────
# WEBSOCKET HANDLER
# ─────────────────────────────────────────────

async def handle_connection(websocket):
    """
    FIX: Each connection gets its own _active_proc slot.
    No shared global proc state between concurrent clients.
    """
    active_proc: subprocess.Popen | None = None
    proc_lock = threading.Lock()

    # Agent conversation history — persists across agent_chat calls in this connection
    agent_history: list[dict] = []
    try:
        from memory import get_conversation_history_for_agent
        agent_history = get_conversation_history_for_agent(200)
    except Exception:
        pass

    # FIX: Bounded queue — prevents unbounded memory growth during fast scans
    send_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=4096)
    loop = asyncio.get_running_loop()

    async def sender():
        while True:
            msg = await send_queue.get()
            try:
                await websocket.send(msg)
            except websockets.exceptions.ConnectionClosed:
                break

    sender_task = asyncio.create_task(sender())

    def q(msg_type, **kw):
        try:
            send_queue.put_nowait(json.dumps({"type": msg_type, **kw}))
        except asyncio.QueueFull:
            pass

    def _q_put_nowait(payload):
        try:
            send_queue.put_nowait(payload)
        except asyncio.QueueFull:
            pass

    def q_threadsafe(msg_type, **kw):
        try:
            payload = json.dumps({"type": msg_type, **kw})
            loop.call_soon_threadsafe(_q_put_nowait, payload)
        except (RuntimeError, AttributeError):
            pass  # Event loop no longer running

    _agent_interrupted = threading.Event()
    try:
        async for raw in websocket:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue

            action = msg.get("action")

            # ── Tool check ──────────────────────────────────────────────────
            if action == "check_tools":
                tools  = await loop.run_in_executor(None, check_tools)
                ollama = await loop.run_in_executor(None, check_ollama)
                q("tools", tools=tools,
                  groups={k: v["description"] for k, v in TOOL_GROUPS.items()})
                q("ollama_status", **ollama)

            # ── Key validation ───────────────────────────────────────────────
            elif action == "validate_key":
                api_key = msg.get("key", "")
                backend = msg.get("backend", "openrouter")
                if backend == "openrouter":
                    valid, message = await loop.run_in_executor(
                        None, validate_openrouter_key, api_key)
                elif backend == "opencode":
                    valid, message = await loop.run_in_executor(
                        None, validate_opencode_key, api_key)
                elif backend == "cerebras":
                    valid, message = await loop.run_in_executor(
                        None, validate_cerebras_key, api_key)
                else:
                    valid, message = False, "Unknown backend"
                q("key_validation", valid=valid, message=message)

            # ── Start scan ──────────────────────────────────────────────────
            elif action == "start_scan":
                target     = msg.get("target", "").strip()
                severity   = msg.get("severity", "critical,high,medium")
                stages     = msg.get("stages", "all")
                outdir     = msg.get("outdir", str(SENTINEL_DIR / "scans"))
                intrusive  = msg.get("intrusive", False)
                ai_backend = msg.get("ai_backend", "none")
                ai_delay   = msg.get("ai_delay", None)
                no_ai = (ai_backend == "none")
                # Always expand ~ so find_latest_run_dir works correctly
                outdir_expanded = str(os.path.expanduser(outdir))

                if not target:
                    q("error", message="No target specified"); continue
                if not AGENT_PATH.exists() and not _IS_FROZEN:
                    q("error", message=f"agent.py not found at {AGENT_PATH}"); continue

                # ── Idempotency check — reject duplicate start_scan within dedup window ──
                clean_target = target.replace("https://", "").replace("http://", "").rstrip("/")
                with _SCAN_REGISTRY_LOCK:
                    last_start = _SCAN_REGISTRY.get(clean_target, 0)
                    now_ts = time.time()
                    if now_ts - last_start < _SCAN_DEDUP_WINDOW_SEC:
                        q("error", message=f"Duplicate scan request for '{clean_target}' ignored (dedup window {_SCAN_DEDUP_WINDOW_SEC:.0f}s). Scan already starting.")
                        continue
                    _SCAN_REGISTRY[clean_target] = now_ts

                with proc_lock:
                    if active_proc and active_proc.poll() is None:
                        q("error", message="A scan is already running. Stop it first.")
                        continue

                cmd = [
                    sys.executable, str(AGENT_PATH), target,
                    "--severity", severity,
                    "--output-dir", outdir_expanded,
                    "--stages", stages,
                    "--skip-check",
                ]
                if intrusive:
                    cmd.append("--enable-intrusive")
                if no_ai:
                    cmd.append("--no-ai")
                if ai_delay is not None:
                    cmd += ["--ai-delay", str(ai_delay)]
                # Always pass --yes so server-launched scans don't block on stdin
                cmd.append("--yes")

                env = os.environ.copy()
                openrouter_key = msg.get("openrouter_key", "")
                if openrouter_key:
                    env["OPENROUTER_API_KEY"] = openrouter_key
                opencode_key = msg.get("opencode_key", "")
                if opencode_key:
                    env["OPENCODE_API_KEY"] = opencode_key
                cerebras_key = msg.get("cerebras_key", "")
                if cerebras_key:
                    env["CEREBRAS_API_KEY"] = cerebras_key

                q("scan_started", target=target, cmd=" ".join(cmd))
                scan_meta = {"outdir": outdir_expanded, "target": clean_target, "no_ai": no_ai}

                def run_agent(meta=scan_meta):
                    nonlocal active_proc
                    try:
                        proc = subprocess.Popen(
                            cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True, bufsize=1, env=env,
                        )
                        with proc_lock:
                            active_proc = proc

                        assert proc.stdout is not None
                        stage_timers: dict = {}
                        for line in iter(proc.stdout.readline, ""):
                            stripped = line.rstrip()
                            # ── Parse SENTINEL stage markers (Architecture §15) ──
                            if stripped.startswith("SENTINEL:STAGE_STARTED:"):
                                stage = stripped.split(":", 2)[2]
                                stage_timers[stage] = time.time()
                                stage = stage.lower()
                                loop.call_soon_threadsafe(
                                    lambda s=stage: send_queue.put_nowait(
                                        json.dumps({"type": "stage_started", "stage": s})
                                    ) if not send_queue.full() else None
                                )
                                continue  # Don't send raw marker line to UI
                            elif stripped.startswith("SENTINEL:STAGE_COMPLETE:"):
                                parts = stripped.split(":", 3)
                                stage = (parts[2] if len(parts) > 2 else "unknown").lower()
                                try:
                                    dur = float(parts[3]) if len(parts) > 3 else 0.0
                                except ValueError:
                                    dur = 0.0
                                loop.call_soon_threadsafe(
                                    lambda s=stage, d=dur: send_queue.put_nowait(
                                        json.dumps({"type": "stage_complete", "stage": s, "duration_sec": d})
                                    ) if not send_queue.full() else None
                                )
                                continue  # Don't send raw marker line to UI

                            loop.call_soon_threadsafe(
                                lambda l=stripped: send_queue.put_nowait(
                                    json.dumps({"type": "line", "text": l})
                                ) if not send_queue.full() else None
                            )

                        proc.wait()
                        rc = proc.returncode

                        all_findings: list = []
                        ai_findings:  list = []
                        report_text:  str  = ""
                        run_dir = find_latest_run_dir(meta["outdir"], meta["target"])
                        if run_dir:
                            all_findings = read_all_findings(run_dir)
                            print(f"[server] DB read: {len(all_findings)} findings from {run_dir}", flush=True)
                            if not meta["no_ai"]:
                                ai_findings = read_ai_findings(run_dir)
                            rpt = find_latest_report(run_dir)
                            if rpt and rpt.exists():
                                try:
                                    report_text = rpt.read_text(encoding="utf-8")
                                except Exception:
                                    pass

                        def _push(payload):
                            if not send_queue.full():
                                send_queue.put_nowait(payload)

                        # Always send scan_findings — even empty list so UI shows
                        # "SCAN COMPLETED — 0 findings" instead of a blank screen.
                        loop.call_soon_threadsafe(
                            _push,
                            json.dumps({"type": "scan_findings", "findings": all_findings}),
                        )
                        if ai_findings:
                            loop.call_soon_threadsafe(
                                _push,
                                json.dumps({"type": "ai_results", "findings": ai_findings}),
                            )
                        if report_text:
                            loop.call_soon_threadsafe(
                                _push,
                                json.dumps({"type": "report_ready", "markdown": report_text}),
                            )
                        # Send explicit scan completion status so UI can always
                        # display "SCAN COMPLETED — N findings" regardless of count.
                        loop.call_soon_threadsafe(
                            _push,
                            json.dumps({
                                "type": "scan_complete_status",
                                "finding_count": len(all_findings),
                                "run_dir": str(run_dir) if run_dir else "",
                                "returncode": rc,
                            }),
                        )
                        loop.call_soon_threadsafe(
                            _push,
                            json.dumps({"type": "scan_done", "returncode": rc, "ok": rc == 0}),
                        )
                        # Release idempotency slot so the user can re-run after finish
                        with _SCAN_REGISTRY_LOCK:
                            _SCAN_REGISTRY.pop(meta.get("target", ""), None)
                    except Exception as ex:
                        loop.call_soon_threadsafe(
                            lambda e=ex: send_queue.put_nowait(
                                json.dumps({"type": "error", "message": str(e)})
                            ) if not send_queue.full() else None
                        )

                threading.Thread(target=run_agent, daemon=True).start()

            # ── Stop scan ────────────────────────────────────────────────────
            elif action == "stop_scan":
                with proc_lock:
                    if active_proc and active_proc.poll() is None:
                        active_proc.terminate()
                        # FIX: Wait briefly for process to exit, then SIGKILL if needed
                        try:
                            active_proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            active_proc.kill()
                            active_proc.wait()
                        q("scan_stopped")
                    else:
                        q("error", message="No scan running")

            # ── Manual fetch of AI results / report ─────────────────────────
            elif action == "get_ai_results":
                outdir = msg.get("outdir", str(SENTINEL_DIR / "scans"))
                target = msg.get("target", "")
                run_dir = find_latest_run_dir(outdir, target)
                if run_dir:
                    findings = await loop.run_in_executor(None, read_ai_findings, run_dir)
                    if findings:
                        q("ai_results", findings=findings)
                # FIX: silently skip when no dir or no AI findings — not an error

            elif action == "get_report":
                outdir = msg.get("outdir", str(SENTINEL_DIR / "scans"))
                target = msg.get("target", "")
                run_dir = find_latest_run_dir(outdir, target)
                if run_dir:
                    rpt = find_latest_report(run_dir)
                    if rpt and rpt.exists():
                        text = await loop.run_in_executor(
                            None, rpt.read_text, "utf-8")
                        q("report_ready", markdown=text)
                    # FIX: silently skip when no report file — not an error,
                    # report is only generated when AI enrichment runs.
                    # Don't flood terminal with red "No report file found" errors.
                else:
                    pass  # FIX: silently skip — no run dir yet is normal mid-scan

            # ── Get findings (per API contract §15) ─────────────────────────
            elif action == "get_findings":
                outdir = msg.get("outdir", str(SENTINEL_DIR / "scans"))
                target = msg.get("target", "")
                run_dir = find_latest_run_dir(outdir, target)
                if run_dir:
                    findings = await loop.run_in_executor(None, read_all_findings, run_dir)
                    q("scan_findings", findings=findings)
                else:
                    q("scan_findings", findings=[])

            elif action == "delete_results":
                target = msg.get("target", "")
                outdir = msg.get("outdir", str(SENTINEL_DIR / "scans"))
                base = Path(os.path.expanduser(outdir)).resolve()
                target_dir = (base / target).resolve()
                if not str(target_dir).startswith(str(base) + os.sep) and target_dir != base:
                    q("results_deleted", target=target, ok=False, reason="Path traversal denied")
                    continue
                if target_dir.exists():
                    import shutil
                    removed = 0
                    for run_dir in sorted(target_dir.iterdir(), reverse=True):
                        if run_dir.is_dir():
                            shutil.rmtree(run_dir, ignore_errors=True)
                            removed += 1
                    q("results_deleted", target=target, ok=True, runs_removed=removed)
                else:
                    q("results_deleted", target=target, ok=False, reason="No scan directory found")

            # ── Memory summary stub (Phase 1 — full memory.py in Phase 2) ───
            elif action == "get_memory_summary":
                target_filter = msg.get("target", None)
                from memory import get_summary as _get_mem_summary
                summary = await loop.run_in_executor(
                    None, _get_mem_summary, target_filter)
                q("memory_summary", data=summary)

            # ── Conversation history ─────────────────────────────────────────
            elif action == "get_conversations":
                from memory import get_conversations as _get_convs
                limit = int(msg.get("limit", 200))
                convs = await loop.run_in_executor(None, _get_convs, limit)
                q("conversations", conversations=convs)

            elif action == "delete_conversation":
                conv_id = msg.get("id", 0)
                if conv_id:
                    from memory import delete_conversation as _del_conv
                    await loop.run_in_executor(None, _del_conv, conv_id)
                    q("conversation_deleted", id=conv_id)

            elif action == "clear_conversations":
                from memory import clear_conversations as _clear_convs
                await loop.run_in_executor(None, _clear_convs)
                q("conversations_cleared")

            # ── Phase 2/3 actions ────────────────────────────────────────────

            elif action == "get_fp_list":
                target = msg.get("target", None)
                fps = await loop.run_in_executor(None, _get_fp_list, target)
                q("fp_list", fps=fps, target=target)

            elif action == "clear_fp":
                fp_hash = msg.get("fp_hash", "")
                ok = await loop.run_in_executor(None, _clear_fp, fp_hash)
                q("fp_cleared", fp_hash=fp_hash, ok=ok)

            elif action == "get_payload_stats":
                stats = await loop.run_in_executor(None, _get_payload_stats)
                q("payload_stats", stats=stats)

            elif action == "get_audit_log":
                limit = int(msg.get("limit", 100))
                action_filter = msg.get("action_filter", None)
                entries = await loop.run_in_executor(
                    None, _get_audit_log, limit, action_filter)
                q("audit_log", entries=entries)

            elif action == "get_disk_usage":
                usage = await loop.run_in_executor(None, _get_disk_usage)
                q("disk_usage", usage=usage)

            elif action == "purge_target":
                target = msg.get("target", "")
                if target:
                    count = await loop.run_in_executor(None, _purge_target, target)
                    q("target_purged", target=target, deleted_count=count)

            elif action == "update_target_notes":
                target  = msg.get("target", "")
                notes   = msg.get("notes", "")
                program = msg.get("program", "")
                ok = await loop.run_in_executor(
                    None, _update_target_notes, target, notes, program)
                q("target_notes_updated", target=target, ok=ok)

            elif action == "delete_target":
                target = msg.get("target", "")
                if target:
                    from memory import delete_target_profile
                    ok = await loop.run_in_executor(None, delete_target_profile, target)
                    _purge_target(target)
                    q("target_deleted", target=target, ok=ok)
                else:
                    q("target_deleted", target=target, ok=False, reason="No target specified")

            elif action == "get_config":
                cfg_flat = await loop.run_in_executor(None, _get_config_flat)
                q("config", config=cfg_flat)

            elif action == "check_resume":
                target = msg.get("target", "")
                result = await loop.run_in_executor(None, _check_resume, target)
                if result:
                    q("resume_available",
                      target=target,
                      run_dir=result["run_dir"],
                      state=result["state"])

            elif action == "get_tool_health":
                # Roadmap Phase 1: return tool health rows for the latest scan of target
                outdir = msg.get("outdir", str(SENTINEL_DIR / "scans"))
                target = msg.get("target", "")
                run_dir = find_latest_run_dir(outdir, target)
                rows: list = []
                if run_dir:
                    db_path = run_dir / "findings.db"
                    if db_path.exists():
                        try:
                            def _read_tool_health(db_path=db_path):
                                conn = sqlite3.connect(str(db_path))
                                conn.row_factory = sqlite3.Row
                                # Get the most recent scan_id for this db
                                scan_row = conn.execute(
                                    "SELECT id FROM scans ORDER BY id DESC LIMIT 1"
                                ).fetchone()
                                if not scan_row:
                                    conn.close()
                                    return []
                                sid = scan_row["id"]
                                rows = conn.execute("""
                                    SELECT tool, installed, version, health_score,
                                           total_runs, crashes, timeouts,
                                           total_runtime_sec, findings_attributed
                                    FROM tool_health WHERE scan_id=?
                                    ORDER BY health_score ASC, tool ASC
                                """, (sid,)).fetchall()
                                conn.close()
                                return [dict(r) for r in rows]
                            health_rows = await loop.run_in_executor(None, _read_tool_health)
                            q("tool_health", rows=health_rows, target=target)
                        except Exception as e:
                            q("tool_health", rows=[], target=target, error=str(e))
                    else:
                        q("tool_health", rows=[], target=target)
                else:
                    q("tool_health", rows=[], target=target)

            # ── Mark/clear false positive ──────────────────────────────────────
            elif action == "mark_fp":
                finding = msg.get("finding", {})
                reason = msg.get("reason", "user marked as FP")
                try:
                    sys.path.insert(0, str(Path(__file__).parent))
                    from memory import get_memory
                    mem = get_memory()
                    mem.learning_loop.register_fp(finding, reason=reason, noted_by="user")
                    q("fp_marked", fp_hash=finding.get("finding_hash", ""), ok=True)
                except Exception as e:
                    q("error", message=f"Failed to mark FP: {e}")

            elif action == "get_program_templates":
                try:
                    sys.path.insert(0, str(Path(__file__).parent))
                    from config import PROGRAM_TEMPLATES
                    q("program_templates", templates=PROGRAM_TEMPLATES)
                except Exception as e:
                    q("program_templates", templates={}, error=str(e))

            elif action == "get_consent_list":
                consent_file = SENTINEL_DIR / "acknowledged_targets.json"
                if consent_file.exists():
                    try:
                        data = json.loads(consent_file.read_text())
                        if isinstance(data, dict):
                            q("consent_list", targets=data)
                        elif isinstance(data, list):
                            q("consent_list", targets={t: {} for t in data})
                        else:
                            q("consent_list", targets={})
                    except Exception:
                        q("consent_list", targets={})
                else:
                    q("consent_list", targets={})

            # ── Agent status check ───────────────────────────────────────────
            elif action == "agent_status":
                backends = await loop.run_in_executor(None, detect_available_backends)
                q("agent_status", available=bool(backends),
                  backends=[b.name for b in backends],
                  primary=backends[0].name if backends else None,
                  model=backends[0].model if backends else None)

            # ── Disconnect AI backend ───────────────────────────────────────
            elif action == "disconnect_ai":
                from ai import BACKENDS
                for name, cfg in BACKENDS.items():
                    if name == "ollama":
                        cfg.base_url = "http://localhost:11434"
                    else:
                        cfg.api_key = None
                    env_var_map = {
                        "openrouter": "OPENROUTER_API_KEY", "opencode": "OPENCODE_API_KEY",
                        "cerebras": "CEREBRAS_API_KEY",
                        "ollama": "OLLAMA_URL",
                    }
                    ev = env_var_map.get(name)
                    if ev and ev in os.environ:
                        del os.environ[ev]
                q("ai_disconnected")

            # ── Configure AI backend from Agent panel ───────────────────────
            elif action == "configure_ai":
                backend_name = msg.get("backend", "")
                api_key = msg.get("api_key", "").strip()
                url = msg.get("url", "").strip()
                try:
                    env_var_map = {
                        "openrouter": "OPENROUTER_API_KEY",
                        "opencode": "OPENCODE_API_KEY",
                        "cerebras": "CEREBRAS_API_KEY",
                        "ollama": "OLLAMA_URL",
                    }
                    env_var = env_var_map.get(backend_name)
                    if not env_var:
                        q("ai_configured", success=False, error=f"Unknown backend: {backend_name}")
                        continue

                    # Set env var for this process lifetime
                    if backend_name == "ollama":
                        os.environ[env_var] = url or "http://localhost:11434"
                    else:
                        if not api_key:
                            q("ai_configured", success=False, error="API key required")
                            continue
                        os.environ[env_var] = api_key

                    # Mutate BACKENDS dict in-place — no importlib.reload needed
                    from ai import reconfigure_backend
                    reconfigure_backend(backend_name, api_key=api_key, url=url)

                    backends = await loop.run_in_executor(None, detect_available_backends)
                    if backends:
                        q("ai_configured", success=True,
                          backend=backends[0].name,
                          model=backends[0].model,
                          available=True)
                    else:
                        q("ai_configured", success=False,
                          error="Could not connect with the provided credentials. Check the key and try again.")
                except Exception as e:
                    q("ai_configured", success=False, error=str(e))

            # ── Agent Interrupt ───────────────────────────────────────────
            elif action == "agent_interrupt":
                _agent_interrupted.set()
                q("agent_interrupted", data={})

            # ── Agent Chat (AI-powered reasoning loop with streaming) ──────────
            elif action == "agent_chat":
                user_input = msg.get("message", "").strip()
                auto_mode = msg.get("auto_mode", False)
                if not user_input:
                    q("agent_error", error="Empty message"); continue

                # ── Mandatory AI check ──
                backends = await loop.run_in_executor(None, detect_available_backends)
                if not backends:
                    q("agent_error", error="No AI backend available. "
                        "Set one of: OLLAMA_URL (local), "
                        "CEREBRAS_API_KEY, OPENROUTER_API_KEY, or OPENCODE_API_KEY "
                        "as environment variables, or start Ollama locally.")
                    continue

                q("agent_start", goal=user_input[:80])
                _agent_interrupted.clear()

                def check_interrupted():
                    return _agent_interrupted.is_set()

                try:
                    from tools import build_registry
                    registry = build_registry()
                    perm_callback = build_permission_callback(q_threadsafe)

                    # Auto-mode: if enabled, auto-grant all permissions
                    if auto_mode:
                        def auto_perm_callback(query):
                            q_threadsafe("agent_thinking", text=f"⚡ Auto-mode: granted — {query[:60]}")
                            return True
                        registry.set_permission_callback(auto_perm_callback)
                    else:
                        registry.set_permission_callback(perm_callback)

                    llm = LLMProvider(backends)

                    run_dir = SENTINEL_DIR / "agent_runs" / str(int(time.time()))
                    brain = AgentBrain(registry, llm, run_dir=run_dir)
                    brain.set_interrupt_event(_agent_interrupted)

                    agent_events: list[dict] = []
                    def on_agent_event(event):
                        etype = event.type
                        edata = event.data
                        agent_events.append({"type": etype, "data": edata})
                        if etype == "agent_thinking":
                            q_threadsafe("agent_thinking", text=edata.get("text", ""),
                                         iteration=edata.get("iteration", 0))
                        elif etype == "agent_action":
                            q_threadsafe("agent_action",
                                         text=edata.get("text", "Deciding next action…"),
                                         tool_calls=edata.get("tool_calls", []))
                        elif etype == "agent_tool_start":
                            q_threadsafe("agent_tool_start", tool=edata.get("tool", ""),
                                         args=edata.get("args", {}))
                        elif etype == "agent_tool_result":
                            q_threadsafe("agent_tool_result", tool=edata.get("tool", ""),
                              result=edata.get("result", ""), success=edata.get("success", False))
                        elif etype == "agent_streaming":
                            q_threadsafe("agent_streaming", text=edata.get("text", ""))
                        elif etype == "agent_stream_end":
                            q_threadsafe("agent_stream_end", text=edata.get("text", ""))
                        elif etype == "agent_response":
                            q_threadsafe("agent_response", text=edata.get("text", ""))
                        elif etype == "agent_complete":
                            q_threadsafe("agent_complete", response=edata.get("response", ""))
                        elif etype == "agent_error":
                            q_threadsafe("agent_error", error=edata.get("error", ""))

                    brain.on_event(on_agent_event)
                    final = await loop.run_in_executor(None, brain.run, user_input, agent_history)

                    if check_interrupted():
                        q("agent_complete", response="interrupted")
                        _agent_interrupted.clear()
                        continue

                    # Store conversation in history for next turn + persist to DB
                    run_id = str(int(time.time() * 1000))
                    agent_history.append({"role": "user", "content": user_input})
                    agent_history.append({"role": "assistant", "content": final})
                    try:
                        from memory import save_conversation
                        save_conversation("user", user_input, run_id)
                        save_conversation("assistant", final, run_id)
                    except Exception:
                        pass  # non-critical

                    # Save findings to DB and send to Results tab
                    if brain._findings:
                        try:
                            findings_db = run_dir / "findings.db"
                            findings_db.parent.mkdir(parents=True, exist_ok=True)
                            conn = sqlite3.connect(str(findings_db))
                            conn.execute("""CREATE TABLE IF NOT EXISTS findings (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                target TEXT, template_id TEXT, name TEXT,
                                severity TEXT, host TEXT, matched_at TEXT,
                                extracted_results TEXT, type TEXT, url TEXT,
                                description TEXT, remediation TEXT, cve_ids TEXT,
                                cvss_score REAL, confidence INTEGER DEFAULT 50,
                                source TEXT DEFAULT 'agent',
                                false_positive INTEGER DEFAULT 0,
                                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                            )""")
                            for f in brain._findings:
                                conn.execute("""INSERT INTO findings
                                    (target, template_id, name, severity, host,
                                     matched_at, extracted_results, type, url,
                                     description, remediation, cve_ids, cvss_score,
                                     confidence, source)
                                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                                    (f.get("target",""), f.get("template_id",""), f.get("name",""),
                                     f.get("severity","info"), f.get("host",""),
                                     f.get("matched_at",""), f.get("extracted_results",""),
                                     f.get("type",""), f.get("url",""),
                                     f.get("description",""), f.get("remediation",""),
                                     f.get("cve_ids",""), f.get("cvss_score"),
                                     f.get("confidence",50), "agent"))
                            conn.commit()
                            conn.close()
                            q("scan_findings", findings=brain._findings)
                        except Exception as db_err:
                            pass

                    q("agent_done", response=final)
                except Exception as e:
                    import traceback
                    traceback.print_exc()
                    q("agent_error", error=str(e))

            elif action == "permission_response":
                request_id = msg.get("request_id", "")
                granted = msg.get("granted", False)
                always = msg.get("always", False)
                if request_id in _pending_permissions:
                    _pending_permissions[request_id]["granted"] = granted
                    _pending_permissions[request_id]["always"] = always
                    _pending_permissions[request_id]["event"].set()

            elif action == "install_tool_from_github":
                """Install a security tool from GitHub that the AI discovered."""
                repo_url = msg.get("repo_url", "")
                tool_name = msg.get("tool_name", "")
                install_cmd = msg.get("install_cmd", "")
                if not repo_url and not install_cmd:
                    q("error", message="No repo URL or install command provided"); continue
                q("agent_thinking", text=f"🔧 Installing {tool_name or 'tool'} from {repo_url or 'custom command'}…")
                try:
                    if install_cmd:
                        proc = await asyncio.create_subprocess_shell(
                            install_cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
                        if proc.returncode == 0:
                            q("agent_thinking", text=f"✅ Installed {tool_name or 'tool'} successfully")
                        else:
                            q("agent_thinking", text=f"⚠️ Install had issues (exit {proc.returncode}): {stderr.decode()[:200]}")
                    else:
                        # Clone and install from GitHub
                        repo_path = repo_url.rstrip('/').replace('https://github.com/', '')
                        clone_url = f"https://github.com/{repo_path}.git"
                        dest = Path.home() / "tools" / repo_path.split('/')[-1]
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        proc = await asyncio.create_subprocess_exec(
                            "git", "clone", "--depth", "1", clone_url, str(dest),
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        await proc.communicate()
                        # Try pip install if setup.py exists
                        req_file = dest / "requirements.txt"
                        setup_file = dest / "setup.py"
                        if req_file.exists():
                            proc2 = await asyncio.create_subprocess_exec(
                                "pip", "install", "-r", str(req_file),
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE,
                            )
                            await proc2.communicate()
                        if setup_file.exists():
                            proc3 = await asyncio.create_subprocess_exec(
                                "pip", "install", "-e", str(dest),
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE,
                            )
                            await proc3.communicate()
                        q("agent_thinking", text=f"✅ Cloned {repo_path} to ~/tools/{dest.name}")
                    q("tools", tools=await loop.run_in_executor(None, check_tools),
                      groups={k: v["description"] for k, v in TOOL_GROUPS.items()})
                except asyncio.TimeoutError:
                    q("agent_error", error=f"Install timed out for {tool_name or repo_url}")
                except Exception as e:
                    q("agent_error", error=f"Install failed: {e}")

            elif action == "find_similar":
                # Phase 2: vector search — requires memory.py with vector index
                # Falls back to basic text search if not available
                finding = msg.get("finding", {})
                top_k   = int(msg.get("top_k", 5))
                try:
                    sys.path.insert(0, str(Path(__file__).parent))
                    from memory import MemoryCore
                    mem = MemoryCore()
                    query_finding = {
                        "name": finding.get("name", ""),
                        "raw_description": finding.get("desc", ""),
                        "template_id": finding.get("template_id", ""),
                    }
                    results = await loop.run_in_executor(
                        None, mem.vector_memory.find_similar, query_finding, top_k)
                    q("similar_findings", findings=results,
                      query_hash=finding.get("id", ""))
                except Exception as e:
                    q("similar_findings", findings=[], query_hash="",
                      error=str(e))

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        sender_task.cancel()
        try:
            await sender_task
        except asyncio.CancelledError:
            pass
        # FIX: Clean up any running proc when client disconnects
        with proc_lock:
            if active_proc and active_proc.poll() is None:
                active_proc.terminate()
                try:
                    active_proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    active_proc.kill()


# ─────────────────────────────────────────────
# HTTP SERVER  (serves ui.html)
# ─────────────────────────────────────────────

logger = logging.getLogger("sentinel-http")

class QuietHandler(SimpleHTTPRequestHandler):
    """Serves static files. Supports PyInstaller bundles via sys._MEIPASS."""
    def __init__(self, *args, **kwargs):
        base_dir = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        super().__init__(*args, directory=base_dir, **kwargs)

    def log_message(self, format, *args):
        if len(args) >= 2:
            try:
                status = int(args[1])
                if status >= 400:
                    logger.warning("%s - %s", self.address_string(), format % args)
            except (ValueError, IndexError):
                pass

    def end_headers(self):
        # FIX: Only allow same-origin (localhost) — not wildcard CORS
        origin = self.headers.get("Origin", "")
        if origin.startswith("http://localhost") or origin.startswith("http://127.0.0.1"):
            self.send_header("Access-Control-Allow-Origin", origin)
        super().end_headers()

    def do_HEAD(self):
        if self.path == "/health":
            body = json.dumps({"status": "ok", "version": VERSION}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return
        super().do_HEAD()

    def do_GET(self):
        # FIX: Simple /health endpoint for process managers / monitoring
        if self.path == "/health":
            body = json.dumps({"status": "ok", "version": VERSION}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


class ReuseHTTPServer(HTTPServer):
    allow_reuse_address = True


def _free_port(port: int):
    try:
        result = subprocess.run(
            ["fuser", "-k", f"{port}/tcp"],
            capture_output=True, timeout=3,
        )
        if result.returncode == 0:
            print(f"  [server] Released stale process on port {port}")
            time.sleep(0.3)
    except FileNotFoundError:
        # fuser not available (macOS, some Linux)
        pass
    except Exception as e:
        logger.debug("_free_port(%d): %s", port, e)


def start_http_server():
    host = os.environ.get("HTTP_HOST", "127.0.0.1")
    _free_port(HTTP_PORT)
    server = ReuseHTTPServer((host, HTTP_PORT), QuietHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

async def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if not _IS_FROZEN and not AGENT_PATH.exists():
        print(f"⚠️  WARNING: agent.py not found at {AGENT_PATH}")

    # ── Auto-update (frozen binary only) ─────────────────────────
    if _IS_FROZEN:
        try:
            req = urllib.request.Request(
                "https://api.github.com/repos/SoukoX/SENTINEL/releases/latest",
                headers={"User-Agent": "SENTINEL/1.0", "Accept": "application/vnd.github.v3+json"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                latest = data.get("tag_name", "")
            if latest and latest != f"v{VERSION}":
                print(f"\n  ⬆ Update available: {latest} (current: v{VERSION})")
                try:
                    ans = input(f"  Download and install {latest} now? [Y/n] ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    ans = "y"
                if ans in ("", "y", "yes"):
                    print(f"  Downloading {latest}…")
                    arch = "linux-x86_64"
                    download_url = f"https://github.com/SoukoX/SENTINEL/releases/download/{latest}/sentinel-{arch}"
                    print(f"  URL: {download_url}")
                    req = urllib.request.Request(download_url, headers={"User-Agent": "SENTINEL/1.0"})
                    with urllib.request.urlopen(req, timeout=120) as resp:
                        total = int(resp.headers.get('Content-Length', 0))
                        print(f"  Size: {total / 1024 / 1024:.1f} MB")
                        chunks = []
                        downloaded = 0
                        next_report = 5
                        while True:
                            chunk = resp.read(262144)
                            if not chunk:
                                break
                            chunks.append(chunk)
                            downloaded += len(chunk)
                            if total > 0:
                                pct = int(downloaded / total * 100)
                                if pct >= next_report:
                                    print(f"\r  Progress: {pct:3d}% ({downloaded/1024/1024:.1f}/{total/1024/1024:.1f} MB)", end="", flush=True)
                                    next_report += 5
                            else:
                                print(f"\r  Downloaded {downloaded/1024/1024:.1f} MB", end="", flush=True)
                        print()
                        new_binary = b"".join(chunks)
                    import tempfile
                    tmp = os.path.join(tempfile.gettempdir(), "sentinel-update")
                    with open(tmp, "wb") as f:
                        f.write(new_binary)
                    os.chmod(tmp, 0o755)
                    current = os.path.realpath("/proc/self/exe")
                    swap_script = f'''#!/bin/bash
sleep 1
mv -f "{tmp}" "{current}"
chmod +x "{current}"
exec "{current}" "$@"
'''
                    script_path = os.path.join(tempfile.gettempdir(), "sentinel-swap.sh")
                    with open(script_path, "w") as f:
                        f.write(swap_script)
                    os.chmod(script_path, 0o755)
                    print(f"  Updated to {latest}. Restarting…\n")
                    os.execv("/bin/bash", ["/bin/bash", script_path] + sys.argv[1:])
                else:
                    print("  Skipping update.\n")
        except Exception as e:
            print(f"  Update check failed: {e}")
            pass  # Silent fail on network issues

    start_http_server()
    print(f"  HTTP server  → http://localhost:{HTTP_PORT}/ui.html")
    print(f"  WebSocket    → ws://{WS_HOST}:{WS_PORT}")
    if not _IS_FROZEN:
        print(f"  agent.py     → {AGENT_PATH} {'✓' if AGENT_PATH.exists() else '✗ NOT FOUND'}")
    print(f"  /health      → http://localhost:{HTTP_PORT}/health")
    print()
    print(f"  Open http://localhost:{HTTP_PORT}/ui.html in your browser")
    print()

    _free_port(WS_PORT)
    async def _ws_process_request(connection, request) -> Response | None:
        """Reject plain HTTP requests hitting the WS port."""
        upgrade = request.headers.get("Upgrade", "").lower()
        if upgrade != "websocket":
            response = connection.respond(400, "Use ws:// not http://")
            response.headers["Access-Control-Allow-Origin"] = "*"
            return response
        return None

    # Security: origins=None is safe here because WS_HOST defaults to 127.0.0.1
    # (loopback only — no remote host can reach the WS port).
    # If WS_HOST=0.0.0.0 (LAN access), add explicit origins or use a regex:
    #   origins=[re.compile(r"https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?")]
    async with ws_serve(
        handle_connection, WS_HOST, WS_PORT,
        process_request=_ws_process_request,
        origins=None,
        ping_interval=30,
        ping_timeout=10,
        max_size=2**20,
        max_queue=32,
    ):
        await asyncio.Future()


if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════════════╗
║   SENTINEL — Cybersecurity Intelligence Platform    ║
║   Daemon v{VERSION}  (Architecture Phase 1)       ║
╚══════════════════════════════════════════════════╝""")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nSentinel daemon stopped.")