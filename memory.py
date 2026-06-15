#!/usr/bin/env python3
"""
SENTINEL — Memory & Learning System
Phase 2 — v1.5

Architecture §4.2: Four-layer memory system
  Layer 1: Episodic  — per-scan context (scan's own DB)
  Layer 2: Semantic  — cross-scan patterns (memory.db)
  Layer 3: Procedural — tool effectiveness per tech stack
  Layer 4: Vector    — TF-IDF semantic search over findings

Phase 2 delivers:
  - Full memory.db schema with all tables
  - Learning loop: tool effectiveness, payload hits, FP memory
  - Target profiles: tech stack, scan history, risk trend
  - False positive registry (never re-alert on confirmed FPs)
  - Payload effectiveness tracking
  - Cross-scan deduplication
  - Memory summary for UI memory panel
  - TF-IDF semantic similarity for "seen this before?" recall
"""

import json
import math
import os
import hashlib
import sqlite3
import re
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────

SENTINEL_DIR = Path(os.environ.get("SENTINEL_DIR", Path.home() / ".sentinel"))
MEMORY_DB_PATH = SENTINEL_DIR / "db" / "memory.db"

VERSION = "2"


# ─────────────────────────────────────────────
# DATABASE INIT
# ─────────────────────────────────────────────

def get_memory_conn() -> sqlite3.Connection:
    """Get a connection to memory.db, creating it if it doesn't exist."""
    MEMORY_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(MEMORY_DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    _init_memory_schema(conn)
    return conn


def _init_memory_schema(conn: sqlite3.Connection):
    conn.executescript("""
        -- Cross-scan pattern table (Architecture §4.2 Layer 2)
        CREATE TABLE IF NOT EXISTS memory_patterns (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern_type      TEXT NOT NULL,  -- 'vuln', 'tech', 'payload', 'fp_signature'
            pattern_key       TEXT NOT NULL,
            pattern_data      TEXT,           -- JSON
            target_hint       TEXT,           -- which target class this applies to
            confidence        REAL DEFAULT 0.5,
            observation_count INTEGER DEFAULT 1,
            first_seen        TEXT NOT NULL,
            last_seen         TEXT NOT NULL,
            verified          INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_mp_type ON memory_patterns(pattern_type);
        CREATE INDEX IF NOT EXISTS idx_mp_key  ON memory_patterns(pattern_key);

        -- False positive registry — never re-alert on these (Architecture §4.2)
        CREATE TABLE IF NOT EXISTS false_positives (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            fp_hash     TEXT UNIQUE NOT NULL,
            reason      TEXT,
            noted_at    TEXT NOT NULL,
            noted_by    TEXT DEFAULT 'user',  -- 'user' or 'ai'
            target      TEXT,
            template_id TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_fp_hash ON false_positives(fp_hash);

        -- Payload effectiveness tracking (Architecture §4.2)
        CREATE TABLE IF NOT EXISTS payload_stats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            payload     TEXT NOT NULL,
            vuln_type   TEXT NOT NULL,  -- xss, sqli, ssrf, etc.
            hit_count   INTEGER DEFAULT 0,
            miss_count  INTEGER DEFAULT 0,
            last_hit    TEXT,
            last_miss   TEXT,
            tech_hints  TEXT DEFAULT '[]'  -- JSON: worked on which tech stacks
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_ps_key ON payload_stats(payload, vuln_type);

        -- Target profiles (Architecture §4.2)
        CREATE TABLE IF NOT EXISTS target_profiles (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            target           TEXT UNIQUE NOT NULL,
            first_seen       TEXT NOT NULL,
            last_seen        TEXT NOT NULL,
            tech_stack       TEXT DEFAULT '{}',  -- JSON
            known_subdomains TEXT DEFAULT '[]',  -- JSON
            scan_count       INTEGER DEFAULT 0,
            total_vulns      INTEGER DEFAULT 0,
            critical_count   INTEGER DEFAULT 0,
            high_count       INTEGER DEFAULT 0,
            medium_count     INTEGER DEFAULT 0,
            low_count        INTEGER DEFAULT 0,
            info_count       INTEGER DEFAULT 0,
            risk_trend       TEXT DEFAULT 'unknown',  -- 'improving', 'degrading', 'stable', 'unknown'
            risk_scores      TEXT DEFAULT '[]',       -- JSON: last 10 scan risk scores
            notes            TEXT DEFAULT '',
            program_name     TEXT DEFAULT '',         -- bug bounty program
            last_scan_uuid   TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_tp_target ON target_profiles(target);

        -- Learning observations (Architecture §5.2)
        CREATE TABLE IF NOT EXISTS learning_observations (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at       TEXT NOT NULL,
            scan_uuid         TEXT NOT NULL,
            observation_type  TEXT NOT NULL,  -- 'tool_effectiveness', 'payload_hit', 'fp_detected', 'tech_stack'
            subject           TEXT NOT NULL,  -- tool name or payload
            context           TEXT DEFAULT '{}',  -- JSON: tech stack, target type, etc.
            outcome           TEXT NOT NULL,      -- 'hit', 'miss', 'fp', 'detected'
            confidence_delta  REAL DEFAULT 0.0
        );
        CREATE INDEX IF NOT EXISTS idx_lo_type    ON learning_observations(observation_type);
        CREATE INDEX IF NOT EXISTS idx_lo_subject ON learning_observations(subject);

        -- Tool effectiveness scores per tech context
        CREATE TABLE IF NOT EXISTS tool_effectiveness (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_name       TEXT NOT NULL,
            tech_context    TEXT NOT NULL,   -- e.g. 'wordpress', 'django', 'php', 'generic'
            hit_count       INTEGER DEFAULT 0,
            total_runs      INTEGER DEFAULT 0,
            avg_findings    REAL DEFAULT 0.0,
            last_updated    TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_te_key ON tool_effectiveness(tool_name, tech_context);

        -- TF-IDF index for vector memory (Architecture §4.2 Layer 4)
        CREATE TABLE IF NOT EXISTS tfidf_documents (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            doc_id      TEXT UNIQUE NOT NULL,  -- finding_hash
            target      TEXT,
            content     TEXT NOT NULL,         -- normalized text for indexing
            tf_json     TEXT NOT NULL,         -- JSON: {term: tf_score}
            severity    TEXT,
            vuln_type   TEXT,
            added_at    TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_tfidf_target ON tfidf_documents(target);

        -- Notification history (Architecture §5.2)
        CREATE TABLE IF NOT EXISTS notified_findings (
            finding_hash TEXT PRIMARY KEY,
            notified_at  TEXT NOT NULL,
            channel      TEXT DEFAULT 'tui'
        );

        -- Scan history index (for cross-scan queries without scanning all DBs)
        CREATE TABLE IF NOT EXISTS scan_index (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_uuid   TEXT UNIQUE NOT NULL,
            target      TEXT NOT NULL,
            started_at  TEXT NOT NULL,
            finished_at TEXT,
            status      TEXT DEFAULT 'running',
            db_path     TEXT NOT NULL,
            risk_score  INTEGER DEFAULT 0,
            finding_count INTEGER DEFAULT 0,
            tech_stack  TEXT DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_si_target ON scan_index(target);

        -- Agent conversation history (chat memory)
        CREATE TABLE IF NOT EXISTS conversations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            role        TEXT NOT NULL,  -- 'user' or 'assistant'
            content     TEXT NOT NULL,
            run_id      TEXT NOT NULL,  -- groups user+assistant pairs
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_conv_run ON conversations(run_id);
        CREATE INDEX IF NOT EXISTS idx_conv_time ON conversations(created_at);
    """)
    conn.commit()


# ─────────────────────────────────────────────
# FALSE POSITIVE REGISTRY
# ─────────────────────────────────────────────

class FPRegistry:
    """False positive memory — never re-alert on confirmed FPs."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def _fp_hash(self, template_id: str, host: str, matched_at: str) -> str:
        raw = f"{template_id}|{host}|{matched_at}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def mark_fp(self, template_id: str, host: str, matched_at: str,
                reason: str = "", noted_by: str = "user", target: str = ""):
        fhash = self._fp_hash(template_id, host, matched_at)
        now = datetime.now().isoformat()
        self.conn.execute("""
            INSERT OR IGNORE INTO false_positives
            (fp_hash, reason, noted_at, noted_by, target, template_id)
            VALUES (?,?,?,?,?,?)
        """, (fhash, reason, now, noted_by, target, template_id))
        self.conn.commit()
        return fhash

    def is_fp(self, template_id: str, host: str, matched_at: str) -> bool:
        fhash = self._fp_hash(template_id, host, matched_at)
        row = self.conn.execute(
            "SELECT id FROM false_positives WHERE fp_hash=?", (fhash,)
        ).fetchone()
        return row is not None

    def filter_findings(self, findings: list[dict]) -> tuple[list[dict], list[dict]]:
        """
        Split findings into (clean, filtered_fp).
        Returns (real_findings, fp_findings).
        """
        real, fps = [], []
        for f in findings:
            if self.is_fp(
                f.get("template_id", ""),
                f.get("host", ""),
                f.get("matched_at", ""),
            ):
                fps.append(f)
            else:
                real.append(f)
        return real, fps

    def get_all(self, target: Optional[str] = None) -> list[dict]:
        if target:
            rows = self.conn.execute(
                "SELECT * FROM false_positives WHERE target=? ORDER BY noted_at DESC", (target,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM false_positives ORDER BY noted_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def clear_fp(self, fp_hash: str):
        self.conn.execute("DELETE FROM false_positives WHERE fp_hash=?", (fp_hash,))
        self.conn.commit()

    def get_common_patterns(self, limit: int = 5) -> list[dict]:
        """Return most-common FP patterns grouped by template_id."""
        rows = self.conn.execute("""
            SELECT template_id, COUNT(*) as count,
                   GROUP_CONCAT(DISTINCT reason) as reasons,
                   GROUP_CONCAT(DISTINCT target) as affected_targets
            FROM false_positives
            WHERE template_id != ''
            GROUP BY template_id
            ORDER BY count DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]


# ─────────────────────────────────────────────
# PAYLOAD EFFECTIVENESS TRACKER
# ─────────────────────────────────────────────

class PayloadTracker:
    """Track which payloads work on which target types."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def record_hit(self, payload: str, vuln_type: str, tech_hints: Optional[list[str]] = None):
        now = datetime.now().isoformat()
        tech_json = json.dumps(tech_hints or [])
        self.conn.execute("""
            INSERT INTO payload_stats (payload, vuln_type, hit_count, last_hit, tech_hints)
            VALUES (?,?,1,?,?)
            ON CONFLICT(payload, vuln_type) DO UPDATE SET
                hit_count = hit_count + 1,
                last_hit = ?,
                tech_hints = ?
        """, (payload, vuln_type, now, tech_json, now, tech_json))
        self.conn.commit()

    def record_miss(self, payload: str, vuln_type: str):
        now = datetime.now().isoformat()
        self.conn.execute("""
            INSERT INTO payload_stats (payload, vuln_type, miss_count, last_miss)
            VALUES (?,?,1,?)
            ON CONFLICT(payload, vuln_type) DO UPDATE SET
                miss_count = miss_count + 1,
                last_miss = ?
        """, (payload, vuln_type, now, now))
        self.conn.commit()

    def get_top_payloads(self, vuln_type: str, tech_hint: Optional[str] = None,
                         limit: int = 20) -> list[dict]:
        """Get highest-effectiveness payloads for a vulnerability type."""
        rows = self.conn.execute("""
            SELECT payload, vuln_type, hit_count, miss_count, last_hit, tech_hints,
                   CAST(hit_count AS REAL) / MAX(hit_count + miss_count, 1) AS effectiveness
            FROM payload_stats
            WHERE vuln_type=? AND hit_count > 0
            ORDER BY effectiveness DESC, hit_count DESC
            LIMIT ?
        """, (vuln_type, limit)).fetchall()
        results = [dict(r) for r in rows]
        if tech_hint:
            # Boost payloads that worked on same tech stack
            for r in results:
                hints = json.loads(r.get("tech_hints", "[]"))
                if tech_hint.lower() in [h.lower() for h in hints]:
                    r["tech_match"] = True
            results.sort(key=lambda x: (x.get("tech_match", False), x["effectiveness"]), reverse=True)
        return results

    def get_stats(self) -> dict:
        rows = self.conn.execute("""
            SELECT vuln_type,
                   SUM(hit_count) as total_hits,
                   SUM(miss_count) as total_misses,
                   COUNT(*) as unique_payloads
            FROM payload_stats
            GROUP BY vuln_type
            ORDER BY total_hits DESC
        """).fetchall()
        return {r["vuln_type"]: dict(r) for r in rows}


# ─────────────────────────────────────────────
# TARGET PROFILES
# ─────────────────────────────────────────────

class TargetProfiler:
    """Remember everything we know about each target."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def get_or_create(self, target: str) -> dict:
        now = datetime.now().isoformat()
        row = self.conn.execute(
            "SELECT * FROM target_profiles WHERE target=?", (target,)
        ).fetchone()
        if row:
            return dict(row)
        self.conn.execute("""
            INSERT INTO target_profiles (target, first_seen, last_seen)
            VALUES (?,?,?)
        """, (target, now, now))
        self.conn.commit()
        return self.get_or_create(target)

    def update_after_scan(self, target: str, scan_result: dict):
        """
        Update target profile after a scan completes.
        scan_result should contain:
          - findings: list of finding dicts
          - tech_stack: dict of detected technologies
          - subdomains: list of subdomains found
          - scan_uuid: unique scan ID
          - risk_score: computed risk score (0-100)
        """
        now = datetime.now().isoformat()
        profile = self.get_or_create(target)

        findings = scan_result.get("findings", [])
        tech_stack = scan_result.get("tech_stack", {})
        subdomains = scan_result.get("subdomains", [])
        risk_score = scan_result.get("risk_score", 0)
        scan_uuid = scan_result.get("scan_uuid", "")

        # Count by severity
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # Compute risk trend
        risk_scores = json.loads(profile.get("risk_scores", "[]"))
        risk_scores.append(risk_score)
        risk_scores = risk_scores[-10:]  # Keep last 10
        trend = self._compute_trend(risk_scores)

        # Merge known subdomains
        known_subs = set(json.loads(profile.get("known_subdomains", "[]")))
        known_subs.update(subdomains)

        # Merge tech stack (union)
        known_tech = json.loads(profile.get("tech_stack", "{}"))
        for k, v in tech_stack.items():
            known_tech[k] = v

        self.conn.execute("""
            UPDATE target_profiles SET
                last_seen=?, scan_count=scan_count+1, total_vulns=total_vulns+?,
                critical_count=critical_count+?, high_count=high_count+?,
                medium_count=medium_count+?, low_count=low_count+?,
                info_count=info_count+?, risk_trend=?, risk_scores=?,
                known_subdomains=?, tech_stack=?, last_scan_uuid=?
            WHERE target=?
        """, (
            now,
            len(findings),
            sev_counts["critical"], sev_counts["high"],
            sev_counts["medium"], sev_counts["low"], sev_counts["info"],
            trend,
            json.dumps(risk_scores),
            json.dumps(sorted(known_subs)),
            json.dumps(known_tech),
            scan_uuid,
            target,
        ))
        self.conn.commit()

    def _compute_trend(self, scores: list[float]) -> str:
        if len(scores) < 2:
            return "unknown"
        recent = sum(scores[-3:]) / len(scores[-3:])
        older = sum(scores[:-3]) / max(len(scores[:-3]), 1) if len(scores) > 3 else scores[0]
        diff = recent - older
        if diff > 5:
            return "degrading"
        elif diff < -5:
            return "improving"
        return "stable"

    def get(self, target: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM target_profiles WHERE target=?", (target,)
        ).fetchone()
        return dict(row) if row else None

    def list_all(self) -> list[dict]:
        rows = self.conn.execute("""
            SELECT * FROM target_profiles ORDER BY last_seen DESC
        """).fetchall()
        return [dict(r) for r in rows]

    def set_notes(self, target: str, notes: str):
        self.conn.execute(
            "UPDATE target_profiles SET notes=? WHERE target=?", (notes, target)
        )
        self.conn.commit()

    def set_program(self, target: str, program_name: str):
        self.conn.execute(
            "UPDATE target_profiles SET program_name=? WHERE target=?", (program_name, target)
        )
        self.conn.commit()

    def delete_target(self, target: str) -> bool:
        """Delete a target profile and all associated data (FP, observations, scan index, vector docs)."""
        self.conn.execute("DELETE FROM target_profiles WHERE target=?", (target,))
        self.conn.execute("DELETE FROM false_positives WHERE target=?", (target,))
        self.conn.execute("DELETE FROM learning_observations WHERE subject=?", (target,))
        self.conn.execute("DELETE FROM scan_index WHERE target=?", (target,))
        self.conn.execute("DELETE FROM tfidf_documents WHERE target=?", (target,))
        self.conn.commit()
        return True


# ─────────────────────────────────────────────
# TOOL EFFECTIVENESS TRACKER
# ─────────────────────────────────────────────

class ToolEffectivenessTracker:
    """Learn which tools produce results on which tech stacks."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def record_tool_run(self, tool_name: str, tech_context: str,
                        finding_count: int, scan_uuid: str,
                        error_category: str = ""):
        now = datetime.now().isoformat()
        row = self.conn.execute(
            "SELECT * FROM tool_effectiveness WHERE tool_name=? AND tech_context=?",
            (tool_name, tech_context)
        ).fetchone()

        if row:
            new_total = row["total_runs"] + 1
            new_hits = row["hit_count"] + (1 if finding_count > 0 else 0)
            new_avg = (row["avg_findings"] * row["total_runs"] + finding_count) / new_total
            self.conn.execute("""
                UPDATE tool_effectiveness SET
                    hit_count=?, total_runs=?, avg_findings=?, last_updated=?
                WHERE tool_name=? AND tech_context=?
            """, (new_hits, new_total, new_avg, now, tool_name, tech_context))
        else:
            self.conn.execute("""
                INSERT INTO tool_effectiveness
                (tool_name, tech_context, hit_count, total_runs, avg_findings, last_updated)
                VALUES (?,?,?,1,?,?)
            """, (tool_name, tech_context, 1 if finding_count > 0 else 0, float(finding_count), now))

        # Record as learning observation
        self.conn.execute("""
            INSERT INTO learning_observations
            (observed_at, scan_uuid, observation_type, subject, context, outcome, confidence_delta)
            VALUES (?,?,?,?,?,?,?)
        """, (
            now, scan_uuid, "tool_effectiveness", tool_name,
            json.dumps({"tech_context": tech_context, "findings": finding_count}),
            "hit" if finding_count > 0 else "miss",
            0.1 if finding_count > 0 else -0.02,
        ))
        self.conn.commit()

    def get_best_tools(self, tech_context: str, min_runs: int = 2) -> list[dict]:
        rows = self.conn.execute("""
            SELECT tool_name, tech_context, hit_count, total_runs, avg_findings,
                   CAST(hit_count AS REAL)/MAX(total_runs,1) AS hit_rate
            FROM tool_effectiveness
            WHERE tech_context=? AND total_runs >= ?
            ORDER BY hit_rate DESC, avg_findings DESC
        """, (tech_context, min_runs)).fetchall()
        return [dict(r) for r in rows]

    def get_skip_tools(self, tech_context: str, threshold: float = 0.05) -> list[str]:
        """Tools that almost never find anything on this tech stack."""
        rows = self.conn.execute("""
            SELECT tool_name
            FROM tool_effectiveness
            WHERE tech_context=? AND total_runs >= 5
              AND CAST(hit_count AS REAL)/total_runs < ?
        """, (tech_context, threshold)).fetchall()
        return [r["tool_name"] for r in rows]


# ─────────────────────────────────────────────
# VECTOR MEMORY (TF-IDF Semantic Search)
# Architecture §4.2 Layer 4
# ─────────────────────────────────────────────

class VectorMemory:
    """TF-IDF based semantic search over finding descriptions."""

    STOP_WORDS = {
        "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
        "of", "with", "by", "from", "is", "was", "are", "were", "has", "have",
        "had", "be", "been", "this", "that", "it", "its", "found", "detected",
    }

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def _tokenize(self, text: str) -> list[str]:
        text = text.lower()
        text = re.sub(r"[^a-z0-9\s\-_/]", " ", text)
        tokens = text.split()
        return [t for t in tokens if t not in self.STOP_WORDS and len(t) > 2]

    def _compute_tf(self, tokens: list[str]) -> dict[str, float]:
        if not tokens:
            return {}
        counter = Counter(tokens)
        total = len(tokens)
        return {term: count / total for term, count in counter.items()}

    def add_finding(self, finding: dict):
        doc_id = finding.get("finding_hash", "")
        if not doc_id:
            return

        # Build searchable content
        parts = [
            finding.get("name", ""),
            finding.get("raw_description", ""),
            finding.get("ai_explanation", ""),
            finding.get("template_id", ""),
            finding.get("category", ""),
        ]
        content = " ".join(p for p in parts if p)
        tokens = self._tokenize(content)
        tf = self._compute_tf(tokens)
        now = datetime.now().isoformat()

        self.conn.execute("""
            INSERT OR REPLACE INTO tfidf_documents
            (doc_id, target, content, tf_json, severity, vuln_type, added_at)
            VALUES (?,?,?,?,?,?,?)
        """, (
            doc_id,
            finding.get("host", ""),
            content,
            json.dumps(tf),
            finding.get("severity", ""),
            finding.get("category", ""),
            now,
        ))
        self.conn.commit()

    def find_similar(self, finding: dict, top_k: int = 5, exclude_hash: Optional[str] = None) -> list[dict]:
        """Find semantically similar past findings using TF-IDF cosine similarity."""
        parts = [
            finding.get("name", ""),
            finding.get("raw_description", ""),
            finding.get("template_id", ""),
        ]
        query_content = " ".join(p for p in parts if p)
        query_tokens = self._tokenize(query_content)
        query_tf = self._compute_tf(query_tokens)

        if not query_tf:
            return []

        rows = self.conn.execute("SELECT * FROM tfidf_documents").fetchall()
        scored = []
        for row in rows:
            if exclude_hash and row["doc_id"] == exclude_hash:
                continue
            doc_tf = json.loads(row["tf_json"])
            score = self._cosine_similarity(query_tf, doc_tf)
            if score > 0.1:
                scored.append((score, dict(row)))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [{"similarity": s, **d} for s, d in scored[:top_k]]

    def _cosine_similarity(self, a: dict[str, float], b: dict[str, float]) -> float:
        common = set(a) & set(b)
        if not common:
            return 0.0
        dot = sum(a[t] * b[t] for t in common)
        mag_a = math.sqrt(sum(v*v for v in a.values()))
        mag_b = math.sqrt(sum(v*v for v in b.values()))
        if mag_a == 0 or mag_b == 0:
            return 0.0
        return dot / (mag_a * mag_b)

    def recall_context(self, query: str, top_k: int = 5) -> str:
        """Give AI context from memory before analysis. Returns formatted string."""
        tokens = self._tokenize(query)
        tf = self._compute_tf(tokens)
        rows = self.conn.execute("SELECT * FROM tfidf_documents").fetchall()
        scored = []
        for row in rows:
            doc_tf = json.loads(row["tf_json"])
            score = self._cosine_similarity(tf, doc_tf)
            if score > 0.1:
                scored.append((score, dict(row)))
        scored.sort(key=lambda x: x[0], reverse=True)
        if not scored:
            return ""
        parts = [f"[Memory: similar finding on {d['target']}: {d['content'][:120]}]"
                 for _, d in scored[:top_k]]
        return "\n".join(parts)


# ─────────────────────────────────────────────
# LEARNING LOOP
# Architecture §4.2 — Learning Loop
# ─────────────────────────────────────────────

class LearningLoop:
    """
    Called after every scan completes. Extracts learnable signals
    and updates all memory layers.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.fp_registry = FPRegistry(conn)
        self.payload_tracker = PayloadTracker(conn)
        self.target_profiler = TargetProfiler(conn)
        self.tool_tracker = ToolEffectivenessTracker(conn)
        self.vector_memory = VectorMemory(conn)

    def process_scan(self, scan_data: dict):
        """
        Main entry point — call after every scan.

        scan_data keys:
          target, scan_uuid, findings, tech_stack, subdomains,
          tools_run (dict: tool_name -> finding_count),
          risk_score, xss_payloads_hit, sqli_payloads_hit
        """
        target = scan_data.get("target", "")
        scan_uuid = scan_data.get("scan_uuid", "")
        findings = scan_data.get("findings", [])
        tech_stack = scan_data.get("tech_stack", {})
        subdomains = scan_data.get("subdomains", [])
        tools_run = scan_data.get("tools_run", {})
        risk_score = scan_data.get("risk_score", 0)
        xss_hits = scan_data.get("xss_payloads_hit", [])
        sqli_hits = scan_data.get("sqli_payloads_hit", [])

        # Determine tech context (simplified to most prominent tech)
        tech_context = _dominant_tech(tech_stack)

        # 1. Update target profile
        self.target_profiler.update_after_scan(target, {
            "findings": findings,
            "tech_stack": tech_stack,
            "subdomains": subdomains,
            "scan_uuid": scan_uuid,
            "risk_score": risk_score,
        })

        # 2. Update tool effectiveness
        for tool_name, finding_count in tools_run.items():
            self.tool_tracker.record_tool_run(tool_name, tech_context, finding_count, scan_uuid)

        # 3. Track payload hits
        for payload in xss_hits:
            self.payload_tracker.record_hit(payload, "xss",
                                            tech_hints=list(tech_stack.keys()))
        for payload in sqli_hits:
            self.payload_tracker.record_hit(payload, "sqli",
                                            tech_hints=list(tech_stack.keys()))

        # 4. Add findings to vector memory
        for f in findings:
            if not f.get("false_positive"):
                self.vector_memory.add_finding(f)

        # 5. Index this scan
        now = datetime.now().isoformat()
        self.conn.execute("""
            INSERT OR REPLACE INTO scan_index
            (scan_uuid, target, started_at, finished_at, status, db_path, risk_score, finding_count, tech_stack)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            scan_uuid, target,
            scan_data.get("started_at", now),
            scan_data.get("finished_at", now),
            "complete",
            scan_data.get("db_path", ""),
            risk_score,
            len(findings),
            json.dumps(tech_stack),
        ))
        self.conn.commit()

    def register_fp(self, finding: dict, reason: str = "", noted_by: str = "user"):
        """Register a finding as a confirmed false positive."""
        self.fp_registry.mark_fp(
            finding.get("template_id", ""),
            finding.get("host", ""),
            finding.get("matched_at", ""),
            reason=reason,
            noted_by=noted_by,
            target=finding.get("host", ""),
        )

    def filter_fps(self, findings: list[dict]) -> tuple[list[dict], list[dict]]:
        return self.fp_registry.filter_findings(findings)


# ─────────────────────────────────────────────
# MEMORY SUMMARY  (for UI memory panel)
# ─────────────────────────────────────────────

class MemoryCore:
    """Top-level memory API used by server.py and agent.py."""

    def __init__(self):
        self.conn = get_memory_conn()
        self.fp_registry = FPRegistry(self.conn)
        self.payload_tracker = PayloadTracker(self.conn)
        self.target_profiler = TargetProfiler(self.conn)
        self.tool_tracker = ToolEffectivenessTracker(self.conn)
        self.vector_memory = VectorMemory(self.conn)
        self.learning_loop = LearningLoop(self.conn)

    def get_full_summary(self, target_filter: Optional[str] = None) -> dict:
        """Full memory summary for the UI memory panel."""
        profiles = self.target_profiler.list_all()
        if target_filter:
            profiles = [p for p in profiles if p["target"] == target_filter]

        total_scans = sum(p["scan_count"] for p in profiles)
        total_vulns = sum(p["total_vulns"] for p in profiles)
        total_fps = self.conn.execute("SELECT COUNT(*) as n FROM false_positives").fetchone()["n"]

        payload_stats = self.payload_tracker.get_stats()

        # Top vulnerable targets
        profiles_sorted = sorted(profiles, key=lambda p: p.get("total_vulns", 0), reverse=True)

        # Skill registry (best tools per tech)
        skill_contexts = self.conn.execute("""
            SELECT DISTINCT tech_context FROM tool_effectiveness ORDER BY tech_context
        """).fetchall()
        skills = {}
        for row in skill_contexts:
            ctx = row["tech_context"]
            best = self.tool_tracker.get_best_tools(ctx)[:5]
            skip = self.tool_tracker.get_skip_tools(ctx)[:3]
            if best:
                skills[ctx] = {"best_tools": [b["tool_name"] for b in best], "skip_tools": skip}

        # Recent learning observations
        recent_obs = self.conn.execute("""
            SELECT * FROM learning_observations
            ORDER BY observed_at DESC LIMIT 20
        """).fetchall()

        return {
            "total_scans": total_scans,
            "total_findings": total_vulns,
            "total_fp_filtered": total_fps,
            "conversation_count": self.conn.execute("SELECT COUNT(*) as n FROM conversations").fetchone()["n"],
            "targets": profiles_sorted,
            "payload_stats": payload_stats,
            "skill_registry": skills,
            "recent_observations": [dict(r) for r in recent_obs],
            "vector_doc_count": self.conn.execute(
                "SELECT COUNT(*) as n FROM tfidf_documents"
            ).fetchone()["n"],
        }

    # ── Conversation History ─────────────────────────────────

    def save_conversation_turn(self, role: str, content: str, run_id: str):
        """Save a single conversation message to the DB."""
        self.conn.execute(
            "INSERT INTO conversations (role, content, run_id) VALUES (?, ?, ?)",
            (role, content, run_id),
        )
        self.conn.commit()

    def get_conversations(self, limit: int = 100) -> list[dict]:
        """Get all conversations, grouped by run_id, newest first."""
        rows = self.conn.execute("""
            SELECT id, role, content, run_id, created_at
            FROM conversations
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def delete_conversation(self, conv_id: int):
        """Delete a single conversation message."""
        self.conn.execute("DELETE FROM conversations WHERE id = ?", (conv_id,))
        self.conn.commit()

    def clear_conversations(self):
        """Delete all conversation history."""
        self.conn.execute("DELETE FROM conversations")
        self.conn.commit()

    def get_target_context(self, target: str) -> str:
        """
        Get rich context about a target for AI pre-prompt.
        Used before AI_ENRICH stage to give AI memory context.
        """
        profile = self.target_profiler.get(target)
        if not profile:
            return f"No prior knowledge of {target}."

        lines = [f"Target: {target}"]
        if profile["scan_count"] > 1:
            lines.append(f"Scanned {profile['scan_count']} times before — {profile['total_vulns']} total vulns found.")
            lines.append(f"Risk trend: {profile['risk_trend']}")

        tech = json.loads(profile.get("tech_stack", "{}"))
        if tech:
            lines.append(f"Known tech stack: {', '.join(tech.keys())}")

        subs = json.loads(profile.get("known_subdomains", "[]"))
        if subs:
            lines.append(f"Known subdomains: {len(subs)} ({', '.join(subs[:5])}{'...' if len(subs)>5 else ''})")

        if profile.get("notes"):
            lines.append(f"Notes: {profile['notes']}")

        return "\n".join(lines)

    def should_skip_finding(self, finding: dict) -> bool:
        """Check if a finding should be suppressed (known FP)."""
        return self.fp_registry.is_fp(
            finding.get("template_id", ""),
            finding.get("host", ""),
            finding.get("matched_at", ""),
        )

    def get_common_fp_patterns(self, limit: int = 5) -> list[dict]:
        """Most-common false positive template patterns."""
        return self.fp_registry.get_common_patterns(limit)

    def close(self):
        self.conn.close()


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _dominant_tech(tech_stack: dict) -> str:
    """Reduce a tech_stack dict to a single context key for indexing."""
    priority = ["wordpress", "drupal", "joomla", "django", "rails", "laravel",
                "spring", "express", "flask", "nextjs", "react", "angular",
                "php", "python", "java", "node", "ruby", "go"]
    tech_lower = {k.lower(): v for k, v in tech_stack.items()}
    for p in priority:
        if p in tech_lower:
            return p
    # Fall back to first detected tech or generic
    if tech_stack:
        return list(tech_stack.keys())[0].lower()
    return "generic"


def compute_risk_score(findings: list[dict]) -> int:
    """Compute a 0-100 risk score from a finding list."""
    SEVERITY_WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
    score = sum(SEVERITY_WEIGHTS.get(f.get("severity", "info"), 0) for f in findings)
    return min(100, score)


# ─────────────────────────────────────────────
# SCAN RESUME HELPER
# ─────────────────────────────────────────────

def load_resumable_state(run_dir: Path) -> Optional[dict]:
    """
    Load scan_state.json from a scan directory for resume logic.
    Returns None if no resumable state found.
    """
    state_file = run_dir / "scan_state.json"
    if not state_file.exists():
        return None
    try:
        state = json.loads(state_file.read_text())
        # Only resume if interrupted (not complete/error)
        if state.get("status") in ("running", "interrupted"):
            return state
    except Exception:
        pass
    return None


def find_resumable_scan(target: str, scans_dir: Path) -> Optional[tuple[Path, dict]]:
    """
    Find the most recent interrupted/running scan for a target.
    Returns (run_dir, state) or None.
    """
    if not scans_dir.exists():
        return None
    safe = target.replace("https://", "").replace("http://", "").rstrip("/")
    candidates = [d for d in scans_dir.iterdir()
                  if d.is_dir() and d.name.startswith(safe + "_")]
    candidates.sort(key=lambda d: d.stat().st_mtime, reverse=True)
    for run_dir in candidates:
        state = load_resumable_state(run_dir)
        if state:
            return run_dir, state
    return None


# ─────────────────────────────────────────────
# STANDALONE API (for use from agent.py / server.py)
# ─────────────────────────────────────────────

_memory_core: Optional[MemoryCore] = None


def get_memory() -> MemoryCore:
    """Singleton accessor for the global MemoryCore."""
    global _memory_core
    if _memory_core is None:
        _memory_core = MemoryCore()
    return _memory_core


def register_false_positive(finding: dict, reason: str = "", noted_by: str = "user"):
    """Convenience wrapper for marking a finding as FP."""
    get_memory().learning_loop.register_fp(finding, reason=reason, noted_by=noted_by)


def post_scan_learning(scan_data: dict):
    """
    Call this after every scan to update all memory layers.
    This is the main entry point for the learning loop.
    """
    get_memory().learning_loop.process_scan(scan_data)


def get_summary(target: Optional[str] = None) -> dict:
    """Get full memory summary (for UI / WebSocket API)."""
    return get_memory().get_full_summary(target_filter=target)


def save_conversation(role: str, content: str, run_id: str):
    """Save a conversation turn to the memory DB."""
    get_memory().save_conversation_turn(role, content, run_id)


def get_conversations(limit: int = 100) -> list[dict]:
    """Get conversation history from memory DB."""
    return get_memory().get_conversations(limit=limit)


def delete_conversation(conv_id: int):
    """Delete a single conversation entry."""
    get_memory().delete_conversation(conv_id)


def clear_conversations():
    """Delete all conversation history."""
    get_memory().clear_conversations()


def delete_target_profile(target: str) -> bool:
    """Delete a target profile and all associated data."""
    return get_memory().target_profiler.delete_target(target)


def get_conversation_history_for_agent(limit: int = 100) -> list[dict]:
    """Get conversations ordered oldest-first for feeding into agent context."""
    rows = get_memory().conn.execute("""
        SELECT role, content FROM conversations
        ORDER BY id ASC LIMIT ?
    """, (limit,)).fetchall()
    return [{"role": r["role"], "content": r["content"]} for r in rows]


def is_known_fp(finding: dict) -> bool:
    """Quick check: is this finding a known false positive?"""
    return get_memory().should_skip_finding(finding)


if __name__ == "__main__":
    # Quick self-test
    import sys
    print("SENTINEL Memory System v1.0 — self-test")
    mem = get_memory()
    summary = get_summary()
    print(f"  Total scans indexed: {summary['total_scans']}")
    print(f"  Total findings:      {summary['total_findings']}")
    print(f"  FP registry:         {summary['total_fp_filtered']} entries")
    print(f"  Vector docs:         {summary['vector_doc_count']}")
    print(f"  Target profiles:     {len(summary['targets'])}")
    print(f"  Skill contexts:      {len(summary['skill_registry'])}")
    mem.close()
    print("OK")