"""
AttackReplayDB — Persistent store for attack payloads and auto-pattern generation.

Stores both blocked and allowed payloads. When the EmbeddingScanner flags an
ALLOWED payload as suspicious/threat, it records it as a potential evasion and
auto-generates regex candidates for human review.

Key capabilities:
- Store all payloads with verdict + enrichment results
- Track evasion attempts (allowed but flagged by embeddings)
- Auto-generate regex candidates from flagged payloads
- Feed new patterns back to InputGuardrail (pending review)
- Provide replay capability for regression testing
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .base import EnrichmentResult, EnrichmentStatus

logger = logging.getLogger(__name__)

REPLAY_DB_PATH = Path(os.getenv("SENTINEL_REPLAY_DB_PATH", "data/attack_replay.db"))
MAX_PAYLOAD_SIZE = 4096  # Store only first N chars of payload (privacy)


@dataclass
class ReplayEntry:
    """A recorded payload with verdict and enrichment metadata."""

    id: str
    payload_hash: str  # SHA-256 of full payload
    payload_prefix: str  # First N chars for pattern generation
    verdict: str  # ALLOW, BLOCK, WARN, REDACT
    source: str  # input_guardrail, output_filter, tool_policy
    category: Optional[str] = None
    enrichment_status: Optional[str] = None  # clean, suspicious, threat
    enrichment_confidence: float = 0.0
    enrichment_scanner: Optional[str] = None
    is_evasion: bool = False  # True if verdict=ALLOW but enrichment=threat/suspicious
    regex_candidate: Optional[str] = None
    reviewed: bool = False
    request_id: Optional[str] = None
    tenant_id: Optional[str] = None
    timestamp: str = ""


@dataclass
class RegexCandidate:
    """A proposed regex pattern generated from evasion analysis."""

    id: str
    pattern: str
    category: str
    source_entries: list[str] = field(default_factory=list)  # ReplayEntry IDs
    confidence: float = 0.0
    false_positive_risk: str = "unknown"  # low, medium, high
    status: str = "pending"  # pending, approved, rejected, deployed
    created_at: str = ""
    reviewed_at: Optional[str] = None
    reviewed_by: Optional[str] = None


class AttackReplayDB:
    """
    SQLite-backed store for attack replay and pattern generation.

    Thread-safe, designed for async enrichment pipeline usage.
    """

    def __init__(self, db_path: Path = REPLAY_DB_PATH):
        self._db_path = db_path
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self._initialize()

    def _initialize(self) -> None:
        """Create DB and tables if needed."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")

        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS replay_entries (
                id TEXT PRIMARY KEY,
                payload_hash TEXT NOT NULL,
                payload_prefix TEXT NOT NULL,
                verdict TEXT NOT NULL,
                source TEXT NOT NULL,
                category TEXT,
                enrichment_status TEXT,
                enrichment_confidence REAL DEFAULT 0.0,
                enrichment_scanner TEXT,
                is_evasion INTEGER DEFAULT 0,
                regex_candidate TEXT,
                reviewed INTEGER DEFAULT 0,
                request_id TEXT,
                tenant_id TEXT,
                timestamp TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_replay_evasion ON replay_entries(is_evasion);
            CREATE INDEX IF NOT EXISTS idx_replay_verdict ON replay_entries(verdict);
            CREATE INDEX IF NOT EXISTS idx_replay_category ON replay_entries(category);
            CREATE INDEX IF NOT EXISTS idx_replay_hash ON replay_entries(payload_hash);
            CREATE INDEX IF NOT EXISTS idx_replay_timestamp ON replay_entries(timestamp);

            CREATE TABLE IF NOT EXISTS regex_candidates (
                id TEXT PRIMARY KEY,
                pattern TEXT NOT NULL,
                category TEXT NOT NULL,
                source_entries TEXT NOT NULL DEFAULT '[]',
                confidence REAL DEFAULT 0.0,
                false_positive_risk TEXT DEFAULT 'unknown',
                status TEXT DEFAULT 'pending',
                created_at TEXT NOT NULL,
                reviewed_at TEXT,
                reviewed_by TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_regex_status ON regex_candidates(status);
        """)
        self._conn.commit()
        logger.info("AttackReplayDB initialized", extra={"path": str(self._db_path)})

    def record(
        self,
        payload: str,
        verdict: str,
        source: str,
        request_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        category: Optional[str] = None,
        enrichment_results: Optional[list[EnrichmentResult]] = None,
    ) -> ReplayEntry:
        """Record a payload with its verdict and enrichment results."""
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()
        payload_prefix = payload[:MAX_PAYLOAD_SIZE]
        entry_id = f"re-{payload_hash[:12]}-{int(time.time() * 1000) % 1000000}"
        now = datetime.now(timezone.utc).isoformat()

        # Determine enrichment status (use highest-severity result)
        enrichment_status = None
        enrichment_confidence = 0.0
        enrichment_scanner = None
        is_evasion = False

        if enrichment_results:
            for er in enrichment_results:
                if er.status in (EnrichmentStatus.THREAT, EnrichmentStatus.SUSPICIOUS):
                    if er.confidence > enrichment_confidence:
                        enrichment_status = er.status.value
                        enrichment_confidence = er.confidence
                        enrichment_scanner = er.scanner
                        if not category and er.category:
                            category = er.category

            # Mark as evasion if verdict was ALLOW but enrichment says threat/suspicious
            if verdict == "ALLOW" and enrichment_status in ("threat", "suspicious"):
                is_evasion = True

        entry = ReplayEntry(
            id=entry_id,
            payload_hash=payload_hash,
            payload_prefix=payload_prefix,
            verdict=verdict,
            source=source,
            category=category,
            enrichment_status=enrichment_status,
            enrichment_confidence=enrichment_confidence,
            enrichment_scanner=enrichment_scanner,
            is_evasion=is_evasion,
            request_id=request_id,
            tenant_id=tenant_id,
            timestamp=now,
        )

        with self._lock:
            self._conn.execute(
                """INSERT OR IGNORE INTO replay_entries
                   (id, payload_hash, payload_prefix, verdict, source, category,
                    enrichment_status, enrichment_confidence, enrichment_scanner,
                    is_evasion, regex_candidate, reviewed, request_id, tenant_id, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    entry.id, entry.payload_hash, entry.payload_prefix,
                    entry.verdict, entry.source, entry.category,
                    entry.enrichment_status, entry.enrichment_confidence,
                    entry.enrichment_scanner, int(entry.is_evasion),
                    entry.regex_candidate, int(entry.reviewed),
                    entry.request_id, entry.tenant_id, entry.timestamp,
                ),
            )
            self._conn.commit()

        # If evasion detected, attempt auto-regex generation
        if is_evasion:
            self._handle_evasion(entry)

        return entry

    def _handle_evasion(self, entry: ReplayEntry) -> None:
        """Handle a detected evasion — generate regex candidate."""
        logger.warning(
            "evasion_detected",
            extra={
                "entry_id": entry.id,
                "category": entry.category,
                "confidence": entry.enrichment_confidence,
                "payload_hash": entry.payload_hash,
            },
        )

        # Generate regex candidate from the payload
        regex = self._generate_regex_candidate(entry.payload_prefix, entry.category)
        if regex:
            self._store_regex_candidate(regex, entry)

    def _generate_regex_candidate(self, payload: str, category: Optional[str]) -> Optional[str]:
        """
        Generate a regex pattern from a payload.

        Strategy:
        - Extract key phrases/tokens that indicate malicious intent
        - Create a flexible pattern that matches variations
        - Prefer broad-but-specific patterns over exact matches
        """
        payload_lower = payload.lower().strip()

        # Common evasion patterns to extract
        patterns_by_category = {
            "prompt_injection": [
                # Look for instruction override patterns
                r"(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|above|prior|earlier)\s+(?:instructions?|rules?|guidelines?|constraints?)",
                r"(?:new|updated|revised)\s+(?:instructions?|rules?|system\s+prompt)",
                r"(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|from\s+now\s+on)",
            ],
            "data_exfiltration": [
                r"(?:exfiltrate|extract|steal|copy|dump|leak)\s+(?:the\s+)?(?:data|secrets?|credentials?|keys?|tokens?|passwords?)",
                r"(?:send|post|upload|transfer)\s+(?:to|via)\s+(?:external|my|attacker)",
            ],
            "command_injection": [
                r"(?:execute|run|spawn|invoke)\s+(?:a\s+)?(?:command|shell|process|script)",
                r"(?:reverse\s+shell|bind\s+shell|web\s+shell)",
            ],
            "ssrf": [
                r"(?:169\.254\.169\.254|metadata\.google\.internal|kubernetes\.default)",
                r"(?:fetch|request|access|connect)\s+(?:to\s+)?(?:internal|localhost|127\.0\.0\.1)",
            ],
        }

        # Try category-specific patterns first
        if category and category in patterns_by_category:
            for pattern in patterns_by_category[category]:
                if re.search(pattern, payload_lower, re.IGNORECASE):
                    return pattern

        # Generic: extract the most distinctive 3-5 word phrase
        # This is a heuristic — human review is required
        words = re.findall(r'[a-z]{3,}', payload_lower)
        if len(words) >= 3:
            # Find suspicious word combinations
            suspicious_words = {
                "ignore", "bypass", "override", "disable", "hack", "exploit",
                "inject", "exfiltrate", "steal", "dump", "shell", "execute",
                "admin", "root", "sudo", "privilege", "escalat",
            }
            key_words = [w for w in words if w in suspicious_words or any(s in w for s in suspicious_words)]
            if key_words:
                # Build a simple regex from context around suspicious words
                pattern_parts = []
                for kw in key_words[:3]:
                    idx = payload_lower.find(kw)
                    if idx >= 0:
                        context = payload_lower[max(0, idx - 10):idx + len(kw) + 10]
                        escaped = re.escape(context.strip())
                        pattern_parts.append(escaped)
                if pattern_parts:
                    return r"(?:" + "|".join(pattern_parts) + r")"

        return None

    def _store_regex_candidate(self, pattern: str, source_entry: ReplayEntry) -> None:
        """Store a regex candidate for review."""
        candidate_id = f"rc-{hashlib.sha256(pattern.encode()).hexdigest()[:12]}"
        now = datetime.now(timezone.utc).isoformat()

        # Validate the regex compiles
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error:
            logger.warning(f"Invalid regex candidate generated: {pattern}")
            return

        # Estimate FP risk based on pattern specificity
        fp_risk = "high" if len(pattern) < 20 else "medium" if len(pattern) < 50 else "low"

        with self._lock:
            # Check if this pattern already exists
            existing = self._conn.execute(
                "SELECT id, source_entries FROM regex_candidates WHERE pattern = ?",
                (pattern,),
            ).fetchone()

            if existing:
                # Update source entries
                entries = json.loads(existing["source_entries"])
                entries.append(source_entry.id)
                self._conn.execute(
                    "UPDATE regex_candidates SET source_entries = ?, confidence = confidence + 0.1 WHERE id = ?",
                    (json.dumps(entries), existing["id"]),
                )
            else:
                self._conn.execute(
                    """INSERT INTO regex_candidates
                       (id, pattern, category, source_entries, confidence, false_positive_risk, status, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)""",
                    (
                        candidate_id, pattern, source_entry.category or "unknown",
                        json.dumps([source_entry.id]),
                        source_entry.enrichment_confidence,
                        fp_risk, now,
                    ),
                )
            self._conn.commit()

        # Update the replay entry with the regex candidate
        with self._lock:
            self._conn.execute(
                "UPDATE replay_entries SET regex_candidate = ? WHERE id = ?",
                (pattern, source_entry.id),
            )
            self._conn.commit()

        logger.info(
            "regex_candidate_generated",
            extra={"pattern": pattern[:80], "category": source_entry.category, "fp_risk": fp_risk},
        )

    # ---- Query API ----

    def get_evasions(self, limit: int = 50, offset: int = 0) -> list[dict]:
        """Get detected evasion attempts."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM replay_entries WHERE is_evasion = 1 ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_regex_candidates(self, status: str = "pending") -> list[dict]:
        """Get regex candidates by status."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM regex_candidates WHERE status = ? ORDER BY confidence DESC",
                (status,),
            ).fetchall()
        return [dict(r) for r in rows]

    def approve_regex(self, candidate_id: str, reviewer: str) -> Optional[str]:
        """Approve a regex candidate. Returns the pattern for deployment."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            row = self._conn.execute(
                "SELECT pattern FROM regex_candidates WHERE id = ?", (candidate_id,)
            ).fetchone()
            if not row:
                return None
            self._conn.execute(
                "UPDATE regex_candidates SET status = 'approved', reviewed_at = ?, reviewed_by = ? WHERE id = ?",
                (now, reviewer, candidate_id),
            )
            self._conn.commit()
        return row["pattern"]

    def reject_regex(self, candidate_id: str, reviewer: str) -> bool:
        """Reject a regex candidate."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                "UPDATE regex_candidates SET status = 'rejected', reviewed_at = ?, reviewed_by = ? WHERE id = ?",
                (now, reviewer, candidate_id),
            )
            self._conn.commit()
        return True

    def get_stats(self) -> dict:
        """Get replay DB statistics."""
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) as cnt FROM replay_entries").fetchone()["cnt"]
            evasions = self._conn.execute("SELECT COUNT(*) as cnt FROM replay_entries WHERE is_evasion = 1").fetchone()["cnt"]
            pending_regex = self._conn.execute("SELECT COUNT(*) as cnt FROM regex_candidates WHERE status = 'pending'").fetchone()["cnt"]
            approved_regex = self._conn.execute("SELECT COUNT(*) as cnt FROM regex_candidates WHERE status = 'approved'").fetchone()["cnt"]

            # Category breakdown for evasions
            category_rows = self._conn.execute(
                "SELECT category, COUNT(*) as cnt FROM replay_entries WHERE is_evasion = 1 GROUP BY category"
            ).fetchall()
            categories = {r["category"] or "unknown": r["cnt"] for r in category_rows}

        return {
            "total_entries": total,
            "evasions_detected": evasions,
            "pending_regex_candidates": pending_regex,
            "approved_regex_candidates": approved_regex,
            "evasion_categories": categories,
        }

    def get_replay_payloads(self, category: Optional[str] = None, verdict: Optional[str] = None, limit: int = 100) -> list[dict]:
        """Get payloads for replay testing."""
        query = "SELECT * FROM replay_entries WHERE 1=1"
        params = []
        if category:
            query += " AND category = ?"
            params.append(category)
        if verdict:
            query += " AND verdict = ?"
            params.append(verdict)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()


# Singleton
_db: Optional[AttackReplayDB] = None


def get_attack_replay_db() -> AttackReplayDB:
    global _db
    if _db is None:
        _db = AttackReplayDB()
    return _db
