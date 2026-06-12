"""
Enrichment Pipeline — Admin API routes.

Provides visibility into the async enrichment pipeline:
- Stats (total entries, evasions, regex candidates)
- Evasion feed (recent detected evasions)
- Regex candidate review (approve/reject)
- Recent entries browsing
"""

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

router = APIRouter()

# Replay DB path — shared volume between proxy and admin
# In docker-compose: shared_data volume at /app/shared/enrichment
# In K8s: siem-stats PVC or dedicated enrichment PVC
_REPLAY_DB_PATH = Path(
    os.environ.get("SENTINEL_REPLAY_DB_PATH", "/app/shared/enrichment/attack_replay.db")
)

# Thread-safe read-only connection
_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None


def _get_conn() -> Optional[sqlite3.Connection]:
    """Get or create a read-only DB connection."""
    global _conn
    if _conn is not None:
        return _conn

    if not _REPLAY_DB_PATH.exists():
        return None

    try:
        # Open in read-only mode (WAL allows concurrent reads)
        uri = f"file:{_REPLAY_DB_PATH}?mode=ro"
        _conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        return _conn
    except Exception:
        return None


def _query(sql: str, params: tuple = ()) -> list[dict]:
    """Execute a read-only query and return results as dicts."""
    with _lock:
        conn = _get_conn()
        if conn is None:
            return []
        try:
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []


def _query_one(sql: str, params: tuple = ()) -> Optional[dict]:
    """Execute a query and return a single result."""
    with _lock:
        conn = _get_conn()
        if conn is None:
            return None
        try:
            row = conn.execute(sql, params).fetchone()
            return dict(row) if row else None
        except Exception:
            return None


# --- Models ---

class RegexReviewRequest(BaseModel):
    candidate_id: str
    action: str  # "approve" or "reject"


# --- Endpoints ---

@router.get("/status")
async def enrichment_status():
    """Get enrichment pipeline status and configuration."""
    db_exists = _REPLAY_DB_PATH.exists()
    enabled = os.environ.get("SENTINEL_ENRICHMENT_ENABLED", "false").lower() == "true"

    result = {
        "enabled": enabled,
        "db_exists": db_exists,
        "db_path": str(_REPLAY_DB_PATH),
        "scanners": [
            {
                "name": "embedding_scanner",
                "description": "Semantic similarity against known attack embeddings",
                "model": os.environ.get("SENTINEL_EMBED_MODEL", "all-MiniLM-L6-v2"),
                "thresholds": {
                    "suspicious": float(os.environ.get("SENTINEL_EMBED_THRESH_SUSPICIOUS", "0.78")),
                    "threat": float(os.environ.get("SENTINEL_EMBED_THRESH_THREAT", "0.88")),
                },
            },
            {
                "name": "skill_enrichment_scanner",
                "description": "Background SkillSpector analysis on tool definitions",
                "enabled": os.environ.get("SENTINEL_SKILL_ENRICHMENT_ENABLED", "false").lower() == "true",
            },
        ],
    }

    if db_exists:
        stats = _query_one("SELECT COUNT(*) as cnt FROM replay_entries")
        result["total_entries"] = stats["cnt"] if stats else 0
    else:
        result["total_entries"] = 0

    return result


@router.get("/stats")
async def enrichment_stats():
    """Get replay DB statistics."""
    if not _REPLAY_DB_PATH.exists():
        return {
            "total_entries": 0,
            "evasions_detected": 0,
            "evasion_rate": 0.0,
            "pending_regex_candidates": 0,
            "approved_regex_candidates": 0,
            "rejected_regex_candidates": 0,
            "evasion_categories": {},
            "verdict_breakdown": {},
        }

    total = _query_one("SELECT COUNT(*) as cnt FROM replay_entries")
    evasions = _query_one("SELECT COUNT(*) as cnt FROM replay_entries WHERE is_evasion = 1")
    pending = _query_one("SELECT COUNT(*) as cnt FROM regex_candidates WHERE status = 'pending'")
    approved = _query_one("SELECT COUNT(*) as cnt FROM regex_candidates WHERE status = 'approved'")
    rejected = _query_one("SELECT COUNT(*) as cnt FROM regex_candidates WHERE status = 'rejected'")

    total_count = total["cnt"] if total else 0
    evasion_count = evasions["cnt"] if evasions else 0

    # Category breakdown
    categories = _query(
        "SELECT category, COUNT(*) as cnt FROM replay_entries WHERE is_evasion = 1 GROUP BY category"
    )
    cat_map = {r["category"] or "unknown": r["cnt"] for r in categories}

    # Verdict breakdown
    verdicts = _query("SELECT verdict, COUNT(*) as cnt FROM replay_entries GROUP BY verdict")
    verdict_map = {r["verdict"]: r["cnt"] for r in verdicts}

    return {
        "total_entries": total_count,
        "evasions_detected": evasion_count,
        "evasion_rate": round(evasion_count / max(total_count, 1) * 100, 2),
        "pending_regex_candidates": pending["cnt"] if pending else 0,
        "approved_regex_candidates": approved["cnt"] if approved else 0,
        "rejected_regex_candidates": rejected["cnt"] if rejected else 0,
        "evasion_categories": cat_map,
        "verdict_breakdown": verdict_map,
    }


@router.get("/evasions")
async def get_evasions(limit: int = 50, offset: int = 0):
    """Get detected evasion attempts (payloads that bypassed regex but ML flagged)."""
    entries = _query(
        "SELECT * FROM replay_entries WHERE is_evasion = 1 ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (min(limit, 200), offset),
    )
    total = _query_one("SELECT COUNT(*) as cnt FROM replay_entries WHERE is_evasion = 1")
    return {
        "entries": entries,
        "total": total["cnt"] if total else 0,
        "limit": limit,
        "offset": offset,
    }


@router.get("/entries")
async def get_entries(
    limit: int = 50,
    offset: int = 0,
    verdict: Optional[str] = None,
    category: Optional[str] = None,
):
    """Browse recent enrichment entries."""
    query = "SELECT * FROM replay_entries WHERE 1=1"
    count_query = "SELECT COUNT(*) as cnt FROM replay_entries WHERE 1=1"
    params: list = []

    if verdict:
        query += " AND verdict = ?"
        count_query += " AND verdict = ?"
        params.append(verdict)
    if category:
        query += " AND category = ?"
        count_query += " AND category = ?"
        params.append(category)

    count_params = tuple(params)
    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([min(limit, 200), offset])

    entries = _query(query, tuple(params))
    total = _query_one(count_query, count_params)
    return {
        "entries": entries,
        "total": total["cnt"] if total else 0,
        "limit": limit,
        "offset": offset,
    }


@router.get("/regex-candidates")
async def get_regex_candidates(status: str = "pending"):
    """Get regex candidates by status (pending, approved, rejected)."""
    if status not in ("pending", "approved", "rejected", "deployed"):
        raise HTTPException(400, "Invalid status. Use: pending, approved, rejected, deployed")

    candidates = _query(
        "SELECT * FROM regex_candidates WHERE status = ? ORDER BY confidence DESC",
        (status,),
    )
    # Parse source_entries JSON
    for c in candidates:
        if isinstance(c.get("source_entries"), str):
            try:
                c["source_entries"] = json.loads(c["source_entries"])
            except Exception:
                c["source_entries"] = []
    return {"candidates": candidates, "status": status}


@router.post("/regex-candidates/review")
async def review_regex_candidate(request: Request, body: RegexReviewRequest):
    """Approve or reject a regex candidate."""
    if body.action not in ("approve", "reject"):
        raise HTTPException(400, "Action must be 'approve' or 'reject'")

    if not _REPLAY_DB_PATH.exists():
        raise HTTPException(404, "Replay DB not found")

    # Need write access for review operations
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    reviewer = "admin"  # TODO: extract from session

    # Open a writable connection for this operation
    try:
        conn = sqlite3.connect(str(_REPLAY_DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row

        row = conn.execute(
            "SELECT pattern FROM regex_candidates WHERE id = ?", (body.candidate_id,)
        ).fetchone()
        if not row:
            conn.close()
            raise HTTPException(404, f"Candidate {body.candidate_id} not found")

        new_status = "approved" if body.action == "approve" else "rejected"
        conn.execute(
            "UPDATE regex_candidates SET status = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ?",
            (new_status, now, reviewer, body.candidate_id),
        )
        conn.commit()
        conn.close()

        return {
            "message": f"Candidate {body.candidate_id} {new_status}",
            "pattern": row["pattern"] if body.action == "approve" else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Review failed: {str(e)}")
