"""Durable storage for security events (the Security Events viewer's history).

The proxy writes a *capped live buffer* to Redis (``bulwark:recent_blocks:*`` and
``bulwark:recent_allowed:*``). A background sync (``events_sync.py``) drains that
buffer into the ``security_events`` table defined here, giving the admin a real,
queryable history that:

* survives Redis flushes / restarts (durable disk-backed store),
* is not bounded by the Redis per-tenant cap,
* supports SQL filtering, pagination and aggregate summaries,
* has age-based retention (enforced by the sync task).

All SQL is written in the SQLite dialect with ``?`` placeholders; the shared
``DatabaseEngine`` translator converts it for PostgreSQL (``?``→``$n``,
``INSERT OR IGNORE``→``ON CONFLICT DO NOTHING``, ISO strings→``TIMESTAMPTZ``).
"""

from __future__ import annotations

import json
import logging
import time
from typing import Optional

from .database import get_database

logger = logging.getLogger(__name__)


# Ordered column list for inserts (``id`` is auto-generated, so excluded).
_INSERT_COLUMNS = (
    "event_id", "ts", "occurred_at", "tenant", "agent", "verdict", "category",
    "severity", "description", "source", "pattern", "request_id", "tool_name",
    "snippet", "input_hash", "metadata", "incident_id", "scope_digests", "created_at",
)

_INSERT_SQL = (
    "INSERT OR IGNORE INTO security_events ("  # noqa: S608 — fixed column list, values bound
    + ", ".join(_INSERT_COLUMNS)
    + ") VALUES ("
    + ", ".join(["?"] * len(_INSERT_COLUMNS))
    + ")"
)

# How the viewer's ``verdict`` feed selector maps to stored verdict values. The
# default feed (None/"") is the security feed: BLOCK + WARN.
_SECURITY_VERDICTS = ("block", "warn")


def _verdict_condition(verdict: Optional[str]) -> tuple[str, list]:
    """Translate the route-level verdict token into a SQL WHERE fragment.

    ``allowed`` → allow feed; ``blocked``/``warned`` → single verdict; anything
    else (None/"") → the security feed (block + warn). Raw verdict values
    (``allow``/``block``/``warn``) are also accepted for direct queries.
    """
    v = (verdict or "").strip().lower()
    if v in ("allowed", "allow"):
        return "verdict = ?", ["allow"]
    if v in ("blocked", "block"):
        return "verdict = ?", ["block"]
    if v in ("warned", "warn"):
        return "verdict = ?", ["warn"]
    # Default: security feed.
    return "verdict IN (?, ?)", list(_SECURITY_VERDICTS)


# Human-readable columns free-text search terms are matched against (OR per term).
_FREE_TEXT_COLUMNS = (
    "tenant", "agent", "verdict", "category", "severity", "description",
    "source", "pattern", "request_id", "tool_name", "snippet", "incident_id",
)


def _like_condition(column: str, value: str) -> tuple[str, str]:
    """Return a case-insensitive substring ``LIKE`` fragment + its bound param.

    ``column`` is always a fixed literal chosen from the code (never user input);
    the searched value is bound. ``LOWER()`` on both sides makes the match
    case-insensitive on PostgreSQL too (SQLite's default ``LIKE`` already is).
    """
    return f"LOWER({column}) LIKE ?", f"%{value.lower()}%"


def _build_filters(
    tenant: Optional[str],
    category: Optional[str],
    severity: Optional[str],
    verdict: Optional[str],
    since: Optional[float] = None,
    until: Optional[float] = None,
    *,
    agent: Optional[str] = None,
    request_id: Optional[str] = None,
    incident_id: Optional[str] = None,
    source: Optional[str] = None,
    pattern: Optional[str] = None,
    tool_name: Optional[str] = None,
    terms: Optional[list[str]] = None,
) -> tuple[str, list]:
    """Build a WHERE clause (without the ``WHERE`` keyword) + bound params.

    ``since``/``until`` bound the event ``ts`` (unix epoch seconds) to a
    half-open ``[since, until)`` window. Both are optional; either may be given
    alone. The ``(tenant, ts DESC)`` / ``ts DESC`` indexes back these range
    scans, so time-window queries stay cheap even over the full retained history.

    The keyword-only ``agent``/``request_id``/``incident_id``/``source``/
    ``pattern``/``tool_name`` filters and free-text ``terms`` back the viewer's
    Splunk-lite search bar (see :mod:`admin.services.event_query`). Scoped fields
    match a case-insensitive substring; each free-text term must match *some*
    human-readable column (OR across columns), and all terms must match (AND).
    """
    conditions: list[str] = []
    params: list = []

    vcond, vparams = _verdict_condition(verdict)
    conditions.append(vcond)
    params.extend(vparams)

    if tenant:
        conditions.append("tenant = ?")
        params.append(tenant)
    if category:
        conditions.append("category = ?")
        params.append(category)
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if since is not None:
        conditions.append("ts >= ?")
        params.append(float(since))
    if until is not None:
        conditions.append("ts < ?")
        params.append(float(until))

    # Scoped substring filters from the search bar (field:value tokens).
    for column, value in (
        ("agent", agent),
        ("request_id", request_id),
        ("incident_id", incident_id),
        ("source", source),
        ("pattern", pattern),
        ("tool_name", tool_name),
    ):
        if value:
            cond, bound = _like_condition(column, value)
            conditions.append(cond)
            params.append(bound)

    # Free-text terms: each term must hit at least one readable column.
    for term in terms or []:
        term = (term or "").strip()
        if not term:
            continue
        ors: list[str] = []
        for column in _FREE_TEXT_COLUMNS:
            cond, bound = _like_condition(column, term)
            ors.append(cond)
            params.append(bound)
        conditions.append("(" + " OR ".join(ors) + ")")

    return " AND ".join(conditions), params


def _row_to_event(row) -> dict:
    """Convert a DB row into the dict shape the events API returns.

    Kept wire-compatible with the historical Redis-backed payload so the
    frontend (events.html) needs no changes: ``ts``/``tenant``/``agent``/
    ``verdict``/``category``/``severity``/``description``/``source``/``pattern``/
    ``request_id``/``tool_name``/``snippet``/``input_hash``/``metadata``. Adds the
    UNIQUE ``event_id`` (additive) so the viewer can use a row-unique render key.
    """
    d = row.to_dict() if hasattr(row, "to_dict") else dict(row)
    meta = d.get("metadata")
    if isinstance(meta, str):
        try:
            meta = json.loads(meta) if meta else {}
        except (json.JSONDecodeError, TypeError):
            meta = {}
    elif meta is None:
        meta = {}
    return {
        # Stable UNIQUE identity (dedup key). Exposed so the viewer's x-for can key
        # on it: a single proxy request emits several events sharing one request_id,
        # so request_id is NOT row-unique and cannot be a render key.
        "event_id": d.get("event_id") or "",
        "ts": d.get("ts"),
        "tenant": d.get("tenant"),
        "agent": d.get("agent") or "",
        "verdict": d.get("verdict"),
        "category": d.get("category"),
        "severity": d.get("severity"),
        "description": d.get("description") or "",
        "source": d.get("source") or "",
        "pattern": d.get("pattern") or "",
        "request_id": d.get("request_id") or "",
        "tool_name": d.get("tool_name") or "",
        "snippet": d.get("snippet") or "",
        "input_hash": d.get("input_hash") or "",
        "metadata": meta,
        "incident_id": d.get("incident_id") or "",
        "scope_digests": (d.get("scope_digests") or "").split(),
    }


class SecurityEventsStore:
    """Async CRUD + analytics over the ``security_events`` table.

    Uses the shared ``DatabaseEngine`` singleton (SQLite or PostgreSQL), so a
    single implementation serves both backends via query translation.
    """

    def _db(self):
        return get_database()

    async def bulk_insert(self, events: list[dict]) -> int:
        """Idempotently insert normalised event dicts. Returns rows inserted.

        Each event must carry a stable ``event_id`` (see ``events_sync``); the
        UNIQUE constraint + ``INSERT OR IGNORE`` makes re-syncing the same Redis
        entry a no-op, so the sync can run every few seconds without duplicating.
        """
        if not events:
            return 0
        db = self._db()
        inserted = 0
        now_iso = _iso_now()
        for e in events:
            try:
                ts_val = e.get("ts")
                params = [
                    e["event_id"],
                    float(ts_val) if ts_val is not None else time.time(),
                    e.get("occurred_at") or _iso_from_ts(e.get("ts")),
                    e.get("tenant") or "unknown",
                    e.get("agent") or "",
                    (e.get("verdict") or "block"),
                    e.get("category") or "",
                    e.get("severity") or "",
                    e.get("description") or "",
                    e.get("source") or "",
                    e.get("pattern") or "",
                    e.get("request_id") or "",
                    e.get("tool_name") or "",
                    e.get("snippet") or "",
                    e.get("input_hash") or "",
                    _dump_metadata(e.get("metadata")),
                    e.get("incident_id") or "",
                    _normalise_scope_digests(e.get("scope_digests")),
                    now_iso,
                ]
                affected = await db.execute(_INSERT_SQL, params)
                inserted += affected or 0
            except Exception as exc:  # never let one bad row abort the batch
                logger.warning("security_event insert failed: %s", exc)
        return inserted

    async def query(
        self,
        *,
        tenant: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        verdict: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        agent: Optional[str] = None,
        request_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        source: Optional[str] = None,
        pattern: Optional[str] = None,
        tool_name: Optional[str] = None,
        terms: Optional[list[str]] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        """Return events (newest first) matching the filters.

        ``since``/``until`` restrict results to the half-open ``[since, until)``
        time window (unix epoch seconds), enabling correlation lookups over a
        recent slice of history without scanning everything. The remaining
        keyword filters + ``terms`` back the viewer's search bar (see
        :func:`admin.services.event_query.parse_event_query`).
        """
        where, params = _build_filters(
            tenant, category, severity, verdict, since, until,
            agent=agent, request_id=request_id, incident_id=incident_id,
            source=source, pattern=pattern, tool_name=tool_name, terms=terms,
        )
        # SQLi-safe (S608): `where` is composed only of fixed "col = ?" / "col IN
        # (?, ?)" fragments built above; every value is a bound param.
        sql = (
            f"SELECT * FROM security_events WHERE {where} "  # noqa: S608
            "ORDER BY ts DESC LIMIT ? OFFSET ?"
        )
        params = [*params, int(limit), int(offset)]
        rows = await self._db().fetch_all(sql, params)
        return [_row_to_event(r) for r in rows]

    async def count(
        self,
        *,
        tenant: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        verdict: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
    ) -> int:
        where, params = _build_filters(tenant, category, severity, verdict, since, until)
        sql = f"SELECT COUNT(*) AS n FROM security_events WHERE {where}"  # noqa: S608 — bound params only
        row = await self._db().fetch_one(sql, params)
        return int(row.get("n", 0)) if row else 0

    async def summary(self) -> dict:
        """Aggregate the security feed (block+warn) over the *full* retained
        history — not just the last N Redis entries — plus an allowed-count.
        """
        db = self._db()
        sec_where = "verdict IN (?, ?)"
        sec_params = list(_SECURITY_VERDICTS)

        async def _group(col: str) -> dict:
            # `col` is a hardcoded literal ("tenant"/"category"/"severity") passed
            # by summary() below — never user input; verdict values are bound.
            sql = (
                f"SELECT {col} AS k, COUNT(*) AS n FROM security_events "  # noqa: S608
                f"WHERE {sec_where} GROUP BY {col}"
            )
            out: dict = {}
            for r in await db.fetch_all(sql, sec_params):
                key = r.get("k") or "unknown"
                out[key] = int(r.get("n", 0))
            return out

        by_tenant = await _group("tenant")
        by_category = await _group("category")
        by_severity = await _group("severity")
        total = sum(by_tenant.values())

        allowed_row = await db.fetch_one(
            "SELECT COUNT(*) AS n FROM security_events WHERE verdict = ?", ["allow"]
        )
        allowed_recorded = int(allowed_row.get("n", 0)) if allowed_row else 0

        return {
            "by_tenant": by_tenant,
            "by_category": by_category,
            "by_severity": by_severity,
            "total": total,
            "allowed_recorded": allowed_recorded,
        }

    async def prune(self, retention_days: int) -> int:
        """Delete events older than ``retention_days``. 0/negative = keep all."""
        if not retention_days or retention_days <= 0:
            return 0
        cutoff = time.time() - (retention_days * 86400)
        affected = await self._db().execute(
            "DELETE FROM security_events WHERE ts < ?", [cutoff]
        )
        return affected or 0

    async def find_by_subject(self, subject_id: str, limit: int = 10000) -> list[dict]:
        """Return events referencing a data subject (for GDPR export)."""
        if not subject_id:
            return []
        like = f"%{subject_id}%"
        sql = (
            "SELECT * FROM security_events WHERE "
            "tenant = ? OR request_id LIKE ? OR snippet LIKE ? "
            "OR metadata LIKE ? OR input_hash LIKE ? "
            "ORDER BY ts DESC LIMIT ?"
        )
        rows = await self._db().fetch_all(
            sql, [subject_id, like, like, like, like, int(limit)]
        )
        return [_row_to_event(r) for r in rows]

    async def erase_subject(self, subject_id: str) -> int:
        """Delete events referencing a data subject (for GDPR erasure)."""
        if not subject_id:
            return 0
        like = f"%{subject_id}%"
        affected = await self._db().execute(
            "DELETE FROM security_events WHERE "
            "tenant = ? OR request_id LIKE ? OR snippet LIKE ? "
            "OR metadata LIKE ? OR input_hash LIKE ?",
            [subject_id, like, like, like, like],
        )
        return affected or 0

    # --- Investigation Center pivots ---------------------------------------

    async def list_correlation_alerts(
        self,
        *,
        tenant: Optional[str] = None,
        verdict: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        """Return correlation-engine alerts (newest first) for the SOC queue.

        The Investigation Center queue is the subset of the durable feed emitted by
        the inline correlation engine — confirmed input↔output exfiltration
        incidents and adaptive origin-risk enforcement decisions — identified by
        ``source = 'correlation_engine'``. Optional ``verdict``/``tenant``/time
        filters narrow the queue; results are backed by the ``ts DESC`` index.
        """
        conditions = ["source = ?"]
        params: list = ["correlation_engine"]
        v = (verdict or "").strip().lower()
        if v in ("blocked", "block"):
            conditions.append("verdict = ?")
            params.append("block")
        elif v in ("warned", "warn"):
            conditions.append("verdict = ?")
            params.append("warn")
        if tenant:
            conditions.append("tenant = ?")
            params.append(tenant)
        if since is not None:
            conditions.append("ts >= ?")
            params.append(float(since))
        if until is not None:
            conditions.append("ts < ?")
            params.append(float(until))
        where = " AND ".join(conditions)
        sql = (
            f"SELECT * FROM security_events WHERE {where} "  # noqa: S608 — bound params only
            "ORDER BY ts DESC LIMIT ? OFFSET ?"
        )
        rows = await self._db().fetch_all(sql, [*params, int(limit), int(offset)])
        return [_row_to_event(r) for r in rows]

    async def find_by_incident(self, incident_id: str) -> list[dict]:
        """Return every event tagged with ``incident_id`` (oldest first).

        These are the correlation-engine event(s) carrying the incident. Their
        ``metadata.contributing_event_ids`` point at the input/output detections
        that produced the incident — fetch those with :meth:`find_by_event_ids`.
        """
        if not incident_id:
            return []
        rows = await self._db().fetch_all(
            "SELECT * FROM security_events WHERE incident_id = ? ORDER BY ts ASC",
            [incident_id],
        )
        return [_row_to_event(r) for r in rows]

    async def find_by_event_ids(self, event_ids: list[str]) -> list[dict]:
        """Return events whose ``event_id`` is in ``event_ids`` (oldest first).

        Used to resolve an incident's ``contributing_event_ids`` into the actual
        input/output detections. Bounded to a sane batch to keep the ``IN`` list
        small; ``event_id`` is UNIQUE (implicitly indexed) so lookups are cheap.
        """
        ids = [e for e in (event_ids or []) if e][:500]
        if not ids:
            return []
        placeholders = ", ".join(["?"] * len(ids))
        sql = (
            f"SELECT * FROM security_events WHERE event_id IN ({placeholders}) "  # noqa: S608 — placeholders only
            "ORDER BY ts ASC"
        )
        rows = await self._db().fetch_all(sql, ids)
        return [_row_to_event(r) for r in rows]

    async def find_by_scope_digest(
        self,
        scope_token: str,
        *,
        since: Optional[float] = None,
        until: Optional[float] = None,
        limit: int = 200,
    ) -> list[dict]:
        """Return events an origin contributed to, newest first (origin timeline).

        ``scope_token`` is a ``"scope_type:digest"`` token as shown by the admin
        ``/correlation/origins`` view. Events are stamped with a space-delimited,
        space-padded ``scope_digests`` string, so a whole-token ``LIKE`` match
        (``'% token %'``) pivots an origin's decayed risk score back to the exact
        blocked/flagged requests that drove it — the durable ledger that lets the
        Investigation Center reconstruct *why* the score rose, with no extra Redis.
        """
        token = (scope_token or "").strip()
        if not token:
            return []
        conditions = ["scope_digests LIKE ?"]
        params: list = [f"% {token} %"]
        if since is not None:
            conditions.append("ts >= ?")
            params.append(float(since))
        if until is not None:
            conditions.append("ts < ?")
            params.append(float(until))
        where = " AND ".join(conditions)
        sql = (
            f"SELECT * FROM security_events WHERE {where} "  # noqa: S608 — bound params only
            "ORDER BY ts DESC LIMIT ?"
        )
        rows = await self._db().fetch_all(sql, [*params, int(limit)])
        return [_row_to_event(r) for r in rows]


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _iso_from_ts(ts) -> str:
    from datetime import datetime, timezone
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return _iso_now()


def _dump_metadata(meta) -> str:
    if not meta:
        return "{}"
    if isinstance(meta, str):
        return meta
    try:
        return json.dumps(meta)
    except (TypeError, ValueError):
        return "{}"


def _normalise_scope_digests(digests) -> str:
    """Flatten origin scope digests into a space-delimited, LIKE-pivotable string.

    Accepts a list of ``"scope_type:digest"`` tokens (as stamped by the proxy) or
    an already-joined string. Stored space-delimited and space-padded so a pivot
    can match a whole token with ``scope_digests LIKE '% session:abcd… %'`` without
    partial-token collisions. Empty/malformed input yields ``""``.
    """
    if not digests:
        return ""
    if isinstance(digests, str):
        tokens = digests.split()
    elif isinstance(digests, (list, tuple)):
        tokens = [str(t).strip() for t in digests if str(t).strip()]
    else:
        return ""
    if not tokens:
        return ""
    # Leading/trailing space so every token is delimited on both sides.
    return " " + " ".join(tokens) + " "


_store: Optional[SecurityEventsStore] = None


def get_security_events_store() -> SecurityEventsStore:
    """Return the process-wide store singleton."""
    global _store
    if _store is None:
        _store = SecurityEventsStore()
    return _store
