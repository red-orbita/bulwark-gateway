"""Analyst triage workflow for the Investigation Center.

The correlation engine (proxy) and the durable event store (``security_events``)
give an analyst the *evidence* for an alert; this store adds the human *workflow*
on top: acknowledge / assign / resolve an alert and attach investigation notes.
State is keyed by a stable *subject*:

* ``incident`` — a confirmed input↔output exfiltration incident, keyed by its
  ``incident_id`` (from correlation metadata), or
* ``origin``  — an at-risk origin, keyed by its ``"scope_type:digest"`` token (the
  same identifier the admin ``/correlation/origins`` view exposes).

Persisted in the ``investigation_triage`` table (migration v6) via the shared
``DatabaseEngine`` so it survives restarts and works on both SQLite and
PostgreSQL. Volume is low (one row per triaged alert, mutated by analyst actions),
so a read-then-write upsert is used rather than backend-specific ``ON CONFLICT``
UPSERT SQL — keeping the store dialect-neutral.

All state changes are additive and auditable: status/assignee transitions and
notes each stamp an actor + UTC timestamp, and notes are never overwritten
(append-only), so the row is itself an investigation trail.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from .database import get_database

logger = logging.getLogger(__name__)

# The two kinds of alert a triage record can hang off.
SUBJECT_TYPES = ("incident", "origin")

# Allowed workflow states. ``open`` is the implicit initial state; analysts may
# move freely between states (including reopening a resolved/dismissed alert),
# which SOC workflows routinely require — so transitions are validated only
# against this set, not a fixed state machine.
STATUSES = ("open", "acknowledged", "in_progress", "resolved", "dismissed")

# Bounds so a single record can never grow without limit (notes are analyst-authored
# free text; a runaway client must not be able to bloat a row unboundedly).
_MAX_NOTES = 500
_MAX_NOTE_LEN = 4000
_MAX_ASSIGNEE_LEN = 128


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_notes(raw) -> list[dict]:
    """Parse the stored notes JSON into a list (never raises)."""
    if not raw:
        return []
    if isinstance(raw, list):
        return raw
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def _row_to_triage(row) -> dict:
    """Convert a DB row into the triage dict the API returns."""
    d = row.to_dict() if hasattr(row, "to_dict") else dict(row)
    return {
        "subject_type": d.get("subject_type"),
        "subject_key": d.get("subject_key"),
        "tenant": d.get("tenant") or "",
        "status": d.get("status") or "open",
        "assignee": d.get("assignee") or "",
        "notes": _load_notes(d.get("notes")),
        "created_at": d.get("created_at"),
        "updated_at": d.get("updated_at"),
    }


class TriageStore:
    """Async CRUD over the ``investigation_triage`` table."""

    def _db(self):
        return get_database()

    @staticmethod
    def valid_subject_type(subject_type: str) -> bool:
        return subject_type in SUBJECT_TYPES

    @staticmethod
    def valid_status(status: str) -> bool:
        return status in STATUSES

    async def get(self, subject_type: str, subject_key: str) -> Optional[dict]:
        """Return the triage record for a subject, or ``None`` if untriaged."""
        if not subject_type or not subject_key:
            return None
        row = await self._db().fetch_one(
            "SELECT * FROM investigation_triage "
            "WHERE subject_type = ? AND subject_key = ?",
            [subject_type, subject_key],
        )
        return _row_to_triage(row) if row else None

    async def get_map(self, subjects: list[tuple[str, str]]) -> dict[tuple[str, str], dict]:
        """Batch-fetch triage records for annotating an alert queue.

        Returns a ``{(subject_type, subject_key): record}`` map for the subset that
        has been triaged. One query with a bounded ``IN`` list keeps the queue
        render to a single round-trip.
        """
        pairs = [(st, sk) for st, sk in (subjects or []) if st and sk][:500]
        if not pairs:
            return {}
        keys = [sk for _st, sk in pairs]
        placeholders = ", ".join(["?"] * len(keys))
        sql = (
            f"SELECT * FROM investigation_triage WHERE subject_key IN ({placeholders})"  # noqa: S608 — placeholders only
        )
        rows = await self._db().fetch_all(sql, keys)
        wanted = set(pairs)
        out: dict[tuple[str, str], dict] = {}
        for r in rows:
            rec = _row_to_triage(r)
            k = (rec["subject_type"], rec["subject_key"])
            if k in wanted:
                out[k] = rec
        return out

    async def list_records(
        self,
        *,
        status: Optional[str] = None,
        subject_type: Optional[str] = None,
        tenant: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """List triage records (most-recently-updated first) for the workqueue."""
        conditions: list[str] = []
        params: list = []
        if status:
            conditions.append("status = ?")
            params.append(status)
        if subject_type:
            conditions.append("subject_type = ?")
            params.append(subject_type)
        if tenant:
            conditions.append("tenant = ?")
            params.append(tenant)
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = (
            f"SELECT * FROM investigation_triage{where} "  # noqa: S608 — bound params only
            "ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        )
        rows = await self._db().fetch_all(sql, [*params, int(limit), int(offset)])
        return [_row_to_triage(r) for r in rows]

    async def _ensure_row(
        self, subject_type: str, subject_key: str, tenant: Optional[str]
    ) -> dict:
        """Return the existing record, creating a default ``open`` one if absent."""
        existing = await self.get(subject_type, subject_key)
        if existing is not None:
            return existing
        now = _iso_now()
        await self._db().execute(
            "INSERT OR IGNORE INTO investigation_triage "
            "(subject_type, subject_key, tenant, status, assignee, notes, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [subject_type, subject_key, tenant or "", "open", "", "[]", now, now],
        )
        created = await self.get(subject_type, subject_key)
        # Concurrent create is absorbed by INSERT OR IGNORE; re-read is authoritative.
        return created if created is not None else {
            "subject_type": subject_type,
            "subject_key": subject_key,
            "tenant": tenant or "",
            "status": "open",
            "assignee": "",
            "notes": [],
            "created_at": now,
            "updated_at": now,
        }

    async def set_state(
        self,
        *,
        subject_type: str,
        subject_key: str,
        tenant: Optional[str],
        actor: str,
        status: Optional[str] = None,
        assignee: Optional[str] = None,
    ) -> dict:
        """Set status and/or assignee, appending an audit note for the change.

        Raises ``ValueError`` for an invalid subject type or status. The change is
        recorded as an appended, actor-stamped note so the record is self-auditing.
        """
        if not self.valid_subject_type(subject_type):
            raise ValueError(f"invalid subject_type: {subject_type}")
        if not subject_key:
            raise ValueError("subject_key is required")
        if status is not None and not self.valid_status(status):
            raise ValueError(f"invalid status: {status}")

        record = await self._ensure_row(subject_type, subject_key, tenant)
        notes = record.get("notes") or []

        changes: list[str] = []
        new_status = record.get("status") or "open"
        new_assignee = record.get("assignee") or ""
        if status is not None and status != new_status:
            changes.append(f"status {new_status} → {status}")
            new_status = status
        if assignee is not None:
            assignee = assignee.strip()[:_MAX_ASSIGNEE_LEN]
            if assignee != new_assignee:
                changes.append(
                    f"assignee {new_assignee or '—'} → {assignee or '—'}"
                )
                new_assignee = assignee

        now = _iso_now()
        if changes:
            notes = self._append_note(
                notes, author=actor, text="; ".join(changes), kind="action"
            )
        await self._db().execute(
            "UPDATE investigation_triage SET status = ?, assignee = ?, notes = ?, "
            "updated_at = ? WHERE subject_type = ? AND subject_key = ?",
            [new_status, new_assignee, json.dumps(notes), now, subject_type, subject_key],
        )
        result = await self.get(subject_type, subject_key)
        return result if result is not None else record

    async def add_note(
        self,
        *,
        subject_type: str,
        subject_key: str,
        tenant: Optional[str],
        actor: str,
        text: str,
    ) -> dict:
        """Append an analyst note. Raises ``ValueError`` on invalid input."""
        if not self.valid_subject_type(subject_type):
            raise ValueError(f"invalid subject_type: {subject_type}")
        if not subject_key:
            raise ValueError("subject_key is required")
        text = (text or "").strip()
        if not text:
            raise ValueError("note text is required")

        record = await self._ensure_row(subject_type, subject_key, tenant)
        notes = self._append_note(
            record.get("notes") or [], author=actor, text=text, kind="note"
        )
        now = _iso_now()
        await self._db().execute(
            "UPDATE investigation_triage SET notes = ?, updated_at = ? "
            "WHERE subject_type = ? AND subject_key = ?",
            [json.dumps(notes), now, subject_type, subject_key],
        )
        result = await self.get(subject_type, subject_key)
        return result if result is not None else record

    @staticmethod
    def _append_note(notes: list[dict], *, author: str, text: str, kind: str) -> list[dict]:
        """Append a bounded, timestamped note, trimming the oldest past the cap."""
        entry = {
            "ts": _iso_now(),
            "author": (author or "system")[:_MAX_ASSIGNEE_LEN],
            "kind": kind,
            "text": text[:_MAX_NOTE_LEN],
        }
        out = [*notes, entry]
        if len(out) > _MAX_NOTES:
            out = out[-_MAX_NOTES:]
        return out


_store: Optional[TriageStore] = None


def get_triage_store() -> TriageStore:
    """Return the process-wide triage store singleton."""
    global _store
    if _store is None:
        _store = TriageStore()
    return _store
