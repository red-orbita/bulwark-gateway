"""Case-scoped *tasks* for the Investigation Center (Phase 0).

A **task** is an analyst checklist item under an investigation case — "collect the
payload", "block the origin", "notify the tenant". Where the case note trail is a
free-form running log, tasks give a case an explicit, ordered to-do list with a
status lifecycle so an analyst (or a shift handover) can see at a glance what is
outstanding.

Persisted in the ``investigation_task`` table (migration v8) via the shared
``DatabaseEngine`` so it survives restarts and works identically on SQLite and
PostgreSQL. Each task is keyed by an app-generated opaque ``task_id`` (generated
here rather than relying on a backend auto-increment / ``RETURNING`` so the store
stays dialect-neutral). Tasks carry an ``order_index`` (max+1 on insert) for
manual ordering, an optional assignee and due timestamp, and an append-only,
actor-stamped note trail — the same self-auditing pattern as the case/triage
stores.
"""

from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Optional

from .database import get_database

logger = logging.getLogger(__name__)

# Task lifecycle states. ``todo`` is the implicit initial state; analysts move
# freely between states (including reopening a done/cancelled task), so
# transitions are validated only against this set, never a fixed state machine.
TASK_STATUSES = ("todo", "in_progress", "done", "cancelled")

# Terminal states — a task counted as closed for progress roll-ups.
_TERMINAL_STATUSES = ("done", "cancelled")

# Bounds so a single case can never accrue an unbounded task set and no one field
# can be bloated by a runaway client.
_MAX_TASKS_PER_CASE = 500
_MAX_TITLE_LEN = 200
_MAX_ASSIGNEE_LEN = 128
_MAX_NOTES = 200
_MAX_NOTE_LEN = 2000


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_task_id() -> str:
    """Generate an opaque, collision-resistant, URL-safe task id."""
    return "task_" + secrets.token_hex(8)


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


def _row_to_task(row) -> dict:
    """Convert a DB row into the task dict the API returns."""
    d = row.to_dict() if hasattr(row, "to_dict") else dict(row)
    return {
        "task_id": d.get("task_id"),
        "case_id": d.get("case_id"),
        "title": d.get("title") or "",
        "status": d.get("status") or "todo",
        "assignee": d.get("assignee") or "",
        "order_index": int(d.get("order_index") or 0),
        "due_at": d.get("due_at"),
        "notes": _load_notes(d.get("notes")),
        "created_by": d.get("created_by") or "",
        "created_at": d.get("created_at"),
        "updated_at": d.get("updated_at"),
    }


class TaskStore:
    """Async CRUD over the ``investigation_task`` table."""

    def _db(self):
        return get_database()

    @staticmethod
    def valid_status(status: str) -> bool:
        return status in TASK_STATUSES

    # ─── Reads ───────────────────────────────────────────────────────────────

    async def list_for_case(self, case_id: str) -> list[dict]:
        """Return a case's tasks in manual order (then creation order)."""
        if not case_id:
            return []
        rows = await self._db().fetch_all(
            "SELECT * FROM investigation_task WHERE case_id = ? "
            "ORDER BY order_index ASC, created_at ASC",
            [case_id],
        )
        return [_row_to_task(r) for r in rows]

    async def get(self, case_id: str, task_id: str) -> Optional[dict]:
        """Return a single task scoped to its case, or ``None`` if absent."""
        if not case_id or not task_id:
            return None
        row = await self._db().fetch_one(
            "SELECT * FROM investigation_task WHERE case_id = ? AND task_id = ?",
            [case_id, task_id],
        )
        return _row_to_task(row) if row else None

    async def _count_for_case(self, case_id: str) -> int:
        row = await self._db().fetch_one(
            "SELECT COUNT(*) AS n FROM investigation_task WHERE case_id = ?",
            [case_id],
        )
        if not row:
            return 0
        d = row.to_dict() if hasattr(row, "to_dict") else dict(row)
        return int(d.get("n") or 0)

    async def _next_order_index(self, case_id: str) -> int:
        row = await self._db().fetch_one(
            "SELECT MAX(order_index) AS m FROM investigation_task WHERE case_id = ?",
            [case_id],
        )
        if not row:
            return 0
        d = row.to_dict() if hasattr(row, "to_dict") else dict(row)
        current = d.get("m")
        return (int(current) + 1) if current is not None else 0

    # ─── Writes ──────────────────────────────────────────────────────────────

    async def add(
        self,
        *,
        case_id: str,
        title: str,
        actor: str,
        assignee: Optional[str] = None,
        due_at: Optional[str] = None,
    ) -> dict:
        """Create a task at the end of the case's list. Raises ``ValueError``."""
        if not case_id:
            raise ValueError("case_id is required")
        title = (title or "").strip()[:_MAX_TITLE_LEN]
        if not title:
            raise ValueError("title is required")
        if await self._count_for_case(case_id) >= _MAX_TASKS_PER_CASE:
            raise ValueError("case has reached its task limit")

        assignee = (assignee or "").strip()[:_MAX_ASSIGNEE_LEN]
        due_at = (due_at or "").strip() or None
        task_id = _new_task_id()
        order_index = await self._next_order_index(case_id)
        now = _iso_now()
        await self._db().execute(
            "INSERT INTO investigation_task "
            "(task_id, case_id, title, status, assignee, order_index, due_at, "
            "notes, created_by, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                task_id, case_id, title, "todo", assignee, order_index, due_at,
                json.dumps([]), (actor or "system")[:_MAX_ASSIGNEE_LEN], now, now,
            ],
        )
        created = await self.get(case_id, task_id)
        if created is None:  # pragma: no cover — write-then-read is authoritative
            raise RuntimeError("task creation failed")
        return created

    async def set_state(
        self,
        *,
        case_id: str,
        task_id: str,
        actor: str,
        status: Optional[str] = None,
        assignee: Optional[str] = None,
        due_at: Optional[str] = None,
    ) -> Optional[dict]:
        """Set a task's status/assignee/due date, appending an audit note per change.

        Returns ``None`` if the task does not exist. Raises ``ValueError`` for an
        invalid status.
        """
        if status is not None and not self.valid_status(status):
            raise ValueError(f"invalid status: {status}")
        task = await self.get(case_id, task_id)
        if task is None:
            return None

        notes = task.get("notes") or []
        changes: list[str] = []
        new_status = task["status"]
        new_assignee = task["assignee"]
        new_due = task["due_at"]

        if status is not None and status != new_status:
            changes.append(f"status {new_status} → {status}")
            new_status = status
        if assignee is not None:
            assignee = assignee.strip()[:_MAX_ASSIGNEE_LEN]
            if assignee != new_assignee:
                changes.append(f"assignee {new_assignee or '—'} → {assignee or '—'}")
                new_assignee = assignee
        if due_at is not None:
            due_norm = due_at.strip() or None
            if due_norm != new_due:
                changes.append(f"due {new_due or '—'} → {due_norm or '—'}")
                new_due = due_norm

        now = _iso_now()
        if changes:
            notes = self._append_note(
                notes, author=actor, text="; ".join(changes), kind="action"
            )
        await self._db().execute(
            "UPDATE investigation_task SET status = ?, assignee = ?, due_at = ?, "
            "notes = ?, updated_at = ? WHERE case_id = ? AND task_id = ?",
            [new_status, new_assignee, new_due, json.dumps(notes), now,
             case_id, task_id],
        )
        return await self.get(case_id, task_id)

    async def add_note(
        self, *, case_id: str, task_id: str, actor: str, text: str
    ) -> Optional[dict]:
        """Append an analyst note to a task. Returns ``None`` if absent."""
        text = (text or "").strip()
        if not text:
            raise ValueError("note text is required")
        task = await self.get(case_id, task_id)
        if task is None:
            return None
        notes = self._append_note(
            task.get("notes") or [], author=actor, text=text, kind="note"
        )
        now = _iso_now()
        await self._db().execute(
            "UPDATE investigation_task SET notes = ?, updated_at = ? "
            "WHERE case_id = ? AND task_id = ?",
            [json.dumps(notes), now, case_id, task_id],
        )
        return await self.get(case_id, task_id)

    async def remove(self, *, case_id: str, task_id: str) -> bool:
        """Delete a task from a case. Returns ``True`` if a row was removed."""
        existing = await self.get(case_id, task_id)
        if existing is None:
            return False
        await self._db().execute(
            "DELETE FROM investigation_task WHERE case_id = ? AND task_id = ?",
            [case_id, task_id],
        )
        return True

    async def progress(self, case_id: str) -> dict:
        """Return a task-completion roll-up for a case (total/done/open counts)."""
        tasks = await self.list_for_case(case_id)
        total = len(tasks)
        done = sum(1 for t in tasks if t["status"] in _TERMINAL_STATUSES)
        return {"total": total, "done": done, "open": total - done}

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


_store: Optional[TaskStore] = None


def get_task_store() -> TaskStore:
    """Return the process-wide task store singleton."""
    global _store
    if _store is None:
        _store = TaskStore()
    return _store
