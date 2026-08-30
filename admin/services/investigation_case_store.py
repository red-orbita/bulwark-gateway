"""Case management for the Investigation Center.

Where ``investigation_triage`` (v6) tracks the workflow of a *single* subject
(an incident, an at-risk origin, or a decomposition session), a **case** groups
several related subjects under one analyst-owned investigation. A working
prompt-injection campaign, for example, typically shows up as several correlated
incidents plus the origins/sessions that drove them — a case lets an analyst pin
them together, give the whole thing a severity + owner, and keep one shared,
append-only note trail.

Persisted across two tables (migration v7) via the shared ``DatabaseEngine`` so
it survives restarts and works identically on SQLite and PostgreSQL:

* ``investigation_case`` — the case record, keyed by an app-generated opaque
  ``case_id`` (generated here rather than relying on a backend auto-increment /
  ``RETURNING`` so the store stays dialect-neutral, matching the rest of the
  admin data layer), and
* ``investigation_case_subject`` — the N:M link between a case and the subjects
  it collects, ``UNIQUE`` per (case, subject).

As with the triage store, every state change is additive and auditable:
status/severity/assignee transitions and notes each stamp an actor + UTC
timestamp, and notes are append-only, so the record is itself an investigation
trail. Volume is low (one row per case), so a read-then-write update is used
rather than backend-specific UPSERT SQL.
"""

from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Optional

from .database import get_database
from .investigation_store import SUBJECT_TYPES

logger = logging.getLogger(__name__)

# Case workflow states. ``open`` is the implicit initial state; analysts move
# freely between states (including reopening a closed case), which SOC workflows
# routinely require — so transitions are validated only against this set, never a
# fixed state machine.
CASE_STATUSES = ("open", "investigating", "contained", "resolved", "closed")

# Case severities, ordered low→critical. Independent of a subject's own severity:
# it is the analyst's assessment of the grouped investigation as a whole.
CASE_SEVERITIES = ("low", "medium", "high", "critical")

# Bounds so a single case can never grow without limit.
_MAX_NOTES = 500
_MAX_NOTE_LEN = 4000
_MAX_TITLE_LEN = 200
_MAX_SUMMARY_LEN = 4000
_MAX_ASSIGNEE_LEN = 128
_MAX_SUBJECT_KEY_LEN = 256
_MAX_SUBJECTS_PER_CASE = 500
_MAX_SEARCH_LEN = 128

# Whitelisted sort columns for ``list_cases``. The API only ever passes a *key*
# from this map into the query — never a raw client string — so the resulting
# ``ORDER BY`` clause is injection-free. ``severity`` is ranked low→critical via a
# dialect-neutral CASE expression so it sorts by real severity, not alphabetically.
_SORT_COLUMNS: dict[str, str] = {
    "updated_at": "updated_at",
    "created_at": "created_at",
    "title": "title",
    "status": "status",
    "severity": (
        "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"
    ),
}
_DEFAULT_SORT = "updated_at"

# ``LIKE`` special characters we neutralise in a user search term so a caller
# cannot turn a substring search into a wildcard/underscore match. Paired with an
# explicit ``ESCAPE '\'`` clause (supported identically by SQLite and PostgreSQL).
_LIKE_ESCAPE = "\\"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _escape_like(term: str) -> str:
    """Escape ``LIKE`` wildcards so a search term matches literally."""
    out = term.replace(_LIKE_ESCAPE, _LIKE_ESCAPE * 2)
    out = out.replace("%", _LIKE_ESCAPE + "%")
    out = out.replace("_", _LIKE_ESCAPE + "_")
    return out


def _new_case_id() -> str:
    """Generate an opaque, collision-resistant, URL-safe case id."""
    return "case_" + secrets.token_hex(8)


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


def _row_to_case(row) -> dict:
    """Convert a DB row into the case dict the API returns (without subjects)."""
    d = row.to_dict() if hasattr(row, "to_dict") else dict(row)
    return {
        "case_id": d.get("case_id"),
        "title": d.get("title") or "",
        "status": d.get("status") or "open",
        "severity": d.get("severity") or "medium",
        "tenant": d.get("tenant") or "",
        "assignee": d.get("assignee") or "",
        "summary": d.get("summary") or "",
        "notes": _load_notes(d.get("notes")),
        "created_by": d.get("created_by") or "",
        "created_at": d.get("created_at"),
        "updated_at": d.get("updated_at"),
    }


def _row_to_subject(row) -> dict:
    """Convert a link row into the subject dict the API returns."""
    d = row.to_dict() if hasattr(row, "to_dict") else dict(row)
    return {
        "subject_type": d.get("subject_type"),
        "subject_key": d.get("subject_key"),
        "added_by": d.get("added_by") or "",
        "added_at": d.get("added_at"),
    }


class CaseStore:
    """Async CRUD over the ``investigation_case`` + link tables."""

    def _db(self):
        return get_database()

    @staticmethod
    def valid_status(status: str) -> bool:
        return status in CASE_STATUSES

    @staticmethod
    def valid_severity(severity: str) -> bool:
        return severity in CASE_SEVERITIES

    @staticmethod
    def valid_subject_type(subject_type: str) -> bool:
        return subject_type in SUBJECT_TYPES

    # ─── Reads ───────────────────────────────────────────────────────────────

    async def _get_row(self, case_id: str) -> Optional[dict]:
        row = await self._db().fetch_one(
            "SELECT * FROM investigation_case WHERE case_id = ?", [case_id]
        )
        return _row_to_case(row) if row else None

    async def get(self, case_id: str) -> Optional[dict]:
        """Return a case with its linked subjects, or ``None`` if absent."""
        if not case_id:
            return None
        case = await self._get_row(case_id)
        if case is None:
            return None
        case["subjects"] = await self.list_subjects(case_id)
        return case

    async def list_subjects(self, case_id: str) -> list[dict]:
        """Return the subjects linked to a case (most-recently-added first)."""
        rows = await self._db().fetch_all(
            "SELECT * FROM investigation_case_subject WHERE case_id = ? "
            "ORDER BY added_at DESC",
            [case_id],
        )
        return [_row_to_subject(r) for r in rows]

    @staticmethod
    def _filter_clause(
        *,
        status: Optional[str],
        severity: Optional[str],
        assignee: Optional[str],
        tenant: Optional[str],
        search: Optional[str],
    ) -> tuple[str, list]:
        """Build a shared, fully-parameterised WHERE clause for the filter set.

        Returns ``(where_sql, params)`` — used identically by ``list_cases``,
        ``count_cases`` and ``stats`` so the three can never drift. Every value is
        bound; the search term is ``LIKE``-escaped and matched literally.
        """
        conditions: list[str] = []
        params: list = []
        if status:
            conditions.append("status = ?")
            params.append(status)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if assignee:
            conditions.append("assignee = ?")
            params.append(assignee[:_MAX_ASSIGNEE_LEN])
        if tenant:
            conditions.append("tenant = ?")
            params.append(tenant)
        if search:
            term = "%" + _escape_like(search.strip()[:_MAX_SEARCH_LEN]) + "%"
            conditions.append(
                "(title LIKE ? ESCAPE '\\' OR case_id LIKE ? ESCAPE '\\' "
                "OR summary LIKE ? ESCAPE '\\')"
            )
            params.extend([term, term, term])
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        return where, params

    async def list_cases(
        self,
        *,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        assignee: Optional[str] = None,
        tenant: Optional[str] = None,
        search: Optional[str] = None,
        sort: str = _DEFAULT_SORT,
        descending: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """List cases with a subject count, filtered/sorted per the arguments.

        ``sort`` is validated against ``_SORT_COLUMNS`` (falling back to the default
        ordering), so only a whitelisted column expression ever reaches the query.
        """
        where, params = self._filter_clause(
            status=status, severity=severity, assignee=assignee,
            tenant=tenant, search=search,
        )
        order_col = _SORT_COLUMNS.get(sort, _SORT_COLUMNS[_DEFAULT_SORT])
        direction = "DESC" if descending else "ASC"
        # Deterministic tiebreak so paging is stable when the sort key ties.
        sql = (
            f"SELECT * FROM investigation_case{where} "  # noqa: S608 — whitelisted column + bound params
            f"ORDER BY {order_col} {direction}, case_id ASC LIMIT ? OFFSET ?"
        )
        rows = await self._db().fetch_all(sql, [*params, int(limit), int(offset)])
        cases = [_row_to_case(r) for r in rows]
        for c in cases:
            c["subject_count"] = await self._count_subjects(c["case_id"])
        return cases

    async def count_cases(
        self,
        *,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        assignee: Optional[str] = None,
        tenant: Optional[str] = None,
        search: Optional[str] = None,
    ) -> int:
        """Return the total number of cases matching a filter set (for paging)."""
        where, params = self._filter_clause(
            status=status, severity=severity, assignee=assignee,
            tenant=tenant, search=search,
        )
        row = await self._db().fetch_one(
            f"SELECT COUNT(*) AS n FROM investigation_case{where}",  # noqa: S608 — bound params only
            params,
        )
        if not row:
            return 0
        d = row.to_dict() if hasattr(row, "to_dict") else dict(row)
        return int(d.get("n") or 0)

    async def stats(
        self,
        *,
        tenant: Optional[str] = None,
        assignee: Optional[str] = None,
    ) -> dict:
        """Aggregate case counts for the Investigation Center KPI header.

        Returns totals broken down by status and severity (tenant-scoped), plus an
        ``open`` roll-up (anything not resolved/closed) and, when ``assignee`` is
        given, that operator's own open workload for the "my work" cards.
        """
        by_status: dict[str, int] = {}
        for st in CASE_STATUSES:
            by_status[st] = await self.count_cases(status=st, tenant=tenant)
        by_severity: dict[str, int] = {}
        for sev in CASE_SEVERITIES:
            by_severity[sev] = await self.count_cases(severity=sev, tenant=tenant)

        total = await self.count_cases(tenant=tenant)
        closed = by_status.get("resolved", 0) + by_status.get("closed", 0)
        result: dict = {
            "total": total,
            "open": total - closed,
            "by_status": by_status,
            "by_severity": by_severity,
        }
        if assignee:
            mine_total = await self.count_cases(tenant=tenant, assignee=assignee)
            mine_closed = 0
            for st in ("resolved", "closed"):
                mine_closed += await self.count_cases(
                    tenant=tenant, assignee=assignee, status=st
                )
            result["mine"] = {"total": mine_total, "open": mine_total - mine_closed}
        return result

    async def _count_subjects(self, case_id: str) -> int:
        row = await self._db().fetch_one(
            "SELECT COUNT(*) AS n FROM investigation_case_subject WHERE case_id = ?",
            [case_id],
        )
        if not row:
            return 0
        d = row.to_dict() if hasattr(row, "to_dict") else dict(row)
        return int(d.get("n") or 0)

    async def find_cases_for_subject(
        self, subject_type: str, subject_key: str
    ) -> list[dict]:
        """Return the (brief) cases a given subject is linked to.

        Lets a subject drill-down show "part of case X" and drives the
        add-to-case affordance's dedupe. Returns id/title/status/severity only.
        """
        if not subject_type or not subject_key:
            return []
        rows = await self._db().fetch_all(
            "SELECT c.case_id, c.title, c.status, c.severity, c.tenant "
            "FROM investigation_case_subject s "
            "JOIN investigation_case c ON c.case_id = s.case_id "
            "WHERE s.subject_type = ? AND s.subject_key = ? "
            "ORDER BY c.updated_at DESC",
            [subject_type, subject_key],
        )
        out: list[dict] = []
        for r in rows:
            d = r.to_dict() if hasattr(r, "to_dict") else dict(r)
            out.append({
                "case_id": d.get("case_id"),
                "title": d.get("title") or "",
                "status": d.get("status") or "open",
                "severity": d.get("severity") or "medium",
                "tenant": d.get("tenant") or "",
            })
        return out

    # ─── Writes ──────────────────────────────────────────────────────────────

    async def create_case(
        self,
        *,
        title: str,
        actor: str,
        severity: str = "medium",
        tenant: Optional[str] = None,
        summary: Optional[str] = None,
    ) -> dict:
        """Create a new case. Raises ``ValueError`` on invalid input."""
        title = (title or "").strip()[:_MAX_TITLE_LEN]
        if not title:
            raise ValueError("title is required")
        if not self.valid_severity(severity):
            raise ValueError(f"invalid severity: {severity}")
        summary = (summary or "").strip()[:_MAX_SUMMARY_LEN]

        case_id = _new_case_id()
        now = _iso_now()
        opened = self._append_note(
            [], author=actor, text=f"case opened ({severity})", kind="action"
        )
        await self._db().execute(
            "INSERT INTO investigation_case "
            "(case_id, title, status, severity, tenant, assignee, summary, notes, "
            "created_by, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [case_id, title, "open", severity, tenant or "", "", summary,
             json.dumps(opened), actor, now, now],
        )
        created = await self.get(case_id)
        if created is None:  # pragma: no cover — write-then-read is authoritative
            raise RuntimeError("case creation failed")
        return created

    async def set_state(
        self,
        *,
        case_id: str,
        actor: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        assignee: Optional[str] = None,
    ) -> Optional[dict]:
        """Set status/severity/assignee, appending an audit note per change.

        Returns ``None`` if the case does not exist. Raises ``ValueError`` for an
        invalid status/severity.
        """
        if status is not None and not self.valid_status(status):
            raise ValueError(f"invalid status: {status}")
        if severity is not None and not self.valid_severity(severity):
            raise ValueError(f"invalid severity: {severity}")

        case = await self._get_row(case_id)
        if case is None:
            return None

        notes = case.get("notes") or []
        changes: list[str] = []
        new_status = case["status"]
        new_severity = case["severity"]
        new_assignee = case["assignee"]

        if status is not None and status != new_status:
            changes.append(f"status {new_status} → {status}")
            new_status = status
        if severity is not None and severity != new_severity:
            changes.append(f"severity {new_severity} → {severity}")
            new_severity = severity
        if assignee is not None:
            assignee = assignee.strip()[:_MAX_ASSIGNEE_LEN]
            if assignee != new_assignee:
                changes.append(f"assignee {new_assignee or '—'} → {assignee or '—'}")
                new_assignee = assignee

        now = _iso_now()
        if changes:
            notes = self._append_note(
                notes, author=actor, text="; ".join(changes), kind="action"
            )
        await self._db().execute(
            "UPDATE investigation_case SET status = ?, severity = ?, assignee = ?, "
            "notes = ?, updated_at = ? WHERE case_id = ?",
            [new_status, new_severity, new_assignee, json.dumps(notes), now, case_id],
        )
        return await self.get(case_id)

    async def add_note(self, *, case_id: str, actor: str, text: str) -> Optional[dict]:
        """Append an analyst note. Returns ``None`` if the case is absent."""
        text = (text or "").strip()
        if not text:
            raise ValueError("note text is required")
        case = await self._get_row(case_id)
        if case is None:
            return None
        notes = self._append_note(
            case.get("notes") or [], author=actor, text=text, kind="note"
        )
        now = _iso_now()
        await self._db().execute(
            "UPDATE investigation_case SET notes = ?, updated_at = ? WHERE case_id = ?",
            [json.dumps(notes), now, case_id],
        )
        return await self.get(case_id)

    async def add_subject(
        self, *, case_id: str, subject_type: str, subject_key: str, actor: str
    ) -> Optional[dict]:
        """Link a subject to a case (idempotent). Returns ``None`` if absent.

        Raises ``ValueError`` for an invalid subject type/key or when the case is
        already at its subject cap.
        """
        if not self.valid_subject_type(subject_type):
            raise ValueError(f"invalid subject_type: {subject_type}")
        subject_key = (subject_key or "").strip()[:_MAX_SUBJECT_KEY_LEN]
        if not subject_key:
            raise ValueError("subject_key is required")

        case = await self._get_row(case_id)
        if case is None:
            return None

        existing = await self.list_subjects(case_id)
        already = any(
            s["subject_type"] == subject_type and s["subject_key"] == subject_key
            for s in existing
        )
        now = _iso_now()
        if not already:
            if len(existing) >= _MAX_SUBJECTS_PER_CASE:
                raise ValueError("case has reached its subject limit")
            await self._db().execute(
                "INSERT OR IGNORE INTO investigation_case_subject "
                "(case_id, subject_type, subject_key, added_by, added_at) "
                "VALUES (?, ?, ?, ?, ?)",
                [case_id, subject_type, subject_key, actor, now],
            )
            notes = self._append_note(
                case.get("notes") or [], author=actor,
                text=f"linked {subject_type}:{subject_key}", kind="action",
            )
            await self._db().execute(
                "UPDATE investigation_case SET notes = ?, updated_at = ? "
                "WHERE case_id = ?",
                [json.dumps(notes), now, case_id],
            )
        return await self.get(case_id)

    async def remove_subject(
        self, *, case_id: str, subject_type: str, subject_key: str, actor: str
    ) -> Optional[dict]:
        """Unlink a subject from a case. Returns ``None`` if the case is absent."""
        case = await self._get_row(case_id)
        if case is None:
            return None
        existing = await self.list_subjects(case_id)
        present = any(
            s["subject_type"] == subject_type and s["subject_key"] == subject_key
            for s in existing
        )
        if present:
            await self._db().execute(
                "DELETE FROM investigation_case_subject "
                "WHERE case_id = ? AND subject_type = ? AND subject_key = ?",
                [case_id, subject_type, subject_key],
            )
            now = _iso_now()
            notes = self._append_note(
                case.get("notes") or [], author=actor,
                text=f"unlinked {subject_type}:{subject_key}", kind="action",
            )
            await self._db().execute(
                "UPDATE investigation_case SET notes = ?, updated_at = ? "
                "WHERE case_id = ?",
                [json.dumps(notes), now, case_id],
            )
        return await self.get(case_id)

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


def render_case_markdown(case: dict) -> str:
    """Render a full case (metadata + subjects + note trail) as a Markdown report.

    Pure and side-effect-free so it is unit-testable without a request. Used by the
    case export endpoint to produce an analyst-portable investigation record. All
    values originate from the durable store; no external content is interpolated.
    """
    title = (case.get("title") or "").strip() or "(untitled case)"
    lines: list[str] = [
        f"# Investigation Case: {title}",
        "",
        f"- **Case ID:** {case.get('case_id') or ''}",
        f"- **Status:** {case.get('status') or 'open'}",
        f"- **Severity:** {case.get('severity') or 'medium'}",
        f"- **Assignee:** {case.get('assignee') or '—'}",
        f"- **Tenant:** {case.get('tenant') or '(global)'}",
        f"- **Opened by:** {case.get('created_by') or ''}",
        f"- **Created:** {case.get('created_at') or ''}",
        f"- **Updated:** {case.get('updated_at') or ''}",
        "",
    ]
    summary = (case.get("summary") or "").strip()
    if summary:
        lines += ["## Summary", "", summary, ""]

    subjects = case.get("subjects") or []
    lines += [f"## Linked Subjects ({len(subjects)})", ""]
    if subjects:
        lines += ["| Type | Key | Added by | Added at |", "| --- | --- | --- | --- |"]
        for s in subjects:
            lines.append(
                f"| {s.get('subject_type') or ''} | {s.get('subject_key') or ''} "
                f"| {s.get('added_by') or ''} | {s.get('added_at') or ''} |"
            )
    else:
        lines.append("_No subjects linked._")
    lines.append("")

    notes = case.get("notes") or []
    lines += [f"## Note Trail ({len(notes)})", ""]
    if notes:
        for n in notes:
            kind = n.get("kind") or "note"
            lines.append(
                f"- **[{n.get('ts') or ''}] {n.get('author') or 'system'}** "
                f"_({kind})_: {n.get('text') or ''}"
            )
    else:
        lines.append("_No notes recorded._")
    lines.append("")
    return "\n".join(lines)


_store: Optional[CaseStore] = None


def get_case_store() -> CaseStore:
    """Return the process-wide case store singleton."""
    global _store
    if _store is None:
        _store = CaseStore()
    return _store
