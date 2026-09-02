"""Case-scoped *observables* for the Investigation Center (Phase 0).

An **observable** is an atomic indicator collected under an investigation case —
an IP, domain, URL, file hash, email, filename, user identifier, or a free-form
``other`` value. Where a linked *subject* (incident / origin / session) points at
the durable evidence behind an alert, an observable is the analyst's own record
of a concrete artefact seen while working the case: "this domain appeared in the
payload", "this hash is the dropped file".

Persisted in the ``investigation_observable`` table (migration v8) via the shared
``DatabaseEngine`` so it survives restarts and works identically on SQLite and
PostgreSQL. Each observable is keyed by an app-generated opaque ``observable_id``
(generated here rather than relying on a backend auto-increment / ``RETURNING`` so
the store stays dialect-neutral, matching the rest of the admin data layer), and
``UNIQUE(case_id, type, value)`` dedupes an indicator within a case — re-adding a
known indicator refreshes its ``last_seen`` rather than creating a duplicate.

An observable can be flagged ``is_ioc`` (stored as INTEGER 0/1 in *both* backends
to avoid cross-dialect BOOLEAN coercion) and carries TLP/PAP handling markers, a
free-form tag list, a provenance ``source``, and a JSON ``enrichment`` blob
populated by the Phase 2 threat-intel connectors (Cortex analyzers, keyed by
connector) via :meth:`ObservableStore.set_enrichment`.
"""

from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Optional

from .database import get_database

logger = logging.getLogger(__name__)

# The kinds of atomic indicator an observable can represent. ``other`` is the
# catch-all for anything that does not fit a structured type.
OBSERVABLE_TYPES = (
    "ip",
    "domain",
    "url",
    "hash",
    "email",
    "filename",
    "user",
    "other",
)

# Traffic Light Protocol handling markers, ordered most→least restrictive. Default
# ``amber`` mirrors the conservative default used across the Investigation Center.
TLP_LEVELS = ("red", "amber", "green", "white")

# Permissible Actions Protocol — how far an indicator may be acted upon.
PAP_LEVELS = ("red", "amber", "green", "white")

# Provenance of an observable. ``manual`` is analyst-entered; ``ioc-check`` is a
# hit surfaced by the proxy IOC scanner; ``cortex`` / ``opencti`` are reserved for
# the Phase 2 enrichment connectors.
OBSERVABLE_SOURCES = ("manual", "ioc-check", "cortex", "opencti")

# Bounds so a single case can never accrue an unbounded observable set and no one
# field can be bloated by a runaway client.
_MAX_OBSERVABLES_PER_CASE = 2000
_MAX_VALUE_LEN = 2048
_MAX_TAGS = 50
_MAX_TAG_LEN = 64
_MAX_ACTOR_LEN = 128
# Cap the number of distinct enrichment keys stored on one observable so a runaway
# caller (or many re-runs under different keys) can never bloat the JSON blob. When
# the cap is hit, the oldest key is evicted (dicts preserve insertion order).
_MAX_ENRICHMENT_KEYS = 20
_MAX_ENRICHMENT_KEY_LEN = 64


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_observable_id() -> str:
    """Generate an opaque, collision-resistant, URL-safe observable id."""
    return "obs_" + secrets.token_hex(8)


def _load_tags(raw) -> list[str]:
    """Parse the stored tags JSON into a list of strings (never raises)."""
    if not raw:
        return []
    parsed = raw if isinstance(raw, list) else None
    if parsed is None:
        try:
            decoded = json.loads(raw)
            parsed = decoded if isinstance(decoded, list) else []
        except (json.JSONDecodeError, TypeError):
            return []
    return [str(t) for t in parsed if isinstance(t, (str, int, float)) and str(t)]


def _normalise_tags(tags: list[str]) -> list[str]:
    """Trim, lower-case, dedupe (order-preserving) and cap a tag list."""
    out: list[str] = []
    seen: set[str] = set()
    for tag in tags or []:
        norm = str(tag).strip().lower()[:_MAX_TAG_LEN]
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
        if len(out) >= _MAX_TAGS:
            break
    return out


def _load_enrichment(raw) -> dict:
    """Parse the stored enrichment JSON into a dict (never raises)."""
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def normalise_value(observable_type: str, value: str) -> str:
    """Normalise an observable value for storage + dedupe (pure).

    Type-aware: network/host/hash/email indicators are case-insensitive so they
    are lower-cased (a hash and its upper-case twin are the same indicator);
    filenames, usernames and ``other`` keep their original case (case can be
    significant). All types are stripped and length-capped.
    """
    v = (value or "").strip()[:_MAX_VALUE_LEN]
    if observable_type in ("ip", "domain", "url", "hash", "email"):
        return v.lower()
    return v


def _row_to_observable(row) -> dict:
    """Convert a DB row into the observable dict the API returns."""
    d = row.to_dict() if hasattr(row, "to_dict") else dict(row)
    return {
        "observable_id": d.get("observable_id"),
        "case_id": d.get("case_id"),
        "type": d.get("type") or "other",
        "value": d.get("value") or "",
        "is_ioc": bool(d.get("is_ioc")),
        "tlp": d.get("tlp") or "amber",
        "pap": d.get("pap") or "amber",
        "tags": _load_tags(d.get("tags")),
        "source": d.get("source") or "manual",
        "enrichment": _load_enrichment(d.get("enrichment")),
        "added_by": d.get("added_by") or "",
        "first_seen": d.get("first_seen"),
        "last_seen": d.get("last_seen"),
    }


class ObservableStore:
    """Async CRUD over the ``investigation_observable`` table."""

    def _db(self):
        return get_database()

    @staticmethod
    def valid_type(observable_type: str) -> bool:
        return observable_type in OBSERVABLE_TYPES

    @staticmethod
    def valid_tlp(tlp: str) -> bool:
        return tlp in TLP_LEVELS

    @staticmethod
    def valid_pap(pap: str) -> bool:
        return pap in PAP_LEVELS

    @staticmethod
    def valid_source(source: str) -> bool:
        return source in OBSERVABLE_SOURCES

    # ─── Reads ───────────────────────────────────────────────────────────────

    async def list_for_case(self, case_id: str) -> list[dict]:
        """Return a case's observables, most-recently-seen first."""
        if not case_id:
            return []
        rows = await self._db().fetch_all(
            "SELECT * FROM investigation_observable WHERE case_id = ? "
            "ORDER BY last_seen DESC",
            [case_id],
        )
        return [_row_to_observable(r) for r in rows]

    async def get(self, case_id: str, observable_id: str) -> Optional[dict]:
        """Return a single observable scoped to its case, or ``None`` if absent."""
        if not case_id or not observable_id:
            return None
        row = await self._db().fetch_one(
            "SELECT * FROM investigation_observable "
            "WHERE case_id = ? AND observable_id = ?",
            [case_id, observable_id],
        )
        return _row_to_observable(row) if row else None

    async def _count_for_case(self, case_id: str) -> int:
        row = await self._db().fetch_one(
            "SELECT COUNT(*) AS n FROM investigation_observable WHERE case_id = ?",
            [case_id],
        )
        if not row:
            return 0
        d = row.to_dict() if hasattr(row, "to_dict") else dict(row)
        return int(d.get("n") or 0)

    async def _find_by_value(
        self, case_id: str, observable_type: str, value: str
    ) -> Optional[dict]:
        row = await self._db().fetch_one(
            "SELECT * FROM investigation_observable "
            "WHERE case_id = ? AND type = ? AND value = ?",
            [case_id, observable_type, value],
        )
        return _row_to_observable(row) if row else None

    # ─── Writes ──────────────────────────────────────────────────────────────

    async def add(
        self,
        *,
        case_id: str,
        observable_type: str,
        value: str,
        actor: str,
        is_ioc: bool = False,
        tlp: str = "amber",
        pap: str = "amber",
        tags: Optional[list[str]] = None,
        source: str = "manual",
    ) -> dict:
        """Add an observable to a case (idempotent per case+type+value).

        Re-adding a known indicator refreshes ``last_seen`` (and any changed
        flags/handling markers) rather than creating a duplicate. Raises
        ``ValueError`` on invalid input or when the case is at its observable cap.
        """
        if not case_id:
            raise ValueError("case_id is required")
        if not self.valid_type(observable_type):
            raise ValueError(f"invalid observable type: {observable_type}")
        if not self.valid_tlp(tlp):
            raise ValueError(f"invalid tlp: {tlp}")
        if not self.valid_pap(pap):
            raise ValueError(f"invalid pap: {pap}")
        if not self.valid_source(source):
            raise ValueError(f"invalid source: {source}")
        norm_value = normalise_value(observable_type, value)
        if not norm_value:
            raise ValueError("value is required")
        norm_tags = _normalise_tags(tags or [])
        now = _iso_now()

        existing = await self._find_by_value(case_id, observable_type, norm_value)
        if existing is not None:
            # Refresh last_seen + handling markers on a repeat sighting.
            await self._db().execute(
                "UPDATE investigation_observable SET is_ioc = ?, tlp = ?, pap = ?, "
                "tags = ?, source = ?, last_seen = ? "
                "WHERE observable_id = ?",
                [
                    1 if is_ioc else 0, tlp, pap, json.dumps(norm_tags), source, now,
                    existing["observable_id"],
                ],
            )
            refreshed = await self.get(case_id, existing["observable_id"])
            if refreshed is None:  # pragma: no cover — write-then-read is authoritative
                raise RuntimeError("observable update failed")
            return refreshed

        if await self._count_for_case(case_id) >= _MAX_OBSERVABLES_PER_CASE:
            raise ValueError("case has reached its observable limit")

        observable_id = _new_observable_id()
        await self._db().execute(
            "INSERT INTO investigation_observable "
            "(observable_id, case_id, type, value, is_ioc, tlp, pap, tags, source, "
            "enrichment, added_by, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                observable_id, case_id, observable_type, norm_value,
                1 if is_ioc else 0, tlp, pap, json.dumps(norm_tags), source,
                None, (actor or "system")[:_MAX_ACTOR_LEN], now, now,
            ],
        )
        created = await self.get(case_id, observable_id)
        if created is None:  # pragma: no cover — write-then-read is authoritative
            raise RuntimeError("observable creation failed")
        return created

    async def set_enrichment(
        self,
        *,
        case_id: str,
        observable_id: str,
        key: str,
        data: dict,
        mark_ioc: bool = False,
    ) -> Optional[dict]:
        """Merge a threat-intel enrichment blob onto an observable (Phase 2).

        Stores ``data`` under ``enrichment[key]`` (merging with any prior blobs),
        refreshes ``last_seen``, and optionally flags the observable ``is_ioc``
        (used when an enrichment verdict is malicious). Returns the refreshed
        observable, or ``None`` if it does not exist under ``case_id``.

        The enrichment map is bounded to ``_MAX_ENRICHMENT_KEYS`` — when full, the
        oldest key is evicted so the JSON blob can never grow unbounded. ``is_ioc``
        is sticky: it is only ever raised here, never cleared.
        """
        existing = await self.get(case_id, observable_id)
        if existing is None:
            return None

        norm_key = str(key).strip()[:_MAX_ENRICHMENT_KEY_LEN]
        if not norm_key:
            raise ValueError("enrichment key is required")

        enrichment = dict(existing.get("enrichment") or {})
        enrichment[norm_key] = data
        # Evict oldest keys (insertion order) until within the cap.
        while len(enrichment) > _MAX_ENRICHMENT_KEYS:
            oldest = next(iter(enrichment))
            enrichment.pop(oldest, None)

        is_ioc = bool(existing.get("is_ioc")) or mark_ioc
        now = _iso_now()
        await self._db().execute(
            "UPDATE investigation_observable SET enrichment = ?, is_ioc = ?, "
            "last_seen = ? WHERE case_id = ? AND observable_id = ?",
            [json.dumps(enrichment), 1 if is_ioc else 0, now, case_id, observable_id],
        )
        refreshed = await self.get(case_id, observable_id)
        if refreshed is None:  # pragma: no cover — write-then-read is authoritative
            raise RuntimeError("observable enrichment update failed")
        return refreshed

    async def remove(self, *, case_id: str, observable_id: str) -> bool:
        """Delete an observable from a case. Returns ``True`` if a row was removed."""
        existing = await self.get(case_id, observable_id)
        if existing is None:
            return False
        await self._db().execute(
            "DELETE FROM investigation_observable "
            "WHERE case_id = ? AND observable_id = ?",
            [case_id, observable_id],
        )
        return True


_store: Optional[ObservableStore] = None


def get_observable_store() -> ObservableStore:
    """Return the process-wide observable store singleton."""
    global _store
    if _store is None:
        _store = ObservableStore()
    return _store
