"""Idempotency map between local objects and remote platform records (Phase 1).

When a case is pushed to TheHive / DFIR-IRIS the platform assigns it a remote id.
We persist that mapping in the ``integration_link`` table (migration v9) keyed by
the composite ``(connector, local_type, local_id)`` so a *re-push* of the same
case updates the existing remote record instead of creating a duplicate.

Like the other Investigation stores this uses the shared ``DatabaseEngine`` so it
behaves identically on SQLite and PostgreSQL, keeps all SQL parameterised, and
performs an UPSERT as an explicit read-then-write (no dialect-specific
``ON CONFLICT`` / ``ON DUPLICATE KEY`` syntax).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from .database import get_database

logger = logging.getLogger(__name__)

# Local object types that may be linked to a remote record. Kept small and
# explicit — Phase 1 only pushes cases.
LINK_TYPES = ("case",)

# Outcome of the last inbound reconcile (Phase 4, migration v13). ``synced`` — the
# local case reflects the last remote read; ``pending`` — a remote read is queued
# but not yet folded in; ``conflict`` — the remote state cannot be safely applied
# (e.g. the remote reopened a locally-closed case) and needs analyst attention.
# NULL (absent from this tuple) means no inbound sync has happened yet.
RECONCILE_STATES = ("synced", "pending", "conflict")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_link(row) -> dict:
    d = row.to_dict() if hasattr(row, "to_dict") else dict(row)
    return {
        "connector": d.get("connector"),
        "local_type": d.get("local_type"),
        "local_id": d.get("local_id"),
        "remote_id": d.get("remote_id") or "",
        "remote_url": d.get("remote_url") or "",
        "last_synced_at": d.get("last_synced_at"),
        "etag": d.get("etag") or "",
        "last_remote_update": d.get("last_remote_update") or "",
        "last_reconciled_at": d.get("last_reconciled_at"),
        "reconcile_state": d.get("reconcile_state") or "",
    }


class IntegrationLinkStore:
    """Async CRUD over the ``integration_link`` idempotency table."""

    def _db(self):
        return get_database()

    async def get(
        self, connector: str, local_type: str, local_id: str
    ) -> Optional[dict]:
        """Return the link for a local object on a connector, or ``None``."""
        if not connector or not local_type or not local_id:
            return None
        row = await self._db().fetch_one(
            "SELECT * FROM integration_link "
            "WHERE connector = ? AND local_type = ? AND local_id = ?",
            [connector, local_type, local_id],
        )
        return _row_to_link(row) if row else None

    async def list_for_local(self, local_type: str, local_id: str) -> list[dict]:
        """Return every connector link for one local object (all platforms)."""
        if not local_type or not local_id:
            return []
        rows = await self._db().fetch_all(
            "SELECT * FROM integration_link WHERE local_type = ? AND local_id = ? "
            "ORDER BY connector ASC",
            [local_type, local_id],
        )
        return [_row_to_link(r) for r in rows]

    async def upsert(
        self,
        *,
        connector: str,
        local_type: str,
        local_id: str,
        remote_id: str,
        remote_url: str = "",
        etag: str = "",
    ) -> dict:
        """Create or update the link for a local object. Returns the stored link."""
        if not connector or not local_type or not local_id:
            raise ValueError("connector, local_type and local_id are required")
        if local_type not in LINK_TYPES:
            raise ValueError(f"invalid local_type: {local_type}")

        now = _iso_now()
        existing = await self.get(connector, local_type, local_id)
        if existing is None:
            await self._db().execute(
                "INSERT INTO integration_link "
                "(connector, local_type, local_id, remote_id, remote_url, "
                "last_synced_at, etag) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [connector, local_type, local_id, remote_id, remote_url, now, etag],
            )
        else:
            await self._db().execute(
                "UPDATE integration_link SET remote_id = ?, remote_url = ?, "
                "last_synced_at = ?, etag = ? "
                "WHERE connector = ? AND local_type = ? AND local_id = ?",
                [remote_id, remote_url, now, etag, connector, local_type, local_id],
            )
        stored = await self.get(connector, local_type, local_id)
        if stored is None:  # pragma: no cover — write-then-read is authoritative
            raise RuntimeError("integration link upsert failed")
        return stored

    async def set_reconcile(
        self,
        *,
        connector: str,
        local_type: str,
        local_id: str,
        reconcile_state: str,
        last_remote_update: Optional[str] = None,
    ) -> Optional[dict]:
        """Record the outcome of an inbound reconcile on an existing link.

        Stamps ``last_reconciled_at`` to now and sets ``reconcile_state`` (one of
        :data:`RECONCILE_STATES`). ``last_remote_update`` — the remote-reported
        "last modified" marker from the read that drove this reconcile — is
        persisted only when provided (a ``None`` leaves the stored value intact so
        a conflict/pending update does not erase the last good marker).

        Returns the updated link, or ``None`` if no link exists for the triple
        (reconcile only ever runs against an already-pushed object, so a missing
        link is a no-op rather than an error).
        """
        if not connector or not local_type or not local_id:
            return None
        if reconcile_state not in RECONCILE_STATES:
            raise ValueError(f"invalid reconcile_state: {reconcile_state}")
        existing = await self.get(connector, local_type, local_id)
        if existing is None:
            return None

        now = _iso_now()
        if last_remote_update is not None:
            await self._db().execute(
                "UPDATE integration_link SET reconcile_state = ?, "
                "last_reconciled_at = ?, last_remote_update = ? "
                "WHERE connector = ? AND local_type = ? AND local_id = ?",
                [
                    reconcile_state, now, last_remote_update,
                    connector, local_type, local_id,
                ],
            )
        else:
            await self._db().execute(
                "UPDATE integration_link SET reconcile_state = ?, "
                "last_reconciled_at = ? "
                "WHERE connector = ? AND local_type = ? AND local_id = ?",
                [reconcile_state, now, connector, local_type, local_id],
            )
        return await self.get(connector, local_type, local_id)

    async def delete(self, connector: str, local_type: str, local_id: str) -> bool:
        """Remove a link. Returns ``True`` if a row was deleted."""
        if not connector or not local_type or not local_id:
            return False
        existing = await self.get(connector, local_type, local_id)
        if existing is None:
            return False
        await self._db().execute(
            "DELETE FROM integration_link "
            "WHERE connector = ? AND local_type = ? AND local_id = ?",
            [connector, local_type, local_id],
        )
        return True


_store: Optional[IntegrationLinkStore] = None


def get_integration_link_store() -> IntegrationLinkStore:
    """Return the process-wide :class:`IntegrationLinkStore` singleton."""
    global _store
    if _store is None:
        _store = IntegrationLinkStore()
    return _store
