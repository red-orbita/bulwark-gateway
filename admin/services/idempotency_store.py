"""Idempotency store for the inbound automation action API (Phase 3.2b).

A SOAR/playbook step that times out and is retried must not double-apply a
mutating action (open a second duplicate case, raise risk twice, promote the same
IOC repeatedly). The standard remedy is an ``Idempotency-Key`` request header: the
first request performs the work and its response is cached; any later request
carrying the same key replays that stored response instead of re-executing.

Scope model — a cached response is keyed by ``(scope, method, path, idem_key)``:

* ``scope`` is a one-way digest of the *presenting credential* (the ``Authorization``
  header), so one playbook's key can never collide with, or replay, another's — and
  the header value itself is never stored.
* ``method`` + ``path`` pin the key to a single endpoint, so reusing a key value
  against a different action is treated as a fresh request, never a false replay.

Only successful (2xx) responses are cached, so a transient failure is freely
retryable. Entries carry a hard TTL and are pruned opportunistically. Every
operation is **fail-open**: any storage error degrades to "no dedupe" (the action
still runs) rather than breaking the automation surface — consistent with the
gateway's integration failure model (the proxy hot path stays fail-closed and is
untouched by this).

Persisted in the ``automation_idempotency`` table (migration v11) via the shared
``DatabaseEngine`` so dedupe survives restarts and behaves identically on SQLite
and PostgreSQL. Timestamps are stored as epoch seconds (numeric) so TTL
comparisons are a plain backend-agnostic ``WHERE expires_at > ?``.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Optional

from .database import get_database

logger = logging.getLogger(__name__)

# Default lifetime of a cached idempotent response. 24h comfortably covers a
# retried playbook step without letting the dedupe table grow unbounded.
DEFAULT_TTL_SECONDS = 24 * 60 * 60

# Cap the stored body so a pathological response can never bloat the table. A
# larger response is simply not cached (the action still ran; a retry re-executes).
_MAX_BODY_BYTES = 256 * 1024


def caller_scope(authorization_header: Optional[str]) -> str:
    """Derive an opaque per-credential scope from the ``Authorization`` header.

    The raw header (which carries the secret key) is never stored — only its
    SHA-256. An absent header collapses to a fixed ``anon`` bucket.
    """
    if not authorization_header:
        return "anon"
    return hashlib.sha256(authorization_header.encode("utf-8")).hexdigest()


class IdempotencyStore:
    """Async cache of idempotent automation responses (fail-open)."""

    def _db(self):
        return get_database()

    async def get(
        self, scope: str, method: str, path: str, idem_key: str
    ) -> Optional[dict]:
        """Return the cached ``{status_code, response_body}`` for a key, else ``None``.

        Returns ``None`` for an unknown OR expired key, and on any storage error
        (fail-open: the caller then executes the action normally).
        """
        if not idem_key:
            return None
        try:
            row = await self._db().fetch_one(
                "SELECT status_code, response_body, expires_at FROM automation_idempotency "
                "WHERE scope = ? AND method = ? AND path = ? AND idem_key = ?",
                [scope, method, path, idem_key],
            )
        except Exception:  # noqa: BLE001 - fail-open: never break the action on a read error
            logger.debug("idempotency get failed (fail-open)", exc_info=True)
            return None
        if row is None:
            return None
        d = row.to_dict() if hasattr(row, "to_dict") else dict(row)
        expires_at = d.get("expires_at")
        if expires_at is not None and float(expires_at) <= time.time():
            return None
        return {
            "status_code": int(d.get("status_code") or 0),
            "response_body": d.get("response_body") or "",
        }

    async def put(
        self,
        scope: str,
        method: str,
        path: str,
        idem_key: str,
        status_code: int,
        response_body: str,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> bool:
        """Cache a response for a key. Returns ``True`` if stored, ``False`` otherwise.

        No-op (returns ``False``) for an empty key or an oversized body. Best-effort
        and fail-open — a storage error is swallowed so the action's own response is
        still returned to the caller unharmed.
        """
        if not idem_key:
            return False
        if len(response_body.encode("utf-8")) > _MAX_BODY_BYTES:
            return False
        now = time.time()
        expires_at = now + max(1, ttl_seconds)
        try:
            db = self._db()
            # Opportunistic prune of expired rows keeps the table bounded without a
            # separate sweeper (volume is low, so this is cheap).
            await db.execute(
                "DELETE FROM automation_idempotency WHERE expires_at <= ?", [now]
            )
            # Delete-then-insert (rather than INSERT OR REPLACE) so the composite
            # primary key is honoured identically on SQLite and PostgreSQL — the
            # engine's UPSERT translation only targets a single PK column.
            await db.execute(
                "DELETE FROM automation_idempotency "
                "WHERE scope = ? AND method = ? AND path = ? AND idem_key = ?",
                [scope, method, path, idem_key],
            )
            await db.execute(
                "INSERT INTO automation_idempotency "
                "(scope, method, path, idem_key, status_code, response_body, "
                "created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [scope, method, path, idem_key, int(status_code),
                 response_body, now, expires_at],
            )
            return True
        except Exception:  # noqa: BLE001 - fail-open: dedupe is advisory, never blocking
            logger.debug("idempotency put failed (fail-open)", exc_info=True)
            return False
