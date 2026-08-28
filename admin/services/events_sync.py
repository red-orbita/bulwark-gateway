"""Security Events sync — drain the Redis live buffer into the durable store.

The proxy writes a *capped live buffer* to Redis (``bulwark:recent_blocks:*`` and
``bulwark:recent_allowed:*``) on the hot path — O(1), no time logic. This
background task periodically:

1. Reads both feeds from Redis (sync redis-py, so run in an executor),
2. Normalises each entry into a durable event dict with a *stable* ``event_id``
   (so re-syncing the same buffer entry is an idempotent no-op),
3. Bulk-inserts into the ``security_events`` table (``INSERT OR IGNORE``),
4. Enforces age-based retention by pruning rows older than ``retention_days``.

Retention, the per-tenant drain cap and the sync cadence are **configurable from
the admin portal** (persisted in the ``config`` table) with env vars as the
bootstrap fallback — see ``events_settings``. Retention is SIEM-aware by default
(the durable admin store is a browsable mirror; the SIEM is the system of
record): a portal override wins, else ``BULWARK_EVENTS_RETENTION_DAYS``, else 90
days when a SIEM exporter is on / 0 (keep forever) when it is not.

The store is async (shared ``DatabaseEngine``); the Redis reads are sync and are
offloaded via ``run_in_executor`` so the event loop is never blocked.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Optional

from . import events_settings

logger = logging.getLogger("bulwark.events_sync")


def _telemetry_enabled() -> bool:
    """Whether a SIEM exporter is configured (proxy's BULWARK_TELEMETRY_ENABLED)."""
    return events_settings._telemetry_enabled()


def resolve_retention_days() -> int:
    """Resolve the effective retention window in days (0 = keep forever).

    Delegates to :mod:`events_settings`: a portal override wins, else the
    ``BULWARK_EVENTS_RETENTION_DAYS`` env var, else a SIEM-aware default
    (90 days when telemetry export is on, else 0 = unlimited).
    """
    return events_settings.effective_retention_days()


def _event_id(entry: dict) -> str:
    """Derive a stable, collision-resistant id for a Redis buffer entry.

    Prefer the proxy-stamped ``event_id`` (``_push_recent_block`` writes the
    originating :class:`SecurityEvent`'s id verbatim). Preserving it end-to-end is
    what lets a correlation incident's ``contributing_event_ids`` — captured from
    those same in-memory events — resolve to these durable rows in the
    Investigation Center drill-down. It is a uuid4 hex, so it is already stable
    and collision-resistant, and ``event_id`` is UNIQUE + ``INSERT OR IGNORE`` so
    re-syncing the same buffer entry stays idempotent.

    Fall back to a content hash of the immutable identifying fields only for
    entries that predate the stamp (or arrive from another push path without one):
    ``ts`` (a float wall-clock from the proxy) plus tenant/verdict/pattern/hash is
    unique in practice; the snippet + request_id disambiguate the rare
    same-millisecond collision.
    """
    explicit = str(entry.get("event_id") or "").strip()
    if explicit:
        return explicit
    parts = "|".join(
        str(entry.get(k, ""))
        for k in (
            "ts", "tenant", "agent", "verdict", "category",
            "pattern", "request_id", "input_hash", "snippet",
        )
    )
    return hashlib.sha256(parts.encode("utf-8", "ignore")).hexdigest()


def _normalise(entry: dict) -> Optional[dict]:
    """Convert a Redis buffer entry into a durable-store event dict."""
    if not isinstance(entry, dict):
        return None
    tenant = entry.get("tenant") or "unknown"
    verdict = entry.get("verdict") or "block"
    return {
        "event_id": _event_id(entry),
        "ts": entry.get("ts"),
        "tenant": tenant,
        "agent": entry.get("agent") or "",
        "verdict": verdict,
        "category": entry.get("category") or "",
        "severity": entry.get("severity") or "",
        "description": entry.get("description") or "",
        "source": entry.get("source") or "",
        "pattern": entry.get("pattern") or "",
        "request_id": entry.get("request_id") or "",
        "tool_name": entry.get("tool_name") or "",
        "snippet": entry.get("snippet") or "",
        "input_hash": entry.get("input_hash") or "",
        "metadata": entry.get("metadata") or {},
        # Investigation Center pivots (present only when the proxy stamped them —
        # i.e. correlation was enabled). Fall back to the correlation metadata for
        # the incident id so a confirmed incident is always joinable even if an
        # older proxy build didn't lift it to the top level.
        "incident_id": (
            entry.get("incident_id")
            or (entry.get("metadata") or {}).get("incident_id")
            or ""
        ),
        "scope_digests": entry.get("scope_digests") or [],
    }


def _drain_redis(max_items: int) -> list[dict]:
    """Read both feeds from Redis (SYNC — must run in an executor).

    Returns normalised event dicts for every buffered block/warn and allowed
    entry across all tenants. Best-effort: any Redis failure yields an empty
    list so the sync loop simply retries next tick.
    """
    try:
        from .redis_sync import (
            fetch_recent_allowed,
            fetch_recent_blocks,
            get_redis_client,
        )
    except Exception:  # pragma: no cover - import guard
        return []

    r = get_redis_client(timeout=2.0)
    if r is None:
        return []

    events: list[dict] = []
    try:
        for raw in fetch_recent_blocks(r, max_items=max_items):
            norm = _normalise(raw)
            if norm:
                events.append(norm)
        for raw in fetch_recent_allowed(r, max_items=max_items):
            norm = _normalise(raw)
            if norm:
                events.append(norm)
    except Exception as exc:  # noqa: BLE001 - best-effort drain
        logger.warning("events_sync_drain_failed: %s", exc)
    return events


class SecurityEventsSync:
    """Background asyncio task: Redis live buffer → durable ``security_events``."""

    def __init__(
        self,
        interval_seconds: Optional[float] = None,
        max_items: Optional[int] = None,
        prune_every_n: int = 20,
    ):
        self._task: asyncio.Task | None = None
        self._running = False
        # Explicit constructor args pin the value (used by tests); otherwise the
        # value is resolved dynamically from events_settings (portal/env/default)
        # on every cycle so changes made in the portal take effect live.
        self._interval_override = interval_seconds
        self._max_items_override = max_items
        # Prune is comparatively expensive; run it every N sync cycles, not each.
        self._prune_every_n = max(1, prune_every_n)
        self._cycles = 0
        # Aggregate stats for the admin status endpoint / observability.
        self.last_inserted = 0
        self.total_inserted = 0
        self.total_pruned = 0
        self.last_error: Optional[str] = None

    @property
    def _interval(self) -> float:
        if self._interval_override is not None:
            return float(self._interval_override)
        return float(events_settings.effective_sync_interval())

    @property
    def _max_items(self) -> int:
        if self._max_items_override is not None:
            return int(self._max_items_override)
        return events_settings.effective_max_items()

    async def reload(self) -> None:
        """Refresh the settings cache so portal changes apply on the next tick."""
        await events_settings.refresh_cache()

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        await events_settings.refresh_cache()
        self._task = asyncio.create_task(self._loop())
        logger.info(
            "Security events sync started (interval=%ss, retention_days=%s)",
            self._interval, resolve_retention_days(),
        )

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Security events sync stopped")

    async def _loop(self) -> None:
        # Let the app finish initialising (DB migrations, etc.) before first run.
        await asyncio.sleep(5)
        while self._running:
            try:
                await self.sync_once()
            except Exception as exc:  # noqa: BLE001 - loop must never die
                self.last_error = str(exc)
                logger.error("events_sync_cycle_error: %s", exc)
            await asyncio.sleep(self._interval)

    async def sync_once(self) -> int:
        """Run one drain→insert (+periodic prune) cycle. Returns rows inserted."""
        from .security_events_store import get_security_events_store

        # Pick up any portal changes to retention/cap/interval for this cycle.
        await events_settings.refresh_cache()

        loop = asyncio.get_event_loop()
        events = await loop.run_in_executor(None, _drain_redis, self._max_items)

        store = get_security_events_store()
        inserted = await store.bulk_insert(events) if events else 0
        self.last_inserted = inserted
        self.total_inserted += inserted

        self._cycles += 1
        if self._cycles % self._prune_every_n == 0:
            pruned = await store.prune(resolve_retention_days())
            self.total_pruned += pruned
            if pruned:
                logger.info("events_sync_pruned %d expired event(s)", pruned)

        if inserted:
            logger.debug("events_sync_inserted %d new event(s)", inserted)
        self.last_error = None
        return inserted

    def status(self) -> dict:
        return {
            "running": self._running,
            "interval_seconds": self._interval,
            "max_items": self._max_items,
            "retention_days": resolve_retention_days(),
            "siem_aware": _telemetry_enabled(),
            "last_inserted": self.last_inserted,
            "total_inserted": self.total_inserted,
            "total_pruned": self.total_pruned,
            "last_error": self.last_error,
        }


# Singleton
_sync: Optional[SecurityEventsSync] = None


def get_events_sync() -> SecurityEventsSync:
    global _sync
    if _sync is None:
        _sync = SecurityEventsSync()
    return _sync
