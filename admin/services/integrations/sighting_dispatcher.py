"""Sighting feedback dispatcher — proxy IOC matches → upstream threat-intel (Phase 5.3).

When the proxy blocks a request because its content matched an indicator from a
threat-intel feed, that block is a *sighting*: hard evidence that the indicator is
live and being exercised in this environment. Reporting it back upstream is what
turns Bulwark from a passive intel *consumer* into a contributor — a MISP sighting
or an OpenCTI ``stixSightingRelationship`` raises the indicator's local score and
feeds community detection.

This background task is the feedback loop. On a configurable interval it sweeps the
durable ``security_events`` store for freshly-blocked IOC matches
(``category=malicious_domain``, ``verdict=block``, ``source=ioc_check``), extracts
the exact ``"<type>:<value>"`` atoms the proxy stamped into ``metadata.ioc_matches``,
resolves each atom's *provenance* (which feed the indicator came from) via the IOC
store, and — only for indicators sourced from a lookup-capable platform we actually
have an enabled connector for — reports the sighting to that platform.

It deliberately mirrors :class:`~admin.services.integrations.reconcile_poller.ReconcilePoller`
(``start`` / ``stop`` / a guarded ``_loop`` + a directly-callable, unit-testable
``dispatch_once``) rather than reusing it — that poller is reconciliation-specific.

Everything is **fail-open** and off by default (``BULWARK_SIGHTING_FEEDBACK_ENABLED``):
a dead remote, an unbuildable connector, a Redis hiccup on the watermark, or a
malformed event degrades to "nothing reported this cycle" and never stops the loop
or affects the proxy hot path. A **TLP data-sharing gate** suppresses any sighting
whose indicator is marked ``TLP:RED`` (never shared to an external, shared platform).
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import deque
from typing import Optional

from .base import ConnectorError

logger = logging.getLogger("bulwark.sighting_dispatcher")

# Threat-intel platforms that (a) expose a sighting-report surface and (b) are the
# feed ``source`` string an IOCEntry carries. A block sourced from anything else
# (a static list, a manual entry, URLhaus, …) has nowhere to report a sighting.
_INTEL_SOURCES = ("opencti", "misp")

# The proxy's IOC block event shape (see src/routes/proxy.py PHASE 2).
_IOC_CATEGORY = "malicious_domain"
_IOC_SOURCE = "ioc_check"
_DESC_PREFIX = "IOC detected in input:"

# Redis key holding the high-water timestamp already swept (survives restarts).
_WATERMARK_KEY = "bulwark:sightings:watermark"

# Bound the in-memory dedupe set so a long-running process can't grow it without
# limit; a swept event older than this many recent ids may be re-reported once,
# which the upstream platforms coalesce (a sighting is idempotent-ish by design).
_SEEN_MAXLEN = 5000


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def parse_ioc_atoms(event: dict) -> list[tuple[str, str]]:
    """Extract ``(ioc_type, value)`` atoms from a proxy IOC block event (pure).

    Prefers the structured ``metadata.ioc_matches`` list the proxy stamps (each
    entry ``"<type>:<value>"``); falls back to parsing the human-readable
    ``description`` (``"IOC detected in input: url:x, ip:y"``) for older events
    that predate the metadata stamp. Deduplicates within the event and drops any
    atom with an empty value. Never raises.
    """
    raw_atoms: list[str] = []

    meta = event.get("metadata")
    if isinstance(meta, dict):
        matches = meta.get("ioc_matches")
        if isinstance(matches, (list, tuple)):
            raw_atoms.extend(str(m) for m in matches)

    if not raw_atoms:
        desc = str(event.get("description") or "")
        body = desc.split(_DESC_PREFIX, 1)[1] if _DESC_PREFIX in desc else ""
        if body:
            raw_atoms.extend(chunk for chunk in body.split(","))

    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw in raw_atoms:
        ioc_type, sep, value = str(raw).strip().partition(":")
        if not sep:
            continue
        ioc_type = ioc_type.strip().lower()
        value = value.strip()
        if not value:
            continue
        atom = (ioc_type, value)
        if atom not in seen:
            seen.add(atom)
            out.append(atom)
    return out


class _Provenance:
    """Where an IOC value came from, for sighting routing (immutable-ish)."""

    __slots__ = ("source", "tlp_red", "entry_id")

    def __init__(self, source: str, *, tlp_red: bool, entry_id: str) -> None:
        self.source = source
        self.tlp_red = tlp_red
        self.entry_id = entry_id


class SightingDispatcher:
    """Background asyncio task: durable IOC blocks → upstream sighting reports."""

    def __init__(
        self,
        *,
        enabled: Optional[bool] = None,
        interval_seconds: Optional[float] = None,
        sweep_limit: Optional[int] = None,
        max_per_sweep: Optional[int] = None,
        startup_delay_seconds: float = 20.0,
    ) -> None:
        self._enabled = (
            enabled
            if enabled is not None
            else _env_bool("BULWARK_SIGHTING_FEEDBACK_ENABLED", False)
        )
        self._interval = (
            interval_seconds
            if interval_seconds is not None
            else _env_float("BULWARK_SIGHTING_POLL_INTERVAL_SECONDS", 300.0)
        )
        self._sweep_limit = (
            sweep_limit
            if sweep_limit is not None
            else _env_int("BULWARK_SIGHTING_SWEEP_LIMIT", 200)
        )
        self._max_per_sweep = (
            max_per_sweep
            if max_per_sweep is not None
            else _env_int("BULWARK_SIGHTING_MAX_PER_SWEEP", 50)
        )
        self._startup_delay = max(0.0, float(startup_delay_seconds))
        self._task: asyncio.Task | None = None
        self._running = False
        # In-process dedupe of already-reported source events (bounded LRU).
        self._seen_event_ids: set[str] = set()
        self._seen_order: deque[str] = deque(maxlen=_SEEN_MAXLEN)
        # Observability counters for the admin status endpoint.
        self.total_reported = 0
        self.total_suppressed = 0
        self.total_failed = 0
        self.last_error: Optional[str] = None

    # ─── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the dispatch loop (idempotent). Inert when disabled."""
        if not self._enabled:
            logger.info("Sighting dispatcher disabled (BULWARK_SIGHTING_FEEDBACK_ENABLED)")
            return
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info(
            "Sighting dispatcher started (interval=%.0fs, sweep_limit=%d, max_per_sweep=%d)",
            self._interval,
            self._sweep_limit,
            self._max_per_sweep,
        )

    async def stop(self) -> None:
        """Stop the dispatch loop and await task teardown."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Sighting dispatcher stopped")

    async def _loop(self) -> None:
        """Main loop — dispatch on the configured interval until stopped."""
        await asyncio.sleep(self._startup_delay)
        while self._running:
            try:
                await self.dispatch_once()
            except Exception as exc:  # noqa: BLE001 — fail-open: never break the loop
                self.last_error = str(exc)
                logger.warning("sighting_dispatch_cycle_failed: %s", exc)
            await asyncio.sleep(max(1.0, self._interval))

    # ─── Core sweep ────────────────────────────────────────────────────────────

    async def dispatch_once(self) -> dict:
        """Run one sweep: durable IOC blocks since the watermark → sighting reports.

        Returns a per-cycle stats blob ``{scanned, reported, suppressed, skipped,
        failed, watermark}``. Fail-open throughout — a per-event/per-atom error is
        counted and skipped, never raised.
        """
        from ..security_events_store import get_security_events_store

        loop = asyncio.get_event_loop()
        watermark = await loop.run_in_executor(None, self._load_watermark)
        now = time.time()

        store = get_security_events_store()
        events = await store.query(
            category=_IOC_CATEGORY,
            verdict="block",
            since=watermark,
            until=now + 1.0,
            limit=self._sweep_limit,
        )
        # query() returns newest-first; process oldest-first so the watermark
        # advances monotonically and a mid-sweep cap leaves a clean resume point.
        events = sorted(events, key=lambda e: float(e.get("ts") or 0.0))

        stats = {"scanned": 0, "reported": 0, "suppressed": 0, "skipped": 0, "failed": 0}
        high_ts = watermark
        dispatched = 0
        capped = False

        for event in events:
            if event.get("source") != _IOC_SOURCE:
                continue
            event_id = str(event.get("event_id") or "")
            if event_id and event_id in self._seen_event_ids:
                continue
            if dispatched >= self._max_per_sweep:
                # Stop advancing the watermark past unprocessed events so the
                # remainder is picked up next sweep.
                capped = True
                break

            stats["scanned"] += 1
            atoms = parse_ioc_atoms(event)
            for ioc_type, value in atoms:
                outcome = await self._dispatch_atom(ioc_type, value, event)
                stats[outcome] = stats.get(outcome, 0) + 1

            if event_id:
                self._mark_seen(event_id)
            high_ts = max(high_ts, float(event.get("ts") or 0.0))
            dispatched += 1

        # Persist the advanced watermark (only when we didn't stop early on the cap
        # with a partial cursor — high_ts already reflects the last full event).
        if not capped and events:
            high_ts = max(high_ts, now)
        if high_ts > watermark:
            await loop.run_in_executor(None, self._save_watermark, high_ts)

        self.total_reported += stats["reported"]
        self.total_suppressed += stats["suppressed"]
        self.total_failed += stats["failed"]
        stats["watermark"] = high_ts
        self.last_error = None
        return stats

    async def _dispatch_atom(self, ioc_type: str, value: str, event: dict) -> str:
        """Report one IOC atom's sighting. Returns an outcome bucket name.

        One of ``reported`` (sent upstream), ``suppressed`` (TLP:RED / policy),
        ``skipped`` (no intel provenance or no enabled connector — nothing to do),
        or ``failed`` (a connector/transport error, audited and swallowed).
        """
        prov = self._resolve_provenance(value)
        if prov is None:
            return "skipped"
        if prov.tlp_red:
            await self._audit(
                "sighting.suppressed", prov.source, value,
                result="success", detail="TLP:RED — not shared externally",
            )
            return "suppressed"

        built = self._resolve_connector(prov.source)
        if built is None:
            return "skipped"
        connector, integration_id = built

        try:
            result = await connector.report_sighting(observable_type=ioc_type, value=value)
        except ConnectorError as exc:
            await self._audit(
                "sighting.failed", integration_id, value,
                result="failure", detail=str(exc)[:200],
            )
            return "failed"
        except Exception as exc:  # noqa: BLE001 — fail-open: an unexpected connector bug
            await self._audit(
                "sighting.failed", integration_id, value,
                result="failure", detail=str(exc)[:200],
            )
            return "failed"

        if isinstance(result, dict) and result.get("reported"):
            await self._audit(
                "sighting.reported", integration_id, value,
                result="success", detail=str(result.get("detail") or "")[:200],
            )
            return "reported"

        # The remote had nothing to sight (unknown/revoked indicator) — a benign
        # no-op, not a failure. Audited at debug granularity via the noop action.
        await self._audit(
            "sighting.noop", integration_id, value,
            result="success", detail=str((result or {}).get("detail") or "no match")[:200],
        )
        return "skipped"

    # ─── Resolution helpers ────────────────────────────────────────────────────

    def _resolve_provenance(self, value: str) -> Optional[_Provenance]:
        """Resolve which threat-intel feed an IOC value came from (best-effort).

        Matches the value against the IOC store, preferring an exact (case-
        insensitive) value hit sourced from a sighting-capable platform. Returns
        ``None`` when the value is unknown to the store or came from a source we
        can't report sightings to (a static list, manual entry, URLhaus, …).
        """
        try:
            from ..ioc_store import get_ioc_store

            entries = get_ioc_store().search(value)
        except Exception:  # noqa: BLE001 — fail-open: no store ⇒ no provenance
            return None

        needle = value.strip().lower()
        for entry in entries:
            if str(entry.value).strip().lower() != needle:
                continue
            source = str(getattr(entry, "source", "") or "").lower()
            if source not in _INTEL_SOURCES:
                continue
            tlp_red = any(str(t).strip().lower() == "tlp:red" for t in (entry.tags or []))
            return _Provenance(source, tlp_red=tlp_red, entry_id=str(entry.id))
        return None

    def _resolve_connector(self, source: str):
        """Build a lookup connector for the first enabled integration of ``source``.

        Returns ``(connector, integration_id)`` or ``None`` when no enabled
        integration of that platform type is configured/buildable.
        """
        try:
            from .registry import get_integration_registry

            registry = get_integration_registry()
        except Exception:  # noqa: BLE001 — fail-open
            return None

        for config in registry.configs:
            if not config.enabled or config.type != source:
                continue
            try:
                connector = registry.build_lookup_connector(config)
            except Exception:  # noqa: BLE001 — fail-open: an unbuildable connector is skipped
                logger.warning("sighting_connector_build_failed", exc_info=True)
                continue
            if connector is not None and callable(getattr(connector, "report_sighting", None)):
                return connector, config.id
        return None

    # ─── Watermark (Redis, best-effort) ────────────────────────────────────────

    def _load_watermark(self) -> float:
        """Read the swept-high-water ts from Redis (SYNC — run in an executor).

        On first run (no key) or any Redis error, anchor to *now* and persist it,
        so the dispatcher never replays the entire history of blocks on cold start.
        """
        try:
            from ..redis_sync import get_redis_client

            client = get_redis_client(timeout=2.0)
            if client is not None:
                raw = client.get(_WATERMARK_KEY)
                if raw is not None:
                    return float(raw)
        except Exception as exc:  # noqa: BLE001 — fail-open: fall through to anchor-now
            logger.debug("sighting_watermark_load_failed: %s", exc)
        now = time.time()
        self._save_watermark(now)
        return now

    def _save_watermark(self, ts: float) -> None:
        """Persist the swept-high-water ts to Redis (SYNC — run in an executor)."""
        try:
            from ..redis_sync import get_redis_client

            client = get_redis_client(timeout=2.0)
            if client is not None:
                client.set(_WATERMARK_KEY, repr(float(ts)))
        except Exception as exc:  # noqa: BLE001 — fail-open: a watermark write is advisory
            logger.debug("sighting_watermark_save_failed: %s", exc)

    # ─── Dedupe + audit ────────────────────────────────────────────────────────

    def _mark_seen(self, event_id: str) -> None:
        """Record an event id in the bounded LRU dedupe set."""
        if event_id in self._seen_event_ids:
            return
        # deque(maxlen) drops its left item on append once full; evict the same
        # id from the mirror set first so the two stay consistent.
        if len(self._seen_order) == self._seen_order.maxlen:
            self._seen_event_ids.discard(self._seen_order[0])
        self._seen_order.append(event_id)
        self._seen_event_ids.add(event_id)

    async def _audit(
        self, action: str, integration_id: str, value: str, *, result: str, detail: str
    ) -> None:
        """Write a best-effort audit record for a sighting outcome."""
        try:
            from ..audit_logger import get_audit_logger

            await get_audit_logger().log(
                actor="system:sighting-dispatcher",
                action=action,
                resource_type="integration",
                resource_id=integration_id or "unknown",
                details=f"{value[:120]} — {detail}",
                result=result,
            )
        except Exception as exc:  # noqa: BLE001 — fail-open: audit must never break dispatch
            logger.debug("sighting_audit_failed: %s", exc)

    # ─── Status ────────────────────────────────────────────────────────────────

    def status(self) -> dict:
        """Return an observability snapshot for the admin status endpoint."""
        return {
            "enabled": self._enabled,
            "running": self._running,
            "interval_seconds": self._interval,
            "sweep_limit": self._sweep_limit,
            "max_per_sweep": self._max_per_sweep,
            "total_reported": self.total_reported,
            "total_suppressed": self.total_suppressed,
            "total_failed": self.total_failed,
            "last_error": self.last_error,
        }


_dispatcher: SightingDispatcher | None = None


def get_sighting_dispatcher() -> SightingDispatcher:
    """Return the process-wide :class:`SightingDispatcher` singleton."""
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = SightingDispatcher()
    return _dispatcher
