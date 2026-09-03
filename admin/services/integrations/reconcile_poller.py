"""Reconcile poller — periodic inbound-sync fallback (Investigation Phase 4.4).

The webhook receiver (:mod:`inbound_webhook`) is the *primary* inbound trigger, but
not every remote can push a callback (no webhook support, an egress-restricted
network, a missed delivery). This background task is the **poll fallback** from
roadmap §6.3: on a configurable interval it sweeps every enabled, sync-capable
connector's active linked cases and folds any remote workflow change back in via
:meth:`ReconcileEngine.sweep`.

It deliberately mirrors :class:`~admin.services.feed_scheduler.FeedScheduler`
(``start`` / ``stop`` / a guarded ``_loop``) rather than reusing it, because that
scheduler is IOC-feed-specific — this is the integrations domain. Everything is
fail-open: a dead remote, an unbuildable connector, or a sweep error degrades to
"nothing reconciled this cycle" and never stops the loop.

Lifespan wiring (starting/stopping this task with the admin app) is deferred to a
later slice; the class stands alone and its :meth:`poll_once` is directly callable
+ unit-testable without the loop.
"""

from __future__ import annotations

import asyncio
import logging
import os

from .reconcile import get_reconcile_engine
from .registry import get_integration_registry

logger = logging.getLogger("bulwark.reconcile_poller")

# Connector types that implement the ad-hoc ``sync_status`` inbound capability.
# (Enrichment/lookup-only types — cortex / opencti — are skipped.)
_SYNC_CAPABLE_TYPES = ("thehive", "dfir_iris")


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


class ReconcilePoller:
    """Periodically sweeps sync-capable connectors' active cases for remote changes."""

    def __init__(
        self,
        *,
        interval_seconds: float | None = None,
        sweep_limit: int | None = None,
        startup_delay_seconds: float = 15.0,
    ) -> None:
        self._interval = (
            interval_seconds
            if interval_seconds is not None
            else _env_float("BULWARK_INTEGRATION_RECONCILE_POLL_INTERVAL_SECONDS", 300.0)
        )
        self._sweep_limit = (
            sweep_limit
            if sweep_limit is not None
            else _env_int("BULWARK_INTEGRATION_RECONCILE_SWEEP_LIMIT", 200)
        )
        self._startup_delay = max(0.0, float(startup_delay_seconds))
        self._task: asyncio.Task | None = None
        self._running = False

    async def start(self) -> None:
        """Start the poll loop (idempotent)."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info(
            "Reconcile poller started (interval=%.0fs, limit=%d)",
            self._interval,
            self._sweep_limit,
        )

    async def stop(self) -> None:
        """Stop the poll loop and await task teardown."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Reconcile poller stopped")

    async def _loop(self) -> None:
        """Main loop — sweep on the configured interval until stopped."""
        await asyncio.sleep(self._startup_delay)
        while self._running:
            try:
                await self.poll_once()
            except Exception as exc:  # noqa: BLE001 — fail-open: never break the loop
                logger.warning("reconcile_poll_cycle_failed: %s", exc)
            await asyncio.sleep(max(1.0, self._interval))

    async def poll_once(self) -> int:
        """Run one sweep across every enabled, sync-capable connector.

        Returns the number of cases successfully reconciled this cycle (best-effort
        metric). Fail-open: a per-connector error is logged and skipped.
        """
        registry = get_integration_registry()
        engine = get_reconcile_engine()
        reconciled = 0
        for config in registry.configs:
            if not config.enabled or config.type not in _SYNC_CAPABLE_TYPES:
                continue
            try:
                connector = registry.build_connector(config)
            except Exception:  # noqa: BLE001 — fail-open: an unbuildable connector is skipped
                logger.warning("reconcile_poll_build_failed", exc_info=True)
                continue
            if connector is None or not callable(getattr(connector, "sync_status", None)):
                continue
            try:
                results = await engine.sweep(
                    connector=connector,
                    connector_type=config.type,
                    integration_id=config.id,
                    limit=self._sweep_limit,
                )
            except Exception:  # noqa: BLE001 — fail-open: a sweep error is one bad cycle
                logger.warning("reconcile_poll_sweep_failed", exc_info=True)
                continue
            reconciled += sum(1 for r in results if r.ok)
        return reconciled


_poller: ReconcilePoller | None = None


def get_reconcile_poller() -> ReconcilePoller:
    """Return the process-wide :class:`ReconcilePoller` singleton."""
    global _poller
    if _poller is None:
        _poller = ReconcilePoller()
    return _poller
