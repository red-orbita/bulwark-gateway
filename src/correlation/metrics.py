"""Correlation-engine observability counters (Redis-backed, in-memory fallback).

Phase 0–3 gave the correlation engine *behaviour* (input↔output correlation,
adaptive origin-risk enforcement) but no *observability*: an operator could not
answer "how many exfiltration incidents did we correlate today?" or "is the event
tap dropping risk telemetry under load?" without grepping logs. This module closes
that gap with a tiny, dependency-light counter surface that the admin service
renders in Prometheus exposition format (see ``admin/routes/health.py``).

Design guarantees (consistent with the rest of the correlation subsystem):

* **Zero cost when the engine is idle.** Counters are only ``record``-ed on the
  branches that actually fire — a confirmed incident or an origin-risk assessment
  (both already rare, security-significant events that do other Redis writes). The
  common ALLOW path never touches this module.
* **Replica-safe.** Every counter is an ``HINCRBY`` of a *delta* into a shared
  hash, so N proxy replicas *sum* correctly instead of clobbering each other. A
  gauge that cannot be summed across replicas (e.g. a per-process queue depth) is
  deliberately *not* stored here.
* **Never breaks the hot path.** A Redis failure degrades to a bounded in-process
  dict (useful in single-process / library mode); it never raises.
* **No connection of its own.** It borrows the already-initialised client from the
  :class:`~src.correlation.risk_state.RiskStateStore` singleton, so enabling
  metrics adds no new Redis connection.
"""

from __future__ import annotations

import threading
from typing import Optional

import structlog

from src.correlation.risk_state import get_risk_state_store

logger = structlog.get_logger()

# Single hash holding every correlation counter (mirrors the ``bulwark:usage:*``
# and ``bulwark:correlation:config`` conventions).
COUNTER_KEY = "bulwark:correlation:counters"

# Canonical field set. Kept explicit so the admin exposition can emit a stable
# zero for counters that have not fired yet (Prometheus counters should exist
# from t=0, not appear only after the first event).
FIELDS: tuple[str, ...] = (
    "incidents_total",          # confirmed input↔output exfiltration correlations
    "incidents_blocked",        # of those, verdict == BLOCK (blocking mode on)
    "origin_risk_total",        # adaptive origin-risk assessments that fired
    "origin_risk_blocked",      # of those, hardened to BLOCK
    "origin_risk_warned",       # of those, flagged WARN
    "tap_published",            # events accepted into the event-tap queue
    "tap_processed",            # events folded into risk state by the consumer
    "tap_dropped",              # events dropped on a full queue (risk telemetry loss)
)


class _CorrelationMetrics:
    """Process-wide best-effort counter sink for the correlation engine."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._local: dict[str, int] = {f: 0 for f in FIELDS}

    def _redis(self):
        # Borrow the risk store's client; it is initialised once at startup with
        # the same URL/TLS settings. None in library/no-redis mode.
        try:
            return get_risk_state_store().redis
        except Exception:  # noqa: BLE001 - never break the caller
            return None

    def record(self, field: str, amount: int = 1) -> None:
        """Increment a correlation counter by ``amount`` (best effort, never raises)."""
        if amount == 0:
            return
        r = self._redis()
        if r is not None:
            try:
                r.hincrby(COUNTER_KEY, field, amount)
                return
            except Exception as e:  # noqa: BLE001 - degrade to in-process
                logger.warning("correlation_metrics_redis_error", field=field, error=str(e))
        with self._lock:
            self._local[field] = self._local.get(field, 0) + amount

    def snapshot(self) -> dict[str, int]:
        """Return all counters (Redis if available, else the in-process view).

        Always returns the full :data:`FIELDS` set (missing counters as 0) so the
        Prometheus exposition is stable across the engine's lifetime.
        """
        out = {f: 0 for f in FIELDS}
        r = self._redis()
        if r is not None:
            try:
                raw = r.hgetall(COUNTER_KEY) or {}
                for f in FIELDS:
                    out[f] = int(raw.get(f, 0) or 0)
                return out
            except Exception as e:  # noqa: BLE001
                logger.warning("correlation_metrics_snapshot_error", error=str(e))
        with self._lock:
            for f in FIELDS:
                out[f] = int(self._local.get(f, 0))
        return out


_metrics: Optional[_CorrelationMetrics] = None


def get_correlation_metrics() -> _CorrelationMetrics:
    """Return the process-wide correlation metrics singleton."""
    global _metrics
    if _metrics is None:
        _metrics = _CorrelationMetrics()
    return _metrics


def record_correlation_metric(field: str, amount: int = 1) -> None:
    """Convenience wrapper: increment a single correlation counter (best effort)."""
    get_correlation_metrics().record(field, amount)
