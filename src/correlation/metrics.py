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

# --- Inline-evaluation latency histogram -------------------------------------
#
# The correlation engine's whole premise is "zero cost when disabled, cheap when
# enabled". This histogram lets an operator *prove* the hot-path cost the inline
# evaluation adds (origin-risk read at PHASE 1r + input↔output correlation at
# PHASE 5c), including the Redis round-trips those paths make.
#
# It is stored in the SAME hash as the counters, under distinct field names, so a
# single ``hgetall`` fetches everything. The pieces are all monotonic counters
# (bucket counts, total count, summed microseconds) → HINCRBY deltas sum correctly
# across replicas, exactly like the other counters. Per-process gauges that cannot
# be summed (e.g. live queue depth) are still deliberately excluded; ``tap_dropped``
# already signals queue saturation replica-safely.
#
# Buckets are upper bounds in SECONDS. Chosen to straddle the expected range: a
# pure in-process assessment (tens of microseconds) through a Redis round-trip
# (~1-10 ms) up to a pathological 1 s outlier.
LATENCY_BUCKETS_SECONDS: tuple[float, ...] = (
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
)

# Hash field names for the histogram (kept in sync with the admin exposition,
# which cannot import this module — see admin/routes/health.py).
LAT_COUNT_FIELD = "eval_lat_count"        # total observations
LAT_SUM_US_FIELD = "eval_lat_sum_us"      # summed latency in integer microseconds
LAT_BUCKET_INF_FIELD = "eval_lat_bucket_inf"  # observations over the largest bound


def latency_bucket_field(le: float) -> str:
    """Hash field holding the (non-cumulative) count for the ``<= le`` bucket."""
    return f"eval_lat_bucket_{le}"


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

    def _bucket_field_for(self, seconds: float) -> str:
        """Return the histogram bucket field a ``seconds`` observation falls into."""
        for le in LATENCY_BUCKETS_SECONDS:
            if seconds <= le:
                return latency_bucket_field(le)
        return LAT_BUCKET_INF_FIELD

    def observe_latency(self, seconds: float) -> None:
        """Record one inline-evaluation latency observation (best effort, never raises).

        Increments the matching bucket, the total count, and the summed
        microseconds — all monotonic counters, so replicas sum correctly via
        HINCRBY. A Redis failure degrades to the in-process map.
        """
        if seconds < 0.0:
            seconds = 0.0
        micros = int(seconds * 1_000_000)
        bucket_field = self._bucket_field_for(seconds)
        r = self._redis()
        if r is not None:
            try:
                pipe = r.pipeline(transaction=False)
                pipe.hincrby(COUNTER_KEY, LAT_COUNT_FIELD, 1)
                pipe.hincrby(COUNTER_KEY, LAT_SUM_US_FIELD, micros)
                pipe.hincrby(COUNTER_KEY, bucket_field, 1)
                pipe.execute()
                return
            except Exception as e:  # noqa: BLE001 - degrade to in-process
                logger.warning("correlation_metrics_latency_error", error=str(e))
        with self._lock:
            self._local[LAT_COUNT_FIELD] = self._local.get(LAT_COUNT_FIELD, 0) + 1
            self._local[LAT_SUM_US_FIELD] = self._local.get(LAT_SUM_US_FIELD, 0) + micros
            self._local[bucket_field] = self._local.get(bucket_field, 0) + 1

    def latency_snapshot(self) -> dict[str, int]:
        """Return the histogram state: count, summed micros, and per-bucket counts.

        Keys: ``count``, ``sum_us``, and one entry per bucket boundary (as a float
        key) plus ``inf``. Reads Redis when available, else the in-process view.
        Never raises.
        """
        bucket_fields = {
            le: latency_bucket_field(le) for le in LATENCY_BUCKETS_SECONDS
        }
        out: dict[str, int] = {"count": 0, "sum_us": 0}
        for le in LATENCY_BUCKETS_SECONDS:
            out[str(le)] = 0
        out["inf"] = 0

        def _fill(getter) -> None:
            out["count"] = int(getter(LAT_COUNT_FIELD) or 0)
            out["sum_us"] = int(getter(LAT_SUM_US_FIELD) or 0)
            for le, field in bucket_fields.items():
                out[str(le)] = int(getter(field) or 0)
            out["inf"] = int(getter(LAT_BUCKET_INF_FIELD) or 0)

        r = self._redis()
        if r is not None:
            try:
                raw = r.hgetall(COUNTER_KEY) or {}
                _fill(lambda f: raw.get(f, 0))
                return out
            except Exception as e:  # noqa: BLE001
                logger.warning("correlation_metrics_latency_snapshot_error", error=str(e))
        with self._lock:
            _fill(lambda f: self._local.get(f, 0))
        return out

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


def observe_correlation_latency(seconds: float) -> None:
    """Convenience wrapper: record one inline-evaluation latency observation."""
    get_correlation_metrics().observe_latency(seconds)
