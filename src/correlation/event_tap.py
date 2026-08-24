"""Correlation event tap — an async bus that feeds security events into risk state.

Phase 0/1 only bumped an origin's risk score on a *confirmed* input↔output
exfiltration. That is high-precision but low-recall: an origin that fires a dozen
prompt-injection WARNs (without yet producing a sensitive output) never
accumulates risk. This tap closes that gap.

Every ``SecurityEvent`` the proxy logs is *published* to this tap fire-and-forget
(``publish`` is non-blocking — one ``put_nowait`` into a bounded queue). A single
background consumer drains the queue and folds each WARN/BLOCK event into the
shared :class:`~src.correlation.risk_state.RiskStateStore`, keyed by the event's
*origin* (session = tenant+agent, plus a smaller tenant-wide bump). Subsequent
requests read that decayed score via
:meth:`~src.correlation.incident.InputOutputCorrelator.evaluate_origin_risk` and
can be hardened.

Design guarantees:

* **Never blocks the hot path.** ``publish`` is O(1) and drops on a full queue
  (recording the drop) rather than awaiting — back-pressure must never stall a
  response. Risk accounting is best-effort telemetry, not a correctness invariant.
* **No amplification.** Events emitted *by* the correlation engine itself
  (``source == "correlation_engine"`` or ``metadata.correlation``) are skipped so
  a risk-based BLOCK cannot feed back into its own score.
* **Only suspicious signals count.** ALLOW verdicts are ignored; risk accrues from
  WARN/BLOCK, weighted by severity via the runtime config.
* **Zero cost when disabled.** The tap is only started (and only published to)
  when ``correlation_enabled`` is set.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Optional

import structlog

from src.correlation.risk_state import get_risk_state_store
from src.correlation.runtime import get_correlation_runtime

logger = structlog.get_logger()

# Bounded queue depth. Sized generously — at steady state the consumer keeps it
# near-empty; the bound only matters under a burst, where dropping excess risk
# telemetry is preferable to unbounded memory growth.
_DEFAULT_MAXSIZE = 10_000

# The tenant-wide scope accrues risk at a fraction of the session scope so a busy
# multi-tenant deployment does not escalate a whole tenant to BLOCK because of one
# noisy agent/session. Enforcement decisions key primarily on the session score.
_TENANT_SCOPE_FRACTION = 0.25


class CorrelationEventTap:
    """Async, bounded, single-consumer bus folding events into risk state."""

    def __init__(self, maxsize: int = _DEFAULT_MAXSIZE) -> None:
        self._maxsize = maxsize
        self._queue: Optional[asyncio.Queue] = None
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._risk = get_risk_state_store()
        self._runtime = get_correlation_runtime()
        # Observability counters (per-process, in-memory).
        self.published = 0
        self.dropped = 0
        self.processed = 0

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Start the background consumer. Idempotent; binds the running loop."""
        if self._running:
            return
        # Create the queue inside the running loop so it binds to the right loop.
        self._queue = asyncio.Queue(maxsize=self._maxsize)
        self._task = asyncio.create_task(self._run())
        self._running = True

    async def stop(self) -> None:
        """Stop the consumer and release the queue. Safe to call when stopped."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None
        self._queue = None

    @property
    def running(self) -> bool:
        return self._running

    # --- producer ----------------------------------------------------------

    def publish(self, event) -> None:
        """Enqueue a security event fire-and-forget. Non-blocking; never raises.

        Skips events that would double-count (correlation-engine output) or carry
        no risk signal (ALLOW). Drops (and counts) on a full queue rather than
        awaiting, so a saturated consumer can never stall the request path.
        """
        q = self._queue
        if q is None:
            return
        try:
            if getattr(event, "source", "") == "correlation_engine":
                return
            md = getattr(event, "metadata", None) or {}
            if md.get("correlation"):
                return
            verdict = event.verdict.value if getattr(event, "verdict", None) else ""
            if verdict not in ("block", "warn"):
                return
            item = (
                event.tenant_id or "",
                event.agent_id or "",
                verdict,
                event.severity or "medium",
            )
            q.put_nowait(item)
            self.published += 1
        except asyncio.QueueFull:
            self.dropped += 1
        except Exception as e:  # noqa: BLE001 - publishing must never break logging
            logger.warning("correlation_tap_publish_error", error=str(e))

    # --- consumer ----------------------------------------------------------

    async def _run(self) -> None:
        queue = self._queue
        if queue is None:  # pragma: no cover - _run is only started after the queue exists
            return
        while True:
            item = await queue.get()
            try:
                self._apply(item)
            except Exception as e:  # noqa: BLE001 - one bad item must not kill the loop
                logger.warning("correlation_tap_apply_error", error=str(e))
            finally:
                queue.task_done()

    def _bump_amount(self, verdict: str, severity: str) -> float:
        cfg = self._runtime.get()
        base = cfg.event_bump_block if verdict == "block" else cfg.event_bump_warn
        if severity == "critical":
            mult = cfg.severity_critical_mult
        elif severity == "high":
            mult = cfg.severity_high_mult
        else:
            mult = 1.0
        return base * mult

    def _apply(self, item: tuple[str, str, str, str]) -> None:
        tenant_id, agent_id, verdict, severity = item
        amount = self._bump_amount(verdict, severity)
        if amount <= 0:
            return
        if agent_id:
            self._risk.bump("session", f"{tenant_id}:{agent_id}", amount)
        if tenant_id:
            self._risk.bump("tenant", tenant_id, amount * _TENANT_SCOPE_FRACTION)
        self.processed += 1

    # --- observability -----------------------------------------------------

    def stats(self) -> dict:
        """Return per-process tap counters (published / dropped / processed)."""
        return {
            "running": self._running,
            "published": self.published,
            "dropped": self.dropped,
            "processed": self.processed,
            "queue_depth": self._queue.qsize() if self._queue is not None else 0,
        }


# Module-level singleton -----------------------------------------------------

_tap: Optional[CorrelationEventTap] = None


def get_event_tap() -> CorrelationEventTap:
    """Return the process-wide correlation event tap singleton."""
    global _tap
    if _tap is None:
        _tap = CorrelationEventTap()
    return _tap
