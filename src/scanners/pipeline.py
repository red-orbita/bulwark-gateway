"""
Scanner Pipeline — Orchestrates scanner execution with priority ordering.

The pipeline manages:
  1. Registration of scanners with priority ordering
  2. Blocking input/output scanners (sequential, first BLOCK wins)
  3. Async input/output scanners (parallel, fire-and-forget)
  4. Health checks and scanner lifecycle
  5. Metrics collection per scanner

Key invariant: Blocking pipeline latency is bounded by the sum of
individual scanner timeouts. Async pipeline runs concurrently with
no impact on response time.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from src.models import GuardrailResult, SecurityEvent, Verdict
from src.scanners.protocol import (
    InputScanner,
    OutputScanner,
    ScanContext,
    ScannerInfo,
    ScannerType,
)

logger = logging.getLogger(__name__)


@dataclass
class ScannerMetrics:
    """Runtime metrics for a registered scanner."""

    total_calls: int = 0
    total_blocks: int = 0
    total_warns: int = 0
    total_errors: int = 0
    total_latency_ms: float = 0.0
    last_error: str | None = None

    @property
    def avg_latency_ms(self) -> float:
        if self.total_calls == 0:
            return 0.0
        return self.total_latency_ms / self.total_calls


@dataclass
class RegisteredScanner:
    """A scanner registered in the pipeline with its metadata and metrics."""

    scanner: InputScanner | OutputScanner
    info: ScannerInfo
    priority: int
    metrics: ScannerMetrics = field(default_factory=ScannerMetrics)
    enabled: bool = True


class ScannerPipeline:
    """Orchestrates scanner execution with priority ordering.

    Scanners are organized into four lanes:
      - input_blocking:  Sequential, hot path. First BLOCK verdict stops pipeline.
      - input_async:     Parallel, fire-and-forget. Results feed enrichment DB.
      - output_blocking: Sequential, output path. Supports REDACT + BLOCK.
      - output_async:    Parallel, fire-and-forget. Output enrichment.

    Usage:
        pipeline = ScannerPipeline()
        pipeline.register(MyInputScanner())
        pipeline.register(MyOutputScanner())

        # In request handler:
        result = await pipeline.run_input_blocking(content, context)
        if result.verdict == Verdict.BLOCK:
            return 403

        # Fire-and-forget:
        asyncio.create_task(pipeline.run_input_async(content, context))
    """

    def __init__(self, default_timeout_ms: float = 5000.0) -> None:
        self._input_blocking: list[RegisteredScanner] = []
        self._input_async: list[RegisteredScanner] = []
        self._output_blocking: list[RegisteredScanner] = []
        self._output_async: list[RegisteredScanner] = []
        self._all_scanners: dict[str, RegisteredScanner] = {}
        self._default_timeout_ms = default_timeout_ms

    def register(
        self,
        scanner: InputScanner | OutputScanner,
        priority: int | None = None,
        enabled: bool = True,
    ) -> None:
        """Register a scanner in the appropriate pipeline lane.

        Args:
            scanner: Scanner instance implementing InputScanner or OutputScanner
            priority: Execution order (lower = first). Defaults to scanner's info.priority
            enabled: Whether the scanner is active
        """
        info = scanner.info
        if priority is not None:
            info.priority = priority

        registered = RegisteredScanner(
            scanner=scanner,
            info=info,
            priority=info.priority,
            enabled=enabled,
        )

        # Route to correct lane based on scanner type
        if info.scanner_type == ScannerType.INPUT_BLOCKING:
            self._input_blocking.append(registered)
            self._input_blocking.sort(key=lambda s: s.priority)
        elif info.scanner_type == ScannerType.INPUT_ASYNC:
            self._input_async.append(registered)
            self._input_async.sort(key=lambda s: s.priority)
        elif info.scanner_type == ScannerType.OUTPUT_BLOCKING:
            self._output_blocking.append(registered)
            self._output_blocking.sort(key=lambda s: s.priority)
        elif info.scanner_type == ScannerType.OUTPUT_ASYNC:
            self._output_async.append(registered)
            self._output_async.sort(key=lambda s: s.priority)

        self._all_scanners[info.name] = registered
        logger.info(
            "scanner_registered",
            extra={
                "name": info.name,
                "version": info.version,
                "type": info.scanner_type.value,
                "priority": info.priority,
                "enabled": enabled,
            },
        )

    def unregister(self, name: str) -> bool:
        """Remove a scanner by name. Returns True if found and removed."""
        if name not in self._all_scanners:
            return False

        registered = self._all_scanners.pop(name)
        for lane in (self._input_blocking, self._input_async, self._output_blocking, self._output_async):
            lane[:] = [s for s in lane if s.info.name != name]

        logger.info("scanner_unregistered", extra={"name": name})
        return True

    def enable(self, name: str) -> bool:
        """Enable a scanner by name."""
        if name in self._all_scanners:
            self._all_scanners[name].enabled = True
            return True
        return False

    def disable(self, name: str) -> bool:
        """Disable a scanner by name (keeps it registered but skips execution)."""
        if name in self._all_scanners:
            self._all_scanners[name].enabled = False
            return True
        return False

    async def run_input_blocking(
        self, content: str, context: ScanContext
    ) -> GuardrailResult:
        """Run blocking input scanners sequentially. First BLOCK wins.

        This is the HOT PATH. Total latency = sum of individual scanner times.
        Scanners are executed in priority order (lowest priority number first).

        Returns:
            Combined GuardrailResult. BLOCK stops immediately.
            WARN events are accumulated. ALLOW is default.
        """
        all_events: list[SecurityEvent] = []
        final_verdict = Verdict.ALLOW

        for registered in self._input_blocking:
            if not registered.enabled:
                continue

            start = time.perf_counter()
            result = await registered.scanner.safe_scan(
                content, context, timeout_ms=self._default_timeout_ms
            )
            elapsed_ms = (time.perf_counter() - start) * 1000

            # Update metrics
            registered.metrics.total_calls += 1
            registered.metrics.total_latency_ms += elapsed_ms

            if result.verdict == Verdict.BLOCK:
                registered.metrics.total_blocks += 1
                all_events.extend(result.events)
                return GuardrailResult(
                    verdict=Verdict.BLOCK,
                    events=all_events,
                    blocked_tools=result.blocked_tools,
                )

            if result.verdict == Verdict.WARN:
                registered.metrics.total_warns += 1
                all_events.extend(result.events)
                final_verdict = Verdict.WARN

            if result.verdict == Verdict.REDACT and result.modified_content:
                all_events.extend(result.events)
                content = result.modified_content  # Pass redacted content to next scanner

        return GuardrailResult(
            verdict=final_verdict,
            events=all_events,
            modified_content=content if final_verdict == Verdict.REDACT else None,
        )

    async def run_input_async(
        self, content: str, context: ScanContext
    ) -> list[GuardrailResult]:
        """Run async input scanners in parallel. Fire-and-forget safe.

        These scanners run AFTER the response is sent. Results are used
        for enrichment, metrics, and feedback loop (auto-regex generation).

        Never blocks the response. Never raises exceptions.
        """
        if not self._input_async:
            return []

        active = [s for s in self._input_async if s.enabled]
        if not active:
            return []

        async def _run_one(registered: RegisteredScanner) -> GuardrailResult | None:
            try:
                start = time.perf_counter()
                result = await registered.scanner.safe_scan(
                    content, context, timeout_ms=self._default_timeout_ms
                )
                elapsed_ms = (time.perf_counter() - start) * 1000
                registered.metrics.total_calls += 1
                registered.metrics.total_latency_ms += elapsed_ms
                if result.verdict == Verdict.BLOCK:
                    registered.metrics.total_blocks += 1
                elif result.verdict == Verdict.WARN:
                    registered.metrics.total_warns += 1
                return result
            except Exception as e:
                registered.metrics.total_errors += 1
                registered.metrics.last_error = str(e)[:200]
                return None

        results = await asyncio.gather(*[_run_one(s) for s in active], return_exceptions=True)
        return [r for r in results if isinstance(r, GuardrailResult)]

    async def run_output_blocking(
        self, content: str, context: ScanContext
    ) -> GuardrailResult:
        """Run blocking output scanners sequentially.

        Supports REDACT (content modification passes to next scanner)
        and BLOCK (stops pipeline, content not returned to user).
        """
        all_events: list[SecurityEvent] = []
        final_verdict = Verdict.ALLOW
        modified = content

        for registered in self._output_blocking:
            if not registered.enabled:
                continue

            start = time.perf_counter()
            result = await registered.scanner.safe_scan(
                modified, context, timeout_ms=self._default_timeout_ms
            )
            elapsed_ms = (time.perf_counter() - start) * 1000

            registered.metrics.total_calls += 1
            registered.metrics.total_latency_ms += elapsed_ms

            if result.verdict == Verdict.BLOCK:
                registered.metrics.total_blocks += 1
                all_events.extend(result.events)
                return GuardrailResult(
                    verdict=Verdict.BLOCK,
                    events=all_events,
                )

            if result.verdict == Verdict.REDACT and result.modified_content:
                modified = result.modified_content
                final_verdict = Verdict.REDACT
                all_events.extend(result.events)

            if result.verdict == Verdict.WARN:
                registered.metrics.total_warns += 1
                all_events.extend(result.events)
                if final_verdict == Verdict.ALLOW:
                    final_verdict = Verdict.WARN

        return GuardrailResult(
            verdict=final_verdict,
            events=all_events,
            modified_content=modified if final_verdict == Verdict.REDACT else None,
        )

    async def run_output_async(
        self, content: str, context: ScanContext
    ) -> list[GuardrailResult]:
        """Run async output scanners in parallel. Fire-and-forget."""
        if not self._output_async:
            return []

        active = [s for s in self._output_async if s.enabled]
        if not active:
            return []

        async def _run_one(registered: RegisteredScanner) -> GuardrailResult | None:
            try:
                start = time.perf_counter()
                result = await registered.scanner.safe_scan(
                    content, context, timeout_ms=self._default_timeout_ms
                )
                elapsed_ms = (time.perf_counter() - start) * 1000
                registered.metrics.total_calls += 1
                registered.metrics.total_latency_ms += elapsed_ms
                return result
            except Exception:
                registered.metrics.total_errors += 1
                return None

        results = await asyncio.gather(*[_run_one(s) for s in active], return_exceptions=True)
        return [r for r in results if isinstance(r, GuardrailResult)]

    # === Lifecycle ===

    async def startup(self) -> None:
        """Initialize all registered scanners."""
        for registered in self._all_scanners.values():
            try:
                await registered.scanner.startup()
                logger.info("scanner_started", extra={"name": registered.info.name})
            except Exception as e:
                logger.error(
                    "scanner_startup_failed",
                    extra={"name": registered.info.name, "error": str(e)[:200]},
                )
                registered.enabled = False

    async def shutdown(self) -> None:
        """Shutdown all registered scanners."""
        for registered in self._all_scanners.values():
            try:
                await registered.scanner.shutdown()
            except Exception as e:
                logger.warning(
                    "scanner_shutdown_error",
                    extra={"name": registered.info.name, "error": str(e)[:200]},
                )

    # === Introspection ===

    def list_scanners(self) -> list[dict[str, Any]]:
        """Return info about all registered scanners."""
        return [
            {
                "name": r.info.name,
                "version": r.info.version,
                "type": r.info.scanner_type.value,
                "priority": r.priority,
                "enabled": r.enabled,
                "description": r.info.description,
                "author": r.info.author,
                "metrics": {
                    "total_calls": r.metrics.total_calls,
                    "total_blocks": r.metrics.total_blocks,
                    "total_warns": r.metrics.total_warns,
                    "total_errors": r.metrics.total_errors,
                    "avg_latency_ms": round(r.metrics.avg_latency_ms, 2),
                },
            }
            for r in self._all_scanners.values()
        ]

    async def health_check(self) -> dict[str, bool]:
        """Run health checks on all scanners."""
        results = {}
        for name, registered in self._all_scanners.items():
            try:
                results[name] = await registered.scanner.health()
            except Exception:
                results[name] = False
        return results

    @property
    def input_blocking_count(self) -> int:
        return len([s for s in self._input_blocking if s.enabled])

    @property
    def input_async_count(self) -> int:
        return len([s for s in self._input_async if s.enabled])

    @property
    def output_blocking_count(self) -> int:
        return len([s for s in self._output_blocking if s.enabled])

    @property
    def output_async_count(self) -> int:
        return len([s for s in self._output_async if s.enabled])

    @property
    def total_count(self) -> int:
        return len(self._all_scanners)

    def apply_ml_config(self, config: dict[str, dict]) -> None:
        """Apply ML scanner config from admin (Redis-synced).

        Enables/disables ML scanners based on admin-pushed configuration.
        Only affects scanners whose names start with 'ml_'.
        """
        for name, cfg in config.items():
            # SECURITY FIX (H-09): Only allow ML config to affect ml_* scanners.
            # Prevents compromised admin from disabling regex/builtin scanners via Redis.
            if not name.startswith("ml_"):
                logger.warning("ml_config_rejected", scanner=name, reason="not_ml_prefix")
                continue
            if name not in self._all_scanners:
                continue
            registered = self._all_scanners[name]
            # Toggle enabled/disabled
            new_enabled = cfg.get("enabled", False)
            if new_enabled != registered.enabled:
                registered.enabled = new_enabled
                logger.info(
                    "ml_scanner_config_applied",
                    extra={"name": name, "enabled": new_enabled},
                )


# === Singleton ===

_pipeline: ScannerPipeline | None = None


def get_scanner_pipeline() -> ScannerPipeline:
    """Get or create the global scanner pipeline singleton."""
    global _pipeline
    if _pipeline is None:
        from src.config import settings
        # Use ml_timeout_ms for async scanner timeout (ML inference needs more time on CPU)
        timeout = max(settings.ml_timeout_ms, 5000) if settings.ml_enabled else 5000.0
        _pipeline = ScannerPipeline(default_timeout_ms=float(timeout))
    return _pipeline


def reset_scanner_pipeline() -> None:
    """Reset the global pipeline (for testing)."""
    global _pipeline
    _pipeline = None
