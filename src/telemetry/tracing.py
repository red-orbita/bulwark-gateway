"""
Sentinel Gateway — OpenTelemetry Distributed Tracing.

Provides W3C-compliant distributed tracing for the proxy request pipeline.
100% optional: if OpenTelemetry packages are not installed or tracing is disabled,
all operations become no-ops with zero overhead.

Usage:
    from src.telemetry.tracing import init_tracing, trace_span, get_tracer

    # At startup (in lifespan):
    init_tracing()

    # Decorator:
    @trace_span("sentinel.guardrail.input")
    async def scan_input(content: str, context: dict) -> GuardrailResult:
        ...

    # Context manager:
    async with trace_span("sentinel.backend.forward") as span:
        span.set_attribute("sentinel.model", model_name)
        response = await forward_request(...)
"""

from __future__ import annotations

import functools
import time
from contextlib import asynccontextmanager, contextmanager
from typing import Any, Callable, Optional, TypeVar, cast

# Lazy imports — OpenTelemetry is OPTIONAL.
# If not installed, the module provides no-op stubs with zero overhead.
try:
    from opentelemetry import trace
    from opentelemetry.context import Context
    from opentelemetry.trace import (
        NonRecordingSpan,
        Span,
        SpanKind,
        StatusCode,
        Tracer,
    )
    from opentelemetry.trace.propagation import get_current_span

    OTEL_AVAILABLE = True
except ImportError:
    trace = None  # type: ignore[assignment]
    OTEL_AVAILABLE = False

_F = TypeVar("_F", bound=Callable[..., Any])

# Module-level singleton — initialized once at startup
_tracer: Optional[Any] = None
_initialized: bool = False
_enabled: bool = False


class _NoOpSpan:
    """Zero-overhead stub when tracing is disabled or otel unavailable."""

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, status: Any, description: str | None = None) -> None:
        pass

    def record_exception(self, exception: BaseException, **kwargs: Any) -> None:
        pass

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        pass

    def end(self, end_time: int | None = None) -> None:
        pass

    def __enter__(self) -> "_NoOpSpan":
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    async def __aenter__(self) -> "_NoOpSpan":
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass


_NOOP_SPAN = _NoOpSpan()


def init_tracing() -> None:
    """Initialize OpenTelemetry tracing.

    Reads configuration from src.config.settings. Must be called once at startup.
    Safe to call even if otel packages are not installed (becomes a no-op).
    """
    global _tracer, _initialized, _enabled

    if _initialized:
        return

    _initialized = True

    from src.config import settings

    if not settings.tracing_enabled:
        _enabled = False
        return

    if not OTEL_AVAILABLE:
        import logging

        logging.getLogger(__name__).warning(
            "SENTINEL_TRACING_ENABLED=true but opentelemetry packages not installed. "
            "Install with: pip install opentelemetry-api opentelemetry-sdk "
            "opentelemetry-exporter-otlp-proto-grpc opentelemetry-exporter-zipkin"
        )
        _enabled = False
        return

    # Now do the heavy imports (only when actually needed)
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        BatchSpanProcessor,
        ConsoleSpanExporter,
        SimpleSpanProcessor,
    )
    from opentelemetry.trace.propagation import set_span_in_context

    # Build resource attributes
    resource = Resource.create(
        {
            "service.name": settings.tracing_service_name,
            "service.version": "0.4.3",
            "deployment.environment": "production" if not settings.debug else "development",
            "service.namespace": "sentinel-gateway",
        }
    )

    # Configure sampler
    sampler = _build_sampler(settings.tracing_sample_rate)

    # Create TracerProvider
    provider = TracerProvider(resource=resource, sampler=sampler)

    # Configure exporter based on setting
    exporter_type = settings.tracing_exporter.lower()

    if exporter_type == "otlp":
        processor = _build_otlp_processor(settings.tracing_endpoint)
    elif exporter_type == "zipkin":
        processor = _build_zipkin_processor(settings.tracing_endpoint)
    elif exporter_type == "console":
        processor = SimpleSpanProcessor(ConsoleSpanExporter())
    elif exporter_type == "none":
        # Provider exists (for context propagation) but no export
        processor = None
    else:
        import logging

        logging.getLogger(__name__).warning(
            f"Unknown tracing exporter '{exporter_type}', falling back to 'none'"
        )
        processor = None

    if processor is not None:
        provider.add_span_processor(processor)

    # Set as global provider
    trace.set_tracer_provider(provider)

    # Create module-level tracer singleton
    _tracer = trace.get_tracer("sentinel-gateway", "0.4.3")
    _enabled = True

    import logging

    logging.getLogger(__name__).info(
        f"OpenTelemetry tracing initialized: exporter={exporter_type}, "
        f"endpoint={settings.tracing_endpoint}, sample_rate={settings.tracing_sample_rate}"
    )


def _build_sampler(sample_rate: float) -> Any:
    """Build a TraceIdRatioBased sampler."""
    from opentelemetry.sdk.trace.sampling import (
        ALWAYS_OFF,
        ALWAYS_ON,
        TraceIdRatioBased,
    )

    if sample_rate >= 1.0:
        return ALWAYS_ON
    elif sample_rate <= 0.0:
        return ALWAYS_OFF
    else:
        return TraceIdRatioBased(sample_rate)


def _build_otlp_processor(endpoint: str) -> Any:
    """Build OTLP gRPC exporter with BatchSpanProcessor."""
    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        # Fall back to HTTP if gRPC not available
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            # HTTP uses port 4318 by default
            if ":4317" in endpoint:
                endpoint = endpoint.replace(":4317", ":4318")
        except ImportError:
            import logging

            logging.getLogger(__name__).warning(
                "OTLP exporter packages not found. Install opentelemetry-exporter-otlp-proto-grpc "
                "or opentelemetry-exporter-otlp-proto-http"
            )
            return None

    exporter = OTLPSpanExporter(endpoint=endpoint)
    return BatchSpanProcessor(
        exporter,
        max_queue_size=2048,
        max_export_batch_size=512,
        schedule_delay_millis=5000,
    )


def _build_zipkin_processor(endpoint: str) -> Any:
    """Build Zipkin exporter with BatchSpanProcessor."""
    try:
        from opentelemetry.exporter.zipkin.json import ZipkinExporter
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        import logging

        logging.getLogger(__name__).warning(
            "Zipkin exporter not found. Install opentelemetry-exporter-zipkin"
        )
        return None

    # Zipkin default endpoint
    if ":4317" in endpoint:
        endpoint = "http://localhost:9411/api/v2/spans"

    exporter = ZipkinExporter(endpoint=endpoint)
    return BatchSpanProcessor(exporter)


def get_tracer() -> Any:
    """Return the module-level tracer singleton.

    Returns a real Tracer if tracing is enabled, otherwise None.
    Callers should use trace_span() instead of this directly.
    """
    return _tracer


def shutdown_tracing() -> None:
    """Flush pending spans and shut down the tracer provider.

    Call during application shutdown to ensure all spans are exported.
    """
    global _tracer, _initialized, _enabled

    if not _enabled or not OTEL_AVAILABLE:
        return

    try:
        provider = trace.get_tracer_provider()
        if hasattr(provider, "force_flush"):
            provider.force_flush(timeout_millis=5000)
        if hasattr(provider, "shutdown"):
            provider.shutdown()
    except Exception:
        pass
    finally:
        _tracer = None
        _initialized = False
        _enabled = False


def trace_span(
    name: str,
    *,
    kind: Any = None,
    attributes: dict[str, Any] | None = None,
) -> Callable[[_F], _F] | Any:
    """Decorator and async context manager for creating trace spans.

    When tracing is disabled, this adds ZERO overhead — the function
    executes directly without any wrapping.

    As a decorator:
        @trace_span("sentinel.guardrail.input")
        async def scan_input(content: str, context: dict) -> GuardrailResult:
            ...

        @trace_span("sentinel.auth")
        def validate_token(token: str) -> dict:
            ...

    As an async context manager:
        async with trace_span("sentinel.backend.forward") as span:
            span.set_attribute("sentinel.model", model_name)
            ...

    As a sync context manager:
        with trace_span("sentinel.ioc_check") as span:
            span.set_attribute("sentinel.ioc_count", count)
            ...
    """
    # If used as a context manager (no function passed)
    if not callable(name) and not isinstance(name, str):
        raise TypeError("trace_span() requires a span name string")

    # Fast path: if tracing is disabled, return no-op
    if not _enabled or _tracer is None:
        # When used as decorator
        class _NoOpWrapper:
            """Allows trace_span to work as both decorator and context manager when disabled."""

            def __call__(self, func: _F) -> _F:
                return func

            def __enter__(self) -> _NoOpSpan:
                return _NOOP_SPAN

            def __exit__(self, *args: Any) -> None:
                pass

            async def __aenter__(self) -> _NoOpSpan:
                return _NOOP_SPAN

            async def __aexit__(self, *args: Any) -> None:
                pass

        return _NoOpWrapper()

    # Resolve span kind
    span_kind = kind if kind is not None else SpanKind.INTERNAL

    class _SpanWrapper:
        """Supports use as decorator, sync context manager, and async context manager."""

        def __call__(self, func: _F) -> _F:
            """Use as decorator."""
            if _is_async(func):

                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    with _tracer.start_as_current_span(
                        name, kind=span_kind, attributes=attributes
                    ) as span:
                        start = time.perf_counter()
                        try:
                            result = await func(*args, **kwargs)
                            span.set_status(StatusCode.OK)
                            return result
                        except Exception as exc:
                            span.set_status(StatusCode.ERROR, str(exc))
                            span.record_exception(exc)
                            raise
                        finally:
                            elapsed_ms = (time.perf_counter() - start) * 1000
                            span.set_attribute("sentinel.latency_ms", round(elapsed_ms, 2))

                return cast(_F, async_wrapper)
            else:

                @functools.wraps(func)
                def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                    with _tracer.start_as_current_span(
                        name, kind=span_kind, attributes=attributes
                    ) as span:
                        start = time.perf_counter()
                        try:
                            result = func(*args, **kwargs)
                            span.set_status(StatusCode.OK)
                            return result
                        except Exception as exc:
                            span.set_status(StatusCode.ERROR, str(exc))
                            span.record_exception(exc)
                            raise
                        finally:
                            elapsed_ms = (time.perf_counter() - start) * 1000
                            span.set_attribute("sentinel.latency_ms", round(elapsed_ms, 2))

                return cast(_F, sync_wrapper)

        def __enter__(self) -> Any:
            self._span = _tracer.start_span(name, kind=span_kind, attributes=attributes)
            self._token = trace.context_api.attach(
                trace.set_span_in_context(self._span)
            )
            self._start = time.perf_counter()
            return self._span

        def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            elapsed_ms = (time.perf_counter() - self._start) * 1000
            self._span.set_attribute("sentinel.latency_ms", round(elapsed_ms, 2))
            if exc_val is not None:
                self._span.set_status(StatusCode.ERROR, str(exc_val))
                self._span.record_exception(exc_val)
            else:
                self._span.set_status(StatusCode.OK)
            self._span.end()
            trace.context_api.detach(self._token)

        async def __aenter__(self) -> Any:
            return self.__enter__()

        async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            self.__exit__(exc_type, exc_val, exc_tb)

    return _SpanWrapper()


def create_request_span(
    *,
    tenant_id: str,
    agent_id: str,
    model: str | None = None,
    request_id: str | None = None,
) -> Any:
    """Create the root request span with standard attributes.

    Returns a span (or _NoOpSpan if tracing disabled) that callers
    should use as a context manager for the full request lifecycle.

    Usage:
        span = create_request_span(tenant_id="corp", agent_id="bot")
        with span:
            span.set_attribute("sentinel.verdict", "allow")
    """
    if not _enabled or _tracer is None:
        return _NOOP_SPAN

    attrs: dict[str, Any] = {
        "sentinel.tenant_id": tenant_id,
        "sentinel.agent_id": agent_id,
    }
    if model:
        attrs["sentinel.model"] = model
    if request_id:
        attrs["sentinel.request_id"] = request_id

    span = _tracer.start_span(
        "sentinel.request",
        kind=SpanKind.SERVER,
        attributes=attrs,
    )
    return span


def add_span_event(name: str, attributes: dict[str, Any] | None = None) -> None:
    """Add an event to the current active span (if any).

    No-op if tracing is disabled or no active span.
    """
    if not _enabled or not OTEL_AVAILABLE:
        return

    span = trace.get_current_span()
    if span and span.is_recording():
        span.add_event(name, attributes=attributes)


def set_span_attributes(attributes: dict[str, Any]) -> None:
    """Set attributes on the current active span.

    No-op if tracing is disabled or no active span.
    Useful for adding verdict/category after guardrail evaluation.
    """
    if not _enabled or not OTEL_AVAILABLE:
        return

    span = trace.get_current_span()
    if span and span.is_recording():
        for key, value in attributes.items():
            if value is not None:
                span.set_attribute(key, value)


def inject_trace_context(headers: dict[str, str]) -> dict[str, str]:
    """Inject W3C traceparent/tracestate into outgoing headers.

    Used when forwarding requests to LLM backends to propagate trace context.
    Returns the headers dict with trace context added (or unchanged if disabled).
    """
    if not _enabled or not OTEL_AVAILABLE:
        return headers

    try:
        from opentelemetry.propagators import textmap
        from opentelemetry.propagate import inject

        inject(headers)
    except Exception:
        pass

    return headers


def extract_trace_context(headers: dict[str, str]) -> Optional[Any]:
    """Extract trace context from incoming request headers.

    Used to continue a trace started by the upstream caller.
    Returns a Context object (or None if no trace context found or disabled).
    """
    if not _enabled or not OTEL_AVAILABLE:
        return None

    try:
        from opentelemetry.propagate import extract

        ctx = extract(headers)
        return ctx
    except Exception:
        return None


def _is_async(func: Callable[..., Any]) -> bool:
    """Check if a function is async (coroutine function)."""
    import asyncio
    import inspect

    return inspect.iscoroutinefunction(func) or asyncio.iscoroutinefunction(func)
