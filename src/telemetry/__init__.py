"""
Sentinel Gateway — Telemetry & SIEM Export Module

Architecture:
    Hot Path (proxy.py) → enqueue(event) [≤2ms, non-blocking]
                              ↓
    Background Worker → batch flush → Transport → SIEM
                              ↓ (on failure)
                         Disk Fallback → Retry with backoff

Constraints:
    - ZERO synchronous I/O in hot path
    - Enqueue overhead ≤2ms p95
    - Bounded in-memory queue (default 10,000 events)
    - Disk fallback on overflow or transport failure
    - Circuit breaker: open after 5 consecutive failures, half-open after 30s
    - Hot-reloadable YAML config per tenant
    - ECS (Elastic Common Schema) as base format
    - CEF/LEEF converters for legacy SIEMs
"""

from .schema import SecurityTelemetryEvent, TelemetryEventCategory, TelemetrySeverity
from .queue import TelemetryQueue, get_telemetry_queue
from .exporter import TelemetryExporter, get_exporter

__all__ = [
    "SecurityTelemetryEvent",
    "TelemetryEventCategory",
    "TelemetrySeverity",
    "TelemetryQueue",
    "get_telemetry_queue",
    "TelemetryExporter",
    "get_exporter",
]
