"""Outbound case-management integrations for the Investigation Center (Phase 1).

This package turns a Bulwark investigation case into a *pushed* record on an
external SOC platform (TheHive 5, DFIR-IRIS). Everything here is **outbound and
fail-open**: a connector error is retried, audited and surfaced in the health
panel, but it never blocks the admin UI or the underlying case store. Connectors
live only in ``admin/`` (the proxy hot-path has no need of them); they reuse the
shared :class:`~src.telemetry.exporter.CircuitBreaker` for backpressure.

Public surface:

* :class:`~admin.services.integrations.base.Connector` — the connector protocol.
* :class:`~admin.services.integrations.base.PushResult` — the result of a push.
* :class:`~admin.services.integrations.base.ConnectorError` — retryable failure.
* :func:`~admin.services.integrations.registry.get_integration_registry` — the
  singleton registry (config load, secrets, health cache, factory).
"""

from __future__ import annotations

from .base import Connector, ConnectorError, ConnectorHealth, PushResult

__all__ = ["Connector", "ConnectorError", "ConnectorHealth", "PushResult"]
