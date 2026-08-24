"""Correlation engine — inline, enforcement-oriented event correlation.

Bulwark's differentiator is that it sits *on the request path*, so it can do
something a SIEM cannot: correlate a request's **input** with its own **output**
synchronously and act on the result before the response leaves the gateway.

Scope (deliberately narrow):

* :mod:`src.correlation.risk_state` — a decaying, Redis-backed (in-memory
  fallback) risk score per *origin* (tenant / session / input-hash). Raising an
  origin's risk state hardens the *next* requests from that origin; it never
  retroactively rewrites a verdict that already shipped.
* :mod:`src.correlation.incident` — the :class:`InputOutputCorrelator`, which
  links a suspicious INPUT verdict to a sensitive OUTPUT detection within a tight
  time window and, on a confirmed exfiltration pattern, WARNs/BLOCKs the response
  and emits a correlated :class:`Incident` for explainability.

Everything multi-source, forensic, cross-tenant, or long-horizon is delegated to
the SIEM (events are already exported in ECS). This module only implements what
requires *inline* enforcement.
"""

from src.correlation.incident import (
    Incident,
    InputOutputCorrelator,
    get_correlator,
)
from src.correlation.risk_state import RiskStateStore, get_risk_state_store

__all__ = [
    "Incident",
    "InputOutputCorrelator",
    "RiskStateStore",
    "get_correlator",
    "get_risk_state_store",
]
