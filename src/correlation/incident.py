"""Input↔output correlation and the correlated :class:`Incident`.

This is Bulwark's inline differentiator: because the gateway sees a request's
**input** and its **output** in the same process, it can confirm that a
*suspicious-but-allowed* input actually produced a *sensitive* output — the
signature of a working prompt-injection / exfiltration — and act on it before the
response ships.

What this does **not** try to be: a cross-request, cross-tenant, or forensic
correlation engine. Those live in the SIEM (events are exported in ECS). Here we
only implement the synchronous, same-request correlation that requires inline
enforcement.

Flow (see :meth:`InputOutputCorrelator.evaluate`):

1. The INPUT guardrail flagged a *suspicious* category but allowed the request
   through (ALLOW/WARN) — e.g. a prompt-injection attempt that wasn't
   individually block-worthy.
2. The OUTPUT filter then detected *sensitive* material in the response — e.g. a
   credential or PII leak.
3. Within a tight time window that pairing confirms exfiltration: emit a
   correlated :class:`Incident`, elevate the origin's risk state, and (when
   ``correlation_blocking`` is on) BLOCK the leaking response.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Iterable, Optional

import structlog
from pydantic import Field

from src.correlation.risk_state import get_risk_state_store
from src.models import SecurityEvent, StrictModel, ThreatCategory, Verdict

logger = structlog.get_logger()

# INPUT categories that, when allowed through, are suspicious enough that a
# subsequent sensitive OUTPUT confirms an exfiltration/injection succeeded.
_SUSPICIOUS_INPUT: frozenset[ThreatCategory] = frozenset({
    ThreatCategory.PROMPT_INJECTION,
    ThreatCategory.JAILBREAK,
    ThreatCategory.EXFILTRATION,
    ThreatCategory.TOOL_ABUSE,
    ThreatCategory.EXCESSIVE_AGENCY,
    ThreatCategory.CROSS_AGENT_INJECTION,
    ThreatCategory.MEMORY_MANIPULATION,
})

# OUTPUT categories that represent sensitive material leaving the gateway.
_SENSITIVE_OUTPUT: frozenset[ThreatCategory] = frozenset({
    ThreatCategory.PII_LEAK,
    ThreatCategory.CREDENTIAL_ACCESS,
    ThreatCategory.EXFILTRATION,
    ThreatCategory.INSECURE_OUTPUT,
    ThreatCategory.MODEL_THEFT,
    ThreatCategory.PRIVACY_ATTACK,
})

# Output categories severe enough to make a confirmed correlation critical.
_CRITICAL_OUTPUT: frozenset[ThreatCategory] = frozenset({
    ThreatCategory.CREDENTIAL_ACCESS,
    ThreatCategory.MODEL_THEFT,
})

# Risk bumps applied to the origin on a confirmed correlation. Session (per
# tenant+agent) carries the most weight; the content fingerprint and tenant get
# smaller bumps so a single origin escalates faster than a whole tenant.
_RISK_BUMP_SESSION = 4.0
_RISK_BUMP_INPUT = 3.0
_RISK_BUMP_TENANT = 1.5


class Incident(StrictModel):
    """A correlated security incident linking an input signal to an output leak.

    Materialised as a first-class object for explainability: it records *which*
    input categories and *which* output categories were paired, the resulting
    origin risk score, and enough identity to trace the chain. It is surfaced to
    the SIEM / events viewer via :meth:`to_security_event` (Phase 1 does not add a
    dedicated ``correlation_incidents`` table — that is Phase 3).
    """

    incident_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    kind: str = "input_output_exfiltration"
    tenant_id: str
    agent_id: str
    verdict: Verdict
    severity: str
    description: str
    input_categories: list[str] = Field(default_factory=list)
    output_categories: list[str] = Field(default_factory=list)
    input_hash: str | None = None
    request_id: str | None = None
    risk_score: float = 0.0

    def to_security_event(self) -> SecurityEvent:
        """Render the incident as a SecurityEvent for logging / SIEM export.

        Category is EXFILTRATION — the confirmed *outcome* — while the paired
        input/output categories and the risk score are carried in ``metadata`` so
        an analyst can reconstruct the chain without a separate lookup.
        """
        return SecurityEvent(
            tenant_id=self.tenant_id,
            agent_id=self.agent_id,
            verdict=self.verdict,
            category=ThreatCategory.EXFILTRATION,
            description=self.description,
            source="correlation_engine",
            severity=self.severity,
            request_id=self.request_id,
            metadata={
                "correlation": True,
                "incident_id": self.incident_id,
                "kind": self.kind,
                "input_categories": self.input_categories,
                "output_categories": self.output_categories,
                "input_hash": self.input_hash or "",
                "risk_score": round(self.risk_score, 2),
            },
        )


def _categories(events: Iterable[SecurityEvent], allowed: frozenset[ThreatCategory]) -> set[ThreatCategory]:
    """Collect the subset of event categories that fall in ``allowed``."""
    out: set[ThreatCategory] = set()
    for e in events:
        cat = getattr(e, "category", None)
        if cat in allowed:
            out.add(cat)
    return out


class InputOutputCorrelator:
    """Correlate a request's suspicious INPUT with its sensitive OUTPUT.

    Stateless w.r.t. requests; all cross-request memory lives in the shared
    :class:`~src.correlation.risk_state.RiskStateStore`. Configuration is read
    from ``settings`` lazily so admin/runtime changes take effect without
    re-instantiation.
    """

    def __init__(self):
        self._risk = get_risk_state_store()

    def _cfg(self):
        from src.config import settings

        return settings

    def evaluate(
        self,
        *,
        input_events: Iterable[SecurityEvent],
        output_events: Iterable[SecurityEvent],
        tenant_id: str,
        agent_id: str,
        input_hash: str | None = None,
        request_id: str | None = None,
        input_detected_at: float | None = None,
    ) -> Optional[Incident]:
        """Return an :class:`Incident` when input↔output exfiltration is confirmed.

        Returns ``None`` when correlation is disabled, when either side is absent,
        or when the input/output pairing falls outside the correlation window.
        Never raises — correlation must never break the response path.
        """
        cfg = self._cfg()
        if not getattr(cfg, "correlation_enabled", False):
            return None

        try:
            in_cats = _categories(input_events, _SUSPICIOUS_INPUT)
            out_cats = _categories(output_events, _SENSITIVE_OUTPUT)
            if not in_cats or not out_cats:
                return None

            # Window guard: input↔output is same-request/synchronous, so this only
            # rejects pathological clock skew or mis-wired async ordering.
            window = float(getattr(cfg, "correlation_window_seconds", 30.0))
            if input_detected_at is not None and (time.time() - input_detected_at) > window:
                return None

            blocking = bool(getattr(cfg, "correlation_blocking", False))
            verdict = Verdict.BLOCK if blocking else Verdict.WARN
            critical = bool(out_cats & _CRITICAL_OUTPUT)
            severity = "critical" if critical else "high"

            # Elevate the origin's risk state. The session (tenant+agent) is the
            # primary origin; the content hash and tenant get smaller bumps.
            if input_hash:
                self._risk.bump("input", input_hash, _RISK_BUMP_INPUT)
            risk_score = self._risk.bump("session", f"{tenant_id}:{agent_id}", _RISK_BUMP_SESSION)
            self._risk.bump("tenant", tenant_id, _RISK_BUMP_TENANT)

            in_desc = ", ".join(sorted(c.value for c in in_cats))
            out_desc = ", ".join(sorted(c.value for c in out_cats))
            action = "blocked" if blocking else "flagged"
            description = (
                f"Correlated exfiltration {action}: suspicious input ({in_desc}) "
                f"was followed by sensitive output ({out_desc}) in the same request. "
                f"Origin risk={risk_score:.1f}."
            )

            incident = Incident(
                tenant_id=tenant_id,
                agent_id=agent_id,
                verdict=verdict,
                severity=severity,
                description=description,
                input_categories=sorted(c.value for c in in_cats),
                output_categories=sorted(c.value for c in out_cats),
                input_hash=input_hash,
                request_id=request_id,
                risk_score=risk_score,
            )
            return incident
        except Exception as e:  # noqa: BLE001 - correlation must never break responses
            logger.warning("correlation_evaluate_error", error=str(e))
            return None


# Module-level singleton -----------------------------------------------------

_correlator: Optional[InputOutputCorrelator] = None


def get_correlator() -> InputOutputCorrelator:
    """Return the process-wide input↔output correlator singleton."""
    global _correlator
    if _correlator is None:
        _correlator = InputOutputCorrelator()
    return _correlator
