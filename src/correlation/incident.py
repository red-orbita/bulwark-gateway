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

from src.correlation.confidence import correlation_confidence
from src.correlation.risk_state import get_risk_state_store
from src.correlation.runtime import get_correlation_runtime
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

# Risk bumps applied to the origin on a confirmed correlation. The subject (the
# specific authenticated actor) and the session (per tenant+agent) carry the most
# weight; the content fingerprint and tenant get smaller bumps so a single origin
# escalates faster than a whole tenant. The subject is the primary hardening
# target (F3): risk must accumulate there because enforcement BLOCKs on it.
_RISK_BUMP_SUBJECT = 4.0
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
    # Content-corroboration confidence in [0, 1] (Phase 4b). Gates the WARN→BLOCK
    # escalation: a bare category co-occurrence scores low and stays WARN.
    confidence: float = 0.0

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
                "confidence": round(self.confidence, 2),
            },
        )


class OriginRiskAssessment(StrictModel):
    """A hardening decision derived from an origin's *accumulated* risk state.

    Unlike :class:`Incident` (which confirms a single request's input↔output
    exfiltration), this is the cross-request feedback signal: an origin whose
    decayed risk score — accrued from prior correlated incidents and WARN/BLOCK
    events via the :mod:`~src.correlation.event_tap` — has crossed a configured
    threshold. It hardens the *current* request even if that request's own input
    looked clean. WARN below the block threshold; BLOCK at/above it (and only when
    ``blocking`` is enabled).

    F3 (blast-radius): the BLOCK decision is taken on the most-specific identity —
    the ``subject`` (authenticated actor) when known, otherwise the ``session``.
    ``scope`` records which was used; ``session_score``/``tenant_score`` are
    surfaced for context. A BLOCK therefore hardens the individual actor, not
    every user that shares the agent session.
    """

    tenant_id: str
    agent_id: str
    verdict: Verdict
    score: float
    session_score: float
    tenant_score: float
    threshold: float
    reason: str
    scope: str = "session"
    request_id: str | None = None

    def to_security_event(self) -> SecurityEvent:
        """Render the assessment as a SecurityEvent for logging / SIEM export.

        Category is POLICY_VIOLATION — the request was hardened by the adaptive
        risk *policy*, not by a fresh content detection. ``metadata.correlation``
        is set so the event tap skips it (no risk-feedback amplification).
        """
        return SecurityEvent(
            tenant_id=self.tenant_id,
            agent_id=self.agent_id,
            verdict=self.verdict,
            category=ThreatCategory.POLICY_VIOLATION,
            description=self.reason,
            source="correlation_engine",
            severity="high" if self.verdict == Verdict.BLOCK else "medium",
            request_id=self.request_id,
            metadata={
                "correlation": True,
                "adaptive_enforcement": True,
                "decision_scope": self.scope,
                "origin_risk_score": round(self.score, 2),
                "origin_session_score": round(self.session_score, 2),
                "origin_tenant_score": round(self.tenant_score, 2),
                "threshold": round(self.threshold, 2),
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
        input_text: str | None = None,
        output_text: str | None = None,
        subject_id: str | None = None,
    ) -> Optional[Incident]:
        """Return an :class:`Incident` when input↔output exfiltration is confirmed.

        Returns ``None`` when correlation is disabled, when either side is absent,
        or when the input/output pairing falls outside the correlation window.
        Never raises — correlation must never break the response path.

        ``input_text``/``output_text`` (Phase 4b) supply the raw content used to
        compute a corroboration *confidence*. The WARN→BLOCK escalation requires
        that confidence to reach ``confidence_block_threshold``; without
        corroborating content a bare category co-occurrence stays WARN even when
        ``blocking`` is on, so the engine does not manufacture a false hard-block.

        ``subject_id`` (F3) is the authenticated actor. When present the confirmed
        risk is accrued primarily to the *subject* scope (the origin enforcement
        BLOCKs on) so the individual actor escalates, not the shared agent session.
        """
        # Master switch stays a process-level settings flag (the event tap is
        # started at boot); the *enforcement* knobs (window/blocking) are read
        # from the runtime config so admin overrides take effect without restart.
        if not getattr(self._cfg(), "correlation_enabled", False):
            return None

        try:
            in_cats = _categories(input_events, _SUSPICIOUS_INPUT)
            out_cats = _categories(output_events, _SENSITIVE_OUTPUT)
            if not in_cats or not out_cats:
                return None

            rc = get_correlation_runtime().get()

            # LATENT window guard (F4). This correlator is strictly *same-request*:
            # ``input_events`` and ``output_events`` come from one request, so they
            # are inherently paired and need no time window to decide the pairing.
            # The proxy therefore deliberately does NOT pass ``input_detected_at``
            # (it stays None ⇒ this branch is skipped). Wiring it naively would make
            # the window measure the backend LLM round-trip (up to the backend
            # timeout, default 120s), so any response slower than ``window_seconds``
            # would silently *skip* correlation — a false-negative. The guard is kept
            # only to reject pathological clock skew / a future async correlator that
            # explicitly supplies a timestamp; ``window_seconds`` is a reserved knob
            # (see src.correlation.runtime), not a live enforcement control.
            window = float(rc.window_seconds)
            if input_detected_at is not None and (time.time() - input_detected_at) > window:
                return None

            critical = bool(out_cats & _CRITICAL_OUTPUT)
            severity = "critical" if critical else "high"

            # Corroboration confidence gates the WARN→BLOCK escalation. Computed
            # from the paired categories plus (when available) the raw content;
            # never raises (returns 0.0 on error → the safe WARN side).
            confidence = correlation_confidence(
                input_text=input_text,
                output_text=output_text,
                critical=critical,
                paired_category_count=len(in_cats) + len(out_cats),
            )
            blocking = bool(rc.blocking)
            block = blocking and confidence >= float(rc.confidence_block_threshold)
            verdict = Verdict.BLOCK if block else Verdict.WARN

            # Elevate the origin's risk state. The subject (authenticated actor)
            # is the primary origin when known — enforcement BLOCKs on it (F3);
            # otherwise the session (tenant+agent) is the most-specific origin. The
            # content hash and tenant get smaller bumps. The incident records the
            # decision-scope score so the meter reflects what would be blocked.
            subject_score: float | None = None
            if subject_id:
                subject_score = self._risk.bump(
                    "subject", f"{tenant_id}:{subject_id}", _RISK_BUMP_SUBJECT
                )
            if input_hash:
                self._risk.bump("input", input_hash, _RISK_BUMP_INPUT)
            session_score = self._risk.bump("session", f"{tenant_id}:{agent_id}", _RISK_BUMP_SESSION)
            self._risk.bump("tenant", tenant_id, _RISK_BUMP_TENANT)
            risk_score = subject_score if subject_score is not None else session_score

            in_desc = ", ".join(sorted(c.value for c in in_cats))
            out_desc = ", ".join(sorted(c.value for c in out_cats))
            action = "blocked" if block else "flagged"
            description = (
                f"Correlated exfiltration {action}: suspicious input ({in_desc}) "
                f"was followed by sensitive output ({out_desc}) in the same request. "
                f"Confidence={confidence:.2f}, origin risk={risk_score:.1f}."
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
                confidence=confidence,
            )
            return incident
        except Exception as e:  # noqa: BLE001 - correlation must never break responses
            logger.warning("correlation_evaluate_error", error=str(e))
            return None

    def evaluate_origin_risk(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        request_id: str | None = None,
        subject_id: str | None = None,
    ) -> Optional[OriginRiskAssessment]:
        """Assess an origin's accumulated risk and return a hardening decision.

        F3 (blast-radius): the BLOCK decision is taken on the most-specific
        identity — the ``subject`` (authenticated actor) when a ``subject_id`` is
        supplied, otherwise the ``session`` (tenant+agent). The broader session and
        tenant scores are read for context and can raise a (non-blocking) WARN, but
        never a BLOCK, so one abusive actor cannot hard-block every user that shares
        the agent. All scope reads are a single round-trip.

        Returns ``None`` when the origin is below the WARN threshold. Never raises.
        """
        try:
            rc = get_correlation_runtime().get()
            # Single round-trip for every enforcement read (F2). When the actor is
            # authenticated the subject score is the decision score; otherwise the
            # session is the most-specific identity and becomes the decision score.
            if subject_id:
                subject_score, session_score, tenant_score = self._risk.get_many(
                    [
                        ("subject", f"{tenant_id}:{subject_id}"),
                        ("session", f"{tenant_id}:{agent_id}"),
                        ("tenant", tenant_id),
                    ]
                )
                decision_score = subject_score
                scope = "subject"
            else:
                session_score, tenant_score = self._risk.get_many(
                    [("session", f"{tenant_id}:{agent_id}"), ("tenant", tenant_id)]
                )
                decision_score = session_score
                scope = "session"

            if decision_score >= rc.risk_block_threshold and rc.blocking:
                return OriginRiskAssessment(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.BLOCK,
                    score=decision_score,
                    session_score=session_score,
                    tenant_score=tenant_score,
                    threshold=rc.risk_block_threshold,
                    scope=scope,
                    request_id=request_id,
                    reason=(
                        f"Adaptive enforcement: {scope} risk {decision_score:.1f} >= block "
                        f"threshold {rc.risk_block_threshold:.1f}, accumulated from "
                        f"prior correlated/suspicious activity. Request hardened to BLOCK."
                    ),
                )
            # WARN can be driven by the decision scope OR the (broader) session —
            # the session flag gives cross-actor visibility without hard-blocking.
            warn_score = max(decision_score, session_score)
            if warn_score >= rc.risk_warn_threshold:
                return OriginRiskAssessment(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.WARN,
                    score=decision_score,
                    session_score=session_score,
                    tenant_score=tenant_score,
                    threshold=rc.risk_warn_threshold,
                    scope=scope,
                    request_id=request_id,
                    reason=(
                        f"Adaptive enforcement: {scope} risk {decision_score:.1f} / "
                        f"session risk {session_score:.1f} >= warn threshold "
                        f"{rc.risk_warn_threshold:.1f}. Origin flagged as elevated."
                    ),
                )
            return None
        except Exception as e:  # noqa: BLE001 - enforcement must never break responses
            logger.warning("origin_risk_evaluate_error", error=str(e))
            return None


# Module-level singleton -----------------------------------------------------

_correlator: Optional[InputOutputCorrelator] = None


def get_correlator() -> InputOutputCorrelator:
    """Return the process-wide input↔output correlator singleton."""
    global _correlator
    if _correlator is None:
        _correlator = InputOutputCorrelator()
    return _correlator
