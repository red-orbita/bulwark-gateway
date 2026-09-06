"""
GA Guard Lite — remote classifier sidecar client.

A thin, dependency-light INPUT scanner that delegates prompt-injection /
jailbreak / harmful-content classification to an operator-provisioned *sidecar*
HTTP service (e.g. a vLLM or Hugging Face text-classification server running the
General Analysis "GA Guard" model, or any compatible classifier). Bulwark does
NOT bundle the model or run ONNX locally for this scanner — it POSTs the user
input to the sidecar and folds the returned score into a Bulwark verdict.

Rationale (pfSense model): rather than compete on "who ships the best classifier
weights", Bulwark co-opts best-of-breed detectors as pluggable engines. The
sidecar is:

  - INERT by default. ``BULWARK_GA_GUARD_ENABLED=false`` means the scanner is
    never even registered (see src/main.py) — zero hot-path cost.
  - ASYNC (WARN-only) by default. ``BULWARK_GA_GUARD_BLOCKING=false`` runs it as
    INPUT_ASYNC enrichment so an augmentation hiccup can never gate traffic. Set
    ``BULWARK_GA_GUARD_BLOCKING=true`` to promote it to INPUT_BLOCKING.
  - Fail-OPEN at request time. The builtin regex floor already runs BLOCKING; a
    transient sidecar outage must not turn every request into a 403 (an
    attacker could DoS the sidecar to fail the whole gateway closed). So a
    network/timeout/parse error in ``scan()`` degrades to ALLOW — even in
    blocking mode — and is logged, never raised.
  - Fail-CLOSED at BOOT for readiness only. If blocking is on and the sidecar is
    unreachable at startup, ``health()`` reports False so the standard
    ``resolve_blocking_readiness`` backstop makes an explicit BULWARK_FAIL_MODE
    decision (refuse to start vs. disable + serve on the regex floor).

Sidecar contract (deliberately tolerant):

    POST {ga_guard_url}
      { "input": "<user text>", "request_id": "...", "tenant": "..." }
    → 200 { "flagged": bool, "score": 0.0..1.0,
            "categories": ["prompt_injection", ...], "reason": "..." }

``score`` absent but ``flagged=true`` is treated as 1.0. Unknown/absent
categories map to PROMPT_INJECTION. Any non-2xx or malformed body → ALLOW.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from src.config import settings
from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.protocol import (
    InputScanner,
    MaturityTier,
    ScanContext,
    ScannerInfo,
    ScannerType,
)

logger = logging.getLogger(__name__)

# Map sidecar category strings → Bulwark ThreatCategory. Unknown/absent → default.
_CATEGORY_MAP: dict[str, ThreatCategory] = {
    "prompt_injection": ThreatCategory.PROMPT_INJECTION,
    "injection": ThreatCategory.PROMPT_INJECTION,
    "prompt-injection": ThreatCategory.PROMPT_INJECTION,
    "jailbreak": ThreatCategory.JAILBREAK,
    "exfiltration": ThreatCategory.EXFILTRATION,
    "data_exfiltration": ThreatCategory.EXFILTRATION,
    "credential_access": ThreatCategory.CREDENTIAL_ACCESS,
    "tool_abuse": ThreatCategory.TOOL_ABUSE,
    "policy_violation": ThreatCategory.POLICY_VIOLATION,
    "pii": ThreatCategory.PII_LEAK,
    "pii_leak": ThreatCategory.PII_LEAK,
}
_DEFAULT_CATEGORY = ThreatCategory.PROMPT_INJECTION


class GaGuardScanner(InputScanner):
    """Remote classifier-sidecar input scanner (GA Guard Lite).

    Configuration (all ``BULWARK_GA_GUARD_*``):
      - ``ENABLED``          master switch (registration gate, default false)
      - ``URL``              sidecar endpoint (POST target)
      - ``BLOCKING``         run in the hot path and BLOCK (default false → WARN)
      - ``BLOCK_THRESHOLD``  score at/above which to BLOCK (default 0.85)
      - ``WARN_THRESHOLD``   score at/above which to WARN (default 0.6)
      - ``TIMEOUT_MS``       per-request budget (default 4000)
      - ``API_KEY`` (+_FILE) optional bearer for the sidecar
      - ``VERIFY_TLS``       verify the sidecar's TLS cert (default true)
    """

    def __init__(
        self,
        *,
        url: str | None = None,
        blocking: bool | None = None,
        block_threshold: float | None = None,
        warn_threshold: float | None = None,
        timeout_ms: int | None = None,
        api_key: str | None = None,
        verify_tls: bool | None = None,
    ) -> None:
        self._url = (url if url is not None else settings.ga_guard_url).strip()
        self._blocking = blocking if blocking is not None else settings.ga_guard_blocking
        self._block_threshold = (
            block_threshold if block_threshold is not None else settings.ga_guard_block_threshold
        )
        self._warn_threshold = (
            warn_threshold if warn_threshold is not None else settings.ga_guard_warn_threshold
        )
        self._timeout_ms = timeout_ms if timeout_ms is not None else settings.ga_guard_timeout_ms
        self._api_key = api_key if api_key is not None else settings.ga_guard_api_key
        self._verify_tls = verify_tls if verify_tls is not None else settings.ga_guard_verify_tls
        self._client: httpx.AsyncClient | None = None
        # Boot-time reachability, only consulted for readiness in blocking mode.
        self._reachable = False

    @property
    def info(self) -> ScannerInfo:
        scanner_type = (
            ScannerType.INPUT_BLOCKING if self._blocking else ScannerType.INPUT_ASYNC
        )
        return ScannerInfo(
            name="ga_guard",
            version="1.0.0",
            scanner_type=scanner_type,
            description="Remote classifier-sidecar input scanner (GA Guard Lite)",
            maturity=MaturityTier.BETA,
            author="bulwark",
            priority=25,  # After regex floor (10) / ML injection (20) if blocking
        )

    def _build_client(self) -> httpx.AsyncClient:
        headers = {"content-type": "application/json"}
        if self._api_key:
            headers["authorization"] = f"Bearer {self._api_key}"
        return httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout_ms / 1000.0),
            verify=self._verify_tls,
            headers=headers,
        )

    async def startup(self) -> None:
        """Create the HTTP client and, in blocking mode, probe the sidecar.

        The probe only sets ``self._reachable`` for the readiness backstop; a
        failed probe never raises (a slow/absent sidecar is a BULWARK_FAIL_MODE
        decision made by resolve_blocking_readiness, not a startup crash).
        """
        if not settings.ga_guard_enabled:
            logger.info("ga_guard_skipped", extra={"reason": "BULWARK_GA_GUARD_ENABLED=false"})
            return
        if not self._url:
            logger.warning("ga_guard_no_url", extra={"reason": "BULWARK_GA_GUARD_URL unset"})
            return

        self._client = self._build_client()

        if not self._blocking:
            # Async/advisory: readiness never gates traffic, so skip the probe.
            self._reachable = True
            logger.info("ga_guard_ready", extra={"mode": "async", "url": self._url})
            return

        # Blocking mode: verify the sidecar answers before we let it gate traffic.
        try:
            resp = await self._client.post(
                self._url,
                json={"input": "healthcheck", "request_id": "startup-probe", "tenant": "system"},
            )
            # Any HTTP response (even non-2xx) means the sidecar is up.
            self._reachable = resp.status_code < 500
        except Exception as e:  # noqa: BLE001 — probe is best-effort; readiness is decided by the backstop
            self._reachable = False
            logger.warning(
                "ga_guard_probe_failed",
                extra={"url": self._url, "error": str(e)[:200]},
            )
        else:
            logger.info(
                "ga_guard_ready",
                extra={"mode": "blocking", "url": self._url, "reachable": self._reachable},
            )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Classify input via the sidecar. Fail-OPEN (ALLOW) on any error."""
        if not settings.ga_guard_enabled or not self._url:
            return GuardrailResult(verdict=Verdict.ALLOW)

        if self._client is None:
            self._client = self._build_client()

        try:
            resp = await self._client.post(
                self._url,
                json={
                    "input": content,
                    "request_id": context.request_id,
                    "tenant": context.tenant_id,
                },
            )
            if resp.status_code >= 400:
                logger.warning(
                    "ga_guard_bad_status",
                    extra={"status": resp.status_code, "request_id": context.request_id},
                )
                return GuardrailResult(verdict=Verdict.ALLOW)
            body = resp.json()
        except Exception as e:  # noqa: BLE001 — fail-OPEN: sidecar hiccup must never gate the request
            # The regex floor already ran BLOCKING; degrade to ALLOW rather than
            # let a transient sidecar outage 403 every request (or be weaponised
            # as a DoS to fail the gateway closed). Never propagate to safe_scan.
            logger.warning(
                "ga_guard_request_failed",
                extra={"url": self._url, "error": str(e)[:200], "request_id": context.request_id},
            )
            return GuardrailResult(verdict=Verdict.ALLOW)

        return self._verdict_from_body(body, context)

    def _verdict_from_body(self, body: Any, context: ScanContext) -> GuardrailResult:
        """Fold a tolerant sidecar response into a Bulwark verdict."""
        if not isinstance(body, dict):
            return GuardrailResult(verdict=Verdict.ALLOW)

        flagged = bool(body.get("flagged", False))
        raw_score = body.get("score")
        try:
            score = float(raw_score) if raw_score is not None else (1.0 if flagged else 0.0)
        except (TypeError, ValueError):
            score = 1.0 if flagged else 0.0
        score = max(0.0, min(1.0, score))

        category = self._map_category(body.get("categories"))
        reason = str(body.get("reason") or "").strip()[:300]

        if score >= self._block_threshold:
            verdict = Verdict.BLOCK if self._blocking else Verdict.WARN
            severity = "high"
        elif score >= self._warn_threshold:
            verdict = Verdict.WARN
            severity = "medium"
        else:
            return GuardrailResult(verdict=Verdict.ALLOW)

        desc = (
            f"GA Guard sidecar flagged input (score: {score:.3f}"
            + (f", {reason}" if reason else "")
            + ")"
        )
        return GuardrailResult(
            verdict=verdict,
            events=[
                SecurityEvent(
                    tenant_id=context.tenant_id,
                    agent_id=context.agent_id,
                    verdict=verdict,
                    category=category,
                    description=desc,
                    source="ga_guard",
                    severity=severity,
                    metadata={
                        "ga_guard_score": score,
                        "block_threshold": self._block_threshold,
                        "warn_threshold": self._warn_threshold,
                        "blocking": self._blocking,
                    },
                )
            ],
        )

    @staticmethod
    def _map_category(categories: Any) -> ThreatCategory:
        """First recognised sidecar category → ThreatCategory, else default."""
        if isinstance(categories, list):
            for c in categories:
                mapped = _CATEGORY_MAP.get(str(c).strip().lower())
                if mapped is not None:
                    return mapped
        elif isinstance(categories, str):
            mapped = _CATEGORY_MAP.get(categories.strip().lower())
            if mapped is not None:
                return mapped
        return _DEFAULT_CATEGORY

    async def health(self) -> bool:
        """Healthy unless blocking + sidecar was unreachable at boot.

        Async/advisory mode (or disabled) is always a valid state — it never
        gates traffic. Only a BLOCKING scanner with an unreachable sidecar is
        reported unhealthy, so the readiness backstop can make the
        BULWARK_FAIL_MODE decision at startup.
        """
        if not settings.ga_guard_enabled:
            return True
        if not self._blocking:
            return True
        return self._reachable

    async def shutdown(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
