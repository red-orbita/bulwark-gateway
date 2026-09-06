"""Presidio-backed PII scanners for the Bulwark scanner pipeline.

Two thin scanners share one lazily-initialised ``_PresidioEngine``:

* ``PresidioOutputScanner`` (OUTPUT_BLOCKING) — detects PII in LLM responses and
  returns a ``REDACT`` verdict with the offending spans masked as
  ``[REDACTED:<ENTITY>]`` in ``modified_content``.
* ``PresidioInputScanner`` (INPUT_ASYNC) — advisory-only; emits a ``WARN`` event
  when a user message contains PII, without modifying or blocking the request.

Design contract
---------------
* **Optional dependency, fail-open.** ``presidio-analyzer`` + a spaCy model are
  an optional extra. If they are not importable the engine is *unavailable*:
  ``health()`` returns ``False``, ``scan()`` returns a clean ``ALLOW`` (no
  redaction, no crash), and a single ``critical`` log line explains why. This is
  the honest degradation for an add-on the operator chose to register but did not
  provision — never a hard pipeline failure.
* **No import-time heavy work.** Presidio/spaCy are imported lazily on first
  ``startup()``/``scan()`` so merely *discovering* the entry-point costs nothing.
* **Deterministic redaction.** Spans are spliced out right-to-left from the
  analyzer results, so offsets never shift mid-rewrite.

Configuration (environment; parsed once per process)
---------------------------------------------------
* ``BULWARK_PRESIDIO_ENTITIES``       — comma-separated Presidio entity names to
  detect (default: a conservative PII set). ``*`` / empty ⇒ all recognizers.
* ``BULWARK_PRESIDIO_SCORE_THRESHOLD`` — float 0–1 min confidence (default 0.5).
* ``BULWARK_PRESIDIO_LANGUAGE``        — analyzer language (default ``en``).
* ``BULWARK_PRESIDIO_SPACY_MODEL``     — spaCy model name (default
  ``en_core_web_lg``); only used to build the NLP engine when provisioned.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.protocol import (
    InputScanner,
    MaturityTier,
    OutputScanner,
    ScanContext,
    ScannerInfo,
    ScannerType,
)

logger = logging.getLogger("bulwark.presidio")

# Conservative default entity set — high-signal PII/identifiers. Operators can
# widen or narrow this via BULWARK_PRESIDIO_ENTITIES.
_DEFAULT_ENTITIES = (
    "CREDIT_CARD",
    "CRYPTO",
    "EMAIL_ADDRESS",
    "IBAN_CODE",
    "IP_ADDRESS",
    "LOCATION",
    "MEDICAL_LICENSE",
    "PERSON",
    "PHONE_NUMBER",
    "US_BANK_NUMBER",
    "US_PASSPORT",
    "US_SSN",
)

# Entity types severe enough to warrant a "high" severity event.
_HIGH_SEVERITY_ENTITIES = frozenset(
    {
        "CREDIT_CARD",
        "US_SSN",
        "US_BANK_NUMBER",
        "US_PASSPORT",
        "IBAN_CODE",
        "MEDICAL_LICENSE",
        "CRYPTO",
    }
)

# Cap the text we hand to the NER engine — bounds worst-case latency/memory on a
# hostile mega-response. Presidio is O(n) but spaCy is not free per token.
_MAX_ANALYZE_CHARS = 100_000


def _parse_entities() -> list[str] | None:
    """Return the configured entity allowlist, or None to mean 'all recognizers'."""
    raw = os.getenv("BULWARK_PRESIDIO_ENTITIES", "").strip()
    if not raw or raw == "*":
        if raw == "*":
            return None  # explicit "all"
        return list(_DEFAULT_ENTITIES)
    entities = [e.strip().upper() for e in raw.split(",") if e.strip()]
    return entities or list(_DEFAULT_ENTITIES)


def _parse_threshold() -> float:
    raw = os.getenv("BULWARK_PRESIDIO_SCORE_THRESHOLD", "").strip()
    if not raw:
        return 0.5
    try:
        val = float(raw)
    except ValueError:
        logger.warning("presidio_bad_threshold", extra={"value": raw[:32]})
        return 0.5
    # Clamp to [0, 1].
    return min(max(val, 0.0), 1.0)


class _PresidioEngine:
    """Lazily-initialised wrapper around Presidio's ``AnalyzerEngine``.

    Import and model load are deferred to first use and guarded by a lock so the
    (expensive) spaCy pipeline is built at most once per process. All failures
    degrade to *unavailable* rather than propagating.
    """

    _instance: _PresidioEngine | None = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        self._analyzer: Any = None
        self._available: bool | None = None  # None = not yet attempted
        self._lock = threading.Lock()
        self._logged_unavailable = False
        self.entities = _parse_entities()
        self.threshold = _parse_threshold()
        self.language = os.getenv("BULWARK_PRESIDIO_LANGUAGE", "en").strip() or "en"
        self.spacy_model = (
            os.getenv("BULWARK_PRESIDIO_SPACY_MODEL", "en_core_web_lg").strip()
            or "en_core_web_lg"
        )

    @classmethod
    def instance(cls) -> _PresidioEngine:
        """Process-wide singleton (the spaCy model is large — share it)."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _ensure_loaded(self) -> bool:
        """Build the analyzer on first use. Returns True if usable."""
        if self._available is not None:
            return self._available
        with self._lock:
            if self._available is not None:
                return self._available
            self._available = self._try_build()
            return self._available

    def _try_build(self) -> bool:
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider
        except ImportError:
            self._log_unavailable(
                "presidio-analyzer is not installed. Install the 'presidio' extra "
                "to activate the Presidio PII scanner."
            )
            return False

        try:
            provider = NlpEngineProvider(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": self.language, "model_name": self.spacy_model}],
                }
            )
            nlp_engine = provider.create_engine()
            self._analyzer = AnalyzerEngine(
                nlp_engine=nlp_engine,
                supported_languages=[self.language],
            )
            logger.info(
                "presidio_engine_ready",
                extra={
                    "language": self.language,
                    "model": self.spacy_model,
                    "entities": "all" if self.entities is None else len(self.entities),
                    "threshold": self.threshold,
                },
            )
            return True
        except Exception as exc:  # noqa: BLE001 — any load failure ⇒ inert, never crash
            self._log_unavailable(
                f"Presidio analyzer failed to initialise (is the spaCy model "
                f"'{self.spacy_model}' downloaded?): {str(exc)[:200]}"
            )
            return False

    def _log_unavailable(self, message: str) -> None:
        if not self._logged_unavailable:
            logger.critical("presidio_unavailable", extra={"detail": message})
            self._logged_unavailable = True

    @property
    def available(self) -> bool:
        return bool(self._ensure_loaded())

    def analyze(self, text: str) -> list[Any]:
        """Return Presidio RecognizerResults above threshold, or [] if unavailable."""
        if not self._ensure_loaded() or self._analyzer is None:
            return []
        if not text:
            return []
        snippet = text[:_MAX_ANALYZE_CHARS]
        try:
            results = self._analyzer.analyze(
                text=snippet,
                language=self.language,
                entities=self.entities,
                score_threshold=self.threshold,
            )
        except Exception as exc:  # noqa: BLE001 — analysis failure ⇒ no findings
            logger.warning("presidio_analyze_failed", extra={"error": str(exc)[:200]})
            return []
        return list(results)

    @staticmethod
    def redact(text: str, results: list[Any]) -> str:
        """Splice PII spans out right-to-left as ``[REDACTED:<ENTITY>]``.

        Right-to-left ordering keeps earlier offsets valid as we rewrite. Only
        spans within ``_MAX_ANALYZE_CHARS`` are considered (matching ``analyze``).
        """
        if not results:
            return text
        # Sort by start descending; splice each span.
        ordered = sorted(results, key=lambda r: r.start, reverse=True)
        out = text
        for r in ordered:
            start, end = r.start, r.end
            if start < 0 or end > len(out) or start >= end:
                continue
            out = out[:start] + f"[REDACTED:{r.entity_type}]" + out[end:]
        return out


def _entity_counts(results: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.entity_type] = counts.get(r.entity_type, 0) + 1
    return counts


def _severity_for(counts: dict[str, int]) -> str:
    if any(entity in _HIGH_SEVERITY_ENTITIES for entity in counts):
        return "high"
    return "medium"


class PresidioOutputScanner(OutputScanner):
    """Blocking output scanner: NER-backed PII detection + redaction.

    Returns ``REDACT`` with ``modified_content`` when PII is found, ``ALLOW``
    when the response is clean OR when Presidio is not provisioned (inert).
    """

    def __init__(self) -> None:
        self._engine = _PresidioEngine.instance()

    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="presidio_pii_output",
            version="0.1.0",
            scanner_type=ScannerType.OUTPUT_BLOCKING,
            description="Contextual (NER) PII detection + redaction in LLM output via Microsoft Presidio",
            maturity=MaturityTier.BETA,
            author="bulwark",
            priority=20,  # after the builtin secret/PII redaction (priority 10)
        )

    async def startup(self) -> None:
        # Warm the (expensive) spaCy model at boot so the first request is fast.
        # Never raises — a missing model degrades to inert.
        self._engine.available  # noqa: B018 — property access triggers lazy load

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        results = self._engine.analyze(content)
        if not results:
            return GuardrailResult(verdict=Verdict.ALLOW)

        counts = _entity_counts(results)
        redacted = self._engine.redact(content, results)
        event = SecurityEvent(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            verdict=Verdict.REDACT,
            category=ThreatCategory.PII_LEAK,
            description=(
                f"Presidio detected {len(results)} PII span(s) in LLM output: "
                + ", ".join(f"{k}×{v}" for k, v in sorted(counts.items()))
            ),
            source=self.info.name,
            severity=_severity_for(counts),
            request_id=context.request_id,
            metadata={"entities": counts, "engine": "presidio"},
        )
        return GuardrailResult(
            verdict=Verdict.REDACT,
            events=[event],
            modified_content=redacted,
        )

    async def health(self) -> bool:
        return self._engine.available


class PresidioInputScanner(InputScanner):
    """Advisory input scanner: flags PII in user messages (async, non-blocking).

    Emits a ``WARN`` event so PII submitted by users is visible in the SIEM,
    without redacting or blocking the request (that is a policy decision the
    operator makes elsewhere). Inert when Presidio is not provisioned.
    """

    def __init__(self) -> None:
        self._engine = _PresidioEngine.instance()

    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="presidio_pii_input",
            version="0.1.0",
            scanner_type=ScannerType.INPUT_ASYNC,
            description="Advisory NER-backed PII detection in user input via Microsoft Presidio",
            maturity=MaturityTier.BETA,
            author="bulwark",
            priority=60,
        )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        results = self._engine.analyze(content)
        if not results:
            return GuardrailResult(verdict=Verdict.ALLOW)

        counts = _entity_counts(results)
        event = SecurityEvent(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            verdict=Verdict.WARN,
            category=ThreatCategory.PII_LEAK,
            description=(
                f"Presidio detected {len(results)} PII span(s) in user input: "
                + ", ".join(f"{k}×{v}" for k, v in sorted(counts.items()))
            ),
            source=self.info.name,
            severity=_severity_for(counts),
            request_id=context.request_id,
            metadata={"entities": counts, "engine": "presidio"},
        )
        # Advisory only — WARN keeps the request flowing while surfacing the event.
        return GuardrailResult(verdict=Verdict.WARN, events=[event])

    async def health(self) -> bool:
        return self._engine.available
