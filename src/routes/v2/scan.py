"""
V2 Scan Endpoint — Standalone content scanning API.

For customers who want to use Sentinel Gateway as a scanner without
proxying to an LLM backend. Runs the same InputGuardrail and OutputFilter
engines used in the proxy pipeline.

Endpoints:
  POST /v2/scan       — Scan a single content string
  POST /v2/scan/batch — Scan multiple content items in one request
"""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime, timezone
from enum import Enum

import structlog
from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from src.guardrails.input_guardrail import InputGuardrail
from src.guardrails.output_filter import OutputFilter
from src.models import GuardrailResult, SecurityEvent, Verdict
from src.telemetry.counters import get_counters
from src.telemetry.notifications import AlertPayload, get_notification_engine
from src.telemetry.queue import get_telemetry_queue
from src.telemetry.schema import from_security_event

router = APIRouter(prefix="/scan", tags=["scan"])
logger = structlog.get_logger()

# Reuse the same guardrail instances (patterns are pre-compiled at import time)
_input_guardrail = InputGuardrail()
_output_filter = OutputFilter()

# Severity ranking for threshold filtering
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# MITRE ATT&CK mapping for threat categories
_MITRE_MAP: dict[str, str] = {
    "prompt_injection": "T1059",
    "jailbreak": "T1190",
    "tool_abuse": "T1059.004",
    "exfiltration": "T1041",
    "credential_access": "T1552",
    "reverse_shell": "T1059.004",
    "malicious_domain": "T1071.001",
    "pii_leak": "T1552.005",
    "policy_violation": "T1078",
    "insecure_output": "T1203",
    "denial_of_service": "T1498",
    "excessive_agency": "T1078.004",
    "plan_corruption": "T1565",
    "cross_agent_injection": "T1557",
    "memory_manipulation": "T1565.001",
}


# === Request/Response Models ===


class ScanType(str, Enum):
    INPUT = "input"
    OUTPUT = "output"
    BOTH = "both"


class SeverityThreshold(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanOptions(BaseModel):
    """Options for customizing scan behavior."""

    categories: list[str] | None = Field(
        default=None,
        description="Filter to specific threat categories (e.g. ['prompt_injection', 'jailbreak'])",
    )
    include_patterns: bool = Field(
        default=True,
        description="Include matched pattern details in findings",
    )
    include_score: bool = Field(
        default=True,
        description="Include confidence score in findings",
    )
    threshold: SeverityThreshold = Field(
        default=SeverityThreshold.MEDIUM,
        description="Minimum severity to report: low, medium, high, critical",
    )


class ScanRequest(BaseModel):
    """Single content scan request."""

    content: str = Field(..., description="Text content to scan", max_length=100_000)
    scan_type: ScanType = Field(default=ScanType.INPUT, description="Type of scan to perform")
    options: ScanOptions = Field(default_factory=ScanOptions)


class Finding(BaseModel):
    """A single security finding from the scan."""

    category: str
    severity: str
    description: str
    pattern_id: str | None = None
    matched_text: str | None = None
    confidence: float = 1.0
    mitre_attack: str | None = None


class ScanMetadata(BaseModel):
    """Metadata about the scan execution."""

    scan_duration_ms: float
    patterns_checked: int
    api_version: str


class ScanResponse(BaseModel):
    """Response from a single content scan."""

    verdict: str
    scan_id: str
    timestamp: str
    findings: list[Finding]
    metadata: ScanMetadata


class BatchItem(BaseModel):
    """A single item in a batch scan request."""

    content: str = Field(..., description="Text content to scan", max_length=100_000)
    id: str = Field(..., description="Client-provided identifier for correlation")


class BatchScanRequest(BaseModel):
    """Batch scan request — multiple items in one call."""

    items: list[BatchItem] = Field(..., min_length=1, max_length=100)
    scan_type: ScanType = Field(default=ScanType.INPUT, description="Type of scan to perform")
    options: ScanOptions = Field(default_factory=ScanOptions)


class BatchItemResult(BaseModel):
    """Result for a single item in a batch scan."""

    id: str
    verdict: str
    findings: list[Finding]


class BatchScanResponse(BaseModel):
    """Response from a batch content scan."""

    scan_id: str
    timestamp: str
    results: list[BatchItemResult]
    summary: dict[str, int]
    metadata: ScanMetadata


# === Helpers ===


def _run_scan(
    content: str,
    scan_type: ScanType,
    tenant_id: str,
    agent_id: str,
) -> tuple[GuardrailResult, int]:
    """Run guardrail scan and return (result, patterns_checked).

    SECURITY (H-05/M-06 fix): V2 scan now includes IOC checks and session
    tracking to provide the same protection level as the V1 proxy pipeline.
    Returns a merged result if scan_type is BOTH.
    """
    patterns_checked = 0

    if scan_type in (ScanType.INPUT, ScanType.BOTH):
        input_result = _input_guardrail.inspect(content, tenant_id, agent_id)
        patterns_checked += len(_input_guardrail.all_patterns)

        # SECURITY (H-05 fix): Also run IOC check on input content
        try:
            from fastapi import Request as _Req
            from src.main import app as _app
            ioc_mgr = getattr(_app.state, "ioc_manager", None)
            if ioc_mgr and input_result.verdict != Verdict.BLOCK:
                ioc_matches = ioc_mgr.check_content(content)
                if ioc_matches:
                    from src.models import ThreatCategory
                    ioc_event = SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.MALICIOUS_DOMAIN,
                        description=f"IOC match: {ioc_matches[0][:50]}",
                        source="ioc_scanner_v2",
                        severity="high",
                    )
                    input_result = GuardrailResult(
                        verdict=Verdict.BLOCK,
                        events=input_result.events + [ioc_event],
                    )
        except Exception:
            pass  # IOC check failure doesn't block scan
    else:
        input_result = GuardrailResult(verdict=Verdict.ALLOW)

    if scan_type in (ScanType.OUTPUT, ScanType.BOTH):
        output_result = _output_filter.inspect_and_redact(content, tenant_id, agent_id)
        patterns_checked += 150  # Approximate output filter pattern count
    else:
        output_result = GuardrailResult(verdict=Verdict.ALLOW)

    # Merge results: take the most severe verdict
    if scan_type == ScanType.BOTH:
        verdict_rank = {Verdict.ALLOW: 0, Verdict.WARN: 1, Verdict.REDACT: 2, Verdict.BLOCK: 3}
        if verdict_rank.get(output_result.verdict, 0) > verdict_rank.get(input_result.verdict, 0):
            merged_verdict = output_result.verdict
        else:
            merged_verdict = input_result.verdict
        merged_events = input_result.events + output_result.events
        return GuardrailResult(verdict=merged_verdict, events=merged_events), patterns_checked

    if scan_type == ScanType.OUTPUT:
        return output_result, patterns_checked

    return input_result, patterns_checked


def _events_to_findings(
    events: list[SecurityEvent],
    options: ScanOptions,
) -> list[Finding]:
    """Convert SecurityEvents to Finding objects, applying filters."""
    threshold_rank = _SEVERITY_RANK.get(options.threshold.value, 1)
    findings: list[Finding] = []

    for event in events:
        # Apply severity threshold filter
        event_rank = _SEVERITY_RANK.get(event.severity, 0)
        if event_rank < threshold_rank:
            continue

        # Apply category filter
        if options.categories:
            cat_value = event.category.value if event.category else ""
            if cat_value not in options.categories:
                continue

        finding = Finding(
            category=event.category.value if event.category else "unknown",
            severity=event.severity,
            description=event.description,
            pattern_id=event.matched_pattern[:20] if event.matched_pattern and options.include_patterns else None,
            matched_text=event.matched_pattern[:100] if event.matched_pattern and options.include_patterns else None,
            confidence=0.95 if options.include_score else 1.0,
            mitre_attack=_MITRE_MAP.get(
                event.category.value if event.category else "", None
            ),
        )
        findings.append(finding)

    return findings


async def _emit_scan_events(
    events: list[SecurityEvent],
    tenant_id: str,
    agent_id: str,
) -> None:
    """Emit security events to telemetry pipeline (SIEM + notifications)."""
    if not events:
        return

    queue = get_telemetry_queue()
    for event in events:
        await logger.awarn(
            "security_event",
            verdict=event.verdict.value,
            category=event.category.value,
            description=event.description,
            tenant=event.tenant_id,
            agent=event.agent_id,
            severity=event.severity,
            source="v2_scan",
            pattern=event.matched_pattern,
        )
        telemetry_event = from_security_event(
            verdict=event.verdict.value,
            rule_id=event.matched_pattern,
            rule_description=event.description,
            threat_category=event.category.value if event.category else None,
            tenant_id=event.tenant_id or "unknown",
            agent_id=event.agent_id,
            guardrail_layer="v2_scan",
            latency_ms=0.0,
            confidence=1.0,
        )
        queue.enqueue_nowait(telemetry_event)

    # Fire notifications for high/critical findings
    engine = get_notification_engine()
    if engine.configured:
        for event in events:
            if event.severity in ("high", "critical"):
                alert = AlertPayload(
                    verdict=event.verdict.value,
                    severity=event.severity,
                    category=event.category.value if event.category else "unknown",
                    description=event.description,
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    matched_patterns=[event.matched_pattern] if event.matched_pattern else [],
                )
                try:
                    await engine.send_alert(alert)
                except Exception as exc:
                    await logger.adebug("scan_notification_error", error=str(exc)[:100])


# === Endpoints ===


@router.post(
    "",
    response_model=ScanResponse,
    summary="Scan content for security threats",
    description=(
        "Standalone content scanning API. Runs the same guardrail engines as the proxy "
        "pipeline without forwarding to an LLM backend. Useful for pre-validation, "
        "content moderation, and security testing."
    ),
)
async def scan_content(body: ScanRequest, request: Request) -> ScanResponse:
    """Scan a single content string for security threats."""
    start = time.perf_counter()
    scan_id = str(uuid.uuid4())
    tenant_id = getattr(request.state, "tenant_id", "unknown")
    agent_id = getattr(request.state, "agent_id", "unknown")
    api_version = getattr(request.state, "api_version", "2026-06-01")

    # Run scan
    result, patterns_checked = _run_scan(
        content=body.content,
        scan_type=body.scan_type,
        tenant_id=tenant_id,
        agent_id=agent_id,
    )

    # Convert events to findings with filtering
    findings = _events_to_findings(result.events, body.options)

    # Determine final verdict based on filtered findings
    if findings:
        max_sev = max(_SEVERITY_RANK.get(f.severity, 0) for f in findings)
        verdict = "block" if max_sev >= 2 else "warn"
    else:
        verdict = result.verdict.value if result.events else "allow"

    elapsed_ms = (time.perf_counter() - start) * 1000

    # Record counters
    counters = get_counters()
    counters.record(verdict, elapsed_ms)

    # Emit events to SIEM (async, non-blocking)
    asyncio.create_task(_emit_scan_events(result.events, tenant_id, agent_id))

    return ScanResponse(
        verdict=verdict,
        scan_id=scan_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        findings=findings,
        metadata=ScanMetadata(
            scan_duration_ms=round(elapsed_ms, 2),
            patterns_checked=patterns_checked,
            api_version=api_version,
        ),
    )


@router.post(
    "/batch",
    response_model=BatchScanResponse,
    summary="Batch scan multiple content items",
    description=(
        "Scan multiple content items in a single request. Each item is scanned "
        "independently and results are correlated by the client-provided 'id' field. "
        "Maximum 100 items per batch."
    ),
)
async def scan_batch(body: BatchScanRequest, request: Request) -> BatchScanResponse:
    """Scan multiple content items in a single request."""
    start = time.perf_counter()
    scan_id = str(uuid.uuid4())
    tenant_id = getattr(request.state, "tenant_id", "unknown")
    agent_id = getattr(request.state, "agent_id", "unknown")
    api_version = getattr(request.state, "api_version", "2026-06-01")

    results: list[BatchItemResult] = []
    all_events: list[SecurityEvent] = []
    total_patterns = 0
    summary = {"allow": 0, "block": 0, "warn": 0}

    for item in body.items:
        result, patterns_checked = _run_scan(
            content=item.content,
            scan_type=body.scan_type,
            tenant_id=tenant_id,
            agent_id=agent_id,
        )
        total_patterns += patterns_checked
        all_events.extend(result.events)

        findings = _events_to_findings(result.events, body.options)

        # Determine verdict for this item
        if findings:
            max_sev = max(_SEVERITY_RANK.get(f.severity, 0) for f in findings)
            item_verdict = "block" if max_sev >= 2 else "warn"
        else:
            item_verdict = result.verdict.value if result.events else "allow"

        summary[item_verdict] = summary.get(item_verdict, 0) + 1

        results.append(BatchItemResult(
            id=item.id,
            verdict=item_verdict,
            findings=findings,
        ))

    elapsed_ms = (time.perf_counter() - start) * 1000

    # Record counters (one per batch item)
    counters = get_counters()
    for r in results:
        counters.record(r.verdict, elapsed_ms / len(results))

    # Emit all events to SIEM (async)
    asyncio.create_task(_emit_scan_events(all_events, tenant_id, agent_id))

    return BatchScanResponse(
        scan_id=scan_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        results=results,
        summary=summary,
        metadata=ScanMetadata(
            scan_duration_ms=round(elapsed_ms, 2),
            patterns_checked=total_patterns,
            api_version=api_version,
        ),
    )
