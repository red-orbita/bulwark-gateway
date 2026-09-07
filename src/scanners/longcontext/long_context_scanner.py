"""
LongContextScanner — regex moderation of the long-context blind spot.

The classic ``InputGuardrail.inspect`` bounds its regex work with a head-first
overlapping sliding window capped at ``max_scan_bytes`` (16 KB default). That is
a deliberate DoS control — but it means an injection buried *past* that boundary
in a very long prompt (a pasted document, a huge retrieved chunk, a many-shot
transcript) never reaches the pattern engine. Competitor "long-context" guards
exist precisely because attackers hide the payload deep in otherwise-benign
bulk.

This scanner closes the gap **additively**: it re-runs the shared
``InputGuardrail`` (single source of truth — no forked patterns, no new
dependencies) only over the content *beyond* the guardrail's own boundary,
chunked into windows small enough that each is scanned in full (never
re-triggering the oversized re-window). It also applies a cheap
many-shot-jailbreak density heuristic over the whole (bounded) content.

It is inert-by-default (registered only when
``BULWARK_LONG_CONTEXT_SCANNING_ENABLED=true``) and, like the ML / MCP scanners,
runs as ``INPUT_ASYNC`` (WARN / enrichment only) unless
``BULWARK_LONG_CONTEXT_SCANNING_BLOCKING=true`` promotes it to
``INPUT_BLOCKING`` (a deep BLOCK-worthy finding then returns 403 before the
request is forwarded). Total regex work is hard-capped by
``BULWARK_LONG_CONTEXT_MAX_SCAN_BYTES`` so the feature can never be turned into a
DoS amplifier.

Zero third-party dependencies (pure regex via the existing guardrail), so it is
always available — no model provisioning required.
"""

from __future__ import annotations

import logging
import re

from src.config import settings
from src.guardrails.input_guardrail import InputGuardrail
from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.protocol import (
    InputScanner,
    MaturityTier,
    ScanContext,
    ScannerInfo,
    ScannerType,
)

logger = logging.getLogger(__name__)

# --- Deep-window sizing -------------------------------------------------------
# Window kept strictly below the guardrail's default ``max_input_size`` (8 KB)
# so each window is scanned in full by ``inspect`` WITHOUT tripping its
# oversized re-window path (which would both add noise and re-truncate to 16 KB,
# defeating the purpose). Clamped defensively at runtime against the live
# guardrail limits. Overlap catches a pattern straddling a window seam.
_WINDOW_SIZE = 6_000
_OVERLAP = 1_500

# Hard ceiling on how many BLOCK/WARN events we surface, and how many distinct
# findings we keep, so an adversarial payload engineered to match on every window
# cannot flood the SIEM.
_MAX_EVENTS = 32

# --- Many-shot jailbreak heuristic --------------------------------------------
# Many-shot jailbreaking (Anthropic, 2024) floods the context with dozens–
# hundreds of faux dialogue turns to erode alignment. We count conversational
# role markers anchored at line starts; an assistant-side marker denotes one
# completed faux turn. The threshold is deliberately conservative — a genuine
# "summarise this chat log" request rarely carries this many role turns — and the
# verdict is WARN/medium, so a false positive never hard-blocks a legit transcript
# unless the operator has explicitly enabled blocking mode.
_ASSISTANT_TURN_RE = re.compile(r"(?im)^[ \t>*#-]{0,6}(?:###\s*)?(?:assistant|ai)\s*[:\-]")
_MANYSHOT_MIN_TURNS = 40


class LongContextScanner(InputScanner):
    """Regex-moderate the content past the input guardrail's scan boundary."""

    def __init__(self, blocking: bool | None = None) -> None:
        self._blocking = (
            blocking if blocking is not None else settings.long_context_scanning_blocking
        )
        # Hard cap on total bytes examined (deep windows + many-shot count) so the
        # feature can never amplify a large prompt into unbounded regex work.
        self._max_scan_bytes = max(
            int(getattr(settings, "long_context_max_scan_bytes", 262_144)),
            _WINDOW_SIZE,
        )
        # Own guardrail instance, compiled once at startup (opt-in ⇒ the 4600-pattern
        # compile cost is only paid when the feature is enabled). Reuses the SSOT
        # pattern set — no forked/duplicated detection logic.
        self._guardrail: InputGuardrail | None = None

    @property
    def info(self) -> ScannerInfo:
        scanner_type = (
            ScannerType.INPUT_BLOCKING if self._blocking else ScannerType.INPUT_ASYNC
        )
        return ScannerInfo(
            name="long_context_scanner",
            version="1.0.0",
            scanner_type=scanner_type,
            description=(
                "Long-context moderation: regex-scans content past the input "
                "guardrail's 16 KB boundary + many-shot jailbreak density heuristic"
            ),
            maturity=MaturityTier.BETA,
            author="bulwark",
            priority=35,
        )

    async def startup(self) -> None:
        """Compile the shared guardrail once (only when this scanner is active)."""
        if self._guardrail is None:
            self._guardrail = InputGuardrail()

    async def health(self) -> bool:
        return self._guardrail is not None

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Scan the long-context tail + many-shot density of ``content``.

        Short content (within the guardrail boundary and below the many-shot
        floor) is a zero-cost ALLOW — the classic guardrail already covered it.
        """
        if not content:
            return GuardrailResult(verdict=Verdict.ALLOW)

        guardrail = self._guardrail
        if guardrail is None:  # startup() not run (defensive) — fail-open
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Bound everything we look at, head-first (the head is already covered, but
        # the tail up to the cap is where the blind spot lives).
        scanned = content[: self._max_scan_bytes]
        boundary = max(int(getattr(guardrail, "max_scan_bytes", 16_000)), 0)
        # Keep each window strictly under the guardrail's oversized threshold so
        # ``inspect`` scans it whole without re-windowing/emitting oversized noise.
        max_input = int(getattr(guardrail, "max_input_size", 8_000))
        window_size = max(min(_WINDOW_SIZE, max_input - 1), 512)
        stride = max(window_size - _OVERLAP, 1)

        events: list[SecurityEvent] = []
        worst_block = False

        # --- Many-shot density heuristic (whole bounded content) --------------
        turn_count = len(_ASSISTANT_TURN_RE.findall(scanned))
        if turn_count >= _MANYSHOT_MIN_TURNS:
            events.append(
                SecurityEvent(
                    tenant_id=context.tenant_id,
                    agent_id=context.agent_id,
                    verdict=Verdict.WARN,
                    category=ThreatCategory.JAILBREAK,
                    description=(
                        f"Many-shot jailbreak pattern: {turn_count} faux dialogue "
                        f"turns in a single prompt (>= {_MANYSHOT_MIN_TURNS})"
                    ),
                    source="long_context_scanner",
                    severity="medium",
                    request_id=context.request_id,
                    metadata={
                        "detection_engine": "long_context",
                        "heuristic": "many_shot_density",
                        "turn_count": turn_count,
                    },
                )
            )

        # --- Deep-window regex over the tail past the boundary ----------------
        # Start one overlap before the boundary so a pattern straddling the seam
        # between the head (already scanned) and the tail is still caught.
        start = max(boundary - _OVERLAP, 0)
        if len(scanned) > start:
            seen: set[str] = set()
            for offset in range(start, len(scanned), stride):
                window = scanned[offset : offset + window_size]
                if not window:
                    break
                try:
                    result = guardrail.inspect(
                        window, context.tenant_id, context.agent_id
                    )
                except Exception as exc:  # pragma: no cover - guardrail is pure regex
                    # Fail-open: the classic guardrail already covered the head, and
                    # the async/blocking safe_scan wrapper handles hard failures.
                    logger.warning(
                        "long_context_scanner_inspect_error",
                        extra={"error": str(exc)[:200]},
                    )
                    break
                for ev in result.events:
                    # The guardrail emits its own "oversized" WARN only above
                    # max_input_size; our windows stay below it, but drop it
                    # defensively so we never surface that internal artefact.
                    if "Oversized input" in ev.description:
                        continue
                    dedup_key = f"{ev.category.value}:{ev.description}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    is_block = ev.verdict == Verdict.BLOCK
                    worst_block = worst_block or is_block
                    # Mirror the ENFORCED outcome: a block-worthy finding carries
                    # BLOCK only when this scanner actually blocks — otherwise WARN,
                    # so the SIEM never records a block that did not happen.
                    enforced_block = is_block and self._blocking
                    events.append(
                        SecurityEvent(
                            tenant_id=context.tenant_id,
                            agent_id=context.agent_id,
                            verdict=Verdict.BLOCK if enforced_block else Verdict.WARN,
                            category=ev.category,
                            description=f"[long-context] {ev.description}",
                            source="long_context_scanner",
                            severity=ev.severity,
                            request_id=context.request_id,
                            matched_pattern=ev.matched_pattern,
                            metadata={
                                "detection_engine": "long_context",
                                "via": "input_guardrail",
                                "window_offset": offset,
                                "original_source": ev.source,
                            },
                        )
                    )
                    if len(events) >= _MAX_EVENTS:
                        break
                if len(events) >= _MAX_EVENTS:
                    break

        if not events:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # A deep BLOCK-worthy finding hardens the request to BLOCK only in blocking
        # mode (the pipeline then returns 403). Otherwise WARN: events are
        # logged/alerted but the request proceeds. In INPUT_ASYNC (non-blocking)
        # registration even a BLOCK is downgraded to logging by the async runner.
        if worst_block and self._blocking:
            return GuardrailResult(verdict=Verdict.BLOCK, events=events)
        return GuardrailResult(verdict=Verdict.WARN, events=events)
