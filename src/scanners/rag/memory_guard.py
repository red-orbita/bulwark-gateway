"""
Memory Guard — Detects multi-turn conversation manipulation attacks.

Protects against adversarial patterns that exploit the conversation history:
  - Context window stuffing (extremely long messages to push out system prompt)
  - Role confusion ("pretend previous messages didn't happen")
  - Multi-turn escalation (gradually building harmful requests across turns)
  - System prompt extraction across multiple turns

Priority: 4 (very early, before language detector at 5)
Mode: INPUT_BLOCKING — blocks manipulation attempts immediately.

Configuration via context.metadata:
  - max_message_length: int (default 10000) — max chars per single message
  - max_conversation_turns: int (default 50) — max messages in conversation

All detection is regex-based with no ML dependency.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from src.config import settings
from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.protocol import InputScanner, ScanContext, ScannerInfo, ScannerType

logger = logging.getLogger(__name__)

# Default thresholds
DEFAULT_MAX_MESSAGE_LENGTH = 10_000  # chars per single message
DEFAULT_MAX_CONVERSATION_TURNS = 50  # messages in conversation history

# === Pattern Definitions ===


@dataclass
class _ManipulationPattern:
    """Pattern for conversation manipulation detection."""

    regex: re.Pattern
    category: ThreatCategory
    severity: str
    description: str
    subcategory: str  # role_confusion, escalation, extraction, stuffing


# Role confusion patterns — attempts to reset or alter conversation context
_ROLE_CONFUSION_PATTERNS: list[_ManipulationPattern] = [
    _ManipulationPattern(
        re.compile(
            r"(pretend|assume|imagine|act\s+as\s+if)\s+(the\s+)?"
            r"(previous|earlier|prior|above)\s+(messages?|conversation|chat|turns?|responses?)\s+"
            r"(didn'?t\s+happen|don'?t\s+exist|never\s+(happened|occurred|existed)|"
            r"were?\s+(not|never)\s+(sent|said|written|real))",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Role confusion: deny existence of previous messages",
        "role_confusion",
    ),
    _ManipulationPattern(
        re.compile(
            r"(forget|disregard|ignore|erase|clear|wipe|reset)\s+"
            r"(all\s+)?(the\s+)?(previous|prior|earlier|above|entire|whole)?\s*"
            r"(conversation|chat|history|context|messages?|dialog(ue)?|turns?|memory)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Role confusion: clear/reset conversation history",
        "role_confusion",
    ),
    _ManipulationPattern(
        re.compile(
            r"(this\s+is\s+a\s+new|start\s+(a\s+)?fresh|begin\s+(a\s+)?new|reset\s+to)\s+"
            r"(conversation|session|chat|dialog(ue)?|context)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "medium",
        "Role confusion: force new conversation context",
        "role_confusion",
    ),
    _ManipulationPattern(
        re.compile(
            r"(the\s+real|actual|true|correct)\s+(conversation|context|instructions?|system\s+prompt)\s+"
            r"(starts?|begins?|is)\s+(here|now|below|next)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Role confusion: redefine conversation start point",
        "role_confusion",
    ),
    _ManipulationPattern(
        re.compile(
            r"(everything|all\s+(messages?)?)\s+(above|before|prior)\s+(this|here|now)\s+"
            r"(is|was|were?)\s+(fake|test|simulated?|not\s+real|injected|planted)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Role confusion: claim prior messages are fake/injected",
        "role_confusion",
    ),
]

# Multi-turn escalation patterns — gradual buildup to harmful requests
_ESCALATION_PATTERNS: list[_ManipulationPattern] = [
    _ManipulationPattern(
        re.compile(
            r"(now\s+that|since)\s+(you'?ve|we'?ve|you\s+have|we\s+have)\s+"
            r"(established|confirmed|agreed|shown|demonstrated|proven)\s+.{0,60}"
            r"(now|next|please|can\s+you)\s+(actually|really|finally)\s+"
            r"(do|give|show|tell|provide|help\s+with|execute)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "medium",
        "Multi-turn escalation: leveraging established rapport",
        "escalation",
    ),
    _ManipulationPattern(
        re.compile(
            r"(you\s+(already|previously|just)\s+(said|agreed|confirmed|told\s+me|showed)|"
            r"as\s+you\s+(said|confirmed|agreed|mentioned)\s+(earlier|before|above))\s+.{0,60}"
            r"(so\s+)?((now|therefore|thus)\s+)?(you\s+(must|should|can|will|need\s+to)\s+)?"
            r"(also|just|simply|go\s+ahead\s+and)?",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "medium",
        "Multi-turn escalation: citing previous agreement to justify action",
        "escalation",
    ),
    _ManipulationPattern(
        re.compile(
            r"(in\s+the\s+(last|previous|earlier)\s+(message|turn|response),?\s+)?"
            r"you\s+(broke|violated|bypassed|ignored|overrode)\s+(your\s+)?"
            r"(own\s+)?(rules?|guidelines?|restrictions?|policies?|safety)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Multi-turn escalation: claim AI already violated rules",
        "escalation",
    ),
]

# System prompt extraction patterns across turns
_EXTRACTION_PATTERNS: list[_ManipulationPattern] = [
    _ManipulationPattern(
        re.compile(
            r"(what|which)\s+(were|are|is)\s+(your|the)\s+"
            r"(original|initial|first|system|hidden|secret)\s+"
            r"(instructions?|prompt|rules?|guidelines?|directives?|constraints?)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "System prompt extraction: asking for original instructions",
        "extraction",
    ),
    _ManipulationPattern(
        re.compile(
            r"(repeat|recite|echo|output|print|display|show\s+me|write\s+out)\s+"
            r"(your\s+)?(entire\s+)?(system\s+prompt|system\s+message|initial\s+instructions?|"
            r"hidden\s+instructions?|secret\s+instructions?|first\s+message)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "System prompt extraction: request to repeat system prompt",
        "extraction",
    ),
    _ManipulationPattern(
        re.compile(
            r"(what\s+did|can\s+you\s+tell\s+me\s+about)\s+(the\s+)?"
            r"(developer|creator|designer|programmer|admin)\s+"
            r"(tell|instruct|program|configure|set\s+up|ask)\s+(you|the\s+AI|the\s+model)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "medium",
        "System prompt extraction: indirect questioning about configuration",
        "extraction",
    ),
    _ManipulationPattern(
        re.compile(
            r"(summarize|paraphrase|rephrase|rewrite)\s+(your\s+)?"
            r"(system\s+prompt|initial\s+instructions?|configuration|setup|rules?)\s+"
            r"(in\s+|as\s+|using\s+)?(your\s+own\s+words|different\s+words|a\s+poem|code|json|bullet\s+points)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "System prompt extraction: request to rephrase system prompt",
        "extraction",
    ),
]


class MemoryGuard(InputScanner):
    """Detects multi-turn conversation manipulation attacks.

    Inspects the full conversation history for patterns that exploit
    the dialog context to manipulate the AI agent:

    1. Context window stuffing: Extremely long messages designed to
       push system prompt out of the context window.
    2. Role confusion: Attempts to deny, reset, or redefine the
       conversation history.
    3. Multi-turn escalation: Gradually building toward harmful requests
       by citing fabricated prior agreements.
    4. System prompt extraction: Across-turn attempts to extract the
       system prompt through indirect questioning.

    Configuration via context.metadata:
      - max_message_length: int (default 10000 chars)
      - max_conversation_turns: int (default 50 turns)
    """

    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="memory_guard",
            version="1.0.0",
            scanner_type=ScannerType.INPUT_BLOCKING,
            description="Multi-turn conversation manipulation detector",
            author="sentinel",
            priority=4,  # Very early, before language detector (5)
        )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Scan conversation for manipulation patterns.

        Args:
            content: The current user message content.
            context: ScanContext with full conversation in context.messages.

        Returns:
            GuardrailResult:
              - BLOCK if manipulation detected
              - ALLOW if conversation is clean
        """
        events: list[SecurityEvent] = []

        # Get configuration from metadata (with defaults)
        max_msg_length = context.metadata.get(
            "max_message_length", DEFAULT_MAX_MESSAGE_LENGTH
        )
        max_turns = context.metadata.get(
            "max_conversation_turns", DEFAULT_MAX_CONVERSATION_TURNS
        )

        # Check 1: Context window stuffing
        stuffing_event = self._check_context_stuffing(
            content, context, max_msg_length, max_turns
        )
        if stuffing_event:
            events.append(stuffing_event)

        # Check 2: Role confusion patterns (on current message)
        role_event = self._check_patterns(
            content, _ROLE_CONFUSION_PATTERNS, context
        )
        if role_event:
            events.append(role_event)

        # Check 3: Multi-turn escalation patterns (on current message)
        escalation_event = self._check_patterns(
            content, _ESCALATION_PATTERNS, context
        )
        if escalation_event:
            events.append(escalation_event)

        # Check 4: System prompt extraction (on current message)
        extraction_event = self._check_patterns(
            content, _EXTRACTION_PATTERNS, context
        )
        if extraction_event:
            events.append(extraction_event)

        if not events:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Determine severity: if any critical/high event, BLOCK; otherwise WARN
        max_severity = max(
            events,
            key=lambda e: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
                e.severity, 0
            ),
        )
        verdict = (
            Verdict.BLOCK
            if max_severity.severity in ("critical", "high")
            else Verdict.WARN
        )

        # Update verdicts on all events to match final decision
        for event in events:
            event.verdict = verdict

        logger.warning(
            "memory_guard_triggered",
            extra={
                "verdict": verdict.value,
                "event_count": len(events),
                "tenant_id": context.tenant_id,
                "agent_id": context.agent_id,
                "request_id": context.request_id,
            },
        )

        return GuardrailResult(verdict=verdict, events=events)

    def _check_context_stuffing(
        self,
        content: str,
        context: ScanContext,
        max_msg_length: int,
        max_turns: int,
    ) -> SecurityEvent | None:
        """Detect context window stuffing attacks.

        Triggers on:
          - Single message exceeding max_message_length
          - Conversation exceeding max_conversation_turns
        """
        # Single message length check
        if len(content) > max_msg_length:
            return SecurityEvent(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                verdict=Verdict.BLOCK,
                category=ThreatCategory.DENIAL_OF_SERVICE,
                description=(
                    f"Context window stuffing: message length {len(content)} "
                    f"exceeds limit {max_msg_length}"
                ),
                source="memory_guard",
                severity="high",
                request_id=context.request_id,
                metadata={
                    "subcategory": "stuffing",
                    "message_length": len(content),
                    "max_allowed": max_msg_length,
                },
            )

        # Conversation turn count check
        if context.messages and len(context.messages) > max_turns:
            return SecurityEvent(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                verdict=Verdict.BLOCK,
                category=ThreatCategory.DENIAL_OF_SERVICE,
                description=(
                    f"Context window stuffing: conversation has {len(context.messages)} "
                    f"turns (limit: {max_turns})"
                ),
                source="memory_guard",
                severity="medium",
                request_id=context.request_id,
                metadata={
                    "subcategory": "stuffing",
                    "turn_count": len(context.messages),
                    "max_allowed": max_turns,
                },
            )

        return None

    def _check_patterns(
        self,
        content: str,
        patterns: list[_ManipulationPattern],
        context: ScanContext,
    ) -> SecurityEvent | None:
        """Check content against a set of manipulation patterns.

        Returns the first match as a SecurityEvent, or None.
        """
        for pattern in patterns:
            match = pattern.regex.search(content)
            if match:
                return SecurityEvent(
                    tenant_id=context.tenant_id,
                    agent_id=context.agent_id,
                    verdict=Verdict.BLOCK,
                    category=pattern.category,
                    description=pattern.description,
                    source="memory_guard",
                    severity=pattern.severity,
                    request_id=context.request_id,
                    matched_pattern=match.group(0)[:200],
                    metadata={
                        "subcategory": pattern.subcategory,
                        "match_position": match.start(),
                    },
                )
        return None

    async def health(self) -> bool:
        """Always healthy — no external dependencies."""
        return True
