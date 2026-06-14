"""
Retrieval Scanner — Scans RAG-retrieved documents for indirect prompt injection.

Inspects document chunks BEFORE they are injected into the LLM context window.
Detects adversarial instructions hiding in retrieved content that attempt to
hijack the agent's behavior (indirect prompt injection / RAG poisoning).

Uses a subset of the existing InputGuardrail patterns (high and critical
severity injection patterns only) optimized for document content scanning.

Priority: 6 (after language detector at 5, before main regex at 10)
Mode: INPUT_BLOCKING — poisoned chunks are redacted before reaching the LLM.

Configuration:
  context.metadata["rag_chunks"] — list of dicts with "id" and "content" keys.
  If not present, scanner returns ALLOW immediately.

When a poisoned chunk is detected:
  - Verdict: REDACT
  - modified_content: original content with the poisoned chunk(s) removed
  - SecurityEvent with category MEMORY_MANIPULATION emitted per poisoned chunk
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.protocol import InputScanner, ScanContext, ScannerInfo, ScannerType

logger = logging.getLogger(__name__)


@dataclass
class _InjectionPattern:
    """Lightweight pattern for RAG chunk scanning."""

    regex: re.Pattern
    category: ThreatCategory
    severity: str
    description: str


# High-severity indirect injection patterns optimized for document content.
# These detect adversarial instructions hiding in retrieved text.
_RAG_INJECTION_PATTERNS: list[_InjectionPattern] = [
    # Delegation markers targeting AI agents
    _InjectionPattern(
        re.compile(
            r"(AI\s+assistant|AI\s+agent|language\s+model|LLM|chatbot|GPT|assistant)\s*[,:]\s*"
            r"(run|execute|perform|do|read|send|forward|POST|GET|curl|fetch)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Indirect injection: delegation marker targeting AI agent in document",
    ),
    # Explicit instruction blocks for AI
    _InjectionPattern(
        re.compile(
            r"(INSTRUCTIONS?\s*(FOR|TO)\s*(THE\s+)?(AI|AGENT|ASSISTANT|BOT|MODEL)|"
            r"NOTE\s+(FOR|TO)\s+(THE\s+)?(AI|AGENT|ASSISTANT))\s*:",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Indirect injection: explicit instruction block for AI in document",
    ),
    # Urgency + agent action directive
    _InjectionPattern(
        re.compile(
            r"(IMPORTANT|ATTENTION|URGENT)\s*[,:]\s*(AI|agent|assistant|model)\s+"
            r"(must|should|needs?\s+to|has\s+to)\s+"
            r"(run|execute|send|forward|POST|curl|read|write|delete)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Indirect injection: urgency + action directive in document",
    ),
    # System prompt override attempts
    _InjectionPattern(
        re.compile(
            r"(system\s*prompt|system\s*message|initial\s*instructions?)\s*[:=]",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "System prompt override attempt in retrieved document",
    ),
    # Chat template tag injection
    _InjectionPattern(
        re.compile(r"\[SYSTEM\]|\[INST\]|<<SYS>>|<\|im_start\|>system", re.I),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Raw prompt format injection (chat template tags) in document",
    ),
    # Instruction override / ignore patterns
    _InjectionPattern(
        re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+"
            r"(instructions?|prompts?|rules?|constraints?)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Instruction override attempt in retrieved document",
    ),
    # Concealment instructions
    _InjectionPattern(
        re.compile(
            r"(do\s+not|don'?t|never)\s+(mention|inform|tell|alert|notify|show|reveal|disclose)\s+"
            r"(the\s+)?(user|human|person|client|operator|admin)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Concealment instruction hiding action from user in document",
    ),
    # Stealthy execution commands
    _InjectionPattern(
        re.compile(
            r"(silently|quietly|secretly|covertly|stealthily)\s+"
            r"(run|execute|perform|do|send|forward|POST|delete|modify|read|write)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Stealth execution command in retrieved document",
    ),
    # Exfiltration via document
    _InjectionPattern(
        re.compile(
            r"(forward|send|POST|transmit|upload|exfil)\s+(all\s+)?(the\s+)?"
            r"(emails?|messages?|data|content|responses?|information|output|results?)\s+"
            r"to\s+\S+\.(com|net|org|io|xyz|ru|cn)",
            re.I,
        ),
        ThreatCategory.EXFILTRATION,
        "high",
        "Data exfiltration instruction in retrieved document",
    ),
    # New instructions / updated rules claim
    _InjectionPattern(
        re.compile(
            r"(new\s+instructions?|updated?\s+rules?|revised\s+prompt)\s*[:=\-]",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Fake instruction update in retrieved document",
    ),
    # Role hijacking in documents
    _InjectionPattern(
        re.compile(
            r"(you\s+are|act\s+as|pretend\s+to\s+be|roleplay\s+as|from\s+now\s+on\s+you\s+are)\s+"
            r"(now\s+)?(a|an|the)?\s*(DAN|unrestricted|unfiltered|jailbroken|evil|malicious)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Persona injection / role hijacking in retrieved document",
    ),
    # Function call literals in document text
    _InjectionPattern(
        re.compile(
            r"(run_command|execute|exec|subprocess\.run|os\.system|eval)\s*\(\s*['\"`]",
            re.I,
        ),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "Suspicious function call literal in retrieved document",
    ),
    # Temporal instruction override
    _InjectionPattern(
        re.compile(
            r"(from\s+now\s+on|henceforth),?\s+(ignore|disregard|forget|bypass|disable)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Temporal instruction override in retrieved document",
    ),
    # Hidden HTML/markdown injection
    _InjectionPattern(
        re.compile(
            r"<!--\s*(SYSTEM|INSTRUCTION|IMPORTANT|AI|AGENT).*?-->",
            re.I | re.DOTALL,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Hidden HTML comment with instructions in document",
    ),
]


class RetrievalScanner(InputScanner):
    """Scans RAG-retrieved document chunks for indirect prompt injection.

    Inspects each chunk in context.metadata["rag_chunks"] against high-severity
    injection patterns. Poisoned chunks are removed from the content and a
    REDACT verdict is returned with security events.

    If no rag_chunks are present in metadata, returns ALLOW immediately.

    Configuration via context.metadata:
      - rag_chunks: list[dict] — each dict has "id" (str) and "content" (str)

    Example metadata:
      {
          "rag_chunks": [
              {"id": "doc-123-chunk-7", "content": "...retrieved text..."},
              {"id": "doc-456-chunk-2", "content": "...more text..."},
          ]
      }
    """

    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="retrieval_scanner",
            version="1.0.0",
            scanner_type=ScannerType.INPUT_BLOCKING,
            description="RAG document chunk scanner for indirect prompt injection",
            author="sentinel",
            priority=6,  # After language detector (5), before main regex (10)
        )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Scan RAG chunks for indirect prompt injection.

        Args:
            content: The user message content (not directly scanned here).
            context: ScanContext with metadata["rag_chunks"] containing
                     retrieved document chunks to inspect.

        Returns:
            GuardrailResult:
              - ALLOW if no rag_chunks or all chunks are clean
              - REDACT if poisoned chunks found (modified_content has them removed)
        """
        rag_chunks: list[dict] | None = context.metadata.get("rag_chunks")

        if not rag_chunks:
            return GuardrailResult(verdict=Verdict.ALLOW)

        poisoned_chunk_ids: list[str] = []
        clean_chunks: list[dict] = []
        events: list[SecurityEvent] = []

        for chunk in rag_chunks:
            chunk_id = chunk.get("id", "unknown")
            chunk_content = chunk.get("content", "")

            if not chunk_content:
                clean_chunks.append(chunk)
                continue

            detection = self._scan_chunk(chunk_content, chunk_id, context)
            if detection is not None:
                poisoned_chunk_ids.append(chunk_id)
                events.append(detection)
                logger.warning(
                    "rag_chunk_poisoned",
                    extra={
                        "chunk_id": chunk_id,
                        "tenant_id": context.tenant_id,
                        "agent_id": context.agent_id,
                        "request_id": context.request_id,
                        "description": detection.description,
                    },
                )
            else:
                clean_chunks.append(chunk)

        if not poisoned_chunk_ids:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Build modified content with poisoned chunks removed
        # Reassemble only clean chunk content
        modified_content = "\n\n".join(
            c.get("content", "") for c in clean_chunks if c.get("content")
        )

        # Update metadata so downstream consumers see filtered chunks
        context.metadata["rag_chunks"] = clean_chunks
        context.metadata["rag_chunks_removed"] = poisoned_chunk_ids

        logger.info(
            "rag_chunks_redacted",
            extra={
                "removed_count": len(poisoned_chunk_ids),
                "remaining_count": len(clean_chunks),
                "tenant_id": context.tenant_id,
                "request_id": context.request_id,
            },
        )

        return GuardrailResult(
            verdict=Verdict.REDACT,
            events=events,
            modified_content=modified_content,
        )

    def _scan_chunk(
        self,
        chunk_content: str,
        chunk_id: str,
        context: ScanContext,
    ) -> SecurityEvent | None:
        """Scan a single chunk against injection patterns.

        Returns a SecurityEvent if poisoned, None if clean.
        """
        for pattern in _RAG_INJECTION_PATTERNS:
            match = pattern.regex.search(chunk_content)
            if match:
                return SecurityEvent(
                    tenant_id=context.tenant_id,
                    agent_id=context.agent_id,
                    verdict=Verdict.REDACT,
                    category=pattern.category,
                    description=(
                        f"Poisoned RAG chunk [{chunk_id}]: {pattern.description}"
                    ),
                    source="retrieval_scanner",
                    severity=pattern.severity,
                    request_id=context.request_id,
                    matched_pattern=match.group(0)[:200],
                    metadata={
                        "chunk_id": chunk_id,
                        "pattern_description": pattern.description,
                        "match_position": match.start(),
                    },
                )
        return None

    async def health(self) -> bool:
        """Always healthy — no external dependencies."""
        return True
