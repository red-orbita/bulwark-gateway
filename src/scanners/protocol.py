"""
Scanner Protocol — Defines the interface all scanners must implement.

Scanners are the atomic units of security checking. Each scanner:
  - Has a unique name and version
  - Declares whether it runs in the blocking hot path or async enrichment
  - Returns a GuardrailResult with a verdict and optional events
  - Must handle its own failures gracefully (never crash the pipeline)
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.models import GuardrailResult, Verdict

logger = logging.getLogger(__name__)


class ScannerType(str, Enum):
    """Where in the pipeline this scanner runs."""

    INPUT_BLOCKING = "input_blocking"  # Hot path, can block requests
    INPUT_ASYNC = "input_async"  # Fire-and-forget enrichment
    OUTPUT_BLOCKING = "output_blocking"  # Output path, can redact/block
    OUTPUT_ASYNC = "output_async"  # Output enrichment


@dataclass
class ScannerInfo:
    """Metadata about a registered scanner."""

    name: str
    version: str
    scanner_type: ScannerType
    description: str = ""
    author: str = "sentinel"
    enabled: bool = True
    priority: int = 50  # Lower = runs first (0-100)


@dataclass
class ScanContext:
    """Context passed to all scanners during execution.

    Provides tenant isolation, request tracing, and shared state
    between scanner stages.
    """

    tenant_id: str
    agent_id: str
    request_id: str
    messages: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    language: str | None = None  # Detected language (set by language detector)
    content_type: str = "text"  # "text", "image", "audio", "multimodal"
    session_id: str | None = None  # For dialog state tracking
    source_ip: str | None = None

    @property
    def user_content(self) -> str:
        """Extract concatenated user message content."""
        parts = []
        for msg in self.messages:
            if msg.get("role") == "user" and msg.get("content"):
                parts.append(msg["content"])
        return " ".join(parts)


class InputScanner(ABC):
    """Abstract base class for all input scanners.

    Input scanners inspect user messages BEFORE they reach the LLM.
    They can be blocking (hot path) or async (enrichment).

    Subclasses must implement:
      - info: property returning ScannerInfo
      - scan(): the actual scanning logic

    Optional overrides:
      - startup(): called once during app startup
      - shutdown(): called once during app shutdown
      - health(): health check for the scanner
    """

    @property
    @abstractmethod
    def info(self) -> ScannerInfo:
        """Scanner metadata."""
        ...

    @abstractmethod
    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Scan input content and return a verdict.

        Args:
            content: The text content to scan (normalized)
            context: Request context (tenant, agent, messages, etc.)

        Returns:
            GuardrailResult with verdict and any security events
        """
        ...

    async def startup(self) -> None:
        """Called once during application startup. Load models, warm caches."""
        pass

    async def shutdown(self) -> None:
        """Called once during application shutdown. Release resources."""
        pass

    async def health(self) -> bool:
        """Return True if scanner is operational."""
        return True

    async def safe_scan(
        self, content: str, context: ScanContext, timeout_ms: float = 5000.0
    ) -> GuardrailResult:
        """Scan with timeout and exception safety. Never raises.

        Args:
            content: Text to scan
            context: Scan context
            timeout_ms: Maximum time in milliseconds

        Returns:
            GuardrailResult — ALLOW on timeout/error (fail-open for async)
            or BLOCK on timeout/error for blocking scanners (fail-closed)
        """
        start = time.perf_counter()
        try:
            result = await asyncio.wait_for(
                self.scan(content, context),
                timeout=timeout_ms / 1000.0,
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            if elapsed_ms > timeout_ms * 0.8:
                logger.warning(
                    "scanner_slow",
                    extra={
                        "scanner": self.info.name,
                        "elapsed_ms": round(elapsed_ms, 1),
                        "timeout_ms": timeout_ms,
                    },
                )
            return result
        except asyncio.TimeoutError:
            logger.warning(
                "scanner_timeout",
                extra={
                    "scanner": self.info.name,
                    "timeout_ms": timeout_ms,
                    "request_id": context.request_id,
                },
            )
            # Fail-closed for blocking scanners, fail-open for async
            if self.info.scanner_type == ScannerType.INPUT_BLOCKING:
                return GuardrailResult(verdict=Verdict.BLOCK)
            return GuardrailResult(verdict=Verdict.ALLOW)
        except Exception as e:
            logger.error(
                "scanner_error",
                extra={
                    "scanner": self.info.name,
                    "error": str(e)[:200],
                    "request_id": context.request_id,
                },
            )
            if self.info.scanner_type == ScannerType.INPUT_BLOCKING:
                return GuardrailResult(verdict=Verdict.ALLOW)  # Don't block on scanner bugs
            return GuardrailResult(verdict=Verdict.ALLOW)


class OutputScanner(ABC):
    """Abstract base class for all output scanners.

    Output scanners inspect LLM responses BEFORE they reach the user.
    They can redact sensitive content or block dangerous outputs.
    """

    @property
    @abstractmethod
    def info(self) -> ScannerInfo:
        """Scanner metadata."""
        ...

    @abstractmethod
    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Scan output content and return a verdict.

        Args:
            content: The LLM response text to scan
            context: Request context

        Returns:
            GuardrailResult with verdict, events, and optional modified_content
        """
        ...

    async def startup(self) -> None:
        """Called once during application startup."""
        pass

    async def shutdown(self) -> None:
        """Called once during application shutdown."""
        pass

    async def health(self) -> bool:
        """Return True if scanner is operational."""
        return True

    async def safe_scan(
        self, content: str, context: ScanContext, timeout_ms: float = 5000.0
    ) -> GuardrailResult:
        """Scan with timeout and exception safety."""
        try:
            return await asyncio.wait_for(
                self.scan(content, context),
                timeout=timeout_ms / 1000.0,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "output_scanner_timeout",
                extra={"scanner": self.info.name, "timeout_ms": timeout_ms},
            )
            return GuardrailResult(verdict=Verdict.ALLOW)
        except Exception as e:
            logger.error(
                "output_scanner_error",
                extra={"scanner": self.info.name, "error": str(e)[:200]},
            )
            return GuardrailResult(verdict=Verdict.ALLOW)
