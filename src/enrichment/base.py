"""
Enrichment Base — Abstract scanner interface for background ML scoring.

All enrichment scanners implement this interface and are invoked
asynchronously AFTER the hot path decision is made.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class EnrichmentStatus(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    THREAT = "threat"
    ERROR = "error"


@dataclass
class EnrichmentResult:
    """Result from an enrichment scanner. Advisory only — never blocks."""

    scanner: str
    status: EnrichmentStatus
    confidence: float = 0.0
    category: Optional[str] = None
    detail: Optional[str] = None
    latency_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)


class BaseEnrichmentScanner(ABC):
    """Abstract base for all enrichment scanners."""

    name: str = "base"
    timeout_ms: float = 200.0  # Max time per scanner (not SLO-bound)

    @abstractmethod
    async def score(self, text: str, request_id: str) -> EnrichmentResult:
        """Score text asynchronously. Must be non-blocking and fail-safe."""
        ...

    async def safe_score(self, text: str, request_id: str) -> EnrichmentResult:
        """Wrapper that guarantees no exceptions propagate."""
        try:
            return await asyncio.wait_for(
                self.score(text, request_id),
                timeout=self.timeout_ms / 1000.0,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "enrichment_timeout", extra={"scanner": self.name, "request_id": request_id}
            )
            return EnrichmentResult(
                scanner=self.name, status=EnrichmentStatus.ERROR, detail="timeout"
            )
        except Exception as e:
            logger.warning("enrichment_error", extra={"scanner": self.name, "error": str(e)})
            return EnrichmentResult(scanner=self.name, status=EnrichmentStatus.ERROR, detail=str(e))
