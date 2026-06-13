"""
Enrichment Manager — Orchestrates background scanners.

Invoked as fire-and-forget after hot path decision.
Results are stored in attack DB and emitted as metrics.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

from .base import BaseEnrichmentScanner, EnrichmentResult, EnrichmentStatus

logger = logging.getLogger(__name__)

ENRICHMENT_ENABLED = os.getenv("SENTINEL_ENRICHMENT_ENABLED", "false").lower() == "true"


class EnrichmentManager:
    """Manages background enrichment scanners."""

    def __init__(self) -> None:
        self.scanners: list[BaseEnrichmentScanner] = []
        self._enabled = ENRICHMENT_ENABLED

    def register(self, scanner: BaseEnrichmentScanner) -> None:
        self.scanners.append(scanner)
        logger.info("enrichment_scanner_registered", extra={"scanner": scanner.name})

    @property
    def enabled(self) -> bool:
        """Return True if enrichment recording is enabled.

        The replay DB records all payloads regardless of whether ML scanners
        are available. ML scanners are optional enrichment layers.
        """
        return self._enabled

    @property
    def has_scanners(self) -> bool:
        """Return True if ML enrichment scanners are registered."""
        return len(self.scanners) > 0

    async def enrich(self, text: str, request_id: str) -> list[EnrichmentResult]:
        """
        Run all scanners in parallel. Fire-and-forget safe.
        Returns results for logging/metrics only.
        """
        if not self.has_scanners:
            return []

        results = await asyncio.gather(
            *[s.safe_score(text, request_id) for s in self.scanners],
            return_exceptions=True,
        )

        # Filter out exceptions (shouldn't happen due to safe_score, but defensive)
        valid_results = [r for r in results if isinstance(r, EnrichmentResult)]

        # Log suspicious/threat findings
        for r in valid_results:
            if r.status in (EnrichmentStatus.SUSPICIOUS, EnrichmentStatus.THREAT):
                logger.warning(
                    "enrichment_detection",
                    extra={
                        "scanner": r.scanner,
                        "status": r.status.value,
                        "confidence": r.confidence,
                        "category": r.category,
                        "request_id": request_id,
                    },
                )

        return valid_results


# Singleton instance
_manager: Optional[EnrichmentManager] = None


def get_enrichment_manager() -> EnrichmentManager:
    global _manager
    if _manager is None:
        _manager = EnrichmentManager()
    return _manager
