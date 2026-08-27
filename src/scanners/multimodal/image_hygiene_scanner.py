"""
Image Hygiene Scanner — deterministic, zero-dependency image guards.

This is the model-free half of multimodal input scanning, split out from the
OCR-based :class:`~src.scanners.multimodal.vision_scanner.VisionScanner` so its
maturity reflects reality. Everything here runs with NO pillow / OCR backend and
is covered by measured deterministic tests, so it ships as ``MaturityTier.BETA``.

Guards (all deterministic):
  * Image gathering — pre-extracted ``image_contents`` metadata, else inline
    ``data:image/...;base64`` URIs embedded in text content.
  * ``allow_images`` policy gate — BLOCK when an agent disallows images.
  * DoS size limit — BLOCK images above the configured byte ceiling.
  * base64 decode validation — WARN on malformed image payloads.
  * Magic-byte format-signature validation — WARN when a data URI's declared
    format disagrees with the real magic bytes (MIME confusion / polyglot /
    disguised payload).

OCR-based image *content* analysis (extract text from pixels → injection scan)
is intentionally NOT here — it lives in the EXPERIMENTAL VisionScanner, which
stays inert until pillow + an OCR backend are installed.

Registered opt-in via ``BULWARK_IMAGE_HYGIENE_SCANNING_ENABLED`` (default off).
INPUT_ASYNC (fire-and-forget) — no LLM call, off the hot path.
"""

from __future__ import annotations

import logging

from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.multimodal import _image_utils
from src.scanners.protocol import (
    InputScanner,
    MaturityTier,
    ScanContext,
    ScannerInfo,
    ScannerType,
)

logger = logging.getLogger(__name__)

# Max image size to process (prevent DoS via large images).
DEFAULT_MAX_IMAGE_SIZE_MB = 5.0


class ImageHygieneScanner(InputScanner):
    """Deterministic image-hygiene guards for multimodal inputs (no OCR)."""

    def __init__(
        self,
        blocking: bool = False,
        max_image_size_mb: float = DEFAULT_MAX_IMAGE_SIZE_MB,
    ) -> None:
        self._blocking = blocking
        self._max_image_bytes = int(max_image_size_mb * 1024 * 1024)

    @property
    def info(self) -> ScannerInfo:
        scanner_type = (
            ScannerType.INPUT_BLOCKING if self._blocking else ScannerType.INPUT_ASYNC
        )
        return ScannerInfo(
            name="image_hygiene_scanner",
            version="1.0.0",
            scanner_type=scanner_type,
            description=(
                "Deterministic image-hygiene guards (policy gate, DoS size "
                "limit, base64 + magic-byte format validation) over inline "
                "data:image URIs — no OCR backend required"
            ),
            maturity=MaturityTier.BETA,
            author="bulwark",
            priority=14,  # Just before the OCR VisionScanner (15)
        )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Run deterministic image guards. No OCR, no external dependency."""
        # Gather images: pre-extracted by the proxy route, else inline data URIs.
        image_contents = context.metadata.get("image_contents", [])
        if not image_contents:
            image_contents = _image_utils.extract_data_uris(content)

        if not image_contents:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Policy gate: images present but disallowed for this agent.
        multimodal_config = context.metadata.get("multimodal", {})
        if not multimodal_config.get("allow_images", True):
            return GuardrailResult(
                verdict=Verdict.BLOCK,
                events=[
                    SecurityEvent(
                        tenant_id=context.tenant_id,
                        agent_id=context.agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.POLICY_VIOLATION,
                        description=(
                            f"Images not allowed for this agent "
                            f"({len(image_contents)} detected)"
                        ),
                        source="image_hygiene_scanner",
                        severity="medium",
                    )
                ],
            )

        all_events: list[SecurityEvent] = []
        for i, image_data in enumerate(image_contents):
            all_events.extend(self._scan_image(image_data, context, index=i))

        if all_events:
            has_block = any(e.verdict == Verdict.BLOCK for e in all_events)
            return GuardrailResult(
                verdict=Verdict.BLOCK if has_block else Verdict.WARN,
                events=all_events,
            )

        return GuardrailResult(verdict=Verdict.ALLOW)

    def _scan_image(
        self,
        image_data: str | bytes,
        context: ScanContext,
        index: int = 0,
    ) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []

        # Decode (base64 validation).
        try:
            image_bytes = _image_utils.decode_image(image_data)
        except ValueError as e:
            events.append(
                SecurityEvent(
                    tenant_id=context.tenant_id,
                    agent_id=context.agent_id,
                    verdict=Verdict.WARN,
                    category=ThreatCategory.POLICY_VIOLATION,
                    description=f"Invalid image format (index {index}): {e}",
                    source="image_hygiene_scanner",
                    severity="low",
                )
            )
            return events

        # DoS size limit.
        if len(image_bytes) > self._max_image_bytes:
            events.append(
                SecurityEvent(
                    tenant_id=context.tenant_id,
                    agent_id=context.agent_id,
                    verdict=Verdict.BLOCK,
                    category=ThreatCategory.DENIAL_OF_SERVICE,
                    description=(
                        f"Image too large: {len(image_bytes) / (1024*1024):.1f} MB "
                        f"(max: {self._max_image_bytes / (1024*1024):.1f} MB)"
                    ),
                    source="image_hygiene_scanner",
                    severity="medium",
                )
            )
            return events

        # Magic-byte format-signature validation.
        fmt_event = self._check_format_signature(image_data, image_bytes, context, index)
        if fmt_event is not None:
            events.append(fmt_event)

        return events

    def _check_format_signature(
        self,
        image_data: str | bytes,
        image_bytes: bytes,
        context: ScanContext,
        index: int,
    ) -> SecurityEvent | None:
        """Corroborate a data URI's declared format against real magic bytes.

        Only fires when ``image_data`` is a ``data:image/<fmt>`` URI (i.e. a
        format was explicitly declared). Raw base64 without a declaration makes
        no claim to contradict, so it is skipped to avoid false positives.
        """
        declared = _image_utils.declared_format(image_data)
        if declared is None:
            return None

        actual = _image_utils.sniff_image_format(image_bytes)
        if actual == declared:
            return None

        if actual is None:
            description = (
                f"Image #{index} declares '{declared}' but carries no valid image "
                f"signature (possible disguised payload)"
            )
        else:
            description = (
                f"Image #{index} format mismatch: declared '{declared}', "
                f"actual '{actual}' (possible MIME confusion / polyglot)"
            )

        return SecurityEvent(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            verdict=Verdict.WARN,
            category=ThreatCategory.POLICY_VIOLATION,
            description=description,
            source="image_hygiene_scanner",
            severity="low",
            metadata={
                "image_index": index,
                "declared_format": declared,
                "actual_format": actual,
            },
        )

    async def health(self) -> bool:
        # Fully deterministic, zero-dependency — always operational.
        return True
