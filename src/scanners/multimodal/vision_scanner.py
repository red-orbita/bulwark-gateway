"""
Vision Scanner — OCR-based image content analysis (EXPERIMENTAL).

This is the OCR half of multimodal input scanning. The deterministic,
zero-dependency image-hygiene guards (data-URI extraction, base64 validation,
DoS size limit, ``allow_images`` policy gate, magic-byte format-signature
validation) have been split into the model-free, BETA
:class:`~src.scanners.multimodal.image_hygiene_scanner.ImageHygieneScanner`.

What remains here is the eponymous, headline capability:

  Image → OCR (extract text from pixels) → injection detection on that text.

SHIPPED STATE (honesty): this capability is **INERT by default**. The ``[vision]``
extra (pillow) is not installed in the default distribution and no OCR backend
(easyocr / pytesseract) ships — and neither fits the distroless, no-torch runtime
— so ``startup()`` leaves ``self._available`` False and ``scan()`` returns ALLOW
immediately. Its OCR-to-injection efficacy is unproven, so the scanner is
declared ``MaturityTier.EXPERIMENTAL`` and must never claim BETA/GA.

To enable OCR, install pillow + an OCR backend deliberately (understanding it will
not load in a stock distroless image). For deterministic image hygiene without
OCR, enable the ``ImageHygieneScanner`` via ``BULWARK_IMAGE_HYGIENE_SCANNING_ENABLED``.
"""

from __future__ import annotations

import asyncio
import io
import logging
import re
from concurrent.futures import ThreadPoolExecutor

from src.config import settings
from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.multimodal import _image_utils
from src.scanners.protocol import InputScanner, MaturityTier, ScanContext, ScannerInfo, ScannerType

logger = logging.getLogger(__name__)

# Max image size to process before OCR (prevent DoS via large images).
MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB


def _vision_deps_available() -> bool:
    """Check if vision dependencies are installed."""
    try:
        from PIL import Image  # noqa: F401
        return True
    except ImportError:
        return False


def _ocr_available() -> bool:
    """Check if OCR backend is available."""
    try:
        import easyocr  # noqa: F401
        return True
    except ImportError:
        pass
    try:
        import pytesseract  # noqa: F401
        return True
    except ImportError:
        pass
    return False


class VisionScanner(InputScanner):
    """Scans images for embedded prompt injection via OCR text extraction.

    Handles the OpenAI vision API format where messages contain image_url
    content blocks with base64-encoded or URL-referenced images.

    Scanning pipeline (only when an OCR backend loaded at startup):
    1. Gather images (pre-extracted metadata or inline data URIs)
    2. Pre-OCR safety: policy gate + size limit
    3. OCR text extraction (EasyOCR or Tesseract)
    4. Run extracted text through injection detection patterns

    The scanner is INERT (returns ALLOW) unless ``self._available`` was set at
    startup. For deterministic image hygiene without OCR, use the
    ``ImageHygieneScanner`` instead.
    """

    def __init__(
        self,
        blocking: bool = False,
        max_image_size_mb: float = 5.0,
        ocr_confidence_threshold: float = 0.3,
    ) -> None:
        self._blocking = blocking
        self._max_image_bytes = int(max_image_size_mb * 1024 * 1024)
        self._ocr_threshold = ocr_confidence_threshold
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="vision")
        self._ocr_reader = None
        self._available = False

    @property
    def info(self) -> ScannerInfo:
        scanner_type = (
            ScannerType.INPUT_BLOCKING if self._blocking else ScannerType.INPUT_ASYNC
        )
        return ScannerInfo(
            name="ml_vision_scanner",
            version="1.0.0",
            scanner_type=scanner_type,
            description="Image OCR + injection detection for multimodal inputs",
            maturity=MaturityTier.EXPERIMENTAL,
            author="bulwark",
            priority=15,  # After language (5), before ML classifiers (20+)
        )

    async def startup(self) -> None:
        """Initialize OCR backend."""
        if not _vision_deps_available():
            logger.info("vision_scanner_skipped", extra={"reason": "pillow not installed"})
            return

        if not settings.ml_enabled:
            logger.info("vision_scanner_skipped", extra={"reason": "ML disabled"})
            return

        if _ocr_available():
            try:
                # Try EasyOCR first (better accuracy, GPU support)
                import easyocr
                self._ocr_reader = easyocr.Reader(
                    ["en"],  # Start with English; expand in future
                    gpu=False,
                    verbose=False,
                )
                self._available = True
                logger.info("vision_scanner_ready", extra={"ocr_backend": "easyocr"})
            except Exception as e:
                logger.warning(
                    "easyocr_init_failed",
                    extra={"error": str(e)[:100]},
                )
                # Try pytesseract as fallback
                try:
                    import pytesseract
                    pytesseract.get_tesseract_version()
                    self._available = True
                    logger.info("vision_scanner_ready", extra={"ocr_backend": "pytesseract"})
                except Exception:
                    logger.info("vision_scanner_skipped", extra={"reason": "no OCR backend"})
        else:
            logger.info("vision_scanner_skipped", extra={"reason": "no OCR library"})

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """OCR-scan images for embedded injection.

        Fully INERT unless an OCR backend loaded at startup (``self._available``).
        The deterministic image-hygiene guards (policy gate, DoS size limit,
        base64 + magic-byte validation) now live in the ``ImageHygieneScanner``.
        """
        if not self._available:
            # No OCR backend — this scanner has nothing to contribute. The
            # deterministic hygiene guards are the ImageHygieneScanner's job.
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Gather images: pre-extracted by the proxy route, else inline data URIs.
        image_contents = context.metadata.get("image_contents", [])
        if not image_contents:
            image_contents = _image_utils.extract_data_uris(content)

        if not image_contents:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Pre-OCR policy gate (defense in depth; ImageHygieneScanner also enforces).
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
                        source="ml_vision_scanner",
                        severity="medium",
                    )
                ],
            )

        all_events: list[SecurityEvent] = []
        for i, image_data in enumerate(image_contents):
            events = await self._scan_image(image_data, context, index=i)
            all_events.extend(events)

        if all_events:
            has_block = any(e.verdict == Verdict.BLOCK for e in all_events)
            return GuardrailResult(
                verdict=Verdict.BLOCK if has_block else Verdict.WARN,
                events=all_events,
            )

        return GuardrailResult(verdict=Verdict.ALLOW)

    async def _scan_image(
        self,
        image_data: str | bytes,
        context: ScanContext,
        index: int = 0,
    ) -> list[SecurityEvent]:
        """OCR-scan a single image (only reached when ``self._available``)."""
        events: list[SecurityEvent] = []

        # Decode image
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
                    source="ml_vision_scanner",
                    severity="low",
                )
            )
            return events

        # Pre-OCR size check (DoS guard on the OCR path itself)
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
                    source="ml_vision_scanner",
                    severity="medium",
                )
            )
            return events

        # OCR extraction + injection scan on the extracted text.
        if context.metadata.get("multimodal", {}).get("ocr_scan", True):
            loop = asyncio.get_event_loop()
            extracted_text = await loop.run_in_executor(
                self._executor, self._ocr_extract, image_bytes
            )

            if extracted_text:
                existing_ocr = context.metadata.get("ocr_extracted_text", [])
                existing_ocr.append(extracted_text)
                context.metadata["ocr_extracted_text"] = existing_ocr

                injection_events = self._check_injection_in_text(
                    extracted_text, context, index
                )
                events.extend(injection_events)

        return events

    def _ocr_extract(self, image_bytes: bytes) -> str | None:
        """Extract text from image using OCR (runs in thread pool).

        Returns extracted text or None if no text found.
        """
        try:
            from PIL import Image

            image = Image.open(io.BytesIO(image_bytes))

            # Dimension check
            if max(image.size) > _image_utils.MAX_IMAGE_DIMENSION:
                # Resize to max dimension while preserving aspect ratio
                image.thumbnail(
                    (_image_utils.MAX_IMAGE_DIMENSION, _image_utils.MAX_IMAGE_DIMENSION)
                )

            if self._ocr_reader is not None:
                # EasyOCR
                import numpy as np
                img_array = np.array(image.convert("RGB"))
                results = self._ocr_reader.readtext(img_array)

                # Filter by confidence threshold
                texts = []
                for _bbox, text, confidence in results:
                    if confidence >= self._ocr_threshold:
                        texts.append(text)

                return " ".join(texts) if texts else None
            else:
                # pytesseract fallback
                import pytesseract
                text = pytesseract.image_to_string(image)
                return text.strip() if text.strip() else None

        except Exception as e:
            logger.debug("ocr_extraction_failed", extra={"error": str(e)[:100]})
            return None

    def _check_injection_in_text(
        self,
        text: str,
        context: ScanContext,
        image_index: int,
    ) -> list[SecurityEvent]:
        """Check OCR-extracted text for injection patterns.

        Uses a subset of critical patterns (not the full 4600-line guardrail)
        to detect obvious injection attempts embedded in images.
        """
        events: list[SecurityEvent] = []

        # Critical injection patterns (subset for OCR text)
        injection_patterns = [
            (r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|prompts?)",
             "Ignore instructions pattern in image"),
            (r"(?i)you\s+are\s+now\s+(a|an|my|free|unrestricted|DAN|jailbr)",
             "Role override pattern in image"),
            (r"(?i)system\s*:\s*(you\s+are|override|new\s+instructions?)",
             "System prompt injection in image"),
            (r"(?i)(forget|disregard|override)\s+(everything|all|your\s+instructions)",
             "Instruction override in image"),
            (r"(?i)developer\s+mode|god\s+mode|jailbreak\s+mode",
             "Jailbreak mode request in image"),
        ]

        for pattern_str, description in injection_patterns:
            match = re.search(pattern_str, text)
            if match:
                events.append(
                    SecurityEvent(
                        tenant_id=context.tenant_id,
                        agent_id=context.agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.PROMPT_INJECTION,
                        description=f"{description} (image #{image_index})",
                        source="ml_vision_scanner",
                        severity="high",
                        metadata={
                            "image_index": image_index,
                            "ocr_text_snippet": text[:200],
                            "matched_text": match.group()[:100],
                        },
                    )
                )
                break  # One detection per image is enough

        return events

    def _extract_data_uris(self, content: str) -> list[str]:
        """Extract base64 data URIs from text content (delegates to _image_utils)."""
        return _image_utils.extract_data_uris(content)

    async def health(self) -> bool:
        # EXPERIMENTAL OCR layer. Registered only when vision scanning is opted in.
        # When it is, report unhealthy unless an OCR backend actually loaded — this
        # surfaces a WARN in admin so the operator knows the flag is on but no
        # image-content analysis is happening (pillow + OCR backend not installed),
        # rather than implying a functional vision scanner. For deterministic image
        # hygiene without OCR, use the ImageHygieneScanner instead.
        if not settings.vision_scanning_enabled:
            return True
        return self._available

    async def shutdown(self) -> None:
        self._executor.shutdown(wait=False)
        self._ocr_reader = None
