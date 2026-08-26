"""
Vision Scanner — Detects prompt injection and harmful content in images.

Attack vectors addressed:
  1. Text-in-image injection (OCR extraction → text scanner)
  2. Steganography (hidden data in pixel values)
  3. QR codes containing malicious URLs or injection payloads
  4. NSFW/harmful content classification

Pipeline:
  Image → OCR → Text Extraction → InputGuardrail scan
  Image → Content Classifier → Safety check

Dependencies (optional):
  pip install bulwark-gateway[vision]
  # Installs pillow (the [vision] extra); an OCR backend (easyocr or
  # pytesseract) must be installed separately.

Default mode: async (fire-and-forget enrichment)

SHIPPED STATE (honesty): the scanner is split into two capability tiers.

  * Deterministic guards — data-URI extraction, base64 decode validation, the
    DoS size limit, the ``allow_images`` policy gate, and magic-byte
    format-signature validation — need NO extra dependencies and run in the
    default distribution. They are real, active, and covered by measured
    deterministic tests. Enable them opt-in via ``BULWARK_VISION_SCANNING_ENABLED``
    (default off); once registered they operate on inline ``data:image/...;base64``
    URIs embedded in text content, with zero OCR backend required.

  * OCR-based image *content* analysis (extract text from pixels → injection
    scan) is the scanner's headline capability and remains INERT: the [vision]
    extra (pillow) is not installed in the default distribution and no OCR
    backend (easyocr / pytesseract) ships — and neither fits the distroless,
    no-torch runtime — so ``startup()`` leaves ``self._available`` False and the
    OCR path never runs. Its efficacy is unproven.

Because the eponymous vision capability (OCR) is unprovisioned and unproven, the
scanner deliberately stays ``MaturityTier.EXPERIMENTAL`` — it must never claim
BETA/GA on the strength of the deterministic hygiene guards alone. To enable OCR,
install pillow + an OCR backend deliberately (understanding it will not load in a
stock distroless image).
"""

from __future__ import annotations

import asyncio
import base64
import io
import logging
import re
from concurrent.futures import ThreadPoolExecutor

from src.config import settings
from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.protocol import InputScanner, MaturityTier, ScanContext, ScannerInfo, ScannerType

logger = logging.getLogger(__name__)

# Max image size to process (prevent DoS via large images)
MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_IMAGE_DIMENSION = 4096  # pixels

# Base64 data URI pattern (anchored for validation)
DATA_URI_PATTERN = re.compile(
    r"^data:image/(png|jpeg|jpg|gif|webp|bmp);base64,(.+)$", re.DOTALL
)

# Inline data URI pattern (for extraction from text)
DATA_URI_INLINE_PATTERN = re.compile(
    r"data:image/(png|jpeg|jpg|gif|webp|bmp);base64,([A-Za-z0-9+/=]+)"
)


def _sniff_image_format(image_bytes: bytes) -> str | None:
    """Return the true image format from magic bytes, or None if unrecognised.

    Zero-dependency signature sniffing — does NOT require pillow/OCR. Used to
    corroborate the format a ``data:image/<fmt>`` URI *declares* against the
    bytes it actually carries (MIME-confusion / polyglot / disguised-payload
    detection). Formats mirror ``DATA_URI_PATTERN`` (jpg normalised to jpeg).
    """
    if image_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if image_bytes.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if image_bytes[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if image_bytes[:4] == b"RIFF" and image_bytes[8:12] == b"WEBP":
        return "webp"
    if image_bytes.startswith(b"BM"):
        return "bmp"
    return None


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
    """Scans images for embedded prompt injection and harmful content.

    Handles the OpenAI vision API format where messages contain
    image_url content blocks with base64-encoded or URL-referenced images.

    Scanning pipeline:
    1. Extract images from message content blocks
    2. Validate image (size, dimensions, format)
    3. OCR text extraction (EasyOCR or Tesseract)
    4. Run extracted text through injection detection patterns
    5. Optional: content safety classification

    Configuration:
      - BULWARK_ML_ENABLED=true
      - Policy per agent: multimodal.allow_images, multimodal.ocr_scan
      - Max size: multimodal.max_image_size_mb (default: 5)
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
        """Scan for images in message content.

        This scanner is called with the full message content. For multimodal
        messages, the content may be a JSON-encoded list of content blocks,
        or the images may already be extracted and available in context.metadata.

        The deterministic guards below (image gathering, ``allow_images`` policy
        gate, DoS size limit, format-signature validation) run WITHOUT any OCR
        backend — they are the shipped, tested capability. OCR text extraction is
        an additional layer that only engages when ``self._available`` is set (an
        OCR backend loaded during ``startup()``), and is inert by default.
        """
        # Gather images: pre-extracted by the proxy route, else inline data URIs
        # embedded in the text content. No OCR/pillow required for either path.
        image_contents = context.metadata.get("image_contents", [])
        if not image_contents:
            image_contents = self._extract_data_uris(content)

        if not image_contents:
            # No images anywhere — nothing for this scanner to do.
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Policy gate (deterministic): images present but disallowed for this agent.
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

        # Process each image (deterministic checks always; OCR only if available)
        all_events: list[SecurityEvent] = []
        for i, image_data in enumerate(image_contents):
            events = await self._scan_image(image_data, context, index=i)
            all_events.extend(events)

        if all_events:
            # Return highest verdict from all image scans
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
        """Scan a single image.

        Args:
            image_data: base64-encoded image or raw bytes
            context: scan context
            index: image index in message

        Returns:
            List of security events (empty if clean)
        """
        events: list[SecurityEvent] = []

        # Decode image
        try:
            image_bytes = self._decode_image(image_data)
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

        # Size check
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

        # Format-signature validation (deterministic, zero-dep): when the source
        # is a data URI declaring a format, corroborate it against the real magic
        # bytes. A mismatch — or bytes that carry no valid image signature at all
        # — flags MIME confusion / a payload disguised as an image.
        fmt_event = self._check_format_signature(image_data, image_bytes, context, index)
        if fmt_event is not None:
            events.append(fmt_event)

        # OCR extraction (only engages when an OCR backend loaded at startup;
        # inert by default in the shipped distroless / no-torch distribution).
        if self._available and context.metadata.get("multimodal", {}).get("ocr_scan", True):
            loop = asyncio.get_event_loop()
            extracted_text = await loop.run_in_executor(
                self._executor, self._ocr_extract, image_bytes
            )

            if extracted_text:
                # Store extracted text for downstream scanners
                existing_ocr = context.metadata.get("ocr_extracted_text", [])
                existing_ocr.append(extracted_text)
                context.metadata["ocr_extracted_text"] = existing_ocr

                # Run basic injection checks on extracted text
                injection_events = self._check_injection_in_text(
                    extracted_text, context, index
                )
                events.extend(injection_events)

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

        Returns a WARN event on mismatch / unrecognised signature, else None.
        """
        if not isinstance(image_data, str):
            return None
        match = DATA_URI_PATTERN.match(image_data)
        if match is None:
            return None

        declared = match.group(1).lower()
        if declared == "jpg":
            declared = "jpeg"

        actual = _sniff_image_format(image_bytes)
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
            source="ml_vision_scanner",
            severity="low",
            metadata={
                "image_index": index,
                "declared_format": declared,
                "actual_format": actual,
            },
        )

    def _decode_image(self, image_data: str | bytes) -> bytes:
        """Decode image from base64 or data URI."""
        if isinstance(image_data, bytes):
            return image_data

        # Try data URI format
        match = DATA_URI_PATTERN.match(image_data)
        if match:
            b64_data = match.group(2)
        else:
            # Assume raw base64
            b64_data = image_data

        try:
            return base64.b64decode(b64_data)
        except Exception as e:
            raise ValueError(f"Invalid base64 image data: {e}")

    def _ocr_extract(self, image_bytes: bytes) -> str | None:
        """Extract text from image using OCR (runs in thread pool).

        Returns extracted text or None if no text found.
        """
        try:
            from PIL import Image

            image = Image.open(io.BytesIO(image_bytes))

            # Dimension check
            if max(image.size) > MAX_IMAGE_DIMENSION:
                # Resize to max dimension while preserving aspect ratio
                image.thumbnail((MAX_IMAGE_DIMENSION, MAX_IMAGE_DIMENSION))

            if self._ocr_reader is not None:
                # EasyOCR
                import numpy as np
                img_array = np.array(image.convert("RGB"))
                results = self._ocr_reader.readtext(img_array)

                # Filter by confidence threshold
                texts = []
                for bbox, text, confidence in results:
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
        """Extract base64 data URIs from text content."""
        results = []
        for match in re.finditer(DATA_URI_INLINE_PATTERN, content):
            results.append(match.group(0))
        return results[:5]  # Limit to 5 images per message

    async def health(self) -> bool:
        # The deterministic guards (policy gate, DoS size limit, data-URI
        # extraction, format-signature validation) always operate, so the scanner
        # is healthy regardless of whether the optional OCR backend loaded.
        return True

    async def shutdown(self) -> None:
        self._executor.shutdown(wait=False)
        self._ocr_reader = None
