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
— so ``startup()`` leaves ``self._available`` False. Advisory mode stays inert;
blocking mode rejects requests containing images when OCR is unavailable.
Its OCR-to-injection efficacy is unproven, so the scanner is
declared ``MaturityTier.EXPERIMENTAL`` and must never claim BETA/GA.

To enable OCR, install pillow + an OCR backend deliberately (understanding it will
not load in a stock distroless image). For deterministic image hygiene without
OCR, enable the ``ImageHygieneScanner`` via ``BULWARK_IMAGE_HYGIENE_SCANNING_ENABLED``.
"""

from __future__ import annotations

import asyncio
import base64
import io
import logging
import re
from concurrent.futures import Future, ThreadPoolExecutor

from src.config import settings
from src.guardrails.input_guardrail import InputGuardrail
from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.multimodal import _image_utils
from src.scanners.protocol import InputScanner, MaturityTier, ScanContext, ScannerInfo, ScannerType

logger = logging.getLogger(__name__)

# Max image size to process before OCR (prevent DoS via large images).
MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_IMAGE_PIXELS = 8_000_000
MAX_OCR_WORKERS = 2
OCR_TIMEOUT_SECONDS = 5.0
MAX_OCR_TEXT_CHARS = 16_000
# Recognize even unsupported/malformed inline images instead of silently skipping them.
# Only a Markdown destination treats ')' as a delimiter. Keep other trailing
# junk for strict base64 validation rather than accepting a valid prefix.
_INLINE_IMAGE = re.compile(
    r"(?<=\]\()data:image/[^\s\"'<>)]*|data:image/[^\s\"'<>]*", re.IGNORECASE
)


class _ImageTooLarge(ValueError):
    """Image exceeds the pre-decode allocation limit."""


def _vision_deps_available() -> bool:
    """Check if vision dependencies are installed."""
    try:
        from PIL import Image  # noqa: F401
        return True
    except Exception:
        return False


def _ocr_available() -> bool:
    """Check if OCR backend is available."""
    try:
        import easyocr  # noqa: F401
        return True
    except Exception:
        logger.debug("easyocr_unavailable")
    try:
        import pytesseract  # noqa: F401
        return True
    except Exception:
        return False
    return False


class VisionScanner(InputScanner):
    """Scans images for embedded prompt injection via OCR text extraction.

    Handles the OpenAI vision API format where messages contain image_url
    content blocks with base64-encoded or URL-referenced images.

    Scanning pipeline:
    1. Gather images (pre-extracted metadata or inline data URIs)
    2. Pre-OCR safety: policy gate + size limit
    3. OCR text extraction (EasyOCR or Tesseract)
    4. Run extracted text through the full input-guardrail engine (same regex
       SSOT as ordinary text input). This does not detect arbitrary visual attacks.

    Without OCR, advisory mode is inert after size/count gates; blocking mode rejects images.
    OCR failures are BLOCK in blocking mode and WARN in advisory mode.
    Existing explicit image policy and byte-size gates remain BLOCK in either mode.
    """

    def __init__(
        self,
        blocking: bool = False,
        max_image_size_mb: float = 5.0,
        ocr_confidence_threshold: float = 0.3,
        ocr_model_directory: str | None = None,
    ) -> None:
        self._blocking = blocking
        self._max_image_bytes = min(int(max_image_size_mb * 1024 * 1024), MAX_IMAGE_SIZE_BYTES)
        if self._max_image_bytes <= 0:
            raise ValueError("Image size limit must be positive")
        self._ocr_threshold = ocr_confidence_threshold
        self._ocr_model_directory = ocr_model_directory
        self._executor = ThreadPoolExecutor(max_workers=MAX_OCR_WORKERS, thread_name_prefix="vision")
        self._ocr_jobs: set[Future[str | None]] = set()
        self._closed = False
        self._ocr_reader = None
        self._available = False
        # Full input-guardrail engine, reused on OCR-extracted text (see
        # _check_injection_in_text). Instantiated lazily — the pattern set is
        # heavy, so we only pay for it when an OCR backend is actually active.
        self._input_guardrail: InputGuardrail | None = None

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
        if self._closed:
            return
        self._available = False
        self._ocr_reader = None
        if not _vision_deps_available():
            logger.info("vision_scanner_skipped", extra={"reason": "pillow not installed"})
            return

        if not settings.vision_scanning_enabled:
            logger.info(
                "vision_scanner_skipped", extra={"reason": "vision scanning disabled"}
            )
            return

        if _ocr_available():
            try:
                # Try EasyOCR first (better accuracy, GPU support)
                import easyocr
                self._ocr_reader = easyocr.Reader(
                    ["en"],  # Start with English; expand in future
                    gpu=False,
                    verbose=False,
                    download_enabled=False,
                    model_storage_directory=self._ocr_model_directory,
                )
                self._available = True
                logger.info("vision_scanner_ready", extra={"ocr_backend": "easyocr"})
            except Exception:
                logger.warning("easyocr_init_failed")
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

        # Warm the shared input-guardrail engine only when OCR is genuinely
        # active, so the heavy pattern compilation is paid at startup (not on the
        # first request) and never at all when the scanner is inert.
        if self._available and self._input_guardrail is None:
            try:
                self._input_guardrail = InputGuardrail()
            except Exception:
                self._available = False
                logger.warning("vision_detection_init_failed")

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """OCR-scan images for embedded injection.

        No images always ALLOW. Size gates precede OCR availability in both modes;
        an unavailable blocking scanner must not allow unexamined images.
        """
        try:
            image_contents = self._collect_images(content, context)
        except _ImageTooLarge:
            event = self._oversize_event(context)
            return GuardrailResult(verdict=event.verdict, events=[event])
        except (TypeError, ValueError):
            event = self._failure_event(context)
            return GuardrailResult(verdict=event.verdict, events=[event])

        if not image_contents:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Check every source before the unavailable-OCR fallback, without decoding
        # or copying a potentially oversized payload. Padding gives the exact byte
        # count for valid base64; strict validation still happens on the OCR path.
        for index, image_data in enumerate(image_contents):
            if isinstance(image_data, bytes):
                too_large = len(image_data) > self._max_image_bytes
            elif len(image_data) > 4 * ((self._max_image_bytes + 2) // 3) + 64:
                too_large = True
            else:
                match = _image_utils.DATA_URI_PATTERN.fullmatch(image_data)
                encoded_length = len(image_data) - (match.start(2) if match else 0)
                padding = 2 if image_data.endswith("==") else int(image_data.endswith("="))
                too_large = (encoded_length // 4) * 3 - padding > self._max_image_bytes
            if too_large:
                event = self._oversize_event(context, index)
                return GuardrailResult(verdict=event.verdict, events=[event])

        if not self._available:
            if not self._blocking:
                return GuardrailResult(verdict=Verdict.ALLOW)
            event = self._failure_event(context)
            return GuardrailResult(verdict=event.verdict, events=[event])

        # Pre-OCR policy gate (defense in depth; ImageHygieneScanner also enforces).
        multimodal_config = context.metadata.get("multimodal", {})
        if not isinstance(multimodal_config, dict):
            event = self._failure_event(context)
            return GuardrailResult(verdict=event.verdict, events=[event])
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

    def _collect_images(self, content: str, context: ScanContext) -> list[str | bytes]:
        """Inspect all roles, not just potentially truncated proxy metadata."""
        images: list[str | bytes] = []
        for message in context.messages:
            if not isinstance(message, dict):
                raise ValueError("Invalid message")
            body = message.get("content")
            if isinstance(body, str):
                images.extend(self._extract_data_uris(body))
            elif isinstance(body, list):
                for block in body:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "image_url":
                        image = block.get("image_url")
                        if isinstance(image, dict):
                            image = image.get("url")
                        if not isinstance(image, str) or not image:
                            raise ValueError("Invalid image reference")
                        images.append(image)
                    elif block.get("type") == "text":
                        images.extend(self._extract_data_uris(block.get("text", "")))
                    if len(images) > _image_utils.MAX_INLINE_IMAGES:
                        raise ValueError("Too many images")
            if len(images) > _image_utils.MAX_INLINE_IMAGES:
                raise ValueError("Too many images")

        supplied = context.metadata.get("image_contents", [])
        if not isinstance(supplied, (list, tuple)) or len(supplied) > _image_utils.MAX_INLINE_IMAGES:
            raise ValueError("Invalid image collection")
        # Metadata and flattened content can mirror the original messages.
        for source in (supplied, self._extract_data_uris(content)):
            for image in source:
                if not isinstance(image, (str, bytes)) or not image:
                    raise ValueError("Invalid image reference")
                if image not in images:
                    images.append(image)
                if len(images) > _image_utils.MAX_INLINE_IMAGES:
                    raise ValueError("Too many images")
        return images

    def _failure_event(self, context: ScanContext, index: int = 0) -> SecurityEvent:
        return SecurityEvent(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            request_id=context.request_id,
            verdict=Verdict.BLOCK if self._blocking else Verdict.WARN,
            category=ThreatCategory.POLICY_VIOLATION,
            description="Image OCR inspection could not be completed",
            source="ml_vision_scanner",
            severity="medium",
            metadata={"image_index": index},
        )

    def _oversize_event(self, context: ScanContext, index: int = 0) -> SecurityEvent:
        event = self._failure_event(context, index)
        event.verdict = Verdict.BLOCK
        event.category = ThreatCategory.DENIAL_OF_SERVICE
        event.description = "Image too large for OCR inspection"
        return event

    async def _scan_image(
        self,
        image_data: str | bytes,
        context: ScanContext,
        index: int = 0,
    ) -> list[SecurityEvent]:
        """OCR-scan a single image (only reached when ``self._available``)."""
        events: list[SecurityEvent] = []

        # Bound the encoded input before allocating decoded bytes.
        try:
            if isinstance(image_data, bytes):
                image_bytes = image_data
            else:
                if len(image_data) > 4 * ((self._max_image_bytes + 2) // 3) + 64:
                    return [self._oversize_event(context, index)]
                match = _image_utils.DATA_URI_PATTERN.fullmatch(image_data)
                encoded = match.group(2) if match else image_data
                image_bytes = base64.b64decode(encoded, validate=True)
        except (TypeError, ValueError):
            return [self._failure_event(context, index)]

        # Pre-OCR size check (DoS guard on the OCR path itself)
        if len(image_bytes) > self._max_image_bytes:
            return [self._oversize_event(context, index)]

        # OCR extraction + injection scan on the extracted text.
        if not context.metadata.get("multimodal", {}).get("ocr_scan", True):
            return [self._failure_event(context, index)] if self._blocking else []
        try:
            # Keep the concurrent future alive across cancellation/timeouts. Releasing
            # a slot when the awaiter ends would allow an unbounded executor queue.
            self._ocr_jobs = {job for job in self._ocr_jobs if not job.done()}
            if self._closed or len(self._ocr_jobs) >= MAX_OCR_WORKERS:
                return [self._failure_event(context, index)]
            job = self._executor.submit(self._ocr_extract, image_bytes)
            self._ocr_jobs.add(job)
            pending = asyncio.wrap_future(job)
            pending.add_done_callback(lambda done: None if done.cancelled() else done.exception())
            extracted_text = await asyncio.wait_for(asyncio.shield(pending), OCR_TIMEOUT_SECONDS)
            if extracted_text is not None and not isinstance(extracted_text, str):
                raise ValueError("Invalid OCR result")
            if extracted_text:
                if len(extracted_text) > MAX_OCR_TEXT_CHARS:
                    raise ValueError("OCR text exceeds limit")
                injection_events = self._check_injection_in_text(
                    extracted_text, context, index
                )
                events.extend(injection_events)
        except Exception:
            return [self._failure_event(context, index)]

        return events

    def _ocr_extract(self, image_bytes: bytes) -> str | None:
        """Extract text from image using OCR (runs in thread pool).

        None means successful OCR with no text; failures propagate to the caller.
        """
        from PIL import Image

        with Image.open(io.BytesIO(image_bytes)) as image:
            width, height = image.size
            if (
                min(width, height) <= 0
                or max(width, height) > _image_utils.MAX_IMAGE_DIMENSION
                or width * height > MAX_IMAGE_PIXELS
                or getattr(image, "n_frames", 1) != 1
            ):
                raise ValueError("Unsupported image geometry or frames")
            # Reject rather than downscale/scan only frame zero, which loses content.
            image.load()

            if self._ocr_reader is not None:
                # EasyOCR
                import numpy as np
                img_array = np.array(image.convert("RGB"))
                results = self._ocr_reader.readtext(img_array)

                # Filter by confidence threshold
                texts = []
                text_size = 0
                for _bbox, text, confidence in results:
                    if confidence >= self._ocr_threshold:
                        text_size += len(text) + 1
                        if text_size > MAX_OCR_TEXT_CHARS:
                            raise ValueError("OCR text exceeds limit")
                        texts.append(text)

                return " ".join(texts) if texts else None
            else:
                # pytesseract fallback
                import pytesseract
                text = pytesseract.image_to_string(image, timeout=OCR_TIMEOUT_SECONDS)
                if len(text) > MAX_OCR_TEXT_CHARS:
                    raise ValueError("OCR text exceeds limit")
                return text.strip() if text.strip() else None

    def _check_injection_in_text(
        self,
        text: str,
        context: ScanContext,
        image_index: int,
    ) -> list[SecurityEvent]:
        """Run OCR-extracted text through the full input-guardrail engine.

        Text smuggled inside an image is judged by the *same* 4600-pattern regex
        SSOT (Unicode normalization + entropy + multi-layer decoding) that vets
        ordinary text input, rather than a hand-picked subset. OCR can miss visual
        content; it is not protection against arbitrary visual attacks. No extra
        dependency, keeping this distroless-safe. Each detection is
        re-contextualized as image-borne (source + metadata) for SIEM clarity.
        """
        guardrail = self._input_guardrail
        if guardrail is None:
            # Lazy fallback (e.g. self._available set without startup()).
            guardrail = self._input_guardrail = InputGuardrail()

        if len(text.encode("utf-8")) > guardrail.max_scan_bytes:
            raise ValueError("OCR text exceeds detection budget")
        result = guardrail.inspect(text, context.tenant_id, context.agent_id)

        events: list[SecurityEvent] = []
        for ev in result.events:
            # Rebuild from safe fields; descriptions, matches and metadata may
            # contain OCR payloads and must not escape into telemetry.
            events.append(SecurityEvent(
                tenant_id=context.tenant_id,
                agent_id=context.agent_id,
                request_id=context.request_id,
                verdict=ev.verdict if self._blocking else Verdict.WARN,
                category=ev.category,
                severity=ev.severity,
                source="ml_vision_scanner",
                description=f"[OCR image #{image_index}] Suspicious extracted text detected",
                metadata={
                    "image_index": image_index,
                    "detection_engine": "input_guardrail",
                    "via": "ocr",
                },
            ))

        return events

    def _extract_data_uris(self, content: str) -> list[str]:
        """Reject overflow before the shared extractor's five-image truncation."""
        for count, _match in enumerate(re.finditer(r"data:image/", content, re.IGNORECASE), 1):
            if count > _image_utils.MAX_INLINE_IMAGES:
                raise ValueError("Too many images")
        images: list[str] = []
        for match in _INLINE_IMAGE.finditer(content):
            if len(images) >= _image_utils.MAX_INLINE_IMAGES:
                raise ValueError("Too many images")
            if match.end() - match.start() > 4 * ((self._max_image_bytes + 2) // 3) + 64:
                raise _ImageTooLarge("Encoded image exceeds limit")
            images.append(match.group(0))
        return images

    async def health(self) -> bool:
        # EXPERIMENTAL OCR layer. Registered only when vision scanning is opted in.
        # When it is, report unhealthy unless an OCR backend actually loaded — this
        # surfaces a WARN in admin so the operator knows the flag is on but no
        # image-content analysis is happening (pillow + OCR backend not installed),
        # rather than implying a functional vision scanner. For deterministic image
        # hygiene without OCR, use the ImageHygieneScanner instead.
        if self._closed:
            return False
        if not settings.vision_scanning_enabled and not self._blocking:
            return True
        return self._available

    async def shutdown(self) -> None:
        self._closed = True
        self._available = False
        self._executor.shutdown(wait=False, cancel_futures=True)
        # Running threads still own the reader; do not switch their OCR backend.
