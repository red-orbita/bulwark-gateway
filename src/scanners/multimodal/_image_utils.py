"""
Shared, stateless image helpers for the multimodal scanners.

These are zero-dependency utilities (no pillow / OCR) used by both the
deterministic ``ImageHygieneScanner`` and the OCR-based ``VisionScanner`` so
there is a single source of truth for data-URI parsing, base64 decoding and
magic-byte format sniffing.
"""

from __future__ import annotations

import base64
import re

# Max image dimension (pixels) the OCR path will process before downscaling.
MAX_IMAGE_DIMENSION = 4096

# Base64 data URI pattern (anchored, for validation of a single value).
DATA_URI_PATTERN = re.compile(
    r"^data:image/(png|jpeg|jpg|gif|webp|bmp);base64,(.+)$", re.DOTALL
)

# Inline data URI pattern (for extraction of multiple URIs embedded in text).
DATA_URI_INLINE_PATTERN = re.compile(
    r"data:image/(png|jpeg|jpg|gif|webp|bmp);base64,([A-Za-z0-9+/=]+)"
)

# Max inline images to pull out of one message (DoS guard on extraction itself).
MAX_INLINE_IMAGES = 5


def sniff_image_format(image_bytes: bytes) -> str | None:
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


def extract_data_uris(content: str) -> list[str]:
    """Extract inline base64 ``data:image`` URIs from text content.

    Returns at most ``MAX_INLINE_IMAGES`` URIs to bound the work done on a
    single hostile message.
    """
    results: list[str] = []
    for match in DATA_URI_INLINE_PATTERN.finditer(content):
        results.append(match.group(0))
        if len(results) >= MAX_INLINE_IMAGES:
            break
    return results


def decode_image(image_data: str | bytes) -> bytes:
    """Decode image bytes from raw bytes, a data URI, or bare base64.

    Raises ``ValueError`` on invalid base64.
    """
    if isinstance(image_data, bytes):
        return image_data

    match = DATA_URI_PATTERN.match(image_data)
    b64_data = match.group(2) if match else image_data

    try:
        return base64.b64decode(b64_data)
    except Exception as e:  # noqa: BLE001 - normalise to ValueError for callers
        raise ValueError(f"Invalid base64 image data: {e}") from e


def declared_format(image_data: str | bytes) -> str | None:
    """Return the format a data URI declares (jpg normalised to jpeg), or None.

    Only a ``data:image/<fmt>`` URI makes a format claim; raw bytes / bare
    base64 declare nothing, so there is nothing to corroborate.
    """
    if not isinstance(image_data, str):
        return None
    match = DATA_URI_PATTERN.match(image_data)
    if match is None:
        return None
    fmt = match.group(1).lower()
    return "jpeg" if fmt == "jpg" else fmt
