"""
Multimodal Scanners — Image and multimedia content scanning.

Provides:
  - ImageHygieneScanner: deterministic, zero-dependency image guards (BETA)
    (allow_images policy gate, DoS size limit, base64 + magic-byte validation)
  - VisionScanner: OCR extraction + injection detection in images (EXPERIMENTAL)

Handles OpenAI vision API format:
  {"role": "user", "content": [
      {"type": "text", "text": "..."},
      {"type": "image_url", "image_url": {"url": "data:image/png;base64,..."}}
  ]}
"""

from src.scanners.multimodal.image_hygiene_scanner import ImageHygieneScanner
from src.scanners.multimodal.vision_scanner import VisionScanner

__all__ = ["ImageHygieneScanner", "VisionScanner"]
