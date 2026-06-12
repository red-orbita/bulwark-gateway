"""
Multimodal Scanners — Image and multimedia content scanning.

Provides:
  - VisionScanner: OCR extraction + injection detection in images

Handles OpenAI vision API format:
  {"role": "user", "content": [
      {"type": "text", "text": "..."},
      {"type": "image_url", "image_url": {"url": "data:image/png;base64,..."}}
  ]}
"""

from src.scanners.multimodal.vision_scanner import VisionScanner

__all__ = ["VisionScanner"]
