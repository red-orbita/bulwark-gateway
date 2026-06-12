"""
Multilingual Scanners — Language-aware security detection.

Provides:
  - LanguageDetector: Identifies input language (sets context.language)
  - MultilingualPatterns: Language-specific attack patterns (regex)
  - MultilingualInjectionClassifier: XLM-R/mDeBERTa ML scanner (Phase 3.3)

Strategy:
  1. LanguageDetector runs first (blocking, priority=5) to identify language
  2. Downstream scanners use context.language to select pattern sets
  3. ML multilingual model covers 100+ languages in single model
  4. Policy enforcement: allowed_languages per agent
"""

from src.scanners.multilingual.language_detector import LanguageDetector
from src.scanners.multilingual.patterns import MultilingualPatterns

__all__ = [
    "LanguageDetector",
    "MultilingualPatterns",
]
