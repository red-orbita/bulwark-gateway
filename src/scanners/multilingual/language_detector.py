"""
Language Detector Scanner — Identifies input language for downstream routing.

Priority: 5 (runs before all other scanners)
Mode: BLOCKING (must complete to inform downstream scanners)

Detection backends (in preference order):
  1. lingua-language-detector (most accurate, pure Python)
  2. fasttext-langdetect (fast, requires model download)
  3. Simple heuristic fallback (script-based detection for CJK/Arabic/Cyrillic)

Policy enforcement:
  - allowed_languages: list of ISO 639-1 codes permitted for this agent
  - block_unknown_language: whether to block undetectable language (default: false)

The detected language is stored in context.metadata["detected_language"] for
downstream scanners (multilingual patterns, ML classifiers).
"""

from __future__ import annotations

import logging
from collections import Counter

from src.config import settings
from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.protocol import InputScanner, ScanContext, ScannerInfo, ScannerType

logger = logging.getLogger(__name__)


def _lingua_available() -> bool:
    """Check if lingua-language-detector is installed."""
    try:
        import lingua  # noqa: F401
        return True
    except ImportError:
        return False


def _fasttext_available() -> bool:
    """Check if fasttext is installed."""
    try:
        import fasttext  # noqa: F401
        return True
    except ImportError:
        return False


# Unicode script ranges for heuristic detection
SCRIPT_RANGES: dict[str, list[tuple[int, int]]] = {
    "han": [(0x4E00, 0x9FFF), (0x3400, 0x4DBF), (0xF900, 0xFAFF)],  # CJK
    "hiragana": [(0x3040, 0x309F)],
    "katakana": [(0x30A0, 0x30FF)],
    "hangul": [(0xAC00, 0xD7AF), (0x1100, 0x11FF)],
    "arabic": [(0x0600, 0x06FF), (0x0750, 0x077F), (0xFB50, 0xFDFF)],
    "cyrillic": [(0x0400, 0x04FF), (0x0500, 0x052F)],
    "devanagari": [(0x0900, 0x097F)],
    "thai": [(0x0E00, 0x0E7F)],
    "latin": [(0x0041, 0x005A), (0x0061, 0x007A), (0x00C0, 0x024F)],
}

# Script to likely language (heuristic, not definitive)
SCRIPT_TO_LANG: dict[str, str] = {
    "han": "zh",
    "hiragana": "ja",
    "katakana": "ja",
    "hangul": "ko",
    "arabic": "ar",
    "cyrillic": "ru",
    "devanagari": "hi",
    "thai": "th",
}


class LanguageDetector(InputScanner):
    """Identifies input language and enforces language policy.

    This scanner MUST run first (priority=5, blocking) so downstream
    scanners can use the detected language to select appropriate
    pattern sets and models.

    Detection pipeline:
    1. Try lingua (most accurate)
    2. Try fasttext (fast, needs model)
    3. Fall back to Unicode script heuristics

    Results stored in context.metadata["detected_language"] as ISO 639-1.
    Also stores confidence score in context.metadata["language_confidence"].
    """

    def __init__(
        self,
        min_confidence: float = 0.6,
        min_text_length: int = 10,
    ) -> None:
        self._min_confidence = min_confidence
        self._min_text_length = min_text_length
        self._backend: str = "heuristic"
        self._lingua_detector = None
        self._fasttext_model = None

    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="language_detector",
            version="1.0.0",
            scanner_type=ScannerType.INPUT_BLOCKING,
            description="Language identification + policy enforcement",
            author="sentinel",
            priority=5,  # Highest priority: must run first
        )

    async def startup(self) -> None:
        """Initialize the best available detection backend."""
        if _lingua_available():
            try:
                from lingua import LanguageDetectorBuilder

                self._lingua_detector = (
                    LanguageDetectorBuilder.from_all_languages()
                    .with_preloaded_language_models()
                    .build()
                )
                self._backend = "lingua"
                logger.info("language_detector_ready", extra={"backend": "lingua"})
                return
            except Exception as e:
                logger.warning(
                    "lingua_init_failed",
                    extra={"error": str(e)[:100]},
                )

        if _fasttext_available():
            try:
                import fasttext

                model_path = settings.ml_model_dir / "lid.176.ftz"
                if model_path.exists():
                    # Suppress fasttext warnings
                    fasttext.FastText.eprint = lambda x: None
                    self._fasttext_model = fasttext.load_model(str(model_path))
                    self._backend = "fasttext"
                    logger.info("language_detector_ready", extra={"backend": "fasttext"})
                    return
                else:
                    logger.info(
                        "fasttext_model_missing",
                        extra={"path": str(model_path)},
                    )
            except Exception as e:
                logger.warning(
                    "fasttext_init_failed",
                    extra={"error": str(e)[:100]},
                )

        # Fallback to heuristic (always available)
        self._backend = "heuristic"
        logger.info("language_detector_ready", extra={"backend": "heuristic"})

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Detect language and enforce policy.

        Steps:
        1. Detect language + confidence (skip if already set in context)
        2. Store in context.metadata for downstream scanners
        3. Check against allowed_languages policy (if configured)
        4. Detect code-switching (language mixing as evasion technique)
        """
        # If language already detected (e.g., by upstream or pre-configured), skip detection
        if "detected_language" in context.metadata and context.metadata["detected_language"] not in ("", None):
            detected = context.metadata["detected_language"]
            confidence = context.metadata.get("language_confidence", 1.0)
        elif len(content.strip()) < self._min_text_length:
            # Skip very short text (unreliable detection)
            context.metadata["detected_language"] = "en"  # Default assumption
            context.metadata["language_confidence"] = 0.0
            context.metadata["language_backend"] = self._backend
            return GuardrailResult(verdict=Verdict.ALLOW)
        else:
            # Detect language
            detected, confidence = self._detect(content)

            # Store in context for downstream scanners
            context.metadata["detected_language"] = detected
            context.metadata["language_confidence"] = confidence
            context.metadata["language_backend"] = self._backend

        # Check for code-switching (potential evasion)
        if len(content) > 50:
            mixed = self._detect_code_switching(content)
            if mixed:
                context.metadata["code_switching"] = True
                context.metadata["detected_scripts"] = mixed

        # Policy enforcement: allowed_languages
        allowed_languages = context.metadata.get("allowed_languages")
        if allowed_languages and detected:
            if detected not in allowed_languages:
                block_unknown = context.metadata.get("block_unknown_language", False)

                # Low confidence + unknown → might be wrong detection, warn only
                if confidence < self._min_confidence:
                    if block_unknown:
                        return GuardrailResult(
                            verdict=Verdict.WARN,
                            events=[
                                SecurityEvent(
                                    tenant_id=context.tenant_id,
                                    agent_id=context.agent_id,
                                    verdict=Verdict.WARN,
                                    category=ThreatCategory.POLICY_VIOLATION,
                                    description=(
                                        f"Unrecognized language (detected: '{detected}', "
                                        f"confidence: {confidence:.2f}). "
                                        f"Allowed: {allowed_languages}"
                                    ),
                                    source="language_detector",
                                    severity="low",
                                    metadata={
                                        "detected_language": detected,
                                        "confidence": confidence,
                                        "allowed_languages": allowed_languages,
                                    },
                                )
                            ],
                        )
                else:
                    # High confidence, clearly wrong language
                    return GuardrailResult(
                        verdict=Verdict.BLOCK,
                        events=[
                            SecurityEvent(
                                tenant_id=context.tenant_id,
                                agent_id=context.agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.POLICY_VIOLATION,
                                description=(
                                    f"Language '{detected}' not allowed for this agent. "
                                    f"Allowed: {allowed_languages}"
                                ),
                                source="language_detector",
                                severity="medium",
                                metadata={
                                    "detected_language": detected,
                                    "confidence": confidence,
                                    "allowed_languages": allowed_languages,
                                },
                            )
                        ],
                    )

        return GuardrailResult(verdict=Verdict.ALLOW)

    def _detect(self, text: str) -> tuple[str, float]:
        """Detect language using best available backend.

        Returns (iso_code, confidence) tuple.
        """
        if self._backend == "lingua" and self._lingua_detector is not None:
            return self._detect_lingua(text)
        elif self._backend == "fasttext" and self._fasttext_model is not None:
            return self._detect_fasttext(text)
        else:
            return self._detect_heuristic(text)

    def _detect_lingua(self, text: str) -> tuple[str, float]:
        """Detect using lingua-language-detector."""
        try:

            result = self._lingua_detector.detect_language_of(text)  # type: ignore[attr-defined]
            if result is None:
                return ("unknown", 0.0)

            # Get confidence
            confidences = self._lingua_detector.compute_language_confidence_values(text)  # type: ignore[attr-defined]
            confidence = 0.0
            for lang_conf in confidences:
                if lang_conf.language == result:
                    confidence = lang_conf.value
                    break

            # Convert lingua Language enum to ISO 639-1
            iso_code = result.iso_code_639_1.name.lower()
            return (iso_code, confidence)

        except Exception as e:
            logger.debug("lingua_detection_failed", extra={"error": str(e)[:100]})
            return self._detect_heuristic(text)

    def _detect_fasttext(self, text: str) -> tuple[str, float]:
        """Detect using fasttext."""
        try:
            # fasttext needs single line
            clean_text = text.replace("\n", " ").strip()
            predictions = self._fasttext_model.predict(clean_text, k=1)  # type: ignore[attr-defined]
            label = predictions[0][0]  # __label__en
            confidence = float(predictions[1][0])
            iso_code = label.replace("__label__", "")
            return (iso_code, confidence)

        except Exception as e:
            logger.debug("fasttext_detection_failed", extra={"error": str(e)[:100]})
            return self._detect_heuristic(text)

    def _detect_heuristic(self, text: str) -> tuple[str, float]:
        """Heuristic detection based on Unicode script analysis.

        Fast fallback that works without external dependencies.
        Identifies scripts (Han, Arabic, Cyrillic, etc.) and maps to languages.
        """
        script_counts: Counter = Counter()

        for char in text:
            if char.isspace() or char in ".,;:!?-()[]{}\"'":
                continue
            cp = ord(char)
            for script_name, ranges in SCRIPT_RANGES.items():
                for start, end in ranges:
                    if start <= cp <= end:
                        script_counts[script_name] = script_counts.get(script_name, 0) + 1
                        break

        if not script_counts:
            return ("unknown", 0.0)

        total_chars = sum(script_counts.values())
        dominant_script = script_counts.most_common(1)[0]
        script_name = dominant_script[0]
        script_ratio = dominant_script[1] / total_chars

        # Map script to language
        if script_name in SCRIPT_TO_LANG:
            return (SCRIPT_TO_LANG[script_name], script_ratio)
        elif script_name == "latin":
            # Latin script → default to English (most common case)
            # Real detection would need n-gram analysis
            return ("en", script_ratio * 0.6)  # Lower confidence for Latin
        else:
            return ("unknown", 0.0)

    def _detect_code_switching(self, text: str) -> list[str] | None:
        """Detect script mixing (potential evasion technique).

        Attackers sometimes mix scripts to bypass monolingual filters:
        - Cyrillic 'а' looks like Latin 'a' (homoglyph)
        - Injecting CJK in middle of English text
        - Arabic RTL mixed with LTR text

        Returns list of detected scripts if multiple are present.
        """
        scripts_found: set[str] = set()

        for char in text:
            if char.isspace() or char in ".,;:!?-()[]{}\"'0123456789":
                continue
            cp = ord(char)
            for script_name, ranges in SCRIPT_RANGES.items():
                for start, end in ranges:
                    if start <= cp <= end:
                        scripts_found.add(script_name)
                        break

        # Treat hiragana+katakana+han as single "Japanese" context (normal)
        japanese_scripts = {"hiragana", "katakana", "han"}
        if scripts_found & japanese_scripts:
            # If ONLY Japanese scripts + maybe latin → normal
            non_jp = scripts_found - japanese_scripts - {"latin"}
            if not non_jp:
                return None

        # Multiple non-related scripts = potential evasion
        if len(scripts_found) >= 3:
            return sorted(scripts_found)

        # Two scripts is common (e.g., Latin + one other in multilingual text)
        # Flag only if unusual combinations
        if len(scripts_found) == 2 and "latin" not in scripts_found:
            return sorted(scripts_found)

        return None

    async def health(self) -> bool:
        return True  # Heuristic fallback always works

    async def shutdown(self) -> None:
        self._lingua_detector = None
        self._fasttext_model = None
