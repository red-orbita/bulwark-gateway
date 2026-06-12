"""
Injection Classifier — ML-based prompt injection detection.

Uses a fine-tuned DeBERTa model (exported to ONNX) to detect prompt
injection attempts that may evade regex patterns. Catches:
  - Paraphrased injection attempts
  - Novel attack formulations
  - Semantic injection (meaning-based, not keyword-based)
  - Multilingual attacks (if multilingual model is used)

Default mode: async (enrichment, no latency impact)
Optional: blocking mode (adds 20-50ms latency with ONNX on CPU)

Model: Fine-tuned on prompt injection datasets (deepset, protectai)
Expected model path: models/injection-classifier/model.onnx
"""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor

from src.config import settings
from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.ml.model_manager import get_model_manager, ml_dependencies_available
from src.scanners.protocol import InputScanner, ScanContext, ScannerInfo, ScannerType

logger = logging.getLogger(__name__)

MODEL_NAME = "injection-classifier"
DEFAULT_LABELS = ["SAFE", "INJECTION"]


class InjectionClassifier(InputScanner):
    """ML-based prompt injection classifier using ONNX Runtime.

    Runs inference on a DeBERTa-based binary classifier that predicts
    whether input text is a prompt injection attempt.

    Configuration:
      - SENTINEL_ML_ENABLED=true (required to activate)
      - SENTINEL_ML_BLOCKING=true (to run in hot path, adds latency)
      - SENTINEL_ML_BLOCK_THRESHOLD=0.9 (confidence to auto-block)
      - SENTINEL_ML_WARN_THRESHOLD=0.7 (confidence to warn)
      - Model files at: models/injection-classifier/{model.onnx, tokenizer.json}
    """

    def __init__(
        self,
        blocking: bool | None = None,
        block_threshold: float | None = None,
        warn_threshold: float | None = None,
    ) -> None:
        self._blocking = blocking if blocking is not None else settings.ml_blocking
        self._block_threshold = block_threshold or settings.ml_block_threshold
        self._warn_threshold = warn_threshold or settings.ml_warn_threshold
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ml-injection")
        self._model_loaded = False

    @property
    def info(self) -> ScannerInfo:
        scanner_type = (
            ScannerType.INPUT_BLOCKING if self._blocking else ScannerType.INPUT_ASYNC
        )
        return ScannerInfo(
            name="ml_injection_classifier",
            version="1.0.0",
            scanner_type=scanner_type,
            description="ML-based prompt injection detection (DeBERTa/ONNX)",
            author="sentinel",
            priority=20,  # After regex (priority=10) if blocking
        )

    async def startup(self) -> None:
        """Load the ONNX model on startup and run warmup inference."""
        if not ml_dependencies_available():
            logger.info("ml_injection_skipped", extra={"reason": "dependencies not installed"})
            return

        if not settings.ml_enabled:
            logger.info("ml_injection_skipped", extra={"reason": "SENTINEL_ML_ENABLED=false"})
            return

        manager = get_model_manager()
        model = manager.load_model(MODEL_NAME, labels=DEFAULT_LABELS)
        self._model_loaded = model is not None
        if self._model_loaded:
            # Warmup inference to avoid cold-start latency on first request
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(self._executor, self._predict, "warmup test")
            logger.info("ml_injection_classifier_ready")

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Classify input as benign or injection.

        Returns:
            BLOCK if confidence >= block_threshold
            WARN if confidence >= warn_threshold
            ALLOW otherwise
        """
        if not self._model_loaded:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Run inference in thread pool (CPU-bound)
        loop = asyncio.get_event_loop()
        predictions = await loop.run_in_executor(
            self._executor, self._predict, content
        )

        if predictions is None:
            return GuardrailResult(verdict=Verdict.ALLOW)

        injection_score = predictions.get("INJECTION", predictions.get("injection", 0.0))

        if injection_score >= self._block_threshold:
            return GuardrailResult(
                verdict=Verdict.BLOCK,
                events=[
                    SecurityEvent(
                        tenant_id=context.tenant_id,
                        agent_id=context.agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.PROMPT_INJECTION,
                        description=f"ML classifier detected prompt injection (confidence: {injection_score:.3f})",
                        source="ml_injection_classifier",
                        severity="high",
                        metadata={
                            "ml_confidence": injection_score,
                            "model": MODEL_NAME,
                            "threshold": self._block_threshold,
                        },
                    )
                ],
            )

        if injection_score >= self._warn_threshold:
            return GuardrailResult(
                verdict=Verdict.WARN,
                events=[
                    SecurityEvent(
                        tenant_id=context.tenant_id,
                        agent_id=context.agent_id,
                        verdict=Verdict.WARN,
                        category=ThreatCategory.PROMPT_INJECTION,
                        description=f"ML classifier: possible prompt injection (confidence: {injection_score:.3f})",
                        source="ml_injection_classifier",
                        severity="medium",
                        metadata={
                            "ml_confidence": injection_score,
                            "model": MODEL_NAME,
                            "threshold": self._warn_threshold,
                        },
                    )
                ],
            )

        return GuardrailResult(verdict=Verdict.ALLOW)

    def _predict(self, text: str) -> dict[str, float] | None:
        """Synchronous prediction (runs in thread pool)."""
        manager = get_model_manager()
        return manager.predict(MODEL_NAME, text)

    async def health(self) -> bool:
        """Healthy if model is loaded or ML is disabled."""
        if not settings.ml_enabled:
            return True  # Disabled is valid state
        return self._model_loaded

    async def shutdown(self) -> None:
        """Shutdown thread pool."""
        self._executor.shutdown(wait=False)
