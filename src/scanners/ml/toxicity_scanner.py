"""
Toxicity Scanner — ML-based toxic/harmful content detection.

Detects toxic, hateful, harassing, violent, or otherwise unsafe content
in user inputs and/or LLM outputs. Uses a multi-label classifier.

Categories detected:
  - toxicity (general)
  - severe_toxicity
  - obscene
  - threat
  - insult
  - identity_attack

Default mode: async (enrichment)
Model: Fine-tuned unitary/toxic-bert or similar (ONNX exported)
Expected path: models/toxicity/model.onnx
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

MODEL_NAME = "toxicity"
DEFAULT_LABELS = ["neutral", "toxic"]


class ToxicityScanner(InputScanner):
    """ML-based toxicity detection using ONNX Runtime.

    Multi-label classifier that detects various types of toxic content.
    Useful for:
      - Content moderation before LLM processing
      - Detecting social engineering via aggressive language
      - Enforcing acceptable use policies
      - Compliance with content safety requirements

    Configuration:
      - SENTINEL_ML_ENABLED=true
      - Model files at: models/toxicity/{model.onnx, tokenizer.json}
    """

    def __init__(
        self,
        blocking: bool = False,
        threshold: float = 0.7,
        severe_threshold: float = 0.5,
    ) -> None:
        self._blocking = blocking
        self._threshold = threshold
        self._severe_threshold = severe_threshold
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ml-toxicity")
        self._model_loaded = False

    @property
    def info(self) -> ScannerInfo:
        scanner_type = (
            ScannerType.INPUT_BLOCKING if self._blocking else ScannerType.INPUT_ASYNC
        )
        return ScannerInfo(
            name="ml_toxicity",
            version="1.0.0",
            scanner_type=scanner_type,
            description="ML-based toxic/harmful content detection (multi-label)",
            author="sentinel",
            priority=25,
        )

    async def startup(self) -> None:
        """Load the ONNX model on startup."""
        if not ml_dependencies_available():
            logger.info("ml_toxicity_skipped", extra={"reason": "dependencies not installed"})
            return

        if not settings.ml_enabled:
            logger.info("ml_toxicity_skipped", extra={"reason": "SENTINEL_ML_ENABLED=false"})
            return

        manager = get_model_manager()
        model = manager.load_model(MODEL_NAME, labels=DEFAULT_LABELS)
        self._model_loaded = model is not None
        if self._model_loaded:
            logger.info("ml_toxicity_scanner_ready")

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Classify input for toxicity.

        Returns:
            BLOCK if toxic confidence >= severe_threshold
            WARN if toxic confidence >= threshold
            ALLOW otherwise

        Supports both binary (neutral/toxic) and multi-label model outputs.
        """
        if not self._model_loaded:
            return GuardrailResult(verdict=Verdict.ALLOW)

        loop = asyncio.get_event_loop()
        predictions = await loop.run_in_executor(
            self._executor, self._predict, content
        )

        if predictions is None:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Determine toxic score (handles both binary and multi-label)
        toxic_score = predictions.get("toxic", 0.0)
        if toxic_score:
            # Binary model: use toxic score directly with threshold-based logic
            if toxic_score >= self._severe_threshold:
                return GuardrailResult(
                    verdict=Verdict.BLOCK,
                    events=[
                        SecurityEvent(
                            tenant_id=context.tenant_id,
                            agent_id=context.agent_id,
                            verdict=Verdict.BLOCK,
                            category=ThreatCategory.POLICY_VIOLATION,
                            description=f"Toxic content detected (confidence: {toxic_score:.3f})",
                            source="ml_toxicity",
                            severity="high",
                            metadata={
                                "toxicity_scores": predictions,
                                "model": MODEL_NAME,
                            },
                        )
                    ],
                )
            if toxic_score >= self._threshold:
                return GuardrailResult(
                    verdict=Verdict.WARN,
                    events=[
                        SecurityEvent(
                            tenant_id=context.tenant_id,
                            agent_id=context.agent_id,
                            verdict=Verdict.WARN,
                            category=ThreatCategory.POLICY_VIOLATION,
                            description=f"Potentially toxic content (confidence: {toxic_score:.3f})",
                            source="ml_toxicity",
                            severity="medium",
                            metadata={
                                "toxicity_scores": predictions,
                                "model": MODEL_NAME,
                            },
                        )
                    ],
                )
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Multi-label model: check severe categories for BLOCK
        severe_score = max(
            predictions.get("severe_toxicity", 0.0),
            predictions.get("threat", 0.0),
        )
        if severe_score >= self._severe_threshold:
            return GuardrailResult(
                verdict=Verdict.BLOCK,
                events=[
                    SecurityEvent(
                        tenant_id=context.tenant_id,
                        agent_id=context.agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.POLICY_VIOLATION,
                        description=f"Toxic content detected (severe: {severe_score:.3f})",
                        source="ml_toxicity",
                        severity="high",
                        metadata={
                            "toxicity_scores": predictions,
                            "model": MODEL_NAME,
                        },
                    )
                ],
            )

        # General toxicity categories → WARN only
        general_score = max(
            predictions.get("toxicity", 0.0),
            predictions.get("insult", 0.0),
            predictions.get("obscene", 0.0),
            predictions.get("identity_attack", 0.0),
        )
        if general_score >= self._threshold:
            return GuardrailResult(
                verdict=Verdict.WARN,
                events=[
                    SecurityEvent(
                        tenant_id=context.tenant_id,
                        agent_id=context.agent_id,
                        verdict=Verdict.WARN,
                        category=ThreatCategory.POLICY_VIOLATION,
                        description=f"Potentially toxic content (confidence: {general_score:.3f})",
                        source="ml_toxicity",
                        severity="medium",
                        metadata={
                            "toxicity_scores": predictions,
                            "model": MODEL_NAME,
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
        if not settings.ml_enabled:
            return True
        return self._model_loaded

    async def shutdown(self) -> None:
        self._executor.shutdown(wait=False)
