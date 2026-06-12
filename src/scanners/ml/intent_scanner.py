"""
Intent Scanner — ML-based adversarial intent detection.

Detects subtle adversarial intents that regex patterns miss:
  - Social engineering (authority impersonation, urgency, emotional manipulation)
  - Manipulation (gaslighting, false context, pretexting)
  - Escalation attempts (privilege escalation, scope creep, boundary testing)
  - Evasion (deliberately obfuscating true intent)

Uses a multi-label classifier to produce per-category confidence scores.

Default mode: async (enrichment)
Model: Multi-label text classifier (ONNX)
Expected path: models/intent-classifier/model.onnx
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

MODEL_NAME = "intent-classifier"

# Intent labels the model produces
INTENT_LABELS = [
    "benign",
    "social_engineering",
    "manipulation",
    "escalation_attempt",
    "evasion",
]

# Map intent labels to threat categories
INTENT_TO_CATEGORY: dict[str, ThreatCategory] = {
    "social_engineering": ThreatCategory.PROMPT_INJECTION,
    "manipulation": ThreatCategory.JAILBREAK,
    "escalation_attempt": ThreatCategory.EXCESSIVE_AGENCY,
    "evasion": ThreatCategory.PROMPT_INJECTION,
}

INTENT_TO_SEVERITY: dict[str, str] = {
    "social_engineering": "high",
    "manipulation": "high",
    "escalation_attempt": "medium",
    "evasion": "medium",
}


class IntentScanner(InputScanner):
    """ML-based adversarial intent detector using multi-label classification.

    Unlike the InjectionClassifier (binary: injection or not), this scanner
    identifies the *type* of adversarial intent, enabling more nuanced
    policy responses.

    Produces multiple labels with independent scores (multi-label, not
    mutually exclusive). A single message can exhibit both social_engineering
    AND escalation_attempt simultaneously.

    Configuration:
      - SENTINEL_ML_ENABLED=true (required)
      - SENTINEL_ML_BLOCKING=true (optional, adds latency)
      - block_threshold: score above which a single intent triggers BLOCK (0.85)
      - warn_threshold: score above which a single intent triggers WARN (0.6)
      - aggregate_threshold: sum of adversarial intents that triggers WARN (1.2)
      - Model files at: models/intent-classifier/{model.onnx, tokenizer.json}
    """

    def __init__(
        self,
        blocking: bool | None = None,
        block_threshold: float = 0.85,
        warn_threshold: float = 0.6,
        aggregate_threshold: float = 1.2,
    ) -> None:
        self._blocking = blocking if blocking is not None else settings.ml_blocking
        self._block_threshold = block_threshold
        self._warn_threshold = warn_threshold
        self._aggregate_threshold = aggregate_threshold
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ml-intent")
        self._model_loaded = False

    @property
    def info(self) -> ScannerInfo:
        scanner_type = (
            ScannerType.INPUT_BLOCKING if self._blocking else ScannerType.INPUT_ASYNC
        )
        return ScannerInfo(
            name="ml_intent_detector",
            version="1.0.0",
            scanner_type=scanner_type,
            description="ML-based adversarial intent detection (multi-label)",
            author="sentinel",
            priority=25,  # After regex (10), before topic (30)
        )

    async def startup(self) -> None:
        """Load the intent classification model."""
        if not ml_dependencies_available():
            logger.info("ml_intent_skipped", extra={"reason": "dependencies not installed"})
            return

        if not settings.ml_enabled:
            logger.info("ml_intent_skipped", extra={"reason": "SENTINEL_ML_ENABLED=false"})
            return

        manager = get_model_manager()
        model = manager.load_model(MODEL_NAME, labels=INTENT_LABELS)
        self._model_loaded = model is not None
        if self._model_loaded:
            logger.info("ml_intent_scanner_ready")

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Classify input for adversarial intent.

        Decision logic:
        1. Any single adversarial intent >= block_threshold → BLOCK
        2. Any single adversarial intent >= warn_threshold → WARN
        3. Sum of adversarial scores >= aggregate_threshold → WARN
           (catches multi-vector attacks that individually stay below threshold)
        4. Otherwise → ALLOW
        """
        if not self._model_loaded:
            return GuardrailResult(verdict=Verdict.ALLOW)

        loop = asyncio.get_event_loop()
        scores = await loop.run_in_executor(
            self._executor, self._predict, content
        )

        if scores is None:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Extract adversarial scores (everything except "benign")
        adversarial_scores = {
            k: v for k, v in scores.items() if k != "benign"
        }

        if not adversarial_scores:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Find the highest adversarial intent
        max_intent = max(adversarial_scores, key=adversarial_scores.get)
        max_score = adversarial_scores[max_intent]

        # Check 1: Single intent above block threshold
        if max_score >= self._block_threshold:
            category = INTENT_TO_CATEGORY.get(max_intent, ThreatCategory.PROMPT_INJECTION)
            severity = INTENT_TO_SEVERITY.get(max_intent, "high")
            return GuardrailResult(
                verdict=Verdict.BLOCK,
                events=[
                    SecurityEvent(
                        tenant_id=context.tenant_id,
                        agent_id=context.agent_id,
                        verdict=Verdict.BLOCK,
                        category=category,
                        description=(
                            f"Adversarial intent detected: '{max_intent}' "
                            f"(confidence: {max_score:.3f})"
                        ),
                        source="ml_intent_detector",
                        severity=severity,
                        metadata={
                            "intent_scores": scores,
                            "primary_intent": max_intent,
                            "threshold": self._block_threshold,
                        },
                    )
                ],
            )

        # Check 2: Single intent above warn threshold
        if max_score >= self._warn_threshold:
            category = INTENT_TO_CATEGORY.get(max_intent, ThreatCategory.PROMPT_INJECTION)
            return GuardrailResult(
                verdict=Verdict.WARN,
                events=[
                    SecurityEvent(
                        tenant_id=context.tenant_id,
                        agent_id=context.agent_id,
                        verdict=Verdict.WARN,
                        category=category,
                        description=(
                            f"Possible adversarial intent: '{max_intent}' "
                            f"(confidence: {max_score:.3f})"
                        ),
                        source="ml_intent_detector",
                        severity="medium",
                        metadata={
                            "intent_scores": scores,
                            "primary_intent": max_intent,
                            "threshold": self._warn_threshold,
                        },
                    )
                ],
            )

        # Check 3: Aggregate adversarial score (multi-vector detection)
        aggregate = sum(adversarial_scores.values())
        if aggregate >= self._aggregate_threshold:
            # Multiple weak signals combine to a warning
            top_intents = sorted(
                adversarial_scores.items(), key=lambda x: x[1], reverse=True
            )[:3]
            intent_summary = ", ".join(f"{k}={v:.2f}" for k, v in top_intents)
            return GuardrailResult(
                verdict=Verdict.WARN,
                events=[
                    SecurityEvent(
                        tenant_id=context.tenant_id,
                        agent_id=context.agent_id,
                        verdict=Verdict.WARN,
                        category=ThreatCategory.PROMPT_INJECTION,
                        description=(
                            f"Multi-vector adversarial intent detected "
                            f"(aggregate: {aggregate:.3f}): {intent_summary}"
                        ),
                        source="ml_intent_detector",
                        severity="medium",
                        metadata={
                            "intent_scores": scores,
                            "aggregate_score": aggregate,
                            "threshold": self._aggregate_threshold,
                        },
                    )
                ],
            )

        return GuardrailResult(verdict=Verdict.ALLOW)

    def _predict(self, text: str) -> dict[str, float] | None:
        """Run multi-label classification inference.

        For multi-label, we apply sigmoid to each logit independently
        (not softmax). Each label is an independent binary decision.
        """
        manager = get_model_manager()
        model = manager.get_model(MODEL_NAME)
        if model is None:
            return None

        try:
            import numpy as np

            encoding = model.tokenizer.encode(text)
            input_ids = np.array([encoding.ids], dtype=np.int64)
            attention_mask = np.array([encoding.attention_mask], dtype=np.int64)

            feeds: dict = {"input_ids": input_ids, "attention_mask": attention_mask}
            if "token_type_ids" in model.input_names:
                feeds["token_type_ids"] = np.zeros_like(input_ids)

            outputs = model.session.run(None, feeds)
            logits = outputs[0][0]

            # Multi-label: sigmoid per logit (independent probabilities)
            probs = 1.0 / (1.0 + np.exp(-logits))

            # Map to labels
            labels = model.labels or INTENT_LABELS
            results = {}
            for i, label in enumerate(labels):
                if i < len(probs):
                    results[label] = float(probs[i])

            return results

        except Exception as e:
            logger.error("intent_prediction_failed", extra={"error": str(e)[:200]})
            return None

    async def health(self) -> bool:
        if not settings.ml_enabled:
            return True
        return self._model_loaded

    async def shutdown(self) -> None:
        self._executor.shutdown(wait=False)
