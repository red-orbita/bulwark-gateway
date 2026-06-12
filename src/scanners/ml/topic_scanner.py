"""
Topic Scanner — ML-based topic boundary enforcement.

Uses zero-shot classification to enforce that conversations stay
within allowed topics per agent. Configurable via policy YAML:

  agents:
    - id: support-bot
      allowed_topics: [billing, technical_support, account_management]
      denied_topics: [politics, religion, adult_content, competitors]

Default mode: async (enrichment)
Model: Zero-shot NLI (e.g., bart-large-mnli or deberta-v3-base-nli, ONNX)
Expected path: models/topic-classifier/model.onnx
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

MODEL_NAME = "topic-classifier"


class TopicScanner(InputScanner):
    """ML-based topic boundary enforcement using zero-shot classification.

    Checks if user input falls within allowed/denied topics for the
    agent being addressed. Uses Natural Language Inference (NLI) model
    for zero-shot topic classification.

    Configuration via policy YAML per agent:
      allowed_topics: list of allowed topic strings
      denied_topics: list of explicitly blocked topic strings
      topic_threshold: confidence threshold (default 0.7)

    If neither allowed_topics nor denied_topics are configured,
    this scanner is a no-op for that agent.
    """

    def __init__(
        self,
        blocking: bool = False,
        default_threshold: float = 0.7,
    ) -> None:
        self._blocking = blocking
        self._default_threshold = default_threshold
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ml-topic")
        self._model_loaded = False

    @property
    def info(self) -> ScannerInfo:
        scanner_type = (
            ScannerType.INPUT_BLOCKING if self._blocking else ScannerType.INPUT_ASYNC
        )
        return ScannerInfo(
            name="ml_topic_classifier",
            version="1.0.0",
            scanner_type=scanner_type,
            description="ML-based topic boundary enforcement (zero-shot NLI)",
            author="sentinel",
            priority=30,
        )

    async def startup(self) -> None:
        """Load the NLI model on startup."""
        if not ml_dependencies_available():
            logger.info("ml_topic_skipped", extra={"reason": "dependencies not installed"})
            return

        if not settings.ml_enabled:
            logger.info("ml_topic_skipped", extra={"reason": "SENTINEL_ML_ENABLED=false"})
            return

        manager = get_model_manager()
        model = manager.load_model(MODEL_NAME)
        self._model_loaded = model is not None
        if self._model_loaded:
            logger.info("ml_topic_scanner_ready")

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Check if content matches allowed/denied topics for this agent.

        Logic:
        1. Get agent's topic policy from context.metadata
        2. If denied_topics: classify against denied list → BLOCK if match
        3. If allowed_topics: classify against allowed list → WARN if no match
        """
        if not self._model_loaded:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Get topic policy for this agent
        denied_topics = context.metadata.get("denied_topics", [])
        allowed_topics = context.metadata.get("allowed_topics", [])
        threshold = context.metadata.get("topic_threshold", self._default_threshold)

        if not denied_topics and not allowed_topics:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Check denied topics first
        if denied_topics:
            loop = asyncio.get_event_loop()
            scores = await loop.run_in_executor(
                self._executor, self._classify_topics, content, denied_topics
            )
            if scores:
                max_topic = max(scores, key=scores.get)
                max_score = scores[max_topic]
                if max_score >= threshold:
                    return GuardrailResult(
                        verdict=Verdict.BLOCK,
                        events=[
                            SecurityEvent(
                                tenant_id=context.tenant_id,
                                agent_id=context.agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.POLICY_VIOLATION,
                                description=f"Denied topic detected: '{max_topic}' (confidence: {max_score:.3f})",
                                source="ml_topic_classifier",
                                severity="medium",
                                metadata={
                                    "topic_scores": scores,
                                    "denied_topic": max_topic,
                                    "threshold": threshold,
                                },
                            )
                        ],
                    )

        # Check allowed topics (warn if off-topic)
        if allowed_topics:
            loop = asyncio.get_event_loop()
            scores = await loop.run_in_executor(
                self._executor, self._classify_topics, content, allowed_topics
            )
            if scores:
                max_topic = max(scores, key=scores.get)
                max_score = scores[max_topic]
                if max_score < threshold:
                    return GuardrailResult(
                        verdict=Verdict.WARN,
                        events=[
                            SecurityEvent(
                                tenant_id=context.tenant_id,
                                agent_id=context.agent_id,
                                verdict=Verdict.WARN,
                                category=ThreatCategory.POLICY_VIOLATION,
                                description=f"Off-topic message (best match: '{max_topic}' at {max_score:.3f})",
                                source="ml_topic_classifier",
                                severity="low",
                                metadata={
                                    "topic_scores": scores,
                                    "allowed_topics": allowed_topics,
                                    "threshold": threshold,
                                },
                            )
                        ],
                    )

        return GuardrailResult(verdict=Verdict.ALLOW)

    def _classify_topics(self, text: str, topics: list[str]) -> dict[str, float] | None:
        """Zero-shot classify text against a list of topic candidates.

        Uses NLI model: for each topic, checks entailment of
        "This text is about {topic}" given the input text.
        """
        manager = get_model_manager()
        model = manager.get_model(MODEL_NAME)
        if model is None:
            return None

        try:
            import numpy as np

            results: dict[str, float] = {}
            for topic in topics:
                # NLI hypothesis: "This text is about {topic}"
                hypothesis = f"This text is about {topic}."
                # Concatenate as [SEP]-separated for NLI models
                nli_input = f"{text} [SEP] {hypothesis}"

                encoding = model.tokenizer.encode(nli_input)
                input_ids = np.array([encoding.ids], dtype=np.int64)
                attention_mask = np.array([encoding.attention_mask], dtype=np.int64)

                feeds: dict = {"input_ids": input_ids, "attention_mask": attention_mask}
                if "token_type_ids" in model.input_names:
                    feeds["token_type_ids"] = np.zeros_like(input_ids)

                outputs = model.session.run(None, feeds)
                logits = outputs[0][0]

                # NLI: [contradiction, neutral, entailment]
                # Topic match = entailment probability
                probs = np.exp(logits) / np.exp(logits).sum()
                # Entailment is typically the last class
                entailment_idx = 2 if len(probs) == 3 else -1
                results[topic] = float(probs[entailment_idx])

            return results

        except Exception as e:
            logger.error("topic_classification_failed", extra={"error": str(e)[:200]})
            return None

    async def health(self) -> bool:
        if not settings.ml_enabled:
            return True
        return self._model_loaded

    async def shutdown(self) -> None:
        self._executor.shutdown(wait=False)
