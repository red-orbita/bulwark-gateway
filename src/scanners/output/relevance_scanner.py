"""
Relevance Scanner — Checks if LLM output is relevant to user's question.

Uses sentence embeddings to compute cosine similarity between the user's
question and the LLM response. Low relevance indicates potential:
  - Off-topic hallucination
  - Model confusion
  - Injection-induced topic drift

Model: Sentence embedding model (e.g., all-MiniLM-L6-v2, ONNX)
Expected path: models/sentence-embeddings/model.onnx
"""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor

from src.config import settings
from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.ml.model_manager import get_model_manager, ml_dependencies_available
from src.scanners.protocol import OutputScanner, ScanContext, ScannerInfo, ScannerType

logger = logging.getLogger(__name__)

MODEL_NAME = "sentence-embeddings"


class RelevanceScanner(OutputScanner):
    """Checks if LLM output is relevant to the user's question.

    Uses cosine similarity between sentence embeddings of:
      - User's last message (the question)
      - LLM response (the answer)

    Low relevance may indicate hallucination, injection-induced drift,
    or model confusion.

    Configuration:
      output_validation:
        relevance_threshold: 0.4   (min cosine similarity)
        relevance_check: true
    """

    def __init__(
        self,
        blocking: bool = False,
        relevance_threshold: float = 0.4,
    ) -> None:
        self._blocking = blocking
        self._relevance_threshold = relevance_threshold
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="relevance")
        self._model_loaded = False

    @property
    def info(self) -> ScannerInfo:
        scanner_type = (
            ScannerType.OUTPUT_BLOCKING if self._blocking else ScannerType.OUTPUT_ASYNC
        )
        return ScannerInfo(
            name="relevance_checker",
            version="1.0.0",
            scanner_type=scanner_type,
            description="Embedding-based relevance scoring for LLM responses",
            author="sentinel",
            priority=30,
        )

    async def startup(self) -> None:
        if not ml_dependencies_available():
            return
        if not settings.ml_enabled:
            return

        manager = get_model_manager()
        model = manager.load_model(MODEL_NAME)
        self._model_loaded = model is not None
        if self._model_loaded:
            logger.info("relevance_scanner_ready")

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Check relevance of output to user's question."""
        if not self._model_loaded:
            return GuardrailResult(verdict=Verdict.ALLOW)

        output_config = context.metadata.get("output_validation", {})
        if not output_config.get("relevance_check", False):
            return GuardrailResult(verdict=Verdict.ALLOW)

        threshold = output_config.get("relevance_threshold", self._relevance_threshold)

        # Get user's question (last user message)
        user_question = self._get_user_question(context)
        if not user_question:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Compute similarity
        loop = asyncio.get_event_loop()
        similarity = await loop.run_in_executor(
            self._executor, self._compute_similarity, user_question, content
        )

        if similarity is None:
            return GuardrailResult(verdict=Verdict.ALLOW)

        if similarity >= threshold:
            return GuardrailResult(verdict=Verdict.ALLOW)

        return GuardrailResult(
            verdict=Verdict.WARN,
            events=[
                SecurityEvent(
                    tenant_id=context.tenant_id,
                    agent_id=context.agent_id,
                    verdict=Verdict.WARN,
                    category=ThreatCategory.INSECURE_OUTPUT,
                    description=(
                        f"Low relevance score: {similarity:.3f} "
                        f"(threshold: {threshold}). Response may be off-topic."
                    ),
                    source="relevance_checker",
                    severity="low",
                    metadata={
                        "relevance_score": similarity,
                        "threshold": threshold,
                        "question_preview": user_question[:100],
                    },
                )
            ],
        )

    def _get_user_question(self, context: ScanContext) -> str:
        """Get the last user message as the reference question."""
        for msg in reversed(context.messages):
            if isinstance(msg, dict) and msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str) and content.strip():
                    return content[:500]
        return ""

    def _compute_similarity(self, text_a: str, text_b: str) -> float | None:
        """Compute cosine similarity between two text embeddings."""
        manager = get_model_manager()
        model = manager.get_model(MODEL_NAME)
        if model is None:
            return None

        try:
            import numpy as np

            emb_a = self._get_embedding(model, text_a)
            emb_b = self._get_embedding(model, text_b[:500])

            if emb_a is None or emb_b is None:
                return None

            # Cosine similarity
            dot = np.dot(emb_a, emb_b)
            norm_a = np.linalg.norm(emb_a)
            norm_b = np.linalg.norm(emb_b)

            if norm_a == 0 or norm_b == 0:
                return 0.0

            return float(dot / (norm_a * norm_b))

        except Exception as e:
            logger.debug("similarity_failed", extra={"error": str(e)[:100]})
            return None

    def _get_embedding(self, model, text: str):
        """Get sentence embedding from model."""
        import numpy as np

        encoding = model.tokenizer.encode(text)
        input_ids = np.array([encoding.ids], dtype=np.int64)
        attention_mask = np.array([encoding.attention_mask], dtype=np.int64)

        feeds: dict = {"input_ids": input_ids, "attention_mask": attention_mask}
        if "token_type_ids" in model.input_names:
            feeds["token_type_ids"] = np.zeros_like(input_ids)

        outputs = model.session.run(None, feeds)

        # Mean pooling over token embeddings
        token_embeddings = outputs[0]  # (1, seq_len, hidden_dim)
        mask_expanded = attention_mask[:, :, None].astype(np.float32)
        sum_embeddings = (token_embeddings * mask_expanded).sum(axis=1)
        sum_mask = mask_expanded.sum(axis=1)
        embedding = sum_embeddings / np.maximum(sum_mask, 1e-9)

        return embedding[0]

    async def health(self) -> bool:
        if not settings.ml_enabled:
            return True
        return self._model_loaded

    async def shutdown(self) -> None:
        self._executor.shutdown(wait=False)
