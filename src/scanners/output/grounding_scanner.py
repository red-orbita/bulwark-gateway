"""
Grounding Scanner — RAG faithfulness checker.

Verifies that LLM output is grounded in (supported by) the provided
context documents. Uses NLI entailment scoring to measure how well
each output claim is supported by the retrieved chunks.

Designed for RAG pipelines where the LLM should only output information
that can be traced back to the source documents.

Model: Same NLI model as HallucinationScanner (shared)
"""

from __future__ import annotations

import asyncio
import logging
import re
from concurrent.futures import ThreadPoolExecutor

from src.config import settings
from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.ml.model_manager import get_model_manager, ml_dependencies_available
from src.scanners.protocol import OutputScanner, ScanContext, ScannerInfo, ScannerType

logger = logging.getLogger(__name__)

MODEL_NAME = "nli-classifier"

# Sentence boundary
SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")


class GroundingScanner(OutputScanner):
    """Checks if LLM output is grounded in provided RAG context.

    Scoring:
      grounding_score = (claims supported by context) / (total claims)
      If grounding_score < threshold → WARN or BLOCK

    The context documents should be provided in:
      context.metadata["rag_context"] — list of retrieved chunk texts
      OR extracted from system messages containing injected documents.

    Configuration:
      output_validation:
        grounding_threshold: 0.7  (min fraction of grounded claims)
        grounding_mode: strict    (strict: all claims must be grounded, lenient: majority)
    """

    def __init__(
        self,
        blocking: bool = False,
        grounding_threshold: float = 0.7,
        max_claims: int = 15,
    ) -> None:
        self._blocking = blocking
        self._grounding_threshold = grounding_threshold
        self._max_claims = max_claims
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="grounding")
        self._model_loaded = False

    @property
    def info(self) -> ScannerInfo:
        scanner_type = (
            ScannerType.OUTPUT_BLOCKING if self._blocking else ScannerType.OUTPUT_ASYNC
        )
        return ScannerInfo(
            name="grounding_checker",
            version="1.0.0",
            scanner_type=scanner_type,
            description="RAG faithfulness — checks output is grounded in context",
            author="sentinel",
            priority=25,
        )

    async def startup(self) -> None:
        if not ml_dependencies_available():
            return
        if not settings.ml_enabled:
            return

        manager = get_model_manager()
        model = manager.load_model(MODEL_NAME, labels=["contradiction", "neutral", "entailment"])
        self._model_loaded = model is not None
        if self._model_loaded:
            logger.info("grounding_scanner_ready")

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Check if output claims are grounded in RAG context."""
        if not self._model_loaded:
            return GuardrailResult(verdict=Verdict.ALLOW)

        output_config = context.metadata.get("output_validation", {})
        threshold = output_config.get("grounding_threshold", self._grounding_threshold)

        # Get RAG context
        rag_context = self._get_rag_context(context)
        if not rag_context:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Extract claims from output
        claims = self._extract_claims(content)
        if not claims:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Score each claim against RAG context
        loop = asyncio.get_event_loop()
        grounded_count = 0
        ungrounded_claims: list[str] = []

        for claim in claims[:self._max_claims]:
            score = await loop.run_in_executor(
                self._executor, self._score_grounding, claim, rag_context
            )
            if score is not None and score >= 0.5:
                grounded_count += 1
            else:
                ungrounded_claims.append(claim[:100])

        total_checked = min(len(claims), self._max_claims)
        grounding_score = grounded_count / total_checked if total_checked > 0 else 1.0

        if grounding_score >= threshold:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Below threshold
        severity = "high" if grounding_score < 0.3 else "medium"
        verdict = Verdict.BLOCK if grounding_score < 0.3 else Verdict.WARN

        return GuardrailResult(
            verdict=verdict,
            events=[
                SecurityEvent(
                    tenant_id=context.tenant_id,
                    agent_id=context.agent_id,
                    verdict=verdict,
                    category=ThreatCategory.INSECURE_OUTPUT,
                    description=(
                        f"Low grounding score: {grounding_score:.2f} "
                        f"({grounded_count}/{total_checked} claims grounded, "
                        f"threshold: {threshold})"
                    ),
                    source="grounding_checker",
                    severity=severity,
                    metadata={
                        "grounding_score": grounding_score,
                        "grounded_claims": grounded_count,
                        "total_claims": total_checked,
                        "ungrounded_samples": ungrounded_claims[:3],
                        "threshold": threshold,
                    },
                )
            ],
        )

    def _get_rag_context(self, context: ScanContext) -> str:
        """Extract RAG context from metadata or system messages."""
        # Explicit RAG context
        rag_chunks = context.metadata.get("rag_context")
        if rag_chunks:
            if isinstance(rag_chunks, list):
                return " ".join(str(c) for c in rag_chunks)[:3000]
            return str(rag_chunks)[:3000]

        # Extract from system message (common pattern: docs injected there)
        for msg in context.messages:
            if isinstance(msg, dict) and msg.get("role") == "system":
                content = msg.get("content", "")
                if len(content) > 200:  # Likely contains injected docs
                    return content[:3000]

        return ""

    def _extract_claims(self, text: str) -> list[str]:
        """Extract factual claims from output."""
        sentences = SENTENCE_SPLIT.split(text)
        claims = []
        for s in sentences:
            s = s.strip()
            if len(s) < 15:
                continue
            if s.endswith("?"):
                continue
            # Skip meta-sentences
            if s.startswith(("I ", "I'm ", "Based on", "According to", "Sure")):
                continue
            claims.append(s)
        return claims

    def _score_grounding(self, claim: str, context: str) -> float | None:
        """Score how well a claim is grounded in context (0-1).

        Uses NLI: context = premise, claim = hypothesis.
        Returns entailment probability.
        """
        manager = get_model_manager()
        model = manager.get_model(MODEL_NAME)
        if model is None:
            return None

        try:
            import numpy as np

            nli_input = f"{context[:500]} [SEP] {claim}"

            encoding = model.tokenizer.encode(nli_input)
            input_ids = np.array([encoding.ids], dtype=np.int64)
            attention_mask = np.array([encoding.attention_mask], dtype=np.int64)

            feeds: dict = {"input_ids": input_ids, "attention_mask": attention_mask}
            if "token_type_ids" in model.input_names:
                feeds["token_type_ids"] = np.zeros_like(input_ids)

            outputs = model.session.run(None, feeds)
            logits = outputs[0][0]
            probs = np.exp(logits) / np.exp(logits).sum()

            # entailment is the last class
            entailment_idx = 2 if len(probs) == 3 else -1
            return float(probs[entailment_idx])

        except Exception as e:
            logger.debug("grounding_score_failed", extra={"error": str(e)[:100]})
            return None

    async def health(self) -> bool:
        if not settings.ml_enabled:
            return True
        return self._model_loaded

    async def shutdown(self) -> None:
        self._executor.shutdown(wait=False)
