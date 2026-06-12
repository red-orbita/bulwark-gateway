"""
Hallucination Scanner — Detects factual inconsistencies in LLM output.

Uses Natural Language Inference (NLI) to check if LLM output is consistent
with the input context. A contradiction between output claims and input
context indicates hallucination.

Strategies:
  1. NLI entailment check (fast, ONNX — primary method)
  2. Claim extraction + per-claim verification
  3. Configurable: threshold, per-agent enable

Model: DeBERTa-v3 fine-tuned for NLI (same model as topic classifier)
Expected path: models/nli-classifier/model.onnx
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

# Sentence boundary pattern for claim extraction
SENTENCE_PATTERN = re.compile(r"(?<=[.!?])\s+(?=[A-Z\u00C0-\u024F])")


class HallucinationScanner(OutputScanner):
    """Detects factual inconsistencies between LLM output and input context.

    For each sentence/claim in the output, checks NLI entailment against
    the concatenated input messages (especially system + user context).

    NLI labels:
      - entailment: claim is supported by context (good)
      - neutral: claim is neither supported nor contradicted (acceptable)
      - contradiction: claim directly conflicts with context (hallucination!)

    Configuration via policy YAML per agent:
      output_validation:
        hallucination_check: true
        hallucination_threshold: 0.7  (contradiction confidence to flag)
        max_claims_to_check: 10       (limit for performance)
    """

    def __init__(
        self,
        blocking: bool = False,
        contradiction_threshold: float = 0.7,
        max_claims: int = 10,
    ) -> None:
        self._blocking = blocking
        self._contradiction_threshold = contradiction_threshold
        self._max_claims = max_claims
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="hallucination")
        self._model_loaded = False

    @property
    def info(self) -> ScannerInfo:
        scanner_type = (
            ScannerType.OUTPUT_BLOCKING if self._blocking else ScannerType.OUTPUT_ASYNC
        )
        return ScannerInfo(
            name="hallucination_detector",
            version="1.0.0",
            scanner_type=scanner_type,
            description="NLI-based hallucination detection for LLM outputs",
            author="sentinel",
            priority=20,
        )

    async def startup(self) -> None:
        """Load the NLI model."""
        if not ml_dependencies_available():
            logger.info("hallucination_skipped", extra={"reason": "ML deps not installed"})
            return

        if not settings.ml_enabled:
            logger.info("hallucination_skipped", extra={"reason": "ML disabled"})
            return

        manager = get_model_manager()
        model = manager.load_model(MODEL_NAME, labels=["contradiction", "neutral", "entailment"])
        self._model_loaded = model is not None
        if self._model_loaded:
            logger.info("hallucination_scanner_ready")

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Check LLM output for hallucinations against input context.

        Args:
            content: The LLM response text
            context: Contains input messages for reference

        Returns:
            WARN if contradiction detected above threshold
            BLOCK if multiple high-confidence contradictions
        """
        if not self._model_loaded:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Check if hallucination check is enabled for this agent
        output_config = context.metadata.get("output_validation", {})
        if not output_config.get("hallucination_check", True):
            return GuardrailResult(verdict=Verdict.ALLOW)

        threshold = output_config.get(
            "hallucination_threshold", self._contradiction_threshold
        )

        # Extract reference context from input messages
        reference = self._extract_reference(context)
        if not reference:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Extract claims from output
        claims = self._extract_claims(content)
        if not claims:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Check each claim against reference
        loop = asyncio.get_event_loop()
        contradictions: list[dict] = []

        for claim in claims[:self._max_claims]:
            result = await loop.run_in_executor(
                self._executor, self._check_entailment, claim, reference
            )
            if result and result.get("contradiction", 0) >= threshold:
                contradictions.append({
                    "claim": claim[:200],
                    "contradiction_score": result["contradiction"],
                    "entailment_score": result.get("entailment", 0),
                })

        if not contradictions:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Multiple contradictions → BLOCK; single → WARN
        if len(contradictions) >= 3:
            verdict = Verdict.BLOCK
            severity = "high"
        else:
            verdict = Verdict.WARN
            severity = "medium"

        top_contradiction = max(contradictions, key=lambda c: c["contradiction_score"])

        return GuardrailResult(
            verdict=verdict,
            events=[
                SecurityEvent(
                    tenant_id=context.tenant_id,
                    agent_id=context.agent_id,
                    verdict=verdict,
                    category=ThreatCategory.INSECURE_OUTPUT,
                    description=(
                        f"Hallucination detected: {len(contradictions)} claim(s) "
                        f"contradict input context (max score: "
                        f"{top_contradiction['contradiction_score']:.3f})"
                    ),
                    source="hallucination_detector",
                    severity=severity,
                    metadata={
                        "contradictions": contradictions[:5],
                        "total_claims_checked": min(len(claims), self._max_claims),
                        "threshold": threshold,
                    },
                )
            ],
        )

    def _extract_reference(self, context: ScanContext) -> str:
        """Extract reference context from input messages."""
        parts = []
        for msg in context.messages:
            if isinstance(msg, dict):
                role = msg.get("role", "")
                content = msg.get("content", "")
                if role in ("system", "user") and content:
                    parts.append(content)
        return " ".join(parts)[:2000]  # Limit reference context length

    def _extract_claims(self, text: str) -> list[str]:
        """Extract individual claims/sentences from output text.

        Uses sentence boundary detection. Filters out very short sentences
        and questions (which aren't factual claims).
        """
        sentences = SENTENCE_PATTERN.split(text)
        claims = []
        for s in sentences:
            s = s.strip()
            # Skip very short fragments and questions
            if len(s) < 10:
                continue
            if s.endswith("?"):
                continue
            if s.startswith(("I ", "I'm ", "Let me ", "Sure,", "Of course,")):
                continue
            claims.append(s)
        return claims

    def _check_entailment(self, claim: str, reference: str) -> dict[str, float] | None:
        """Check NLI entailment between reference (premise) and claim (hypothesis).

        Returns dict with scores for: contradiction, neutral, entailment.
        """
        manager = get_model_manager()
        model = manager.get_model(MODEL_NAME)
        if model is None:
            return None

        try:
            import numpy as np

            # NLI format: premise [SEP] hypothesis
            nli_input = f"{reference[:500]} [SEP] {claim}"

            encoding = model.tokenizer.encode(nli_input)
            input_ids = np.array([encoding.ids], dtype=np.int64)
            attention_mask = np.array([encoding.attention_mask], dtype=np.int64)

            feeds: dict = {"input_ids": input_ids, "attention_mask": attention_mask}
            if "token_type_ids" in model.input_names:
                feeds["token_type_ids"] = np.zeros_like(input_ids)

            outputs = model.session.run(None, feeds)
            logits = outputs[0][0]

            # Softmax
            probs = np.exp(logits) / np.exp(logits).sum()

            labels = model.labels or ["contradiction", "neutral", "entailment"]
            return {labels[i]: float(probs[i]) for i in range(min(len(labels), len(probs)))}

        except Exception as e:
            logger.debug("entailment_check_failed", extra={"error": str(e)[:100]})
            return None

    async def health(self) -> bool:
        if not settings.ml_enabled:
            return True
        return self._model_loaded

    async def shutdown(self) -> None:
        self._executor.shutdown(wait=False)
