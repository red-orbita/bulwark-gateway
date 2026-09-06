"""
Prompt Guard 2 — Meta's multilingual prompt-injection / jailbreak classifier.

A second ML input scanner that complements ``InjectionClassifier`` to form a
detection *ensemble*: each model registers as an independent input scanner and
their verdicts are combined by the pipeline lane (the strongest verdict wins).
Where the ProtectAI DeBERTa-v3 injection model is English-centric, Meta's
Llama-Prompt-Guard-2-86M is a DeBERTa-v2 classifier trained by Meta on a broad
multilingual jailbreak/injection corpus (en, fr, de, hi, it, pt, es, th), so the
two disagree on different attack shapes — the ensemble raises recall without
lowering either model's own precision bar.

Binary model: id2label = {0: BENIGN, 1: MALICIOUS}. "MALICIOUS" covers both
direct prompt injection and jailbreak framings (Prompt Guard 2 folds PG1's
separate injection/jailbreak heads into one malicious class).

Default mode: async (enrichment, no latency impact).
Optional: blocking mode (shares BULWARK_ML_BLOCKING with the other ML scanners).

Model artifact: gravitee-io/Llama-Prompt-Guard-2-86M-onnx (ONNX export of
meta-llama/Llama-Prompt-Guard-2-86M; Llama 4 Community License — the operator
provisions it deliberately via scripts/download-models.py --prompt-guard).
Expected model path: models/prompt-guard-2/model.onnx
"""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor

from src.config import settings
from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.ml.model_manager import get_model_manager, ml_dependencies_available
from src.scanners.protocol import InputScanner, MaturityTier, ScanContext, ScannerInfo, ScannerType

logger = logging.getLogger(__name__)

MODEL_NAME = "prompt-guard-2"
# Order MUST match the model's config.json id2label: {0: BENIGN, 1: MALICIOUS}.
DEFAULT_LABELS = ["BENIGN", "MALICIOUS"]


class PromptGuard2Classifier(InputScanner):
    """Meta Prompt Guard 2 injection/jailbreak classifier (DeBERTa-v2/ONNX).

    Runs inference on Meta's binary Prompt Guard 2 model that predicts whether
    input text is a malicious (injection/jailbreak) prompt. Registered alongside
    ``InjectionClassifier`` to form a two-model input ensemble.

    Configuration (shared with the other ML scanners):
      - BULWARK_ML_ENABLED=true (required to activate)
      - BULWARK_ML_BLOCKING=true (to run in hot path, adds latency)
      - BULWARK_ML_BLOCK_THRESHOLD (confidence to auto-block, default 0.85)
      - BULWARK_ML_WARN_THRESHOLD (confidence to warn, default 0.6)
      - Model files at: models/prompt-guard-2/{model.onnx, tokenizer.json}
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
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="ml-prompt-guard")
        self._model_loaded = False

    @property
    def info(self) -> ScannerInfo:
        scanner_type = (
            ScannerType.INPUT_BLOCKING if self._blocking else ScannerType.INPUT_ASYNC
        )
        return ScannerInfo(
            name="ml_prompt_guard",
            version="1.0.0",
            scanner_type=scanner_type,
            description="ML-based prompt injection/jailbreak detection (Meta Prompt Guard 2 / DeBERTa-v2 / ONNX)",
            maturity=MaturityTier.BETA,
            author="bulwark",
            priority=22,  # Sibling to the injection classifier (20); ensemble lane
        )

    async def startup(self) -> None:
        """Load the ONNX model on startup and run warmup inference."""
        if not ml_dependencies_available():
            logger.info("ml_prompt_guard_skipped", extra={"reason": "dependencies not installed"})
            return

        if not settings.ml_enabled:
            logger.info("ml_prompt_guard_skipped", extra={"reason": "BULWARK_ML_ENABLED=false"})
            return

        manager = get_model_manager()
        model = manager.load_model(MODEL_NAME, labels=DEFAULT_LABELS)
        self._model_loaded = model is not None
        if self._model_loaded:
            # Warmup inference to avoid cold-start latency on first request.
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(self._executor, self._predict, "warmup test")
            logger.info("ml_prompt_guard_ready")

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Classify input as benign or malicious (injection/jailbreak).

        Returns:
            BLOCK if confidence >= block_threshold
            WARN if confidence >= warn_threshold
            ALLOW otherwise
        """
        if not self._model_loaded:
            # Fail-closed when the model is unavailable (mirrors InjectionClassifier
            # P7-01): an attacker who can force a model unload (OOM, corrupted
            # weights) must not thereby bypass ML detection. The main.py registrar
            # only registers this scanner when its model files are present, so a
            # deployment without the model never reaches this blocking state.
            return GuardrailResult(
                verdict=Verdict.BLOCK,
                events=[SecurityEvent(
                    tenant_id="system",
                    agent_id="ml_scanner",
                    verdict=Verdict.BLOCK,
                    category=ThreatCategory.PROMPT_INJECTION,
                    description="Prompt Guard 2 classifier unavailable — fail-closed (model not loaded)",
                    source="ml_prompt_guard",
                    severity="high",
                )],
            )

        # Run inference in thread pool (CPU-bound).
        loop = asyncio.get_event_loop()
        predictions = await loop.run_in_executor(
            self._executor, self._predict, content
        )

        if predictions is None:
            # Inference error ⇒ fail-open (ALLOW); the injection classifier and
            # regex lanes still cover this request.
            return GuardrailResult(verdict=Verdict.ALLOW)

        malicious_score = predictions.get("MALICIOUS", predictions.get("malicious", 0.0))

        if malicious_score >= self._block_threshold:
            return GuardrailResult(
                verdict=Verdict.BLOCK,
                events=[
                    SecurityEvent(
                        tenant_id=context.tenant_id,
                        agent_id=context.agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.PROMPT_INJECTION,
                        description=f"Prompt Guard 2 detected malicious prompt (confidence: {malicious_score:.3f})",
                        source="ml_prompt_guard",
                        severity="high",
                        metadata={
                            "ml_confidence": malicious_score,
                            "model": MODEL_NAME,
                            "threshold": self._block_threshold,
                        },
                    )
                ],
            )

        if malicious_score >= self._warn_threshold:
            return GuardrailResult(
                verdict=Verdict.WARN,
                events=[
                    SecurityEvent(
                        tenant_id=context.tenant_id,
                        agent_id=context.agent_id,
                        verdict=Verdict.WARN,
                        category=ThreatCategory.PROMPT_INJECTION,
                        description=f"Prompt Guard 2: possible malicious prompt (confidence: {malicious_score:.3f})",
                        source="ml_prompt_guard",
                        severity="medium",
                        metadata={
                            "ml_confidence": malicious_score,
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
            return True  # Disabled is a valid state
        return self._model_loaded

    async def shutdown(self) -> None:
        """Shutdown thread pool."""
        self._executor.shutdown(wait=False)
