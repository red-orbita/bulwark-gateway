"""
Model Manager — Manages ML model lifecycle for scanner inference.

Handles:
  - Lazy model loading (only when first needed)
  - ONNX Runtime session management
  - Tokenizer loading and caching
  - Model hot-swap without downtime
  - Health status per model
  - Graceful fallback when models unavailable

Models are stored in the configured model directory (SENTINEL_ML_MODEL_DIR).
Expected structure:
  models/
    injection-classifier/
      model.onnx
      tokenizer.json
      config.json
    toxicity/
      model.onnx
      tokenizer.json
      config.json
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Optional imports — graceful if not installed
try:
    import numpy as np

    _NUMPY_AVAILABLE = True
except ImportError:
    _NUMPY_AVAILABLE = False

try:
    import onnxruntime as ort

    _ORT_AVAILABLE = True
except ImportError:
    _ORT_AVAILABLE = False

try:
    from tokenizers import Tokenizer

    _TOKENIZERS_AVAILABLE = True
except ImportError:
    _TOKENIZERS_AVAILABLE = False


def ml_dependencies_available() -> bool:
    """Check if all ML dependencies are installed."""
    return _NUMPY_AVAILABLE and _ORT_AVAILABLE and _TOKENIZERS_AVAILABLE


@dataclass
class LoadedModel:
    """A loaded ONNX model ready for inference."""

    name: str
    version: str
    session: Any  # ort.InferenceSession
    tokenizer: Any  # Tokenizer
    max_length: int = 512
    labels: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def input_names(self) -> list[str]:
        """Get ONNX model input names."""
        if self.session is None:
            return []
        return [inp.name for inp in self.session.get_inputs()]

    @property
    def output_names(self) -> list[str]:
        """Get ONNX model output names."""
        if self.session is None:
            return []
        return [out.name for out in self.session.get_outputs()]


class ModelManager:
    """Manages ML model lifecycle: loading, versioning, inference.

    Thread-safe singleton that handles model loading lazily and
    provides health checks for monitoring.
    """

    def __init__(self, model_dir: Path) -> None:
        self._model_dir = model_dir
        self._models: dict[str, LoadedModel] = {}
        self._lock = threading.Lock()
        self._available = ml_dependencies_available()

    @property
    def available(self) -> bool:
        """Whether ML inference is possible (dependencies installed)."""
        return self._available

    def load_model(
        self,
        name: str,
        model_subdir: str | None = None,
        max_length: int = 512,
        labels: list[str] | None = None,
    ) -> LoadedModel | None:
        """Load an ONNX model from disk.

        Args:
            name: Model identifier
            model_subdir: Subdirectory under model_dir (defaults to name)
            max_length: Maximum input token length
            labels: Classification labels (for classifiers)

        Returns:
            LoadedModel instance or None if loading fails
        """
        if not self._available:
            logger.warning("ml_deps_missing", extra={"model": name})
            return None

        subdir = model_subdir or name
        model_path = self._model_dir / subdir

        if not model_path.exists():
            logger.info("model_dir_not_found", extra={"model": name, "path": str(model_path)})
            return None

        onnx_path = model_path / "model.onnx"
        tokenizer_path = model_path / "tokenizer.json"

        if not onnx_path.exists():
            logger.warning("model_onnx_missing", extra={"model": name, "path": str(onnx_path)})
            return None

        if not tokenizer_path.exists():
            logger.warning("model_tokenizer_missing", extra={"model": name, "path": str(tokenizer_path)})
            return None

        try:
            # Load ONNX session
            sess_options = ort.SessionOptions()
            sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            sess_options.intra_op_num_threads = 2  # Limit CPU threads
            sess_options.inter_op_num_threads = 1

            session = ort.InferenceSession(
                str(onnx_path),
                sess_options=sess_options,
                providers=["CPUExecutionProvider"],
            )

            # Load tokenizer
            tokenizer = Tokenizer.from_file(str(tokenizer_path))
            tokenizer.enable_truncation(max_length=max_length)
            tokenizer.enable_padding(length=max_length)

            # Read version from config if available
            version = "1.0.0"
            config_path = model_path / "config.json"
            if config_path.exists():
                import json
                with open(config_path) as f:
                    config = json.load(f)
                    version = config.get("version", version)
                    if not labels:
                        labels = config.get("labels", [])

            loaded = LoadedModel(
                name=name,
                version=version,
                session=session,
                tokenizer=tokenizer,
                max_length=max_length,
                labels=labels or [],
            )

            with self._lock:
                self._models[name] = loaded

            logger.info(
                "model_loaded",
                extra={
                    "model": name,
                    "version": version,
                    "inputs": loaded.input_names,
                    "outputs": loaded.output_names,
                    "labels": labels,
                },
            )
            return loaded

        except Exception as e:
            logger.error("model_load_failed", extra={"model": name, "error": str(e)[:200]})
            return None

    def get_model(self, name: str) -> LoadedModel | None:
        """Get a loaded model by name (thread-safe)."""
        with self._lock:
            return self._models.get(name)

    def is_loaded(self, name: str) -> bool:
        """Check if a model is loaded."""
        with self._lock:
            return name in self._models

    def unload_model(self, name: str) -> bool:
        """Unload a model to free memory."""
        with self._lock:
            if name in self._models:
                del self._models[name]
                logger.info("model_unloaded", extra={"model": name})
                return True
            return False

    def list_models(self) -> list[dict[str, Any]]:
        """List all loaded models."""
        with self._lock:
            return [
                {
                    "name": m.name,
                    "version": m.version,
                    "labels": m.labels,
                    "max_length": m.max_length,
                }
                for m in self._models.values()
            ]

    def predict(
        self,
        model_name: str,
        text: str,
    ) -> dict[str, float] | None:
        """Run inference on a loaded model.

        Args:
            model_name: Name of the loaded model
            text: Input text to classify

        Returns:
            Dict mapping label -> confidence score, or None if model unavailable
        """
        model = self.get_model(model_name)
        if model is None:
            return None

        try:
            # Tokenize
            encoding = model.tokenizer.encode(text)
            input_ids = np.array([encoding.ids], dtype=np.int64)
            attention_mask = np.array([encoding.attention_mask], dtype=np.int64)

            # Prepare inputs
            feeds: dict[str, Any] = {}
            input_names = model.input_names
            if "input_ids" in input_names:
                feeds["input_ids"] = input_ids
            if "attention_mask" in input_names:
                feeds["attention_mask"] = attention_mask
            if "token_type_ids" in input_names:
                feeds["token_type_ids"] = np.zeros_like(input_ids)

            # Run inference
            outputs = model.session.run(None, feeds)

            # Process logits → probabilities
            logits = outputs[0][0]  # First output, first batch item
            probabilities = _softmax(logits)

            # Map to labels
            if model.labels:
                return {
                    label: float(prob)
                    for label, prob in zip(model.labels, probabilities)
                }
            else:
                return {f"class_{i}": float(p) for i, p in enumerate(probabilities)}

        except Exception as e:
            logger.error(
                "inference_failed",
                extra={"model": model_name, "error": str(e)[:200]},
            )
            return None


def _softmax(logits) -> Any:
    """Compute softmax probabilities from logits."""
    import numpy as np
    exp_logits = np.exp(logits - np.max(logits))
    return exp_logits / exp_logits.sum()


# === Singleton ===

_manager: ModelManager | None = None
_manager_lock = threading.Lock()


def get_model_manager(model_dir: Path | None = None) -> ModelManager:
    """Get or create the global model manager singleton."""
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                from src.config import settings
                _manager = ModelManager(model_dir or settings.ml_model_dir)
    return _manager
