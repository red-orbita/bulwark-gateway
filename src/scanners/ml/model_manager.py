"""
Model Manager — Manages ML model lifecycle for scanner inference.

Handles:
  - Lazy model loading (only when first needed)
  - ONNX Runtime session management
  - Tokenizer loading and caching
  - Model hot-swap without downtime (atomic under-lock slot replacement;
    a failed swap keeps the old model serving — see ``hot_swap``)
  - Artifact drift detection (in-memory model vs. on-disk bytes — ``detect_drift``)
  - Health status per model
  - Graceful fallback when models unavailable

Models are stored in the configured model directory (BULWARK_ML_MODEL_DIR).
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

import hashlib
import json as _json
import logging
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# SECURITY FIX (H-08): Verify ML model integrity before loading.
# A model manifest file maps each load-bearing file's path (model.onnx,
# tokenizer.json, config.json) to its expected SHA-256 hash.
_MODEL_MANIFEST_PATH = Path(__file__).parent.parent.parent.parent / "config" / "model_manifest.json"
_MODEL_DIR = Path(os.environ.get("BULWARK_ML_MODEL_DIR",
                                  str(Path(__file__).parent.parent.parent.parent / "models")))


def _verify_model_integrity(model_path: Path, model_dir: Path | None = None) -> bool:
    """Verify a model file matches its expected hash from the manifest.

    Works for ANY load-bearing model file (model.onnx, tokenizer.json,
    config.json) — the key is the file's path relative to ``model_dir``.

    SECURITY FIX (H-12): Removed BULWARK_ML_SKIP_INTEGRITY bypass.
    Model integrity verification is ALWAYS enforced. To deploy a new model:
    1. Compute SHA-256: sha256sum models/your_model/model.onnx
    2. Add to config/model_manifest.json every load-bearing file:
       {"your_model/model.onnx": "<sha256>",
        "your_model/tokenizer.json": "<sha256>",
        "your_model/config.json": "<sha256>"}
    3. Deploy. Integrity check passes.

    This prevents an attacker with container access from replacing ONNX models
    (or their tokenizer/config) with backdoored versions (e.g., a tokenizer that
    maps attacks to benign ids, or a config that inverts the label order).

    ``model_dir`` is the base directory the caller used to build ``model_path``
    (the ModelManager's own ``self._model_dir``). It MUST be passed by real
    callers so the manifest key is computed against the same base that
    constructed the path. Both the base and the model path are resolved to
    absolute form before comparison — otherwise a relative ``model_dir`` (the
    default, ``Path("models")``) would never be ``is_relative_to`` the absolute
    module-level ``_MODEL_DIR``, the key would silently fall back to the bare
    filename, miss the ``subdir/model.onnx`` manifest entry, and fail closed —
    bricking ML with the default configuration.
    """
    if not _MODEL_MANIFEST_PATH.exists():
        logger.error("model_manifest_missing_blocked",
                    extra={"path": str(_MODEL_MANIFEST_PATH),
                           "note": "Create config/model_manifest.json with model SHA-256 hashes"})
        return False  # Fail-closed: no manifest = no trust

    manifest = _json.loads(_MODEL_MANIFEST_PATH.read_text())
    # SECURITY (L-11 fix): Use relative path from model directory as key
    # instead of just filename to prevent hash collisions when models with
    # the same name exist in different subdirectories.
    #
    # Resolve BOTH the base and the model path so the relative-vs-absolute
    # mismatch between settings.ml_model_dir (relative default) and the
    # module-level _MODEL_DIR (absolute default) cannot break key derivation.
    base_resolved = (model_dir or _MODEL_DIR).resolve()
    model_resolved = model_path.resolve()
    model_key = str(model_resolved.relative_to(base_resolved)) \
        if model_resolved.is_relative_to(base_resolved) else model_path.name
    expected_hash = manifest.get(model_key) or manifest.get(model_path.name)
    if not expected_hash:
        logger.error("model_hash_missing_blocked", extra={"model": model_key,
                    "note": "Model not in manifest — cannot verify integrity"})
        return False  # Fail-closed: unknown model = untrusted

    actual_hash = hashlib.sha256(model_resolved.read_bytes()).hexdigest()
    if actual_hash != expected_hash:
        logger.critical("model_integrity_failed", extra={"model": model_path.name,
                       "expected": expected_hash[:16], "actual": actual_hash[:16]})
        return False
    return True


# The load-bearing files whose bytes together determine a model's behaviour.
# A change to ANY of them changes the model's verdict (weights, tokenizer, or
# label ordering), so all three participate in the drift identity below.
_LOAD_BEARING_FILES = ("model.onnx", "tokenizer.json", "config.json")


def _compute_content_hash(model_path: Path) -> str:
    """Order-stable combined SHA-256 over a model's load-bearing files.

    This is the *artifact identity* used for drift detection: it digests
    ``(filename, sha256(file))`` for every load-bearing file that exists under
    ``model_path``. If any load-bearing byte on disk changes (a swapped
    tokenizer, reordered config, or replaced weights), the digest changes and
    ``detect_drift`` reports the in-memory model as stale.

    Files that are absent are skipped (config.json is optional), but their
    presence/absence still affects the digest because the filename is folded in
    only when the file exists — adding a previously-absent config.json therefore
    also registers as drift.

    Note: this is a *change detector*, not an integrity check. It says "the
    bytes on disk differ from what was loaded", not "the bytes on disk are
    trusted". Trust is enforced fail-closed by ``_verify_model_integrity`` at
    (re)load time — i.e. inside ``hot_swap``.
    """
    h = hashlib.sha256()
    for fname in _LOAD_BEARING_FILES:
        fpath = model_path / fname
        if not fpath.exists():
            continue
        h.update(fname.encode())
        h.update(b"\0")
        h.update(hashlib.sha256(fpath.read_bytes()).hexdigest().encode())
        h.update(b"\0")
    return h.hexdigest()


def _scan_artifact_rce(path: Path) -> dict[str, Any] | None:
    """Static opcode scan of a model file for a load-time RCE gadget.

    Defense-in-depth complement to the hash-pin integrity gate (C-hard). Even a
    hash-matched, integrity-verified artifact is refused at load if a static
    scan finds a live pickle code-execution gadget. This closes the residual
    gap in a TOFU trust model: if ``config/model_manifest.json`` was bootstrapped
    from a poisoned upstream pull, the hash matches (it pins the malicious bytes)
    yet the file still carries an RCE payload. Deserializing an ONNX model does
    not execute pickle, but an artifact *disguised* as ``model.onnx`` that is
    really a pickle would — so we scan the exact bytes about to be loaded.

    Reuses the stdlib-only artifact scanner shared with SkillSpector, which
    NEVER deserializes the file (``pickletools.genops`` opcode walk only). Only
    CRITICAL findings gate a load (the sole critical rule is a live
    REDUCE/BUILD-wired execution gadget); legitimate opaque formats (real ONNX)
    score low and never block.

    Returns the first CRITICAL finding dict if the artifact must be refused,
    else ``None``. NEVER raises: a scanner import/parse error degrades to
    ``None`` so a scan glitch can never brick a legitimate, integrity-verified
    model — the fail-closed hash pin remains the primary trust gate.
    """
    try:
        from src.scanners.artifacts.model_artifact_scanner import analyze_file

        findings = analyze_file(path, str(path))
    except Exception as e:  # scanner unavailable / unexpected parse error
        logger.warning("artifact_scan_unavailable",
                       extra={"path": str(path), "error": str(e)[:200]})
        return None

    for finding in findings:
        if finding.get("severity") == "critical":
            return finding
    return None


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


def model_files_present(model_subdir: str, model_dir: Path | None = None) -> bool:
    """Check whether a model's required files exist on disk (no loading).

    Used at scanner-registration time to decide whether an ML scanner should
    be registered AT ALL. This prevents registering a *blocking* scanner whose
    model is not provisioned — which would otherwise fail-closed and BLOCK ALL
    TRAFFIC (P0 landmine): a blocking scanner with ``_model_loaded=False`` returns
    BLOCK for every request.

    This is a cheap filesystem existence check only. It does NOT verify integrity
    (that happens fail-closed at load time in ``_verify_model_integrity``); a model
    whose files exist but whose hash is untrusted will still be refused at load,
    and the post-startup readiness check is the backstop for that case.

    Returns False on any path-traversal attempt or missing file (fail-safe).
    """
    if model_dir is None:
        from src.config import settings
        model_dir = settings.ml_model_dir

    try:
        base_resolved = Path(model_dir).resolve()
        target = (base_resolved / model_subdir).resolve()
        # Prevent path traversal via model_subdir (blocks ../../etc).
        if not str(target).startswith(str(base_resolved) + os.sep) and target != base_resolved:
            return False
    except (OSError, ValueError):
        return False

    return (target / "model.onnx").exists() and (target / "tokenizer.json").exists()


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
    # Artifact identity at load time — combined hash of the load-bearing files
    # (weights + tokenizer + config) as they were on disk when this model was
    # built. ``detect_drift`` compares this against the current on-disk bytes.
    content_hash: str = ""

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

        # Preserve the caller's *explicit* label request separately from the
        # labels finally used (which may be derived from config.json below).
        # hot_swap replays load_model with these original args so a reload
        # reproduces the exact same load semantics.
        requested_labels = list(labels) if labels else None

        subdir = model_subdir or name
        model_path = self._model_dir / subdir

        # SECURITY (H-12 fix): Prevent path traversal via model_subdir.
        # Resolved path must be within model_dir (blocks ../../etc attacks).
        try:
            resolved = model_path.resolve()
            model_dir_resolved = self._model_dir.resolve()
            if not str(resolved).startswith(str(model_dir_resolved) + "/") and resolved != model_dir_resolved:
                logger.critical("model_path_traversal_blocked",
                              extra={"model": name, "subdir": subdir,
                                     "resolved": str(resolved)})
                return None
        except (OSError, ValueError):
            return None

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

        config_path = model_path / "config.json"

        try:
            # SECURITY FIX (H-08): Verify model integrity before loading.
            # Pass this manager's own base dir so the manifest key is derived
            # against the same base that built onnx_path (fixes the relative
            # vs absolute mismatch that would otherwise brick the default config).
            if not _verify_model_integrity(onnx_path, self._model_dir):
                logger.error("model_load_blocked", extra={"model": name,
                            "reason": "integrity_check_failed"})
                return None

            # SECURITY: verify ALL load-bearing files, not just the ONNX weights.
            # The model's verdict does not depend on model.onnx alone:
            #   - tokenizer.json (mandatory) turns text into token ids. A poisoned
            #     tokenizer can silently remap an attack payload to benign ids so
            #     the classifier scores it SAFE — a full bypass that never touches
            #     the pinned weights.
            #   - config.json (when present) drives the label ordering (id2label)
            #     for NLI-style models; a silent reorder inverts entailment vs
            #     contradiction (and SAFE vs INJECTION), flipping every verdict.
            # Both are pinned in the manifest and fail-closed here so the
            # "model-driven, tamper-evident" label guarantee below is real.
            if not _verify_model_integrity(tokenizer_path, self._model_dir):
                logger.error("model_load_blocked", extra={"model": name,
                            "reason": "tokenizer_integrity_failed"})
                return None
            if config_path.exists() and not _verify_model_integrity(config_path, self._model_dir):
                logger.error("model_load_blocked", extra={"model": name,
                            "reason": "config_integrity_failed"})
                return None

            # SECURITY (C-hard): defense-in-depth artifact scan AFTER integrity.
            # A hash-pinned file is only as trustworthy as the pull that seeded
            # the manifest (TOFU). Statically scan the exact bytes about to be
            # loaded for a load-time code-execution gadget — catches an artifact
            # disguised as model.onnx that is really a malicious pickle, even
            # when its hash matches the (poisoned) manifest. The scan never
            # deserializes; only a CRITICAL finding (live RCE gadget) blocks.
            for artifact_path in (onnx_path, tokenizer_path, config_path):
                if not artifact_path.exists():
                    continue
                gadget = _scan_artifact_rce(artifact_path)
                if gadget is not None:
                    logger.critical("model_load_blocked_rce_gadget",
                                    extra={"model": name,
                                           "file": artifact_path.name,
                                           "rule": gadget.get("rule_id"),
                                           "detail": gadget.get("detail", "")[:200]})
                    return None

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

            # Read version + labels from config if available. The file's
            # integrity was already verified above (fail-closed), so the label
            # ordering derived here is genuinely tamper-evident.
            version = "1.0.0"
            if config_path.exists():
                import json
                with open(config_path) as f:
                    config = json.load(f)
                    version = config.get("version", version)
                    if not labels:
                        # Prefer an explicit `labels` list; otherwise derive the
                        # label order from the model's own `id2label` map (ordered
                        # by integer id). This keeps class ordering MODEL-DRIVEN and
                        # tamper-evident (config.json is hash-pinned) — critical for
                        # NLI/classifier models whose label order varies (a silent
                        # swap inverts every verdict).
                        labels = config.get("labels", [])
                        if not labels and isinstance(config.get("id2label"), dict):
                            try:
                                id2label = {
                                    int(k): v for k, v in config["id2label"].items()
                                }
                                labels = [id2label[i] for i in sorted(id2label)]
                            except (ValueError, KeyError, TypeError):
                                labels = []

            loaded = LoadedModel(
                name=name,
                version=version,
                session=session,
                tokenizer=tokenizer,
                max_length=max_length,
                labels=labels or [],
                # Remember how this model was loaded so hot_swap can rebuild it
                # from the identical arguments, and record the artifact identity
                # so detect_drift can compare against the current on-disk bytes.
                metadata={
                    "model_subdir": subdir,
                    "requested_labels": requested_labels,
                },
                content_hash=_compute_content_hash(model_path),
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

    def detect_drift(self, name: str) -> dict[str, Any] | None:
        """Detect artifact drift for a loaded model: in-memory vs on-disk bytes.

        Compares the content hash captured when the model was loaded against a
        freshly-computed hash of the load-bearing files currently on disk. This
        catches the case where the model directory was updated (new weights /
        tokenizer / config pushed by a provisioning job) after the process
        loaded the old bytes, so the serving model is stale.

        This is a pure *change* signal — it does NOT verify the new bytes are
        trusted; that gate runs fail-closed inside ``hot_swap`` at reload time.

        Returns:
            ``None`` if the model is not loaded, otherwise a dict::

                {"name", "drifted": bool, "loaded_hash", "disk_hash"}
        """
        with self._lock:
            model = self._models.get(name)
            if model is None:
                return None
            loaded_hash = model.content_hash
            subdir = model.metadata.get("model_subdir", name)

        # Filesystem read done outside the lock — the in-memory model keeps
        # serving while we hash the on-disk artifacts.
        disk_hash = _compute_content_hash(self._model_dir / subdir)
        return {
            "name": name,
            "drifted": disk_hash != loaded_hash,
            "loaded_hash": loaded_hash,
            "disk_hash": disk_hash,
        }

    def hot_swap(self, name: str) -> bool:
        """Atomically reload a model from disk, replacing the in-memory slot.

        Rebuilds the model completely from the SAME arguments used originally,
        re-running the fail-closed integrity gate (``_verify_model_integrity``)
        on every load-bearing file. The new model is built OUTSIDE the lock
        (integrity hashing + ONNX session construction are slow), so the
        currently-loaded model keeps serving with zero downtime during the
        rebuild. ``load_model`` then performs the slot replacement atomically
        under the lock.

        Fail-closed: on ANY failure (missing files, integrity mismatch, corrupt
        ONNX/tokenizer) the rebuild returns ``None`` without touching the slot,
        so the previously-loaded model is left serving untouched. A bad on-disk
        update can never take a healthy model offline.

        Returns:
            ``True`` if the model was reloaded and swapped, ``False`` if the
            model was not loaded or the reload failed (old model retained).
        """
        with self._lock:
            old = self._models.get(name)
            if old is None:
                return False
            subdir = old.metadata.get("model_subdir", name)
            max_length = old.max_length
            requested_labels = old.metadata.get("requested_labels")

        # Rebuild + atomic store happen in load_model; on failure it returns
        # None and leaves self._models[name] (the old model) in place.
        new = self.load_model(
            name,
            model_subdir=subdir,
            max_length=max_length,
            labels=list(requested_labels) if requested_labels else None,
        )
        if new is None:
            logger.warning("model_hot_swap_failed_kept_old", extra={"model": name})
            return False
        logger.info("model_hot_swapped",
                    extra={"model": name, "version": new.version,
                           "content_hash": new.content_hash[:16]})
        return True

    def hot_swap_all(self) -> dict[str, bool]:
        """Hot-swap every currently-loaded model that has drifted on disk.

        Only models whose on-disk artifacts actually changed are reloaded —
        unchanged models are left serving as-is (no needless rebuild). Each
        swap is independently fail-closed: a failed reload keeps that model's
        old bytes serving and does not affect the others.

        Returns:
            Dict mapping model name -> swap outcome, for every model that was
            found to have drifted (``True`` swapped, ``False`` reload failed).
            Unchanged models are omitted.
        """
        with self._lock:
            names = list(self._models.keys())

        results: dict[str, bool] = {}
        for name in names:
            drift = self.detect_drift(name)
            if drift is not None and drift["drifted"]:
                results[name] = self.hot_swap(name)
        return results

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
                    for label, prob in zip(model.labels, probabilities, strict=False)
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
