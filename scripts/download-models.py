#!/usr/bin/env python3
"""Download ML models for Bulwark Gateway async scanner pipeline.

Usage:
    python scripts/download-models.py [--all | --injection | --toxicity | --embeddings | --nli]

Models:
    injection-classifier: DeBERTa-v3 prompt injection detector (~700MB)
    toxicity: RoBERTa toxicity classifier (~250MB)
    sentence-embeddings: all-MiniLM-L6-v2 embeddings for RelevanceScanner (~90MB)
    nli-classifier: DeBERTa-v3 NLI for Hallucination/Grounding scanners (~540MB)

Requirements:
    pip install huggingface-hub

Destination: models/ (configurable via BULWARK_ML_MODEL_DIR)
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

# Integrity manifest consumed by src/scanners/ml/model_manager.py (fail-closed).
# Keyed by the model's path relative to the model directory, e.g.
# "injection-classifier/model.onnx" -> "<sha256>".
_MANIFEST_PATH = Path(__file__).resolve().parent.parent / "config" / "model_manifest.json"


def _sha256(path: Path) -> str:
    """Stream a file through SHA-256 without loading it fully into memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def update_manifest(onnx_path: Path, key: str) -> bool:
    """Verify or record the SHA-256 of a downloaded model in the manifest.

    Security: the manifest is the trust anchor for ONNX models. If an entry
    already exists for this model, the freshly downloaded file MUST match it —
    a mismatch means the upstream artifact changed (or was tampered with), so we
    abort instead of silently trusting new bytes. If no entry exists, we record
    it (bootstrap) and print the hash so a maintainer can review and commit it.
    """
    actual = _sha256(onnx_path)

    manifest: dict = {}
    if _MANIFEST_PATH.exists():
        try:
            manifest = json.loads(_MANIFEST_PATH.read_text())
        except (ValueError, OSError) as e:
            print(f"  ERROR: cannot read manifest {_MANIFEST_PATH}: {e}")
            return False

    expected = manifest.get(key)
    if expected and expected != actual:
        print(f"  INTEGRITY MISMATCH for {key}")
        print(f"    manifest : {expected}")
        print(f"    download : {actual}")
        print("    Refusing to overwrite a pinned hash. If this upgrade is")
        print(f"    intentional, update the value in {_MANIFEST_PATH} manually.")
        return False

    if expected == actual:
        print(f"  integrity OK ({key})")
        return True

    manifest[key] = actual
    _MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    _MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"  manifest updated: {key} -> {actual}")
    print(f"    (review and commit {_MANIFEST_PATH})")
    return True


def download_model(repo_id: str, files: list[tuple[str, str]], dest: Path) -> bool:
    """Download model files from HuggingFace Hub."""
    try:
        from huggingface_hub import hf_hub_download
    except ImportError:
        print("ERROR: huggingface-hub not installed. Run: pip install huggingface-hub")
        return False

    dest.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {repo_id} → {dest}")

    tmp_dir = tempfile.mkdtemp(prefix="bulwark-models-dl-")
    try:
        for remote_file, local_name in files:
            try:
                local = hf_hub_download(
                    repo_id=repo_id,
                    filename=remote_file,
                    local_dir=tmp_dir,
                )
                target = dest / local_name
                shutil.copy2(local, target)
                size_mb = target.stat().st_size / 1024 / 1024
                print(f"  {local_name} ({size_mb:.1f} MB)")
            except Exception as e:
                print(f"  FAILED: {remote_file} — {e}")
                return False
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return True


def download_injection(model_dir: Path) -> bool:
    """Download prompt injection classifier (DeBERTa-v3, ~700MB)."""
    dest = model_dir / "injection-classifier"
    ok = download_model(
        repo_id="protectai/deberta-v3-base-prompt-injection-v2",
        files=[
            ("onnx/model.onnx", "model.onnx"),
            ("onnx/tokenizer.json", "tokenizer.json"),
            ("onnx/config.json", "config.json"),
        ],
        dest=dest,
    )
    if ok:
        ok = update_manifest(dest / "model.onnx", "injection-classifier/model.onnx")
    return ok


def download_toxicity(model_dir: Path) -> bool:
    """Download toxicity classifier (RoBERTa, ~250MB)."""
    dest = model_dir / "toxicity"
    ok = download_model(
        repo_id="Deepchecks/roberta_toxicity_classifier_onnx",
        files=[
            ("model_optimized.onnx", "model.onnx"),
            ("tokenizer.json", "tokenizer.json"),
            ("config.json", "config.json"),
        ],
        dest=dest,
    )
    if ok:
        ok = update_manifest(dest / "model.onnx", "toxicity/model.onnx")
    return ok


def download_embeddings(model_dir: Path) -> bool:
    """Download sentence-embedding model (all-MiniLM-L6-v2 ONNX, ~90MB).

    Powers the RelevanceScanner (embedding cosine similarity between the user's
    question and the LLM response). The scanner expects mean-pooled token
    embeddings, so we download the plain fp32 ONNX export (``onnx/model.onnx``)
    whose output is the last hidden state (1, seq_len, hidden_dim).
    """
    dest = model_dir / "sentence-embeddings"
    ok = download_model(
        repo_id="sentence-transformers/all-MiniLM-L6-v2",
        files=[
            ("onnx/model.onnx", "model.onnx"),
            ("tokenizer.json", "tokenizer.json"),
            ("config.json", "config.json"),
        ],
        dest=dest,
    )
    if ok:
        ok = update_manifest(dest / "model.onnx", "sentence-embeddings/model.onnx")
    return ok


def download_nli(model_dir: Path) -> bool:
    """Download NLI classifier (cross-encoder/nli-deberta-v3-small ONNX, ~540MB).

    Shared by the HallucinationScanner (claim vs. input-context entailment) and
    the GroundingScanner (RAG-claim vs. source-chunk entailment). This is a
    3-class cross-encoder NLI model. IMPORTANT: its label order is
    ``["contradiction", "entailment", "neutral"]`` (from the model's own
    ``id2label``) — NOT the SNLI/MNLI ``entailment/neutral/contradiction``
    ordering. The ONNX loader reads ``id2label`` straight from ``config.json`` so
    the ordering is model-driven and tamper-evident; the scanners resolve classes
    by NAME, never by a hardcoded index.
    """
    dest = model_dir / "nli-classifier"
    ok = download_model(
        repo_id="cross-encoder/nli-deberta-v3-small",
        files=[
            ("onnx/model.onnx", "model.onnx"),
            ("tokenizer.json", "tokenizer.json"),
            ("config.json", "config.json"),
        ],
        dest=dest,
    )
    if ok:
        ok = update_manifest(dest / "model.onnx", "nli-classifier/model.onnx")
    return ok


def main():
    parser = argparse.ArgumentParser(description="Download ML models for Bulwark Gateway")
    parser.add_argument("--all", action="store_true", help="Download all models")
    parser.add_argument("--injection", action="store_true", help="Download injection classifier")
    parser.add_argument("--toxicity", action="store_true", help="Download toxicity classifier")
    parser.add_argument("--embeddings", action="store_true", help="Download sentence-embedding model")
    parser.add_argument("--nli", action="store_true", help="Download NLI classifier (hallucination/grounding)")
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=Path(os.environ.get("BULWARK_ML_MODEL_DIR", "models")),
        help="Model directory (default: models/)",
    )
    args = parser.parse_args()

    if not any([args.all, args.injection, args.toxicity, args.embeddings, args.nli]):
        args.all = True

    model_dir = args.model_dir
    success = True

    if args.all or args.injection:
        if not download_injection(model_dir):
            success = False

    if args.all or args.toxicity:
        if not download_toxicity(model_dir):
            success = False

    if args.all or args.embeddings:
        if not download_embeddings(model_dir):
            success = False

    if args.all or args.nli:
        if not download_nli(model_dir):
            success = False

    if success:
        print(f"\nModels ready at: {model_dir.resolve()}")
        print("Enable with: BULWARK_ML_ENABLED=true")
    else:
        print("\nSome downloads failed.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
