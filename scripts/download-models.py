#!/usr/bin/env python3
"""Download ML models for Sentinel Gateway async scanner pipeline.

Usage:
    python scripts/download-models.py [--all | --injection | --toxicity]

Models:
    injection-classifier: DeBERTa-v3 prompt injection detector (~700MB)
    toxicity: RoBERTa toxicity classifier (~250MB)

Requirements:
    pip install huggingface-hub

Destination: models/ (configurable via SENTINEL_ML_MODEL_DIR)
"""

import argparse
import os
import shutil
import sys
from pathlib import Path


def download_model(repo_id: str, files: list[tuple[str, str]], dest: Path) -> bool:
    """Download model files from HuggingFace Hub."""
    try:
        from huggingface_hub import hf_hub_download
    except ImportError:
        print("ERROR: huggingface-hub not installed. Run: pip install huggingface-hub")
        return False

    dest.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {repo_id} → {dest}")

    for remote_file, local_name in files:
        try:
            local = hf_hub_download(
                repo_id=repo_id,
                filename=remote_file,
                local_dir="/tmp/sentinel-models-dl",
            )
            target = dest / local_name
            shutil.copy2(local, target)
            size_mb = target.stat().st_size / 1024 / 1024
            print(f"  {local_name} ({size_mb:.1f} MB)")
        except Exception as e:
            print(f"  FAILED: {remote_file} — {e}")
            return False

    return True


def download_injection(model_dir: Path) -> bool:
    """Download prompt injection classifier (DeBERTa-v3, ~700MB)."""
    return download_model(
        repo_id="protectai/deberta-v3-base-prompt-injection-v2",
        files=[
            ("onnx/model.onnx", "model.onnx"),
            ("onnx/tokenizer.json", "tokenizer.json"),
            ("onnx/config.json", "config.json"),
        ],
        dest=model_dir / "injection-classifier",
    )


def download_toxicity(model_dir: Path) -> bool:
    """Download toxicity classifier (RoBERTa, ~250MB)."""
    return download_model(
        repo_id="Deepchecks/roberta_toxicity_classifier_onnx",
        files=[
            ("model_optimized.onnx", "model.onnx"),
            ("tokenizer.json", "tokenizer.json"),
            ("config.json", "config.json"),
        ],
        dest=model_dir / "toxicity",
    )


def main():
    parser = argparse.ArgumentParser(description="Download ML models for Sentinel Gateway")
    parser.add_argument("--all", action="store_true", help="Download all models")
    parser.add_argument("--injection", action="store_true", help="Download injection classifier")
    parser.add_argument("--toxicity", action="store_true", help="Download toxicity classifier")
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=Path(os.environ.get("SENTINEL_ML_MODEL_DIR", "models")),
        help="Model directory (default: models/)",
    )
    args = parser.parse_args()

    if not any([args.all, args.injection, args.toxicity]):
        args.all = True

    model_dir = args.model_dir
    success = True

    if args.all or args.injection:
        if not download_injection(model_dir):
            success = False

    if args.all or args.toxicity:
        if not download_toxicity(model_dir):
            success = False

    if success:
        print(f"\nModels ready at: {model_dir.resolve()}")
        print("Enable with: SENTINEL_ML_ENABLED=true")
    else:
        print("\nSome downloads failed.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
