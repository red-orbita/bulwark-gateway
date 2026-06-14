#!/usr/bin/env python3
"""
Download sentence-transformers model for enrichment pipeline.

Used by the Helm init-container to pre-populate the enrichment PVC
with model files so the proxy doesn't need network access at runtime.

Usage:
    python download-enrichment-model.py [MODEL_NAME] [TARGET_DIR]

Defaults:
    MODEL_NAME = all-MiniLM-L6-v2
    TARGET_DIR = /app/shared/enrichment/sentence-transformers
"""

import os
import sys
import json
import hashlib
import urllib.request
import urllib.error
from pathlib import Path

MODEL_NAME = os.getenv("SENTINEL_EMBED_MODEL", sys.argv[1] if len(sys.argv) > 1 else "all-MiniLM-L6-v2")
TARGET_DIR = Path(os.getenv("SENTENCE_TRANSFORMERS_HOME", sys.argv[2] if len(sys.argv) > 2 else "/app/shared/enrichment/sentence-transformers"))

# HuggingFace Hub API
HF_API = "https://huggingface.co/api/models"
HF_BASE = "https://huggingface.co"

# Files needed for sentence-transformers inference
REQUIRED_FILES = [
    "config.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
    "vocab.txt",
    "modules.json",
    "sentence_bert_config.json",
]

# Model files (at least one must exist)
MODEL_FILES = [
    "model.safetensors",
    "pytorch_model.bin",
]


def download_file(url: str, dest: Path, expected_size: int | None = None) -> bool:
    """Download a file with progress indication."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "sentinel-gateway/0.2.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            dest.parent.mkdir(parents=True, exist_ok=True)
            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            chunk_size = 1024 * 1024  # 1MB chunks

            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = (downloaded / total) * 100
                        print(f"  {dest.name}: {downloaded // 1024}KB / {total // 1024}KB ({pct:.0f}%)", flush=True)

            if expected_size and downloaded != expected_size:
                print(f"  WARNING: Expected {expected_size} bytes, got {downloaded}", flush=True)
                return False

            return True
    except (urllib.error.URLError, OSError) as e:
        print(f"  ERROR downloading {url}: {e}", flush=True)
        return False


def get_model_files(model_name: str) -> list[dict]:
    """Get list of files in the model repository from HuggingFace API."""
    url = f"{HF_API}/sentence-transformers/{model_name}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "sentinel-gateway/0.2.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return data.get("siblings", [])
    except Exception as e:
        print(f"  WARNING: API call failed ({e}), using hardcoded file list", flush=True)
        return []


def model_already_downloaded(model_dir: Path) -> bool:
    """Check if model is already present and complete."""
    if not model_dir.exists():
        return False

    # Check for config.json (always required)
    if not (model_dir / "config.json").exists():
        return False

    # Check for at least one model weight file
    has_weights = any((model_dir / f).exists() for f in MODEL_FILES)
    if not has_weights:
        return False

    # Check for tokenizer
    if not (model_dir / "tokenizer.json").exists() and not (model_dir / "vocab.txt").exists():
        return False

    return True


def main():
    print(f"=== Sentinel Gateway Model Download ===")
    print(f"Model: sentence-transformers/{MODEL_NAME}")
    print(f"Target: {TARGET_DIR}")
    print()

    # Model files go into a subdirectory named after the model
    model_dir = TARGET_DIR / f"sentence-transformers_{MODEL_NAME}"

    # Check if already downloaded
    if model_already_downloaded(model_dir):
        print(f"Model already exists at {model_dir}")
        print("Skipping download (delete directory to force re-download)")
        return 0

    print(f"Downloading model to {model_dir}...")
    model_dir.mkdir(parents=True, exist_ok=True)

    # Get file list from HuggingFace API
    repo_files = get_model_files(MODEL_NAME)

    if repo_files:
        # Download files from API listing
        files_to_download = []
        for file_info in repo_files:
            filename = file_info.get("rfilename", "")
            # Skip large unnecessary files
            if filename.startswith(".") or filename.endswith(".md") or "onnx" in filename.lower():
                continue
            # Include all config, tokenizer, and model files
            if any(filename == f for f in REQUIRED_FILES + MODEL_FILES):
                files_to_download.append(filename)
            elif filename.startswith("1_Pooling/") or filename.startswith("2_Normalize/"):
                files_to_download.append(filename)
    else:
        # Fallback: try known files for all-MiniLM-L6-v2
        files_to_download = REQUIRED_FILES + ["model.safetensors", "1_Pooling/config.json"]

    success_count = 0
    fail_count = 0

    for filename in files_to_download:
        url = f"{HF_BASE}/sentence-transformers/{MODEL_NAME}/resolve/main/{filename}"
        dest = model_dir / filename
        if dest.exists():
            print(f"  {filename}: already exists, skipping")
            success_count += 1
            continue

        print(f"  Downloading: {filename}")
        if download_file(url, dest):
            success_count += 1
        else:
            fail_count += 1

    print()
    print(f"Download complete: {success_count} files OK, {fail_count} failed")

    if not model_already_downloaded(model_dir):
        print("WARNING: Model appears incomplete after download")
        print("The enrichment pipeline will attempt to download at runtime")
        return 1

    # Write a marker file so we know this was a clean download
    marker = model_dir / ".sentinel-download-complete"
    marker.write_text(json.dumps({
        "model": MODEL_NAME,
        "version": "0.2.0",
        "files": success_count,
    }))

    print(f"Model ready at {model_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
