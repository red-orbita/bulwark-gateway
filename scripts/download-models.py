#!/usr/bin/env python3
"""Download ML models for Bulwark Gateway async scanner pipeline.

Usage:
    python scripts/download-models.py [--all | --injection | --toxicity
                                       | --embeddings | --nli | --fasttext]
    python scripts/download-models.py --verify   # integrity-check on-disk models

Models:
    injection-classifier: DeBERTa-v3 prompt injection detector (~700MB)
    toxicity: RoBERTa toxicity classifier (~250MB)
    sentence-embeddings: all-MiniLM-L6-v2 embeddings for RelevanceScanner (~90MB)
    nli-classifier: DeBERTa-v3 NLI for Hallucination/Grounding scanners (~540MB)
    fasttext: lid.176.ftz language-ID model for LanguageDetector (~917KB)

Requirements:
    pip install '.[ml-provision]'   # only for the ONNX models (HF Hub client)
    # --fasttext and --verify need no extra dependency (stdlib only)

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

# Canonical fastText language-identification model (176 languages, compressed,
# ~917 KB). Served from Facebook AI's public file host — the same origin the
# fastText project documents. Pinned by SHA-256 in the manifest on first
# download (TOFU), identical trust model to the ONNX artifacts.
_FASTTEXT_LID_URL = "https://dl.fbaipublicfiles.com/fasttext/supervised-models/lid.176.ftz"

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
        print("ERROR: huggingface-hub not installed. Run: pip install '.[ml-provision]'")
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


def download_url(url: str, dest: Path) -> bool:
    """Download a single file over HTTPS to ``dest`` (stdlib only, no HF dep).

    Security: refuses any non-HTTPS URL, streams the body to a temp file in
    bounded chunks (never buffering the whole payload), and only publishes the
    final file on success. Used for artifacts that are not on HuggingFace Hub.
    """
    import urllib.request

    if not url.lower().startswith("https://"):
        print(f"  REFUSED: non-HTTPS model URL: {url}")
        return False

    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {url} → {dest}")

    tmp_fd, tmp_name = tempfile.mkstemp(prefix="bulwark-url-dl-", suffix=".part")
    os.close(tmp_fd)
    tmp = Path(tmp_name)
    try:
        with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 (HTTPS enforced above)
            status = getattr(resp, "status", 200)
            if status not in (200, None):
                print(f"  FAILED: HTTP {status}")
                return False
            with open(tmp, "wb") as out:
                shutil.copyfileobj(resp, out, length=1024 * 1024)
        shutil.copy2(tmp, dest)
        size_kb = dest.stat().st_size / 1024
        print(f"  {dest.name} ({size_kb:.0f} KB)")
        return True
    except Exception as e:
        print(f"  FAILED: {url} — {e}")
        return False
    finally:
        tmp.unlink(missing_ok=True)


def _pin_model_files(dest: Path, subdir: str) -> bool:
    """Pin every load-bearing file of a downloaded model in the manifest.

    Security: the model's verdict depends on more than the ONNX weights. A
    poisoned ``tokenizer.json`` can remap an attack payload to benign token ids,
    and a reordered ``config.json`` (id2label) inverts every verdict. So all
    three are hashed and pinned, mirroring what ``model_manager`` fail-closes on
    at load time. ``config.json`` is optional (some models ship none); when
    present it is pinned too.
    """
    ok = update_manifest(dest / "model.onnx", f"{subdir}/model.onnx")
    if ok:
        ok = update_manifest(dest / "tokenizer.json", f"{subdir}/tokenizer.json")
    if ok and (dest / "config.json").exists():
        ok = update_manifest(dest / "config.json", f"{subdir}/config.json")
    return ok


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
        ok = _pin_model_files(dest, "injection-classifier")
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
        ok = _pin_model_files(dest, "toxicity")
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
        ok = _pin_model_files(dest, "sentence-embeddings")
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
        ok = _pin_model_files(dest, "nli-classifier")
    return ok


def download_fasttext(model_dir: Path) -> bool:
    """Download the fastText language-ID model (lid.176.ftz, ~917 KB).

    Powers the LanguageDetector's ``fasttext`` backend — a far more accurate
    default than the Unicode-script heuristic, without lingua's 170 MB wheel.
    This only provisions the model file; using it also needs the runtime
    package (``pip install '.[fasttext]'``). The file is loaded directly by
    ``src/scanners/multilingual/language_detector.py`` from
    ``BULWARK_ML_MODEL_DIR / lid.176.ftz`` and its hash is recorded in the
    integrity manifest for tamper-evidence.
    """
    dest = model_dir / "lid.176.ftz"
    ok = download_url(_FASTTEXT_LID_URL, dest)
    if ok:
        ok = update_manifest(dest, "lid.176.ftz")
    return ok


def verify_models(model_dir: Path) -> bool:
    """Integrity-check every pinned model on disk against the manifest.

    Downloads nothing and needs no third-party dependency (stdlib only). For each
    entry in ``config/model_manifest.json`` it re-hashes the corresponding file
    under ``model_dir`` and compares it to the pinned SHA-256. This is the same
    fail-closed check ``model_manager._verify_model_integrity`` runs at load time,
    exposed as an offline audit so operators can validate a provisioned volume
    (e.g. after copying models into an image) without starting the proxy.

    Manifest keys are the model's path relative to the model directory, e.g.
    ``injection-classifier/model.onnx`` or ``lid.176.ftz``.

    Returns True only if the manifest is non-empty and EVERY pinned file exists
    and matches. A missing file, a hash mismatch, or an unreadable/empty manifest
    all fail closed (returns False).
    """
    if not _MANIFEST_PATH.exists():
        print(f"ERROR: no integrity manifest at {_MANIFEST_PATH}")
        return False

    try:
        manifest: dict = json.loads(_MANIFEST_PATH.read_text())
    except (ValueError, OSError) as e:
        print(f"ERROR: cannot read manifest {_MANIFEST_PATH}: {e}")
        return False

    if not manifest:
        print(f"ERROR: integrity manifest {_MANIFEST_PATH} is empty — nothing to verify")
        return False

    # Metadata keys (e.g. "_comment") document the manifest; they are not model
    # files on disk, so exclude them from the file set being verified.
    file_keys = sorted(k for k in manifest if not k.startswith("_"))
    print(f"Verifying {len(file_keys)} pinned model file(s) under {model_dir.resolve()}")
    all_ok = True
    for key in file_keys:
        expected = manifest[key]
        path = model_dir / key
        if not path.exists():
            print(f"  MISSING: {key} (not provisioned under {model_dir})")
            all_ok = False
            continue
        actual = _sha256(path)
        if actual == expected:
            print(f"  OK      {key}")
        else:
            print(f"  MISMATCH {key}")
            print(f"    manifest : {expected}")
            print(f"    on disk  : {actual}")
            all_ok = False

    return all_ok


def main():
    parser = argparse.ArgumentParser(description="Download ML models for Bulwark Gateway")
    parser.add_argument("--all", action="store_true", help="Download all models")
    parser.add_argument("--injection", action="store_true", help="Download injection classifier")
    parser.add_argument("--toxicity", action="store_true", help="Download toxicity classifier")
    parser.add_argument("--embeddings", action="store_true", help="Download sentence-embedding model")
    parser.add_argument("--nli", action="store_true", help="Download NLI classifier (hallucination/grounding)")
    parser.add_argument("--fasttext", action="store_true", help="Download fastText language-ID model (lid.176.ftz)")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify on-disk models against the integrity manifest (no download)",
    )
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=Path(os.environ.get("BULWARK_ML_MODEL_DIR", "models")),
        help="Model directory (default: models/)",
    )
    args = parser.parse_args()

    # --verify is a standalone, offline audit mode: never mix it with downloads.
    if args.verify:
        if verify_models(args.model_dir):
            print("\nAll pinned models verified OK.")
        else:
            print("\nModel integrity verification FAILED.", file=sys.stderr)
            sys.exit(1)
        return

    if not any([args.all, args.injection, args.toxicity, args.embeddings, args.nli, args.fasttext]):
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

    if args.all or args.fasttext:
        if not download_fasttext(model_dir):
            success = False

    if success:
        print(f"\nModels ready at: {model_dir.resolve()}")
        print("Enable with: BULWARK_ML_ENABLED=true")
    else:
        print("\nSome downloads failed.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
