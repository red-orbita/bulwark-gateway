#!/usr/bin/env python3
"""
Model Export & Download Utility for Sentinel Gateway ML Scanners.

Downloads pre-trained models from HuggingFace, exports them to ONNX format,
and prepares them for use with the Sentinel ML scanner pipeline.

Usage:
    # Download and export all models
    python scripts/export_models.py --all

    # Download specific model
    python scripts/export_models.py --model injection-classifier

    # Export with quantization (smaller, faster on CPU)
    python scripts/export_models.py --all --quantize

    # List available models
    python scripts/export_models.py --list

    # Verify existing models
    python scripts/export_models.py --verify

Requirements:
    pip install sentinel-gateway[ml]
    pip install optimum[exporters] transformers torch

Models exported:
    models/injection-classifier/    DeBERTa-v3 fine-tuned on prompt injection
    models/toxicity-classifier/     Multi-label toxicity (Jigsaw-based)
    models/intent-classifier/       Multi-label adversarial intent
    models/topic-classifier/        NLI-based zero-shot (bart-large-mnli)
    models/language-detector/       Language identification (Phase 3)
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# Project root
ROOT = Path(__file__).parent.parent
DEFAULT_MODEL_DIR = ROOT / "models"

# Model registry: name → HuggingFace model ID + export config
MODEL_REGISTRY: dict[str, dict] = {
    "injection-classifier": {
        "hf_model": "protectai/deberta-v3-base-prompt-injection-v2",
        "task": "text-classification",
        "labels": ["benign", "injection"],
        "description": "Prompt injection binary classifier (DeBERTa-v3-base)",
        "max_length": 512,
    },
    "toxicity-classifier": {
        "hf_model": "unitary/toxic-bert",
        "task": "text-classification",
        "labels": [
            "toxicity",
            "severe_toxicity",
            "obscene",
            "threat",
            "insult",
            "identity_attack",
        ],
        "description": "Multi-label toxicity classifier (BERT-based)",
        "max_length": 512,
    },
    "intent-classifier": {
        "hf_model": "facebook/bart-large-mnli",
        "task": "zero-shot-classification",
        "labels": [
            "benign",
            "social_engineering",
            "manipulation",
            "escalation_attempt",
            "evasion",
        ],
        "description": "Adversarial intent detector (fine-tune from MNLI)",
        "max_length": 512,
        "note": "For production, fine-tune on labeled adversarial intent data",
    },
    "topic-classifier": {
        "hf_model": "facebook/bart-large-mnli",
        "task": "zero-shot-classification",
        "labels": [],  # Dynamic: topics come from policy config
        "description": "Zero-shot NLI topic classifier (BART-large-MNLI)",
        "max_length": 512,
    },
    "language-detector": {
        "hf_model": "papluca/xlm-roberta-base-language-detection",
        "task": "text-classification",
        "labels": [
            "ar", "bg", "de", "el", "en", "es", "fr", "hi", "it", "ja",
            "nl", "pl", "pt", "ru", "sw", "th", "tr", "ur", "vi", "zh",
        ],
        "description": "Language identification (XLM-RoBERTa, 20 languages)",
        "max_length": 512,
    },
}


def check_dependencies() -> bool:
    """Verify export dependencies are available."""
    missing = []
    try:
        import transformers  # noqa: F401
    except ImportError:
        missing.append("transformers")

    try:
        import torch  # noqa: F401
    except ImportError:
        missing.append("torch")

    try:
        import onnx  # noqa: F401
    except ImportError:
        missing.append("onnx")

    try:
        import tokenizers  # noqa: F401
    except ImportError:
        missing.append("tokenizers")

    if missing:
        logger.error(
            f"Missing dependencies: {', '.join(missing)}. "
            f"Install with: pip install transformers torch onnx tokenizers"
        )
        return False
    return True


def list_models() -> None:
    """Print available models."""
    print("\nAvailable models for Sentinel Gateway ML scanners:\n")
    print(f"{'Name':<25} {'Task':<25} {'Description'}")
    print("-" * 90)
    for name, config in MODEL_REGISTRY.items():
        print(f"{name:<25} {config['task']:<25} {config['description']}")
    print(f"\nTotal: {len(MODEL_REGISTRY)} models")
    print(f"Default output: {DEFAULT_MODEL_DIR}/")


def verify_models(model_dir: Path) -> None:
    """Verify existing model files."""
    print(f"\nVerifying models in: {model_dir}\n")
    all_ok = True

    for name in MODEL_REGISTRY:
        model_path = model_dir / name
        onnx_file = model_path / "model.onnx"
        tokenizer_file = model_path / "tokenizer.json"
        config_file = model_path / "config.json"

        status_parts = []
        if not model_path.exists():
            print(f"  [ MISSING ] {name}/")
            all_ok = False
            continue

        if onnx_file.exists():
            size_mb = onnx_file.stat().st_size / (1024 * 1024)
            status_parts.append(f"model.onnx ({size_mb:.1f} MB)")
        else:
            status_parts.append("model.onnx MISSING")
            all_ok = False

        if tokenizer_file.exists():
            status_parts.append("tokenizer.json OK")
        else:
            status_parts.append("tokenizer.json MISSING")
            all_ok = False

        if config_file.exists():
            status_parts.append("config.json OK")

        ok = onnx_file.exists() and tokenizer_file.exists()
        marker = "  OK  " if ok else " FAIL "
        print(f"  [{marker}] {name}/ — {', '.join(status_parts)}")

    print()
    if all_ok:
        print("All models verified successfully.")
    else:
        print("Some models are missing. Run with --all to download and export.")


def export_model(
    name: str,
    model_dir: Path,
    quantize: bool = False,
    force: bool = False,
) -> bool:
    """Download and export a single model to ONNX.

    Steps:
    1. Download from HuggingFace (cached)
    2. Export to ONNX via optimum or torch.onnx
    3. Save tokenizer as tokenizer.json (fast tokenizer format)
    4. Optionally quantize (int8 dynamic quantization)
    5. Write config.json with metadata
    """
    config = MODEL_REGISTRY.get(name)
    if config is None:
        logger.error(f"Unknown model: {name}. Use --list to see available models.")
        return False

    output_dir = model_dir / name
    onnx_path = output_dir / "model.onnx"

    if onnx_path.exists() and not force:
        logger.info(f"Model '{name}' already exists at {output_dir}. Use --force to re-export.")
        return True

    logger.info(f"Exporting model: {name}")
    logger.info(f"  HuggingFace: {config['hf_model']}")
    logger.info(f"  Task: {config['task']}")
    logger.info(f"  Output: {output_dir}")

    try:
        from transformers import AutoTokenizer

        # Step 1: Download tokenizer
        logger.info("  Downloading tokenizer...")
        tokenizer = AutoTokenizer.from_pretrained(config["hf_model"])

        # Step 2: Export to ONNX
        output_dir.mkdir(parents=True, exist_ok=True)

        # Try optimum first (cleaner export)
        try:
            from optimum.onnxruntime import ORTModelForSequenceClassification

            logger.info("  Exporting via optimum (recommended)...")
            model = ORTModelForSequenceClassification.from_pretrained(
                config["hf_model"], export=True
            )
            model.save_pretrained(output_dir)
            # optimum saves as model.onnx automatically
        except ImportError:
            # Fallback: manual torch.onnx export
            logger.info("  optimum not available, using torch.onnx.export...")
            _export_with_torch(config, output_dir)

        # Step 3: Save tokenizer
        logger.info("  Saving fast tokenizer...")
        tokenizer.save_pretrained(output_dir)

        # Ensure tokenizer.json exists (fast tokenizer format)
        tokenizer_json = output_dir / "tokenizer.json"
        if not tokenizer_json.exists():
            # Some tokenizers don't have fast version; use the saved files
            logger.warning(f"  tokenizer.json not generated (slow tokenizer). Using vocab files.")

        # Step 4: Optional quantization
        if quantize:
            _quantize_model(output_dir)

        # Step 5: Write config.json
        model_config = {
            "name": name,
            "version": "1.0.0",
            "hf_model": config["hf_model"],
            "task": config["task"],
            "labels": config["labels"],
            "max_length": config["max_length"],
            "quantized": quantize,
            "description": config["description"],
        }
        config_path = output_dir / "config.json"
        config_path.write_text(json.dumps(model_config, indent=2))

        # Verify output
        final_onnx = output_dir / "model.onnx"
        if final_onnx.exists():
            size_mb = final_onnx.stat().st_size / (1024 * 1024)
            logger.info(f"  Export complete: {size_mb:.1f} MB")
            return True
        else:
            logger.error(f"  Export failed: model.onnx not found in {output_dir}")
            return False

    except Exception as e:
        logger.error(f"  Export failed: {e}")
        return False


def _export_with_torch(config: dict, output_dir: Path) -> None:
    """Export model using torch.onnx (fallback when optimum unavailable)."""
    import torch
    from transformers import AutoModelForSequenceClassification

    model = AutoModelForSequenceClassification.from_pretrained(config["hf_model"])
    model.eval()

    # Dummy input
    dummy_input = torch.ones(1, config["max_length"], dtype=torch.long)
    dummy_attention = torch.ones(1, config["max_length"], dtype=torch.long)

    onnx_path = output_dir / "model.onnx"

    torch.onnx.export(
        model,
        (dummy_input, dummy_attention),
        str(onnx_path),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "sequence"},
            "attention_mask": {0: "batch", 1: "sequence"},
            "logits": {0: "batch"},
        },
        opset_version=14,
    )


def _quantize_model(output_dir: Path) -> None:
    """Apply dynamic INT8 quantization to reduce model size and improve CPU inference."""
    try:
        from onnxruntime.quantization import QuantType, quantize_dynamic

        onnx_path = output_dir / "model.onnx"
        quantized_path = output_dir / "model_quantized.onnx"

        logger.info("  Applying INT8 dynamic quantization...")
        quantize_dynamic(
            str(onnx_path),
            str(quantized_path),
            weight_type=QuantType.QInt8,
        )

        # Replace original with quantized version
        original_size = onnx_path.stat().st_size / (1024 * 1024)
        quantized_size = quantized_path.stat().st_size / (1024 * 1024)
        reduction = (1 - quantized_size / original_size) * 100

        # Keep original as backup
        backup = output_dir / "model_fp32.onnx"
        shutil.move(str(onnx_path), str(backup))
        shutil.move(str(quantized_path), str(onnx_path))

        logger.info(
            f"  Quantized: {original_size:.1f} MB → {quantized_size:.1f} MB "
            f"({reduction:.0f}% reduction)"
        )

    except ImportError:
        logger.warning("  onnxruntime.quantization not available, skipping quantization")
    except Exception as e:
        logger.warning(f"  Quantization failed: {e}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sentinel Gateway — ML Model Export Utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/export_models.py --list
  python scripts/export_models.py --all
  python scripts/export_models.py --model injection-classifier --quantize
  python scripts/export_models.py --verify
        """,
    )
    parser.add_argument("--list", action="store_true", help="List available models")
    parser.add_argument("--verify", action="store_true", help="Verify existing models")
    parser.add_argument("--all", action="store_true", help="Export all models")
    parser.add_argument("--model", type=str, help="Export a specific model by name")
    parser.add_argument(
        "--output", type=str, default=str(DEFAULT_MODEL_DIR),
        help=f"Output directory (default: {DEFAULT_MODEL_DIR})",
    )
    parser.add_argument(
        "--quantize", action="store_true",
        help="Apply INT8 quantization (smaller/faster on CPU)",
    )
    parser.add_argument("--force", action="store_true", help="Re-export even if exists")

    args = parser.parse_args()
    model_dir = Path(args.output)

    if args.list:
        list_models()
        return 0

    if args.verify:
        verify_models(model_dir)
        return 0

    if not args.all and not args.model:
        parser.print_help()
        return 1

    # Check dependencies before attempting export
    if not check_dependencies():
        return 1

    model_dir.mkdir(parents=True, exist_ok=True)

    if args.all:
        results = {}
        for name in MODEL_REGISTRY:
            ok = export_model(name, model_dir, quantize=args.quantize, force=args.force)
            results[name] = ok

        print("\n" + "=" * 60)
        print("Export Summary:")
        print("=" * 60)
        for name, ok in results.items():
            status = "OK" if ok else "FAILED"
            print(f"  [{status:>6}] {name}")

        failed = sum(1 for ok in results.values() if not ok)
        if failed:
            logger.error(f"{failed}/{len(results)} models failed to export")
            return 1
        logger.info(f"All {len(results)} models exported successfully to {model_dir}/")
        return 0

    if args.model:
        ok = export_model(args.model, model_dir, quantize=args.quantize, force=args.force)
        return 0 if ok else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
