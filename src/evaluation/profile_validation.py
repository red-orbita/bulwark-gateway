"""Offline candidate validation, never a production readiness endpoint."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
from dataclasses import asdict
from pathlib import Path
from time import perf_counter
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.evaluation.attacks import Attack
from src.evaluation.corpora import LabeledSample, split_samples
from src.evaluation.evidence import (
    IncompleteScanError,
    _interval,
    observed_environment,
    read_bounded,
    require_complete_scan,
    validate_corpus,
)
from src.evaluation.runner import EvaluationRunner
from src.guardrails.input_guardrail import InputGuardrail
from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.builtin.regex_scanner import RegexInputScanner
from src.scanners.pipeline import ScannerPipeline
from src.scanners.protocol import InputScanner, ScanContext


class ProfileConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    profile: Literal["regex", "local_hybrid"] = "regex"
    block_threshold: float = Field(default=0.9, gt=0, le=1)
    warn_threshold: float = Field(default=0.7, gt=0, le=1)
    timeout_seconds: float = Field(default=60, gt=0, le=300)

    @model_validator(mode="after")
    def ordered_thresholds(self) -> ProfileConfig:
        if self.warn_threshold > self.block_threshold:
            raise ValueError("WARN threshold must not exceed BLOCK threshold")
        return self


class EvidenceScan(InputScanner):
    async def safe_scan(self, content: str, context: ScanContext,
                        timeout_ms: float = 5000.0) -> GuardrailResult:
        # Runtime safe_scan turns exceptions into BLOCK without an error marker.
        # That must not be counted as a successful detection in an evidence run.
        try:
            result = await asyncio.wait_for(self.scan(content, context), timeout_ms / 1000)
        except Exception:
            raise RuntimeError("Offline scanner failed; evidence invalid") from None
        require_complete_scan(result.events)
        return result


class OfflineRegexScanner(EvidenceScan, RegexInputScanner):
    def __init__(self) -> None:
        self._engine = InputGuardrail(offline=True)

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        return await asyncio.to_thread(self._engine.inspect, content, context.tenant_id, context.agent_id)


async def build_profile(config: ProfileConfig, model_dir: Path) -> tuple[ScannerPipeline | None, dict]:
    """Reuse scanners without booting services or changing global settings/managers.

    Artifacts must already exist and be trusted by the repository model manifest.
    The caller must own an immutable model directory for the entire run.
    """
    pipeline = ScannerPipeline()
    regex = OfflineRegexScanner()
    pipeline.register(regex)
    readiness = {
        "ready": True, "scope": "offline_candidate_only", "maturity": "BETA",
        "profile_config": config.model_dump(),
        "profile_config_sha256": hashlib.sha256(
            json.dumps(config.model_dump(), sort_keys=True).encode(),
        ).hexdigest(),
        "observed_environment": observed_environment(regex._engine),
        "model": {"status": "not_requested"},
    }
    if config.profile == "regex":
        return pipeline, readiness

    from src.scanners.ml import model_manager
    from src.scanners.ml.injection_classifier import InjectionClassifier

    def load_verified():
        base = model_dir.resolve()
        directory = base / "injection-classifier"
        if directory.is_symlink():
            raise ValueError("Symlink model directory refused")
        hashes = {}
        for name, limit in (("model.onnx", 256 * 1024 * 1024),
                            ("tokenizer.json", 8 * 1024 * 1024), ("config.json", 65536)):
            artifact = directory / name
            data = read_bounded(artifact, limit)
            hashes[f"injection-classifier/{name}"] = hashlib.sha256(data).hexdigest()
            if name == "config.json":
                metadata = json.loads(data)
        # Preflight bounds the existing manager's reads; trust still comes from
        # its existing fail-closed verifier, not from a newly computed hash.
        manifest_data = read_bounded(model_manager._MODEL_MANIFEST_PATH, 1024 * 1024)
        trusted = json.loads(manifest_data)
        if any(trusted.get(key) != value for key, value in hashes.items()):
            raise ValueError("Model hash mismatch")
        labels = metadata.get("labels")
        if not labels and isinstance(metadata.get("id2label"), dict):
            labels = [metadata["id2label"].get(str(index)) for index in range(2)]
        if not isinstance(labels, list) or sorted(labels) != ["INJECTION", "SAFE"]:
            raise ValueError("Verified binary label mapping required")
        manager = model_manager.ModelManager(base)
        if not manager.available:
            raise ValueError("ML dependencies missing")
        model = manager.load_model("injection-classifier")
        if model is None or model.labels != labels:
            raise ValueError("Model load failed")
        return manager, hashes, hashlib.sha256(manifest_data).hexdigest()

    try:
        manager, hashes, manifest_hash = await asyncio.wait_for(
            asyncio.to_thread(load_verified), timeout=config.timeout_seconds,
        )
    except FileNotFoundError:
        readiness.update(ready=False, model={"status": "missing_artifacts_or_trust_manifest"})
        return None, readiness
    except (OSError, ValueError, TypeError, KeyError, TimeoutError):
        readiness.update(ready=False, model={"status": "unavailable_or_unverified"})
        return None, readiness

    class VerifiedClassifier(EvidenceScan, InjectionClassifier):
        # Production's singleton/boot flag is intentionally not modified. Refuse
        # missing/NaN scores instead of grading a fallback ALLOW as model quality.
        def _predict(self, text: str) -> dict[str, float]:
            scores = manager.predict("injection-classifier", text)
            if (not isinstance(scores, dict) or set(scores) != {"SAFE", "INJECTION"}
                    or any(not math.isfinite(v) or not 0 <= v <= 1 for v in scores.values())
                    or not math.isclose(sum(scores.values()), 1, abs_tol=0.001)):
                raise ValueError("Invalid model inference")
            return scores

    scanner = VerifiedClassifier(blocking=True, block_threshold=config.block_threshold,
                                 warn_threshold=config.warn_threshold)
    try:
        await asyncio.wait_for(asyncio.to_thread(scanner._predict, "warmup test"),
                               timeout=config.timeout_seconds)
    except (ValueError, TypeError, TimeoutError):
        await scanner.shutdown()
        readiness.update(ready=False, model={"status": "inference_failed"})
        return None, readiness
    scanner._model_loaded = True
    pipeline.register(scanner)
    readiness["model"] = {
        "status": "verified_loaded_warmed", "artifact_sha256": hashes,
        "trusted_manifest_sha256": manifest_hash,
        "inference_failure_policy": "invalidate_evidence_not_allow",
        "provider": "CPUExecutionProvider", "max_tokens": 512,
        "intra_op_threads": 2, "inter_op_threads": 1,
    }
    return pipeline, readiness


async def validate_profile(
    corpus: Path, *, manifest: Path, tuning: Path | None, config: ProfileConfig,
    model_dir: Path, revision: str, hardware: str,
) -> dict:
    if not revision or not hardware or len(revision) > 128 or len(hardware) > 512:
        raise ValueError("Bounded revision and hardware descriptions required")
    rows, provenance = await asyncio.to_thread(
        validate_corpus, corpus, manifest_path=manifest, tuning_path=tuning,
    )
    pipeline, readiness = await build_profile(config, model_dir)
    result = {
        "schema_version": 1, "revision_operator_supplied": revision,
        "hardware_operator_supplied": hardware, "corpus": provenance,
        "readiness": readiness, "evidence_valid": False, "acceptance": "not_established",
        "latency_scope": "sequential_input_pipeline_not_proxy_or_backend",
        "latency_population": "all_corpus_samples_once_excluding_injection_recheck",
        "incomplete_scans": 0,
        "limitations": [
            "Operator attestation is not independent peer review",
            "No LLM execution: misses are guardrail bypasses, not attack success",
            "Offline classifier overrides inference failure handling; not deployment parity",
            "ML truncates at 512 tokens; multilingual and indirect labels do not establish protocol coverage",
            "No production readiness, SIEM delivery or latency SLO claim",
        ],
    }
    if pipeline is None:
        result["status"] = "not_ready"
        return result
    samples = [LabeledSample(
        text=row["text"], label=row["label"], source=row["source"],
        category=ThreatCategory(row["category"]) if row["category"] != "other" else None,
    ) for row in rows]
    attacks, benign = split_samples(samples)
    latencies: list[float] = []  # At most MAX_SAMPLES, bounded by corpus validation.
    record_latency = True

    class ObservedRunner(EvaluationRunner):
        async def run_single(self, attack: Attack) -> tuple[Verdict, float, list[SecurityEvent]]:
            started = perf_counter()
            verdict, latency, events = await super().run_single(attack)
            elapsed = (perf_counter() - started) * 1000
            require_complete_scan(events)
            if record_latency:
                latencies.append(elapsed)
            return verdict, latency, events

    runner = ObservedRunner(pipeline)
    try:
        async with asyncio.timeout(config.timeout_seconds):
            report = await runner.run_evaluation(attacks, benign_samples=benign)
            record_latency = False
            injection = [attack for attack in attacks if attack.category == ThreatCategory.PROMPT_INJECTION]
            injection_report = await runner.run_evaluation(injection, benign_samples=benign)
        errors = sum(item["metrics"]["total_errors"] for item in pipeline.list_scanners())
        if errors:
            result["status"] = "scanner_error"
            return result
        counts = report.confusion_block
        injection_counts = injection_report.confusion_block
        if counts is None or injection_counts is None or report.confusion_flag is None:
            raise RuntimeError("Incomplete evaluator metrics")
        recall_ci = _interval(injection_counts.tp, len(injection))
        fpr_ci = _interval(counts.fp, len(benign))
        result.update(
            status="measured", evidence_valid=True,
            confusion_block=asdict(counts), confusion_flag=asdict(report.confusion_flag),
            injection_samples=len(injection), benign_samples=len(benign),
            injection_recall_block=injection_counts.tp / len(injection) if injection else None,
            benign_fpr_block=counts.fp / len(benign) if benign else None,
            injection_recall_block_95ci=recall_ci, benign_fpr_block_95ci=fpr_ci,
            p95_ms=sorted(latencies)[math.ceil(len(latencies) * .95) - 1] if latencies else None,
            latency_samples=len(latencies),
            statistical_target_met=bool(recall_ci and fpr_ci and recall_ci[0] >= 0.8 and fpr_ci[1] <= 0.02),
            scanners_evaluated=[item["name"] for item in pipeline.list_scanners()],
        )
        # Never promote a profile automatically: source independence, target
        # workload and operator review cannot be established by this process.
        return result
    except TimeoutError:
        result["status"] = "evaluation_timeout"
        return result
    except IncompleteScanError:
        result.update(status="scan_incomplete", incomplete_scans=1)
        return result
    except RuntimeError:
        result["status"] = "scanner_error"
        return result
    finally:
        await pipeline.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--tuning", type=Path)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--model-dir", type=Path, default=Path("models"))
    parser.add_argument("--revision", required=True)
    parser.add_argument("--hardware", required=True)
    args = parser.parse_args()
    try:
        config = ProfileConfig.model_validate_json(read_bounded(args.config, 16384))
        report = asyncio.run(validate_profile(
            args.corpus, manifest=args.manifest, tuning=args.tuning, config=config,
            model_dir=args.model_dir, revision=args.revision, hardware=args.hardware,
        ))
    except (OSError, ValueError):
        report = {"status": "invalid_inputs", "evidence_valid": False}
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["evidence_valid"] else 2)


if __name__ == "__main__":
    main()
