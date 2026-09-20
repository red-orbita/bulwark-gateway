"""Offline evidence from operator-labeled holdouts; no prompts in the report."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import stat
import time
import unicodedata
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from src.guardrails.input_guardrail import InputGuardrail
from src.models import SecurityEvent, Verdict

MAX_CORPUS_BYTES = 8 * 1024 * 1024
MAX_SAMPLES = 2000
Tag = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[\w .:/@+-]+$")]
SHA256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class IncompleteScanError(RuntimeError):
    """A protective fallback is not a completed security evaluation."""


def require_complete_scan(events: list[SecurityEvent]) -> None:
    if any(event.source == "input_guardrail_budget"
           or event.metadata.get("reason") == "scan_incomplete"
           or event.metadata.get("scan_incomplete") is True for event in events):
        raise IncompleteScanError("Offline scan incomplete; evidence invalid")


class CorpusRow(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    text: str = Field(min_length=1, max_length=16384)
    label: Literal["malicious", "benign"]
    source: Tag
    language: Tag
    channel: Tag
    category: Literal["prompt_injection", "jailbreak", "other"] = "other"


class CorpusManifest(BaseModel):
    """Operator assertions, not a certification of unseen data or legal rights."""

    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal[1]
    corpus_sha256: SHA256
    classification: Literal["operator_attested_independent", "previously known baseline"]
    owner: Tag
    provenance_ref: Tag
    label_review_ref: Tag
    rights_review_ref: Tag
    collected_at: Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")]
    used_for_tuning: bool
    tuning_sha256: SHA256 | None = None


def read_bounded(path: Path, limit: int) -> bytes:
    """Reject special files/symlinks and cap reads, including racing growth."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("File is not regular or exceeds byte budget")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("File exceeds byte budget")
    return data


def _fingerprint(text: str) -> str:
    # Catches trivial case/Unicode/whitespace relabeling, not semantic paraphrases.
    normalized = " ".join(unicodedata.normalize("NFKC", text).casefold().split())
    return hashlib.sha256(normalized.encode()).hexdigest()


def load_labeled_corpus(path: Path) -> tuple[bytes, list[dict]]:
    data = read_bounded(path, MAX_CORPUS_BYTES)
    rows: list[dict] = []
    seen: set[str] = set()
    for line in data.splitlines():
        if not line.strip():
            continue
        try:
            row = CorpusRow.model_validate_json(line).model_dump()
        except ValueError:
            raise ValueError("Invalid corpus row schema") from None
        if not row["text"].strip() or len(row["text"].encode()) > 16384:
            raise ValueError("Invalid corpus text byte size")
        digest = _fingerprint(row["text"])
        if digest in seen:
            raise ValueError("Duplicate normalized sample in corpus")
        seen.add(digest)
        rows.append(row)
        if len(rows) > MAX_SAMPLES:
            raise ValueError("Corpus exceeds 2000 samples")
    if not rows:
        raise ValueError("Empty corpus")
    return data, rows


def validate_corpus(
    path: Path, *, manifest_path: Path | None = None, tuning_path: Path | None = None,
) -> tuple[list[dict], dict]:
    data, rows = load_labeled_corpus(path)
    digest = hashlib.sha256(data).hexdigest()
    fingerprints = {_fingerprint(row["text"]) for row in rows}
    tuning_hash = None
    if tuning_path is not None:
        tuning_data, tuning = load_labeled_corpus(tuning_path)
        tuning_hash = hashlib.sha256(tuning_data).hexdigest()
        if fingerprints & {_fingerprint(row["text"]) for row in tuning}:
            raise ValueError("Holdout overlaps tuning corpus")
    provenance: dict = {
        "corpus_sha256": digest, "samples": len(rows),
        "classification": "unverified_operator_corpus",
        "tuning_overlap_checked": tuning_path is not None,
        "tuning_sha256": tuning_hash, "independence_certified": False,
        "bundled_overlap_checked": False,
    }
    if manifest_path is None:
        return rows, provenance
    manifest_bytes = read_bounded(manifest_path, 16384)
    try:
        manifest = CorpusManifest.model_validate_json(manifest_bytes)
    except ValueError:
        raise ValueError("Invalid corpus manifest schema") from None
    if manifest.corpus_sha256 != digest:
        raise ValueError("Corpus SHA-256 does not match manifest")
    if manifest.tuning_sha256 != tuning_hash:
        raise ValueError("Tuning SHA-256 does not match manifest")
    if manifest.classification == "operator_attested_independent":
        if manifest.used_for_tuning or tuning_path is None:
            raise ValueError("Independent corpus requires declared tuning exclusion")
        # Do not merge known data into an operator holdout (CorpusLoader does).
        shards = sorted(Path(__file__).with_name("data").glob("*.jsonl"))
        if not shards or len(shards) > 64:
            raise ValueError("Bundled exclusion inventory unavailable or over budget")
        examples = sorted((Path(__file__).resolve().parents[2] / "config" / "examples").glob("evaluation*.jsonl"))
        if len(examples) > 64:
            raise ValueError("Known example inventory over budget")
        shards.extend(examples)
        inventory = {}
        for shard in shards:
            known = read_bounded(shard, MAX_CORPUS_BYTES)
            inventory[shard.name] = hashlib.sha256(known).hexdigest()
            for line in known.splitlines():
                if line.strip() and _fingerprint(json.loads(line)["text"]) in fingerprints:
                    raise ValueError("Independent corpus overlaps previously known baseline")
        provenance["bundled_overlap_checked"] = True
        provenance["bundled_exclusion_sha256"] = inventory
    provenance.update({
        "classification": manifest.classification,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "operator_attestation": manifest.model_dump(exclude={"corpus_sha256", "tuning_sha256"}),
    })
    return rows, provenance


def observed_environment(engine: InputGuardrail) -> dict:
    """Allowlisted facts only: no environment dump, hostname, paths or credentials."""
    config = {name: getattr(engine, name) for name in (
        "max_scan_bytes", "max_input_size", "max_concat_bytes",
        "regex_budget_seconds", "messages_budget_seconds",
    )}
    return {
        "python": platform.python_version(), "platform": platform.system(),
        "machine": platform.machine(), "kernel": platform.release(),
        "logical_cpus": os.cpu_count(),
        "affinity_cpus": len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
        "host_memory_bytes": os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"),
        "engine_config": config,
        "engine_config_sha256": hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest(),
        "pattern_set_sha256": hashlib.sha256(json.dumps([
            (pattern.regex.pattern, pattern.regex.flags, pattern.category.value, pattern.severity)
            for pattern in engine.all_patterns
        ], ensure_ascii=True).encode()).hexdigest(),
        "limits_scope": "host facts; container quotas and co-tenant contention not measured",
    }


def _interval(successes: int, total: int) -> list[float] | None:
    """Wilson 95% interval; zero samples is unknown, not perfect accuracy."""
    if not total:
        return None
    z = 1.96
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    radius = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [round(max(0, center - radius), 6), round(min(1, center + radius), 6)]


def evaluate_holdout(path: Path, *, revision: str, hardware: str, tuning_path: Path | None = None,
                     manifest_path: Path | None = None) -> dict:
    """Strict labeled JSONL, bounded locally; this cannot certify source independence."""
    if not revision or not hardware or len(revision) > 128 or len(hardware) > 512:
        raise ValueError("Revision and hardware description are required")
    rows, provenance = validate_corpus(path, manifest_path=manifest_path, tuning_path=tuning_path)
    engine = InputGuardrail(offline=True)
    latencies = []
    incomplete_scans = 0
    groups: dict[str, dict[str, int]] = {}
    for row in rows:
        started = time.perf_counter()
        result = engine.inspect(row["text"], "evaluation", "offline")
        latencies.append((time.perf_counter() - started) * 1000)
        incomplete = False
        try:
            require_complete_scan(result.events)
        except IncompleteScanError:
            incomplete = True
            incomplete_scans += 1
        for group in ("all", f"language:{row['language']}", f"channel:{row['channel']}", f"source:{row['source']}"):
            counts = groups.setdefault(group, {"malicious": 0, "benign": 0, "blocked_attack": 0,
                                               "flagged_attack": 0, "blocked_benign": 0, "flagged_benign": 0,
                                               "incomplete_malicious": 0, "incomplete_benign": 0})
            malicious = row["label"] == "malicious"
            counts["malicious" if malicious else "benign"] += 1
            if incomplete:
                counts["incomplete_malicious" if malicious else "incomplete_benign"] += 1
                continue
            counts["blocked_attack" if malicious else "blocked_benign"] += int(result.verdict == Verdict.BLOCK)
            counts["flagged_attack" if malicious else "flagged_benign"] += int(result.verdict != Verdict.ALLOW)
    metrics = {}
    for group, counts in groups.items():
        metrics[group] = {**counts,
            "recall_block_95ci": None if incomplete_scans else _interval(counts["blocked_attack"], counts["malicious"]),
            "fpr_block_95ci": None if incomplete_scans else _interval(counts["blocked_benign"], counts["benign"]),
        }
    ordered = sorted(latencies)
    return {
        "schema_version": 2, "revision_operator_supplied": revision, "hardware_operator_supplied": hardware,
        "evidence_valid": not incomplete_scans,
        "status": "scan_incomplete" if incomplete_scans else "measured",
        "incomplete_scans": incomplete_scans,
        "python": platform.python_version(), "platform": platform.system(),
        **provenance, "observed_environment": observed_environment(engine),
        "profile": "regex_inspect_only", "max_scan_bytes": engine.max_scan_bytes,
        "engine_limits": {
            "max_input_size": engine.max_input_size, "max_concat_bytes": engine.max_concat_bytes,
            "regex_budget_seconds": engine.regex_budget_seconds,
            "messages_budget_seconds": engine.messages_budget_seconds,
        },
        "dynamic_registry": "disabled_offline",
        "latency_scope": "sequential_scan_not_proxy_or_backend", "concurrency": 1,
        "p95_ms": ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)],
        "metrics": metrics,
        "limitations": ["Source independence not certified", "No model or attack-success evaluation"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--hardware", required=True)
    parser.add_argument("--tuning", type=Path)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    try:
        report = evaluate_holdout(args.corpus, revision=args.revision, hardware=args.hardware,
                                  tuning_path=args.tuning, manifest_path=args.manifest)
    except (ValueError, OSError):
        print(json.dumps({"status": "invalid_inputs", "evidence_valid": False}))
        raise SystemExit(2) from None
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["evidence_valid"] else 2)


if __name__ == "__main__":
    main()
