"""Shared evaluation harness — generate attacks, run them through a pipeline, serialize.

This is the single orchestration point used by BOTH:

  * the proxy's internal ``POST /internal/evaluation/run`` endpoint, which runs
    the evaluation against the REAL, fully-populated scanner pipeline (ML,
    multilingual, RAG — whatever the proxy has loaded); and
  * the admin's local fallback, which runs a regex-only pipeline when the proxy
    is unreachable (and the deployment is configured to degrade rather than fail).

Keeping the orchestration here guarantees both paths emit an identically shaped
report dict, so the admin API / UI contract does not depend on where the
evaluation actually ran. The only difference is the ``pipeline_source`` /
``scanners_evaluated`` provenance fields the caller stamps onto the result.
"""

from __future__ import annotations

import dataclasses

from src.evaluation.adaptive import AdaptiveRedTeam, serialize_adaptive_report
from src.evaluation.attacks import AttackGenerator
from src.evaluation.corpora import CorpusStats, load_corpus, split_samples
from src.evaluation.datasets import STANDARD_BENIGN
from src.evaluation.runner import EvaluationReport, EvaluationRunner
from src.models import ThreatCategory
from src.scanners.pipeline import ScannerPipeline

# Deterministic seed so identical parameters produce identical attack sets
# regardless of which service (proxy or admin) generates them.
_ATTACK_SEED = 42

# Default category set when the caller does not specify one. Matches the
# admin route's supported categories so behaviour is stable across the wire.
DEFAULT_CATEGORIES: tuple[ThreatCategory, ...] = (
    ThreatCategory.PROMPT_INJECTION,
    ThreatCategory.JAILBREAK,
    ThreatCategory.EXFILTRATION,
    ThreatCategory.CREDENTIAL_ACCESS,
)


def input_scanner_names(pipeline: ScannerPipeline) -> list[str]:
    """Names of the ENABLED input-blocking scanners a report actually exercised.

    ``run_input_blocking`` only runs the input-blocking lane, so only those
    scanners genuinely participate in an input-guardrail evaluation. Reporting
    output/async scanners here would overstate what was measured.
    """
    names: list[str] = []
    for s in pipeline.list_scanners():
        if s.get("type") == "input_blocking" and s.get("enabled", False):
            names.append(s["name"])
    return names


def _serialize_report(report: EvaluationReport, pipeline: ScannerPipeline) -> dict:
    """Serialize an EvaluationReport with the frontend array + scanner provenance.

    Shared by every evaluation entrypoint so the admin API / UI contract does not
    depend on whether the attacks came from the generator or an external corpus.
    """
    result = dataclasses.asdict(report)
    result["categories"] = [
        {
            "name": cat,
            "total": data["total"],
            "detected": data["detected"],
            "missed": data["missed"],
            "rate": data["detection_rate"],
            "avg_latency_ms": data.get("latency_p50", 0),
        }
        for cat, data in report.category_breakdown.items()
    ]
    result["scanners_evaluated"] = input_scanner_names(pipeline)
    return result


def _per_source_recall(report: EvaluationReport) -> list[dict]:
    """Derive per-dataset recall from the attack log (technique = corpus/<source>).

    External corpora collapse several sources onto the same ThreatCategory, so
    the category rollup alone hides which dataset the pipeline is weak on. This
    reconstructs source-level detection from ``attack_log`` entries, which for the
    bundled subset fully cover the malicious set (the log is capped at 500, so
    for very large operator-supplied corpora this is a lower-bound sample).
    """
    buckets: dict[str, dict[str, int]] = {}
    for entry in report.attack_log:
        technique = entry.technique or ""
        if not technique.startswith("corpus/"):
            continue
        source = technique.split("/", 1)[1]
        b = buckets.setdefault(source, {"total": 0, "detected": 0, "blocked": 0})
        b["total"] += 1
        if entry.detected:
            b["detected"] += 1
        if entry.verdict in ("block", "redact"):
            b["blocked"] += 1
    out: list[dict] = []
    for source, b in sorted(buckets.items()):
        total = b["total"]
        out.append({
            "source": source,
            "total": total,
            "detected": b["detected"],
            "blocked": b["blocked"],
            "recall_flag": round(b["detected"] / total, 4) if total else 0.0,
            "recall_block": round(b["blocked"] / total, 4) if total else 0.0,
        })
    return out


async def run_evaluation_report(
    pipeline: ScannerPipeline,
    categories: list[ThreatCategory] | None = None,
    count_per_category: int = 5,
    include_benign: bool = True,
) -> dict:
    """Generate attacks, run them through ``pipeline``, return a serialized report.

    Args:
        pipeline: the scanner pipeline to evaluate. The caller decides whether
            this is the real proxy singleton or a regex-only fallback.
        categories: threat categories to test; defaults to ``DEFAULT_CATEGORIES``.
        count_per_category: attacks generated per category.
        include_benign: include the standard benign dataset for false-positive
            measurement.

    Returns:
        A dict of ``EvaluationReport`` fields plus a frontend-friendly
        ``categories`` array and a ``scanners_evaluated`` provenance list. The
        caller is expected to stamp a ``pipeline_source`` label.
    """
    resolved = list(categories) if categories else list(DEFAULT_CATEGORIES)

    generator = AttackGenerator(seed=_ATTACK_SEED)
    attacks = generator.generate_attacks(
        categories=resolved,
        count_per_category=count_per_category,
    )

    runner = EvaluationRunner(pipeline=pipeline)
    benign_samples = STANDARD_BENIGN if include_benign else None
    report = await runner.run_evaluation(attacks, benign_samples=benign_samples)

    return _serialize_report(report, pipeline)


async def run_corpus_report(
    pipeline: ScannerPipeline,
    sources: list[str] | None = None,
    limit_per_source: int | None = None,
    external_dir: str | None = ...,  # type: ignore[assignment]
) -> dict:
    """Evaluate ``pipeline`` against the EXTERNAL labeled corpora (ground truth).

    Unlike ``run_evaluation_report`` (which grades attacks the gateway authored),
    this loads static, externally-sourced malicious+benign samples with
    provenance (see ``corpora.py``) and scores the pipeline against them. This is
    the defensible benchmark: the labels were not written by Bulwark.

    Args:
        pipeline: scanner pipeline to evaluate.
        sources: restrict to these corpus source names (default: all bundled).
        limit_per_source: cap samples per source (for fast smoke runs).
        external_dir: sentinel ``...`` reads ``$BULWARK_EVAL_DATASET_DIR``; pass
            ``None`` to force the bundled floor only (hermetic runs).

    Returns:
        The serialized report plus ``corpus_stats`` (provenance) and
        ``per_source`` recall. Raises ``ValueError`` if the corpus is empty so a
        caller never reports a benchmark that silently ran on nothing.
    """
    samples, stats = load_corpus(
        sources=sources,
        limit_per_source=limit_per_source,
        external_dir=external_dir,
    )
    if not samples:
        raise ValueError(
            "evaluation corpus is empty: no samples loaded from the bundled data "
            "dir or $BULWARK_EVAL_DATASET_DIR. Run scripts/fetch-eval-corpora.py."
        )

    attacks, benign = split_samples(samples)
    runner = EvaluationRunner(pipeline=pipeline)
    report = await runner.run_evaluation(attacks, benign_samples=benign or None)

    result = _serialize_report(report, pipeline)
    result["corpus_stats"] = stats.as_dict() if isinstance(stats, CorpusStats) else stats
    result["per_source"] = _per_source_recall(report)
    return result


async def run_adaptive_report(
    pipeline: ScannerPipeline,
    categories: list[ThreatCategory] | None = None,
    count_per_category: int = 5,
    generations: int = 3,
    variants_per_attack: int = 4,
) -> dict:
    """Run the adaptive red-team (replay before/after) against ``pipeline``.

    Generates a deterministic seed corpus, then measures how far an *adaptive*
    attacker — one who mutates payloads the pipeline blocked — can raise their
    attack success rate. The headline signal is ``asr_uplift`` (adapted −
    baseline): a robust pipeline keeps it near zero, a brittle exact-string
    matcher shows a large jump.

    Args:
        pipeline: the scanner pipeline to attack. The caller decides whether this
            is the real proxy singleton or a regex-only fallback.
        categories: threat categories to seed; defaults to ``DEFAULT_CATEGORIES``.
        count_per_category: seed attacks generated per category.
        generations: number of mutation rounds (bounded 1..10 by the red team).
        variants_per_attack: children spawned per blocked lineage per round.

    Returns:
        A serialized ``AdaptiveReport`` dict plus a ``scanners_evaluated``
        provenance list. The caller stamps a ``pipeline_source`` label.
    """
    resolved = list(categories) if categories else list(DEFAULT_CATEGORIES)

    generator = AttackGenerator(seed=_ATTACK_SEED)
    seeds = generator.generate_attacks(
        categories=resolved,
        count_per_category=count_per_category,
    )

    red_team = AdaptiveRedTeam(pipeline=pipeline, generator=generator)
    report = await red_team.run(
        seeds,
        generations=generations,
        variants_per_attack=variants_per_attack,
    )

    result = serialize_adaptive_report(report)
    result["scanners_evaluated"] = input_scanner_names(pipeline)
    return result
