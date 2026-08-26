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

from src.evaluation.attacks import AttackGenerator
from src.evaluation.datasets import STANDARD_BENIGN
from src.evaluation.runner import EvaluationRunner
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
