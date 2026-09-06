"""
Evaluation CLI — Command-line interface for running guardrail evaluations.

Usage:
    bulwark evaluate --attacks standard --min-detection-rate 0.95
    bulwark evaluate --attacks exhaustive --report json --output report.json
    bulwark evaluate --compare baseline.json current.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from src.evaluation.attacks import AttackGenerator
from src.evaluation.datasets import (
    BenignDataset,
    get_exhaustive_attacks,
    get_standard_attacks,
)
from src.evaluation.runner import EvaluationRunner


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the evaluation CLI."""
    parser = argparse.ArgumentParser(
        prog="bulwark evaluate",
        description="Bulwark Gateway — Guardrail Evaluation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  bulwark evaluate run --attacks standard --min-detection-rate 0.95
  bulwark evaluate run --attacks exhaustive --report json --output report.json
  bulwark evaluate corpus --report json --output corpus-benchmark.json
  bulwark evaluate corpus --bundled-only --min-recall 0.90 --max-fpr 0.05
  bulwark evaluate compare baseline.json current.json
""",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # === Run command (default) ===
    run_parser = subparsers.add_parser(
        "run",
        help="Run evaluation against the scanner pipeline",
    )
    run_parser.add_argument(
        "--attacks",
        choices=["standard", "exhaustive", "custom"],
        default="standard",
        help="Attack dataset to use (default: standard)",
    )
    run_parser.add_argument(
        "--categories",
        nargs="+",
        choices=[
            "prompt_injection",
            "jailbreak",
            "exfiltration",
            "credential_access",
        ],
        help="Specific categories to test (default: all)",
    )
    run_parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Total number of attacks to generate (default: 100)",
    )
    run_parser.add_argument(
        "--benign",
        action="store_true",
        default=True,
        help="Include benign samples for FP testing (default: true)",
    )
    run_parser.add_argument(
        "--no-benign",
        action="store_true",
        help="Skip benign sample testing",
    )
    run_parser.add_argument(
        "--min-detection-rate",
        type=float,
        default=0.0,
        metavar="RATE",
        help="Minimum acceptable detection rate (0.0-1.0). Exit 1 if below.",
    )
    run_parser.add_argument(
        "--max-fp-rate",
        type=float,
        default=1.0,
        metavar="RATE",
        help="Maximum acceptable false positive rate (0.0-1.0). Exit 1 if above.",
    )
    run_parser.add_argument(
        "--report",
        choices=["text", "json", "html"],
        default="text",
        help="Output format (default: text)",
    )
    run_parser.add_argument(
        "--output",
        type=str,
        default=None,
        metavar="FILE",
        help="Write report to file instead of stdout",
    )
    run_parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )

    # === Corpus command (external labeled ground truth) ===
    corpus_parser = subparsers.add_parser(
        "corpus",
        help="Benchmark the pipeline against EXTERNAL labeled corpora (F1/FPR/latency)",
        description=(
            "Score the scanner pipeline against static, externally-sourced "
            "labeled samples (malicious AND benign) with provenance. Unlike "
            "'run' — which grades attacks the gateway authored — this is the "
            "defensible, shareable benchmark: the ground-truth labels were not "
            "written by Bulwark. Emits precision/recall/F1/FPR under both the "
            "'block' and 'flag' decision policies, per-source recall, and "
            "latency percentiles."
        ),
    )
    corpus_parser.add_argument(
        "--sources",
        nargs="+",
        default=None,
        metavar="SOURCE",
        help="Restrict to these corpus source names (default: all bundled shards)",
    )
    corpus_parser.add_argument(
        "--limit-per-source",
        type=int,
        default=None,
        metavar="N",
        help="Cap samples kept per source (for fast smoke runs)",
    )
    corpus_parser.add_argument(
        "--bundled-only",
        action="store_true",
        help=(
            "Ignore $BULWARK_EVAL_DATASET_DIR and evaluate only the reproducible "
            "bundled floor (hermetic, deterministic runs)"
        ),
    )
    corpus_parser.add_argument(
        "--policy",
        choices=["block", "flag"],
        default="block",
        help=(
            "Decision policy the pass/fail gates are measured against: 'block' "
            "(BLOCK/REDACT only — enforced) or 'flag' (also WARN — surfaced). "
            "Default: block"
        ),
    )
    corpus_parser.add_argument(
        "--min-recall",
        type=float,
        default=0.0,
        metavar="RATE",
        help="Minimum acceptable recall (0.0-1.0) under --policy. Exit 1 if below.",
    )
    corpus_parser.add_argument(
        "--max-fpr",
        type=float,
        default=1.0,
        metavar="RATE",
        help="Maximum acceptable false-positive rate (0.0-1.0) under --policy. Exit 1 if above.",
    )
    corpus_parser.add_argument(
        "--min-f1",
        type=float,
        default=0.0,
        metavar="SCORE",
        help="Minimum acceptable F1 score (0.0-1.0) under --policy. Exit 1 if below.",
    )
    corpus_parser.add_argument(
        "--report",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    corpus_parser.add_argument(
        "--output",
        type=str,
        default=None,
        metavar="FILE",
        help="Write report to file instead of stdout (the shareable artifact)",
    )

    # === Compare command ===
    compare_parser = subparsers.add_parser(
        "compare",
        help="Compare two evaluation reports",
    )
    compare_parser.add_argument(
        "baseline",
        type=str,
        help="Path to baseline report (JSON)",
    )
    compare_parser.add_argument(
        "current",
        type=str,
        help="Path to current report (JSON)",
    )
    compare_parser.add_argument(
        "--report",
        choices=["text", "json"],
        default="text",
        help="Comparison output format (default: text)",
    )

    return parser


async def _run_evaluation(args: argparse.Namespace) -> int:
    """Execute the evaluation run command.

    Returns exit code: 0 for pass, 1 for threshold violation.
    """
    from src.models import ThreatCategory

    # Determine attack set
    if args.attacks == "standard":
        attacks = get_standard_attacks(count=args.count)
    elif args.attacks == "exhaustive":
        attacks = get_exhaustive_attacks(count=args.count)
    else:
        # Custom: use categories and count
        categories = None
        if args.categories:
            cat_map = {
                "prompt_injection": ThreatCategory.PROMPT_INJECTION,
                "jailbreak": ThreatCategory.JAILBREAK,
                "exfiltration": ThreatCategory.EXFILTRATION,
                "credential_access": ThreatCategory.CREDENTIAL_ACCESS,
            }
            categories = [cat_map[c] for c in args.categories]

        generator = AttackGenerator(seed=args.seed)
        count_per_cat = max(1, args.count // (len(categories) if categories else 4))
        attacks = generator.generate_attacks(
            categories=categories,
            count_per_category=count_per_cat,
        )

    # Benign samples
    benign_samples: list[str] | None = None
    if not args.no_benign:
        benign_samples = BenignDataset.load()

    # Populate the scanner pipeline. Standalone entrypoints (this CLI, CI) do
    # NOT run the app lifespan, so the global pipeline singleton would otherwise
    # be empty and report 0% detection. Register the always-on GA built-ins via
    # the shared SSOT helper (no tenant policy engine in eval context — the
    # tool-policy scanner degrades to ALLOW), then start them.
    from src.scanners.builtin import register_builtin_scanners
    from src.scanners.pipeline import get_scanner_pipeline

    pipeline = get_scanner_pipeline()
    if not pipeline.list_scanners():
        register_builtin_scanners(pipeline)
        await pipeline.startup()

    # Run evaluation
    runner = EvaluationRunner()
    report = await runner.run_evaluation(attacks, benign_samples=benign_samples)

    # Generate and output report
    output_text = runner.generate_report(report, format=args.report)

    if args.output:
        output_path = Path(args.output)
        output_path.write_text(output_text, encoding="utf-8")
        print(f"Report written to: {args.output}")
    else:
        print(output_text)

    # Check thresholds
    exit_code = 0

    if args.min_detection_rate > 0.0:
        if report.detection_rate < args.min_detection_rate:
            print(
                f"\nFAILED: Detection rate {report.detection_rate:.1%} "
                f"< minimum {args.min_detection_rate:.1%}",
                file=sys.stderr,
            )
            exit_code = 1

    if args.max_fp_rate < 1.0:
        if report.false_positive_rate > args.max_fp_rate:
            print(
                f"\nFAILED: False positive rate {report.false_positive_rate:.1%} "
                f"> maximum {args.max_fp_rate:.1%}",
                file=sys.stderr,
            )
            exit_code = 1

    return exit_code


def _format_corpus_text(result: dict) -> str:
    """Render a corpus benchmark result dict as a shareable text report.

    ``run_corpus_report`` returns a serialized ``EvaluationReport`` dict merged
    with ``corpus_stats`` (provenance) and ``per_source`` (per-dataset recall),
    so this formatter reads plain dict keys rather than an object.
    """
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("  SENTINEL GATEWAY — External Corpus Benchmark")
    lines.append("=" * 72)
    lines.append(f"  Timestamp: {result.get('timestamp', 'unknown')}")

    scanners = result.get("scanners_evaluated") or []
    lines.append(f"  Scanners:  {', '.join(scanners) if scanners else '(none)'}")
    lines.append("")

    # --- Corpus provenance (ground truth) ---
    stats = result.get("corpus_stats") or {}
    lines.append("  CORPUS (independent ground truth)")
    lines.append("  " + "-" * 40)
    lines.append(f"  Total samples:   {stats.get('total', 0)}")
    lines.append(f"  Malicious:       {stats.get('malicious', 0)}")
    lines.append(f"  Benign:          {stats.get('benign', 0)}")
    lines.append(f"  Skipped (bad):   {stats.get('skipped_lines', 0)}")
    shards = stats.get("shards") or []
    lines.append(f"  Shards:          {', '.join(shards) if shards else '(none)'}")
    by_source = stats.get("by_source") or {}
    if by_source:
        lines.append("  By source:")
        for src, n in sorted(by_source.items()):
            lines.append(f"    {src:<28} {n}")
    lines.append("")

    # --- Detection quality under both decision policies ---
    lines.append("  DETECTION QUALITY")
    lines.append("  " + "-" * 40)
    header = f"  {'Policy':<10} {'Prec':<8} {'Recall':<8} {'F1':<8} {'FPR':<8}"
    lines.append(header)
    for key in ("confusion_block", "confusion_flag"):
        cm = result.get(key)
        if not cm:
            continue
        lines.append(
            f"  {cm['policy']:<10} {cm['precision']:<8.3f} {cm['recall']:<8.3f} "
            f"{cm['f1']:<8.3f} {cm['fpr']:<8.3f}"
        )
        lines.append(
            f"    └─ TP={cm['tp']} FP={cm['fp']} TN={cm['tn']} FN={cm['fn']}"
        )
    lines.append("")
    lines.append(
        f"  Attack Success Rate: {result.get('attack_success_rate', 0.0):.1%}"
        "  (malicious reaching backend — not blocked)"
    )
    lines.append("")

    # --- Latency ---
    lines.append("  LATENCY (ms)")
    lines.append("  " + "-" * 40)
    lines.append(f"  P50:  {result.get('latency_p50', 0.0):.2f} ms")
    lines.append(f"  P95:  {result.get('latency_p95', 0.0):.2f} ms")
    lines.append(f"  P99:  {result.get('latency_p99', 0.0):.2f} ms")
    lines.append("")

    # --- Per-source recall ---
    per_source = result.get("per_source") or []
    if per_source:
        lines.append("  PER-SOURCE RECALL")
        lines.append("  " + "-" * 40)
        lines.append(
            f"  {'Source':<24} {'Total':<8} {'Block':<8} {'Flag':<8}"
        )
        lines.append("  " + "-" * 48)
        for row in per_source:
            lines.append(
                f"  {row['source']:<24} {row['total']:<8} "
                f"{row['recall_block']:<8.3f} {row['recall_flag']:<8.3f}"
            )
        lines.append("")

    lines.append("=" * 72)
    return "\n".join(lines)


def _corpus_gate(result: dict, policy: str, key: str, default: float) -> float:
    """Pull a metric (recall/f1/fpr) for the selected policy from a result dict."""
    cm = result.get(f"confusion_{policy}") or {}
    val = cm.get(key, default)
    return float(val) if val is not None else default


async def _run_corpus(args: argparse.Namespace) -> int:
    """Execute the external-corpus benchmark command.

    Returns exit code: 0 for pass, 1 for threshold violation or empty corpus.
    """
    from src.evaluation.harness import run_corpus_report
    from src.scanners.builtin import register_builtin_scanners
    from src.scanners.pipeline import get_scanner_pipeline

    # Populate the pipeline exactly as the 'run' command does — standalone
    # entrypoints do not run the app lifespan, so the singleton is otherwise empty.
    pipeline = get_scanner_pipeline()
    if not pipeline.list_scanners():
        register_builtin_scanners(pipeline)
        await pipeline.startup()

    # `--bundled-only` forces the hermetic floor; otherwise the sentinel default
    # lets the loader read $BULWARK_EVAL_DATASET_DIR.
    external_dir: str | None = None if args.bundled_only else ...  # type: ignore[assignment]

    try:
        result = await run_corpus_report(
            pipeline,
            sources=args.sources,
            limit_per_source=args.limit_per_source,
            external_dir=external_dir,
        )
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    result["pipeline_source"] = "cli-builtin-pipeline"

    if args.report == "json":
        output_text = json.dumps(result, indent=2)
    else:
        output_text = _format_corpus_text(result)

    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"Report written to: {args.output}")
    else:
        print(output_text)

    # --- Threshold gates (against the selected decision policy) ---
    exit_code = 0
    policy = args.policy

    if args.min_recall > 0.0:
        recall = _corpus_gate(result, policy, "recall", 0.0)
        if recall < args.min_recall:
            print(
                f"\nFAILED: {policy} recall {recall:.1%} "
                f"< minimum {args.min_recall:.1%}",
                file=sys.stderr,
            )
            exit_code = 1

    if args.min_f1 > 0.0:
        f1 = _corpus_gate(result, policy, "f1", 0.0)
        if f1 < args.min_f1:
            print(
                f"\nFAILED: {policy} F1 {f1:.3f} < minimum {args.min_f1:.3f}",
                file=sys.stderr,
            )
            exit_code = 1

    if args.max_fpr < 1.0:
        fpr = _corpus_gate(result, policy, "fpr", 0.0)
        if fpr > args.max_fpr:
            print(
                f"\nFAILED: {policy} false-positive rate {fpr:.1%} "
                f"> maximum {args.max_fpr:.1%}",
                file=sys.stderr,
            )
            exit_code = 1

    return exit_code


def _compare_reports(args: argparse.Namespace) -> int:
    """Compare two evaluation reports and show delta.

    Returns exit code: 0 for improvement/same, 1 for regression.
    """
    baseline_path = Path(args.baseline)
    current_path = Path(args.current)

    if not baseline_path.exists():
        print(f"Error: baseline file not found: {args.baseline}", file=sys.stderr)
        return 1
    if not current_path.exists():
        print(f"Error: current file not found: {args.current}", file=sys.stderr)
        return 1

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    current = json.loads(current_path.read_text(encoding="utf-8"))

    if args.report == "json":
        comparison = _build_comparison_json(baseline, current)
        print(json.dumps(comparison, indent=2))
    else:
        _print_comparison_text(baseline, current)

    # Regression check: current detection rate should be >= baseline
    baseline_rate = baseline.get("detection_rate", 0)
    current_rate = current.get("detection_rate", 0)

    if current_rate < baseline_rate - 0.01:  # Allow 1% tolerance
        print(
            f"\nREGRESSION: Detection rate dropped from "
            f"{baseline_rate:.1%} to {current_rate:.1%}",
            file=sys.stderr,
        )
        return 1

    return 0


def _build_comparison_json(
    baseline: dict, current: dict
) -> dict:
    """Build structured comparison between two reports."""
    return {
        "baseline_timestamp": baseline.get("timestamp", "unknown"),
        "current_timestamp": current.get("timestamp", "unknown"),
        "detection_rate": {
            "baseline": baseline.get("detection_rate", 0),
            "current": current.get("detection_rate", 0),
            "delta": current.get("detection_rate", 0) - baseline.get("detection_rate", 0),
        },
        "false_positive_rate": {
            "baseline": baseline.get("false_positive_rate", 0),
            "current": current.get("false_positive_rate", 0),
            "delta": current.get("false_positive_rate", 0) - baseline.get("false_positive_rate", 0),
        },
        "bypass_rate": {
            "baseline": baseline.get("bypass_rate", 0),
            "current": current.get("bypass_rate", 0),
            "delta": current.get("bypass_rate", 0) - baseline.get("bypass_rate", 0),
        },
        "latency_p95": {
            "baseline": baseline.get("latency", {}).get("p95_ms", 0),
            "current": current.get("latency", {}).get("p95_ms", 0),
            "delta": (
                current.get("latency", {}).get("p95_ms", 0)
                - baseline.get("latency", {}).get("p95_ms", 0)
            ),
        },
    }


def _print_comparison_text(baseline: dict, current: dict) -> None:
    """Print text comparison table."""
    print("=" * 70)
    print("  SENTINEL GATEWAY — Evaluation Comparison")
    print("=" * 70)
    print(f"  Baseline: {baseline.get('timestamp', 'unknown')}")
    print(f"  Current:  {current.get('timestamp', 'unknown')}")
    print()

    metrics = [
        ("Detection Rate", "detection_rate", True),      # Higher is better
        ("False Positive Rate", "false_positive_rate", False),  # Lower is better
        ("Bypass Rate", "bypass_rate", False),            # Lower is better
    ]

    print(f"  {'Metric':<22} {'Baseline':<12} {'Current':<12} {'Delta':<12} {'Status'}")
    print("  " + "-" * 66)

    for label, key, higher_is_better in metrics:
        b_val = baseline.get(key, 0)
        c_val = current.get(key, 0)
        delta = c_val - b_val

        if higher_is_better:
            status = "improved" if delta > 0.01 else ("regressed" if delta < -0.01 else "same")
        else:
            status = "improved" if delta < -0.01 else ("regressed" if delta > 0.01 else "same")

        delta_str = f"{delta:+.1%}"
        status_marker = {"improved": "+", "regressed": "!", "same": "="}[status]

        print(
            f"  {label:<22} {b_val:<12.1%} {c_val:<12.1%} {delta_str:<12} [{status_marker}] {status}"
        )

    # Latency comparison
    b_lat = baseline.get("latency", {}).get("p95_ms", 0)
    c_lat = current.get("latency", {}).get("p95_ms", 0)
    lat_delta = c_lat - b_lat
    lat_status = "improved" if lat_delta < -1.0 else ("regressed" if lat_delta > 1.0 else "same")
    lat_symbol = "=" if lat_status == "same" else ("+" if lat_status == "improved" else "!")

    print(
        f"  {'Latency P95 (ms)':<22} {b_lat:<12.2f} {c_lat:<12.2f} "
        f"{lat_delta:+<12.2f} [{lat_symbol}] {lat_status}"
    )

    print()
    print("=" * 70)


def main() -> None:
    """CLI entry point for evaluation framework."""
    parser = _build_parser()
    args = parser.parse_args()

    # Default to 'run' if no subcommand given
    if args.command is None:
        args.command = "run"
        # Re-parse with 'run' defaults
        args = parser.parse_args(["run"] + sys.argv[1:])

    if args.command == "run":
        exit_code = asyncio.run(_run_evaluation(args))
    elif args.command == "corpus":
        exit_code = asyncio.run(_run_corpus(args))
    elif args.command == "compare":
        exit_code = _compare_reports(args)
    else:
        parser.print_help()
        exit_code = 0

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
