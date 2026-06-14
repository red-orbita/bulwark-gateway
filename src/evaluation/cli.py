"""
Evaluation CLI — Command-line interface for running guardrail evaluations.

Usage:
    sentinel evaluate --attacks standard --min-detection-rate 0.95
    sentinel evaluate --attacks exhaustive --report json --output report.json
    sentinel evaluate --compare baseline.json current.json
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
        prog="sentinel evaluate",
        description="Sentinel Gateway — Guardrail Evaluation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  sentinel evaluate --attacks standard --min-detection-rate 0.95
  sentinel evaluate --attacks exhaustive --report json --output report.json
  sentinel evaluate --compare baseline.json current.json
  sentinel evaluate --categories prompt_injection jailbreak --count 50
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

    print(
        f"  {'Latency P95 (ms)':<22} {b_lat:<12.2f} {c_lat:<12.2f} "
        f"{lat_delta:+<12.2f} [{'=' if lat_status == 'same' else ('+' if lat_status == 'improved' else '!')}] {lat_status}"
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
    elif args.command == "compare":
        exit_code = _compare_reports(args)
    else:
        parser.print_help()
        exit_code = 0

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
