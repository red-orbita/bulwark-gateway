"""
Evaluation Runner — Executes attacks against the scanner pipeline and measures efficacy.

Produces detailed reports with detection rates, false positive rates,
latency percentiles, and per-category breakdowns.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.models import ThreatCategory, Verdict
from src.scanners.pipeline import ScannerPipeline
from src.scanners.protocol import ScanContext

from .attacks import Attack

logger = logging.getLogger(__name__)


@dataclass
class MissedAttack:
    """Details of an attack that bypassed detection."""

    payload: str
    category: str
    technique: str
    difficulty: str
    actual_verdict: str


@dataclass
class AttackLogEntry:
    """Detailed log entry for a single attack evaluation.

    Provides full transparency: what was tested, what happened, and why.
    """

    payload: str
    category: str
    technique: str
    difficulty: str
    verdict: str                    # actual verdict (allow/block/warn)
    detected: bool                  # True if blocked/warned
    latency_ms: float               # Processing time
    matched_pattern: str | None     # First matched pattern (what triggered detection)
    guardrail_description: str | None  # Human-readable description of what caught it
    severity: str | None            # Severity of matched rule
    source: str | None              # Which scanner/guardrail (e.g. "input_guardrail")


@dataclass
class EvaluationReport:
    """Complete evaluation results with metrics."""

    total_attacks: int
    detected: int
    missed: int
    false_positives: int
    detection_rate: float
    false_positive_rate: float
    bypass_rate: float
    latency_p50: float
    latency_p95: float
    latency_p99: float
    category_breakdown: dict[str, dict[str, Any]] = field(default_factory=dict)
    missed_attacks: list[MissedAttack] = field(default_factory=list)
    attack_log: list[AttackLogEntry] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class _SingleResult:
    """Internal result from running a single attack."""

    attack: Attack
    actual_verdict: Verdict
    latency_ms: float
    detected: bool
    matched_pattern: str | None = None
    guardrail_description: str | None = None
    severity: str | None = None
    source: str | None = None


class EvaluationRunner:
    """Runs attack payloads through the scanner pipeline and collects metrics.

    Usage:
        from src.scanners.pipeline import get_scanner_pipeline
        from src.evaluation import AttackGenerator, EvaluationRunner

        generator = AttackGenerator(seed=42)
        attacks = generator.generate_attacks(count_per_category=20)

        runner = EvaluationRunner(pipeline=get_scanner_pipeline())
        report = await runner.run_evaluation(attacks)
        print(runner.generate_report(report))
    """

    def __init__(self, pipeline: ScannerPipeline | None = None) -> None:
        """Initialize runner with a scanner pipeline.

        Args:
            pipeline: ScannerPipeline instance to evaluate. If None,
                      imports the global singleton at runtime.
        """
        self._pipeline = pipeline

    @property
    def pipeline(self) -> ScannerPipeline:
        """Lazy-load pipeline if not provided."""
        if self._pipeline is None:
            from src.scanners.pipeline import get_scanner_pipeline
            self._pipeline = get_scanner_pipeline()
        return self._pipeline

    async def run_evaluation(
        self,
        attacks: list[Attack],
        benign_samples: list[str] | None = None,
    ) -> EvaluationReport:
        """Run full evaluation: attacks + optional benign samples.

        Args:
            attacks: List of Attack instances to test detection against.
            benign_samples: Optional list of benign prompts to test for false positives.

        Returns:
            EvaluationReport with detection metrics and latency percentiles.
        """
        logger.info(
            "evaluation_started",
            extra={
                "attack_count": len(attacks),
                "benign_count": len(benign_samples) if benign_samples else 0,
            },
        )

        # Run all attacks
        results: list[_SingleResult] = []
        for attack in attacks:
            verdict, latency, events = await self.run_single(attack)
            detected = verdict in (Verdict.BLOCK, Verdict.WARN)

            # Extract the primary detection info from events
            matched_pattern = None
            guardrail_desc = None
            severity = None
            source = None
            if events:
                # Use the highest-severity event as the primary match
                primary = max(events, key=lambda e: {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(e.severity, 0))
                matched_pattern = primary.matched_pattern
                guardrail_desc = primary.description
                severity = primary.severity
                source = primary.source

            results.append(_SingleResult(
                attack=attack,
                actual_verdict=verdict,
                latency_ms=latency,
                detected=detected,
                matched_pattern=matched_pattern,
                guardrail_description=guardrail_desc,
                severity=severity,
                source=source,
            ))

        # Run benign samples to measure false positives
        false_positives = 0
        benign_latencies: list[float] = []

        if benign_samples:
            for sample in benign_samples:
                benign_attack = Attack(
                    payload=sample,
                    category=attacks[0].category if attacks else ThreatCategory.PROMPT_INJECTION,
                    technique="benign",
                    expected_verdict=Verdict.ALLOW,
                    difficulty="easy",
                )
                verdict, latency, _ = await self.run_single(benign_attack)
                benign_latencies.append(latency)
                if verdict in (Verdict.BLOCK, Verdict.WARN):
                    false_positives += 1

        return self._compute_metrics(results, false_positives, len(benign_samples or []))

    async def run_single(self, attack: Attack) -> tuple[Verdict, float, list]:
        """Run a single attack through the pipeline.

        Args:
            attack: Attack instance to evaluate.

        Returns:
            Tuple of (actual verdict, latency in milliseconds, security events).
        """
        context = ScanContext(
            tenant_id="eval-tenant",
            agent_id="eval-agent",
            request_id=f"eval-{uuid.uuid4().hex[:12]}",
            messages=[{"role": "user", "content": attack.payload}],
            metadata={"evaluation": True, "category": attack.category.value if hasattr(attack.category, 'value') else str(attack.category)},
        )

        start = time.perf_counter()
        result = await self.pipeline.run_input_blocking(attack.payload, context)
        elapsed_ms = (time.perf_counter() - start) * 1000

        return result.verdict, elapsed_ms, result.events

    def _compute_metrics(
        self,
        results: list[_SingleResult],
        false_positives: int,
        benign_count: int,
    ) -> EvaluationReport:
        """Compute evaluation metrics from raw results.

        Args:
            results: List of individual attack results.
            false_positives: Number of benign samples incorrectly flagged.
            benign_count: Total number of benign samples tested.

        Returns:
            Complete EvaluationReport.
        """
        total = len(results)
        if total == 0:
            return EvaluationReport(
                total_attacks=0,
                detected=0,
                missed=0,
                false_positives=false_positives,
                detection_rate=0.0,
                false_positive_rate=0.0,
                bypass_rate=0.0,
                latency_p50=0.0,
                latency_p95=0.0,
                latency_p99=0.0,
            )

        detected = sum(1 for r in results if r.detected)
        missed = total - detected

        # Latency percentiles
        latencies = sorted(r.latency_ms for r in results)
        p50 = self._percentile(latencies, 50)
        p95 = self._percentile(latencies, 95)
        p99 = self._percentile(latencies, 99)

        # Per-category breakdown
        category_breakdown: dict[str, dict[str, Any]] = {}
        categories_seen: dict[str, list[_SingleResult]] = {}

        for r in results:
            cat = r.attack.category.value
            if cat not in categories_seen:
                categories_seen[cat] = []
            categories_seen[cat].append(r)

        for cat, cat_results in categories_seen.items():
            cat_total = len(cat_results)
            cat_detected = sum(1 for r in cat_results if r.detected)
            cat_latencies = sorted(r.latency_ms for r in cat_results)

            # Per-difficulty breakdown
            difficulty_breakdown: dict[str, dict[str, Any]] = {}
            for difficulty in ("easy", "medium", "hard"):
                diff_results = [r for r in cat_results if r.attack.difficulty == difficulty]
                if diff_results:
                    diff_detected = sum(1 for r in diff_results if r.detected)
                    difficulty_breakdown[difficulty] = {
                        "total": len(diff_results),
                        "detected": diff_detected,
                        "rate": diff_detected / len(diff_results),
                    }

            category_breakdown[cat] = {
                "total": cat_total,
                "detected": cat_detected,
                "missed": cat_total - cat_detected,
                "detection_rate": cat_detected / cat_total if cat_total > 0 else 0.0,
                "latency_p50": self._percentile(cat_latencies, 50),
                "latency_p95": self._percentile(cat_latencies, 95),
                "by_difficulty": difficulty_breakdown,
            }

        detection_rate = detected / total if total > 0 else 0.0
        fp_rate = false_positives / benign_count if benign_count > 0 else 0.0
        bypass_rate = missed / total if total > 0 else 0.0

        # Collect missed attacks (cap at 50 to avoid huge responses)
        missed_details: list[MissedAttack] = []
        for r in results:
            if not r.detected and len(missed_details) < 50:
                missed_details.append(MissedAttack(
                    payload=r.attack.payload[:500],  # Truncate long payloads
                    category=r.attack.category.value,
                    technique=r.attack.technique,
                    difficulty=r.attack.difficulty,
                    actual_verdict=r.actual_verdict.value,
                ))

        # Build full attack log (every attack, capped at 500 entries)
        attack_log: list[AttackLogEntry] = []
        for r in results[:500]:
            attack_log.append(AttackLogEntry(
                payload=r.attack.payload[:300],
                category=r.attack.category.value,
                technique=r.attack.technique,
                difficulty=r.attack.difficulty,
                verdict=r.actual_verdict.value,
                detected=r.detected,
                latency_ms=round(r.latency_ms, 2),
                matched_pattern=r.matched_pattern[:200] if r.matched_pattern else None,
                guardrail_description=r.guardrail_description,
                severity=r.severity,
                source=r.source,
            ))

        return EvaluationReport(
            total_attacks=total,
            detected=detected,
            missed=missed,
            false_positives=false_positives,
            detection_rate=detection_rate,
            false_positive_rate=fp_rate,
            bypass_rate=bypass_rate,
            latency_p50=p50,
            latency_p95=p95,
            latency_p99=p99,
            category_breakdown=category_breakdown,
            missed_attacks=missed_details,
            attack_log=attack_log,
        )

    def generate_report(
        self, report: EvaluationReport, format: str = "text"
    ) -> str:
        """Format an evaluation report for display.

        Args:
            report: EvaluationReport to format.
            format: Output format — "text", "json", or "html".

        Returns:
            Formatted report string.
        """
        if format == "json":
            return self._report_json(report)
        elif format == "html":
            return self._report_html(report)
        return self._report_text(report)

    def _report_text(self, report: EvaluationReport) -> str:
        """Generate text table report."""
        lines: list[str] = []
        lines.append("=" * 70)
        lines.append("  SENTINEL GATEWAY — Guardrail Evaluation Report")
        lines.append("=" * 70)
        lines.append(f"  Timestamp: {report.timestamp}")
        lines.append("")
        lines.append("  SUMMARY")
        lines.append("  " + "-" * 40)
        lines.append(f"  Total Attacks:      {report.total_attacks}")
        lines.append(f"  Detected:           {report.detected}")
        lines.append(f"  Missed (Bypassed):  {report.missed}")
        lines.append(f"  False Positives:    {report.false_positives}")
        lines.append("")
        lines.append(f"  Detection Rate:     {report.detection_rate:.1%}")
        lines.append(f"  False Positive Rate:{report.false_positive_rate:.1%}")
        lines.append(f"  Bypass Rate:        {report.bypass_rate:.1%}")
        lines.append("")
        lines.append("  LATENCY (ms)")
        lines.append("  " + "-" * 40)
        lines.append(f"  P50:  {report.latency_p50:.2f} ms")
        lines.append(f"  P95:  {report.latency_p95:.2f} ms")
        lines.append(f"  P99:  {report.latency_p99:.2f} ms")
        lines.append("")

        if report.category_breakdown:
            lines.append("  PER-CATEGORY BREAKDOWN")
            lines.append("  " + "-" * 40)
            header = f"  {'Category':<25} {'Detected':<10} {'Total':<8} {'Rate':<8}"
            lines.append(header)
            lines.append("  " + "-" * 55)

            for cat, data in sorted(report.category_breakdown.items()):
                rate = f"{data['detection_rate']:.0%}"
                lines.append(
                    f"  {cat:<25} {data['detected']:<10} {data['total']:<8} {rate:<8}"
                )

                # Difficulty sub-breakdown
                for diff, diff_data in data.get("by_difficulty", {}).items():
                    diff_rate = f"{diff_data['rate']:.0%}"
                    lines.append(
                        f"    {diff:<23} {diff_data['detected']:<10} "
                        f"{diff_data['total']:<8} {diff_rate:<8}"
                    )

        lines.append("")
        lines.append("=" * 70)

        # Pass/fail indicator
        if report.detection_rate >= 0.95:
            lines.append("  RESULT: PASS (detection rate >= 95%)")
        elif report.detection_rate >= 0.90:
            lines.append("  RESULT: WARN (detection rate >= 90% but < 95%)")
        else:
            lines.append("  RESULT: FAIL (detection rate < 90%)")

        lines.append("=" * 70)
        return "\n".join(lines)

    def _report_json(self, report: EvaluationReport) -> str:
        """Generate JSON report."""
        data = {
            "total_attacks": report.total_attacks,
            "detected": report.detected,
            "missed": report.missed,
            "false_positives": report.false_positives,
            "detection_rate": round(report.detection_rate, 4),
            "false_positive_rate": round(report.false_positive_rate, 4),
            "bypass_rate": round(report.bypass_rate, 4),
            "latency": {
                "p50_ms": round(report.latency_p50, 2),
                "p95_ms": round(report.latency_p95, 2),
                "p99_ms": round(report.latency_p99, 2),
            },
            "category_breakdown": report.category_breakdown,
            "timestamp": report.timestamp,
        }
        return json.dumps(data, indent=2)

    def _report_html(self, report: EvaluationReport) -> str:
        """Generate HTML report."""
        status_class = "pass" if report.detection_rate >= 0.95 else (
            "warn" if report.detection_rate >= 0.90 else "fail"
        )

        rows = ""
        for cat, data in sorted(report.category_breakdown.items()):
            rows += (
                f"<tr>"
                f"<td>{cat}</td>"
                f"<td>{data['detected']}</td>"
                f"<td>{data['total']}</td>"
                f"<td>{data['detection_rate']:.1%}</td>"
                f"</tr>\n"
            )

        return f"""<!DOCTYPE html>
<html>
<head>
  <title>Sentinel Gateway — Evaluation Report</title>
  <style>
    body {{ font-family: monospace; margin: 2em; background: #1a1a2e; color: #e0e0e0; }}
    h1 {{ color: #00d4aa; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
    th, td {{ border: 1px solid #333; padding: 8px; text-align: left; }}
    th {{ background: #16213e; }}
    .pass {{ color: #00d4aa; }}
    .warn {{ color: #f4a261; }}
    .fail {{ color: #e63946; }}
    .metric {{ font-size: 1.5em; font-weight: bold; }}
  </style>
</head>
<body>
  <h1>Sentinel Gateway — Evaluation Report</h1>
  <p>Timestamp: {report.timestamp}</p>

  <h2>Summary</h2>
  <table>
    <tr><th>Metric</th><th>Value</th></tr>
    <tr><td>Total Attacks</td><td>{report.total_attacks}</td></tr>
    <tr><td>Detected</td><td>{report.detected}</td></tr>
    <tr><td>Missed</td><td>{report.missed}</td></tr>
    <tr><td>False Positives</td><td>{report.false_positives}</td></tr>
    <tr><td>Detection Rate</td><td class="{status_class} metric">{report.detection_rate:.1%}</td></tr>
    <tr><td>Bypass Rate</td><td>{report.bypass_rate:.1%}</td></tr>
    <tr><td>FP Rate</td><td>{report.false_positive_rate:.1%}</td></tr>
  </table>

  <h2>Latency</h2>
  <table>
    <tr><th>Percentile</th><th>Latency (ms)</th></tr>
    <tr><td>P50</td><td>{report.latency_p50:.2f}</td></tr>
    <tr><td>P95</td><td>{report.latency_p95:.2f}</td></tr>
    <tr><td>P99</td><td>{report.latency_p99:.2f}</td></tr>
  </table>

  <h2>Per-Category Breakdown</h2>
  <table>
    <tr><th>Category</th><th>Detected</th><th>Total</th><th>Rate</th></tr>
    {rows}
  </table>

  <h2 class="{status_class}">
    {"PASS" if report.detection_rate >= 0.95 else ("WARN" if report.detection_rate >= 0.90 else "FAIL")}
  </h2>
</body>
</html>"""

    @staticmethod
    def _percentile(sorted_values: list[float], pct: int) -> float:
        """Compute percentile from a sorted list of values."""
        if not sorted_values:
            return 0.0
        n = len(sorted_values)
        idx = (pct / 100.0) * (n - 1)
        lower = int(idx)
        upper = min(lower + 1, n - 1)
        frac = idx - lower
        return sorted_values[lower] * (1 - frac) + sorted_values[upper] * frac
