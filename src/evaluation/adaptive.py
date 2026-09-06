"""
Adaptive Red-Team — evolves attacks that the pipeline currently blocks, measuring
how much an *adaptive* attacker can raise their success rate (replay before/after).

Most benchmarks fire a static corpus once and report a single detection rate. A
real adversary does not stop at the first block: they mutate a payload that got
caught and try again. This module models that loop as a bounded, deterministic
evolutionary search:

  1. Score the seed attacks → the **baseline ASR** (how many get through as-is).
  2. Take the seeds the pipeline BLOCKED (the frontier worth attacking) and, over
     a few generations, apply intent-preserving evasion mutations
     (``AttackGenerator.mutate``), re-scoring each variant. Any variant that now
     reaches the backend "breaks" that seed's lineage.
  3. Report the **adapted ASR** an attacker achieves once mutation is allowed and
     the **uplift** (adapted − baseline). A robust pipeline keeps the uplift near
     zero; a brittle exact-string matcher shows a large uplift.

The search is a beam search over lineages: each still-blocked variant spawns a
few children per generation; a lineage is retired as soon as one child breaks
through (no wasted work), and the frontier is capped (``beam_width``) so runtime
stays bounded regardless of how many seeds are blocked. Fully deterministic under
the generator's seed, so a report is reproducible.

"Success" for the attacker is the same honest definition the runner uses for ASR:
a verdict that is NOT ``BLOCK``/``REDACT`` (a ``WARN`` still forwards the request,
so it counts as a breakthrough). This module never enforces anything — it only
measures — so it has no fail-open/closed posture of its own.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone

from src.models import Verdict
from src.scanners.pipeline import ScannerPipeline
from src.scanners.protocol import ScanContext

from .attacks import Attack, AttackGenerator

logger = logging.getLogger(__name__)


def _is_breakthrough(verdict: Verdict) -> bool:
    """True if the attack reached the backend (attacker success).

    Mirrors the runner's ASR definition: only BLOCK/REDACT stop the request, so
    anything else — including WARN — is a breakthrough for the attacker.
    """
    return verdict not in (Verdict.BLOCK, Verdict.REDACT)


@dataclass
class AttackVariant:
    """One evolved payload produced and scored during the adaptive search."""

    payload: str
    category: str
    technique: str          # e.g. "adaptive/homoglyph" (lineage of the last op)
    generation: int         # which generation produced it (1-based)
    root_seed_index: int    # index of the seed lineage this descends from
    verdict: str
    broke_through: bool     # reached the backend (not block/redact)


@dataclass
class AdaptiveRound:
    """Per-generation progress of the adaptive search."""

    generation: int
    variants_tested: int
    breakthroughs: int          # variants (this round) that reached the backend
    new_lineages_broken: int    # blocked seeds first broken THIS round
    round_asr: float            # breakthroughs / variants_tested (this round)
    cumulative_adapted_asr: float  # ASR achievable so far (seeds + broken lineages)


@dataclass
class AdaptiveReport:
    """Complete adaptive red-team result (replay before/after)."""

    seed_count: int
    generations: int
    variants_per_attack: int
    beam_width: int
    baseline_asr: float          # ASR of the seed set, no mutation (before)
    adapted_asr: float           # ASR an adaptive attacker achieves (after)
    asr_uplift: float            # adapted − baseline (resilience gap; higher = worse)
    baseline_bypasses: int       # seeds that got through as-is
    lineages_broken: int         # blocked seeds an evasion was found for
    total_variants_tested: int
    total_breakthroughs: int
    rounds: list[AdaptiveRound] = field(default_factory=list)
    # A capped sample of the evasions discovered, for operator triage — which
    # payloads/operators actually broke the pipeline.
    breakthroughs: list[AttackVariant] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class _Lineage:
    """Mutable state for one seed lineage still being evolved."""

    root_seed_index: int
    current: Attack          # the latest variant to mutate from next


class AdaptiveRedTeam:
    """Runs a bounded, deterministic adaptive-evasion search against a pipeline.

    Usage::

        from src.scanners.pipeline import get_scanner_pipeline
        from src.evaluation import AttackGenerator, AdaptiveRedTeam

        generator = AttackGenerator(seed=42)
        seeds = generator.generate_attacks(count_per_category=10)

        red_team = AdaptiveRedTeam(pipeline=get_scanner_pipeline(), generator=generator)
        report = await red_team.run(seeds, generations=3, variants_per_attack=4)
        print(report.baseline_asr, "->", report.adapted_asr)
    """

    # Hard ceiling on total variants scored in one run, independent of the
    # generation/beam parameters, so an operator-triggered run can never turn
    # into an unbounded workload against the pipeline.
    _MAX_TOTAL_VARIANTS = 5000

    # Upper bound on a variant payload's length. Mutations COMPOUND across
    # generations (a still-blocked child is mutated again next round), and the
    # ``encoding`` operator re-wraps its input — so an un-broken lineage would
    # otherwise grow its payload without bound (base64-of-base64…), turning both
    # scoring and the next mutation into an accidental DoS. Truncating the carried
    # payload keeps compounding meaningful while bounding per-variant cost.
    _MAX_PAYLOAD_CHARS = 8192

    def __init__(
        self,
        pipeline: ScannerPipeline | None = None,
        generator: AttackGenerator | None = None,
    ) -> None:
        """Initialize the red team.

        Args:
            pipeline: pipeline to attack. If None, the global singleton is
                imported lazily at run time (same contract as EvaluationRunner).
            generator: seeded AttackGenerator supplying the mutation operators.
                If None, a seeded (seed=42) generator is created so runs are
                reproducible by default.
        """
        self._pipeline = pipeline
        self._generator = generator or AttackGenerator(seed=42)

    @property
    def pipeline(self) -> ScannerPipeline:
        """Lazy-load the pipeline singleton if one was not injected."""
        if self._pipeline is None:
            from src.scanners.pipeline import get_scanner_pipeline
            self._pipeline = get_scanner_pipeline()
        return self._pipeline

    async def run(
        self,
        seeds: list[Attack],
        generations: int = 3,
        variants_per_attack: int = 4,
        beam_width: int = 24,
        max_breakthrough_samples: int = 100,
    ) -> AdaptiveReport:
        """Run the adaptive-evasion search and return a replay-before/after report.

        Args:
            seeds: the seed attacks to evolve (typically from AttackGenerator).
            generations: number of mutation rounds (bounded 1..10).
            variants_per_attack: children spawned per lineage per round (1..16).
            beam_width: max still-blocked lineages evolved per round (bounds work).
            max_breakthrough_samples: cap on discovered-evasion samples kept.

        Returns:
            An ``AdaptiveReport`` with baseline vs adapted ASR, per-round
            progression, and a capped sample of the evasions found.
        """
        generations = max(1, min(int(generations), 10))
        variants_per_attack = max(1, min(int(variants_per_attack), 16))
        beam_width = max(1, min(int(beam_width), 256))

        seed_count = len(seeds)
        if seed_count == 0:
            return AdaptiveReport(
                seed_count=0,
                generations=generations,
                variants_per_attack=variants_per_attack,
                beam_width=beam_width,
                baseline_asr=0.0,
                adapted_asr=0.0,
                asr_uplift=0.0,
                baseline_bypasses=0,
                lineages_broken=0,
                total_variants_tested=0,
                total_breakthroughs=0,
            )

        # --- Round 0: score the seeds as-is (baseline / "before") ----------
        blocked: list[_Lineage] = []
        baseline_bypasses = 0
        for idx, seed in enumerate(seeds):
            verdict = await self._score(seed)
            if _is_breakthrough(verdict):
                baseline_bypasses += 1
            else:
                blocked.append(_Lineage(root_seed_index=idx, current=seed))

        baseline_asr = round(baseline_bypasses / seed_count, 4)

        # --- Adaptive rounds: try to break the blocked seeds ("after") -----
        solved_lineages: set[int] = set()
        breakthrough_samples: list[AttackVariant] = []
        rounds: list[AdaptiveRound] = []
        total_variants = 0
        total_breakthroughs = 0
        frontier = blocked

        for gen in range(1, generations + 1):
            if not frontier:
                break

            variants_tested = 0
            round_breakthroughs = 0
            new_broken = 0
            next_frontier: list[_Lineage] = []

            for lineage in frontier[:beam_width]:
                if lineage.root_seed_index in solved_lineages:
                    continue
                if total_variants >= self._MAX_TOTAL_VARIANTS:
                    break

                broke = False
                for _ in range(variants_per_attack):
                    if total_variants >= self._MAX_TOTAL_VARIANTS:
                        break
                    child = self._generator.mutate(lineage.current)
                    # Bound compounding growth before it reaches the scanner or
                    # the next mutation (see _MAX_PAYLOAD_CHARS).
                    if len(child.payload) > self._MAX_PAYLOAD_CHARS:
                        child = replace(
                            child, payload=child.payload[: self._MAX_PAYLOAD_CHARS]
                        )
                    verdict = await self._score(child)
                    total_variants += 1
                    variants_tested += 1

                    if _is_breakthrough(verdict):
                        round_breakthroughs += 1
                        total_breakthroughs += 1
                        solved_lineages.add(lineage.root_seed_index)
                        new_broken += 1
                        if len(breakthrough_samples) < max_breakthrough_samples:
                            breakthrough_samples.append(
                                self._make_variant(child, gen, lineage.root_seed_index, verdict, True)
                            )
                        broke = True
                        break

                    # Still blocked: evolve this variant further next round
                    # (mutations stack), keeping the lineage on the frontier.
                    lineage.current = child

                if not broke:
                    next_frontier.append(lineage)

            cumulative_adapted = round(
                (baseline_bypasses + len(solved_lineages)) / seed_count, 4
            )
            rounds.append(AdaptiveRound(
                generation=gen,
                variants_tested=variants_tested,
                breakthroughs=round_breakthroughs,
                new_lineages_broken=new_broken,
                round_asr=round(round_breakthroughs / variants_tested, 4) if variants_tested else 0.0,
                cumulative_adapted_asr=cumulative_adapted,
            ))
            frontier = next_frontier

        lineages_broken = len(solved_lineages)
        adapted_asr = round((baseline_bypasses + lineages_broken) / seed_count, 4)

        logger.info(
            "adaptive_redteam_complete seeds=%d baseline_asr=%.3f adapted_asr=%.3f "
            "uplift=%.3f lineages_broken=%d variants=%d",
            seed_count, baseline_asr, adapted_asr, adapted_asr - baseline_asr,
            lineages_broken, total_variants,
        )

        return AdaptiveReport(
            seed_count=seed_count,
            generations=generations,
            variants_per_attack=variants_per_attack,
            beam_width=beam_width,
            baseline_asr=baseline_asr,
            adapted_asr=adapted_asr,
            asr_uplift=round(adapted_asr - baseline_asr, 4),
            baseline_bypasses=baseline_bypasses,
            lineages_broken=lineages_broken,
            total_variants_tested=total_variants,
            total_breakthroughs=total_breakthroughs,
            rounds=rounds,
            breakthroughs=breakthrough_samples,
        )

    async def _score(self, attack: Attack) -> Verdict:
        """Run one attack through the input-blocking lane and return its verdict."""
        context = ScanContext(
            tenant_id="adaptive-eval-tenant",
            agent_id="adaptive-eval-agent",
            request_id=f"adaptive-{uuid.uuid4().hex[:12]}",
            messages=[{"role": "user", "content": attack.payload}],
            metadata={"adaptive_evaluation": True},
        )
        result = await self.pipeline.run_input_blocking(attack.payload, context)
        return result.verdict

    @staticmethod
    def _make_variant(
        attack: Attack,
        generation: int,
        root_seed_index: int,
        verdict: Verdict,
        broke_through: bool,
    ) -> AttackVariant:
        """Build a serializable AttackVariant record (payload truncated)."""
        return AttackVariant(
            payload=attack.payload[:300],
            category=attack.category.value,
            technique=attack.technique,
            generation=generation,
            root_seed_index=root_seed_index,
            verdict=verdict.value,
            broke_through=broke_through,
        )


def serialize_adaptive_report(report: AdaptiveReport) -> dict:
    """Serialize an AdaptiveReport to a plain dict for the admin API / UI."""
    return asdict(report)
