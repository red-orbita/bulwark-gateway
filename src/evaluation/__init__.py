"""
Phase 8: Red Teaming + Evaluation Framework.

Provides automated attack generation, evaluation running, and reporting
for testing guardrail detection efficacy.
"""

from src.evaluation.adaptive import (
    AdaptiveRedTeam,
    AdaptiveReport,
    AdaptiveRound,
    AttackVariant,
    serialize_adaptive_report,
)
from src.evaluation.attacks import Attack, AttackGenerator
from src.evaluation.runner import EvaluationReport, EvaluationRunner

__all__ = [
    "AdaptiveRedTeam",
    "AdaptiveReport",
    "AdaptiveRound",
    "Attack",
    "AttackGenerator",
    "AttackVariant",
    "EvaluationReport",
    "EvaluationRunner",
    "serialize_adaptive_report",
]
