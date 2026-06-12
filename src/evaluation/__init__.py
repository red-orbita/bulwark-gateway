"""
Phase 8: Red Teaming + Evaluation Framework.

Provides automated attack generation, evaluation running, and reporting
for testing guardrail detection efficacy.
"""

from src.evaluation.attacks import Attack, AttackGenerator
from src.evaluation.runner import EvaluationReport, EvaluationRunner

__all__ = [
    "Attack",
    "AttackGenerator",
    "EvaluationReport",
    "EvaluationRunner",
]
