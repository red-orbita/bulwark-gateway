"""
Dialog Engine — YAML-based dialog flow control for AI agents.

Provides a lightweight dialog state machine that constrains agent
conversations to predefined flows. Acts as a simplified Colang
alternative with keyword-based intent matching.

Components:
  - DialogEngine: Processes messages through dialog flows with session state
  - DialogDecision: Result of dialog processing (allow/redirect/block)
  - DialogFlow: Defines nodes in the dialog graph
  - load_dialog_config: Loads dialog flows from YAML files
"""

from src.dialog.engine import (
    DialogDecision,
    DialogEngine,
    DialogFlow,
    load_dialog_config,
)

__all__ = [
    "DialogDecision",
    "DialogEngine",
    "DialogFlow",
    "load_dialog_config",
]
