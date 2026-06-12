"""
Dialog Engine — YAML-based dialog flow control.

A lightweight dialog state machine that constrains agent conversations
to predefined flows. Simplified Colang alternative with keyword-based
intent matching.

Features:
  - YAML-defined dialog flows (trigger → allowed/denied intents → response)
  - Session state tracking (in-memory, keyed by session_id)
  - Keyword-based intent matching (ML intent scanner handles real classification)
  - Three possible actions: allow, redirect (canned response), block

YAML format example:
  greeting:
    trigger:
      - hello
      - hi
      - hey
    allowed_intents:
      - ask_question
      - request_help
    denied_intents:
      - request_harmful
      - jailbreak
    on_denied: "I cannot help with that request."
    next_nodes:
      - ask_question
      - farewell

  ask_question:
    trigger:
      - question
      - how do I
      - explain
    allowed_intents:
      - followup
      - farewell
    denied_intents:
      - request_harmful
    on_denied: "That topic is not allowed."
    next_nodes:
      - followup
      - farewell
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from src.models import Verdict
from src.scanners.protocol import ScanContext

logger = logging.getLogger(__name__)


@dataclass
class DialogFlow:
    """A single node in the dialog flow graph.

    Attributes:
        trigger: Keywords that activate this flow node.
        allowed_intents: Intents permitted from this state.
        denied_intents: Intents blocked from this state.
        on_denied: Canned response when a denied intent is matched.
        next_nodes: Valid flow nodes reachable from this state.
    """

    trigger: list[str] = field(default_factory=list)
    allowed_intents: list[str] = field(default_factory=list)
    denied_intents: list[str] = field(default_factory=list)
    on_denied: str = "I cannot process that request in the current context."
    next_nodes: list[str] = field(default_factory=list)


@dataclass
class DialogDecision:
    """Result of dialog engine processing.

    Attributes:
        action: One of "allow", "redirect", "block".
        response: Optional canned response (set for redirect/block actions).
        matched_node: Name of the dialog flow node that matched (if any).
        matched_intent: The intent that was detected (if any).
    """

    action: str  # "allow", "redirect", "block"
    response: str | None = None
    matched_node: str | None = None
    matched_intent: str | None = None


@dataclass
class _SessionState:
    """Internal session tracking state."""

    current_node: str | None = None
    turn_count: int = 0
    history: list[str] = field(default_factory=list)


class DialogEngine:
    """YAML-based dialog flow engine with session state.

    Processes messages through a graph of dialog flow nodes.
    Uses keyword matching to detect intents and enforce allowed/denied
    transitions per node.

    Session state is stored in-memory (session_id -> current_node).
    For production distributed deployments, extend with Redis backing.

    Usage:
        flows = load_dialog_config(Path("config/dialog.yaml"))
        engine = DialogEngine(flows)
        decision = await engine.process(message, session_id, context)
    """

    def __init__(self, flows: dict[str, DialogFlow]) -> None:
        """Initialize dialog engine with flow definitions.

        Args:
            flows: Mapping of node_name -> DialogFlow. Must contain at least
                   one node to be functional.
        """
        self._flows = flows
        self._sessions: dict[str, _SessionState] = {}
        logger.info(
            "dialog_engine_initialized",
            extra={"flow_count": len(flows), "nodes": list(flows.keys())},
        )

    async def process(
        self,
        message: str,
        session_id: str,
        context: ScanContext,
    ) -> DialogDecision:
        """Process a message through the dialog flow engine.

        Args:
            message: The user message text.
            session_id: Unique session identifier for state tracking.
            context: Scan context (provides tenant, agent, metadata).

        Returns:
            DialogDecision with action and optional canned response.
        """
        if not self._flows:
            return DialogDecision(action="allow")

        # Get or create session state
        session = self._get_or_create_session(session_id)
        session.turn_count += 1
        session.history.append(message[:200])  # Keep truncated history

        # Detect intent from message (keyword-based)
        detected_intent = self._detect_intent(message)

        # Determine current node
        current_node_name = session.current_node
        current_node = self._flows.get(current_node_name) if current_node_name else None

        # If no current node, try to match a trigger to enter a flow
        just_entered = False
        if current_node is None:
            entry_node_name = self._find_entry_node(message)
            if entry_node_name:
                session.current_node = entry_node_name
                current_node = self._flows[entry_node_name]
                just_entered = True
                logger.debug(
                    "dialog_flow_entered",
                    extra={
                        "session_id": session_id,
                        "node": entry_node_name,
                        "tenant_id": context.tenant_id,
                    },
                )

        # If still no node matched, allow (no flow constraint applies)
        if current_node is None:
            return DialogDecision(action="allow")

        # If we just entered a node via its own trigger, allow the entry message
        if just_entered and detected_intent == session.current_node:
            return DialogDecision(
                action="allow", matched_node=session.current_node
            )

        # Check if detected intent is denied in current node
        if detected_intent and detected_intent in current_node.denied_intents:
            logger.warning(
                "dialog_intent_denied",
                extra={
                    "session_id": session_id,
                    "node": session.current_node,
                    "intent": detected_intent,
                    "tenant_id": context.tenant_id,
                    "agent_id": context.agent_id,
                },
            )
            return DialogDecision(
                action="redirect",
                response=current_node.on_denied,
                matched_node=session.current_node,
                matched_intent=detected_intent,
            )

        # Check if detected intent leads to a valid next node
        if detected_intent and current_node.next_nodes:
            next_node = self._find_next_node(detected_intent, current_node.next_nodes)
            if next_node:
                session.current_node = next_node
                logger.debug(
                    "dialog_flow_transition",
                    extra={
                        "session_id": session_id,
                        "from_node": current_node_name,
                        "to_node": next_node,
                    },
                )

        # If intent is explicitly allowed or no intent constraint, allow
        if detected_intent and current_node.allowed_intents:
            if detected_intent in current_node.allowed_intents:
                return DialogDecision(
                    action="allow",
                    matched_node=session.current_node,
                    matched_intent=detected_intent,
                )
            # Intent detected but not in allowed list — block
            if current_node.denied_intents or current_node.allowed_intents:
                logger.warning(
                    "dialog_intent_not_allowed",
                    extra={
                        "session_id": session_id,
                        "node": session.current_node,
                        "intent": detected_intent,
                        "allowed": current_node.allowed_intents,
                    },
                )
                return DialogDecision(
                    action="block",
                    response=current_node.on_denied,
                    matched_node=session.current_node,
                    matched_intent=detected_intent,
                )

        return DialogDecision(action="allow", matched_node=session.current_node)

    def _get_or_create_session(self, session_id: str) -> _SessionState:
        """Get existing session or create a new one."""
        if session_id not in self._sessions:
            self._sessions[session_id] = _SessionState()
        return self._sessions[session_id]

    def _detect_intent(self, message: str) -> str | None:
        """Detect intent from message using keyword matching.

        This is a basic keyword-based approach. The ML IntentScanner
        provides real classification for production use.

        Returns the name of the first matched intent (flow node name
        whose trigger keywords match), or None.
        """
        message_lower = message.lower()
        for node_name, flow in self._flows.items():
            for keyword in flow.trigger:
                if keyword.lower() in message_lower:
                    return node_name
        return None

    def _find_entry_node(self, message: str) -> str | None:
        """Find a flow node whose trigger keywords match the message."""
        message_lower = message.lower()
        for node_name, flow in self._flows.items():
            for keyword in flow.trigger:
                if keyword.lower() in message_lower:
                    return node_name
        return None

    def _find_next_node(
        self, intent: str, valid_next: list[str]
    ) -> str | None:
        """Find a valid next node matching the detected intent."""
        if intent in valid_next:
            return intent
        # Check if intent triggers any of the valid next nodes
        for next_name in valid_next:
            flow = self._flows.get(next_name)
            if flow:
                for keyword in flow.trigger:
                    if keyword.lower() == intent.lower():
                        return next_name
        return None

    def reset_session(self, session_id: str) -> None:
        """Reset a session to initial state.

        Args:
            session_id: The session to reset.
        """
        if session_id in self._sessions:
            del self._sessions[session_id]
            logger.debug("dialog_session_reset", extra={"session_id": session_id})

    def get_session_node(self, session_id: str) -> str | None:
        """Get the current node for a session (for debugging/testing).

        Args:
            session_id: The session to query.

        Returns:
            Current node name or None if session doesn't exist.
        """
        session = self._sessions.get(session_id)
        return session.current_node if session else None

    @property
    def flow_names(self) -> list[str]:
        """List all registered flow node names."""
        return list(self._flows.keys())


def load_dialog_config(path: Path) -> dict[str, DialogFlow]:
    """Load dialog flow definitions from a YAML file.

    Args:
        path: Path to the YAML dialog configuration file.

    Returns:
        Mapping of node_name -> DialogFlow.

    Raises:
        FileNotFoundError: If the YAML file doesn't exist.
        ValueError: If the YAML structure is invalid.

    YAML format:
        node_name:
          trigger: [keyword1, keyword2, ...]
          allowed_intents: [intent1, intent2, ...]
          denied_intents: [intent1, intent2, ...]
          on_denied: "Canned response text"
          next_nodes: [node1, node2, ...]
    """
    if not path.exists():
        raise FileNotFoundError(f"Dialog config not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError(
            f"Dialog config must be a YAML mapping, got: {type(raw).__name__}"
        )

    flows: dict[str, DialogFlow] = {}

    for node_name, node_config in raw.items():
        if not isinstance(node_config, dict):
            logger.warning(
                "dialog_config_skip_node",
                extra={"node": node_name, "reason": "not a mapping"},
            )
            continue

        flows[node_name] = DialogFlow(
            trigger=_ensure_list(node_config.get("trigger", [])),
            allowed_intents=_ensure_list(node_config.get("allowed_intents", [])),
            denied_intents=_ensure_list(node_config.get("denied_intents", [])),
            on_denied=str(
                node_config.get(
                    "on_denied",
                    "I cannot process that request in the current context.",
                )
            ),
            next_nodes=_ensure_list(node_config.get("next_nodes", [])),
        )

    logger.info(
        "dialog_config_loaded",
        extra={"path": str(path), "flow_count": len(flows)},
    )

    return flows


def _ensure_list(value: Any) -> list[str]:
    """Ensure a value is a list of strings.

    Handles YAML scalars (single string) and lists.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]
