"""
Tool Policy Engine — RBAC enforcement on tool calls.

Defines which tools each agent/tenant can use, with what parameters,
and under what conditions. This is the core differentiator vs generic
text-level guardrails.
"""
from dataclasses import dataclass, field
from typing import Any
from src.models import Verdict, ThreatCategory, SecurityEvent, GuardrailResult, ToolCall


@dataclass
class ToolPolicy:
    """Policy for a single tool."""
    name: str
    allowed: bool = True
    max_calls_per_request: int = 10
    denied_arguments: dict[str, list[str]] = field(default_factory=dict)
    required_arguments: list[str] = field(default_factory=list)
    argument_patterns: dict[str, str] = field(default_factory=dict)  # regex allowlist per arg


@dataclass
class AgentPolicy:
    """Complete policy for an agent within a tenant."""
    tenant_id: str
    agent_id: str
    allowed_tools: list[str] = field(default_factory=list)  # empty = all allowed
    denied_tools: list[str] = field(default_factory=list)
    tool_policies: dict[str, ToolPolicy] = field(default_factory=dict)
    max_tool_calls_per_request: int = 20
    allow_command_execution: bool = False
    allow_file_write: bool = False
    allow_network_access: bool = True
    sandbox_level: str = "standard"  # "minimal", "standard", "strict"


class ToolPolicyEngine:
    """Enforces tool-level RBAC policies."""

    def __init__(self):
        self.policies: dict[str, AgentPolicy] = {}  # key: "tenant_id:agent_id"

    def register_policy(self, policy: AgentPolicy):
        key = f"{policy.tenant_id}:{policy.agent_id}"
        self.policies[key] = policy

    def get_policy(self, tenant_id: str, agent_id: str) -> AgentPolicy | None:
        return self.policies.get(f"{tenant_id}:{agent_id}")

    def evaluate_tool_call(
        self, tool_call: ToolCall, tenant_id: str, agent_id: str,
        call_count: int = 0
    ) -> GuardrailResult:
        """Evaluate a single tool call against the policy."""
        policy = self.get_policy(tenant_id, agent_id)

        # No policy = use defaults (deny dangerous tools)
        if not policy:
            return self._evaluate_default(tool_call, tenant_id, agent_id)

        events: list[SecurityEvent] = []

        # Check if tool is explicitly denied
        if tool_call.name in policy.denied_tools:
            events.append(SecurityEvent(
                tenant_id=tenant_id,
                agent_id=agent_id,
                verdict=Verdict.BLOCK,
                category=ThreatCategory.POLICY_VIOLATION,
                description=f"Tool '{tool_call.name}' is denied by policy",
                source="tool_policy_engine",
                severity="high",
                tool_name=tool_call.name,
            ))
            return GuardrailResult(verdict=Verdict.BLOCK, events=events, blocked_tools=[tool_call.name])

        # Check allowlist (if defined, only listed tools are allowed)
        if policy.allowed_tools and tool_call.name not in policy.allowed_tools:
            events.append(SecurityEvent(
                tenant_id=tenant_id,
                agent_id=agent_id,
                verdict=Verdict.BLOCK,
                category=ThreatCategory.POLICY_VIOLATION,
                description=f"Tool '{tool_call.name}' not in allowlist",
                source="tool_policy_engine",
                severity="high",
                tool_name=tool_call.name,
            ))
            return GuardrailResult(verdict=Verdict.BLOCK, events=events, blocked_tools=[tool_call.name])

        # Check rate limit per request
        if call_count >= policy.max_tool_calls_per_request:
            events.append(SecurityEvent(
                tenant_id=tenant_id,
                agent_id=agent_id,
                verdict=Verdict.BLOCK,
                category=ThreatCategory.POLICY_VIOLATION,
                description=f"Max tool calls per request exceeded ({policy.max_tool_calls_per_request})",
                source="tool_policy_engine",
                severity="medium",
                tool_name=tool_call.name,
            ))
            return GuardrailResult(verdict=Verdict.BLOCK, events=events)

        # Check command execution permission
        if tool_call.name in ("run_command", "execute", "bash", "shell", "terminal"):
            if not policy.allow_command_execution:
                events.append(SecurityEvent(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.BLOCK,
                    category=ThreatCategory.TOOL_ABUSE,
                    description="Command execution not allowed for this agent",
                    source="tool_policy_engine",
                    severity="critical",
                    tool_name=tool_call.name,
                ))
                return GuardrailResult(verdict=Verdict.BLOCK, events=events, blocked_tools=[tool_call.name])

        # Check file write permission
        if tool_call.name in ("write_file", "create_file", "edit_file", "save"):
            if not policy.allow_file_write:
                events.append(SecurityEvent(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.BLOCK,
                    category=ThreatCategory.TOOL_ABUSE,
                    description="File write not allowed for this agent",
                    source="tool_policy_engine",
                    severity="high",
                    tool_name=tool_call.name,
                ))
                return GuardrailResult(verdict=Verdict.BLOCK, events=events, blocked_tools=[tool_call.name])

        # Check tool-specific policies
        tool_policy = policy.tool_policies.get(tool_call.name)
        if tool_policy:
            result = self._evaluate_tool_policy(tool_call, tool_policy, tenant_id, agent_id)
            if result.verdict == Verdict.BLOCK:
                return result

        return GuardrailResult(verdict=Verdict.ALLOW, events=events)

    def evaluate_tool_calls(
        self, tool_calls: list[ToolCall], tenant_id: str, agent_id: str
    ) -> GuardrailResult:
        """Evaluate a batch of tool calls."""
        all_events: list[SecurityEvent] = []
        blocked: list[str] = []

        for i, tc in enumerate(tool_calls):
            result = self.evaluate_tool_call(tc, tenant_id, agent_id, call_count=i)
            all_events.extend(result.events)
            blocked.extend(result.blocked_tools)
            if result.verdict == Verdict.BLOCK:
                return GuardrailResult(
                    verdict=Verdict.BLOCK, events=all_events, blocked_tools=blocked
                )

        return GuardrailResult(verdict=Verdict.ALLOW, events=all_events)

    def _evaluate_default(self, tool_call: ToolCall, tenant_id: str, agent_id: str) -> GuardrailResult:
        """Default policy: block dangerous tools when no explicit policy exists."""
        dangerous_tools = {
            "run_command", "execute", "bash", "shell", "terminal",
            "write_file", "delete_file", "rm",
        }
        if tool_call.name in dangerous_tools:
            event = SecurityEvent(
                tenant_id=tenant_id,
                agent_id=agent_id,
                verdict=Verdict.BLOCK,
                category=ThreatCategory.TOOL_ABUSE,
                description=f"Tool '{tool_call.name}' blocked by default policy (no explicit policy configured)",
                source="tool_policy_engine",
                severity="high",
                tool_name=tool_call.name,
            )
            return GuardrailResult(verdict=Verdict.BLOCK, events=[event], blocked_tools=[tool_call.name])
        return GuardrailResult(verdict=Verdict.ALLOW)

    def _evaluate_tool_policy(
        self, tool_call: ToolCall, policy: ToolPolicy, tenant_id: str, agent_id: str
    ) -> GuardrailResult:
        """Evaluate tool-specific argument constraints."""
        import re
        events: list[SecurityEvent] = []

        # Check denied argument values
        for arg_name, denied_values in policy.denied_arguments.items():
            arg_value = str(tool_call.arguments.get(arg_name, ""))
            for denied in denied_values:
                if denied.lower() in arg_value.lower():
                    events.append(SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.POLICY_VIOLATION,
                        description=f"Denied argument value '{denied}' in {arg_name}",
                        source="tool_policy_engine",
                        severity="high",
                        tool_name=tool_call.name,
                        matched_pattern=denied,
                    ))
                    return GuardrailResult(verdict=Verdict.BLOCK, events=events, blocked_tools=[tool_call.name])

        # Check argument allowlist patterns
        for arg_name, pattern_str in policy.argument_patterns.items():
            arg_value = str(tool_call.arguments.get(arg_name, ""))
            if arg_value and not re.match(pattern_str, arg_value):
                events.append(SecurityEvent(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.BLOCK,
                    category=ThreatCategory.POLICY_VIOLATION,
                    description=f"Argument '{arg_name}' doesn't match allowed pattern",
                    source="tool_policy_engine",
                    severity="medium",
                    tool_name=tool_call.name,
                ))
                return GuardrailResult(verdict=Verdict.BLOCK, events=events, blocked_tools=[tool_call.name])

        return GuardrailResult(verdict=Verdict.ALLOW, events=events)
