"""MCP server inventory and risk assessment."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Capability risk tiers
_HIGH_RISK_CAPABILITIES = frozenset(
    ["file_write", "shell_exec", "network_access", "code_execution", "process_spawn"]
)
_MEDIUM_RISK_CAPABILITIES = frozenset(
    ["database_read", "file_read", "database_write", "env_access", "secret_read"]
)
_LOW_RISK_CAPABILITIES = frozenset(
    ["text_generation", "search", "embedding", "summarization", "translation"]
)


@dataclass
class MCPTool:
    """Represents a tool exposed by an MCP server."""

    name: str
    description: str
    parameters: dict = field(default_factory=dict)
    capabilities: list[str] = field(default_factory=list)


@dataclass
class MCPServer:
    """Represents a discovered MCP server."""

    url: str
    name: str
    version: str
    tools: list[MCPTool] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class RiskAssessment:
    """Risk assessment result for an MCP tool or server."""

    score: float  # 0-10
    findings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


class MCPInventory:
    """Inventories MCP servers and assesses their risk posture."""

    def __init__(self) -> None:
        self._usage_cache: dict[str, dict] = {}

    async def enumerate_tools(self, server_url: str) -> list[MCPTool]:
        """List tools available on an MCP server.

        Connects to the MCP server and retrieves the tool manifest.

        Args:
            server_url: URL of the MCP server.

        Returns:
            List of tools exposed by the server.
        """
        import httpx

        tools: list[MCPTool] = []

        # MCP protocol: POST with JSON-RPC to list tools
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1,
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(server_url, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, OSError, ValueError) as exc:
            logger.warning("Failed to enumerate tools at %s: %s", server_url, exc)
            return tools

        result = data.get("result", {})
        tool_list = result.get("tools", [])

        for tool_data in tool_list:
            name = tool_data.get("name", "unknown")
            description = tool_data.get("description", "")
            parameters = tool_data.get("inputSchema", tool_data.get("parameters", {}))
            capabilities = self._infer_capabilities(name, description, parameters)

            tools.append(
                MCPTool(
                    name=name,
                    description=description,
                    parameters=parameters,
                    capabilities=capabilities,
                )
            )

        return tools

    def assess_risk(self, tool: MCPTool) -> RiskAssessment:
        """Assess the risk of an MCP tool based on its capabilities.

        Args:
            tool: The MCP tool to assess.

        Returns:
            Risk assessment with score, findings, and recommendations.
        """
        score = self._score_capabilities(tool.capabilities)
        findings: list[str] = []
        recommendations: list[str] = []

        for cap in tool.capabilities:
            if cap in _HIGH_RISK_CAPABILITIES:
                findings.append(
                    f"High-risk capability '{cap}' detected in tool '{tool.name}'"
                )
            elif cap in _MEDIUM_RISK_CAPABILITIES:
                findings.append(
                    f"Medium-risk capability '{cap}' detected in tool '{tool.name}'"
                )

        # Generate recommendations based on findings
        if score >= 7.0:
            recommendations.append(
                f"Tool '{tool.name}' should be placed in strict sandbox mode"
            )
            recommendations.append("Require explicit human approval before execution")
            recommendations.append("Enable full audit logging for all invocations")
        elif score >= 4.0:
            recommendations.append(
                f"Tool '{tool.name}' should have argument validation enabled"
            )
            recommendations.append("Monitor usage patterns for anomalies")
        else:
            recommendations.append(
                f"Tool '{tool.name}' is low-risk; standard monitoring sufficient"
            )

        # Check for dangerous combinations
        caps_set = set(tool.capabilities)
        if caps_set & {"shell_exec", "code_execution"} and "network_access" in caps_set:
            findings.append(
                "CRITICAL: Tool combines code execution with network access — "
                "potential for reverse shell or data exfiltration"
            )
            score = min(score + 2.0, 10.0)
            recommendations.append("Block or require MFA for combined exec+network tools")

        if "file_write" in caps_set and "network_access" in caps_set:
            findings.append(
                "Tool combines file write with network access — "
                "potential for malware download and persistence"
            )
            score = min(score + 1.0, 10.0)

        if not tool.description:
            findings.append(f"Tool '{tool.name}' has no description — may indicate deception")
            score = min(score + 0.5, 10.0)

        return RiskAssessment(
            score=round(min(score, 10.0), 1),
            findings=findings,
            recommendations=recommendations,
        )

    def suggest_policy(
        self,
        tools: list[MCPTool],
        *,
        tenant_id: str = "default",
        agent_id: str = "mcp-agent",
    ) -> dict:
        """Derive a conservative starter AgentPolicy from enumerated MCP tools.

        This closes the "discovered agent -> suggested policy" gap: instead of
        leaving discovery results display-only, we synthesize a **deny-by-default
        starter scaffold** grounded entirely in the tools actually enumerated on
        the server and the capabilities inferred for each. It is a *suggestion*
        for an operator to review — never auto-applied — and is emitted in the
        exact YAML shape consumed by ``src/policies/loader.py`` so it can be
        dropped into ``config/policies/`` verbatim after review.

        Grounding rules (all derived from observed capabilities, nothing invented):

        - A tool is **denied** when it carries an execution- or write-class
          capability (``shell_exec`` / ``code_execution`` / ``process_spawn`` /
          ``file_write``) — the genuine RCE / persistence vectors. This mirrors
          the project's own example posture (``denied_tools: [run_command, bash,
          write_file, ...]`` in ``config/policies/``). Everything else is allowed.
        - ``allow_command_execution`` / ``allow_file_write`` stay ``False``
          (deny-by-default), consistent with those tools being denied.
        - ``allow_network_access`` mirrors whether any *allowed* tool actually
          needs network access — blocking egress otherwise.
        - ``sandbox_level`` is ``strict`` when anything was denied or any allowed
          tool still scores high-risk, else ``standard``.
        - Each *allowed* medium/high-risk tool gets a per-tool rate cap so the
          scaffold is defensive out of the box.

        Args:
            tools: Tools enumerated from the MCP server.
            tenant_id: Tenant the policy is scoped to.
            agent_id: Agent id the policy is scoped to.

        Returns:
            A dict in policy-file YAML shape with an extra ``_rationale`` block
            (per-tool score + why it landed in allow/deny) for operator review.
            The ``_rationale`` key is advisory metadata; the loader ignores
            unknown keys, so the dict remains loadable as-is.
        """
        # Execution/write-class capabilities are denied by default — these are
        # the RCE and persistence vectors an operator must consciously enable.
        _DENY_CAPS = {"shell_exec", "code_execution", "process_spawn", "file_write"}
        _HIGH_RISK_SCORE = 7.0

        allowed_tools: list[str] = []
        denied_tools: list[str] = []
        tool_policies: list[dict] = []
        rationale: list[dict] = []
        network_needed = False
        has_high_risk_allowed = False

        for tool in tools:
            assessment = self.assess_risk(tool)
            caps = set(tool.capabilities)
            deny_caps = caps & _DENY_CAPS
            deny = bool(deny_caps)

            if deny:
                denied_tools.append(tool.name)
                reason = f"execution/write-class capability {sorted(deny_caps)}"
            else:
                allowed_tools.append(tool.name)
                if "network_access" in caps:
                    network_needed = True
                if assessment.score >= _HIGH_RISK_SCORE:
                    has_high_risk_allowed = True
                # Rate-cap non-trivial allowed tools (anything above the low tier).
                if assessment.score >= 4.0:
                    tool_policies.append(
                        {"name": tool.name, "allowed": True, "max_calls": 5}
                    )
                reason = f"no execution/write capability (score {assessment.score})"

            rationale.append(
                {
                    "tool": tool.name,
                    "score": assessment.score,
                    "capabilities": sorted(caps),
                    "decision": "deny" if deny else "allow",
                    "reason": reason,
                }
            )

        strict = bool(denied_tools) or has_high_risk_allowed
        agent: dict = {
            "id": agent_id,
            "sandbox_level": "strict" if strict else "standard",
            "allowed_tools": sorted(allowed_tools),
            "denied_tools": sorted(denied_tools),
            "allow_command_execution": False,
            "allow_file_write": False,
            "allow_network_access": network_needed,
            "max_tool_calls": 20,
        }
        if tool_policies:
            agent["tool_policies"] = sorted(tool_policies, key=lambda p: p["name"])

        return {
            "tenant": tenant_id,
            "agents": [agent],
            "_rationale": rationale,
        }

    async def monitor_usage(self, server_url: str) -> dict:
        """Track usage statistics for an MCP server.

        Args:
            server_url: URL of the MCP server to monitor.

        Returns:
            Dict with usage statistics.
        """

        stats: dict = {
            "server_url": server_url,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "status": "unknown",
            "tools_count": 0,
            "total_risk_score": 0.0,
            "high_risk_tools": [],
        }

        # Try to get server info and tool list
        tools = await self.enumerate_tools(server_url)
        if not tools:
            stats["status"] = "unreachable_or_empty"
            return stats

        stats["status"] = "active"
        stats["tools_count"] = len(tools)

        total_risk = 0.0
        for tool in tools:
            assessment = self.assess_risk(tool)
            total_risk += assessment.score
            if assessment.score >= 7.0:
                stats["high_risk_tools"].append(
                    {"name": tool.name, "risk_score": assessment.score}
                )

        stats["total_risk_score"] = round(total_risk, 1)
        stats["average_risk_score"] = round(total_risk / len(tools), 1) if tools else 0.0

        # Cache for trend analysis
        self._usage_cache[server_url] = stats

        return stats

    def _score_capabilities(self, capabilities: list[str]) -> float:
        """Score a list of capabilities by risk level.

        Risk tiers:
        - file_write, shell_exec, network_access → high risk (7-10)
        - database_read, file_read → medium (4-6)
        - text_generation, search → low (1-3)

        Args:
            capabilities: List of capability strings.

        Returns:
            Aggregated risk score (0-10).
        """
        if not capabilities:
            return 1.0  # Unknown capabilities get baseline risk

        max_score = 0.0
        cumulative = 0.0

        for cap in capabilities:
            if cap in _HIGH_RISK_CAPABILITIES:
                cap_score = 8.0
            elif cap in _MEDIUM_RISK_CAPABILITIES:
                cap_score = 5.0
            elif cap in _LOW_RISK_CAPABILITIES:
                cap_score = 2.0
            else:
                # Unknown capability — treat as medium risk
                cap_score = 4.0

            max_score = max(max_score, cap_score)
            cumulative += cap_score

        # Score is weighted: 70% max single capability + 30% average
        avg_score = cumulative / len(capabilities) if capabilities else 0.0
        final_score = (max_score * 0.7) + (avg_score * 0.3)

        return round(min(final_score, 10.0), 1)

    def _infer_capabilities(
        self, name: str, description: str, parameters: dict
    ) -> list[str]:
        """Infer tool capabilities from its name, description, and parameters.

        Args:
            name: Tool name.
            description: Tool description.
            parameters: Tool parameter schema.

        Returns:
            List of inferred capability strings.
        """
        capabilities: list[str] = []
        text = f"{name} {description}".lower()
        param_text = str(parameters).lower()

        # High risk indicators
        if any(kw in text for kw in ["exec", "shell", "bash", "command", "run"]):
            capabilities.append("shell_exec")
        if any(kw in text for kw in ["write_file", "file_write", "save", "create_file"]):
            capabilities.append("file_write")
        if any(kw in text for kw in ["http", "fetch", "request", "download", "upload"]):
            capabilities.append("network_access")
        if any(kw in text for kw in ["eval", "execute_code", "code_exec"]):
            capabilities.append("code_execution")
        if any(kw in text for kw in ["spawn", "subprocess", "fork"]):
            capabilities.append("process_spawn")

        # Medium risk indicators
        if any(kw in text for kw in ["read_file", "file_read", "open_file", "cat"]):
            capabilities.append("file_read")
        if any(kw in text for kw in ["query", "select", "database", "sql"]):
            capabilities.append("database_read")
        if any(kw in text for kw in ["insert", "update", "delete", "drop"]):
            capabilities.append("database_write")
        if any(kw in text for kw in ["env", "environment", "getenv"]):
            capabilities.append("env_access")

        # Low risk indicators
        if any(kw in text for kw in ["search", "find", "lookup", "query"]) and not capabilities:
            capabilities.append("search")
        if any(kw in text for kw in ["generate", "complete", "chat"]):
            capabilities.append("text_generation")
        if any(kw in text for kw in ["embed", "vector", "similarity"]):
            capabilities.append("embedding")

        # Check parameters for path/url patterns suggesting file or network access
        if "path" in param_text or "file" in param_text:
            if "file_read" not in capabilities and "file_write" not in capabilities:
                capabilities.append("file_read")
        if "url" in param_text or "endpoint" in param_text:
            if "network_access" not in capabilities:
                capabilities.append("network_access")

        return capabilities if capabilities else ["text_generation"]
