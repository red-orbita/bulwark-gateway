"""
Policy Loader — Loads YAML policy files into the tool policy engine.
"""
import yaml
import structlog
from pathlib import Path
from src.guardrails.tool_policy import AgentPolicy, ToolPolicy, ToolPolicyEngine

logger = structlog.get_logger()


class PolicyLoader:
    """Loads and manages agent policies from YAML files."""

    def __init__(self, policies_dir: Path):
        self.policies_dir = policies_dir
        self.engine = ToolPolicyEngine()
        self._policies: list[AgentPolicy] = []

    @property
    def count(self) -> int:
        return len(self._policies)

    async def load_all(self):
        """Load all policy YAML files from the policies directory."""
        if not self.policies_dir.exists():
            await logger.awarn("policies_dir_missing", path=str(self.policies_dir))
            return

        for policy_file in self.policies_dir.glob("*.yaml"):
            try:
                await self._load_file(policy_file)
            except Exception as e:
                await logger.aerror("policy_load_error", file=str(policy_file), error=str(e))

    async def _load_file(self, path: Path):
        """Load a single policy file."""
        with open(path) as f:
            data = yaml.safe_load(f)

        if not data or "agents" not in data:
            return

        tenant_id = data.get("tenant", "default")

        for agent_data in data["agents"]:
            policy = self._parse_agent_policy(tenant_id, agent_data)
            self.engine.register_policy(policy)
            self._policies.append(policy)
            await logger.ainfo(
                "policy_loaded",
                tenant=tenant_id,
                agent=policy.agent_id,
                tools_allowed=len(policy.allowed_tools),
                tools_denied=len(policy.denied_tools),
            )

    def _parse_agent_policy(self, tenant_id: str, data: dict) -> AgentPolicy:
        """Parse agent policy from YAML dict."""
        tool_policies = {}
        for tp_data in data.get("tool_policies", []):
            tp = ToolPolicy(
                name=tp_data["name"],
                allowed=tp_data.get("allowed", True),
                max_calls_per_request=tp_data.get("max_calls", 10),
                denied_arguments=tp_data.get("denied_arguments", {}),
                required_arguments=tp_data.get("required_arguments", []),
                argument_patterns=tp_data.get("argument_patterns", {}),
            )
            tool_policies[tp.name] = tp

        return AgentPolicy(
            tenant_id=tenant_id,
            agent_id=data["id"],
            allowed_tools=data.get("allowed_tools", []),
            denied_tools=data.get("denied_tools", []),
            tool_policies=tool_policies,
            max_tool_calls_per_request=data.get("max_tool_calls", 20),
            allow_command_execution=data.get("allow_command_execution", False),
            allow_file_write=data.get("allow_file_write", False),
            allow_network_access=data.get("allow_network_access", True),
            sandbox_level=data.get("sandbox_level", "standard"),
        )

    def reload(self):
        """Hot-reload policies without restart."""
        self.engine = ToolPolicyEngine()
        self._policies = []
        import asyncio
        asyncio.create_task(self.load_all())
