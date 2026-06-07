"""
Policy Loader — Loads YAML policy files into the tool policy engine.
Supports hot-reload via polling (no external dependencies).
"""

import asyncio
from pathlib import Path

import structlog
import yaml

from src.guardrails.tool_policy import AgentPolicy, ToolPolicy, ToolPolicyEngine

logger = structlog.get_logger()


class PolicyLoader:
    """Loads and manages agent policies from YAML files with hot-reload."""

    def __init__(self, policies_dir: Path):
        self.policies_dir = policies_dir
        self.engine = ToolPolicyEngine()
        self._policies: list[AgentPolicy] = []
        self._file_mtimes: dict[str, float] = {}
        self._reload_task: asyncio.Task | None = None

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
                self._file_mtimes[str(policy_file)] = policy_file.stat().st_mtime
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

    async def reload(self):
        """Hot-reload policies without restart."""
        await logger.ainfo("policy_reload_start")
        new_engine = ToolPolicyEngine()
        new_policies: list[AgentPolicy] = []

        if not self.policies_dir.exists():
            return

        for policy_file in self.policies_dir.glob("*.yaml"):
            try:
                with open(policy_file) as f:
                    data = yaml.safe_load(f)
                if not data or "agents" not in data:
                    continue
                tenant_id = data.get("tenant", "default")
                for agent_data in data["agents"]:
                    policy = self._parse_agent_policy(tenant_id, agent_data)
                    new_engine.register_policy(policy)
                    new_policies.append(policy)
                self._file_mtimes[str(policy_file)] = policy_file.stat().st_mtime
            except Exception as e:
                await logger.aerror("policy_reload_error", file=str(policy_file), error=str(e))

        # Atomic swap
        self.engine = new_engine
        self._policies = new_policies
        await logger.ainfo("policy_reload_complete", count=len(new_policies))

    async def start_hot_reload(self, interval_seconds: int = 5):
        """Start background polling for policy file changes."""
        self._reload_task = asyncio.create_task(self._poll_changes(interval_seconds))

    async def stop_hot_reload(self):
        """Stop the hot-reload polling task."""
        if self._reload_task:
            self._reload_task.cancel()
            try:
                await self._reload_task
            except asyncio.CancelledError:
                pass

    async def _poll_changes(self, interval: int):
        """Poll for file changes and reload if modified."""
        while True:
            await asyncio.sleep(interval)
            try:
                changed = False
                if not self.policies_dir.exists():
                    continue

                current_files = set(str(p) for p in self.policies_dir.glob("*.yaml"))
                known_files = set(self._file_mtimes.keys())

                # New or removed files
                if current_files != known_files:
                    changed = True
                else:
                    # Check mtimes
                    for fpath in current_files:
                        mtime = Path(fpath).stat().st_mtime
                        if self._file_mtimes.get(fpath) != mtime:
                            changed = True
                            break

                if changed:
                    await self.reload()
            except asyncio.CancelledError:
                break
            except Exception as e:
                await logger.aerror("policy_poll_error", error=str(e))
