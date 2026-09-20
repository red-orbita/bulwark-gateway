"""
Policy Loader — Loads YAML policy files into the tool policy engine.
Supports hot-reload via polling (no external dependencies).
"""

import asyncio
import os
from pathlib import Path

import structlog
import yaml

from src.guardrails.attachments import AttachmentPolicy
from src.guardrails.backend_egress import BackendEgressPolicy
from src.guardrails.input_dlp import InputDlpPolicy
from src.guardrails.tool_policy import AgentPolicy, ToolPolicy, ToolPolicyEngine

logger = structlog.get_logger()


class PolicyLoader:
    """Loads and manages agent policies from YAML files with hot-reload."""

    def __init__(self, policies_dir: Path):
        self.policies_dir = policies_dir
        self.engine = ToolPolicyEngine()
        self._policies: list[AgentPolicy] = []
        self._file_mtimes: dict[str, tuple[int, int, int, int, int]] = {}
        self._reload_task: asyncio.Task | None = None

    @property
    def count(self) -> int:
        return len(self._policies)

    async def load_all(self):
        """Startup cannot silently omit a tenant whose policy failed validation."""
        await self.reload(strict=True)

    @staticmethod
    def _file_version(info: os.stat_result) -> tuple[int, int, int, int, int]:
        return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns

    @staticmethod
    def _read_policy_file(path: Path) -> tuple[dict, tuple[int, int, int, int, int]]:
        with path.open("rb") as stream:
            version = PolicyLoader._file_version(os.fstat(stream.fileno()))
            raw = stream.read(1024 * 1024 + 1)
            if PolicyLoader._file_version(os.fstat(stream.fileno())) != version:
                raise ValueError("Policy changed during read")
        if len(raw) > 1024 * 1024:
            raise ValueError("Policy file exceeds size limit")
        data = yaml.safe_load(raw)
        # Shipped and persisted baseline policies historically use agents: {}.
        # Preserve only that empty representation, not arbitrary mapping shapes.
        if isinstance(data, dict) and data.get("agents") == {}:
            data["agents"] = []
        if not isinstance(data, dict) or not isinstance(data.get("agents"), list):
            raise ValueError("Policy must contain an agents list")
        if len(data["agents"]) > 1024:
            raise ValueError("Policy exceeds 1024 agents")
        return data, version

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
                parameter_schema=tp_data.get("parameter_schema", {}),
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
            output_validation=data.get("output_validation", {}) or {},
            allowed_languages=data.get("allowed_languages", []) or [],
            block_unknown_language=bool(data.get("block_unknown_language", False)),
            multimodal=data.get("multimodal", {}) or {},
            input_dlp=InputDlpPolicy.model_validate(data.get("input_dlp", {})),
            backend_egress=BackendEgressPolicy.model_validate(data.get("backend_egress", {})),
            attachments=AttachmentPolicy.model_validate(data.get("attachments", {})),
        )

    async def reload(self, *, strict: bool = False):
        """Hot-reload policies without restart."""
        await logger.ainfo("policy_reload_start")
        new_engine = ToolPolicyEngine()
        new_policies: list[AgentPolicy] = []
        new_mtimes: dict[str, tuple[int, int, int, int, int]] = {}
        errors = False
        identities: set[tuple[str, str]] = set()

        if not self.policies_dir.exists():
            return

        for policy_file in self.policies_dir.glob("*.yaml"):
            try:
                data, version = await asyncio.to_thread(self._read_policy_file, policy_file)
                tenant_id = data.get("tenant", "default")
                for agent_data in data["agents"]:
                    policy = self._parse_agent_policy(tenant_id, agent_data)
                    identity = (policy.tenant_id, policy.agent_id)
                    if identity in identities:
                        raise ValueError("Duplicate tenant/agent policy")
                    identities.add(identity)
                    new_engine.register_policy(policy)
                    new_policies.append(policy)
                if self._file_version(policy_file.stat()) != version:
                    raise ValueError("Policy replaced during reload")
                new_mtimes[str(policy_file)] = version
            except Exception:
                errors = True
                await logger.aerror("policy_reload_error", file=str(policy_file))

        # No await between this final check and publication: never stamp old
        # contents with the metadata of a replacement file.
        try:
            current = {str(p): self._file_version(p.stat()) for p in self.policies_dir.glob("*.yaml")}
            errors = errors or current != new_mtimes
        except OSError:
            errors = True

        if errors:
            await logger.aerror("policy_reload_rejected", reason="invalid_policy", keeping="previous")
            if strict:
                raise RuntimeError("Policy validation failed; refusing partial startup")
            return

        # SECURITY FIX (H-04): Refuse to swap to empty policy engine.
        # If all policy files fail to parse, keep the previous (working) engine.
        if not new_policies and self._policies and len(self._policies) > 0:
            await logger.aerror("policy_reload_rejected", reason="new_engine_empty", keeping="previous")
            return

        # SECURITY FIX (M-03): Atomic swap with version monotonic counter.
        # The version counter allows request handlers to detect mid-request
        # policy changes and re-evaluate if needed (TOCTOU mitigation).
        self._policy_version = getattr(self, "_policy_version", 0) + 1
        self.engine = new_engine
        self._policies = new_policies
        self._file_mtimes = new_mtimes

        # SECURITY FIX (M-01): Invalidate response cache on policy reload
        # to prevent stale cached responses from bypassing updated policies
        try:
            from src.services.response_cache import get_response_cache
            get_response_cache().clear()
        except Exception:  # noqa: S110 — cache may not be initialized yet; invalidation is best-effort
            pass  # Cache may not be initialized yet

        await logger.ainfo("policy_reload_complete", count=len(new_policies), version=self._policy_version)

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
                        mtime = self._file_version(Path(fpath).stat())
                        if self._file_mtimes.get(fpath) != mtime:
                            changed = True
                            break

                if changed:
                    await self.reload()
            except asyncio.CancelledError:
                break
            except Exception as e:
                await logger.aerror("policy_poll_error", error=str(e))
