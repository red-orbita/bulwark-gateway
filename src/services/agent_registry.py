"""
Agent Registry — Resolves backend URLs per tenant/agent.

Loads from config/agents.yaml, hot-reloadable via admin endpoint.
Provides dynamic routing so sentinel-gateway can proxy to multiple backends.
Loads per-tenant quota configuration for resource isolation.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import structlog
import yaml

from src.middleware.quotas import (
    TenantQuotaConfig,
    clear_tenant_quotas,
    register_tenant_quotas,
)

logger = structlog.get_logger()

# M-03: Expand ${VAR:-default} patterns in config values
_ENV_PATTERN = re.compile(r'\$\{([^}:]+)(?::-([^}]*))?\}')


def _expand_env(value):
    """Expand environment variables in string values (${VAR:-default} syntax)."""
    if not isinstance(value, str):
        return value
    def _replace(m):
        var_name = m.group(1)
        default = m.group(2) or ""
        return os.environ.get(var_name, default)
    return _ENV_PATTERN.sub(_replace, value)


@dataclass
class AgentBackend:
    """Backend configuration for a specific agent."""

    backend_url: str
    timeout: float = 120.0
    description: str = ""
    auth_header: str | None = None
    auth_token: str | None = None  # H-04: Backend auth from config, not client headers
    health_endpoint: str = "/health"
    path_prefix: str = "/v1"
    trusted: bool = True  # Backends from config are operator-trusted (skip SSRF check)
    fallback_backends: list["AgentBackend"] = field(default_factory=list)
    max_retries: int = 1  # 0 = no retry, 1 = try fallback once


@dataclass
class AgentRegistryDefaults:
    """Default backend config for unregistered agents."""

    backend_url: str = "http://localhost:11434"
    timeout: float = 120.0
    auth_header: str | None = None
    health_endpoint: str = "/health"


class AgentRegistry:
    """Resolves tenant/agent pairs to backend configurations.

    Lookup order:
      1. Exact match: tenants[tenant_id].agents[agent_id]
      2. Tenant default: tenants[tenant_id].agents["*"] (wildcard)
      3. Global default: defaults section
    """

    def __init__(self, config_path: Path | None = None):
        # Prefer shared PVC path (written by admin), fallback to image seed
        if config_path:
            self.config_path = config_path
        else:
            env_path = os.environ.get("SENTINEL_AGENTS_FILE")
            self.config_path = Path(env_path) if env_path else Path("config/agents.yaml")
        self._agents: dict[str, AgentBackend] = {}  # key: "tenant:agent"
        self._defaults = AgentRegistryDefaults()
        self._mtime: float = 0.0

    @property
    def count(self) -> int:
        return len(self._agents)

    def _file_changed(self) -> bool:
        try:
            return os.path.getmtime(self.config_path) != self._mtime
        except OSError:
            return False

    async def load(self):
        """Load agent registry from YAML config."""
        if not self.config_path.exists():
            await logger.awarn("agent_registry_missing", path=str(self.config_path))
            return

        try:
            mtime = os.path.getmtime(self.config_path)
            with open(self.config_path) as f:
                data = yaml.safe_load(f) or {}

            new_agents: dict[str, AgentBackend] = {}

            # Parse defaults
            defaults = data.get("defaults", {})
            self._defaults = AgentRegistryDefaults(
                backend_url=_expand_env(defaults.get("backend_url", "http://localhost:11434")),
                timeout=defaults.get("timeout", 120.0),
                auth_header=defaults.get("auth_header"),
                health_endpoint=defaults.get("health_endpoint", "/health"),
            )

            # Parse tenant agents and quotas
            tenants = data.get("tenants", {})
            clear_tenant_quotas()  # Reset before reload
            tenants_with_quotas = 0

            for tenant_id, tenant_data in tenants.items():
                if not isinstance(tenant_data, dict):
                    continue

                # Parse per-tenant quotas
                quotas_cfg = tenant_data.get("quotas")
                if isinstance(quotas_cfg, dict):
                    quota = TenantQuotaConfig(
                        max_concurrent_requests=quotas_cfg.get(
                            "max_concurrent_requests", 0
                        ),
                        max_tokens_per_day=quotas_cfg.get("max_tokens_per_day", 0),
                        max_request_size_bytes=quotas_cfg.get(
                            "max_request_size_bytes", 0
                        ),
                        allowed_models=quotas_cfg.get("allowed_models"),
                        priority_weight=quotas_cfg.get("priority_weight", 1.0),
                        rate_limit_rpm=quotas_cfg.get("rate_limit_rpm", 0),
                    )
                    register_tenant_quotas(tenant_id, quota)
                    tenants_with_quotas += 1

                # Parse agents
                agents = tenant_data.get("agents", {})
                for agent_id, agent_cfg in agents.items():
                    if not isinstance(agent_cfg, dict):
                        continue
                    key = f"{tenant_id}:{agent_id}"

                    # Parse fallback backends
                    fallbacks = []
                    for fb_cfg in agent_cfg.get("fallback_backends", []):
                        if isinstance(fb_cfg, dict):
                            fallbacks.append(AgentBackend(
                                backend_url=_expand_env(fb_cfg.get("backend_url", "")),
                                timeout=fb_cfg.get("timeout", self._defaults.timeout),
                                auth_header=fb_cfg.get("auth_header"),
                                auth_token=fb_cfg.get("auth_token"),
                                health_endpoint=fb_cfg.get("health_endpoint", "/health"),
                                path_prefix=fb_cfg.get("path_prefix", "/v1"),
                            ))

                    new_agents[key] = AgentBackend(
                        backend_url=_expand_env(agent_cfg.get("backend_url", self._defaults.backend_url)),
                        timeout=agent_cfg.get("timeout", self._defaults.timeout),
                        description=agent_cfg.get("description", ""),
                        auth_header=agent_cfg.get("auth_header", self._defaults.auth_header),
                        auth_token=agent_cfg.get("auth_token"),  # H-04: from config only
                        health_endpoint=agent_cfg.get(
                            "health_endpoint", self._defaults.health_endpoint
                        ),
                        path_prefix=agent_cfg.get("path_prefix", "/v1"),
                        fallback_backends=fallbacks,
                        max_retries=agent_cfg.get("max_retries", 1 if fallbacks else 0),
                    )

            # Atomic swap
            self._agents = new_agents
            self._mtime = mtime

            await logger.ainfo(
                "agent_registry_loaded",
                agents=len(self._agents),
                tenants=len(tenants),
                tenants_with_quotas=tenants_with_quotas,
            )
        except Exception as e:
            await logger.aerror("agent_registry_load_error", error=str(e))

    def resolve(self, tenant_id: str, agent_id: str) -> AgentBackend | None:
        """Resolve backend for tenant/agent pair.

        Lookup order:
          1. Exact: tenant_id:agent_id
          2. Wildcard: tenant_id:*
          3. None (M-02: reject unregistered tenants — no global fallback)
        """
        # Exact match
        key = f"{tenant_id}:{agent_id}"
        if key in self._agents:
            return self._agents[key]

        # Tenant wildcard
        wildcard = f"{tenant_id}:*"
        if wildcard in self._agents:
            return self._agents[wildcard]

        # M-02: Do NOT fall back to global defaults for unknown tenants
        return None

    def list_agents(self) -> list[dict]:
        """List all registered agents."""
        result = []
        for key, backend in self._agents.items():
            tenant_id, agent_id = key.split(":", 1)
            result.append(
                {
                    "tenant_id": tenant_id,
                    "agent_id": agent_id,
                    "backend_url": backend.backend_url,
                    "timeout": backend.timeout,
                    "description": backend.description,
                }
            )
        return result

    def register(self, tenant_id: str, agent_id: str, backend: AgentBackend):
        """Register or update an agent backend (runtime, not persisted)."""
        self._agents[f"{tenant_id}:{agent_id}"] = backend

    def unregister(self, tenant_id: str, agent_id: str) -> bool:
        """Remove an agent from the registry."""
        key = f"{tenant_id}:{agent_id}"
        if key in self._agents:
            del self._agents[key]
            return True
        return False
