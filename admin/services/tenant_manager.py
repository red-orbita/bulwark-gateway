"""Tenant & Agent manager — business logic with YAML persistence."""
import logging
import os
import shutil
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
import yaml

from admin.models.tenants import (
    AgentCreate,
    AgentInfo,
    AgentStatus,
    AgentUpdate,
    DefaultsInfo,
    DefaultsUpdate,
    HealthCheckResponse,
    HealthStatus,
    TenantCreate,
    TenantInfo,
    TenantStatus,
    TenantUpdate,
)

logger = logging.getLogger(__name__)

_instance: Optional["TenantManager"] = None
_lock = threading.Lock()


def get_tenant_manager() -> "TenantManager":
    """Singleton accessor for TenantManager."""
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = TenantManager()
    return _instance


# Writable path for agent config (env-configurable, defaults to persistent volume)
_AGENTS_DATA_DIR = os.environ.get("SENTINEL_AGENTS_DATA_DIR", "/app/data")
_AGENTS_SEED_PATH = Path("config/agents.yaml")  # Read-only seed from image


class TenantManager:
    """Manages tenants and agents with YAML persistence.

    On first startup, copies the seed config from the read-only image
    (config/agents.yaml) to the writable data volume. Subsequent reads
    and writes use the writable copy.
    """

    def __init__(self, config_path: Path | None = None):
        self._config_path = config_path or Path(_AGENTS_DATA_DIR) / "agents.yaml"
        self._seed_path = _AGENTS_SEED_PATH
        self._data: dict = {}
        self._rw_lock = threading.RLock()
        self._ensure_writable_copy()
        self._load()

    def _ensure_writable_copy(self):
        """Copy seed config to writable path if it doesn't exist yet."""
        if self._config_path.exists():
            return
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        if self._seed_path.exists():
            shutil.copy2(self._seed_path, self._config_path)
            logger.warning("agents_config_seeded src=%s dst=%s", self._seed_path, self._config_path)
        else:
            # No seed — start with empty config
            with open(self._config_path, "w") as f:
                yaml.safe_dump({"tenants": {}}, f)
            logger.warning("agents_config_created dst=%s", self._config_path)

    def _load(self):
        """Load config from YAML."""
        if self._config_path.exists():
            with open(self._config_path) as f:
                self._data = yaml.safe_load(f) or {}
        if "tenants" not in self._data:
            self._data["tenants"] = {}

    def persist(self):
        """Write state back to agents.yaml.

        Note: uses direct write (not atomic rename) for Docker bind-mount compatibility.
        """
        with self._rw_lock:
            try:
                with open(self._config_path, "w") as f:
                    yaml.safe_dump(self._data, f, default_flow_style=False, sort_keys=False)
            except OSError as e:
                logger.error("agents_config_persist_failed path=%s error=%s", self._config_path, e)
                raise RuntimeError(f"Failed to persist agent config: {e}") from e

    # --- Tenant helpers ---

    def _tenant_meta(self, tenant_id: str) -> dict:
        """Get or create tenant metadata sub-dict."""
        tenant = self._data["tenants"].setdefault(tenant_id, {})
        return tenant.setdefault("_meta", {})

    # --- Tenant CRUD ---

    def list_tenants(self) -> list[TenantInfo]:
        with self._rw_lock:
            results = []
            for tid, tdata in self._data.get("tenants", {}).items():
                if not isinstance(tdata, dict):
                    continue
                meta = tdata.get("_meta", {})
                agents = tdata.get("agents", {})
                results.append(TenantInfo(
                    id=tid,
                    name=meta.get("name", tid),
                    status=TenantStatus(meta.get("status", "active")),
                    agent_count=len(agents) if isinstance(agents, dict) else 0,
                    contact_email=meta.get("contact_email"),
                    created_at=meta.get("created_at"),
                ))
            return results

    def get_tenant(self, tenant_id: str) -> Optional[TenantInfo]:
        with self._rw_lock:
            tdata = self._data.get("tenants", {}).get(tenant_id)
            if tdata is None or not isinstance(tdata, dict):
                return None
            meta = tdata.get("_meta", {})
            agents = tdata.get("agents", {})
            return TenantInfo(
                id=tenant_id,
                name=meta.get("name", tenant_id),
                status=TenantStatus(meta.get("status", "active")),
                agent_count=len(agents) if isinstance(agents, dict) else 0,
                contact_email=meta.get("contact_email"),
                created_at=meta.get("created_at"),
            )

    def create_tenant(self, req: TenantCreate) -> TenantInfo:
        with self._rw_lock:
            if req.id in self._data["tenants"]:
                raise ValueError(f"Tenant '{req.id}' already exists")
            now = datetime.now(timezone.utc).isoformat()
            self._data["tenants"][req.id] = {
                "_meta": {
                    "name": req.name,
                    "status": "active",
                    "contact_email": req.contact_email,
                    "created_at": now,
                },
                "agents": {},
            }
            self.persist()
            return TenantInfo(
                id=req.id,
                name=req.name,
                status=TenantStatus.ACTIVE,
                agent_count=0,
                contact_email=req.contact_email,
                created_at=now,
            )

    def update_tenant(self, tenant_id: str, req: TenantUpdate) -> Optional[TenantInfo]:
        with self._rw_lock:
            tdata = self._data["tenants"].get(tenant_id)
            if tdata is None:
                return None
            meta = tdata.setdefault("_meta", {})
            if req.name is not None:
                meta["name"] = req.name
            if req.status is not None:
                meta["status"] = req.status.value
            if req.contact_email is not None:
                meta["contact_email"] = req.contact_email
            self.persist()
            return self.get_tenant(tenant_id)

    def delete_tenant(self, tenant_id: str) -> bool:
        """Hard-delete: remove tenant and all its agents."""
        with self._rw_lock:
            if tenant_id not in self._data["tenants"]:
                return False
            del self._data["tenants"][tenant_id]
            self.persist()
            return True

    def pause_tenant(self, tenant_id: str) -> Optional[TenantInfo]:
        """Toggle pause state."""
        with self._rw_lock:
            tdata = self._data["tenants"].get(tenant_id)
            if tdata is None:
                return None
            meta = tdata.setdefault("_meta", {})
            current = meta.get("status", "active")
            meta["status"] = "active" if current == "paused" else "paused"
            self.persist()
            return self.get_tenant(tenant_id)

    # --- Agent CRUD ---

    def list_agents_for_tenant(self, tenant_id: str) -> Optional[list[AgentInfo]]:
        with self._rw_lock:
            tdata = self._data["tenants"].get(tenant_id)
            if tdata is None:
                return None
            agents = tdata.get("agents", {})
            return [self._agent_to_info(tenant_id, aid, acfg) for aid, acfg in agents.items() if isinstance(acfg, dict)]

    def list_all_agents(self) -> list[AgentInfo]:
        with self._rw_lock:
            results = []
            for tid, tdata in self._data.get("tenants", {}).items():
                if not isinstance(tdata, dict):
                    continue
                for aid, acfg in tdata.get("agents", {}).items():
                    if isinstance(acfg, dict):
                        results.append(self._agent_to_info(tid, aid, acfg))
            return results

    def create_agent(self, req: AgentCreate) -> AgentInfo:
        with self._rw_lock:
            tdata = self._data["tenants"].get(req.tenant_id)
            if tdata is None:
                raise KeyError(f"Tenant '{req.tenant_id}' not found")
            agents = tdata.setdefault("agents", {})
            if req.agent_id in agents:
                raise ValueError(f"Agent '{req.agent_id}' already exists in tenant '{req.tenant_id}'")
            cfg: dict = {
                "backend_url": req.backend_url,
                "timeout": req.timeout,
                "health_endpoint": req.health_endpoint,
                "path_prefix": req.path_prefix,
                "status": "active",
            }
            if req.model:
                cfg["model"] = req.model
            if req.auth_header:
                cfg["auth_header"] = req.auth_header
            if req.description:
                cfg["description"] = req.description
            agents[req.agent_id] = cfg
            self.persist()
            return self._agent_to_info(req.tenant_id, req.agent_id, cfg)

    def update_agent(self, tenant_id: str, agent_id: str, req: AgentUpdate) -> Optional[AgentInfo]:
        with self._rw_lock:
            tdata = self._data["tenants"].get(tenant_id)
            if tdata is None:
                return None
            agents = tdata.get("agents", {})
            if agent_id not in agents:
                return None
            cfg = agents[agent_id]
            for field in ("backend_url", "model", "timeout", "health_endpoint", "path_prefix", "auth_header", "description"):
                val = getattr(req, field, None)
                if val is not None:
                    cfg[field] = val
            if req.status is not None:
                cfg["status"] = req.status.value
            self.persist()
            return self._agent_to_info(tenant_id, agent_id, cfg)

    def delete_agent(self, tenant_id: str, agent_id: str) -> bool:
        with self._rw_lock:
            tdata = self._data["tenants"].get(tenant_id)
            if tdata is None:
                return False
            agents = tdata.get("agents", {})
            if agent_id not in agents:
                return False
            del agents[agent_id]
            self.persist()
            return True

    def pause_agent(self, tenant_id: str, agent_id: str) -> Optional[AgentInfo]:
        with self._rw_lock:
            tdata = self._data["tenants"].get(tenant_id)
            if tdata is None:
                return None
            agents = tdata.get("agents", {})
            if agent_id not in agents:
                return None
            cfg = agents[agent_id]
            current = cfg.get("status", "active")
            cfg["status"] = "active" if current == "paused" else "paused"
            self.persist()
            return self._agent_to_info(tenant_id, agent_id, cfg)

    async def health_check(self, tenant_id: str, agent_id: str) -> Optional[HealthCheckResponse]:
        with self._rw_lock:
            tdata = self._data["tenants"].get(tenant_id)
            if tdata is None:
                return None
            agents = tdata.get("agents", {})
            if agent_id not in agents:
                return None
            cfg = agents[agent_id]
            url = cfg.get("backend_url", "") + cfg.get("health_endpoint", "/health")

        now = datetime.now(timezone.utc)
        try:
            start = time.monotonic()
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)
            latency = (time.monotonic() - start) * 1000
            status = HealthStatus.HEALTHY if resp.status_code < 400 else HealthStatus.UNHEALTHY
        except Exception:
            latency = None
            status = HealthStatus.UNHEALTHY

        return HealthCheckResponse(
            agent_id=agent_id,
            status=status,
            latency_ms=round(latency, 2) if latency else None,
            last_checked=now,
        )

    # --- Defaults CRUD ---

    def get_defaults(self) -> DefaultsInfo:
        """Get global agent defaults."""
        with self._rw_lock:
            defaults = self._data.get("defaults", {})
            return DefaultsInfo(
                backend_url=defaults.get("backend_url", "http://ollama:11434"),
                timeout=defaults.get("timeout", 120.0),
                auth_header=defaults.get("auth_header"),
                health_endpoint=defaults.get("health_endpoint", "/health"),
            )

    def update_defaults(self, req: DefaultsUpdate) -> DefaultsInfo:
        """Update global agent defaults."""
        with self._rw_lock:
            defaults = self._data.setdefault("defaults", {})
            if req.backend_url is not None:
                defaults["backend_url"] = req.backend_url
            if req.timeout is not None:
                defaults["timeout"] = req.timeout
            if req.auth_header is not None:
                defaults["auth_header"] = req.auth_header if req.auth_header != "" else None
            if req.health_endpoint is not None:
                defaults["health_endpoint"] = req.health_endpoint
            self.persist()
            return self.get_defaults()

    # --- Helpers ---

    @staticmethod
    def _agent_to_info(tenant_id: str, agent_id: str, cfg: dict) -> AgentInfo:
        return AgentInfo(
            agent_id=agent_id,
            tenant_id=tenant_id,
            backend_url=cfg.get("backend_url", ""),
            model=cfg.get("model"),
            timeout=cfg.get("timeout", 120.0),
            status=AgentStatus(cfg.get("status", "active")),
            health_endpoint=cfg.get("health_endpoint", "/health"),
            path_prefix=cfg.get("path_prefix", "/v1"),
            auth_header=cfg.get("auth_header"),
            allowed_tools=cfg.get("allowed_tools"),
            denied_tools=cfg.get("denied_tools"),
            description=cfg.get("description"),
        )
