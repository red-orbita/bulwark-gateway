"""Admin -> proxy shared-state sync contract (agents registry).

In every deployment the admin service *owns* the agent registry: it seeds and
writes ``agents.yaml`` into its writable data dir (admin_data volume in Docker
Compose, admin-data PVC in Helm), and the proxy reads that same file read-only
(``BULWARK_AGENTS_FILE`` -> ``/app/shared/admin/agents.yaml``).

If that wiring is broken (e.g. the proxy reads a different, static file, as it
did in Docker Compose before parity was fixed), tenant/agent changes made in the
admin UI never reach the proxy hot path and backend routing silently goes stale.

These tests lock the contract at the unit level, independent of container mounts:

* the admin seeds ``agents.yaml`` on first init and the proxy registry loads it,
* a tenant/agent created through the admin API is visible to a fresh proxy
  registry pointed at the same file (positive), and
* a proxy registry pointed at a non-existent file degrades gracefully with an
  empty registry instead of crashing (negative).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from admin.models.tenants import AgentCreate, TenantCreate
from admin.services.tenant_manager import TenantManager
from src.services.agent_registry import AgentRegistry

_SEED_YAML = textwrap.dedent(
    """
    defaults:
      backend_url: http://seed-backend:11434
      timeout: 30.0
    tenants:
      acme:
        agents:
          bot:
            path_prefix: /v1
            model: tinyllama
            status: active
    """
).strip()


@pytest.fixture
def seeded_cwd(monkeypatch, tmp_path):
    """A tmp working dir containing the read-only image seed at config/agents.yaml."""
    seed_dir = tmp_path / "config"
    seed_dir.mkdir()
    (seed_dir / "agents.yaml").write_text(_SEED_YAML)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_admin_seeds_agents_file_proxy_reads_it(seeded_cwd):
    """Positive: admin seeds the shared file; proxy registry loads the seeded agent."""
    shared = seeded_cwd / "shared" / "admin" / "agents.yaml"

    # --- admin process: TenantManager seeds the writable/shared copy on init ---
    TenantManager(config_path=shared)
    assert shared.exists(), "admin must seed agents.yaml into the shared path"

    # --- proxy process: AgentRegistry reads the SAME file ---
    registry = AgentRegistry(config_path=shared)
    import asyncio

    asyncio.run(registry.load())
    assert registry.count >= 1
    assert registry.resolve("acme", "bot") is not None


def test_admin_crud_reaches_proxy(seeded_cwd):
    """Round-trip: a tenant/agent created via the admin API is seen by the proxy."""
    shared = seeded_cwd / "shared" / "admin" / "agents.yaml"

    manager = TenantManager(config_path=shared)
    manager.create_tenant(TenantCreate(id="newco", name="New Co"))
    manager.create_agent(
        AgentCreate(agent_id="assistant", tenant_id="newco", backend_url="http://newco-llm:8000")
    )

    # Fresh proxy registry (simulates the separate proxy process) loads from disk.
    import asyncio

    registry = AgentRegistry(config_path=shared)
    asyncio.run(registry.load())

    backend = registry.resolve("newco", "assistant")
    assert backend is not None
    assert backend.backend_url == "http://newco-llm:8000"
    # Seeded agent from the original file is still present.
    assert registry.resolve("acme", "bot") is not None


def test_proxy_missing_agents_file_is_graceful(tmp_path):
    """Negative: proxy pointed at a non-existent file must not crash (empty registry)."""
    import asyncio

    registry = AgentRegistry(config_path=tmp_path / "does-not-exist.yaml")
    asyncio.run(registry.load())
    assert registry.count == 0
    assert registry.resolve("acme", "bot") is None


def test_env_var_drives_proxy_agents_path(monkeypatch, tmp_path):
    """BULWARK_AGENTS_FILE must govern where the proxy reads the registry from."""
    target = tmp_path / "shared" / "admin" / "agents.yaml"
    monkeypatch.setenv("BULWARK_AGENTS_FILE", str(target))
    registry = AgentRegistry()
    assert registry.config_path == Path(str(target))
