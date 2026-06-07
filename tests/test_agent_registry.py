"""Tests for Agent Registry — multi-backend routing."""

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from src.services.agent_registry import AgentBackend, AgentRegistry


@pytest.fixture
def registry_file(tmp_path):
    config = {
        "defaults": {
            "backend_url": "http://default-llm:8080",
            "timeout": 60.0,
        },
        "tenants": {
            "example-corp": {
                "agents": {
                    "support-bot": {
                        "backend_url": "http://support-llm:8080",
                        "timeout": 30.0,
                        "description": "Support chatbot",
                    },
                    "code-assist": {
                        "backend_url": "http://code-llm:8080",
                        "timeout": 120.0,
                    },
                }
            },
            "healthcare": {
                "agents": {
                    "*": {
                        "backend_url": "http://hipaa-llm:8080",
                        "timeout": 45.0,
                        "description": "HIPAA-compliant default",
                    },
                    "clinical": {
                        "backend_url": "http://clinical-llm:8080",
                        "timeout": 30.0,
                    },
                }
            },
        },
    }
    p = tmp_path / "agents.yaml"
    p.write_text(yaml.dump(config))
    return p


class TestAgentRegistry:
    @pytest.mark.asyncio
    async def test_load_from_yaml(self, registry_file):
        reg = AgentRegistry(registry_file)
        await reg.load()
        assert reg.count == 4  # 2 example-corp + 2 healthcare

    @pytest.mark.asyncio
    async def test_exact_match(self, registry_file):
        reg = AgentRegistry(registry_file)
        await reg.load()
        backend = reg.resolve("example-corp", "support-bot")
        assert backend.backend_url == "http://support-llm:8080"
        assert backend.timeout == 30.0

    @pytest.mark.asyncio
    async def test_wildcard_tenant(self, registry_file):
        """Tenant with '*' agent catches all unmatched agents."""
        reg = AgentRegistry(registry_file)
        await reg.load()
        # Unknown agent in healthcare → falls to wildcard
        backend = reg.resolve("healthcare", "unknown-agent")
        assert backend.backend_url == "http://hipaa-llm:8080"

    @pytest.mark.asyncio
    async def test_exact_over_wildcard(self, registry_file):
        """Exact match takes priority over wildcard."""
        reg = AgentRegistry(registry_file)
        await reg.load()
        backend = reg.resolve("healthcare", "clinical")
        assert backend.backend_url == "http://clinical-llm:8080"

    @pytest.mark.asyncio
    async def test_global_default(self, registry_file):
        """Unknown tenant/agent returns None (M-02: reject unregistered)."""
        reg = AgentRegistry(registry_file)
        await reg.load()
        backend = reg.resolve("unknown-tenant", "unknown-agent")
        assert backend is None

    @pytest.mark.asyncio
    async def test_runtime_register(self, registry_file):
        reg = AgentRegistry(registry_file)
        await reg.load()
        assert reg.count == 4

        reg.register(
            "new-tenant",
            "new-agent",
            AgentBackend(
                backend_url="http://new-llm:9000",
                timeout=10.0,
            ),
        )
        assert reg.count == 5
        backend = reg.resolve("new-tenant", "new-agent")
        assert backend.backend_url == "http://new-llm:9000"

    @pytest.mark.asyncio
    async def test_runtime_unregister(self, registry_file):
        reg = AgentRegistry(registry_file)
        await reg.load()
        assert reg.unregister("example-corp", "support-bot") is True
        assert reg.count == 3
        # M-02: After unregister, resolve returns None (no global fallback)
        backend = reg.resolve("example-corp", "support-bot")
        assert backend is None

    @pytest.mark.asyncio
    async def test_list_agents(self, registry_file):
        reg = AgentRegistry(registry_file)
        await reg.load()
        agents = reg.list_agents()
        assert len(agents) == 4
        assert any(a["agent_id"] == "support-bot" for a in agents)
        assert any(a["tenant_id"] == "healthcare" for a in agents)

    @pytest.mark.asyncio
    async def test_missing_config_file(self, tmp_path):
        """Missing config → no agents, resolve returns None (M-02)."""
        reg = AgentRegistry(tmp_path / "nonexistent.yaml")
        await reg.load()
        assert reg.count == 0
        backend = reg.resolve("any", "agent")
        assert backend is None
