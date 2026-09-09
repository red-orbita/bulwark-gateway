"""Tests for Agent Registry — multi-backend routing."""


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


class TestEnvExpansionScope:
    """S-23: ``_expand_env`` must not resolve Bulwark's own process secrets
    (all under the ``BULWARK_`` namespace, except the documented
    ``BULWARK_BACKEND*`` routing var) into a backend URL — even though today the
    config is operator-authored, this is defense-in-depth against a future
    delegated config-write surface."""

    def test_backend_var_still_expands(self, monkeypatch):
        from src.services.agent_registry import _expand_env

        monkeypatch.setenv("BULWARK_BACKEND_URL", "http://real-backend:9000")
        assert _expand_env("${BULWARK_BACKEND_URL}") == "http://real-backend:9000"
        # ...and the documented ${VAR:-default} default form is preserved.
        monkeypatch.delenv("BULWARK_BACKEND_URL", raising=False)
        assert _expand_env("${BULWARK_BACKEND_URL:-http://d:1}") == "http://d:1"

    def test_secret_var_is_never_expanded(self, monkeypatch):
        from src.services.agent_registry import _expand_env

        monkeypatch.setenv("BULWARK_JWT_SECRET", "super-secret-value")
        # No default → collapses to empty, NEVER the secret value.
        assert "super-secret-value" not in _expand_env("http://x/${BULWARK_JWT_SECRET}")
        assert _expand_env("${BULWARK_JWT_SECRET}") == ""

    def test_secret_var_with_default_uses_default_not_secret(self, monkeypatch):
        from src.services.agent_registry import _expand_env

        monkeypatch.setenv("BULWARK_API_KEYS", "k1,k2,k3")
        assert _expand_env("${BULWARK_API_KEYS:-none}") == "none"

    def test_other_sensitive_bulwark_vars_blocked(self, monkeypatch):
        from src.services.agent_registry import _expand_env

        for name in ("BULWARK_REDIS_PASSWORD", "BULWARK_KEY_ENCRYPTION_KEY", "BULWARK_OTX_KEY"):
            monkeypatch.setenv(name, "leak-me")
            assert _expand_env("${%s}" % name) == ""

    def test_operator_owned_non_bulwark_var_still_expands(self, monkeypatch):
        from src.services.agent_registry import _expand_env

        # The operator's OWN environment is not in the threat model.
        monkeypatch.setenv("OLLAMA_HOST", "http://ollama:11434")
        assert _expand_env("${OLLAMA_HOST}") == "http://ollama:11434"
        monkeypatch.setenv("BACKEND_IP", "10.0.0.5")
        assert _expand_env("http://${BACKEND_IP}:8080") == "http://10.0.0.5:8080"

    @pytest.mark.asyncio
    async def test_backend_url_cannot_leak_secret_through_config(self, tmp_path, monkeypatch):
        """End-to-end: a backend_url referencing a secret resolves WITHOUT it."""
        monkeypatch.setenv("BULWARK_JWT_SECRET", "top-secret-jwt")
        cfg = {
            "defaults": {"backend_url": "http://d:1"},
            "tenants": {
                "t": {"agents": {"a": {"backend_url": "http://evil/${BULWARK_JWT_SECRET}"}}}
            },
        }
        path = tmp_path / "agents.yaml"
        path.write_text(yaml.safe_dump(cfg))
        reg = AgentRegistry(path)
        await reg.load()
        backend = reg.resolve("t", "a")
        assert backend is not None
        assert "top-secret-jwt" not in backend.backend_url
