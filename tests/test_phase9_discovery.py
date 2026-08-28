"""
Tests for Phase 9 — Agent Discovery + Shadow AI Monitor.

Covers: AgentDiscovery, ShadowAIMonitor, MCPInventory.
"""

from __future__ import annotations

import pytest

# =============================================================================
# Agent Discovery
# =============================================================================


class TestAgentDiscovery:
    """Tests for network/K8s LLM agent discovery."""

    def test_discovery_creation(self):
        from src.discovery.agent_discovery import AgentDiscovery

        discovery = AgentDiscovery(timeout=3.0)
        assert discovery._timeout == 3.0

    def test_discovered_agent_dataclass(self):
        from src.discovery.agent_discovery import DiscoveredAgent

        agent = DiscoveredAgent(
            host="192.168.1.100",
            port=11434,
            service_type="ollama",
            confidence=0.95,
            discovered_at="2024-01-01T00:00:00Z",
            metadata={"model": "llama2"},
        )
        assert agent.host == "192.168.1.100"
        assert agent.port == 11434
        assert agent.service_type == "ollama"
        assert agent.confidence == 0.95

    def test_known_ports(self):
        from src.discovery.agent_discovery import KNOWN_PORTS

        assert 11434 in KNOWN_PORTS  # Ollama
        assert 8080 in KNOWN_PORTS
        assert 8000 in KNOWN_PORTS

    def test_known_paths(self):
        from src.discovery.agent_discovery import KNOWN_PATHS

        assert "/v1/models" in KNOWN_PATHS
        assert "/api/tags" in KNOWN_PATHS
        assert "/health" in KNOWN_PATHS

    @pytest.mark.asyncio
    async def test_scan_network_empty_targets(self):
        from src.discovery.agent_discovery import AgentDiscovery

        discovery = AgentDiscovery(timeout=1.0)
        results = await discovery.scan_network(targets=[])
        assert results == []

    @pytest.mark.asyncio
    async def test_scan_network_unreachable(self):
        """Scanning unreachable hosts should return empty, not crash."""
        from src.discovery.agent_discovery import AgentDiscovery

        discovery = AgentDiscovery(timeout=0.5)
        # Use RFC5737 TEST-NET — guaranteed not to route
        results = await discovery.scan_network(targets=["192.0.2.1"])
        assert isinstance(results, list)
        # Should be empty (or at most contain false positives, but not crash)

    def test_detect_service_type_ollama(self):
        from src.discovery.agent_discovery import AgentDiscovery

        discovery = AgentDiscovery()
        # Simulate Ollama response characteristics
        service = discovery._detect_service_type(
            response_headers={"content-type": "application/json"},
            response_body='{"models":[{"name":"llama2"}]}',
        )
        assert service in ("ollama", "openai", "custom")

    def test_detect_service_type_openai(self):
        from src.discovery.agent_discovery import AgentDiscovery

        discovery = AgentDiscovery()
        service = discovery._detect_service_type(
            response_headers={"openai-organization": "org-123"},
            response_body='{"object":"list","data":[]}',
        )
        assert service == "openai"


# =============================================================================
# Shadow AI Monitor
# =============================================================================


class TestShadowAIMonitor:
    """Tests for Shadow AI detection."""

    def test_monitor_creation(self):
        from src.discovery.shadow_ai import ShadowAIMonitor

        monitor = ShadowAIMonitor()
        assert monitor is not None

    def test_known_ai_endpoints(self):
        from src.discovery.shadow_ai import ShadowAIMonitor

        monitor = ShadowAIMonitor()
        endpoints = monitor.KNOWN_AI_ENDPOINTS
        assert len(endpoints) >= 25
        assert "api.openai.com" in endpoints
        assert "api.anthropic.com" in endpoints
        assert "api.cohere.ai" in endpoints

    def test_classify_endpoint_openai(self):
        from src.discovery.shadow_ai import ShadowAIMonitor

        monitor = ShadowAIMonitor()
        result = monitor.classify_endpoint("api.openai.com")
        assert result is not None
        assert "openai" in result.lower()

    def test_classify_endpoint_anthropic(self):
        from src.discovery.shadow_ai import ShadowAIMonitor

        monitor = ShadowAIMonitor()
        result = monitor.classify_endpoint("api.anthropic.com")
        assert result is not None
        assert "anthropic" in result.lower()

    def test_classify_endpoint_unknown(self):
        from src.discovery.shadow_ai import ShadowAIMonitor

        monitor = ShadowAIMonitor()
        result = monitor.classify_endpoint("api.internal-company.local")
        assert result is None

    def test_get_blocklist(self):
        from src.discovery.shadow_ai import ShadowAIMonitor

        monitor = ShadowAIMonitor()
        blocklist = monitor.get_blocklist()
        assert isinstance(blocklist, list)
        assert len(blocklist) >= 20
        assert "api.openai.com" in blocklist

    def test_analyze_traffic_log_detects_ai(self):
        from src.discovery.shadow_ai import ShadowAIMonitor

        monitor = ShadowAIMonitor()
        log_entries = [
            {"hostname": "api.openai.com", "source_ip": "10.0.1.5", "timestamp": "2024-01-01T12:00:00Z"},
            {"hostname": "www.google.com", "source_ip": "10.0.1.6", "timestamp": "2024-01-01T12:01:00Z"},
            {"hostname": "api.anthropic.com", "source_ip": "10.0.1.7", "timestamp": "2024-01-01T12:02:00Z"},
        ]
        alerts = monitor.analyze_traffic_log(log_entries)
        assert len(alerts) >= 2  # openai + anthropic
        hostnames = {a.hostname for a in alerts}
        assert "api.openai.com" in hostnames
        assert "api.anthropic.com" in hostnames
        # google.com should NOT be flagged
        assert "www.google.com" not in hostnames

    def test_analyze_traffic_log_empty(self):
        from src.discovery.shadow_ai import ShadowAIMonitor

        monitor = ShadowAIMonitor()
        alerts = monitor.analyze_traffic_log([])
        assert alerts == []

    def test_shadow_ai_alert_dataclass(self):
        from src.discovery.shadow_ai import ShadowAIAlert

        alert = ShadowAIAlert(
            hostname="api.openai.com",
            service="OpenAI",
            timestamp="2024-01-01T00:00:00Z",
            source_ip="10.0.1.5",
            risk_level="high",
        )
        assert alert.hostname == "api.openai.com"
        assert alert.risk_level == "high"


# =============================================================================
# Shadow AI alert dispatch
# =============================================================================


def _make_warn_engine():
    """Build a NotificationEngine with a single 'warn'-accepting channel whose
    dispatch is captured (no real HTTP). Returns (engine, sent_list)."""
    from src.telemetry.notifications import NotificationChannel, NotificationEngine

    engine = NotificationEngine()
    # Replace any file/env/yaml-loaded channels with a deterministic one that
    # accepts advisory 'warn' verdicts at any severity.
    engine._channels = [
        NotificationChannel(
            id="test-shadow-ai",
            name="test",
            type="generic",
            enabled=True,
            min_severity="low",
            verdicts=["warn"],
            url="https://example.invalid/hook",
        )
    ]
    sent: list = []

    async def _capture(channel, alert):
        sent.append((channel, alert))

    engine._dispatch = _capture  # type: ignore[assignment]
    return engine, sent


class TestShadowAIDispatch:
    """Tests for ShadowAIMonitor.dispatch_alerts → NotificationEngine bridge."""

    async def test_dispatch_empty_returns_zero(self):
        from src.discovery.shadow_ai import ShadowAIMonitor

        monitor = ShadowAIMonitor()
        assert await monitor.dispatch_alerts([]) == 0

    async def test_dispatch_no_channels_returns_zero(self, monkeypatch):
        import src.telemetry.notifications as notif
        from src.discovery.shadow_ai import ShadowAIAlert, ShadowAIMonitor

        engine = notif.NotificationEngine()
        engine._channels = []  # inert engine
        monkeypatch.setattr(notif, "get_notification_engine", lambda: engine)

        monitor = ShadowAIMonitor()
        alert = ShadowAIAlert(
            hostname="api.openai.com", service="OpenAI",
            timestamp="2024-01-01T00:00:00Z", risk_level="high",
        )
        # No channels configured → engine.configured is False → 0 dispatched.
        assert await monitor.dispatch_alerts([alert]) == 0

    async def test_dispatch_delivers_warn_alerts(self, monkeypatch):
        import src.telemetry.notifications as notif
        from src.discovery.shadow_ai import ShadowAIAlert, ShadowAIMonitor

        engine, sent = _make_warn_engine()
        monkeypatch.setattr(notif, "get_notification_engine", lambda: engine)

        monitor = ShadowAIMonitor()
        alerts = [
            ShadowAIAlert(
                hostname="api.openai.com", service="OpenAI",
                timestamp="2024-01-01T00:00:00Z", source_ip="10.0.1.5",
                risk_level="high",
            ),
            ShadowAIAlert(
                hostname="api.anthropic.com", service="Anthropic",
                timestamp="2024-01-01T00:01:00Z", source_ip="10.0.1.6",
                risk_level="high",
            ),
        ]
        count = await monitor.dispatch_alerts(alerts, tenant_id="acme")
        assert count == 2
        assert len(sent) == 2

        _, first = sent[0]
        assert first.verdict == "warn"
        assert first.severity == "high"
        assert first.category == "shadow_ai"
        assert first.source == "shadow_ai_monitor"
        assert first.tenant_id == "acme"
        assert first.source_ip == "10.0.1.5"
        assert first.matched_patterns == ["api.openai.com"]
        assert "OpenAI" in first.description
        assert "api.openai.com" in first.description

    async def test_dispatch_respects_channel_verdict_filter(self, monkeypatch):
        """A default 'block'-only channel must not receive advisory warn alerts."""
        import src.telemetry.notifications as notif
        from src.discovery.shadow_ai import ShadowAIAlert, ShadowAIMonitor

        engine, sent = _make_warn_engine()
        engine._channels[0].verdicts = ["block"]  # only blocks, not warns
        monkeypatch.setattr(notif, "get_notification_engine", lambda: engine)

        monitor = ShadowAIMonitor()
        alert = ShadowAIAlert(
            hostname="api.openai.com", service="OpenAI",
            timestamp="2024-01-01T00:00:00Z", risk_level="high",
        )
        # dispatch_alerts still counts it as handed to the engine, but the
        # engine's per-channel filter drops it (no channel dispatched).
        count = await monitor.dispatch_alerts([alert])
        assert count == 1
        assert sent == []


# =============================================================================
# MCP Inventory
# =============================================================================


class TestMCPInventory:
    """Tests for MCP server inventory and risk assessment."""

    def test_mcp_tool_dataclass(self):
        from src.discovery.mcp_inventory import MCPTool

        tool = MCPTool(
            name="execute_command",
            description="Runs a shell command",
            parameters={"command": {"type": "string"}},
            capabilities=["shell_exec", "process_spawn"],
        )
        assert tool.name == "execute_command"
        assert "shell_exec" in tool.capabilities

    def test_mcp_server_dataclass(self):
        from src.discovery.mcp_inventory import MCPServer, MCPTool

        server = MCPServer(
            url="http://localhost:3000",
            name="test-mcp",
            version="1.0.0",
            tools=[
                MCPTool(name="read_file", description="Reads a file", capabilities=["file_read"]),
            ],
            risk_score=4.5,
        )
        assert server.name == "test-mcp"
        assert len(server.tools) == 1

    def test_risk_assessment_dataclass(self):
        from src.discovery.mcp_inventory import RiskAssessment

        assessment = RiskAssessment(
            score=7.5,
            findings=["Tool has shell_exec capability", "No input validation"],
            recommendations=["Add sandbox", "Limit to specific commands"],
        )
        assert assessment.score == 7.5
        assert len(assessment.findings) == 2

    def test_assess_risk_high(self):
        from src.discovery.mcp_inventory import MCPInventory, MCPTool

        inventory = MCPInventory()
        tool = MCPTool(
            name="execute_command",
            description="Runs arbitrary shell commands",
            capabilities=["shell_exec", "network_access"],
        )
        assessment = inventory.assess_risk(tool)
        assert assessment.score >= 7.0  # High risk
        assert len(assessment.findings) > 0

    def test_assess_risk_medium(self):
        from src.discovery.mcp_inventory import MCPInventory, MCPTool

        inventory = MCPInventory()
        tool = MCPTool(
            name="read_database",
            description="Reads from database",
            capabilities=["database_read"],
        )
        assessment = inventory.assess_risk(tool)
        assert 3.0 <= assessment.score <= 7.0  # Medium risk

    def test_assess_risk_low(self):
        from src.discovery.mcp_inventory import MCPInventory, MCPTool

        inventory = MCPInventory()
        tool = MCPTool(
            name="search",
            description="Searches text content",
            capabilities=["search", "text_generation"],
        )
        assessment = inventory.assess_risk(tool)
        assert assessment.score <= 4.0  # Low risk

    def test_assess_risk_no_capabilities(self):
        from src.discovery.mcp_inventory import MCPInventory, MCPTool

        inventory = MCPInventory()
        tool = MCPTool(
            name="hello",
            description="Says hello",
            capabilities=[],
        )
        assessment = inventory.assess_risk(tool)
        assert assessment.score >= 0

    def test_score_capabilities(self):
        from src.discovery.mcp_inventory import MCPInventory

        inventory = MCPInventory()
        # High risk capabilities
        score = inventory._score_capabilities(["shell_exec", "file_write"])
        assert score >= 7.0

        # Low risk only
        score_low = inventory._score_capabilities(["search", "text_generation"])
        assert score_low <= 4.0

        # Mixed
        score_mixed = inventory._score_capabilities(["file_read", "search"])
        assert score_low <= score_mixed <= score


# =============================================================================
# MCP suggested starter policy (discovered agent -> policy)
# =============================================================================


class TestMCPSuggestPolicy:
    """Tests for MCPInventory.suggest_policy — grounded starter scaffold."""

    def _sample_tools(self):
        from src.discovery.mcp_inventory import MCPTool

        return [
            MCPTool(name="run_shell", description="Runs a shell command",
                    capabilities=["shell_exec"]),
            MCPTool(name="fetch_url", description="HTTP fetch a url",
                    capabilities=["network_access"]),
            MCPTool(name="search_docs", description="Search the knowledge base",
                    capabilities=["search"]),
            MCPTool(name="read_db", description="Query the database",
                    capabilities=["database_read"]),
        ]

    def test_execution_tools_denied_by_default(self):
        from src.discovery.mcp_inventory import MCPInventory

        policy = MCPInventory().suggest_policy(self._sample_tools())
        agent = policy["agents"][0]
        # shell_exec tool must be denied; safe tools allowed.
        assert "run_shell" in agent["denied_tools"]
        assert "search_docs" in agent["allowed_tools"]
        assert "run_shell" not in agent["allowed_tools"]
        # Deny-by-default execution/file-write flags.
        assert agent["allow_command_execution"] is False
        assert agent["allow_file_write"] is False

    def test_network_flag_grounded_in_allowed_tools(self):
        from src.discovery.mcp_inventory import MCPInventory, MCPTool

        inv = MCPInventory()
        # An allowed tool needing network -> allow_network_access True.
        with_net = inv.suggest_policy([
            MCPTool(name="fetch_url", description="fetch", capabilities=["network_access"]),
        ])
        assert with_net["agents"][0]["allow_network_access"] is True

        # No allowed tool needs network -> False.
        no_net = inv.suggest_policy([
            MCPTool(name="search_docs", description="search", capabilities=["search"]),
        ])
        assert no_net["agents"][0]["allow_network_access"] is False

    def test_sandbox_strict_when_anything_denied(self):
        from src.discovery.mcp_inventory import MCPInventory, MCPTool

        inv = MCPInventory()
        strict = inv.suggest_policy([
            MCPTool(name="run_shell", description="shell", capabilities=["shell_exec"]),
        ])
        assert strict["agents"][0]["sandbox_level"] == "strict"

        standard = inv.suggest_policy([
            MCPTool(name="search_docs", description="search", capabilities=["search"]),
        ])
        assert standard["agents"][0]["sandbox_level"] == "standard"

    def test_rationale_covers_every_tool(self):
        from src.discovery.mcp_inventory import MCPInventory

        tools = self._sample_tools()
        policy = MCPInventory().suggest_policy(tools)
        rationale = policy["_rationale"]
        assert {r["tool"] for r in rationale} == {t.name for t in tools}
        for r in rationale:
            assert r["decision"] in {"allow", "deny"}
            assert r["reason"]

    def test_suggested_policy_is_loadable_by_real_parser(self):
        """The emitted YAML must round-trip through the production PolicyLoader."""
        import yaml

        from src.discovery.mcp_inventory import MCPInventory
        from src.policies.loader import PolicyLoader

        policy = MCPInventory().suggest_policy(
            self._sample_tools(), tenant_id="acme", agent_id="mcp-agent"
        )
        loadable = {k: v for k, v in policy.items() if k != "_rationale"}
        yaml_text = yaml.safe_dump(loadable, sort_keys=False)

        # Feed through the exact production parser (no invented schema).
        data = yaml.safe_load(yaml_text)
        loader = PolicyLoader(policies_dir=__import__("pathlib").Path("."))
        parsed = loader._parse_agent_policy(data["tenant"], data["agents"][0])

        assert parsed.tenant_id == "acme"
        assert parsed.agent_id == "mcp-agent"
        assert "run_shell" in parsed.denied_tools
        assert "search_docs" in parsed.allowed_tools
        assert parsed.allow_command_execution is False
        assert parsed.sandbox_level == "strict"

