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
