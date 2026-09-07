"""Tests for the lethal-trifecta config-time analyzer."""

from __future__ import annotations

from src.discovery.lethal_trifecta import (
    LethalTrifectaAnalyzer,
    TrifectaPillar,
    _canonicalize,
)
from src.discovery.mcp_inventory import MCPTool


class TestAnalyzeCapabilities:
    def test_complete_trifecta_is_critical(self) -> None:
        analyzer = LethalTrifectaAnalyzer()
        # secret_read (data) + search (exposure) + file_write (exfil)
        result = analyzer.analyze_capabilities(
            ["secret_read", "search", "file_write"]
        )
        assert result.complete is True
        assert result.verdict == "critical"
        assert result.score >= 8.0
        assert set(result.pillars_present) == {
            TrifectaPillar.DATA_ACCESS.value,
            TrifectaPillar.UNTRUSTED_EXPOSURE.value,
            TrifectaPillar.EXFILTRATION.value,
        }
        assert result.break_recommendation is not None

    def test_network_access_supplies_two_pillars(self) -> None:
        analyzer = LethalTrifectaAnalyzer()
        # network_access = exposure + exfiltration; add file_read for data access
        result = analyzer.analyze_capabilities(["file_read", "network_access"])
        assert result.complete is True
        assert result.verdict == "critical"

    def test_two_pillars_is_warn(self) -> None:
        analyzer = LethalTrifectaAnalyzer()
        # data access + exfiltration, no untrusted exposure
        result = analyzer.analyze_capabilities(["file_read", "file_write"])
        assert result.complete is False
        assert result.verdict == "warn"
        assert 4.0 <= result.score < 8.0
        assert len(result.pillars_present) == 2
        assert result.break_recommendation is None

    def test_single_pillar_is_safe(self) -> None:
        analyzer = LethalTrifectaAnalyzer()
        result = analyzer.analyze_capabilities(["file_read", "database_read"])
        assert result.complete is False
        assert result.verdict == "safe"
        assert result.score <= 3.0
        assert result.pillars_present == [TrifectaPillar.DATA_ACCESS.value]

    def test_no_recognized_capabilities_is_safe_zero(self) -> None:
        analyzer = LethalTrifectaAnalyzer()
        result = analyzer.analyze_capabilities(["text_generation", "embedding"])
        assert result.complete is False
        assert result.verdict == "safe"
        assert result.score == 0.0
        assert result.pillars_present == []

    def test_execution_capability_alone_completes_trifecta(self) -> None:
        analyzer = LethalTrifectaAnalyzer()
        # shell_exec spans all three pillars on its own
        result = analyzer.analyze_capabilities(["shell_exec"])
        assert result.complete is True
        assert result.verdict == "critical"

    def test_break_recommendation_targets_cheapest_pillar(self) -> None:
        analyzer = LethalTrifectaAnalyzer()
        # data access backed by 2 caps, exposure by 1 (search), exfil by 1
        result = analyzer.analyze_capabilities(
            ["file_read", "secret_read", "search", "file_write"]
        )
        assert result.complete is True
        # cheapest pillar (fewest caps) should be exposure or exfiltration, not
        # data_access which has two contributing capabilities.
        assert TrifectaPillar.DATA_ACCESS.value not in result.break_recommendation


class TestCapabilityReconciliation:
    def test_synonyms_canonicalize(self) -> None:
        assert _canonicalize("filesystem_read") == "file_read"
        assert _canonicalize("HTTP") == "network_access"
        assert _canonicalize("environment") == "env_access"
        assert _canonicalize("subprocess") == "process_spawn"

    def test_synonym_vocab_completes_trifecta(self) -> None:
        analyzer = LethalTrifectaAnalyzer()
        # mcp_privilege-style vocabulary reconciled into canonical pillars
        result = analyzer.analyze_capabilities(
            ["filesystem_read", "web", "upload"]
        )
        # filesystem_read -> data access; web/upload -> network (exposure+exfil)
        assert result.complete is True
        assert result.verdict == "critical"


class TestAnalyzeTools:
    def test_trifecta_emerges_across_tools(self) -> None:
        analyzer = LethalTrifectaAnalyzer()
        tools = [
            MCPTool(name="read_secret", description="", capabilities=["secret_read"]),
            MCPTool(name="web_search", description="", capabilities=["search"]),
            MCPTool(name="post_data", description="", capabilities=["network_access"]),
        ]
        result = analyzer.analyze_tools(tools)
        assert result.complete is True
        assert result.verdict == "critical"

    def test_single_benign_tool_is_safe(self) -> None:
        analyzer = LethalTrifectaAnalyzer()
        tools = [
            MCPTool(name="reader", description="", capabilities=["file_read"]),
        ]
        result = analyzer.analyze_tools(tools)
        assert result.verdict == "safe"
        assert result.complete is False


class TestAnalyzeAgent:
    def test_policy_gates_suppress_blocked_capabilities(self) -> None:
        analyzer = LethalTrifectaAnalyzer()
        # tool names imply read + fetch + write, but write/network are gated off
        result = analyzer.analyze_agent(
            allowed_tools=["read_file", "fetch_url", "write_file"],
            allow_command_execution=False,
            allow_file_write=False,
            allow_network_access=False,
        )
        # only file_read survives the gates -> single pillar, safe
        assert result.verdict == "safe"
        assert result.complete is False

    def test_open_policy_can_complete_trifecta(self) -> None:
        analyzer = LethalTrifectaAnalyzer()
        result = analyzer.analyze_agent(
            allowed_tools=["read_file", "fetch_url"],
            allow_network_access=True,
        )
        # file_read (data) + fetch/network (exposure + exfil) => complete
        assert result.complete is True
        assert result.verdict == "critical"

    def test_denied_tools_excluded(self) -> None:
        analyzer = LethalTrifectaAnalyzer()
        result = analyzer.analyze_agent(
            allowed_tools=["read_file", "fetch_url"],
            denied_tools=["fetch_url"],
            allow_network_access=True,
        )
        # fetch_url denied => only file_read => safe
        assert result.verdict == "safe"
        assert result.complete is False
