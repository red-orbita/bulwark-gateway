"""No implicit capabilities in strict policies; no malformed-argument approvals."""

from unittest.mock import MagicMock

import pytest

from src.guardrails.tool_policy import AgentPolicy, ToolPolicyEngine
from src.models import GuardrailResult, ToolCall, Verdict
from src.scanners.builtin.tool_policy_scanner import ToolPolicyScanner
from src.scanners.protocol import ScanContext


@pytest.mark.parametrize("tool", ["web_search", "custom_export", "calculate"])
def test_strict_empty_allowlist_denies_even_safe_named_tools(tool):
    engine = ToolPolicyEngine()
    engine.register_policy(AgentPolicy(tenant_id="t", agent_id="a", sandbox_level="strict"))
    result = engine.evaluate_tool_call(ToolCall(name=tool, arguments={}), "t", "a")
    assert result.verdict == Verdict.BLOCK
    assert result.blocked_tools == [tool]


@pytest.mark.parametrize("mode", ["standard", "strict"])
def test_explicit_allowed_tool_still_works(mode):
    engine = ToolPolicyEngine()
    engine.register_policy(AgentPolicy(tenant_id="t", agent_id="a", sandbox_level=mode, allowed_tools=["calculate"]))
    assert engine.evaluate_tool_call(ToolCall(name="calculate", arguments={}), "t", "a").verdict == Verdict.ALLOW


def test_quota_block_identifies_tool_for_proxy_removal():
    engine = ToolPolicyEngine()
    engine.register_policy(AgentPolicy(tenant_id="t", agent_id="a", allowed_tools=["calculate"], max_tool_calls_per_request=1))
    result = engine.evaluate_tool_calls([ToolCall(name="calculate"), ToolCall(name="calculate")], "t", "a")
    assert result.verdict == Verdict.BLOCK
    assert "calculate" in result.blocked_tools


@pytest.mark.parametrize("raw", ['{"path":', '{"a":1,"a":2}', '["a"]', '{"value":NaN}', '{"x":Infinity}'])
async def test_builtin_scanner_never_validates_substituted_empty_arguments(raw):
    engine = MagicMock()
    engine.evaluate_tool_calls.return_value = GuardrailResult(verdict=Verdict.ALLOW)
    ctx = ScanContext(tenant_id="t", agent_id="a", request_id="r", metadata={
        "tool_calls": [{"function": {"name": "calculate", "arguments": raw}}],
    })
    result = await ToolPolicyScanner(engine).safe_scan("", ctx)
    assert result.verdict == Verdict.BLOCK
    engine.evaluate_tool_calls.assert_not_called()


async def test_builtin_scanner_without_policy_cannot_approve_tool_calls():
    ctx = ScanContext(tenant_id="t", agent_id="a", request_id="r", metadata={
        "tool_calls": [{"function": {"name": "calculate", "arguments": "{}"}}],
    })
    assert (await ToolPolicyScanner().safe_scan("", ctx)).verdict == Verdict.BLOCK
    assert (await ToolPolicyScanner().safe_scan("hello", ScanContext(tenant_id="t", agent_id="a", request_id="r"))).verdict == Verdict.ALLOW
