"""Adapter regression contracts without downloading external frameworks."""

import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.models import Verdict
from src.sdk.guard import ScanResult, SecurityError
from src.sdk.integrations.autogen import AutoGenGuard, _replace_message_text
from src.sdk.integrations.crewai import CrewAIGuard, _replace_task_text
from src.sdk.integrations.langchain import LangChainGuard, _replace_lc_output
from src.sdk.integrations.llamaindex import LlamaIndexGuard, _replace_response_text


@pytest.fixture
def fake_guard():
    clean = ScanResult(verdict=Verdict.ALLOW)
    return SimpleNamespace(scan_input=AsyncMock(return_value=clean), scan_output=AsyncMock(return_value=clean),
                           scan_input_sync=MagicMock(return_value=clean), scan_output_sync=MagicMock(return_value=clean))


@pytest.fixture
def langchain_module(monkeypatch):
    module = ModuleType("langchain_core.runnables")
    module.Runnable = type("Runnable", (), {})
    module.RunnableConfig = dict
    monkeypatch.setitem(sys.modules, "langchain_core", ModuleType("langchain_core"))
    monkeypatch.setitem(sys.modules, "langchain_core.runnables", module)


@pytest.mark.parametrize("adapter", ["langchain", "llamaindex"])
@pytest.mark.parametrize("asynchronous", [False, True])
async def test_input_redaction_prevents_original_forwarding(fake_guard, langchain_module, adapter, asynchronous):
    redact = ScanResult(verdict=Verdict.REDACT, modified_content="")
    fake_guard.scan_input.return_value = redact
    fake_guard.scan_input_sync.return_value = redact
    engine = SimpleNamespace(invoke=MagicMock(return_value="safe"), ainvoke=AsyncMock(return_value="safe"),
                             query=MagicMock(return_value="safe"), aquery=AsyncMock(return_value="safe"))
    wrapped = (LangChainGuard if adapter == "langchain" else LlamaIndexGuard)(guard=fake_guard).wrap(engine)
    with pytest.raises(SecurityError):
        if asynchronous:
            await getattr(wrapped, "ainvoke" if adapter == "langchain" else "aquery")("private")
        else:
            getattr(wrapped, "invoke" if adapter == "langchain" else "query")("private")
    engine.invoke.assert_not_called()
    engine.query.assert_not_called()
    engine.ainvoke.assert_not_awaited()
    engine.aquery.assert_not_awaited()


@pytest.mark.parametrize("adapter", ["langchain", "llamaindex", "autogen", "crewai"])
@pytest.mark.parametrize("replacement", ["", "[REDACTED]", None])
async def test_output_redaction_cannot_return_original(fake_guard, langchain_module, adapter, replacement):
    fake_guard.scan_output.return_value = ScanResult(verdict=Verdict.REDACT, modified_content=replacement)
    fake_guard.scan_output_sync.return_value = fake_guard.scan_output.return_value
    if adapter == "langchain":
        wrapped = LangChainGuard(guard=fake_guard).wrap(SimpleNamespace(ainvoke=AsyncMock(return_value="private")))
        async def call():
            return await wrapped.ainvoke("hello")
    elif adapter == "llamaindex":
        wrapped = LlamaIndexGuard(guard=fake_guard).wrap(SimpleNamespace(aquery=AsyncMock(return_value="private")))
        async def call():
            return await wrapped.aquery("hello")
    elif adapter == "autogen":
        wrapped = AutoGenGuard(guard=fake_guard)
        async def call():
            return await wrapped.scan_reply_async("private")
    else:
        ok, output = CrewAIGuard(guard=fake_guard).task_guardrail("private")
        assert ok == (replacement is not None)
        assert "private" not in output
        return
    if replacement is None:
        with pytest.raises(SecurityError):
            await call()
    else:
        assert await call() == replacement


@pytest.mark.parametrize("helper,attribute", [(_replace_message_text, "content"), (_replace_lc_output, "content"),
                                             (_replace_task_text, "raw"), (_replace_response_text, "response")])
def test_immutable_output_never_returns_secret(helper, attribute):
    immutable = type("Immutable", (), {attribute: property(lambda self: "private")})()
    with pytest.raises(SecurityError):
        helper(immutable, "")


def test_crewai_filter_exception_rejects_task(fake_guard):
    fake_guard.scan_output_sync.side_effect = RuntimeError("private diagnostics")
    ok, message = CrewAIGuard(guard=fake_guard).task_guardrail("private")
    assert not ok
    assert "private" not in message


def test_crewai_input_redaction_blocks_execution(fake_guard):
    fake_guard.scan_input_sync.return_value = ScanResult(verdict=Verdict.REDACT, modified_content="")
    backend = MagicMock(return_value="safe")
    wrapped = CrewAIGuard(guard=fake_guard).guard_tool(backend)
    with pytest.raises(SecurityError):
        wrapped("private")
    backend.assert_not_called()


@pytest.mark.parametrize("asynchronous", [False, True])
async def test_autogen_scans_all_roles_and_blocks_changed_input(fake_guard, asynchronous):
    fake_guard.scan_input.return_value = ScanResult(verdict=Verdict.REDACT, modified_content="")
    fake_guard.scan_input_sync.return_value = fake_guard.scan_input.return_value
    sync = MagicMock(return_value="safe")
    async_call = AsyncMock(return_value="safe")
    agent = SimpleNamespace(generate_reply=sync, a_generate_reply=async_call)
    AutoGenGuard(guard=fake_guard).wrap_agent(agent)
    with pytest.raises(SecurityError):
        if asynchronous:
            await agent.a_generate_reply(messages=[{"role": "tool", "content": "private"}])
        else:
            agent.generate_reply(messages=[{"role": "tool", "content": "private"}])
    sync.assert_not_called()
    async_call.assert_not_awaited()


def test_autogen_cannot_use_uninspected_implicit_history(fake_guard):
    backend = MagicMock(return_value="safe")
    agent = SimpleNamespace(generate_reply=backend)
    AutoGenGuard(guard=fake_guard).wrap_agent(agent)
    with pytest.raises(SecurityError):
        agent.generate_reply()
    backend.assert_not_called()


def test_crewai_redacts_selected_field_or_rejects(fake_guard):
    class Output:
        content = "not selected"
        @property
        def raw(self):
            return "private"
    output = Output()
    fake_guard.scan_output_sync.return_value = ScanResult(verdict=Verdict.REDACT, modified_content="")
    ok, message = CrewAIGuard(guard=fake_guard).task_guardrail(output)
    assert not ok
    assert "private" not in message
    assert output.content == "not selected"
