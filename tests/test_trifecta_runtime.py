"""Tests for the runtime lethal-trifecta accumulator (FASE 3.2).

Covers:

* The shared pillar-projection helpers on ``src.discovery.lethal_trifecta``
  (``pillars_for_capabilities`` / ``pillars_for_tools``).
* :class:`TrifectaStateStore` — sliding-window accumulation, the one-shot
  ``newly_completed`` transition, window decay, and the empty-input no-ops (all on
  the in-memory fallback, no Redis).
* :class:`RuntimeTrifectaTracker` — inert when disabled, completion via tools
  spanning all three pillars, the input/output category pillars, WARN-vs-BLOCK
  mode, origin risk elevation, single-emit semantics, and fail-open on error.
"""

from __future__ import annotations

import pytest

from src.correlation.risk_state import RiskStateStore
from src.correlation.trifecta_runtime import (
    RuntimeTrifectaTracker,
    TrifectaStateStore,
)
from src.discovery.lethal_trifecta import (
    TrifectaPillar,
    pillars_for_capabilities,
    pillars_for_tools,
)
from src.models import ThreatCategory, Verdict

# ─── pillar-projection helpers ───────────────────────────────────────────────


def test_pillars_for_capabilities_single_pillar():
    assert pillars_for_capabilities(["read_file"]) == {TrifectaPillar.DATA_ACCESS}


def test_pillars_for_capabilities_network_spans_two():
    assert pillars_for_capabilities(["network_access"]) == {
        TrifectaPillar.UNTRUSTED_EXPOSURE,
        TrifectaPillar.EXFILTRATION,
    }


def test_pillars_for_capabilities_execution_spans_all():
    assert pillars_for_capabilities(["shell_exec"]) == set(TrifectaPillar)


def test_pillars_for_capabilities_benign_is_empty():
    assert pillars_for_capabilities(["text_generation", "unknown_cap"]) == set()


def test_pillars_for_tools_infers_from_name():
    # A shell tool name is inferred to shell_exec -> all pillars.
    assert pillars_for_tools(["run_shell_command"]) == set(TrifectaPillar)


def test_pillars_for_tools_empty_and_blank():
    assert pillars_for_tools([]) == set()
    assert pillars_for_tools(["", "chat_complete"]) == set()


# ─── TrifectaStateStore ──────────────────────────────────────────────────────


def _mem_store() -> TrifectaStateStore:
    s = TrifectaStateStore()
    s.initialize(redis_url=None)  # force in-memory fallback
    return s


def test_store_accumulates_and_completes_once():
    s = _mem_store()
    live, done = s.observe("session", "acme:bot", {"data_access"}, 1800.0)
    assert live == {"data_access"}
    assert done is False

    live, done = s.observe("session", "acme:bot", {"untrusted_exposure"}, 1800.0)
    assert live == {"data_access", "untrusted_exposure"}
    assert done is False

    # Third distinct pillar completes the trifecta — transition fires exactly here.
    live, done = s.observe("session", "acme:bot", {"exfiltration"}, 1800.0)
    assert live == {"data_access", "untrusted_exposure", "exfiltration"}
    assert done is True

    # A subsequent observe of an already-complete origin does NOT re-fire.
    _live, done = s.observe("session", "acme:bot", {"exfiltration"}, 1800.0)
    assert done is False


def test_store_single_request_all_three_completes():
    s = _mem_store()
    live, done = s.observe(
        "session", "acme:bot", {"data_access", "untrusted_exposure", "exfiltration"}, 1800.0
    )
    assert live == {"data_access", "untrusted_exposure", "exfiltration"}
    assert done is True


def test_store_empty_scope_or_pillars_is_noop():
    s = _mem_store()
    assert s.observe("session", "", {"data_access"}, 1800.0) == (set(), False)
    assert s.observe("session", "acme:bot", set(), 1800.0) == (set(), False)


def test_store_window_decays_stale_pillars():
    s = _mem_store()
    # Seed two pillars far in the past (beyond the window).
    s.observe("session", "acme:bot", {"data_access", "untrusted_exposure"}, 1800.0, now=1_000.0)
    # A tiny window means the earlier pillars have expired by the next observe.
    live, done = s.observe("session", "acme:bot", {"exfiltration"}, 10.0, now=5_000.0)
    # Only the fresh pillar is live; the trifecta is NOT complete.
    assert live == {"exfiltration"}
    assert done is False


def test_store_scopes_are_isolated():
    s = _mem_store()
    s.observe("session", "acme:bot", {"data_access", "untrusted_exposure"}, 1800.0)
    # A different origin shares no accumulated state.
    live, done = s.observe("session", "acme:other", {"exfiltration"}, 1800.0)
    assert live == {"exfiltration"}
    assert done is False


# ─── RuntimeTrifectaTracker ──────────────────────────────────────────────────


def _tracker() -> RuntimeTrifectaTracker:
    t = RuntimeTrifectaTracker()
    # Inject fresh, isolated in-memory stores so the singletons don't leak state.
    t._store = _mem_store()
    risk = RiskStateStore()
    risk.initialize(redis_url=None)
    t._risk = risk
    return t


@pytest.fixture
def _enable(monkeypatch):
    from src.config import settings

    monkeypatch.setattr(settings, "trifecta_runtime_enabled", True, raising=False)
    monkeypatch.setattr(settings, "trifecta_runtime_blocking", False, raising=False)
    monkeypatch.setattr(settings, "trifecta_runtime_window_seconds", 1800.0, raising=False)
    return settings


def test_tracker_inert_when_disabled(monkeypatch):
    from src.config import settings

    monkeypatch.setattr(settings, "trifecta_runtime_enabled", False, raising=False)
    t = _tracker()
    event = t.observe_request(
        tenant_id="acme",
        agent_id="bot",
        tool_names=["run_shell_command"],  # would complete if enabled
        input_categories=[],
        output_categories=[],
    )
    assert event is None


def test_tracker_completes_via_single_execution_tool(_enable):
    t = _tracker()
    event = t.observe_request(
        tenant_id="acme",
        agent_id="bot",
        tool_names=["run_shell_command"],  # shell_exec spans all three pillars
        input_categories=[],
        output_categories=[],
    )
    assert event is not None
    assert event.verdict == Verdict.WARN
    assert event.category == ThreatCategory.EXCESSIVE_AGENCY
    assert event.source == "trifecta_runtime"
    assert event.metadata["correlation"] is True
    assert event.metadata["trifecta_runtime"] is True


def test_tracker_completes_across_requests_with_categories(_enable):
    t = _tracker()
    # Request 1: a data-access tool -> DATA_ACCESS only.
    assert (
        t.observe_request(
            tenant_id="acme",
            agent_id="bot",
            tool_names=["read_file"],
            input_categories=[],
            output_categories=[],
        )
        is None
    )
    # Request 2: a suspicious INPUT -> UNTRUSTED_EXPOSURE. Still incomplete.
    assert (
        t.observe_request(
            tenant_id="acme",
            agent_id="bot",
            tool_names=[],
            input_categories=[ThreatCategory.PROMPT_INJECTION],
            output_categories=[],
        )
        is None
    )
    # Request 3: a sensitive OUTPUT -> EXFILTRATION. Completes the trifecta.
    event = t.observe_request(
        tenant_id="acme",
        agent_id="bot",
        tool_names=[],
        input_categories=[],
        output_categories=[ThreatCategory.PII_LEAK],
    )
    assert event is not None
    assert event.verdict == Verdict.WARN


def test_tracker_blocking_mode_emits_block(_enable, monkeypatch):
    monkeypatch.setattr(_enable, "trifecta_runtime_blocking", True, raising=False)
    t = _tracker()
    event = t.observe_request(
        tenant_id="acme",
        agent_id="bot",
        tool_names=["run_shell_command"],
        input_categories=[],
        output_categories=[],
    )
    assert event is not None
    assert event.verdict == Verdict.BLOCK
    assert event.severity == "critical"


def test_tracker_elevates_origin_risk(_enable):
    t = _tracker()
    t.observe_request(
        tenant_id="acme",
        agent_id="bot",
        tool_names=["run_shell_command"],
        input_categories=[],
        output_categories=[],
        subject_id="user-1",
    )
    # The completing trifecta bumps the subject (primary), session and tenant.
    assert t._risk.get("subject", "acme:user-1") > 0.0
    assert t._risk.get("session", "acme:bot") > 0.0
    assert t._risk.get("tenant", "acme") > 0.0


def test_tracker_emits_only_once(_enable):
    t = _tracker()
    first = t.observe_request(
        tenant_id="acme",
        agent_id="bot",
        tool_names=["run_shell_command"],
        input_categories=[],
        output_categories=[],
    )
    assert first is not None
    # A second completing request from the same origin does not re-emit.
    second = t.observe_request(
        tenant_id="acme",
        agent_id="bot",
        tool_names=["run_shell_command"],
        input_categories=[],
        output_categories=[],
    )
    assert second is None


def test_tracker_subject_scope_isolated_from_session(_enable):
    t = _tracker()
    # user-1 accumulates two pillars.
    t.observe_request(
        tenant_id="acme",
        agent_id="bot",
        tool_names=["read_file"],
        input_categories=[ThreatCategory.PROMPT_INJECTION],
        output_categories=[],
        subject_id="user-1",
    )
    # user-2 (same session) supplies the third pillar — must NOT complete user-1.
    event = t.observe_request(
        tenant_id="acme",
        agent_id="bot",
        tool_names=[],
        input_categories=[],
        output_categories=[ThreatCategory.PII_LEAK],
        subject_id="user-2",
    )
    assert event is None


def test_tracker_no_signal_returns_none(_enable):
    t = _tracker()
    event = t.observe_request(
        tenant_id="acme",
        agent_id="bot",
        tool_names=["chat_complete"],  # benign -> no pillar
        input_categories=[],
        output_categories=[],
    )
    assert event is None


def test_tracker_fail_open_on_store_error(_enable):
    t = _tracker()

    class _BoomStore:
        def observe(self, *a, **k):
            raise RuntimeError("boom")

    t._store = _BoomStore()  # type: ignore[assignment]
    event = t.observe_request(
        tenant_id="acme",
        agent_id="bot",
        tool_names=["run_shell_command"],
        input_categories=[],
        output_categories=[],
    )
    assert event is None  # never raises, degrades to no-event
