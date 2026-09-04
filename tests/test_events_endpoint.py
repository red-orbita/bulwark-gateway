"""Endpoint tests for the Security Events viewer feed selection.

``list_security_events`` now reads the **durable** ``security_events`` table (not
the Redis live buffer). The ``verdict`` query param selects the feed: ``allowed``
reads the opt-in allowed records, ``blocked``/``warned`` narrow the security feed
by verdict, and the default returns the whole security feed (BLOCK + WARN).

Each test seeds a migrated throwaway SQLite store and drives the route directly.
"""

from __future__ import annotations

import pytest

from admin.routes import events as events_mod
from admin.services import security_events_store as store_mod
from admin.services.database import create_engine
from admin.services.migrations import run_migrations
from admin.services.security_events_store import SecurityEventsStore


@pytest.fixture
async def seeded_store(tmp_path, monkeypatch):
    """Migrated SQLite store, wired into the singleton the route resolves."""
    db_path = tmp_path / "endpoint_test.db"
    engine = create_engine(f"sqlite:///{db_path}")
    await engine.init()
    await run_migrations(engine)
    monkeypatch.setattr(store_mod, "get_database", lambda: engine)
    monkeypatch.setattr(store_mod, "_store", None)

    store = SecurityEventsStore()

    def _evt(event_id, *, ts, tenant, verdict, category, severity):
        return {
            "event_id": event_id, "ts": ts, "tenant": tenant, "agent": "bot",
            "verdict": verdict, "category": category, "severity": severity,
            "description": "d", "source": "input_guardrail", "pattern": "P",
            "request_id": "", "tool_name": "", "snippet": "", "input_hash": "",
            "metadata": {},
        }

    await store.bulk_insert([
        _evt("b", ts=3.0, tenant="acme", verdict="block", category="prompt_injection", severity="high"),
        _evt("w", ts=2.0, tenant="acme", verdict="warn", category="jailbreak", severity="medium"),
        _evt("a", ts=5.0, tenant="acme", verdict="allow", category="allowed", severity="info"),
    ])
    try:
        yield store
    finally:
        await engine.close()


async def _call(**kwargs):
    kwargs.setdefault("tenant", None)
    kwargs.setdefault("category", None)
    kwargs.setdefault("severity", None)
    kwargs.setdefault("verdict", None)
    kwargs.setdefault("q", None)
    kwargs.setdefault("limit", 50)
    kwargs.setdefault("offset", 0)
    kwargs.setdefault("user", None)
    return await events_mod.list_security_events(**kwargs)


async def test_default_feed_returns_block_and_warn(seeded_store):
    """No verdict → security feed (BLOCK + WARN), allowed records untouched."""
    result = await _call()
    verdicts = {e["verdict"] for e in result}
    assert verdicts == {"block", "warn"}
    assert "allow" not in verdicts


async def test_verdict_allowed_reads_allowed_feed(seeded_store):
    result = await _call(verdict="allowed")
    assert len(result) == 1
    assert result[0]["verdict"] == "allow"
    assert result[0]["category"] == "allowed"


async def test_verdict_blocked_filters_security_feed(seeded_store):
    result = await _call(verdict="blocked")
    assert [e["verdict"] for e in result] == ["block"]


async def test_verdict_warned_filters_security_feed(seeded_store):
    result = await _call(verdict="warned")
    assert [e["verdict"] for e in result] == ["warn"]


async def test_limit_is_applied(seeded_store):
    result = await _call(limit=1)
    assert len(result) == 1


# ─── search bar (q) ──────────────────────────────────────────────────────────

async def test_q_scoped_field_filters_feed(seeded_store):
    """A 'category:' token in q narrows the security feed."""
    result = await _call(q="category:jailbreak")
    assert [e["category"] for e in result] == ["jailbreak"]


async def test_q_free_text_matches_column(seeded_store):
    """A bare term matches any readable column (here the category text)."""
    result = await _call(q="prompt_injection")
    assert [e["verdict"] for e in result] == ["block"]


async def test_q_verdict_token_selects_feed(seeded_store):
    """verdict: in q flows through the feed selector like the dropdown."""
    result = await _call(q="verdict:allowed")
    assert [e["verdict"] for e in result] == ["allow"]


async def test_dropdown_wins_over_q_for_shared_field(seeded_store):
    """When both set category, the explicit dropdown value takes precedence."""
    # Dropdown says prompt_injection; q says jailbreak → dropdown wins → block row.
    result = await _call(category="prompt_injection", q="category:jailbreak")
    assert [e["category"] for e in result] == ["prompt_injection"]


async def test_q_last_window_bounds_results(seeded_store):
    """last:<n><unit> excludes events older than the window (all seeds are ancient)."""
    result = await _call(q="last:1h")
    assert result == []


async def test_summary_counts_full_history(seeded_store):
    summary = await events_mod.event_summary(user=None)
    assert summary["total"] == 2  # block + warn
    assert summary["allowed_recorded"] == 1
    assert summary["by_tenant"] == {"acme": 2}


async def test_compliance_mappings_serves_the_ssot():
    """The endpoint reflects src/telemetry/compliance.py (no separate hardcoded copy)."""
    data = await events_mod.compliance_mappings(user=None)

    assert data["owasp_version"] == "2025"

    catalog = data["catalog"]
    assert catalog["LLM01"]["framework"] == "owasp"
    assert catalog["LLM01"]["url"].startswith("https://")
    assert catalog["LLM01"]["label"]

    refs = data["category_refs"]
    # Ordered OWASP → ATLAS → ATT&CK, straight from the SSOT.
    assert refs["prompt_injection"] == ["LLM01", "AML.T0051", "T1059"]
    assert refs["model_theft"][0] == "LLM10"  # 2025 Unbounded Consumption

    # Every code the UI is asked to render must have a catalog entry.
    for category, codes in refs.items():
        for code in codes:
            assert code in catalog, f"{category}: {code} missing from served catalog"


async def test_compliance_mappings_matches_module_source():
    """The served payload is a faithful projection of the compliance module."""
    from src.telemetry.compliance import all_mappings, reference_catalog

    data = await events_mod.compliance_mappings(user=None)
    assert set(data["catalog"]) == set(reference_catalog())
    assert set(data["category_refs"]) == set(all_mappings())

