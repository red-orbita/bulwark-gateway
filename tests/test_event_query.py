"""Tests for the Security Events search parser (``event_query``).

Exercises the Splunk/Wazuh-lite query grammar: scoped ``field:value`` filters,
quoting, the ``last:<n><unit>`` relative-time window, free-text terms, aliases,
and the forgiving degradation of malformed input to free text.
"""

from __future__ import annotations

from admin.services.event_query import ParsedEventQuery, parse_event_query

# ─── empty / whitespace ──────────────────────────────────────────────────────

def test_empty_query_is_empty():
    parsed = parse_event_query("")
    assert parsed.is_empty()
    assert parsed.terms == []


def test_none_query_is_empty():
    assert parse_event_query(None).is_empty()


def test_whitespace_only_is_empty():
    assert parse_event_query("   \t ").is_empty()


# ─── scoped field:value ──────────────────────────────────────────────────────

def test_scalar_fields_parse():
    parsed = parse_event_query(
        "tenant:acme agent:support-bot category:jailbreak severity:high "
        "verdict:block request_id:req-1 incident_id:inc-9 source:input_guardrail "
        "pattern:PAT-1"
    )
    assert parsed.tenant == "acme"
    assert parsed.agent == "support-bot"
    assert parsed.category == "jailbreak"
    assert parsed.severity == "high"
    assert parsed.verdict == "block"
    assert parsed.request_id == "req-1"
    assert parsed.incident_id == "inc-9"
    assert parsed.source == "input_guardrail"
    assert parsed.pattern == "PAT-1"
    assert parsed.terms == []


def test_tool_alias_maps_to_tool_name():
    assert parse_event_query("tool:run_command").tool_name == "run_command"
    assert parse_event_query("tool_name:bash").tool_name == "bash"


def test_quoted_value_stays_one_token():
    parsed = parse_event_query('tenant:"acme corp" hello world')
    assert parsed.tenant == "acme corp"
    assert parsed.terms == ["hello", "world"]


def test_empty_field_value_falls_through_to_term():
    # "tenant:" has no value → treated as a free-text term, not a tenant filter.
    parsed = parse_event_query("tenant:")
    assert parsed.tenant is None
    assert parsed.terms == ["tenant:"]


# ─── free text ───────────────────────────────────────────────────────────────

def test_bare_words_are_terms():
    parsed = parse_event_query("drop table users")
    assert parsed.terms == ["drop", "table", "users"]
    assert parsed.tenant is None


def test_unknown_field_becomes_free_text():
    parsed = parse_event_query("foo:bar")
    assert parsed.terms == ["foo:bar"]


def test_mixed_scoped_and_free_text():
    parsed = parse_event_query("tenant:acme exfiltration base64")
    assert parsed.tenant == "acme"
    assert parsed.terms == ["exfiltration", "base64"]


# ─── last:<n><unit> relative time ────────────────────────────────────────────

def test_last_hours_sets_since():
    parsed = parse_event_query("last:24h", now=1000.0)
    assert parsed.since == 1000.0 - 24 * 3600


def test_last_minutes_days_weeks_seconds():
    assert parse_event_query("last:30m", now=1000.0).since == 1000.0 - 30 * 60
    assert parse_event_query("last:7d", now=1000.0).since == 1000.0 - 7 * 86400
    assert parse_event_query("last:2w", now=1000.0).since == 1000.0 - 2 * 604800
    assert parse_event_query("last:45s", now=1000.0).since == 1000.0 - 45


def test_last_is_case_insensitive_unit():
    assert parse_event_query("last:1H", now=1000.0).since == 1000.0 - 3600


def test_invalid_last_becomes_term():
    parsed = parse_event_query("last:banana", now=1000.0)
    assert parsed.since is None
    assert parsed.terms == ["last:banana"]


def test_repeated_last_keeps_tightest_window():
    parsed = parse_event_query("last:7d last:1h", now=1000.0)
    # The most recent (largest) lower bound wins.
    assert parsed.since == 1000.0 - 3600


# ─── robustness ──────────────────────────────────────────────────────────────

def test_unbalanced_quote_falls_back_to_whitespace_split():
    parsed = parse_event_query('tenant:acme "unterminated')
    # Must not raise; degrades to whitespace tokens.
    assert parsed.tenant == "acme"
    assert '"unterminated' in parsed.terms


def test_field_is_case_insensitive():
    assert parse_event_query("Tenant:acme").tenant == "acme"


def test_returns_parsed_event_query_instance():
    assert isinstance(parse_event_query("x"), ParsedEventQuery)
