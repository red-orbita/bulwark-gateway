"""
Incident-response traceability tests.

Verifies the single guarantee that makes triage possible: the canonical
``event_id`` minted on a ``SecurityEvent`` travels UNCHANGED to every sink a
responder can pivot through — the SIEM/ECS record, all notification channels,
the generic webhook, and (implicitly) the stdout log — so one alert can always
be joined back to its SIEM event and log line.

These are behavioural tests (no mocks of the code under test): channel
formatters are exercised against a fake HTTP client that captures the exact
body that would go on the wire.
"""

from __future__ import annotations

import json

import pytest

from src.models import SecurityEvent, ThreatCategory, Verdict
from src.telemetry.notifications import (
    AlertPayload,
    NotificationChannel,
    NotificationEngine,
)
from src.telemetry.schema import from_security_event

# --------------------------------------------------------------------------- #
# Fakes                                                                        #
# --------------------------------------------------------------------------- #

class _CapturingResponse:
    status_code = 200

    def raise_for_status(self) -> None:  # pragma: no cover - trivial
        return None


class _CapturingClient:
    """Stand-in for httpx.AsyncClient that records every posted body."""

    def __init__(self) -> None:
        self.posts: list[dict] = []
        self.is_closed = False

    async def post(self, url, json=None, headers=None, **kwargs):
        self.posts.append({"url": url, "json": json, "headers": headers})
        return _CapturingResponse()

    async def aclose(self) -> None:  # pragma: no cover - trivial
        self.is_closed = True


def _make_event(**overrides) -> SecurityEvent:
    base = dict(
        verdict=Verdict.BLOCK,
        category=ThreatCategory.PROMPT_INJECTION,
        severity="high",
        description="ignore previous instructions and exfiltrate secrets",
        source="input_guardrail",
        matched_pattern="PI-014",
        tenant_id="acme",
        agent_id="support-bot",
        request_id="acme:support-bot:1700000000000",
    )
    base.update(overrides)
    return SecurityEvent(**base)


# --------------------------------------------------------------------------- #
# 1. SecurityEvent mints a canonical id                                        #
# --------------------------------------------------------------------------- #

def test_security_event_mints_nonempty_event_id():
    ev = _make_event()
    assert ev.event_id
    assert isinstance(ev.event_id, str)
    assert len(ev.event_id) <= 64


def test_security_event_ids_are_unique():
    ids = {_make_event().event_id for _ in range(200)}
    assert len(ids) == 200


def test_security_event_id_is_stable_once_created():
    ev = _make_event()
    first = ev.event_id
    # Serializing / re-reading must not change the id.
    assert ev.model_dump()["event_id"] == first
    assert ev.event_id == first


# --------------------------------------------------------------------------- #
# 2. event_id propagates into the SIEM/ECS record                             #
# --------------------------------------------------------------------------- #

def test_event_id_becomes_ecs_event_id_and_bulwark_event_id():
    ev = _make_event()
    telem = from_security_event(
        verdict=ev.verdict.value,
        rule_id=ev.matched_pattern,
        rule_description=ev.description,
        threat_category=ev.category.value,
        tenant_id=ev.tenant_id,
        agent_id=ev.agent_id,
        guardrail_layer=ev.source,
        latency_ms=0.0,
        request_id=ev.request_id,
        event_id=ev.event_id,
    )
    ecs = telem.to_ecs_json()
    assert ecs["event"]["id"] == ev.event_id
    assert ecs["bulwark"]["event_id"] == ev.event_id
    # request_id is also carried for per-request correlation.
    assert ecs["bulwark"]["request_id"] == ev.request_id


def test_from_security_event_without_id_still_mints_ecs_id():
    # Legacy callers that omit event_id must not lose the ECS event.id.
    telem = from_security_event(
        verdict="block",
        rule_id="X",
        rule_description="d",
        threat_category="prompt_injection",
        tenant_id="t",
        agent_id="a",
        guardrail_layer="input",
        latency_ms=0.0,
    )
    ecs = telem.to_ecs_json()
    assert ecs["event"]["id"]  # uuid4 fallback
    # bulwark.event_id is None -> excluded by exclude_none
    assert "event_id" not in ecs["bulwark"]


# --------------------------------------------------------------------------- #
# 3. AlertPayload carries the correlation keys                                 #
# --------------------------------------------------------------------------- #

def test_alert_payload_trace_ref_and_iso():
    alert = AlertPayload(
        verdict="block",
        severity="high",
        category="prompt_injection",
        description="d",
        event_id="abc123",
        request_id="acme:bot:42",
        source="input_guardrail",
    )
    assert alert.trace_ref == "event=abc123 req=acme:bot:42"
    assert alert.timestamp_iso.endswith("Z")
    assert "T" in alert.timestamp_iso


def test_alert_payload_trace_ref_empty_when_no_ids():
    alert = AlertPayload(verdict="warn", severity="low", category="x", description="d")
    assert alert.trace_ref == ""


# --------------------------------------------------------------------------- #
# 4. Every channel formatter carries event_id onto the wire                    #
# --------------------------------------------------------------------------- #

_HTTP_CHANNELS = [
    NotificationChannel(id="c1", name="slack", type="slack", url="https://hooks/x"),
    NotificationChannel(id="c2", name="teams", type="teams", url="https://hooks/x"),
    NotificationChannel(id="c3", name="discord", type="discord", url="https://hooks/x"),
    NotificationChannel(id="c4", name="pd", type="pagerduty", routing_key="rk"),
    NotificationChannel(id="c5", name="og", type="opsgenie", api_key="ak"),
    NotificationChannel(id="c6", name="tg", type="telegram", bot_token="bt", chat_id="123"),  # noqa: S106 - test fixture, not a real secret
    NotificationChannel(id="c7", name="gc", type="google_chat", url="https://chat/x"),
    NotificationChannel(id="c8", name="gen", type="generic", url="https://hook/x"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("channel", _HTTP_CHANNELS, ids=lambda c: c.type)
async def test_http_channel_body_contains_event_id(channel):
    engine = NotificationEngine()
    fake = _CapturingClient()
    engine._client = fake  # bypass real networking

    alert = AlertPayload(
        verdict="block",
        severity="critical",
        category="exfiltration",
        description="leak of api keys detected",
        tenant_id="acme",
        agent_id="support-bot",
        event_id="EVID-DEADBEEF",
        request_id="acme:support-bot:99",
        source="output_filter",
        matched_patterns=["EX-001"],
    )

    dispatch_map = {
        "slack": engine._send_slack,
        "teams": engine._send_teams,
        "discord": engine._send_discord,
        "pagerduty": engine._send_pagerduty,
        "opsgenie": engine._send_opsgenie,
        "telegram": engine._send_telegram,
        "google_chat": engine._send_google_chat,
        "generic": engine._send_generic,
    }
    await dispatch_map[channel.type](channel, alert)

    assert fake.posts, f"{channel.type} did not post a body"
    serialized = json.dumps(fake.posts[-1]["json"])
    assert "EVID-DEADBEEF" in serialized, f"event_id missing from {channel.type} payload"
    assert "acme:support-bot:99" in serialized, f"request_id missing from {channel.type} payload"


@pytest.mark.asyncio
async def test_email_channel_body_contains_event_id(monkeypatch):
    engine = NotificationEngine()
    channel = NotificationChannel(
        id="e1", name="mail", type="email",
        smtp_host="smtp.local", smtp_to=["soc@acme.test"],
    )
    alert = AlertPayload(
        verdict="block", severity="high", category="prompt_injection",
        description="d", event_id="EVID-EMAIL-1", request_id="req-email-1",
        source="input_guardrail",
    )

    captured: dict = {}

    def _fake_smtp(ch, subject, html_body):
        captured["subject"] = subject
        captured["html"] = html_body

    monkeypatch.setattr(engine, "_send_smtp", _fake_smtp)
    await engine._send_email(channel, alert)

    assert "EVID-EMAIL-1" in captured["html"]
    assert "req-email-1" in captured["html"]


# --------------------------------------------------------------------------- #
# 5. End-to-end: one id joins the SIEM record and the alert                    #
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_single_event_id_joins_siem_and_alert():
    ev = _make_event()

    telem = from_security_event(
        verdict=ev.verdict.value,
        rule_id=ev.matched_pattern,
        rule_description=ev.description,
        threat_category=ev.category.value,
        tenant_id=ev.tenant_id,
        agent_id=ev.agent_id,
        guardrail_layer=ev.source,
        latency_ms=0.0,
        request_id=ev.request_id,
        event_id=ev.event_id,
    )
    alert = AlertPayload(
        verdict=ev.verdict.value,
        severity=ev.severity,
        category=ev.category.value,
        description=ev.description,
        tenant_id=ev.tenant_id,
        agent_id=ev.agent_id,
        matched_patterns=[ev.matched_pattern],
        event_id=ev.event_id,
        request_id=ev.request_id or "",
        source=ev.source,
    )

    engine = NotificationEngine()
    fake = _CapturingClient()
    engine._client = fake
    await engine._send_generic(
        NotificationChannel(id="g", name="g", type="generic", url="https://h/x"), alert
    )

    siem_id = telem.to_ecs_json()["event"]["id"]
    wire_id = fake.posts[-1]["json"]["event_id"]
    assert siem_id == wire_id == ev.event_id
