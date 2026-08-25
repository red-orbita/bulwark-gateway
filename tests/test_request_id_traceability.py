"""
Fase B — per-request correlation-id (``request_id``) traceability tests.

Where ``event_id`` gives a per-detection grain (Fase A), ``request_id`` is the
per-HTTP-request key that joins EVERY event / log / SIEM record / alert produced
while handling one request. Two guarantees are verified here:

  1. ``RequestIDMiddleware`` establishes exactly one id per request — honouring a
     well-formed inbound ``X-Request-ID`` (distributed tracing) but sanitising
     hostile/oversized/malformed input by minting a fresh id — and always echoes
     it back on the response so a caller can correlate.
  2. The proxy stamping helper (``_ensure_request_id``) is idempotent,
     order-independent and lets an explicit id (used on the streaming path where
     the ContextVar cannot be trusted across the response boundary) take
     precedence over the request-scoped ContextVar.

Behavioural tests — the real middleware / real helper are exercised, no mocks of
the code under test.
"""

from __future__ import annotations

import re
from uuid import uuid4

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from src.middleware.request_id import (
    _HEADER,
    _SAFE_REQUEST_ID,
    RequestIDMiddleware,
    _resolve_request_id,
)
from src.models import SecurityEvent, ThreatCategory, Verdict
from src.routes.proxy import _ensure_request_id, _request_id

_HEX32 = re.compile(r"^[0-9a-f]{32}$")


def _make_event(**overrides) -> SecurityEvent:
    base = dict(
        verdict=Verdict.BLOCK,
        category=ThreatCategory.PROMPT_INJECTION,
        severity="high",
        description="ignore previous instructions",
        source="input_guardrail",
        tenant_id="acme",
        agent_id="support-bot",
    )
    base.update(overrides)
    return SecurityEvent(**base)


# --------------------------------------------------------------------------- #
# 1. _resolve_request_id: honour well-formed inbound, sanitise everything else #
# --------------------------------------------------------------------------- #

def test_resolve_honours_wellformed_inbound():
    assert _resolve_request_id("trace-abc.123:node_7") == "trace-abc.123:node_7"


def test_resolve_mints_fresh_when_absent():
    rid = _resolve_request_id(None)
    assert _HEX32.match(rid)


def test_resolve_mints_fresh_when_empty():
    assert _HEX32.match(_resolve_request_id(""))


@pytest.mark.parametrize(
    "hostile",
    [
        "id with spaces",
        "bad\r\nInjected-Header: 1",       # CRLF header injection
        "path/traversal",                    # slash not allowed
        "semicolon;drop",                    # punctuation not allowed
        "unicode\u202eoverride",             # control / bidi
        "x" * 129,                           # oversized (>128, would overflow SIEM field)
        "<script>alert(1)</script>",
    ],
)
def test_resolve_rejects_hostile_inbound(hostile):
    rid = _resolve_request_id(hostile)
    # Rejected -> a fresh, safe id is minted instead of trusting the input.
    assert rid != hostile
    assert _HEX32.match(rid)
    assert _SAFE_REQUEST_ID.match(rid)


def test_resolve_accepts_max_length_boundary():
    at_bound = "a" * 128
    assert _resolve_request_id(at_bound) == at_bound
    over_bound = "a" * 129
    assert _resolve_request_id(over_bound) != over_bound


# --------------------------------------------------------------------------- #
# 2. Middleware integration: mint / honour / sanitise + always echo            #
# --------------------------------------------------------------------------- #

def _build_app() -> Starlette:
    async def endpoint(request):
        # Prove the id reached the handler via request.state (same channel the
        # proxy uses to derive its correlation id).
        return PlainTextResponse(getattr(request.state, "request_id", "MISSING"))

    app = Starlette(routes=[Route("/echo", endpoint)])
    app.add_middleware(RequestIDMiddleware)
    return app


def test_middleware_mints_and_echoes_when_absent():
    client = TestClient(_build_app())
    resp = client.get("/echo")
    echoed = resp.headers[_HEADER]
    assert _HEX32.match(echoed)
    # Same id reached the handler (request.state) and the response header.
    assert resp.text == echoed


def test_middleware_honours_wellformed_inbound():
    client = TestClient(_build_app())
    resp = client.get("/echo", headers={_HEADER: "upstream-trace-42"})
    assert resp.headers[_HEADER] == "upstream-trace-42"
    assert resp.text == "upstream-trace-42"


def test_middleware_sanitises_hostile_inbound():
    client = TestClient(_build_app())
    resp = client.get("/echo", headers={_HEADER: "bad;value/with spaces"})
    echoed = resp.headers[_HEADER]
    assert echoed != "bad;value/with spaces"
    assert _HEX32.match(echoed)
    assert resp.text == echoed


def test_middleware_echo_matches_handler_view():
    # The echoed header must be the exact id the handler saw — never a second id.
    client = TestClient(_build_app())
    resp = client.get("/echo")
    assert resp.text == resp.headers[_HEADER]


# --------------------------------------------------------------------------- #
# 3. _ensure_request_id: stamp-all, idempotent, explicit-precedence            #
# --------------------------------------------------------------------------- #

def test_ensure_stamps_all_events_from_contextvar():
    token = _request_id.set("req-CTX-1")
    try:
        events = [_make_event(), _make_event(), _make_event()]
        assert all(e.request_id is None for e in events)
        _ensure_request_id(events)
        assert {e.request_id for e in events} == {"req-CTX-1"}
    finally:
        _request_id.reset(token)


def test_ensure_explicit_takes_precedence_over_contextvar():
    token = _request_id.set("req-CTX-2")
    try:
        events = [_make_event()]
        # Streaming path passes the id explicitly because the ContextVar cannot
        # be trusted across the response boundary; explicit must win.
        _ensure_request_id(events, request_id="req-EXPLICIT")
        assert events[0].request_id == "req-EXPLICIT"
    finally:
        _request_id.reset(token)


def test_ensure_is_idempotent_and_never_overwrites():
    events = [_make_event(request_id="req-ALREADY")]
    _ensure_request_id(events, request_id="req-OTHER")
    # An event that already carries an id keeps it (shared objects reach several
    # sinks; re-stamping must not rewrite history).
    assert events[0].request_id == "req-ALREADY"


def test_ensure_noop_without_any_id():
    # No ContextVar, no explicit id -> events are left untouched (no crash).
    token = _request_id.set(None)
    try:
        events = [_make_event()]
        _ensure_request_id(events)
        assert events[0].request_id is None
    finally:
        _request_id.reset(token)


def test_ensure_order_independent_shared_object():
    # Model the real sink fan-out: the SAME event object is handed to _log_events,
    # then the webhook alerter, then recent-blocks. The first stamp wins and the
    # later idempotent calls observe the identical id.
    ev = _make_event()
    shared = [ev]
    _ensure_request_id(shared, request_id="req-SHARED")
    # Later sinks (no explicit id, empty ContextVar) must not clear/replace it.
    _ensure_request_id(shared)
    assert ev.request_id == "req-SHARED"


def test_stamped_request_id_within_field_bound():
    # A honoured inbound id is already length-bounded by the middleware charset,
    # so it always fits SecurityEvent.request_id (max_length=128).
    rid = _resolve_request_id("a" * 128)
    ev = _make_event()
    _ensure_request_id([ev], request_id=rid)
    assert ev.request_id == rid
    assert len(ev.request_id) <= 128


def test_fresh_id_uniqueness():
    ids = {_resolve_request_id(None) for _ in range(200)}
    assert len(ids) == 200
    # Sanity: our reference generator agrees on shape.
    assert _HEX32.match(uuid4().hex)
