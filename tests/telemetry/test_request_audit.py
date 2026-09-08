"""Activity auditing covers clean, rejected, streaming and interrupted requests."""

from types import SimpleNamespace

import pytest

from src.middleware import request_audit


@pytest.mark.parametrize("status", [200, 403, 401, 429, 502])
async def test_one_activity_event_without_payloads_or_untrusted_identity(monkeypatch, status):
    records = []
    monkeypatch.setattr(request_audit.settings, "siem_request_audit_enabled", True)
    monkeypatch.setattr(request_audit, "get_telemetry_queue", lambda: SimpleNamespace(enqueue_nowait=lambda e: records.append(e) or True))
    messages = []
    async def app(scope, receive, send):
        if status != 401:
            scope["state"].update(tenant_id="verified-tenant", agent_id="agent", subject_id="verified-subject")
        await send({"type": "http.response.start", "status": status, "headers": []})
        await send({"type": "http.response.body", "body": b"private-response", "more_body": True})
        await send({"type": "http.response.body", "body": b"private-tail", "more_body": False})
    async def receive():
        pytest.fail("Audit must not read request body")
    async def send(message):
        messages.append(message)
    scope = {"type": "http", "path": "/v1/secret-path", "query_string": b"token=private-query", "method": "POST",
             "state": {"request_id": "trace"}, "headers": [(b"x-tenant-id", b"forged-tenant")],
             "route": SimpleNamespace(path="/v1/{item}")}
    await request_audit.RequestAuditMiddleware(app)(scope, receive, send)
    assert len(records) == 1 and len(messages) == 3
    record = records[0]
    assert record.event.kind == "event"
    assert record.event.action == "request_completed"
    assert record.bulwark.verdict == "not_evaluated"
    assert record.tenant.id == ("unknown" if status == 401 else "verified-tenant")
    assert record.labels["http_status_code"] == str(status)
    assert record.bulwark.request_id == "trace"
    wire = record.model_dump_json()
    assert all(secret not in wire for secret in ("private-response", "private-query", "secret-path", "forged-tenant"))


async def test_interrupted_stream_is_not_success(monkeypatch):
    records = []
    monkeypatch.setattr(request_audit.settings, "siem_request_audit_enabled", True)
    monkeypatch.setattr(request_audit, "get_telemetry_queue", lambda: SimpleNamespace(enqueue_nowait=lambda e: records.append(e) or True))
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        raise RuntimeError("stream disconnected")
    async def noop(*args):
        pass
    with pytest.raises(RuntimeError):
        await request_audit.RequestAuditMiddleware(app)({"type": "http", "path": "/v2/scan", "state": {}}, noop, noop)
    assert records[0].event.action == "request_interrupted"
    assert records[0].event.outcome == "failure"


@pytest.mark.parametrize("enabled,path", [(False, "/v1/chat/completions"), (True, "/health")])
async def test_disabled_and_health_are_inert(monkeypatch, enabled, path):
    monkeypatch.setattr(request_audit.settings, "siem_request_audit_enabled", enabled)
    def unexpected_queue():
        pytest.fail("Queue must stay untouched")
    monkeypatch.setattr(request_audit, "get_telemetry_queue", unexpected_queue)
    async def app(scope, receive, send):
        await send({"type": "http.response.body", "body": b"ok"})
    async def noop(*args):
        pass
    await request_audit.RequestAuditMiddleware(app)({"type": "http", "path": path}, noop, noop)


async def test_queue_error_never_breaks_response(monkeypatch):
    monkeypatch.setattr(request_audit.settings, "siem_request_audit_enabled", True)
    def broken_queue():
        raise OSError("disk unavailable")
    monkeypatch.setattr(request_audit, "get_telemetry_queue", broken_queue)
    async def app(scope, receive, send):
        await send({"type": "http.response.body", "body": b"ok"})
    async def noop(*args):
        pass
    await request_audit.RequestAuditMiddleware(app)({"type": "http", "path": "/v1/chat/completions"}, noop, noop)
