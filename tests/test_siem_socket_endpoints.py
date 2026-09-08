"""Socket transport destinations must survive admin create/edit validation."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from admin.routes import siem


@pytest.mark.parametrize("ttype", ["syslog_udp", "syslog_tcp", "syslog_tls", "tcp_tls"])
async def test_socket_create_and_edit_keep_separate_host_port(monkeypatch, ttype):
    monkeypatch.setenv("BULWARK_SIEM_SSRF_ALLOW_PRIVATE", "true")
    monkeypatch.setattr(siem, "_transports", [])
    monkeypatch.setattr(siem, "_save_transports", lambda: None)
    monkeypatch.setattr(siem, "get_audit_logger", lambda: SimpleNamespace(log=AsyncMock()))
    user = SimpleNamespace(sub="test-admin")
    created = await siem.create_transport({
        "transport_type": ttype, "endpoint": "192.168.1.10", "port": 1514,
    }, user=user)
    assert created["endpoint"] == "192.168.1.10"
    updated = await siem.update_transport(created["id"], {"port": 2514}, user=user)
    assert updated["port"] == 2514
    with pytest.raises(HTTPException) as error:
        await siem.update_transport(created["id"], {"endpoint": "127.0.0.1"}, user=user)
    assert error.value.status_code == 400
    assert siem._transports[0]["endpoint"] == "192.168.1.10"


@pytest.mark.parametrize("host", ["127.0.0.1", "169.254.169.254", "::1", "localhost", "collector:1514", "host/path", "user@host"])
def test_socket_invalid_or_restricted_destination(host, monkeypatch):
    monkeypatch.setenv("BULWARK_SIEM_SSRF_ALLOW_PRIVATE", "true")
    assert siem._validate_transport_endpoint({"transport_type": "syslog_tcp", "endpoint": host})


def test_socket_private_requires_opt_in(monkeypatch):
    monkeypatch.delenv("BULWARK_SIEM_SSRF_ALLOW_PRIVATE", raising=False)
    assert siem._validate_transport_endpoint({"transport_type": "syslog_tcp", "endpoint": "192.168.1.10"})


def test_socket_ipv6_private_allowed(monkeypatch):
    monkeypatch.setenv("BULWARK_SIEM_SSRF_ALLOW_PRIVATE", "true")
    assert siem._validate_transport_endpoint({"transport_type": "syslog_tcp", "endpoint": "fd00::2"}) is None


def test_rfc5424_keeps_ecs_fields_and_valid_priority():
    from src.telemetry.schema import from_security_event
    from src.telemetry.transports.syslog import SyslogConfig, SyslogFormat, SyslogTransport

    event = from_security_event(
        verdict="block", rule_id="test", rule_description="Synthetic event\nsecond line",
        threat_category="prompt_injection", tenant_id="test-tenant", agent_id="test-agent",
        guardrail_layer="input", latency_ms=0,
    )
    wire = SyslogTransport(SyslogConfig(format=SyslogFormat.RFC5424))._format_event(event)
    priority, timestamp, host, app, proc, msgid, structured, payload = wire.split(" ", 7)
    assert priority == "<11>1"  # user facility (8) + error severity (3)
    assert (host, app, proc, msgid, structured) == ("bulwark-gateway", "bulwark", "-", "-", "-")
    assert timestamp == event.timestamp
    assert json.loads(payload) == event.to_ecs_json()
    assert "\n" not in wire


@pytest.mark.parametrize("failures,expected,calls", [(1, True, 2), (2, False, 2)])
async def test_syslog_reconnect_retry_is_bounded(monkeypatch, failures, expected, calls):
    from src.telemetry.transports.syslog import SyslogConfig, SyslogProtocol, SyslogTransport

    transport = SyslogTransport(SyslogConfig(protocol=SyslogProtocol.TCP))
    send = AsyncMock(side_effect=[False] * failures + [True])
    monkeypatch.setattr(transport, "_send_once", send)
    assert await transport.send_batch([]) is expected
    assert send.await_count == calls
