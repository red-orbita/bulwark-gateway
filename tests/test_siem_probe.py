"""Tests for the real SIEM connectivity probes (admin/routes/siem.py).

These validate the honest connectivity test that replaced the fabricated
``latency_ms=12.5`` success. Coverage includes host parsing, the SSRF guard
tuned for internal collectors, and per-transport probe behaviour (file / TCP /
TLS / UDP / HTTP) with positive and negative cases.

No external network is used: TCP/UDP positives run against ephemeral local
servers with the loopback SSRF guard patched off (loopback is otherwise blocked
by design), and negatives use closed ports / blocked hosts.
"""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from admin.routes import siem


@pytest.mark.parametrize("transport", ["syslog_tcp", "syslog_udp", "syslog_tls", "tcp_tls", "http_rest"])
async def test_wazuh_network_test_uses_configured_transport(monkeypatch, transport):
    monkeypatch.setattr(siem, "get_audit_logger", lambda: SimpleNamespace(log=AsyncMock()))
    probe = AsyncMock(return_value="network-result")
    manager = AsyncMock(side_effect=AssertionError("Network test must not use manager API"))
    monkeypatch.setattr(siem, "_probe_transport", probe)
    monkeypatch.setattr(siem, "_test_wazuh_connection", manager)
    config = {"platform": "wazuh", "transport_type": transport, "endpoint": "collector.example", "port": 5514}
    assert await siem.test_siem_connection(config, SimpleNamespace(sub="operator")) == "network-result"
    probe.assert_awaited_once_with(config)
    manager.assert_not_awaited()


@pytest.mark.parametrize("transport", [None, "file"])
async def test_wazuh_file_test_keeps_manager_checks(monkeypatch, transport):
    monkeypatch.setattr(siem, "get_audit_logger", lambda: SimpleNamespace(log=AsyncMock()))
    manager = AsyncMock(return_value="manager-result")
    monkeypatch.setattr(siem, "_test_wazuh_connection", manager)
    config = {"platform": "wazuh"}
    if transport is not None:
        config["transport_type"] = transport
    assert await siem.test_siem_connection(config, SimpleNamespace(sub="operator")) == "manager-result"
    manager.assert_awaited_once_with(config)


@pytest.mark.parametrize("url", [None, "", " "])
async def test_wazuh_file_without_api_url_fails_without_network(monkeypatch, url):
    def forbidden(*args):
        pytest.fail("Unconfigured manager test must not resolve an implicit endpoint")

    monkeypatch.setattr(siem, "_validate_url_no_ssrf", forbidden)
    result = await siem._test_wazuh_connection({"wazuh_api_url": url})
    assert not result.success and result.latency_ms == 0
    assert "Configure a Wazuh manager API URL" in result.error


async def test_wazuh_network_route_still_blocks_localhost(monkeypatch):
    monkeypatch.setattr(siem, "get_audit_logger", lambda: SimpleNamespace(log=AsyncMock()))
    result = await siem.test_siem_connection(
        {"platform": "wazuh", "transport_type": "syslog_tcp", "endpoint": "localhost", "port": 5514},
        SimpleNamespace(sub="operator"),
    )
    assert not result.success and "SSRF" in result.error


@pytest.mark.parametrize("transport", ["http_rest", "syslog_tcp", "syslog_udp", "file"])
async def test_slow_dns_validation_does_not_block_event_loop(monkeypatch, transport):
    entered = threading.Event()
    release = threading.Event()
    main_thread = threading.get_ident()
    thread_ids = []

    def slow_validation(*args):
        thread_ids.append(threading.get_ident())
        entered.set()
        release.wait(timeout=2)
        return "Blocked test destination"

    monkeypatch.setattr(siem, "_check_probe_host", slow_validation)
    monkeypatch.setattr(siem, "_validate_url_no_ssrf", slow_validation)
    config = {"platform": "wazuh", "transport_type": transport,
              "endpoint": "collector.example", "wazuh_api_url": "https://collector.example:55000"}
    probe = siem._test_wazuh_connection if transport == "file" else siem._probe_transport
    task = asyncio.create_task(probe(config))
    try:
        async with asyncio.timeout(1):
            while not entered.is_set():
                await asyncio.sleep(0.01)
        assert len(thread_ids) == 1 and thread_ids[0] != main_thread
        assert not task.done(), "The event loop must run while DNS is still pending"
    finally:
        release.set()
        result = await asyncio.wait_for(task, timeout=3)
    assert not result.success and "SSRF" in result.error

# ─── _endpoint_host_port ─────────────────────────────────────────────────────


def test_endpoint_host_port_full_url():
    host, port = siem._endpoint_host_port("https://splunk.example.com:8088/services/collector", 443)
    assert host == "splunk.example.com"
    assert port == 8088


def test_endpoint_host_port_url_default_port():
    host, port = siem._endpoint_host_port("https://splunk.example.com/collector", 443)
    assert host == "splunk.example.com"
    assert port == 443


def test_endpoint_host_port_bare_host_port():
    host, port = siem._endpoint_host_port("collector.corp.net:6514", 514)
    assert host == "collector.corp.net"
    assert port == 6514


def test_endpoint_host_port_bare_host_default():
    host, port = siem._endpoint_host_port("syslog.corp.net", 514)
    assert host == "syslog.corp.net"
    assert port == 514


# ─── _check_probe_host (SSRF guard) ──────────────────────────────────────────


def test_check_probe_host_empty():
    assert siem._check_probe_host("", 514) == "Empty hostname"


def test_check_probe_host_blocked_hostname():
    err = siem._check_probe_host("localhost", 514)
    assert err is not None and "Blocked hostname" in err


def test_check_probe_host_internal_suffix():
    err = siem._check_probe_host("collector.internal", 514)
    assert err is not None and "internal" in err


def test_check_probe_host_loopback_ip():
    err = siem._check_probe_host("127.0.0.1", 514)
    assert err is not None and "blocked range" in err


def test_check_probe_host_metadata_ip():
    err = siem._check_probe_host("169.254.169.254", 80)
    assert err is not None and "blocked range" in err


def test_check_probe_host_ipv6_loopback():
    err = siem._check_probe_host("::1", 514)
    assert err is not None and "blocked range" in err


def test_check_probe_host_allows_rfc1918():
    # Real SIEM collectors live on internal networks — these must be allowed.
    assert siem._check_probe_host("10.0.0.5", 514) is None
    assert siem._check_probe_host("192.168.1.10", 6514) is None
    assert siem._check_probe_host("172.16.4.20", 514) is None


def test_check_probe_host_unresolvable():
    # .invalid is a reserved TLD guaranteed to fail resolution (RFC 6761).
    err = siem._check_probe_host("nonexistent-host.invalid", 514)
    assert err is not None and "Cannot resolve" in err


# ─── _probe_transport dispatch ───────────────────────────────────────────────


async def test_probe_transport_no_endpoint():
    result = await siem._probe_transport({"transport_type": "http_rest", "endpoint": ""})
    assert result.success is False
    assert "No endpoint specified" in result.error


async def test_probe_transport_ssrf_blocked_http():
    result = await siem._probe_transport(
        {"transport_type": "http_rest", "endpoint": "http://localhost:8088", "platform": "splunk"}
    )
    assert result.success is False
    assert "SSRF" in result.error


# ─── _probe_file ─────────────────────────────────────────────────────────────


def test_probe_file_writable(tmp_path):
    endpoint = str(tmp_path / "events.ndjson")
    result = siem._probe_file({"endpoint": endpoint}, "elastic", "file")
    assert result.success is True
    assert "writable" in result.detail.lower()


def test_probe_file_missing_directory():
    result = siem._probe_file(
        {"endpoint": "/nonexistent-dir-xyz-123/events.ndjson"}, "elastic", "file"
    )
    assert result.success is False
    assert "does not exist" in result.error


# ─── _probe_tcp ──────────────────────────────────────────────────────────────


async def test_probe_tcp_success(monkeypatch):
    # Patch off the loopback guard so we can exercise a real local server.
    monkeypatch.setattr(siem, "_check_probe_host", lambda h, p: None)

    async def _handle(reader, writer):
        writer.close()

    server = await asyncio.start_server(_handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await siem._probe_tcp(
            {"endpoint": "127.0.0.1", "port": port}, "qradar", "syslog_tcp", use_tls=False
        )
    finally:
        server.close()
        await server.wait_closed()

    assert result.success is True
    assert "TCP connect OK" in result.detail
    assert result.latency_ms >= 0.0


async def test_probe_tcp_connection_refused(monkeypatch):
    monkeypatch.setattr(siem, "_check_probe_host", lambda h, p: None)
    # Bind then close to obtain a port that is guaranteed closed.
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()

    result = await siem._probe_tcp(
        {"endpoint": "127.0.0.1", "port": port}, "qradar", "syslog_tcp", use_tls=False
    )
    assert result.success is False
    assert "Cannot connect" in result.error


async def test_probe_tcp_ssrf_blocked():
    result = await siem._probe_tcp(
        {"endpoint": "localhost", "port": 514}, "qradar", "syslog_tcp", use_tls=False
    )
    assert result.success is False
    assert "SSRF" in result.error


async def test_probe_tcp_tls_handshake_fails_on_plain_server(monkeypatch):
    # Exercises the use_tls branch: a plain TCP server cannot complete a TLS
    # handshake, so the probe must report failure (not a fabricated success).
    monkeypatch.setattr(siem, "_check_probe_host", lambda h, p: None)

    async def _handle(reader, writer):
        await asyncio.sleep(0.05)
        writer.close()

    server = await asyncio.start_server(_handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await siem._probe_tcp(
            {"endpoint": "127.0.0.1", "port": port}, "custom", "tcp_tls", use_tls=True
        )
    finally:
        server.close()
        await server.wait_closed()

    assert result.success is False
    assert "Cannot connect" in result.error


# ─── _probe_udp ──────────────────────────────────────────────────────────────


async def test_probe_udp_success(monkeypatch):
    monkeypatch.setattr(siem, "_check_probe_host", lambda h, p: None)
    result = await siem._probe_udp(
        {"endpoint": "127.0.0.1", "port": 51999}, "qradar", "syslog_udp"
    )
    # UDP is connectionless: sending succeeds locally and the detail is honest.
    assert result.success is True
    assert "not confirmable" in result.detail


async def test_probe_udp_ssrf_blocked():
    result = await siem._probe_udp(
        {"endpoint": "localhost", "port": 514}, "qradar", "syslog_udp"
    )
    assert result.success is False
    assert "SSRF" in result.error


# ─── _probe_http ─────────────────────────────────────────────────────────────


async def test_probe_http_ssrf_blocked():
    result = await siem._probe_http(
        {"endpoint": "https://localhost:8088", "platform": "splunk"}, "splunk", "http_rest"
    )
    assert result.success is False
    assert "SSRF" in result.error


async def test_probe_http_connect_error(monkeypatch):
    # Allowed host but nothing listening on a closed loopback port → ConnectError.
    monkeypatch.setattr(siem, "_check_probe_host", lambda h, p: None)
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()

    result = await siem._probe_http(
        {"endpoint": f"http://127.0.0.1:{port}", "platform": "elastic"}, "elastic", "http_rest"
    )
    assert result.success is False
    assert result.error  # some connection error surfaced honestly
