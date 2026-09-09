"""Regression tests for 3rd-pass egress SSRF hardening (B1, B2, C-29).

B1  admin/services/ioc_store.py  — feed-URL SSRF blocklist parity with the proxy
    (adds 0.0.0.0/8 and IPv4-mapped IPv6 encodings that previously leaked through).
B2  admin/services/ioc_store.py  — feed fetchers follow redirects MANUALLY, so a
    3xx from a public feed host to an internal address can no longer be
    auto-followed to cloud metadata / loopback.
C-29 src/telemetry/notifications.py — operator-configured webhook URLs are SSRF
    validated at send-time and redirects are not auto-followed.
"""

from __future__ import annotations

import pytest

from admin.services import ioc_store
from src.telemetry import notifications

# ─── B1: extended blocklist parity ───────────────────────────────────────────


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",   # AWS/GCP/Azure metadata
        "http://127.0.0.1/internal",                  # loopback
        "http://0.0.0.0/",                            # "this" network → loopback on Linux
        "http://10.0.0.5/",                           # RFC1918 A
        "http://172.16.0.9/",                         # RFC1918 B
        "http://192.168.1.10/",                       # RFC1918 C
        "http://100.64.0.1/",                         # CGNAT
        "http://[::1]/",                              # IPv6 loopback
        "http://localhost/",                          # blocked hostname
        "http://foo.internal/",                       # blocked suffix
    ],
)
def test_b1_blocked_targets_are_rejected(monkeypatch, url):
    # Force DNS to resolve literals/hostnames to their own value so getaddrinfo
    # never hits the network (localhost/foo.internal short-circuit before DNS).
    def _fake_getaddrinfo(host, port, proto=0):
        # Map hostnames used below to an internal IP to exercise the IP path too.
        return [(2, 1, 6, "", (host if _looks_ipv4(host) else "10.0.0.5", port or 443))]

    monkeypatch.setattr(ioc_store.socket, "getaddrinfo", _fake_getaddrinfo)
    assert ioc_store._validate_url_no_ssrf(url) is not None


def test_b1_ipv4_mapped_metadata_is_normalised(monkeypatch):
    # ::ffff:169.254.169.254 must be normalised to 169.254.* and blocked.
    def _fake_getaddrinfo(host, port, proto=0):
        return [(10, 1, 6, "", ("::ffff:169.254.169.254", port or 443, 0, 0))]

    monkeypatch.setattr(ioc_store.socket, "getaddrinfo", _fake_getaddrinfo)
    assert ioc_store._validate_url_no_ssrf("http://feed.example.com/") is not None


def test_b1_public_target_is_allowed(monkeypatch):
    def _fake_getaddrinfo(host, port, proto=0):
        return [(2, 1, 6, "", ("93.184.216.34", port or 443))]  # example.com public IP

    monkeypatch.setattr(ioc_store.socket, "getaddrinfo", _fake_getaddrinfo)
    assert ioc_store._validate_url_no_ssrf("https://feed.example.com/iocs") is None


def _looks_ipv4(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


# ─── B2: redirect to internal target is not followed ─────────────────────────


class _FakeResp:
    def __init__(self, status_code=200, headers=None, text="", json_data=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self._json = json_data

    @property
    def is_redirect(self):
        return self.status_code in (301, 302, 303, 307, 308)

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


def test_b2_redirect_to_metadata_is_blocked(monkeypatch):
    """A public feed 302-redirecting to 169.254.169.254 must be refused."""
    calls = {"n": 0}

    def _fake_request(method, url, headers=None, follow_redirects=False, **kwargs):
        calls["n"] += 1
        # First hop: public host redirects to metadata.
        return _FakeResp(302, headers={"location": "http://169.254.169.254/latest/"})

    def _fake_getaddrinfo(host, port, proto=0):
        if host == "feed.example.com":
            return [(2, 1, 6, "", ("93.184.216.34", port or 443))]
        return [(2, 1, 6, "", ("169.254.169.254", port or 443))]

    import httpx

    monkeypatch.setattr(httpx, "request", _fake_request)
    monkeypatch.setattr(ioc_store.socket, "getaddrinfo", _fake_getaddrinfo)

    with pytest.raises(RuntimeError, match="SSRF"):
        ioc_store._safe_httpx_request("GET", "https://feed.example.com/iocs")


def test_b2_public_redirect_is_followed(monkeypatch):
    """A redirect between public hosts is followed (legit behaviour preserved)."""
    seq = [
        _FakeResp(302, headers={"location": "https://cdn.example.net/iocs"}),
        _FakeResp(200, text="ok"),
    ]

    def _fake_request(method, url, headers=None, follow_redirects=False, **kwargs):
        return seq.pop(0)

    def _fake_getaddrinfo(host, port, proto=0):
        return [(2, 1, 6, "", ("93.184.216.34", port or 443))]

    import httpx

    monkeypatch.setattr(httpx, "request", _fake_request)
    monkeypatch.setattr(ioc_store.socket, "getaddrinfo", _fake_getaddrinfo)

    resp = ioc_store._safe_httpx_request("GET", "https://feed.example.com/iocs")
    assert resp.status_code == 200
    assert resp.text == "ok"


def test_b2_cross_host_redirect_drops_credentials(monkeypatch):
    """Auth headers must not be forwarded to a different host on redirect."""
    seen_headers = []

    def _fake_request(method, url, headers=None, follow_redirects=False, **kwargs):
        seen_headers.append(headers or {})
        if len(seen_headers) == 1:
            return _FakeResp(302, headers={"location": "https://other.example.net/x"})
        return _FakeResp(200, text="done")

    def _fake_getaddrinfo(host, port, proto=0):
        return [(2, 1, 6, "", ("93.184.216.34", port or 443))]

    import httpx

    monkeypatch.setattr(httpx, "request", _fake_request)
    monkeypatch.setattr(ioc_store.socket, "getaddrinfo", _fake_getaddrinfo)

    ioc_store._safe_httpx_request(
        "GET", "https://feed.example.com/x", headers={"Authorization": "secret-key"}
    )
    assert "Authorization" in seen_headers[0]          # first hop keeps creds
    assert "Authorization" not in seen_headers[1]       # cross-host hop drops them


def test_b2_redirect_loop_is_bounded(monkeypatch):
    def _fake_request(method, url, headers=None, follow_redirects=False, **kwargs):
        return _FakeResp(302, headers={"location": "https://loop.example.com/next"})

    def _fake_getaddrinfo(host, port, proto=0):
        return [(2, 1, 6, "", ("93.184.216.34", port or 443))]

    import httpx

    monkeypatch.setattr(httpx, "request", _fake_request)
    monkeypatch.setattr(ioc_store.socket, "getaddrinfo", _fake_getaddrinfo)

    with pytest.raises(RuntimeError, match="redirect"):
        ioc_store._safe_httpx_request("GET", "https://loop.example.com/start")


# ─── C-29: notification webhook SSRF guard ───────────────────────────────────


@pytest.mark.asyncio
async def test_c29_internal_webhook_is_blocked(monkeypatch):
    async def _fake_getaddrinfo(host, port, proto=0):
        return [(2, 1, 6, "", ("169.254.169.254", port or 443))]

    class _Loop:
        async def getaddrinfo(self, *a, **k):
            return await _fake_getaddrinfo(*a, **k)

    monkeypatch.setattr(notifications.asyncio, "get_event_loop", lambda: _Loop())
    reason = await notifications._notify_url_ssrf_error("http://metadata/latest")
    assert reason is not None


@pytest.mark.asyncio
async def test_c29_localhost_webhook_is_blocked():
    reason = await notifications._notify_url_ssrf_error("http://localhost:8080/hook")
    assert reason is not None


@pytest.mark.asyncio
async def test_c29_public_webhook_is_allowed(monkeypatch):
    class _Loop:
        async def getaddrinfo(self, *a, **k):
            return [(2, 1, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(notifications.asyncio, "get_event_loop", lambda: _Loop())
    reason = await notifications._notify_url_ssrf_error("https://hooks.slack.com/services/x")
    assert reason is None


@pytest.mark.asyncio
async def test_c29_non_http_scheme_blocked():
    assert await notifications._notify_url_ssrf_error("file:///etc/passwd") is not None
    assert await notifications._notify_url_ssrf_error("gopher://x/") is not None


@pytest.mark.asyncio
async def test_c29_client_disables_auto_redirects():
    engine = notifications.NotificationEngine()
    client = await engine._get_client()
    try:
        assert client.follow_redirects is False
    finally:
        await client.aclose()
