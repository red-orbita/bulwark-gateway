import pytest
from pydantic import ValidationError

from src.guardrails.backend_egress import BackendEgressPolicy


@pytest.mark.parametrize("url", [
    "https://api.example.com/v1/chat/completions", "https://API.EXAMPLE.COM:443/v1/chat/completions",
    "https://api.example.com./v1/chat/completions",
])
def test_exact_allowed_origin(url):
    policy = BackendEgressPolicy(enabled=True, allowed_origins=("https://api.example.com/",))
    assert policy.permits(url)


@pytest.mark.parametrize("url", [
    "https://api.example.com.attacker.test/v1", "https://attacker.test/api.example.com", "http://api.example.com/v1",
    "https://api.example.com:8443/v1", "https://api.example.com@attacker.test/v1", "https://user@api.example.com/v1",
    "https://api.example.com\\@attacker.test/v1", "https://api%2eexample.com/v1", "file:///etc/passwd",
    "https://api.example.com:0/v1", "https://api.example.com/v1#hidden", " https://api.example.com/v1",
])
def test_origin_bypasses_are_denied(url):
    assert not BackendEgressPolicy(enabled=True, allowed_origins=("https://api.example.com",)).permits(url)


@pytest.mark.parametrize("origin", ["https://*.example.com", "https://api.example.com/path", "https://api.example.com?q=x",
                                    "https://user:password@api.example.com", "https://[fe80::1%eth0]", "https://x:0"])
def test_invalid_allowlist_rejected(origin):
    with pytest.raises(ValidationError):
        BackendEgressPolicy(enabled=True, allowed_origins=(origin,))


def test_enabled_empty_allowlist_rejected():
    with pytest.raises(ValidationError):
        BackendEgressPolicy(enabled=True)


def test_ipv6_and_idna_canonicalization():
    policy = BackendEgressPolicy(enabled=True, allowed_origins=("https://[2001:db8::1]", "https://xn--bcher-kva.example"))
    assert policy.permits("https://[2001:0db8:0:0:0:0:0:1]:443/v1")
    assert policy.permits("https://b\u00fccher.example/v1")


def test_idna_rules_match_httpx_not_python_codec():
    import httpx
    url = "https://fa\u00df.example/v1"
    assert httpx.URL(url).raw_host == b"xn--fa-hia.example"
    assert not BackendEgressPolicy(enabled=True, allowed_origins=("https://fass.example",)).permits(url)
    assert BackendEgressPolicy(enabled=True, allowed_origins=("https://xn--fa-hia.example",)).permits(url)
    assert BackendEgressPolicy(enabled=True, allowed_origins=("https://fa\u00df.example",)).allowed_origins == (
        "https://xn--fa-hia.example",
    )
