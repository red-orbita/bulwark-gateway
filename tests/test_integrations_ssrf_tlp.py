"""Regression tests for S-24 (configurable unmarked-TLP fail-closed default) and
S-25 (SSRF egress guard + no redirect-following on the integration connectors).

S-24: an investigation observable that carries NO explicit ``tlp`` marking is
treated as ``BULWARK_INVESTIGATION_DEFAULT_TLP`` (default ``amber`` = shareable)
by every external-push data-sharing gate. A data-sharing-strict deployment sets
``red`` so an unmarked-but-sensitive indicator is excluded from any outward push
until an operator marks it explicitly. An unrecognised value fails safe to
``amber`` (a parse fallback, never fail-open sharing).

S-25: the concrete HTTP connectors (opencti/misp/thehive/dfir_iris/cortex) run
the SAME shared SSRF guard TAXII uses against their operator-supplied
``base_url`` before every request, so a connector pointed at cloud-metadata or an
internal-only host is refused (without tripping the circuit breaker), and no
client follows redirects (a 3xx to an internal target cannot smuggle egress).
"""

from __future__ import annotations

import pytest

from admin.services.integrations import misp, opencti, taxii
from admin.services.integrations.base import ConnectorError, HttpConnectorBase
from admin.services.investigation_observable_store import default_tlp

# ─── S-24: default_tlp() resolution ──────────────────────────────────────────

def test_default_tlp_is_amber_by_default(monkeypatch):
    """Backward-compatible: with no override an unmarked observable is amber."""
    _patch_settings(monkeypatch, "amber")
    assert default_tlp() == "amber"


def test_default_tlp_honours_strict_red(monkeypatch):
    _patch_settings(monkeypatch, "red")
    assert default_tlp() == "red"


def test_default_tlp_accepts_all_known_levels(monkeypatch):
    for level in ("red", "amber", "green", "white"):
        _patch_settings(monkeypatch, level)
        assert default_tlp() == level


def test_default_tlp_case_insensitive(monkeypatch):
    _patch_settings(monkeypatch, "RED")
    assert default_tlp() == "red"


def test_default_tlp_garbage_fails_safe_to_amber(monkeypatch):
    """An unrecognised configured value degrades to amber — a fail-safe *parse*,
    never a fail-open (which would be to silently share)."""
    _patch_settings(monkeypatch, "totally-bogus")
    assert default_tlp() == "amber"


def test_default_tlp_empty_fails_safe_to_amber(monkeypatch):
    _patch_settings(monkeypatch, "")
    assert default_tlp() == "amber"


# ─── S-24: the push gates honour the configured default for unmarked obs ──────

@pytest.mark.parametrize(
    "is_restricted",
    [misp._is_restricted, opencti._is_restricted, taxii._is_restricted],
)
def test_unmarked_observable_shareable_by_default(monkeypatch, is_restricted):
    _patch_settings(monkeypatch, "amber")
    assert is_restricted({"value": "1.2.3.4"}) is False


@pytest.mark.parametrize(
    "is_restricted",
    [misp._is_restricted, opencti._is_restricted, taxii._is_restricted],
)
def test_unmarked_observable_restricted_when_default_red(monkeypatch, is_restricted):
    """The core S-24 win: flip the default to red and an UNMARKED observable is
    now excluded from every external push gate."""
    _patch_settings(monkeypatch, "red")
    assert is_restricted({"value": "1.2.3.4"}) is True


@pytest.mark.parametrize(
    "is_restricted",
    [misp._is_restricted, opencti._is_restricted, taxii._is_restricted],
)
def test_explicit_marking_overrides_default(monkeypatch, is_restricted):
    """An explicitly-marked observable is unaffected by the unmarked default."""
    _patch_settings(monkeypatch, "red")
    assert is_restricted({"value": "1.2.3.4", "tlp": "green"}) is False


def test_select_tlp_helpers_default_unmarked(monkeypatch):
    """The most-restrictive-marking selectors treat unmarked as the default."""
    _patch_settings(monkeypatch, "amber")
    assert taxii.select_publish_tlp([{"value": "a"}]) == "amber"
    assert misp.select_event_tlp([{"value": "a"}]) == "amber"
    assert opencti.select_report_marking([{"value": "a"}]) == "amber"


# ─── S-25: SSRF egress guard on the shared connector base ─────────────────────

def _base(url: str) -> HttpConnectorBase:
    return HttpConnectorBase(base_url=url)


async def test_request_blocks_cloud_metadata_base_url():
    """A connector pointed at the cloud-metadata link-local address is refused
    BEFORE any socket is opened."""
    conn = _base("http://169.254.169.254/latest/meta-data")
    with pytest.raises(ConnectorError) as exc:
        await conn._request("GET", "/x")
    assert "SSRF protection" in str(exc.value)


async def test_request_blocks_loopback_base_url():
    conn = _base("http://127.0.0.1:8080")
    with pytest.raises(ConnectorError) as exc:
        await conn._request("GET", "/x")
    assert "SSRF protection" in str(exc.value)


async def test_request_blocks_rfc1918_base_url():
    conn = _base("http://10.0.0.5")
    with pytest.raises(ConnectorError) as exc:
        await conn._request("GET", "/x")
    assert "SSRF protection" in str(exc.value)


async def test_ssrf_block_does_not_trip_circuit():
    """A config-level SSRF rejection is not a remote flap — it must NOT record a
    circuit-breaker failure (otherwise a mis-typed host would 'open' the circuit
    and mask the real reason)."""
    conn = _base("http://169.254.169.254")
    assert conn._circuit.can_execute() is True
    for _ in range(10):
        with pytest.raises(ConnectorError):
            await conn._request("GET", "/x")
    # Circuit still closed — no failures were recorded by the SSRF path.
    assert conn._circuit.can_execute() is True


async def test_egress_guard_error_returns_none_for_public_host():
    """Sanity: the guard passes a public host (DNS resolves off-box). Skipped if
    the sandbox has no outbound DNS."""
    conn = _base("https://example.com")
    try:
        err = conn._egress_guard_error()
    except Exception:  # pragma: no cover - environment without DNS
        pytest.skip("no outbound DNS in sandbox")
    assert err is None


def test_clients_do_not_follow_redirects():
    """S-25: both the pooled and short-lived client factories must construct with
    ``follow_redirects=False`` so a 3xx to an internal target is not chased."""
    import inspect

    src = inspect.getsource(HttpConnectorBase)
    # Two AsyncClient constructions (pooled __aenter__ + short-lived _request),
    # each must pin follow_redirects=False.
    assert src.count("follow_redirects=False") >= 2
    assert "follow_redirects=True" not in src


# ─── helpers ─────────────────────────────────────────────────────────────────

def _patch_settings(monkeypatch, value: str) -> None:
    """Point ``default_tlp``'s lazily-imported ``src.config.settings`` at a stub
    carrying the given ``investigation_default_tlp``."""
    import src.config as cfg

    monkeypatch.setattr(cfg.settings, "investigation_default_tlp", value, raising=False)
