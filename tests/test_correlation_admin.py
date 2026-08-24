"""Tests for the admin Correlation Engine surface.

Covers:
  - correlation route helpers (_defaults / _numeric_bounds / _read_override /
    _decay / _summarize_origin / _all_risk_keys / _can_write).
  - correlation endpoints (status / config fields / origins / config PUT+DELETE /
    delete origin / reset) against a fake Redis.
  - RBAC wiring for correlation:* permissions.
"""

from __future__ import annotations

import fnmatch
import time
from datetime import datetime, timedelta, timezone

import pytest

from admin.models.auth import TokenPayload, UserRole

# ═══════════════════════════════════════════════════════════════════════
# Fakes
# ═══════════════════════════════════════════════════════════════════════


class FakeRedis:
    """Minimal decode_responses-style Redis: hashes + TTL + scan."""

    def __init__(self):
        self.hashes: dict[str, dict[str, str]] = {}
        self.ttls: dict[str, int] = {}
        self.fail_ping = False

    def ping(self):
        if self.fail_ping:
            raise ConnectionError("no redis")
        return True

    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    def hset(self, key, field=None, value=None, mapping=None):
        h = self.hashes.setdefault(key, {})
        if mapping:
            for k, v in mapping.items():
                h[k] = str(v)
        elif field is not None:
            h[field] = str(value)

    def ttl(self, key):
        return self.ttls.get(key, -1)

    def scan_iter(self, match="*", count=100):
        for k in list(self.hashes):
            if fnmatch.fnmatch(k, match):
                yield k

    def delete(self, *keys):
        n = 0
        for k in keys:
            if k in self.hashes:
                del self.hashes[k]
                n += 1
        return n


class FakeAudit:
    def __init__(self):
        self.entries = []

    async def log(self, **kwargs):
        self.entries.append(kwargs)


def _token(role: UserRole) -> TokenPayload:
    now = datetime.now(timezone.utc)
    return TokenPayload(sub=f"{role.value}-user", role=role, exp=now + timedelta(hours=1), iat=now)


def _admin() -> TokenPayload:
    return _token(UserRole.ADMIN)


def _viewer() -> TokenPayload:
    return _token(UserRole.VIEWER)


_DIGEST_A = "a1b2c3d4e5f60718"
_DIGEST_B = "0011223344556677"


def _seed_origins(r: FakeRedis, now: float | None = None):
    """One tenant + two session origins with accumulated (fresh) risk."""
    now = now or time.time()
    r.hashes[f"bulwark:risk:session:{_DIGEST_A}"] = {"score": "6.0", "ts": str(now)}
    r.ttls[f"bulwark:risk:session:{_DIGEST_A}"] = 800
    r.hashes[f"bulwark:risk:session:{_DIGEST_B}"] = {"score": "2.0", "ts": str(now)}
    r.ttls[f"bulwark:risk:session:{_DIGEST_B}"] = 400
    r.hashes[f"bulwark:risk:tenant:{_DIGEST_A}"] = {"score": "3.0", "ts": str(now)}
    r.ttls[f"bulwark:risk:tenant:{_DIGEST_A}"] = 900


# ═══════════════════════════════════════════════════════════════════════
# route helpers
# ═══════════════════════════════════════════════════════════════════════


class TestCorrelationHelpers:
    def test_defaults_shape(self):
        from admin.routes.correlation import _defaults

        d = _defaults()
        assert d["risk_block_threshold"] == 7.0
        assert d["risk_warn_threshold"] == 4.0
        assert d["blocking"] is False
        assert d["event_bump_warn"] == 0.5

    def test_numeric_bounds(self):
        from admin.routes.correlation import _numeric_bounds

        b = _numeric_bounds()
        assert b["risk_block_threshold"] == (0.1, 10.0)
        assert "blocking" not in b

    def test_read_override_filters_invalid(self):
        from admin.routes.correlation import _read_override

        r = FakeRedis()
        r.hashes["bulwark:correlation:config"] = {
            "risk_block_threshold": "6.5",
            "blocking": "true",
            "risk_warn_threshold": "999",   # out of bounds → dropped
            "bogus": "5",                    # unknown → ignored
        }
        ov = _read_override(r)
        assert ov == {"risk_block_threshold": 6.5, "blocking": True}

    def test_read_override_absent(self):
        from admin.routes.correlation import _read_override

        assert _read_override(FakeRedis()) == {}

    def test_decay_halves_at_half_life(self):
        from admin.routes.correlation import _decay

        assert _decay(8.0, 0.0, 900.0) == 8.0
        assert _decay(8.0, 900.0, 900.0) == pytest.approx(4.0, abs=0.01)
        assert _decay(8.0, 1800.0, 900.0) == pytest.approx(2.0, abs=0.01)

    def test_summarize_origin(self):
        from admin.routes.correlation import _summarize_origin

        r = FakeRedis()
        now = time.time()
        _seed_origins(r, now)
        s = _summarize_origin(r, f"bulwark:risk:session:{_DIGEST_A}", 900.0, now)
        assert s["scope_type"] == "session"
        assert s["digest"] == _DIGEST_A
        assert s["score"] == pytest.approx(6.0, abs=0.05)
        assert s["stored_score"] == 6.0
        assert s["ttl_seconds"] == 800

    def test_summarize_origin_rejects_bad_scope(self):
        from admin.routes.correlation import _summarize_origin

        r = FakeRedis()
        r.hashes["bulwark:risk:bogus:" + _DIGEST_A] = {"score": "5", "ts": str(time.time())}
        assert _summarize_origin(r, "bulwark:risk:bogus:" + _DIGEST_A, 900.0, time.time()) is None

    def test_summarize_origin_rejects_bad_digest(self):
        from admin.routes.correlation import _summarize_origin

        r = FakeRedis()
        key = "bulwark:risk:session:not-hex!"
        r.hashes[key] = {"score": "5", "ts": str(time.time())}
        assert _summarize_origin(r, key, 900.0, time.time()) is None

    def test_all_risk_keys(self):
        from admin.routes.correlation import _all_risk_keys

        r = FakeRedis()
        _seed_origins(r)
        r.hashes["bulwark:correlation:config"] = {"blocking": "1"}
        keys = _all_risk_keys(r)
        assert f"bulwark:risk:session:{_DIGEST_A}" in keys
        assert "bulwark:correlation:config" not in keys  # config not a risk key

    def test_can_write_by_role(self):
        from admin.routes.correlation import _can_write

        assert _can_write(_admin()) is True
        assert _can_write(_viewer()) is False


# ═══════════════════════════════════════════════════════════════════════
# endpoints
# ═══════════════════════════════════════════════════════════════════════


class TestCorrelationEndpoints:
    @pytest.fixture
    def wired(self, monkeypatch):
        import admin.routes.correlation as correlation

        r = FakeRedis()
        _seed_origins(r)
        audit = FakeAudit()
        monkeypatch.setattr(correlation, "_redis", lambda: r)
        monkeypatch.setattr(correlation, "get_audit_logger", lambda: audit)
        return correlation, r, audit

    async def test_status(self, wired):
        correlation, _, _ = wired
        out = await correlation.correlation_status(user=_admin())
        assert out["redis_connected"] is True
        assert out["can_write"] is True
        assert out["active_origins"] == 3
        assert out["effective"]["risk_block_threshold"] == 7.0
        assert out["overridden"] is False

    async def test_status_reflects_override(self, wired):
        correlation, r, _ = wired
        r.hashes["bulwark:correlation:config"] = {"risk_block_threshold": "5.0", "blocking": "true"}
        out = await correlation.correlation_status(user=_admin())
        assert out["overridden"] is True
        assert out["effective"]["risk_block_threshold"] == 5.0
        assert out["effective"]["blocking"] is True
        assert out["defaults"]["risk_block_threshold"] == 7.0  # defaults unchanged

    async def test_status_viewer_cannot_write(self, wired):
        correlation, _, _ = wired
        out = await correlation.correlation_status(user=_viewer())
        assert out["can_write"] is False

    async def test_config_fields(self, wired):
        correlation, _, _ = wired
        out = await correlation.correlation_config_fields(user=_admin())
        assert "blocking" in out["boolean_fields"]
        assert out["numeric_fields"]["risk_block_threshold"] == {"min": 0.1, "max": 10.0}

    async def test_origins_sorted_by_score(self, wired):
        correlation, _, _ = wired
        out = await correlation.correlation_origins(user=_admin())
        assert out["redis_connected"] is True
        assert out["count"] == 3
        scores = [o["score"] for o in out["origins"]]
        assert scores == sorted(scores, reverse=True)
        assert out["origins"][0]["score"] == pytest.approx(6.0, abs=0.05)

    async def test_update_config(self, wired):
        correlation, r, audit = wired
        from admin.routes.correlation import CorrelationConfigUpdate

        out = await correlation.update_correlation_config(
            CorrelationConfigUpdate(risk_block_threshold=5.5, blocking=True), user=_admin()
        )
        assert r.hashes["bulwark:correlation:config"]["risk_block_threshold"] == "5.5"
        assert r.hashes["bulwark:correlation:config"]["blocking"] == "1"
        assert out["override"]["risk_block_threshold"] == 5.5
        assert out["override"]["blocking"] is True
        assert audit.entries[-1]["action"] == "correlation.config_update"

    async def test_update_config_empty_rejected(self, wired):
        correlation, _, _ = wired
        from fastapi import HTTPException

        from admin.routes.correlation import CorrelationConfigUpdate

        with pytest.raises(HTTPException) as ei:
            await correlation.update_correlation_config(CorrelationConfigUpdate(), user=_admin())
        assert ei.value.status_code == 400

    async def test_clear_config(self, wired):
        correlation, r, audit = wired
        r.hashes["bulwark:correlation:config"] = {"risk_block_threshold": "5.0"}
        await correlation.clear_correlation_config(user=_admin())
        assert "bulwark:correlation:config" not in r.hashes
        assert audit.entries[-1]["action"] == "correlation.config_clear"

    async def test_delete_origin(self, wired):
        correlation, r, audit = wired
        out = await correlation.delete_origin("session", _DIGEST_A, user=_admin())
        assert out["keys_deleted"] == 1
        assert f"bulwark:risk:session:{_DIGEST_A}" not in r.hashes
        assert f"bulwark:risk:session:{_DIGEST_B}" in r.hashes  # untouched
        assert audit.entries[-1]["action"] == "correlation.origin_delete"

    async def test_delete_origin_invalid_scope(self, wired):
        correlation, _, _ = wired
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as ei:
            await correlation.delete_origin("bogus", _DIGEST_A, user=_admin())
        assert ei.value.status_code == 400

    async def test_delete_origin_invalid_digest(self, wired):
        correlation, _, _ = wired
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as ei:
            await correlation.delete_origin("session", "not-a-hash!", user=_admin())
        assert ei.value.status_code == 400

    async def test_reset_all(self, wired):
        correlation, r, audit = wired
        r.hashes["bulwark:correlation:config"] = {"risk_block_threshold": "5.0"}
        out = await correlation.reset_all_origins(user=_admin())
        assert out["keys_deleted"] == 3
        assert not any(k.startswith("bulwark:risk:") for k in r.hashes)
        assert "bulwark:correlation:config" in r.hashes  # config preserved
        assert audit.entries[-1]["action"] == "correlation.reset"

    async def test_origins_no_redis(self, monkeypatch):
        import admin.routes.correlation as correlation

        monkeypatch.setattr(correlation, "_redis", lambda: None)
        out = await correlation.correlation_origins(user=_admin())
        assert out["redis_connected"] is False
        assert out["origins"] == []


class TestCorrelationRbacWiring:
    def test_permissions(self):
        from admin.models.auth import ROLE_PERMISSIONS, UserRole

        assert "correlation:read" in ROLE_PERMISSIONS[UserRole.ADMIN]
        assert "correlation:write" in ROLE_PERMISSIONS[UserRole.ADMIN]
        assert "correlation:write" in ROLE_PERMISSIONS[UserRole.SECURITY]
        assert "correlation:read" in ROLE_PERMISSIONS[UserRole.AUDITOR]
        assert "correlation:write" not in ROLE_PERMISSIONS[UserRole.AUDITOR]
        assert "correlation:read" in ROLE_PERMISSIONS[UserRole.VIEWER]
        assert "correlation:write" not in ROLE_PERMISSIONS[UserRole.VIEWER]

    def test_all_permissions_catalog(self):
        from admin.routes.rbac import ALL_PERMISSIONS

        assert "correlation:read" in ALL_PERMISSIONS
        assert "correlation:write" in ALL_PERMISSIONS
