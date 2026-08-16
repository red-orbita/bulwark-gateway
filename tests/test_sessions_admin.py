"""Tests for the admin Session Decomposition Tracker surface.

Covers:
  - SessionDecompositionTracker runtime override (Redis-driven thresholds +
    windows) with throttled refresh + instance-attr shadowing — the proxy side
    of the admin tuning controls.
  - sessions route helpers (_num / _defaults / _catalog / _read_override /
    _summarize_session / _all_session_keys / _can_write).
  - sessions endpoints (status / signals / active / config PUT+DELETE /
    delete session / reset) against a fake Redis.
  - RBAC wiring for sessions:* permissions.
"""

from __future__ import annotations

import fnmatch
from datetime import datetime, timedelta, timezone

import pytest

from admin.models.auth import TokenPayload, UserRole

# ═══════════════════════════════════════════════════════════════════════
# Fakes
# ═══════════════════════════════════════════════════════════════════════


class FakeRedis:
    """Minimal decode_responses-style Redis: hashes + sorted sets + TTL."""

    def __init__(self):
        self.hashes: dict[str, dict[str, str]] = {}
        self.zsets: dict[str, dict[str, float]] = {}
        self.ttls: dict[str, int] = {}
        self.fail_ping = False

    def ping(self):
        if self.fail_ping:
            raise ConnectionError("no redis")
        return True

    # --- hashes ---
    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    def hset(self, key, field=None, value=None, mapping=None):
        h = self.hashes.setdefault(key, {})
        if mapping:
            for k, v in mapping.items():
                h[k] = str(v)
        elif field is not None:
            h[field] = str(value)

    # --- sorted sets ---
    def zadd(self, key, mapping):
        z = self.zsets.setdefault(key, {})
        for member, score in mapping.items():
            z[member] = float(score)

    def zrange(self, key, start, stop, withscores=False):
        items = sorted(self.zsets.get(key, {}).items(), key=lambda kv: kv[1])
        # emulate inclusive python-style slice semantics of redis zrange
        if stop == -1:
            sliced = items[start:]
        else:
            sliced = items[start:stop + 1]
        if withscores:
            return [(m, s) for m, s in sliced]
        return [m for m, _ in sliced]

    def ttl(self, key):
        return self.ttls.get(key, -1)

    # --- keys / scan ---
    def _all_keys(self):
        return set(self.hashes) | set(self.zsets)

    def scan_iter(self, match="*", count=100):
        for k in list(self._all_keys()):
            if fnmatch.fnmatch(k, match):
                yield k

    def delete(self, *keys):
        n = 0
        for k in keys:
            if k in self.hashes:
                del self.hashes[k]
                n += 1
            if k in self.zsets:
                del self.zsets[k]
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


_KEY_A = "a1b2c3d4e5f60718"
_KEY_B = "0011223344556677"


def _seed_sessions(r: FakeRedis):
    """Two 5m sessions + one 30m session with accumulated signals."""
    r.zsets[f"bulwark:session:{_KEY_A}:signals"] = {
        "shellcode:3.0": 1000.0,
        "reverse_shell:3.5": 1001.0,
    }
    r.ttls[f"bulwark:session:{_KEY_A}:signals"] = 240
    r.zsets[f"bulwark:session:{_KEY_B}:signals"] = {
        "xss:1.5": 1002.0,
    }
    r.ttls[f"bulwark:session:{_KEY_B}:signals"] = 120
    r.zsets[f"bulwark:session_30m:{_KEY_A}:signals"] = {
        "recon:1.5": 900.0,
        "exfiltration:2.5": 950.0,
    }
    r.ttls[f"bulwark:session_30m:{_KEY_A}:signals"] = 1700


# ═══════════════════════════════════════════════════════════════════════
# Tracker runtime override (src/ change)
# ═══════════════════════════════════════════════════════════════════════


class TestSessionTrackerRuntimeOverride:
    def _tracker(self):
        from src.guardrails.session_tracker import SessionDecompositionTracker

        t = SessionDecompositionTracker()
        t._redis = None
        return t

    def test_seeds_instance_defaults_from_class(self):
        from src.guardrails.session_tracker import SessionDecompositionTracker as T

        t = self._tracker()
        assert t.BLOCK_THRESHOLD == T.BLOCK_THRESHOLD
        assert t.WINDOW_SECONDS == T.WINDOW_SECONDS
        assert t.BLOCK_THRESHOLD_30M == T.BLOCK_THRESHOLD_30M

    def test_no_redis_is_noop(self):
        t = self._tracker()
        t._refresh_runtime_config()  # no redis → nothing changes, no error
        assert t.BLOCK_THRESHOLD == 8.0

    def test_override_applies_thresholds_and_windows(self):
        t = self._tracker()
        r = FakeRedis()
        r.hashes["bulwark:session:config"] = {
            "block_threshold": "6.5",
            "warn_threshold": "3.5",
            "window_seconds": "600",
            "block_threshold_30m": "4.0",
            "warn_threshold_30m": "2.0",
            "window_30m_seconds": "3600",
        }
        t._redis = r
        t._runtime_checked_at = 0.0
        t._refresh_runtime_config()
        assert t.BLOCK_THRESHOLD == 6.5
        assert t.WARN_THRESHOLD == 3.5
        assert t.WINDOW_SECONDS == 600
        assert isinstance(t.WINDOW_SECONDS, int)
        assert t.BLOCK_THRESHOLD_30M == 4.0
        assert t.WARN_THRESHOLD_30M == 2.0
        assert t.WINDOW_30M_SECONDS == 3600

    def test_refresh_is_throttled(self):
        import time

        t = self._tracker()
        r = FakeRedis()
        r.hashes["bulwark:session:config"] = {"block_threshold": "2.0"}
        t._redis = r
        t._runtime_checked_at = time.time()  # just checked → skip
        t._refresh_runtime_config()
        assert t.BLOCK_THRESHOLD == 8.0  # not applied (throttled)
        t._runtime_checked_at = 0.0
        t._refresh_runtime_config()
        assert t.BLOCK_THRESHOLD == 2.0

    def test_malformed_and_negative_ignored(self):
        t = self._tracker()
        r = FakeRedis()
        r.hashes["bulwark:session:config"] = {
            "block_threshold": "-1",
            "warn_threshold": "not-a-number",
            "window_seconds": "0",
        }
        t._redis = r
        t._runtime_checked_at = 0.0
        t._refresh_runtime_config()
        assert t.BLOCK_THRESHOLD == 8.0
        assert t.WARN_THRESHOLD == 5.0
        assert t.WINDOW_SECONDS == 300

    def test_partial_override_only_touches_present_fields(self):
        t = self._tracker()
        r = FakeRedis()
        r.hashes["bulwark:session:config"] = {"warn_threshold": "4.2"}
        t._redis = r
        t._runtime_checked_at = 0.0
        t._refresh_runtime_config()
        assert t.WARN_THRESHOLD == 4.2
        assert t.BLOCK_THRESHOLD == 8.0  # untouched


# ═══════════════════════════════════════════════════════════════════════
# sessions route helpers
# ═══════════════════════════════════════════════════════════════════════


class TestSessionsHelpers:
    def test_num_parsing(self):
        from admin.routes.sessions import _num

        assert _num("6.5", False) == 6.5
        assert _num("600", True) == 600
        assert _num("0", False) is None
        assert _num("-3", True) is None
        assert _num("bad", False) is None

    def test_defaults_shape(self):
        from admin.routes.sessions import _CONFIG_FIELDS, _defaults

        d = _defaults()
        assert set(d) == set(_CONFIG_FIELDS)
        assert d["block_threshold"] == 8.0
        assert d["window_seconds"] == 300

    def test_catalog_nonempty(self):
        from admin.routes.sessions import _catalog

        cat = _catalog()
        assert len(cat["signals"]) > 20
        assert all("signal_id" in s and "weight" in s for s in cat["signals"])
        assert len(cat["combinations"]) >= 5
        assert all("description" in c and "signals" in c for c in cat["combinations"])

    def test_read_override_filters_invalid(self):
        from admin.routes.sessions import _read_override

        r = FakeRedis()
        r.hashes["bulwark:session:config"] = {
            "block_threshold": "6.5",
            "window_seconds": "-1",  # invalid → dropped
            "bogus": "5",            # unknown → ignored
        }
        ov = _read_override(r)
        assert ov == {"block_threshold": 6.5}

    def test_read_override_absent(self):
        from admin.routes.sessions import _read_override

        assert _read_override(FakeRedis()) == {}

    def test_summarize_session(self):
        from admin.routes.sessions import _summarize_session

        r = FakeRedis()
        _seed_sessions(r)
        s = _summarize_session(r, f"bulwark:session:{_KEY_A}:signals", "5m")
        assert s["session_key"] == _KEY_A
        assert s["window"] == "5m"
        assert s["score"] == 6.5  # 3.0 + 3.5
        assert s["signal_count"] == 2
        assert set(s["distinct_signals"]) == {"shellcode", "reverse_shell"}
        assert s["ttl_seconds"] == 240

    def test_summarize_empty_returns_none(self):
        from admin.routes.sessions import _summarize_session

        assert _summarize_session(FakeRedis(), "bulwark:session:x:signals", "5m") is None

    def test_all_session_keys_classifies_windows(self):
        from admin.routes.sessions import _all_session_keys

        r = FakeRedis()
        _seed_sessions(r)
        keys = dict(_all_session_keys(r))
        assert keys[f"bulwark:session:{_KEY_A}:signals"] == "5m"
        assert keys[f"bulwark:session:{_KEY_B}:signals"] == "5m"
        assert keys[f"bulwark:session_30m:{_KEY_A}:signals"] == "30m"
        # config hash must not be picked up as a session
        r.hashes["bulwark:session:config"] = {"block_threshold": "6"}
        assert "bulwark:session:config" not in dict(_all_session_keys(r))

    def test_can_write_by_role(self):
        from admin.routes.sessions import _can_write

        assert _can_write(_admin()) is True
        assert _can_write(_viewer()) is False


# ═══════════════════════════════════════════════════════════════════════
# sessions endpoints
# ═══════════════════════════════════════════════════════════════════════


class TestSessionsEndpoints:
    @pytest.fixture
    def wired(self, monkeypatch):
        import admin.routes.sessions as sessions

        r = FakeRedis()
        _seed_sessions(r)
        audit = FakeAudit()
        monkeypatch.setattr(sessions, "_redis", lambda: r)
        monkeypatch.setattr(sessions, "get_audit_logger", lambda: audit)
        return sessions, r, audit

    async def test_status(self, wired):
        sessions, _, _ = wired
        out = await sessions.sessions_status(user=_admin())
        assert out["redis_connected"] is True
        assert out["can_write"] is True
        assert out["active_sessions"] == 3
        assert out["effective"]["block_threshold"] == 8.0
        assert out["overridden"] is False
        assert out["catalog_counts"]["signals"] > 20

    async def test_status_reflects_override(self, wired):
        sessions, r, _ = wired
        r.hashes["bulwark:session:config"] = {"block_threshold": "6.0"}
        out = await sessions.sessions_status(user=_admin())
        assert out["overridden"] is True
        assert out["effective"]["block_threshold"] == 6.0
        assert out["defaults"]["block_threshold"] == 8.0  # defaults unchanged

    async def test_status_viewer_cannot_write(self, wired):
        sessions, _, _ = wired
        out = await sessions.sessions_status(user=_viewer())
        assert out["can_write"] is False

    async def test_signals_catalog(self, wired):
        sessions, _, _ = wired
        out = await sessions.sessions_signals(user=_admin())
        assert out["count"] > 20
        assert out["combinations"]

    async def test_active_sorted_by_score(self, wired):
        sessions, _, _ = wired
        out = await sessions.sessions_active(user=_admin())
        assert out["redis_connected"] is True
        assert out["count"] == 3
        scores = [s["score"] for s in out["sessions"]]
        assert scores == sorted(scores, reverse=True)
        assert out["sessions"][0]["score"] == 6.5  # KEY_A 5m on top

    async def test_update_config(self, wired):
        sessions, r, audit = wired
        from admin.routes.sessions import SessionConfigUpdate

        out = await sessions.update_session_config(
            SessionConfigUpdate(block_threshold=6.5, window_seconds=600), user=_admin()
        )
        assert r.hashes["bulwark:session:config"]["block_threshold"] == "6.5"
        assert r.hashes["bulwark:session:config"]["window_seconds"] == "600"
        assert out["override"]["block_threshold"] == 6.5
        assert audit.entries[-1]["action"] == "sessions.config_update"

    async def test_update_config_empty_rejected(self, wired):
        sessions, _, _ = wired
        from fastapi import HTTPException

        from admin.routes.sessions import SessionConfigUpdate

        with pytest.raises(HTTPException) as ei:
            await sessions.update_session_config(SessionConfigUpdate(), user=_admin())
        assert ei.value.status_code == 400

    async def test_clear_config(self, wired):
        sessions, r, audit = wired
        r.hashes["bulwark:session:config"] = {"block_threshold": "6.0"}
        await sessions.clear_session_config(user=_admin())
        assert "bulwark:session:config" not in r.hashes
        assert audit.entries[-1]["action"] == "sessions.config_clear"

    async def test_delete_session_both_windows(self, wired):
        sessions, r, audit = wired
        out = await sessions.delete_session(_KEY_A, user=_admin())
        assert out["keys_deleted"] == 2  # 5m + 30m
        assert f"bulwark:session:{_KEY_A}:signals" not in r.zsets
        assert f"bulwark:session_30m:{_KEY_A}:signals" not in r.zsets
        assert f"bulwark:session:{_KEY_B}:signals" in r.zsets  # untouched
        assert audit.entries[-1]["action"] == "sessions.delete"

    async def test_delete_session_invalid_key(self, wired):
        sessions, _, _ = wired
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as ei:
            await sessions.delete_session("not-a-hash!", user=_admin())
        assert ei.value.status_code == 400

    async def test_reset_all(self, wired):
        sessions, r, audit = wired
        r.hashes["bulwark:session:config"] = {"block_threshold": "6.0"}
        out = await sessions.reset_all_sessions(user=_admin())
        assert out["keys_deleted"] == 3
        assert not r.zsets  # all signal keys gone
        assert "bulwark:session:config" in r.hashes  # config preserved
        assert audit.entries[-1]["action"] == "sessions.reset"

    async def test_active_no_redis(self, monkeypatch):
        import admin.routes.sessions as sessions

        monkeypatch.setattr(sessions, "_redis", lambda: None)
        out = await sessions.sessions_active(user=_admin())
        assert out["redis_connected"] is False
        assert out["sessions"] == []


class TestSessionsRbacWiring:
    def test_permissions(self):
        from admin.models.auth import ROLE_PERMISSIONS, UserRole

        assert "sessions:read" in ROLE_PERMISSIONS[UserRole.ADMIN]
        assert "sessions:write" in ROLE_PERMISSIONS[UserRole.ADMIN]
        assert "sessions:write" in ROLE_PERMISSIONS[UserRole.SECURITY]
        assert "sessions:read" in ROLE_PERMISSIONS[UserRole.AUDITOR]
        assert "sessions:write" not in ROLE_PERMISSIONS[UserRole.AUDITOR]
        assert "sessions:read" in ROLE_PERMISSIONS[UserRole.VIEWER]
        assert "sessions:write" not in ROLE_PERMISSIONS[UserRole.VIEWER]
