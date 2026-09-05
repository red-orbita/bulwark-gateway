"""Tests for the admin Cost & Usage and Response Cache surfaces.

Covers:
  - ResponseCache runtime override (Redis-driven enable/disable + TTL) with
    throttled refresh — the proxy-side of the admin kill-switch.
  - Cost route helpers + endpoints (status / tenants / detail / pricing / reset)
    against a fake Redis.
  - Cache route helpers + endpoints (status / config override / flush / stats)
    against a fake Redis.
  - RBAC wiring for cost:* and cache:* permissions.
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
    """Minimal decode_responses-style Redis for the admin cost/cache routes."""

    def __init__(self):
        self.hashes: dict[str, dict[str, str]] = {}
        self.strings: dict[str, str] = {}
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

    def hincrby(self, key, field, amount=1):
        h = self.hashes.setdefault(key, {})
        h[field] = str(int(float(h.get(field, 0))) + amount)

    def hincrbyfloat(self, key, field, amount=0.0):
        h = self.hashes.setdefault(key, {})
        h[field] = str(float(h.get(field, 0)) + amount)

    # --- keys / scan ---
    def _all_keys(self):
        return set(self.hashes) | set(self.strings)

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
            if k in self.strings:
                del self.strings[k]
                n += 1
        return n


class FakeAudit:
    def __init__(self):
        self.entries = []

    async def log(self, **kwargs):
        self.entries.append(kwargs)


def _seed_cost(r: FakeRedis):
    """Two tenants + agents + global, mirroring CostTracker's schema."""
    r.hashes["bulwark:cost:acme:tokens"] = {
        "prompt": "1000", "completion": "500", "total": "1500",
        "requests": "10", "cost_usd": "0.0125",
    }
    r.hashes["bulwark:cost:acme:support-bot"] = {
        "prompt": "600", "completion": "300", "total": "900",
        "requests": "6", "cost_usd": "0.0075", "model": "gpt-4o",
    }
    r.hashes["bulwark:cost:acme:code-assistant"] = {
        "prompt": "400", "completion": "200", "total": "600",
        "requests": "4", "cost_usd": "0.005", "model": "tinyllama",
    }
    r.hashes["bulwark:cost:globex:tokens"] = {
        "prompt": "200", "completion": "100", "total": "300",
        "requests": "3", "cost_usd": "0.002",
    }
    r.hashes["bulwark:cost:global"] = {
        "prompt": "1200", "completion": "600", "total": "1800",
        "requests": "13", "cost_usd": "0.0145",
    }


def _seed_trend(r: FakeRedis):
    """Daily spend buckets: today and two days ago (a gap on 'yesterday')."""
    today = datetime.now(timezone.utc).date()
    d0 = today.isoformat()
    d2 = (today - timedelta(days=2)).isoformat()
    r.hashes["bulwark:cost:daily:cost_usd"] = {d0: "0.01", d2: "0.005"}
    r.hashes["bulwark:cost:daily:total"] = {d0: "1000", d2: "500"}
    r.hashes["bulwark:cost:daily:requests"] = {d0: "8", d2: "4"}


def _seed_roi(r: FakeRedis):
    """Per-tenant verdict counters + detection categories for the ROI view."""
    r.hashes["bulwark:usage:total"] = {"acme": "80", "globex": "20"}
    r.hashes["bulwark:usage:block"] = {"acme": "12", "globex": "3"}
    r.hashes["bulwark:usage:allow"] = {"acme": "60", "globex": "15"}
    r.hashes["bulwark:usage:warn"] = {"acme": "8", "globex": "2"}
    r.hashes["bulwark:usage:redact"] = {"acme": "0"}
    r.hashes["bulwark:detections:category"] = {
        "prompt_injection": "10", "jailbreak": "4", "exfiltration": "1",
    }


def _token(role: UserRole) -> TokenPayload:
    now = datetime.now(timezone.utc)
    return TokenPayload(sub=f"{role.value}-user", role=role, exp=now + timedelta(hours=1), iat=now)


def _admin() -> TokenPayload:
    return _token(UserRole.ADMIN)


def _viewer() -> TokenPayload:
    return _token(UserRole.VIEWER)


# ═══════════════════════════════════════════════════════════════════════
# ResponseCache runtime override (src/ change)
# ═══════════════════════════════════════════════════════════════════════


class TestResponseCacheRuntimeOverride:
    def _cache(self, enabled=True, ttl=300):
        from src.services.response_cache import ResponseCache

        c = ResponseCache(ttl=ttl, max_size=50, enabled=enabled)
        c._redis = None
        return c

    def test_no_redis_uses_env_config(self):
        c = self._cache(enabled=False)
        assert c.enabled is False
        c._enabled = True
        assert c.enabled is True  # no redis → in-process flag wins

    def test_redis_override_disables(self):
        c = self._cache(enabled=True)
        r = FakeRedis()
        r.hashes["bulwark:cache:config"] = {"enabled": "false"}
        c._redis = r
        c._runtime_checked_at = 0.0  # force refresh
        assert c.enabled is False

    def test_redis_override_updates_ttl(self):
        c = self._cache(enabled=True, ttl=300)
        r = FakeRedis()
        r.hashes["bulwark:cache:config"] = {"enabled": "true", "ttl": "1800"}
        c._redis = r
        c._runtime_checked_at = 0.0
        assert c.enabled is True
        assert c._ttl == 1800

    def test_refresh_is_throttled(self):
        c = self._cache(enabled=True)
        r = FakeRedis()
        r.hashes["bulwark:cache:config"] = {"enabled": "false"}
        c._redis = r
        import time

        c._runtime_checked_at = time.time()  # just checked → skip
        assert c.enabled is True  # override NOT applied yet (throttled)
        c._runtime_checked_at = 0.0  # allow refresh
        assert c.enabled is False

    def test_empty_config_leaves_state(self):
        c = self._cache(enabled=True, ttl=300)
        r = FakeRedis()  # no config hash
        c._redis = r
        c._runtime_checked_at = 0.0
        assert c.enabled is True
        assert c._ttl == 300

    def test_malformed_ttl_ignored(self):
        c = self._cache(enabled=True, ttl=300)
        r = FakeRedis()
        r.hashes["bulwark:cache:config"] = {"ttl": "not-a-number"}
        c._redis = r
        c._runtime_checked_at = 0.0
        _ = c.enabled
        assert c._ttl == 300


# ═══════════════════════════════════════════════════════════════════════
# Cost route helpers
# ═══════════════════════════════════════════════════════════════════════


class TestCostHelpers:
    def test_to_summary_typed(self):
        from admin.routes.cost import _to_summary

        s = _to_summary({"prompt": "10", "completion": "5", "total": "15",
                         "requests": "2", "cost_usd": "0.01"})
        assert s["prompt_tokens"] == 10
        assert s["total_tokens"] == 15
        assert s["total_requests"] == 2
        assert s["estimated_cost_usd"] == 0.01

    def test_to_summary_empty(self):
        from admin.routes.cost import _to_summary

        s = _to_summary({})
        assert s["total_tokens"] == 0
        assert s["estimated_cost_usd"] == 0.0

    def test_can_write_by_role(self):
        from admin.routes.cost import _can_write

        assert _can_write(_admin()) is True
        assert _can_write(_viewer()) is False


class TestCostEndpoints:
    @pytest.fixture
    def wired(self, monkeypatch):
        import admin.routes.cost as cost

        r = FakeRedis()
        _seed_cost(r)
        audit = FakeAudit()
        monkeypatch.setattr(cost, "_redis", lambda: r)
        monkeypatch.setattr(cost, "get_audit_logger", lambda: audit)
        return cost, r, audit

    async def test_status(self, wired):
        cost, r, _ = wired
        out = await cost.cost_status(user=_admin())
        assert out["redis_connected"] is True
        assert out["can_write"] is True
        assert out["global"]["total_tokens"] == 1800
        assert out["tenants_tracked"] == 2

    async def test_status_viewer_cannot_write(self, wired):
        cost, _, _ = wired
        out = await cost.cost_status(user=_viewer())
        assert out["can_write"] is False

    async def test_tenants_sorted_by_cost(self, wired):
        cost, _, _ = wired
        out = await cost.cost_tenants(_user=_admin())
        assert out["count"] == 2
        ids = [t["tenant_id"] for t in out["tenants"]]
        assert ids == ["acme", "globex"]  # acme has higher cost → first

    async def test_tenant_detail_agents(self, wired):
        cost, _, _ = wired
        out = await cost.cost_tenant_detail("acme", _user=_admin())
        assert out["tenant"]["total_tokens"] == 1500
        assert out["agent_count"] == 2
        models = {a["agent_id"]: a["model"] for a in out["agents"]}
        assert models["support-bot"] == "gpt-4o"
        assert models["code-assistant"] == "tinyllama"

    async def test_tenant_detail_invalid_id(self, wired):
        cost, _, _ = wired
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as ei:
            await cost.cost_tenant_detail("Bad_ID!", _user=_admin())
        assert ei.value.status_code == 400

    async def test_pricing_readonly(self, wired):
        cost, _, _ = wired
        out = await cost.cost_pricing(_user=_admin())
        assert out["editable"] is False
        assert any(row["model"] == "gpt-4o" for row in out["pricing"])

    async def test_reset_tenant(self, wired):
        cost, r, audit = wired
        out = await cost.reset_tenant_cost("acme", user=_admin())
        assert out["keys_deleted"] >= 3  # tokens + 2 agents
        assert "bulwark:cost:acme:tokens" not in r.hashes
        assert "bulwark:cost:globex:tokens" in r.hashes  # untouched
        assert audit.entries and audit.entries[-1]["action"] == "cost.reset_tenant"

    async def test_reset_all(self, wired):
        cost, r, audit = wired
        out = await cost.reset_all_cost(user=_admin())
        assert out["keys_deleted"] >= 5
        assert not any(k.startswith("bulwark:cost:") for k in r.hashes)
        assert audit.entries[-1]["action"] == "cost.reset_all"


class TestCostTrend:
    @pytest.fixture
    def wired(self, monkeypatch):
        import admin.routes.cost as cost

        r = FakeRedis()
        _seed_trend(r)
        monkeypatch.setattr(cost, "_redis", lambda: r)
        return cost, r

    async def test_trend_window_is_continuous(self, wired):
        cost, _ = wired
        out = await cost.cost_trend(days=7, _user=_admin())
        assert out["redis_connected"] is True
        assert out["days"] == 7
        # Continuous series: exactly `days` points even though only 2 have data.
        assert len(out["points"]) == 7
        # Ascending by date, last point is today.
        dates = [p["date"] for p in out["points"]]
        assert dates == sorted(dates)
        assert dates[-1] == datetime.now(timezone.utc).date().isoformat()

    async def test_trend_totals_sum_only_window(self, wired):
        cost, _ = wired
        out = await cost.cost_trend(days=7, _user=_admin())
        assert out["totals"]["cost_usd"] == pytest.approx(0.015)
        assert out["totals"]["total_tokens"] == 1500
        assert out["totals"]["total_requests"] == 12

    async def test_trend_gap_days_are_zero(self, wired):
        cost, _ = wired
        out = await cost.cost_trend(days=7, _user=_admin())
        today = datetime.now(timezone.utc).date().isoformat()
        yesterday = (datetime.now(timezone.utc).date() - timedelta(days=1)).isoformat()
        by_date = {p["date"]: p for p in out["points"]}
        assert by_date[today]["cost_usd"] == pytest.approx(0.01)
        assert by_date[yesterday]["cost_usd"] == 0.0  # gap filled with zero
        assert by_date[yesterday]["total_requests"] == 0

    async def test_trend_no_redis_returns_empty(self, monkeypatch):
        import admin.routes.cost as cost

        monkeypatch.setattr(cost, "_redis", lambda: None)
        out = await cost.cost_trend(days=30, _user=_admin())
        assert out["redis_connected"] is False
        assert out["points"] == []


class TestCostRoi:
    @pytest.fixture
    def wired(self, monkeypatch):
        import admin.routes.cost as cost

        r = FakeRedis()
        _seed_roi(r)
        monkeypatch.setattr(cost, "_redis", lambda: r)
        return cost, r

    async def test_roi_totals_summed_across_tenants(self, wired):
        cost, _ = wired
        out = await cost.cost_roi(_user=_admin())
        assert out["redis_connected"] is True
        assert out["total_requests"] == 100  # 80 + 20
        assert out["blocked"] == 15          # 12 + 3
        assert out["allowed"] == 75          # 60 + 15
        assert out["warned"] == 10           # 8 + 2

    async def test_roi_block_rate(self, wired):
        cost, _ = wired
        out = await cost.cost_roi(_user=_admin())
        assert out["block_rate"] == pytest.approx(0.15)  # 15 / 100

    async def test_roi_top_categories_sorted(self, wired):
        cost, _ = wired
        out = await cost.cost_roi(_user=_admin())
        cats = [(c["category"], c["count"]) for c in out["top_categories"]]
        assert cats[0] == ("prompt_injection", 10)
        assert cats == sorted(cats, key=lambda c: c[1], reverse=True)

    async def test_roi_no_redis_returns_empty(self, monkeypatch):
        import admin.routes.cost as cost

        monkeypatch.setattr(cost, "_redis", lambda: None)
        out = await cost.cost_roi(_user=_admin())
        assert out["redis_connected"] is False
        assert out["blocked"] == 0
        assert out["block_rate"] == 0.0


# ═══════════════════════════════════════════════════════════════════════
# Cache route helpers + endpoints
# ═══════════════════════════════════════════════════════════════════════


class TestCacheHelpers:
    def test_is_entry_key(self):
        from admin.routes.cache import _is_entry_key

        assert _is_entry_key("bulwark:cache:abc123") is True
        assert _is_entry_key("bulwark:cache:stats") is False
        assert _is_entry_key("bulwark:cache:config") is False
        assert _is_entry_key("bulwark:other:x") is False

    def test_read_config_absent(self):
        from admin.routes.cache import _read_config

        cfg = _read_config(FakeRedis())
        assert cfg["overridden"] is False
        assert cfg["enabled"] is None

    def test_read_config_present(self):
        from admin.routes.cache import _read_config

        r = FakeRedis()
        r.hashes["bulwark:cache:config"] = {"enabled": "true", "ttl": "900"}
        cfg = _read_config(r)
        assert cfg["overridden"] is True
        assert cfg["enabled"] is True
        assert cfg["ttl"] == 900


class TestCacheEndpoints:
    @pytest.fixture
    def wired(self, monkeypatch):
        import admin.routes.cache as cache

        r = FakeRedis()
        r.hashes["bulwark:cache:stats"] = {
            "hits": "80", "misses": "20", "evictions": "3", "savings_tokens": "4000",
        }
        r.hashes["bulwark:cache:abc"] = {"x": "1"}  # entry
        r.hashes["bulwark:cache:def"] = {"x": "1"}  # entry
        audit = FakeAudit()
        monkeypatch.setattr(cache, "_redis", lambda: r)
        monkeypatch.setattr(cache, "get_audit_logger", lambda: audit)
        return cache, r, audit

    async def test_status_stats_and_entries(self, wired):
        cache, _, _ = wired
        out = await cache.cache_status(user=_admin())
        assert out["redis_connected"] is True
        assert out["can_write"] is True
        assert out["stats"]["hits"] == 80
        assert out["stats"]["hit_rate"] == 0.8
        assert out["entries"] == 2  # stats/config excluded

    async def test_update_config(self, wired):
        cache, r, audit = wired
        from admin.routes.cache import CacheConfigUpdate

        out = await cache.update_cache_config(
            CacheConfigUpdate(enabled=False, ttl=600), user=_admin()
        )
        assert r.hashes["bulwark:cache:config"]["enabled"] == "false"
        assert r.hashes["bulwark:cache:config"]["ttl"] == "600"
        assert out["override"]["overridden"] is True
        assert audit.entries[-1]["action"] == "cache.config_update"

    async def test_update_config_empty_rejected(self, wired):
        cache, _, _ = wired
        from fastapi import HTTPException

        from admin.routes.cache import CacheConfigUpdate

        with pytest.raises(HTTPException) as ei:
            await cache.update_cache_config(CacheConfigUpdate(), user=_admin())
        assert ei.value.status_code == 400

    async def test_clear_config(self, wired):
        cache, r, _ = wired
        r.hashes["bulwark:cache:config"] = {"enabled": "false"}
        await cache.clear_cache_config(user=_admin())
        assert "bulwark:cache:config" not in r.hashes

    async def test_flush_keeps_stats_and_config(self, wired):
        cache, r, audit = wired
        r.hashes["bulwark:cache:config"] = {"enabled": "true"}
        out = await cache.flush_cache(user=_admin())
        assert out["entries_deleted"] == 2
        assert "bulwark:cache:abc" not in r.hashes
        assert "bulwark:cache:stats" in r.hashes  # preserved
        assert "bulwark:cache:config" in r.hashes  # preserved
        assert audit.entries[-1]["action"] == "cache.flush"

    async def test_reset_stats(self, wired):
        cache, r, audit = wired
        await cache.reset_cache_stats(user=_admin())
        assert "bulwark:cache:stats" not in r.hashes
        assert audit.entries[-1]["action"] == "cache.stats_reset"


class TestCostTrackerDailyBuckets:
    """The proxy-side CostTracker must feed the management spend-trend hashes."""

    class _Pipe:
        def __init__(self, r):
            self.r = r

        def hincrby(self, key, field, amount=1):
            h = self.r.hashes.setdefault(key, {})
            h[field] = int(float(h.get(field, 0))) + amount

        def hincrbyfloat(self, key, field, amount=0.0):
            h = self.r.hashes.setdefault(key, {})
            h[field] = float(h.get(field, 0)) + amount

        def hset(self, key, field=None, value=None, mapping=None):
            h = self.r.hashes.setdefault(key, {})
            if field is not None:
                h[field] = value

        def execute(self):
            return True

    class _PipelineRedis:
        def __init__(self):
            self.hashes: dict = {}

        def pipeline(self, transaction=False):
            return TestCostTrackerDailyBuckets._Pipe(self)

    def test_record_usage_writes_daily_buckets(self):
        import time

        from src.services.cost_tracker import CostTracker

        t = CostTracker()
        r = self._PipelineRedis()
        t._redis = r
        t.record_usage(
            "acme", "support-bot", "gpt-4o",
            {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
        )
        day = time.strftime("%Y-%m-%d", time.gmtime())
        assert r.hashes["bulwark:cost:daily:total"][day] == 150
        assert r.hashes["bulwark:cost:daily:requests"][day] == 1
        assert r.hashes["bulwark:cost:daily:cost_usd"][day] > 0
        # Existing global/tenant accounting must still be intact.
        assert r.hashes["bulwark:cost:global"]["total"] == 150


class TestRbacWiring:
    def test_cost_permissions(self):
        from admin.models.auth import ROLE_PERMISSIONS, UserRole

        assert "cost:read" in ROLE_PERMISSIONS[UserRole.ADMIN]
        assert "cost:write" in ROLE_PERMISSIONS[UserRole.ADMIN]
        assert "cost:write" in ROLE_PERMISSIONS[UserRole.SECURITY]
        assert "cost:read" in ROLE_PERMISSIONS[UserRole.AUDITOR]
        assert "cost:write" not in ROLE_PERMISSIONS[UserRole.AUDITOR]
        assert "cost:read" in ROLE_PERMISSIONS[UserRole.VIEWER]
        assert "cost:write" not in ROLE_PERMISSIONS[UserRole.VIEWER]

    def test_cache_permissions(self):
        from admin.models.auth import ROLE_PERMISSIONS, UserRole

        assert "cache:write" in ROLE_PERMISSIONS[UserRole.ADMIN]
        assert "cache:write" in ROLE_PERMISSIONS[UserRole.SECURITY]
        assert "cache:read" in ROLE_PERMISSIONS[UserRole.AUDITOR]
        assert "cache:write" not in ROLE_PERMISSIONS[UserRole.AUDITOR]
        assert "cache:read" in ROLE_PERMISSIONS[UserRole.VIEWER]
        assert "cache:write" not in ROLE_PERMISSIONS[UserRole.VIEWER]
