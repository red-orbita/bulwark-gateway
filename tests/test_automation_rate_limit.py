"""Tests for per-key automation rate limiting (Phase 3.2c).

Covers the three moving parts wired on top of the service-account credential:

* :class:`AutomationRateLimiter` — the sliding-window budget itself, exercised on
  both the in-memory fallback path and a faked Redis path (allow → deny →
  rollback, plus graceful degradation when a Redis op raises);
* the ``rate_limit_rpm`` column plumbing through :class:`ServiceAccountStore`
  (coercion of ``None`` / blank / negative / string input, persistence, exposure);
* enforcement inside ``require_permission_automation`` — a throttled key gets a
  ``429`` (with an audit record), an unbounded (``0``) key is never throttled, and
  the environment default applies when an account carries no override.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from starlette.requests import Request

# ─── shared fixtures / helpers ───────────────────────────────────────────────


@pytest.fixture
async def engine(tmp_path):
    """A migrated throwaway SQLite engine (includes migration v12)."""
    from admin.services.database import create_engine
    from admin.services.migrations import run_migrations

    eng = create_engine(f"sqlite:///{tmp_path / 'svc_ratelimit_test.db'}")
    await eng.init()
    await run_migrations(eng)
    try:
        yield eng
    finally:
        await eng.close()


@pytest.fixture
async def store(engine, monkeypatch):
    from admin.services import service_account_store as mod
    from admin.services.service_account_store import ServiceAccountStore

    monkeypatch.setattr(mod, "get_database", lambda: engine)
    return ServiceAccountStore()


def _dummy_request() -> Request:
    return Request({"type": "http", "headers": [], "query_string": b""})


def _creds(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


class _FakePipeline:
    """Minimal Redis pipeline stand-in for the sliding-window sorted set."""

    def __init__(self, client: "_FakeRedis"):
        self._client = client
        self._card_key: str | None = None

    def zremrangebyscore(self, *_a, **_k):
        return self

    def zadd(self, key, mapping):
        self._client.sets.setdefault(key, {}).update(mapping)
        return self

    def zcard(self, key):
        self._card_key = key
        return self

    def expire(self, *_a, **_k):
        return self

    def execute(self):
        card = len(self._client.sets.get(self._card_key, {}))
        return [None, None, card, True]


class _FakeRedis:
    def __init__(self):
        self.sets: dict[str, dict] = {}

    def pipeline(self, transaction: bool = True):
        return _FakePipeline(self)

    def zrem(self, key, member):
        self.sets.get(key, {}).pop(member, None)


class _RaisingRedis:
    def pipeline(self, transaction: bool = True):
        raise RuntimeError("redis down")


class _FakeAudit:
    def __init__(self):
        self.calls: list[dict] = []

    async def log(self, **kw):
        self.calls.append(kw)


# ═══════════════════════════════════════════════════════════════════════════
# AutomationRateLimiter
# ═══════════════════════════════════════════════════════════════════════════


class TestAutomationRateLimiter:
    def test_in_memory_allows_up_to_limit_then_rejects(self, monkeypatch):
        from admin.services import automation_rate_limit as mod

        monkeypatch.setattr(mod, "get_redis_client", lambda timeout=1.0: None)
        limiter = mod.AutomationRateLimiter()
        assert limiter.consume("acct-a", 3) is True
        assert limiter.consume("acct-a", 3) is True
        assert limiter.consume("acct-a", 3) is True
        assert limiter.consume("acct-a", 3) is False  # 4th over budget

    def test_in_memory_keys_are_independent(self, monkeypatch):
        from admin.services import automation_rate_limit as mod

        monkeypatch.setattr(mod, "get_redis_client", lambda timeout=1.0: None)
        limiter = mod.AutomationRateLimiter()
        assert limiter.consume("acct-a", 1) is True
        assert limiter.consume("acct-a", 1) is False
        # A different key has its own fresh budget.
        assert limiter.consume("acct-b", 1) is True

    def test_zero_or_negative_limit_is_unbounded(self, monkeypatch):
        from admin.services import automation_rate_limit as mod

        # Redis must not even be consulted for an unbounded limit.
        def _boom(timeout=1.0):
            raise AssertionError("get_redis_client should not be called")

        monkeypatch.setattr(mod, "get_redis_client", _boom)
        limiter = mod.AutomationRateLimiter()
        for _ in range(50):
            assert limiter.consume("acct", 0) is True
            assert limiter.consume("acct", -5) is True

    def test_redis_path_allows_then_denies_with_rollback(self, monkeypatch):
        from admin.services import automation_rate_limit as mod

        fake = _FakeRedis()
        monkeypatch.setattr(mod, "get_redis_client", lambda timeout=1.0: fake)
        limiter = mod.AutomationRateLimiter()

        assert limiter.consume("acct", 2) is True
        assert limiter.consume("acct", 2) is True
        # 3rd exceeds the window; the limiter rolls its own member back out.
        assert limiter.consume("acct", 2) is False
        redis_key = mod._REDIS_KEY_PREFIX + "acct"
        assert len(fake.sets[redis_key]) == 2  # rollback kept the window at 2

    def test_redis_error_degrades_to_in_memory(self, monkeypatch):
        from admin.services import automation_rate_limit as mod

        monkeypatch.setattr(mod, "get_redis_client", lambda timeout=1.0: _RaisingRedis())
        limiter = mod.AutomationRateLimiter()
        # Redis raises → fall back to in-memory enforcement (still enforced,
        # never a silent allow, never a hard deny on infra error).
        assert limiter.consume("acct", 1) is True
        assert limiter.consume("acct", 1) is False

    def test_default_rate_limit_rpm_env(self, monkeypatch):
        from admin.services import automation_rate_limit as mod

        monkeypatch.setenv("BULWARK_AUTOMATION_RATE_LIMIT_RPM", "37")
        assert mod.default_rate_limit_rpm() == 37
        monkeypatch.setenv("BULWARK_AUTOMATION_RATE_LIMIT_RPM", "not-an-int")
        assert mod.default_rate_limit_rpm() == mod._DEFAULT_RPM
        monkeypatch.delenv("BULWARK_AUTOMATION_RATE_LIMIT_RPM", raising=False)
        assert mod.default_rate_limit_rpm() == mod._DEFAULT_RPM

    def test_singleton_is_stable(self):
        from admin.services import automation_rate_limit as mod

        assert mod.get_automation_rate_limiter() is mod.get_automation_rate_limiter()


# ═══════════════════════════════════════════════════════════════════════════
# Store — rate_limit_rpm column plumbing
# ═══════════════════════════════════════════════════════════════════════════


class TestStoreRateLimitColumn:
    async def test_coerce_rate_limit(self):
        from admin.services.service_account_store import _coerce_rate_limit

        assert _coerce_rate_limit(None) is None
        assert _coerce_rate_limit("") is None
        assert _coerce_rate_limit("nope") is None
        assert _coerce_rate_limit(5) == 5
        assert _coerce_rate_limit("12") == 12
        assert _coerce_rate_limit(-3) == 0  # negatives clamp to explicit-unbounded
        assert _coerce_rate_limit(0) == 0

    async def test_mint_persists_and_exposes_override(self, store):
        acct = await store.mint(
            name="p", permissions=["automation:respond"], created_by="a",
            rate_limit_rpm=25,
        )
        assert acct["rate_limit_rpm"] == 25
        fetched = await store.get(acct["account_id"])
        assert fetched["rate_limit_rpm"] == 25
        # verify() also carries it (used by the auth resolver).
        resolved = await store.verify(acct["key"])
        assert resolved["rate_limit_rpm"] == 25

    async def test_mint_without_override_is_none(self, store):
        acct = await store.mint(
            name="p", permissions=["automation:respond"], created_by="a"
        )
        assert acct["rate_limit_rpm"] is None
        assert (await store.get(acct["account_id"]))["rate_limit_rpm"] is None


# ═══════════════════════════════════════════════════════════════════════════
# Enforcement inside require_permission_automation
# ═══════════════════════════════════════════════════════════════════════════


class TestAutomationEnforcement:
    async def test_per_key_override_throttles_with_429_and_audit(
        self, store, monkeypatch
    ):
        from admin.services import audit_logger as audit_mod
        from admin.services import auth_service
        from admin.services import automation_rate_limit as rl

        # Force in-memory enforcement + a fresh limiter so state is isolated.
        monkeypatch.setattr(rl, "get_redis_client", lambda timeout=1.0: None)
        monkeypatch.setattr(rl, "_limiter", rl.AutomationRateLimiter())
        fake_audit = _FakeAudit()
        monkeypatch.setattr(audit_mod, "get_audit_logger", lambda: fake_audit)

        acct = await store.mint(
            name="p", permissions=["automation:respond"], created_by="a",
            rate_limit_rpm=2,
        )
        dep = auth_service.require_permission_automation("automation:respond")
        # First two calls succeed.
        await dep(_dummy_request(), _creds(acct["key"]))
        await dep(_dummy_request(), _creds(acct["key"]))
        # Third is throttled.
        with pytest.raises(HTTPException) as ei:
            await dep(_dummy_request(), _creds(acct["key"]))
        assert ei.value.status_code == 429
        assert ei.value.headers.get("Retry-After") == "60"
        assert any(
            c["action"] == "service_account.rate_limited" for c in fake_audit.calls
        )

    async def test_zero_override_is_never_throttled(self, store, monkeypatch):
        from admin.services import auth_service
        from admin.services import automation_rate_limit as rl

        monkeypatch.setattr(rl, "get_redis_client", lambda timeout=1.0: None)
        monkeypatch.setattr(rl, "_limiter", rl.AutomationRateLimiter())

        acct = await store.mint(
            name="p", permissions=["automation:respond"], created_by="a",
            rate_limit_rpm=0,
        )
        dep = auth_service.require_permission_automation("automation:respond")
        for _ in range(20):
            payload = await dep(_dummy_request(), _creds(acct["key"]))
            assert payload.sub == f"service-account:{acct['account_id']}"

    async def test_env_default_applies_without_override(self, store, monkeypatch):
        from admin.services import auth_service
        from admin.services import automation_rate_limit as rl

        monkeypatch.setattr(rl, "get_redis_client", lambda timeout=1.0: None)
        monkeypatch.setattr(rl, "_limiter", rl.AutomationRateLimiter())
        monkeypatch.setenv("BULWARK_AUTOMATION_RATE_LIMIT_RPM", "1")

        acct = await store.mint(
            name="p", permissions=["automation:respond"], created_by="a"
        )
        dep = auth_service.require_permission_automation("automation:respond")
        await dep(_dummy_request(), _creds(acct["key"]))  # 1st ok (default RPM=1)
        with pytest.raises(HTTPException) as ei:
            await dep(_dummy_request(), _creds(acct["key"]))
        assert ei.value.status_code == 429
