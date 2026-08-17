"""Tests for audit-log filtering, counting and the query route wiring.

Covers the audit.html dead-control fixes:
  - free-text ``search`` across actor/action/resource/details
  - ``date_from``/``date_to`` window (with end-of-day extension)
  - ``tenant_id`` pushed into SQL so the total count stays consistent
  - ``count()`` returns the real total (not the current page length), surfaced
    to the UI via the ``X-Total-Count`` header.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

os.environ.setdefault("ADMIN_JWT_SECRET", "test-secret-that-is-at-least-32-characters-long-xx")
os.environ.setdefault("BULWARK_JWT_SECRET", "test-secret-that-is-at-least-32-characters-long-xx")

from admin.models.auth import TokenPayload, UserRole  # noqa: E402
from admin.models.metrics import AuditQuery  # noqa: E402
from admin.services.audit_logger import AuditLogger, build_audit_filters  # noqa: E402


def _admin() -> TokenPayload:
    now = datetime.now(timezone.utc)
    return TokenPayload(sub="admin-user", role=UserRole.ADMIN, exp=now + timedelta(hours=1), iat=now)


@pytest.fixture
async def audit(tmp_path):
    log = AuditLogger(db_path=str(tmp_path / "audit.db"))
    await log.initialize()
    # Seed a spread of entries.
    await log.log(actor="admin", action="policy_create", resource_type="policy",
                  resource_id="acme/support-bot", details="created for tenant acme")
    await log.log(actor="security", action="guardrail_update", resource_type="guardrail",
                  resource_id="rule-42", details="tuned regex")
    await log.log(actor="admin", action="policy_delete", resource_type="policy",
                  resource_id="globex/legacy", details="removed for tenant globex")
    await log.log(actor="auditor", action="login", resource_type="auth",
                  resource_id="auditor", details="successful login")
    yield log
    await log.close()


# ─── build_audit_filters unit ────────────────────────────────────────────────


class TestBuildAuditFilters:
    def test_empty_query_no_conditions(self):
        conds, params = build_audit_filters(AuditQuery())
        assert conds == []
        assert params == []

    def test_actor_and_action_bound(self):
        conds, params = build_audit_filters(AuditQuery(actor="admin", action="login"))
        assert "actor = ?" in conds
        assert "action = ?" in conds
        assert params == ["admin", "login"]

    def test_search_expands_to_all_columns(self):
        conds, params = build_audit_filters(AuditQuery(search="acme"))
        assert len(conds) == 1
        assert conds[0].count("LIKE ?") == 5  # actor/action/type/resource/details
        assert params == ["%acme%"] * 5

    def test_tenant_id_matches_resource_or_details(self):
        conds, params = build_audit_filters(AuditQuery(tenant_id="globex"))
        assert conds == ["(resource_id LIKE ? OR COALESCE(details, '') LIKE ?)"]
        assert params == ["%globex%", "%globex%"]

    def test_dates_use_isoformat(self):
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = datetime(2026, 1, 2, tzinfo=timezone.utc)
        conds, params = build_audit_filters(AuditQuery(start_date=start, end_date=end))
        assert "timestamp >= ?" in conds
        assert "timestamp <= ?" in conds
        assert params == [start.isoformat(), end.isoformat()]


# ─── query + count against real SQLite ───────────────────────────────────────


class TestQueryAndCount:
    async def test_search_positive(self, audit):
        rows = await audit.query(AuditQuery(search="acme"))
        assert len(rows) == 1
        assert rows[0].resource_id == "acme/support-bot"

    async def test_search_negative(self, audit):
        rows = await audit.query(AuditQuery(search="does-not-exist"))
        assert rows == []

    async def test_search_matches_details(self, audit):
        rows = await audit.query(AuditQuery(search="regex"))
        assert len(rows) == 1
        assert rows[0].action == "guardrail_update"

    async def test_actor_filter(self, audit):
        rows = await audit.query(AuditQuery(actor="admin"))
        assert {r.actor for r in rows} == {"admin"}
        assert len(rows) == 2

    async def test_tenant_id_filter_in_sql(self, audit):
        rows = await audit.query(AuditQuery(tenant_id="globex"))
        assert len(rows) == 1
        assert rows[0].resource_id == "globex/legacy"

    async def test_count_matches_query_total(self, audit):
        q = AuditQuery(actor="admin")
        assert await audit.count(q) == 2

    async def test_count_ignores_pagination(self, audit):
        # Page of size 1 returns 1 row, but count reflects the real total.
        page = await audit.query(AuditQuery(limit=1, offset=0))
        assert len(page) == 1
        assert await audit.count(AuditQuery()) == 4

    async def test_count_with_search(self, audit):
        assert await audit.count(AuditQuery(search="tenant")) == 2  # acme + globex details

    async def test_count_no_match(self, audit):
        assert await audit.count(AuditQuery(actor="ghost")) == 0


# ─── route: date parsing + X-Total-Count header ──────────────────────────────


class TestQueryRoute:
    @pytest.fixture
    def wired(self, monkeypatch, audit):
        import admin.routes.audit as audit_routes

        monkeypatch.setattr(audit_routes, "get_audit_logger", lambda: audit)
        return audit_routes

    async def test_returns_total_count_header(self, wired):
        resp = await wired.query_audit_log(user=_admin())
        assert resp.headers["X-Total-Count"] == "4"

    async def test_pagination_total_is_real_not_page_length(self, wired):
        # One row per page, but the header still reports the full total.
        resp = await wired.query_audit_log(limit=1, offset=0, user=_admin())
        import json

        body = json.loads(bytes(resp.body))
        assert len(body) == 1
        assert resp.headers["X-Total-Count"] == "4"

    async def test_search_param_filters(self, wired):
        resp = await wired.query_audit_log(search="globex", user=_admin())
        assert resp.headers["X-Total-Count"] == "1"

    async def test_date_from_is_inclusive_lower_bound(self, wired):
        today = datetime.now(timezone.utc).date().isoformat()
        resp = await wired.query_audit_log(date_from=today, user=_admin())
        # All seeded entries are from "now" → all included.
        assert resp.headers["X-Total-Count"] == "4"

    async def test_future_date_from_excludes_all(self, wired):
        future = (datetime.now(timezone.utc) + timedelta(days=2)).date().isoformat()
        resp = await wired.query_audit_log(date_from=future, user=_admin())
        assert resp.headers["X-Total-Count"] == "0"

    async def test_date_to_extends_to_end_of_day(self, wired):
        # A bare date upper bound must include entries later that same day.
        today = datetime.now(timezone.utc).date().isoformat()
        resp = await wired.query_audit_log(date_to=today, user=_admin())
        assert resp.headers["X-Total-Count"] == "4"

    async def test_invalid_date_ignored(self, wired):
        resp = await wired.query_audit_log(date_from="not-a-date", user=_admin())
        assert resp.headers["X-Total-Count"] == "4"
