"""Tests for outbound case-management integrations (Investigation Phase 1).

Covers the four moving parts of the integration subsystem against real
migrated SQLite state and a mocked REST transport (``pytest-httpx``):

* :class:`IntegrationLinkStore` — the connector↔local↔remote idempotency map
  (migration v9): create, idempotent update, lookup, listing, delete.
* :class:`IntegrationRegistry` — config persistence + masking, out-of-band secret
  resolution, and the connector factory.
* :class:`TheHiveConnector` / :class:`DfirIrisConnector` — create + idempotent
  update pushes, health probes, IRIS error-envelope handling, and the
  retry/circuit-breaker fail path (:class:`ConnectorError`).
* the ``/admin/integrations/*`` route handlers — status/CRUD, push (create then
  idempotent update), RBAC (viewer is read-only) and tenant scoping.
* :class:`EventWebhookEmitter` + the ``/admin/integrations/webhooks/*`` routes —
  the SOAR-trigger seed (Phase 1.3): subscription persistence/filtering, best-effort
  fail-open fan-out, and the case-lifecycle emission (escalation-only ``severity_raised``).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from admin.models.auth import TokenPayload, UserRole


def _mk_token(sub: str, role: UserRole, tenant: str | None = None) -> TokenPayload:
    now = datetime.now(timezone.utc)
    return TokenPayload(sub=sub, role=role, tenant=tenant,
                        exp=now + timedelta(hours=1), iat=now)

# ─── shared fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
async def engine(tmp_path):
    """A migrated throwaway SQLite engine shared by the store fixtures."""
    from admin.services.database import create_engine
    from admin.services.migrations import run_migrations

    eng = create_engine(f"sqlite:///{tmp_path / 'integrations_test.db'}")
    await eng.init()
    await run_migrations(eng)
    try:
        yield eng
    finally:
        await eng.close()


@pytest.fixture
async def link_store(engine, monkeypatch):
    from admin.services import integration_link_store as mod
    from admin.services.integration_link_store import IntegrationLinkStore

    monkeypatch.setattr(mod, "get_database", lambda: engine)
    return IntegrationLinkStore()


@pytest.fixture
def registry(tmp_path, monkeypatch):
    """A fresh registry backed by a throwaway config file."""
    from admin.services.integrations import registry as reg_mod

    monkeypatch.setattr(reg_mod, "_CONFIG_FILE", tmp_path / "integrations.json")
    return reg_mod.IntegrationRegistry()


def _thehive_config():
    from admin.services.integrations.registry import IntegrationConfig

    return IntegrationConfig(
        id="th1",
        name="Prod TheHive",
        type="thehive",
        base_url="http://thehive.test",
        api_key="secret-key",
    )


def _iris_config():
    from admin.services.integrations.registry import IntegrationConfig

    return IntegrationConfig(
        id="ir1",
        name="Prod IRIS",
        type="dfir_iris",
        base_url="http://iris.test",
        api_key="secret-key",
        customer_id=2,
    )


def _cortex_config():
    from admin.services.integrations.registry import IntegrationConfig

    return IntegrationConfig(
        id="cx1",
        name="Prod Cortex",
        type="cortex",
        base_url="http://cortex.test",
        api_key="secret-key",
    )


def _opencti_config():
    from admin.services.integrations.registry import IntegrationConfig

    return IntegrationConfig(
        id="oc1",
        name="Prod OpenCTI",
        type="opencti",
        base_url="http://opencti.test",
        api_key="secret-key",
    )


_CASE = {
    "case_id": "case_abc",
    "title": "Suspicious exfiltration",
    "summary": "origin over risk threshold",
    "severity": "high",
    "status": "open",
    "tenant": "acme",
    "tags": ["exfil"],
}


# ─── IntegrationLinkStore ────────────────────────────────────────────────────


async def test_link_store_upsert_is_idempotent(link_store):
    created = await link_store.upsert(
        connector="thehive",
        local_type="case",
        local_id="case_abc",
        remote_id="~1",
        remote_url="http://thehive.test/cases/~1/details",
    )
    assert created["remote_id"] == "~1"
    first_synced = created["last_synced_at"]

    # Re-push maps to the SAME row (no duplicate) and refreshes provenance.
    updated = await link_store.upsert(
        connector="thehive",
        local_type="case",
        local_id="case_abc",
        remote_id="~1",
        remote_url="http://thehive.test/cases/~1/details",
        etag="v2",
    )
    assert updated["etag"] == "v2"
    assert updated["last_synced_at"] >= first_synced

    links = await link_store.list_for_local("case", "case_abc")
    assert len(links) == 1


async def test_link_store_get_and_delete(link_store):
    assert await link_store.get("thehive", "case", "missing") is None
    await link_store.upsert(
        connector="dfir_iris", local_type="case", local_id="case_x", remote_id="9"
    )
    got = await link_store.get("dfir_iris", "case", "case_x")
    assert got and got["remote_id"] == "9"
    assert await link_store.delete("dfir_iris", "case", "case_x") is True
    assert await link_store.delete("dfir_iris", "case", "case_x") is False


async def test_link_store_rejects_unknown_local_type(link_store):
    with pytest.raises(ValueError):
        await link_store.upsert(
            connector="thehive", local_type="widget", local_id="1", remote_id="1"
        )


async def test_link_store_reconcile_columns_default_empty(link_store):
    """A freshly pushed link has no inbound-reconcile bookkeeping yet (v13)."""
    link = await link_store.upsert(
        connector="thehive", local_type="case", local_id="case_r", remote_id="~1"
    )
    assert link["reconcile_state"] == ""
    assert link["last_reconciled_at"] is None
    assert link["last_remote_update"] == ""


async def test_link_store_set_reconcile_records_state(link_store):
    await link_store.upsert(
        connector="thehive", local_type="case", local_id="case_r", remote_id="~1"
    )
    updated = await link_store.set_reconcile(
        connector="thehive",
        local_type="case",
        local_id="case_r",
        reconcile_state="synced",
        last_remote_update="2024-01-02T03:04:05+00:00",
    )
    assert updated is not None
    assert updated["reconcile_state"] == "synced"
    assert updated["last_remote_update"] == "2024-01-02T03:04:05+00:00"
    assert updated["last_reconciled_at"] is not None
    # The outbound provenance (remote_id) is untouched by an inbound reconcile.
    assert updated["remote_id"] == "~1"


async def test_link_store_set_reconcile_preserves_marker_when_omitted(link_store):
    """A conflict/pending update without a fresh marker keeps the last good one."""
    await link_store.upsert(
        connector="thehive", local_type="case", local_id="case_r", remote_id="~1"
    )
    await link_store.set_reconcile(
        connector="thehive", local_type="case", local_id="case_r",
        reconcile_state="synced", last_remote_update="2024-01-02T03:04:05+00:00",
    )
    updated = await link_store.set_reconcile(
        connector="thehive", local_type="case", local_id="case_r",
        reconcile_state="conflict",
    )
    assert updated is not None
    assert updated["reconcile_state"] == "conflict"
    assert updated["last_remote_update"] == "2024-01-02T03:04:05+00:00"


async def test_link_store_set_reconcile_missing_link_is_none(link_store):
    assert await link_store.set_reconcile(
        connector="thehive", local_type="case", local_id="nope",
        reconcile_state="synced",
    ) is None


async def test_link_store_set_reconcile_rejects_bad_state(link_store):
    await link_store.upsert(
        connector="thehive", local_type="case", local_id="case_r", remote_id="~1"
    )
    with pytest.raises(ValueError):
        await link_store.set_reconcile(
            connector="thehive", local_type="case", local_id="case_r",
            reconcile_state="bogus",
        )


async def test_link_store_upsert_preserves_reconcile_columns(link_store):
    """A re-push (outbound) must not clobber inbound reconcile bookkeeping."""
    await link_store.upsert(
        connector="thehive", local_type="case", local_id="case_r", remote_id="~1"
    )
    await link_store.set_reconcile(
        connector="thehive", local_type="case", local_id="case_r",
        reconcile_state="synced", last_remote_update="2024-01-02T03:04:05+00:00",
    )
    re_pushed = await link_store.upsert(
        connector="thehive", local_type="case", local_id="case_r",
        remote_id="~1", etag="v2",
    )
    assert re_pushed["etag"] == "v2"
    assert re_pushed["reconcile_state"] == "synced"
    assert re_pushed["last_remote_update"] == "2024-01-02T03:04:05+00:00"


async def test_link_store_find_by_remote(link_store):
    """find_by_remote reverse-resolves the local link(s) from a remote id."""
    await link_store.upsert(
        connector="thehive", local_type="case", local_id="case_a", remote_id="~7"
    )
    await link_store.upsert(
        connector="thehive", local_type="case", local_id="case_b", remote_id="~7"
    )
    # A different remote id / connector must not bleed in.
    await link_store.upsert(
        connector="thehive", local_type="case", local_id="case_c", remote_id="~8"
    )
    await link_store.upsert(
        connector="dfir_iris", local_type="case", local_id="case_d", remote_id="~7"
    )
    hits = await link_store.find_by_remote("thehive", "~7")
    assert {h["local_id"] for h in hits} == {"case_a", "case_b"}
    assert await link_store.find_by_remote("thehive", "missing") == []
    assert await link_store.find_by_remote("", "~7") == []


@pytest.fixture
async def link_and_cases(engine, monkeypatch):
    """Wire both the link store and the case store to the throwaway engine."""
    from admin.services import integration_link_store as link_mod
    from admin.services import investigation_case_store as case_mod

    monkeypatch.setattr(link_mod, "get_database", lambda: engine)
    monkeypatch.setattr(case_mod, "get_database", lambda: engine)
    monkeypatch.setattr(case_mod, "_store", None, raising=False)
    return {
        "links": link_mod.IntegrationLinkStore(),
        "cases": case_mod.get_case_store(),
    }


async def test_link_store_list_active_case_links_excludes_terminal(link_and_cases):
    """The JOIN skips locally-terminal cases and carries the joined case status."""
    links = link_and_cases["links"]
    cases = link_and_cases["cases"]

    active = await cases.create_case(title="Active", actor="admin", tenant="acme")
    closed = await cases.create_case(title="Closed", actor="admin", tenant="acme")
    await cases.set_state(case_id=closed["case_id"], actor="admin", status="closed")
    for c in (active, closed):
        await links.upsert(
            connector="thehive", local_type="case",
            local_id=c["case_id"], remote_id="~" + c["case_id"],
        )

    rows = await links.list_active_case_links(
        "thehive", exclude_statuses=("resolved", "closed")
    )
    ids = {r["local_id"] for r in rows}
    assert active["case_id"] in ids
    assert closed["case_id"] not in ids
    row = next(r for r in rows if r["local_id"] == active["case_id"])
    assert row["case_status"] == "open"
    assert row["case_tenant"] == "acme"


async def test_link_store_list_active_case_links_respects_limit(link_and_cases):
    links = link_and_cases["links"]
    cases = link_and_cases["cases"]
    for i in range(3):
        c = await cases.create_case(title=f"C{i}", actor="admin", tenant="acme")
        await links.upsert(
            connector="thehive", local_type="case",
            local_id=c["case_id"], remote_id=f"~{i}",
        )
    rows = await links.list_active_case_links("thehive", limit=2)
    assert len(rows) == 2
    assert await links.list_active_case_links("") == []


# ─── IntegrationRegistry ─────────────────────────────────────────────────────


def test_registry_add_persists_and_reloads(registry, tmp_path, monkeypatch):
    registry.add(_thehive_config())
    assert len(registry.configs) == 1

    # A brand-new registry over the same file must see the persisted config.
    from admin.services.integrations import registry as reg_mod

    fresh = reg_mod.IntegrationRegistry()
    assert len(fresh.configs) == 1
    assert fresh.get("th1").name == "Prod TheHive"


def test_registry_rejects_duplicate_id(registry):
    registry.add(_thehive_config())
    with pytest.raises(ValueError):
        registry.add(_thehive_config())


def test_registry_update_and_toggle_and_remove(registry):
    registry.add(_thehive_config())
    updated = registry.update("th1", {"name": "Renamed", "id": "hacked"})
    assert updated.name == "Renamed"
    assert updated.id == "th1"  # id is immutable

    assert registry.toggle("th1") is False
    assert registry.toggle("th1") is True
    assert registry.remove("th1") is True
    assert registry.get("th1") is None


def test_registry_secret_resolution_prefers_env(registry, monkeypatch):
    registry.add(_thehive_config())
    config = registry.get("th1")
    # Inline value used when no override is present.
    assert registry._resolve_api_key(config) == "secret-key"
    # Out-of-band secret (Docker/env) wins.
    monkeypatch.setenv("BULWARK_INTEGRATION_TH1_API_KEY", "from-env")
    assert registry._resolve_api_key(config) == "from-env"


def test_registry_factory_builds_typed_connectors(registry):
    from admin.services.integrations.dfir_iris import DfirIrisConnector
    from admin.services.integrations.thehive import TheHiveConnector

    assert isinstance(registry.build_connector(_thehive_config()), TheHiveConnector)
    assert isinstance(registry.build_connector(_iris_config()), DfirIrisConnector)


def test_registry_factory_returns_none_when_incomplete(registry):
    from admin.services.integrations.registry import IntegrationConfig

    incomplete = IntegrationConfig(id="x", name="x", type="thehive", base_url="", api_key="")
    assert registry.build_connector(incomplete) is None


def test_registry_supports_cortex_type():
    from admin.services.integrations.registry import INTEGRATION_TYPES

    assert "cortex" in INTEGRATION_TYPES


def test_registry_builds_enrichment_connector_for_cortex(registry):
    from admin.services.integrations.cortex import CortexConnector

    conn = registry.build_enrichment_connector(_cortex_config())
    assert isinstance(conn, CortexConnector)
    # A push-target type has no enrichment connector; a Cortex is not a push target.
    assert registry.build_enrichment_connector(_thehive_config()) is None
    assert registry.build_connector(_cortex_config()) is None


def test_registry_enrichment_connector_none_when_incomplete(registry):
    from admin.services.integrations.registry import IntegrationConfig

    incomplete = IntegrationConfig(id="x", name="x", type="cortex", base_url="", api_key="")
    assert registry.build_enrichment_connector(incomplete) is None


async def test_registry_health_probes_cortex_via_enrichment_connector(registry, httpx_mock):
    registry.add(_cortex_config())
    httpx_mock.add_response(
        method="GET", url="http://cortex.test/api/analyzer", json=[]
    )
    health = await registry.health("cx1", force=True)
    assert health.ok is True
    assert health.detail == "authenticated"


def test_registry_supports_opencti_type():
    from admin.services.integrations.registry import INTEGRATION_TYPES

    assert "opencti" in INTEGRATION_TYPES


def test_registry_builds_lookup_connector_for_opencti(registry):
    from admin.services.integrations.opencti import OpenCTIConnector

    conn = registry.build_lookup_connector(_opencti_config())
    assert isinstance(conn, OpenCTIConnector)
    # OpenCTI is a lookup + push target (but not an enrichment/Cortex target).
    assert registry.build_lookup_connector(_cortex_config()) is None
    assert isinstance(registry.build_connector(_opencti_config()), OpenCTIConnector)
    assert registry.build_enrichment_connector(_opencti_config()) is None


def test_registry_lookup_connector_none_when_incomplete(registry):
    from admin.services.integrations.registry import IntegrationConfig

    incomplete = IntegrationConfig(id="x", name="x", type="opencti", base_url="", api_key="")
    assert registry.build_lookup_connector(incomplete) is None


async def test_registry_health_probes_opencti_via_lookup_connector(registry, httpx_mock):
    registry.add(_opencti_config())
    httpx_mock.add_response(
        method="POST", url="http://opencti.test/graphql",
        json={"data": {"about": {"version": "6.2.0"}}},
    )
    health = await registry.health("oc1", force=True)
    assert health.ok is True
    assert "6.2.0" in health.detail


# ─── TheHive connector ───────────────────────────────────────────────────────


async def test_thehive_push_create(httpx_mock):
    from admin.services.integrations.thehive import TheHiveConnector

    httpx_mock.add_response(
        method="POST",
        url="http://thehive.test/api/v1/case",
        json={"_id": "~123"},
        status_code=201,
    )
    conn = TheHiveConnector(base_url="http://thehive.test", api_key="k")
    result = await conn.push_case(_CASE, [], [])
    assert result.created is True
    assert result.remote_id == "~123"
    assert "cases/~123" in result.remote_url


async def test_thehive_push_update_is_idempotent(httpx_mock):
    from admin.services.integrations.thehive import TheHiveConnector

    httpx_mock.add_response(
        method="PATCH",
        url="http://thehive.test/api/v1/case/~123",
        status_code=200,
        json={},
    )
    conn = TheHiveConnector(base_url="http://thehive.test", api_key="k")
    result = await conn.push_case(_CASE, [], [], remote_id="~123")
    assert result.created is False
    assert result.remote_id == "~123"


async def test_thehive_test_connection_ok(httpx_mock):
    from admin.services.integrations.thehive import TheHiveConnector

    httpx_mock.add_response(
        method="GET", url="http://thehive.test/api/v1/user/current", json={"login": "a"}
    )
    conn = TheHiveConnector(base_url="http://thehive.test", api_key="k")
    health = await conn.test_connection()
    assert health.ok is True


async def test_thehive_push_4xx_raises_connector_error(httpx_mock):
    from admin.services.integrations.base import ConnectorError
    from admin.services.integrations.thehive import TheHiveConnector

    httpx_mock.add_response(
        method="POST",
        url="http://thehive.test/api/v1/case",
        status_code=401,
        json={"message": "unauthorized"},
    )
    conn = TheHiveConnector(base_url="http://thehive.test", api_key="k")
    with pytest.raises(ConnectorError) as exc:
        await conn.push_case(_CASE, [], [])
    assert exc.value.status == 401


async def test_connector_retries_then_raises(httpx_mock, monkeypatch):
    from admin.services.integrations import base as base_mod
    from admin.services.integrations.base import ConnectorError
    from admin.services.integrations.thehive import TheHiveConnector

    # Neutralise backoff so the retry loop is instant.
    monkeypatch.setattr(base_mod, "_BASE_BACKOFF_SECONDS", 0.0)
    monkeypatch.setattr(base_mod, "_MAX_BACKOFF_SECONDS", 0.0)
    for _ in range(base_mod._MAX_ATTEMPTS):
        httpx_mock.add_exception(httpx.ConnectError("boom"))

    conn = TheHiveConnector(base_url="http://thehive.test", api_key="k")
    with pytest.raises(ConnectorError):
        await conn.push_case(_CASE, [], [])
    # The circuit breaker recorded the failure.
    assert conn.circuit_state in ("closed", "open")


# ─── DFIR-IRIS connector ─────────────────────────────────────────────────────


async def test_iris_push_create(httpx_mock):
    from admin.services.integrations.dfir_iris import DfirIrisConnector

    httpx_mock.add_response(
        method="POST",
        url="http://iris.test/manage/cases/add",
        json={"status": "success", "data": {"case_id": 42}},
        status_code=200,
    )
    conn = DfirIrisConnector(base_url="http://iris.test", api_key="k", customer_id=2)
    result = await conn.push_case(_CASE, [], [])
    assert result.created is True
    assert result.remote_id == "42"


async def test_iris_error_envelope_raises(httpx_mock):
    from admin.services.integrations.base import ConnectorError
    from admin.services.integrations.dfir_iris import DfirIrisConnector

    # IRIS returns HTTP 200 with an error envelope — must be treated as a failure.
    httpx_mock.add_response(
        method="POST",
        url="http://iris.test/manage/cases/add",
        json={"status": "error", "message": "bad customer"},
        status_code=200,
    )
    conn = DfirIrisConnector(base_url="http://iris.test", api_key="k")
    with pytest.raises(ConnectorError):
        await conn.push_case(_CASE, [], [])


# ─── connector sync_status (Phase 4 inbound reconcile) ───────────────────────


async def test_thehive_sync_status_maps_state(httpx_mock):
    from admin.services.integrations.base import REMOTE_STATUS_IN_PROGRESS
    from admin.services.integrations.thehive import TheHiveConnector

    httpx_mock.add_response(
        method="GET",
        url="http://thehive.test/api/v1/case/~123",
        json={
            "stage": "InProgress",
            "severity": 3,
            "assignee": "analyst@soc",
            "_updatedAt": 1_700_000_000_000,
        },
    )
    httpx_mock.add_response(
        method="GET",
        url="http://thehive.test/api/v1/case/~123/comment",
        json=[{"message": "triaged"}, {"message": ""}, {"nope": 1}],
    )
    conn = TheHiveConnector(base_url="http://thehive.test", api_key="k")
    state = await conn.sync_status("~123")
    assert state is not None
    assert state.remote_id == "~123"
    assert state.status == REMOTE_STATUS_IN_PROGRESS
    assert state.raw_status == "InProgress"
    assert state.severity == "high"
    assert state.assignee == "analyst@soc"
    assert state.closed is False
    assert state.last_remote_update.startswith("2023-11-14")
    assert state.comments == ["triaged"]


async def test_thehive_sync_status_detects_closed(httpx_mock):
    from admin.services.integrations.thehive import TheHiveConnector

    httpx_mock.add_response(
        method="GET",
        url="http://thehive.test/api/v1/case/~9",
        json={"stage": "Closed", "severity": 4},
    )
    httpx_mock.add_response(
        method="GET",
        url="http://thehive.test/api/v1/case/~9/comment",
        json=[],
    )
    conn = TheHiveConnector(base_url="http://thehive.test", api_key="k")
    state = await conn.sync_status("~9")
    assert state is not None
    assert state.closed is True
    assert state.status == "closed"
    assert state.severity == "critical"


async def test_thehive_sync_status_unreachable_is_none(httpx_mock, monkeypatch):
    from admin.services.integrations import base as base_mod
    from admin.services.integrations.thehive import TheHiveConnector

    monkeypatch.setattr(base_mod, "_MAX_ATTEMPTS", 1)
    httpx_mock.add_exception(httpx.ConnectError("down"))
    conn = TheHiveConnector(base_url="http://thehive.test", api_key="k")
    assert await conn.sync_status("~123") is None


async def test_thehive_sync_status_comment_fetch_fail_is_empty(httpx_mock, monkeypatch):
    """A failing comment fetch degrades to [] — it never fails the whole sync."""
    from admin.services.integrations import base as base_mod
    from admin.services.integrations.thehive import TheHiveConnector

    monkeypatch.setattr(base_mod, "_MAX_ATTEMPTS", 1)
    httpx_mock.add_response(
        method="GET",
        url="http://thehive.test/api/v1/case/~5",
        json={"stage": "New", "severity": 1},
    )
    httpx_mock.add_response(
        method="GET",
        url="http://thehive.test/api/v1/case/~5/comment",
        status_code=404,
        json={"message": "no comments endpoint"},
    )
    conn = TheHiveConnector(base_url="http://thehive.test", api_key="k")
    state = await conn.sync_status("~5")
    assert state is not None
    assert state.status == "open"
    assert state.severity == "low"
    assert state.comments == []


async def test_iris_sync_status_maps_state(httpx_mock):
    from admin.services.integrations.base import REMOTE_STATUS_OPEN
    from admin.services.integrations.dfir_iris import DfirIrisConnector

    httpx_mock.add_response(
        method="GET",
        url="http://iris.test/manage/cases/42?cid=42",
        json={
            "status": "success",
            "data": {
                "state_name": "Open",
                "severity_id": 4,
                "owner": "ir-lead",
                "last_update_date": "2024-01-02T03:04:05",
                "comments": [{"comment_text": "opened"}, {"comment_text": ""}],
            },
        },
    )
    conn = DfirIrisConnector(base_url="http://iris.test", api_key="k")
    state = await conn.sync_status("42")
    assert state is not None
    assert state.status == REMOTE_STATUS_OPEN
    assert state.severity == "high"
    assert state.assignee == "ir-lead"
    assert state.closed is False
    assert state.last_remote_update == "2024-01-02T03:04:05"
    assert state.comments == ["opened"]


async def test_iris_sync_status_close_date_marks_closed(httpx_mock):
    from admin.services.integrations.dfir_iris import DfirIrisConnector

    httpx_mock.add_response(
        method="GET",
        url="http://iris.test/manage/cases/7?cid=7",
        json={
            "status": "success",
            "data": {
                "state_name": "Open",
                "severity_id": 2,
                "close_date": "2024-02-01T00:00:00",
            },
        },
    )
    conn = DfirIrisConnector(base_url="http://iris.test", api_key="k")
    state = await conn.sync_status("7")
    assert state is not None
    assert state.closed is True
    assert state.status == "closed"


async def test_iris_sync_status_error_envelope_is_none(httpx_mock, monkeypatch):
    from admin.services.integrations import base as base_mod
    from admin.services.integrations.dfir_iris import DfirIrisConnector

    monkeypatch.setattr(base_mod, "_MAX_ATTEMPTS", 1)
    httpx_mock.add_response(
        method="GET",
        url="http://iris.test/manage/cases/7?cid=7",
        json={"status": "error", "message": "nope"},
        status_code=200,
    )
    conn = DfirIrisConnector(base_url="http://iris.test", api_key="k")
    assert await conn.sync_status("7") is None


# ─── reconcile engine (Phase 4.2 field-partitioned inbound reconcile) ────────


def _remote_state(**kw):
    from admin.services.integrations.base import RemoteState

    return RemoteState(remote_id=kw.pop("remote_id", "~1"), **kw)


class _FakeSyncConn:
    """A connector stub exposing only the ad-hoc ``sync_status`` capability."""

    kind = "thehive"

    def __init__(self, state):
        self._state = state
        self.calls = 0

    async def sync_status(self, remote_id):
        self.calls += 1
        return self._state


@pytest.fixture
async def reconcile_env(engine, monkeypatch):
    """Wire the reconcile engine's stores + a fresh webhook emitter to the test db."""
    from admin.services import integration_link_store as link_mod
    from admin.services import investigation_case_store as case_mod
    from admin.services.integrations import event_webhook as ew_mod
    from admin.services.integrations import reconcile as rec_mod

    monkeypatch.setattr(link_mod, "get_database", lambda: engine)
    monkeypatch.setattr(case_mod, "get_database", lambda: engine)
    monkeypatch.setattr(link_mod, "_store", link_mod.IntegrationLinkStore())
    monkeypatch.setattr(case_mod, "_store", None, raising=False)
    monkeypatch.setattr(rec_mod, "_engine", None, raising=False)
    # A fresh emitter with no subscriptions → re-emit is a cheap no-op we can spy on.
    emitted: list[tuple] = []
    emitter = ew_mod.EventWebhookEmitter()

    async def _spy_emit(event_type, *, tenant=None, data=None):
        emitted.append((event_type, tenant, data))
        return []

    monkeypatch.setattr(emitter, "emit", _spy_emit)
    monkeypatch.setattr(ew_mod, "_emitter", emitter)

    link_store = link_mod.IntegrationLinkStore()
    case_store = case_mod.get_case_store()
    engine_obj = rec_mod.ReconcileEngine()

    async def _linked_case(**case_kw):
        case = await case_store.create_case(
            title=case_kw.pop("title", "Exfil"),
            actor="admin",
            severity=case_kw.pop("severity", "medium"),
            tenant=case_kw.pop("tenant", "acme"),
        )
        await link_store.upsert(
            connector="thehive", local_type="case",
            local_id=case["case_id"], remote_id="~1",
        )
        return case

    return {
        "engine": engine_obj,
        "case_store": case_store,
        "link_store": link_store,
        "linked_case": _linked_case,
        "emitted": emitted,
    }


def test_plan_reconcile_pure_field_partition():
    """The planner maps only whitelisted workflow fields — never detection facts."""
    from admin.services.integrations.reconcile import plan_reconcile

    case = {"status": "open", "severity": "medium", "assignee": ""}
    remote = _remote_state(
        status="in_progress", severity="high", assignee="analyst",
        comments=["looked malicious"],
    )
    plan = plan_reconcile(case, remote)
    assert plan.status == "investigating"
    assert plan.severity == "high"
    assert plan.assignee == "analyst"
    assert plan.new_comments == ["looked malicious"]
    assert plan.conflict is False
    assert plan.reconcile_state == "synced"


def test_plan_reconcile_severity_escalate_only():
    """A remote severity *downgrade* is ignored by default (escalate-only)."""
    from admin.services.integrations.reconcile import plan_reconcile

    case = {"status": "investigating", "severity": "high"}
    plan = plan_reconcile(case, _remote_state(status="in_progress", severity="low"))
    assert plan.severity is None
    # But an explicit non-escalate-only reconcile applies it.
    plan2 = plan_reconcile(
        case, _remote_state(status="in_progress", severity="low"),
        escalate_only_severity=False,
    )
    assert plan2.severity == "low"


def test_plan_reconcile_anti_reopen_is_conflict():
    """A remote reopen of a locally-closed case never applies — it's a conflict."""
    from admin.services.integrations.reconcile import plan_reconcile

    case = {"status": "closed", "severity": "high"}
    plan = plan_reconcile(case, _remote_state(status="open", raw_status="New"))
    assert plan.status is None
    assert plan.conflict is True
    assert "reopen" in plan.conflict_reason
    assert plan.reconcile_state == "conflict"


def test_plan_reconcile_dedups_known_comments():
    from admin.services.integrations.reconcile import plan_reconcile

    case = {"status": "open"}
    remote = _remote_state(status="open", comments=["a", "b", "a"])
    plan = plan_reconcile(case, remote, known_remote_texts={"a"})
    assert plan.new_comments == ["b"]


async def test_reconcile_applies_status_severity_assignee(reconcile_env):
    env = reconcile_env
    case = await env["linked_case"](severity="medium")
    conn = _FakeSyncConn(
        _remote_state(status="in_progress", severity="high", assignee="ir-lead")
    )
    result = await env["engine"].reconcile_case(
        connector=conn, connector_type="thehive",
        integration_id="th1", case=case,
    )
    assert result.ok is True
    assert result.reconcile_state == "synced"
    stored = await env["case_store"].get(case["case_id"])
    assert stored["status"] == "investigating"
    assert stored["severity"] == "high"
    assert stored["assignee"] == "ir-lead"
    link = await env["link_store"].get("thehive", "case", case["case_id"])
    assert link["reconcile_state"] == "synced"


async def test_reconcile_close_reemits_resolved_webhook(reconcile_env):
    env = reconcile_env
    case = await env["linked_case"](severity="high")
    conn = _FakeSyncConn(_remote_state(status="closed", closed=True))
    result = await env["engine"].reconcile_case(
        connector=conn, connector_type="thehive",
        integration_id="th1", case=case,
    )
    assert result.status == "closed"
    stored = await env["case_store"].get(case["case_id"])
    assert stored["status"] == "closed"
    # A reconcile-originated resolved event is re-emitted, tagged loop-safe.
    kinds = [e[0] for e in env["emitted"]]
    assert "case.resolved" in kinds
    resolved = next(e for e in env["emitted"] if e[0] == "case.resolved")
    assert resolved[2]["source"] == "reconcile"


async def test_reconcile_anti_reopen_conflict_records_note(reconcile_env):
    env = reconcile_env
    case = await env["linked_case"]()
    # Close the case locally first.
    await env["case_store"].set_state(
        case_id=case["case_id"], actor="admin", status="closed"
    )
    closed = await env["case_store"].get(case["case_id"])
    conn = _FakeSyncConn(_remote_state(status="open", raw_status="New"))
    result = await env["engine"].reconcile_case(
        connector=conn, connector_type="thehive",
        integration_id="th1", case=closed,
    )
    assert result.conflict is True
    assert result.reconcile_state == "conflict"
    stored = await env["case_store"].get(case["case_id"])
    # Never silently reopened.
    assert stored["status"] == "closed"
    assert any(
        "reconcile conflict" in (n.get("text") or "") for n in stored["notes"]
    )
    link = await env["link_store"].get("thehive", "case", case["case_id"])
    assert link["reconcile_state"] == "conflict"


async def test_reconcile_comment_sync_is_idempotent(reconcile_env):
    env = reconcile_env
    case = await env["linked_case"]()
    conn = _FakeSyncConn(_remote_state(status="open", comments=["remote note one"]))
    await env["engine"].reconcile_case(
        connector=conn, connector_type="thehive", integration_id="th1", case=case,
    )
    after_first = await env["case_store"].get(case["case_id"])
    remote_notes_1 = [
        n for n in after_first["notes"] if "remote note one" in (n.get("text") or "")
    ]
    assert len(remote_notes_1) == 1

    # Re-reading the SAME remote comment must not double-append.
    result2 = await env["engine"].reconcile_case(
        connector=conn, connector_type="thehive",
        integration_id="th1", case=after_first,
    )
    assert result2.comments_added == 0
    after_second = await env["case_store"].get(case["case_id"])
    remote_notes_2 = [
        n for n in after_second["notes"] if "remote note one" in (n.get("text") or "")
    ]
    assert len(remote_notes_2) == 1


async def test_reconcile_unreachable_remote_is_noop(reconcile_env):
    env = reconcile_env
    case = await env["linked_case"]()
    conn = _FakeSyncConn(None)  # dead remote
    result = await env["engine"].reconcile_case(
        connector=conn, connector_type="thehive",
        integration_id="th1", case=case,
    )
    assert result.ok is False
    assert "unreachable" in result.detail
    link = await env["link_store"].get("thehive", "case", case["case_id"])
    # Link reconcile bookkeeping untouched on an unreachable remote.
    assert link["reconcile_state"] == ""


async def test_reconcile_unlinked_case_is_noop(reconcile_env):
    env = reconcile_env
    case = await env["case_store"].create_case(
        title="Unlinked", actor="admin", tenant="acme"
    )
    conn = _FakeSyncConn(_remote_state(status="open"))
    result = await env["engine"].reconcile_case(
        connector=conn, connector_type="thehive",
        integration_id="th1", case=case,
    )
    assert result.ok is False
    assert "not linked" in result.detail
    assert conn.calls == 0


async def test_reconcile_connector_without_sync_is_noop(reconcile_env):
    env = reconcile_env
    case = await env["linked_case"]()

    class _NoSync:
        kind = "thehive"

    result = await env["engine"].reconcile_case(
        connector=_NoSync(), connector_type="thehive",
        integration_id="th1", case=case,
    )
    assert result.ok is False
    assert "does not support" in result.detail


# ─── reconcile trigger paths (Phase 4.4: by-remote-id + sweep) ───────────────


async def test_reconcile_by_remote_id_reconciles_linked_case(reconcile_env):
    env = reconcile_env
    case = await env["linked_case"](severity="medium")  # linked to remote "~1"
    conn = _FakeSyncConn(_remote_state(status="in_progress", severity="high"))
    results = await env["engine"].reconcile_by_remote_id(
        connector=conn, connector_type="thehive",
        integration_id="th1", remote_id="~1",
    )
    assert len(results) == 1 and results[0].ok is True
    stored = await env["case_store"].get(case["case_id"])
    assert stored["status"] == "investigating"
    assert stored["severity"] == "high"


async def test_reconcile_by_remote_id_unknown_remote_is_empty(reconcile_env):
    env = reconcile_env
    conn = _FakeSyncConn(_remote_state(status="open"))
    results = await env["engine"].reconcile_by_remote_id(
        connector=conn, connector_type="thehive",
        integration_id="th1", remote_id="~does-not-exist",
    )
    assert results == []
    assert conn.calls == 0


async def test_reconcile_sweep_reconciles_active_skips_closed(reconcile_env):
    env = reconcile_env
    # Two active linked cases + one locally-closed one (must be swept over).
    from admin.services.integration_link_store import IntegrationLinkStore

    links = IntegrationLinkStore()
    active_ids = []
    for i in range(2):
        c = await env["case_store"].create_case(
            title=f"Active{i}", actor="admin", tenant="acme"
        )
        await links.upsert(
            connector="thehive", local_type="case",
            local_id=c["case_id"], remote_id=f"~a{i}",
        )
        active_ids.append(c["case_id"])
    closed = await env["case_store"].create_case(
        title="Closed", actor="admin", tenant="acme"
    )
    await env["case_store"].set_state(
        case_id=closed["case_id"], actor="admin", status="closed"
    )
    await links.upsert(
        connector="thehive", local_type="case",
        local_id=closed["case_id"], remote_id="~closed",
    )

    conn = _FakeSyncConn(_remote_state(status="in_progress", severity="high"))
    results = await env["engine"].sweep(
        connector=conn, connector_type="thehive", integration_id="th1",
    )
    assert len(results) == len(active_ids)
    assert all(r.ok for r in results)
    for cid in active_ids:
        stored = await env["case_store"].get(cid)
        assert stored["status"] == "investigating"


# ─── inbound webhook receiver (Phase 4.4: HMAC verify + extract + debounce) ──


def _sign(secret: str, body: bytes) -> str:
    import hashlib
    import hmac

    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_inbound_verify_signature_valid(monkeypatch):
    from admin.services.integrations import inbound_webhook as iw

    monkeypatch.setenv("BULWARK_INTEGRATION_TH1_INBOUND_SECRET", "shh")
    body = b'{"objectId":"~1"}'
    assert iw.verify_inbound_signature("th1", body, _sign("shh", body)) is True


def test_inbound_verify_signature_forged_is_rejected(monkeypatch):
    from admin.services.integrations import inbound_webhook as iw

    monkeypatch.setenv("BULWARK_INTEGRATION_TH1_INBOUND_SECRET", "shh")
    body = b'{"objectId":"~1"}'
    # Right shape, wrong key.
    assert iw.verify_inbound_signature("th1", body, _sign("wrong", body)) is False
    # Tampered body against a valid signature.
    assert iw.verify_inbound_signature("th1", b'{"objectId":"~2"}', _sign("shh", body)) is False


def test_inbound_verify_signature_fail_closed_without_secret(monkeypatch):
    from admin.services.integrations import inbound_webhook as iw

    monkeypatch.delenv("BULWARK_INTEGRATION_TH1_INBOUND_SECRET", raising=False)
    body = b'{"objectId":"~1"}'
    # No configured secret ⇒ cannot authenticate ⇒ reject (fail-closed).
    assert iw.verify_inbound_signature("th1", body, _sign("anything", body)) is False
    # Missing header ⇒ reject even with a secret.
    monkeypatch.setenv("BULWARK_INTEGRATION_TH1_INBOUND_SECRET", "shh")
    assert iw.verify_inbound_signature("th1", body, None) is False


def test_inbound_extract_remote_id_per_type():
    from admin.services.integrations.inbound_webhook import extract_remote_id

    assert extract_remote_id("thehive", {"objectId": "~123"}) == "~123"
    assert extract_remote_id("thehive", {"object": {"_id": "~9"}}) == "~9"
    assert extract_remote_id("dfir_iris", {"case_id": 42}) == "42"
    assert extract_remote_id("dfir_iris", {"data": {"case_id": 7}}) == "7"
    # Generic fall-through for a hand-rolled forwarder.
    assert extract_remote_id("thehive", {"id": "~5"}) == "~5"
    # Nothing resolvable ⇒ empty (route treats as accepted no-op).
    assert extract_remote_id("thehive", {"unrelated": 1}) == ""
    assert extract_remote_id("thehive", "not-a-dict") == ""


def test_inbound_debouncer_coalesces():
    from admin.services.integrations.inbound_webhook import InboundDebouncer

    deb = InboundDebouncer(window_seconds=100.0)
    assert deb.claim("thehive", "~1") is True
    # Immediate repeat inside the window is dropped.
    assert deb.claim("thehive", "~1") is False
    # A different remote id is independent.
    assert deb.claim("thehive", "~2") is True
    # Zero window disables debouncing.
    always = InboundDebouncer(window_seconds=0)
    assert always.claim("thehive", "~1") is True
    assert always.claim("thehive", "~1") is True


# ─── reconcile poller (Phase 4.4: poll fallback) ─────────────────────────────


async def test_reconcile_poller_poll_once_sweeps_enabled(reconcile_env, monkeypatch):
    env = reconcile_env
    from admin.services.integrations import reconcile_poller as rp_mod
    from admin.services.integrations.registry import IntegrationConfig

    case = await env["linked_case"]()  # linked to remote "~1" on connector "thehive"

    class _FakeRegistry:
        configs = [
            IntegrationConfig(
                id="th1", name="TH", type="thehive",
                base_url="http://th.test", api_key="k",
            ),
            # A disabled + a non-sync-capable type must be skipped.
            IntegrationConfig(
                id="cx1", name="CX", type="cortex",
                base_url="http://cx.test", api_key="k",
            ),
        ]

        def build_connector(self, config):
            return _FakeSyncConn(_remote_state(status="in_progress"))

    monkeypatch.setattr(rp_mod, "get_integration_registry", lambda: _FakeRegistry())
    monkeypatch.setattr(rp_mod, "get_reconcile_engine", lambda: env["engine"])

    poller = rp_mod.ReconcilePoller()
    reconciled = await poller.poll_once()
    assert reconciled == 1
    stored = await env["case_store"].get(case["case_id"])
    assert stored["status"] == "investigating"


# ─── routes ──────────────────────────────────────────────────────────────────


@pytest.fixture
def wired_routes(engine, registry, monkeypatch):
    """Wire the route-layer singletons to the throwaway engine + registry."""
    from admin.routes import integrations as routes
    from admin.services import (
        integration_link_store as link_mod,
    )
    from admin.services import (
        investigation_case_store as case_mod,
    )
    from admin.services import (
        investigation_observable_store as obs_mod,
    )
    from admin.services import (
        investigation_task_store as task_mod,
    )

    monkeypatch.setattr(link_mod, "get_database", lambda: engine)
    monkeypatch.setattr(case_mod, "get_database", lambda: engine)
    monkeypatch.setattr(obs_mod, "get_database", lambda: engine)
    monkeypatch.setattr(task_mod, "get_database", lambda: engine)
    monkeypatch.setattr(link_mod, "_store", link_mod.IntegrationLinkStore())
    monkeypatch.setattr(case_mod, "_store", None, raising=False)
    monkeypatch.setattr(routes, "get_integration_registry", lambda: registry)
    return routes


def _admin() -> TokenPayload:
    return _mk_token("admin", UserRole.ADMIN, tenant=None)


def _viewer() -> TokenPayload:
    return _mk_token("viewer", UserRole.VIEWER, tenant=None)


async def test_route_create_and_status_masks_secret(wired_routes):
    routes = wired_routes
    created = await routes.create_integration(
        data={
            "name": "TheHive",
            "type": "thehive",
            "base_url": "http://thehive.test",
            "api_key": "top-secret",
        },
        user=_admin(),
    )
    assert created["integration"]["api_key"] == "***"

    status = await routes.status(user=_admin())
    assert status["count"] == 1
    assert status["can_write"] is True
    assert status["integrations"][0]["api_key"] == "***"


async def test_route_create_rejects_bad_type(wired_routes):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        await wired_routes.create_integration(
            data={"name": "x", "type": "splunk", "base_url": "http://x"},
            user=_admin(),
        )
    assert exc.value.status_code == 400


async def test_route_push_create_then_idempotent_update(wired_routes, httpx_mock, monkeypatch):
    routes = wired_routes
    # A real case to push.
    from admin.services.investigation_case_store import CaseStore

    case = await CaseStore().create_case(
        title="Exfil", actor="admin", severity="high", tenant="acme"
    )
    case_id = case["case_id"]

    await routes.create_integration(
        data={
            "name": "TheHive",
            "type": "thehive",
            "base_url": "http://thehive.test",
            "api_key": "k",
        },
        user=_admin(),
    )
    integration_id = routes.get_integration_registry().configs[0].id

    # First push → create.
    httpx_mock.add_response(
        method="POST", url="http://thehive.test/api/v1/case", json={"_id": "~55"}, status_code=201
    )
    first = await routes.push_case(
        case_id, data={"integration_id": integration_id}, user=_admin()
    )
    assert first["created"] is True and first["remote_id"] == "~55"

    # Second push → the link store makes it an idempotent UPDATE (PATCH), not create.
    httpx_mock.add_response(
        method="PATCH", url="http://thehive.test/api/v1/case/~55", status_code=200, json={}
    )
    second = await routes.push_case(
        case_id, data={"integration_id": integration_id}, user=_admin()
    )
    assert second["created"] is False and second["remote_id"] == "~55"


async def test_route_push_failure_is_fail_open(wired_routes, httpx_mock):
    from fastapi import HTTPException

    from admin.services.investigation_case_store import CaseStore

    routes = wired_routes
    case = await CaseStore().create_case(title="X", actor="admin", tenant="acme")
    await routes.create_integration(
        data={"name": "TH", "type": "thehive", "base_url": "http://thehive.test", "api_key": "k"},
        user=_admin(),
    )
    integration_id = routes.get_integration_registry().configs[0].id

    httpx_mock.add_response(
        method="POST", url="http://thehive.test/api/v1/case", status_code=403, json={"m": "no"}
    )
    with pytest.raises(HTTPException) as exc:
        await routes.push_case(
            case["case_id"], data={"integration_id": integration_id}, user=_admin()
        )
    # Fail-open: surfaced as a gateway error, the local case is untouched.
    assert exc.value.status_code == 502


async def test_route_push_opencti_creates_report(wired_routes, httpx_mock):
    from admin.services.investigation_case_store import CaseStore
    from admin.services.investigation_observable_store import ObservableStore

    routes = wired_routes
    case = await CaseStore().create_case(title="Exfil", actor="admin", tenant="acme")
    case_id = case["case_id"]
    await ObservableStore().add(
        case_id=case_id, observable_type="domain", value="evil.test",
        actor="admin", tlp="amber",
    )
    await routes.create_integration(
        data={"name": "OC", "type": "opencti", "base_url": "http://opencti.test", "api_key": "k"},
        user=_admin(),
    )
    integration_id = routes.get_integration_registry().configs[0].id

    # obs upsert, then report create.
    httpx_mock.add_response(method="POST", url="http://opencti.test/graphql",
                            json={"data": {"stixCyberObservableAdd": {"id": "obs1"}}})
    httpx_mock.add_response(method="POST", url="http://opencti.test/graphql",
                            json={"data": {"reportAdd": {"id": "rep1"}}})

    result = await routes.push_case(
        case_id, data={"integration_id": integration_id}, user=_admin()
    )
    assert result["created"] is True
    assert result["remote_id"] == "rep1"


async def test_route_push_opencti_tlp_gate_returns_400(wired_routes):
    from fastapi import HTTPException

    from admin.services.investigation_case_store import CaseStore
    from admin.services.investigation_observable_store import ObservableStore

    routes = wired_routes
    case = await CaseStore().create_case(title="Exfil", actor="admin", tenant="acme")
    case_id = case["case_id"]
    # Only a TLP:RED observable → nothing shareable → local policy refusal (400),
    # the remote is never contacted (no HTTP responses registered).
    await ObservableStore().add(
        case_id=case_id, observable_type="ip", value="9.9.9.9",
        actor="admin", tlp="red", pap="red",
    )
    await routes.create_integration(
        data={"name": "OC", "type": "opencti", "base_url": "http://opencti.test", "api_key": "k"},
        user=_admin(),
    )
    integration_id = routes.get_integration_registry().configs[0].id

    with pytest.raises(HTTPException) as exc:
        await routes.push_case(
            case_id, data={"integration_id": integration_id}, user=_admin()
        )
    assert exc.value.status_code == 400


async def test_route_rbac_viewer_cannot_create(wired_routes):
    from fastapi import HTTPException

    # require_permission is enforced by the dependency; calling the handler with a
    # viewer token via the dependency raises 403. We assert the permission gate
    # rejects a viewer at the dependency layer.
    from admin.services.auth_service import require_permission

    dep = require_permission("integrations:write")
    with pytest.raises(HTTPException) as exc:
        await dep(user=_viewer())
    assert exc.value.status_code == 403


async def test_route_push_tenant_scoping_no_leak(wired_routes, monkeypatch):
    from fastapi import HTTPException

    from admin.services.investigation_case_store import CaseStore

    routes = wired_routes
    case = await CaseStore().create_case(title="X", actor="admin", tenant="acme")
    await routes.create_integration(
        data={"name": "TH", "type": "thehive", "base_url": "http://thehive.test", "api_key": "k"},
        user=_admin(),
    )
    integration_id = routes.get_integration_registry().configs[0].id

    other = _mk_token("op", UserRole.SECURITY, tenant="other-corp")
    with pytest.raises(HTTPException) as exc:
        await routes.push_case(
            case["case_id"], data={"integration_id": integration_id}, user=other
        )
    assert exc.value.status_code == 404  # cross-tenant: no existence leak


# ─── Cortex analyzers route (Phase 2 enrichment) ─────────────────────────────


async def test_route_analyzers_lists_for_cortex(wired_routes, httpx_mock):
    routes = wired_routes
    await routes.create_integration(
        data={
            "name": "Cortex", "type": "cortex",
            "base_url": "http://cortex.test", "api_key": "k",
        },
        user=_admin(),
    )
    integration_id = routes.get_integration_registry().configs[0].id
    httpx_mock.add_response(
        method="GET", url="http://cortex.test/api/analyzer",
        json=[{"id": "VT_3_0", "name": "VirusTotal", "dataTypeList": ["ip"]}],
    )
    out = await routes.list_integration_analyzers(integration_id, user=_admin())
    assert out["count"] == 1
    assert out["analyzers"][0]["id"] == "VT_3_0"


async def test_route_analyzers_rejects_non_cortex(wired_routes):
    from fastapi import HTTPException

    routes = wired_routes
    await routes.create_integration(
        data={
            "name": "TheHive", "type": "thehive",
            "base_url": "http://thehive.test", "api_key": "k",
        },
        user=_admin(),
    )
    integration_id = routes.get_integration_registry().configs[0].id
    with pytest.raises(HTTPException) as exc:
        await routes.list_integration_analyzers(integration_id, user=_admin())
    assert exc.value.status_code == 400


async def test_route_analyzers_unknown_integration_is_404(wired_routes):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        await wired_routes.list_integration_analyzers("nope", user=_admin())
    assert exc.value.status_code == 404


async def test_route_analyzers_unreachable_is_502(wired_routes, httpx_mock, monkeypatch):
    from fastapi import HTTPException

    from admin.services.integrations import base as base_mod

    monkeypatch.setattr(base_mod, "_BASE_BACKOFF_SECONDS", 0.0)
    monkeypatch.setattr(base_mod, "_MAX_BACKOFF_SECONDS", 0.0)
    routes = wired_routes
    await routes.create_integration(
        data={
            "name": "Cortex", "type": "cortex",
            "base_url": "http://cortex.test", "api_key": "k",
        },
        user=_admin(),
    )
    integration_id = routes.get_integration_registry().configs[0].id
    for _ in range(base_mod._MAX_ATTEMPTS):
        httpx_mock.add_exception(httpx.ConnectError("boom"))
    with pytest.raises(HTTPException) as exc:
        await routes.list_integration_analyzers(integration_id, user=_admin())
    assert exc.value.status_code == 502


# ─── Cortex responders route (Phase 2 response actions) ──────────────────────


async def test_route_responders_lists_for_cortex(wired_routes, httpx_mock):
    routes = wired_routes
    await routes.create_integration(
        data={
            "name": "Cortex", "type": "cortex",
            "base_url": "http://cortex.test", "api_key": "k",
        },
        user=_admin(),
    )
    integration_id = routes.get_integration_registry().configs[0].id
    httpx_mock.add_response(
        method="GET", url="http://cortex.test/api/responder",
        json=[{"id": "block_ip_1", "name": "Block IP", "dataTypeList": ["ip"]}],
    )
    out = await routes.list_integration_responders(integration_id, user=_admin())
    assert out["count"] == 1
    assert out["responders"][0]["id"] == "block_ip_1"


async def test_route_responders_rejects_non_cortex(wired_routes):
    from fastapi import HTTPException

    routes = wired_routes
    await routes.create_integration(
        data={
            "name": "TheHive", "type": "thehive",
            "base_url": "http://thehive.test", "api_key": "k",
        },
        user=_admin(),
    )
    integration_id = routes.get_integration_registry().configs[0].id
    with pytest.raises(HTTPException) as exc:
        await routes.list_integration_responders(integration_id, user=_admin())
    assert exc.value.status_code == 400


async def test_route_responders_unknown_integration_is_404(wired_routes):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        await wired_routes.list_integration_responders("nope", user=_admin())
    assert exc.value.status_code == 404


async def test_route_responders_unreachable_is_502(wired_routes, httpx_mock, monkeypatch):
    from fastapi import HTTPException

    from admin.services.integrations import base as base_mod

    monkeypatch.setattr(base_mod, "_BASE_BACKOFF_SECONDS", 0.0)
    monkeypatch.setattr(base_mod, "_MAX_BACKOFF_SECONDS", 0.0)
    routes = wired_routes
    await routes.create_integration(
        data={
            "name": "Cortex", "type": "cortex",
            "base_url": "http://cortex.test", "api_key": "k",
        },
        user=_admin(),
    )
    integration_id = routes.get_integration_registry().configs[0].id
    for _ in range(base_mod._MAX_ATTEMPTS):
        httpx_mock.add_exception(httpx.ConnectError("boom"))
    with pytest.raises(HTTPException) as exc:
        await routes.list_integration_responders(integration_id, user=_admin())
    assert exc.value.status_code == 502


# ─── Event webhooks (SOAR trigger seed, Phase 1.3) ───────────────────────────


@pytest.fixture
def webhook_env(tmp_path, monkeypatch):
    """Isolate the emitter: a throwaway config file + a fresh singleton."""
    from admin.services.integrations import event_webhook as mod

    monkeypatch.setattr(mod, "_CONFIG_FILE", tmp_path / "integration_webhooks.json")
    monkeypatch.setattr(mod, "_emitter", None, raising=False)
    return mod


def _sub(**overrides):
    from admin.services.integrations.event_webhook import WebhookSubscription

    base = dict(
        id="w1", name="SOAR", url="http://soar.test/hook",
        events=[], enabled=True, verify_tls=True,
    )
    base.update(overrides)
    return WebhookSubscription(**base)


# ─── WebhookSubscription / emitter unit ──────────────────────────────────────


def test_webhook_subscription_filtering_and_roundtrip():
    from admin.services.integrations.event_webhook import WebhookSubscription

    named = _sub(events=["case.opened"])
    assert named.wants("case.opened") is True
    assert named.wants("case.resolved") is False
    # empty events ⇒ every event
    assert _sub(events=[]).wants("case.resolved") is True
    # disabled ⇒ nothing, regardless of filter
    assert _sub(enabled=False).wants("case.opened") is False
    # dict round-trip is loss-free
    assert WebhookSubscription.from_dict(named.to_dict()) == named


def test_webhook_public_dict_masks_secret():
    from admin.services.integrations.event_webhook import WebhookSubscription

    sub = _sub(secret="topsecret")
    # Disk view keeps the raw secret so persistence + update-merge work.
    assert sub.to_dict()["secret"] == "topsecret"
    # A full disk round-trip preserves the secret.
    assert WebhookSubscription.from_dict(sub.to_dict()) == sub

    # API view never leaks the raw secret, only whether one is set.
    public = sub.to_public_dict()
    assert "secret" not in public
    assert public["has_secret"] is True
    assert _sub(secret="").to_public_dict()["has_secret"] is False


def test_emitter_add_persists_and_reloads(webhook_env):
    emitter = webhook_env.get_event_webhook_emitter()
    emitter.add(_sub())
    assert len(emitter.subscriptions) == 1

    # A brand-new emitter over the same file must see the persisted subscription.
    fresh = webhook_env.EventWebhookEmitter()
    assert len(fresh.subscriptions) == 1
    assert fresh.get("w1").name == "SOAR"


def test_emitter_rejects_duplicate_id(webhook_env):
    emitter = webhook_env.get_event_webhook_emitter()
    emitter.add(_sub())
    with pytest.raises(ValueError):
        emitter.add(_sub())


def test_emitter_update_toggle_remove(webhook_env):
    emitter = webhook_env.get_event_webhook_emitter()
    emitter.add(_sub())

    updated = emitter.update("w1", {"name": "Renamed", "id": "hacked"})
    assert updated.name == "Renamed"
    assert updated.id == "w1"  # id is immutable

    assert emitter.toggle("w1") is False
    assert emitter.toggle("w1") is True
    assert emitter.remove("w1") is True
    assert emitter.get("w1") is None

    # Misses return falsy sentinels, never raise.
    assert emitter.update("missing", {}) is None
    assert emitter.toggle("missing") is None
    assert emitter.remove("missing") is False


def test_emitter_malformed_config_degrades_to_empty(webhook_env):
    webhook_env._CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    webhook_env._CONFIG_FILE.write_text("{ not valid json")
    emitter = webhook_env.EventWebhookEmitter()
    assert emitter.subscriptions == []


# ─── emit() fan-out ──────────────────────────────────────────────────────────


async def test_emit_fans_out_to_matching_only(webhook_env, httpx_mock):
    emitter = webhook_env.get_event_webhook_emitter()
    emitter.add(_sub(id="all", url="http://soar.test/all", events=[]))
    emitter.add(_sub(id="resolved", url="http://soar.test/resolved", events=["case.resolved"]))
    emitter.add(_sub(id="off", url="http://soar.test/off", events=[], enabled=False))

    # Only the wildcard subscriber should be hit for case.opened.
    httpx_mock.add_response(url="http://soar.test/all", status_code=200)
    results = await emitter.emit("case.opened", tenant="acme", data={"case_id": "c1"})

    assert [r.subscription_id for r in results] == ["all"]
    assert all(r.ok for r in results)
    assert {str(req.url) for req in httpx_mock.get_requests()} == {"http://soar.test/all"}

    # Stable envelope shape is what a SOAR runner subscribes to.
    body = json.loads(httpx_mock.get_requests()[0].content)
    assert body["event"] == "case.opened"
    assert body["tenant"] == "acme"
    assert body["data"]["case_id"] == "c1"
    assert body["event_id"].startswith("evt_")
    assert body["timestamp"]


async def test_emit_without_targets_makes_no_request(webhook_env):
    emitter = webhook_env.get_event_webhook_emitter()
    # No subscriptions at all ⇒ instant empty return, zero HTTP.
    assert await emitter.emit("case.opened") == []


async def test_emit_is_fail_open_on_transport_error(webhook_env, httpx_mock):
    emitter = webhook_env.get_event_webhook_emitter()
    emitter.add(_sub(url="http://soar.test/hook"))
    httpx_mock.add_exception(httpx.ConnectError("endpoint down"))

    # A dead endpoint is reported, never raised — case management must not break.
    results = await emitter.emit("case.opened")
    assert len(results) == 1
    assert results[0].ok is False
    assert "ConnectError" in results[0].detail


async def test_emitter_test_ping(webhook_env, httpx_mock):
    emitter = webhook_env.get_event_webhook_emitter()
    emitter.add(_sub(url="http://soar.test/hook"))
    httpx_mock.add_response(url="http://soar.test/hook", status_code=204)

    result = await emitter.test("w1")
    assert result.ok is True
    body = json.loads(httpx_mock.get_requests()[0].content)
    assert body["event"] == "test.ping"

    # Unknown subscription is a graceful miss, not an HTTP call.
    missing = await emitter.test("nope")
    assert missing.ok is False
    assert "unknown" in missing.detail


# ─── HMAC signing + versioned envelope (Phase 3.1) ───────────────────────────


async def test_envelope_carries_schema_version(webhook_env, httpx_mock):
    emitter = webhook_env.get_event_webhook_emitter()
    emitter.add(_sub(url="http://soar.test/hook"))
    httpx_mock.add_response(url="http://soar.test/hook", status_code=200)

    await emitter.emit("case.opened", tenant="acme", data={"case_id": "c1"})
    body = json.loads(httpx_mock.get_requests()[0].content)
    assert body["schema_version"] == webhook_env.EVENT_SCHEMA_VERSION


async def test_delivery_is_hmac_signed_when_secret_present(webhook_env, httpx_mock):
    import hashlib
    import hmac

    emitter = webhook_env.get_event_webhook_emitter()
    emitter.add(_sub(url="http://soar.test/hook", secret="s3cr3t"))
    httpx_mock.add_response(url="http://soar.test/hook", status_code=200)

    await emitter.emit("case.opened", tenant="acme", data={"case_id": "c1"})
    req = httpx_mock.get_requests()[0]

    # The signature must verify against the EXACT bytes transmitted.
    expected = hmac.new(b"s3cr3t", req.content, hashlib.sha256).hexdigest()
    assert req.headers["X-Bulwark-Signature"] == f"sha256={expected}"
    # Delivery metadata headers are always present.
    assert req.headers["X-Bulwark-Event"] == "case.opened"
    assert req.headers["X-Bulwark-Delivery"].startswith("evt_")
    assert req.headers["content-type"] == "application/json"


async def test_delivery_is_unsigned_when_no_secret(webhook_env, httpx_mock):
    emitter = webhook_env.get_event_webhook_emitter()
    emitter.add(_sub(url="http://soar.test/hook"))  # no secret
    httpx_mock.add_response(url="http://soar.test/hook", status_code=200)

    await emitter.emit("case.opened")
    req = httpx_mock.get_requests()[0]
    # No secret ⇒ no signature header, but metadata headers still ride along.
    assert "X-Bulwark-Signature" not in req.headers
    assert req.headers["X-Bulwark-Event"] == "case.opened"


async def test_secret_resolved_from_env_over_inline(webhook_env, httpx_mock, monkeypatch):
    import hashlib
    import hmac

    # An out-of-band env secret must win over the inline value.
    monkeypatch.setenv("BULWARK_INTEGRATION_WEBHOOK_W1_SECRET", "env-wins")
    emitter = webhook_env.get_event_webhook_emitter()
    emitter.add(_sub(id="w1", url="http://soar.test/hook", secret="inline-loses"))
    httpx_mock.add_response(url="http://soar.test/hook", status_code=200)

    await emitter.emit("case.opened")
    req = httpx_mock.get_requests()[0]
    expected = hmac.new(b"env-wins", req.content, hashlib.sha256).hexdigest()
    assert req.headers["X-Bulwark-Signature"] == f"sha256={expected}"


# ─── webhook routes ──────────────────────────────────────────────────────────


async def test_wh_route_create_validation_and_listing(webhook_env):
    from fastapi import HTTPException

    from admin.routes import integration_webhooks as wr

    with pytest.raises(HTTPException) as e1:
        await wr.create_webhook(data={"url": "http://x"}, user=_admin())
    assert e1.value.status_code == 400
    with pytest.raises(HTTPException) as e2:
        await wr.create_webhook(data={"name": "x"}, user=_admin())
    assert e2.value.status_code == 400

    out = await wr.create_webhook(
        data={"name": "SOAR", "url": "http://soar.test/hook", "events": ["case.opened"]},
        user=_admin(),
    )
    assert out["webhook"]["name"] == "SOAR"
    assert out["webhook"]["id"]  # server-assigned

    listing = await wr.list_webhooks(user=_admin())
    assert len(listing["webhooks"]) == 1
    assert "case.opened" in listing["event_types"]

    events = await wr.list_event_types(user=_admin())
    assert set(events["event_types"]) == {
        "case.opened", "case.severity_raised", "case.resolved"
    }


async def test_wh_route_masks_secret_on_create_and_list(webhook_env):
    from admin.routes import integration_webhooks as wr

    out = await wr.create_webhook(
        data={"name": "SOAR", "url": "http://soar.test/hook", "secret": "topsecret"},
        user=_admin(),
    )
    # The write-only secret is never echoed back — only a has_secret flag.
    assert "secret" not in out["webhook"]
    assert out["webhook"]["has_secret"] is True

    listing = await wr.list_webhooks(user=_admin())
    assert all("secret" not in w for w in listing["webhooks"])
    assert listing["webhooks"][0]["has_secret"] is True

    # But the secret is persisted on disk (needed for signing) and usable.
    stored = webhook_env.get_event_webhook_emitter().get(out["webhook"]["id"])
    assert stored.secret == "topsecret"


async def test_wh_route_missing_subscription_is_404(webhook_env):
    from fastapi import HTTPException

    from admin.routes import integration_webhooks as wr

    with pytest.raises(HTTPException) as e_upd:
        await wr.update_webhook("missing", data={"name": "z"}, user=_admin())
    assert e_upd.value.status_code == 404
    with pytest.raises(HTTPException) as e_del:
        await wr.delete_webhook("missing", user=_admin())
    assert e_del.value.status_code == 404
    with pytest.raises(HTTPException) as e_tog:
        await wr.toggle_webhook("missing", user=_admin())
    assert e_tog.value.status_code == 404
    with pytest.raises(HTTPException) as e_test:
        await wr.test_webhook("missing", user=_admin())
    assert e_test.value.status_code == 404


async def test_wh_route_update_toggle_test_reload_delete(webhook_env, httpx_mock):
    from admin.routes import integration_webhooks as wr

    created = await wr.create_webhook(
        data={"name": "SOAR", "url": "http://soar.test/hook"}, user=_admin()
    )
    wid = created["webhook"]["id"]

    upd = await wr.update_webhook(wid, data={"name": "Renamed", "id": "hacked"}, user=_admin())
    assert upd["webhook"]["name"] == "Renamed"
    assert upd["webhook"]["id"] == wid  # id immutable

    assert (await wr.toggle_webhook(wid, user=_admin()))["enabled"] is False

    # test() ignores the enabled filter — a disabled sub can still be probed.
    httpx_mock.add_response(url="http://soar.test/hook", status_code=200)
    assert (await wr.test_webhook(wid, user=_admin()))["ok"] is True

    assert "reloaded" in (await wr.reload_webhooks(user=_admin()))["message"].lower()
    assert "deleted" in (await wr.delete_webhook(wid, user=_admin()))["message"].lower()


async def test_wh_route_rbac_viewer_is_read_only():
    from fastapi import HTTPException

    from admin.services.auth_service import require_permission

    # Webhook writes reuse the integrations:write gate; a viewer is rejected at
    # the dependency layer before any handler runs.
    dep = require_permission("integrations:write")
    with pytest.raises(HTTPException) as exc:
        await dep(user=_viewer())
    assert exc.value.status_code == 403


# ─── case-lifecycle emission ─────────────────────────────────────────────────


async def test_case_state_escalation_fires_webhook(engine, webhook_env, httpx_mock, monkeypatch):
    from admin.routes import investigation_cases as ic
    from admin.services import investigation_case_store as case_mod
    from admin.services.investigation_case_store import CaseStore

    monkeypatch.setattr(case_mod, "get_database", lambda: engine)
    monkeypatch.setattr(case_mod, "_store", None, raising=False)

    webhook_env.get_event_webhook_emitter().add(_sub(url="http://soar.test/hook", events=[]))

    case = await CaseStore().create_case(
        title="Exfil", actor="admin", severity="medium", tenant="acme"
    )
    case_id = case["case_id"]

    httpx_mock.add_response(url="http://soar.test/hook", status_code=200)
    resp = await ic.set_case_state(
        case_id,
        ic.CaseStateRequest(severity="critical"),
        user=_mk_token("admin", UserRole.ADMIN, tenant="acme"),
    )
    assert resp["case"]["severity"] == "critical"

    reqs = httpx_mock.get_requests()
    assert len(reqs) == 1
    payload = json.loads(reqs[0].content)
    assert payload["event"] == "case.severity_raised"
    assert payload["tenant"] == "acme"
    assert payload["data"]["from_severity"] == "medium"
    assert payload["data"]["to_severity"] == "critical"


async def test_case_state_deescalation_does_not_fire(engine, webhook_env, httpx_mock, monkeypatch):
    from admin.routes import investigation_cases as ic
    from admin.services import investigation_case_store as case_mod
    from admin.services.investigation_case_store import CaseStore

    monkeypatch.setattr(case_mod, "get_database", lambda: engine)
    monkeypatch.setattr(case_mod, "_store", None, raising=False)

    # A live subscriber exists — proving it's the escalation logic, not the absence
    # of a target, that suppresses the event.
    webhook_env.get_event_webhook_emitter().add(_sub(url="http://soar.test/hook", events=[]))

    case = await CaseStore().create_case(
        title="Noise", actor="admin", severity="high", tenant="acme"
    )
    resp = await ic.set_case_state(
        case["case_id"],
        ic.CaseStateRequest(severity="low"),
        user=_mk_token("admin", UserRole.ADMIN, tenant="acme"),
    )
    assert resp["case"]["severity"] == "low"
    # A lowered severity is not a lifecycle event: no delivery attempted.
    assert httpx_mock.get_requests() == []
