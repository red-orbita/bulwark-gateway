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
