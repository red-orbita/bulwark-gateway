"""Admin runtime failures must still close its background services."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """No real user database for lifecycle boundary tests."""


@pytest.mark.parametrize("fault", [None, "runtime", "database", "audit", "scheduler", "gdpr",
                                   "events", "reconcile", "sightings", "stop", "cancel"])
async def test_admin_lifespan_closes_after_runtime_exception(monkeypatch, fault):
    import asyncio

    from admin import main

    closed = []

    def service(name):
        async def close():
            closed.append(name)
            if fault == "stop" and name == "sightings":
                raise RuntimeError("synthetic cleanup failure")
        async def start():
            if fault == name:
                raise RuntimeError("synthetic startup failure")
        return SimpleNamespace(initialize=start, start=start, stop=close, close=close)

    audit, scheduler, gdpr, events, reconcile, sightings = [service(name) for name in (
        "audit", "scheduler", "gdpr", "events", "reconcile", "sightings")]
    monkeypatch.setattr(main, "get_metrics", Mock())
    monkeypatch.setattr(main, "get_audit_logger", lambda: audit)
    monkeypatch.setattr("admin.services.database.init_database", AsyncMock(
        return_value=object(), side_effect=RuntimeError("synthetic database failure") if fault == "database" else None))
    monkeypatch.setattr("admin.services.database.close_database", service("database").close)
    monkeypatch.setattr("admin.services.user_store.get_user_store", lambda: SimpleNamespace(initialize=Mock()))
    monkeypatch.setattr("admin.routes.rbac.apply_persisted_overrides", Mock(return_value=0))
    monkeypatch.setattr("admin.services.service_account_seed.seed_service_accounts", AsyncMock())
    monkeypatch.setattr("admin.services.tenant_manager.get_tenant_manager", Mock())
    monkeypatch.setattr("admin.services.feed_scheduler.get_feed_scheduler", lambda: scheduler)
    monkeypatch.setattr("admin.services.gdpr.get_gdpr_service", lambda: gdpr)
    monkeypatch.setattr("admin.services.events_sync.get_events_sync", lambda: events)
    monkeypatch.setattr("admin.services.integrations.reconcile_poller.get_reconcile_poller", lambda: reconcile)
    monkeypatch.setattr("admin.services.integrations.sighting_dispatcher.get_sighting_dispatcher", lambda: sightings)

    async def run():
        async with main.lifespan(SimpleNamespace(state=SimpleNamespace())):
            if fault == "runtime":
                raise RuntimeError("synthetic runtime failure")
            if fault == "cancel":
                raise asyncio.CancelledError

    if fault == "cancel":
        with pytest.raises(asyncio.CancelledError):
            await run()
    elif fault:
        with pytest.raises(RuntimeError, match="synthetic"):
            await run()
    else:
        await run()
    order = ["database", "audit", "scheduler", "gdpr", "events", "reconcile", "sightings"]
    acquired = order[:order.index(fault) + 1] if fault in order else order
    assert closed == list(reversed(acquired))
