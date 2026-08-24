"""Tests for portal-configurable durable-history settings (``events_settings``).

Retention, the per-tenant drain cap and the sync cadence are configurable from
the admin portal (persisted in the shared ``config`` table) with env vars as the
bootstrap fallback. These tests pin down the **precedence** contract
(portal DB override > env var > built-in/SIEM-aware default), the ``-1`` "auto"
sentinel, the validation rules in ``update_settings`` and the two portal
endpoints.

Each test wires a migrated throwaway SQLite ``config`` table into the module's
lazily-imported ``get_database`` and resets the process-level cache so the
module-level ``_cache`` never leaks between tests.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from admin.models.auth import TokenPayload, UserRole
from admin.services import database as db_mod
from admin.services import events_settings
from admin.services.database import create_engine
from admin.services.migrations import run_migrations


@pytest.fixture
async def wired_config(tmp_path, monkeypatch):
    """Migrated SQLite engine wired into the lazily-imported ``get_database``.

    ``events_settings`` imports ``get_database`` from ``.database`` *inside* each
    function, so patching the attribute on the ``database`` module is enough for
    both ``refresh_cache`` and ``_persist`` to reach our throwaway DB.
    """
    db_path = tmp_path / "settings_test.db"
    engine = create_engine(f"sqlite:///{db_path}")
    await engine.init()
    await run_migrations(engine)
    monkeypatch.setattr(db_mod, "get_database", lambda: engine)

    # Ensure no env override / stale cache bleeds in from another test.
    for var in (
        "BULWARK_EVENTS_RETENTION_DAYS",
        "BULWARK_EVENTS_MAX_PER_TENANT",
        "BULWARK_EVENTS_SYNC_INTERVAL",
        "BULWARK_TELEMETRY_ENABLED",
    ):
        monkeypatch.delenv(var, raising=False)
    events_settings.reset_cache_for_tests()
    try:
        yield engine
    finally:
        events_settings.reset_cache_for_tests()
        await engine.close()


# ─── retention precedence ─────────────────────────────────────────────────────

async def test_retention_default_unlimited_without_siem(wired_config):
    await events_settings.refresh_cache()
    assert events_settings.effective_retention_days() == 0


async def test_retention_default_siem_aware(wired_config, monkeypatch):
    monkeypatch.setenv("BULWARK_TELEMETRY_ENABLED", "true")
    await events_settings.refresh_cache()
    assert events_settings.effective_retention_days() == 90


async def test_retention_env_overrides_default(wired_config, monkeypatch):
    monkeypatch.setenv("BULWARK_EVENTS_RETENTION_DAYS", "45")
    monkeypatch.setenv("BULWARK_TELEMETRY_ENABLED", "true")
    await events_settings.refresh_cache()
    # Env wins over the SIEM-aware 90-day default.
    assert events_settings.effective_retention_days() == 45


async def test_retention_portal_override_wins_over_env(wired_config, monkeypatch):
    monkeypatch.setenv("BULWARK_EVENTS_RETENTION_DAYS", "45")
    await events_settings.update_settings(
        {"retention_mode": "custom", "retention_days": 7}, actor="tester"
    )
    # DB (portal) override beats the env var.
    assert events_settings.effective_retention_days() == 7


async def test_retention_auto_sentinel_falls_back_to_env(wired_config, monkeypatch):
    monkeypatch.setenv("BULWARK_EVENTS_RETENTION_DAYS", "45")
    # First pin a custom value, then switch back to auto — auto must ignore the
    # stored -1 sentinel and defer to env/SIEM again.
    await events_settings.update_settings(
        {"retention_mode": "custom", "retention_days": 7}, actor="tester"
    )
    assert events_settings.effective_retention_days() == 7
    await events_settings.update_settings({"retention_mode": "auto"}, actor="tester")
    assert events_settings.effective_retention_days() == 45


async def test_retention_zero_means_forever(wired_config):
    await events_settings.update_settings(
        {"retention_mode": "custom", "retention_days": 0}, actor="tester"
    )
    assert events_settings.effective_retention_days() == 0


# ─── max_per_tenant precedence ────────────────────────────────────────────────

async def test_max_items_default(wired_config):
    await events_settings.refresh_cache()
    assert events_settings.effective_max_items() == events_settings.DEFAULT_MAX_PER_TENANT


async def test_max_items_env_override(wired_config, monkeypatch):
    monkeypatch.setenv("BULWARK_EVENTS_MAX_PER_TENANT", "250")
    await events_settings.refresh_cache()
    assert events_settings.effective_max_items() == 250


async def test_max_items_portal_wins_over_env(wired_config, monkeypatch):
    monkeypatch.setenv("BULWARK_EVENTS_MAX_PER_TENANT", "250")
    await events_settings.update_settings({"max_per_tenant": 500}, actor="tester")
    assert events_settings.effective_max_items() == 500


async def test_max_items_clear_restores_env(wired_config, monkeypatch):
    monkeypatch.setenv("BULWARK_EVENTS_MAX_PER_TENANT", "250")
    await events_settings.update_settings({"max_per_tenant": 500}, actor="tester")
    assert events_settings.effective_max_items() == 500
    await events_settings.update_settings({"max_per_tenant": None}, actor="tester")
    assert events_settings.effective_max_items() == 250


# ─── sync_interval precedence ─────────────────────────────────────────────────

async def test_sync_interval_default(wired_config):
    await events_settings.refresh_cache()
    assert events_settings.effective_sync_interval() == events_settings.DEFAULT_SYNC_INTERVAL


async def test_sync_interval_portal_wins_over_env(wired_config, monkeypatch):
    monkeypatch.setenv("BULWARK_EVENTS_SYNC_INTERVAL", "15")
    await events_settings.update_settings({"sync_interval_seconds": 60}, actor="tester")
    assert events_settings.effective_sync_interval() == 60


# ─── validation ───────────────────────────────────────────────────────────────

async def test_custom_mode_requires_days(wired_config):
    with pytest.raises(events_settings.SettingsValidationError):
        await events_settings.update_settings({"retention_mode": "custom"}, actor="t")


async def test_retention_days_out_of_range_rejected(wired_config):
    with pytest.raises(events_settings.SettingsValidationError):
        await events_settings.update_settings(
            {"retention_mode": "custom", "retention_days": events_settings.MAX_RETENTION_DAYS + 1},
            actor="t",
        )


async def test_retention_days_negative_rejected(wired_config):
    with pytest.raises(events_settings.SettingsValidationError):
        await events_settings.update_settings(
            {"retention_mode": "custom", "retention_days": -5}, actor="t"
        )


async def test_bad_retention_mode_rejected(wired_config):
    with pytest.raises(events_settings.SettingsValidationError):
        await events_settings.update_settings({"retention_mode": "weird"}, actor="t")


async def test_bool_is_rejected_as_int(wired_config):
    with pytest.raises(events_settings.SettingsValidationError):
        await events_settings.update_settings({"max_per_tenant": True}, actor="t")


async def test_max_per_tenant_below_min_rejected(wired_config):
    with pytest.raises(events_settings.SettingsValidationError):
        await events_settings.update_settings(
            {"max_per_tenant": events_settings.MIN_MAX_PER_TENANT - 1}, actor="t"
        )


async def test_sync_interval_out_of_range_rejected(wired_config):
    with pytest.raises(events_settings.SettingsValidationError):
        await events_settings.update_settings(
            {"sync_interval_seconds": events_settings.MAX_SYNC_INTERVAL + 1}, actor="t"
        )


async def test_non_dict_payload_rejected(wired_config):
    with pytest.raises(events_settings.SettingsValidationError):
        await events_settings.update_settings("nope", actor="t")


# ─── get_settings view ────────────────────────────────────────────────────────

async def test_get_settings_reports_auto_mode_and_source(wired_config):
    view = await events_settings.get_settings()
    assert view["retention"]["mode"] == "auto"
    assert view["retention"]["source"] == "default"
    assert view["retention"]["unlimited"] is True
    assert view["max_per_tenant"]["source"] == "default"
    assert view["sync_interval_seconds"]["effective"] == events_settings.DEFAULT_SYNC_INTERVAL


async def test_get_settings_reports_portal_source(wired_config):
    await events_settings.update_settings(
        {"retention_mode": "custom", "retention_days": 30}, actor="tester"
    )
    view = await events_settings.get_settings()
    assert view["retention"]["mode"] == "custom"
    assert view["retention"]["custom_days"] == 30
    assert view["retention"]["effective_days"] == 30
    assert view["retention"]["source"] == "portal"


async def test_get_settings_reports_environment_source(wired_config, monkeypatch):
    monkeypatch.setenv("BULWARK_EVENTS_RETENTION_DAYS", "45")
    view = await events_settings.get_settings()
    assert view["retention"]["source"] == "environment"
    assert view["retention"]["effective_days"] == 45


# ─── persistence round-trips through the config table ─────────────────────────

async def test_override_persists_across_cache_reset(wired_config):
    await events_settings.update_settings(
        {"retention_mode": "custom", "retention_days": 12}, actor="tester"
    )
    # Drop the in-process cache and reload purely from the DB.
    events_settings.reset_cache_for_tests()
    await events_settings.refresh_cache()
    assert events_settings.effective_retention_days() == 12


# ─── portal endpoints ─────────────────────────────────────────────────────────

def _token(role: UserRole = UserRole.ADMIN) -> TokenPayload:
    now = datetime.now(timezone.utc)
    return TokenPayload(
        sub="tester", role=role, tenant=None, exp=now + timedelta(hours=1), iat=now
    )


async def test_endpoint_get_settings(wired_config):
    from admin.routes import events as events_mod

    result = await events_mod.get_events_settings(user=_token())
    assert result["retention"]["mode"] == "auto"
    assert "max_per_tenant" in result
    assert "sync_interval_seconds" in result


async def test_endpoint_post_settings_persists_and_reloads(wired_config, monkeypatch):
    from admin.routes import events as events_mod
    from admin.services import events_sync as sync_mod

    # Point the sync singleton's reload() at our wired DB (it calls refresh_cache).
    monkeypatch.setattr(sync_mod, "_sync", None)

    result = await events_mod.update_events_settings(
        data={"retention_mode": "custom", "retention_days": 21}, user=_token()
    )
    assert result["retention"]["effective_days"] == 21
    assert result["retention"]["source"] == "portal"
    # And the change is durable / cache-independent.
    events_settings.reset_cache_for_tests()
    await events_settings.refresh_cache()
    assert events_settings.effective_retention_days() == 21


async def test_endpoint_post_settings_validation_error_maps_to_400(wired_config):
    from fastapi import HTTPException

    from admin.routes import events as events_mod

    with pytest.raises(HTTPException) as exc_info:
        await events_mod.update_events_settings(
            data={"retention_mode": "custom"}, user=_token()
        )
    assert exc_info.value.status_code == 400
