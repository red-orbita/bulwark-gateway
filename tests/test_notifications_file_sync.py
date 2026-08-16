"""Tests for the notification-channel file-sync contract.

The admin service (port 8090) and the proxy service (port 8080) do NOT share
state via Redis for notification channels. They synchronize through a single
JSON file whose location is governed by the ``BULWARK_NOTIFICATIONS_FILE``
environment variable (``src/telemetry/notifications.py``).

In every deployment (Docker Compose and Helm/k8s) both services must point at
the *same* path on a shared volume, otherwise channels configured in the admin
UI never reach the proxy hot path and alerting silently no-ops (a dead control).

These tests lock down that contract:

* the env var actually drives the on-disk path,
* a channel persisted by an "admin" engine is read back by a fresh "proxy"
  engine pointed at the same file (positive), and
* a "proxy" engine pointed at a *different* file does NOT see it (negative).
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

import src.config
import src.telemetry.notifications as notif


@pytest.fixture
def isolated_notifications(monkeypatch, tmp_path):
    """Reload the notifications module with an isolated channels file + cwd.

    Reloading rebinds the module-level ``_CHANNELS_FILE`` from the env var.
    We also chdir into an empty tmp cwd so the module's relative lookups for
    ``config/notifications.yaml`` don't leak repo-provided channels into the
    assertions. The module is reloaded back to defaults on teardown so the
    mutated global path can't leak into other test files.
    """
    channels_file = tmp_path / "shared" / "notifications" / "channels.json"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BULWARK_NOTIFICATIONS_FILE", str(channels_file))
    # No legacy webhook env channels — keep the file the only source.
    monkeypatch.setattr(src.config.settings, "webhook_alert_urls", "", raising=False)
    importlib.reload(notif)
    try:
        yield notif, channels_file
    finally:
        monkeypatch.delenv("BULWARK_NOTIFICATIONS_FILE", raising=False)
        importlib.reload(notif)


def test_env_var_drives_channels_file_path(isolated_notifications):
    """BULWARK_NOTIFICATIONS_FILE must control the persistent storage path."""
    mod, channels_file = isolated_notifications
    assert mod._CHANNELS_FILE == channels_file


def test_default_path_when_env_unset(monkeypatch):
    """With the env var unset the module falls back to the documented default."""
    monkeypatch.delenv("BULWARK_NOTIFICATIONS_FILE", raising=False)
    mod = importlib.reload(notif)
    try:
        assert mod._CHANNELS_FILE == Path("data/notifications_channels.json")
    finally:
        importlib.reload(notif)


def test_admin_write_is_read_by_proxy_same_file(isolated_notifications):
    """Positive: admin persists a channel; a fresh proxy engine reads it back.

    Simulates the two processes: each constructs its own NotificationEngine
    (as admin and proxy do in separate containers), but both resolve the same
    shared file, so the channel created by admin is visible to the proxy.
    """
    mod, channels_file = isolated_notifications

    # --- "admin" process persists a channel ---
    admin_engine = mod.NotificationEngine()
    channel = mod.NotificationChannel(
        id="ops-slack",
        name="Ops Slack",
        type="slack",
        url="https://hooks.slack.example/T000/B000/xxx",
        min_severity="high",
        verdicts=["block"],
    )
    admin_engine.save_channels([channel])

    # File actually written on the shared volume path.
    assert channels_file.exists()

    # --- "proxy" process reads from the same file on startup ---
    proxy_engine = mod.NotificationEngine()
    ids = {c.id for c in proxy_engine.channels}
    assert "ops-slack" in ids
    loaded = next(c for c in proxy_engine.channels if c.id == "ops-slack")
    assert loaded.url == "https://hooks.slack.example/T000/B000/xxx"
    assert loaded.type == "slack"
    assert proxy_engine.configured is True


def test_proxy_pointed_at_different_file_sees_nothing(isolated_notifications, tmp_path):
    """Negative: a divergent path breaks sync — the channel is invisible.

    This is exactly the failure mode when the deployment forgets to wire the
    shared volume / env var in one of the two services.
    """
    mod, _channels_file = isolated_notifications
    admin_engine = mod.NotificationEngine()
    admin_engine.save_channels([
        mod.NotificationChannel(id="ops-slack", name="Ops Slack", type="slack", url="https://x"),
    ])

    # Repoint the module at an unrelated file (the misconfigured proxy).
    other = tmp_path / "elsewhere" / "channels.json"
    mod._CHANNELS_FILE = other
    proxy_engine = mod.NotificationEngine()
    assert all(c.id != "ops-slack" for c in proxy_engine.channels)
    assert proxy_engine.configured is False


def test_missing_file_is_graceful(isolated_notifications):
    """Proxy starting before admin ever wrote the file must not crash."""
    mod, channels_file = isolated_notifications
    assert not channels_file.exists()
    engine = mod.NotificationEngine()  # must not raise
    assert engine.channels == []
    assert engine.configured is False
