"""Engineer activity selection persists and updates proxy behavior at runtime."""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from admin.routes import siem
from src.middleware.request_audit import RequestAuditMiddleware


async def test_activity_mode_roundtrip_and_runtime_reload(tmp_path, monkeypatch):
    monkeypatch.setenv("BULWARK_SIEM_ACTIVITY_FILE", str(tmp_path / "activity.json"))
    monkeypatch.setattr(siem, "get_audit_logger", lambda: SimpleNamespace(log=AsyncMock()))
    user = SimpleNamespace(sub="engineer")
    async def app(*args):
        pass
    middleware = RequestAuditMiddleware(app)
    await siem.set_activity_mode(siem.ActivityMode(mode="all_requests"), user)
    assert (await siem.get_activity_mode(user)).mode == "all_requests"
    assert await middleware._audit_enabled() is True
    await siem.set_activity_mode(siem.ActivityMode(mode="detections"), user)
    middleware._checked = 0
    assert await middleware._audit_enabled() is False


def test_invalid_or_extra_activity_fields_rejected():
    with pytest.raises(ValidationError):
        siem.ActivityMode(mode="all_bodies")
    with pytest.raises(ValidationError):
        siem.ActivityMode(mode="all_requests", export_secrets=True)
