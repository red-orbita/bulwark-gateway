"""Tests for opt-in capability master flags surfaced through scanner status.

Covers:
  - Proxy ``GET /internal/scanners/status`` exposes every opt-in capability
    master flag (schema/relevance/hallucination/grounding/image_hygiene/vision)
    so the admin UI can honestly show which graduated scanners are registered
    vs dormant.
  - Admin ``ml_scanner_status`` threads those flags into ``global.capability_flags``,
    preferring the proxy's authoritative state over the admin-pod env fallback.

Neither test loads a model — the flags are pure Settings booleans and the admin
route is exercised with a mocked proxy payload.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

_CAPABILITY_FLAGS = (
    "schema_validation_enabled",
    "relevance_scanning_enabled",
    "hallucination_scanning_enabled",
    "grounding_scanning_enabled",
    "image_hygiene_scanning_enabled",
    "vision_scanning_enabled",
)


# ═══════════════════════════════════════════════════════════════════════
# Proxy /internal/scanners/status
# ═══════════════════════════════════════════════════════════════════════


class TestInternalStatusExposesFlags:
    async def test_all_capability_flags_present(self):
        from src.routes.health import internal_scanner_status

        resp = await internal_scanner_status(request=SimpleNamespace())
        import json

        body = json.loads(resp.body)
        for flag in _CAPABILITY_FLAGS:
            assert flag in body, f"missing capability flag {flag}"
            assert isinstance(body[flag], bool)

    async def test_flags_reflect_settings(self, monkeypatch):
        from src.config import settings
        from src.routes.health import internal_scanner_status

        monkeypatch.setattr(settings, "image_hygiene_scanning_enabled", True)
        monkeypatch.setattr(settings, "vision_scanning_enabled", False)

        import json

        resp = await internal_scanner_status(request=SimpleNamespace())
        body = json.loads(resp.body)
        assert body["image_hygiene_scanning_enabled"] is True
        assert body["vision_scanning_enabled"] is False


# ═══════════════════════════════════════════════════════════════════════
# Admin ml_scanner_status → global.capability_flags
# ═══════════════════════════════════════════════════════════════════════


class TestAdminCapabilityFlags:
    @pytest.fixture
    def user(self):
        from admin.models.auth import TokenPayload, UserRole

        now = datetime.now(timezone.utc)
        return TokenPayload(
            sub="admin-user", role=UserRole.ADMIN, exp=now + timedelta(hours=1), iat=now
        )

    async def test_env_fallback_when_proxy_unreachable(self, monkeypatch, user):
        import admin.routes.ml_scanners as ml

        monkeypatch.setattr(ml, "_query_proxy_scanner_status", lambda: _async_none())
        monkeypatch.setenv("BULWARK_IMAGE_HYGIENE_SCANNING_ENABLED", "true")
        monkeypatch.setenv("BULWARK_VISION_SCANNING_ENABLED", "false")

        out = await ml.ml_scanner_status(_user=user)
        flags = out["global"]["capability_flags"]
        for flag in _CAPABILITY_FLAGS:
            assert flag in flags
        assert flags["image_hygiene_scanning_enabled"] is True
        assert flags["vision_scanning_enabled"] is False

    async def test_proxy_state_overrides_env(self, monkeypatch, user):
        import admin.routes.ml_scanners as ml

        # Env says off, but the authoritative proxy says image hygiene is on.
        monkeypatch.setenv("BULWARK_IMAGE_HYGIENE_SCANNING_ENABLED", "false")
        proxy_payload = {
            "ml_enabled": False,
            "lanes": {},
            "scanners": [],
            "image_hygiene_scanning_enabled": True,
            "vision_scanning_enabled": True,
        }
        monkeypatch.setattr(
            ml, "_query_proxy_scanner_status", lambda: _async_value(proxy_payload)
        )

        out = await ml.ml_scanner_status(_user=user)
        flags = out["global"]["capability_flags"]
        assert flags["image_hygiene_scanning_enabled"] is True
        assert flags["vision_scanning_enabled"] is True


# ═══════════════════════════════════════════════════════════════════════
# Admin ml_scanner_status → read-only Union cards (A3)
# ═══════════════════════════════════════════════════════════════════════


class TestReadOnlyUnionCards:
    @pytest.fixture
    def user(self):
        from admin.models.auth import TokenPayload, UserRole

        now = datetime.now(timezone.utc)
        return TokenPayload(
            sub="admin-user", role=UserRole.ADMIN, exp=now + timedelta(hours=1), iat=now
        )

    def _proxy_payload(self):
        # Mix of tunable (known to _DEFAULT_SCANNERS) and non-tunable scanners.
        return {
            "ml_enabled": True,
            "ml_blocking": False,
            "lanes": {"input_blocking": 2, "input_async": 1, "output_blocking": 2, "total": 5},
            "scanners": [
                # Tunable — matches an admin config key directly.
                {"name": "ml_injection_classifier", "type": "input_blocking",
                 "enabled": True, "healthy": True, "maturity": "beta",
                 "description": "injection", "priority": 20, "metrics": {"scanned": 3}},
                # Tunable — proxy name differs from admin key (alias).
                {"name": "ml_toxicity", "type": "input_async",
                 "enabled": True, "healthy": True, "maturity": "beta",
                 "description": "toxicity", "priority": 25, "metrics": {"scanned": 7}},
                # Non-tunable GA builtins → read-only union cards.
                {"name": "regex_input", "type": "input_blocking",
                 "enabled": True, "healthy": True, "maturity": "ga",
                 "description": "regex", "priority": 10, "metrics": {}},
                {"name": "output_redaction", "type": "output_blocking",
                 "enabled": True, "healthy": True, "maturity": "ga",
                 "description": "redaction", "priority": 12, "metrics": {}},
                # Non-tunable multimodal (experimental) → read-only union card.
                {"name": "ml_vision_scanner", "type": "input_async",
                 "enabled": False, "healthy": False, "maturity": "experimental",
                 "description": "ocr", "priority": 14, "metrics": {}},
            ],
        }

    async def test_union_surfaces_non_tunable_scanners_as_read_only(self, monkeypatch, user):
        import admin.routes.ml_scanners as ml

        monkeypatch.setattr(
            ml, "_query_proxy_scanner_status", lambda: _async_value(self._proxy_payload())
        )

        out = await ml.ml_scanner_status(_user=user)
        by_name = {s["name"]: s for s in out["scanners"]}

        # Non-tunable proxy scanners appear, flagged read_only.
        for pname in ("regex_input", "output_redaction", "ml_vision_scanner"):
            assert pname in by_name, f"missing union card {pname}"
            assert by_name[pname]["read_only"] is True

        # Tunable scanners stay editable.
        assert by_name["ml_injection_classifier"]["read_only"] is False

    async def test_no_duplicate_card_for_aliased_toxicity(self, monkeypatch, user):
        import admin.routes.ml_scanners as ml

        monkeypatch.setattr(
            ml, "_query_proxy_scanner_status", lambda: _async_value(self._proxy_payload())
        )

        out = await ml.ml_scanner_status(_user=user)
        names = [s["name"] for s in out["scanners"]]

        # The proxy "ml_toxicity" must NOT create a second read-only card — it
        # maps onto the tunable "ml_toxicity_scanner" admin key via alias.
        assert "ml_toxicity" not in names
        assert names.count("ml_toxicity_scanner") == 1
        tox = next(s for s in out["scanners"] if s["name"] == "ml_toxicity_scanner")
        assert tox["read_only"] is False
        # Alias resolves the proxy status → real metrics threaded in.
        assert tox["metrics"] == {"scanned": 7}

    async def test_union_card_derived_fields(self, monkeypatch, user):
        import admin.routes.ml_scanners as ml

        monkeypatch.setattr(
            ml, "_query_proxy_scanner_status", lambda: _async_value(self._proxy_payload())
        )

        out = await ml.ml_scanner_status(_user=user)
        by_name = {s["name"]: s for s in out["scanners"]}

        vision = by_name["ml_vision_scanner"]
        assert vision["display_name"] == "Vision Scanner"
        assert vision["category"] == "multimodal"
        assert vision["maturity"] == "experimental"
        assert vision["blocking"] is False           # input_async → not blocking
        assert vision["model_path"] == ""            # avoids "Model Missing" badge
        assert vision["ready"] is False              # disabled + unhealthy

        redaction = by_name["output_redaction"]
        assert redaction["category"] == "output"     # output_* type
        assert redaction["blocking"] is True         # output_blocking
        assert redaction["ready"] is True            # enabled + healthy

    async def test_no_union_cards_when_proxy_unreachable(self, monkeypatch, user):
        import admin.routes.ml_scanners as ml

        monkeypatch.setattr(ml, "_query_proxy_scanner_status", lambda: _async_none())

        out = await ml.ml_scanner_status(_user=user)
        # Only the tunable defaults are present; every card is editable.
        assert all(s["read_only"] is False for s in out["scanners"])
        assert not any(s["name"] == "regex_input" for s in out["scanners"])


def _async_none():
    async def _c():
        return None

    return _c()


def _async_value(value):
    async def _c():
        return value

    return _c()
