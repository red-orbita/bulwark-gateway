"""
Tests for the API version negotiation middleware.

Covers version resolution AND the deprecation/sunset response-header path,
which is dormant in production (no version is currently deprecated) but is a
documented part of the API contract (RFC 8594 Sunset / RFC 8288 Deprecation).
Locking it with tests prevents the branch from bit-rotting until a real
deprecation event flips a version's ``deprecated`` flag.
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

import src.middleware.api_version as apiv
from src.middleware.api_version import APIVersion, APIVersionMiddleware, get_version


def _build_app() -> Starlette:
    """Minimal Starlette app wrapping only the version middleware."""

    async def ok(request):  # noqa: ANN001, ANN202 — test stub
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/x", ok)])
    app.add_middleware(APIVersionMiddleware)
    return app


class TestGetVersion:
    """Resolution rules for X-API-Version → APIVersion."""

    def test_none_resolves_to_latest(self):
        assert get_version(None).version == apiv.LATEST_VERSION

    def test_unknown_resolves_to_latest(self):
        # An unrecognized (but well-formed) version falls back to latest.
        assert get_version("1999-01-01").version == apiv.LATEST_VERSION

    def test_known_resolves_exact(self):
        known = apiv.SUPPORTED_VERSIONS[0].version
        assert get_version(known).version == known


class TestVersionHeaders:
    """Response-header behavior of the middleware."""

    def test_echoes_resolved_version(self):
        client = TestClient(_build_app())
        r = client.get("/x", headers={"X-API-Version": apiv.LATEST_VERSION})
        assert r.headers["X-API-Version"] == apiv.LATEST_VERSION
        # No supported version is deprecated → no deprecation headers.
        assert "Deprecation" not in r.headers
        assert "Sunset" not in r.headers

    def test_missing_header_defaults_to_latest(self):
        client = TestClient(_build_app())
        r = client.get("/x")
        assert r.headers["X-API-Version"] == apiv.LATEST_VERSION

    def test_malformed_version_falls_back_to_latest(self):
        client = TestClient(_build_app())
        r = client.get("/x", headers={"X-API-Version": "not-a-date"})
        assert r.headers["X-API-Version"] == apiv.LATEST_VERSION
        assert "Deprecation" not in r.headers

    def test_deprecated_version_emits_deprecation_and_sunset(self, monkeypatch):
        """When the resolved version is deprecated, both headers are set."""
        dep = APIVersion(
            version="2024-01-01",
            label="legacy",
            deprecated=True,
            sunset_date="2026-12-31",
        )
        cur = APIVersion(version="2026-06-01", label="current", deprecated=False)
        monkeypatch.setattr(apiv, "SUPPORTED_VERSIONS", [dep, cur])
        monkeypatch.setattr(apiv, "_VERSION_MAP", {v.version: v for v in (dep, cur)})
        monkeypatch.setattr(apiv, "LATEST_VERSION", cur.version)

        client = TestClient(_build_app())
        r = client.get("/x", headers={"X-API-Version": "2024-01-01"})

        assert r.headers["X-API-Version"] == "2024-01-01"
        assert r.headers["Deprecation"] == "true"
        assert r.headers["Sunset"] == "2026-12-31"

    def test_deprecated_without_sunset_omits_sunset_header(self, monkeypatch):
        """A deprecated version with no sunset date emits Deprecation but not Sunset."""
        dep = APIVersion(
            version="2024-01-01",
            label="legacy",
            deprecated=True,
            sunset_date=None,
        )
        monkeypatch.setattr(apiv, "SUPPORTED_VERSIONS", [dep])
        monkeypatch.setattr(apiv, "_VERSION_MAP", {dep.version: dep})
        monkeypatch.setattr(apiv, "LATEST_VERSION", dep.version)

        client = TestClient(_build_app())
        r = client.get("/x", headers={"X-API-Version": "2024-01-01"})

        assert r.headers["Deprecation"] == "true"
        assert "Sunset" not in r.headers

    def test_current_version_never_marked_deprecated(self, monkeypatch):
        """Resolving to a non-deprecated version must not emit deprecation headers,
        even when a deprecated version also exists in the table."""
        dep = APIVersion(
            version="2024-01-01", label="legacy", deprecated=True, sunset_date="2026-12-31"
        )
        cur = APIVersion(version="2026-06-01", label="current", deprecated=False)
        monkeypatch.setattr(apiv, "SUPPORTED_VERSIONS", [dep, cur])
        monkeypatch.setattr(apiv, "_VERSION_MAP", {v.version: v for v in (dep, cur)})
        monkeypatch.setattr(apiv, "LATEST_VERSION", cur.version)

        client = TestClient(_build_app())
        r = client.get("/x", headers={"X-API-Version": "2026-06-01"})

        assert r.headers["X-API-Version"] == "2026-06-01"
        assert "Deprecation" not in r.headers
        assert "Sunset" not in r.headers
