"""Tests for the in-UI dashboards feature.

Three layers, all offline (no live Prometheus / Redis):

  * ``admin.services.prometheus_query`` — scalar coercion, result parsing, and
    the async HTTP client driven by an ``httpx.MockTransport``.
  * ``admin.services.dashboard_catalog`` — range presets, template rendering,
    and structural integrity of the four ported dashboards.
  * ``admin.routes.dashboards`` — status, 404, Prometheus shaping per panel
    type, and the Redis degraded-mode fallback for every ``fallback`` key.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from admin.models.auth import TokenPayload, UserRole

# ═══════════════════════════════════════════════════════════════════════
# Fixtures / helpers
# ═══════════════════════════════════════════════════════════════════════


def _admin() -> TokenPayload:
    now = datetime.now(timezone.utc)
    return TokenPayload(sub="admin-user", role=UserRole.ADMIN, exp=now + timedelta(hours=1), iat=now)


def _mock_client(handler) -> "object":
    """Build a PrometheusClient whose pooled httpx client uses MockTransport."""
    from admin.services.prometheus_query import PrometheusClient

    client = PrometheusClient(base_url="http://prometheus:9090")
    client._client = httpx.AsyncClient(
        base_url="http://prometheus:9090",
        transport=httpx.MockTransport(handler),
    )
    return client


def _success(result, result_type):
    return httpx.Response(200, json={"status": "success", "data": {"resultType": result_type, "result": result}})


# ═══════════════════════════════════════════════════════════════════════
# prometheus_query — pure helpers
# ═══════════════════════════════════════════════════════════════════════


class TestCoerceFloat:
    def test_valid(self):
        from admin.services.prometheus_query import _coerce_float

        assert _coerce_float("3.5") == 3.5
        assert _coerce_float("0") == 0.0
        assert _coerce_float(7) == 7.0

    def test_nan_inf_dropped(self):
        from admin.services.prometheus_query import _coerce_float

        assert _coerce_float("NaN") is None
        assert _coerce_float("+Inf") is None
        assert _coerce_float("-Inf") is None

    def test_garbage(self):
        from admin.services.prometheus_query import _coerce_float

        assert _coerce_float("abc") is None
        assert _coerce_float(None) is None


class TestParseResult:
    def test_vector(self):
        from admin.services.prometheus_query import _parse_result

        out = _parse_result(
            [{"metric": {"__name__": "x", "verdict": "block"}, "value": [1700000000, "5"]}],
            "vector",
        )
        assert len(out) == 1
        assert out[0].metric["verdict"] == "block"
        assert out[0].last_value == 5.0
        assert out[0].values == [(1700000000.0, 5.0)]

    def test_matrix(self):
        from admin.services.prometheus_query import _parse_result

        out = _parse_result(
            [{"metric": {"tenant": "acme"}, "values": [[1, "1"], [2, "2"], [3, "3"]]}],
            "matrix",
        )
        assert out[0].last_value == 3.0
        assert len(out[0].values) == 3

    def test_matrix_drops_nan_points(self):
        from admin.services.prometheus_query import _parse_result

        out = _parse_result(
            [{"metric": {}, "values": [[1, "1"], [2, "NaN"], [3, "3"]]}],
            "matrix",
        )
        assert [v for _, v in out[0].values] == [1.0, 3.0]

    def test_empty_series_has_none_last_value(self):
        from admin.services.prometheus_query import _parse_result

        out = _parse_result([{"metric": {}, "value": [1, "NaN"]}], "vector")
        assert out[0].last_value is None


# ═══════════════════════════════════════════════════════════════════════
# prometheus_query — async client (MockTransport)
# ═══════════════════════════════════════════════════════════════════════


class TestPrometheusClient:
    async def test_query_instant(self):
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/v1/query"
            return _success([{"metric": {"verdict": "allow"}, "value": [1, "10"]}], "vector")

        client = _mock_client(handler)
        samples = await client.query_instant("sum by (verdict)(bulwark_verdicts_total)")
        assert samples[0].last_value == 10.0
        await client.close()

    async def test_query_range(self):
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/v1/query_range"
            return _success([{"metric": {}, "values": [[1, "1"], [2, "2"]]}], "matrix")

        client = _mock_client(handler)
        samples = await client.query_range("rate(x[5m])", 0, 100, 10)
        assert samples[0].last_value == 2.0
        await client.close()

    async def test_non_200_returns_none(self):
        client = _mock_client(lambda r: httpx.Response(503, text="down"))
        assert await client.query_instant("x") is None
        await client.close()

    async def test_bad_envelope_returns_none(self):
        client = _mock_client(lambda r: httpx.Response(200, json={"status": "error"}))
        assert await client.query_instant("x") is None
        await client.close()

    async def test_transport_error_returns_none(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        client = _mock_client(handler)
        assert await client.query_instant("x") is None
        await client.close()

    async def test_available_true_and_cached(self):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return _success([{"metric": {}, "value": [1, "1"]}], "vector")

        client = _mock_client(handler)
        assert await client.available() is True
        assert await client.available() is True  # cached — no 2nd probe
        assert calls["n"] == 1
        await client.close()

    async def test_available_false_on_error(self):
        client = _mock_client(lambda r: httpx.Response(500))
        assert await client.available() is False
        await client.close()


# ═══════════════════════════════════════════════════════════════════════
# dashboard_catalog
# ═══════════════════════════════════════════════════════════════════════


class TestCatalog:
    def test_resolve_range_default(self):
        from admin.services.dashboard_catalog import resolve_range

        assert resolve_range(None).key == "6h"
        assert resolve_range("bogus").key == "6h"
        assert resolve_range("24h").key == "24h"

    def test_render_expr_substitutes_all_tokens(self):
        from admin.services.dashboard_catalog import render_expr, resolve_range

        preset = resolve_range("7d")
        expr = render_expr(
            'sum(rate(x{tenant=~"$tenant",category=~"$category"}[$timerange])) / $__range', preset
        )
        assert "$timerange" not in expr and "$__range" not in expr
        assert "$tenant" not in expr and "$category" not in expr
        assert "15m" in expr  # 7d preset rate window
        assert "7d" in expr

    def test_render_legend_templating(self):
        from admin.services.dashboard_catalog import render_legend

        assert render_legend("{{tenant}} — {{verdict}}", {"tenant": "acme", "verdict": "block"}) == "acme — block"

    def test_render_legend_defaults_to_metric_name(self):
        from admin.services.dashboard_catalog import render_legend

        assert render_legend("", {"__name__": "bulwark_x"}) == "bulwark_x"

    def test_render_legend_missing_label_is_empty(self):
        from admin.services.dashboard_catalog import render_legend

        # A template referencing an absent label renders empty then falls back.
        assert render_legend("{{nope}}", {"__name__": "m"}) == "m"

    def test_four_dashboards_present(self):
        from admin.services.dashboard_catalog import DASHBOARDS, list_dashboards

        uids = {d["uid"] for d in list_dashboards()}
        assert uids == {"bulwark-overview", "bulwark-security", "bulwark-slo", "bulwark-correlation"}
        assert set(DASHBOARDS) == uids

    def test_panel_integrity(self):
        """Every panel has targets; every table target has a column; grid sane."""
        from admin.services.dashboard_catalog import DASHBOARDS

        for dash in DASHBOARDS.values():
            assert dash.panels, dash.uid
            for p in dash.panels:
                assert p.targets, f"{dash.uid}:{p.id} has no targets"
                assert p.type in {"timeseries", "stat", "gauge", "piechart", "barchart", "table"}
                assert set(p.grid) == {"w", "h", "x", "y"}
                assert 1 <= p.grid["w"] <= 24

    def test_fallback_panels_are_instant(self):
        """A Redis fallback only makes sense for a plain instant counter query."""
        from admin.services.dashboard_catalog import DASHBOARDS

        for dash in DASHBOARDS.values():
            for p in dash.panels:
                if p.fallback:
                    assert all(t.instant for t in p.targets), f"{dash.uid}:{p.id}"
                    assert not p.requires_prometheus, f"{dash.uid}:{p.id}"


# ═══════════════════════════════════════════════════════════════════════
# dashboards route
# ═══════════════════════════════════════════════════════════════════════


class FakeClient:
    """Stand-in Prometheus client returning fixed samples for all targets."""

    def __init__(self, available=True, instant=None, range_=None):
        self._available = available
        self._instant = instant if instant is not None else []
        self._range = range_ if range_ is not None else []
        self.base_url = "http://prometheus:9090"

    async def available(self):
        return self._available

    async def query_instant(self, expr):
        return list(self._instant)

    async def query_range(self, expr, start, end, step):
        return list(self._range)


def _sample(metric, value):
    from admin.services.prometheus_query import Sample

    return Sample(metric=metric, values=[(1700000000.0, value)])


def _series(metric, points):
    from admin.services.prometheus_query import Sample

    return Sample(metric=metric, values=points)


class TestDashboardsStatus:
    async def test_status(self, monkeypatch):
        import admin.routes.dashboards as d

        monkeypatch.setattr(d, "get_prometheus_client", lambda: FakeClient(available=True))
        out = await d.dashboards_status(_user=_admin())
        assert out["prometheus_available"] is True
        assert len(out["dashboards"]) == 4
        assert any(r["key"] == "6h" for r in out["ranges"])


class TestDashboardData:
    async def test_unknown_uid_404(self, monkeypatch):
        from fastapi import HTTPException

        import admin.routes.dashboards as d

        monkeypatch.setattr(d, "get_prometheus_client", lambda: FakeClient())
        with pytest.raises(HTTPException) as ei:
            await d.dashboard_data("does-not-exist", range=None, _user=_admin())
        assert ei.value.status_code == 404

    async def test_prometheus_shaping_not_degraded(self, monkeypatch):
        import admin.routes.dashboards as d

        # One instant sample + one range series — satisfies every panel target.
        fake = FakeClient(
            available=True,
            instant=[_sample({"verdict": "block", "tenant": "acme"}, 3.0)],
            range_=[_series({"tenant": "acme"}, [(1.0, 1.0), (2.0, 2.0)])],
        )
        monkeypatch.setattr(d, "get_prometheus_client", lambda: fake)
        out = await d.dashboard_data("bulwark-overview", range="6h", _user=_admin())
        assert out["prometheus_available"] is True
        assert out["degraded"] is False
        assert out["range"]["key"] == "6h"
        assert all(p["source"] == "prometheus" for p in out["panels"])
        # Panel shapes carry the expected keys.
        by_type = {p["type"]: p for p in out["panels"]}
        assert "series" in by_type["timeseries"]
        assert "items" in by_type["piechart"]
        assert "value" in by_type["stat"]

    async def test_prometheus_up_but_empty_is_not_degraded(self, monkeypatch):
        import admin.routes.dashboards as d

        # Prometheus reachable but returns no series → panels present, empty, and
        # still sourced from prometheus (NOT degraded, NOT redis).
        monkeypatch.setattr(d, "get_prometheus_client", lambda: FakeClient(available=True, instant=[], range_=[]))
        out = await d.dashboard_data("bulwark-security", range="1h", _user=_admin())
        assert out["degraded"] is False
        assert all(p["source"] == "prometheus" for p in out["panels"])

    async def test_degraded_redis_fallback(self, monkeypatch):
        import admin.routes.dashboards as d

        monkeypatch.setattr(d, "get_prometheus_client", lambda: FakeClient(available=False))
        monkeypatch.setattr(d, "_read_redis_datasets", lambda: _redis_ds())
        out = await d.dashboard_data("bulwark-overview", range="6h", _user=_admin())
        assert out["prometheus_available"] is False
        assert out["degraded"] is True
        sources = {p["source"] for p in out["panels"]}
        # Fallback-eligible panels come from redis; the rest are 'unavailable'.
        assert "redis" in sources
        assert "unavailable" in sources
        # A fallback panel actually carries data.
        verdicts = next(p for p in out["panels"] if p["title"] == "Verdict Distribution")
        assert verdicts["source"] == "redis"
        assert {i["label"] for i in verdicts["items"]} == {"allow", "block", "warn", "redact"}

    async def test_degraded_without_redis_is_all_unavailable(self, monkeypatch):
        import admin.routes.dashboards as d

        monkeypatch.setattr(d, "get_prometheus_client", lambda: FakeClient(available=False))
        monkeypatch.setattr(d, "_read_redis_datasets", lambda: {})
        out = await d.dashboard_data("bulwark-slo", range="6h", _user=_admin())
        assert out["degraded"] is True
        assert all(p["source"] == "unavailable" for p in out["panels"])


# ── Redis fallback dataset used by the degraded-mode tests ────────────────────


def _redis_ds() -> dict:
    return {
        "verdicts_global": {"block": 10, "allow": 90, "warn": 5, "redact": 2},
        "requests_total": 107,
        "detections_category": {"prompt_injection": 8, "jailbreak": 2},
        "detections_pattern": {"PI-001": 5, "JB-002": 2},
        "usage_total": {"acme": 100, "globex": 50},
        "usage_block": {"acme": 8, "globex": 2},
        "usage_allow": {"acme": 90, "globex": 45},
        "usage_warn": {"acme": 2, "globex": 3},
        "usage_redact": {"acme": 0, "globex": 0},
        "correlation_counters": {"incidents_total": 4, "incidents_blocked": 1, "tap_dropped": 0},
    }


class TestRedisFallbackShapes:
    """Every catalogued fallback key resolves to a sensibly shaped panel."""

    def _panel(self, fallback: str):
        from admin.services.dashboard_catalog import DASHBOARDS

        for dash in DASHBOARDS.values():
            for p in dash.panels:
                if p.fallback == fallback:
                    return p
        raise AssertionError(f"no panel with fallback={fallback}")

    def test_every_fallback_key_has_a_resolver(self):
        import admin.routes.dashboards as d
        from admin.services.dashboard_catalog import DASHBOARDS

        ds = _redis_ds()
        seen = set()
        for dash in DASHBOARDS.values():
            for p in dash.panels:
                if not p.fallback or p.fallback in seen:
                    continue
                seen.add(p.fallback)
                out = d._resolve_from_redis(p, ds)
                assert out is not None, p.fallback
                assert out["source"] == "redis"

    def test_verdicts_global_shape(self):
        import admin.routes.dashboards as d

        out = d._resolve_from_redis(self._panel("verdicts_global"), _redis_ds())
        labels = {i["label"]: i["value"] for i in out["items"]}
        assert labels == {"allow": 90, "block": 10, "warn": 5, "redact": 2}

    def test_blocking_by_tenant_rate(self):
        import admin.routes.dashboards as d

        panel = self._panel("blocking_by_tenant")
        out = d._resolve_from_redis(panel, _redis_ds())
        acme = next(r for r in out["rows"] if r[panel.key_column] == "acme")
        assert acme["Block Rate"] == pytest.approx(0.08, abs=1e-6)

    def test_correlation_counters_rows(self):
        import admin.routes.dashboards as d

        panel = self._panel("correlation_counters")
        out = d._resolve_from_redis(panel, _redis_ds())
        rowmap = {r[panel.key_column]: r["Count"] for r in out["rows"]}
        assert rowmap["Incidents"] == 4
        assert rowmap["Incidents blocked"] == 1
        # Missing counter fields default to 0, not KeyError.
        assert rowmap["Origin-risk assessments"] == 0

    def test_empty_dataset_returns_none(self):
        import admin.routes.dashboards as d

        assert d._resolve_from_redis(self._panel("verdicts_global"), {}) is None


class TestReadRedisDatasets:
    def test_no_client_returns_empty(self, monkeypatch):
        import admin.routes.dashboards as d
        import admin.services.redis_sync as rs

        monkeypatch.setattr(rs, "get_redis_client", lambda *a, **k: None)
        assert d._read_redis_datasets() == {}

    def test_int_coercion(self):
        from admin.routes.dashboards import _i

        assert _i("5") == 5
        assert _i(None) == 0
        assert _i("garbage") == 0
