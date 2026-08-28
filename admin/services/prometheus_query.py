"""Read-only Prometheus query client for the in-UI dashboards.

The admin portal ports the four Grafana dashboards (overview / security / slo /
correlation) into its own UI. Grafana talks to Prometheus; so does this client.
It issues **only** the server-side PromQL catalog (``dashboard_catalog.py``) —
never operator-supplied PromQL — against the Prometheus HTTP API
(``/api/v1/query`` and ``/api/v1/query_range``).

Design constraints (see AGENTS.md / SECURE-CODING-STANDARDS):

* No new dependencies — reuses ``httpx`` (already an admin dependency).
* Fail-soft: every call degrades to ``None``/empty rather than raising into the
  request path, so an unreachable or NetworkPolicy-blocked Prometheus makes the
  dashboards render in *degraded* mode (Redis instant fallback) instead of 500.
* Reachability is cached (~30s) so a down Prometheus does not add a full
  connect-timeout to every panel request.

Prometheus reachability inside the cluster is via the Service DNS name
``http://prometheus:9090`` (the same URL Grafana's datasource uses). Override
with ``BULWARK_PROMETHEUS_URL``.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

import httpx

# Default matches the in-cluster Prometheus Service (helm monitoring.yaml) and
# the Grafana datasource URL. The FQDN form does not resolve from every pod, so
# the short Service name is used deliberately.
_DEFAULT_URL = "http://prometheus:9090"

# Per-request timeout. Prometheus instant/range queries over these small,
# recording-rule-backed series are sub-100ms in practice; a short ceiling keeps
# a slow/hung Prometheus from stalling a dashboard panel load.
_QUERY_TIMEOUT_SECONDS = 3.0

# Reachability probe cache. A single cheap probe result is reused for this long
# so a down Prometheus costs one timeout per window, not one per panel.
_AVAILABILITY_TTL_SECONDS = 30.0


@dataclass
class Sample:
    """A single (labels, points) series from a Prometheus query result.

    * ``metric`` — the label set (``__name__`` included when present).
    * ``values`` — list of ``(unix_seconds, float_value)`` points. An instant
      query yields exactly one point; a range query yields many. Points whose
      value is not a finite float (``NaN``/``Inf``/parse error) are dropped.
    """

    metric: dict[str, str]
    values: list[tuple[float, float]] = field(default_factory=list)

    @property
    def last_value(self) -> float | None:
        """Most recent numeric value, or ``None`` when the series is empty."""
        return self.values[-1][1] if self.values else None


def _coerce_float(raw: object) -> float | None:
    """Parse a Prometheus scalar string to a finite float, else ``None``.

    Prometheus encodes ``NaN``/``+Inf``/``-Inf`` as strings; those are treated
    as "no data" so a panel renders a gap rather than a bogus spike.
    """
    try:
        val = float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if val != val or val in (float("inf"), float("-inf")):  # NaN or Inf
        return None
    return val


def _parse_result(result: list[dict], result_type: str) -> list[Sample]:
    """Normalise a Prometheus ``data`` block into ``Sample`` objects.

    Handles both ``vector`` (instant, single ``value``) and ``matrix`` (range,
    many ``values``) result types. Unknown/scalar shapes yield an empty list.
    """
    samples: list[Sample] = []
    for entry in result:
        metric = entry.get("metric", {}) or {}
        points: list[tuple[float, float]] = []
        if result_type == "vector":
            raw = entry.get("value")
            if isinstance(raw, (list, tuple)) and len(raw) == 2:
                ts = _coerce_float(raw[0])
                val = _coerce_float(raw[1])
                if ts is not None and val is not None:
                    points.append((ts, val))
        elif result_type == "matrix":
            for raw in entry.get("values", []) or []:
                if isinstance(raw, (list, tuple)) and len(raw) == 2:
                    ts = _coerce_float(raw[0])
                    val = _coerce_float(raw[1])
                    if ts is not None and val is not None:
                        points.append((ts, val))
        samples.append(Sample(metric={str(k): str(v) for k, v in metric.items()}, values=points))
    return samples


class PrometheusClient:
    """Minimal async Prometheus HTTP API client (query + query_range).

    A single instance is shared process-wide (see ``get_prometheus_client``); it
    lazily builds one pooled ``httpx.AsyncClient`` and reuses it. All methods are
    best-effort and never raise into the caller — failures return ``None``.
    """

    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (base_url or os.getenv("BULWARK_PROMETHEUS_URL") or _DEFAULT_URL).rstrip("/")
        self._client: httpx.AsyncClient | None = None
        self._available_cache: bool | None = None
        self._available_ts: float = 0.0

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=_QUERY_TIMEOUT_SECONDS,
            )
        return self._client

    async def close(self) -> None:
        """Close the pooled client (called on app shutdown / test teardown)."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get(self, path: str, params: dict) -> tuple[list[dict], str] | None:
        """Issue a GET and return ``(data.result, data.resultType)``, or ``None``.

        Returns ``None`` on any transport error, non-200 status, or a Prometheus
        ``status != "success"`` envelope. The result type is returned alongside
        the result (never stored on ``self``) so concurrent ``asyncio.gather``
        callers cannot race on shared state.
        """
        try:
            resp = await self._get_client().get(path, params=params)
        except (httpx.HTTPError, OSError):
            return None
        if resp.status_code != 200:
            return None
        try:
            payload = resp.json()
        except ValueError:
            return None
        if not isinstance(payload, dict) or payload.get("status") != "success":
            return None
        data = payload.get("data") or {}
        result = data.get("result")
        if not isinstance(result, list):
            return None
        return result, str(data.get("resultType", ""))

    async def query_instant(self, expr: str) -> list[Sample] | None:
        """Run an instant query (``/api/v1/query``). ``None`` on failure."""
        got = await self._get("/api/v1/query", {"query": expr})
        if got is None:
            return None
        result, result_type = got
        return _parse_result(result, result_type or "vector")

    async def query_range(
        self, expr: str, start: float, end: float, step: float
    ) -> list[Sample] | None:
        """Run a range query (``/api/v1/query_range``). ``None`` on failure.

        ``start``/``end`` are unix seconds; ``step`` is the resolution in
        seconds. Prometheus caps a range at 11,000 points, so callers must size
        ``step`` from the window (``dashboard_catalog`` presets do this).
        """
        got = await self._get(
            "/api/v1/query_range",
            {"query": expr, "start": start, "end": end, "step": step},
        )
        if got is None:
            return None
        result, result_type = got
        return _parse_result(result, result_type or "matrix")

    async def available(self) -> bool:
        """Return whether Prometheus answered a trivial query recently.

        Result is cached for ``_AVAILABILITY_TTL_SECONDS`` so a persistently
        down/blocked Prometheus is probed at most once per window. Probes with
        the cheapest possible query (``vector(1)``).
        """
        now = time.monotonic()
        if self._available_cache is not None and (now - self._available_ts) < _AVAILABILITY_TTL_SECONDS:
            return self._available_cache
        got = await self._get("/api/v1/query", {"query": "vector(1)"})
        self._available_cache = got is not None
        self._available_ts = time.monotonic()
        return self._available_cache


_client_singleton: PrometheusClient | None = None


def get_prometheus_client() -> PrometheusClient:
    """Return the process-wide Prometheus client singleton."""
    global _client_singleton
    if _client_singleton is None:
        _client_singleton = PrometheusClient()
    return _client_singleton
