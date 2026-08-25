"""Producer-side tests for the admin Prometheus exposition helpers.

Covers the honest-observability rendering path added for the Grafana overhaul:

  * ``_esc``                    — Prometheus label-value escaping
  * ``_render_labeled_counter`` — single-label counter family rendering
  * ``_render_redis_prometheus``— cluster-wide series pulled from Redis (pipeline)
  * ``_render_proxy_telemetry`` — real proxy latency/throughput gauges from cache

and the proxy-side detection counters that feed the category / severity / pattern
breakdowns (``_push_recent_block``).

Every render helper is fail-closed: an unreachable / faulting source must yield an
empty string so the scrape still succeeds with whatever other families are present
— never a partial/garbage exposition and never a raised exception.
"""

from __future__ import annotations

import pytest

import admin.routes.health as health
from src.guardrails import dynamic_registry as registry_mod
from src.models import SecurityEvent, ThreatCategory, Verdict
from src.routes import proxy as proxy_mod

# ═══════════════════════════════════════════════════════════════════════
# Fakes
# ═══════════════════════════════════════════════════════════════════════


class _FakePipeline:
    """Records queued read ops and replays them against the parent FakeRedis."""

    def __init__(self, redis: "_FakeRedis") -> None:
        self._redis = redis
        self._ops: list[tuple[str, tuple]] = []

    def mget(self, *keys):
        # _render_redis_prometheus passes keys positionally; tolerate a list too.
        if len(keys) == 1 and isinstance(keys[0], (list, tuple)):
            keys = tuple(keys[0])
        self._ops.append(("mget", keys))
        return self

    def hgetall(self, key):
        self._ops.append(("hgetall", (key,)))
        return self

    def execute(self):
        if self._redis.fail_execute:
            raise ConnectionError("pipeline boom")
        out = []
        for op, args in self._ops:
            if op == "mget":
                out.append([self._redis.strings.get(k) for k in args])
            else:  # hgetall
                out.append(dict(self._redis.hashes.get(args[0], {})))
        return out


class _FakeRedis:
    """decode_responses-style stub: string keys + hashes + pipeline + hincrby."""

    def __init__(self) -> None:
        self.strings: dict[str, str] = {}
        self.hashes: dict[str, dict[str, str]] = {}
        self.fail_execute = False

    def pipeline(self, transaction: bool = True):
        return _FakePipeline(self)

    def hincrby(self, key: str, field: str, amount: int = 1) -> int:
        h = self.hashes.setdefault(key, {})
        h[field] = str(int(h.get(field, "0")) + amount)
        return int(h[field])

    # recent-blocks list ops (used by _push_recent_block before the counters)
    def lpush(self, key, value):
        return 1

    def ltrim(self, key, start, end):
        return True


def _seed_full(r: _FakeRedis) -> None:
    """A realistic, fully-populated snapshot across every family."""
    r.strings.update({
        "bulwark:global:requests_total": "290",
        "bulwark:global:block": "183",
        "bulwark:global:allow": "101",
        "bulwark:global:warn": "6",
        "bulwark:global:redact": "0",
        "bulwark:siem:batches_sent": "66071",
        "bulwark:siem:events_exported": "66071",
        "bulwark:siem:export_errors": "12",
    })
    r.hashes["bulwark:usage:total"] = {"default-corp": "290", "acme": "40"}
    r.hashes["bulwark:usage:block"] = {"default-corp": "183"}
    r.hashes["bulwark:usage:allow"] = {"default-corp": "101"}
    r.hashes["bulwark:usage:warn"] = {"default-corp": "6"}
    r.hashes["bulwark:usage:redact"] = {}
    r.hashes["bulwark:detections:category"] = {"prompt_injection": "120", "jailbreak": "63"}
    r.hashes["bulwark:detections:severity"] = {"high": "150", "critical": "33"}
    r.hashes["bulwark:detections:pattern"] = {"PL-001": "88", "JB-002": "40"}
    r.hashes["bulwark:cost:global"] = {
        "prompt": "10000", "completion": "5000", "requests": "290", "cost_usd": "1.25",
    }
    r.hashes["bulwark:correlation:counters"] = {"incidents_total": "3"}


# ═══════════════════════════════════════════════════════════════════════
# _esc
# ═══════════════════════════════════════════════════════════════════════


class TestEsc:
    def test_escapes_backslash(self):
        assert health._esc(r"a\b") == r"a\\b"

    def test_escapes_double_quote(self):
        assert health._esc('say "hi"') == 'say \\"hi\\"'

    def test_escapes_newline(self):
        assert health._esc("a\nb") == "a\\nb"

    def test_combined_injection_attempt_fully_escaped(self):
        # Adversarial: a label value crafted to break out of the {label="..."}
        # clause and inject a second series. All three metacharacters neutralised.
        raw = 'x" } evil{a="1'
        out = health._esc(raw)
        assert '"' not in out.replace('\\"', "")  # every quote is backslash-escaped
        assert out == 'x\\" } evil{a=\\"1'

    def test_plain_string_unchanged(self):
        assert health._esc("prompt_injection") == "prompt_injection"

    def test_empty_string_unchanged(self):
        assert health._esc("") == ""


# ═══════════════════════════════════════════════════════════════════════
# _render_labeled_counter
# ═══════════════════════════════════════════════════════════════════════


class TestRenderLabeledCounter:
    def test_renders_help_type_and_samples(self):
        out = health._render_labeled_counter(
            "bulwark_x_total", "help text", {"a": "3", "b": "7"}, "tenant",
        )
        assert out[0] == "# HELP bulwark_x_total help text"
        assert out[1] == "# TYPE bulwark_x_total counter"
        assert 'bulwark_x_total{tenant="a"} 3' in out
        assert 'bulwark_x_total{tenant="b"} 7' in out

    def test_coerces_non_numeric_to_zero(self):
        out = health._render_labeled_counter(
            "bulwark_x_total", "h", {"a": "not-a-number", "b": None}, "k",
        )
        assert 'bulwark_x_total{k="a"} 0' in out
        assert 'bulwark_x_total{k="b"} 0' in out

    def test_label_value_is_escaped(self):
        out = health._render_labeled_counter(
            "bulwark_x_total", "h", {'ten"ant': "1"}, "tenant",
        )
        assert 'bulwark_x_total{tenant="ten\\"ant"} 1' in out

    def test_empty_samples_yields_no_lines(self):
        # An absent subsystem must contribute nothing — not even a bare header.
        assert health._render_labeled_counter("m", "h", {}, "l") == []

    def test_none_samples_yields_no_lines(self):
        assert health._render_labeled_counter("m", "h", None, "l") == []


# ═══════════════════════════════════════════════════════════════════════
# _render_redis_prometheus
# ═══════════════════════════════════════════════════════════════════════


class TestRenderRedisPrometheus:
    def _wire(self, monkeypatch, r):
        from admin.services import redis_sync
        monkeypatch.setattr(redis_sync, "get_redis_client", lambda timeout=0.5: r)

    def test_full_snapshot_emits_all_families(self, monkeypatch):
        r = _FakeRedis()
        _seed_full(r)
        self._wire(monkeypatch, r)

        out = health._render_redis_prometheus()

        assert "bulwark_requests_total 290" in out
        assert 'bulwark_verdicts_total{verdict="block"} 183' in out
        assert 'bulwark_verdicts_total{verdict="allow"} 101' in out
        assert 'bulwark_requests_by_tenant_total{tenant="default-corp"} 290' in out
        assert 'bulwark_verdicts_by_tenant_total{tenant="default-corp",verdict="block"} 183' in out
        assert 'bulwark_detections_by_category_total{category="prompt_injection"} 120' in out
        assert 'bulwark_detections_by_severity_total{severity="critical"} 33' in out
        assert 'bulwark_pattern_matches_total{pattern_id="PL-001"} 88' in out
        assert 'bulwark_tokens_total{direction="prompt"} 10000' in out
        assert "bulwark_cost_usd_total 1.25" in out
        assert "bulwark_siem_batches_sent_total 66071" in out
        assert "bulwark_siem_export_errors_total 12" in out
        # correlation counters always emitted (stable zero when unset)
        assert "bulwark_correlation_incidents_total 3" in out
        # well-formed exposition: trailing newline, no bare HELP without samples
        assert out.endswith("\n")

    def test_pattern_series_bounded_to_max(self, monkeypatch):
        # Adversarial cardinality: 250 distinct custom patterns must not blow up
        # the scrape — only the top _MAX_PATTERN_SERIES (200) by count are emitted.
        r = _FakeRedis()
        _seed_full(r)
        r.hashes["bulwark:detections:pattern"] = {f"P-{i:04d}": str(i) for i in range(250)}
        self._wire(monkeypatch, r)

        out = health._render_redis_prometheus()
        series = [ln for ln in out.splitlines()
                  if ln.startswith("bulwark_pattern_matches_total{")]
        assert len(series) == health._MAX_PATTERN_SERIES == 200
        # top-N by count: the highest-count pattern is present, a low one is not.
        assert 'bulwark_pattern_matches_total{pattern_id="P-0249"}' in out
        assert 'bulwark_pattern_matches_total{pattern_id="P-0000"}' not in out

    def test_absent_optional_families_are_omitted(self, monkeypatch):
        # Only globals present → no cost/token block, no per-tenant block, but the
        # scrape is still valid (globals + siem + correlation always emitted).
        r = _FakeRedis()
        r.strings["bulwark:global:requests_total"] = "5"
        self._wire(monkeypatch, r)

        out = health._render_redis_prometheus()
        assert "bulwark_requests_total 5" in out
        assert "bulwark_tokens_total" not in out
        assert "bulwark_requests_by_tenant_total" not in out
        assert "bulwark_detections_by_category_total" not in out

    def test_none_client_returns_empty(self, monkeypatch):
        from admin.services import redis_sync
        monkeypatch.setattr(redis_sync, "get_redis_client", lambda timeout=0.5: None)
        assert health._render_redis_prometheus() == ""

    def test_pipeline_fault_returns_empty(self, monkeypatch):
        # Fail-closed: a Redis fault must NOT raise or emit a partial exposition.
        r = _FakeRedis()
        _seed_full(r)
        r.fail_execute = True
        self._wire(monkeypatch, r)
        assert health._render_redis_prometheus() == ""

    def test_client_factory_raising_returns_empty(self, monkeypatch):
        def _boom(timeout=0.5):
            raise RuntimeError("cannot connect")
        from admin.services import redis_sync
        monkeypatch.setattr(redis_sync, "get_redis_client", _boom)
        assert health._render_redis_prometheus() == ""


# ═══════════════════════════════════════════════════════════════════════
# _render_proxy_telemetry
# ═══════════════════════════════════════════════════════════════════════


class TestRenderProxyTelemetry:
    def test_full_stats_emit_gauges(self, monkeypatch):
        monkeypatch.setattr(health, "_telemetry_cache", {"proxy": {
            "latency_p50_ms": 3.5,
            "latency_p95_ms": 42.0,
            "latency_p99_ms": 88.25,
            "requests_per_second": 12.5,
            "errors": 4,
        }})
        out = health._render_proxy_telemetry()
        assert "bulwark_proxy_latency_p50_ms 3.50" in out
        assert "bulwark_proxy_latency_p95_ms 42.00" in out
        assert "bulwark_proxy_latency_p99_ms 88.25" in out
        assert "# TYPE bulwark_proxy_latency_p95_ms gauge" in out
        assert "bulwark_proxy_requests_per_second 12.50" in out
        assert "bulwark_proxy_errors_total 4" in out
        assert "# TYPE bulwark_proxy_errors_total counter" in out
        assert out.endswith("\n")

    def test_partial_stats_emit_only_present_keys(self, monkeypatch):
        monkeypatch.setattr(health, "_telemetry_cache", {"proxy": {
            "latency_p95_ms": 10.0,
        }})
        out = health._render_proxy_telemetry()
        assert "bulwark_proxy_latency_p95_ms 10.00" in out
        assert "bulwark_proxy_latency_p50_ms" not in out
        assert "bulwark_proxy_requests_per_second" not in out
        assert "bulwark_proxy_errors_total" not in out

    def test_non_numeric_latency_coerced(self, monkeypatch):
        # Adversarial/garbage cache value must not raise — coerced to 0.00.
        monkeypatch.setattr(health, "_telemetry_cache", {"proxy": {
            "latency_p50_ms": "not-a-float",
        }})
        out = health._render_proxy_telemetry()
        assert "bulwark_proxy_latency_p50_ms 0.00" in out

    def test_empty_cache_returns_empty(self, monkeypatch):
        monkeypatch.setattr(health, "_telemetry_cache", {"proxy": {}})
        assert health._render_proxy_telemetry() == ""

    def test_missing_proxy_key_returns_empty(self, monkeypatch):
        monkeypatch.setattr(health, "_telemetry_cache", {})
        assert health._render_proxy_telemetry() == ""


# ═══════════════════════════════════════════════════════════════════════
# proxy _push_recent_block — detection counters
# ═══════════════════════════════════════════════════════════════════════


def _event(**over) -> SecurityEvent:
    base = dict(
        tenant_id="acme",
        agent_id="support-bot",
        verdict=Verdict.BLOCK,
        category=ThreatCategory.PROMPT_INJECTION,
        description="Instruction override attempt",
        source="input_guardrail",
        severity="high",
        matched_pattern="PL-001",
    )
    base.update(over)
    return SecurityEvent(**base)


@pytest.fixture
def counter_registry(monkeypatch):
    fake = _FakeRedis()

    class _Reg:
        _redis = fake

    monkeypatch.setattr(registry_mod, "get_pattern_registry", lambda: _Reg())
    return fake


class TestPushRecentBlockCounters:
    def test_increments_category_severity_pattern(self, counter_registry):
        proxy_mod._push_recent_block([_event()], "acme", "support-bot")
        assert counter_registry.hashes["bulwark:detections:category"]["prompt_injection"] == "1"
        assert counter_registry.hashes["bulwark:detections:severity"]["high"] == "1"
        assert counter_registry.hashes["bulwark:detections:pattern"]["PL-001"] == "1"

    def test_counts_accumulate_across_calls(self, counter_registry):
        proxy_mod._push_recent_block([_event()], "acme", "support-bot")
        proxy_mod._push_recent_block([_event()], "acme", "support-bot")
        assert counter_registry.hashes["bulwark:detections:category"]["prompt_injection"] == "2"
        assert counter_registry.hashes["bulwark:detections:severity"]["high"] == "2"

    def test_pattern_id_truncated_to_128(self, counter_registry):
        long_id = "X" * 300
        proxy_mod._push_recent_block([_event(matched_pattern=long_id)], "acme", "support-bot")
        keys = list(counter_registry.hashes["bulwark:detections:pattern"].keys())
        assert len(keys) == 1
        assert len(keys[0]) == 128

    def test_empty_pattern_id_skips_pattern_counter(self, counter_registry):
        proxy_mod._push_recent_block([_event(matched_pattern=None)], "acme", "support-bot")
        # category/severity still counted, but no pattern hash written.
        assert counter_registry.hashes["bulwark:detections:category"]["prompt_injection"] == "1"
        assert "bulwark:detections:pattern" not in counter_registry.hashes

    def test_missing_redis_is_noop(self, monkeypatch):
        class _Reg:
            _redis = None
        monkeypatch.setattr(registry_mod, "get_pattern_registry", lambda: _Reg())
        # Must not raise even though there is no backend to count into.
        proxy_mod._push_recent_block([_event()], "acme", "support-bot")
