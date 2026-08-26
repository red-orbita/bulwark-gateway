"""Tests for the evaluation wiring: shared harness + proxy delegation.

These cover the Phase-1 change that makes ``/admin/evaluation`` measure the
REAL guardrail pipeline (delegated to the proxy, where ML/multilingual/RAG
models are loaded) instead of a regex-only pipeline built inside the admin pod.

The confusion-matrix math itself lives in ``test_phase8_evaluation.py``; here we
assert the plumbing: report shape/provenance, the proxy internal endpoint, and
the admin fallback policy keyed off ``BULWARK_FAIL_MODE``.
"""

from __future__ import annotations

import pytest

from src.models import ThreatCategory

# ---------------------------------------------------------------------------
# Fake httpx so the wire code (URL building, status handling) is exercised
# without a live proxy.
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status_code: int, json_data, text: str = "") -> None:
        self.status_code = status_code
        self._json = json_data
        self.text = text

    def json(self):
        return self._json


def _install_fake_httpx(
    monkeypatch,
    *,
    post_response=None,
    get_response=None,
    raise_exc=None,
):
    """Patch httpx.AsyncClient; return a dict capturing the request details."""
    import httpx

    captured: dict = {}

    class _Client:
        def __init__(self, *args, **kwargs) -> None:
            captured["timeout"] = kwargs.get("timeout")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url, json=None):
            captured["post_url"] = url
            captured["post_json"] = json
            if raise_exc is not None:
                raise raise_exc
            return post_response

        async def get(self, url):
            captured["get_url"] = url
            if raise_exc is not None:
                raise raise_exc
            return get_response

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    return captured


def _regex_pipeline():
    from src.scanners.builtin.regex_scanner import RegexInputScanner
    from src.scanners.pipeline import ScannerPipeline

    pipeline = ScannerPipeline()
    pipeline.register(RegexInputScanner())
    return pipeline


# ---------------------------------------------------------------------------
# Shared harness
# ---------------------------------------------------------------------------


class TestHarness:
    @pytest.mark.asyncio
    async def test_report_shape_and_provenance(self):
        from src.evaluation.harness import run_evaluation_report

        result = await run_evaluation_report(
            _regex_pipeline(),
            categories=[ThreatCategory.PROMPT_INJECTION],
            count_per_category=3,
            include_benign=True,
        )
        # Report fields survive serialization
        assert result["total_attacks"] >= 3
        assert "confusion_block" in result
        assert result["benign_total"] > 0
        # Frontend array + provenance
        assert isinstance(result["categories"], list) and result["categories"]
        # Only the enabled input-blocking scanner participated
        assert result["scanners_evaluated"] == ["regex_input"]

    @pytest.mark.asyncio
    async def test_default_categories_when_none(self):
        from src.evaluation.harness import DEFAULT_CATEGORIES, run_evaluation_report

        result = await run_evaluation_report(
            _regex_pipeline(), categories=None, count_per_category=2, include_benign=False
        )
        cats = {c["name"] for c in result["categories"]}
        # Every default category that produced attacks is represented
        assert cats.issubset({c.value for c in DEFAULT_CATEGORIES})
        assert result["benign_total"] == 0

    @pytest.mark.asyncio
    async def test_input_scanner_names_excludes_disabled(self):
        from src.evaluation.harness import input_scanner_names

        pipeline = _regex_pipeline()
        pipeline.disable("regex_input")
        # A disabled scanner must not be reported as evaluated.
        assert input_scanner_names(pipeline) == []


# ---------------------------------------------------------------------------
# Proxy internal endpoint
# ---------------------------------------------------------------------------


class TestProxyInternalEndpoint:
    def _client(self, monkeypatch):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        import src.scanners.pipeline as pipeline_mod
        from src.routes import health

        # The endpoint pulls the real singleton; substitute a regex pipeline so
        # the test does not depend on app-lifespan scanner registration.
        pipeline = _regex_pipeline()
        monkeypatch.setattr(pipeline_mod, "get_scanner_pipeline", lambda: pipeline)

        app = FastAPI()
        app.include_router(health.router)
        return TestClient(app)

    def test_run_returns_full_pipeline_report(self, monkeypatch):
        client = self._client(monkeypatch)
        resp = client.post(
            "/internal/evaluation/run",
            json={"categories": ["prompt_injection"], "count_per_category": 3},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["pipeline_source"] == "proxy-full-pipeline"
        assert data["scanners_evaluated"] == ["regex_input"]
        assert data["total_attacks"] >= 3

    def test_run_defaults_with_empty_body(self, monkeypatch):
        client = self._client(monkeypatch)
        resp = client.post("/internal/evaluation/run", json={})
        assert resp.status_code == 200
        assert resp.json()["total_attacks"] > 0

    def test_run_rejects_unknown_category(self, monkeypatch):
        client = self._client(monkeypatch)
        resp = client.post(
            "/internal/evaluation/run",
            json={"categories": ["not_a_category"]},
        )
        assert resp.status_code == 400

    def test_run_rejects_untemplated_category(self, monkeypatch):
        # A valid ThreatCategory with no attack templates (e.g. rate_limit) must
        # be rejected, not silently produce zero attacks.
        client = self._client(monkeypatch)
        resp = client.post(
            "/internal/evaluation/run",
            json={"categories": ["rate_limit"]},
        )
        assert resp.status_code == 400
        assert "no attack templates" in resp.json()["detail"]

    def test_run_accepts_expanded_category(self, monkeypatch):
        # A newly supported category (reverse_shell) must be accepted and yield
        # attacks through the real pipeline.
        client = self._client(monkeypatch)
        resp = client.post(
            "/internal/evaluation/run",
            json={"categories": ["reverse_shell"], "count_per_category": 4},
        )
        assert resp.status_code == 200
        assert resp.json()["total_attacks"] >= 4

    def test_count_is_bounded(self, monkeypatch):
        client = self._client(monkeypatch)
        # Absurd count is clamped, not honored verbatim (DoS guard).
        resp = client.post(
            "/internal/evaluation/run",
            json={"categories": ["prompt_injection"], "count_per_category": 100000, "include_benign": False},
        )
        assert resp.status_code == 200
        # 200 cap * 1 category, plus generator may add encoding variants.
        assert resp.json()["total_attacks"] <= 200 * 4


# ---------------------------------------------------------------------------
# Admin delegation + fail-mode fallback
# ---------------------------------------------------------------------------


class TestAdminDelegation:
    def test_resolve_categories_default_is_stable(self):
        import admin.routes.evaluation as ev

        # Default (None) must stay the original four regardless of how many
        # categories the generator now supports, so /run behaviour is unchanged.
        assert ev._resolve_categories(None) == [
            ThreatCategory.PROMPT_INJECTION,
            ThreatCategory.JAILBREAK,
            ThreatCategory.EXFILTRATION,
            ThreatCategory.CREDENTIAL_ACCESS,
        ]

    def test_resolve_categories_accepts_expanded(self):
        import admin.routes.evaluation as ev

        resolved = ev._resolve_categories(["reverse_shell", "memory_manipulation"])
        assert resolved == [
            ThreatCategory.REVERSE_SHELL,
            ThreatCategory.MEMORY_MANIPULATION,
        ]

    def test_resolve_categories_rejects_unknown(self):
        from fastapi import HTTPException

        import admin.routes.evaluation as ev

        with pytest.raises(HTTPException) as exc:
            ev._resolve_categories(["definitely_not_real"])
        assert exc.value.status_code == 400

    def test_resolve_categories_rejects_untemplated(self):
        from fastapi import HTTPException

        import admin.routes.evaluation as ev

        # rate_limit is a valid ThreatCategory but has no attack templates.
        with pytest.raises(HTTPException) as exc:
            ev._resolve_categories(["rate_limit"])
        assert exc.value.status_code == 400
        assert "no attack templates" in exc.value.detail

    @pytest.mark.asyncio
    async def test_delegate_success_returns_proxy_report(self, monkeypatch):
        import admin.routes.evaluation as ev

        captured = _install_fake_httpx(
            monkeypatch,
            post_response=_FakeResponse(200, {"total_attacks": 7, "pipeline_source": "proxy-full-pipeline"}),
        )
        out = await ev._delegate_evaluation_to_proxy(
            [ThreatCategory.PROMPT_INJECTION], count_per_category=5, include_benign=True
        )
        assert out == {"total_attacks": 7, "pipeline_source": "proxy-full-pipeline"}
        assert captured["post_url"].endswith("/internal/evaluation/run")
        assert captured["post_json"]["categories"] == ["prompt_injection"]
        assert captured["post_json"]["count_per_category"] == 5

    @pytest.mark.asyncio
    async def test_delegate_non_200_returns_none(self, monkeypatch):
        import admin.routes.evaluation as ev

        _install_fake_httpx(monkeypatch, post_response=_FakeResponse(500, None, text="boom"))
        out = await ev._delegate_evaluation_to_proxy(None, 5, True)
        assert out is None

    @pytest.mark.asyncio
    async def test_delegate_exception_returns_none(self, monkeypatch):
        import admin.routes.evaluation as ev

        _install_fake_httpx(monkeypatch, raise_exc=RuntimeError("connrefused"))
        out = await ev._delegate_evaluation_to_proxy(None, 5, True)
        assert out is None

    @pytest.mark.asyncio
    async def test_perform_evaluation_prefers_proxy(self, monkeypatch):
        import admin.routes.evaluation as ev

        async def _fake_delegate(categories, count, benign):
            return {"total_attacks": 9, "detected": 9}

        monkeypatch.setattr(ev, "_delegate_evaluation_to_proxy", _fake_delegate)
        result = await ev.perform_evaluation(count_per_category=3)
        assert result["total_attacks"] == 9
        # Provenance is stamped when the proxy omits it.
        assert result["pipeline_source"] == "proxy-full-pipeline"

    @pytest.mark.asyncio
    async def test_fallback_regex_when_open(self, monkeypatch):
        import admin.routes.evaluation as ev

        async def _down(categories, count, benign):
            return None

        monkeypatch.setattr(ev, "_delegate_evaluation_to_proxy", _down)
        monkeypatch.setenv("BULWARK_FAIL_MODE", "open")

        result = await ev.perform_evaluation(
            categories=[ThreatCategory.PROMPT_INJECTION], count_per_category=3
        )
        assert result["pipeline_source"] == "admin-local-regex-only"
        assert result["scanners_evaluated"] == ["regex_input"]
        assert result["total_attacks"] >= 3

    @pytest.mark.asyncio
    async def test_fallback_refuses_when_closed(self, monkeypatch):
        from fastapi import HTTPException

        import admin.routes.evaluation as ev

        async def _down(categories, count, benign):
            return None

        monkeypatch.setattr(ev, "_delegate_evaluation_to_proxy", _down)
        monkeypatch.setenv("BULWARK_FAIL_MODE", "closed")

        with pytest.raises(HTTPException) as exc:
            await ev.perform_evaluation(
                categories=[ThreatCategory.PROMPT_INJECTION], count_per_category=3
            )
        assert exc.value.status_code == 503
        assert "regex-only" in exc.value.detail


# ---------------------------------------------------------------------------
# Status endpoint honesty
# ---------------------------------------------------------------------------


class TestStatusHonesty:
    @pytest.mark.asyncio
    async def test_status_reflects_proxy_scanners(self, monkeypatch):
        import admin.routes.evaluation as ev

        async def _scanners():
            return ["regex_input", "ml_injection_classifier"]

        monkeypatch.setattr(ev, "_query_proxy_input_scanners", _scanners)
        status = await ev.evaluation_status(user=None)
        assert status.pipeline_source == "proxy-full-pipeline"
        assert status.proxy_reachable is True
        assert status.scanner_count == 2
        assert "ml_injection_classifier" in status.scanner_names

    @pytest.mark.asyncio
    async def test_status_fallback_when_proxy_down(self, monkeypatch):
        import admin.routes.evaluation as ev

        async def _none():
            return None

        monkeypatch.setattr(ev, "_query_proxy_input_scanners", _none)
        status = await ev.evaluation_status(user=None)
        assert status.pipeline_source == "admin-local-regex-only"
        assert status.proxy_reachable is False
        assert status.scanner_names == ["regex_input"]

    @pytest.mark.asyncio
    async def test_query_proxy_input_scanners_filters(self, monkeypatch):
        import admin.routes.evaluation as ev

        payload = {
            "scanners": [
                {"name": "regex_input", "type": "input_blocking", "enabled": True},
                {"name": "output_redaction", "type": "output_blocking", "enabled": True},
                {"name": "ml_toxicity", "type": "input_blocking", "enabled": False},
            ]
        }
        captured = _install_fake_httpx(monkeypatch, get_response=_FakeResponse(200, payload))
        names = await ev._query_proxy_input_scanners()
        # Only enabled input-blocking scanners; output + disabled excluded.
        assert names == ["regex_input"]
        assert captured["get_url"].endswith("/internal/scanners/status")


# ---------------------------------------------------------------------------
# External-corpus evaluation: proxy endpoint + admin delegation
# ---------------------------------------------------------------------------


class TestProxyCorpusEndpoint:
    def _client(self, monkeypatch):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        import src.scanners.pipeline as pipeline_mod
        from src.routes import health

        pipeline = _regex_pipeline()
        monkeypatch.setattr(pipeline_mod, "get_scanner_pipeline", lambda: pipeline)

        app = FastAPI()
        app.include_router(health.router)
        return TestClient(app)

    def test_corpus_returns_full_pipeline_report(self, monkeypatch):
        client = self._client(monkeypatch)
        # limit_per_source keeps the bundled-corpus run fast.
        resp = client.post(
            "/internal/evaluation/corpus",
            json={"limit_per_source": 5, "include_external_dir": False},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["pipeline_source"] == "proxy-full-pipeline"
        assert data["scanners_evaluated"] == ["regex_input"]
        # Corpus provenance + per-source recall are attached.
        assert "corpus_stats" in data
        assert isinstance(data["per_source"], list) and data["per_source"]

    def test_corpus_defaults_with_empty_body(self, monkeypatch):
        client = self._client(monkeypatch)
        resp = client.post("/internal/evaluation/corpus", json={})
        assert resp.status_code == 200
        assert "corpus_stats" in resp.json()

    def test_corpus_rejects_bad_sources(self, monkeypatch):
        client = self._client(monkeypatch)
        resp = client.post(
            "/internal/evaluation/corpus", json={"sources": [123, "advbench"]}
        )
        assert resp.status_code == 400

    def test_corpus_rejects_bad_limit(self, monkeypatch):
        client = self._client(monkeypatch)
        resp = client.post(
            "/internal/evaluation/corpus", json={"limit_per_source": 0}
        )
        assert resp.status_code == 400

    def test_corpus_unknown_source_is_empty_400(self, monkeypatch):
        client = self._client(monkeypatch)
        # A source name that matches no bundled corpus yields an empty run, which
        # the endpoint surfaces as 400 (never a silent zero-sample benchmark).
        resp = client.post(
            "/internal/evaluation/corpus",
            json={"sources": ["does_not_exist"], "include_external_dir": False},
        )
        assert resp.status_code == 400


class TestAdminCorpusDelegation:
    @pytest.mark.asyncio
    async def test_delegate_success_returns_proxy_report(self, monkeypatch):
        import admin.routes.evaluation as ev

        captured = _install_fake_httpx(
            monkeypatch,
            post_response=_FakeResponse(
                200, {"total_attacks": 360, "pipeline_source": "proxy-full-pipeline"}
            ),
        )
        out = await ev._delegate_corpus_to_proxy(
            ["advbench"], limit_per_source=10, include_external_dir=False
        )
        assert out["total_attacks"] == 360
        assert captured["post_url"].endswith("/internal/evaluation/corpus")
        assert captured["post_json"]["sources"] == ["advbench"]
        assert captured["post_json"]["limit_per_source"] == 10
        assert captured["post_json"]["include_external_dir"] is False

    @pytest.mark.asyncio
    async def test_delegate_400_raises_not_degrades(self, monkeypatch):
        from fastapi import HTTPException

        import admin.routes.evaluation as ev

        # A 400 (empty/misconfigured corpus) is a real client error — it must be
        # surfaced, never masked by the regex fallback.
        _install_fake_httpx(
            monkeypatch,
            post_response=_FakeResponse(400, {"detail": "corpus is empty"}, text="corpus is empty"),
        )
        with pytest.raises(HTTPException) as exc:
            await ev._delegate_corpus_to_proxy(None, None, True)
        assert exc.value.status_code == 400
        assert "empty" in exc.value.detail

    @pytest.mark.asyncio
    async def test_delegate_non_200_returns_none(self, monkeypatch):
        import admin.routes.evaluation as ev

        _install_fake_httpx(monkeypatch, post_response=_FakeResponse(500, None, text="boom"))
        out = await ev._delegate_corpus_to_proxy(None, None, True)
        assert out is None

    @pytest.mark.asyncio
    async def test_delegate_exception_returns_none(self, monkeypatch):
        import admin.routes.evaluation as ev

        _install_fake_httpx(monkeypatch, raise_exc=RuntimeError("connrefused"))
        out = await ev._delegate_corpus_to_proxy(None, None, True)
        assert out is None

    @pytest.mark.asyncio
    async def test_perform_corpus_prefers_proxy(self, monkeypatch):
        import admin.routes.evaluation as ev

        async def _fake_delegate(sources, limit, include_ext):
            return {"total_attacks": 360, "detected": 47}

        monkeypatch.setattr(ev, "_delegate_corpus_to_proxy", _fake_delegate)
        result = await ev.perform_corpus_evaluation()
        assert result["total_attacks"] == 360
        assert result["pipeline_source"] == "proxy-full-pipeline"

    @pytest.mark.asyncio
    async def test_fallback_regex_when_open(self, monkeypatch):
        import admin.routes.evaluation as ev

        async def _down(sources, limit, include_ext):
            return None

        monkeypatch.setattr(ev, "_delegate_corpus_to_proxy", _down)
        monkeypatch.setenv("BULWARK_FAIL_MODE", "open")

        result = await ev.perform_corpus_evaluation(
            limit_per_source=5, include_external_dir=False
        )
        assert result["pipeline_source"] == "admin-local-regex-only"
        assert result["scanners_evaluated"] == ["regex_input"]
        assert "corpus_stats" in result

    @pytest.mark.asyncio
    async def test_fallback_refuses_when_closed(self, monkeypatch):
        from fastapi import HTTPException

        import admin.routes.evaluation as ev

        async def _down(sources, limit, include_ext):
            return None

        monkeypatch.setattr(ev, "_delegate_corpus_to_proxy", _down)
        monkeypatch.setenv("BULWARK_FAIL_MODE", "closed")

        with pytest.raises(HTTPException) as exc:
            await ev.perform_corpus_evaluation()
        assert exc.value.status_code == 503
        assert "regex-only" in exc.value.detail
