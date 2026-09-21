"""Bounded runner contracts without starting a proxy or touching existing labs."""

import importlib.util
import json
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError


@pytest.fixture
def runner():
    spec = importlib.util.spec_from_file_location("validation_load", Path(__file__).parents[1] / "scripts/validation-load.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("values", [{"requests": 65}, {"requests": 3}, {"requests": 5}, {"concurrency": 8},
    {"context_bytes": 8193}, {"document_bytes": 4097}, {"run_timeout_seconds": 121.0},
    {"request_timeout_seconds": 6.0}, {"backend_delay_ms": 11.0}])
def test_hard_caps(runner, values):
    with pytest.raises(ValidationError):
        runner.Config(**values)


def test_deterministic_bounded_mix(runner):
    config = runner.Config()
    fixtures = [runner.fixture(i, "1", config) for i in range(4)]
    assert fixtures == [runner.fixture(i, "1", config) for i in range(4)]
    assert [text is None for _, _, text in fixtures] == [False, True, False, True]
    assert len(fixtures[0][2]) == 2048
    assert len(fixtures[2][2]) == 1024
    assert all(len(json.dumps(body)) < 16384 for _, body, _ in fixtures)


@pytest.mark.parametrize("field,value", [("root_free_bytes", 4 * 1024**3),
    ("workspace_free_bytes", 0), ("host_available_bytes", 1024**3),
    ("cgroup_headroom_bytes", 0), ("proxy_rss_bytes", 2 * 1024**3), ("runner_rss_bytes", 2 * 1024**3)])
def test_pressure_stops(runner, field, value):
    sample = {"root_free_bytes": 6 * runner.GIB, "workspace_free_bytes": 2 * runner.GIB,
              "host_available_bytes": 3 * runner.GIB}
    runner.require_reserve(sample)
    with pytest.raises(RuntimeError, match="resource_pressure"):
        runner.require_reserve({**sample, field: value})


def test_percentiles_include_expected_blocks_not_errors(runner):
    rows = [{"latency_ms": n, "ok": True, "status": 200 if n % 2 else 403} for n in range(1, 21)]
    result = runner.summarize(rows, 2)
    assert (result["p50_ms"], result["p95_ms"], result["errors"]) == (10, 19, 0)
    assert result["completions_per_second"] == 10


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["ok", "wrong_status", "wrong_body", "timeout", "oversized", "unavailable"])
async def test_http_measurement_errors_are_not_retried(runner, mode):
    calls = []

    async def respond(request):
        body = json.loads(request.content)
        calls.append(body)
        if mode == "timeout":
            raise httpx.ReadTimeout("synthetic")
        if mode == "oversized":
            return httpx.Response(200, content=b"x" * 65537)
        if mode == "unavailable":
            return httpx.Response(503, json={"error": {"code": "audit_admission_failed"}})
        code = 403 if "blocked" in body["model"] else 200
        return httpx.Response(500 if mode == "wrong_status" else code, json={"choices": [{
            "message": {"content": "wrong" if mode == "wrong_body" else runner.REPLY}}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond), base_url="http://test", timeout=1) as client:
        result = {}
        await runner.measure(client, 1, "test", 4, runner.Config(), result)
    assert len(calls) == (4 if mode in {"ok", "unavailable"} else 1)
    assert result["errors"] == (0 if mode == "ok" else 4 if mode == "unavailable" else 1)
    assert result["unfinished"] == (0 if mode in {"ok", "unavailable"} else 3)
    if mode == "unavailable":
        assert all(row["error_code"] == "audit_admission_failed" for row in result["rows"])


@pytest.mark.asyncio
async def test_failed_startup_cleans_private_credentials_and_owned_resources(runner, tmp_path, monkeypatch):
    from unittest.mock import MagicMock

    (tmp_path / "shared").mkdir()
    # This test exercises cleanup with mocked processes, not host capacity.
    monkeypatch.setattr(runner, "resource_snapshot", lambda *args, **kwargs: {
        "root_free_bytes": 10 * runner.GIB, "workspace_free_bytes": 10 * runner.GIB,
        "host_available_bytes": 4 * runner.GIB, "cgroup_headroom_bytes": 2 * runner.GIB})
    real_root = runner.ROOT
    # Source hashes read the real checkout; only the evidence parent is redirected.
    monkeypatch.setattr(runner.tempfile, "mkdtemp", lambda **kwargs: str(tmp_path / "shared"))
    sock = MagicMock()
    sock.getsockname.return_value = ("127.0.0.1", 12345)
    sock.fileno.return_value = 8
    monkeypatch.setattr(runner.lab_utils, "listener", lambda host: sock)
    thread = MagicMock()
    thread.is_alive.return_value = False
    monkeypatch.setattr(runner.threading, "Thread", lambda **kwargs: thread)

    def fail_start(*args, **kwargs):
        directory = kwargs["cwd"]
        for name in ("api-keys", "jwt-secret", "agents.yaml", "transports.json"):
            assert (directory / name).stat().st_mode & 0o777 == 0o600
        assert kwargs["env"]["BULWARK_RATE_LIMIT_ENABLED"] == "true"
        assert kwargs["env"]["BULWARK_FAIL_MODE"] == "closed"
        assert kwargs["env"]["PYTHONPATH"] == str(real_root)
        assert "--workers" in args[0] and kwargs["pass_fds"] == (8,)
        raise RuntimeError("synthetic startup failure")

    monkeypatch.setattr(runner.subprocess, "Popen", fail_start)
    report = await runner.run("192.168.49.1", runner.Config())
    assert not report["passed"] and report["failure_type"] == "RuntimeError"
    assert report["processes_stopped"] and report["peers_stopped"] and not report["cleanup_errors"]
    assert not (tmp_path / "shared" / "api-keys").exists()
    assert not (tmp_path / "shared" / "agents.yaml").exists()
    assert sock.close.call_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["127.0.0.1", "0.0.0.0", "8.8.8.8", "::1"])
async def test_reject_non_private_backend_before_side_effects(runner, host):
    with pytest.raises(ValueError):
        await runner.run(host, runner.Config())
