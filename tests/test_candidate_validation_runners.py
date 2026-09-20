"""Local validation boundaries, no Docker or operator services in these tests."""

import importlib
import json
import subprocess
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

ROOT = Path(__file__).parents[1]


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """No operator database initialization."""


@pytest.mark.parametrize("tls", [False, True])
async def test_temporary_http_server_closes_on_failure(monkeypatch, tmp_path, tls):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    monkeypatch.chdir(tmp_path)
    probe = importlib.import_module("runtime-candidate-smoke")
    app = FastAPI()

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    with pytest.raises(RuntimeError, match="synthetic"):
        async with probe.running_app(app, tls=tls) as client:
            response = await client.get("/health")
            assert response.status_code == 200 and response.json() == {"status": "ok"}
            url = str(client.base_url)
            raise RuntimeError("synthetic")
    async with httpx.AsyncClient(timeout=1, trust_env=False) as client:
        with pytest.raises(httpx.ConnectError):
            await client.get(url)
    if tls:
        assert (tmp_path / "server.key").stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("fault", [None, "scan", "convert", "schema"])
def test_candidate_evidence_does_not_promote_partial_results(monkeypatch, tmp_path, fault):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    runner = importlib.import_module("validation-candidate-release")
    shared = tmp_path / "shared"
    cache = shared / "cache"
    (cache / "db").mkdir(parents=True)
    now = datetime.now(timezone.utc)
    metadata = {"Version": 2, "UpdatedAt": now.isoformat(), "DownloadedAt": now.isoformat(),
                "NextUpdate": (now + timedelta(hours=12)).isoformat()}
    (cache / "db/metadata.json").write_text(json.dumps(metadata))
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    image = "sha256:" + "a" * 64
    monkeypatch.setattr(sys, "argv", ["runner", "--admin", image, "--proxy", image, "--cache", str(cache)])
    active = False

    @contextmanager
    def slot(root):
        nonlocal active
        active = True
        yield
        active = False

    def run(args, **kwargs):
        assert active and kwargs["check"] and kwargs["timeout"] <= 150
        if args[1] == "run":
            assert "--network=none" in args and "--pull=never" in args
            assert "--read-only" in args and "--cpus=1" in args
            operation = args[args.index(runner.SCANNER) + 1]
            if (fault == "scan" and operation == "image") or (fault == "convert" and operation == "convert"):
                raise subprocess.CalledProcessError(1, args)
        return subprocess.CompletedProcess(args, 0)

    def validate_sbom(*args):
        if fault == "schema":
            raise ValueError("synthetic schema failure")

    verifier = importlib.import_module("verify-release")
    monkeypatch.setattr(verifier, "read_regular", lambda path, *args:
                        path.read_bytes() if path.name == "metadata.json" else b"{}")
    monkeypatch.setattr(verifier, "validate_scan", lambda *args: None)
    monkeypatch.setattr(verifier, "validate_sbom", validate_sbom)
    monkeypatch.setattr(verifier, "validate_scan_freshness", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner, "validation_slot", slot)
    monkeypatch.setattr(runner.subprocess, "run", run)
    if fault:
        with pytest.raises((ValueError, subprocess.CalledProcessError)):
            runner.main()
    else:
        runner.main()
    report = json.loads(next(shared.glob("candidate-release-*/report.json")).read_text())
    assert report["production_approved"] is False
    assert len(report["images"]) == (0 if fault else 2)


def test_unknown_runtime_family_never_reaches_signing():
    # Runtime variants are admitted explicitly, never by any arbitrary apk prefix.
    text = (ROOT / "scripts/verify-release.py").read_text()
    assert '"wolfi": "pkg:apk/wolfi/"' in text
    assert '"debian": "pkg:deb/debian/"' in text


@pytest.mark.parametrize("fault", [None, "old", "future", "expired", "naive", "missing", "redownload_old"])
def test_vulnerability_database_freshness(monkeypatch, fault):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    runner = importlib.import_module("validation-candidate-release")
    now = datetime(2026, 9, 19, 12, tzinfo=timezone.utc)
    metadata = {"Version": 2, "UpdatedAt": (now - timedelta(hours=4)).isoformat(),
                "DownloadedAt": now.isoformat(), "NextUpdate": (now + timedelta(hours=20)).isoformat()}
    if fault in ("old", "redownload_old"):
        metadata["UpdatedAt"] = (now - timedelta(days=2)).isoformat()
    elif fault == "future":
        metadata["UpdatedAt"] = (now + timedelta(hours=2)).isoformat()
    elif fault == "expired":
        metadata["NextUpdate"] = (now - timedelta(seconds=1)).isoformat()
    elif fault == "naive":
        metadata["UpdatedAt"] = "2026-09-19T10:00:00"
    elif fault == "missing":
        del metadata["DownloadedAt"]
    if fault:
        with pytest.raises(ValueError, match="stale or metadata"):
            runner.validate_database_metadata(metadata, now)
    else:
        runner.validate_database_metadata(metadata, now)
