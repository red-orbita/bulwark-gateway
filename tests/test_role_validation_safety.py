"""Isolation and failure behavior of candidate role/migration validation."""

import importlib
import json
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """No real operator database."""


@pytest.mark.parametrize("module", ["validation-user-store-upgrade", "validation-role-entrypoints"])
def test_runners_reject_mutable_images(monkeypatch, module):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    runner = importlib.import_module(module)
    flags = ["--previous", "--candidate"] if "upgrade" in module else ["--admin", "--proxy"]
    monkeypatch.setattr(sys, "argv", ["runner", flags[0], "mutable:latest", flags[1], "sha256:" + "a" * 64])
    with pytest.raises(SystemExit):
        runner.main()


@pytest.mark.parametrize("fail", [False, True])
def test_role_probe_cleanup_is_scoped_and_secrets_removed(monkeypatch, tmp_path, fail):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    runner = importlib.import_module("validation-role-entrypoints")
    (tmp_path / "shared").mkdir()
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    image = "sha256:" + "a" * 64
    monkeypatch.setattr(sys, "argv", ["runner", "--admin", image, "--proxy", image])
    calls = []
    stopped = False

    @contextmanager
    def slot(root):
        assert root == tmp_path
        yield

    def run(args, **kwargs):
        nonlocal stopped
        calls.append(args)
        if args[1] == "run":
            stopped = False
            assert "--network=none" in args and "--pull=never" in args and "--read-only" in args
            assert args[-1] == image
            for env in (arg for arg in args if "_FILE=" in arg):
                assert "=/run/secrets/" in env
            if fail:
                raise subprocess.CalledProcessError(1, args)
        if args[1] == "stop":
            stopped = True
        if args[1] == "inspect":
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps({
                "Running": not stopped, "Health": {"Status": "healthy"}, "ExitCode": 0, "OOMKilled": False}).encode())
        return subprocess.CompletedProcess(args, 0, stdout=b"owned")

    monkeypatch.setattr(runner, "validation_slot", slot)
    monkeypatch.setattr(runner.subprocess, "run", run)
    if fail:
        with pytest.raises(subprocess.CalledProcessError):
            runner.main()
    else:
        runner.main()
    report_path = next((tmp_path / "shared").glob("*/report.json"))
    for directory in report_path.parent.iterdir():
        if directory.is_dir():
            assert not list(directory.iterdir())
    report = json.loads(report_path.read_text())
    assert report["production_approved"] is False
    assert len(report["images"]) == (0 if fail else 2)
    assert all(args[-1].startswith("bulwark-role-probe-") for args in calls if args[1] == "rm")


def test_role_candidate_targets_are_separate():
    proxy = (ROOT / "Dockerfile").read_text()
    assert "COPY admin" not in proxy
    assert "/app/docker/proxy_launcher.py" in proxy
    admin = (ROOT / "docker/Dockerfile.admin").read_text()
    assert "COPY admin/ /app/admin/" in admin and "admin.main:app" in admin
    assert '"/app/docker/verify_runtime.py", "admin"' in admin
