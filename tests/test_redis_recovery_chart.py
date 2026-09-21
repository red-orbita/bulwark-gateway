"""Offline Redis recovery manifest contracts; no user PVCs are modified."""

import importlib.util
from pathlib import Path

import pytest

from tests.test_helm_attachments import render


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Rendering and helper checks need no user database."""


def test_redis_recovery_existing_volume_and_immutable_image():
    digest = "sha256:" + "a" * 64
    docs = render(flags=("--set", f"redis.existingClaim=redis-recovered,redis.image.digest={digest}"))
    assert ("PersistentVolumeClaim", "redis-data") not in docs
    spec = docs["Deployment", "redis"]["spec"]["template"]["spec"]
    assert next(v for v in spec["volumes"] if v["name"] == "redis-data")["persistentVolumeClaim"]["claimName"] == "redis-recovered"
    container = spec["containers"][0]
    assert container["image"] == "redis@" + digest
    assert container["startupProbe"]["failureThreshold"] == 60
    assert container["startupProbe"]["periodSeconds"] == 5
    assert "REDISCLI_AUTH=" in container["startupProbe"]["exec"]["command"][-1]


def test_default_standalone_still_creates_pvc():
    assert ("PersistentVolumeClaim", "redis-data") in render()


@pytest.mark.parametrize("value", ["0", "121", "-1"])
def test_startup_budget_bounds(value):
    render(flags=("--set", "redis.startupFailureThreshold=" + value), error="startupFailureThreshold")


def test_digest_validation():
    render(flags=("--set", "redis.image.digest=sha256:bad"), error="redis.image.digest")


def test_backup_helper_mounts_original_read_only():
    path = Path(__file__).parents[1] / "scripts/recover-k8s-redis.py"
    spec = importlib.util.spec_from_file_location("redis_recovery", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    pod = runner.helper("test-copy", "new-copy", original=True)["spec"]
    assert pod["terminationGracePeriodSeconds"] == 5
    mounts = pod["containers"][0]["volumeMounts"]
    assert next(m for m in mounts if m["name"] == "original")["readOnly"]
    assert "--fix" not in path.read_text()
