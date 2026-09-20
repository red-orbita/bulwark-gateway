"""Canonical release packaging checks; never installs packages or starts services."""

import importlib.util
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[1]


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """No operator database needed."""


@pytest.fixture
def verifier(monkeypatch):
    spec = importlib.util.spec_from_file_location("runtime_verifier", ROOT / "docker/verify_runtime.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "sys", SimpleNamespace(version_info=(3, 14)))
    monkeypatch.setattr(module, "platform", SimpleNamespace(machine=lambda: "x86_64", python_version=lambda: "3.14.7"))
    monkeypatch.setattr(module, "os", SimpleNamespace(getuid=lambda: 65532))
    monkeypatch.setattr(module, "importlib", SimpleNamespace(
        import_module=lambda name: None, util=SimpleNamespace(find_spec=lambda name: None),
        metadata=SimpleNamespace(version=lambda name: "1.0")))
    monkeypatch.setattr(module, "verify_dependencies", lambda *args: None)
    original = Path.exists
    monkeypatch.setattr(Path, "exists", lambda path: False if str(path).startswith(("/bin/", "/usr/bin/", "/sbin/"))
                        else original(path))
    return module


@pytest.mark.parametrize("role,postgres", [("admin", False), ("proxy", False), ("proxy", True)])
def test_runtime_verifies_role_lock_set(verifier, tmp_path, role, postgres):
    name = "requirements-admin.lock" if role == "admin" else "requirements.lock"
    (tmp_path / name).write_text("example==1.0 --hash=sha256:" + "a" * 64)
    if postgres:
        (tmp_path / "requirements-postgres.lock").write_text("asyncpg==1.0 --hash=sha256:" + "b" * 64)
    report = verifier.verify(role, tmp_path)
    assert report["locked_packages"] == 1 + postgres and report["production_approved"] is False
    assert report["postgres"] == (role == "admin" or postgres)


@pytest.mark.parametrize("fault", ["version", "architecture", "uid", "missing_lock", "extra_lock", "hashless", "symlink", "drift", "admin_tree"])
def test_runtime_fails_closed(verifier, tmp_path, monkeypatch, fault):
    path = tmp_path / "requirements.lock"
    path.write_text("example==1.0 --hash=sha256:" + "a" * 64)
    if fault == "version":
        monkeypatch.setattr(verifier.sys, "version_info", (3, 13))
    elif fault == "architecture":
        monkeypatch.setattr(verifier.platform, "machine", lambda: "aarch64")
    elif fault == "uid":
        monkeypatch.setattr(verifier.os, "getuid", lambda: 0)
    elif fault == "missing_lock":
        path.unlink()
    elif fault == "extra_lock":
        (tmp_path / "requirements-admin.lock").write_text("extra")
    elif fault == "hashless":
        path.write_text("example>=1.0")
    elif fault == "symlink":
        path.unlink()
        path.symlink_to(tmp_path / "absent")
    elif fault == "drift":
        monkeypatch.setattr(verifier.importlib.metadata, "version", lambda name: "2.0")
    elif fault == "admin_tree":
        original = Path.exists
        monkeypatch.setattr(Path, "exists", lambda path: True if str(path) == "/app/admin" else original(path))
    with pytest.raises(ValueError):
        verifier.verify("proxy", tmp_path)


@pytest.mark.parametrize("ml,embeddings", [("false", "false"), ("true", "false"), ("false", "true"), ("TRUE", "false")])
def test_unlocked_extras_cannot_silently_enter_release(ml, embeddings):
    dockerfile = (ROOT / "Dockerfile").read_text()
    command = next(line[4:] for line in dockerfile.splitlines() if line.startswith('RUN test "$INSTALL_ML"'))
    result = subprocess.run(["/bin/sh", "-c", command], env={"INSTALL_ML": ml, "INSTALL_EMBEDDINGS": embeddings},  # noqa: S603
                            timeout=5, check=False)
    assert (result.returncode == 0) == (ml == embeddings == "false")


@pytest.mark.parametrize("commit", ["", "a" * 40, "unreviewed"])
def test_unreviewed_skillspector_install_is_refused(commit):
    text = (ROOT / "docker/Dockerfile.admin").read_text()
    command = next(line[4:] for line in text.splitlines() if line.startswith('RUN test -z "$SKILLSPECTOR_COMMIT"'))
    result = subprocess.run(["/bin/sh", "-c", command], env={"SKILLSPECTOR_COMMIT": commit},  # noqa: S603
                            timeout=5, check=False)
    assert (result.returncode == 0) == (commit == "")


def test_compose_and_ci_keep_canonical_build_paths():
    import yaml

    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    for role in ("admin", "proxy"):
        assert compose["services"][role]["platform"] == "linux/amd64"
    workflow = yaml.safe_load((ROOT / ".github/workflows/deploy.yml").read_text())
    builds = [step for step in workflow["jobs"]["build"]["steps"] if step.get("id") in ("proxy", "admin")]
    assert len(builds) == 2
    assert all(step["with"]["platforms"] == "linux/amd64" for step in builds)


@pytest.mark.parametrize("fault", [None, "missing", "version", "extra", "python"])
def test_target_interpreter_dependency_markers(monkeypatch, fault):
    spec = importlib.util.spec_from_file_location("dependency_verifier", ROOT / "docker/verify_runtime.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "sys", SimpleNamespace(path=[], version_info=(3, 14, 7)))
    monkeypatch.setattr("packaging.markers.default_environment", lambda: {
        "python_version": "3.14", "python_full_version": "3.14.7+", "sys_platform": "linux"})
    packages = {"root": "1.0", "required": "2.0", "optional": "1.0"}
    if fault == "missing":
        del packages["required"]
    if fault == "extra":
        del packages["optional"]
    if fault == "version":
        packages["required"] = "1.0"
    def distribution(name):
        return SimpleNamespace(metadata={"Requires-Python": ">=3.15" if fault == "python" else ">=3.11"},
            requires=['required[child]>=2; python_version >= "3.14"',
                      'absent>=1; python_version < "3.14"'] if name == "root" else
            ['optional>=1; extra == "child"'] if name == "required" else [])
    monkeypatch.setattr(module.importlib.metadata, "distribution", distribution)
    if fault:
        with pytest.raises(ValueError):
            module.verify_dependencies(packages, {"root": {"standard"}})
    else:
        module.verify_dependencies(packages, {"root": {"standard"}})
