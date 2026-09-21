"""Offline regression checks; never install packages or build/pull images."""

import importlib.metadata
import re
import subprocess
import tomllib

import pytest
import yaml

from tests.packaging_locks import ROOT, ci_entries, lock_entries, main, verify_installed


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Packaging tests must not initialize application databases."""


def test_postgres_reuses_all_reviewed_admin_hashes_and_no_other_dependencies():
    admin = lock_entries((ROOT / "requirements-admin.lock").read_text())
    postgres = lock_entries((ROOT / "requirements-postgres.lock").read_text())
    proxy = lock_entries((ROOT / "requirements.lock").read_text())
    assert postgres == {"asyncpg": admin["asyncpg"]}
    assert not postgres.keys() & proxy.keys()
    assert "cryptography" not in proxy and "sqlcipher3-binary" not in proxy


def test_explicit_ci_composition_preserves_admin_and_proxy_only_hashes():
    admin = lock_entries((ROOT / "requirements-admin.lock").read_text())
    proxy = lock_entries((ROOT / "requirements.lock").read_text())
    combined = ci_entries()
    assert all(combined[name] == entry for name, entry in admin.items())
    assert combined.keys() - admin.keys() == {
        "attrs", "jsonschema", "jsonschema-specifications", "referencing", "rpds-py",
    }
    assert all(entry == proxy[name] for name, entry in combined.items() if name not in admin)


@pytest.mark.parametrize("text", [
    "asyncpg>=0.29", "asyncpg==0.31.0", "-r requirements-admin.lock",
    "--extra-index-url https://untrusted.invalid", "asyncpg @ https://untrusted.invalid/a.whl",
    "asyncpg==0.31.0 --hash=sha256:not-a-hash",
])
def test_lock_parser_rejects_unpinned_or_unhashed_input(text):
    with pytest.raises(ValueError, match="exact version"):
        lock_entries(text)


def test_duplicate_and_conflicting_locks_fail(monkeypatch):
    entry = lock_entries((ROOT / "requirements-postgres.lock").read_text())["asyncpg"]
    with pytest.raises(ValueError, match="Duplicate"):
        lock_entries(entry + "\n" + entry)
    monkeypatch.setattr("sys.argv", ["packaging_locks.py", "verify",
                                   str(ROOT / "requirements.lock"), str(ROOT / "requirements-admin.lock")])
    with pytest.raises(ValueError, match="Conflicting locks"):
        main()


def test_installed_version_parity_rejects_overwrite_and_absent_package(monkeypatch):
    entries = lock_entries((ROOT / "requirements-postgres.lock").read_text())
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "0.31.0")
    verify_installed(entries)
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "0.29.0")
    with pytest.raises(ValueError, match="differs from lock"):
        verify_installed(entries)

    def absent(name):
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", absent)
    with pytest.raises(importlib.metadata.PackageNotFoundError):
        verify_installed(entries)


def test_ci_cli_emits_hash_lock_and_non_hash_constraints(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["packaging_locks.py", "ci"])
    main()
    assert lock_entries(capsys.readouterr().out) == ci_entries()
    monkeypatch.setattr("sys.argv", ["packaging_locks.py", "constraints"])
    main()
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == len(ci_entries())
    assert all(re.fullmatch(r"[\w-]+==[\w.]+", line) for line in lines)
    monkeypatch.setattr("sys.argv", ["packaging_locks.py", "tooling"])
    main()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert capsys.readouterr().out.splitlines() == project["project"]["optional-dependencies"]["dev"]


@pytest.mark.parametrize("variant", ["false", "true", "TRUE", "", "true; exit 0"])
def test_docker_postgres_selection_fails_closed_without_installing(variant):
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "ARG INSTALL_POSTGRES=false" in dockerfile
    assert "COPY requirements.lock requirements-postgres.lock ./" in dockerfile
    assert "pip install --no-cache-dir --no-deps ." not in dockerfile
    command = dockerfile.split('RUN case "$INSTALL_POSTGRES"', 1)[1].split("\n\n", 1)[0]
    # Replace python with a shell function that records arguments, never invokes pip.
    result = subprocess.run(  # noqa: S603
        ["/bin/sh", "-c", 'python() { printf "%s\\n" "$*"; }; case "$INSTALL_POSTGRES"' + command],
        env={"INSTALL_POSTGRES": variant}, text=True, capture_output=True, timeout=5,
    )
    if variant not in ("true", "false"):
        assert result.returncode != 0 and "must be true or false" in result.stderr
        assert not result.stdout
    else:
        assert result.returncode == 0
        install, = result.stdout.splitlines()
        assert "--target /packages --python-version 3.14" in install
        assert "--only-binary=:all: --require-hashes -r requirements.lock" in install
        assert ("-r requirements-postgres.lock" in install) == (variant == "true")
        assert "--no-deps" not in install
        assert '["python3", "/app/docker/verify_runtime.py", "proxy"]' in dockerfile
        assert "source=/verification,target=/verification" in dockerfile


def test_runtime_matrix_and_operator_are_clean_and_never_merge_service_locks():
    jobs = yaml.safe_load((ROOT / ".github/workflows/deploy.yml").read_text())["jobs"]
    matrix = jobs["test-runtime-locks"]
    assert any(step.get("with", {}).get("python-version") == "3.14" for step in matrix["steps"])
    assert not matrix["strategy"]["fail-fast"]
    assert {row["runtime"]: row["locks"] for row in matrix["strategy"]["matrix"]["include"]} == {
        "proxy": "requirements.lock", "proxy-postgres": "requirements.lock requirements-postgres.lock",
        "admin": "requirements-admin.lock",
    }
    command = next(step["run"] for step in matrix["steps"] if "run" in step)
    assert "python -m venv .runtime-venv" in command
    assert "--only-binary=:all: --require-hashes" in command
    assert "pip check" in command and "packaging_locks.py verify" in command
    assert "pip install" in command and "pytest" not in command
    operator = next(step["run"] for step in jobs["deploy-production"]["steps"]
                    if step.get("name") == "Install locked operator dependencies")
    assert "python -m venv .operator-venv" in operator
    assert 'packaging_locks.py ci > "$RUNNER_TEMP/operator.lock"' in operator
    assert '--require-hashes -r "$RUNNER_TEMP/operator.lock"' in operator
    assert 'packaging_locks.py verify "$RUNNER_TEMP/operator.lock"' in operator
    assert "requirements.lock" not in operator
    assert "pip check" in operator


def test_anyio_tls_idna_security_fix_is_pinned_in_both_runtimes():
    for filename in ("requirements.lock", "requirements-admin.lock"):
        entries = lock_entries((ROOT / filename).read_text())
        assert entries["anyio"].startswith("anyio==4.14.2 ")
        assert "9f505dda5ac9f0c8309b5e8bd445a8c2bf7246f3ce950121e45ea15bc41d1494" in entries["anyio"]


def test_release_selects_postgres_and_gates_deployment_on_exact_image_import():
    jobs = yaml.safe_load((ROOT / ".github/workflows/deploy.yml").read_text())["jobs"]
    steps = jobs["build"]["steps"]
    build = next(step for step in steps if step.get("id") == "proxy")
    assert "INSTALL_POSTGRES=true" in build["with"]["build-args"]
    assert "INSTALL_ML=false" in build["with"]["build-args"]
    check = next(step for step in steps if step.get("name") == "Verify PostgreSQL driver in exact proxy image")
    assert steps.index(check) > steps.index(build)
    assert "if" not in check and not check.get("continue-on-error")
    assert "@${{ steps.proxy.outputs.digest }}" in check["env"]["PROXY_IMAGE"]
    assert '--entrypoint python3 "$PROXY_IMAGE"' in check["run"]
    assert "import asyncpg.protocol.protocol" in check["run"]
    assert "--network=none --read-only --cap-drop=ALL" in check["run"]
    assert jobs["deploy-production"]["needs"] == "build"
