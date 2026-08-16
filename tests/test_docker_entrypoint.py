"""
GAP-A regression tests — proxy entrypoint worker parametrization.

The Dockerfile previously hardcoded ``CMD ["--workers", "4"]`` independently of
``BULWARK_WORKERS``. Because the in-memory fallback rate limiter divides the
per-worker token bucket by ``BULWARK_WORKERS`` (src/middleware/rate_limit.py),
a mismatch between the *real* uvicorn worker count and ``BULWARK_WORKERS`` let
each worker over-allow traffic. These tests pin the entrypoint contract:

  * the real ``--workers`` value is derived from ``BULWARK_WORKERS``
  * the default (unset) worker count stays aligned with the limiter divisor
    default and ``settings.workers`` (all 4)
  * garbage / non-positive input fails closed instead of silently defaulting
  * the Dockerfile invokes the script via ``exec`` (APT-13 signal handling)

The entrypoint is a POSIX shell script, so we exercise it for real by shadowing
``python`` on PATH with a stub that echoes its arguments.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
ENTRYPOINT = REPO_ROOT / "docker" / "entrypoint-proxy.sh"
DOCKERFILE = REPO_ROOT / "Dockerfile"


def _run_entrypoint(tmp_path: Path, workers_env: str | None) -> subprocess.CompletedProcess:
    """Run the entrypoint with a fake `python` that prints its args and exits 0."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_python = fake_bin / "python"
    fake_python.write_text('#!/bin/sh\necho "PYTHON_ARGS: $*"\nexit 0\n')
    fake_python.chmod(0o755)

    env = {"PATH": f"{fake_bin}:{os.environ.get('PATH', '')}"}
    if workers_env is not None:
        env["BULWARK_WORKERS"] = workers_env

    return subprocess.run(  # noqa: S603 - fixed, test-controlled args
        ["/bin/sh", str(ENTRYPOINT)],
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
    )


def test_entrypoint_exists_and_is_executable():
    assert ENTRYPOINT.is_file(), "proxy entrypoint script missing"
    mode = ENTRYPOINT.stat().st_mode
    # Source tree ships it readable/executable; the image chmods 0555.
    assert mode & stat.S_IXUSR, "entrypoint should be executable for the owner"


def test_entrypoint_is_valid_posix_shell():
    # `sh -n` does a syntax-only parse — catches typos without executing.
    result = subprocess.run(  # noqa: S603 - fixed, test-controlled args
        ["/bin/sh", "-n", str(ENTRYPOINT)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, f"entrypoint has shell syntax errors: {result.stderr}"


@pytest.mark.parametrize("value", ["1", "2", "8"])
def test_workers_derived_from_env(tmp_path, value):
    result = _run_entrypoint(tmp_path, value)
    assert result.returncode == 0, result.stderr
    assert f"--workers {value}" in result.stdout, result.stdout


def test_default_workers_is_four_when_unset(tmp_path):
    # Must match the rate limiter divisor default and settings.workers so an
    # unset BULWARK_WORKERS keeps real workers == limiter divisor.
    result = _run_entrypoint(tmp_path, None)
    assert result.returncode == 0, result.stderr
    assert "--workers 4" in result.stdout, result.stdout


@pytest.mark.parametrize("bad", ["abc", "1.5", "-3", "0", "4x"])
def test_invalid_workers_fails_closed(tmp_path, bad):
    result = _run_entrypoint(tmp_path, bad)
    assert result.returncode == 1, (
        f"BULWARK_WORKERS={bad!r} should fail closed, got rc={result.returncode}"
    )
    # Must not have reached the exec (no uvicorn invocation).
    assert "PYTHON_ARGS" not in result.stdout, result.stdout


def test_empty_workers_defaults_to_four(tmp_path):
    # An explicitly empty BULWARK_WORKERS is treated as unset by `${VAR:-4}`,
    # falling back to the safe default aligned with the limiter divisor.
    result = _run_entrypoint(tmp_path, "")
    assert result.returncode == 0, result.stderr
    assert "--workers 4" in result.stdout, result.stdout


def test_entrypoint_targets_uvicorn_app(tmp_path):
    result = _run_entrypoint(tmp_path, "1")
    assert "-m uvicorn src.main:app" in result.stdout, result.stdout
    # Preserve the hardened uvicorn flags from the old CMD.
    for flag in ("--host 0.0.0.0", "--port 8080", "--no-server-header"):
        assert flag in result.stdout, f"missing hardened flag {flag}: {result.stdout}"


def test_dockerfile_uses_script_entrypoint_and_no_hardcoded_workers():
    text = DOCKERFILE.read_text()
    assert 'ENTRYPOINT ["/app/docker/entrypoint-proxy.sh"]' in text, (
        "Dockerfile should invoke the parametrized entrypoint script"
    )
    # The old hardcoded worker CMD must be gone.
    assert '"--workers", "4"' not in text, (
        "Dockerfile still hardcodes --workers independently of BULWARK_WORKERS"
    )


def test_worker_defaults_are_aligned():
    """settings.workers, the rate limiter divisor default, and the entrypoint
    default must all be 4 so behavior is consistent when BULWARK_WORKERS unset."""
    from src.config import Settings

    assert Settings.model_fields["workers"].default == 4

    rate_limit_src = (REPO_ROOT / "src" / "middleware" / "rate_limit.py").read_text()
    assert rate_limit_src.count('os.environ.get("BULWARK_WORKERS", "4")') >= 1, (
        "rate limiter divisor default drifted from 4"
    )

    entry_src = ENTRYPOINT.read_text()
    assert 'BULWARK_WORKERS:-4' in entry_src, "entrypoint default drifted from 4"
