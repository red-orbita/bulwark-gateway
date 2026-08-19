"""
GAP-A regression tests — proxy entrypoint worker parametrization.

The Dockerfile previously hardcoded ``CMD ["--workers", "4"]`` independently of
``BULWARK_WORKERS``. Because the in-memory fallback rate limiter divides the
per-worker token bucket by ``BULWARK_WORKERS`` (src/middleware/rate_limit.py),
a mismatch between the *real* uvicorn worker count and ``BULWARK_WORKERS`` let
each worker over-allow traffic. These tests pin the entrypoint contract:

  * the real ``--workers`` value is derived from ``BULWARK_WORKERS``
  * the default (unset/empty) worker count stays aligned with the limiter
    divisor default and ``settings.workers`` (all 4)
  * garbage / non-positive input fails closed instead of silently defaulting
  * the Dockerfile invokes the launcher via ``exec`` (APT-13 signal handling)

Since the distroless migration the entrypoint is a **Python** launcher
(``docker/proxy_launcher.py``) rather than a POSIX shell script — distroless
runtime images ship no ``/bin/sh``. The security-critical worker derivation now
lives in ``_resolve_workers()``, which we exercise directly.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = REPO_ROOT / "docker" / "proxy_launcher.py"
DOCKERFILE = REPO_ROOT / "Dockerfile"


def _load_launcher():
    """Import ``docker/proxy_launcher.py`` as a standalone module."""
    spec = importlib.util.spec_from_file_location("proxy_launcher", LAUNCHER)
    assert spec and spec.loader, "cannot load proxy_launcher.py"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _resolve(monkeypatch, workers_env: str | None) -> str:
    """Set/clear BULWARK_WORKERS and return the launcher's resolved worker count."""
    if workers_env is None:
        monkeypatch.delenv("BULWARK_WORKERS", raising=False)
    else:
        monkeypatch.setenv("BULWARK_WORKERS", workers_env)
    return _load_launcher()._resolve_workers()


def test_launcher_exists():
    assert LAUNCHER.is_file(), "proxy launcher missing"


@pytest.mark.parametrize("value", ["1", "2", "8"])
def test_workers_derived_from_env(monkeypatch, value):
    assert _resolve(monkeypatch, value) == value


def test_default_workers_is_four_when_unset(monkeypatch):
    # Must match the rate limiter divisor default and settings.workers so an
    # unset BULWARK_WORKERS keeps real workers == limiter divisor.
    assert _resolve(monkeypatch, None) == "4"


def test_empty_workers_defaults_to_four(monkeypatch):
    # An explicitly empty BULWARK_WORKERS is treated as unset (historical
    # ``${VAR:-4}`` semantics), falling back to the safe default of 4.
    assert _resolve(monkeypatch, "") == "4"


@pytest.mark.parametrize("bad", ["abc", "1.5", "-3", "0", "4x"])
def test_invalid_workers_fails_closed(monkeypatch, bad):
    # A non-empty, non-positive-integer value must abort startup (SystemExit 1),
    # never silently default.
    with pytest.raises(SystemExit) as exc:
        _resolve(monkeypatch, bad)
    assert exc.value.code == 1


def test_workers_normalises_leading_zeros(monkeypatch):
    # "007" -> "7": uvicorn must receive a canonical integer string.
    assert _resolve(monkeypatch, "007") == "7"


def test_launcher_targets_uvicorn_app():
    text = LAUNCHER.read_text()
    assert '"src.main:app"' in text, text
    # Preserve the hardened uvicorn flags from the old CMD.
    for flag in ("0.0.0.0", "8080", "--no-server-header"):
        assert flag in text, f"missing hardened flag {flag}"
    # PID-1 signal handling: launcher must os.execv into uvicorn (not subprocess).
    assert "os.execv" in text, "launcher must exec into uvicorn for SIGTERM handling"


def test_dockerfile_uses_launcher_entrypoint_and_no_hardcoded_workers():
    text = DOCKERFILE.read_text()
    assert 'ENTRYPOINT ["python3", "/app/docker/proxy_launcher.py"]' in text, (
        "Dockerfile should invoke the distroless Python launcher"
    )
    # The old hardcoded worker CMD must be gone.
    assert '"--workers", "4"' not in text, (
        "Dockerfile still hardcodes --workers independently of BULWARK_WORKERS"
    )


def test_worker_defaults_are_aligned():
    """settings.workers, the rate limiter divisor default, and the launcher
    default must all be 4 so behavior is consistent when BULWARK_WORKERS unset."""
    from src.config import Settings

    assert Settings.model_fields["workers"].default == 4

    rate_limit_src = (REPO_ROOT / "src" / "middleware" / "rate_limit.py").read_text()
    assert rate_limit_src.count('os.environ.get("BULWARK_WORKERS", "4")') >= 1, (
        "rate limiter divisor default drifted from 4"
    )

    launcher_src = LAUNCHER.read_text()
    assert '_DEFAULT_WORKERS = "4"' in launcher_src, "launcher default drifted from 4"
