#!/usr/bin/env python3
"""Bulwark Gateway — Proxy launcher (distroless-compatible).

This is the Python replacement for the former shell entrypoint
(``docker/entrypoint-proxy.sh``). Distroless runtime images ship **no shell**,
so the worker-count derivation that used to live in ``/bin/sh`` is performed
here and we ``os.execv`` into uvicorn, *replacing* this process. Because uvicorn
takes over PID 1 it receives ``SIGTERM`` directly for graceful shutdown — this
preserves the APT-13 guarantee the shell script had via ``exec`` (no ``/bin/sh``
swallowing signals, no zombie workers).

Worker count (GAP-A):
    ``--workers`` is derived from ``BULWARK_WORKERS`` so the *actual* number of
    uvicorn worker processes matches the value the rate limiter uses to divide
    its per-worker token buckets (src/middleware/rate_limit.py) and the value
    reported by config (src/config.py). A hardcoded worker count would let each
    real worker use the full per-worker rate when the in-memory fallback limiter
    is active (Redis down), over-allowing traffic by up to N-fold.

Fail-closed:
    A missing ``BULWARK_WORKERS`` defaults to 4 (matches the historical default
    and the limiter/config fallbacks). Any non-integer or < 1 value aborts
    startup rather than silently defaulting.
"""

from __future__ import annotations

import os
import sys

_DEFAULT_WORKERS = "4"


def _resolve_workers() -> str:
    """Validate and return the uvicorn worker count as a string.

    An unset *or empty* ``BULWARK_WORKERS`` falls back to the default (4),
    preserving the historical POSIX ``${BULWARK_WORKERS:-4}`` semantics of the
    former shell entrypoint (an empty value is treated as "unset", not as an
    error, so a blank env var in a ConfigMap can never CrashLoop the pod).
    Any *non-empty* non-positive-integer input aborts startup (fail-closed).
    """
    raw = os.environ.get("BULWARK_WORKERS", "").strip() or _DEFAULT_WORKERS
    if not raw.isdigit() or int(raw) < 1:
        sys.stderr.write(
            f"FATAL: BULWARK_WORKERS must be a positive integer, got '{raw}'\n"
        )
        raise SystemExit(1)
    # Normalise (drops leading zeros, e.g. "007" -> "7").
    return str(int(raw))


def main() -> None:
    workers = _resolve_workers()
    argv = [
        sys.executable,
        "-m",
        "uvicorn",
        "src.main:app",
        "--host",
        "0.0.0.0",  # nosec B104 — container binds all interfaces; network exposure is controlled by the orchestrator / NetworkPolicies, not the app.
        "--port",
        "8080",
        "--access-log",
        "--log-level",
        "warning",
        "--no-server-header",
        "--workers",
        workers,
    ]
    # Replace this process so uvicorn becomes PID 1 (direct SIGTERM handling).
    os.execv(sys.executable, argv)


if __name__ == "__main__":
    main()
