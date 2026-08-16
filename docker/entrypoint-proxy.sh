#!/bin/sh
# ============================================================
# Bulwark Gateway — Proxy entrypoint
# ============================================================
# Parametrizes the uvicorn worker count from BULWARK_WORKERS so the *actual*
# number of worker processes matches the value the rate limiter uses to divide
# per-worker token buckets (src/middleware/rate_limit.py:102,132) and the value
# reported by config (src/config.py:34).
#
# GAP-A: The Dockerfile previously hardcoded `CMD ["--workers", "4"]`, which was
# independent of BULWARK_WORKERS (Compose/Helm set it to 1). When Redis is
# unavailable and the in-memory fallback limiter is active, this mismatch lets
# each of the N real workers use the full per-worker rate (divisor assumed 1),
# over-allowing traffic by up to N-fold. Deriving --workers from BULWARK_WORKERS
# keeps the real worker count and the limiter's divisor in lockstep.
#
# APT-13: use `exec` so uvicorn replaces this shell as PID 1 and receives
# SIGTERM directly for graceful shutdown (no zombie processes, no /bin/sh
# swallowing signals).
# ============================================================
set -eu

# Default 4 matches the historical Dockerfile default AND the fallback defaults
# in src/middleware/rate_limit.py / src/config.py, so an unset BULWARK_WORKERS
# keeps the real worker count aligned with the limiter divisor.
WORKERS="${BULWARK_WORKERS:-4}"

# Fail-closed on non-integer / empty input rather than silently defaulting.
case "$WORKERS" in
    '' | *[!0-9]*)
        echo "FATAL: BULWARK_WORKERS must be a positive integer, got '${WORKERS}'" >&2
        exit 1
        ;;
esac
if [ "$WORKERS" -lt 1 ]; then
    echo "FATAL: BULWARK_WORKERS must be >= 1, got '${WORKERS}'" >&2
    exit 1
fi

exec python -m uvicorn src.main:app \
    --host 0.0.0.0 \
    --port 8080 \
    --access-log \
    --log-level warning \
    --no-server-header \
    --workers "$WORKERS"
