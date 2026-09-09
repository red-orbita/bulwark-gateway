"""Shared Redis connection bootstrap for the proxy's optional Redis-backed stores.

Several independent hot-path components keep their *own* Redis client so that a
failure in one degrades that component in isolation (risk state, the session
decomposition tracker, the dialog session store, the correlation runtime-config
overlay, ...). Historically each one hand-rolled the *identical* connection block:

    import redis
    kwargs = {"decode_responses": True, "socket_timeout": 1}
    if redis_url.startswith("rediss://") and redis_tls_insecure:
        import ssl
        kwargs["ssl_cert_reqs"] = ssl.CERT_NONE
    client = redis.from_url(redis_url, **kwargs)
    client.ping()

Four copies drift independently — a TLS or timeout fix in one silently misses the
others. :func:`connect_redis` is the single source of truth for *how* a client is
constructed (decode-responses, socket timeout, and the ``rediss://`` +
``tls_insecure`` → ``ssl.CERT_NONE`` handling).

Deliberately **not** in scope here:

* **Ownership / lifecycle.** Each caller still owns its own client, its own
  in-memory fallback, and its own circuit breaker. This helper only *builds* a
  connection; it does not share or cache one.
* **Degradation logging.** Callers keep their own ``try/except`` and their own
  distinct ``*_redis_unavailable`` warning event, so observability still says
  *which* subsystem lost Redis. This helper raises on failure and lets the caller
  decide how to degrade (that is the whole point of per-component isolation).

Zero new dependencies: ``redis`` and ``ssl`` are imported lazily exactly as the
inlined blocks did, so importing this module never pulls in ``redis`` and the
in-memory-only deployments stay dependency-free.
"""

from __future__ import annotations

import re
from typing import Any

# Applied to every client so a slow/unreachable Redis cannot stall a hot-path
# call indefinitely. Callers that need a tighter budget pass ``socket_timeout``.
_DEFAULT_SOCKET_TIMEOUT = 1.0


# ─── Redis key-segment hygiene (S-19) ────────────────────────────────────────
# A tenant_id / agent_id is interpolated verbatim into colon-delimited Redis key
# NAMES (``bulwark:cost:{tenant_id}:tokens``, ``bulwark:recent_blocks:{tenant_id}``,
# ``bulwark:vkeys:{tenant_id}:active`` …). The auth middleware already constrains
# request-path tenant/agent ids to ``[A-Za-z0-9_-]{1,64}`` (``_SAFE_ID`` in
# ``src/middleware/auth.py``), so on the proxy hot path this helper is a no-op. It
# exists to make every key-building callsite *self-defending* (defense in depth):
# a value that reaches a store from a NON-request path, or a future regression that
# relaxes the auth edge, can never smuggle a ``:`` to cross the delimiter into
# another tenant's namespace (e.g. a tenant literally named ``victim:tokens``
# colliding with ``bulwark:cost:victim:tokens``). Any character outside the safe
# class — notably ``:`` — is mapped to ``_``; a valid id is returned unchanged so
# existing keys/data keep their exact names.
_KEY_SEGMENT_UNSAFE = re.compile(r"[^A-Za-z0-9_-]")
_KEY_SEGMENT_MAX_LEN = 64


def safe_key_segment(value: Any, *, max_len: int = _KEY_SEGMENT_MAX_LEN) -> str:
    """Sanitise a single value for safe interpolation into a Redis key name.

    Maps any character outside ``[A-Za-z0-9_-]`` (notably the ``:`` key delimiter)
    to ``_`` and truncates to ``max_len``. Never raises and never rejects — the
    key-building callsites are largely fire-and-forget (cost/quota metrics), so a
    hostile value is degraded to a harmless one rather than dropping the write. An
    empty / ``None`` value becomes ``"unknown"`` so a key can never collapse a
    delimiter (``bulwark:cost::tokens``).
    """
    text = ("" if value is None else str(value))[:max_len]
    sanitised = _KEY_SEGMENT_UNSAFE.sub("_", text)
    return sanitised or "unknown"


def connect_redis(
    redis_url: str,
    *,
    redis_tls_insecure: bool = False,
    socket_timeout: float = _DEFAULT_SOCKET_TIMEOUT,
    ping: bool = True,
) -> Any:
    """Build a Redis client with the platform's standard options.

    Args:
        redis_url: ``redis://`` or ``rediss://`` connection URL. Must be truthy;
            callers gate on ``if redis_url:`` before calling.
        redis_tls_insecure: When the URL is ``rediss://`` and this is true, skip
            TLS certificate verification (``ssl.CERT_NONE``). Ignored for plain
            ``redis://``. Mirrors ``BULWARK_REDIS_TLS_INSECURE``.
        socket_timeout: Per-operation socket timeout in seconds.
        ping: When true (default), issue a ``PING`` so connection failures surface
            here rather than on the first hot-path use. Set false to defer the
            round-trip.

    Returns:
        A configured ``redis.Redis`` client (``decode_responses=True``).

    Raises:
        Any ``redis`` connection/import error. Callers are expected to catch this
        and degrade to their in-memory fallback with a component-specific log.
    """
    import redis

    kwargs: dict[str, Any] = {
        "decode_responses": True,
        "socket_timeout": socket_timeout,
    }
    if redis_url.startswith("rediss://") and redis_tls_insecure:
        import ssl

        kwargs["ssl_cert_reqs"] = ssl.CERT_NONE

    client = redis.from_url(redis_url, **kwargs)
    if ping:
        client.ping()
    return client
