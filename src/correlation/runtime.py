"""Runtime-tunable configuration for the correlation feedback loop.

The correlation engine's *enforcement* behaviour (WARN/BLOCK thresholds, event→
risk bump weights, decay) must be adjustable **without a restart** so an operator
can tighten or loosen the adaptive loop during an incident. This mirrors
:mod:`src.guardrails.session_tracker`'s runtime-override pattern:

.. note::
   ``window_seconds`` is a **latent/reserved** tunable (see :data:`_LATENT_FIELDS`).
   The input↔output correlator is strictly *same-request*: a request's input signals
   and that same request's output signals are inherently paired, so no time window is
   needed to decide the pairing, and the proxy deliberately does **not** feed the
   correlator an ``input_detected_at`` timestamp. Wiring one naively would make the
   window measure the backend LLM round-trip latency (up to the backend timeout,
   default 120s) and any response slower than the window would silently *skip*
   correlation — a false-negative. The field is kept (parsed, bounded, accepted) so
   existing overrides don't break and so a future *cross-request / asynchronous*
   correlator can adopt it, but it currently has **no enforcement effect**.

* Defaults come live from :mod:`src.config` ``settings`` (so with no override the
  behaviour equals the static configuration and unit tests stay deterministic).
* An optional Redis HASH at ``bulwark:correlation:config`` overlays those defaults.
  It is re-read at most every :data:`_REFRESH_INTERVAL` seconds (throttled) so the
  hot path pays at most one cheap Redis round-trip every few seconds, never per
  request.
* The admin surface (``admin/routes/correlation.py``) writes that HASH.

The **master switch** ``correlation_enabled`` is intentionally *not* runtime
tunable here: enabling correlation requires the event-tap consumer to be started
at boot (see ``src/main.py``), so it stays a process-level ``settings`` flag.

This module never raises: a Redis failure degrades to the static defaults.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional

import structlog

logger = structlog.get_logger()

# Redis HASH holding the runtime override (written by the admin service).
RUNTIME_CONFIG_KEY = "bulwark:correlation:config"

# Minimum seconds between Redis re-reads of the override (throttle the hot path).
_REFRESH_INTERVAL = 5.0

# Defaults for fields that have no ``settings`` counterpart (the event→risk
# scoring weights). Kept here so the whole scoring model lives in one place.
_DEFAULT_EVENT_BUMP_WARN = 0.5       # risk added per WARN security event
_DEFAULT_EVENT_BUMP_BLOCK = 1.0      # risk added per BLOCK security event
_DEFAULT_SEVERITY_HIGH_MULT = 1.5    # multiplier for high-severity events
_DEFAULT_SEVERITY_CRITICAL_MULT = 2.0  # multiplier for critical-severity events

# Numeric tunables: field -> (min, max). Bounds mirror the admin validation and
# guard against nonsensical overrides (e.g. a zero/negative threshold that would
# block everything). ``blocking`` is a bool and handled separately.
_NUMERIC_FIELDS: dict[str, tuple[float, float]] = {
    "window_seconds": (1.0, 3600.0),
    "risk_block_threshold": (0.1, 10.0),
    "risk_warn_threshold": (0.1, 10.0),
    "risk_decay_seconds": (10.0, 604800.0),
    "event_bump_warn": (0.0, 10.0),
    "event_bump_block": (0.0, 10.0),
    "severity_high_mult": (0.1, 10.0),
    "severity_critical_mult": (0.1, 10.0),
    # Content-corroboration confidence required to escalate a confirmed
    # correlation from WARN to BLOCK (Phase 4b). Bounded to the [0, 1] scale of
    # src.correlation.confidence.correlation_confidence.
    "confidence_block_threshold": (0.0, 1.0),
}

# Latent/reserved tunables: accepted and bounded (so existing overrides keep
# working and the admin surface can flag them) but currently NOT enforced. See
# the module docstring — ``window_seconds`` is inert for same-request correlation
# and is reserved for a future cross-request/async correlator.
_LATENT_FIELDS: frozenset[str] = frozenset({"window_seconds"})

# Every tunable field name (numeric + the boolean), for the admin surface.
TUNABLE_FIELDS: tuple[str, ...] = ("blocking",) + tuple(_NUMERIC_FIELDS)


def numeric_field_bounds() -> dict[str, tuple[float, float]]:
    """Return the (min, max) bounds for each numeric tunable (for admin validation)."""
    return dict(_NUMERIC_FIELDS)


def latent_fields() -> frozenset[str]:
    """Return tunables that are accepted but not currently enforced.

    The admin surface uses this to render such fields read-only / reserved rather
    than as live enforcement knobs (honesty: an operator must not believe a knob
    changes behaviour when it does not). See the module docstring for why
    ``window_seconds`` is latent under same-request correlation.
    """
    return _LATENT_FIELDS


@dataclass(frozen=True)
class CorrelationConfig:
    """Effective, point-in-time correlation configuration snapshot."""

    blocking: bool
    window_seconds: float
    risk_block_threshold: float
    risk_warn_threshold: float
    risk_decay_seconds: float
    event_bump_warn: float
    event_bump_block: float
    severity_high_mult: float
    severity_critical_mult: float
    confidence_block_threshold: float


def _clampf(value: float, lo: float, hi: float) -> float:
    return lo if value < lo else hi if value > hi else value


def default_config() -> dict:
    """Return the static default config (settings + built-in weights), no override.

    Exposed for the admin surface so it can render "defaults vs effective" without
    reaching into private helpers. Reads ``settings`` live.
    """
    return CorrelationRuntimeConfig._defaults()


class CorrelationRuntimeConfig:
    """Merges static ``settings`` defaults with a throttled Redis override."""

    def __init__(self) -> None:
        self._redis = None
        self._lock = threading.Lock()
        self._override_num: dict[str, float] = {}
        self._override_blocking: Optional[bool] = None
        self._last_refresh = 0.0
        self._initialized = False

    # --- lifecycle ---------------------------------------------------------

    def initialize(
        self,
        redis_url: Optional[str] = None,
        redis_tls_insecure: bool = False,
    ) -> None:
        """Connect to Redis once at startup. No-op-safe without a URL."""
        if redis_url:
            try:
                import redis

                kwargs: dict = {"decode_responses": True, "socket_timeout": 1}
                if redis_url.startswith("rediss://") and redis_tls_insecure:
                    import ssl

                    kwargs["ssl_cert_reqs"] = ssl.CERT_NONE
                self._redis = redis.from_url(redis_url, **kwargs)
                self._redis.ping()
            except Exception as e:  # noqa: BLE001 - degrade to static defaults
                logger.warning("correlation_runtime_redis_unavailable", error=str(e))
                self._redis = None
        self._initialized = True

    # --- defaults + refresh ------------------------------------------------

    @staticmethod
    def _defaults() -> dict:
        # Read live from settings so monkeypatched/updated settings are honoured
        # and so no override == static configuration behaviour.
        from src.config import settings

        return {
            "blocking": bool(getattr(settings, "correlation_blocking", False)),
            "window_seconds": float(getattr(settings, "correlation_window_seconds", 30.0)),
            "risk_block_threshold": float(getattr(settings, "correlation_risk_block_threshold", 7.0)),
            "risk_warn_threshold": float(getattr(settings, "correlation_risk_warn_threshold", 4.0)),
            "risk_decay_seconds": float(getattr(settings, "correlation_risk_decay_seconds", 900.0)),
            "event_bump_warn": _DEFAULT_EVENT_BUMP_WARN,
            "event_bump_block": _DEFAULT_EVENT_BUMP_BLOCK,
            "severity_high_mult": _DEFAULT_SEVERITY_HIGH_MULT,
            "severity_critical_mult": _DEFAULT_SEVERITY_CRITICAL_MULT,
            "confidence_block_threshold": float(
                getattr(settings, "correlation_confidence_block_threshold", 0.5)
            ),
        }

    def _maybe_refresh(self) -> None:
        now = time.time()
        if now - self._last_refresh < _REFRESH_INTERVAL:
            return
        self._last_refresh = now
        if self._redis is None:
            return
        try:
            raw = self._redis.hgetall(RUNTIME_CONFIG_KEY) or {}
        except Exception as e:  # noqa: BLE001 - keep previous override on failure
            logger.warning("correlation_runtime_refresh_error", error=str(e))
            return

        num: dict[str, float] = {}
        for field_name, (lo, hi) in _NUMERIC_FIELDS.items():
            if field_name in raw:
                try:
                    num[field_name] = _clampf(float(raw[field_name]), lo, hi)
                except (TypeError, ValueError):
                    continue
        blocking: Optional[bool] = None
        if "blocking" in raw:
            blocking = str(raw["blocking"]).strip().lower() in ("1", "true", "yes", "on")

        with self._lock:
            self._override_num = num
            self._override_blocking = blocking

    # --- public API --------------------------------------------------------

    def get(self) -> CorrelationConfig:
        """Return the current effective configuration snapshot (never raises)."""
        try:
            self._maybe_refresh()
        except Exception as e:  # noqa: BLE001
            logger.warning("correlation_runtime_get_error", error=str(e))
        merged = self._defaults()
        with self._lock:
            for k, v in self._override_num.items():
                merged[k] = v
            if self._override_blocking is not None:
                merged["blocking"] = self._override_blocking
        return CorrelationConfig(**merged)

    def override_state(self) -> dict:
        """Return the raw override (for the admin surface). Empty == no override."""
        self._maybe_refresh()
        with self._lock:
            out: dict[str, float | bool] = dict(self._override_num)
            if self._override_blocking is not None:
                out["blocking"] = self._override_blocking
            return out


# Module-level singleton -----------------------------------------------------

_runtime: Optional[CorrelationRuntimeConfig] = None


def get_correlation_runtime() -> CorrelationRuntimeConfig:
    """Return the process-wide correlation runtime-config singleton."""
    global _runtime
    if _runtime is None:
        _runtime = CorrelationRuntimeConfig()
    return _runtime
