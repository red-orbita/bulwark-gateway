"""Dialog session state store (Redis-backed, in-memory fallback).

The dialog engine is a per-session state machine: turn *N*'s routing decision
depends on the ``current_node`` that turn *N-1* left the session in. Holding that
state in a bare process-local ``dict`` (as the engine originally did) has two
defects the moment the proxy runs more than one replica (the shipped HPA runs 2-10):

* **Cross-replica incorrectness** — consecutive turns of one conversation can land
  on different pods, each seeing ``current_node = None`` and mis-routing the flow.
* **Unbounded growth** — every new ``session_id`` leaked an entry that lived
  forever (no TTL, no eviction).

This store fixes both by mirroring the proven ``correlation/risk_state.py``
pattern: Redis is the source of truth (shared across replicas, TTL'd), with a
bounded in-memory map as a graceful fallback when Redis is absent or unhealthy.
It never raises on the hot path — a backend error degrades to per-worker state,
never a 500.

State persisted per session is intentionally minimal: the state-machine position
(``current_node``) and a ``turn_count``. Session keys are derived from the
authenticated ``tenant_id`` / ``agent_id`` plus the caller's ``session_id`` and
hashed before they touch Redis, so (a) two tenants cannot collide on the same
``session_id`` and (b) a raw ``session_id`` (potentially PII) never becomes a
Redis key.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any, Optional

import structlog

from src.redis_bootstrap import connect_redis

logger = structlog.get_logger()

# Redis key namespace for dialog session state.
_KEY_PREFIX = "bulwark:dialog"

# Default idle TTL for a session record (seconds). A conversation that goes quiet
# for this long is forgotten — bounding Redis memory the way the in-memory map is
# bounded below. Overridable via ``initialize(ttl_seconds=...)``.
_DEFAULT_TTL_SECONDS = 3600

# Bounded in-memory fallback capacity (FIFO-ish eviction), mirroring
# ``risk_state._MAX_LOCAL_ENTRIES``. This is the eviction the original engine dict
# lacked entirely.
_MAX_LOCAL_ENTRIES = 50_000

# Circuit breaker: the dialog store sits inline in the request path when the
# engine is wired in. With ``socket_timeout=1s`` and no breaker a slow/down Redis
# would add up to 1s to every turn. After this many consecutive errors the breaker
# opens and calls short-circuit to the in-memory fallback until a cooldown elapses,
# then one half-open probe re-tests. (Identical semantics to risk_state's F2.)
_CB_FAIL_THRESHOLD = 5
_CB_COOLDOWN_SECONDS = 5.0


@dataclass
class DialogSessionState:
    """The load-bearing per-session state: state-machine position + turn count.

    ``current_node`` is the position in the dialog graph (``None`` before any
    trigger matched). ``turn_count`` is a monotonic counter of processed turns.
    """

    current_node: Optional[str] = None
    turn_count: int = 0


@dataclass
class _LocalEntry:
    """In-memory fallback record: state + when it was last written."""

    state: DialogSessionState
    updated_at: float


class DialogSessionStore:
    """Redis-backed dialog session state with a bounded in-memory fallback.

    Public API is deliberately tiny — ``load`` / ``save`` / ``delete`` — because
    the engine performs a read-modify-write per turn: load at the start of
    ``process``, mutate locally, persist at the end. Dialog turns are sequential
    per session (a user awaits each response before sending the next), so a
    plain load-then-save is race-free in practice without needing a Lua CAS.
    """

    def __init__(self, ttl_seconds: int = _DEFAULT_TTL_SECONDS) -> None:
        self._ttl = max(1, int(ttl_seconds))
        self._redis: Optional[Any] = None
        self._local: dict[str, _LocalEntry] = {}
        self._initialized = False
        # Circuit breaker state. ``_cb_opened_at == 0.0`` ⇒ closed.
        self._cb_failures = 0
        self._cb_opened_at = 0.0

    # --- lifecycle ---------------------------------------------------------

    def initialize(
        self,
        redis_url: Optional[str] = None,
        redis_tls_insecure: bool = False,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """Connect to Redis (once). No-op-safe without a URL (in-memory mode)."""
        if ttl_seconds is not None:
            self._ttl = max(1, int(ttl_seconds))
        if redis_url:
            try:
                self._redis = connect_redis(
                    redis_url, redis_tls_insecure=redis_tls_insecure
                )
            except Exception as e:  # noqa: BLE001 - degrade to in-memory
                logger.warning("dialog_session_redis_unavailable", error=str(e))
                self._redis = None
        self._initialized = True

    def _ensure_initialized(self) -> None:
        """Lazily initialize from global settings on first use.

        The dialog engine is not always wired at startup (so ``main.py`` does not
        call ``initialize`` for it). Lazy init means that whenever the engine IS
        activated, Redis backing engages automatically from the platform's
        ``settings.redis_url`` — no extra wiring, correct across replicas by
        default. Falls back to in-memory if settings are unavailable.
        """
        if self._initialized:
            return
        try:
            from src.config import settings

            self.initialize(
                redis_url=settings.redis_url,
                redis_tls_insecure=settings.redis_tls_insecure,
            )
        except Exception as e:  # noqa: BLE001 - never block on config import
            logger.warning("dialog_session_lazy_init_failed", error=str(e))
            self._initialized = True

    @property
    def redis(self):
        """The shared Redis client (or ``None`` in in-memory fallback mode)."""
        return self._redis

    # --- key derivation ----------------------------------------------------

    @staticmethod
    def make_session_key(tenant_id: str, agent_id: str, session_id: str) -> str:
        """Compose the namespaced logical key for a session.

        Namespacing by authenticated tenant/agent prevents one tenant's
        ``session_id`` from colliding with another's (cross-tenant isolation).
        """
        return f"{tenant_id or ''}:{agent_id or ''}:{session_id or ''}"

    @staticmethod
    def _redis_key(session_key: str) -> str:
        digest = hashlib.sha256(session_key.encode()).hexdigest()[:16]
        return f"{_KEY_PREFIX}:{digest}"

    # --- circuit breaker ---------------------------------------------------

    def _cb_should_skip(self) -> bool:
        if self._cb_opened_at == 0.0:
            return False
        if time.time() - self._cb_opened_at >= _CB_COOLDOWN_SECONDS:
            return False  # half-open: allow one probe through
        return True

    def _cb_success(self) -> None:
        if self._cb_failures or self._cb_opened_at:
            logger.info("dialog_session_circuit_closed")
        self._cb_failures = 0
        self._cb_opened_at = 0.0

    def _cb_failure(self) -> None:
        self._cb_failures += 1
        if self._cb_failures >= _CB_FAIL_THRESHOLD and self._cb_opened_at == 0.0:
            self._cb_opened_at = time.time()
            logger.warning(
                "dialog_session_circuit_opened",
                consecutive_failures=self._cb_failures,
                cooldown_seconds=_CB_COOLDOWN_SECONDS,
            )
        elif self._cb_opened_at != 0.0:
            self._cb_opened_at = time.time()

    @property
    def circuit_open(self) -> bool:
        return self._cb_opened_at != 0.0 and self._cb_should_skip()

    # --- public API --------------------------------------------------------

    def load(self, session_key: str) -> DialogSessionState:
        """Return the stored state for a session (fresh state if absent).

        Never raises — a backend error yields the in-memory fallback value (or a
        fresh state), so a turn is never dropped on a Redis hiccup.
        """
        self._ensure_initialized()
        if self._redis is not None and not self._cb_should_skip():
            try:
                out = self._load_redis(session_key)
                self._cb_success()
                return out
            except Exception as e:  # noqa: BLE001 - degrade, never break hot path
                logger.warning("dialog_session_load_redis_error", error=str(e))
                self._cb_failure()
        return self._load_local(session_key)

    def save(self, session_key: str, state: DialogSessionState) -> None:
        """Persist a session's state with a refreshed idle TTL. Never raises."""
        self._ensure_initialized()
        if self._redis is not None and not self._cb_should_skip():
            try:
                self._save_redis(session_key, state)
                self._cb_success()
                return
            except Exception as e:  # noqa: BLE001
                logger.warning("dialog_session_save_redis_error", error=str(e))
                self._cb_failure()
        self._save_local(session_key, state)

    def delete(self, session_key: str) -> None:
        """Forget a session (reset). Never raises."""
        self._ensure_initialized()
        if self._redis is not None and not self._cb_should_skip():
            try:
                self._redis.delete(self._redis_key(session_key))
                self._cb_success()
                return
            except Exception as e:  # noqa: BLE001
                logger.warning("dialog_session_delete_redis_error", error=str(e))
                self._cb_failure()
        self._local.pop(session_key, None)

    # --- redis backend -----------------------------------------------------

    def _load_redis(self, session_key: str) -> DialogSessionState:
        cur = self._redis.hgetall(self._redis_key(session_key)) or {}  # type: ignore[union-attr]
        if not cur:
            return DialogSessionState()
        node = cur.get("node") or None
        try:
            turns = int(cur.get("turns", 0) or 0)
        except (TypeError, ValueError):
            turns = 0
        return DialogSessionState(current_node=node, turn_count=turns)

    def _save_redis(self, session_key: str, state: DialogSessionState) -> None:
        key = self._redis_key(session_key)
        # Store node as empty string when None (Redis hashes have no null value);
        # ``_load_redis`` maps "" back to None.
        self._redis.hset(  # type: ignore[union-attr]
            key,
            mapping={"node": state.current_node or "", "turns": int(state.turn_count)},
        )
        self._redis.expire(key, self._ttl)  # type: ignore[union-attr]

    # --- in-memory fallback ------------------------------------------------

    def _load_local(self, session_key: str) -> DialogSessionState:
        entry = self._local.get(session_key)
        if entry is None:
            return DialogSessionState()
        # Honour the idle TTL in the fallback too so behaviour matches Redis.
        if time.time() - entry.updated_at > self._ttl:
            self._local.pop(session_key, None)
            return DialogSessionState()
        # Return a copy so the caller's mutations don't retroactively alter the
        # stored entry before an explicit save.
        return DialogSessionState(
            current_node=entry.state.current_node,
            turn_count=entry.state.turn_count,
        )

    def _save_local(self, session_key: str, state: DialogSessionState) -> None:
        if len(self._local) >= _MAX_LOCAL_ENTRIES and session_key not in self._local:
            self._local.pop(next(iter(self._local)), None)
        self._local[session_key] = _LocalEntry(
            state=DialogSessionState(
                current_node=state.current_node,
                turn_count=state.turn_count,
            ),
            updated_at=time.time(),
        )


# Module-level singleton -----------------------------------------------------

_store: Optional[DialogSessionStore] = None


def get_dialog_session_store() -> DialogSessionStore:
    """Return the process-wide dialog session store singleton."""
    global _store
    if _store is None:
        _store = DialogSessionStore()
    return _store
