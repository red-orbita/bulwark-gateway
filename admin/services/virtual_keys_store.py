"""Admin-side access to the shared VirtualKeyManager.

Reuses the proxy's virtual key subsystem (``src.services.virtual_keys``) so
that key encryption (Fernet) and the Redis schema (``bulwark:vkeys:*``) have a
single source of truth. The manager keeps per-process in-memory state, so this
wrapper hydrates a tenant's keys from Redis before every list/rotate/revoke
operation — the admin process never creates the keys the proxy replicas hold in
memory, and vice versa.

The manager requires ``BULWARK_KEY_ENCRYPTION_KEY`` and raises ``SystemExit`` at
init if it is missing (a deliberate fail-closed choice for the proxy). Here we
catch that so the admin process keeps running and the UI/API can surface a clear
"unavailable" state instead of crashing.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

_manager: Any = None
_init_error: Optional[str] = None


class VirtualKeysUnavailable(RuntimeError):
    """Raised when the virtual key subsystem cannot be initialized."""


def _get_manager() -> Any:
    """Lazily construct the shared VirtualKeyManager.

    Routes the manager through the admin Redis pool so it reads/writes the same
    Redis instance the rest of the admin service uses. Raises
    ``VirtualKeysUnavailable`` when the encryption key is not configured.
    """
    global _manager, _init_error
    if _manager is not None:
        return _manager
    if _init_error is not None:
        raise VirtualKeysUnavailable(_init_error)

    try:
        from src.services.virtual_keys import VirtualKeyManager

        mgr = VirtualKeyManager()
    except SystemExit as e:
        _init_error = str(e) or "BULWARK_KEY_ENCRYPTION_KEY is not configured"
        raise VirtualKeysUnavailable(_init_error) from None
    except BaseException as e:  # noqa: BLE001 - init must never crash admin
        _init_error = f"virtual key manager init failed: {e}"
        raise VirtualKeysUnavailable(_init_error) from None

    # Share the admin Redis pool for cross-process consistency.
    try:
        from .redis_sync import get_redis_client

        client = get_redis_client()
        if client is not None:
            mgr._redis = client
    except Exception:  # noqa: S110 - fall back to manager's own connection
        pass

    _manager = mgr
    return _manager


def is_available() -> tuple[bool, Optional[str]]:
    """Return (available, reason). reason is set only when unavailable."""
    try:
        _get_manager()
        return True, None
    except VirtualKeysUnavailable as e:
        return False, str(e)


def redis_connected() -> bool:
    """Whether the manager has a live Redis connection (persistence enabled)."""
    try:
        mgr = _get_manager()
    except VirtualKeysUnavailable:
        return False
    return getattr(mgr, "_redis", None) is not None


def _vk_public(vk: Any) -> dict[str, Any]:
    """Serialize a VirtualKey to a non-secret dict."""
    return {
        "key_id": vk.key_id,
        "provider": vk.provider,
        "is_active": vk.is_active,
        "created_at": vk.created_at,
        "expires_at": vk.expires_at,
        "expired": vk.expired,
        "usage_count": vk.usage_count,
        "last_used_at": vk.last_used_at,
        "description": vk.description,
    }


def list_keys(tenant_id: str) -> list[dict[str, Any]]:
    """List a tenant's virtual keys (metadata only, never the secret)."""
    mgr = _get_manager()
    mgr.hydrate_tenant(tenant_id)
    return mgr.list_keys(tenant_id)


def create_key(
    tenant_id: str,
    provider: str,
    backend_api_key: str,
    description: str = "",
    expires_in_days: Optional[int] = None,
) -> dict[str, Any]:
    """Create a new virtual key. The plaintext backend key is never persisted."""
    mgr = _get_manager()
    vk = mgr.create_key(
        tenant_id=tenant_id,
        provider=provider,
        backend_api_key=backend_api_key,
        description=description,
        expires_in_days=expires_in_days,
    )
    return _vk_public(vk)


def rotate_key(
    tenant_id: str, provider: str, new_backend_key: str
) -> Optional[dict[str, Any]]:
    """Rotate the active key for a tenant/provider; deprecates the old one."""
    mgr = _get_manager()
    mgr.hydrate_tenant(tenant_id)
    vk = mgr.rotate_key(tenant_id, provider, new_backend_key)
    return _vk_public(vk) if vk else None


def revoke_key(tenant_id: str, key_id: str) -> bool:
    """Revoke a specific virtual key by id."""
    mgr = _get_manager()
    mgr.hydrate_tenant(tenant_id)
    return mgr.revoke_key(tenant_id, key_id)


def audit_trail(limit: int = 100) -> list[dict[str, Any]]:
    """Return the most recent virtual key operations (global, newest first)."""
    try:
        mgr = _get_manager()
    except VirtualKeysUnavailable:
        return []
    redis = getattr(mgr, "_redis", None)
    if redis is None:
        return []
    try:
        raw = redis.lrange("bulwark:vkeys:audit", 0, max(0, limit - 1)) or []
    except Exception:  # noqa: BLE001
        return []
    entries: list[dict[str, Any]] = []
    for item in raw:
        if isinstance(item, bytes):
            item = item.decode()
        try:
            entries.append(json.loads(item))
        except (ValueError, TypeError):
            continue
    return entries
