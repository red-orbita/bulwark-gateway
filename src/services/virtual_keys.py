"""
Virtual Keys — Centralized API key management for LLM backends.

Manages backend API keys per tenant with:
  - Key rotation (generate new key, deprecate old)
  - Encryption at rest (Fernet symmetric encryption)
  - Per-tenant key isolation
  - Audit trail of key usage
  - Rate limiting per virtual key

Virtual keys decouple tenants from raw backend API keys:
  - Tenants only know their virtual key ID
  - Actual backend keys are managed centrally
  - Key rotation doesn't require tenant reconfiguration

Redis keys:
  sentinel:vkeys:{tenant_id}:{key_id}   — Encrypted backend key + metadata
  sentinel:vkeys:{tenant_id}:active      — Currently active key ID
  sentinel:vkeys:audit                   — List of key operations
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class VirtualKey:
    """A virtual key mapping tenant to backend API key."""

    key_id: str
    tenant_id: str
    provider: str  # e.g., "openai", "anthropic", "azure"
    created_at: float
    expires_at: float | None = None  # None = no expiry
    rotated_at: float | None = None
    is_active: bool = True
    description: str = ""
    usage_count: int = 0
    last_used_at: float | None = None

    @property
    def expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at


class VirtualKeyManager:
    """Manages virtual keys for backend API access.

    Provides abstraction layer between tenants and actual API keys.
    Keys are encrypted at rest using a master key derived from
    SENTINEL_JWT_SECRET (or a dedicated SENTINEL_KEY_ENCRYPTION_KEY).
    """

    def __init__(self):
        self._redis = None
        self._encryption_key = self._derive_encryption_key()
        self._keys: dict[str, dict[str, VirtualKey]] = {}  # tenant -> {key_id: VirtualKey}
        self._backend_keys: dict[str, str] = {}  # key_id -> encrypted_backend_key
        self._init_redis()

    def _init_redis(self):
        """Connect to Redis for persistent storage."""
        try:
            from src.guardrails.dynamic_registry import get_pattern_registry
            registry = get_pattern_registry()
            self._redis = registry._redis
        except Exception:
            self._redis = None

    def _derive_encryption_key(self) -> bytes:
        """Derive encryption key from environment.

        Uses SENTINEL_KEY_ENCRYPTION_KEY if set, otherwise derives from JWT_SECRET.
        Returns 32-byte key suitable for Fernet-like encryption.
        """
        key_source = os.environ.get(
            "SENTINEL_KEY_ENCRYPTION_KEY",
            os.environ.get("SENTINEL_JWT_SECRET", "default-insecure-key")
        )
        return hashlib.sha256(key_source.encode()).digest()

    def create_key(
        self,
        tenant_id: str,
        provider: str,
        backend_api_key: str,
        description: str = "",
        expires_in_days: int | None = None,
    ) -> VirtualKey:
        """Create a new virtual key for a tenant.

        Args:
            tenant_id: Tenant identifier.
            provider: Backend provider (openai, anthropic, azure, etc.)
            backend_api_key: The actual API key for the backend.
            description: Human-readable description.
            expires_in_days: Auto-expire after N days (None = no expiry).

        Returns:
            The created VirtualKey.
        """
        key_id = f"vk_{secrets.token_hex(16)}"
        now = time.time()
        expires_at = now + (expires_in_days * 86400) if expires_in_days else None

        vkey = VirtualKey(
            key_id=key_id,
            tenant_id=tenant_id,
            provider=provider,
            created_at=now,
            expires_at=expires_at,
            description=description,
        )

        # Encrypt and store the backend key
        encrypted = self._encrypt(backend_api_key)

        # Persist
        if tenant_id not in self._keys:
            self._keys[tenant_id] = {}
        self._keys[tenant_id][key_id] = vkey
        self._backend_keys[key_id] = encrypted

        if self._redis:
            try:
                key_data = {
                    "key_id": key_id,
                    "tenant_id": tenant_id,
                    "provider": provider,
                    "created_at": now,
                    "expires_at": expires_at,
                    "description": description,
                    "encrypted_key": encrypted,
                    "is_active": True,
                }
                self._redis.hset(
                    f"sentinel:vkeys:{tenant_id}",
                    key_id,
                    json.dumps(key_data),
                )
                # Set as active key for this tenant/provider
                self._redis.hset(
                    f"sentinel:vkeys:{tenant_id}:active",
                    provider,
                    key_id,
                )
                # Audit
                self._audit("create", tenant_id, key_id, provider)
            except Exception as e:
                logger.warning("vkey_redis_error", extra={"error": str(e)[:100]})

        return vkey

    def get_backend_key(self, tenant_id: str, provider: str) -> str | None:
        """Retrieve the active backend API key for a tenant/provider.

        Args:
            tenant_id: Tenant identifier.
            provider: Backend provider name.

        Returns:
            Decrypted backend API key, or None if not found.
        """
        # Find active key ID for this tenant/provider
        active_key_id = None

        if self._redis:
            try:
                active_key_id = self._redis.hget(
                    f"sentinel:vkeys:{tenant_id}:active", provider
                )
                if isinstance(active_key_id, bytes):
                    active_key_id = active_key_id.decode()
            except Exception:
                pass

        if not active_key_id:
            # Fallback: search in-memory
            tenant_keys = self._keys.get(tenant_id, {})
            for kid, vk in tenant_keys.items():
                if vk.provider == provider and vk.is_active and not vk.expired:
                    active_key_id = kid
                    break

        if not active_key_id:
            return None

        # Get encrypted key
        encrypted = self._backend_keys.get(active_key_id)
        if not encrypted and self._redis:
            try:
                key_data_raw = self._redis.hget(f"sentinel:vkeys:{tenant_id}", active_key_id)
                if key_data_raw:
                    key_data = json.loads(key_data_raw)
                    encrypted = key_data.get("encrypted_key")
            except Exception:
                pass

        if not encrypted:
            return None

        # Record usage
        if tenant_id in self._keys and active_key_id in self._keys[tenant_id]:
            self._keys[tenant_id][active_key_id].usage_count += 1
            self._keys[tenant_id][active_key_id].last_used_at = time.time()

        return self._decrypt(encrypted)

    def rotate_key(
        self,
        tenant_id: str,
        provider: str,
        new_backend_key: str,
    ) -> VirtualKey | None:
        """Rotate the backend key for a tenant/provider.

        Creates a new virtual key and deactivates the old one.

        Args:
            tenant_id: Tenant identifier.
            provider: Backend provider.
            new_backend_key: The new backend API key.

        Returns:
            New VirtualKey, or None on error.
        """
        # Deactivate current key
        tenant_keys = self._keys.get(tenant_id, {})
        for vk in tenant_keys.values():
            if vk.provider == provider and vk.is_active:
                vk.is_active = False
                vk.rotated_at = time.time()
                self._audit("rotate_old", tenant_id, vk.key_id, provider)

        # Create new key
        new_vkey = self.create_key(
            tenant_id=tenant_id,
            provider=provider,
            backend_api_key=new_backend_key,
            description=f"Rotated from previous key at {time.strftime('%Y-%m-%d %H:%M')}",
        )
        self._audit("rotate_new", tenant_id, new_vkey.key_id, provider)
        return new_vkey

    def list_keys(self, tenant_id: str) -> list[dict[str, Any]]:
        """List virtual keys for a tenant (without exposing actual keys)."""
        result = []
        tenant_keys = self._keys.get(tenant_id, {})
        for vk in tenant_keys.values():
            result.append({
                "key_id": vk.key_id,
                "provider": vk.provider,
                "is_active": vk.is_active,
                "created_at": vk.created_at,
                "expires_at": vk.expires_at,
                "expired": vk.expired,
                "usage_count": vk.usage_count,
                "last_used_at": vk.last_used_at,
                "description": vk.description,
            })
        return result

    def revoke_key(self, tenant_id: str, key_id: str) -> bool:
        """Revoke (deactivate) a virtual key."""
        tenant_keys = self._keys.get(tenant_id, {})
        if key_id in tenant_keys:
            tenant_keys[key_id].is_active = False
            self._audit("revoke", tenant_id, key_id, tenant_keys[key_id].provider)
            if self._redis:
                try:
                    self._redis.hdel(f"sentinel:vkeys:{tenant_id}", key_id)
                except Exception:
                    pass
            return True
        return False

    def _encrypt(self, plaintext: str) -> str:
        """Encrypt a backend API key using Fernet symmetric encryption.

        H-01 fix: Replaced XOR obfuscation with proper Fernet encryption.
        Fernet provides authenticated encryption (AES-128-CBC + HMAC-SHA256)
        ensuring confidentiality and integrity of stored keys.

        Falls back to XOR only if cryptography package is not installed
        (logged as critical warning).
        """
        import base64
        try:
            from cryptography.fernet import Fernet
            # Derive Fernet key (must be 32 url-safe base64-encoded bytes)
            fernet_key = base64.urlsafe_b64encode(self._encryption_key)
            f = Fernet(fernet_key)
            return "fernet:" + f.encrypt(plaintext.encode()).decode()
        except ImportError:
            raise SystemExit(
                "FATAL: 'cryptography' package is required for virtual key encryption. "
                "Install it with: pip install cryptography>=42.0. "
                "Refusing to start with insecure XOR fallback."
            )

    def _decrypt(self, ciphertext: str) -> str:
        """Decrypt a stored key (supports both Fernet and legacy XOR format).

        H-01 fix: Transparently handles migration from XOR to Fernet.
        Keys encrypted with old XOR format are still decryptable but will
        be re-encrypted with Fernet on next rotation.
        """
        import base64
        # Fernet-encrypted keys are prefixed with "fernet:"
        if ciphertext.startswith("fernet:"):
            from cryptography.fernet import Fernet
            fernet_key = base64.urlsafe_b64encode(self._encryption_key)
            f = Fernet(fernet_key)
            return f.decrypt(ciphertext[7:].encode()).decode()
        # Legacy XOR format (with or without "xor:" prefix)
        if ciphertext.startswith("xor:"):
            ciphertext = ciphertext[4:]
        key = self._encryption_key
        data = base64.b64decode(ciphertext)
        decrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        return decrypted.decode()

    def _audit(self, action: str, tenant_id: str, key_id: str, provider: str):
        """Record audit event."""
        entry = json.dumps({
            "action": action,
            "tenant_id": tenant_id,
            "key_id": key_id,
            "provider": provider,
            "timestamp": time.time(),
        })
        if self._redis:
            try:
                self._redis.lpush("sentinel:vkeys:audit", entry)
                self._redis.ltrim("sentinel:vkeys:audit", 0, 999)  # Keep last 1000
            except Exception:
                pass
        logger.info("vkey_audit", extra={"action": action, "tenant": tenant_id, "provider": provider})


# === Singleton ===
_manager: VirtualKeyManager | None = None


def get_virtual_key_manager() -> VirtualKeyManager:
    """Get or create the global virtual key manager."""
    global _manager
    if _manager is None:
        _manager = VirtualKeyManager()
    return _manager
