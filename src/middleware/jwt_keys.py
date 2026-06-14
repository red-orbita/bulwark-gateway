"""
JWT Key Management — supports RSA (RS256) and EC (ES256) asymmetric keys.

Enterprise features:
  - Load PEM keys from file paths
  - JWKS endpoint integration for external IdP (Azure AD, Okta, Auth0, etc.)
  - Cached JWKS responses with configurable TTL (default 1h)
  - Key rotation: verify against current AND previous key via 'kid' matching
  - Fail-closed: if key loading fails, all JWT verification is rejected

Security model:
  - Only the private key can sign tokens (held by IdP or token service)
  - Verification needs only the public key (safe to distribute)
  - Key compromise does NOT affect previously-issued tokens with different kid
"""

import logging
import time
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Optional dependency: cryptography (required for RS256/ES256)
_CRYPTOGRAPHY_AVAILABLE = False
try:
    from cryptography.hazmat.primitives.serialization import (
        load_pem_public_key,
        load_pem_private_key,
    )
    from cryptography.hazmat.primitives.asymmetric import rsa, ec

    _CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    pass


class JWTKeyError(Exception):
    """Raised when key loading or validation fails."""

    pass


class JWKSCache:
    """Thread-safe cache for JWKS (JSON Web Key Set) responses.

    Fetches keys from a remote JWKS endpoint and caches them.
    Supports key rotation via 'kid' (Key ID) lookup.
    """

    # SECURITY (H-07 fix): Maximum time to use stale keys after fetch failure.
    # After this period, fail-closed (reject all JWTs). Prevents indefinite
    # use of potentially compromised/revoked keys.
    MAX_STALE_SECONDS = 300  # 5 minutes max staleness

    def __init__(self, jwks_url: str, ttl_seconds: int = 3600):
        self._jwks_url = jwks_url
        self._ttl_seconds = ttl_seconds
        self._keys: dict[str, dict] = {}  # kid -> key_data
        self._all_keys: list[dict] = []  # All keys (for fallback when no kid)
        self._last_fetch: float = 0.0
        self._lock = threading.Lock()
        self._fetch_error: Optional[str] = None

    @property
    def url(self) -> str:
        return self._jwks_url

    def _is_expired(self) -> bool:
        return (time.time() - self._last_fetch) > self._ttl_seconds

    def _fetch_jwks(self) -> None:
        """Fetch JWKS from remote endpoint. Fail-closed on error."""
        try:
            import httpx

            # SECURITY (M-14 fix): Disable redirects to prevent DNS poisoning
            # attacks that redirect JWKS fetch to attacker-controlled endpoint.
            response = httpx.get(self._jwks_url, timeout=10.0, follow_redirects=False)
            response.raise_for_status()
            data = response.json()

            keys = data.get("keys", [])
            if not keys:
                raise JWTKeyError(f"JWKS endpoint returned no keys: {self._jwks_url}")

            new_keys: dict[str, dict] = {}
            for key_data in keys:
                kid = key_data.get("kid")
                if kid:
                    new_keys[kid] = key_data

            self._keys = new_keys
            self._all_keys = keys
            self._last_fetch = time.time()
            self._fetch_error = None

            logger.info(
                "JWKS cache refreshed",
                extra={
                    "url": self._jwks_url,
                    "key_count": len(keys),
                    "kids": list(new_keys.keys()),
                },
            )

        except Exception as e:
            self._fetch_error = str(e)
            logger.error(
                "JWKS fetch failed (fail-closed: rejecting all JWT tokens)",
                extra={"url": self._jwks_url, "error": str(e)},
            )
            # SECURITY (H-07 fix): Enforce max staleness. If keys are older than
            # MAX_STALE_SECONDS, clear them to fail-closed. Prevents indefinite
            # use of potentially compromised keys when JWKS endpoint is unreachable.
            stale_age = time.time() - self._last_fetch
            if self._keys and stale_age > self.MAX_STALE_SECONDS:
                logger.critical(
                    "JWKS keys exceeded max staleness — clearing (fail-closed)",
                    extra={
                        "stale_seconds": stale_age,
                        "max_stale_seconds": self.MAX_STALE_SECONDS,
                    },
                )
                self._keys = {}
                self._all_keys = []

            if not self._keys:
                raise JWTKeyError(
                    f"JWKS fetch failed and no cached keys available: {e}"
                )

    def get_key(self, kid: Optional[str] = None) -> dict:
        """Get a JWK by kid. Refreshes cache if expired.

        Args:
            kid: Key ID from JWT header. If None, returns first available key.

        Returns:
            JWK dict suitable for PyJWT's jwt.algorithms.RSAAlgorithm.from_jwk()

        Raises:
            JWTKeyError: If key not found or fetch fails.
        """
        with self._lock:
            if self._is_expired() or not self._keys:
                self._fetch_jwks()

        if kid and kid in self._keys:
            return self._keys[kid]

        if kid:
            # kid not found — maybe key was rotated. Force refresh once.
            with self._lock:
                self._fetch_jwks()
            if kid in self._keys:
                return self._keys[kid]
            raise JWTKeyError(
                f"Key ID '{kid}' not found in JWKS. "
                f"Available kids: {list(self._keys.keys())}"
            )

        # No kid specified — return first key
        if self._all_keys:
            return self._all_keys[0]

        raise JWTKeyError("No keys available in JWKS cache")

    def get_public_key_for_verification(self, kid: Optional[str] = None, algorithm: str = "RS256"):
        """Get a public key object suitable for PyJWT verification.

        Args:
            kid: Key ID from JWT header.
            algorithm: JWT algorithm (RS256 or ES256).

        Returns:
            Public key object for jwt.decode().

        Raises:
            JWTKeyError: If key conversion fails.
        """
        if not _CRYPTOGRAPHY_AVAILABLE:
            raise JWTKeyError(
                "cryptography package is required for JWKS support. "
                "Install with: pip install 'pyjwt[crypto]' or pip install cryptography"
            )


        jwk_data = self.get_key(kid)
        kty = jwk_data.get("kty", "")

        try:
            if kty == "RSA" and algorithm.startswith("RS"):
                from jwt.algorithms import RSAAlgorithm

                return RSAAlgorithm.from_jwk(jwk_data)
            elif kty == "EC" and algorithm.startswith("ES"):
                from jwt.algorithms import ECAlgorithm

                return ECAlgorithm.from_jwk(jwk_data)
            else:
                raise JWTKeyError(
                    f"Unsupported JWK key type '{kty}' for algorithm '{algorithm}'"
                )
        except Exception as e:
            if isinstance(e, JWTKeyError):
                raise
            raise JWTKeyError(f"Failed to convert JWK to public key: {e}")


def _require_cryptography() -> None:
    """Check that the cryptography package is available."""
    if not _CRYPTOGRAPHY_AVAILABLE:
        raise JWTKeyError(
            "cryptography package is required for RS256/ES256 JWT support. "
            "Install with: pip install 'pyjwt[crypto]' or pip install cryptography"
        )


def load_public_key(path: str):
    """Load a PEM-encoded public key from file.

    Supports both RSA and EC public keys.

    Args:
        path: Path to PEM public key file.

    Returns:
        Public key object for jwt.decode().

    Raises:
        JWTKeyError: If file not found, unreadable, or not a valid PEM key.
    """
    _require_cryptography()

    key_path = Path(path)
    if not key_path.is_file():
        raise JWTKeyError(f"Public key file not found: {path}")

    try:
        key_data = key_path.read_bytes()
    except (OSError, IOError) as e:
        raise JWTKeyError(f"Cannot read public key file '{path}': {e}")

    try:
        public_key = load_pem_public_key(key_data)
    except Exception as e:
        raise JWTKeyError(f"Invalid PEM public key in '{path}': {e}")

    # Validate key type
    if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        raise JWTKeyError(
            f"Unsupported key type in '{path}': expected RSA or EC public key, "
            f"got {type(public_key).__name__}"
        )

    logger.info(
        "Loaded public key",
        extra={"path": path, "type": type(public_key).__name__},
    )
    return public_key


def load_private_key(path: str, password: Optional[bytes] = None):
    """Load a PEM-encoded private key from file.

    Used for token generation (admin service, testing).

    Args:
        path: Path to PEM private key file.
        password: Optional passphrase for encrypted keys.

    Returns:
        Private key object for jwt.encode().

    Raises:
        JWTKeyError: If file not found or not a valid PEM key.
    """
    _require_cryptography()

    key_path = Path(path)
    if not key_path.is_file():
        raise JWTKeyError(f"Private key file not found: {path}")

    try:
        key_data = key_path.read_bytes()
    except (OSError, IOError) as e:
        raise JWTKeyError(f"Cannot read private key file '{path}': {e}")

    try:
        private_key = load_pem_private_key(key_data, password=password)
    except Exception as e:
        raise JWTKeyError(f"Invalid PEM private key in '{path}': {e}")

    if not isinstance(private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise JWTKeyError(
            f"Unsupported key type in '{path}': expected RSA or EC private key, "
            f"got {type(private_key).__name__}"
        )

    logger.info(
        "Loaded private key",
        extra={"path": path, "type": type(private_key).__name__},
    )
    return private_key


# Module-level singletons (initialized on first use)
_public_key = None
_private_key = None
_jwks_cache: Optional[JWKSCache] = None
_initialized = False


def initialize(
    algorithm: str,
    public_key_path: str = "",
    private_key_path: str = "",
    jwks_url: str = "",
    jwks_ttl: int = 3600,
) -> None:
    """Initialize JWT key management based on configuration.

    Called at application startup. Validates that required keys are available
    for the configured algorithm.

    Args:
        algorithm: JWT algorithm (HS256, RS256, ES256).
        public_key_path: Path to PEM public key file.
        private_key_path: Path to PEM private key file (optional, for signing).
        jwks_url: JWKS endpoint URL (alternative to public_key_path).
        jwks_ttl: JWKS cache TTL in seconds (default 1h).

    Raises:
        JWTKeyError: If configuration is invalid for the algorithm.
    """
    global _public_key, _private_key, _jwks_cache, _initialized

    if algorithm == "HS256":
        # Symmetric — no key management needed
        _initialized = True
        return

    if algorithm not in ("RS256", "ES256"):
        raise JWTKeyError(
            f"Unsupported JWT algorithm: '{algorithm}'. "
            f"Supported: HS256, RS256, ES256"
        )

    _require_cryptography()

    # Must have at least one verification source
    if not public_key_path and not jwks_url:
        raise JWTKeyError(
            f"Algorithm '{algorithm}' requires either "
            f"SENTINEL_JWT_PUBLIC_KEY_PATH or SENTINEL_JWT_JWKS_URL to be set. "
            f"Without a public key, token verification is impossible."
        )

    # Load public key from file
    if public_key_path:
        _public_key = load_public_key(public_key_path)

    # Initialize JWKS cache
    if jwks_url:
        _jwks_cache = JWKSCache(jwks_url, ttl_seconds=jwks_ttl)
        logger.info("JWKS endpoint configured", extra={"url": jwks_url, "ttl": jwks_ttl})

    # Load private key (optional — only needed for token generation)
    if private_key_path:
        _private_key = load_private_key(private_key_path)

    _initialized = True
    logger.info(
        "JWT asymmetric key management initialized",
        extra={
            "algorithm": algorithm,
            "has_public_key": _public_key is not None,
            "has_private_key": _private_key is not None,
            "has_jwks": _jwks_cache is not None,
        },
    )


def get_verification_key(algorithm: str, kid: Optional[str] = None):
    """Get the appropriate key for JWT verification.

    Resolution order:
    1. If JWKS is configured and JWT has a 'kid' header, use JWKS lookup
    2. If JWKS is configured without kid, use first available JWKS key
    3. If a static public key is loaded, use that
    4. Fail-closed: raise JWTKeyError

    Args:
        algorithm: JWT algorithm (RS256/ES256).
        kid: Key ID from JWT header (optional).

    Returns:
        Public key object for jwt.decode().

    Raises:
        JWTKeyError: If no suitable key is found.
    """
    if not _initialized:
        raise JWTKeyError("JWT key management not initialized. Call initialize() first.")

    # If JWKS is configured and we have a kid, prefer JWKS
    if _jwks_cache and kid:
        try:
            return _jwks_cache.get_public_key_for_verification(kid, algorithm)
        except JWTKeyError:
            # Fall through to static key if JWKS lookup fails and we have one
            if _public_key:
                logger.warning(
                    "JWKS lookup failed for kid, falling back to static public key",
                    extra={"kid": kid},
                )
                return _public_key
            raise

    # JWKS without kid — use first available key
    if _jwks_cache and not _public_key:
        return _jwks_cache.get_public_key_for_verification(kid=None, algorithm=algorithm)

    # Static public key
    if _public_key:
        return _public_key

    raise JWTKeyError(
        "No verification key available. "
        "Configure SENTINEL_JWT_PUBLIC_KEY_PATH or SENTINEL_JWT_JWKS_URL."
    )


def get_signing_key():
    """Get the private key for token generation.

    Returns:
        Private key object for jwt.encode().

    Raises:
        JWTKeyError: If no private key is configured.
    """
    if not _initialized:
        raise JWTKeyError("JWT key management not initialized.")

    if _private_key is None:
        raise JWTKeyError(
            "No private key configured. "
            "Set SENTINEL_JWT_PRIVATE_KEY_PATH for token generation."
        )
    return _private_key


def is_asymmetric(algorithm: str) -> bool:
    """Check if the algorithm requires asymmetric key management."""
    return algorithm in ("RS256", "ES256")
