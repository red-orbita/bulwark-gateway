"""Application configuration via environment variables and Docker secrets."""

import os
from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_secret_file(env_name: str, prefix: str = "SENTINEL_") -> str | None:
    """Read a secret from a Docker secrets file if *_FILE env var is set."""
    file_path = os.getenv(f"{prefix}{env_name}_FILE") or os.getenv(f"{env_name}_FILE")
    if file_path:
        p = Path(file_path)
        if p.is_file():
            return p.read_text().strip()
    return None


class Settings(BaseSettings):
    """Sentinel Gateway configuration.

    All settings can be overridden via environment variables
    prefixed with SENTINEL_ (e.g., SENTINEL_PORT=9000).

    Secrets can be provided via Docker secret files:
      SENTINEL_JWT_SECRET_FILE=/run/secrets/jwt_secret
      SENTINEL_REDIS_PASSWORD_FILE=/run/secrets/redis_password
    """

    # Server
    host: str = "0.0.0.0"
    port: int = 8080
    workers: int = 4
    debug: bool = False
    mode: str = "proxy"  # "proxy" or "sidecar"

    # Auth
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    # H-03: JWT audience/issuer for cross-service isolation (set to prevent admin→proxy reuse)
    jwt_audience: str = "sentinel-proxy"
    jwt_issuer: str = "sentinel-gateway"
    api_keys_enabled: bool = True
    # Comma-separated list of valid API keys (e.g., "key1,key2,key3")
    # If empty and api_keys_enabled=True, only JWT auth works
    api_keys: str = ""

    # Backend (upstream agent/LLM)
    backend_url: str = "http://localhost:11434"  # Default: local Ollama
    backend_timeout: float = 120.0

    # Policies
    policies_dir: Path = Path("config/policies")

    # Agent Registry (multi-backend routing)
    agents_config: Path = Path("config/agents.yaml")

    # IOC
    ioc_path: Path = Path("config/iocs.json")

    # IOC Feed API Keys (all optional — feeds with missing keys are skipped)
    urlhaus_key: str = ""
    threatfox_key: str = ""
    otx_key: str = ""
    abuseipdb_key: str = ""

    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_rpm: int = 60  # requests per minute per tenant
    rate_limit_rpm_burst: int = 10

    # Redis (for distributed rate limiting, pattern sync, SIEM stats)
    redis_url: str | None = None
    redis_password: str | None = None  # Separate password for K8s (injected into URL)
    redis_tls_insecure: bool = False  # Skip TLS cert verification (self-signed certs)

    # Logging
    log_format: str = "json"  # "json" or "console"
    log_level: str = "INFO"

    # Security
    fail_mode: str = "closed"  # "closed" (block on error) or "open" (allow on error)
    cors_origins: List[str] = []  # Empty = no CORS; set explicitly via SENTINEL_CORS_ORIGINS

    # Webhook alerts (comma-separated: "type|name|url" or just "url")
    webhook_alert_urls: str = ""

    # Scanner Pipeline
    scanners_dir: Path = Path("config/scanners")  # Drop-in scanner plugins directory
    scanners_pipeline_enabled: bool = True  # Use new scanner pipeline (vs legacy direct calls)

    # ML Scanner Settings (Phase 2+)
    ml_enabled: bool = False  # Master switch for ML-based scanners
    ml_blocking: bool = False  # If True, ML scanners can block requests (adds latency)
    ml_block_threshold: float = 0.9  # Confidence threshold for ML to auto-block
    ml_warn_threshold: float = 0.7  # Confidence threshold for ML to warn
    ml_timeout_ms: int = 10000  # Max ML inference time in milliseconds (CPU: ~1-5s)
    ml_model_dir: Path = Path("models")  # Directory for ML model files

    # RAG Guard (Phase 5)
    rag_enabled: bool = False  # Master switch for RAG scanners (retrieval + memory guard)

    # Multilingual Detection (Phase 3)
    multilingual_enabled: bool = False  # Master switch for language detection + multilingual patterns

    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_file=".env",
        extra="ignore",
        secrets_dir="/run/secrets",  # Docker secrets mount point
    )


def _build_settings() -> "Settings":
    """Build settings with Docker secret file overrides.

    Reads *_FILE env vars pointing to /run/secrets/* (Docker secrets pattern).
    Falls back to direct env vars for local dev.
    """
    s = Settings()

    # JWT secret
    jwt_from_file = _read_secret_file("JWT_SECRET")
    if jwt_from_file:
        s.jwt_secret = jwt_from_file

    # API keys
    api_keys_from_file = _read_secret_file("API_KEYS")
    if api_keys_from_file:
        s.api_keys = api_keys_from_file

    # IOC feed keys
    for key_name in ("URLHAUS_KEY", "THREATFOX_KEY", "OTX_KEY", "ABUSEIPDB_KEY"):
        val = _read_secret_file(key_name)
        if val:
            setattr(s, key_name.lower(), val)

    # Redis password → inject into URL (supports redis:// and rediss:// schemes)
    redis_pw = _read_secret_file("REDIS_PASSWORD")
    if not redis_pw and s.redis_password:
        redis_pw = s.redis_password  # From SENTINEL_REDIS_PASSWORD env var (K8s)
    if redis_pw and s.redis_url:
        scheme_match = "://" in s.redis_url and (
            s.redis_url.startswith("redis://") or s.redis_url.startswith("rediss://")
        )
        if scheme_match:
            # SECURITY FIX (VULN 1.7): URL-encode the password to prevent injection.
            # A password containing '@' could redirect the connection to a malicious host.
            from urllib.parse import quote as url_quote
            safe_pw = url_quote(redis_pw, safe="")
            if "@" not in s.redis_url:
                s.redis_url = s.redis_url.replace("://", f"://:{safe_pw}@")
            elif ":@" in s.redis_url:
                s.redis_url = s.redis_url.replace(":@", f":{safe_pw}@")

    return s


settings = _build_settings()


def validate_settings():
    """Validate critical security settings at startup."""
    # SECURITY FIX (VULN 1.5): Expanded blocklist of known-insecure secrets
    # These are publicly documented in README, .env.example, and now in the pentest report
    insecure_secrets = {
        "change-me-in-production",
        "sentinel-jwt-dev-secret-change-in-prod",
        "sentinel-admin-change-me-in-production",
        "",
        "secret",
        "test",
        "dev",
        "admin",
        "password",
        "changeme",
    }
    jwt = settings.jwt_secret.lower().strip()

    # H-02: Check both blocklist AND entropy (minimum 32 bytes of randomness)
    is_insecure = jwt in insecure_secrets or len(settings.jwt_secret) < 32

    if is_insecure:
        if settings.debug:
            # SECURITY FIX: In debug mode, auto-generate a random secret instead of
            # allowing the insecure default. This prevents the attack vector where
            # debug=true + known secret = forge arbitrary tokens.
            import secrets as _secrets
            import logging
            generated = _secrets.token_hex(32)
            settings.jwt_secret = generated  # type: ignore[misc]
            logging.getLogger(__name__).warning(
                "INSECURE JWT_SECRET detected in debug mode — auto-generated random secret. "
                "Set SENTINEL_JWT_SECRET to a strong value for persistent tokens."
            )
        else:
            raise SystemExit(
                "FATAL: SENTINEL_JWT_SECRET is insecure. "
                "Set a strong secret (32+ chars of random data) via environment variable or Docker secret."
            )


# Validation is called explicitly by src/main.py at startup, not at import time.
# This allows admin service to import settings without proxy-specific validation failing.
