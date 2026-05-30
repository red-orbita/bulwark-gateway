"""Application configuration via environment variables."""
from pydantic_settings import BaseSettings
from typing import List
from pathlib import Path


class Settings(BaseSettings):
    """Sentinel Gateway configuration.

    All settings can be overridden via environment variables
    prefixed with SENTINEL_ (e.g., SENTINEL_PORT=9000).
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
    api_keys_enabled: bool = True

    # Backend (upstream agent/LLM)
    backend_url: str = "http://localhost:11434"  # Default: local Ollama
    backend_timeout: float = 120.0

    # Policies
    policies_dir: Path = Path("config/policies")

    # IOC
    ioc_path: Path = Path("config/iocs.json")

    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_rpm: int = 60  # requests per minute per tenant
    rate_limit_rpm_burst: int = 10

    # Redis (for distributed rate limiting)
    redis_url: str | None = None

    # Logging
    log_format: str = "json"  # "json" or "console"
    log_level: str = "INFO"

    # Security
    fail_mode: str = "closed"  # "closed" (block on error) or "open" (allow on error)
    cors_origins: List[str] = ["*"]

    model_config = {"env_prefix": "SENTINEL_", "env_file": ".env"}


settings = Settings()
