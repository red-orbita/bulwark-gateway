"""Docker Secrets reader — resolves secrets from /run/secrets/ files.

Docker Swarm/Compose secrets are mounted as files at /run/secrets/<name>.
This module provides a unified way to read secrets with fallback to
environment variables for local development.

Priority:
  1. Docker secret file (via *_FILE env var pointing to /run/secrets/*)
  2. Direct env var (for local dev without Docker)
  3. Default value (if provided)

Usage:
    from admin.services.secrets import read_secret
    jwt_secret = read_secret("ADMIN_JWT_SECRET", required=True)
"""

from __future__ import annotations

import os
from pathlib import Path


def read_secret(env_name: str, default: str | None = None, required: bool = False) -> str:
    """Read a secret from Docker secret file or environment variable.

    Args:
        env_name: Name of the env var (e.g., "ADMIN_JWT_SECRET").
                  Will also check for {env_name}_FILE pointing to a file path.
        default: Default value if not found anywhere.
        required: If True, raises SystemExit if secret not found.

    Returns:
        The secret value (stripped of trailing whitespace/newlines).
    """
    # 1. Check for _FILE variant (Docker secrets pattern)
    file_env = f"{env_name}_FILE"
    secret_file = os.getenv(file_env)
    if secret_file:
        path = Path(secret_file)
        if path.is_file():
            value = path.read_text().strip()
            if value:
                return value

    # 2. Check direct env var
    value = os.getenv(env_name)
    if value:
        return value

    # 3. Default or fail
    if default is not None:
        return default

    if required:
        raise SystemExit(
            f"FATAL: Secret '{env_name}' not found. "
            f"Set either {file_env} (path to file) or {env_name} (direct value)."
        )

    return ""
