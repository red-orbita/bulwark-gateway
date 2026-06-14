"""Configuration Manager — Runtime config access with masking and hot-reload."""

from __future__ import annotations

from typing import Any, Optional

from .audit_logger import get_audit_logger

# Fields that require a restart to take effect
RESTART_REQUIRED_FIELDS = {"jwt_secret", "host", "port", "workers", "redis_url"}

# Sensitive fields that must be masked in GET responses
SENSITIVE_FIELDS = {"jwt_secret", "api_keys", "urlhaus_key", "threatfox_key", "otx_key", "abuseipdb_key"}

# Section definitions mapping section name -> list of settings field names
SECTIONS = {
    "proxy": ["backend_url", "backend_timeout", "fail_mode", "mode"],
    "security": ["api_keys_enabled", "cors_origins", "jwt_secret", "jwt_algorithm", "api_keys"],
    "logging": ["log_level", "log_format", "debug"],
    "feeds": ["urlhaus_key", "threatfox_key", "otx_key", "abuseipdb_key"],
    "rate_limiting": ["rate_limit_enabled", "rate_limit_rpm", "rate_limit_rpm_burst"],
}

# Fields that can be hot-reloaded (updated without restart)
HOT_RELOADABLE = {
    "backend_url", "backend_timeout", "fail_mode", "mode",
    "api_keys_enabled", "cors_origins", "api_keys",
    "log_level", "log_format", "debug",
    "urlhaus_key", "threatfox_key", "otx_key", "abuseipdb_key",
    "rate_limit_enabled", "rate_limit_rpm", "rate_limit_rpm_burst",
}


def _mask_value(key: str, value: Any) -> Any:
    """Mask sensitive values."""
    if key in SENSITIVE_FIELDS:
        if isinstance(value, str) and len(value) > 0:
            return value[:3] + "***" if len(value) > 3 else "***"
    return value


class ConfigManager:
    """Singleton wrapper around src.config.settings for safe admin access."""

    def get_config(self, section: Optional[str] = None) -> dict[str, Any]:
        """Get current config values with sensitive fields masked."""
        from src.config import settings

        if section:
            if section not in SECTIONS:
                raise ValueError(f"Unknown section: {section}. Valid: {list(SECTIONS.keys())}")
            fields = SECTIONS[section]
        else:
            fields = [f for fs in SECTIONS.values() for f in fs]

        result = {}
        for field in fields:
            value = getattr(settings, field, None)
            # Convert non-serializable types
            if isinstance(value, list):
                value = list(value)
            result[field] = _mask_value(field, value)
        return result

    async def update_config(self, section: str, data: dict[str, Any], actor: str) -> dict[str, Any]:
        """Validate and apply hot-reloadable config changes."""
        from src.config import settings

        if section not in SECTIONS:
            raise ValueError(f"Unknown section: {section}. Valid: {list(SECTIONS.keys())}")

        valid_fields = set(SECTIONS[section])
        errors = []
        applied = {}
        restart_needed = []

        for key, value in data.items():
            if key not in valid_fields:
                errors.append(f"Field '{key}' not in section '{section}'")
                continue
            if key in RESTART_REQUIRED_FIELDS:
                restart_needed.append(key)
                continue
            if key not in HOT_RELOADABLE:
                errors.append(f"Field '{key}' cannot be hot-reloaded")
                continue

            # Type validation
            current = getattr(settings, key, None)
            if current is not None and not isinstance(value, type(current)):
                # Allow int->float coercion
                if isinstance(current, float) and isinstance(value, (int, float)):
                    value = float(value)
                elif isinstance(current, int) and isinstance(value, int):
                    pass
                elif isinstance(current, bool) and isinstance(value, bool):
                    pass
                elif isinstance(current, str) and isinstance(value, str):
                    pass
                elif isinstance(current, list) and isinstance(value, list):
                    pass
                else:
                    errors.append(f"Type mismatch for '{key}': expected {type(current).__name__}")
                    continue

            setattr(settings, key, value)
            applied[key] = _mask_value(key, value)

        # Audit log
        audit = get_audit_logger()
        await audit.log(
            actor=actor,
            action="config_update",
            resource_type="config",
            resource_id=section,
            details=f"Updated: {list(applied.keys())}",
        )

        result: dict[str, Any] = {"applied": applied}
        if errors:
            result["errors"] = errors
        if restart_needed:
            result["restart_required"] = restart_needed
        return result

    def validate_config(self, section: str, data: dict[str, Any]) -> dict[str, Any]:
        """Validate proposed config without applying."""
        if section not in SECTIONS:
            return {"valid": False, "errors": [f"Unknown section: {section}"]}

        from src.config import settings
        valid_fields = set(SECTIONS[section])
        errors = []
        warnings = []

        for key, value in data.items():
            if key not in valid_fields:
                errors.append(f"Field '{key}' not in section '{section}'")
                continue
            if key in RESTART_REQUIRED_FIELDS:
                warnings.append(f"Field '{key}' requires restart to take effect")

            current = getattr(settings, key, None)
            if current is not None and not isinstance(value, type(current)):
                if isinstance(current, float) and isinstance(value, (int, float)):
                    pass
                else:
                    errors.append(f"Type mismatch for '{key}': expected {type(current).__name__}, got {type(value).__name__}")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
        }

    def get_restart_required_fields(self) -> list[dict[str, str]]:
        """List fields that need restart to take effect."""
        from src.config import settings
        return [
            {"field": f, "current_value": _mask_value(f, getattr(settings, f, None))}
            for f in sorted(RESTART_REQUIRED_FIELDS)
        ]


_manager: Optional[ConfigManager] = None


def get_config_manager() -> ConfigManager:
    global _manager
    if _manager is None:
        _manager = ConfigManager()
    return _manager
