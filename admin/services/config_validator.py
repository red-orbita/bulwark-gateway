"""Config Validator & Hot Reloader — Dry-run + atomic apply."""

from __future__ import annotations

import difflib
import hashlib
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from ..models.config import PolicyValidationResult, PolicyDiff

POLICIES_DIR = Path("config/policies")
BACKUP_DIR = POLICIES_DIR / ".backup"


class ConfigValidator:
    """Validates policy YAML against schema and runs dry-run tests."""

    @staticmethod
    def validate_yaml(content: str) -> PolicyValidationResult:
        """Parse and validate YAML policy content."""
        errors: list[str] = []
        warnings: list[str] = []
        agents: list[str] = []

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            return PolicyValidationResult(valid=False, errors=[f"YAML parse error: {e}"])

        if not isinstance(data, dict):
            return PolicyValidationResult(valid=False, errors=["Policy must be a YAML mapping"])

        # Required fields
        if "tenant" not in data:
            errors.append("Missing required field: 'tenant'")
        if "agents" not in data:
            warnings.append("No 'agents' section defined")
        else:
            if isinstance(data["agents"], dict):
                agents = list(data["agents"].keys())
                for agent_name, agent_config in data["agents"].items():
                    if not isinstance(agent_config, dict):
                        errors.append(f"Agent '{agent_name}' must be a mapping")
                        continue
                    # Validate tool policy
                    tools = agent_config.get("tools", {})
                    if isinstance(tools, dict):
                        allowed = tools.get("allowed", [])
                        denied = tools.get("denied", [])
                        overlap = set(allowed) & set(denied)
                        if overlap:
                            errors.append(f"Agent '{agent_name}': tools in both allowed and denied: {overlap}")

        return PolicyValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            affected_agents=agents,
        )

    @staticmethod
    def validate_regex_pattern(pattern: str) -> tuple[bool, Optional[str]]:
        """Test if a regex pattern compiles without error and is not ReDoS-vulnerable."""
        import re
        try:
            re.compile(pattern)
        except re.error as e:
            return False, str(e)

        # ReDoS heuristics: reject patterns with nested quantifiers or overlapping alternation
        # Dangerous: (a+)+, (a*)*,  (a+|b+)*, (\w+\s*)+ etc.
        _REDOS_INDICATORS = [
            r'(\(.+[+*]\))[+*]',           # nested quantifiers: (x+)+ or (x*)*
            r'(\(.+[+*]\)){2,}',            # repeated group with quantifier
            r'[+*]\s*[+*]',                 # adjacent quantifiers (possessive-like but not in Python)
        ]
        for indicator in _REDOS_INDICATORS:
            if re.search(indicator, pattern):
                return False, "Pattern rejected: potential ReDoS (nested/overlapping quantifiers)"

        # Length limit
        if len(pattern) > 1000:
            return False, "Pattern too long (max 1000 chars)"

        # Test with a stress string to detect catastrophic backtracking (10ms budget)
        import signal
        import threading

        test_input = "a" * 50 + "!" + "a" * 50
        compiled = re.compile(pattern, re.IGNORECASE)

        result: list = [True]

        def _test():
            try:
                compiled.search(test_input)
            except Exception:
                pass

        t = threading.Thread(target=_test, daemon=True)
        t.start()
        t.join(timeout=0.05)  # 50ms max
        if t.is_alive():
            return False, "Pattern rejected: regex execution exceeded time limit (possible ReDoS)"

        return True, None


class HotReloader:
    """Atomic config hot-reload with backup and rollback."""

    @staticmethod
    def backup_policy(policy_name: str) -> Optional[str]:
        """Backup current policy before overwrite. Returns backup path."""
        source = POLICIES_DIR / f"{policy_name}.yaml"
        if not source.exists():
            return None
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        backup_path = BACKUP_DIR / f"{policy_name}.{timestamp}.yaml"
        shutil.copy2(source, backup_path)
        return str(backup_path)

    @staticmethod
    def apply_policy(policy_name: str, content: str) -> bool:
        """Atomically write policy (write to .tmp, rename)."""
        target = POLICIES_DIR / f"{policy_name}.yaml"
        tmp = POLICIES_DIR / f"{policy_name}.yaml.tmp"
        try:
            tmp.write_text(content, encoding="utf-8")
            tmp.rename(target)  # Atomic on POSIX
            return True
        except Exception:
            if tmp.exists():
                tmp.unlink()
            return False

    @staticmethod
    def rollback_policy(policy_name: str, version_timestamp: Optional[str] = None) -> bool:
        """Restore policy from backup. If no timestamp, use latest."""
        backups = sorted(BACKUP_DIR.glob(f"{policy_name}.*.yaml"), reverse=True)
        if not backups:
            return False

        if version_timestamp:
            target_backup = BACKUP_DIR / f"{policy_name}.{version_timestamp}.yaml"
            if not target_backup.exists():
                return False
        else:
            target_backup = backups[0]  # Latest

        target = POLICIES_DIR / f"{policy_name}.yaml"
        shutil.copy2(target_backup, target)
        return True

    @staticmethod
    def get_policy_versions(policy_name: str) -> list[dict]:
        """List available versions (current + backups)."""
        versions = []
        current = POLICIES_DIR / f"{policy_name}.yaml"
        if current.exists():
            stat = current.stat()
            versions.append({
                "version": "current",
                "timestamp": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                "size": stat.st_size,
                "checksum": hashlib.sha256(current.read_bytes()).hexdigest()[:16],
            })

        backups = sorted(BACKUP_DIR.glob(f"{policy_name}.*.yaml"), reverse=True)
        for i, backup in enumerate(backups[:10]):
            stat = backup.stat()
            ts = backup.stem.split(".")[-1]  # Extract timestamp from filename
            versions.append({
                "version": f"backup-{i+1}",
                "timestamp": ts,
                "size": stat.st_size,
                "checksum": hashlib.sha256(backup.read_bytes()).hexdigest()[:16],
                "path": str(backup),
            })
        return versions

    @staticmethod
    def diff_versions(policy_name: str, version_from: str, version_to: str = "current") -> Optional[str]:
        """Generate unified diff between two versions."""
        if version_to == "current":
            to_path = POLICIES_DIR / f"{policy_name}.yaml"
        else:
            to_path = Path(version_to)

        from_path = Path(version_from)
        if not from_path.exists() or not to_path.exists():
            return None

        from_lines = from_path.read_text().splitlines(keepends=True)
        to_lines = to_path.read_text().splitlines(keepends=True)
        diff = difflib.unified_diff(from_lines, to_lines, fromfile=str(from_path), tofile=str(to_path))
        return "".join(diff)
