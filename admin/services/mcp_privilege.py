"""
MCP Least Privilege Analysis — Sentinel Gateway SkillSpector Integration

Validates that MCP server/tool declarations match their actual code behavior.
Detects over-permissioned tools (request more access than needed) and
under-declared tools (use capabilities without declaring them).

Detection categories:
  LP1: Underdeclared Capability — code uses capabilities not in permissions
  LP2: Wildcard Permission — permission list contains wildcards
  LP3: Missing Permission Declaration — no permissions but code has capabilities
  LP4: Overdeclared Permission — permission declared but no matching code

Adapted from opencode-security-agent for use within Sentinel Gateway's
SkillSpector hybrid scanner. Works on both source code and manifest metadata.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Capability detection: what code actually does
# ---------------------------------------------------------------------------

_CAPABILITY_PATTERNS: dict[str, list[re.Pattern]] = {
    "filesystem_read": [
        re.compile(r"open\s*\(.+['\"]r['\"]", re.MULTILINE),
        re.compile(r"\.read_text\(\)", re.MULTILINE),
        re.compile(r"\.read_bytes\(\)", re.MULTILINE),
        re.compile(r"os\.(listdir|scandir|walk)\(", re.MULTILINE),
        re.compile(r"fs\.(readFile|readdir|stat)\(", re.MULTILINE),
    ],
    "filesystem_write": [
        re.compile(r"open\s*\(.+['\"][wa]['\"]", re.MULTILINE),
        re.compile(r"\.write_text\(", re.MULTILINE),
        re.compile(r"\.write_bytes\(", re.MULTILINE),
        re.compile(r"shutil\.(copy|move|rmtree)\(", re.MULTILINE),
        re.compile(r"fs\.(writeFile|mkdir|rename|unlink)\(", re.MULTILINE),
    ],
    "network": [
        re.compile(r"requests\.(get|post|put|delete|patch)\(", re.MULTILINE),
        re.compile(r"urllib\.request\.urlopen\(", re.MULTILINE),
        re.compile(r"aiohttp\.ClientSession\(", re.MULTILINE),
        re.compile(r"httpx\.(get|post|put|AsyncClient)\(", re.MULTILINE),
        re.compile(r"fetch\s*\(", re.MULTILINE),
        re.compile(r"axios\.(get|post|put|delete)\(", re.MULTILINE),
    ],
    "subprocess": [
        re.compile(r"subprocess\.(run|call|Popen|check_call|check_output)\(", re.MULTILINE),
        re.compile(r"os\.(system|popen)\(", re.MULTILINE),
        re.compile(r"child_process\.(exec|spawn|fork)\(", re.MULTILINE),
    ],
    "environment": [
        re.compile(r"os\.(environ|getenv)", re.MULTILINE),
        re.compile(r"process\.env\.", re.MULTILINE),
    ],
    "database": [
        re.compile(r"(sqlite3|psycopg2|mysql|pymongo|redis)\.(connect|Connection)\(", re.MULTILINE),
        re.compile(r"sqlalchemy\.create_engine\(", re.MULTILINE),
        re.compile(r"(mongoose|sequelize|knex)\.(connect|connection)\(", re.MULTILINE),
    ],
    "crypto": [
        re.compile(r"(cryptography|Crypto|hashlib|hmac)\.", re.MULTILINE),
        re.compile(r"from\s+(cryptography|Crypto)", re.MULTILINE),
        re.compile(r"require\s*\(\s*['\"]crypto['\"]", re.MULTILINE),
    ],
}

_WILDCARD_INDICATORS = {"*", "all", "full", "any", "unrestricted", "admin"}

# Permission string → capability mapping
_PERMISSION_MAP: dict[str, set[str]] = {
    "read": {"filesystem_read"},
    "write": {"filesystem_write"},
    "file": {"filesystem_read", "filesystem_write"},
    "filesystem": {"filesystem_read", "filesystem_write"},
    "fs": {"filesystem_read", "filesystem_write"},
    "network": {"network"},
    "net": {"network"},
    "http": {"network"},
    "fetch": {"network"},
    "exec": {"subprocess"},
    "execute": {"subprocess"},
    "shell": {"subprocess"},
    "subprocess": {"subprocess"},
    "command": {"subprocess"},
    "env": {"environment"},
    "environment": {"environment"},
    "db": {"database"},
    "database": {"database"},
    "sql": {"database"},
    "crypto": {"crypto"},
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _detect_capabilities(source: str) -> set[str]:
    """Detect actual capabilities used in source code."""
    capabilities: set[str] = set()
    for cap_name, patterns in _CAPABILITY_PATTERNS.items():
        for regex in patterns:
            if regex.search(source):
                capabilities.add(cap_name)
                break
    return capabilities


def _extract_declared_permissions(metadata: dict[str, Any]) -> set[str]:
    """Extract declared permissions from MCP metadata."""
    permissions: set[str] = set()

    perm_keys = ("permissions", "capabilities", "scopes", "access")
    for key in perm_keys:
        value = metadata.get(key)
        if value is None:
            continue
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    permissions.add(item.lower())
                elif isinstance(item, dict):
                    permissions.add(item.get("name", "").lower())
        elif isinstance(value, dict):
            for k, v in value.items():
                if v:
                    permissions.add(k.lower())
        elif isinstance(value, str):
            permissions.add(value.lower())

    return permissions


def _normalize_permissions(perms: set[str]) -> set[str]:
    """Normalize permission strings to capability categories."""
    capabilities: set[str] = set()
    for perm in perms:
        perm_lower = perm.lower().strip()
        for keyword, caps in _PERMISSION_MAP.items():
            if keyword in perm_lower:
                capabilities.update(caps)
    return capabilities


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_permissions(
    source_content: str,
    metadata: Optional[dict[str, Any]] = None,
    source_label: str = "",
) -> list[dict[str, Any]]:
    """
    Analyze MCP permissions vs actual code capabilities.

    Args:
        source_content: Combined source code content
        metadata: Parsed manifest/config with permission declarations
        source_label: Label for finding location

    Returns:
        List of finding dicts
    """
    findings: list[dict[str, Any]] = []

    actual_capabilities = _detect_capabilities(source_content)
    if not actual_capabilities:
        return findings  # No capabilities detected — nothing to check

    if metadata is None:
        metadata = {}

    declared_permissions = _extract_declared_permissions(metadata)

    # LP3: No permissions declared but code has capabilities
    if not declared_permissions and actual_capabilities:
        findings.append({
            "rule_id": "SEN-MCP-LP3",
            "severity": "medium",
            "message": (
                f"No permissions declared but code uses: "
                f"{', '.join(sorted(actual_capabilities))}"
            ),
            "confidence": 75,
            "category": "mcp_privilege",
            "file": source_label,
            "capabilities_detected": sorted(actual_capabilities),
        })
        return findings

    # LP2: Wildcard permissions
    for perm in declared_permissions:
        if perm in _WILDCARD_INDICATORS:
            findings.append({
                "rule_id": "SEN-MCP-LP2",
                "severity": "medium",
                "message": f"Wildcard permission declared: '{perm}'",
                "confidence": 90,
                "category": "mcp_privilege",
                "file": source_label,
            })

    # Normalize declared permissions to capability categories
    declared_capabilities = _normalize_permissions(
        declared_permissions - _WILDCARD_INDICATORS
    )

    # LP1: Underdeclared — code uses capability not in permissions
    if declared_permissions:
        underdeclared = actual_capabilities - declared_capabilities
        for cap in underdeclared:
            findings.append({
                "rule_id": "SEN-MCP-LP1",
                "severity": "high",
                "message": f"Code uses '{cap}' capability not declared in permissions",
                "confidence": 80,
                "category": "mcp_privilege",
                "file": source_label,
            })

    # LP4: Overdeclared — permission declared but no matching code
    if declared_capabilities and actual_capabilities:
        overdeclared = declared_capabilities - actual_capabilities
        for cap in overdeclared:
            findings.append({
                "rule_id": "SEN-MCP-LP4",
                "severity": "low",
                "message": f"Permission '{cap}' declared but no matching code found",
                "confidence": 60,
                "category": "mcp_privilege",
                "file": source_label,
            })

    return findings


def analyze_content(
    content: str,
    source_label: str = "",
) -> list[dict[str, Any]]:
    """
    Analyze content for MCP privilege issues.

    Attempts to extract permissions from structured data and detect
    capabilities in the source code.

    Args:
        content: Raw file content (may be source code, YAML, or JSON)
        source_label: Source label for findings

    Returns:
        List of finding dicts
    """
    metadata: dict[str, Any] = {}

    # Try to extract metadata from JSON
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            metadata = data
    except (json.JSONDecodeError, ValueError):
        pass

    return analyze_permissions(content, metadata, source_label)


def analyze_directory(dir_path: Path) -> list[dict[str, Any]]:
    """
    Analyze a directory: gather source code and metadata, then check privileges.

    Looks for manifest files (mcp.json, package.json, etc.) and scans
    source code for actual capabilities.
    """
    findings: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {}

    # Auto-detect manifest
    manifest_names = ("mcp.json", "manifest.json", "package.json", "tool.json", "server.json")
    for name in manifest_names:
        manifest_path = dir_path / name
        if manifest_path.exists():
            try:
                metadata = json.loads(manifest_path.read_text(encoding="utf-8"))
                break
            except (OSError, json.JSONDecodeError):
                continue

    # Gather source code
    source_parts: list[str] = []
    code_extensions = {".py", ".js", ".ts", ".mjs", ".cjs"}
    for f in dir_path.rglob("*"):
        if (
            f.is_file()
            and f.suffix in code_extensions
            and "node_modules" not in str(f)
            and "__pycache__" not in str(f)
        ):
            try:
                source_parts.append(f.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue

    if source_parts:
        combined_source = "\n".join(source_parts)
        findings = analyze_permissions(combined_source, metadata, str(dir_path))

    return findings


# Pattern count for status reporting
PATTERN_COUNT = sum(len(patterns) for patterns in _CAPABILITY_PATTERNS.values()) + 2  # +2 for wildcard/normalize
