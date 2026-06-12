"""
Plugin Specification — Defines the metadata schema for Sentinel plugins.

Every plugin must include a `sentinel-plugin.yaml` file at its root
that conforms to the PluginSpec model. This module handles loading,
parsing, and validating plugin specifications.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class PluginType(str, Enum):
    """The pipeline stage this plugin targets."""

    INPUT_SCANNER = "input_scanner"
    OUTPUT_SCANNER = "output_scanner"
    ENRICHMENT = "enrichment"


@dataclass
class PluginConfigParam:
    """A single configurable parameter exposed by a plugin."""

    name: str
    type: str  # str, float, int, bool
    default: Any = None
    description: str = ""


@dataclass
class PluginModelSpec:
    """Specification for an ML model required by the plugin."""

    name: str
    size: str  # e.g. "150MB", "2.3GB"
    url: str  # Download URL


class PluginSpec(BaseModel):
    """Complete plugin specification loaded from sentinel-plugin.yaml."""

    name: str = Field(..., description="Unique plugin identifier (kebab-case)")
    version: str = Field(..., description="SemVer version string")
    author: str = Field(..., description="Plugin author or organization")
    license: str = Field(default="MIT", description="SPDX license identifier")
    description: str = Field(default="", description="Human-readable description")
    type: PluginType = Field(..., description="Plugin pipeline stage")
    blocking: bool = Field(
        default=False,
        description="Whether this plugin runs in the blocking hot path",
    )
    requires: dict[str, str] = Field(
        default_factory=dict,
        description="Python package dependencies (package -> version spec)",
    )
    models: list[PluginModelSpec] = Field(
        default_factory=list,
        description="ML models required by this plugin",
    )
    config: dict[str, PluginConfigParam] = Field(
        default_factory=dict,
        description="Configurable parameters",
    )

    class Config:
        arbitrary_types_allowed = True


# --------------------------------------------------------------------------
# Version pattern (loose SemVer)
# --------------------------------------------------------------------------
_SEMVER_RE = re.compile(
    r"^\d+\.\d+\.\d+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$"
)
_NAME_RE = re.compile(r"^[a-z][a-z0-9\-]{1,63}$")
_VALID_PARAM_TYPES = {"str", "float", "int", "bool"}


def load_plugin_spec(path: Path) -> PluginSpec:
    """Load a PluginSpec from a sentinel-plugin.yaml file.

    Args:
        path: Path to the sentinel-plugin.yaml file or to the plugin directory.

    Returns:
        Parsed and validated PluginSpec instance.

    Raises:
        FileNotFoundError: If the spec file doesn't exist.
        ValueError: If the YAML is malformed or doesn't match the schema.
    """
    spec_file = path if path.is_file() else path / "sentinel-plugin.yaml"

    if not spec_file.exists():
        raise FileNotFoundError(f"Plugin spec not found: {spec_file}")

    with spec_file.open("r", encoding="utf-8") as f:
        raw: dict[str, Any] = yaml.safe_load(f)

    if not isinstance(raw, dict):
        raise ValueError(f"Invalid plugin spec format in {spec_file}")

    # Parse nested dataclass fields from raw dicts
    if "models" in raw and isinstance(raw["models"], list):
        raw["models"] = [
            PluginModelSpec(**m) if isinstance(m, dict) else m
            for m in raw["models"]
        ]

    if "config" in raw and isinstance(raw["config"], dict):
        raw["config"] = {
            k: PluginConfigParam(**v) if isinstance(v, dict) else v
            for k, v in raw["config"].items()
        }

    spec = PluginSpec(**raw)
    logger.debug("loaded_plugin_spec", extra={"plugin": spec.name, "version": spec.version})
    return spec


def validate_plugin_spec(spec: PluginSpec) -> list[str]:
    """Validate a PluginSpec and return a list of error messages.

    Returns an empty list if the spec is fully valid.

    Args:
        spec: The PluginSpec to validate.

    Returns:
        List of human-readable validation error strings.
    """
    errors: list[str] = []

    # Name validation
    if not _NAME_RE.match(spec.name):
        errors.append(
            f"Invalid plugin name '{spec.name}': must be lowercase kebab-case, "
            f"2-64 chars, starting with a letter."
        )

    # Version validation
    if not _SEMVER_RE.match(spec.version):
        errors.append(
            f"Invalid version '{spec.version}': must follow SemVer (e.g. 1.0.0)."
        )

    # Author must not be empty
    if not spec.author.strip():
        errors.append("Author field must not be empty.")

    # Description recommended
    if not spec.description.strip():
        errors.append("Description is empty (recommended to provide one).")

    # Validate config param types
    for param_name, param in spec.config.items():
        if param.type not in _VALID_PARAM_TYPES:
            errors.append(
                f"Config param '{param_name}' has invalid type '{param.type}'. "
                f"Must be one of: {', '.join(sorted(_VALID_PARAM_TYPES))}."
            )

    # Validate model specs
    for model in spec.models:
        if not model.url:
            errors.append(f"Model '{model.name}' is missing a download URL.")
        if not model.size:
            errors.append(f"Model '{model.name}' is missing a size estimate.")

    # Validate requires keys look like package names
    for pkg, ver in spec.requires.items():
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_\-\.]*$", pkg):
            errors.append(f"Invalid package name in requires: '{pkg}'.")
        if not ver:
            errors.append(f"Package '{pkg}' has empty version constraint.")

    return errors
