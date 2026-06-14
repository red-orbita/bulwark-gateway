"""
Scanner Discovery — Plugin loading from entry points and drop-in directories.

Supports two discovery mechanisms:
  1. Python entry_points (pip-installable packages under 'sentinel.scanners' group)
  2. Drop-in directory (Python files in config/scanners/)

Security: Drop-in scanners are loaded but NOT executed until explicitly
registered in the pipeline. Entry point scanners follow the same rule.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import inspect
import logging
from pathlib import Path
from typing import Type

from src.scanners.protocol import InputScanner, OutputScanner

logger = logging.getLogger(__name__)


def discover_entry_point_scanners() -> list[Type[InputScanner | OutputScanner]]:
    """Discover scanner classes from installed packages via entry_points.

    Packages register scanners in pyproject.toml:
        [project.entry-points."sentinel.scanners"]
        my_scanner = "my_package.scanner:MyScannerClass"

    Returns:
        List of scanner classes (not instances)
    """
    scanners: list[Type[InputScanner | OutputScanner]] = []

    try:
        eps = importlib.metadata.entry_points()
        # Python 3.12+ returns SelectableGroups, earlier returns dict
        if hasattr(eps, "select"):
            scanner_eps = eps.select(group="sentinel.scanners")
        else:
            scanner_eps = eps.get("sentinel.scanners", [])  # type: ignore[attr-defined]

        for ep in scanner_eps:
            try:
                cls = ep.load()
                if _is_valid_scanner_class(cls):
                    scanners.append(cls)
                    logger.info(
                        "plugin_discovered",
                        extra={"name": ep.name, "module": ep.value, "source": "entry_point"},
                    )
                else:
                    logger.warning(
                        "plugin_invalid",
                        extra={"name": ep.name, "reason": "not a valid scanner class"},
                    )
            except Exception as e:
                logger.warning(
                    "plugin_load_failed",
                    extra={"name": ep.name, "error": str(e)[:200]},
                )
    except Exception as e:
        logger.warning("entry_points_scan_failed", extra={"error": str(e)[:200]})

    return scanners


def discover_directory_scanners(
    scanner_dir: Path,
) -> list[Type[InputScanner | OutputScanner]]:
    """Discover scanner classes from Python files in a directory.

    Each .py file in the directory is loaded as a module. Classes that
    subclass InputScanner or OutputScanner are collected.

    Args:
        scanner_dir: Path to directory containing scanner .py files

    Returns:
        List of scanner classes (not instances)
    """
    scanners: list[Type[InputScanner | OutputScanner]] = []

    if not scanner_dir.exists() or not scanner_dir.is_dir():
        return scanners

    for py_file in sorted(scanner_dir.glob("*.py")):
        if py_file.name.startswith("_"):
            continue  # Skip __init__.py, _helpers.py, etc.

        try:
            module = _load_module_from_path(py_file)
            if module is None:
                continue

            for name, obj in inspect.getmembers(module, inspect.isclass):
                if name.startswith("_"):
                    continue
                if _is_valid_scanner_class(obj) and obj.__module__ == module.__name__:
                    scanners.append(obj)
                    logger.info(
                        "plugin_discovered",
                        extra={
                            "name": name,
                            "file": str(py_file),
                            "source": "directory",
                        },
                    )
        except Exception as e:
            logger.warning(
                "plugin_file_load_failed",
                extra={"file": str(py_file), "error": str(e)[:200]},
            )

    return scanners


def discover_all_scanners(
    scanner_dir: Path | None = None,
) -> list[Type[InputScanner | OutputScanner]]:
    """Discover all available scanner classes from all sources.

    Args:
        scanner_dir: Optional path to drop-in scanner directory

    Returns:
        Combined list of scanner classes from entry_points and directory
    """
    scanners = discover_entry_point_scanners()

    if scanner_dir:
        scanners.extend(discover_directory_scanners(scanner_dir))

    # Deduplicate by class name (entry_points take priority)
    seen_names: set[str] = set()
    unique: list[Type[InputScanner | OutputScanner]] = []
    for cls in scanners:
        if cls.__name__ not in seen_names:
            seen_names.add(cls.__name__)
            unique.append(cls)

    logger.info("plugin_discovery_complete", extra={"total": len(unique)})
    return unique


def instantiate_scanner(
    cls: Type[InputScanner | OutputScanner],
    config: dict | None = None,
) -> InputScanner | OutputScanner:
    """Safely instantiate a scanner class.

    Args:
        cls: Scanner class to instantiate
        config: Optional configuration dict passed to constructor

    Returns:
        Scanner instance

    Raises:
        TypeError: If class cannot be instantiated
    """
    try:
        if config:
            return cls(**config)  # type: ignore
        return cls()  # type: ignore
    except TypeError:
        # Try without config if constructor doesn't accept kwargs
        if config:
            return cls()  # type: ignore
        raise


# === Internal helpers ===


def _is_valid_scanner_class(cls: type) -> bool:
    """Check if a class is a valid scanner (subclass of InputScanner or OutputScanner)."""
    if not inspect.isclass(cls):
        return False
    if cls in (InputScanner, OutputScanner):
        return False  # Don't include the abstract bases themselves
    return issubclass(cls, (InputScanner, OutputScanner))


def _load_module_from_path(path: Path):
    """Dynamically load a Python module from a file path."""
    module_name = f"sentinel_scanner_plugin_{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
