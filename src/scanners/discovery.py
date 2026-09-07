"""
Scanner Discovery — Plugin loading from entry points and drop-in directories.

Supports two discovery mechanisms:
  1. Python entry_points (pip-installable packages under 'bulwark.scanners' group)
  2. Drop-in directory (Python files in config/scanners/)

Trust boundary
--------------
These two mechanisms sit on opposite sides of a trust boundary and are
deliberately treated differently:

  * Drop-in directory scanners (``config/scanners/*.py``) are UNTRUSTED. A file
    dropped into that directory is executed at import time — a classic local
    RCE vector. Every candidate file is therefore passed through the AST static
    analysis gate (:func:`src.plugins.sandbox.analyze_plugin_source`, STRICT
    import whitelist) BEFORE its module is ever imported. A file whose source
    is not statically ``safe`` (risk score >= 4.0, syntax errors, blocked
    imports/builtins) is logged and skipped without being executed.

  * Entry-point scanners (``bulwark.scanners`` group) are TRUSTED via the
    ``pip install`` boundary: installing the package already ran its
    ``setup.py``/build backend as the operator, and legitimate engines
    (Presidio, torch, httpx, …) intentionally import modules the STRICT
    whitelist forbids. Applying the whitelist gate here would break every
    real-world engine, so entry-point scanners are NOT re-gated — the trust
    decision was made at install time.

Note: passing the AST gate is necessary but not sufficient — a discovered
scanner class is still not *executed* until explicitly registered in the
pipeline.
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
        [project.entry-points."bulwark.scanners"]
        my_scanner = "my_package.scanner:MyScannerClass"

    Trust boundary: entry-point scanners are trusted via the ``pip install``
    boundary and are NOT passed through the STRICT AST import whitelist that
    guards drop-in directory scanners — a legitimate engine may import modules
    the whitelist forbids. See the module docstring for the full rationale.

    Returns:
        List of scanner classes (not instances)
    """
    scanners: list[Type[InputScanner | OutputScanner]] = []

    try:
        eps = importlib.metadata.entry_points()
        # Python 3.12+ returns SelectableGroups, earlier returns dict
        if hasattr(eps, "select"):
            scanner_eps = eps.select(group="bulwark.scanners")
        else:
            scanner_eps = eps.get("bulwark.scanners", [])  # type: ignore[attr-defined]

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

    Security: because a file in this directory is executed at import time
    (a local RCE vector), every candidate is passed through the AST static
    analysis gate (STRICT import whitelist) BEFORE it is imported. A file whose
    source is not statically safe is logged and skipped without execution.

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

        # Trust boundary: drop-in scanners are UNTRUSTED. Statically vet the
        # source with the STRICT AST gate before importing (which executes it).
        if not _passes_ast_gate(py_file):
            continue

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


def _passes_ast_gate(py_file: Path) -> bool:
    """Statically vet a drop-in scanner file before it is imported/executed.

    Reads the source and runs the STRICT AST import-whitelist analysis
    (:func:`src.plugins.sandbox.analyze_plugin_source`). Returns True only when
    the source is statically ``safe`` (risk score < 4.0, no blocked
    imports/builtins, no syntax error). Any read/parse failure or an unsafe
    verdict is logged and treated as a fail-closed skip — the module is never
    imported.

    Import of the sandbox is done lazily so entry-point-only deployments (no
    drop-in directory) never pay for it.
    """
    try:
        source = py_file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        logger.warning(
            "plugin_ast_gate_read_failed",
            extra={"file": str(py_file), "error": str(e)[:200]},
        )
        return False

    try:
        from src.plugins.sandbox import analyze_plugin_source

        result = analyze_plugin_source(source, filename=str(py_file))
    except Exception as e:  # pragma: no cover - defensive, gate must fail closed
        logger.warning(
            "plugin_ast_gate_error",
            extra={"file": str(py_file), "error": str(e)[:200]},
        )
        return False

    if not result.safe:
        top = result.findings[0] if result.findings else None
        logger.critical(
            "plugin_ast_blocked_at_discovery",
            extra={
                "file": str(py_file),
                "risk_score": result.risk_score,
                "verdict": result.verdict,
                "finding": top.message[:200] if top else "",
                "category": top.category if top else "",
                "line": top.line if top else 0,
            },
        )
        return False

    return True


def _is_valid_scanner_class(cls: type) -> bool:
    """Check if a class is a valid scanner (subclass of InputScanner or OutputScanner)."""
    if not inspect.isclass(cls):
        return False
    if cls in (InputScanner, OutputScanner):
        return False  # Don't include the abstract bases themselves
    return issubclass(cls, (InputScanner, OutputScanner))


def _load_module_from_path(path: Path):
    """Dynamically load a Python module from a file path."""
    module_name = f"bulwark_scanner_plugin_{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
