"""
Plugin Manager — Handles plugin lifecycle (install, uninstall, enable, disable).

Manages the plugin directory, performs security checks on plugin code,
and provides scanner instances to the pipeline.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import re
import shutil
import sys
from pathlib import Path
from typing import Union

from src.plugins.spec import PluginSpec, PluginType, load_plugin_spec, validate_plugin_spec
from src.scanners.protocol import InputScanner, OutputScanner, ScannerInfo, ScannerType

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Security patterns to flag in plugin source code
# --------------------------------------------------------------------------
_DANGEROUS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\beval\s*\("), "Use of eval() is forbidden"),
    (re.compile(r"\bexec\s*\("), "Use of exec() is forbidden"),
    (re.compile(r"\b__import__\s*\("), "Use of __import__() is forbidden"),
    (re.compile(r"\bos\.system\s*\("), "Use of os.system() is forbidden"),
    (re.compile(r"\bsubprocess\b"), "Use of subprocess module is forbidden"),
    (re.compile(r"\bpickle\b"), "Use of pickle module is forbidden"),
    (re.compile(r"\bshelve\b"), "Use of shelve module is forbidden"),
    (re.compile(r"\bctypes\b"), "Use of ctypes module is forbidden"),
    (re.compile(r"\bos\.exec"), "Use of os.exec* functions is forbidden"),
    (re.compile(r"\bos\.spawn"), "Use of os.spawn* functions is forbidden"),
]

# State file tracking enabled/disabled plugins
_STATE_FILE = "plugin-state.json"


class PluginManager:
    """Manages plugin lifecycle within a plugin directory.

    Attributes:
        plugin_dir: Root directory where plugins are stored.
    """

    def __init__(self, plugin_dir: Path) -> None:
        """Initialize the plugin manager.

        Args:
            plugin_dir: Directory where plugins are installed.
        """
        self.plugin_dir = plugin_dir
        self.plugin_dir.mkdir(parents=True, exist_ok=True)
        self._state_path = self.plugin_dir / _STATE_FILE
        self._state: dict[str, dict] = self._load_state()

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def _load_state(self) -> dict[str, dict]:
        """Load plugin state from disk."""
        if self._state_path.exists():
            try:
                with self._state_path.open("r", encoding="utf-8") as f:
                    return json.loads(f.read())
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("plugin_state_load_error", extra={"error": str(e)})
        return {}

    def _save_state(self) -> None:
        """Persist plugin state to disk."""
        with self._state_path.open("w", encoding="utf-8") as f:
            f.write(json.dumps(self._state, indent=2))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_installed(self) -> list[PluginSpec]:
        """List all installed plugins.

        Returns:
            List of PluginSpec for each installed plugin.
        """
        plugins: list[PluginSpec] = []
        for child in sorted(self.plugin_dir.iterdir()):
            if not child.is_dir():
                continue
            spec_file = child / "sentinel-plugin.yaml"
            if spec_file.exists():
                try:
                    spec = load_plugin_spec(spec_file)
                    plugins.append(spec)
                except Exception as e:
                    logger.warning(
                        "plugin_load_error",
                        extra={"path": str(child), "error": str(e)},
                    )
        return plugins

    def install(self, name: str, source: str = "hub") -> bool:
        """Install a plugin from the hub or a local path.

        Args:
            name: Plugin name or path to local plugin directory.
            source: 'hub' for marketplace or 'local' for filesystem path.

        Returns:
            True if installation succeeded, False otherwise.
        """
        if source == "local":
            source_path = Path(name)
            if not source_path.is_dir():
                logger.error("plugin_install_not_dir", extra={"path": name})
                return False

            spec_file = source_path / "sentinel-plugin.yaml"
            if not spec_file.exists():
                logger.error("plugin_install_no_spec", extra={"path": name})
                return False

            spec = load_plugin_spec(spec_file)
            errors = validate_plugin_spec(spec)
            if errors:
                for err in errors:
                    logger.error("plugin_spec_invalid", extra={"error": err})
                return False

            # Security check
            warnings = self._security_check(source_path)
            if warnings:
                for w in warnings:
                    logger.warning("plugin_security_warning", extra={"warning": w})
                return False

            # Copy to plugin directory
            dest = self.plugin_dir / spec.name
            if dest.exists():
                logger.error("plugin_already_installed", extra={"name": spec.name})
                return False

            shutil.copytree(source_path, dest)
            self._state[spec.name] = {"enabled": True, "version": spec.version}
            self._save_state()
            logger.info("plugin_installed", extra={"name": spec.name, "version": spec.version})
            return True

        elif source == "hub":
            # Hub integration placeholder — would fetch from remote registry
            logger.info(
                "plugin_hub_install",
                extra={"name": name, "status": "not_implemented"},
            )
            # TODO: Implement hub download, signature verification, install
            logger.warning(
                "plugin_hub_not_available",
                extra={"message": "Plugin hub is not yet available. Use source='local'."},
            )
            return False

        else:
            logger.error("plugin_install_unknown_source", extra={"source": source})
            return False

    def uninstall(self, name: str) -> bool:
        """Uninstall a plugin by name.

        Args:
            name: Plugin name to uninstall.

        Returns:
            True if uninstallation succeeded, False otherwise.
        """
        plugin_path = self.plugin_dir / name
        if not plugin_path.is_dir():
            logger.error("plugin_not_found", extra={"name": name})
            return False

        shutil.rmtree(plugin_path)
        self._state.pop(name, None)
        self._save_state()
        logger.info("plugin_uninstalled", extra={"name": name})
        return True

    def enable(self, name: str) -> bool:
        """Enable a disabled plugin.

        Args:
            name: Plugin name to enable.

        Returns:
            True if the plugin was enabled, False if not found.
        """
        plugin_path = self.plugin_dir / name
        if not plugin_path.is_dir():
            logger.error("plugin_not_found", extra={"name": name})
            return False

        if name not in self._state:
            self._state[name] = {"enabled": True}
        else:
            self._state[name]["enabled"] = True

        self._save_state()
        logger.info("plugin_enabled", extra={"name": name})
        return True

    def disable(self, name: str) -> bool:
        """Disable an enabled plugin.

        Args:
            name: Plugin name to disable.

        Returns:
            True if the plugin was disabled, False if not found.
        """
        plugin_path = self.plugin_dir / name
        if not plugin_path.is_dir():
            logger.error("plugin_not_found", extra={"name": name})
            return False

        if name not in self._state:
            self._state[name] = {"enabled": False}
        else:
            self._state[name]["enabled"] = False

        self._save_state()
        logger.info("plugin_disabled", extra={"name": name})
        return True

    def get_scanner(self, name: str) -> Union[InputScanner, OutputScanner, None]:
        """Load and return a scanner instance from an installed plugin.

        Args:
            name: Plugin name to load.

        Returns:
            An InputScanner or OutputScanner instance, or None if loading fails.
        """
        plugin_path = self.plugin_dir / name
        if not plugin_path.is_dir():
            logger.error("plugin_not_found", extra={"name": name})
            return None

        # Check enabled state
        state = self._state.get(name, {})
        if not state.get("enabled", True):
            logger.info("plugin_disabled_skip", extra={"name": name})
            return None

        # Load spec to determine scanner module
        try:
            spec = load_plugin_spec(plugin_path)
        except Exception as e:
            logger.error("plugin_spec_error", extra={"name": name, "error": str(e)})
            return None

        # Find scanner.py in plugin directory
        scanner_file = plugin_path / "scanner.py"
        if not scanner_file.exists():
            logger.error("plugin_no_scanner_module", extra={"name": name})
            return None

        # Dynamic import
        try:
            module_name = f"sentinel_plugin_{name.replace('-', '_')}"
            module_spec = importlib.util.spec_from_file_location(module_name, scanner_file)
            if module_spec is None or module_spec.loader is None:
                logger.error("plugin_import_failed", extra={"name": name})
                return None

            module = importlib.util.module_from_spec(module_spec)
            sys.modules[module_name] = module
            module_spec.loader.exec_module(module)  # type: ignore[union-attr]

            # Look for Scanner class
            scanner_cls = getattr(module, "Scanner", None)
            if scanner_cls is None:
                logger.error("plugin_no_scanner_class", extra={"name": name})
                return None

            instance = scanner_cls()

            if spec.type == PluginType.INPUT_SCANNER and isinstance(instance, InputScanner):
                return instance
            elif spec.type == PluginType.OUTPUT_SCANNER and isinstance(instance, OutputScanner):
                return instance
            else:
                logger.error(
                    "plugin_type_mismatch",
                    extra={"name": name, "declared": spec.type, "actual": type(instance).__name__},
                )
                return None

        except Exception as e:
            logger.error("plugin_load_error", extra={"name": name, "error": str(e)})
            return None

    def scaffold(self, name: str, output_dir: Path) -> Path:
        """Create a template plugin directory structure.

        Args:
            name: Plugin name (kebab-case).
            output_dir: Parent directory to create the plugin in.

        Returns:
            Path to the created plugin directory.
        """
        plugin_dir = output_dir / name
        plugin_dir.mkdir(parents=True, exist_ok=True)
        tests_dir = plugin_dir / "tests"
        tests_dir.mkdir(exist_ok=True)

        # sentinel-plugin.yaml
        spec_content = f"""name: {name}
version: 0.1.0
author: your-name
license: MIT
description: A custom Sentinel Gateway scanner plugin.
type: input_scanner
blocking: false
requires: {{}}
models: []
config:
  threshold:
    name: threshold
    type: float
    default: 0.7
    description: Detection confidence threshold (0.0-1.0)
"""
        (plugin_dir / "sentinel-plugin.yaml").write_text(spec_content, encoding="utf-8")

        # scanner.py
        scanner_content = f'''"""
{name} — Custom input scanner plugin for Sentinel Gateway.
"""

from __future__ import annotations

from src.models import GuardrailResult, Verdict
from src.scanners.protocol import InputScanner, ScanContext, ScannerInfo, ScannerType


class Scanner(InputScanner):
    """Custom input scanner.

    Implement your detection logic in the scan() method.
    """

    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="{name}",
            version="0.1.0",
            scanner_type=ScannerType.INPUT_ASYNC,
            description="Custom scanner plugin",
            author="your-name",
        )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Scan input content for threats.

        Args:
            content: Normalized text to scan.
            context: Request context with tenant/agent info.

        Returns:
            GuardrailResult with verdict.
        """
        # TODO: Implement your detection logic here
        return GuardrailResult(verdict=Verdict.ALLOW)

    async def startup(self) -> None:
        """Load models or warm caches on startup."""
        pass

    async def shutdown(self) -> None:
        """Release resources on shutdown."""
        pass
'''
        (plugin_dir / "scanner.py").write_text(scanner_content, encoding="utf-8")

        # tests/test_scanner.py
        test_content = f'''"""
Tests for {name} scanner plugin.
"""

import pytest

from scanner import Scanner
from src.models import Verdict
from src.scanners.protocol import ScanContext


@pytest.fixture
def scanner() -> Scanner:
    return Scanner()


@pytest.fixture
def context() -> ScanContext:
    return ScanContext(
        tenant_id="test-tenant",
        agent_id="test-agent",
        request_id="req-001",
        messages=[{{"role": "user", "content": "Hello world"}}],
    )


@pytest.mark.asyncio
async def test_allow_benign_input(scanner: Scanner, context: ScanContext) -> None:
    """Benign input should be allowed."""
    result = await scanner.scan("Hello, how can I help?", context)
    assert result.verdict == Verdict.ALLOW


@pytest.mark.asyncio
async def test_scanner_info(scanner: Scanner) -> None:
    """Scanner info should be populated."""
    info = scanner.info
    assert info.name == "{name}"
    assert info.version == "0.1.0"
'''
        (tests_dir / "test_scanner.py").write_text(test_content, encoding="utf-8")

        # README.md
        readme_content = f"""# {name}

A custom scanner plugin for Sentinel Gateway.

## Installation

```bash
sentinel plugin install ./{name} --source local
```

## Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| threshold | float | 0.7 | Detection confidence threshold |

## Development

```bash
# Run tests
cd {name}
pytest tests/ -v

# Test in sentinel
sentinel plugin test ./{name}
```
"""
        (plugin_dir / "README.md").write_text(readme_content, encoding="utf-8")

        logger.info("plugin_scaffolded", extra={"name": name, "path": str(plugin_dir)})
        return plugin_dir

    # ------------------------------------------------------------------
    # Security
    # ------------------------------------------------------------------

    def _security_check(self, plugin_path: Path) -> list[str]:
        """Scan plugin source files for dangerous patterns.

        Args:
            plugin_path: Root directory of the plugin to check.

        Returns:
            List of security warning strings. Empty if no issues found.
        """
        warnings: list[str] = []

        python_files = list(plugin_path.rglob("*.py"))
        for py_file in python_files:
            try:
                content = py_file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                warnings.append(f"Could not read file: {py_file.relative_to(plugin_path)}")
                continue

            for pattern, message in _DANGEROUS_PATTERNS:
                matches = pattern.findall(content)
                if matches:
                    rel_path = py_file.relative_to(plugin_path)
                    warnings.append(f"{rel_path}: {message} (found {len(matches)} occurrence(s))")

        return warnings
