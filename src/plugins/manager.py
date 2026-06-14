"""
Plugin Manager — Handles plugin lifecycle (install, uninstall, enable, disable).

Manages the plugin directory, performs security checks on plugin code,
and provides scanner instances to the pipeline.

SECURITY: All plugins are sandboxed at multiple levels:
1. AST-based static analysis at install time (blocks dangerous code patterns)
2. Restricted import system at runtime (only whitelisted modules)
3. Network access blocked during execution (no sockets)
4. Filesystem access restricted to plugin's own directory (read-only)
5. Execution timeout enforced (default 5s)
6. Decompression bomb protection at upload time
"""

from __future__ import annotations

import importlib.util
import json
import logging
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Union

from src.plugins.sandbox import (
    PluginSandbox,
    SandboxConfig,
    analyze_plugin_directory,
    analyze_plugin_source,
    StaticAnalysisResult,
)
from src.plugins.spec import PluginSpec, PluginType, load_plugin_spec, validate_plugin_spec
from src.scanners.protocol import InputScanner, OutputScanner, ScannerInfo

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# Legacy regex patterns (fast pre-filter, AST is authoritative)
# These catch blatant dangerous patterns. False negatives are caught by AST.
# Must NOT false-positive on legitimate code (re.compile, json.load, etc).
# --------------------------------------------------------------------------
_DANGEROUS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\beval\s*\("), "Use of eval() is forbidden"),
    (re.compile(r"\bexec\s*\("), "Use of exec() is forbidden"),
    (re.compile(r"\b__import__\s*\("), "Use of __import__() is forbidden"),
    (re.compile(r"\bos\.system\s*\("), "Use of os.system() is forbidden"),
    (re.compile(r"^\s*import\s+subprocess\b", re.MULTILINE), "Use of subprocess module is forbidden"),
    (re.compile(r"^\s*from\s+subprocess\b", re.MULTILINE), "Use of subprocess module is forbidden"),
    (re.compile(r"^\s*import\s+pickle\b", re.MULTILINE), "Use of pickle module is forbidden"),
    (re.compile(r"^\s*import\s+shelve\b", re.MULTILINE), "Use of shelve module is forbidden"),
    (re.compile(r"^\s*import\s+ctypes\b", re.MULTILINE), "Use of ctypes module is forbidden"),
    (re.compile(r"\bos\.exec"), "Use of os.exec* functions is forbidden"),
    (re.compile(r"\bos\.spawn"), "Use of os.spawn* functions is forbidden"),
    # Network / execution
    (re.compile(r"^\s*import\s+socket\b", re.MULTILINE), "Use of socket module is forbidden"),
    (re.compile(r"^\s*import\s+threading\b", re.MULTILINE), "Use of threading module is forbidden"),
    (re.compile(r"^\s*import\s+multiprocessing\b", re.MULTILINE), "Use of multiprocessing is forbidden"),
    (re.compile(r"\bos\.popen\s*\("), "Use of os.popen() is forbidden"),
    (re.compile(r"\bos\.fork\s*\("), "Use of os.fork() is forbidden"),
    # Obfuscation indicators (standalone compile, not re.compile)
    (re.compile(r"(?<!re\.)(?<!\w)compile\s*\("), "Use of compile() is suspicious (code execution)"),
    (re.compile(r"\bgetattr\s*\(\s*__builtins__"), "Accessing __builtins__ via getattr is forbidden"),
    (re.compile(r"\b__subclasses__\b"), "Access to __subclasses__ is forbidden"),
    (re.compile(r"\b__globals__\b"), "Access to __globals__ is forbidden"),
    (re.compile(r"\b__code__\b"), "Access to __code__ is forbidden"),
    (re.compile(r"^\s*import\s+importlib\b", re.MULTILINE), "Use of importlib is forbidden"),
]

# State file tracking enabled/disabled plugins
_STATE_FILE = "plugin-state.json"


class SandboxedScanner:
    """Wraps a plugin scanner so every scan() call executes inside the sandbox.

    This ensures that even if a plugin's __init__ passed, its scan() method
    cannot perform dangerous operations at runtime.

    Implements both InputScanner and OutputScanner interfaces transparently.
    """

    def __init__(
        self,
        scanner: Union[InputScanner, OutputScanner],
        sandbox: PluginSandbox,
        plugin_name: str,
    ) -> None:
        self._scanner = scanner
        self._sandbox = sandbox
        self._plugin_name = plugin_name

    @property
    def info(self) -> ScannerInfo:
        """Delegate to wrapped scanner."""
        return self._scanner.info

    async def scan(self, content: str, context: Any) -> Any:
        """Execute scan() inside the sandbox.

        Protections active during scan:
        - Import restrictions (only whitelisted modules)
        - Network blocked (no sockets)
        - Filesystem restricted (read-only, plugin dir only)
        - Timeout enforced (5s default)
        """
        from src.models import GuardrailResult, Verdict

        try:
            with self._sandbox.activate():
                result = await self._scanner.scan(content, context)
            return result
        except TimeoutError:
            logger.critical(
                "plugin_scan_timeout",
                extra={"plugin": self._plugin_name},
            )
            # SECURITY (H-10 fix): Fail-CLOSED. A timed-out plugin cannot
            # guarantee content safety. Block rather than allow unscanned.
            return GuardrailResult(verdict=Verdict.BLOCK)
        except (PermissionError, ImportError) as e:
            logger.critical(
                "plugin_scan_sandbox_violation",
                extra={"plugin": self._plugin_name, "error": str(e)},
            )
            # SECURITY (H-10 fix): Sandbox escape attempt = immediate BLOCK.
            # This indicates the plugin is actively trying to break out.
            return GuardrailResult(verdict=Verdict.BLOCK)
        except Exception as e:
            logger.error(
                "plugin_scan_error",
                extra={"plugin": self._plugin_name, "error": str(e)},
            )
            # SECURITY (H-10 fix): Unhandled crash = BLOCK (fail-closed).
            # A malicious plugin could auto-crash to disable detection.
            return GuardrailResult(verdict=Verdict.BLOCK)

    async def startup(self) -> None:
        """Delegate startup (sandboxed)."""
        try:
            with self._sandbox.activate():
                await self._scanner.startup()
        except Exception as e:
            logger.warning(
                "plugin_startup_error",
                extra={"plugin": self._plugin_name, "error": str(e)},
            )

    async def shutdown(self) -> None:
        """Delegate shutdown (sandboxed)."""
        try:
            with self._sandbox.activate():
                await self._scanner.shutdown()
        except Exception:
            pass

    # Make isinstance() checks work
    def __class_getitem__(cls, item):
        return cls


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
                logger.error("plugin_already_installed", extra={"plugin_name": spec.name})
                return False

            shutil.copytree(source_path, dest)
            self._state[spec.name] = {"enabled": True, "version": spec.version}
            self._save_state()
            logger.info("plugin_installed", extra={"plugin_name": spec.name, "version": spec.version})
            return True

        elif source == "hub":
            # Hub integration placeholder — would fetch from remote registry
            logger.info(
                "plugin_hub_install",
                extra={"plugin_name": name, "status": "not_implemented"},
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
            logger.error("plugin_not_found", extra={"plugin_name": name})
            return False

        shutil.rmtree(plugin_path)
        self._state.pop(name, None)
        self._save_state()
        logger.info("plugin_uninstalled", extra={"plugin_name": name})
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
            logger.error("plugin_not_found", extra={"plugin_name": name})
            return False

        if name not in self._state:
            self._state[name] = {"enabled": True}
        else:
            self._state[name]["enabled"] = True

        self._save_state()
        logger.info("plugin_enabled", extra={"plugin_name": name})
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
            logger.error("plugin_not_found", extra={"plugin_name": name})
            return False

        if name not in self._state:
            self._state[name] = {"enabled": False}
        else:
            self._state[name]["enabled"] = False

        self._save_state()
        logger.info("plugin_disabled", extra={"plugin_name": name})
        return True

    def get_scanner(self, name: str) -> Union[InputScanner, OutputScanner, None]:
        """Load and return a SANDBOXED scanner instance from an installed plugin.

        SECURITY: The scanner is loaded inside a sandbox that:
        1. Re-validates source via AST analysis before loading
        2. Restricts imports to whitelisted modules during exec_module
        3. Scanner.scan() must be called within sandbox.activate() context

        Args:
            name: Plugin name to load.

        Returns:
            An InputScanner or OutputScanner instance, or None if loading fails.
        """
        plugin_path = self.plugin_dir / name
        if not plugin_path.is_dir():
            logger.error("plugin_not_found", extra={"plugin_name": name})
            return None

        # Check enabled state
        state = self._state.get(name, {})
        if not state.get("enabled", True):
            logger.info("plugin_disabled_skip", extra={"plugin_name": name})
            return None

        # Load spec to determine scanner module
        try:
            spec = load_plugin_spec(plugin_path)
        except Exception as e:
            logger.error("plugin_spec_error", extra={"plugin_name": name, "error": str(e)})
            return None

        # Find scanner.py in plugin directory
        scanner_file = plugin_path / "scanner.py"
        if not scanner_file.exists():
            logger.error("plugin_no_scanner_module", extra={"plugin_name": name})
            return None

        # SECURITY: Re-validate source at load time (defense-in-depth)
        try:
            source_code = scanner_file.read_text(encoding="utf-8")
            ast_result = analyze_plugin_source(source_code, filename=f"{name}/scanner.py")
            if not ast_result.safe:
                logger.critical(
                    "plugin_ast_blocked_at_load",
                    extra={
                        "plugin_name": name,
                        "risk_score": ast_result.risk_score,
                        "findings": len(ast_result.findings),
                        "top_finding": ast_result.findings[0].message if ast_result.findings else "",
                    },
                )
                return None
        except Exception as e:
            logger.error("plugin_ast_check_failed", extra={"plugin_name": name, "error": str(e)})
            return None

        # Dynamic import WITH sandbox active (restricts what the module can do on import)
        sandbox = PluginSandbox(name, plugin_path, SandboxConfig(timeout_seconds=10.0))

        try:
            module_name = f"sentinel_plugin_{name.replace('-', '_')}"

            # Remove cached module if exists (force re-import with sandbox)
            sys.modules.pop(module_name, None)

            module_spec = importlib.util.spec_from_file_location(module_name, scanner_file)
            if module_spec is None or module_spec.loader is None:
                logger.error("plugin_import_failed", extra={"plugin_name": name})
                return None

            module = importlib.util.module_from_spec(module_spec)
            sys.modules[module_name] = module

            # Execute module INSIDE sandbox (blocks dangerous imports/network/fs)
            with sandbox.activate():
                module_spec.loader.exec_module(module)  # type: ignore[union-attr]

            # Look for Scanner class
            scanner_cls = getattr(module, "Scanner", None)
            if scanner_cls is None:
                logger.error("plugin_no_scanner_class", extra={"plugin_name": name})
                return None

            instance = scanner_cls()

            if spec.type == PluginType.INPUT_SCANNER and isinstance(instance, InputScanner):
                # Wrap the scanner in a sandboxed proxy
                return SandboxedScanner(instance, sandbox, name)  # type: ignore[return-value]
            elif spec.type == PluginType.OUTPUT_SCANNER and isinstance(instance, OutputScanner):
                return SandboxedScanner(instance, sandbox, name)  # type: ignore[return-value]
            else:
                logger.error(
                    "plugin_type_mismatch",
                    extra={"plugin_name": name, "declared": spec.type, "actual": type(instance).__name__},
                )
                return None

        except (ImportError, PermissionError, TimeoutError) as e:
            logger.critical(
                "plugin_sandbox_violation_at_load",
                extra={"plugin_name": name, "error": str(e), "type": type(e).__name__},
            )
            # Remove from sys.modules on failure
            sys.modules.pop(f"sentinel_plugin_{name.replace('-', '_')}", None)
            return None
        except Exception as e:
            logger.error("plugin_load_error", extra={"plugin_name": name, "error": str(e)})
            sys.modules.pop(f"sentinel_plugin_{name.replace('-', '_')}", None)
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

        logger.info("plugin_scaffolded", extra={"plugin_name": name, "path": str(plugin_dir)})
        return plugin_dir

    # ------------------------------------------------------------------
    # Security
    # ------------------------------------------------------------------

    def _security_check(self, plugin_path: Path) -> list[str]:
        """Scan plugin source files for dangerous patterns using BOTH regex AND AST.

        This runs at INSTALL time. Both checks must pass for installation to proceed.

        Layer 1: Regex patterns (fast pre-filter, catches obvious issues)
        Layer 2: AST analysis (catches obfuscation, dynamic imports, getattr tricks)

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

            rel_path = py_file.relative_to(plugin_path)

            # Layer 1: Regex patterns (fast)
            for pattern, message in _DANGEROUS_PATTERNS:
                matches = pattern.findall(content)
                if matches:
                    warnings.append(f"{rel_path}: {message} (found {len(matches)} occurrence(s))")

            # Layer 2: AST analysis (thorough)
            ast_result = analyze_plugin_source(content, filename=str(rel_path))
            for finding in ast_result.findings:
                warnings.append(
                    f"{rel_path}:{finding.line}: [{finding.severity.upper()}] "
                    f"{finding.category}: {finding.message}"
                )

        return warnings

    def security_audit(self, name: str) -> StaticAnalysisResult:
        """Run a complete security audit on an installed plugin.

        Returns the full AST analysis result with structured findings.
        Used by the admin UI security check endpoint.

        Args:
            name: Plugin name to audit.

        Returns:
            StaticAnalysisResult with findings, score, and verdict.
        """
        plugin_path = self.plugin_dir / name
        if not plugin_path.is_dir():
            from src.plugins.sandbox import SecurityFinding as SF
            return StaticAnalysisResult(
                safe=False,
                findings=[SF(
                    severity="critical",
                    category="not_found",
                    message=f"Plugin '{name}' not found",
                )],
                risk_score=10.0,
            )

        return analyze_plugin_directory(plugin_path)
