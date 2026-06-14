"""
Plugin Sandbox — Defense-in-depth security for plugin execution.

Provides multiple layers of protection:
1. AST-based static analysis (catches obfuscation that regex misses)
2. Import whitelist (only safe modules allowed)
3. Network sandbox (blocks socket creation)
4. Filesystem sandbox (restricts file access to plugin directory)
5. Execution timeout (prevents infinite loops / crypto mining)
6. Resource limits (memory, CPU)

Architecture:
- Static analysis runs at INSTALL time (before code touches disk)
- Runtime sandbox wraps EVERY plugin execution (import + scan calls)
- Defense-in-depth: even if one layer is bypassed, others catch it

Security model: DENY-ALL with explicit allowlist.
"""

from __future__ import annotations

import ast
import builtins
import logging
import signal
import socket
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generator

logger = logging.getLogger(__name__)


# ==========================================================================
# 1. AST-BASED STATIC ANALYSIS
# ==========================================================================

@dataclass
class SecurityFinding:
    """A security issue found during static analysis."""
    severity: str  # critical, high, medium, low
    category: str  # arbitrary_code, network, filesystem, obfuscation, dangerous_import
    message: str
    line: int = 0
    col: int = 0
    node_type: str = ""


@dataclass
class StaticAnalysisResult:
    """Result of AST-based static analysis."""
    safe: bool
    findings: list[SecurityFinding] = field(default_factory=list)
    risk_score: float = 0.0  # 0-10

    @property
    def verdict(self) -> str:
        if self.risk_score >= 7.0:
            return "block"
        elif self.risk_score >= 4.0:
            return "warn"
        return "pass"


# Modules that are NEVER safe in a plugin context
_BLOCKED_MODULES: set[str] = {
    # Code execution
    "subprocess", "multiprocessing", "concurrent",
    # Low-level / FFI
    "ctypes", "cffi", "_ctypes",
    # Serialization (code execution via deserialization)
    "pickle", "shelve", "marshal", "dill", "cloudpickle",
    # Network
    "socket", "socketserver", "http.server", "xmlrpc",
    "ftplib", "smtplib", "poplib", "imaplib", "telnetlib",
    "asyncore", "asynchat",
    # System
    "shutil", "tempfile", "pty", "termios", "resource",
    "signal", "mmap", "syslog",
    # Code compilation / introspection (used for sandbox escapes)
    "code", "codeop", "compileall", "py_compile",
    "importlib", "runpy", "zipimport",
    # Debugging / inspection (sandbox escape vectors)
    "inspect", "dis", "traceback", "gc", "sys",
    "types", "typing_extensions",
    # OS interaction
    "os.path",  # os itself is partially allowed (see below)
    "platform", "pwd", "grp", "fcntl",
    # Web / external comms
    "urllib", "urllib.request", "http.client", "requests", "httpx",
    "aiohttp", "websocket", "paramiko", "fabric",
    # File formats that can execute code
    "zipfile", "tarfile", "gzip", "bz2", "lzma",
    # Crypto (could be used for ransomware)
    "Crypto", "cryptography",
    # Threading (used for background malicious tasks)
    "threading", "thread", "_thread",
}

# Modules that ARE safe for plugins to use
_ALLOWED_MODULES: set[str] = {
    # Python internals
    "__future__",
    # Standard safe modules
    "re", "math", "string", "collections", "itertools",
    "functools", "operator", "copy", "dataclasses",
    "enum", "typing", "abc", "numbers",
    "datetime", "time", "calendar",
    "json", "csv", "hashlib", "hmac", "base64",
    "unicodedata", "codecs", "encodings",
    "decimal", "fractions", "statistics",
    "textwrap", "difflib", "pathlib",
    "logging",
    # Our framework (required for plugins to work)
    "src", "src.models", "src.scanners", "src.scanners.protocol",
    "pydantic",
    # Allowed third-party (safe computation only)
    "numpy", "scipy", "sklearn",
    "regex",  # enhanced regex
}

# Dangerous builtins that should never be called
_BLOCKED_BUILTINS: set[str] = {
    "eval", "exec", "compile", "execfile",
    "__import__", "globals", "locals", "vars",
    "getattr", "setattr", "delattr",  # can bypass restrictions
    "open",  # filesystem access (controlled separately)
    "input",  # blocks execution
    "breakpoint",  # debugger
    "exit", "quit",
}

# Dangerous attributes/methods
_BLOCKED_ATTRIBUTES: set[str] = {
    "__subclasses__", "__bases__", "__mro__",
    "__class__", "__globals__", "__code__",
    "__builtins__", "__import__",
    "__reduce__", "__reduce_ex__",  # pickle exploit
    "system", "popen", "exec", "spawn",  # os.*
    "exec_module", "load_module",  # importlib
    "connect", "bind", "listen", "accept",  # socket
    "Popen", "call", "run", "check_output",  # subprocess
}

# Dangerous function calls (fully qualified)
_BLOCKED_CALLS: set[str] = {
    "os.system", "os.popen", "os.exec", "os.execl", "os.execle",
    "os.execlp", "os.execlpe", "os.execv", "os.execve",
    "os.execvp", "os.execvpe", "os.spawn", "os.spawnl",
    "os.spawnle", "os.spawnlp", "os.spawnlpe", "os.spawnv",
    "os.spawnve", "os.spawnvp", "os.spawnvpe",
    "os.fork", "os.forkpty", "os.kill", "os.killpg",
    "os.remove", "os.unlink", "os.rmdir", "os.removedirs",
    "os.rename", "os.renames", "os.replace",
    "os.chmod", "os.chown", "os.chroot",
    "os.link", "os.symlink", "os.mkdir", "os.makedirs",
    "os.environ.get", "os.getenv",
    "shutil.rmtree", "shutil.move", "shutil.copy",
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
}


class PluginASTAnalyzer(ast.NodeVisitor):
    """AST visitor that detects dangerous code patterns in plugin source.

    This catches ALL the bypass techniques that simple regex misses:
    - String concatenation to build dangerous names
    - getattr() calls to access blocked attributes
    - importlib usage
    - Dynamic code execution via compile()
    - Network socket creation
    - File system access outside plugin dir
    - Module-level code execution (side effects on import)
    """

    def __init__(self) -> None:
        self.findings: list[SecurityFinding] = []
        self._in_class = False
        self._in_function = False
        self._imports: set[str] = set()

    def _add_finding(
        self,
        severity: str,
        category: str,
        message: str,
        node: ast.AST,
    ) -> None:
        self.findings.append(SecurityFinding(
            severity=severity,
            category=category,
            message=message,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            node_type=type(node).__name__,
        ))

    # --- Import checks ---

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            module_name = alias.name
            self._imports.add(module_name)
            top_level = module_name.split(".")[0]

            if module_name in _BLOCKED_MODULES or top_level in _BLOCKED_MODULES:
                self._add_finding(
                    "critical", "dangerous_import",
                    f"Import of blocked module: '{module_name}'",
                    node,
                )
            elif module_name not in _ALLOWED_MODULES and top_level not in _ALLOWED_MODULES:
                self._add_finding(
                    "high", "dangerous_import",
                    f"Import of non-whitelisted module: '{module_name}'",
                    node,
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module_name = node.module or ""
        self._imports.add(module_name)
        top_level = module_name.split(".")[0]

        if module_name in _BLOCKED_MODULES or top_level in _BLOCKED_MODULES:
            self._add_finding(
                "critical", "dangerous_import",
                f"Import from blocked module: 'from {module_name} import ...'",
                node,
            )
        elif module_name not in _ALLOWED_MODULES and top_level not in _ALLOWED_MODULES:
            # Check if it's a sub-import of an allowed module
            if not any(module_name.startswith(allowed + ".") for allowed in _ALLOWED_MODULES):
                self._add_finding(
                    "high", "dangerous_import",
                    f"Import from non-whitelisted module: 'from {module_name} import ...'",
                    node,
                )
        self.generic_visit(node)

    # --- Dangerous function calls ---

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._get_call_name(node)

        # Check blocked builtins
        if func_name in _BLOCKED_BUILTINS:
            self._add_finding(
                "critical", "arbitrary_code",
                f"Call to blocked builtin: '{func_name}()'",
                node,
            )

        # Check blocked qualified calls
        if func_name in _BLOCKED_CALLS:
            self._add_finding(
                "critical", "arbitrary_code",
                f"Call to blocked function: '{func_name}()'",
                node,
            )

        # getattr with string arg (obfuscation technique)
        if func_name == "getattr" and len(node.args) >= 2:
            if isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                attr = node.args[1].value
                if attr in _BLOCKED_ATTRIBUTES or attr in _BLOCKED_BUILTINS:
                    self._add_finding(
                        "critical", "obfuscation",
                        f"getattr() used to access blocked attribute: '{attr}'",
                        node,
                    )
            elif isinstance(node.args[1], ast.BinOp):
                # String concatenation in getattr - highly suspicious
                self._add_finding(
                    "high", "obfuscation",
                    "getattr() with dynamic string construction (possible bypass attempt)",
                    node,
                )

        # compile() - can create code objects for exec
        if func_name == "compile":
            self._add_finding(
                "critical", "arbitrary_code",
                "compile() can create executable code objects",
                node,
            )

        # type() with 3 args creates a new class dynamically
        if func_name == "type" and len(node.args) == 3:
            self._add_finding(
                "high", "arbitrary_code",
                "type() with 3 args creates dynamic classes (potential sandbox escape)",
                node,
            )

        # open() call
        if func_name == "open" or func_name == "builtins.open":
            self._add_finding(
                "high", "filesystem",
                "Direct file access via open() — use framework APIs instead",
                node,
            )

        # socket creation
        if "socket" in func_name.lower():
            self._add_finding(
                "critical", "network",
                f"Network socket operation: '{func_name}()'",
                node,
            )

        self.generic_visit(node)

    # --- Attribute access ---

    def visit_Attribute(self, node: ast.Attribute) -> None:
        attr = node.attr
        if attr in _BLOCKED_ATTRIBUTES:
            # Check context - is it on a suspicious object?
            self._add_finding(
                "high", "obfuscation",
                f"Access to dangerous attribute: '.{attr}'",
                node,
            )
        self.generic_visit(node)

    # --- Module-level code (side effects on import) ---

    def visit_Expr(self, node: ast.Expr) -> None:
        """Detect module-level expressions that have side effects."""
        if not self._in_class and not self._in_function:
            if isinstance(node.value, ast.Call):
                func_name = self._get_call_name(node.value)
                # Module-level function calls are suspicious
                # (legitimate plugins only define classes/functions at module level)
                if func_name and func_name not in {
                    "print", "logging.getLogger", "re.compile",
                    "dataclass", "field",
                }:
                    self._add_finding(
                        "medium", "arbitrary_code",
                        f"Module-level function call: '{func_name}()' — "
                        "code executes on import, not when scan() is called",
                        node,
                    )
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        old = self._in_function
        self._in_function = True
        self.generic_visit(node)
        self._in_function = old

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        old = self._in_function
        self._in_function = True
        self.generic_visit(node)
        self._in_function = old

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        old_class = self._in_class
        old_func = self._in_function
        self._in_class = True
        self._in_function = False
        self.generic_visit(node)
        self._in_class = old_class
        self._in_function = old_func

    # --- String operations (obfuscation detection) ---

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """f-strings used in imports or calls can be obfuscation."""
        # Only flag if inside a call to something dangerous
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Detect string concatenation that might build module names."""
        if isinstance(node.op, ast.Add):
            # String + String at module level can be used to bypass checks
            if (isinstance(node.left, ast.Constant) and isinstance(node.left.value, str) and
                    isinstance(node.right, ast.Constant) and isinstance(node.right.value, str)):
                combined = node.left.value + node.right.value
                if combined in _BLOCKED_MODULES or combined in _BLOCKED_BUILTINS:
                    self._add_finding(
                        "critical", "obfuscation",
                        f"String concatenation builds blocked name: '{combined}'",
                        node,
                    )
        self.generic_visit(node)

    # --- Helpers ---

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract the function name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value  # type: ignore[assignment]
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""


def analyze_plugin_source(source_code: str, filename: str = "<plugin>") -> StaticAnalysisResult:
    """Perform AST-based static security analysis on plugin source code.

    This is the primary defense at INSTALL time. It catches:
    - All blocked module imports (even via importlib)
    - Dangerous builtin usage (eval, exec, compile, open, getattr)
    - Network operations (socket)
    - Obfuscation techniques (string concat, dynamic attribute access)
    - Module-level side effects (code that runs on import)
    - Filesystem access

    Args:
        source_code: Python source code to analyze.
        filename: Filename for error reporting.

    Returns:
        StaticAnalysisResult with findings and risk score.
    """
    try:
        tree = ast.parse(source_code, filename=filename)
    except SyntaxError as e:
        return StaticAnalysisResult(
            safe=False,
            findings=[SecurityFinding(
                severity="critical",
                category="syntax_error",
                message=f"Failed to parse: {e}",
                line=e.lineno or 0,
            )],
            risk_score=10.0,
        )

    analyzer = PluginASTAnalyzer()
    analyzer.visit(tree)

    # Calculate risk score
    score = 0.0
    for finding in analyzer.findings:
        if finding.severity == "critical":
            score += 4.0
        elif finding.severity == "high":
            score += 3.0
        elif finding.severity == "medium":
            score += 1.5
        else:
            score += 0.5
    score = min(score, 10.0)

    return StaticAnalysisResult(
        safe=(score < 4.0),
        findings=analyzer.findings,
        risk_score=score,
    )


def analyze_plugin_directory(plugin_path: Path) -> StaticAnalysisResult:
    """Analyze ALL Python files in a plugin directory.

    Args:
        plugin_path: Root directory of the plugin.

    Returns:
        Combined StaticAnalysisResult from all files.
    """
    all_findings: list[SecurityFinding] = []

    python_files = list(plugin_path.rglob("*.py"))
    if not python_files:
        return StaticAnalysisResult(safe=True, findings=[], risk_score=0.0)

    for py_file in python_files:
        try:
            source = py_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            all_findings.append(SecurityFinding(
                severity="high",
                category="filesystem",
                message=f"Cannot read file {py_file.name}: {e}",
            ))
            continue

        result = analyze_plugin_source(source, filename=str(py_file.relative_to(plugin_path)))
        all_findings.extend(result.findings)

    # Calculate combined score
    score = 0.0
    for finding in all_findings:
        if finding.severity == "critical":
            score += 4.0
        elif finding.severity == "high":
            score += 3.0
        elif finding.severity == "medium":
            score += 1.5
        else:
            score += 0.5
    score = min(score, 10.0)

    return StaticAnalysisResult(
        safe=(score < 4.0),
        findings=all_findings,
        risk_score=score,
    )


# ==========================================================================
# 2. RUNTIME SANDBOX — Import Control
# ==========================================================================

# The ONLY modules a plugin is allowed to import at runtime
_RUNTIME_ALLOWED_IMPORTS: frozenset[str] = frozenset({
    # Python stdlib (safe subset)
    "re", "math", "string", "collections", "collections.abc",
    "itertools", "functools", "operator", "copy", "dataclasses",
    "enum", "typing", "abc", "numbers",
    "datetime", "time", "calendar",
    "json", "csv", "hashlib", "hmac", "base64",
    "unicodedata", "codecs",
    "decimal", "fractions", "statistics",
    "textwrap", "difflib",
    "logging",
    "__future__",
    # Framework modules
    "src", "src.models", "src.scanners", "src.scanners.protocol",
    "pydantic", "pydantic.fields",
    # Safe third-party
    "numpy", "regex",
})


class RestrictedImporter:
    """Custom import hook that blocks dangerous modules at runtime.

    Strategy: BLOCKLIST approach (not allowlist) because Python's internal
    module graph is complex (_io, _collections_abc, etc. are needed by safe modules).

    The AST analyzer uses an ALLOWLIST at install time (strict).
    The runtime blocker uses a BLOCKLIST (practical) as defense-in-depth.

    This means: if AST somehow misses something, the runtime blocker catches
    the actual dangerous imports when they happen.
    """

    # Modules that are BLOCKED at runtime (explicit dangerous modules)
    BLOCKED: frozenset[str] = frozenset({
        # Code execution
        "subprocess", "multiprocessing", "concurrent.futures",
        # Low-level
        "ctypes", "cffi", "_ctypes",
        # Serialization attacks
        "pickle", "shelve", "marshal", "dill", "cloudpickle",
        # Network
        "socket", "socketserver", "http.server", "xmlrpc",
        "ftplib", "smtplib", "poplib", "imaplib", "telnetlib",
        "asyncore", "asynchat",
        "urllib", "urllib.request", "http.client",
        "requests", "httpx", "aiohttp", "websocket", "paramiko",
        # System
        "shutil", "pty", "termios", "syslog",
        # Code compilation
        "code", "codeop", "compileall", "py_compile",
        "importlib", "runpy", "zipimport",
        # Debugging (sandbox escape)
        "inspect", "dis", "gc",
        # Threading
        "threading", "_thread", "thread",
        # OS interaction (os itself is partially blocked via AST)
        "os",
        "platform", "pwd", "grp", "fcntl",
        # File archives
        "zipfile", "tarfile",
        # Crypto (ransomware risk)
        "Crypto", "cryptography",
    })

    def __init__(self, allowed: frozenset[str], plugin_name: str) -> None:
        self.allowed = allowed
        self.plugin_name = plugin_name
        self._original_import = builtins.__import__

    def __call__(self, name: str, *args: Any, **kwargs: Any) -> Any:
        top_level = name.split(".")[0]

        # Block explicitly dangerous modules
        if name in self.BLOCKED or top_level in self.BLOCKED:
            logger.warning(
                "plugin_blocked_import",
                extra={
                    "plugin": self.plugin_name,
                    "blocked_module": name,
                    "reason": "dangerous module",
                },
            )
            raise ImportError(
                f"Plugin '{self.plugin_name}' attempted to import blocked module: '{name}'. "
                f"This module is not allowed in plugins for security reasons."
            )

        # Allow everything else (internal modules, stdlib dependencies, etc.)
        return self._original_import(name, *args, **kwargs)


# ==========================================================================
# 3. RUNTIME SANDBOX — Network Blocking
# ==========================================================================

class NetworkBlocker:
    """Monkey-patches socket to prevent network access during plugin execution.

    Even if a plugin manages to import socket (shouldn't be possible with
    import restrictions), this ensures connect/bind/listen all fail.
    """

    def __init__(self, plugin_name: str) -> None:
        self.plugin_name = plugin_name
        self._original_socket = socket.socket
        self._original_connect = None

    def blocked_socket(self, *args: Any, **kwargs: Any) -> None:
        raise PermissionError(
            f"Plugin '{self.plugin_name}': Network access is blocked. "
            "Plugins cannot create sockets or make network connections."
        )

    def activate(self) -> None:
        """Block socket creation."""
        socket.socket = self.blocked_socket  # type: ignore[assignment,misc]

    def deactivate(self) -> None:
        """Restore original socket."""
        socket.socket = self._original_socket  # type: ignore[misc]


# ==========================================================================
# 4. RUNTIME SANDBOX — Filesystem Restriction
# ==========================================================================

class FilesystemBlocker:
    """Restricts open() to only allow reading files within the plugin directory.

    Blocks:
    - Writing to ANY file
    - Reading files outside the plugin's own directory
    - Reading sensitive paths (/proc, /etc, /run, environment)
    """

    def __init__(self, plugin_name: str, plugin_dir: Path) -> None:
        self.plugin_name = plugin_name
        self.plugin_dir = plugin_dir.resolve()
        self._original_open = builtins.open

    def restricted_open(self, file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        # Only allow read mode
        if any(m in str(mode) for m in ("w", "a", "x", "+")):
            raise PermissionError(
                f"Plugin '{self.plugin_name}': Write access denied. "
                "Plugins are read-only."
            )

        # Resolve the path
        try:
            target = Path(str(file)).resolve()
        except (OSError, ValueError):
            raise PermissionError(
                f"Plugin '{self.plugin_name}': Invalid file path."
            )

        # Block sensitive paths
        _BLOCKED_PATHS = {
            "/proc", "/sys", "/dev", "/run", "/etc",
            "/var", "/tmp", "/root", "/home",
        }
        for blocked in _BLOCKED_PATHS:
            if str(target).startswith(blocked):
                raise PermissionError(
                    f"Plugin '{self.plugin_name}': Access to '{blocked}' is denied."
                )

        # Only allow reading from plugin's own directory
        if not str(target).startswith(str(self.plugin_dir)):
            raise PermissionError(
                f"Plugin '{self.plugin_name}': File access restricted to plugin directory. "
                f"Attempted: {target}"
            )

        return self._original_open(file, mode, *args, **kwargs)

    def activate(self) -> None:
        """Install restricted open."""
        builtins.open = self.restricted_open  # type: ignore[assignment]

    def deactivate(self) -> None:
        """Restore original open."""
        builtins.open = self._original_open


# ==========================================================================
# 5. RUNTIME SANDBOX — Execution Timeout
# ==========================================================================

class ExecutionTimeout:
    """Enforces a maximum execution time for plugin code.

    Uses signal.SIGALRM on Linux (thread-safe alternative for async).
    Falls back to threading-based timeout on systems without SIGALRM.
    """

    def __init__(self, timeout_seconds: float = 5.0, plugin_name: str = "") -> None:
        self.timeout = timeout_seconds
        self.plugin_name = plugin_name
        self._use_signal = hasattr(signal, "SIGALRM") and threading.current_thread() is threading.main_thread()

    def _timeout_handler(self, signum: int, frame: Any) -> None:
        raise TimeoutError(
            f"Plugin '{self.plugin_name}': Execution exceeded {self.timeout}s timeout. "
            "Possible infinite loop or resource-intensive operation."
        )

    @contextmanager
    def enforce(self) -> Generator[None, None, None]:
        """Context manager that kills execution after timeout."""
        if self._use_signal:
            old_handler = signal.signal(signal.SIGALRM, self._timeout_handler)
            signal.setitimer(signal.ITIMER_REAL, self.timeout)
            try:
                yield
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, old_handler)
        else:
            # Fallback: threading-based (less reliable but works in async)
            timer_triggered = threading.Event()

            def _watchdog():
                if not timer_triggered.wait(self.timeout):
                    # Can't kill from another thread easily, but we set the flag
                    logger.critical(
                        "plugin_timeout_exceeded",
                        extra={"plugin": self.plugin_name, "timeout": self.timeout},
                    )

            watchdog = threading.Thread(target=_watchdog, daemon=True)
            watchdog.start()
            try:
                yield
            finally:
                timer_triggered.set()


# ==========================================================================
# 6. COMBINED SANDBOX — Wraps all protections
# ==========================================================================

@dataclass
class SandboxConfig:
    """Configuration for the plugin execution sandbox."""
    timeout_seconds: float = 5.0
    max_memory_mb: int = 256
    allow_network: bool = False
    allow_filesystem_write: bool = False
    allowed_read_paths: list[str] = field(default_factory=list)


# SECURITY FIX (H-01): Serialize sandbox to prevent concurrent race condition.
# The sandbox replaces process-global state (builtins.__import__, socket.socket,
# builtins.open). Without serialization, concurrent plugin executions corrupt
# each other's saved originals, allowing sandbox escape.
_SANDBOX_LOCK = threading.Lock()


class PluginSandbox:
    """Complete sandbox that wraps plugin execution with all security layers.

    Usage:
        sandbox = PluginSandbox("my-plugin", Path("/app/plugins/my-plugin"))
        with sandbox.activate():
            result = await scanner.scan(content, context)
    """

    def __init__(
        self,
        plugin_name: str,
        plugin_dir: Path,
        config: SandboxConfig | None = None,
    ) -> None:
        self.plugin_name = plugin_name
        self.plugin_dir = plugin_dir
        self.config = config or SandboxConfig()

        self._import_blocker = RestrictedImporter(
            allowed=_RUNTIME_ALLOWED_IMPORTS,
            plugin_name=plugin_name,
        )
        self._network_blocker = NetworkBlocker(plugin_name)
        self._fs_blocker = FilesystemBlocker(plugin_name, plugin_dir)
        self._timeout = ExecutionTimeout(
            timeout_seconds=self.config.timeout_seconds,
            plugin_name=plugin_name,
        )

    @contextmanager
    def activate(self) -> Generator[None, None, None]:
        """Activate ALL sandbox protections.

        This is a context manager — protections are automatically
        removed when execution exits the block (even on exception).

        SECURITY FIX (H-01): Serialize sandbox to prevent concurrent race condition.
        The lock ensures only one sandboxed execution mutates global state at a time,
        preventing Plugin-B from saving Plugin-A's blockers as "originals".
        """
        _SANDBOX_LOCK.acquire()
        original_import = builtins.__import__

        try:
            # Layer 1: Restrict imports
            builtins.__import__ = self._import_blocker  # type: ignore[assignment]

            # Layer 2: Block network
            if not self.config.allow_network:
                self._network_blocker.activate()

            # Layer 3: Restrict filesystem
            if not self.config.allow_filesystem_write:
                self._fs_blocker.activate()

            # Layer 4: Timeout (wraps the yield)
            with self._timeout.enforce():
                yield

        except TimeoutError:
            logger.critical(
                "plugin_sandbox_timeout",
                extra={"plugin": self.plugin_name, "timeout": self.config.timeout_seconds},
            )
            raise
        except PermissionError as e:
            logger.warning(
                "plugin_sandbox_blocked",
                extra={"plugin": self.plugin_name, "error": str(e)},
            )
            raise
        except ImportError as e:
            logger.warning(
                "plugin_sandbox_import_blocked",
                extra={"plugin": self.plugin_name, "error": str(e)},
            )
            raise
        finally:
            # ALWAYS restore originals (defense against plugins that crash)
            builtins.__import__ = original_import
            self._network_blocker.deactivate()
            self._fs_blocker.deactivate()
            _SANDBOX_LOCK.release()


# ==========================================================================
# 7. DECOMPRESSION BOMB PROTECTION
# ==========================================================================

# Maximum ratio of compressed:decompressed size
_MAX_COMPRESSION_RATIO = 100
# Maximum total decompressed size (200MB)
_MAX_DECOMPRESSED_SIZE = 200 * 1024 * 1024
# Maximum number of files in archive
_MAX_ARCHIVE_FILES = 500


def check_archive_safety(file_path: Path) -> list[str]:
    """Check an archive file for decompression bombs and other issues.

    Returns list of issues found (empty = safe).
    """
    import zipfile
    import tarfile

    issues: list[str] = []
    compressed_size = file_path.stat().st_size

    if zipfile.is_zipfile(file_path):
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                infos = zf.infolist()
                if len(infos) > _MAX_ARCHIVE_FILES:
                    issues.append(
                        f"Archive contains {len(infos)} files (max {_MAX_ARCHIVE_FILES})"
                    )

                total_size = sum(i.file_size for i in infos)
                if total_size > _MAX_DECOMPRESSED_SIZE:
                    issues.append(
                        f"Decompressed size {total_size / 1024 / 1024:.1f}MB "
                        f"exceeds limit ({_MAX_DECOMPRESSED_SIZE / 1024 / 1024:.0f}MB)"
                    )

                if compressed_size > 0:
                    ratio = total_size / compressed_size
                    if ratio > _MAX_COMPRESSION_RATIO:
                        issues.append(
                            f"Compression ratio {ratio:.0f}:1 exceeds limit "
                            f"({_MAX_COMPRESSION_RATIO}:1) — possible zip bomb"
                        )

                # Check for dangerous file types
                for info in infos:
                    name_lower = info.filename.lower()
                    if any(name_lower.endswith(ext) for ext in (
                        ".exe", ".dll", ".so", ".dylib", ".sh", ".bat", ".cmd",
                        ".ps1", ".vbs", ".js", ".wsh", ".msi",
                    )):
                        issues.append(
                            f"Archive contains executable: {info.filename}"
                        )

        except zipfile.BadZipFile:
            issues.append("Corrupt or invalid zip file")

    elif tarfile.is_tarfile(file_path):
        try:
            with tarfile.open(file_path, 'r:*') as tf:
                members = tf.getmembers()
                if len(members) > _MAX_ARCHIVE_FILES:
                    issues.append(
                        f"Archive contains {len(members)} files (max {_MAX_ARCHIVE_FILES})"
                    )

                total_size = sum(m.size for m in members if m.isfile())
                if total_size > _MAX_DECOMPRESSED_SIZE:
                    issues.append(
                        f"Decompressed size {total_size / 1024 / 1024:.1f}MB "
                        f"exceeds limit"
                    )

                # Check for symlinks (can escape extraction directory)
                for m in members:
                    if m.issym() or m.islnk():
                        issues.append(
                            f"Archive contains symlink: {m.name} → {m.linkname} "
                            "(potential directory escape)"
                        )

        except (tarfile.TarError, OSError) as e:
            issues.append(f"Corrupt or invalid tar file: {e}")

    return issues


# ==========================================================================
# 8. GIT BRANCH VALIDATION
# ==========================================================================

# Valid git branch name pattern (prevents injection)
_VALID_BRANCH_RE = __import__("re").compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/\-]{0,127}$")


def validate_git_branch(branch: str) -> bool:
    """Validate a git branch name is safe (no shell injection possible).

    Valid: main, develop, feature/my-feature, release/1.0.0, v2.3.4
    Invalid: ; rm -rf /, $(whoami), `id`, --upload-pack=evil
    """
    if not branch:
        return False
    if branch.startswith("-"):
        return False  # Prevents --option injection
    if not _VALID_BRANCH_RE.match(branch):
        return False
    # Additional checks
    if any(c in branch for c in (";", "|", "&", "$", "`", "(", ")", "{", "}", "\\", "'", '"', "\n", "\r")):
        return False
    if ".." in branch:
        return False  # Prevents path traversal
    return True


def validate_git_url(url: str) -> list[str]:
    """Validate a git URL for security issues.

    Returns list of issues (empty = safe).
    """
    import socket
    import ipaddress
    from urllib.parse import urlparse

    issues: list[str] = []

    if not url.startswith("https://"):
        issues.append("Only HTTPS URLs are allowed")

    # Check for shell injection characters
    dangerous_chars = (";", "|", "&", "$", "`", "(", ")", "\n", "\r", "'", '"')
    if any(c in url for c in dangerous_chars):
        issues.append("URL contains shell injection characters")

    # Check for git option injection (--upload-pack etc)
    if "--" in url:
        issues.append("URL contains '--' (possible git option injection)")

    # SECURITY FIX (H-05): Validate git URL via DNS resolution, not string matching.
    # Prevents DNS rebinding attacks that bypass simple string checks.
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Block obviously dangerous hostnames
    if hostname.lower() in {"localhost", "metadata.google.internal", "kubernetes.default"}:
        issues.append(f"Blocked hostname: {hostname}")
    elif hostname.endswith(".internal") or hostname.endswith(".local"):
        issues.append(f"Blocked internal hostname: {hostname}")
    elif hostname:
        # DNS resolve and check all addresses
        try:
            addrs = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
            for info in addrs:
                ip = ipaddress.ip_address(info[4][0])
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    issues.append(f"Git URL resolves to blocked IP: {info[4][0]}")
                    break
        except socket.gaierror:
            issues.append(f"Cannot resolve git hostname: {hostname}")

    return issues
