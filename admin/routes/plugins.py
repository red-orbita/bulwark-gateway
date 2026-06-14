"""Admin API routes for plugin management.

Supports:
- List installed plugins (with enabled state)
- Install from file upload (.zip/.tar.gz)
- Install from Git URL (clone + validate)
- Scaffold new plugin template
- Enable / Disable / Uninstall
- Security audit with risk scoring
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import zipfile
import tarfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel, Field

from admin.models.auth import TokenPayload
from admin.services.auth_service import require_permission
from src.plugins.manager import PluginManager
from src.plugins.sandbox import (
    analyze_plugin_directory,
    check_archive_safety,
    validate_git_branch,
    validate_git_url,
)
from src.plugins.spec import PluginSpec

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/plugins", tags=["plugins"])

_PLUGIN_DIR = Path("/app/plugins") if Path("/app").exists() else Path("plugins")
_MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10MB


# --- Request models ---


class UninstallRequest(BaseModel):
    """Request to uninstall a plugin."""
    name: str = Field(..., description="Plugin name to uninstall")


class ScaffoldRequest(BaseModel):
    """Request to scaffold a new plugin."""
    name: str = Field(..., description="Plugin name (kebab-case)")


class GitInstallRequest(BaseModel):
    """Request to install a plugin from a Git URL."""
    url: str = Field(..., description="Git repository URL (https://...)")
    branch: str = Field("main", description="Branch to clone")


# --- Response models ---


class PluginResponse(BaseModel):
    """Plugin information response (includes runtime state)."""
    name: str
    version: str
    author: str
    license: str
    description: str
    type: str
    blocking: bool
    enabled: bool = True
    security_issues: int = 0


class SecurityFinding(BaseModel):
    """Individual security finding."""
    rule_id: str
    severity: str  # critical, high, medium, low
    message: str
    location: str = ""


class SecurityCheckResponse(BaseModel):
    """Security check result matching UI expectations."""
    plugin_name: str
    risk_score: float  # 0.0 - 10.0
    verdict: str  # pass, warn, block
    findings: list[SecurityFinding]


# --- Helpers ---


def _get_plugin_manager() -> PluginManager:
    """Create a PluginManager instance with the default plugin directory."""
    try:
        return PluginManager(plugin_dir=_PLUGIN_DIR)
    except OSError as e:
        logger.warning("plugin_dir_unavailable", extra={"path": str(_PLUGIN_DIR), "error": str(e)})
        raise HTTPException(
            status_code=503,
            detail=f"Plugin directory not available: {e}. Mount a writable volume at /app/plugins.",
        )


def _spec_to_response(spec: PluginSpec, manager: PluginManager) -> PluginResponse:
    """Convert a PluginSpec to response model with runtime state."""
    state = manager._state.get(spec.name, {})
    enabled = state.get("enabled", True)
    security_issues = state.get("security_issues", 0)
    return PluginResponse(
        name=spec.name,
        version=spec.version,
        author=spec.author,
        license=spec.license,
        description=spec.description,
        type=spec.type.value,
        blocking=spec.blocking,
        enabled=enabled,
        security_issues=security_issues,
    )


def _compute_security_findings(warnings: list[str]) -> tuple[list[SecurityFinding], float, str]:
    """Convert raw warnings into structured findings + risk score + verdict.

    Scoring: each warning = 2.0 points (capped at 10.0).
    Verdict: <4.0=pass, <7.0=warn, >=7.0=block.
    """
    findings: list[SecurityFinding] = []
    for i, warning in enumerate(warnings):
        # Parse warning format: "file.py: message (found N occurrence(s))"
        parts = warning.split(": ", 1)
        location = parts[0] if len(parts) > 1 else ""
        message = parts[1] if len(parts) > 1 else warning

        # Determine severity based on pattern content
        severity = "medium"
        if any(k in message.lower() for k in ("eval(", "exec(", "subprocess", "__import__")):
            severity = "high"
        elif any(k in message.lower() for k in ("ctypes", "os.exec", "os.spawn")):
            severity = "critical"
        elif any(k in message.lower() for k in ("pickle", "shelve")):
            severity = "medium"

        findings.append(SecurityFinding(
            rule_id=f"SEC-PLG-{i + 1:03d}",
            severity=severity,
            message=message,
            location=location,
        ))

    # Score: 2 points per finding for medium, 3 for high, 4 for critical
    score = 0.0
    for f in findings:
        if f.severity == "critical":
            score += 4.0
        elif f.severity == "high":
            score += 3.0
        else:
            score += 2.0
    score = min(score, 10.0)

    # Verdict
    if score >= 7.0:
        verdict = "block"
    elif score >= 4.0:
        verdict = "warn"
    else:
        verdict = "pass"

    return findings, score, verdict


def _extract_archive(file_path: Path, dest_dir: Path) -> Path:
    """Extract .zip or .tar.gz to dest_dir. Returns plugin root dir."""
    if zipfile.is_zipfile(file_path):
        with zipfile.ZipFile(file_path, 'r') as zf:
            # Security: reject entries with absolute paths or ..
            for name in zf.namelist():
                if name.startswith('/') or '..' in name:
                    raise ValueError(f"Unsafe path in archive: {name}")
            zf.extractall(dest_dir)
    elif tarfile.is_tarfile(file_path):
        with tarfile.open(file_path, 'r:*') as tf:
            for member in tf.getmembers():
                if member.name.startswith('/') or '..' in member.name:
                    raise ValueError(f"Unsafe path in archive: {member.name}")
            tf.extractall(dest_dir, filter='data')
    else:
        raise ValueError("Unsupported archive format. Use .zip or .tar.gz")

    # Find the plugin root (directory containing sentinel-plugin.yaml)
    for root, dirs, files in os.walk(dest_dir):
        if "sentinel-plugin.yaml" in files:
            return Path(root)

    raise ValueError("Archive does not contain sentinel-plugin.yaml")


# --- Endpoints ---


@router.get("/", response_model=list[PluginResponse])
def list_plugins(
    user: TokenPayload = Depends(require_permission("admin:read")),
) -> list[PluginResponse]:
    """List all installed plugins with their enabled state."""
    manager = _get_plugin_manager()
    plugins = manager.list_installed()
    return [_spec_to_response(spec, manager) for spec in plugins]


@router.get("/{name}", response_model=PluginResponse)
def get_plugin(
    name: str,
    user: TokenPayload = Depends(require_permission("admin:read")),
) -> PluginResponse:
    """Get a specific plugin by name."""
    manager = _get_plugin_manager()
    plugins = manager.list_installed()
    for spec in plugins:
        if spec.name == name:
            return _spec_to_response(spec, manager)
    raise HTTPException(status_code=404, detail=f"Plugin '{name}' not found")


@router.post("/install/upload", response_model=dict)
async def install_from_upload(
    file: UploadFile = File(..., description="Plugin archive (.zip or .tar.gz)"),
    user: TokenPayload = Depends(require_permission("guardrails:write")),
) -> dict:
    """Install a plugin from an uploaded archive file.

    The archive must contain a sentinel-plugin.yaml at the root (or one level deep).
    A security check runs automatically — installation fails if critical issues are found.
    """
    manager = _get_plugin_manager()

    # Validate file size
    content = await file.read()
    if len(content) > _MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="File too large (max 10MB)")

    # Validate filename
    filename = file.filename or "plugin.zip"
    if not (filename.endswith(".zip") or filename.endswith(".tar.gz") or filename.endswith(".tgz")):
        raise HTTPException(status_code=400, detail="Only .zip and .tar.gz archives are supported")

    # Extract to temp dir
    tmp_dir = None
    try:
        tmp_dir = Path(tempfile.mkdtemp(prefix="sentinel-plugin-"))
        archive_path = tmp_dir / filename
        archive_path.write_bytes(content)

        # SECURITY: Check for decompression bombs BEFORE extracting
        bomb_issues = check_archive_safety(archive_path)
        if bomb_issues:
            raise HTTPException(
                status_code=400,
                detail=f"Archive security check failed: {'; '.join(bomb_issues)}"
            )

        extract_dir = tmp_dir / "extracted"
        extract_dir.mkdir()
        plugin_root = _extract_archive(archive_path, extract_dir)

        # SECURITY: AST analysis BEFORE install (catch everything regex misses)
        ast_result = analyze_plugin_directory(plugin_root)
        if not ast_result.safe:
            top_findings = "; ".join(
                f"[{f.severity}] {f.message}" for f in ast_result.findings[:3]
            )
            raise HTTPException(
                status_code=400,
                detail=f"Plugin security analysis FAILED (score {ast_result.risk_score:.1f}/10): {top_findings}"
            )

        # Install from extracted path (uses manager.install which validates + security checks)
        success = manager.install(name=str(plugin_root), source="local")
        if not success:
            # Try to give more specific error
            from src.plugins.spec import load_plugin_spec, validate_plugin_spec
            spec_file = plugin_root / "sentinel-plugin.yaml"
            if spec_file.exists():
                spec = load_plugin_spec(spec_file)
                errors = validate_plugin_spec(spec)
                if errors:
                    raise HTTPException(status_code=400, detail=f"Validation errors: {'; '.join(errors)}")
                # Security check failed
                warnings = manager._security_check(plugin_root)
                if warnings:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Security check failed: {'; '.join(warnings[:3])}"
                    )
            raise HTTPException(status_code=400, detail="Installation failed")

        # Determine plugin name from spec
        from src.plugins.spec import load_plugin_spec
        spec = load_plugin_spec(plugin_root / "sentinel-plugin.yaml")
        logger.info("plugin_installed_upload", extra={"name": spec.name, "user": user.sub})
        return {"status": "installed", "name": spec.name, "version": spec.version, "source": "upload"}

    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("plugin_upload_error", extra={"error": str(e)})
        raise HTTPException(status_code=500, detail=f"Installation error: {str(e)}")
    finally:
        if tmp_dir and tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)


@router.post("/install/url", response_model=dict)
async def install_from_url(
    req: GitInstallRequest,
    user: TokenPayload = Depends(require_permission("guardrails:write")),
) -> dict:
    """Install a plugin from a Git repository URL.

    Clones the repo, validates the plugin spec, runs security checks,
    and installs to the plugin directory.
    """
    manager = _get_plugin_manager()

    # SECURITY: Validate URL thoroughly
    url_issues = validate_git_url(req.url)
    if url_issues:
        raise HTTPException(status_code=400, detail=f"URL validation failed: {'; '.join(url_issues)}")

    # SECURITY: Validate branch name (prevents --option injection)
    if not validate_git_branch(req.branch):
        raise HTTPException(
            status_code=400,
            detail="Invalid branch name. Must be alphanumeric with ._/- only, cannot start with '-'"
        )

    tmp_dir = None
    try:
        tmp_dir = Path(tempfile.mkdtemp(prefix="sentinel-plugin-git-"))
        clone_dir = tmp_dir / "repo"

        # Clone with depth 1 (minimal), timeout 30s
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", req.branch, req.url, str(clone_dir)],
            capture_output=True, text=True, timeout=30,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
        if result.returncode != 0:
            error_msg = result.stderr.strip()[:200] if result.stderr else "Clone failed"
            raise HTTPException(status_code=400, detail=f"Git clone failed: {error_msg}")

        # Find sentinel-plugin.yaml
        spec_file = clone_dir / "sentinel-plugin.yaml"
        if not spec_file.exists():
            # Try one level deep
            for child in clone_dir.iterdir():
                if child.is_dir() and (child / "sentinel-plugin.yaml").exists():
                    clone_dir = child
                    spec_file = child / "sentinel-plugin.yaml"
                    break
            else:
                raise HTTPException(
                    status_code=400,
                    detail="Repository does not contain sentinel-plugin.yaml"
                )

        # Remove .git directory (not needed, saves space)
        git_dir = clone_dir / ".git"
        if git_dir.exists():
            shutil.rmtree(git_dir, ignore_errors=True)

        # SECURITY: AST analysis BEFORE install
        ast_result = analyze_plugin_directory(clone_dir)
        if not ast_result.safe:
            top_findings = "; ".join(
                f"[{f.severity}] {f.message}" for f in ast_result.findings[:3]
            )
            raise HTTPException(
                status_code=400,
                detail=f"Plugin security analysis FAILED (score {ast_result.risk_score:.1f}/10): {top_findings}"
            )

        # Install from cloned path
        success = manager.install(name=str(clone_dir), source="local")
        if not success:
            from src.plugins.spec import load_plugin_spec, validate_plugin_spec
            spec = load_plugin_spec(spec_file)
            errors = validate_plugin_spec(spec)
            if errors:
                raise HTTPException(status_code=400, detail=f"Validation errors: {'; '.join(errors)}")
            warnings = manager._security_check(clone_dir)
            if warnings:
                raise HTTPException(
                    status_code=400,
                    detail=f"Security check failed: {'; '.join(warnings[:3])}"
                )
            raise HTTPException(status_code=400, detail="Installation failed")

        from src.plugins.spec import load_plugin_spec
        spec = load_plugin_spec(spec_file)
        logger.info("plugin_installed_git", extra={"name": spec.name, "url": req.url, "user": user.sub})
        return {"status": "installed", "name": spec.name, "version": spec.version, "source": "git", "url": req.url}

    except HTTPException:
        raise
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Git clone timed out (30s)")
    except Exception as e:
        logger.error("plugin_git_install_error", extra={"url": req.url, "error": str(e)})
        raise HTTPException(status_code=500, detail=f"Installation error: {str(e)}")
    finally:
        if tmp_dir and tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)


@router.post("/uninstall", response_model=dict)
def uninstall_plugin(
    req: UninstallRequest,
    user: TokenPayload = Depends(require_permission("guardrails:write")),
) -> dict:
    """Uninstall a plugin by name."""
    manager = _get_plugin_manager()
    success = manager.uninstall(name=req.name)
    if not success:
        raise HTTPException(status_code=404, detail=f"Plugin '{req.name}' not found")
    logger.info("plugin_uninstalled", extra={"name": req.name, "user": user.sub})
    return {"status": "uninstalled", "name": req.name}


@router.post("/{name}/enable", response_model=dict)
def enable_plugin(
    name: str,
    user: TokenPayload = Depends(require_permission("guardrails:write")),
) -> dict:
    """Enable a disabled plugin."""
    manager = _get_plugin_manager()
    success = manager.enable(name=name)
    if not success:
        raise HTTPException(status_code=404, detail=f"Plugin '{name}' not found")
    logger.info("plugin_enabled", extra={"name": name, "user": user.sub})
    return {"status": "enabled", "name": name}


@router.post("/{name}/disable", response_model=dict)
def disable_plugin(
    name: str,
    user: TokenPayload = Depends(require_permission("guardrails:write")),
) -> dict:
    """Disable an enabled plugin."""
    manager = _get_plugin_manager()
    success = manager.disable(name=name)
    if not success:
        raise HTTPException(status_code=404, detail=f"Plugin '{name}' not found")
    logger.info("plugin_disabled", extra={"name": name, "user": user.sub})
    return {"status": "disabled", "name": name}


@router.post("/scaffold", response_model=dict)
def scaffold_plugin(
    req: ScaffoldRequest,
    user: TokenPayload = Depends(require_permission("guardrails:write")),
) -> dict:
    """Create a new plugin scaffold with boilerplate structure."""
    manager = _get_plugin_manager()
    plugin_path = manager.plugin_dir / req.name
    if plugin_path.exists():
        raise HTTPException(status_code=400, detail=f"Plugin '{req.name}' already exists")
    created_path = manager.scaffold(name=req.name, output_dir=manager.plugin_dir)
    logger.info("plugin_scaffolded", extra={"name": req.name, "user": user.sub})
    return {"status": "scaffolded", "name": req.name, "path": str(created_path)}


@router.post("/{name}/security-check", response_model=SecurityCheckResponse)
def security_check_plugin(
    name: str,
    user: TokenPayload = Depends(require_permission("guardrails:write")),
) -> SecurityCheckResponse:
    """Run a security audit on an installed plugin.

    Returns risk score (0-10), verdict (pass/warn/block), and detailed findings.
    """
    manager = _get_plugin_manager()
    plugin_path = manager.plugin_dir / name
    if not plugin_path.is_dir():
        raise HTTPException(status_code=404, detail=f"Plugin '{name}' not found")

    warnings = manager._security_check(plugin_path)
    findings, risk_score, verdict = _compute_security_findings(warnings)

    # Store issue count in state for the list view
    if name not in manager._state:
        manager._state[name] = {"enabled": True}
    manager._state[name]["security_issues"] = len(findings)
    manager._save_state()

    logger.info(
        "plugin_security_check",
        extra={"name": name, "score": risk_score, "verdict": verdict, "findings": len(findings), "user": user.sub},
    )

    return SecurityCheckResponse(
        plugin_name=name,
        risk_score=risk_score,
        verdict=verdict,
        findings=findings,
    )


class PluginTestRequest(BaseModel):
    """Request to test a plugin with sample input."""
    content: str = Field(..., description="Text content to scan", max_length=10000)
    tenant_id: str = Field("test-tenant", description="Simulated tenant ID")
    agent_id: str = Field("test-agent", description="Simulated agent ID")


class PluginTestResponse(BaseModel):
    """Result of a live plugin test."""
    plugin_name: str
    verdict: str  # allow, block, warn, redact
    execution_time_ms: float
    events: list[dict] = []
    error: Optional[str] = None


@router.post("/{name}/test", response_model=PluginTestResponse)
async def test_plugin(
    name: str,
    req: PluginTestRequest,
    user: TokenPayload = Depends(require_permission("guardrails:write")),
) -> PluginTestResponse:
    """Live-test a plugin by running it against provided content.

    Loads the plugin scanner, executes it with the given input text,
    and returns the verdict + any security events it produced.
    This does NOT affect real traffic — it's a sandbox test.
    """
    import time

    manager = _get_plugin_manager()
    plugin_path = manager.plugin_dir / name
    if not plugin_path.is_dir():
        raise HTTPException(status_code=404, detail=f"Plugin '{name}' not found")

    # Load scanner
    scanner = manager.get_scanner(name)
    if scanner is None:
        # Try to give specific error
        scanner_file = plugin_path / "scanner.py"
        if not scanner_file.exists():
            raise HTTPException(status_code=400, detail="Plugin has no scanner.py")
        state = manager._state.get(name, {})
        if not state.get("enabled", True):
            raise HTTPException(status_code=400, detail="Plugin is disabled — enable it first to test")
        raise HTTPException(status_code=500, detail="Failed to load plugin scanner (check logs)")

    # Build context
    from src.scanners.protocol import ScanContext
    context = ScanContext(
        tenant_id=req.tenant_id,
        agent_id=req.agent_id,
        request_id=f"test-{int(time.time())}",
        messages=[{"role": "user", "content": req.content}],
    )

    # Execute scanner
    start = time.perf_counter()
    try:
        result = await scanner.scan(req.content, context)
        elapsed_ms = (time.perf_counter() - start) * 1000

        events_data = []
        for evt in (result.events or []):
            events_data.append({
                "verdict": evt.verdict.value if hasattr(evt.verdict, 'value') else str(evt.verdict),
                "category": evt.category.value if hasattr(evt.category, 'value') else str(evt.category),
                "severity": evt.severity,
                "description": evt.description,
                "source": evt.source,
                "metadata": evt.metadata or {},
            })

        return PluginTestResponse(
            plugin_name=name,
            verdict=result.verdict.value if hasattr(result.verdict, 'value') else str(result.verdict),
            execution_time_ms=round(elapsed_ms, 2),
            events=events_data,
        )

    except Exception as e:
        elapsed_ms = (time.perf_counter() - start) * 1000
        logger.error("plugin_test_error", extra={"name": name, "error": str(e)})
        return PluginTestResponse(
            plugin_name=name,
            verdict="error",
            execution_time_ms=round(elapsed_ms, 2),
            error=str(e),
        )
