"""Admin API routes for skill security scanning (SkillSpector integration)."""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from pydantic import BaseModel, Field

from admin.models.auth import TokenPayload
from admin.services.auth_service import require_permission
from admin.services.skill_scanner import (
    ScanResult,
    ScanVerdict,
    SkillScanner,
    get_skill_scanner,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/skills", tags=["skills"])


# --- Request/Response models ---


class ScanPathRequest(BaseModel):
    """Request to scan a file path on the server."""
    path: str = Field(..., description="Path to skill definition file or directory")
    scan_id: Optional[str] = Field(None, description="Optional scan identifier")


class ScanContentRequest(BaseModel):
    """Request to scan inline skill content."""
    content: str = Field(..., min_length=1, max_length=1_000_000, description="Skill definition content")
    filename: str = Field("skill.yaml", description="Filename hint for format detection")
    scan_id: Optional[str] = Field(None, description="Optional scan identifier")


class ScanResponse(BaseModel):
    """Scan result response."""
    scan_id: str
    timestamp: str
    risk_score: float
    risk_severity: str
    verdict: str
    findings: list[dict]
    recommendation: str
    scan_duration_ms: float
    scanner_version: str
    input_path: str
    error: str
    engine: str = ""


class ScannerStatusResponse(BaseModel):
    """Scanner availability and configuration status."""
    enabled: bool
    available: bool
    mode: str
    version: str
    block_threshold: float
    warn_threshold: float
    cache_size: int
    skillspector_installed: bool = False
    skillspector_version: str = "unavailable"
    sentinel_rules_count: int = 0
    mcp_security_patterns: int = 0
    total_patterns: int = 0


class ScanHistoryEntry(BaseModel):
    """Summary entry for scan history."""
    scan_id: str
    timestamp: str
    input_path: str
    risk_score: float
    verdict: str
    finding_count: int


# --- In-memory scan history (last N results) ---
_scan_history: list[dict] = []
_MAX_HISTORY = 50


def _record_scan(result: ScanResult) -> None:
    """Store scan result in history ring buffer."""
    _scan_history.append(result.to_dict())
    while len(_scan_history) > _MAX_HISTORY:
        _scan_history.pop(0)


# --- Endpoints ---


@router.get("/status", response_model=ScannerStatusResponse)
def scanner_status(
    user: TokenPayload = Depends(require_permission("policies:read")),
) -> ScannerStatusResponse:
    """Get SkillSpector scanner status and configuration."""
    scanner = get_skill_scanner()
    st = scanner.status()
    return ScannerStatusResponse(**st)


@router.post("/scan/path", response_model=ScanResponse)
async def scan_path(
    req: ScanPathRequest,
    user: TokenPayload = Depends(require_permission("policies:write")),
) -> ScanResponse:
    """Scan a skill definition by server-side file path.

    Requires the file to exist on the admin pod filesystem.
    Use /scan/upload for client-side files.
    """
    scanner = get_skill_scanner()

    # Security: prevent path traversal attacks
    import os.path
    normalized = os.path.normpath(req.path)
    if ".." in normalized.split(os.sep):
        raise HTTPException(status_code=400, detail="Path traversal detected")

    if not os.path.exists(normalized):
        raise HTTPException(status_code=404, detail=f"Path not found: {normalized}")

    result = await scanner.scan(normalized, scan_id=req.scan_id)
    _record_scan(result)

    logger.info(
        "skill_scan_completed scan_id=%s path=%s score=%.1f verdict=%s",
        result.scan_id, req.path, result.risk_score, result.verdict.value,
    )

    return ScanResponse(**result.to_dict())


@router.post("/scan/content", response_model=ScanResponse)
async def scan_content(
    req: ScanContentRequest,
    user: TokenPayload = Depends(require_permission("policies:write")),
) -> ScanResponse:
    """Scan inline skill definition content.

    Accepts YAML or JSON skill definitions as string content.
    """
    scanner = get_skill_scanner()
    result = await scanner.scan_content(
        content=req.content,
        filename=req.filename,
        scan_id=req.scan_id,
    )
    _record_scan(result)

    logger.info(
        "skill_scan_completed scan_id=%s content_len=%d score=%.1f verdict=%s",
        result.scan_id, len(req.content), result.risk_score, result.verdict.value,
    )

    return ScanResponse(**result.to_dict())


@router.post("/scan/upload", response_model=ScanResponse)
async def scan_upload(
    file: UploadFile = File(..., description="Skill definition file to scan"),
    user: TokenPayload = Depends(require_permission("policies:write")),
) -> ScanResponse:
    """Scan an uploaded skill definition file.

    Supported formats: YAML (.yaml, .yml), JSON (.json)
    Max file size: 1MB (enforced by body_size_limit middleware)
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename required")

    # Validate file extension
    allowed_extensions = {".yaml", ".yml", ".json", ".toml"}
    ext = "." + file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(allowed_extensions))}",
        )

    content = await file.read()
    if len(content) > 1_000_000:
        raise HTTPException(status_code=413, detail="File too large (max 1MB)")

    scanner = get_skill_scanner()
    result = await scanner.scan_content(
        content=content.decode("utf-8", errors="replace"),
        filename=file.filename,
    )
    _record_scan(result)

    logger.info(
        "skill_scan_upload scan_id=%s file=%s score=%.1f verdict=%s",
        result.scan_id, file.filename, result.risk_score, result.verdict.value,
    )

    return ScanResponse(**result.to_dict())


@router.get("/history", response_model=list[ScanHistoryEntry])
def scan_history(
    limit: int = Query(20, ge=1, le=50),
    verdict: Optional[str] = Query(None, description="Filter by verdict: pass, warn, block, error"),
    user: TokenPayload = Depends(require_permission("policies:read")),
) -> list[ScanHistoryEntry]:
    """Get recent scan history."""
    entries = list(reversed(_scan_history))  # Most recent first

    if verdict:
        entries = [e for e in entries if e.get("verdict") == verdict]

    return [
        ScanHistoryEntry(
            scan_id=e["scan_id"],
            timestamp=e["timestamp"],
            input_path=e.get("input_path", ""),
            risk_score=e.get("risk_score", 0.0),
            verdict=e.get("verdict", "error"),
            finding_count=len(e.get("findings", [])),
        )
        for e in entries[:limit]
    ]


@router.get("/history/{scan_id}", response_model=ScanResponse)
def get_scan_result(
    scan_id: str,
    user: TokenPayload = Depends(require_permission("policies:read")),
) -> ScanResponse:
    """Get detailed result for a specific scan."""
    for entry in reversed(_scan_history):
        if entry.get("scan_id") == scan_id:
            return ScanResponse(**entry)
    raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found in history")
