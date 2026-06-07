"""Admin API routes for IOC management."""

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from typing import Optional

from admin.models.iocs import (
    FeedConfig,
    FeedCreate,
    FeedUpdate,
    IOCBulkImport,
    IOCCreate,
    IOCEntry,
    IOCSeverity,
    IOCStats,
    IOCType,
    IOCUpdate,
)
from admin.models.auth import TokenPayload
from admin.services.audit_logger import AuditLogger, get_audit_logger
from admin.services.auth_service import require_permission
from admin.services.ioc_store import IOCStore, get_ioc_store

router = APIRouter(prefix="/admin/iocs", tags=["iocs"])


def _store() -> IOCStore:
    return get_ioc_store()


def _audit() -> AuditLogger:
    return get_audit_logger()


# --- IOC CRUD ---


@router.get("", response_model=dict)
def list_iocs(
    type: Optional[IOCType] = None,
    source: Optional[str] = None,
    severity: Optional[IOCSeverity] = None,
    active: Optional[bool] = None,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    store: IOCStore = Depends(_store),
    user: TokenPayload = Depends(require_permission("iocs:read")),
):
    """List IOCs with filtering and pagination."""
    entries, total = store.list(
        ioc_type=type, source=source, severity=severity,
        active=active, search=search, page=page, per_page=per_page,
    )
    return {
        "items": [e.model_dump(mode="json") for e in entries],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


@router.get("/stats", response_model=IOCStats)
def get_stats(store: IOCStore = Depends(_store), user: TokenPayload = Depends(require_permission("iocs:read"))):
    """Get IOC statistics."""
    return store.stats()


@router.get("/search", response_model=list[IOCEntry])
def search_iocs(
    q: str = Query(..., min_length=2),
    store: IOCStore = Depends(_store),
    user: TokenPayload = Depends(require_permission("iocs:read")),
):
    """Search IOCs by value (partial match)."""
    return store.search(q)


@router.get("/export")
def export_iocs(
    format: str = Query("json", pattern="^(json|csv)$"),
    store: IOCStore = Depends(_store),
    user: TokenPayload = Depends(require_permission("iocs:read")),
):
    """Export all IOCs in JSON or CSV format."""
    if format == "csv":
        content = store.export_csv()
        return Response(content=content, media_type="text/csv",
                        headers={"Content-Disposition": "attachment; filename=iocs.csv"})
    content = store.export_json()
    return Response(content=content, media_type="application/json",
                    headers={"Content-Disposition": "attachment; filename=iocs.json"})


@router.post("", response_model=IOCEntry, status_code=201)
async def create_ioc(
    req: IOCCreate,
    store: IOCStore = Depends(_store),
    audit: AuditLogger = Depends(_audit),
    user: TokenPayload = Depends(require_permission("iocs:write")),
):
    """Create a single IOC entry."""
    entry = store.create(req)
    await audit.log(
        actor=user.sub, action="ioc_create", resource_type="ioc",
        resource_id=entry.id, payload=entry.value, result="success",
    )
    return entry


@router.post("/bulk", response_model=dict, status_code=201)
async def bulk_import(
    req: IOCBulkImport,
    store: IOCStore = Depends(_store),
    audit: AuditLogger = Depends(_audit),
    user: TokenPayload = Depends(require_permission("iocs:write")),
):
    """Bulk import IOC entries."""
    entries = store.bulk_import(req.entries)
    await audit.log(
        actor="admin", action="ioc_bulk_import", resource_type="ioc",
        resource_id="bulk", payload=f"{len(entries)} entries", result="success",
    )
    return {"imported": len(entries), "items": [e.model_dump(mode="json") for e in entries]}


@router.put("/{ioc_id}", response_model=IOCEntry)
async def update_ioc(
    ioc_id: str,
    req: IOCUpdate,
    store: IOCStore = Depends(_store),
    audit: AuditLogger = Depends(_audit),
    user: TokenPayload = Depends(require_permission("iocs:write")),
):
    """Update an IOC entry."""
    entry = store.update(ioc_id, req)
    if not entry:
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_id}' not found")
    await audit.log(
        actor="admin", action="ioc_update", resource_type="ioc",
        resource_id=ioc_id, result="success",
    )
    return entry


@router.delete("/{ioc_id}", status_code=204)
async def delete_ioc(
    ioc_id: str,
    store: IOCStore = Depends(_store),
    audit: AuditLogger = Depends(_audit),
    user: TokenPayload = Depends(require_permission("iocs:write")),
):
    """Delete an IOC entry."""
    if not store.delete(ioc_id):
        raise HTTPException(status_code=404, detail=f"IOC '{ioc_id}' not found")
    await audit.log(
        actor="admin", action="ioc_delete", resource_type="ioc",
        resource_id=ioc_id, result="success",
    )


# --- Feed management ---


@router.get("/feeds", response_model=list[FeedConfig])
def list_feeds(store: IOCStore = Depends(_store), user: TokenPayload = Depends(require_permission("iocs:read"))):
    """List all feed configurations."""
    return store.list_feeds()


@router.post("/feeds", response_model=FeedConfig, status_code=201)
async def create_feed(
    req: FeedCreate,
    store: IOCStore = Depends(_store),
    audit: AuditLogger = Depends(_audit),
    user: TokenPayload = Depends(require_permission("iocs:write")),
):
    """Create a new IOC feed source."""
    result = store.create_feed(req)
    await audit.log(
        actor=user.sub, action="feed_create", resource_type="feed",
        resource_id=result.id, result="success",
    )
    return result


@router.get("/feeds/{feed_id}", response_model=FeedConfig)
def get_feed(
    feed_id: str,
    store: IOCStore = Depends(_store),
    user: TokenPayload = Depends(require_permission("iocs:read")),
):
    """Get a specific feed configuration."""
    result = store.get_feed(feed_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Feed '{feed_id}' not found")
    return result


@router.put("/feeds/{feed_id}", response_model=FeedConfig)
async def update_feed(
    feed_id: str,
    req: FeedUpdate,
    store: IOCStore = Depends(_store),
    audit: AuditLogger = Depends(_audit),
    user: TokenPayload = Depends(require_permission("iocs:write")),
):
    """Update feed configuration."""
    result = store.update_feed(feed_id, req)
    if not result:
        raise HTTPException(status_code=404, detail=f"Feed '{feed_id}' not found")
    await audit.log(
        actor=user.sub, action="feed_update", resource_type="feed",
        resource_id=feed_id, result="success",
    )
    return result


@router.delete("/feeds/{feed_id}")
async def delete_feed(
    feed_id: str,
    store: IOCStore = Depends(_store),
    audit: AuditLogger = Depends(_audit),
    user: TokenPayload = Depends(require_permission("iocs:write")),
):
    """Delete a feed source."""
    if not store.delete_feed(feed_id):
        raise HTTPException(status_code=404, detail=f"Feed '{feed_id}' not found")
    await audit.log(
        actor=user.sub, action="feed_delete", resource_type="feed",
        resource_id=feed_id, result="success",
    )
    return {"status": "deleted"}


@router.patch("/feeds/{feed_id}/toggle", response_model=FeedConfig)
async def toggle_feed(
    feed_id: str,
    store: IOCStore = Depends(_store),
    audit: AuditLogger = Depends(_audit),
    user: TokenPayload = Depends(require_permission("iocs:write")),
):
    """Toggle feed enabled/disabled."""
    result = store.toggle_feed(feed_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Feed '{feed_id}' not found")
    await audit.log(
        actor=user.sub, action="feed_toggle", resource_type="feed",
        resource_id=feed_id, details=f"enabled={result.enabled}", result="success",
    )
    return result


@router.post("/feeds/update", response_model=dict)
async def trigger_feed_update(
    feed_id: Optional[str] = Query(default=None, description="Specific feed to update (all if omitted)"),
    store: IOCStore = Depends(_store),
    audit: AuditLogger = Depends(_audit),
    user: TokenPayload = Depends(require_permission("iocs:write")),
):
    """Trigger update for all enabled feeds or a specific one."""
    import asyncio

    loop = asyncio.get_event_loop()
    results = await loop.run_in_executor(None, lambda: store.trigger_feed_update(feed_id))

    total_added = sum(r.get("count", 0) for r in results.values())

    await audit.log(
        actor=user.sub, action="feed_trigger", resource_type="feed",
        resource_id=feed_id or "all", details=f"total_added={total_added}",
        result="success" if all(r.get("status") in ("ok", "disabled") for r in results.values()) else "partial",
    )

    return {"status": "completed", "total_added": total_added, "feeds": results}
