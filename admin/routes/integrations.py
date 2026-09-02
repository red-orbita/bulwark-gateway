"""Outbound integration management + case-push routes (Investigation Phase 1).

Exposes the integration registry to the admin UI: list/create/update/delete
targets, toggle them, probe health, and push an investigation case to a
configured platform (TheHive / DFIR-IRIS / OpenCTI).

Everything is **fail-open**: a push that the remote rejects is audited and
returned as a ``502`` with a human-readable detail, but it never mutates or
blocks the local case. A push refused by local data-sharing policy (e.g. an
all-``TLP:RED`` case to OpenCTI) is a ``400`` — the remote is never contacted.
Secrets are masked in every response. All routes are gated by the dedicated
``integrations:read`` / ``integrations:write`` permissions.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Body, Depends, HTTPException

from ..models.auth import ROLE_PERMISSIONS, TokenPayload
from ..services.audit_logger import get_audit_logger
from ..services.auth_service import require_permission
from ..services.integration_link_store import get_integration_link_store
from ..services.integrations.base import ConnectorError, TlpGateError
from ..services.integrations.registry import (
    INTEGRATION_TYPES,
    IntegrationConfig,
    get_integration_registry,
)
from ..services.investigation_case_store import get_case_store
from ..services.investigation_observable_store import get_observable_store
from ..services.investigation_task_store import get_task_store

router = APIRouter()


def _can_write(user: TokenPayload) -> bool:
    """True if the caller's role includes ``integrations:write``."""
    return "integrations:write" in ROLE_PERMISSIONS.get(user.role, set())


def _mask(config: dict) -> dict:
    """Mask secret fields in an integration config for API responses."""
    masked = dict(config)
    if masked.get("api_key"):
        masked["api_key"] = "***"
    return masked


async def _get_case_scoped(user: TokenPayload, case_id: str) -> dict:
    """Fetch a case, enforcing tenant scoping (404 on cross-tenant, no leak)."""
    case = await get_case_store().get(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    if user.tenant and (case.get("tenant") or "") != user.tenant:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


# ─── Status + config CRUD ─────────────────────────────────────────────────────


@router.get("/status")
async def status(user: TokenPayload = Depends(require_permission("integrations:read"))):
    """Registry status: supported types + configured targets (masked)."""
    registry = get_integration_registry()
    return {
        "supported_types": list(INTEGRATION_TYPES),
        "count": len(registry.configs),
        "can_write": _can_write(user),
        "integrations": [_mask(c.to_dict()) for c in registry.configs],
    }


@router.get("")
async def list_integrations(
    user: TokenPayload = Depends(require_permission("integrations:read")),
):
    """List all configured integrations (secrets masked)."""
    registry = get_integration_registry()
    return {"integrations": [_mask(c.to_dict()) for c in registry.configs]}


@router.get("/{integration_id}")
async def get_integration(
    integration_id: str,
    user: TokenPayload = Depends(require_permission("integrations:read")),
):
    """Get a single integration config (secrets masked)."""
    config = get_integration_registry().get(integration_id)
    if config is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    return {"integration": _mask(config.to_dict())}


@router.post("")
async def create_integration(
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("integrations:write")),
):
    """Create a new outbound integration target."""
    registry = get_integration_registry()
    audit = get_audit_logger()

    if not data.get("name"):
        raise HTTPException(status_code=400, detail="'name' is required")
    if data.get("type") not in INTEGRATION_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"'type' must be one of: {', '.join(INTEGRATION_TYPES)}",
        )
    if not data.get("base_url"):
        raise HTTPException(status_code=400, detail="'base_url' is required")

    data["id"] = str(uuid.uuid4())[:8]
    config = IntegrationConfig.from_dict(data)
    registry.add(config)

    await audit.log(
        actor=user.sub,
        action="integration_created",
        resource_type="integration",
        resource_id=config.id,
        details=str({"name": config.name, "type": config.type}),
    )
    return {"integration": _mask(config.to_dict()), "message": "Integration created"}


@router.put("/{integration_id}")
async def update_integration(
    integration_id: str,
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("integrations:write")),
):
    """Update an existing integration config."""
    registry = get_integration_registry()
    audit = get_audit_logger()

    data.pop("id", None)
    updated = registry.update(integration_id, data)
    if updated is None:
        raise HTTPException(status_code=404, detail="Integration not found")

    await audit.log(
        actor=user.sub,
        action="integration_updated",
        resource_type="integration",
        resource_id=integration_id,
        details=str({"fields": list(data.keys())}),
    )
    return {"integration": _mask(updated.to_dict()), "message": "Integration updated"}


@router.delete("/{integration_id}")
async def delete_integration(
    integration_id: str,
    user: TokenPayload = Depends(require_permission("integrations:write")),
):
    """Delete an integration config."""
    registry = get_integration_registry()
    audit = get_audit_logger()

    if not registry.remove(integration_id):
        raise HTTPException(status_code=404, detail="Integration not found")

    await audit.log(
        actor=user.sub,
        action="integration_deleted",
        resource_type="integration",
        resource_id=integration_id,
    )
    return {"message": "Integration deleted"}


@router.post("/{integration_id}/toggle")
async def toggle_integration(
    integration_id: str,
    user: TokenPayload = Depends(require_permission("integrations:write")),
):
    """Enable/disable an integration."""
    enabled = get_integration_registry().toggle(integration_id)
    if enabled is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    return {
        "enabled": enabled,
        "message": f"Integration {'enabled' if enabled else 'disabled'}",
    }


@router.post("/{integration_id}/test")
async def test_integration(
    integration_id: str,
    user: TokenPayload = Depends(require_permission("integrations:write")),
):
    """Probe an integration's reachability (bypasses the health cache)."""
    registry = get_integration_registry()
    if registry.get(integration_id) is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    health = await registry.health(integration_id, force=True)
    return {
        "ok": health.ok,
        "detail": health.detail,
        "checked_at": health.checked_at,
        "circuit_state": health.circuit_state,
    }


@router.get("/{integration_id}/health")
async def integration_health(
    integration_id: str,
    user: TokenPayload = Depends(require_permission("integrations:read")),
):
    """Return a (cached) health snapshot for the health panel."""
    registry = get_integration_registry()
    if registry.get(integration_id) is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    health = await registry.health(integration_id)
    return {
        "ok": health.ok,
        "detail": health.detail,
        "checked_at": health.checked_at,
        "circuit_state": health.circuit_state,
    }


@router.get("/{integration_id}/analyzers")
async def list_integration_analyzers(
    integration_id: str,
    user: TokenPayload = Depends(require_permission("integrations:read")),
):
    """List a Cortex integration's enabled analyzer catalog.

    Enrichment (Cortex) only: other integration types have no analyzer concept and
    are rejected 400. Fail-open — a Cortex that is unreachable surfaces a ``502``
    without ever touching local state.
    """
    registry = get_integration_registry()
    config = registry.get(integration_id)
    if config is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    if config.type != "cortex":
        raise HTTPException(
            status_code=400, detail="Analyzers are only available for cortex integrations"
        )
    connector = registry.build_enrichment_connector(config)
    if connector is None:
        raise HTTPException(
            status_code=400, detail="Integration is not fully configured"
        )
    try:
        analyzers = await connector.list_analyzers()
    except ConnectorError as exc:
        raise HTTPException(status_code=502, detail=f"Analyzer list failed: {exc}") from None
    return {"analyzers": analyzers, "count": len(analyzers)}


@router.get("/{integration_id}/responders")
async def list_integration_responders(
    integration_id: str,
    user: TokenPayload = Depends(require_permission("integrations:read")),
):
    """List a Cortex integration's enabled responder catalog.

    Enrichment (Cortex) only: other integration types have no responder concept and
    are rejected 400. Fail-open — a Cortex that is unreachable surfaces a ``502``
    without ever touching local state.
    """
    registry = get_integration_registry()
    config = registry.get(integration_id)
    if config is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    if config.type != "cortex":
        raise HTTPException(
            status_code=400, detail="Responders are only available for cortex integrations"
        )
    connector = registry.build_enrichment_connector(config)
    if connector is None:
        raise HTTPException(
            status_code=400, detail="Integration is not fully configured"
        )
    try:
        responders = await connector.list_responders()
    except ConnectorError as exc:
        raise HTTPException(status_code=502, detail=f"Responder list failed: {exc}") from None
    return {"responders": responders, "count": len(responders)}


@router.post("/reload")
async def reload_integrations(
    user: TokenPayload = Depends(require_permission("integrations:write")),
):
    """Reload integration configs from disk."""
    registry = get_integration_registry()
    registry.reload()
    return {"message": "Integrations reloaded", "count": len(registry.configs)}


# ─── Case push ────────────────────────────────────────────────────────────────


@router.post("/push/case/{case_id}")
async def push_case(
    case_id: str,
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("integrations:write")),
):
    """Push (create or idempotently update) an investigation case to a platform.

    The body must carry ``integration_id``. The case's observables and tasks are
    included. If the case was pushed to this platform before, the existing remote
    record is updated instead of creating a duplicate (link-store idempotency).
    """
    integration_id = str(data.get("integration_id") or "").strip()
    if not integration_id:
        raise HTTPException(status_code=400, detail="'integration_id' is required")

    registry = get_integration_registry()
    config = registry.get(integration_id)
    if config is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    if not config.enabled:
        raise HTTPException(status_code=400, detail="Integration is disabled")

    case = await _get_case_scoped(user, case_id)
    connector = registry.build_connector(config)
    if connector is None:
        raise HTTPException(
            status_code=400, detail="Integration is not fully configured"
        )

    observables = await get_observable_store().list_for_case(case_id)
    tasks = await get_task_store().list_for_case(case_id)

    link_store = get_integration_link_store()
    existing = await link_store.get(config.type, "case", case_id)
    remote_id = (existing or {}).get("remote_id") or None

    audit = get_audit_logger()
    try:
        result = await connector.push_case(
            case, observables, tasks, remote_id=remote_id
        )
    except TlpGateError as exc:
        # Local data-sharing policy refusal (e.g. everything is TLP:RED) — the
        # remote was never contacted for the restricted data. Audit + 400.
        await audit.log(
            actor=user.sub,
            action="integration_push_blocked",
            resource_type="integration",
            resource_id=integration_id,
            details=str({"case_id": case_id, "reason": str(exc)}),
        )
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except ConnectorError as exc:
        await audit.log(
            actor=user.sub,
            action="integration_push_failed",
            resource_type="integration",
            resource_id=integration_id,
            details=str({"case_id": case_id, "error": str(exc)}),
        )
        # Fail-open: surface the failure without ever touching the local case.
        raise HTTPException(status_code=502, detail=f"Push failed: {exc}") from None

    link = await link_store.upsert(
        connector=config.type,
        local_type="case",
        local_id=case_id,
        remote_id=result.remote_id,
        remote_url=result.remote_url,
        etag=result.etag,
    )

    await audit.log(
        actor=user.sub,
        action="integration_push_succeeded",
        resource_type="integration",
        resource_id=integration_id,
        details=str(
            {
                "case_id": case_id,
                "remote_id": result.remote_id,
                "created": result.created,
            }
        ),
    )
    return {
        "ok": True,
        "created": result.created,
        "remote_id": result.remote_id,
        "remote_url": result.remote_url,
        "detail": result.detail,
        "link": link,
    }


@router.get("/push/case/{case_id}/links")
async def case_links(
    case_id: str,
    user: TokenPayload = Depends(require_permission("integrations:read")),
):
    """List the remote records a case has been pushed to (all platforms)."""
    await _get_case_scoped(user, case_id)
    links = await get_integration_link_store().list_for_local("case", case_id)
    return {"links": links}
