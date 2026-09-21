"""Opt-in durable evidence admission, independent of guardrail verdicts."""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, Literal

from .schema import (
    BulwarkFields,
    ECSEvent,
    SecurityTelemetryEvent,
    TelemetryEventCategory,
    TelemetrySeverity,
    TenantFields,
)

if TYPE_CHECKING:
    from .exporter import TelemetryExporter

AdmissionFailure = Literal[
    "audit_admission_invalid_config",
    "audit_admission_invalid_context",
    "audit_admission_unavailable",
    "audit_admission_not_durable",
    "audit_admission_no_route",
    "audit_admission_rejected",
    "audit_admission_timeout",
]
_SAFE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}")


async def admit_before_upstream(
    *,
    required: bool,
    exporter: TelemetryExporter | None,
    authenticated: bool,
    tenant_id: str,
    agent_id: str | None,
    request_id: str,
    timeout_ms: int = 250,
) -> AdmissionFailure | None:
    """Return None to continue, otherwise a stable reason to deny before I/O.

    Inject the started app-state exporter, authenticated middleware identities,
    and a server-generated request ID. No singleton, settings, request body,
    headers, URL, network probe, or remote acknowledgement is consulted here.
    Disabled mode touches no state and creates no evidence. Required mode is
    independent of the general fail-open setting and completion-audit switch.

    Cancellation propagates, never authorizing forwarding. A timeout may await
    the queue's cancellation-safe commit cleanup beyond the configured budget;
    an accepted row with no forwarded request is an intentional safe ambiguity.
    """
    if not required:
        return None
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= 10_000:
        return "audit_admission_invalid_config"
    if authenticated is not True or any(
        not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None
        for value in (tenant_id, request_id, *(() if agent_id is None else (agent_id,)))
    ):
        return "audit_admission_invalid_context"

    try:
        if exporter is None or exporter._initialized is not True or exporter._running is not True:
            return "audit_admission_unavailable"
        queue = exporter._queue
        if queue.durable is not True:
            return "audit_admission_not_durable"
        # Use the same tenant scopes as delivery. Shared mode additionally needs
        # a registered immutable snapshot present in the queue's current routes.
        if not any(
            (tw.tenant_scope == "global" or tenant_id in (
                tw.tenant_scope if isinstance(tw.tenant_scope, set) else {tw.tenant_scope}
            ))
            and (not queue.shared or (
                tw.snapshot is not None and tw.snapshot in queue._destinations and tw.snapshot.allows(tenant_id)
            ))
            for tw in exporter._transports
        ):
            return "audit_admission_no_route"

        record = SecurityTelemetryEvent(
            message="Gateway pre-upstream audit evidence",
            tags=["bulwark-gateway", "audit-admission"],
            event=ECSEvent(
                kind="event", category=TelemetryEventCategory.WEB,
                action="upstream_admission", outcome="unknown",
                severity=TelemetrySeverity.INFORMATIONAL,
            ),
            bulwark=BulwarkFields(
                verdict="not_evaluated", guardrail_layer="audit_admission", request_id=request_id,
            ),
            tenant=TenantFields(id=tenant_id, agent_id=agent_id),
        )
        deadline = asyncio.get_running_loop().time() + timeout_ms / 1000
        accepted = await asyncio.wait_for(queue.enqueue(record), timeout=timeout_ms / 1000)
        # Even a queue implementation that suppresses cancellation cannot grant
        # late admission after the decision budget expired.
        if asyncio.get_running_loop().time() >= deadline:
            return "audit_admission_timeout"
        return None if accepted is True else "audit_admission_rejected"
    except TimeoutError:
        return "audit_admission_timeout"
    except Exception:
        # Never expose exception text: storage errors may contain DSNs/secrets.
        return "audit_admission_unavailable"
