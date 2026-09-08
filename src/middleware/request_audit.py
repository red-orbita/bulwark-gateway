"""Optional SIEM request activity, separate from security detections.

Pure ASGI middleware observes completion without consuming or buffering bodies.
HTTP success is not a guardrail ALLOW: output may have been redacted or blocked.
"""

import asyncio
import json
import logging
import os
import time
from pathlib import Path

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from src.config import settings
from src.telemetry.queue import get_telemetry_queue
from src.telemetry.schema import (
    BulwarkFields,
    ECSEvent,
    SecurityTelemetryEvent,
    TelemetryEventCategory,
    TelemetrySeverity,
    TenantFields,
)

logger = logging.getLogger(__name__)


class RequestAuditMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self._enabled = settings.siem_request_audit_enabled
        self._checked = 0.0
        self._lock = asyncio.Lock()

    async def _audit_enabled(self) -> bool:
        if time.monotonic() - self._checked >= 2:
            async with self._lock:
                if time.monotonic() - self._checked >= 2:
                    try:
                        path = Path(os.getenv("BULWARK_SIEM_ACTIVITY_FILE", "shared/siem/activity.json"))
                        raw = await asyncio.to_thread(path.read_text)
                        mode = json.loads(raw)["mode"]
                        if mode not in ("detections", "all_requests"):
                            raise ValueError("Invalid activity mode")
                        self._enabled = mode == "all_requests"
                    except FileNotFoundError:
                        self._enabled = settings.siem_request_audit_enabled
                    except (OSError, ValueError, KeyError, TypeError):
                        logger.warning("request_audit_config_unavailable")
                    self._checked = time.monotonic()
        return self._enabled

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or not scope.get("path", "").startswith(("/v1/", "/v2/"))
            or not await self._audit_enabled()
        ):
            await self.app(scope, receive, send)
            return

        started = time.perf_counter_ns()
        status = 0
        completed = False
        failed = False

        async def observe(message: Message) -> None:
            nonlocal status, completed
            await send(message)
            if message["type"] == "http.response.start":
                status = message["status"]
            elif message["type"] == "http.response.body" and not message.get("more_body", False):
                completed = True

        try:
            await self.app(scope, receive, observe)
        except BaseException:
            failed = True
            raise
        finally:
            # Audit is best effort and cannot change the response or hide errors.
            try:
                duration = time.perf_counter_ns() - started
                state = scope.get("state", {})
                action = "request_completed" if completed and not failed else "request_interrupted"
                route = scope.get("route")
                labels = {
                    "http_method": scope.get("method", "")[:16],
                    "http_status_code": str(status),
                    # Never export a user-controlled path/query (may carry secrets).
                    "route": getattr(route, "path", "unmatched")[:256],
                    "response_complete": str(completed and not failed).lower(),
                }
                record = SecurityTelemetryEvent(
                    message="Gateway request activity",
                    tags=["bulwark-gateway", "request-audit"],
                    labels=labels,
                    event=ECSEvent(
                        kind="event", category=TelemetryEventCategory.WEB, action=action,
                        outcome="success" if completed and not failed and 200 <= status < 400 else "failure",
                        severity=TelemetrySeverity.INFORMATIONAL, duration=duration,
                    ),
                    bulwark=BulwarkFields(
                        verdict="not_evaluated", guardrail_layer="request_audit",
                        request_id=state.get("request_id"), latency_ms=duration / 1_000_000,
                    ),
                    # Only authentication middleware state, never tenant headers.
                    tenant=TenantFields(
                        id=state.get("tenant_id", "unknown") if state.get("subject_id") else "unknown",
                        agent_id=state.get("agent_id") if state.get("subject_id") else None,
                    ),
                )
                if not get_telemetry_queue().enqueue_nowait(record):
                    logger.warning("request_audit_queue_full")
            except Exception:
                logger.warning("request_audit_unavailable")
