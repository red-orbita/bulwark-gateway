"""Validation routes — Dry-run/apply config changes + orchestrator task runner."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from fastapi import APIRouter, Depends, HTTPException

from ..models.auth import TokenPayload
from ..models.config import ConfigApplyRequest, ConfigApplyResult
from ..services.audit_logger import get_audit_logger
from ..services.auth_service import require_permission
from ..services.config_validator import ConfigValidator, HotReloader

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Orchestrator task runner
#
# Backs the dashboard "Orchestrator Actions" panel. Each button triggers a
# short-lived background task whose result the UI polls for. Tasks delegate to
# the shared evaluation helpers so the logic stays DRY with /admin/evaluation.
# ---------------------------------------------------------------------------

# Bounded in-memory task registry (best-effort; admin runs as a single replica).
_TASKS: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
_MAX_TASKS = 100


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _prune_tasks() -> None:
    """Evict oldest completed tasks once the registry exceeds the cap."""
    while len(_TASKS) > _MAX_TASKS:
        _TASKS.popitem(last=False)


async def _run_qa_validation() -> dict[str, Any]:
    from .evaluation import perform_qa_validation

    return await asyncio.to_thread(perform_qa_validation)


async def _run_benchmark() -> dict[str, Any]:
    from .evaluation import perform_benchmark

    return await asyncio.to_thread(perform_benchmark)


async def _run_redteam_audit() -> dict[str, Any]:
    from .evaluation import perform_evaluation

    # Quick preset: all supported categories, 5 attacks each, with benign set.
    return await perform_evaluation(count_per_category=5, include_benign=True)


# task name -> (human label, coroutine factory)
_TASK_RUNNERS: dict[str, tuple[str, Callable[[], Awaitable[dict[str, Any]]]]] = {
    "qa-validation": ("QA Validation", _run_qa_validation),
    "redteam-audit": ("Red Team Audit", _run_redteam_audit),
    "performance-benchmark": ("Performance Benchmark", _run_benchmark),
}


def _format_output(task: str, result: dict[str, Any]) -> str:
    """Render a task result as a readable text block for the dashboard <pre>."""
    lines: list[str] = []
    if task == "qa-validation":
        lines.append(
            f"QA Validation: {result.get('status', 'n/a').upper()}  "
            f"({result.get('passed', 0)}/{result.get('total', 0)} passed, "
            f"{result.get('failed', 0)} failed)"
        )
        for r in result.get("results", []):
            mark = "PASS" if r.get("pass") else "FAIL"
            lines.append(
                f"  [{mark}] {r.get('name')}: expected={r.get('expected')} "
                f"actual={r.get('actual')}"
            )
    elif task == "performance-benchmark":
        lines.append(
            f"Benchmark: {result.get('status', 'n/a').upper()}  "
            f"(target p95 < {result.get('target_p95_ms')}ms)"
        )
        lines.append(
            f"  iterations={result.get('iterations')}  "
            f"p50={result.get('p50_ms')}ms  p95={result.get('p95_ms')}ms  "
            f"p99={result.get('p99_ms')}ms  max={result.get('max_ms')}ms  "
            f"avg={result.get('avg_ms')}ms"
        )
    elif task == "redteam-audit":
        lines.append(
            f"Red Team Audit: {result.get('detected', 0)}/"
            f"{result.get('total_attacks', 0)} attacks detected "
            f"(detection={result.get('detection_rate', 0):.1%}, "
            f"bypass={result.get('bypass_rate', 0):.1%}, "
            f"false-positives={result.get('false_positive_rate', 0):.1%})"
        )
        for cat in result.get("categories", []):
            lines.append(
                f"  {cat.get('name')}: {cat.get('detected')}/{cat.get('total')} "
                f"detected ({cat.get('rate', 0):.1%})"
            )
    else:  # pragma: no cover - guarded by caller
        lines.append(str(result))
    return "\n".join(lines)


async def _execute_task(task_id: str, task: str) -> None:
    """Run a task coroutine and record its outcome in the registry."""
    _label, runner = _TASK_RUNNERS[task]
    try:
        result = await runner()
        entry = _TASKS.get(task_id)
        if entry is None:
            return
        entry.update(
            status="completed",
            output=_format_output(task, result),
            result=result,
            finished_at=_now(),
        )
    except Exception as exc:  # noqa: BLE001 - report failure to the operator
        logger.exception("orchestrator_task_failed task=%s id=%s", task, task_id)
        entry = _TASKS.get(task_id)
        if entry is not None:
            entry.update(
                status="failed",
                output=f"Task '{task}' failed: {exc}",
                error=str(exc),
                finished_at=_now(),
            )


@router.post("/trigger/{task}")
async def trigger_task(
    task: str,
    user: TokenPayload = Depends(require_permission("guardrails:test")),
):
    """Start an orchestrator task in the background and return its id.

    Supported tasks: ``qa-validation``, ``redteam-audit``,
    ``performance-benchmark``. Poll ``GET /admin/validate/task/{id}`` for results.
    """
    if task not in _TASK_RUNNERS:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown task '{task}'. Supported: {sorted(_TASK_RUNNERS)}",
        )

    task_id = f"{task}-{uuid.uuid4().hex[:12]}"
    _TASKS[task_id] = {
        "task_id": task_id,
        "task": task,
        "label": _TASK_RUNNERS[task][0],
        "status": "running",
        "output": None,
        "result": None,
        "started_at": _now(),
        "finished_at": None,
        "actor": user.sub,
    }
    _prune_tasks()

    asyncio.create_task(_execute_task(task_id, task))

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="orchestrator_trigger",
        resource_type="orchestrator_task",
        resource_id=task,
        details=json.dumps({"task_id": task_id}),
    )

    return {"task_id": task_id, "task": task, "status": "running"}


@router.get("/task/{task_id}")
async def get_task(
    task_id: str,
    user: TokenPayload = Depends(require_permission("admin:read")),
):
    """Return the current status and output of an orchestrator task."""
    entry = _TASKS.get(task_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found")
    return entry


@router.post("/dry-run")
async def dry_run_validation(
    content: str,
    user: TokenPayload = Depends(require_permission("config:validate")),
):
    """Validate config without applying. Returns validation result."""
    result = ConfigValidator.validate_yaml(content)
    return result.model_dump()


@router.post("/apply")
async def apply_config(
    req: ConfigApplyRequest,
    user: TokenPayload = Depends(require_permission("policies:apply")),
):
    """
    Apply policy: Dry-Run → Validate → Backup → Atomic Write → Audit.
    """
    from pathlib import Path

    path = Path("config/policies") / f"{req.policy_name}.yaml"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Policy '{req.policy_name}' not found")

    content = path.read_text()
    validation = ConfigValidator.validate_yaml(content)

    if req.dry_run:
        return ConfigApplyResult(
            success=validation.valid,
            policy_name=req.policy_name,
            version=1,
            dry_run=True,
            validation=validation,
        )

    if not validation.valid:
        raise HTTPException(status_code=422, detail={"errors": validation.errors})

    # Backup + apply
    HotReloader.backup_policy(req.policy_name)

    # Trigger hot-reload on proxy (if shared filesystem)
    # In production: send signal or API call to proxy service
    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="apply", resource_type="policy", resource_id=req.policy_name)

    from datetime import datetime, timezone
    return ConfigApplyResult(
        success=True,
        policy_name=req.policy_name,
        version=1,
        applied_at=datetime.now(timezone.utc),
        dry_run=False,
        validation=validation,
        rollback_version=0,
    )
