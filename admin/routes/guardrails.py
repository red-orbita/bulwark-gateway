"""Guardrail & Filter routes — Pattern management + sandbox testing + persistence."""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import JSONResponse

from ..models.auth import TokenPayload
from ..models.config import GuardrailTestRequest, GuardrailTestResult
from ..services.auth_service import require_permission
from ..services.config_validator import ConfigValidator
from ..services.audit_logger import get_audit_logger
from ..services.guardrails_store import get_guardrails_store
from ..services.redis_sync import sync_all, sync_disabled_patterns, sync_custom_patterns

router = APIRouter()

# In-memory state for guardrail module toggles and params
_PARAMS_FILE = Path("/app/data/guardrail_params.json")
_module_state = {"input": True, "tool_policy": True, "output": True}
_params = {"entropy_threshold": 4.5, "max_input_size": 102400, "max_nesting_depth": 10, "chunk_window": 4096}


def _load_persisted_state():
    """Load params/module state from disk if available."""
    global _params, _module_state
    if _PARAMS_FILE.exists():
        try:
            data = json.loads(_PARAMS_FILE.read_text())
            if "params" in data:
                _params.update(data["params"])
            if "modules" in data:
                _module_state.update(data["modules"])
        except Exception:
            pass


def _save_persisted_state():
    """Save params/module state to disk."""
    try:
        _PARAMS_FILE.parent.mkdir(parents=True, exist_ok=True)
        _PARAMS_FILE.write_text(json.dumps({"params": _params, "modules": _module_state}, indent=2))
    except Exception:
        pass


# Load on import
_load_persisted_state()

# In-memory pattern registry (loaded from guardrail source at startup)
_patterns_cache: list[dict] | None = None


def _load_patterns() -> list[dict]:
    """Extract pattern metadata from guardrail modules."""
    global _patterns_cache
    if _patterns_cache is not None:
        return _patterns_cache

    patterns = []
    try:
        from src.guardrails.input_guardrail import InputGuardrail
        ig = InputGuardrail()
        for i, p in enumerate(getattr(ig, 'all_patterns', [])):
            patterns.append({
                "id": f"input-{i}",
                "layer": "input",
                "description": getattr(p, 'description', f'Pattern {i}'),
                "regex": getattr(p, 'regex', None).pattern[:120] if getattr(p, 'regex', None) else '',
                "severity": getattr(p, 'severity', 'medium'),
                "category": p.category.value if hasattr(p, 'category') and p.category else 'unknown',
                "enabled": True,
            })
    except Exception:
        pass

    try:
        from src.guardrails.output_filter import (
            OutputFilter, REDACTION_PATTERNS, DANGEROUS_OUTPUT_PATTERNS, HUMAN_REVIEW_PATTERNS
        )
        # REDACTION_PATTERNS: list of (compiled_regex, label) tuples
        for i, p in enumerate(REDACTION_PATTERNS):
            regex_str = p[0].pattern[:120] if hasattr(p[0], 'pattern') else str(p[0])[:120]
            label = p[1] if len(p) > 1 else f"redaction_{i}"
            patterns.append({
                "id": f"output-redact-{i}",
                "layer": "output",
                "description": f"REDACT: {label}",
                "regex": regex_str,
                "severity": "medium",
                "category": "credential_leak",
                "enabled": True,
            })
        # DANGEROUS_OUTPUT_PATTERNS: list of (compiled_regex, description) tuples
        for i, p in enumerate(DANGEROUS_OUTPUT_PATTERNS):
            regex_str = p[0].pattern[:120] if hasattr(p[0], 'pattern') else str(p[0])[:120]
            label = p[1] if len(p) > 1 else f"dangerous_{i}"
            patterns.append({
                "id": f"output-danger-{i}",
                "layer": "output",
                "description": f"DANGEROUS: {label}",
                "regex": regex_str,
                "severity": "critical",
                "category": "insecure_output",
                "enabled": True,
            })
        # HUMAN_REVIEW_PATTERNS
        for i, p in enumerate(HUMAN_REVIEW_PATTERNS):
            regex_str = p[0].pattern[:120] if hasattr(p[0], 'pattern') else str(p[0])[:120]
            label = p[1] if len(p) > 1 else f"review_{i}"
            patterns.append({
                "id": f"output-review-{i}",
                "layer": "output",
                "description": f"REVIEW: {label}",
                "regex": regex_str,
                "severity": "high",
                "category": "overreliance",
                "enabled": True,
            })
    except Exception:
        pass

    # Load tool policy rules from YAML policy files — show generic capabilities
    try:
        import yaml
        from pathlib import Path
        policies_dir = Path("config/policies")
        if policies_dir.exists():
            # Collect unique rule types across all tenants (generic, not tenant-specific)
            denied_tools_set: set = set()
            arg_restrictions: set = set()
            rate_limits_found = False
            max_calls_found = False

            for policy_file in policies_dir.glob("*.yaml"):
                with open(policy_file) as f:
                    policy = yaml.safe_load(f)
                for agent in policy.get("agents", []):
                    for tool in agent.get("denied_tools", []):
                        denied_tools_set.add(tool)
                    for tp in agent.get("tool_policies", []):
                        tool_name = tp.get("name", "")
                        if tp.get("rate_limit"):
                            rate_limits_found = True
                        if tp.get("max_calls_per_session"):
                            max_calls_found = True
                        for arg, denied_vals in tp.get("denied_arguments", {}).items():
                            if isinstance(denied_vals, list):
                                for val in denied_vals:
                                    arg_restrictions.add((tool_name, arg, str(val)))

            # Generate generic patterns
            for tool in sorted(denied_tools_set):
                patterns.append({
                    "id": f"tool-deny-{tool}",
                    "layer": "tool_policy",
                    "description": f"DENY tool: {tool}",
                    "regex": tool,
                    "severity": "high",
                    "category": "tool_deny",
                    "enabled": True,
                })
            for tool_name, arg, val in sorted(arg_restrictions):
                patterns.append({
                    "id": f"tool-arg-{tool_name}-{arg}-{hash(val) % 10000}",
                    "layer": "tool_policy",
                    "description": f"BLOCK argument: {tool_name}.{arg} contains '{val}'",
                    "regex": str(val),
                    "severity": "medium",
                    "category": "arg_restriction",
                    "enabled": True,
                })
            if rate_limits_found:
                patterns.append({
                    "id": "tool-rate-limit",
                    "layer": "tool_policy",
                    "description": "Rate limit enforcement per tool",
                    "regex": "rate_limit",
                    "severity": "medium",
                    "category": "rate_limit",
                    "enabled": True,
                })
            if max_calls_found:
                patterns.append({
                    "id": "tool-max-calls",
                    "layer": "tool_policy",
                    "description": "Max calls per session enforcement",
                    "regex": "max_calls_per_session",
                    "severity": "medium",
                    "category": "session_limit",
                    "enabled": True,
                })
    except Exception:
        pass

    _patterns_cache = patterns

    # Load persisted state on first access
    store = get_guardrails_store()
    store.load_state()

    return patterns


@router.get("/patterns")
async def list_patterns(user: TokenPayload = Depends(require_permission("guardrails:read"))):
    """List all guardrail patterns with metadata."""
    return _load_patterns()


@router.post("/patterns/{pattern_id}/toggle")
async def toggle_pattern(
    pattern_id: str,
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Toggle a pattern on/off."""
    patterns = _load_patterns()
    for p in patterns:
        if p["id"] == pattern_id:
            p["enabled"] = not p["enabled"]
            audit = get_audit_logger()
            await audit.log(actor=user.sub, action="guardrail_toggle", resource_type="pattern", resource_id=pattern_id)
            get_guardrails_store().save_state()
            sync_disabled_patterns(patterns)
            return {"id": pattern_id, "enabled": p["enabled"]}
    raise HTTPException(status_code=404, detail="Pattern not found")


@router.put("/patterns/{pattern_id}")
async def update_pattern(
    pattern_id: str,
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Update a pattern's description, regex, severity, category, enabled state."""
    patterns = _load_patterns()
    for p in patterns:
        if p["id"] == pattern_id:
            if "description" in data:
                p["description"] = data["description"]
            if "regex" in data:
                valid, error = ConfigValidator.validate_regex_pattern(data["regex"])
                if not valid:
                    raise HTTPException(status_code=422, detail=f"Invalid regex: {error}")
                p["regex"] = data["regex"]
            if "severity" in data:
                p["severity"] = data["severity"]
            if "category" in data:
                p["category"] = data["category"]
            if "enabled" in data:
                p["enabled"] = data["enabled"]
            audit = get_audit_logger()
            await audit.log(actor=user.sub, action="guardrail_update", resource_type="pattern", resource_id=pattern_id)
            get_guardrails_store().save_state()
            sync_all(patterns)
            return p
    raise HTTPException(status_code=404, detail="Pattern not found")


@router.post("/patterns")
async def create_pattern(
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Create a new pattern."""
    regex = data.get("regex", "")
    if regex:
        valid, error = ConfigValidator.validate_regex_pattern(regex)
        if not valid:
            raise HTTPException(status_code=422, detail=f"Invalid regex: {error}")

    patterns = _load_patterns()
    new_id = f"{data.get('layer', 'input')}-custom-{uuid.uuid4().hex[:8]}"
    new_pattern = {
        "id": new_id,
        "layer": data.get("layer", "input"),
        "description": data.get("description", "Custom pattern"),
        "regex": regex,
        "severity": data.get("severity", "high"),
        "category": data.get("category", "custom"),
        "enabled": True,
    }
    patterns.append(new_pattern)

    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="guardrail_create", resource_type="pattern", resource_id=new_id)
    get_guardrails_store().save_state()
    sync_custom_patterns(patterns)
    return new_pattern


@router.delete("/patterns/{pattern_id}")
async def delete_pattern(
    pattern_id: str,
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Delete a custom pattern."""
    patterns = _load_patterns()
    for i, p in enumerate(patterns):
        if p["id"] == pattern_id:
            if "custom" not in pattern_id:
                raise HTTPException(status_code=400, detail="Cannot delete built-in patterns")
            patterns.pop(i)
            audit = get_audit_logger()
            await audit.log(actor=user.sub, action="guardrail_delete", resource_type="pattern", resource_id=pattern_id)
            get_guardrails_store().save_state()
            sync_all(patterns)
            return {"deleted": pattern_id}
    raise HTTPException(status_code=404, detail="Pattern not found")


@router.post("/modules/{module}/toggle")
async def toggle_module(
    module: str,
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Toggle an entire guardrail module on/off."""
    if module not in _module_state:
        raise HTTPException(status_code=400, detail=f"Invalid module: {module}")
    _module_state[module] = not _module_state[module]
    _save_persisted_state()
    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="module_toggle", resource_type="guardrail_module", resource_id=module)
    get_guardrails_store().save_state()
    return {"module": module, "enabled": _module_state[module]}


@router.get("/params")
async def get_params(user: TokenPayload = Depends(require_permission("guardrails:read"))):
    """Get current detection parameters."""
    return _params


@router.put("/params")
async def update_params(
    params: dict = Body(...),
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Update detection parameters."""
    for key in ("entropy_threshold", "max_input_size", "max_nesting_depth", "chunk_window"):
        if key in params:
            _params[key] = params[key]
    _save_persisted_state()
    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="params_update", resource_type="guardrail_params", resource_id="global")
    get_guardrails_store().save_state()
    return _params


# --- Persistence endpoints ---


@router.post("/persist")
async def force_persist(user: TokenPayload = Depends(require_permission("guardrails:write"))):
    """Force save current guardrail state to disk."""
    store = get_guardrails_store()
    store.save_state()
    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="guardrail_persist", resource_type="guardrail_state", resource_id="manual")
    return {"status": "persisted"}


@router.get("/export")
async def export_config(user: TokenPayload = Depends(require_permission("guardrails:read"))):
    """Export full guardrails config as downloadable JSON."""
    store = get_guardrails_store()
    data = store.export_config()
    return JSONResponse(
        content=data,
        headers={"Content-Disposition": "attachment; filename=guardrails_config.json"},
    )


@router.post("/import")
async def import_config(
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Import guardrails config from JSON."""
    store = get_guardrails_store()
    store.import_config(data)
    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="guardrail_import", resource_type="guardrail_state", resource_id="import")
    return {"status": "imported"}


@router.get("/history")
async def guardrail_history(user: TokenPayload = Depends(require_permission("guardrails:read"))):
    """Get guardrail change history."""
    store = get_guardrails_store()
    return await store.get_history()


# --- Output pattern endpoints ---


@router.get("/output-patterns")
async def list_output_patterns(user: TokenPayload = Depends(require_permission("guardrails:read"))):
    """List output filter patterns."""
    patterns = _load_patterns()
    return [p for p in patterns if p["layer"] == "output"]


@router.post("/output-patterns")
async def create_output_pattern(
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Create a new output filter pattern."""
    data["layer"] = "output"
    regex = data.get("regex", "")
    if regex:
        valid, error = ConfigValidator.validate_regex_pattern(regex)
        if not valid:
            raise HTTPException(status_code=422, detail=f"Invalid regex: {error}")

    patterns = _load_patterns()
    new_id = f"output-custom-{uuid.uuid4().hex[:8]}"
    new_pattern = {
        "id": new_id,
        "layer": "output",
        "description": data.get("description", "Custom output pattern"),
        "regex": regex,
        "severity": data.get("severity", "high"),
        "category": data.get("category", "output_filter"),
        "enabled": True,
    }
    patterns.append(new_pattern)

    audit = get_audit_logger()
    await audit.log(actor=user.sub, action="guardrail_create", resource_type="pattern", resource_id=new_id)
    get_guardrails_store().save_state()
    return new_pattern


@router.put("/output-patterns/{pattern_id}")
async def update_output_pattern(
    pattern_id: str,
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Update an output filter pattern."""
    patterns = _load_patterns()
    for p in patterns:
        if p["id"] == pattern_id and p["layer"] == "output":
            if "description" in data:
                p["description"] = data["description"]
            if "regex" in data:
                valid, error = ConfigValidator.validate_regex_pattern(data["regex"])
                if not valid:
                    raise HTTPException(status_code=422, detail=f"Invalid regex: {error}")
                p["regex"] = data["regex"]
            if "severity" in data:
                p["severity"] = data["severity"]
            if "category" in data:
                p["category"] = data["category"]
            if "enabled" in data:
                p["enabled"] = data["enabled"]
            audit = get_audit_logger()
            await audit.log(actor=user.sub, action="guardrail_update", resource_type="pattern", resource_id=pattern_id)
            get_guardrails_store().save_state()
            return p
    raise HTTPException(status_code=404, detail="Output pattern not found")


@router.delete("/output-patterns/{pattern_id}")
async def delete_output_pattern(
    pattern_id: str,
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Delete an output filter pattern."""
    patterns = _load_patterns()
    for i, p in enumerate(patterns):
        if p["id"] == pattern_id and p["layer"] == "output":
            if "custom" not in pattern_id:
                raise HTTPException(status_code=400, detail="Cannot delete built-in patterns")
            patterns.pop(i)
            audit = get_audit_logger()
            await audit.log(actor=user.sub, action="guardrail_delete", resource_type="pattern", resource_id=pattern_id)
            get_guardrails_store().save_state()
            return {"deleted": pattern_id}
    raise HTTPException(status_code=404, detail="Output pattern not found")


# --- Tool policy endpoints ---


@router.get("/tool-policy/{tenant_id}/{agent_id}")
async def get_tool_policy(
    tenant_id: str,
    agent_id: str,
    user: TokenPayload = Depends(require_permission("guardrails:read")),
):
    """Get tool policy rules for a specific tenant/agent."""
    try:
        from src.guardrails.tool_policy import ToolPolicy
        tp = ToolPolicy()
        rules = tp.get_rules(tenant_id, agent_id)
        return {"tenant_id": tenant_id, "agent_id": agent_id, "rules": rules}
    except Exception:
        # Fallback: read from policy YAML files (search by tenant field)
        import yaml
        from pathlib import Path
        policies_dir = Path("config/policies")
        if not policies_dir.exists():
            raise HTTPException(status_code=404, detail=f"No policy for tenant: {tenant_id}")

        # Find policy file that matches this tenant
        agent_policy = None
        for policy_file in policies_dir.glob("*.yaml"):
            try:
                with open(policy_file) as f:
                    policy = yaml.safe_load(f)
                if policy.get("tenant") == tenant_id:
                    for agent in policy.get("agents", []):
                        if agent.get("id") == agent_id:
                            agent_policy = agent
                            break
                    if agent_policy:
                        break
            except Exception:
                continue

        if not agent_policy:
            raise HTTPException(status_code=404, detail=f"No policy for {tenant_id}/{agent_id}")

        return {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "rules": {
                "allowed_tools": agent_policy.get("allowed_tools", []),
                "denied_tools": agent_policy.get("denied_tools", []),
                "max_tool_calls": agent_policy.get("max_tool_calls", 0),
                "sandbox_level": agent_policy.get("sandbox_level", "standard"),
                "tool_policies": agent_policy.get("tool_policies", []),
            },
        }


@router.put("/tool-policy/{tenant_id}/{agent_id}")
async def update_tool_policy(
    tenant_id: str,
    agent_id: str,
    data: dict = Body(...),
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Update tool policy rules for a specific tenant/agent."""
    import yaml
    from pathlib import Path

    # Sanitize tenant_id and agent_id against path traversal
    if "/" in tenant_id or "\\" in tenant_id or ".." in tenant_id:
        raise HTTPException(status_code=400, detail="Invalid tenant_id")
    if "/" in agent_id or "\\" in agent_id or ".." in agent_id:
        raise HTTPException(status_code=400, detail="Invalid agent_id")

    policies_dir = Path("config/policies").resolve()
    policy_path = (policies_dir / f"{tenant_id}.yaml").resolve()
    if not policy_path.is_relative_to(policies_dir):
        raise HTTPException(status_code=400, detail="Invalid path")
    if not policy_path.exists():
        raise HTTPException(status_code=404, detail=f"No policy for tenant: {tenant_id}")

    with open(policy_path) as f:
        policy = yaml.safe_load(f)

    if "agents" not in policy:
        policy["agents"] = {}
    if agent_id not in policy["agents"]:
        policy["agents"][agent_id] = {}
    policy["agents"][agent_id]["tools"] = data.get("rules", data)

    with open(policy_path, "w") as f:
        yaml.safe_dump(policy, f, default_flow_style=False)

    audit = get_audit_logger()
    await audit.log(
        actor=user.sub,
        action="tool_policy_update",
        resource_type="tool_policy",
        resource_id=f"{tenant_id}/{agent_id}",
    )
    get_guardrails_store().save_state()
    return {"tenant_id": tenant_id, "agent_id": agent_id, "rules": policy["agents"][agent_id]["tools"]}


@router.post("/test", response_model=GuardrailTestResult)
async def test_guardrail(
    req: GuardrailTestRequest,
    user: TokenPayload = Depends(require_permission("guardrails:test")),
):
    """Sandbox: test a payload against the guardrail engine."""
    start = time.perf_counter()

    if req.layer == "input":
        from src.guardrails.input_guardrail import InputGuardrail
        ig = InputGuardrail()
        result = ig.inspect(req.payload, req.tenant_id, req.agent_id)
    elif req.layer == "output":
        from src.guardrails.output_filter import OutputFilter
        of = OutputFilter()
        result = of.inspect_and_redact(req.payload, req.tenant_id, req.agent_id)
    else:
        raise HTTPException(status_code=400, detail=f"Invalid layer: {req.layer}")

    latency_ms = (time.perf_counter() - start) * 1000

    events = []
    for e in result.events:
        events.append({
            "description": e.description,
            "category": e.category.value if e.category else None,
            "severity": getattr(e, "severity", None),
            "matched_pattern": getattr(e, "matched_pattern", None),
        })

    matched_patterns_info = []
    for e in events:
        if e.get("matched_pattern"):
            matched_patterns_info.append({
                "id": e.get("matched_pattern", ""),
                "description": e.get("description", ""),
                "category": e.get("category", ""),
            })

    return GuardrailTestResult(
        verdict=result.verdict.value,
        events=events,
        latency_ms=round(latency_ms, 3),
        matched_patterns=matched_patterns_info,
    )


@router.post("/validate-pattern")
async def validate_pattern(
    pattern: str = Body(..., embed=True),
    user: TokenPayload = Depends(require_permission("guardrails:write")),
):
    """Validate a regex pattern without applying it."""
    valid, error = ConfigValidator.validate_regex_pattern(pattern)
    return {"valid": valid, "error": error}


@router.get("/stats")
async def guardrail_stats(user: TokenPayload = Depends(require_permission("guardrails:read"))):
    """Get guardrail pattern statistics."""
    patterns = _load_patterns()
    layers = {}
    for p in patterns:
        layers[p["layer"]] = layers.get(p["layer"], 0) + 1

    return {
        "total_patterns": len(patterns),
        "active_patterns": sum(1 for p in patterns if p["enabled"]),
        "layers": layers,
        "modules": _module_state,
    }
