"""
Proxy route — OpenAI-compatible chat completions endpoint with guardrails.

Flow:
  1. Receive request
  2. Input guardrail (prompt injection, jailbreak)
  3. IOC check on content
  4. Forward to backend
  5. Intercept tool calls → tool policy enforcement
  6. Output filter (redact secrets/PII)
  7. Return response
"""
import json
import httpx
import structlog
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse

from src.config import settings
from src.models import (
    ChatRequest, ToolCall, Verdict, ThreatCategory, SecurityEvent, GuardrailResult
)
from src.guardrails.input_guardrail import InputGuardrail
from src.guardrails.output_filter import OutputFilter
from src.guardrails.tool_policy import ToolPolicyEngine

router = APIRouter()
logger = structlog.get_logger()

input_guardrail = InputGuardrail()
output_filter = OutputFilter()


@router.post("/chat/completions")
async def chat_completions(request: Request):
    """OpenAI-compatible chat completions with security guardrails."""
    tenant_id = getattr(request.state, "tenant_id", "default")
    agent_id = getattr(request.state, "agent_id", "default")

    # Parse request body
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    messages = body.get("messages", [])

    # === PHASE 1: Input Guardrail ===
    input_result = input_guardrail.inspect_messages(messages, tenant_id, agent_id)

    if input_result.verdict == Verdict.BLOCK:
        await _log_events(input_result.events)
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": "Request blocked by security policy",
                    "type": "security_violation",
                    "code": "input_guardrail_block",
                    "details": [e.description for e in input_result.events],
                }
            },
        )

    if input_result.verdict == Verdict.WARN:
        await _log_events(input_result.events)

    # === PHASE 2: IOC Check ===
    ioc_manager = request.app.state.ioc_manager
    for msg in messages:
        content = msg.get("content", "") or ""
        ioc_matches = ioc_manager.check_content(content)
        if ioc_matches:
            event = SecurityEvent(
                tenant_id=tenant_id,
                agent_id=agent_id,
                verdict=Verdict.BLOCK,
                category=ThreatCategory.MALICIOUS_DOMAIN,
                description=f"IOC detected in input: {', '.join(ioc_matches[:5])}",
                source="ioc_check",
                severity="critical",
            )
            await _log_events([event])
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": "Request contains known malicious indicators",
                        "type": "security_violation",
                        "code": "ioc_block",
                    }
                },
            )

    # === PHASE 3: Forward to backend ===
    try:
        async with httpx.AsyncClient(timeout=settings.backend_timeout) as client:
            # Forward with original headers minus auth (re-auth to backend separately)
            backend_headers = {
                "Content-Type": "application/json",
            }
            # If backend needs its own auth, add it here
            backend_auth = request.headers.get("X-Backend-Auth")
            if backend_auth:
                backend_headers["Authorization"] = f"Bearer {backend_auth}"

            resp = await client.post(
                f"{settings.backend_url}/v1/chat/completions",
                json=body,
                headers=backend_headers,
            )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Backend timeout")
    except httpx.ConnectError:
        raise HTTPException(status_code=502, detail="Backend unreachable")

    if resp.status_code != 200:
        return JSONResponse(status_code=resp.status_code, content=resp.json())

    response_data = resp.json()

    # === PHASE 4: Tool Call Policy Enforcement ===
    policy_engine = request.app.state.policy_loader.engine
    choices = response_data.get("choices", [])

    for choice in choices:
        message = choice.get("message", {})
        tool_calls_raw = message.get("tool_calls", [])

        if tool_calls_raw:
            tool_calls = [
                ToolCall(
                    id=tc.get("id"),
                    name=tc.get("function", {}).get("name", ""),
                    arguments=json.loads(tc.get("function", {}).get("arguments", "{}")),
                )
                for tc in tool_calls_raw
            ]

            policy_result = policy_engine.evaluate_tool_calls(tool_calls, tenant_id, agent_id)

            if policy_result.verdict == Verdict.BLOCK:
                await _log_events(policy_result.events)
                # Remove blocked tool calls from response
                message["tool_calls"] = [
                    tc for tc in tool_calls_raw
                    if tc.get("function", {}).get("name") not in policy_result.blocked_tools
                ]
                # If all tools blocked, return a text response instead
                if not message["tool_calls"]:
                    message.pop("tool_calls", None)
                    message["content"] = (
                        "I cannot perform that action as it violates the security policy. "
                        f"Blocked tools: {', '.join(policy_result.blocked_tools)}"
                    )

            # Also check tool call arguments for IOCs
            for tc in tool_calls:
                args_str = json.dumps(tc.arguments)
                ioc_matches = ioc_manager.check_content(args_str)
                if ioc_matches:
                    await logger.awarn(
                        "ioc_in_tool_call", tool=tc.name,
                        matches=ioc_matches, tenant=tenant_id
                    )

    # === PHASE 5: Output Filter ===
    for choice in choices:
        message = choice.get("message", {})
        content = message.get("content")
        if content:
            filter_result = output_filter.inspect_and_redact(content, tenant_id, agent_id)
            if filter_result.verdict == Verdict.REDACT and filter_result.modified_content:
                message["content"] = filter_result.modified_content
                await _log_events(filter_result.events)

    return JSONResponse(content=response_data)


@router.post("/tool/validate")
async def validate_tool_call(request: Request):
    """
    Sidecar mode endpoint: validate a tool call before execution.
    Called by agent frameworks that support pre-execution hooks.
    """
    tenant_id = getattr(request.state, "tenant_id", "default")
    agent_id = getattr(request.state, "agent_id", "default")

    body = await request.json()
    tool_call = ToolCall(
        id=body.get("id"),
        name=body.get("name", ""),
        arguments=body.get("arguments", {}),
    )

    policy_engine = request.app.state.policy_loader.engine
    result = policy_engine.evaluate_tool_call(tool_call, tenant_id, agent_id)

    # Also run input guardrail on arguments
    args_str = json.dumps(tool_call.arguments)
    input_result = input_guardrail.inspect(args_str, tenant_id, agent_id)

    if input_result.verdict == Verdict.BLOCK:
        result = GuardrailResult(
            verdict=Verdict.BLOCK,
            events=result.events + input_result.events,
            blocked_tools=[tool_call.name],
        )

    if result.events:
        await _log_events(result.events)

    return {
        "verdict": result.verdict.value,
        "allowed": result.verdict != Verdict.BLOCK,
        "blocked_tools": result.blocked_tools,
        "events": [e.model_dump(mode="json") for e in result.events] if result.events else [],
    }


async def _log_events(events: list[SecurityEvent]):
    """Log security events for SIEM."""
    for event in events:
        await logger.awarn(
            "security_event",
            verdict=event.verdict.value,
            category=event.category.value,
            description=event.description,
            tenant=event.tenant_id,
            agent=event.agent_id,
            severity=event.severity,
            tool=event.tool_name,
            pattern=event.matched_pattern,
        )
