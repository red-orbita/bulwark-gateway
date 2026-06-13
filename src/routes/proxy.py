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

Streaming:
  When stream=true, responses are forwarded as SSE with chunk-level
  output filtering. Content is buffered in small windows for pattern
  matching before being flushed to the client.
"""

import asyncio
import ipaddress
import json
import socket
import time
from urllib.parse import urlparse

import httpx
import structlog
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from src.config import settings
from src.enrichment.manager import get_enrichment_manager
from src.guardrails.input_guardrail import InputGuardrail
from src.guardrails.output_filter import OutputFilter
from src.guardrails.session_tracker import get_session_tracker
from src.models import (
    GuardrailResult,
    SecurityEvent,
    ThreatCategory,
    ToolCall,
    Verdict,
)
from src.scanners.pipeline import get_scanner_pipeline
from src.scanners.protocol import ScanContext
from src.telemetry.counters import get_counters
from src.telemetry.queue import get_telemetry_queue
from src.telemetry.schema import from_security_event
from src.telemetry.notifications import get_notification_engine, AlertPayload

router = APIRouter()
logger = structlog.get_logger()

input_guardrail = InputGuardrail()
output_filter = OutputFilter()

# C-01/H-01: SSRF prevention — Two-tier approach:
# 1. _ALWAYS_BLOCKED: Cloud metadata, link-local, loopback — blocked for ALL requests
# 2. _USER_CONTENT_BLOCKED: Private ranges (10/172/192) — blocked only for user-supplied URLs
#    Admin-configured backends (agents.yaml) are allowed to use private IPs (cluster-internal).
#    DNS rebinding protection still applies: we resolve at request-time, not registration-time.

_ALWAYS_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / AWS metadata
    ipaddress.ip_network("0.0.0.0/8"),         # "This" network
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
    ipaddress.ip_network("::ffff:127.0.0.0/104"),  # IPv4-mapped loopback
    ipaddress.ip_network("::ffff:169.254.0.0/112"),  # IPv4-mapped link-local
]

_USER_CONTENT_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),        # Private Class A
    ipaddress.ip_network("172.16.0.0/12"),     # Private Class B
    ipaddress.ip_network("192.168.0.0/16"),    # Private Class C
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT (shared address space)
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique local
    ipaddress.ip_network("::ffff:10.0.0.0/104"),  # IPv4-mapped private
    ipaddress.ip_network("::ffff:172.16.0.0/108"),  # IPv4-mapped private
    ipaddress.ip_network("::ffff:192.168.0.0/112"),  # IPv4-mapped private
]

_BLOCKED_HOSTNAMES = {
    "metadata.google.internal", "metadata.google.internal.",
    "metadata", "localhost",
    "kubernetes.default", "kubernetes.default.svc",
}

# Cloud metadata IPs (explicit for clarity)
_BLOCKED_IPS = {
    "169.254.169.254",   # AWS/GCP/Azure metadata
    "fd00:ec2::254",     # AWS IPv6 metadata
    "100.100.100.200",   # Alibaba Cloud metadata
}


def _is_ssrf_target(url: str, *, allow_private: bool = False) -> bool:
    """Validate URL at request-time to prevent SSRF via DNS rebinding (C-01).

    Resolves hostname to IP and checks against blocked CIDR ranges.

    Args:
        url: The URL to validate.
        allow_private: If True (operator-configured backends), allow RFC1918 private IPs
                       but still block metadata/loopback/link-local. If False (user content),
                       block all private and special-use ranges.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Block known dangerous hostnames (always)
    if hostname.lower().rstrip(".") in _BLOCKED_HOSTNAMES:
        return True
    # Block .internal/.local for user content, but allow for operator backends
    # (K8s services use .svc.cluster.local)
    if not allow_private:
        if hostname.lower().endswith(".internal") or hostname.lower().endswith(".local"):
            return True

    # Resolve DNS at request time (prevents DNS rebinding)
    try:
        addr_infos = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError):
        return True  # Fail-closed: cannot resolve → block

    for addr_info in addr_infos:
        ip_str = addr_info[4][0]
        if ip_str in _BLOCKED_IPS:
            return True
        try:
            ip = ipaddress.ip_address(ip_str)
            # Always-blocked: metadata, loopback, link-local
            for network in _ALWAYS_BLOCKED_NETWORKS:
                if ip in network:
                    return True
            # User-content only: private ranges (10/172/192, CGNAT, ULA)
            if not allow_private:
                for network in _USER_CONTENT_BLOCKED_NETWORKS:
                    if ip in network:
                        return True
        except ValueError:
            return True  # Fail-closed

    return False


@router.post("/chat/completions")
async def chat_completions(request: Request):
    """OpenAI-compatible chat completions with security guardrails."""
    _req_start = time.perf_counter()
    _counters = get_counters()
    tenant_id = getattr(request.state, "tenant_id", "default")
    agent_id = getattr(request.state, "agent_id", "default")
    source_ip = request.client.host if request.client else None

    # Parse request body
    # SECURITY FIX (VULN 1.6): Enforce body size limit regardless of Content-Length header.
    # Chunked transfer encoding has no Content-Length, so the previous check was bypassable.
    # Now we read the raw body with an explicit size cap.
    MAX_BODY_SIZE = 10 * 1024 * 1024  # 10MB
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_BODY_SIZE:
        return JSONResponse(
            status_code=413,
            content={"error": {"message": "Request body too large (max 10MB)", "type": "validation_error", "code": "body_too_large"}},
        )
    try:
        raw_body = await request.body()
        if len(raw_body) > MAX_BODY_SIZE:
            return JSONResponse(
                status_code=413,
                content={"error": {"message": "Request body too large (max 10MB)", "type": "validation_error", "code": "body_too_large"}},
            )
        body = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON body") from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid request body") from exc

    messages = body.get("messages", [])

    # === PHASE 1: Input Guardrail ===
    # Use scanner pipeline if available, otherwise fall back to direct call
    _pipeline = get_scanner_pipeline()
    if _pipeline.input_blocking_count > 0 and settings.scanners_pipeline_enabled:
        _scan_ctx = ScanContext(
            tenant_id=tenant_id,
            agent_id=agent_id,
            request_id=f"{tenant_id}:{agent_id}:{int(time.time()*1000)}",
            messages=messages,
            source_ip=source_ip,
        )
        user_content = " ".join(
            msg.get("content", "") for msg in messages if msg.get("role") == "user" and msg.get("content")
        )
        input_result = await _pipeline.run_input_blocking(user_content, _scan_ctx)
    else:
        input_result = input_guardrail.inspect_messages(messages, tenant_id, agent_id)

    if input_result.verdict == Verdict.BLOCK:
        await _log_events(input_result.events, source_ip)
        asyncio.create_task(_fire_webhook_alert(input_result.events, tenant_id, agent_id))
        _push_recent_block(input_result.events, tenant_id, agent_id)
        _counters.record("block", (time.perf_counter() - _req_start) * 1000)
        _record_tenant_usage(tenant_id, "block")
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": "Request blocked by security policy",
                    "type": "security_violation",
                    "code": "input_guardrail_block",
                }
            },
        )

    if input_result.verdict == Verdict.WARN:
        await _log_events(input_result.events, source_ip)
        asyncio.create_task(_fire_webhook_alert(input_result.events, tenant_id, agent_id))

    # === PHASE 1a: Multi-turn decomposition check ===
    # Tracks threat signal accumulation across requests from same session.
    # Even if the current request passed input guardrail (ALLOW/WARN), the accumulated
    # context across multiple requests may reveal a decomposition attack.
    if input_result.verdict != Verdict.BLOCK:
        _session_tracker = get_session_tracker()
        user_content_for_session = " ".join(
            msg.get("content", "") for msg in messages if msg.get("role") == "user" and msg.get("content")
        )
        if user_content_for_session:
            session_result = _session_tracker.check_and_update(
                user_content_for_session, tenant_id, agent_id, source_ip
            )
            if session_result.verdict == Verdict.BLOCK:
                await _log_events(session_result.events, source_ip)
                asyncio.create_task(_fire_webhook_alert(session_result.events, tenant_id, agent_id))
                _push_recent_block(session_result.events, tenant_id, agent_id)
                _counters.record("block", (time.perf_counter() - _req_start) * 1000)
                _record_tenant_usage(tenant_id, "block")
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": {
                            "message": "Request blocked: multi-turn attack pattern detected",
                            "type": "security_violation",
                            "code": "session_decomposition_block",
                        }
                    },
                )
            elif session_result.verdict == Verdict.WARN:
                await _log_events(session_result.events, source_ip)
                asyncio.create_task(_fire_webhook_alert(session_result.events, tenant_id, agent_id))

    # === PHASE 1b: Fire async ML scanners immediately (parallel with backend call) ===
    # These run in the background regardless of client disconnection.
    if settings.scanners_pipeline_enabled and _pipeline.input_async_count > 0:
        user_content_for_async = " ".join(
            msg.get("content", "") for msg in messages if msg.get("role") == "user" and msg.get("content")
        )
        if user_content_for_async:
            asyncio.create_task(_run_async_scanners_and_log(user_content_for_async, _scan_ctx, tenant_id, agent_id))

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
            await _log_events([event], source_ip)
            asyncio.create_task(_fire_webhook_alert([event], tenant_id, agent_id))
            _push_recent_block([event], tenant_id, agent_id)
            _counters.record("block", (time.perf_counter() - _req_start) * 1000)
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
    # Resolve backend dynamically from agent registry (auto-reload on config change)
    agent_registry = request.app.state.agent_registry
    if agent_registry._file_changed():
        await agent_registry.load()
    backend = agent_registry.resolve(tenant_id, agent_id)

    # M-02: Reject unregistered tenants/agents (fail-closed)
    if backend is None:
        return JSONResponse(
            status_code=403,
            content={"error": {"message": "Unknown tenant or agent", "type": "authorization_error"}},
        )

    is_streaming = body.get("stream", False)

    # === Response Cache: check for cached response (non-streaming only) ===
    from src.services.response_cache import get_response_cache
    response_cache = get_response_cache()
    if response_cache.enabled and not is_streaming:
        cached_response = response_cache.get(body)
        if cached_response:
            # Cache hit — skip backend call entirely
            _counters.record("allow", (time.perf_counter() - _req_start) * 1000)
            _record_tenant_usage(tenant_id, "allow")
            return JSONResponse(content=cached_response)

    # Build ordered list of backends to try (primary + fallbacks)
    backends_to_try = [backend] + backend.fallback_backends

    last_error = None
    for attempt_idx, current_backend in enumerate(backends_to_try):
        try:
            async with httpx.AsyncClient(timeout=current_backend.timeout) as client:
                backend_headers = {
                    "Content-Type": "application/json",
                }
                # Use agent-specific auth if configured
                # H-04: Only forward auth from pre-configured backend auth, NOT from client headers
                if current_backend.auth_header and current_backend.auth_token:
                    backend_headers[current_backend.auth_header] = current_backend.auth_token

                backend_url = f"{current_backend.backend_url.rstrip('/')}{current_backend.path_prefix}/chat/completions"

                # SECURITY FIX (VULN 1.2): ALWAYS perform SSRF check at request-time,
                # even for operator-configured backends. DNS rebinding can cause a
                # previously-valid hostname to resolve to dangerous IPs (169.254.169.254,
                # loopback, link-local) between registration and request time.
                # allow_private=True: admin-configured backends CAN use cluster-internal
                # RFC1918 IPs (10.x, 172.16.x, 192.168.x) but NOT metadata/loopback.
                if _is_ssrf_target(backend_url, allow_private=True):
                    logger.warning("ssrf_blocked", backend_url=backend_url, tenant=tenant_id, agent=agent_id)
                    return JSONResponse(
                        status_code=403,
                        content={"error": {"message": "Backend URL resolves to blocked address", "type": "security_violation", "code": "ssrf_block"}},
                    )

                if is_streaming:
                    # Streaming path: forward SSE with chunk-level guardrails
                    policy_engine = request.app.state.policy_loader.engine
                    return await _handle_streaming(
                        client,
                        backend_url,
                        body,
                        backend_headers,
                        tenant_id,
                        agent_id,
                        source_ip,
                        ioc_manager,
                        policy_engine,
                    )

                resp = await client.post(
                    backend_url,
                    json=body,
                    headers=backend_headers,
                )

                # If we got a server error (5xx) and have fallbacks, try next
                if resp.status_code >= 500 and attempt_idx < len(backends_to_try) - 1:
                    await logger.awarn(
                        "backend_failover",
                        primary=current_backend.backend_url,
                        status=resp.status_code,
                        attempt=attempt_idx + 1,
                        next_backend=backends_to_try[attempt_idx + 1].backend_url,
                    )
                    continue

                # Success or client error — stop trying
                break

        except (httpx.TimeoutException, httpx.ConnectError) as exc:
            last_error = exc
            if attempt_idx < len(backends_to_try) - 1:
                # Log failover and try next backend
                await logger.awarn(
                    "backend_failover",
                    primary=current_backend.backend_url,
                    error=type(exc).__name__,
                    attempt=attempt_idx + 1,
                    next_backend=backends_to_try[attempt_idx + 1].backend_url,
                )
                continue
            else:
                # All backends exhausted
                _counters.record_error()
                _counters.record("allow", (time.perf_counter() - _req_start) * 1000)
                _record_tenant_usage(tenant_id, "allow")
                if isinstance(exc, httpx.TimeoutException):
                    raise HTTPException(status_code=504, detail="Request timed out") from exc
                raise HTTPException(status_code=502, detail="Service unavailable") from exc

    if resp.status_code != 200:
        _counters.record("allow", (time.perf_counter() - _req_start) * 1000)
        _record_tenant_usage(tenant_id, "allow")
        try:
            error_body = resp.json()
        except Exception:
            error_body = {"error": resp.text[:500]}
        return JSONResponse(status_code=resp.status_code, content=error_body)

    try:
        response_data = resp.json()
    except Exception:
        return JSONResponse(status_code=502, content={"error": "Backend returned invalid JSON"})

    # === PHASE 4: Tool Call Policy Enforcement ===
    policy_engine = request.app.state.policy_loader.engine
    choices = response_data.get("choices", [])

    for choice in choices:
        message = choice.get("message", {})
        tool_calls_raw = message.get("tool_calls", [])

        if tool_calls_raw:
            tool_calls = []
            for tc in tool_calls_raw:
                try:
                    args = json.loads(tc.get("function", {}).get("arguments", "{}"))
                except (json.JSONDecodeError, TypeError):
                    args = {}
                tool_calls.append(
                    ToolCall(
                        id=tc.get("id"),
                        name=tc.get("function", {}).get("name", ""),
                        arguments=args,
                    )
                )

            policy_result = policy_engine.evaluate_tool_calls(tool_calls, tenant_id, agent_id)

            if policy_result.verdict == Verdict.BLOCK:
                await _log_events(policy_result.events, source_ip)
                asyncio.create_task(_fire_webhook_alert(policy_result.events, tenant_id, agent_id))
                _push_recent_block(policy_result.events, tenant_id, agent_id)
                # Remove blocked tool calls from response
                message["tool_calls"] = [
                    tc
                    for tc in tool_calls_raw
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
                        "ioc_in_tool_call", tool=tc.name, matches=ioc_matches, tenant=tenant_id
                    )

    # === PHASE 5: Output Filter ===
    for choice in choices:
        message = choice.get("message", {})
        content = message.get("content")
        if content:
            # Use scanner pipeline for output filtering if available
            if _pipeline.output_blocking_count > 0 and settings.scanners_pipeline_enabled:
                _out_ctx = ScanContext(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    request_id=_scan_ctx.request_id if settings.scanners_pipeline_enabled else "",
                    messages=messages,
                    source_ip=source_ip,
                )
                filter_result = await _pipeline.run_output_blocking(content, _out_ctx)
            else:
                filter_result = output_filter.inspect_and_redact(content, tenant_id, agent_id)

            if filter_result.verdict == Verdict.REDACT and filter_result.modified_content:
                message["content"] = filter_result.modified_content
                await _log_events(filter_result.events, source_ip)
                asyncio.create_task(_fire_webhook_alert(filter_result.events, tenant_id, agent_id))
            elif filter_result.verdict == Verdict.BLOCK:
                # Block dangerous output entirely — replace with safe message
                message["content"] = "[Content blocked by security policy — output contained dangerous material]"
                await _log_events(filter_result.events, source_ip)
                asyncio.create_task(_fire_webhook_alert(filter_result.events, tenant_id, agent_id))
                _push_recent_block(filter_result.events, tenant_id, agent_id)
            elif filter_result.verdict == Verdict.WARN and filter_result.events:
                # WARN: log to SIEM + notify but don't modify content
                await _log_events(filter_result.events, source_ip)
                asyncio.create_task(_fire_webhook_alert(filter_result.events, tenant_id, agent_id))

    # === PHASE 5b: Output Async Scanners (fire-and-forget) ===
    # Run async output scanners (hallucination detection, etc.) in background.
    if settings.scanners_pipeline_enabled and _pipeline.output_async_count > 0:
        for choice in choices:
            message = choice.get("message", {})
            content = message.get("content")
            if content:
                _out_ctx = ScanContext(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    request_id=_scan_ctx.request_id if settings.scanners_pipeline_enabled else "",
                    messages=messages,
                    source_ip=source_ip,
                )
                asyncio.create_task(_run_output_async_scanners(content, _out_ctx, tenant_id, agent_id))

    # === PHASE 6: Async Enrichment (fire-and-forget) ===
    # Note: Async scanners already fired at Phase 1b (before backend call).
    # Only legacy enrichment manager runs here.
    enrichment_mgr = get_enrichment_manager()
    if enrichment_mgr.enabled:
        # Collect all user message content for enrichment
        user_content = " ".join(
            msg.get("content", "") for msg in messages if msg.get("role") == "user" and msg.get("content")
        )
        if user_content:
            request_id = f"{tenant_id}:{agent_id}:{int(time.time()*1000)}"
            asyncio.create_task(
                _enrich_and_record(user_content, input_result.verdict.value, request_id, tenant_id)
            )

    # === Cost Tracking: parse usage tokens from response ===
    usage_data = response_data.get("usage")
    response_model = response_data.get("model", body.get("model", "unknown"))
    if usage_data:
        from src.services.cost_tracker import get_cost_tracker
        cost_tracker = get_cost_tracker()
        cost_tracker.record_usage(tenant_id, agent_id, response_model, usage_data)

    # === Response Cache: store successful response ===
    if response_cache.enabled and not is_streaming:
        response_cache.put(body, response_data)

    _counters.record(input_result.verdict.value, (time.perf_counter() - _req_start) * 1000)
    _record_tenant_usage(tenant_id, input_result.verdict.value)
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
        await _log_events(result.events, request.client.host if request.client else None)
        if result.verdict == Verdict.BLOCK:
            asyncio.create_task(_fire_webhook_alert(result.events, tenant_id, agent_id))

    return {
        "verdict": result.verdict.value,
        "allowed": result.verdict != Verdict.BLOCK,
        "blocked_tools": result.blocked_tools,
        "events": [e.model_dump(mode="json") for e in result.events] if result.events else [],
    }


async def _handle_streaming(
    client: httpx.AsyncClient,
    url: str,
    body: dict,
    headers: dict,
    tenant_id: str,
    agent_id: str,
    source_ip: str | None,
    ioc_manager,
    policy_engine,
) -> StreamingResponse:
    """Forward streaming SSE response with chunk-level output guardrails.

    Strategy:
    - Buffer content tokens in a sliding window (BUFFER_SIZE chars)
    - Run output filter on each buffer flush
    - If REDACT verdict: replace content with redacted version
    - If dangerous output detected: terminate stream with error event
    - C-01: Tool call chunks are BUFFERED and policy-checked BEFORE yielding to client
    """
    BUFFER_SIZE = 256  # chars before flushing to client

    async def stream_generator():
        content_buffer = ""
        tool_call_buffer: dict[int, dict] = {}  # index -> {name, arguments}
        tool_call_lines: list[str] = []  # C-01: Buffer raw SSE lines until policy validated
        blocked = False

        try:
            async with client.stream("POST", url, json=body, headers=headers) as resp:
                if resp.status_code != 200:
                    error_body = await resp.aread()
                    yield f"data: {error_body.decode()}\n\n"
                    return

                async for line in resp.aiter_lines():
                    if blocked:
                        break

                    if not line.startswith("data: "):
                        yield f"{line}\n"
                        continue

                    data = line[6:]
                    if data == "[DONE]":
                        # Flush remaining buffer
                        if content_buffer:
                            redacted = _filter_chunk(content_buffer, tenant_id, agent_id, source_ip)
                            if redacted is None:
                                # Dangerous content — emit error
                                yield _make_error_event("Output blocked by security policy")
                                blocked = True
                                break
                            yield _make_content_event(redacted)
                        yield "data: [DONE]\n\n"
                        return

                    try:
                        chunk = json.loads(data)
                    except json.JSONDecodeError:
                        yield f"{line}\n"
                        continue

                    choices = chunk.get("choices", [])
                    for choice in choices:
                        delta = choice.get("delta", {})
                        finish_reason = choice.get("finish_reason")

                        # C-01: Accumulate tool calls — do NOT yield until policy validated
                        if "tool_calls" in delta:
                            for tc_delta in delta["tool_calls"]:
                                idx = tc_delta.get("index", 0)
                                if idx not in tool_call_buffer:
                                    tool_call_buffer[idx] = {"name": "", "arguments": ""}
                                if "function" in tc_delta:
                                    fn = tc_delta["function"]
                                    if "name" in fn:
                                        tool_call_buffer[idx]["name"] = fn["name"]
                                    if "arguments" in fn:
                                        tool_call_buffer[idx]["arguments"] += fn["arguments"]
                            # Buffer the SSE line — NOT yielded yet
                            tool_call_lines.append(f"{line}\n\n")
                            continue

                        # C-01: Tool calls finished — perform policy check BEFORE yielding
                        if finish_reason == "tool_calls" and tool_call_buffer:
                            # Build ToolCall objects for policy evaluation
                            tool_calls_for_policy = []
                            for idx in sorted(tool_call_buffer.keys()):
                                tc_data = tool_call_buffer[idx]
                                try:
                                    args = json.loads(tc_data["arguments"]) if tc_data["arguments"] else {}
                                except (json.JSONDecodeError, TypeError):
                                    args = {}
                                tool_calls_for_policy.append(
                                    ToolCall(
                                        id=f"call_{idx}",
                                        name=tc_data["name"],
                                        arguments=args,
                                    )
                                )

                            policy_result = policy_engine.evaluate_tool_calls(
                                tool_calls_for_policy, tenant_id, agent_id
                            )

                            if policy_result.verdict == Verdict.BLOCK:
                                # Log security events + fire notifications
                                await _log_events(policy_result.events, source_ip)
                                asyncio.create_task(_fire_webhook_alert(policy_result.events, tenant_id, agent_id))
                                _push_recent_block(policy_result.events, tenant_id, agent_id)
                                # Emit error instead of tool calls
                                blocked_names = ", ".join(policy_result.blocked_tools)
                                yield _make_error_event(
                                    f"Tool calls blocked by security policy: {blocked_names}"
                                )
                                blocked = True
                                break

                            # Policy ALLOW — now yield all buffered tool call lines
                            for buffered_line in tool_call_lines:
                                yield buffered_line
                            yield f"{line}\n\n"  # yield the finish event
                            tool_call_lines.clear()
                            tool_call_buffer.clear()
                            continue

                        # Content token — buffer for output filtering
                        content_token = delta.get("content")
                        if content_token:
                            content_buffer += content_token

                            # Flush when buffer is full (sliding window filter)
                            if len(content_buffer) >= BUFFER_SIZE:
                                redacted = _filter_chunk(
                                    content_buffer, tenant_id, agent_id, source_ip
                                )
                                if redacted is None:
                                    yield _make_error_event("Output blocked by security policy")
                                    blocked = True
                                    break
                                yield _make_content_event(redacted)
                                content_buffer = ""
                            continue

                        # Non-content delta (role, etc) — pass through
                        yield f"{line}\n\n"

        except httpx.TimeoutException:
            yield _make_error_event("Request timed out")
        except httpx.ConnectError:
            yield _make_error_event("Service unavailable")

    return StreamingResponse(
        stream_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _filter_chunk(content: str, tenant_id: str, agent_id: str, source_ip: str | None) -> str | None:
    """Run output filter on a content chunk.

    Returns redacted content, or None if content should be blocked entirely.
    Events from this function are emitted asynchronously via _emit_streaming_events.
    """
    result = output_filter.inspect_and_redact(content, tenant_id, agent_id)
    if result.verdict == Verdict.BLOCK:
        # Fire telemetry for streaming block (fire-and-forget)
        if result.events:
            _schedule_streaming_telemetry(result.events, tenant_id, agent_id, source_ip)
        return None
    if result.verdict == Verdict.REDACT and result.modified_content:
        # Fire telemetry for streaming redaction (fire-and-forget)
        if result.events:
            _schedule_streaming_telemetry(result.events, tenant_id, agent_id, source_ip)
        return result.modified_content
    return content


def _schedule_streaming_telemetry(
    events: list[SecurityEvent], tenant_id: str, agent_id: str, source_ip: str | None
):
    """Schedule streaming telemetry emission. Safe to call from sync context."""
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_emit_streaming_events(events, tenant_id, agent_id, source_ip))
    except RuntimeError:
        # No running event loop (e.g., in unit tests) — skip telemetry
        pass


async def _emit_streaming_events(
    events: list[SecurityEvent], tenant_id: str, agent_id: str, source_ip: str | None
):
    """Emit telemetry events from streaming output filter (fire-and-forget)."""
    try:
        await _log_events(events, source_ip)
        await _fire_webhook_alert(events, tenant_id, agent_id)
    except Exception:
        pass  # Never let telemetry errors affect streaming


def _make_content_event(content: str) -> str:
    """Create an SSE event with a content delta."""
    chunk = {"choices": [{"index": 0, "delta": {"content": content}, "finish_reason": None}]}
    return f"data: {json.dumps(chunk)}\n\n"


def _make_error_event(message: str) -> str:
    """Create an SSE error event and terminate stream."""
    error = {
        "error": {
            "message": message,
            "type": "security_violation",
            "code": "output_guardrail_block",
        }
    }
    return f"data: {json.dumps(error)}\n\ndata: [DONE]\n\n"


async def _run_async_scanners_and_log(
    content: str, context, tenant_id: str, agent_id: str
):
    """Run async scanners and log any security events they produce."""
    try:
        pipeline = get_scanner_pipeline()
        results = await pipeline.run_input_async(content, context)
        for result in results:
            if result.events:
                await _log_events(result.events)
                await _fire_webhook_alert(result.events, tenant_id, agent_id)
    except Exception as e:
        # Log async scanner failures for debugging (don't crash)
        await logger.awarn("async_scanner_error", error=str(e)[:200])


async def _run_output_async_scanners(
    content: str, context, tenant_id: str, agent_id: str
):
    """Run async OUTPUT scanners (hallucination, relevance, etc.) and log events."""
    try:
        pipeline = get_scanner_pipeline()
        results = await pipeline.run_output_async(content, context)
        for result in results:
            if result.events:
                await _log_events(result.events)
                await _fire_webhook_alert(result.events, tenant_id, agent_id)
    except Exception as e:
        await logger.awarn("output_async_scanner_error", error=str(e)[:200])


async def _log_events(events: list[SecurityEvent], source_ip: str | None = None):
    """Log security events for SIEM and enqueue to telemetry pipeline."""
    queue = get_telemetry_queue()
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
        # Enqueue to telemetry — non-blocking, ≤2ms
        telemetry_event = from_security_event(
            verdict=event.verdict.value,
            rule_id=event.matched_pattern,
            rule_description=event.description,
            threat_category=event.category.value if event.category else None,
            tenant_id=event.tenant_id or "unknown",
            agent_id=event.agent_id,
            guardrail_layer=event.source or "unknown",
            latency_ms=0.0,
            source_ip=source_ip,
            confidence=1.0,
        )
        queue.enqueue_nowait(telemetry_event)


async def _fire_webhook_alert(events: list[SecurityEvent], tenant_id: str, agent_id: str):
    """Fire notification alerts for block/warn events."""
    engine = get_notification_engine()
    if not engine.configured:
        return
    for event in events:
        alert = AlertPayload(
            verdict=event.verdict.value if event.verdict else "block",
            severity=event.severity or "high",
            category=event.category.value if event.category else "unknown",
            description=event.description,
            tenant_id=tenant_id,
            agent_id=agent_id,
            matched_patterns=[event.matched_pattern] if event.matched_pattern else [],
        )
        try:
            await engine.send_alert(alert)
        except Exception as e:
            logger.error(f"notification_error: {type(e).__name__}: {e}")


def _push_recent_block(events: list[SecurityEvent], tenant_id: str, agent_id: str):
    """Push block event to Redis recent-blocks list (non-blocking, best effort)."""
    try:
        from src.guardrails.dynamic_registry import get_pattern_registry
        registry = get_pattern_registry()
        r = registry._redis
        if not r:
            return
        import json as _json
        for event in events[:3]:  # Max 3 events per block
            entry = _json.dumps({
                "ts": time.time(),
                "tenant": tenant_id,
                "agent": agent_id,
                "category": event.category.value if event.category else "unknown",
                "description": event.description,
                "severity": event.severity or "high",
                "pattern": event.matched_pattern or "",
            })
            r.lpush("sentinel:recent_blocks", entry)
            r.ltrim("sentinel:recent_blocks", 0, 49)  # Keep last 50
    except Exception:
        pass


def _record_tenant_usage(tenant_id: str, verdict: str):
    """Increment per-tenant AND global usage counters in Redis (best effort)."""
    try:
        from src.guardrails.dynamic_registry import get_pattern_registry
        registry = get_pattern_registry()
        r = registry._redis
        if not r:
            return
        r.hincrby("sentinel:usage:total", tenant_id, 1)
        r.hincrby(f"sentinel:usage:{verdict}", tenant_id, 1)
        # Global counters (persist across pod restarts)
        r.incrby("sentinel:global:requests_total", 1)
        r.incrby(f"sentinel:global:{verdict}", 1)
    except Exception:
        pass


async def _enrich_and_record(
    text: str, verdict: str, request_id: str, tenant_id: str
) -> None:
    """Fire-and-forget: run enrichment scanners and record in AttackReplayDB.

    Also emits security events to SIEM if enrichment detects anything notable
    (e.g., embedding similarity match to known attacks, post-hoc detection).
    """
    try:
        enrichment_mgr = get_enrichment_manager()
        results = await enrichment_mgr.enrich(text, request_id)

        # Record in AttackReplayDB
        from src.enrichment.attack_replay_db import get_attack_replay_db
        replay_db = get_attack_replay_db()
        replay_db.record(
            payload=text,
            verdict=verdict,
            source="input_guardrail",
            request_id=request_id,
            tenant_id=tenant_id,
            enrichment_results=results,
        )

        # Emit SIEM events if enrichment found something notable
        if results:
            for enrichment_result in results:
                # Enrichment results with similarity > threshold produce events
                if hasattr(enrichment_result, "verdict") and enrichment_result.verdict != Verdict.ALLOW:
                    event = SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id="enrichment",
                        verdict=enrichment_result.verdict,
                        category=ThreatCategory.PROMPT_INJECTION,
                        description=f"Enrichment detection: {getattr(enrichment_result, 'description', 'semantic match')}",
                        source="enrichment_pipeline",
                        severity="medium",
                        metadata={"request_id": request_id},
                    )
                    await _log_events([event])
    except Exception as e:
        # Never let enrichment errors affect anything
        await logger.awarn("enrichment_pipeline_error", error=str(e))
