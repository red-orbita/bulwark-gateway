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
import os
import socket
import time
from contextvars import ContextVar
from urllib.parse import urlparse
from uuid import uuid4

import httpx
import structlog
from cachetools import TTLCache
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from src.config import settings
from src.correlation.event_tap import get_event_tap
from src.correlation.incident import get_correlator
from src.correlation.metrics import observe_correlation_latency, record_correlation_metric
from src.enrichment.manager import get_enrichment_manager
from src.guardrails.input_guardrail import InputGuardrail
from src.guardrails.output_filter import OutputFilter
from src.guardrails.session_tracker import get_session_tracker
from src.guardrails.tool_policy import _normalize_tool_name
from src.middleware.auth import _is_token_revoked
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
from src.telemetry.notifications import AlertPayload, get_notification_engine
from src.telemetry.queue import get_telemetry_queue
from src.telemetry.schema import from_security_event

router = APIRouter()
logger = structlog.get_logger()

# F3 (blast-radius): the authenticated subject for the request currently being
# handled, propagated to the correlation event tap without threading it through
# every ``_log_events`` call site. A ContextVar is task-local and is copied into
# child tasks spawned via ``asyncio.create_task`` (streaming / fire-and-forget
# enrichment) at creation time, so background risk accrual still attributes to the
# right subject. It is set from ``request.state.subject_id`` (server-derived,
# hashed downstream) and is NEVER written to logs or SIEM.
_request_subject: ContextVar[str | None] = ContextVar("bulwark_request_subject", default=None)

# Fase B (IR traceability): the stable per-request correlation id (honoured from
# an inbound X-Request-ID or minted by RequestIDMiddleware). Published here as a
# task-local ContextVar — inherited by fire-and-forget child tasks — so the event
# sinks can stamp it onto EVERY SecurityEvent without threading request_id through
# ~50 call sites. All events of one HTTP request thus share this key (the SIEM,
# logs, notifications and recent-blocks all join on it); event_id keeps the
# per-detection grain. Set from ``request.state.request_id``.
_request_id: ContextVar[str | None] = ContextVar("bulwark_request_id", default=None)


def _ensure_request_id(
    events: list[SecurityEvent], request_id: str | None = None
) -> None:
    """Stamp the request correlation id onto events that don't already carry one.

    Idempotent and order-independent: guardrail/pipeline engines produce events
    without a request_id, so this is where they inherit the per-request key. An
    explicit ``request_id`` (used on the streaming path, where ContextVar
    propagation across the response boundary is not guaranteed) takes precedence;
    otherwise the request-scoped ContextVar is used.
    """
    rid = request_id or _request_id.get()
    if not rid:
        return
    for ev in events:
        if not ev.request_id:
            ev.request_id = rid

input_guardrail = InputGuardrail()
output_filter = OutputFilter(
    redact_email=settings.redact_email,
    redact_phone=settings.redact_phone,
)


def _resolve_vault_key(tenant_id: str, provider: str) -> str | None:
    """Resolve the active backend key for (tenant, provider) from the vault.

    Defensive by design: the virtual-key manager raises ``SystemExit`` when
    ``BULWARK_KEY_ENCRYPTION_KEY`` is unset and may raise on Redis/crypto
    errors — none of that may ever crash a request on the hot path. Returns
    ``None`` when the vault is unavailable or holds no active key.
    """
    if not (
        os.environ.get("BULWARK_KEY_ENCRYPTION_KEY")
        or os.environ.get("BULWARK_KEY_ENCRYPTION_KEY_FILE")
        or os.environ.get("KEY_ENCRYPTION_KEY_FILE")
    ):
        return None
    try:
        from src.services.virtual_keys import get_virtual_key_manager

        mgr = get_virtual_key_manager()
        return mgr.get_backend_key(tenant_id, provider)
    except (Exception, SystemExit):  # noqa: BLE001 - vault must never break the hot path
        return None


def _resolve_backend_auth(backend, tenant_id: str) -> tuple[dict[str, str], str | None]:
    """Build the auth header(s) to send to ``backend`` for ``tenant_id``.

    Virtual Keys integration (data-path enforcement): when the backend declares
    a ``provider``, the credential is sourced from the encrypted per-tenant
    virtual-key vault at request time, taking precedence over any static
    ``auth_token`` in agents.yaml. This is what actually places the Virtual Keys
    subsystem on the request path — rotating/revoking a key in the vault changes
    (or cuts) backend access on the very next request.

    Returns ``(headers, error)``. When ``error`` is non-None the caller MUST
    fail closed: a provider was declared but no credential could be resolved,
    and we refuse to forward an unauthenticated request to the backend.
    """
    headers: dict[str, str] = {}
    provider = getattr(backend, "provider", None)
    if provider:
        vault_key = _resolve_vault_key(tenant_id, provider)
        if vault_key:
            header_name = backend.auth_header or "Authorization"
            scheme = getattr(backend, "auth_scheme", "Bearer ")
            headers[header_name] = f"{scheme}{vault_key}"
            return headers, None
        # Migration fallback: a static token in config is still honored so
        # operators can adopt virtual keys incrementally.
        if backend.auth_header and backend.auth_token:
            headers[backend.auth_header] = backend.auth_token
            return headers, None
        # Fail closed: provider declared but neither a vault key nor a static
        # token is available. Do not forward unauthenticated.
        return headers, f"no virtual key configured for provider '{provider}'"
    # No provider declared: legacy static auth from config (H-04).
    if backend.auth_header and backend.auth_token:
        headers[backend.auth_header] = backend.auth_token
    return headers, None

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

# PERFORMANCE (M-03 fix): Cache DNS resolutions for SSRF checks (5s TTL).
# Prevents blocking the event loop on repeated getaddrinfo() calls.
_DNS_CACHE: TTLCache = TTLCache(maxsize=256, ttl=5.0)

# H-04 fix: Maximum size for accumulated tool call arguments in streaming responses.
# Prevents memory exhaustion from malicious/compromised backends streaming infinite data.
_MAX_TOOL_ARGS_BYTES = int(os.environ.get("BULWARK_MAX_TOOL_ARGS_BYTES", str(1024 * 1024)))  # 1MB default

# SECURITY FIX (H-05): Per-tenant stream limit to prevent one tenant from
# exhausting all concurrent streaming slots and blocking other tenants.
# Previously a single global semaphore meant one tenant could block ALL streaming.
_MAX_CONCURRENT_STREAMS = int(os.environ.get("BULWARK_MAX_CONCURRENT_STREAMS", "50"))
_MAX_STREAMS_PER_TENANT = int(os.environ.get("BULWARK_MAX_STREAMS_PER_TENANT", "10"))
_TENANT_STREAM_LIMIT_MSG = f"Too many concurrent streams for tenant (max {_MAX_STREAMS_PER_TENANT})"
_stream_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_STREAMS)
_tenant_stream_counts: dict[str, int] = {}  # tenant_id -> active stream count (in-memory fallback)
_tenant_stream_lock = asyncio.Lock()

# P8-01 fix: Redis key prefix for distributed stream counting.
# With multiple Uvicorn workers, in-memory counters are per-process.
# Redis provides cross-worker consistency for true per-tenant limits.
_STREAM_KEY_PREFIX = "bulwark:streams"
_STREAM_KEY_GLOBAL = f"{_STREAM_KEY_PREFIX}:global"
_STREAM_TTL = 300  # Safety-net TTL (seconds) — auto-expire if decrement is lost


def _check_json_depth(obj, max_depth: int = 50, current: int = 0):
    """Post-parse depth check that catches nested arrays (P6-01 fix).

    object_pairs_hook only fires for JSON objects (dicts), not arrays.
    This recursive validator catches both dict and list nesting.
    """
    if current > max_depth:
        raise ValueError(f"JSON nesting exceeds {max_depth} levels")
    if isinstance(obj, dict):
        for v in obj.values():
            _check_json_depth(v, max_depth, current + 1)
    elif isinstance(obj, list):
        for item in obj:
            _check_json_depth(item, max_depth, current + 1)


def _get_stream_redis():
    """Get Redis client for stream counting (reuses dynamic registry connection)."""
    try:
        from src.guardrails.dynamic_registry import get_pattern_registry
        registry = get_pattern_registry()
        return registry._redis
    except Exception:
        return None


def _sanitize_backend_error(status_code: int, raw_body: bytes) -> dict:
    """Sanitize backend error responses before forwarding to client.

    SECURITY FIX (H-13): Never forward raw backend error bodies to clients.
    They may contain stack traces, internal URLs, database errors, or secrets.
    Return a safe, generic error message instead.
    """
    # Map common HTTP errors to safe messages
    safe_messages = {
        400: "Backend rejected the request (invalid format)",
        401: "Backend authentication failed",
        403: "Backend access denied",
        404: "Backend endpoint not found",
        429: "Backend rate limit exceeded",
        500: "Backend internal error",
        502: "Backend unavailable (bad gateway)",
        503: "Backend temporarily unavailable",
        504: "Backend request timed out",
    }
    message = safe_messages.get(status_code, f"Backend returned error {status_code}")
    return {
        "error": {
            "message": message,
            "type": "backend_error",
            "code": f"backend_{status_code}",
        }
    }


# SECURITY FIX (H-05): Shared httpx.AsyncClient with connection pooling.
# Previously, each request created a new client (new TCP connection + FD),
# making file descriptor exhaustion trivial. A shared pool limits total
# outbound connections and reuses TCP connections for performance.
_HTTP_POOL_LIMITS = httpx.Limits(
    max_connections=int(os.environ.get("BULWARK_MAX_BACKEND_CONNECTIONS", "100")),
    max_keepalive_connections=int(os.environ.get("BULWARK_MAX_KEEPALIVE", "20")),
    keepalive_expiry=30.0,
)
# SECURITY FIX (DOS-01): Pool acquisition timeout prevents connection exhaustion DoS.
# Without this, when all 100 connections are in use, new requests block for up to 120s
# (full backend timeout). This starves ALL tenants. With pool_timeout=5s, blocked
# requests fail fast with 503, allowing the system to shed load gracefully.
_POOL_ACQUIRE_TIMEOUT = float(os.environ.get("BULWARK_POOL_ACQUIRE_TIMEOUT", "5.0"))
_shared_client: httpx.AsyncClient | None = None


def _get_shared_client(timeout: float = 120.0) -> httpx.AsyncClient:
    """Get or create the shared httpx client with connection pooling."""
    global _shared_client
    if _shared_client is None or _shared_client.is_closed:
        _shared_client = httpx.AsyncClient(
            limits=_HTTP_POOL_LIMITS,
            timeout=httpx.Timeout(timeout, connect=10.0, pool=_POOL_ACQUIRE_TIMEOUT),
            follow_redirects=False,
        )
    return _shared_client


def _check_ips_blocked(addr_infos: list, *, allow_private: bool = False) -> bool:
    """Check resolved IP addresses against blocked CIDR ranges."""
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


def _is_ssrf_target(url: str, *, allow_private: bool = False) -> bool:
    """Validate URL at request-time to prevent SSRF via DNS rebinding (C-01).

    Resolves hostname to IP and checks against blocked CIDR ranges.
    Uses sync DNS resolution with TTL cache — prefer async_is_ssrf_target
    in async contexts for non-blocking behavior.

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
    # PERFORMANCE (M-03 fix): Use short-TTL cache to avoid blocking on repeated lookups.
    cache_key = (hostname, parsed.port or 443)
    try:
        if cache_key in _DNS_CACHE:
            addr_infos = _DNS_CACHE[cache_key]
        else:
            addr_infos = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
            _DNS_CACHE[cache_key] = addr_infos
    except (socket.gaierror, OSError):
        return True  # Fail-closed: cannot resolve → block

    return _check_ips_blocked(addr_infos, allow_private=allow_private)


async def _async_is_ssrf_target(url: str, *, allow_private: bool = False) -> bool:
    """H-03 fix: Async SSRF validation using event loop DNS resolution.

    Uses asyncio.get_event_loop().getaddrinfo() which runs DNS resolution
    in a thread pool, preventing the async event loop from stalling on
    slow DNS responses (DoS vector when cache is cold).
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    if hostname.lower().rstrip(".") in _BLOCKED_HOSTNAMES:
        return True
    if not allow_private:
        if hostname.lower().endswith(".internal") or hostname.lower().endswith(".local"):
            return True

    cache_key = (hostname, parsed.port or 443)
    try:
        if cache_key in _DNS_CACHE:
            addr_infos = _DNS_CACHE[cache_key]
        else:
            loop = asyncio.get_event_loop()
            addr_infos = await loop.getaddrinfo(
                hostname, parsed.port or 443, proto=socket.IPPROTO_TCP
            )
            _DNS_CACHE[cache_key] = addr_infos
    except (socket.gaierror, OSError):
        return True  # Fail-closed

    return _check_ips_blocked(addr_infos, allow_private=allow_private)


# Max structured images pulled from one request (DoS guard on extraction itself,
# mirrors _image_utils.MAX_INLINE_IMAGES for the inline-data-URI path).
_MAX_STRUCTURED_IMAGES = 5


def _get_agent_policy(request, tenant_id: str, agent_id: str):
    """Return the AgentPolicy for a tenant/agent, or None if unavailable.

    Safe accessor over ``request.app.state.policy_loader.engine`` that never
    raises on the hot path (missing loader/engine in some test or boot contexts
    simply yields ``None`` — callers then skip policy-driven metadata).
    """
    try:
        engine = request.app.state.policy_loader.engine
    except AttributeError:
        return None
    if engine is None:
        return None
    return engine.get_policy(tenant_id, agent_id)


def _content_to_text(content: object) -> str:
    """Flatten an OpenAI message ``content`` field to plain scannable text.

    ``content`` is either a plain string or, for the multimodal (vision) API, a
    list of typed blocks like ``{"type": "text", "text": "..."}`` and
    ``{"type": "image_url", "image_url": {"url": "..."}}``. Only the text blocks
    carry scannable prose; image payloads are handled separately by
    ``_extract_image_contents``. Returns ``""`` for anything unrecognised.

    Without this, ``" ".join(msg.get("content", "") ...)`` raises ``TypeError``
    on list content, so a single multimodal message would crash the hot path.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
        return " ".join(parts)
    return ""


def _extract_image_contents(messages: list[dict]) -> list[str]:
    """Extract image payloads from structured ``image_url`` blocks in messages.

    Returns the raw ``url`` values (base64 ``data:image/...`` URIs *and* remote
    ``http(s)://`` URLs) from OpenAI-vision ``{"type": "image_url", ...}`` blocks,
    so the multimodal scanners can read them from
    ``context.metadata["image_contents"]`` instead of only recovering inline
    data URIs from flattened text (which misses remote URLs and structured
    payloads entirely). Bounded to ``_MAX_STRUCTURED_IMAGES`` to cap work on a
    single hostile request.
    """
    images: list[str] = []
    for msg in messages:
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "image_url":
                continue
            image_url = block.get("image_url")
            url = image_url.get("url") if isinstance(image_url, dict) else image_url
            if isinstance(url, str) and url:
                images.append(url)
                if len(images) >= _MAX_STRUCTURED_IMAGES:
                    return images
    return images


@router.post("/chat/completions")
async def chat_completions(request: Request):
    """OpenAI-compatible chat completions with security guardrails."""
    _req_start = time.perf_counter()
    _counters = get_counters()
    tenant_id = getattr(request.state, "tenant_id", "default")
    agent_id = getattr(request.state, "agent_id", "default")
    # F3 (blast-radius): the authenticated actor (JWT sub / API-key digest). Used
    # only as a correlation risk scope; hardening keys on the subject so one
    # abusive actor does not block every user sharing the agent. Published to the
    # event tap via a ContextVar (task-local, inherited by child tasks).
    subject_id = getattr(request.state, "subject_id", None)
    _request_subject.set(subject_id)
    # Fase B: one stable correlation id for every event/log/alert of THIS request.
    # RequestIDMiddleware set it on request.state (honouring an inbound
    # X-Request-ID); fall back to a fresh id for direct/test invocations.
    request_id = getattr(request.state, "request_id", None) or uuid4().hex
    _request_id.set(request_id)
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
                content={
                    "error": {
                        "message": "Request body too large (max 10MB)",
                        "type": "validation_error",
                        "code": "body_too_large",
                    }
                },
        )
    try:
        raw_body = await request.body()
        if len(raw_body) > MAX_BODY_SIZE:
            return JSONResponse(
                status_code=413,
            content={
                "error": {
                    "message": "Request body too large (max 10MB)",
                    "type": "validation_error",
                    "code": "body_too_large",
                }
            },
            )
        # SECURITY FIX (H-06): Use object_pairs_hook to detect and reject
        # duplicate JSON keys. Duplicate keys create parser differentials
        # between the proxy (last-wins) and backends (first-wins or error),
        # enabling guardrail bypass.
        # SECURITY FIX (M-06): Limit JSON nesting depth to prevent
        # stack overflow / memory exhaustion from deeply nested payloads.
        _MAX_JSON_DEPTH = 50
        _current_depth = [0]

        def _reject_duplicate_keys(pairs):
            _current_depth[0] += 1
            if _current_depth[0] > _MAX_JSON_DEPTH:
                raise json.JSONDecodeError(
                    f"JSON nesting depth exceeds limit ({_MAX_JSON_DEPTH})", "", 0
                )
            keys = {}
            for key, value in pairs:
                if key in keys:
                    raise json.JSONDecodeError(
                        f"Duplicate key: '{key}'", "", 0
                    )
                keys[key] = value
            _current_depth[0] -= 1
            return keys
        body = json.loads(raw_body, object_pairs_hook=_reject_duplicate_keys)
        # SECURITY FIX (P6-01): Post-parse depth check that catches nested arrays.
        # object_pairs_hook only fires for JSON objects (dicts), not arrays.
        # 5000 nested arrays would bypass the depth limit without this check.
        _check_json_depth(body, max_depth=_MAX_JSON_DEPTH)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON body") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid request body: excessive nesting") from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid request body") from exc

    # SECURITY FIX (P6-02): Strip null bytes and C0 control characters from all message content.
    # JSON \u0000 is valid but breaks regex word boundaries (\b): "ig\x00nore" doesn't match \bignore\b.
    # LLM backends strip nulls during tokenization, so the model sees the full injection.
    # Also strip C0 controls (0x01-0x08, 0x0B, 0x0C, 0x0E-0x1F) which serve no text purpose.
    import re as _re_proxy
    _C0_CONTROL_RE = _re_proxy.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
    for msg in body.get("messages", []):
        if isinstance(msg.get("content"), str):
            msg["content"] = _C0_CONTROL_RE.sub("", msg["content"])
        # Handle content arrays (multimodal messages with text parts)
        elif isinstance(msg.get("content"), list):
            for part in msg["content"]:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    part["text"] = _C0_CONTROL_RE.sub("", part["text"])

    messages = body.get("messages", [])

    # === PHASE 1: Input Guardrail ===
    # Use scanner pipeline if available, otherwise fall back to direct call
    _pipeline = get_scanner_pipeline()
    if _pipeline.input_blocking_count > 0 and settings.scanners_pipeline_enabled:
        _scan_ctx = ScanContext(
            tenant_id=tenant_id,
            agent_id=agent_id,
            request_id=request_id,
            messages=messages,
            source_ip=source_ip,
        )
        # Stash the inbound tool DEFINITIONS (MCP/OpenAI `tools` array) so the
        # opt-in McpToolScanner can inspect them for tool poisoning. The message
        # guardrail only scans prose; without this the tool array reaches the
        # backend unscanned. Absent/empty ⇒ the scanner is a zero-cost ALLOW.
        _tool_defs = body.get("tools")
        if isinstance(_tool_defs, list) and _tool_defs:
            _scan_ctx.metadata["tool_definitions"] = _tool_defs
        # Pre-extract structured vision-API image payloads (data URIs + remote
        # URLs) so the multimodal scanners read them from metadata instead of
        # only recovering inline data URIs from flattened text. Mark the request
        # multimodal so downstream scanners can branch on modality.
        _image_contents = _extract_image_contents(messages)
        if _image_contents:
            _scan_ctx.metadata["image_contents"] = _image_contents
            _scan_ctx.content_type = "multimodal"
        # Thread the agent's opt-in multilingual + multimodal policy into the input
        # scan context so the LanguageDetector / ImageHygiene / Vision scanners can
        # enforce per-agent `allowed_languages` / `multimodal` settings. Without this
        # the scanners' enforcement branches never receive policy data and fail open.
        _in_policy = _get_agent_policy(request, tenant_id, agent_id)
        if _in_policy is not None:
            if _in_policy.allowed_languages:
                _scan_ctx.metadata["allowed_languages"] = _in_policy.allowed_languages
                _scan_ctx.metadata["block_unknown_language"] = _in_policy.block_unknown_language
            if _in_policy.multimodal:
                _scan_ctx.metadata["multimodal"] = _in_policy.multimodal
        # SECURITY FIX (M-08): Scan ALL role messages, not just 'user'.
        # System/tool messages can contain attacker-controlled content that bypasses scanning.
        # Join all message content for cross-message pattern detection.
        all_content = " ".join(
            _content_to_text(msg.get("content")) for msg in messages if msg.get("content")
        )
        # Also scan user messages individually for single-message attacks
        user_messages = [
            _content_to_text(msg.get("content")) for msg in messages if msg.get("role") == "user" and msg.get("content")
        ]
        user_content = " ".join(user_messages)
        # Use the broader scan (all content) for guardrail evaluation
        scan_content = all_content if all_content else user_content
        input_result = await _pipeline.run_input_blocking(scan_content, _scan_ctx)
    else:
        input_result = input_guardrail.inspect_messages(messages, tenant_id, agent_id)

    if input_result.verdict == Verdict.BLOCK:
        await _log_events(input_result.events, source_ip)
        asyncio.create_task(_fire_webhook_alert(input_result.events, tenant_id, agent_id))
        _push_recent_block(input_result.events, tenant_id, agent_id, snippet_source=scan_content)
        _counters.record("block", (time.perf_counter() - _req_start) * 1000)
        _record_tenant_usage(tenant_id, "block")
        # Record blocked payload in enrichment replay DB (async, fire-and-forget)
        enrichment_mgr = get_enrichment_manager()
        if enrichment_mgr.enabled:
            user_content = " ".join(
                _content_to_text(msg.get("content"))
                for msg in messages
                if msg.get("role") == "user" and msg.get("content")
            )
            if user_content:
                asyncio.create_task(
                    _enrich_and_record(user_content, "block", request_id, tenant_id)
                )
        # SECURITY FIX (M-09): Constant-time block response to prevent timing oracle.
        # Without this, attackers can distinguish regex blocks (~5ms) from ML blocks (~50ms)
        # and use the timing difference to fingerprint which detection layer caught them.
        _MIN_BLOCK_LATENCY_MS = 50  # Minimum response time for all blocks
        _elapsed_ms = (time.perf_counter() - _req_start) * 1000
        if _elapsed_ms < _MIN_BLOCK_LATENCY_MS:
            await asyncio.sleep((_MIN_BLOCK_LATENCY_MS - _elapsed_ms) / 1000)
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": "Request blocked by security policy",
                    "type": "security_violation",
                    "code": "security_block",
                }
            },
        )

    if input_result.verdict == Verdict.WARN:
        await _log_events(input_result.events, source_ip)
        asyncio.create_task(_fire_webhook_alert(input_result.events, tenant_id, agent_id))
        # An incident analyst needs to see EVERY warned request — not just blocks —
        # in the Security Events viewer. Push all WARN events to recent_blocks
        # (exception-allowed ones carry allowed_by_exception + exception_scope in
        # metadata, which the UI renders as an "ALLOWED" badge with the scope).
        _warn_snippet_src = " ".join(
            _content_to_text(m.get("content"))
            for m in messages
            if m.get("content")
        )
        _push_recent_block(
            input_result.events, tenant_id, agent_id, snippet_source=_warn_snippet_src
        )
        _record_tenant_usage(tenant_id, "warn")

    # === PHASE 1r: Adaptive origin-risk enforcement ===
    # Cross-request feedback loop: read the origin's accumulated (decayed) risk
    # score — built up from prior correlated incidents and WARN/BLOCK events via
    # the correlation event tap — and harden THIS request if it has crossed the
    # configured threshold, even when the current input looked clean. WARN below
    # the block threshold; BLOCK at/above it (only when correlation_blocking is
    # on). Zero cost when correlation is disabled.
    if settings.correlation_enabled and input_result.verdict != Verdict.BLOCK:
        _risk_t0 = time.perf_counter()
        _risk_assessment = get_correlator().evaluate_origin_risk(
            tenant_id=tenant_id,
            agent_id=agent_id,
            request_id=request_id,
            subject_id=subject_id,
        )
        observe_correlation_latency(time.perf_counter() - _risk_t0)
        if _risk_assessment is not None:
            _risk_event = _risk_assessment.to_security_event()
            record_correlation_metric("origin_risk_total")
            await _log_events([_risk_event], source_ip)
            _risk_snippet = " ".join(
                _content_to_text(m.get("content"))
                for m in messages
                if m.get("content")
            )
            _push_recent_block(
                [_risk_event], tenant_id, agent_id, snippet_source=_risk_snippet
            )
            if _risk_assessment.verdict == Verdict.BLOCK:
                asyncio.create_task(
                    _fire_webhook_alert([_risk_event], tenant_id, agent_id)
                )
                record_correlation_metric("origin_risk_blocked")
                _counters.record("block", (time.perf_counter() - _req_start) * 1000)
                _record_tenant_usage(tenant_id, "block")
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": {
                            "message": "Request blocked by security policy",
                            "type": "security_violation",
                            "code": "security_block",
                        }
                    },
                )
            record_correlation_metric("origin_risk_warned")
            _record_tenant_usage(tenant_id, "warn")

    # === PHASE 1a: Multi-turn decomposition check ===
    # Tracks threat signal accumulation across requests from same session.
    # Even if the current request passed input guardrail (ALLOW/WARN), the accumulated
    # context across multiple requests may reveal a decomposition attack.
    if input_result.verdict != Verdict.BLOCK:
        _session_tracker = get_session_tracker()
        user_content_for_session = " ".join(
            _content_to_text(msg.get("content")) for msg in messages if msg.get("role") == "user" and msg.get("content")
        )
        if user_content_for_session:
            session_result = _session_tracker.check_and_update(
                user_content_for_session, tenant_id, agent_id, source_ip or ""
            )
            if session_result.verdict == Verdict.BLOCK:
                await _log_events(session_result.events, source_ip)
                asyncio.create_task(_fire_webhook_alert(session_result.events, tenant_id, agent_id))
                _push_recent_block(session_result.events, tenant_id, agent_id, snippet_source=user_content_for_session)
                _counters.record("block", (time.perf_counter() - _req_start) * 1000)
                _record_tenant_usage(tenant_id, "block")
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": {
                            "message": "Request blocked by security policy",
                            "type": "security_violation",
                            "code": "security_block",
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
            _content_to_text(msg.get("content")) for msg in messages if msg.get("role") == "user" and msg.get("content")
        )
        if user_content_for_async:
            asyncio.create_task(_run_async_scanners_and_log(user_content_for_async, _scan_ctx, tenant_id, agent_id))

    # === PHASE 2: IOC Check ===
    ioc_manager = request.app.state.ioc_manager
    for msg in messages:
        content = _content_to_text(msg.get("content"))
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
                # Carry the exact "<type>:<value>" atoms so the admin sighting
                # feedback loop can report them upstream to threat-intel platforms
                # without re-parsing the human-readable description. Capped to keep
                # the durable-store row bounded.
                metadata={"ioc_matches": ioc_matches[:16]},
            )
            await _log_events([event], source_ip)
            asyncio.create_task(_fire_webhook_alert([event], tenant_id, agent_id))
            _push_recent_block([event], tenant_id, agent_id, snippet_source=scan_content)
            _counters.record("block", (time.perf_counter() - _req_start) * 1000)
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": "Request blocked by security policy",
                        "type": "security_violation",
                        "code": "security_block",
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
                    content={
                        "error": {
                            "message": "Request blocked by security policy",
                            "type": "security_violation",
                            "code": "security_block",
                        }
                    },
        )

    is_streaming = body.get("stream", False)

    # === Response Cache: check for cached response (non-streaming only) ===
    from src.services.response_cache import get_response_cache
    response_cache = get_response_cache()
    if response_cache.enabled and not is_streaming:
        cached_response = response_cache.get(body, tenant_id, agent_id)
        if cached_response:
            # Cache hit — skip backend call entirely
            _counters.record("allow", (time.perf_counter() - _req_start) * 1000)
            _record_tenant_usage(tenant_id, "allow")
            _push_recent_allowed(
                tenant_id, agent_id,
                snippet_source=" ".join(
                    _content_to_text(m.get("content"))
                    for m in messages
                    if m.get("content")
                ),
                request_id=request_id,
            )
            return JSONResponse(content=cached_response)

    # Build ordered list of backends to try (primary + fallbacks)
    backends_to_try = [backend] + backend.fallback_backends

    for attempt_idx, current_backend in enumerate(backends_to_try):
        try:
            # SECURITY FIX (H-05): Use shared client with connection pool
            # instead of creating a new client per request (FD exhaustion)
            client = _get_shared_client(timeout=current_backend.timeout)
            backend_headers = {
                "Content-Type": "application/json",
            }
            # Use agent-specific auth if configured.
            # H-04: Only forward auth from pre-configured backend auth, NOT from client headers.
            # Virtual Keys (data-path enforcement): when the backend declares a
            # provider, the credential is resolved from the encrypted per-tenant
            # vault at request time. Fail closed if a provider is declared but no
            # credential (vault or static) can be resolved — never forward an
            # unauthenticated request to a paid/privileged backend.
            auth_headers, auth_error = _resolve_backend_auth(current_backend, tenant_id)
            if auth_error is not None:
                logger.error(
                    "backend_credential_unavailable",
                    tenant=tenant_id,
                    agent=agent_id,
                    provider=getattr(current_backend, "provider", None),
                    reason=auth_error,
                )
                return JSONResponse(
                    status_code=502,
                    content={
                        "error": {
                            "message": "Backend credential unavailable",
                            "type": "configuration_error",
                            "code": "backend_credential_unavailable",
                        }
                    },
                )
            backend_headers.update(auth_headers)

            backend_url = f"{current_backend.backend_url.rstrip('/')}{current_backend.path_prefix}/chat/completions"

            # SECURITY FIX (VULN 1.2): ALWAYS perform SSRF check at request-time,
            # even for operator-configured backends. DNS rebinding can cause a
            # previously-valid hostname to resolve to dangerous IPs (169.254.169.254,
            # loopback, link-local) between registration and request time.
            # allow_private=True: admin-configured backends CAN use cluster-internal
            # RFC1918 IPs (10.x, 172.16.x, 192.168.x) but NOT metadata/loopback.
            # H-03 fix: Use async DNS resolution to avoid blocking the event loop.
            if await _async_is_ssrf_target(backend_url, allow_private=True):
                logger.warning("ssrf_blocked", backend_url=backend_url, tenant=tenant_id, agent=agent_id)
                return JSONResponse(
                    status_code=403,
            content={
                "error": {
                    "message": "Request blocked by security policy",
                    "type": "security_violation",
                    "code": "security_block",
                }
            },
                )

            if is_streaming:
                # SECURITY FIX (H-05): Per-tenant stream limit enforcement.
                # Check both global capacity and per-tenant limit.
                if _stream_semaphore.locked():
                    return JSONResponse(
                        status_code=503,
                        content={
                            "error": {
                                "message": "Too many concurrent streaming connections",
                                "type": "capacity_error",
                                "code": "stream_limit",
                            }
                        },
                    )

                # P8-01 fix: Use Redis for distributed stream counting across workers.
                # Falls back to in-memory if Redis is unavailable.
                r = _get_stream_redis()
                use_redis = r is not None
                tenant_stream_key = f"{_STREAM_KEY_PREFIX}:{tenant_id}"

                if use_redis:
                    try:
                        # Atomic check-and-increment for per-tenant limit
                        current_tenant = r.incr(tenant_stream_key)
                        r.expire(tenant_stream_key, _STREAM_TTL)
                        if current_tenant > _MAX_STREAMS_PER_TENANT:
                            r.decr(tenant_stream_key)
                            return JSONResponse(
                                status_code=429,
                                content={
                                    "error": {
                                        "message": _TENANT_STREAM_LIMIT_MSG,
                                        "type": "rate_limit",
                                        "code": "tenant_stream_limit",
                                    }
                                },
                            )
                        # Global distributed check
                        current_global = r.incr(_STREAM_KEY_GLOBAL)
                        r.expire(_STREAM_KEY_GLOBAL, _STREAM_TTL)
                        if current_global > _MAX_CONCURRENT_STREAMS:
                            r.decr(_STREAM_KEY_GLOBAL)
                            r.decr(tenant_stream_key)
                            return JSONResponse(
                                status_code=503,
                        content={
                            "error": {
                                "message": "Too many concurrent streaming connections",
                                "type": "capacity_error",
                                "code": "stream_limit",
                            }
                        },
                            )
                    except Exception:
                        # Redis failed mid-operation — fall back to in-memory
                        use_redis = False
                        r = None

                if not use_redis:
                    # In-memory fallback (per-process only — best effort)
                    async with _tenant_stream_lock:
                        current_count = _tenant_stream_counts.get(tenant_id, 0)
                        if current_count >= _MAX_STREAMS_PER_TENANT:
                            return JSONResponse(
                                status_code=429,
                                content={
                                    "error": {
                                        "message": _TENANT_STREAM_LIMIT_MSG,
                                        "type": "rate_limit",
                                        "code": "tenant_stream_limit",
                                    }
                                },
                            )
                        _tenant_stream_counts[tenant_id] = current_count + 1

                try:
                    async with _stream_semaphore:
                        # Streaming path: forward SSE with chunk-level guardrails
                        policy_engine = request.app.state.policy_loader.engine
                        # SECURITY FIX (RC-07): Pass token jti for periodic re-validation
                        token_jti = getattr(request.state, "token_jti", None)
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
                            token_jti=token_jti,
                            request_id=request_id,
                        )
                finally:
                    if use_redis:
                        try:
                            r.decr(tenant_stream_key)
                            r.decr(_STREAM_KEY_GLOBAL)
                        except Exception:  # noqa: S110 — best-effort stream-counter decrement; Redis TTL reclaims it
                            pass  # Best effort — TTL will clean up
                    else:
                        async with _tenant_stream_lock:
                            _tenant_stream_counts[tenant_id] = _tenant_stream_counts.get(tenant_id, 1) - 1
                            if _tenant_stream_counts[tenant_id] <= 0:
                                del _tenant_stream_counts[tenant_id]

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
                    # SECURITY FIX (DOS-01): Distinguish pool timeout from backend timeout.
                    # PoolTimeout means the connection pool is exhausted — return 503 (overloaded)
                    # to shed load and prevent cascading failures across all tenants.
                    if "pool" in type(exc).__name__.lower() or "PoolTimeout" in str(type(exc)):
                        raise HTTPException(
                            status_code=503,
                            detail="Service temporarily overloaded — connection pool exhausted",
                        ) from exc
                    raise HTTPException(status_code=504, detail="Request timed out") from exc
                raise HTTPException(status_code=502, detail="Service unavailable") from exc

    if resp.status_code != 200:
        _counters.record("allow", (time.perf_counter() - _req_start) * 1000)
        _record_tenant_usage(tenant_id, "allow")
        # FASE 5.1: Never forward raw backend error content to client
        return JSONResponse(
            status_code=resp.status_code,
            content={"error": "Backend returned error", "status": resp.status_code},
        )

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
            malformed_arg_tools: list[str] = []
            for tc in tool_calls_raw:
                tc_name = tc.get("function", {}).get("name", "")
                try:
                    args = json.loads(tc.get("function", {}).get("arguments", "{}"))
                except (json.JSONDecodeError, TypeError):
                    # SECURITY FIX (PENTEST-DEEP CRIT-4): Fail-closed on malformed
                    # tool arguments. An adversary can embed blocked argument patterns
                    # in deliberately broken JSON to bypass denied_arguments checks.
                    malformed_arg_tools.append(tc_name)
                    args = {}
                tool_calls.append(
                    ToolCall(
                        id=tc.get("id"),
                        name=tc_name,
                        arguments=args,
                    )
                )

            # Block tools with malformed arguments (fail-closed)
            if malformed_arg_tools:
                logger.warning(
                    "tool_call_malformed_arguments",
                    extra={
                        "tools": malformed_arg_tools,
                        "tenant_id": tenant_id,
                        "agent_id": agent_id,
                    },
                )
                # Remove malformed tool calls from response
                message["tool_calls"] = [
                    tc for tc in tool_calls_raw
                    if tc.get("function", {}).get("name", "") not in malformed_arg_tools
                ]
                if not message.get("tool_calls"):
                    message.pop("tool_calls", None)
                    message["content"] = (
                        "Tool call blocked: malformed arguments detected."
                    )

            policy_result = policy_engine.evaluate_tool_calls(tool_calls, tenant_id, agent_id)

            if policy_result.verdict == Verdict.BLOCK:
                await _log_events(policy_result.events, source_ip)
                asyncio.create_task(_fire_webhook_alert(policy_result.events, tenant_id, agent_id))
                _push_recent_block(
                    policy_result.events,
                    tenant_id,
                    agent_id,
                    snippet_source=", ".join(t for t in policy_result.blocked_tools) or None,
                )
                # Remove blocked tool calls from response
                # SECURITY FIX (PENTEST-DEEP CRIT-3): Normalize tool names before
                # comparison to prevent Unicode confusable bypass (F-01).
                message["tool_calls"] = [
                    tc
                    for tc in tool_calls_raw
                    if _normalize_tool_name(tc.get("function", {}).get("name", "")) not in policy_result.blocked_tools
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
    # SECURITY FIX (AC-01): Also filter tool_call arguments for secrets/PII.
    # Previously only message.content was scanned, allowing secret exfiltration
    # via tool call arguments returned to the client.
    # Collect every output-side detection so PHASE 5c can correlate it against the
    # request's INPUT verdict (input↔output exfiltration confirmation).
    _output_events_corr: list[SecurityEvent] = []
    for choice in choices:
        message = choice.get("message", {})
        for tc in message.get("tool_calls", []):
            args_raw = tc.get("function", {}).get("arguments", "")
            if args_raw:
                tc_filter = output_filter.inspect_and_redact(args_raw, tenant_id, agent_id)
                if tc_filter.verdict == Verdict.REDACT and tc_filter.modified_content:
                    tc["function"]["arguments"] = tc_filter.modified_content
                    _output_events_corr.extend(tc_filter.events)
                    await _log_events(tc_filter.events, source_ip)
                elif tc_filter.verdict == Verdict.BLOCK:
                    # Dangerous content in tool args — nullify the tool call
                    tc["function"]["arguments"] = "{}"
                    _output_events_corr.extend(tc_filter.events)
                    await _log_events(tc_filter.events, source_ip)
                    asyncio.create_task(_fire_webhook_alert(tc_filter.events, tenant_id, agent_id))

    for choice in choices:
        message = choice.get("message", {})
        content = message.get("content")
        if content:
            # Use scanner pipeline for output filtering if available
            if _pipeline.output_blocking_count > 0 and settings.scanners_pipeline_enabled:
                # Thread the agent's opt-in structured-output validation config into
                # the scan context so SchemaValidator can resolve a schema. Inert for
                # agents without an `output_validation` policy block (empty dict).
                _out_meta: dict = {}
                _agent_policy = policy_engine.get_policy(tenant_id, agent_id)
                if _agent_policy is not None and _agent_policy.output_validation:
                    _out_meta["output_validation"] = _agent_policy.output_validation
                _out_ctx = ScanContext(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    request_id=_scan_ctx.request_id if settings.scanners_pipeline_enabled else "",
                    messages=messages,
                    source_ip=source_ip,
                    metadata=_out_meta,
                )
                filter_result = await _pipeline.run_output_blocking(content, _out_ctx)
            else:
                filter_result = output_filter.inspect_and_redact(content, tenant_id, agent_id)

            if filter_result.verdict == Verdict.REDACT and filter_result.modified_content:
                message["content"] = filter_result.modified_content
                _output_events_corr.extend(filter_result.events)
                await _log_events(filter_result.events, source_ip)
                asyncio.create_task(_fire_webhook_alert(filter_result.events, tenant_id, agent_id))
            elif filter_result.verdict == Verdict.BLOCK:
                # Block dangerous output entirely — replace with safe message
                message["content"] = "[Content blocked by security policy — output contained dangerous material]"
                _output_events_corr.extend(filter_result.events)
                await _log_events(filter_result.events, source_ip)
                asyncio.create_task(_fire_webhook_alert(filter_result.events, tenant_id, agent_id))
                _push_recent_block(filter_result.events, tenant_id, agent_id, snippet_source=content)
            elif filter_result.verdict == Verdict.WARN and filter_result.events:
                # WARN: log to SIEM + notify but don't modify content
                _output_events_corr.extend(filter_result.events)
                await _log_events(filter_result.events, source_ip)
                asyncio.create_task(_fire_webhook_alert(filter_result.events, tenant_id, agent_id))

    # === PHASE 5c: Input↔Output Correlation ===
    # Bulwark's inline differentiator: a *suspicious-but-allowed* INPUT (e.g. a
    # prompt-injection attempt that wasn't individually block-worthy) followed by
    # a *sensitive* OUTPUT (credential/PII leak) in the SAME request confirms an
    # exfiltration. When confirmed we elevate the origin's risk state and — if
    # correlation_blocking is on — replace the leaking content. Zero cost when
    # disabled or when either side produced no relevant detections.
    if settings.correlation_enabled and input_result.events and _output_events_corr:
        import hashlib as _hashlib

        _corr_input = " ".join(
            _content_to_text(m.get("content"))
            for m in messages
            if m.get("content")
        )
        _corr_hash = (
            _hashlib.sha256(_corr_input.encode("utf-8", "ignore")).hexdigest()[:16]
            if _corr_input
            else None
        )
        # Concatenated sensitive-output content — supplies the raw text the
        # correlator uses to compute corroboration confidence (Phase 4b). Only the
        # WARN→BLOCK escalation depends on it; category detection is unchanged.
        _corr_output = " ".join(
            _c.get("message", {}).get("content", "")
            for _c in choices
            if isinstance(_c.get("message", {}).get("content"), str)
            and _c.get("message", {}).get("content")
        )
        _corr_t0 = time.perf_counter()
        incident = get_correlator().evaluate(
            input_events=input_result.events,
            output_events=_output_events_corr,
            tenant_id=tenant_id,
            agent_id=agent_id,
            input_hash=_corr_hash,
            request_id=request_id,
            input_text=_corr_input,
            output_text=_corr_output,
            subject_id=subject_id,
        )
        observe_correlation_latency(time.perf_counter() - _corr_t0)
        if incident is not None:
            _corr_event = incident.to_security_event()
            record_correlation_metric("incidents_total")
            await _log_events([_corr_event], source_ip)
            asyncio.create_task(_fire_webhook_alert([_corr_event], tenant_id, agent_id))
            _push_recent_block([_corr_event], tenant_id, agent_id, snippet_source=_corr_input)
            # Persist the sensitive-OUTPUT detections that corroborated this
            # incident. They were logged (SIEM) but not written to the durable
            # buffer, so without this the incident's output-side
            # ``contributing_event_ids`` could not resolve in the Investigation
            # Center drill-down (the input-side events are already pushed at the
            # Phase-1 WARN gate). Pushing with their original event_id makes the
            # pivot join; the UNIQUE constraint keeps it idempotent. Gated on a
            # confirmed incident ⇒ zero cost on the common path. snippet_source is
            # omitted: the output text carries the leaked secret and must not seed
            # a stored preview (the redacted incident snippet already covers it).
            _push_recent_block(
                _output_events_corr, tenant_id, agent_id, snippet_source=None
            )
            if incident.verdict == Verdict.BLOCK:
                # Confirmed exfiltration — scrub the response before it ships.
                for choice in choices:
                    _msg = choice.get("message", {})
                    if _msg.get("content"):
                        _msg["content"] = (
                            "[Content blocked by security policy — "
                            "correlated exfiltration detected]"
                        )
                    _msg.pop("tool_calls", None)
                record_correlation_metric("incidents_blocked")
                _counters.record("block", (time.perf_counter() - _req_start) * 1000)
                _record_tenant_usage(tenant_id, "block")
                return JSONResponse(content=response_data)

    # === PHASE 5b: Output Async Scanners (fire-and-forget) ===
    # Run async output scanners (hallucination detection, etc.) in background.
    if settings.scanners_pipeline_enabled and _pipeline.output_async_count > 0:
        for choice in choices:
            message = choice.get("message", {})
            content = message.get("content")
            if content:
                # Thread the agent's opt-in output_validation config (e.g.
                # relevance_check) into the async scan context, mirroring the
                # OUTPUT_BLOCKING path. Inert for agents without the policy block.
                _async_meta: dict = {}
                _async_policy = policy_engine.get_policy(tenant_id, agent_id)
                if _async_policy is not None and _async_policy.output_validation:
                    _async_meta["output_validation"] = _async_policy.output_validation
                _out_ctx = ScanContext(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    request_id=_scan_ctx.request_id if settings.scanners_pipeline_enabled else "",
                    messages=messages,
                    source_ip=source_ip,
                    metadata=_async_meta,
                )
                asyncio.create_task(_run_output_async_scanners(content, _out_ctx, tenant_id, agent_id))

    # === PHASE 6: Async Enrichment (fire-and-forget) ===
    # Note: Async scanners already fired at Phase 1b (before backend call).
    # Only legacy enrichment manager runs here.
    # Records ALL payloads in AttackReplayDB for analysis, even without ML scanners.
    enrichment_mgr = get_enrichment_manager()
    if enrichment_mgr.enabled:
        # Collect all user message content for enrichment
        user_content = " ".join(
            _content_to_text(msg.get("content")) for msg in messages if msg.get("role") == "user" and msg.get("content")
        )
        if user_content:
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
        response_cache.put(body, response_data, tenant_id, agent_id)

    _counters.record(input_result.verdict.value, (time.perf_counter() - _req_start) * 1000)
    _record_tenant_usage(tenant_id, input_result.verdict.value)
    # Opt-in visibility: record ALLOW verdicts as browsable events. WARN was
    # already pushed to recent_blocks upstream, so only log genuine ALLOWs here
    # to avoid double-recording.
    if input_result.verdict == Verdict.ALLOW:
        _allow_snippet = " ".join(
            _content_to_text(m.get("content"))
            for m in messages
            if m.get("content")
        )
        _push_recent_allowed(
            tenant_id, agent_id, snippet_source=_allow_snippet,
            request_id=request_id,
        )
    return JSONResponse(content=response_data)


@router.post("/tool/validate")
async def validate_tool_call(request: Request):
    """
    Sidecar mode endpoint: validate a tool call before execution.
    Called by agent frameworks that support pre-execution hooks.
    """
    tenant_id = getattr(request.state, "tenant_id", "default")
    agent_id = getattr(request.state, "agent_id", "default")
    # Fase B: one stable correlation id for every event/log/alert of THIS request.
    request_id = getattr(request.state, "request_id", None) or uuid4().hex
    _request_id.set(request_id)

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
        await _log_events(result.events, request.client.host if request.client else None, request_id)
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
    token_jti: str | None = None,
    request_id: str | None = None,
) -> StreamingResponse:
    """Forward streaming SSE response with chunk-level output guardrails.

    Strategy:
    - Buffer content tokens in a sliding window (BUFFER_SIZE chars)
    - Run output filter on each buffer flush
    - If REDACT verdict: replace content with redacted version
    - If dangerous output detected: terminate stream with error event
    - C-01: Tool call chunks are BUFFERED and policy-checked BEFORE yielding to client
    - RC-07: Periodic token re-validation during long streams
    """
    BUFFER_SIZE = 256  # chars before flushing to client
    # SECURITY FIX (C-04): 50% overlapping window prevents boundary-split secret leakage
    OVERLAP_SIZE = 128
    # SECURITY FIX (M-07): Max stream duration and body size to prevent worker starvation
    MAX_STREAM_DURATION_SECONDS = 300  # 5 minutes
    MAX_STREAM_BYTES = 50 * 1024 * 1024  # 50MB
    # SECURITY FIX (RC-07): Re-validate token every 30 seconds during streaming.
    # Previously tokens were only validated once at request start, allowing revoked
    # tokens to continue receiving data for up to 5 minutes.
    TOKEN_REVALIDATION_INTERVAL = 30  # seconds

    # Re-publish the correlation id on the ContextVar for the streaming task chain
    # (BaseHTTPMiddleware/StreamingResponse may run the generator in a fresh
    # context where the handler's ContextVar did not propagate).
    if request_id:
        _request_id.set(request_id)

    async def stream_generator():
        content_buffer = ""
        tool_call_buffer: dict[int, dict] = {}  # index -> {name, arguments}
        tool_call_lines: list[str] = []  # C-01: Buffer raw SSE lines until policy validated
        blocked = False
        stream_start = time.monotonic()
        last_revalidation = stream_start  # RC-07: Track last token check
        total_bytes = 0

        try:
            async with client.stream("POST", url, json=body, headers=headers) as resp:
                if resp.status_code != 200:
                    error_body = await resp.aread()
                    # SECURITY FIX (H-13): Sanitize backend error responses.
                    # Do NOT forward raw error bodies — they may contain internal
                    # infrastructure details, stack traces, or secrets.
                    safe_error = _sanitize_backend_error(resp.status_code, error_body)
                    yield f"data: {json.dumps(safe_error)}\n\n"
                    return

                async for line in resp.aiter_lines():
                    if blocked:
                        break

                    # SECURITY (M-07): Enforce max stream duration
                    if time.monotonic() - stream_start > MAX_STREAM_DURATION_SECONDS:
                        yield _make_error_event("Stream terminated: max duration exceeded")
                        break

                    # SECURITY FIX (RC-07): Periodic token re-validation.
                    # Revoked tokens must not continue receiving streaming data.
                    # Check every TOKEN_REVALIDATION_INTERVAL seconds.
                    now = time.monotonic()
                    if token_jti and (now - last_revalidation) >= TOKEN_REVALIDATION_INTERVAL:
                        last_revalidation = now
                        if _is_token_revoked(token_jti):
                            logger.warning(
                                "streaming_token_revoked",
                                extra={"tenant": tenant_id, "jti": token_jti},
                            )
                            yield _make_error_event("Stream terminated: token revoked")
                            break

                    # SECURITY (M-07): Enforce max response body size
                    total_bytes += len(line.encode("utf-8"))
                    if total_bytes > MAX_STREAM_BYTES:
                        yield _make_error_event("Stream terminated: max body size exceeded")
                        break

                    if not line.startswith("data: "):
                        # SECURITY FIX (CRIT-03): Scan ALL SSE lines through output filter,
                        # not just data lines. SSE comments (:), event types, and IDs can
                        # be used by compromised backends to exfiltrate secrets.
                        filtered_line = _filter_chunk(line, tenant_id, agent_id, source_ip, request_id)
                        if filtered_line is None:
                            # Secret detected in non-data line — strip it silently
                            logger.warning(
                                "sse_nondata_secret_stripped",
                                extra={"tenant": tenant_id, "line_type": line[:10]},
                            )
                            continue
                        yield f"{filtered_line}\n"
                        continue

                    data = line[6:]
                    if data == "[DONE]":
                        # Flush remaining buffer
                        if content_buffer:
                            redacted = _filter_chunk(content_buffer, tenant_id, agent_id, source_ip, request_id)
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
                        # SECURITY FIX (CRIT-03): Malformed JSON in data lines must also
                        # be scanned. A compromised backend could send secrets as non-JSON.
                        filtered_data = _filter_chunk(data, tenant_id, agent_id, source_ip, request_id)
                        if filtered_data is None:
                            logger.warning(
                                "sse_malformed_json_secret_stripped",
                                extra={"tenant": tenant_id},
                            )
                            continue
                        yield f"data: {filtered_data}\n\n"
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
                                        # H-04 fix: Bound tool call buffer to prevent memory
                                        # exhaustion from malicious/compromised backends streaming
                                        # infinite tool call arguments.
                                        if len(tool_call_buffer[idx]["arguments"]) > _MAX_TOOL_ARGS_BYTES:
                                            logger.warning(
                                                "tool_call_buffer_overflow",
                                                extra={"index": idx, "size": len(tool_call_buffer[idx]["arguments"])},
                                            )
                                            yield _make_error_event("Tool call arguments exceeded maximum size")
                                            return
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
                                await _log_events(policy_result.events, source_ip, request_id)
                                asyncio.create_task(_fire_webhook_alert(policy_result.events, tenant_id, agent_id))
                                _push_recent_block(
                                    policy_result.events,
                                    tenant_id,
                                    agent_id,
                                    snippet_source=", ".join(policy_result.blocked_tools) or None,
                                )
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

                            # SECURITY FIX (C-04): 50% overlapping window prevents boundary-split secret leakage
                            # Flush when buffer is full — retain last OVERLAP_SIZE chars for next scan
                            if len(content_buffer) >= BUFFER_SIZE:
                                redacted = _filter_chunk(
                                    content_buffer, tenant_id, agent_id, source_ip, request_id
                                )
                                if redacted is None:
                                    yield _make_error_event("Output blocked by security policy")
                                    blocked = True
                                    break
                                # Yield only the non-overlapping portion (already scanned)
                                yield_portion = redacted[:len(redacted) - OVERLAP_SIZE]
                                yield _make_content_event(yield_portion)
                                # Keep overlap for next iteration to catch boundary-split patterns
                                content_buffer = content_buffer[-OVERLAP_SIZE:]
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


def _filter_chunk(
    content: str,
    tenant_id: str,
    agent_id: str,
    source_ip: str | None,
    request_id: str | None = None,
) -> str | None:
    """Run output filter on a content chunk.

    Returns redacted content, or None if content should be blocked entirely.
    Events from this function are emitted asynchronously via _emit_streaming_events.

    ``request_id`` is threaded explicitly: the streaming generator runs in a
    response-boundary context where the request-scoped ContextVar is not
    guaranteed to propagate, so the correlation id is passed down by hand.
    """
    result = output_filter.inspect_and_redact(content, tenant_id, agent_id)
    if result.verdict == Verdict.BLOCK:
        # Fire telemetry for streaming block (fire-and-forget)
        if result.events:
            _schedule_streaming_telemetry(result.events, tenant_id, agent_id, source_ip, request_id)
        return None
    if result.verdict == Verdict.REDACT and result.modified_content:
        # Fire telemetry for streaming redaction (fire-and-forget)
        if result.events:
            _schedule_streaming_telemetry(result.events, tenant_id, agent_id, source_ip, request_id)
        return result.modified_content
    return content


def _schedule_streaming_telemetry(
    events: list[SecurityEvent],
    tenant_id: str,
    agent_id: str,
    source_ip: str | None,
    request_id: str | None = None,
):
    """Schedule streaming telemetry emission. Safe to call from sync context."""
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(
            _emit_streaming_events(events, tenant_id, agent_id, source_ip, request_id)
        )
    except RuntimeError:
        # No running event loop (e.g., in unit tests) — skip telemetry
        pass


async def _emit_streaming_events(
    events: list[SecurityEvent],
    tenant_id: str,
    agent_id: str,
    source_ip: str | None,
    request_id: str | None = None,
):
    """Emit telemetry events from streaming output filter (fire-and-forget)."""
    try:
        await _log_events(events, source_ip, request_id)
        await _fire_webhook_alert(events, tenant_id, agent_id)
    except Exception as exc:
        logger.warning("streaming_telemetry_emit_failed", error=str(exc))


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


async def _log_events(
    events: list[SecurityEvent],
    source_ip: str | None = None,
    request_id: str | None = None,
):
    """Log security events for SIEM and enqueue to telemetry pipeline."""
    # Stamp the per-request correlation id onto events that lack one (guardrail/
    # pipeline engines produce events without it) so the stdout log and SIEM
    # export share the same request_id as every other sink for this request.
    _ensure_request_id(events, request_id)
    queue = get_telemetry_queue()
    for event in events:
        # F3: an allow-exception degrades BLOCK→WARN and tags the metadata. Surface
        # that in BOTH the stdout log and the SIEM export so an incident analyst can
        # tell an exception-allowed attack apart from a generic warn.
        _md = event.metadata or {}
        _allowed_by_exception = bool(_md.get("allowed_by_exception"))
        _exception_scope = _md.get("exception_scope") or _md.get("allowed_by_exception_scope")
        await logger.awarn(
            "security_event",
            event_id=event.event_id,
            request_id=event.request_id,
            verdict=event.verdict.value,
            category=event.category.value,
            description=event.description,
            tenant=event.tenant_id,
            agent=event.agent_id,
            severity=event.severity,
            tool=event.tool_name,
            pattern=event.matched_pattern,
            allowed_by_exception=_allowed_by_exception,
            exception_scope=_exception_scope,
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
            request_id=event.request_id,
            confidence=1.0,
            allowed_by_exception=_allowed_by_exception,
            exception_scope=_exception_scope,
            event_id=event.event_id,
        )
        queue.enqueue_nowait(telemetry_event)

        # Feed the correlation event tap (feedback loop) fire-and-forget. Only
        # active when correlation is enabled; publish() is non-blocking and drops
        # on back-pressure, so this can never stall the response path. The subject
        # (F3) is read from the request-scoped ContextVar so risk accrues to the
        # specific actor without threading it through every call site or ever
        # writing it into the event/SIEM record.
        if settings.correlation_enabled:
            get_event_tap().publish(event, subject_id=_request_subject.get())


async def _fire_webhook_alert(events: list[SecurityEvent], tenant_id: str, agent_id: str):
    """Fire notification alerts for block/warn events."""
    engine = get_notification_engine()
    if not engine.configured:
        return
    # Ensure the alert carries the same request_id as the SIEM/log records even
    # when this runs as a detached task (ContextVar is inherited at task creation).
    _ensure_request_id(events)
    for event in events:
        alert = AlertPayload(
            verdict=event.verdict.value if event.verdict else "block",
            severity=event.severity or "high",
            category=event.category.value if event.category else "unknown",
            description=event.description,
            tenant_id=tenant_id,
            agent_id=agent_id,
            matched_patterns=[event.matched_pattern] if event.matched_pattern else [],
            event_id=event.event_id,
            request_id=event.request_id or "",
            source=event.source or "",
        )
        try:
            await engine.send_alert(alert)
        except Exception as e:
            logger.error(f"notification_error: {type(e).__name__}: {e}")


def _make_block_snippet(snippet_source: str | None) -> tuple[str | None, str | None]:
    """Produce a privacy-safe (redacted + truncated) snippet plus a content hash.

    F1 (event detail): the recent-blocks list is shown verbatim in the admin UI,
    so we must never persist raw user input. We (1) hash the full original for
    correlation, then (2) redact secrets/PII via the output filter and truncate
    to a bounded preview. Best-effort: any failure yields (None, hash-or-None).
    """
    if not snippet_source:
        return None, None
    import hashlib as _hashlib

    input_hash: str | None = None
    try:
        input_hash = _hashlib.sha256(snippet_source.encode("utf-8", "ignore")).hexdigest()[:16]
    except Exception:
        input_hash = None

    snippet: str | None = None
    try:
        # SECURITY: redact secrets/PII DIRECTLY — do NOT route through
        # output_filter.inspect_and_redact(), whose indirect-injection check
        # short-circuits (returns BLOCK) BEFORE the secret-redaction stage.
        # A blocked request's input almost always contains injection patterns,
        # so relying on that path would persist secrets verbatim (e.g. an AWS
        # key embedded in an injection string). Applying the patterns here
        # guarantees the stored preview is always scrubbed.
        import unicodedata as _ud

        from src.guardrails.output_filter import (
            REDACTION_PATTERNS as _RP,
        )
        from src.guardrails.output_filter import (
            _strip_invisible as _strip,
        )
        text = _strip(_ud.normalize("NFKC", snippet_source))
        for pattern, _name, replacement in _RP:
            text = pattern.sub(replacement or "[REDACTED]", text)
        preview = " ".join(text.split())  # collapse whitespace/newlines
        _MAX = 240
        snippet = preview[:_MAX] + ("…" if len(preview) > _MAX else "")
    except Exception:
        snippet = None
    return snippet, input_hash


def _origin_scope_digests(
    tenant_id: str,
    agent_id: str,
    subject_id: str | None,
    input_hash: str | None,
) -> list[str]:
    """Compute the origin-risk scope digests a blocked request contributes to.

    Investigation Center (zero-cost when correlation is off — the sole caller
    gates on ``settings.correlation_enabled``). Returns ``"{scope_type}:{digest}"``
    tokens for exactly the scopes the correlation engine accrues risk to
    (:mod:`src.correlation.incident`): subject (when authenticated), session,
    tenant, and the content fingerprint. The digest is produced by
    :meth:`RiskStateStore.scope_digest` — the same function that names the
    ``bulwark:risk:*`` keys and the admin ``/correlation/origins`` view — so an
    analyst can pivot a decayed origin score straight to the durable events that
    drove it. Never raises: any failure yields an empty list.
    """
    try:
        from src.correlation.risk_state import RiskStateStore

        scopes: list[tuple[str, str]] = [
            ("session", f"{tenant_id}:{agent_id}"),
            ("tenant", tenant_id),
        ]
        if subject_id:
            scopes.append(("subject", f"{tenant_id}:{subject_id}"))
        if input_hash:
            scopes.append(("input", input_hash))
        return [f"{st}:{RiskStateStore.scope_digest(st, sid)}" for st, sid in scopes]
    except Exception:  # noqa: BLE001 - stamping is best-effort, never break the push
        return []


def _push_recent_block(
    events: list[SecurityEvent],
    tenant_id: str,
    agent_id: str,
    snippet_source: str | None = None,
):
    """Push block event to Redis recent-blocks list (non-blocking, best effort)."""
    try:
        from src.guardrails.dynamic_registry import get_pattern_registry
        registry = get_pattern_registry()
        r = registry._redis
        if not r:
            return
        # Stamp the per-request id so the admin recent-blocks entry correlates
        # with the SIEM/log/notification records for the same request.
        _ensure_request_id(events)
        import json as _json
        # F1: privacy-safe preview + correlation hash (computed once per push).
        snippet, input_hash = _make_block_snippet(snippet_source)
        # Investigation Center: stamp the origin-risk scope digests this block
        # contributes to, so the durable event store can pivot origin→events.
        # Gated on correlation_enabled ⇒ zero added work when the engine is off.
        scope_digests: list[str] = []
        if getattr(settings, "correlation_enabled", False):
            scope_digests = _origin_scope_digests(
                tenant_id, agent_id, _request_subject.get(), input_hash
            )
        # SECURITY FIX (SGW-XT-002): Per-tenant recent_blocks key.
        # Previously all tenants shared a single list, leaking block metadata
        # across tenant boundaries.
        redis_key = f"bulwark:recent_blocks:{tenant_id}"
        for event in events[:3]:  # Max 3 events per block
            category = event.category.value if event.category else "unknown"
            severity = event.severity or "high"
            pattern_id = (event.matched_pattern or "").strip()
            # An incident_id in the event metadata (correlation engine) is lifted
            # to a top-level field so the durable store can index it directly.
            incident_id = ""
            if event.metadata:
                incident_id = str(event.metadata.get("incident_id") or "")
            entry = _json.dumps({
                "ts": time.time(),
                "event_id": event.event_id,
                "tenant": tenant_id,
                "agent": agent_id,
                "category": category,
                "description": event.description,
                "severity": severity,
                "pattern": event.matched_pattern or "",
                # F1: full event detail (previously dropped, forcing a shallow UI).
                "verdict": event.verdict.value if event.verdict else "block",
                "source": event.source or "",
                "request_id": event.request_id or "",
                "tool_name": event.tool_name or "",
                "metadata": event.metadata or {},
                "snippet": snippet or "",
                "input_hash": input_hash or "",
                # Investigation Center pivots (empty unless correlation is on).
                "incident_id": incident_id,
                "scope_digests": scope_digests,
            })
            r.lpush(redis_key, entry)
            r.ltrim(redis_key, 0, max(1, settings.events_max_per_tenant) - 1)
            # Observability counters (bounded cardinality: category is a fixed
            # ThreatCategory enum; severity is a fixed 4-value set). These feed the
            # Grafana Security dashboard's per-category / per-severity breakdowns.
            # Best effort — already inside the surrounding try/except.
            r.hincrby("bulwark:detections:category", category, 1)
            r.hincrby("bulwark:detections:severity", severity, 1)
            # Pattern id is bounded by the registered pattern set; truncate
            # defensively to keep the Redis field (and later Prometheus label)
            # size bounded even for dynamically-added custom patterns.
            if pattern_id:
                r.hincrby("bulwark:detections:pattern", pattern_id[:128], 1)
    except Exception as exc:
        logger.warning("recent_blocks_push_failed", error=str(exc))


def _push_recent_allowed(
    tenant_id: str,
    agent_id: str,
    snippet_source: str | None = None,
    request_id: str | None = None,
):
    """Record an ALLOWED request as a browsable event (opt-in, best effort).

    Unlike blocks/warns, an allowed request carries no SecurityEvent (nothing was
    detected), so we synthesise a minimal, privacy-safe record: a redacted +
    truncated snippet and a correlation hash — never the raw input. Stored under a
    DEDICATED key (``bulwark:recent_allowed:<tenant>``) so high-volume legitimate
    traffic never evicts the security-relevant block/warn events from their list.
    Gated behind ``settings.log_allowed`` and capped at ``settings.events_max_per_tenant``.
    """
    if not settings.log_allowed:
        return
    try:
        from src.guardrails.dynamic_registry import get_pattern_registry
        registry = get_pattern_registry()
        r = registry._redis
        if not r:
            return
        import json as _json
        snippet, input_hash = _make_block_snippet(snippet_source)
        redis_key = f"bulwark:recent_allowed:{tenant_id}"
        cap = max(1, int(settings.events_max_per_tenant))
        entry = _json.dumps({
            "ts": time.time(),
            "tenant": tenant_id,
            "agent": agent_id,
            "category": "allowed",
            "description": "Request passed all guardrails",
            "severity": "info",
            "pattern": "",
            "verdict": "allow",
            "source": "input_guardrail",
            "request_id": request_id or "",
            "tool_name": "",
            "metadata": {},
            "snippet": snippet or "",
            "input_hash": input_hash or "",
        })
        r.lpush(redis_key, entry)
        r.ltrim(redis_key, 0, cap - 1)
    except Exception as exc:
        logger.warning("recent_allowed_push_failed", error=str(exc))


def _record_tenant_usage(tenant_id: str, verdict: str):
    """Increment per-tenant AND global usage counters in Redis (best effort)."""
    try:
        from src.guardrails.dynamic_registry import get_pattern_registry
        registry = get_pattern_registry()
        r = registry._redis
        if not r:
            return
        r.hincrby("bulwark:usage:total", tenant_id, 1)
        r.hincrby(f"bulwark:usage:{verdict}", tenant_id, 1)
        # Global counters (persist across pod restarts)
        r.incrby("bulwark:global:requests_total", 1)
        r.incrby(f"bulwark:global:{verdict}", 1)
        # Daily verdict buckets (one field per UTC day) — feed the admin
        # "Management" trend so security volume (threats blocked/warned) is
        # visible over time, not just as a running total. Bounded: a single
        # field per day per verdict; best effort inside the surrounding guard.
        _day = time.strftime("%Y-%m-%d", time.gmtime())
        r.hincrby("bulwark:usage:daily:total", _day, 1)
        r.hincrby(f"bulwark:usage:daily:{verdict}", _day, 1)
    except Exception as exc:
        logger.warning("tenant_usage_counter_failed", error=str(exc), tenant_id=tenant_id)


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
                    _enrich_desc = getattr(enrichment_result, "description", "semantic match")
                    event = SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id="enrichment",
                        verdict=enrichment_result.verdict,
                        category=ThreatCategory.PROMPT_INJECTION,
                        description=f"Enrichment detection: {_enrich_desc}",
                        source="enrichment_pipeline",
                        severity="medium",
                        metadata={"request_id": request_id},
                    )
                    await _log_events([event], request_id=request_id)
    except Exception as e:
        # Never let enrichment errors affect anything
        await logger.awarn("enrichment_pipeline_error", error=str(e))
