"""
Bulwark Gateway — Admin Portal Backend

Separate FastAPI application for administration. Runs as independent service
or mounted as sub-app on a different port. ZERO impact on proxy hot path.

Features:
- Policy CRUD with validation + atomic hot-reload
- Guardrail pattern management + sandbox testing
- SIEM transport configuration + connection testing
- Real-time SSE metrics stream
- Audit log (immutable, exportable)
- RBAC (admin, security, auditor, viewer)
"""

from __future__ import annotations

import contextvars
import hashlib
import logging
import os
import secrets
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Routes
from .routes import (
    audit,
    auth,
    cache,
    config,
    correlation,
    cost,
    dashboards,
    discovery,
    enrichment,
    evaluation,
    events,
    gdpr,
    guardrails,
    health,
    integration_webhooks,
    integrations,
    investigation,
    investigation_cases,
    iocs,
    ml_scanners,
    notifications,
    plugins,
    policies,
    quotas,
    rate_limits,
    rbac,
    service_accounts,
    sessions,
    siem,
    skills,
    tenants,
    users,
    validate,
    virtual_keys,
)
from .routes.auth import _should_set_secure_cookie
from .services.audit_logger import get_audit_logger
from .services.prometheus_client import get_metrics

logger = logging.getLogger("bulwark.admin")

# H-1: per-request CSP nonce. Generated fresh in the security-headers middleware
# and read back both by the response header and by the Jinja `csp_nonce()` global
# so every inline <script> block can authenticate itself. Because a nonce is
# present, browsers ignore 'unsafe-inline' for script-src, so injected inline
# scripts (reflected/stored XSS) can no longer execute.
_csp_nonce_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "csp_nonce", default=""
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Admin app lifecycle."""
    # Initialize database abstraction layer (PostgreSQL or SQLite)
    # This runs schema migrations and provides the async engine for new code.
    # Existing services (user_store, audit_logger) continue using their own
    # connections until individually migrated to use the shared engine.
    from .services.database import close_database, init_database
    db_engine = await init_database()
    app.state.db = db_engine

    get_metrics()  # Initialize singleton
    audit_log = get_audit_logger()
    await audit_log.initialize()
    # Initialize user store (create tables + seed defaults)
    from .services.user_store import get_user_store
    user_store = get_user_store()
    user_store.initialize()
    # Declaratively seed service accounts from BULWARK_SERVICE_ACCOUNTS_SEED[_FILE]
    # so a SOAR/playbook key exists the moment a fresh gateway boots (GitOps /
    # unattended deploys). Idempotent (keyed on the key hash) and best-effort: a
    # bad spec is logged and skipped, never fatal. Runs after the DB is migrated
    # (service_account table exists) and the user store is up.
    try:
        from .services.service_account_seed import seed_service_accounts
        await seed_service_accounts()
    except Exception as exc:  # noqa: BLE001 — startup seeding is best-effort
        logger.warning("service_account_seed_deferred error=%s", exc)
    # Eagerly seed the agents registry at startup so agents.yaml exists in the
    # shared admin_data volume / admin-data PVC BEFORE the proxy reads it
    # read-only. TenantManager is a lazy singleton whose __init__ seeds from the
    # image's config/agents.yaml (_ensure_writable_copy); without this, agents.yaml
    # is only written when the tenants UI is first opened, leaving the proxy with an
    # empty registry on boot. Baked into the image so it applies identically to
    # Docker Compose (depends_on: admin) and Helm (shared PVC).
    #
    # NOTE: the IOC DB is intentionally NOT seeded here — the feed scheduler below
    # already calls get_ioc_store() during startup (feed_scheduler seeds from
    # config/iocs.json). Loading it twice just re-parses a large file on the hot
    # startup path and risks racing a concurrent writer during rolling updates.
    #
    # Best-effort: a not-yet-writable volume must not crash the admin (the lazy
    # singleton retries on first request), so failures are logged, not fatal.
    try:
        from .services.tenant_manager import get_tenant_manager
        get_tenant_manager()
    except Exception as exc:  # noqa: BLE001 — startup seeding is best-effort
        logger.warning("agents_seed_deferred error=%s", exc)
    # Start background feed scheduler
    from .services.feed_scheduler import get_feed_scheduler
    scheduler = get_feed_scheduler()
    await scheduler.start()
    # Initialize GDPR compliance service
    from .services.gdpr import get_gdpr_service
    gdpr_service = get_gdpr_service()
    await gdpr_service.initialize()
    # Start the durable Security Events sync: drains the proxy's capped Redis
    # live buffer (bulwark:recent_blocks:* / recent_allowed:*) into the
    # security_events table so the viewer has a real, queryable history that
    # survives Redis flushes and outlives the per-tenant cap. Retention is
    # SIEM-aware (see events_sync.resolve_retention_days).
    from .services.events_sync import get_events_sync
    events_sync = get_events_sync()
    await events_sync.start()
    # Start the reconcile poller (Investigation Phase 4): the poll-fallback half of
    # the two inbound-sync trigger paths. On a configurable interval it sweeps every
    # enabled, sync-capable (TheHive / DFIR-IRIS) connector's active linked cases
    # and folds any remote workflow change back into the local case. Fail-open: a
    # dead remote or a sweep error is one skipped cycle, never a crash.
    from .services.integrations.reconcile_poller import get_reconcile_poller
    reconcile_poller = get_reconcile_poller()
    await reconcile_poller.start()
    yield
    await reconcile_poller.stop()
    await events_sync.stop()
    await scheduler.stop()
    await gdpr_service.close()
    await audit_log.close()
    await close_database()


_admin_debug = os.getenv("ADMIN_DEBUG", "false").lower() in ("true", "1")

app = FastAPI(
    title="Bulwark Gateway Admin Portal",
    version="1.0.0",
    description="Administration interface for Bulwark Gateway security proxy",
    lifespan=lifespan,
    docs_url="/docs" if _admin_debug else None,
    redoc_url="/redoc" if _admin_debug else None,
    openapi_url="/openapi.json" if _admin_debug else None,
)

# CORS — configurable via env; deny by default in production
_cors_origins = os.getenv("ADMIN_CORS_ORIGINS", "")
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins.split(","),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        allow_headers=["Authorization", "Content-Type"],
    )
# If ADMIN_CORS_ORIGINS is not set, NO CORS middleware is added (same-origin only)


# Security headers middleware
@app.middleware("http")
async def security_headers(request, call_next):
    # H-1: mint a fresh CSP nonce for this request BEFORE rendering so the
    # Jinja `csp_nonce()` global (see below) emits the matching value on every
    # inline <script>. The same nonce is echoed in the response header.
    nonce = secrets.token_urlsafe(16)
    token = _csp_nonce_var.set(nonce)
    try:
        response = await call_next(request)
    finally:
        _csp_nonce_var.reset(token)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    # H-4: X-XSS-Protection is deprecated; its legacy auditor introduced
    # vulnerabilities in older browsers. Disable it and rely on CSP instead.
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    # H-1: script-src is now nonce-based — 'unsafe-inline' is GONE, so an
    # attacker who injects <script> cannot execute it (the nonce is unguessable
    # and rotates per request). Two 'unsafe-*' remain, honestly scoped:
    #   • script-src 'unsafe-eval' — Alpine.js (non-CSP build) evaluates every
    #     x-data/@click/:class/x-show expression via new Function(). Removing it
    #     requires the Alpine CSP build + rewriting all template expressions.
    #   • style-src 'unsafe-inline' — the UI carries static style="" attributes,
    #     which CSP nonces cannot cover (nonces apply to <style> elements, not
    #     attributes). Removing it requires migrating those to utility classes.
    # All third-party origins are already eliminated (qrcodejs + fonts vendored
    # under /static), so the policy is fully self-contained and air-gap safe.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    return response


# Auth guard for HTML pages — redirect to /login if no valid token
_PUBLIC_PATHS = {"/login", "/static", "/admin/auth", "/admin/health", "/favicon.ico"}


@app.middleware("http")
async def auth_guard_pages(request: Request, call_next):
    """Protect HTML page routes. API routes are protected by their own dependencies.

    Strategy:
    - If valid token found (cookie or header) → serve page normally
    - If no token and no localStorage fallback possible → redirect to /login
    - Pages are HTML shells; actual data is fetched via authenticated API calls.
      The base.html template handles client-side auth (redirects to /login on 401).
    """
    path = request.url.path

    # Allow public paths, static assets, and API routes (they have their own auth)
    if any(path.startswith(p) for p in _PUBLIC_PATHS):
        return await call_next(request)

    # Only guard HTML page routes (not /admin/* API routes)
    is_page_route = (
        path in ("/", "/policies", "/guardrails", "/allowlist", "/siem", "/audit",
                 "/tenants", "/agents", "/users", "/iocs", "/settings", "/coverage",
                 "/rbac", "/setup", "/status", "/notifications", "/skills",
                 "/plugins", "/evaluation", "/discovery", "/ml-scanners",
                 "/rate-limits", "/enrichment", "/events", "/tenant-analytics",
                 "/gdpr", "/virtual-keys", "/quotas", "/cost", "/cache",
                 "/sessions", "/correlation", "/investigation", "/integrations",
                 "/service-accounts")
    )

    if is_page_route:
        # Check for token in cookie or Authorization header
        token = request.cookies.get("admin_token")
        if not token:
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]

        if token:
            # Validate token
            from .services.auth_service import AuthService
            payload = AuthService.verify_token(token)
            if payload is None:
                # Invalid/expired token — clear cookie and redirect
                from fastapi.responses import RedirectResponse
                resp = RedirectResponse(url="/login", status_code=302)
                resp.delete_cookie("admin_token", path="/")
                return resp
        # No server-side token: serve the page anyway.
        # base.html JavaScript will check localStorage and redirect to /login
        # if no valid session exists. This prevents redirect loops when
        # HttpOnly cookies fail (e.g., Secure flag on HTTP).

    return await call_next(request)


# Body size limit middleware (1MB max for admin API)
_MAX_BODY_SIZE = 1 * 1024 * 1024  # 1MB


@app.middleware("http")
async def body_size_limit(request: Request, call_next):
    """Reject requests with bodies exceeding 1MB."""
    # P9-02 fix: Also check actual body size (catches chunked encoding bypass)
    content_length = request.headers.get("content-length")
    if content_length:
        if int(content_length) > _MAX_BODY_SIZE:
            return Response(
                content='{"detail":"Request body too large (max 1MB)"}',
                status_code=413,
                media_type="application/json",
            )
    else:
        # No Content-Length: may be chunked. Read and check actual size.
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()
            if len(body) > _MAX_BODY_SIZE:
                return Response(
                    content='{"detail":"Request body too large (max 1MB)"}',
                    status_code=413,
                    media_type="application/json",
                )
    return await call_next(request)


# P9-04: CSRF protection middleware for state-changing requests
_CSRF_EXEMPT = {
    "/admin/auth/login",
    "/admin/auth/force-change-password",
    "/admin/health",
    "/admin/health/detailed",
    "/admin/health/sse",
}

# CSRF-exempt path *prefixes* (Phase 4). The inbound reconcile receiver
# (``/admin/integrations/inbound/{integration_id}``) authenticates a remote/SOAR
# callback with a per-request HMAC over the raw body — it uses no ambient cookie,
# so it is structurally CSRF-immune and must be reachable without a CSRF token.
# The path carries a dynamic id, so it is matched by prefix rather than by the
# exact-match set above.
_CSRF_EXEMPT_PREFIXES = ("/admin/integrations/inbound/",)


def _is_service_account_request(request: Request) -> bool:
    """True when the request authenticates with a service-account key (Phase 3.2b).

    CSRF is a browser/cookie-session defence: a cross-site attacker can silently
    replay ambient cookies but cannot set a custom ``Authorization`` header on a
    cross-origin request (that requires a CORS preflight the admin never grants).
    A service-account key (``Authorization: Bearer bwk_sa_…``) is therefore
    inherently CSRF-immune, so exempting it lets SOAR/playbook automation reach the
    mutating action endpoints without a CSRF token — while every cookie-session
    request keeps full CSRF enforcement. The scope is deliberately narrow (only the
    ``bwk_sa_`` prefix), so ordinary admin JWTs/sessions are never exempted.
    """
    auth = request.headers.get("authorization", "")
    return auth.startswith("Bearer bwk_sa_")


@app.middleware("http")
async def csrf_protection(request: Request, call_next):
    """Validate CSRF token on state-changing requests."""
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        path = request.url.path
        exempt = (
            path in _CSRF_EXEMPT
            or any(path.startswith(p) for p in _CSRF_EXEMPT_PREFIXES)
            or _is_service_account_request(request)
        )
        if not exempt:
            csrf_cookie = request.cookies.get("_csrf_token")
            csrf_header = request.headers.get("x-csrf-token")
            if not csrf_cookie or not csrf_header or not secrets.compare_digest(csrf_cookie, csrf_header):
                return Response(
                    content='{"detail":"CSRF validation failed"}',
                    status_code=403,
                    media_type="application/json",
                )

    response = await call_next(request)

    # Set CSRF cookie on all responses if not present
    if "_csrf_token" not in request.cookies:
        csrf_token = secrets.token_hex(32)
        response.set_cookie(
            "_csrf_token", csrf_token, httponly=False, samesite="strict",
            secure=_should_set_secure_cookie(request)
        )
    return response


# Phase 3.2b: Idempotency-Key dedupe for the inbound automation action API.
_IDEMPOTENT_METHODS = {"POST", "PUT", "DELETE"}
_IDEMPOTENT_PATH_PREFIX = "/admin/investigation"


@app.middleware("http")
async def automation_idempotency(request: Request, call_next):
    """Replay the cached response for a repeated automation ``Idempotency-Key``.

    Deliberately narrow so it is zero-cost for everything else: it engages ONLY for
    a service-account request (``Authorization: Bearer bwk_sa_…``) that carries an
    ``Idempotency-Key`` header on a mutating call to the investigation action
    surface. Restricting it to service-account credentials means the dedupe scope is
    always a distinct per-key digest (a human cookie session, which carries no such
    header, can never collide) and matches the sole use case — a SOAR/playbook step
    that retries after a timeout must not double-apply its effect.

    The first request runs normally; only a 2xx response is cached (a transient
    failure stays freely retryable). A later request with the same key replays the
    stored response instead of re-executing. Every storage touch is fail-open: any
    error degrades to normal execution, never breaking the action.
    """
    idem_key = request.headers.get("idempotency-key")
    if (
        not idem_key
        or request.method not in _IDEMPOTENT_METHODS
        or not request.url.path.startswith(_IDEMPOTENT_PATH_PREFIX)
        or not _is_service_account_request(request)
    ):
        return await call_next(request)

    from .services.idempotency_store import IdempotencyStore, caller_scope

    scope = caller_scope(request.headers.get("authorization"))
    method = request.method
    path = request.url.path
    store = IdempotencyStore()

    cached = await store.get(scope, method, path, idem_key)
    if cached is not None:
        return Response(
            content=cached["response_body"],
            status_code=cached["status_code"],
            media_type="application/json",
            headers={"Idempotency-Replay": "true"},
        )

    response = await call_next(request)

    # Buffer the streamed body so it can be both cached and returned. These action
    # endpoints are small JSON responses (never SSE), so this is bounded.
    chunks = [section async for section in response.body_iterator]
    raw = b"".join(chunks)
    rebuilt = Response(
        content=raw,
        status_code=response.status_code,
        headers=dict(response.headers),
        media_type=response.media_type,
    )
    if 200 <= response.status_code < 300:
        try:
            await store.put(
                scope, method, path, idem_key,
                response.status_code, raw.decode("utf-8", errors="replace"),
            )
        except Exception:  # noqa: BLE001 - fail-open: caching must never break the response
            logger.debug("automation idempotency store failed (fail-open)", exc_info=True)
    return rebuilt


# Static files + templates
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_STATIC_DIR = os.path.join(BASE_DIR, "static")
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# H-1: expose the per-request CSP nonce to every template. Inline <script>
# blocks emit nonce="{{ csp_nonce() }}" so they authenticate against the
# script-src nonce set by the security-headers middleware.
templates.env.globals["csp_nonce"] = lambda: _csp_nonce_var.get("")

# Cache-busting for static assets. The vendored CSS/JS are served without a
# per-deploy version marker, so a browser can hold a stale copy across an image
# rebuild (the file URL never changes). asset_url() appends a content-hash
# ?v= marker so any byte change forces a fresh fetch, while unchanged files keep
# a stable URL (and stay cacheable). SRI integrity is unaffected — it validates
# content, not the URL. The hash is memoised by (path, mtime) so each file is
# read at most once per change; on any lookup error the path is returned
# unchanged so a missing file can never break rendering.
_asset_version_cache: dict[str, tuple[float, str]] = {}


def _asset_url(path: str) -> str:
    if not path.startswith("/static/"):
        return path
    rel = path[len("/static/"):]
    try:
        full = os.path.normpath(os.path.join(_STATIC_DIR, rel))
        # Path-traversal guard: never hash a file outside the static root.
        if full != _STATIC_DIR and not full.startswith(_STATIC_DIR + os.sep):
            return path
        mtime = os.path.getmtime(full)
        cached = _asset_version_cache.get(path)
        if cached is not None and cached[0] == mtime:
            version = cached[1]
        else:
            with open(full, "rb") as fh:
                version = hashlib.sha256(fh.read()).hexdigest()[:12]
            _asset_version_cache[path] = (mtime, version)
    except OSError:
        return path
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}v={version}"


templates.env.globals["asset_url"] = _asset_url

# Include routers
app.include_router(auth.router, prefix="/admin/auth", tags=["auth"])
app.include_router(health.router, prefix="/admin/health", tags=["health"])
app.include_router(policies.router, prefix="/admin/policies", tags=["policies"])
app.include_router(guardrails.router, prefix="/admin/guardrails", tags=["guardrails"])
app.include_router(siem.router, prefix="/admin/siem", tags=["siem"])
app.include_router(audit.router, prefix="/admin/audit", tags=["audit"])
app.include_router(validate.router, prefix="/admin/validate", tags=["validate"])
app.include_router(users.router, prefix="/admin", tags=["users"])
app.include_router(tenants.router, tags=["tenants"])
app.include_router(config.router, prefix="/admin/config", tags=["config"])
app.include_router(iocs.router, tags=["iocs"])
app.include_router(rbac.router, prefix="/admin/rbac", tags=["rbac"])
app.include_router(notifications.router, prefix="/admin/notifications", tags=["notifications"])
app.include_router(skills.router, tags=["skills"])
app.include_router(plugins.router, tags=["plugins"])
app.include_router(evaluation.router, tags=["evaluation"])
app.include_router(discovery.router, tags=["discovery"])
app.include_router(ml_scanners.router, prefix="/admin/ml-scanners", tags=["ml-scanners"])
app.include_router(rate_limits.router, prefix="/admin/rate-limits", tags=["rate-limits"])
app.include_router(enrichment.router, prefix="/admin/enrichment", tags=["enrichment"])
app.include_router(events.router, prefix="/admin/events", tags=["events"])
app.include_router(gdpr.router, prefix="/admin/gdpr", tags=["gdpr"])
app.include_router(virtual_keys.router, prefix="/admin/virtual-keys", tags=["virtual-keys"])
app.include_router(quotas.router, prefix="/admin/quotas", tags=["quotas"])
app.include_router(cost.router, prefix="/admin/cost", tags=["cost"])
app.include_router(cache.router, prefix="/admin/cache", tags=["cache"])
app.include_router(sessions.router, prefix="/admin/sessions", tags=["sessions"])
app.include_router(
    service_accounts.router,
    prefix="/admin/service-accounts",
    tags=["service-accounts"],
)
app.include_router(correlation.router, prefix="/admin/correlation", tags=["correlation"])
app.include_router(investigation.router, prefix="/admin/investigation", tags=["investigation"])
app.include_router(
    investigation_cases.router,
    prefix="/admin/investigation/cases",
    tags=["investigation"],
)
app.include_router(dashboards.router, prefix="/admin/dashboards", tags=["dashboards"])
# Register the webhook subrouter BEFORE the integrations router so a bare
# ``GET /admin/integrations/webhooks`` is not captured by the single-segment
# ``GET /admin/integrations/{integration_id}`` lookup.
app.include_router(
    integration_webhooks.router,
    prefix="/admin/integrations/webhooks",
    tags=["integrations"],
)
app.include_router(integrations.router, prefix="/admin/integrations", tags=["integrations"])


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve the admin dashboard."""
    return templates.TemplateResponse(request, "pages/dashboard.html")


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page."""
    return templates.TemplateResponse(request, "pages/login.html")


@app.get("/policies", response_class=HTMLResponse)
async def policies_page(request: Request):
    """Policy management page."""
    return templates.TemplateResponse(request, "pages/policies.html")


@app.get("/guardrails", response_class=HTMLResponse)
async def guardrails_page(request: Request):
    """Guardrail manager page."""
    return templates.TemplateResponse(request, "pages/guardrails.html")


@app.get("/allowlist", response_class=HTMLResponse)
async def allowlist_page(request: Request):
    """Allowlist / allow-exceptions management page."""
    return templates.TemplateResponse(request, "pages/allowlist.html")


@app.get("/siem", response_class=HTMLResponse)
async def siem_page(request: Request):
    """SIEM configuration page."""
    return templates.TemplateResponse(request, "pages/siem.html")


@app.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request):
    """Audit log page."""
    return templates.TemplateResponse(request, "pages/audit.html")


@app.get("/tenants", response_class=HTMLResponse)
async def tenants_page(request: Request):
    """Tenant management page."""
    return templates.TemplateResponse(request, "pages/tenants.html")


@app.get("/agents", response_class=HTMLResponse)
async def agents_page(request: Request):
    """Agent management page."""
    return templates.TemplateResponse(request, "pages/agents.html")


@app.get("/users")
async def users_page_redirect():
    """Redirect to unified Access Control page."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/rbac", status_code=302)


@app.get("/iocs", response_class=HTMLResponse)
async def iocs_page(request: Request):
    """IOC management page."""
    return templates.TemplateResponse(request, "pages/iocs.html")


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """System settings page."""
    return templates.TemplateResponse(request, "pages/settings.html")


@app.get("/coverage", response_class=HTMLResponse)
async def coverage_page(request: Request):
    """Security coverage matrix page."""
    return templates.TemplateResponse(request, "pages/coverage.html")


@app.get("/rbac", response_class=HTMLResponse)
async def rbac_page(request: Request):
    """RBAC management page."""
    return templates.TemplateResponse(request, "pages/rbac.html")


@app.get("/setup", response_class=HTMLResponse)
async def onboarding_page(request: Request):
    """Onboarding wizard for first-time setup."""
    return templates.TemplateResponse(request, "pages/onboarding.html")


@app.get("/status", response_class=HTMLResponse)
async def status_page(request: Request):
    """System status page."""
    return templates.TemplateResponse(request, "pages/status.html")


@app.get("/notifications", response_class=HTMLResponse)
async def notifications_page(request: Request):
    """Notification channels management page."""
    return templates.TemplateResponse(request, "pages/notifications.html")


@app.get("/skills", response_class=HTMLResponse)
async def skills_page(request: Request):
    """Skill security scanner (SkillSpector) page."""
    return templates.TemplateResponse(request, "pages/skills.html")


@app.get("/plugins", response_class=HTMLResponse)
async def plugins_page(request: Request):
    """Plugin management page."""
    return templates.TemplateResponse(request, "pages/plugins.html")


@app.get("/evaluation", response_class=HTMLResponse)
async def evaluation_page(request: Request):
    """Security evaluation / red teaming page."""
    return templates.TemplateResponse(request, "pages/evaluation.html")


@app.get("/discovery", response_class=HTMLResponse)
async def discovery_page(request: Request):
    """Agent discovery and Shadow AI monitoring page."""
    return templates.TemplateResponse(request, "pages/discovery.html")


@app.get("/ml-scanners", response_class=HTMLResponse)
async def ml_scanners_page(request: Request):
    """ML Scanner management page."""
    return templates.TemplateResponse(request, "pages/ml_scanners.html")


@app.get("/rate-limits", response_class=HTMLResponse)
async def rate_limits_page(request: Request):
    """Rate limiting management page."""
    return templates.TemplateResponse(request, "pages/rate_limits.html")


@app.get("/enrichment", response_class=HTMLResponse)
async def enrichment_page(request: Request):
    """Enrichment pipeline visibility page."""
    return templates.TemplateResponse(request, "pages/enrichment.html")


@app.get("/events", response_class=HTMLResponse)
async def events_page(request: Request):
    """Security events viewer — filterable by tenant, category, severity."""
    return templates.TemplateResponse(request, "pages/events.html")


@app.get("/tenant-analytics", response_class=HTMLResponse)
async def tenant_analytics_page(request: Request):
    """Per-tenant usage analytics dashboard."""
    return templates.TemplateResponse(request, "pages/tenant_analytics.html")


@app.get("/gdpr", response_class=HTMLResponse)
async def gdpr_page(request: Request):
    """GDPR compliance console — erasure, access export, retention, inventory."""
    return templates.TemplateResponse(request, "pages/gdpr.html")


@app.get("/virtual-keys", response_class=HTMLResponse)
async def virtual_keys_page(request: Request):
    """Virtual Keys vault — centralized backend API key management."""
    return templates.TemplateResponse(request, "pages/virtual_keys.html")


@app.get("/quotas", response_class=HTMLResponse)
async def quotas_page(request: Request):
    """Per-tenant resource quotas — concurrency, token budgets, model access."""
    return templates.TemplateResponse(request, "pages/quotas.html")


@app.get("/cost", response_class=HTMLResponse)
async def cost_page(request: Request):
    """Cost & token usage analytics — per-tenant spend, pricing, resets."""
    return templates.TemplateResponse(request, "pages/cost.html")


@app.get("/cache", response_class=HTMLResponse)
async def cache_page(request: Request):
    """Response cache console — stats, runtime kill-switch, flush."""
    return templates.TemplateResponse(request, "pages/cache.html")


@app.get("/sessions", response_class=HTMLResponse)
async def sessions_page(request: Request):
    """Session decomposition tracker — thresholds, active sessions, reset."""
    return templates.TemplateResponse(request, "pages/sessions.html")


@app.get("/correlation", response_class=HTMLResponse)
async def correlation_page(request: Request):
    """Adaptive correlation engine — enforcement tuning, active origins, reset."""
    return templates.TemplateResponse(request, "pages/correlation.html")


@app.get("/investigation", response_class=HTMLResponse)
async def investigation_page(request: Request):
    """Investigation Center — SOC triage workspace for correlated alerts."""
    return templates.TemplateResponse(request, "pages/investigation.html")


@app.get("/integrations", response_class=HTMLResponse)
async def integrations_page(request: Request):
    """Integrations — outbound case-management connectors (TheHive / DFIR-IRIS)."""
    return templates.TemplateResponse(request, "pages/integrations.html")


@app.get("/service-accounts", response_class=HTMLResponse)
async def service_accounts_page(request: Request):
    """Service accounts — scoped, non-interactive automation credentials."""
    return templates.TemplateResponse(request, "pages/service_accounts.html")
