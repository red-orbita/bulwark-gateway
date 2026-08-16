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

from .services.audit_logger import get_audit_logger
from .services.prometheus_client import get_metrics
from .routes.auth import _should_set_secure_cookie

# Routes
from .routes import policies, guardrails, siem, audit, health, validate, auth, users, tenants, config, iocs, rbac, notifications, skills
from .routes import (
    plugins, evaluation, discovery, ml_scanners, rate_limits, enrichment,
    events, gdpr, virtual_keys, quotas, cost, cache, sessions,
)

logger = logging.getLogger("bulwark.admin")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Admin app lifecycle."""
    # Initialize database abstraction layer (PostgreSQL or SQLite)
    # This runs schema migrations and provides the async engine for new code.
    # Existing services (user_store, audit_logger) continue using their own
    # connections until individually migrated to use the shared engine.
    from .services.database import init_database, close_database
    db_engine = await init_database()
    app.state.db = db_engine

    get_metrics()  # Initialize singleton
    audit_log = get_audit_logger()
    await audit_log.initialize()
    # Initialize user store (create tables + seed defaults)
    from .services.user_store import get_user_store
    user_store = get_user_store()
    user_store.initialize()
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
    yield
    await scheduler.stop()
    await gdpr_service.close()
    await audit_log.close()
    await close_database()


_admin_debug = os.getenv("ADMIN_DEBUG", "false").lower() in ("true", "1")

app = FastAPI(
    title="Bulwark Gateway Admin Portal",
    version="0.2.0",
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
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    # H-4: X-XSS-Protection is deprecated; its legacy auditor introduced
    # vulnerabilities in older browsers. Disable it and rely on CSP instead.
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    # H-1: 'unsafe-inline'/'unsafe-eval' remain REQUIRED (Alpine.js evaluates
    # expressions via new Function() and the UI uses inline <script>/style
    # attributes). All third-party origins have been eliminated: qrcodejs and
    # the Inter/JetBrains Mono fonts are now vendored under /static, so the
    # policy is fully self-contained and air-gap safe (no CDN, no Google Fonts).
    # Follow-up hardening: switch to the Alpine CSP build + per-request nonces
    # to drop the remaining 'unsafe-*'.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
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
        path in ("/", "/policies", "/guardrails", "/siem", "/audit",
                 "/tenants", "/agents", "/users", "/iocs", "/settings", "/coverage",
                 "/rbac", "/setup", "/status", "/notifications", "/skills",
                 "/plugins", "/evaluation", "/discovery", "/ml-scanners",
                 "/rate-limits", "/enrichment", "/events", "/tenant-analytics",
                 "/gdpr", "/virtual-keys", "/quotas", "/cost", "/cache",
                 "/sessions")
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
_CSRF_EXEMPT = {"/admin/auth/login", "/admin/auth/force-change-password", "/admin/health", "/admin/health/detailed", "/admin/health/sse"}


@app.middleware("http")
async def csrf_protection(request: Request, call_next):
    """Validate CSRF token on state-changing requests."""
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        if request.url.path not in _CSRF_EXEMPT:
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


# Static files + templates
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

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
