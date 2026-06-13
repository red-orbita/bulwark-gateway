"""
Sentinel Gateway — Admin Portal Backend

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

import asyncio
import os
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Response, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .models.auth import UserRole, TokenPayload
from .services.auth_service import AuthService, get_current_user, require_role
from .services.audit_logger import AuditLogger, get_audit_logger
from .services.prometheus_client import PrometheusMetrics, get_metrics

# Routes
from .routes import policies, guardrails, siem, audit, health, validate, auth, users, tenants, config, iocs, rbac, notifications, skills
from .routes import plugins, evaluation, discovery, ml_scanners, rate_limits, enrichment, events


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Admin app lifecycle."""
    metrics = get_metrics()
    audit_log = get_audit_logger()
    await audit_log.initialize()
    # Initialize user store (create tables + seed defaults)
    from .services.user_store import get_user_store
    user_store = get_user_store()
    user_store.initialize()
    # Start background feed scheduler
    from .services.feed_scheduler import get_feed_scheduler
    scheduler = get_feed_scheduler()
    await scheduler.start()
    yield
    await scheduler.stop()
    await audit_log.close()


_admin_debug = os.getenv("ADMIN_DEBUG", "false").lower() in ("true", "1")

app = FastAPI(
    title="Sentinel Gateway Admin Portal",
    version="0.2.0",
    description="Administration interface for Sentinel Gateway security proxy",
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
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    return response


# Auth guard for HTML pages — redirect to /login if no valid token
_PUBLIC_PATHS = {"/login", "/static", "/admin/auth", "/admin/health", "/favicon.ico"}


@app.middleware("http")
async def auth_guard_pages(request: Request, call_next):
    """Protect HTML page routes. API routes are protected by their own dependencies."""
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
                 "/rate-limits", "/enrichment", "/events", "/tenant-analytics")
    )

    if is_page_route:
        # Check for token in cookie or Authorization header
        token = request.cookies.get("admin_token")
        if not token:
            auth_header = request.headers.get("authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]

        if not token:
            from fastapi.responses import RedirectResponse
            return RedirectResponse(url="/login", status_code=302)

        # Validate token
        from .services.auth_service import AuthService
        payload = AuthService.verify_token(token)
        if payload is None:
            from fastapi.responses import RedirectResponse
            return RedirectResponse(url="/login", status_code=302)

    return await call_next(request)


# Body size limit middleware (1MB max for admin API)
_MAX_BODY_SIZE = 1 * 1024 * 1024  # 1MB


@app.middleware("http")
async def body_size_limit(request: Request, call_next):
    """Reject requests with bodies exceeding 1MB."""
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > _MAX_BODY_SIZE:
        return Response(
            content='{"detail":"Request body too large (max 1MB)"}',
            status_code=413,
            media_type="application/json",
        )
    return await call_next(request)


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
