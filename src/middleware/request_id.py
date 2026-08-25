"""
Request-ID middleware — establishes a stable correlation id for every request.

Incident-response traceability (Fase B): every proxied HTTP request is given a
single ``request_id`` that is shared by ALL security events, log lines, SIEM
records and notifications produced while handling it. This is what lets a
responder pull *every* detection/phase of one request together (the per-detection
``event_id`` handles the finer grain).

Behaviour:
  - Honour an inbound ``X-Request-ID`` header when it is well-formed (so an
    upstream gateway / mesh / client trace id flows through unchanged for
    end-to-end distributed tracing). Untrusted input is validated against a
    conservative charset and length bound before it is trusted.
  - Otherwise mint a fresh ``uuid4().hex``.
  - Publish it on ``request.state.request_id`` (read by the proxy handler, which
    stamps it onto events) and echo it back on the response ``X-Request-ID``
    header so the caller can correlate too.

Runs outermost so even auth-rejected requests get a traceable id + echo header.
"""

from __future__ import annotations

import re
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Accept only a conservative id charset (alphanumeric + . _ - :) bounded to 128
# chars — matches SecurityEvent.request_id max_length. Anything else (control
# chars, header-injection attempts, oversized ids) is rejected and replaced with
# a freshly minted id, so a malicious X-Request-ID can neither poison logs nor
# overflow the SIEM field.
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")

_HEADER = "X-Request-ID"


def _resolve_request_id(inbound: str | None) -> str:
    """Return a trusted request id: the inbound one if well-formed, else a new one."""
    if inbound and _SAFE_REQUEST_ID.match(inbound):
        return inbound
    return uuid4().hex


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = _resolve_request_id(request.headers.get(_HEADER))
        # Shared via scope["state"] → visible to inner middleware and the endpoint.
        request.state.request_id = request_id
        response: Response = await call_next(request)
        # Echo for client/upstream correlation (idempotent — never leak a different id).
        response.headers[_HEADER] = request_id
        return response
