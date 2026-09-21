"""Scoped binary uploads and approved-text resolution; inert without a service."""

from __future__ import annotations

import asyncio
import copy
import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Literal

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.requests import ClientDisconnect

from src.attachments.store import MAX_RAW_BYTES, StoreError

if TYPE_CHECKING:
    from src.attachments.service import AttachmentService

router = APIRouter(prefix="/v1/attachments", tags=["attachments"])
UPLOAD_SECONDS = 10.0
MAX_REFERENCES = 5
MAX_RESOLVED_BYTES = 64 * 1024
ALLOWED_MIMES = frozenset({
    "text/plain", "text/markdown", "text/csv", "application/json",
    "image/png", "image/jpeg", "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
})
_ID = re.compile(r"att_[0-9a-f]{64}")


class _FileReference(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    file_id: str = Field(min_length=68, max_length=68, pattern=r"^att_[0-9a-f]{64}$")


class _FileBlock(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    type: Literal["file"]
    file: _FileReference


@contextmanager
def _store_errors() -> Iterator[None]:
    try:
        yield
    except StoreError as exc:
        status = {
            "not_found": 404, "not_ready": 409, "policy_changed": 409,
            "too_large": 413, "capacity": 429, "busy": 429,
        }.get(exc.code, 503)
        # Integrity/configuration failures are not public storage diagnostics.
        raise HTTPException(status, exc.code if status != 503 else "unavailable") from None


def _context(request: Request) -> tuple[AttachmentService, dict[str, str], str]:
    service = getattr(request.app.state, "attachment_service", None)
    if service is None:
        raise HTTPException(404, "not_found")
    identity = {
        "tenant": getattr(request.state, "tenant_id", None),
        "agent": getattr(request.state, "agent_id", None),
        "owner": getattr(request.state, "attachment_owner", None),
    }
    scope: dict[str, str] = {}
    for key, value in identity.items():
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise HTTPException(401, "unauthorized")
        scope[key] = value
    with _store_errors():
        policy = service.current_policy(scope["tenant"], scope["agent"])
        if policy is None:
            raise HTTPException(404, "not_found")
    return service, scope, policy[0]


@router.post("", status_code=202)
async def upload_attachment(request: Request, response: Response) -> dict[str, Any]:
    service, scope, _ = _context(request)
    content_types = request.headers.getlist("content-type")
    if len(content_types) != 1:
        raise HTTPException(415, "unsupported_media_type")
    mime = content_types[0].split(";", 1)[0].strip().lower()
    if mime not in ALLOWED_MIMES:
        raise HTTPException(415, "unsupported_media_type")
    with _store_errors():
        if not service.accepts_mime(scope["tenant"], scope["agent"], mime):
            raise HTTPException(415, "unsupported_media_type")
        upload_limit = min(MAX_RAW_BYTES, service.upload_limit(scope["tenant"], scope["agent"], mime))
        quota_bytes = getattr(request.state, "attachment_quota_bytes", 0)
        if isinstance(quota_bytes, int) and quota_bytes > 0:
            upload_limit = min(upload_limit, quota_bytes)
    if request.headers.get("content-encoding", "identity").lower() != "identity":
        raise HTTPException(415, "unsupported_media_type")
    lengths = request.headers.getlist("content-length")
    declared = None
    if lengths:
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0]) or "transfer-encoding" in request.headers:
            raise HTTPException(400, "invalid_length")
        if len(lengths[0]) > 20:
            raise HTTPException(413, "too_large")
        declared = int(lengths[0])
        if declared > upload_limit:
            raise HTTPException(413, "too_large")
        if declared == 0:
            raise HTTPException(400, "empty_body")
    raw = bytearray()
    try:
        async with asyncio.timeout(UPLOAD_SECONDS):
            async for chunk in request.stream():
                size = len(raw) + len(chunk)
                if size > upload_limit:
                    raise HTTPException(413, "too_large")
                if declared is not None and size > declared:
                    raise HTTPException(400, "invalid_length")
                raw.extend(chunk)
                # Buffered tiny chunks must not starve the receive deadline.
                await asyncio.sleep(0)
    except TimeoutError:
        raise HTTPException(408, "upload_timeout") from None
    except ClientDisconnect:
        raise HTTPException(400, "incomplete_body") from None
    if declared is not None and len(raw) != declared:
        raise HTTPException(400, "invalid_length")
    if not raw:
        raise HTTPException(400, "empty_body")
    with _store_errors():
        # Admission uses fresh policy after the potentially slow upload.
        policy = service.current_policy(scope["tenant"], scope["agent"])
        if policy is None:
            raise HTTPException(404, "not_found")
        if not service.accepts_mime(scope["tenant"], scope["agent"], mime):
            raise HTTPException(415, "unsupported_media_type")
        if len(raw) > service.upload_limit(scope["tenant"], scope["agent"], mime):
            raise HTTPException(413, "too_large")
        result = await service.store.create(**scope, mime=mime, raw=bytes(raw), policy_revision=policy[0])
    response.headers["Cache-Control"] = "no-store"
    return result


@router.get("/{id}")
async def get_attachment(id: str, request: Request, response: Response) -> dict[str, Any]:
    service, scope, _ = _context(request)
    if not _ID.fullmatch(id):
        raise HTTPException(404, "not_found")
    with _store_errors():
        result = await service.store.get(id, **scope)
    if result is None:
        raise HTTPException(404, "not_found")
    response.headers["Cache-Control"] = "no-store"
    return result


@router.delete("/{id}", status_code=204)
async def delete_attachment(id: str, request: Request) -> Response:
    service, scope, _ = _context(request)
    if not _ID.fullmatch(id):
        raise HTTPException(404, "not_found")
    with _store_errors():
        deleted = await service.store.delete(id, **scope)
    if not deleted:
        raise HTTPException(404, "not_found")
    return Response(status_code=204, headers={"Cache-Control": "no-store"})


async def resolve_chat_attachments(body: dict, request: Request) -> dict:
    """Copy a handler-bounded JSON body, replacing only exact local references.

    Run before the existing attachment guard and input scanners. This helper does
    not authorize other file formats or bypass the normal chat security pipeline.
    """
    if not isinstance(body, dict):
        raise HTTPException(400, "invalid_body")
    try:
        resolved = copy.deepcopy(body)
    except RecursionError:
        raise HTTPException(400, "invalid_body") from None
    references: list[tuple[list, int, str]] = []
    messages = resolved.get("messages")
    if not isinstance(messages, list):
        return resolved
    for message in messages:
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            continue
        for index, block in enumerate(content):
            file = block.get("file") if isinstance(block, dict) else None
            file_id = file.get("file_id") if isinstance(file, dict) else None
            if not isinstance(file_id, str) or not file_id.startswith("att_"):
                continue
            try:
                reference = _FileBlock.model_validate(block)
            except ValidationError:
                raise HTTPException(400, "invalid_attachment_reference") from None
            if len(references) == MAX_REFERENCES:
                raise HTTPException(413, "too_large")
            references.append((content, index, reference.file.file_id))
    if not references:
        return resolved
    service, scope, revision = _context(request)
    total = 0
    with _store_errors():
        limits = service.attachment_policy(scope["tenant"], scope["agent"])
        if len(references) > limits.max_attachments:
            raise HTTPException(413, "too_large")
        for content, index, file_id in references:
            policy = service.current_policy(scope["tenant"], scope["agent"])
            if policy is None:
                raise HTTPException(404, "not_found")
            if policy[0] != revision:
                raise HTTPException(409, "policy_changed")
            # Store.resolve atomically checks scope, TTL, approved state, revision
            # and the extracted-text SHA-256. review_required never releases text.
            text = await service.store.resolve(file_id, **scope, policy_revision=policy[0])
            total += len(text.encode("utf-8"))
            if total > min(MAX_RESOLVED_BYTES, limits.max_total_bytes):
                raise HTTPException(413, "too_large")
            content[index] = {"type": "text", "text": text}
        policy = service.current_policy(scope["tenant"], scope["agent"])
        if policy is None or policy[0] != revision:
            raise HTTPException(409, "policy_changed")
    return resolved
