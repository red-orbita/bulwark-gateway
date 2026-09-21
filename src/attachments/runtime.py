"""Local lifecycle/configuration wiring for opt-in asynchronous attachments."""

import asyncio
import hashlib
import json
from pathlib import Path

from fastapi import FastAPI

from src.attachments.service import DOCX_MIME, NATIVE_MIMES, TEXT_MIMES, AttachmentService
from src.attachments.store import get_attachment_store
from src.config import Settings
from src.guardrails.attachments import AttachmentPolicy
from src.guardrails.input_dlp import InputDlpPolicy
from src.guardrails.tool_policy import AgentPolicy


async def start_attachment_service(app: FastAPI, settings: Settings) -> AttachmentService:
    """Explicit storage authority and single worker; no implicit local fallback."""
    if settings.workers != 1 or settings.attachment_service_db_url_file is None:
        raise RuntimeError("Attachment service requires one worker and an explicit database URL file")
    url_file = settings.attachment_service_db_url_file

    def provisioned_config() -> tuple[str, str]:
        try:
            with url_file.open("rb") as stream:
                raw = stream.read(16385)
            if not raw or len(raw) > 16384:
                raise ValueError("Invalid database URL")
            url = raw.decode("utf-8").strip()
            if not url:
                raise ValueError("Invalid database URL")
            # Invalidate approvals after code/model-free rule changes. This is
            # an observed source fingerprint, not an operator-supplied label.
            root = Path(__file__).resolve().parents[1]
            digest = hashlib.sha256(b"bulwark-async-attachments-v1")
            for directory in ("attachments", "guardrails"):
                for path in sorted((root / directory).rglob("*.py")):
                    digest.update(str(path.relative_to(root)).encode())
                    digest.update(path.read_bytes())
            return url, digest.hexdigest()
        except (OSError, ValueError, UnicodeError):
            raise RuntimeError("Attachment service configuration unavailable") from None

    url, code_revision = await asyncio.to_thread(provisioned_config)
    store = get_attachment_store(
        url,
        max_documents=settings.attachment_service_max_documents,
        max_bytes=settings.attachment_service_max_bytes,
        max_per_tenant=settings.attachment_service_max_per_tenant,
        ttl_seconds=settings.attachment_service_ttl_seconds,
    )

    def scope_policy(tenant: str, agent: str) -> AgentPolicy | None:
        policy = app.state.policy_loader.engine.get_policy(tenant, agent)
        if policy is None or not policy.attachments.async_enabled:
            return None
        return policy

    def attachment_policy(tenant: str, agent: str) -> AttachmentPolicy:
        policy = scope_policy(tenant, agent)
        if policy is None:
            raise ValueError("Attachment policy unavailable")
        limits = policy.attachments
        return limits.model_copy(update={
            "max_file_bytes": min(limits.max_file_bytes, settings.attachment_max_file_bytes),
            "max_document_bytes": min(limits.max_document_bytes, settings.attachment_max_document_bytes),
            "max_total_bytes": min(limits.max_total_bytes, settings.attachment_max_total_bytes),
            "max_attachments": min(limits.max_attachments, settings.attachment_max_count),
        })

    def allowed_mimes(tenant: str, agent: str) -> frozenset[str]:
        policy = scope_policy(tenant, agent)
        if policy is None:
            return frozenset()
        formats = set(TEXT_MIMES)
        if policy.attachments.extract_documents:
            formats.add(DOCX_MIME)
            if settings.attachment_extract_documents and settings.attachment_parser_isolation_confirmed:
                formats.update(NATIVE_MIMES)
        return frozenset(formats)

    def current_policy(tenant: str, agent: str) -> tuple[str, InputDlpPolicy] | None:
        policy = scope_policy(tenant, agent)
        if policy is None:
            return None
        specific = policy.input_dlp
        budget = settings.input_dlp_max_bytes if settings.input_dlp_enabled else 65536
        if specific.enabled:
            budget = min(budget, specific.max_bytes)
        effective = InputDlpPolicy(
            enabled=True, max_bytes=budget,
            redact_email=settings.redact_email or (specific.enabled and specific.redact_email),
            redact_phone=settings.redact_phone or (specific.enabled and specific.redact_phone),
            blocked_terms=specific.blocked_terms if specific.enabled else (),
        )
        fingerprint = json.dumps({
            "code": code_revision, "dlp": effective.model_dump(mode="json"),
            "attachments": attachment_policy(tenant, agent).model_dump(mode="json"),
            "formats": sorted(allowed_mimes(tenant, agent)), "languages": settings.attachment_extraction_languages,
        }, sort_keys=True)
        return hashlib.sha256(fingerprint.encode()).hexdigest(), effective

    service = AttachmentService(
        store, policy_provider=current_policy, allowed_mimes_provider=allowed_mimes,
        attachment_policy_provider=attachment_policy,
        work_dir=settings.attachment_extraction_work_dir,
        parser_isolation_confirmed=settings.attachment_parser_isolation_confirmed,
        languages=settings.attachment_extraction_languages,
    )
    try:
        await service.start()
    except BaseException:
        await store.close()
        raise
    return service
