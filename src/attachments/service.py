"""Single-worker, fail-closed attachment conversion; no HTTP or upstream calls."""

from __future__ import annotations

import asyncio
import logging
import math
from collections.abc import Callable
from pathlib import Path
from time import monotonic
from typing import Any, TypeVar

from src.attachments.store import MAX_TEXT_BYTES, AttachmentStore, StoreError
from src.guardrails.attachments import AttachmentPolicy
from src.guardrails.document_extraction import ExtractionError, extract_document
from src.guardrails.docx_extraction import DocxError, extract_docx
from src.guardrails.input_dlp import InputDlpPolicy, inspect_request
from src.guardrails.input_guardrail import InputGuardrail
from src.models import Verdict

LEASE_SECONDS = 300
PROCESS_SECONDS = 240.0
NATIVE_SECONDS = 90.0
FINISH_SECONDS = 30.0
FINISH_ATTEMPTS = 5
WINDOW_CHARS = 4096
OVERLAP_CHARS = 1024
MAX_WINDOWS = 128
TEXT_MIMES = frozenset({"text/plain", "text/markdown", "application/json", "text/csv"})
NATIVE_MIMES = frozenset({"application/pdf", "image/png", "image/jpeg"})
DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
T = TypeVar("T")
logger = logging.getLogger(__name__)


class AttachmentService:
    """Own one store lifecycle and at most one active parsing/scanning job.

    The synchronous provider must be a fast local lookup. Its revision must cover
    the effective policy AND scanner/conversion version; never reuse revisions.
    """

    def __init__(
        self,
        store: AttachmentStore,
        *,
        policy_provider: Callable[[str, str], tuple[str, InputDlpPolicy] | None],
        work_dir: Path | None = None,
        parser_isolation_confirmed: bool = False,
        languages: str = "eng",
        poll_seconds: float = 0.2,
        allowed_mimes_provider: Callable[[str, str], frozenset[str]] | None = None,
        attachment_policy_provider: Callable[[str, str], AttachmentPolicy] | None = None,
    ) -> None:
        if (not callable(policy_provider) or isinstance(poll_seconds, bool)
                or not isinstance(poll_seconds, (int, float))
                or not math.isfinite(poll_seconds) or poll_seconds <= 0
                or (allowed_mimes_provider is not None and not callable(allowed_mimes_provider))
                or (attachment_policy_provider is not None and not callable(attachment_policy_provider))):
            raise ValueError("invalid_service_configuration")
        self.store = store
        self._policy_provider = policy_provider
        self._allowed_mimes_provider = allowed_mimes_provider
        self._attachment_policy_provider = attachment_policy_provider
        self._work_dir = work_dir
        self._parser_isolation_confirmed = parser_isolation_confirmed is True
        self._languages = languages
        self._poll_seconds = poll_seconds
        self._worker: asyncio.Task[None] | None = None
        self._processing = asyncio.Lock()
        self._lifecycle = asyncio.Lock()
        self._stopping = False
        self.ready = False

    def attachment_policy(self, tenant: str, agent: str) -> AttachmentPolicy:
        """Resolve local size/count limits; provider errors never relax limits."""
        try:
            policy = (AttachmentPolicy(max_file_bytes=65536) if self._attachment_policy_provider is None
                      else self._attachment_policy_provider(tenant, agent))
            if not isinstance(policy, AttachmentPolicy):
                raise ValueError("invalid_attachment_policy")
            return policy
        except Exception:
            raise StoreError("unavailable") from None

    def upload_limit(self, tenant: str, agent: str, mime: str) -> int:
        policy = self.attachment_policy(tenant, agent)
        return (min(policy.max_file_bytes, policy.max_total_bytes) if mime in TEXT_MIMES
                else policy.max_document_bytes)

    def accepts_mime(self, tenant: str, agent: str, mime: str) -> bool:
        """Check current format policy without parsing, I/O or cross-scope caching."""
        try:
            supported = TEXT_MIMES | NATIVE_MIMES | {DOCX_MIME}
            allowed = supported if self._allowed_mimes_provider is None else self._allowed_mimes_provider(tenant, agent)
            if not isinstance(allowed, frozenset) or any(not isinstance(value, str) for value in allowed):
                raise ValueError("invalid_format_policy")
            return mime in supported and mime in allowed
        except Exception:
            raise StoreError("unavailable") from None

    def current_policy(self, tenant: str, agent: str) -> tuple[str, InputDlpPolicy] | None:
        """Fresh, uncached provider result, including immediately before resolve.

        Failures expose only a stable store code, never provider/DSN details.
        """
        try:
            policy = self._policy_provider(tenant, agent)
            if policy is not None and (
                not isinstance(policy, tuple) or len(policy) != 2
                or not isinstance(policy[0], str) or not 1 <= len(policy[0]) <= 256
                or not isinstance(policy[1], InputDlpPolicy)
            ):
                raise ValueError("invalid_policy")
            return policy
        except Exception:
            raise StoreError("unavailable") from None

    async def start(self) -> None:
        async with self._lifecycle:
            if self._worker is not None and not self._worker.done():
                return
            self.ready = False
            await self.store.initialize()
            self._stopping = False
            self._worker = asyncio.create_task(self._run(), name="attachment-worker")
            self.ready = True

    async def stop(self) -> None:
        async with self._lifecycle:
            self.ready = False
            self._stopping = True
            if self._worker is not None:
                self._worker.cancel()
                try:
                    await self._worker
                except asyncio.CancelledError:
                    if not self._worker.cancelled():
                        raise
                self._worker = None
            # Also drain an explicitly invoked process_once before closing storage.
            async with self._processing:
                await self.store.close()

    async def _run(self) -> None:
        try:
            while not self._stopping:
                try:
                    worked = await self.process_once()
                    self.ready = True
                except StoreError as error:
                    # Claims/finishes remain fenced; unavailable storage is never ALLOW.
                    if error.code != "busy":
                        self.ready = False
                    worked = False
                if not worked:
                    await asyncio.sleep(self._poll_seconds)
        except Exception:
            # Observe task failures without leaking parser or database diagnostics.
            logger.error("attachment_worker_failed")
        finally:
            self.ready = False

    async def _in_thread(self, operation: Callable[[], T]) -> T:
        task = asyncio.create_task(asyncio.to_thread(operation))
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            # Cancelling to_thread does not stop its thread. Keep the job slot
            # until it exits, including under repeated cancellation during shutdown.
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    continue
                except Exception:
                    break
            if not task.cancelled():
                task.exception()
            raise

    async def process_once(self) -> bool:
        """Claim one job; True means claimed, not necessarily committed/approved.

        False means idle, stopping, or this instance is already processing. A
        cancelled or uncommitted job is recoverable only through lease expiry.
        """
        if self._stopping or self._processing.locked():
            return False
        async with self._processing:
            job = await self.store.claim(lease_seconds=LEASE_SECONDS)
            if job is None:
                return False
            deadline = monotonic() + PROCESS_SECONDS
            text: str | None = None
            state, reason = "review_required", "policy_changed"
            try:
                async with asyncio.timeout(PROCESS_SECONDS):
                    policy = self.current_policy(job["tenant"], job["agent"])
                    if policy is not None and policy[0] == job["policy_revision"]:
                        if not self.accepts_mime(job["tenant"], job["agent"], job["mime"]):
                            state, reason = "review_required", "unsupported_format"
                        elif len(job["raw"]) > self.upload_limit(job["tenant"], job["agent"], job["mime"]):
                            state, reason = "review_required", "incomplete"
                        else:
                            extracted = await self._extract(job)
                            text = extracted
                            limits = self.attachment_policy(job["tenant"], job["agent"])
                            if len(extracted.encode("utf-8")) > limits.max_total_bytes:
                                state, reason = "review_required", "incomplete"
                            else:
                                state, reason = await self._in_thread(
                                    lambda: self._scan(extracted, job, policy[1], deadline)
                                )
            except (DocxError, ExtractionError) as error:
                # Do not propagate parser diagnostics into public status/logs.
                state = "review_required"
                if error.reason == "no_text":
                    reason = "no_text"
                elif error.reason in {"unavailable", "busy", "invalid_languages"}:
                    reason = "extraction_unavailable"
                elif error.reason in {
                    "timeout", "incomplete", "input_limit", "output_limit", "pixel_limit", "page_limit",
                    "entry_limit", "uncompressed_limit", "compression_ratio_limit",
                    "xml_depth_limit", "xml_node_limit", "text_limit", "extraction_failed",
                }:
                    reason = "incomplete"
                elif error.reason == "unsupported_mime":
                    reason = "unsupported_format"
                else:
                    reason = "unsafe_document"
            except TimeoutError:
                state, reason = "review_required", "incomplete"
            except UnicodeError:
                state, reason = "review_required", "unsafe_document"
            except Exception:
                state, reason = "failed", "processor_failed"

            # This bounded persistence phase never re-extracts or re-scans. The
            # lease allows 60s beyond processing for draining/terminal bookkeeping.
            try:
                async with asyncio.timeout(FINISH_SECONDS):
                    for attempt in range(FINISH_ATTEMPTS):
                        try:
                            current = self.current_policy(job["tenant"], job["agent"])
                        except StoreError:
                            current = None
                        if current is None or current[0] != job["policy_revision"]:
                            state, reason = "review_required", "policy_changed"
                        elif state == "approved":
                            try:
                                if not self.accepts_mime(job["tenant"], job["agent"], job["mime"]):
                                    state, reason = "review_required", "unsupported_format"
                            except StoreError:
                                state, reason = "review_required", "incomplete"
                        try:
                            await self.store.finish(
                                job["id"], job["lease_token"], state=state,
                                text=text if state == "approved" else None, reason=reason,
                            )
                            return True
                        except StoreError as error:
                            if error.code == "capacity" and state == "approved":
                                state, reason = "review_required", "incomplete"
                            elif not error.retryable:
                                raise
                            if attempt + 1 < FINISH_ATTEMPTS:
                                await asyncio.sleep(0.05 * 2**attempt)
            except TimeoutError:
                return True  # Leave the lease intact for expiry/recovery.
            return True

    async def _extract(self, job: dict[str, Any]) -> str:
        mime, raw = job["mime"], job["raw"]
        if mime in TEXT_MIMES:
            return raw.decode("utf-8-sig")
        if mime == DOCX_MIME:
            document = await self._in_thread(lambda: extract_docx(raw))
            # The store supports text only. These labels preserve block provenance
            # for readers, not trusted roles or an authenticated structured schema.
            return "\n".join(f"[DOCX {b.kind} {b.index}]\n{b.text}" for b in document.blocks)
        if mime in NATIVE_MIMES:
            if not self._parser_isolation_confirmed or self._work_dir is None:
                raise ExtractionError("unavailable")
            async with asyncio.timeout(NATIVE_SECONDS):
                return await extract_document(
                    raw, mime, work_dir=self._work_dir, languages=self._languages, sandbox=True,
                )
        raise ExtractionError("unsupported_mime")

    def _scan(
        self, text: str, job: dict[str, Any], policy: InputDlpPolicy, deadline: float,
    ) -> tuple[str, str]:
        size = len(text.encode("utf-8"))
        if not text.strip():
            return "review_required", "no_text"
        if "\x00" in text:
            return "review_required", "unsafe_document"
        if size > min(MAX_TEXT_BYTES, policy.max_bytes):
            return "review_required", "incomplete"
        if monotonic() >= deadline:
            return "review_required", "incomplete"
        # Secrets always block, even when tenant DLP is not enabled. The tenant
        # policy adds PII/classification restrictions; this worker never redacts.
        dlp = inspect_request(
            {"text": text}, job["tenant"], job["agent"], job["id"],
            max_bytes=min(262144, policy.max_bytes + 4),
            redact_email=policy.redact_email, redact_phone=policy.redact_phone,
            blocked_terms=policy.blocked_terms,
        )
        if monotonic() >= deadline:
            return "review_required", "incomplete"
        if any(event.metadata.get("reason") == "input_dlp_incomplete" for event in dlp.events):
            return "review_required", "incomplete"
        if dlp.verdict != Verdict.ALLOW:
            return "blocked", "input_dlp"
        guard = InputGuardrail(offline=True)
        # Fixed per-window settings: environment tuning must not silently truncate
        # attachment inspections or weaken a revision-pinned, offline decision.
        guard.max_input_size = guard.max_scan_bytes = 16384
        guard.regex_budget_seconds = 1.5
        state, reason = "approved", "approved"
        for number, start in enumerate(range(0, len(text), WINDOW_CHARS - OVERLAP_CHARS)):
            if number >= MAX_WINDOWS or monotonic() >= deadline:
                return "review_required", "incomplete"
            result = guard.inspect(text[start:start + WINDOW_CHARS], job["tenant"], job["agent"])
            if monotonic() >= deadline:
                return "review_required", "incomplete"
            if any(event.source == "input_guardrail_budget" for event in result.events):
                return "review_required", "incomplete"
            if result.verdict == Verdict.BLOCK:
                return "blocked", "input_detection"
            if result.verdict != Verdict.ALLOW:
                state, reason = "review_required", "input_detection"
            if start + WINDOW_CHARS >= len(text):
                break
        return state, reason
