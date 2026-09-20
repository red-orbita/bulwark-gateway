"""Strict chat attachments; optional isolated local extraction, never retrieval."""

import asyncio
import base64
import copy
import re
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from queue import Queue
from typing import Annotated, Any, Literal, Protocol, get_args

from pydantic import BaseModel, ConfigDict, Field, StrictBool

from src.guardrails.document_extraction import ExtractionError, ExtractionReason, extract_document
from src.guardrails.input_dlp import InputDlpPolicy, inspect_request
from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict

MAX_TEXT_BYTES = 16_000
MAX_TOTAL_BYTES = 65_536
MAX_ATTACHMENTS = 5
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_TOTAL_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_SCAN_WINDOWS = 128
DOCUMENT_PROVENANCE = "[User-provided document text; original file not forwarded (no_file)]\n"
MAX_NODES = 4096
MAX_INSPECTION_JOBS = 2
INSPECTION_TIMEOUT_SECONDS = 5.0
# ThreadPoolExecutor starts threads only on first submission. Admission bounds
# outstanding work, not just workers, and never uses asyncio's DNS/default pool.
_inspection_executor = ThreadPoolExecutor(max_workers=MAX_INSPECTION_JOBS, thread_name_prefix="attachment-inspection")
_inspection_slots: Queue[None] = Queue(maxsize=MAX_INSPECTION_JOBS)
_MIME_EXTENSIONS = {
    "text/plain": (".txt",),
    "text/markdown": (".md", ".markdown"),
    "application/json": (".json",),
    "text/csv": (".csv",),
}
_DOCUMENT_EXTENSIONS = {
    "image/png": (".png",), "image/jpeg": (".jpg", ".jpeg"), "application/pdf": (".pdf",),
}
_ALTERNATE_FIELDS = frozenset({
    "attachments", "attachment", "input", "input_file", "input_image", "input_audio",
    "audio", "document", "image", "image_url", "file", "files", "file_id", "file_data",
    "file_url", "images", "documents", "video", "video_url", "extracted_text",
})
_SCHEMA_POSITIONS = {
    ("body", "tools"): "tools",
    ("body", "functions"): "functions",
    ("body", "response_format"): "response_format",
    ("tool", "function"): "function",
    ("function", "parameters"): "schema",
    ("response_format", "json_schema"): "json_schema",
    ("json_schema", "schema"): "schema",
}


def shutdown_attachment_executor() -> None:
    """Stop admission at application shutdown; running jobs keep their slots."""
    _inspection_executor.shutdown(wait=False, cancel_futures=True)


async def _run_inspection(
    inspect: Callable[..., GuardrailResult], /, *args: Any, **kwargs: Any,
) -> GuardrailResult:
    slots = _inspection_slots
    slots.put_nowait(None)
    try:
        job = _inspection_executor.submit(inspect, *args, **kwargs)
    except BaseException:
        slots.get_nowait()
        raise

    def finished(_: Future[GuardrailResult]) -> None:
        # This callback belongs to the concurrent future, not the request task:
        # timeout/cancellation/loop closure cannot release a running job's slot.
        slots.get_nowait()

    job.add_done_callback(finished)
    result = asyncio.wrap_future(job)
    result.add_done_callback(lambda future: None if future.cancelled() else future.exception())
    return await asyncio.wait_for(asyncio.shield(result), timeout=INSPECTION_TIMEOUT_SECONDS)


class AttachmentPolicy(BaseModel):
    """Resolved operator policy, inherited/selected by the caller, never the body."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    enabled: StrictBool = False
    async_enabled: StrictBool = False
    extract_documents: StrictBool = False
    max_document_bytes: Annotated[int, Field(strict=True, ge=1, le=MAX_DOCUMENT_BYTES)] = MAX_DOCUMENT_BYTES
    max_file_bytes: Annotated[int, Field(strict=True, ge=1, le=MAX_TOTAL_BYTES)] = MAX_TEXT_BYTES
    max_total_bytes: Annotated[int, Field(strict=True, ge=1, le=MAX_TOTAL_BYTES)] = MAX_TOTAL_BYTES
    max_attachments: Annotated[int, Field(strict=True, ge=1, le=MAX_ATTACHMENTS)] = MAX_ATTACHMENTS


class AttachmentInputGuardrail(Protocol):
    """The shared synchronous engine and its actual no-truncation limits."""

    @property
    def max_scan_bytes(self) -> int: ...

    @property
    def max_input_size(self) -> int: ...

    def inspect(self, content: str, tenant_id: str = "", agent_id: str = "") -> GuardrailResult: ...


class AttachmentInspection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    guardrail_result: GuardrailResult
    # This is request data, NOT telemetry. Never serialize/log the whole result.
    sanitized_body: dict[str, Any] | None = Field(default=None, repr=False)


class _TextBlock(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    type: Literal["text"]
    text: str = Field(max_length=2_097_152)


class _InlineFile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    filename: str = Field(min_length=1, max_length=255)
    file_data: str = Field(min_length=1, max_length=4 * ((MAX_DOCUMENT_BYTES + 2) // 3) + 64)


class _FileBlock(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    type: Literal["file"]
    file: _InlineFile


class _InlineImage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    url: str = Field(min_length=1, max_length=4 * ((MAX_DOCUMENT_BYTES + 2) // 3) + 64)
    detail: Literal["auto", "low", "high"] = "auto"


class _ImageBlock(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    type: Literal["image_url"]
    image_url: _InlineImage


def _text_windows(text: str, limit: int) -> list[str]:
    """Byte-bounded UTF-8 windows, with up to 256 characters of overlap."""
    if limit < 4:
        raise ValueError("Insufficient scan window")
    windows: list[str] = []
    start = 0
    while start < len(text):
        if len(windows) >= MAX_SCAN_WINDOWS:
            raise ValueError("Scan window budget")
        window = text[start:start + limit].encode("utf-8")[:limit].decode("utf-8", errors="ignore")
        windows.append(window)
        if start + len(window) == len(text):
            break
        start += len(window) - min(256, len(window) // 2)
    return windows


async def inspect_chat_attachments(
    body: dict[str, Any], tenant_id: str, agent_id: str, request_id: str,
    *, policy: AttachmentPolicy, input_guardrail: AttachmentInputGuardrail,
    dlp_options: InputDlpPolicy | None = None,
    extraction_work_dir: Path | None = None,
    extraction_languages: str = "eng",
    parser_isolation_confirmed: bool = False,
) -> AttachmentInspection:
    """Replace accepted attachments with scanned text, or fail closed atomically.

    DLP always runs on extracted files. ``dlp_options`` carries resolved global +
    agent settings; its ``enabled`` field does not disable this attachment floor.
    Plain message text remains the caller's normal input guardrail responsibility.
    Document extraction requires operator-supplied isolation and storage settings;
    body claims never enable it. Extraction failures are not attack detections.
    Only ``guardrail_result.events`` is safe to export, never ``sanitized_body``.
    """
    events: list[SecurityEvent] = []
    reason = "inspection_unavailable"
    extraction_reason = "invalid_document"
    try:
        if not isinstance(policy, AttachmentPolicy):
            raise ValueError("Unvalidated policy")
        if not policy.enabled:
            return AttachmentInspection(guardrail_result=GuardrailResult(verdict=Verdict.ALLOW))
        options = dlp_options if dlp_options is not None else InputDlpPolicy()
        if not isinstance(options, InputDlpPolicy):
            raise ValueError("Unvalidated DLP options")
        if not isinstance(body, dict):
            raise ValueError("Invalid chat body")
        messages = body.get("messages")
        if not isinstance(messages, list) or not 0 < len(messages) <= 1024:
            raise ValueError("Invalid messages")

        # Only standard schema positions are data definitions, not channels.
        # Extensions cannot bypass checks by naming a field "parameters"/"tools".
        if len(body) > MAX_NODES or _ALTERNATE_FIELDS.intersection(body):
            raise ValueError("Unsupported channel")
        pending: list[tuple[Any, str]] = [
            (value, _SCHEMA_POSITIONS.get(("body", key), "channel"))
            for key, value in body.items() if key != "messages"
        ]
        for message in messages:
            if not isinstance(message, dict) or len(message) > 7 or set(message) - {
                "role", "content", "name", "tool_calls", "tool_call_id", "function_call", "refusal",
            }:
                raise ValueError("Invalid message")
            if message.get("role") not in {"user", "assistant", "system", "developer", "tool", "function"}:
                raise ValueError("Invalid role")
            if len(pending) + len(message) > MAX_NODES:
                raise ValueError("Structure limit")
            pending.extend((value, "channel") for key, value in message.items() if key != "content")
        nodes = len(body)
        while pending:
            value, position = pending.pop()
            nodes += 1
            if isinstance(value, dict):
                if position != "schema":
                    if _ALTERNATE_FIELDS.intersection(value):
                        raise ValueError("Unsupported channel")
                    modality = value.get("type")
                    if isinstance(modality, str) and modality in _ALTERNATE_FIELDS:
                        raise ValueError("Unsupported modality")
                if nodes + len(pending) + len(value) > MAX_NODES:
                    raise ValueError("Structure limit")
                pending.extend(
                    (child, "schema" if position == "schema" else _SCHEMA_POSITIONS.get((position, key), "channel"))
                    for key, child in value.items()
                )
            elif isinstance(value, list):
                if nodes + len(pending) + len(value) > MAX_NODES:
                    raise ValueError("Structure limit")
                child_position = {"tools": "tool", "functions": "function", "schema": "schema"}.get(
                    position, "channel",
                )
                pending.extend((child, child_position) for child in value)
            if nodes > MAX_NODES:
                raise ValueError("Structure limit")

        # Freeze all bytes AND the context that will be returned before yielding.
        # A caller mutating later blocks/roles during extraction cannot bypass admission.
        snapshot_nodes = nodes
        for message in messages:
            content = message.get("content")
            if content is None or isinstance(content, str):
                continue
            if not isinstance(content, list) or snapshot_nodes + len(content) > MAX_NODES:
                raise ValueError("Invalid content")
            snapshot_nodes += len(content)
            for block in content:
                if not isinstance(block, dict):
                    raise ValueError("Invalid block")
                if block.get("type") == "text":
                    _TextBlock.model_validate(block)
                elif block.get("type") == "file":
                    _FileBlock.model_validate(block)
                elif block.get("type") == "image_url" and policy.extract_documents:
                    _ImageBlock.model_validate(block)
                else:
                    raise ValueError("Unsupported modality")
        body = copy.deepcopy(body)
        messages = body["messages"]
        replacements: list[tuple[int, int, str]] = []
        total = 0
        document_total = 0
        has_documents = False
        scan_windows = 0
        for message_index, message in enumerate(messages):
            content = message.get("content")
            if content is None or isinstance(content, str):
                continue
            if not isinstance(content, list) or nodes + len(content) > MAX_NODES:
                raise ValueError("Invalid content")
            nodes += len(content)
            for block_index, block in enumerate(content):
                if not isinstance(block, dict):
                    raise ValueError("Invalid block")
                if block.get("type") == "text":
                    _TextBlock.model_validate(block)
                    continue
                is_image = block.get("type") == "image_url" and policy.extract_documents
                if block.get("type") != "file" and not is_image:
                    raise ValueError("Unsupported modality")
                if len(replacements) >= policy.max_attachments:
                    raise ValueError("Attachment count limit")
                if is_image:
                    data = _ImageBlock.model_validate(block).image_url.url
                    filename = None
                else:
                    file = _FileBlock.model_validate(block).file
                    filename, data = file.filename, file.file_data
                    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]*", filename):
                        raise ValueError("Invalid filename")
                header, separator, encoded = data.partition(",")
                mime = header.removeprefix("data:").removesuffix(";base64")
                document = policy.extract_documents and mime in _DOCUMENT_EXTENSIONS
                extensions = _DOCUMENT_EXTENSIONS if document else _MIME_EXTENSIONS
                if (not separator or header != f"data:{mime};base64"
                        or mime not in extensions
                        or (is_image and mime not in {"image/png", "image/jpeg"})
                        or (filename is not None and not filename.lower().endswith(extensions[mime]))):
                    raise ValueError("Unsupported representation")
                limit = (min(policy.max_document_bytes, MAX_TOTAL_DOCUMENT_BYTES - document_total) if document
                         else min(policy.max_file_bytes, policy.max_total_bytes - total, MAX_TEXT_BYTES,
                                  input_guardrail.max_scan_bytes, input_guardrail.max_input_size))
                if limit <= 0 or len(encoded) > 4 * ((limit + 2) // 3):
                    raise ValueError("Attachment byte limit")
                raw = base64.b64decode(encoded, validate=True)
                if not raw or len(raw) > limit or base64.b64encode(raw).decode("ascii") != encoded:
                    raise ValueError("Invalid or oversized base64")
                if document:
                    has_documents = True
                    document_total += len(raw)
                    extraction_reason = "unavailable"
                    if parser_isolation_confirmed is not True or not isinstance(extraction_work_dir, Path):
                        raise ValueError("Parser isolation unavailable")
                    extraction_reason = "extraction_failed"
                    try:
                        text = await extract_document(raw, mime, work_dir=extraction_work_dir,
                                                      languages=extraction_languages)
                    except ExtractionError as exc:
                        extraction_reason = (exc.reason if exc.reason in get_args(ExtractionReason)
                                             else "extraction_failed")
                        raise
                    extraction_reason = "output_limit"
                    if not isinstance(text, str) or len(text) > MAX_TOTAL_BYTES:
                        raise ValueError("Invalid extraction output")
                    if not text.strip():
                        extraction_reason = "no_text"
                        raise ValueError("Empty extraction")
                    text = DOCUMENT_PROVENANCE + text
                    if len(text.encode("utf-8")) > policy.max_total_bytes - total:
                        raise ValueError("Extracted text byte limit")
                else:
                    text = raw.decode("utf-8", errors="strict")
                    if any(ord(ch) < 32 and ch not in "\t\n\r" or 127 <= ord(ch) <= 159 for ch in text):
                        raise ValueError("Non-text data")
                    if raw.lstrip().startswith((b"%PDF-", b"PK\x03\x04", b"{\\rtf", b"-----BEGIN PGP MESSAGE-----")):
                        raise ValueError("Unsupported document")
                total += len(text.encode("utf-8"))
                extraction_reason = "inspection_incomplete"
                windows = (_text_windows(text, min(MAX_TEXT_BYTES, input_guardrail.max_scan_bytes,
                                                   input_guardrail.max_input_size)) if document else [text])
                scan_windows += len(windows)
                if scan_windows > MAX_SCAN_WINDOWS:
                    raise ValueError("Scan window budget")
                for window in windows:
                    scanned = await _run_inspection(input_guardrail.inspect, window, tenant_id, agent_id)
                    if scanned.verdict == Verdict.REDACT or scanned.modified_content is not None:
                        raise ValueError("Unsupported scanner rewrite")
                    if any(event.source in {"input_guardrail_budget", "input_guardrail_msg_budget"}
                           for event in scanned.events):
                        raise ValueError("Incomplete scan")
                    if scanned.verdict != Verdict.ALLOW or scanned.events:
                        verdict = (Verdict.BLOCK if scanned.verdict == Verdict.BLOCK
                                   or any(e.verdict == Verdict.BLOCK for e in scanned.events) else Verdict.WARN)
                        events.append(SecurityEvent(
                            tenant_id=tenant_id, agent_id=agent_id, request_id=request_id,
                            verdict=verdict,
                            category=scanned.events[0].category if scanned.events else ThreatCategory.POLICY_VIOLATION,
                            severity="high" if verdict == Verdict.BLOCK else "medium",
                            description="Attachment text matched the input security policy",
                            source="attachment_guard", metadata={"reason": "input_detection"},
                        ))
                        if verdict == Verdict.BLOCK:
                            return AttachmentInspection(
                                guardrail_result=GuardrailResult(verdict=verdict, events=events))
                replacements.append((message_index, block_index, text))
                extraction_reason = "invalid_document"

        if replacements:
            extraction_reason = "inspection_incomplete"
            if total > options.max_bytes:
                raise ValueError("DLP byte limit")
            # The empty wrapper avoids key=value duplication. Charge text once
            # above, not again for overlap; each DLP call is still bounded.
            dlp_batches = ([[window] for _, _, text in replacements
                            for window in _text_windows(text, min(MAX_TEXT_BYTES, options.max_bytes))]
                           if has_documents else [[text for _, _, text in replacements]])
            if len(dlp_batches) > MAX_SCAN_WINDOWS:
                raise ValueError("DLP window budget")
            for batch in dlp_batches:
                dlp = await _run_inspection(
                    inspect_request, {"": batch}, tenant_id, agent_id, request_id,
                    max_bytes=options.max_bytes, redact_email=options.redact_email,
                    redact_phone=options.redact_phone, blocked_terms=options.blocked_terms,
                )
                if dlp.verdict != Verdict.ALLOW:
                    reason = "input_dlp"
                    if any(e.metadata.get("reason") == "input_dlp_incomplete" for e in dlp.events):
                        reason = "inspection_unavailable"
                    raise ValueError("Attachment DLP rejected")

        sanitized = None
        if replacements:
            # Copy only changed containers; never mutate the original request or
            # return partially rewritten data when a later attachment fails.
            sanitized = dict(body)
            sanitized["messages"] = list(messages)
            for message_index, block_index, text in replacements:
                message = dict(sanitized["messages"][message_index])
                message["content"] = list(message["content"])
                message["content"][block_index] = {"type": "text", "text": text}
                sanitized["messages"][message_index] = message
        return AttachmentInspection(
            guardrail_result=GuardrailResult(verdict=Verdict.WARN if events else Verdict.ALLOW, events=events),
            sanitized_body=sanitized,
        )
    except Exception:
        # Never export parser/scanner exceptions, matches, names, URLs or payloads.
        events.append(SecurityEvent(
            tenant_id=tenant_id, agent_id=agent_id, request_id=request_id,
            verdict=Verdict.BLOCK, category=ThreatCategory.POLICY_VIOLATION,
            severity="high", source="attachment_guard",
            description="Attachment inspection unavailable" if reason == "inspection_unavailable"
            else "Attachment blocked by input data-loss prevention policy",
            metadata={"reason": reason, **({"extraction_reason": extraction_reason}
                      if isinstance(policy, AttachmentPolicy) and policy.extract_documents
                      and reason == "inspection_unavailable" else {})},
        ))
        return AttachmentInspection(guardrail_result=GuardrailResult(verdict=Verdict.BLOCK, events=events))
