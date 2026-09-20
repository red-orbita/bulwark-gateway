# Strict Chat Attachments

`src/guardrails/attachments.py` is wired before upstream delivery in
`POST /v1/chat/completions`, with or without streaming and independently of the
scanner-pipeline flag. No live deployment is changed. Admission defaults to
text-only. The helper additionally supports opt-in local PNG/JPEG OCR and PDF
extraction through `document_extraction.extract_document`, but only with explicit
operator-confirmed parser isolation. Configuration, policy lookup, proxy and Helm
wiring are included; no running deployment is changed by adding these controls.

## Activation

Set `BULWARK_ATTACHMENT_GUARD_ENABLED=true`, or an authenticated agent's YAML
`attachments.enabled: true`. Global enabled protection cannot be disabled or
weakened by the agent's policy: enabled limits combine using the smaller bound.
Other settings: `BULWARK_ATTACHMENT_MAX_FILE_BYTES` (16000),
`BULWARK_ATTACHMENT_MAX_TOTAL_BYTES` (65536), `BULWARK_ATTACHMENT_MAX_COUNT` (5).
Helm exposes these through `proxy.attachments`; see `CHATBOT-HELM.md`.

To accept supported images/PDF by converting them to inspected text, also set:

```text
BULWARK_ATTACHMENT_EXTRACT_DOCUMENTS=true
BULWARK_ATTACHMENT_PARSER_ISOLATION_CONFIRMED=true
BULWARK_ATTACHMENT_EXTRACTION_WORK_DIR=/operator/private/extraction
BULWARK_ATTACHMENT_EXTRACTION_LANGUAGES=eng+spa
BULWARK_ATTACHMENT_MAX_DOCUMENT_BYTES=2097152
```

The work directory must already exist and have an adequate storage quota. The
confirmation is operator approval, not a client claim; Bubblewrap isolation is
still mandatory on this route and fails without namespace/native-tool support.
For a policy-enabled agent use `attachments.extract_documents: true`. If global
strict admission is enabled, both the global extraction switch and any enabled
agent policy's extraction permission must allow conversion. This never switches
extraction on through a request body or OCR result supplied by the client.

## Client Outcomes

| Outcome | HTTP behavior |
|---|---|
| Extracted text accepted by guardrail/DLP | Forward extracted text only, preserving the message role |
| Actual input-policy or DLP match | 403 security-policy rejection |
| Unreadable, encrypted, unsupported, empty or incomplete extraction | 422 document-processing error; not an accusation of attack |
| Extractor unavailable, busy, failed or timed out | 503 document-processing error; never forward the original as fallback |

Processing errors produce operational telemetry (`event.kind=event`,
`bulwark.verdict=not_evaluated`) with a fixed reason. They do not accrue correlation
risk or trigger attack detections. A UI can offer a readable export or operator
review; no review queue or automatic release mechanism is implemented here.
Text-only strict mode retains its original rejection behavior when extraction
has not been enabled. No mode guarantees every legitimate document can be parsed.

```yaml
tenant: example-corp
agents:
  - id: document-chatbot
    sandbox_level: strict
    allowed_tools: []
    attachments:
      enabled: true
      max_file_bytes: 8000
      max_total_bytes: 32000
      max_attachments: 4
```

The chatbot must route the actual request through Bulwark. Uploads going directly
to a provider/storage or retrieved outside this path are not covered. There is no
new `/files` upload or provider Responses API endpoint. Unsupported provider wire
formats require a trusted integration; client assertions of scanning are rejected.

## Contract

```python
async def inspect_chat_attachments(
    body: dict[str, Any], tenant_id: str, agent_id: str, request_id: str,
    *, policy: AttachmentPolicy, input_guardrail: AttachmentInputGuardrail,
    dlp_options: InputDlpPolicy | None = None,
    extraction_work_dir: Path | None = None,
    extraction_languages: str = "eng",
    parser_isolation_confirmed: bool = False,
) -> AttachmentInspection:
    ...
```

`AttachmentInspection.guardrail_result` is the shared `GuardrailResult`.
`sanitized_body` is optional: absent when disabled, unchanged or blocked; present
on an accepted request containing files. BLOCK must stop forwarding even when
`sanitized_body` is absent. The input dictionary is never mutated.

`AttachmentPolicy` is a frozen Pydantic model with unknown fields forbidden:

| Field | Default | Accepted values |
| --- | --- | --- |
| enabled | false | Strict boolean; true enables strict admission |
| extract_documents | false | Strict boolean; opt into PNG/JPEG/PDF extraction when admission is enabled |
| max_document_bytes | 2097152 | Strict integer 1-2097152; decoded bytes per document |
| max_file_bytes | 16000 | Strict integer 1-65536 |
| max_total_bytes | 65536 | Strict integer 1-65536 |
| max_attachments | 5 | Strict integer 1-5, across all messages |

The effective per-text-file limit also includes 16000 bytes, the shared engine's
`max_scan_bytes` and `max_input_size`, and the remaining total budget. A configured
larger file budget cannot bypass the text scan ceiling. Excess is rejected, never
truncated. Up to 1024 messages and a bounded 4096-node envelope are accepted.
The chat route retains HTTP request-size/rate limits and normal chat validation.
Converted structured text is scanned again in bounded overlapping windows by the
real message engine, with 64 KiB/128-block limits and a wall-clock budget. Exceeding
that budget blocks as incomplete inspection, not as a detected malicious document.

Documents have a separate hard **4 MiB combined decoded-byte limit**; the existing
five-attachment count includes both text files and documents. Extracted UTF-8 text
and fixed provenance labels share `max_total_bytes` (at most 64 KiB) with text files.
The extractor itself caps each result at 32 KiB. No original bytes are truncated
to fit. Every document's text is scanned in UTF-8-safe windows bounded by the
smaller of 16000, `max_scan_bytes`, and `max_input_size`, with up to 256 characters
of overlap. At most 128 input windows and 128 final DLP windows are admitted per
request; insufficient window or scanner budgets fail closed.

`parser_isolation_confirmed` must be exactly `True`, and `extraction_work_dir`
must be a `Path`; otherwise local extraction is never invoked. The extractor
requires an existing absolute private work directory with operator-provisioned
storage quotas. Neither the boolean nor the path proves OS isolation. Follow
the deployment gate in [DOCUMENT-EXTRACTION.md](DOCUMENT-EXTRACTION.md): isolate
the parser identity, credentials, mounts, network and resource consumption.
Never derive these arguments or `extraction_languages` from the request body.
Default language is `eng`; `eng+spa` requires both installed language datasets.
Missing tools, language data or isolation are unavailable inspection, not an
attack verdict. There is no automatic provisioning or download.

The proxy resolves this policy from the authenticated tenant/agent's operator
configuration and global settings before calling. It never uses body identity or
scan flags to authorize anything. If both scopes are disabled, the guard is inert, including for existing
plain-text requests; it is not proof that an attachment was inspected.

## Accepted Format

```json
{
  "messages": [{
    "role": "user",
    "content": [{
      "type": "file",
      "file": {
        "filename": "greeting.txt",
        "file_data": "data:text/plain;base64,SGVsbG8="
      }
    }]
  }]
}
```

Supported MIME/extension pairs: `text/plain` + `.txt`, `text/markdown` + `.md`
or `.markdown`, `application/json` + `.json`, `text/csv` + `.csv`. Filename is
required, limited to 255 ASCII characters without path separators, and discarded.
MIME must match exactly; MIME parameters, bare base64, malformed/noncanonical
base64 and MIME/extension mismatches are rejected. Text must be nonempty UTF-8
without binary C0/C1 controls (tab, CR and LF are permitted).

JSON and CSV are inspected as text, not deserialized or executed. MIME/extensions
are admission hints, not trusted content classification. Common disguised document
signatures are rejected; UTF-8/control checks are not an antivirus engine.

With `extract_documents=true`, these additional file MIME/extension pairs are
accepted: `image/png` + `.png`, `image/jpeg` + `.jpg`/`.jpeg`, and `application/pdf`
+ `.pdf`. Images can also use the standard inline image block:

```json
{"type":"image_url","image_url":{"url":"data:image/png;base64,...","detail":"auto"}}
```

Only PNG/JPEG are allowed in `image_url`; `detail` is optional and may be `auto`,
`low` or `high` (it never reduces inspection). MIME magic, image geometry, PDF
page/encryption limits and parsing completeness are checked by the extractor,
not inferred from filenames. PDFs combine embedded text and OCR of every accepted
page. Unreadable/blank documents are unavailable, not allowed as empty content.

Each accepted file becomes exactly `{"type":"text","text": extracted_text}`.
Document text includes the fixed prefix
`[User-provided document text; original file not forwarded (no_file)]` plus a
newline. It is scanned along with the extracted content, labels provenance only,
and grants no trust or authority. Text-file output is unchanged.
Only this scanned text reaches the model, never the original bytes, filename,
base64 or attachment metadata. All roles are covered, including system, developer,
assistant and tool. A late unsupported/sixth file rejects the whole request with
no partial body returned. Ordinary text blocks are validated structurally but
remain the normal input pipeline's scanning responsibility.
The full returned context and attachment data are snapshotted before the first
await: mutations to the caller's later files, roles or messages cannot introduce
unscanned content into the returned body. Cancellation propagates; it never
returns a partially sanitized request.

Without the document opt-in, PDF and all images remain blocked. DOCX, ZIP,
encrypted documents, `file_id`, references, remote URLs, audio and unknown content
types remain blocked in either mode. There is no remote fetch or dependency
download. Opt-in extraction writes private temporary files and invokes native
parsers inside the operator-provisioned isolation boundary. Alternative
attachment fields at body/message level or in extension envelopes are rejected.
Schema contents at `tools[].function.parameters`, `functions[].parameters` and
`response_format.json_schema.schema` are data definitions, not modality channels:
properties named `input`, `file` or `image`, including nullable `type` arrays,
are permitted. Their nodes still count toward the envelope budget. The exemption
is positional: a schema-shaped object inside an arbitrary extension does not
disable attachment checks. Other tool/schema security checks remain upstream
pipeline responsibilities.
Unknown message/block fields are not forwarded. Client-provided `extracted_text`
or `scanned` claims never establish inspection; inline image/file schemas reject
such additional fields. Body flags cannot enable extraction or authorize parsers.

## Integration Order

1. Authenticate, enforce request limits, resolve the trusted agent policy snapshot.
2. Call the helper before cache lookup, pipeline text extraction or any upstream
   call, for both streaming and non-streaming requests, independent of other
   guardrail-enable flags.
3. Export only `result.guardrail_result.events` via existing telemetry. On BLOCK,
   never forward. The legacy response remains 403. When the effective operator
   policy has `extract_documents=true`, the caller should map unavailable
   inspection to a generic 422 (unsupported/uninspectable document or limits) or
   503 (missing isolation/runtime, busy, timeout or incomplete scanning), not an
   attack detection. Actual input/DLP detections remain security-policy blocks.
   HTTP mapping is the proxy integrator's responsibility, not this helper's.
4. When `sanitized_body is not None`, assign it to `body` and rebuild `messages`
   and every derived input/upstream representation from it. Never fall back to
   the original file-bearing body on a forwarding/retry/fallback path.
5. Continue the normal input, IOC, corporate whole-request DLP and output pipeline.

```python
result = await inspect_chat_attachments(
    body, tenant_id, agent_id, request_id,
    policy=resolved_attachment_policy,
    input_guardrail=shared_input_guardrail,
    dlp_options=effective_dlp_options,
    extraction_work_dir=operator_work_dir,
    extraction_languages="eng",
    parser_isolation_confirmed=operator_isolation_confirmed,
)
# Emit result.guardrail_result.events through existing telemetry.
if result.guardrail_result.verdict == Verdict.BLOCK:
    # Map unavailable inspection only in document mode; never expose diagnostics.
    return blocked_response
if result.sanitized_body is not None:
    body = result.sanitized_body
messages = body.get("messages", [])
```

`AttachmentInputGuardrail` is a self-contained protocol for the shared synchronous
`inspect(text, tenant_id, agent_id)` and its two size limits. The async helper runs
the bounded shared engine and DLP in a dedicated executor, with no admin imports.
The shared engine retains its own regex budget; exceptions and unsupported REDACT
results fail closed rather than forwarding original bytes. WARNs remain WARNs.

## Executor Lifecycle

At most **two outstanding inspection jobs per process** are admitted, across
input-guardrail and DLP calls. Admission never waits for a slot: overload blocks
immediately as `inspection_unavailable`. Each submitted job has a **5-second
await timeout** (not a total request deadline). No work is submitted to asyncio's
default executor for text inspection, preserving its availability for DNS and
unrelated operations. Document extraction has its own two-call admission and
native process/time/resource limits; see `DOCUMENT-EXTRACTION.md`.

Timeout blocks the request; request cancellation propagates to its caller. Neither
releases a running job's slot. The concurrent future's completion callback releases
it only when the actual worker finishes, even after request cancellation or event
loop closure. Late exceptions are consumed. Python threads cannot be forcibly
killed: two stuck jobs keep admission closed, rather than spawning replacement
workers or accumulating an unbounded queue. Normal text requests need no slot.

Threads start lazily on the first admitted inspection, not at import, and there
are at most two persistent worker threads per process. The integrator can call
`shutdown_attachment_executor()` at application shutdown: it stops admission,
cancels not-yet-running work and retires workers after running jobs finish, without
blocking the event loop. Shutdown is terminal for this process-local executor;
it is not automatically recreated by later requests. The standard executor also
joins workers on process exit. No lifecycle wiring outside this helper is included.

## Corporate DLP

Baseline secret/PII DLP always inspects every extracted file, even if global DLP
and `InputDlpPolicy.enabled` are false. `dlp_options` is an operator-resolved
`InputDlpPolicy`, not client input. Pass the same effective corporate options used
by the ordinary request DLP path:

- `max_bytes`: smaller budget when global and agent DLP are enabled; otherwise
  the enabled scope's budget, or 65536 for the attachment-only floor.
- `redact_email` / `redact_phone`: global option OR the enabled agent option.
- `blocked_terms`: the enabled agent policy's normalized terms, or empty tuple.

Its `enabled` flag cannot disable the attachment floor. All extracted strings
are charged once under the aggregate DLP byte budget (including provenance).
For requests containing documents, final DLP scans overlapping chunks of at most
16000 UTF-8 bytes, preserving the complete forwarded text. Overlap is scanned
but not double-charged against the corporate budget. Legacy text-only requests
retain their single aggregate DLP call. Secret/PII matches
BLOCK, not redact. Original data and additional contextual DLP candidates have
separate bounded budgets so contextual inspection does not double-charge file
bytes. This does not replace whole-request DLP, business-data
classification or context-aware detection across split files/messages.
Phone matching inherits the existing detector's limited formats (for example,
`+12025550147`; multiple internal separators are not reliably matched).

## Privacy And Limits

Events use authenticated IDs, fixed descriptions/reason codes and no payload,
filename, URL, raw match, original scanner metadata or exception text. Unsupported
formats and incomplete inspection use `category=policy_violation` and
`reason=inspection_unavailable`: this is not a claim of malicious detection.
Real input matches use `reason=input_detection`; DLP blocks use `reason=input_dlp`.
Only when `extract_documents=true`, unavailable events additionally include
`metadata.extraction_reason`. Values are allowlisted extractor reasons
(`unsupported_mime`, `invalid_document`, `input_limit`, `pixel_limit`, `page_limit`,
`encrypted_pdf`, `output_limit`, `no_text`, `busy`, `timeout`, `unavailable`,
`invalid_languages`, `extraction_failed`) or the helper's `inspection_incomplete`.
Envelope/admission failures default to `invalid_document`; missing isolation to
`unavailable`; unexpected extraction exceptions to `extraction_failed`. Scanner
exceptions, exhausted windows and incomplete DLP use `inspection_incomplete`.
Exception text and unrecognized exception reason values are never exported.

`sanitized_body` still contains user data. Never log or export the entire helper
result; only its `guardrail_result.events` are designed for telemetry. Scanner
coverage is the shared engine's coverage, not a guarantee that every prompt
injection, encoded secret, polyglot or malicious document can be identified.

## What The Chatbot Can Claim

| Input | Strict attachment guard |
|---|---|
| Supported inline UTF-8 text file | Decoded, scanned for input attacks and sensitive data; only extracted text forwarded |
| PNG/JPEG | Default rejected; opt-in isolated OCR, full extracted-text scanning and text-only forwarding |
| PDF | Default rejected; opt-in isolated embedded + rendered-page OCR, then full extracted-text scanning |
| DOCX, archive or encrypted file | Rejected; no partial extraction or decompression fallback |
| Remote URL / provider file ID | Rejected without fetching; later provider content cannot differ from a scanned copy |
| Client-provided OCR/extracted text or scan status | Not trusted as evidence about the original attachment |

The separate `VisionScanner(blocking=True)` can scan OCR-extracted image text when
an operator provisions the OCR runtime. It now blocks image inspection failures
and prevents automatic EasyOCR downloads. It cannot guarantee recognition of low-
contrast, handwritten, multilingual, adversarial or purely visual instructions.
Its presence does not override strict attachment admission. The local extraction
integration likewise cannot guarantee recognition of visual instructions or
complete semantic PDF coverage. Representative labeled corpora and parser
isolation remain required; synthetic tests are not a production security claim.

## Focused Verification

```bash
pytest tests/test_document_attachment_flow.py tests/test_attachment_guard.py -q
BULWARK_TEST_DOCUMENT_TOOLS=1 pytest tests/test_document_attachment_flow.py -k synthetic_native -q
```

Failure, hostile-text and scanner tests fake extraction, so arbitrary bytes never
reach native tools. The explicitly opt-in native integration tests reuse generated
benign PNG/PDF fixtures and perform no installs, downloads or service changes.
