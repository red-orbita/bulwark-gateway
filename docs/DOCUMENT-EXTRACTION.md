# Local Document Extraction

`src.guardrails.document_extraction.extract_document` is wired into opt-in chat
attachment admission, proxy configuration and Helm. It supports PNG, JPEG and PDF
text conversion without forwarding binary inputs. Native tools and sandbox support
must be provisioned by the operator; the stock distroless image does not include them.

```python
async def extract_document(
    data: bytes, mime: str, *, work_dir: Path, languages: str = "eng",
    sandbox: bool = True,
) -> str: ...
```

The caller supplies already-decoded bytes and an exact MIME (`image/png`,
`image/jpeg`, `application/pdf`). There is no URL, client filename, executable,
command, tessdata directory or download argument. `work_dir`, `languages` and `sandbox`
must come from operator configuration, never the request. Paths to native
binaries are fixed to `/usr/bin/{tesseract,pdfinfo,pdftoppm,pdftotext}`. The Python
interpreter inside the sandbox is fixed to `/usr/bin/python3`; provisioning is
the operator's responsibility. The repository/virtualenv interpreter is never
mounted inside the sandbox.
Installed Tesseract language data is required (default `eng`, e.g. `eng+spa`).
No Python OCR libraries, model downloads, services or containers are installed.

## Deployment Gate

**Bubblewrap isolation is enforced by default.** Every native invocation uses
fixed `/usr/bin/bwrap` with `--unshare-all`, `--die-with-parent`, `--new-session`
and all capabilities dropped. The private mount namespace contains read-only
`/usr`, `/lib`, `/lib64`, optionally the single `/etc/ld.so.cache` file, namespace
`/proc`, minimal `/dev`, private tmpfs `/tmp`, and the request-private directory
bound read-write at `/work`. Host home, repository, `/media`, credentials and
the rest of `/etc` are not mounted. Internal file arguments are rewritten to
`/work`; a generated minimal fontconfig file uses only `/usr/share/fonts` and a
private cache, without mounting host or user font configuration. The network and
PID namespaces are private. There is no automatic unsandboxed fallback: absent
Bubblewrap or failure to start the resource-limited worker raises `unavailable`.

The operator must provision Bubblewrap, namespace support, native tools, fonts and
language data. Keep the mounted runtime free of credentials, patched and
supply-chain controlled. Also provision an unprivileged identity, OS syscall
controls and aggregate memory/CPU/PID/storage quotas. Namespace isolation is not
a VM or a complete defense against kernel vulnerabilities, and per-process limits
do not replace cgroup quotas. Only synthetic documents are used in local tests.

`sandbox=False` is an explicit **operator-only** escape for trusted local tests or
an independently isolated parser deployment. It uses `sys.executable` and resource
limits but has no filesystem/network sandbox; never expose this switch to clients
or use it as an availability fallback. No global security setting is changed.

`work_dir` must be an existing absolute directory on an operator-selected
persistent filesystem, private to the extraction identity, with quotas and
appropriate permissions. No implicit mkdir or fallback to `/tmp` occurs. Every
request uses a fresh mode-0700 subdirectory; originals, rendered pages and tool
output are removed on success, failure and cancellation before releasing capacity.
Abrupt host/process death can leave remnants: configure startup/retention cleanup
and encryption at rest. Persistence cannot be verified from a `Path`; the operator
must not point it at a memory-backed filesystem with an inadequate budget.

## Extraction Contract

- PNG/JPEG: structural header/magic and geometry preflight, then direct Tesseract
  OCR. PNG CRC/chunk framing is checked; APNG is rejected rather than scanning
  only its first frame. JPEG baseline/extended/progressive headers are supported;
  this is not a complete JPEG validator. Native decoding remains untrusted.
- PDF: require PDF magic, one unambiguous page count and explicit unencrypted
  status from `pdfinfo`. All accepted pages get both `pdftotext` extraction and
  `pdftoppm` rendering followed by OCR. No embedded-text-only shortcut, first-page
  shortcut or byte-regex fallback. Poppler diagnostics fail closed as potentially
  partial parsing. Labels identify each page's embedded and OCR text; duplicates
  are intentional. Invisible embedded text can therefore remain an inspection
  candidate alongside OCR of the rendered view.
- Return only the combined text. No originals, previews, pixel arrays, metadata,
  native diagnostics or filenames are returned. No fetching, links, JavaScript
  execution or forwarding to any backend is implemented.
- Output remains **untrusted content**, potentially including prompt injection,
  credentials, markup or control characters. This is text-only conversion, not
  approval or an injection-removal algorithm. OCR is lossy: it can miss small,
  stylized, rotated, multilingual or visually deceptive text. PDF rendering plus
  embedded extraction is not a proof that every PDF object was inspected; visual
  meaning, attachments, layers and active features are not preserved.
- The primary pipeline must scan **all** extracted text with its input guardrail
  and DLP, respect scanner size budgets, then replace the original attachment with
  the inspected/redacted text only. A 32-KiB result exceeds a 16-KiB scanner window:
  never silently scan only a prefix. Enforce aggregate request limits as well.
- Every PDF page must yield non-whitespace OCR text. If both channels on any page
  are empty, raise `no_text`; if only embedded text exists, raise `incomplete`.
  A readable neighbouring page cannot mask an unreadable/blank page. OCR-only pages
  are accepted (scanned PDFs need not contain embedded text). This conservative
  contract can reject legitimate blank pages or diagrams: report **extraction
  incomplete/unavailable**, not maliciousness, and never forward the original as
  a fallback. Nonempty OCR is still not proof that every visual element was read.

## Budgets

| Resource | Limit |
|----------|-------|
| Decoded input | 2 MiB per document (caller must bound HTTP/base64 input too) |
| Active extractions | 2 per Python process, immediate `busy` on excess; no wait queue |
| PDF pages | 1-5, all processed sequentially |
| Image geometry | 8,000,000 pixels and 8,000 pixels per axis |
| PDF geometry | Same gate at 150 DPI, on every reported page |
| PDF render | Longest axis capped at 2,800 pixels, then PNG geometry checked |
| Returned UTF-8 | 32 KiB total, including all embedded/OCR labels; never truncated |
| Native stdout/stderr/text file | RLIMIT_FSIZE 32 KiB + 1, bounded reads |
| Renderer files/stdout/stderr | RLIMIT_FSIZE 32 MiB per file, bounded reads |
| Each native process | 15 CPU seconds, 768 MiB address space, 64 FDs, no core dumps |
| Wall time | 20 seconds per child, 90 seconds per extraction across native stages |

Wall budgets are checked between stages and while polling children; slow filesystem
operations and kernel-uninterruptible tasks can delay final cleanup. Capacity is
deliberately retained until cleanup completes. File-size limits are per file, not
a disk quota; provide an aggregate storage quota. Worker counts multiply across
processes/replicas, so admission and quotas must also be enforced at deployment level.

File I/O and child supervision use a dedicated `ThreadPoolExecutor(max_workers=2)`,
never the event loop's default executor. Admission is released by a callback on
the **concurrent future**, only when actual work ends, even if the asyncio wrapper
is cancelled and the originating loop closes. Cancellation signals the worker to
stop; while its wrapper is live the caller waits for cleanup. A cancelled wrapper
may propagate cancellation sooner, but cannot release the occupied slot.

Inside Bubblewrap, `/usr/bin/python3 -I -c <constant program>` applies resource
limits before execing the allowlisted native binary, without shell or `preexec_fn`.
Environment contains fixed `PATH`, private `HOME`/`TMPDIR`, `LC_ALL=C`, a generated
fontconfig path and single-thread settings. No credentials are inherited. There
are no unbounded stdout/stderr pipes. Timeout/cancellation kills the launcher
process group and reaps the direct child; Bubblewrap's parent-death and PID
namespace lifecycle terminate isolated descendants. Unsandboxed mode only kills
same-group descendants, not children that escape that group. This is not a
cgroup supervisor. Files are cleaned before actual worker admission is released.

Failures raise `ExtractionError` with a safe `reason`: `unsupported_mime`,
`invalid_document`, `input_limit`, `pixel_limit`, `page_limit`, `encrypted_pdf`,
`output_limit`, `no_text`, `incomplete`, `busy`, `timeout`, `unavailable`, `invalid_languages` or
`extraction_failed`. A native process hitting a resource limit may report the
generic `extraction_failed`. Cancellation propagates `asyncio.CancelledError`
with worker-owned cleanup/admission as described above. Never log bytes, returned text, parser diagnostics or traceback
locals; safe reason codes are sufficient for caller telemetry.

## Verification

```bash
pytest tests/test_document_extraction.py -q
BULWARK_TEST_DOCUMENT_TOOLS=1 pytest tests/test_document_extraction.py -q
```

Native tests are explicitly opt-in and skip if the fixed binaries are unavailable;
if installed Bubblewrap cannot establish the required namespaces, they fail rather
than testing an unsandboxed fallback. They exercise sandbox mounts, interpreter,
network isolation, timeouts/cancellation and real PNG/JPEG/PDF extraction.
They use only locally generated PNG/PDF content (and JPEG rendered from synthetic
PDF), never real user documents. No native tools or language data are installed
by tests. The real HTTP lab with `--documents` exercises the integrated proxy using
generated benign/injection-bearing PNG and PDF fixtures; the runner is
`scripts/chatbot-e2e-lab.py`. Review its resource and isolation prerequisites before
execution; reports and generated credentials are local-only artifacts.
