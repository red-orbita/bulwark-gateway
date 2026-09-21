# Structured DOCX Extraction

Standalone helper in `src/guardrails/docx_extraction.py`. It is **not wired into
attachments, the proxy, configuration or the existing document extractor**.
Existing admission and PDF behavior are unchanged. No dependencies, native tools,
downloads, services or global protection switches are added.

```python
def extract_docx(data: bytes) -> DocumentText: ...

class DocumentBlock(BaseModel):
    kind: Literal["paragraph", "table", "header", "footer"]
    index: int
    text: str

class DocumentText(BaseModel):
    text: str
    blocks: list[DocumentBlock]
    external_hyperlinks: int = 0
    skipped_metadata_parts: int = 0
```

Both models use `frozen=True, extra="forbid"`, bounded fields and typed blocks.
Pydantic freezing prevents attribute assignment, not in-place list mutation;
callers must treat the returned list as read-only. Models are data carriers, not
proof of inspection. Constructing a model directly bypasses extractor validation.

## Supported Subset

- Standard transitional OOXML text-only `.docx` packages, with a content-types
  manifest, root officeDocument relationship and `word/document.xml`.
- Body paragraphs, runs, nested tables/cell paragraphs, text-only content
  controls, headers and footers. Header/footer parts are inspected even if orphaned.
- Hidden and tracked-deleted text is retained for scanning, not rendered away.
  Tabs, breaks, Unicode and blank paragraphs are preserved. Wholly empty or
  whitespace-only documents return `no_text`, not an attack verdict.
- Body blocks appear first, in XML order. Each table-cell paragraph is its own
  `table` block. Then header/footer parts follow lexicographic member order.
  A paragraph in a header/footer table keeps the `header`/`footer` kind. Indices
  are global zero-based extraction indices, not page numbers or physical layout.
  `text` is the block texts joined with a newline, without injected labels.
- Normal external hyperlinks retain **displayed text only**. Targets are discarded,
  counted in `external_hyperlinks`, never fetched, logged, returned or forwarded.
  This count measures relationships, not clicks or visible link occurrences.
  Internal bookmark anchors without relationship targets are text-only too.
- Known styles, settings, numbering, fonts, themes and document properties are
  bounded and XML-parsed, but excluded from output and counted in
  `skipped_metadata_parts`. Formatting, generated numbering, author properties,
  link destinations and layout are not a text inspection claim. No original
  metadata values or archive filenames are returned.

## Review Required

`DocxError.reason` is a fixed safe code; `DocxError.classification` is
`review_required`. A refusal means extraction could not satisfy this text-only
contract, **not that the document is malware**. No partial result is returned.

Embedded images, thumbnails, diagrams, charts, OLE objects and alternate content
are refused as `unsupported_embedded_content`, even when surrounding text is
benign. Macros, ActiveX, fields (including ordinary generated page fields),
embedded fonts, templates and mail merge are refused. External relationships
other than displayed hyperlinks are refused. Unknown parts/elements, footnotes,
endnotes, comments, strict OOXML and unsupported encodings require review rather
than being silently omitted. Legitimate simple text/table documents are accepted;
this is intentionally not a full Word renderer or universal DOCX reader.

Reasons: `input_limit`, `entry_limit`, `uncompressed_limit`,
`compression_ratio_limit`, `xml_depth_limit`, `xml_node_limit`, `text_limit`,
`invalid_document`, `unsafe_archive`, `unsafe_xml`, `encrypted_document`,
`unsupported_embedded_content`, `unsupported_active_content`,
`unsupported_external_relationship`, `unsupported_content`, `no_text`.

ZIP-encrypted entries are rejected. OLE compound containers (used for encrypted
Office files, also legacy `.doc`) receive `encrypted_document`; this is a
conservative container refusal, not proof of encryption. No decryption is attempted.

## Limits

### XML Security Boundary

Every member is decoded as UTF-8 before parsing. NULs, unsupported encoding
declarations, DOCTYPE and ENTITY declarations are rejected before constructing
the XML parser. This preflight is mandatory: the target's additional `doctype`
rejection is not an immediate Expat abort guarantee across implementations.
The bounded TreeBuilder limits tree depth and aggregate node count; archive/input
budgets remain separate protections. Neither these checks nor a scanner waiver
replace maintaining a patched Python/Expat runtime.

The scoped B314/Semgrep annotations document this specific guarded call, not a
general exemption for XML parsing. Tests check both parser-construction rejection
and valid predefined/numeric XML entities. B108 in the native extractor refers
to a new `/tmp` tmpfs inside Bubblewrap's private namespace, not a predictable
host file. Real credentials, arbitrary XML entry points and host temporary files
remain subject to the default security rules.

| Resource | Hard Limit |
|----------|------------|
| Already-decoded input | 2 MiB |
| ZIP entries, including directories | 128 |
| Aggregate uncompressed member bytes | 8 MiB |
| Per-member uncompressed/compressed ratio | 100 |
| XML depth per part, root counted as 1 | 32 |
| XML element nodes across all parts | 10,000 |
| Returned UTF-8 text, including separators | 32 KiB |

Only stored/deflated members are supported. All archive entries are preflighted
before decompression; reads are bounded, CRC-checked by `zipfile`, and sizes
rechecked. No disk extraction occurs. Traversal, ambiguous/noncanonical member
paths, duplicate/case-colliding names, NUL truncation and symlinks/special files
are rejected. Internal relationships resolve only to known members; none perform
filesystem access. XML is UTF-8 only (ASCII and UTF-8 BOM supported). Explicit
DTD/entity and encoding rejection precedes ElementTree; a bounded tree builder
enforces depth/node limits during parsing. This is structural validation of the
supported subset, not complete OOXML schema validation or antivirus scanning.

## Caller Contract

1. Bound HTTP/base64 input before decoding. Apply aggregate request size and
   concurrency limits. The helper is synchronous bounded CPU work; a production
   async integration should use its existing bounded worker admission, not run
   unbounded parallel calls on the event loop.
2. Treat all returned text as untrusted, including attack instructions, secrets,
   markup and control characters. Conversion is **not** an ALLOW verdict and
   does not strip prompt injection. Escape text when displaying it as HTML.
3. Re-scan **every** extracted block and the combined text with the primary input
   guardrail/DLP using overlap-aware windows and cross-block context. A 32-KiB
   result exceeds a 16-KiB guard window; scanning only its prefix is insufficient.
4. Feed only the inspected/redacted text downstream, with trusted block provenance.
   Never forward the original DOCX, link targets, unredacted blocks, or raw bytes
   after an error. No bypass/ALLOW fallback or blanket DOCX exemption is provided.
5. Report extraction failures as processing/review-required outcomes separately
   from actual detections. Log only safe codes/counts, never document content,
   raw parser exceptions, filenames, URLs or traceback locals.

## PDF Blank Handling

Not changed here: safe blank-page acceptance requires the primary PDF extractor
to distinguish verified blank rendering from OCR failure, diagrams and hidden
text. Empty OCR alone cannot establish that distinction. The current extractor
returns `no_text` or `incomplete` and its regression tests retain that behavior.
Implementing a PDF bypass in this DOCX helper would both violate ownership and
weaken existing coverage. A future primary change needs bounded rendering-based
blank verification and synthetic hidden-text/nonblank-unreadable regressions.

## Verification

```bash
pytest tests/test_docx_extraction.py -q
```

Fixtures are synthetic ZIPs generated entirely in memory. Tests cover benign
paragraph/table/header/footer extraction, real guardrail ALLOW/BLOCK decisions,
hyperlink text-only handling, unsupported/active content, package/XML validation,
encryption, CRC errors and resource budgets. No live endpoint or native tool is
needed. These tests demonstrate helper behavior, not production attachment wiring.
