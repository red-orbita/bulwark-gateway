"""Bounded OOXML text conversion, not a security verdict or DOCX forwarding gate."""

from __future__ import annotations

import io
import posixpath
import re
import stat
import xml.etree.ElementTree as ET
import zipfile
import zlib
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_ENTRIES = 128
MAX_UNCOMPRESSED_BYTES = 8 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100
MAX_XML_DEPTH = 32
MAX_XML_NODES = 10_000
MAX_TEXT_BYTES = 32 * 1024

_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
_REL = "{http://schemas.openxmlformats.org/package/2006/relationships}"
_CT = "{http://schemas.openxmlformats.org/package/2006/content-types}"
_OFFICE_REL = _R[1:-1] + "/"
_WORD_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml."
_RELS_TYPE = "application/vnd.openxmlformats-package.relationships+xml"
_AUXILIARY = {
    "word/styles.xml": (_WORD_TYPE + "styles+xml", _W + "styles"),
    "word/settings.xml": (_WORD_TYPE + "settings+xml", _W + "settings"),
    "word/webSettings.xml": (_WORD_TYPE + "webSettings+xml", _W + "webSettings"),
    "word/fontTable.xml": (_WORD_TYPE + "fontTable+xml", _W + "fonts"),
    "word/numbering.xml": (_WORD_TYPE + "numbering+xml", _W + "numbering"),
    "docProps/core.xml": (
        "application/vnd.openxmlformats-package.core-properties+xml",
        "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}coreProperties",
    ),
    "docProps/app.xml": (
        "application/vnd.openxmlformats-officedocument.extended-properties+xml",
        "{http://schemas.openxmlformats.org/officeDocument/2006/extended-properties}Properties",
    ),
    "docProps/custom.xml": (
        "application/vnd.openxmlformats-officedocument.custom-properties+xml",
        "{http://schemas.openxmlformats.org/officeDocument/2006/custom-properties}Properties",
    ),
}
_INTERNAL_RELATIONS = {
    _OFFICE_REL + "officeDocument": "document",
    _OFFICE_REL + "header": "header",
    _OFFICE_REL + "footer": "footer",
    **{_OFFICE_REL + name: name for name in (
        "styles", "settings", "webSettings", "fontTable", "numbering", "theme",
    )},
    _OFFICE_REL + "extended-properties": "app",
    _OFFICE_REL + "custom-properties": "custom",
    "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties": "core",
}

DocxReason = Literal[
    "input_limit", "entry_limit", "uncompressed_limit", "compression_ratio_limit",
    "xml_depth_limit", "xml_node_limit", "text_limit", "invalid_document",
    "unsafe_archive", "unsafe_xml", "encrypted_document", "unsupported_embedded_content",
    "unsupported_active_content", "unsupported_external_relationship", "unsupported_content", "no_text",
]
BlockKind = Literal["paragraph", "table", "header", "footer"]


class DocxError(Exception):
    """Safe reason only. Review required is not a malware accusation."""

    classification: Literal["review_required"] = "review_required"

    def __init__(self, reason: DocxReason) -> None:
        self.reason = reason
        super().__init__(reason)


class DocumentBlock(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: BlockKind
    index: int = Field(ge=0, lt=MAX_XML_NODES)
    text: str = Field(max_length=MAX_TEXT_BYTES)


class DocumentText(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    text: str = Field(max_length=MAX_TEXT_BYTES)
    blocks: list[DocumentBlock] = Field(max_length=MAX_XML_NODES)
    external_hyperlinks: int = Field(default=0, ge=0, le=MAX_XML_NODES)
    skipped_metadata_parts: int = Field(default=0, ge=0, le=MAX_ENTRIES)


class _BoundedTree(ET.TreeBuilder):
    """Reject growth before building deep/large trees; nodes shared across parts."""

    def __init__(self, budget: list[int]) -> None:
        super().__init__()
        self.budget = budget
        self.depth = 0

    def start(self, tag: str, attrs: dict[str, str]) -> ET.Element:
        self.depth += 1
        self.budget[0] += 1
        if self.depth > MAX_XML_DEPTH:
            raise DocxError("xml_depth_limit")
        if self.budget[0] > MAX_XML_NODES:
            raise DocxError("xml_node_limit")
        local = tag.rsplit("}", 1)[-1].lower()
        if local in {"drawing", "pict", "object", "altchunk", "imagedata", "oleobject"}:
            raise DocxError("unsupported_embedded_content")
        if local in {
            "instrtext", "delinstrtext", "fldsimple", "fldchar", "attachedtemplate",
            "mailmerge", "control", "ocx", "embedregular", "embedbold", "embeditalic", "embedbolditalic",
            "script", "subdoc",
        }:
            raise DocxError("unsupported_active_content")
        return super().start(tag, attrs)

    def end(self, tag: str) -> ET.Element:
        element = super().end(tag)
        self.depth -= 1
        return element

    def pi(self, target: str, text: str | None = None) -> ET.Element:
        raise DocxError("unsupported_active_content")


def _parse_xml(raw: bytes, budget: list[int]) -> ET.Element:
    # UTF-8 only: reject NUL/UTF-16/32 before the lexical DTD/entity gate so an
    # alternate encoding cannot hide declarations from the explicit check.
    text = raw.decode("utf-8-sig")
    if "\x00" in text or re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
        raise DocxError("unsafe_xml")
    declaration = re.match(r"\s*<\?xml\b[^?]*\?>", text)
    if declaration:
        encoding = re.search(r"\bencoding\s*=\s*(['\"])(.*?)\1", declaration[0])
        if encoding and encoding[2].lower() not in {"utf-8", "utf8", "us-ascii"}:
            raise DocxError("unsafe_xml")
    return ET.fromstring(text, parser=ET.XMLParser(target=_BoundedTree(budget)))  # noqa: S314 - gated above


def _part_kind(name: str) -> tuple[str, str, str]:
    if name == "[Content_Types].xml":
        return "manifest", "", _CT + "Types"
    if name == "_rels/.rels" or re.fullmatch(r"(?:word|docProps)/_rels/[A-Za-z0-9]+\.xml\.rels", name):
        return "relationships", _RELS_TYPE, _REL + "Relationships"
    if name == "word/document.xml":
        return "document", _WORD_TYPE + "document.main+xml", _W + "document"
    match = re.fullmatch(r"word/(header|footer)[0-9]*\.xml", name)
    if match:
        kind = match[1]
        return kind, _WORD_TYPE + kind + "+xml", _W + ("hdr" if kind == "header" else "ftr")
    if name in _AUXILIARY:
        content_type, root = _AUXILIARY[name]
        return name.rsplit("/", 1)[-1][:-4], content_type, root
    if re.fullmatch(r"word/theme/theme[0-9]+\.xml", name):
        return ("theme", "application/vnd.openxmlformats-officedocument.theme+xml",
                "{http://schemas.openxmlformats.org/drawingml/2006/main}theme")
    lowered = name.lower()
    if "vba" in lowered or "activex" in lowered:
        raise DocxError("unsupported_active_content")
    if any(item in lowered for item in ("/media/", "/embeddings/", "/diagrams/", "/charts/", "thumbnail")):
        raise DocxError("unsupported_embedded_content")
    raise DocxError("unsupported_content")


def extract_docx(data: bytes) -> DocumentText:
    """Extract a conservative text-only subset, or raise content-free DocxError.

    No disk, network, native tools, logging, security verdict or global wiring.
    The caller must re-scan ALL text and forward only inspected/redacted text.
    """
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_INPUT_BYTES:
        raise DocxError("input_limit")
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        # Office encryption uses OLE; legacy .doc uses it too. Never decrypt.
        raise DocxError("encrypted_document")
    try:
        if not data.startswith(b"PK\x03\x04"):
            raise DocxError("invalid_document")
        trees: dict[str, ET.Element] = {}
        kinds: dict[str, tuple[str, str, str]] = {}
        budget = [0]
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ENTRIES:
                raise DocxError("entry_limit")
            names: set[str] = set()
            total = 0
            for entry in entries:
                name = entry.filename
                mode = stat.S_IFMT(entry.external_attr >> 16)
                if (entry.orig_filename != name or not re.fullmatch(r"[A-Za-z0-9_./\[\]-]+", name)
                        or name.startswith("/") or any(p in {"", ".", ".."} for p in name.rstrip("/").split("/"))
                        or name.casefold() in names or mode not in {0, stat.S_IFREG, stat.S_IFDIR}
                        or (mode == stat.S_IFDIR and not entry.is_dir())):
                    raise DocxError("unsafe_archive")
                names.add(name.casefold())
                if entry.flag_bits & (1 | 64):
                    raise DocxError("encrypted_document")
                if entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise DocxError("unsafe_archive")
                total += entry.file_size
                if total > MAX_UNCOMPRESSED_BYTES:
                    raise DocxError("uncompressed_limit")
                if entry.file_size > MAX_COMPRESSION_RATIO * max(1, entry.compress_size):
                    raise DocxError("compression_ratio_limit")
                if entry.is_dir():
                    if entry.file_size:
                        raise DocxError("unsafe_archive")
                    continue
                kinds[name] = _part_kind(name)
            # Preflight the entire central directory before decompressing any part.
            actual_total = 0
            for entry in entries:
                if entry.is_dir():
                    continue
                with archive.open(entry) as member:
                    raw = member.read(min(entry.file_size, MAX_UNCOMPRESSED_BYTES - actual_total) + 1)
                actual_total += len(raw)
                if len(raw) != entry.file_size or actual_total > MAX_UNCOMPRESSED_BYTES:
                    raise DocxError("uncompressed_limit")
                tree = _parse_xml(raw, budget)
                if tree.tag != kinds[entry.filename][2]:
                    raise DocxError("invalid_document")
                trees[entry.filename] = tree

        if not {"[Content_Types].xml", "_rels/.rels", "word/document.xml"} <= trees.keys():
            raise DocxError("invalid_document")
        defaults: dict[str, str] = {}
        overrides: dict[str, str] = {}
        for node in trees["[Content_Types].xml"]:
            content_type = node.get("ContentType", "")
            if "macro" in content_type.lower() or "vba" in content_type.lower():
                raise DocxError("unsupported_active_content")
            if node.tag == _CT + "Default":
                key, mapping = node.get("Extension", ""), defaults
            elif node.tag == _CT + "Override":
                part = node.get("PartName", "")
                if not part.startswith("/") or part[1:] not in trees:
                    raise DocxError("invalid_document")
                key, mapping = part[1:], overrides
            else:
                raise DocxError("invalid_document")
            if not key or not content_type or key in mapping or len(node):
                raise DocxError("invalid_document")
            mapping[key] = content_type
        for name, (_, content_type, _) in kinds.items():
            if content_type and overrides.get(name, defaults.get(name.rsplit(".", 1)[-1])) != content_type:
                raise DocxError("unsupported_content")

        links: dict[str, dict[str, str]] = {}
        external_hyperlinks = 0
        office_documents = 0
        for name, tree in trees.items():
            if kinds[name][0] != "relationships":
                continue
            source = "" if name == "_rels/.rels" else name.replace("/_rels/", "/")[:-5]
            if source and source not in trees:
                raise DocxError("invalid_document")
            links[source] = {}
            for rel in tree:
                rid, target, relation = rel.get("Id", ""), rel.get("Target", ""), rel.get("Type", "")
                target_mode = rel.get("TargetMode", "Internal")
                if (rel.tag != _REL + "Relationship" or not rid or not target
                        or rid in links[source] or len(rel) or target_mode not in {"Internal", "External"}):
                    raise DocxError("invalid_document")
                if relation == _OFFICE_REL + "hyperlink" and target_mode == "External":
                    if kinds.get(source, ("",))[0] not in {"document", "header", "footer"}:
                        raise DocxError("unsupported_external_relationship")
                    external_hyperlinks += 1
                    links[source][rid] = "hyperlink"
                    continue  # Discard target entirely; retain only displayed w:t later.
                if target_mode == "External":
                    raise DocxError("unsupported_external_relationship")
                expected = _INTERNAL_RELATIONS.get(relation)
                if expected is None:
                    if relation in {_OFFICE_REL + item for item in (
                        "image", "oleObject", "package", "chart", "aFChunk",
                    )}:
                        raise DocxError("unsupported_embedded_content")
                    raise DocxError("unsupported_content")
                if not re.fullmatch(r"[A-Za-z0-9_./-]+", target):
                    raise DocxError("unsafe_archive")
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(source), target))
                if resolved.startswith("/") or resolved not in kinds or kinds[resolved][0] != expected:
                    raise DocxError("invalid_document")
                if expected == "document":
                    if source:
                        raise DocxError("invalid_document")
                    office_documents += 1
                links[source][rid] = expected
        if office_documents != 1:
            raise DocxError("invalid_document")

        blocks: list[DocumentBlock] = []
        text_size = 0
        properties = {_W + tag for tag in ("pPr", "rPr", "tblPr", "tblGrid", "trPr", "tcPr", "sectPr", "sdtPr")}
        markers = {_W + tag for tag in ("bookmarkStart", "bookmarkEnd", "proofErr", "lastRenderedPageBreak")}

        def walk(node: ET.Element, kind: BlockKind, paragraph: list[str] | None = None) -> None:
            nonlocal text_size
            if node.tag in properties or node.tag in markers:
                # Attribute-only formatting is discarded, never character data
                # hidden on the property/marker or anywhere in its subtree.
                if any(
                    child.tag in {_W + "t", _W + "delText", _W + "p"}
                    or (child.text or "").strip() or (child.tail or "").strip()
                    for child in node.iter()
                ):
                    raise DocxError("unsupported_content")
                return
            if node.tag not in {_W + "t", _W + "delText"} and (node.text or "").strip():
                raise DocxError("unsupported_content")
            if any((child.tail or "").strip() for child in node):
                raise DocxError("unsupported_content")
            if node.tag == _W + "p":
                if paragraph is not None:
                    raise DocxError("unsupported_content")
                pieces: list[str] = []
                for child in node:
                    walk(child, kind, pieces)
                text = "".join(pieces)
                text_size += len(text.encode("utf-8")) + bool(blocks)
                if text_size > MAX_TEXT_BYTES:
                    raise DocxError("text_limit")
                blocks.append(DocumentBlock(kind=kind, index=len(blocks), text=text))
                return
            if node.tag in {_W + "t", _W + "delText", _W + "tab", _W + "br", _W + "cr"}:
                if paragraph is None or len(node):
                    raise DocxError("unsupported_content")
                value = {_W + "tab": "\t", _W + "br": "\n", _W + "cr": "\n"}.get(node.tag, node.text or "")
                paragraph.append(value)
                return
            if node.tag not in {_W + tag for tag in (
                "document", "body", "hdr", "ftr", "tbl", "tr", "tc", "r", "hyperlink",
                "sdt", "sdtContent", "ins", "del", "moveFrom", "moveTo",
            )}:
                raise DocxError("unsupported_content")
            if node.tag == _W + "tbl" and kind == "paragraph":
                kind = "table"
            for child in node:
                walk(child, kind, paragraph)

        for name in ["word/document.xml", *sorted(n for n in trees if kinds[n][0] in {"header", "footer"})]:
            tree = trees[name]
            for node in tree.iter():
                for attr, value in node.attrib.items():
                    if attr.startswith(_R):
                        expected = {
                            _W + "hyperlink": "hyperlink", _W + "headerReference": "header",
                            _W + "footerReference": "footer",
                        }.get(node.tag)
                        if attr != _R + "id" or expected is None or links.get(name, {}).get(value) != expected:
                            raise DocxError("unsupported_content")
            if kinds[name][0] == "document":
                if len(tree) != 1 or tree[0].tag != _W + "body":
                    raise DocxError("invalid_document")
                walk(tree, "paragraph")
            else:
                walk(tree, "header" if kinds[name][0] == "header" else "footer")
        text = "\n".join(block.text for block in blocks)
        if not text.strip():
            raise DocxError("no_text")
        return DocumentText(
            text=text, blocks=blocks, external_hyperlinks=external_hyperlinks,
            skipped_metadata_parts=sum(k[0] not in {"manifest", "relationships", "document", "header", "footer"}
                                       for k in kinds.values()),
        )
    except DocxError:
        raise
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, NotImplementedError, ET.ParseError, zlib.error):
        raise DocxError("invalid_document") from None
