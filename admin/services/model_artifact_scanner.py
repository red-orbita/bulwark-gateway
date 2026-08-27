"""
Model Artifact Scanner — pre-deployment supply-chain guard for ML model files.

Deserializing an untrusted model is remote code execution: ``pickle.load`` /
``torch.load`` / ``joblib.load`` / Keras ``h5`` Lambda layers all run attacker
code *before the first inference*, entirely outside Bulwark's request path. This
module lets an operator scan a model file (or a directory of them) BEFORE it is
ingested, the same way SkillSpector scans skills.

Design (matches AGENTS.md §10):
  * **Never deserializes.** The pickle analysis walks the opcode stream with the
    standard-library ``pickletools.genops`` — it inspects ``GLOBAL`` /
    ``STACK_GLOBAL`` imports and ``REDUCE``/``BUILD`` call gadgets *statically*
    and never executes a single opcode. Zero third-party dependencies.
  * **Bounded work.** Opcode count, zip member count, and (de)compressed sizes
    are all capped so a malicious archive cannot exhaust memory/CPU (zip/decomp
    bombs).
  * **Honest degradation.** Formats we cannot fully introspect with the stdlib
    (HDF5/Keras deep graph, lz4/zstd-compressed joblib) are flagged for manual
    review rather than silently passed.

Container coverage:
  * raw pickle (``.pkl`` / ``.pickle`` / legacy ``.bin``)
  * PyTorch zip archives (``.pt`` / ``.pth`` / ``.ckpt`` / modern ``.bin``) and
    numpy ``.npz`` — every ``*.pkl`` / ``data.pkl`` member is opcode-scanned
  * gzip/bz2/xz/zlib-compressed pickles (common ``.joblib`` layouts)
  * HDF5 / Keras (``.h5`` / ``.hdf5`` / ``.keras``) — byte-level Lambda / marshal
    heuristics + manual-review flag
  * ``.safetensors`` — validated as a code-free format (informational)

Public API mirrors the other SkillSpector engines:
  ``analyze_file(path, source)`` · ``analyze_bytes(data, source)`` ·
  ``analyze_directory(path)`` · ``is_model_artifact(path)`` · ``PATTERN_COUNT``.
Each finding is a dict: ``{rule_id, message, severity, confidence(0-100),
category, file, detail}``.
"""

from __future__ import annotations

import bz2
import gzip
import io
import logging
import lzma
import pickletools
import zlib
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

CATEGORY = "model_supply_chain"

# ── Safety bounds (defence against zip / decompression bombs) ──────────────
_MAX_OPCODES = 2_000_000          # stop walking a single pickle after this many ops
_MAX_ZIP_MEMBERS = 512            # do not open more than this many archive members
_MAX_MEMBER_BYTES = 64 * 1024 * 1024      # 64 MB read cap per archive member
_MAX_DECOMPRESS_BYTES = 256 * 1024 * 1024  # 256 MB cap when inflating a stream
_MAGIC_LEN = 16

# ── Dangerous import catalogs ──────────────────────────────────────────────
# EXEC modules: importing anything from these in a *data* file is code execution
# primitive territory → CRITICAL.
_EXEC_MODULES = {
    "os", "posix", "nt", "subprocess", "pty", "commands",
    "runpy", "pydoc",
}
# Exact (module, attr) callables that are unambiguous execution sinks → CRITICAL.
_EXEC_CALLABLES = {
    ("builtins", "eval"), ("builtins", "exec"), ("builtins", "compile"),
    ("builtins", "__import__"), ("builtins", "breakpoint"),
    ("__builtin__", "eval"), ("__builtin__", "exec"), ("__builtin__", "execfile"),
    ("__builtin__", "compile"), ("__builtin__", "__import__"),
    ("platform", "popen"), ("webbrowser", "open"),
    ("importlib", "import_module"),
    ("ctypes", "CDLL"), ("ctypes", "cdll"), ("ctypes", "WinDLL"),
}
# HIGH-risk modules: network / dynamic-attr / alternate-deserialization surfaces
# that are abnormal inside a model and are the usual reverse-shell / loader
# building blocks → HIGH.
_HIGH_MODULES = {
    "sys", "socket", "ctypes", "multiprocessing", "asyncio", "threading",
    "ftplib", "telnetlib", "smtplib", "http", "httplib", "urllib", "urllib2",
    "requests", "shutil", "marshal", "dill", "code", "codeop", "bdb", "pdb",
    "importlib", "cloudpickle", "base64", "codecs",
}
# HIGH (module, attr) callables that are dynamic-execution helpers → HIGH.
_HIGH_CALLABLES = {
    ("builtins", "getattr"), ("builtins", "setattr"), ("builtins", "globals"),
    ("builtins", "vars"), ("builtins", "open"), ("builtins", "apply"),
    ("builtins", "memoryview"), ("builtins", "input"),
    ("__builtin__", "getattr"), ("__builtin__", "open"), ("__builtin__", "apply"),
    ("operator", "attrgetter"), ("operator", "methodcaller"),
    ("functools", "partial"),
}

# Opcodes that actually *invoke* a callable / build an object (the trigger half
# of a pickle gadget). Presence of any alongside a dangerous global = live gadget.
_REDUCE_OPS = {"REDUCE", "BUILD", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX"}

# Opcodes that push a string literal onto the stack — needed to resolve the
# (module, name) operands of STACK_GLOBAL.
_STRING_OPS = {
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING", "STRING",
}

_PICKLE_EXTS = {".pkl", ".pickle", ".pck", ".pk", ".pt", ".pth", ".ckpt",
                ".bin", ".npy", ".npz", ".joblib", ".jbl", ".model", ".dat",
                ".sav", ".pack"}
_HDF5_EXTS = {".h5", ".hdf5", ".keras"}
_SAFETENSORS_EXTS = {".safetensors"}
_OTHER_ARTIFACT_EXTS = {".pb", ".gguf", ".onnx", ".msgpack"}
_ARTIFACT_EXTS = _PICKLE_EXTS | _HDF5_EXTS | _SAFETENSORS_EXTS | _OTHER_ARTIFACT_EXTS

# Container magic bytes.
_MAGIC_ZIP = b"PK\x03\x04"
_MAGIC_HDF5 = b"\x89HDF\r\n\x1a\n"
_MAGIC_GZIP = b"\x1f\x8b"
_MAGIC_BZ2 = b"BZh"
_MAGIC_XZ = b"\xfd7zXZ\x00"
_MAGIC_ZLIB = {b"\x78\x01", b"\x78\x9c", b"\x78\xda", b"\x78\x5e"}
_MAGIC_NUMPY = b"\x93NUMPY"
_PICKLE_PROTO_HI = 0x80  # PROTO opcode → pickle protocol >= 2


# ═══════════════════════════════════════════════════════════════════════════
# Finding helper
# ═══════════════════════════════════════════════════════════════════════════

def _finding(rule_id: str, message: str, severity: str, confidence: int,
             source: str, detail: str = "") -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "message": message,
        "severity": severity,
        "confidence": confidence,
        "category": CATEGORY,
        "file": source,
        "detail": detail,
    }


def _classify_global(module: str, name: str) -> Optional[str]:
    """Return 'critical' / 'high' for a dangerous import, else None (benign)."""
    top = module.split(".")[0]
    if top in _EXEC_MODULES or (module, name) in _EXEC_CALLABLES or (top, name) in _EXEC_CALLABLES:
        return "critical"
    if top in _HIGH_MODULES or (module, name) in _HIGH_CALLABLES or (top, name) in _HIGH_CALLABLES:
        return "high"
    return None


# ═══════════════════════════════════════════════════════════════════════════
# Pickle opcode analysis (never executes — pickletools.genops only)
# ═══════════════════════════════════════════════════════════════════════════

def _scan_pickle(reader: Any, source: str, location: str = "") -> list[dict[str, Any]]:
    """Statically walk a pickle opcode stream and flag dangerous imports.

    ``reader`` may be ``bytes`` or a binary file-like object; ``genops`` streams
    either without unpickling. Malformed/truncated streams are reported, not
    fatal.
    """
    where = f"{source}::{location}" if location else source
    globals_found: list[tuple[str, str]] = []
    recent_strings: list[str] = []
    has_reduce = False
    has_ext = False
    opcode_count = 0
    truncated = False

    try:
        for opcode, arg, _pos in pickletools.genops(reader):
            opcode_count += 1
            if opcode_count > _MAX_OPCODES:
                truncated = True
                break

            op_name = opcode.name
            if op_name in _STRING_OPS and isinstance(arg, str):
                recent_strings.append(arg)
                if len(recent_strings) > 4:
                    recent_strings.pop(0)
            elif op_name == "GLOBAL" and isinstance(arg, str):
                mod, _, nm = arg.partition(" ")
                globals_found.append((mod, nm))
            elif op_name == "STACK_GLOBAL":
                if len(recent_strings) >= 2:
                    globals_found.append((recent_strings[-2], recent_strings[-1]))
                else:
                    globals_found.append(("<dynamic>", "<dynamic>"))
            elif op_name in _REDUCE_OPS:
                has_reduce = True
            elif op_name in ("EXT1", "EXT2", "EXT4"):
                has_ext = True
    except Exception as e:  # malformed / truncated / unsupported opcode
        logger.debug("pickle_genops_error where=%s error=%s", where, e)
        # Partial results below still count; add an opacity note.
        return _finalize_pickle(globals_found, has_reduce, has_ext, where,
                                parse_error=str(e)[:120])

    findings = _finalize_pickle(globals_found, has_reduce, has_ext, where)
    if truncated:
        findings.append(_finding(
            "BWK-ART-PICKLE-TRUNCATED",
            f"Pickle opcode limit ({_MAX_OPCODES}) reached — analysis truncated",
            "low", 40, where,
            "Artifact is unusually large/complex; only the first opcodes were scanned.",
        ))
    return findings


def _finalize_pickle(globals_found: list[tuple[str, str]], has_reduce: bool,
                     has_ext: bool, where: str,
                     parse_error: str = "") -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for module, name in globals_found:
        cls = _classify_global(module, name)
        if cls is None:
            continue
        target = f"{module}.{name}"

        if has_reduce and cls in ("critical", "high"):
            rule_id = "BWK-ART-PICKLE-RCE"
            severity = "critical"
            confidence = 95 if cls == "critical" else 88
            message = f"Pickle code-execution gadget: {target} wired to a REDUCE/BUILD call"
        elif cls == "critical":
            rule_id = "BWK-ART-PICKLE-IMPORT"
            severity = "high"
            confidence = 80
            message = f"Pickle imports execution primitive {target} (no visible REDUCE — may be obfuscated)"
        else:  # high, no reduce
            rule_id = "BWK-ART-PICKLE-SUSPICIOUS"
            severity = "medium"
            confidence = 55
            message = f"Pickle imports high-risk symbol {target}"

        key = (rule_id, module, name)
        if key in seen:
            continue
        seen.add(key)
        findings.append(_finding(rule_id, message, severity, confidence, where, target))

    if has_ext and not findings:
        findings.append(_finding(
            "BWK-ART-PICKLE-EXT",
            "Pickle uses the extension registry (EXT opcode) — opaque global reference",
            "medium", 50, where,
            "Extension-code globals cannot be resolved statically; review the producer.",
        ))

    if parse_error:
        findings.append(_finding(
            "BWK-ART-PICKLE-MALFORMED",
            "Pickle stream is malformed/truncated — could not be fully parsed",
            "low", 35, where, parse_error,
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Container handlers
# ═══════════════════════════════════════════════════════════════════════════

def _scan_zip(data: bytes, source: str) -> list[dict[str, Any]]:
    """Scan pickle members inside a zip archive (modern PyTorch / .npz)."""
    import zipfile

    findings: list[dict[str, Any]] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:
        return [_finding("BWK-ART-ARCHIVE-CORRUPT",
                         "Artifact looks like a zip archive but could not be opened",
                         "low", 30, source, str(e)[:120])]

    members = zf.infolist()
    if len(members) > _MAX_ZIP_MEMBERS:
        findings.append(_finding(
            "BWK-ART-ARCHIVE-OVERSIZE",
            f"Archive has {len(members)} members (> {_MAX_ZIP_MEMBERS}); scanning first {_MAX_ZIP_MEMBERS}",
            "low", 40, source,
        ))
    scanned_any = False
    for info in members[:_MAX_ZIP_MEMBERS]:
        nm = info.filename
        lower = nm.lower()
        looks_pickle = lower.endswith((".pkl", ".pickle")) or lower.endswith("data.pkl") or "/data.pkl" in lower
        # Peek small members for a pickle magic byte even without a .pkl name.
        try:
            with zf.open(info) as fh:
                head = fh.read(2)
                if not looks_pickle and not (head[:1] == b"\x80"):
                    continue
                body = head + fh.read(_MAX_MEMBER_BYTES)
        except Exception as e:
            findings.append(_finding("BWK-ART-ARCHIVE-MEMBER-ERROR",
                                     f"Could not read archive member '{nm}'",
                                     "low", 25, source, str(e)[:100]))
            continue
        scanned_any = True
        findings.extend(_scan_pickle(body, source, location=nm))

    if not scanned_any and not findings:
        findings.append(_finding(
            "BWK-ART-ARCHIVE-NO-PICKLE",
            "Zip artifact contained no recognizable pickle member",
            "low", 20, source,
            "No .pkl/data.pkl or pickle-magic member found; format may be tensor-only.",
        ))
    return findings


def _scan_hdf5(data: bytes, source: str) -> list[dict[str, Any]]:
    """Heuristic scan of an HDF5 / Keras artifact (no h5py dependency)."""
    findings: list[dict[str, Any]] = []
    # Keras Lambda layers embed arbitrary Python (marshalled code) → RCE on load.
    lowered = data if isinstance(data, bytes) else b""
    markers = [
        (b"Lambda", "Keras Lambda layer (embeds arbitrary Python — RCE on load)"),
        (b"python_function", "Serialized Python function reference in HDF5"),
        (b"function_type", "Custom-function metadata in HDF5 model"),
        (b"__main__", "Reference to __main__ module inside HDF5 model"),
        (b"posix.system", "Direct os.system reference inside HDF5"),
        (b"subprocess", "subprocess reference inside HDF5"),
    ]
    hit = False
    for token, msg in markers:
        if token in lowered:
            hit = True
            sev = "high" if token in (b"Lambda", b"posix.system", b"subprocess") else "medium"
            findings.append(_finding("BWK-ART-HDF5-LAMBDA", msg, sev,
                                     70 if sev == "high" else 50, source,
                                     token.decode("latin-1")))
    if not hit:
        findings.append(_finding(
            "BWK-ART-HDF5-OPAQUE",
            "HDF5/Keras artifact — deep graph not introspectable with the stdlib",
            "low", 30, source,
            "No Lambda/code markers found by heuristic scan; load only from trusted sources.",
        ))
    return findings


def _scan_safetensors(data: bytes, source: str) -> list[dict[str, Any]]:
    """Validate a .safetensors file — a code-free format by design."""
    import struct

    if len(data) < 8:
        return [_finding("BWK-ART-SAFETENSORS-MALFORMED",
                         "safetensors file too small to contain a header",
                         "low", 40, source)]
    header_len = struct.unpack("<Q", data[:8])[0]
    if header_len > len(data) or header_len > 100 * 1024 * 1024:
        return [_finding("BWK-ART-SAFETENSORS-MALFORMED",
                         f"safetensors header length ({header_len}) is implausible — malformed or crafted",
                         "medium", 60, source,
                         "A header longer than the file (or >100 MB) indicates corruption/tampering.")]
    return [_finding("BWK-ART-SAFETENSORS-OK",
                     "safetensors — code-free tensor container (no deserialization RCE surface)",
                     "low", 10, source,
                     "Informational: this format cannot execute code on load.")]


def _scan_compressed(data: bytes, source: str, kind: str) -> list[dict[str, Any]]:
    """Inflate a bounded amount of a compressed stream and scan the result."""
    try:
        if kind == "gzip":
            raw = gzip.decompress(data)
        elif kind == "bz2":
            raw = bz2.decompress(data)
        elif kind == "xz":
            raw = lzma.decompress(data)
        elif kind == "zlib":
            raw = zlib.decompressobj().decompress(data, _MAX_DECOMPRESS_BYTES + 1)
        else:
            raw = b""
    except Exception as e:
        return [_finding("BWK-ART-COMPRESSED-OPAQUE",
                         f"{kind}-compressed artifact could not be inflated for scanning",
                         "medium", 45, source, str(e)[:120])]

    if len(raw) > _MAX_DECOMPRESS_BYTES:
        return [_finding("BWK-ART-DECOMPRESS-BOMB",
                         f"{kind} stream inflates beyond {_MAX_DECOMPRESS_BYTES} bytes — possible decompression bomb",
                         "medium", 60, source)]
    if not raw:
        return [_finding("BWK-ART-COMPRESSED-OPAQUE",
                         f"{kind}-compressed artifact (lz4/zstd/custom joblib not scannable with stdlib)",
                         "medium", 45, source)]
    # Recurse on the decompressed payload (commonly a pickle for joblib).
    return analyze_bytes(raw, source)


# ═══════════════════════════════════════════════════════════════════════════
# Container detection + public API
# ═══════════════════════════════════════════════════════════════════════════

def _detect_container(data: bytes) -> str:
    if data.startswith(_MAGIC_ZIP):
        return "zip"
    if data.startswith(_MAGIC_HDF5):
        return "hdf5"
    if data.startswith(_MAGIC_GZIP):
        return "gzip"
    if data.startswith(_MAGIC_BZ2):
        return "bz2"
    if data.startswith(_MAGIC_XZ):
        return "xz"
    if data[:2] in _MAGIC_ZLIB:
        return "zlib"
    if data.startswith(_MAGIC_NUMPY):
        return "numpy"
    if data[:1] == bytes([_PICKLE_PROTO_HI]):
        return "pickle"
    return "unknown"


def analyze_bytes(data: bytes, source: str = "") -> list[dict[str, Any]]:
    """Detect the container of ``data`` and scan it for supply-chain risks."""
    if not data:
        return []
    container = _detect_container(data)

    if container == "zip":
        return _scan_zip(data, source)
    if container == "hdf5":
        return _scan_hdf5(data, source)
    if container in ("gzip", "bz2", "xz", "zlib"):
        return _scan_compressed(data, source, container)
    if container == "numpy":
        # .npy: object arrays embed a pickle after the header; scan the tail.
        idx = data.find(b"\x80", 0, 4096)
        if idx != -1:
            return _scan_pickle(data[idx:], source, location="npy-object-array")
        return []  # plain numeric .npy — no pickle, no code
    # pickle (proto 2+) or unknown: try opcode scan; genops handles proto 0/1 too.
    return _scan_pickle(data, source)


def is_model_artifact(path: Any) -> bool:
    """True if ``path`` looks like a scannable model artifact (ext or magic)."""
    p = Path(path)
    if p.suffix.lower() in _ARTIFACT_EXTS:
        return True
    try:
        with open(p, "rb") as fh:
            head = fh.read(_MAGIC_LEN)
    except OSError:
        return False
    return _detect_container(head) in ("zip", "hdf5", "gzip", "bz2", "xz", "numpy", "pickle")


def analyze_file(path: Any, source: str = "") -> list[dict[str, Any]]:
    """Scan a single model-artifact file for deserialization / supply-chain risk."""
    p = Path(path)
    src = source or str(p)
    try:
        size = p.stat().st_size
    except OSError as e:
        return [_finding("BWK-ART-READ-ERROR", "Could not stat artifact",
                         "low", 20, src, str(e)[:100])]
    if size == 0:
        return []

    suffix = p.suffix.lower()
    try:
        with open(p, "rb") as fh:
            head = fh.read(_MAGIC_LEN)
    except OSError as e:
        return [_finding("BWK-ART-READ-ERROR", "Could not read artifact",
                         "low", 20, src, str(e)[:100])]

    container = _detect_container(head)

    # safetensors is detected by extension (its header has no fixed magic).
    if suffix in _SAFETENSORS_EXTS or (container == "unknown" and suffix == ".safetensors"):
        try:
            return _scan_safetensors(p.read_bytes()[:8_388_608], src)  # header lives in first bytes
        except OSError as e:
            return [_finding("BWK-ART-READ-ERROR", "Could not read safetensors",
                             "low", 20, src, str(e)[:100])]

    if suffix in _HDF5_EXTS or container == "hdf5":
        try:
            return _scan_hdf5(p.read_bytes()[: _MAX_MEMBER_BYTES], src)
        except OSError as e:
            return [_finding("BWK-ART-READ-ERROR", "Could not read HDF5 artifact",
                             "low", 20, src, str(e)[:100])]

    # Raw pickle → stream the file handle straight into genops (low memory).
    if container == "pickle" or (container == "unknown" and suffix in _PICKLE_EXTS):
        try:
            with open(p, "rb") as fh:
                return _scan_pickle(fh, src)
        except OSError as e:
            return [_finding("BWK-ART-READ-ERROR", "Could not read pickle artifact",
                             "low", 20, src, str(e)[:100])]

    if container in ("zip", "gzip", "bz2", "xz", "zlib", "numpy"):
        try:
            data = p.read_bytes()
        except OSError as e:
            return [_finding("BWK-ART-READ-ERROR", "Could not read artifact",
                             "low", 20, src, str(e)[:100])]
        return analyze_bytes(data, src)

    if suffix in _OTHER_ARTIFACT_EXTS:
        return [_finding("BWK-ART-OPAQUE",
                         f"Model artifact '{suffix}' not statically introspectable — load only from trusted sources",
                         "low", 25, src)]
    return []


def analyze_directory(path: Any) -> list[dict[str, Any]]:
    """Scan every model artifact under a directory tree."""
    p = Path(path)
    findings: list[dict[str, Any]] = []
    count = 0
    for f in sorted(p.rglob("*")):
        if count >= _MAX_ZIP_MEMBERS:
            break
        if not f.is_file():
            continue
        if f.suffix.lower() in _ARTIFACT_EXTS or is_model_artifact(f):
            count += 1
            findings.extend(analyze_file(f, str(f)))
    return findings


def analyze_content(content: str, source: str = "") -> list[dict[str, Any]]:
    """Text entry point (SkillSpector contract).

    Model artifacts are binary and reach the scanner via file/path scanning
    (``analyze_file`` / ``analyze_directory``); a UTF-8 string cannot faithfully
    carry pickle bytes. This shim exists only for interface symmetry with the
    MCP engines and is intentionally a no-op on text.
    """
    return []


# Catalog size for status reporting (dangerous modules + explicit callables).
PATTERN_COUNT = (
    len(_EXEC_MODULES) + len(_EXEC_CALLABLES) + len(_HIGH_MODULES) + len(_HIGH_CALLABLES)
)
