"""
Artifact Output Scanner — flags serialized-artifact RCE gadgets in LLM output.

THREAT (OWASP LLM02, insecure output handling): an LLM or one of its tools can
emit a *serialized model artifact* inline in a response — most plausibly a
base64 blob or a ``data:`` URI carrying a Python pickle / PyTorch / joblib
payload. If a downstream automated consumer decodes and **deserializes** that
blob (``pickle.load`` / ``torch.load`` / ``joblib.load``), attacker code runs at
load time, entirely outside the model's inference path. The proxy's text-level
``output_filter`` only greps *decoded base64 for ASCII secret strings*; it never
performs opcode analysis, so a base64-encoded pickle-RCE payload passes cleanly.

SHIPPED STATE (honesty): this is a **DETECTIVE** control, not a preventive one.
It is OUTPUT_ASYNC (fire-and-forget, off the response hot path): it NEVER
modifies or blocks the response — it emits a WARN ``SecurityEvent``
(``ThreatCategory.INSECURE_OUTPUT``) to the SIEM / alert channels. The rationale
is deliberate: the threat is real but niche, and base64 blobs in responses are
frequently benign (images, embeddings, attachments), so blocking every response
that carries base64 would false-positive. Registered only when
``BULWARK_ARTIFACT_OUTPUT_SCANNING_ENABLED=true``; otherwise SDK-accessible only.

It reuses the shared, stdlib-only opcode engine
(``src/scanners/artifacts/model_artifact_scanner.py``) that **never
deserializes** — it walks the pickle opcode stream with ``pickletools.genops``.
Only genuinely dangerous findings (a live RCE gadget or an imported execution
primitive — severity ``high``/``critical``) are surfaced; low/medium structural
noise (malformed/truncated/opaque, expected when non-pickle base64 such as an
image is decoded) is dropped so the WARN stays high-signal. No LLM call.
"""

from __future__ import annotations

import base64
import binascii
import logging
import re

from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.artifacts import model_artifact_scanner as mas
from src.scanners.protocol import (
    MaturityTier,
    OutputScanner,
    ScanContext,
    ScannerInfo,
    ScannerType,
)

logger = logging.getLogger(__name__)

# ── Extraction / cost bounds ────────────────────────────────────────────────
# A base64 run must be at least this long to be worth decoding (40 chars → ~30
# decoded bytes). Below this it cannot carry a meaningful serialized artifact.
_MIN_B64_CHARS = 40
# Do not decode more than this many base64 chars from a single candidate
# (~6 MB decoded) — bounds memory against a giant blob.
_MAX_B64_CHARS = 8_000_000
# Do not analyse more than this many candidate blobs per response.
_MAX_CANDIDATES = 16
# Only the leading bytes are needed to decide whether a blob is a scannable
# artifact (pickle proto opcode / container magic).
_MAGIC_PROBE = 16

# ``data:[<mediatype>][;base64],<payload>`` — capture the base64 payload.
_DATA_URI_RE = re.compile(
    r"data:[^,\s]*?;base64,([A-Za-z0-9+/=\s]{%d,})" % _MIN_B64_CHARS,
    re.IGNORECASE,
)
# Standalone base64 runs (no data-URI wrapper). Whitespace is stripped later.
_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % _MIN_B64_CHARS)

# Container magic bytes that mark a decoded blob as a scannable artifact.
_ARTIFACT_MAGICS: tuple[bytes, ...] = (
    b"PK\x03\x04",              # zip (PyTorch / numpy .npz)
    b"\x89HDF\r\n\x1a\n",       # HDF5 / Keras
    b"\x1f\x8b",                # gzip
    b"BZh",                     # bz2
    b"\xfd7zXZ\x00",            # xz
    b"\x93NUMPY",               # numpy .npy
)
_ZLIB_MAGICS: frozenset[bytes] = frozenset(
    {b"\x78\x01", b"\x78\x9c", b"\x78\xda", b"\x78\x5e"}
)
_PICKLE_PROTO_HI = 0x80  # PROTO opcode → pickle protocol >= 2

# Findings below this severity are structural noise for opportunistic base64
# decoding (e.g. a decoded image is a "malformed pickle"). Only surface real
# execution risk.
_SURFACED_SEVERITIES = frozenset({"high", "critical"})


def _looks_scannable(head: bytes) -> bool:
    """Cheap pre-filter: does this blob look like a serialized artifact?

    Avoids running the opcode walker over every base64 image/embedding. Covers
    pickle protocol >= 2 (the default for ``pickle.dumps`` / ``torch.save``) and
    the binary containers the engine understands. Proto 0/1 ASCII pickles are
    intentionally not matched here — they are vanishingly rare as base64 output
    exfil and would widen the false-positive surface.
    """
    if len(head) < 2:
        return False
    if head[0] == _PICKLE_PROTO_HI:
        return True
    if head[:2] in _ZLIB_MAGICS:
        return True
    return any(head.startswith(magic) for magic in _ARTIFACT_MAGICS)


class ArtifactOutputScanner(OutputScanner):
    """Detects serialized-artifact RCE gadgets embedded in LLM output.

    Decodes inline base64 blobs / ``data:`` URIs from the response text and runs
    the shared stdlib pickle-opcode engine (never deserializes) over the bytes,
    emitting a WARN event when a load-time RCE gadget is present. Detective only:
    it never blocks or rewrites the response.
    """

    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="artifact_output_scanner",
            version="1.0.0",
            scanner_type=ScannerType.OUTPUT_ASYNC,
            description="Detects serialized-artifact (pickle) RCE gadgets in LLM output",
            maturity=MaturityTier.BETA,
            author="bulwark",
            priority=40,
        )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        if not content:
            return GuardrailResult(verdict=Verdict.ALLOW)

        findings = self._scan_candidates(content)
        if not findings:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Rank by severity so the emitted event leads with the worst finding.
        worst = max(findings, key=lambda f: f.get("confidence", 0))
        rules = sorted({f["rule_id"] for f in findings})
        top_severity = "critical" if any(
            f["severity"] == "critical" for f in findings
        ) else "high"

        return GuardrailResult(
            verdict=Verdict.WARN,
            events=[
                SecurityEvent(
                    tenant_id=context.tenant_id,
                    agent_id=context.agent_id,
                    verdict=Verdict.WARN,
                    category=ThreatCategory.INSECURE_OUTPUT,
                    description=(
                        "Serialized-artifact RCE gadget in LLM output: "
                        f"{worst['message']} "
                        "(a downstream consumer deserializing this blob would "
                        "execute code). Detected in an embedded base64 artifact."
                    ),
                    source="artifact_output_scanner",
                    severity="high",
                    matched_pattern=worst["rule_id"],
                    metadata={
                        "rules": rules,
                        "artifact_severity": top_severity,
                        "finding_count": len(findings),
                        "detail": str(worst.get("detail", ""))[:200],
                    },
                )
            ],
        )

    def _scan_candidates(self, content: str) -> list[dict]:
        """Extract, decode and opcode-scan base64 artifact candidates."""
        findings: list[dict] = []
        seen: set[bytes] = set()
        analysed = 0

        for raw in self._iter_b64_candidates(content):
            if analysed >= _MAX_CANDIDATES:
                break
            data = self._safe_b64decode(raw)
            if data is None or len(data) < 8:
                continue
            # De-duplicate identical blobs (data-URI + raw-run overlap).
            fingerprint = data[:64]
            if fingerprint in seen:
                continue
            seen.add(fingerprint)

            if not _looks_scannable(data[:_MAGIC_PROBE]):
                continue

            analysed += 1
            try:
                raw_findings = mas.analyze_bytes(data, source="llm-output")
            except Exception as e:  # engine is defensive; never let it crash the tap
                logger.debug("artifact_output_scan_error error=%s", str(e)[:120])
                continue

            for f in raw_findings:
                if f.get("severity") in _SURFACED_SEVERITIES:
                    findings.append(f)

        return findings

    def _iter_b64_candidates(self, content: str):
        """Yield candidate base64 strings (data-URI payloads first, then runs)."""
        for m in _DATA_URI_RE.finditer(content):
            yield m.group(1)
        for m in _B64_RUN_RE.finditer(content):
            yield m.group(0)

    @staticmethod
    def _safe_b64decode(raw: str) -> bytes | None:
        """Strip whitespace, bound size, and strictly base64-decode."""
        cleaned = "".join(raw.split())
        if len(cleaned) < _MIN_B64_CHARS or len(cleaned) > _MAX_B64_CHARS:
            return None
        # Correct padding to a multiple of 4 without trusting the producer.
        pad = len(cleaned) % 4
        if pad:
            cleaned += "=" * (4 - pad)
        try:
            return base64.b64decode(cleaned, validate=True)
        except (binascii.Error, ValueError):
            return None

    async def health(self) -> bool:
        # Pure stdlib engine, no external model/deps — always functional when
        # registered. Honest: reports healthy because it genuinely works.
        return True
