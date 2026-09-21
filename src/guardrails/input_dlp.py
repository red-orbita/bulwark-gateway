"""Bounded pre-upstream DLP using the existing secret/PII detector, without I/O."""

import json
import unicodedata
from time import monotonic
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

from src.guardrails.output_filter import OutputFilter
from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict

_SENSITIVE = frozenset({ThreatCategory.CREDENTIAL_ACCESS, ThreatCategory.PII_LEAK})
_WINDOW_BYTES = 16384
_OVERLAP_CHARS = 256
_MAX_WINDOWS = 128
_MAX_INSPECTION_SECONDS = 1.0


class InputDlpPolicy(BaseModel):
    """Operator-owned additive policy; a tenant cannot weaken global protection."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    enabled: StrictBool = False
    max_bytes: Annotated[int, Field(strict=True, ge=1, le=262144)] = 65536
    redact_email: StrictBool = False
    redact_phone: StrictBool = False
    blocked_terms: tuple[Annotated[str, Field(strict=True, min_length=3, max_length=128)], ...] = Field(
        default=(), max_length=32,
    )

    @field_validator("blocked_terms")
    @classmethod
    def normalize_terms(cls, terms: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple("".join(
            ch for ch in unicodedata.normalize("NFKC", term).casefold() if unicodedata.category(ch) != "Cf"
        ).strip() for term in terms)
        if any(len(term) < 3 or len(term) > 128 for term in normalized):
            raise ValueError("Classification terms must contain 3-128 meaningful characters")
        return tuple(dict.fromkeys(normalized))


def inspect_request(
    body: dict, tenant_id: str, agent_id: str, request_id: str,
    *, max_bytes: int = 65536, redact_email: bool = False, redact_phone: bool = False,
    blocked_terms: tuple[str, ...] = (),
) -> GuardrailResult:
    """Block known sensitive strings in all request fields before upstream egress.

    This is not a business-data classifier or OCR. Keys are scanned as well as
    values, with scalar key=value context charged separately. UTF-8 windows
    overlap without recharging raw bytes. Work budgets fail closed; no partial
    scan is reported as clean.
    """
    pending: list[tuple[object, bool]] = [(body, False)]
    nodes = size = contextual_size = windows = 0
    json_context_size = 0
    reason = "sensitive_input"
    try:
        deadline = monotonic() + _MAX_INSPECTION_SECONDS
        detector = OutputFilter(detect_injection=False, redact_email=redact_email, redact_phone=redact_phone)
        if not 0 < max_bytes <= 262144:
            raise ValueError("Invalid inspection budget")
        terms = InputDlpPolicy(blocked_terms=blocked_terms).blocked_terms
        while pending:
            if monotonic() >= deadline:
                raise ValueError("Inspection time limit")
            value, contextual = pending.pop()
            nodes += 1
            if nodes > 4096:
                raise ValueError("Node limit")
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                value = str(value)
            if isinstance(value, str):
                if len(value) > (6 * max_bytes + 16384 if contextual else max_bytes):
                    raise ValueError("Text limit")
                encoded_size = len(value.encode("utf-8"))
                if not contextual:
                    size += encoded_size
                if size > max_bytes or contextual_size > max_bytes + 4096:
                    raise ValueError("Text limit")
                if terms:
                    # Normalize the bounded candidate as a whole: neither a window
                    # seam nor stripped format characters may split a classification.
                    normalized = unicodedata.normalize("NFKC", value).casefold()
                    normalized = "".join(ch for ch in normalized if unicodedata.category(ch) != "Cf")
                    if any(term in normalized for term in terms):
                        reason = "restricted_classification"
                        break
                start = 0
                while start < len(value):
                    if windows >= _MAX_WINDOWS or monotonic() >= deadline:
                        raise ValueError("Inspection work limit")
                    window = value[start:start + _WINDOW_BYTES].encode("utf-8")[:_WINDOW_BYTES].decode(
                        "utf-8", errors="ignore",
                    )
                    windows += 1
                    result = detector.inspect_and_redact(window, tenant_id, agent_id)
                    # Cooperative deadline: an individual synchronous regex call
                    # cannot be interrupted, but an overrun must never yield ALLOW.
                    if monotonic() >= deadline:
                        raise ValueError("Inspection time limit")
                    if any(event.category in _SENSITIVE for event in result.events):
                        break
                    if result.verdict == Verdict.BLOCK:
                        # The detector may stop before its secret stage.
                        raise ValueError("Incomplete detector scan")
                    if start + len(window) == len(value):
                        start = len(value)
                    else:
                        start += len(window) - _OVERLAP_CHARS
                else:
                    continue
                break
            elif isinstance(value, (dict, list)):
                count = len(value) * (4 if isinstance(value, dict) else 1)
                if nodes + len(pending) + count > 4096:
                    raise ValueError("Node limit")
                if isinstance(value, dict):
                    pending.extend((key, False) for key in value)
                    pending.extend((child, False) for child in value.values())
                    for key, child in value.items():
                        if isinstance(child, (str, int, float)) and not isinstance(child, bool):
                            if len(str(key)) + len(str(child)) + 1 > max_bytes + 4096:
                                raise ValueError("Text limit")
                            # Charge generated context before queuing it, bounding
                            # retained copies as well as regex work independently.
                            contextual_size += len(str(key).encode("utf-8")) + len(str(child).encode("utf-8")) + 1
                            if contextual_size > max_bytes + 4096:
                                raise ValueError("Context limit")
                            # JSON syntax is significant to detectors such as
                            # Docker registry auth; key=value alone loses it.
                            candidate = json.dumps({str(key): child}, ensure_ascii=False, separators=(",", ":"))
                            json_context_size += len(candidate.encode("utf-8"))
                            if json_context_size > 6 * max_bytes + 16384:
                                raise ValueError("JSON context limit")
                            pending.append((candidate, True))
                            pending.append((f"{key}={child}", True))
                else:
                    pending.extend((child, False) for child in value)
        else:
            if monotonic() >= deadline:
                raise ValueError("Inspection time limit")
            return GuardrailResult(verdict=Verdict.ALLOW)
    except Exception:
        reason = "input_dlp_incomplete"
    return GuardrailResult(verdict=Verdict.BLOCK, events=[SecurityEvent(
        tenant_id=tenant_id, agent_id=agent_id, request_id=request_id,
        verdict=Verdict.BLOCK, category=ThreatCategory.POLICY_VIOLATION,
        description="Request blocked by input data-loss prevention policy",
        source="input_dlp", severity="high", metadata={"reason": reason},
    )])
