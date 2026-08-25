"""Content-corroboration confidence for input↔output correlation (Phase 4b).

The base correlator (:mod:`src.correlation.incident`) confirms an exfiltration by
*category intersection*: a suspicious-but-allowed INPUT category paired with a
sensitive OUTPUT category in the same request. That intersection is a strong
*signal*, but on its own it cannot tell a genuine leak from an incidental
co-occurrence (e.g. a jailbreak-flavoured question whose benign answer happens to
trip a PII regex). Hard-BLOCKing on that alone risks false "confirmed
exfiltration".

This module adds a **corroboration confidence** in ``[0.0, 1.0]`` that the
correlator uses to gate the WARN→BLOCK escalation: pure category co-occurrence
scores low (stays WARN), while independent content evidence raises it toward a
BLOCK.

Honest scope — what this is and is **not**:

* It is a *corroboration* score built from cheap, deterministic, hot-path-safe
  signals. It does **not** prove data-flow (that the leaked output bytes were
  *derived* from the injected input). True taint tracking is out of scope; the
  SIEM remains the system of record for forensic correlation.
* No LLM calls, no network, no regex catastrophes: pure string work over a
  bounded prefix of each side (:data:`_MAX_CHARS`), so the added hot-path cost is
  O(bounded) and constant.

Signals (summed, then clamped to ``[0, 1]``):

* **Secret-like entropy in the output** (weight :data:`_W_ENTROPY`): a
  high-entropy token in the response is very unlikely to be a false PII/credential
  regex hit — it looks like a real key/blob leaving the gateway.
* **Critical output category** (weight :data:`_W_CRITICAL`): a
  CREDENTIAL_ACCESS / MODEL_THEFT output is inherently more decisive than a lone
  PII match.
* **Lexical linkage** (weight :data:`_W_LEXICAL`, scaled by containment): the
  output echoes distinctive tokens that appeared in the suspicious input — the
  injection referenced material that then reappears in the response.
* **Multi-signal corroboration** (weight :data:`_W_CORROBORATION`): more than one
  paired category, i.e. the detection is not resting on a single regex.

This module never raises: any internal error yields ``0.0`` (→ WARN, the safe
side) so confidence scoring can never break the response path or manufacture a
block.
"""

from __future__ import annotations

import math
import re

# Bounded prefix (characters) scanned per side. Caps hot-path CPU regardless of
# response size (a multi-megabyte completion is truncated before tokenizing).
_MAX_CHARS = 16384

# Cap on the number of distinct significant tokens kept per side (bounds the set
# operations for the lexical-linkage signal).
_MAX_TOKENS = 512

# Significant token: alphanumeric run of length >= 4 (filters most stopwords and
# punctuation noise). Lowercased before comparison.
_TOKEN_RE = re.compile(r"[A-Za-z0-9]{4,}")

# Candidate secret token: a long, dense run that may include the symbol alphabet
# common to base64 / keys / hashes. Entropy is checked separately.
_SECRET_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")

# A token counts as "secret-like" when it is at least this long AND its Shannon
# entropy per character is at least this high (bits/char). Real API keys, base64
# blobs and hashes clear this; natural-language words do not.
_SECRET_MIN_LEN = 20
_SECRET_MIN_ENTROPY = 3.5

# Signal weights. Deliberately sum to > 1.0 so several weak-to-moderate signals
# combine, but the result is clamped to 1.0. Chosen so that a genuine credential
# leak (entropy + critical) clears the default 0.5 block threshold, while a bare
# category co-occurrence does not.
_W_ENTROPY = 0.40
_W_CRITICAL = 0.30
_W_LEXICAL = 0.20
_W_CORROBORATION = 0.10


def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of ``s``. ``0.0`` for empty input."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    return entropy


def _has_secret_like_token(text: str) -> bool:
    """True if ``text`` contains a long, high-entropy (secret-like) token."""
    for m in _SECRET_CANDIDATE_RE.finditer(text):
        tok = m.group(0)
        if len(tok) >= _SECRET_MIN_LEN and _shannon_entropy(tok) >= _SECRET_MIN_ENTROPY:
            return True
    return False


def _significant_tokens(text: str) -> set[str]:
    """Return up to :data:`_MAX_TOKENS` distinct lowercased significant tokens."""
    out: set[str] = set()
    for m in _TOKEN_RE.finditer(text):
        out.add(m.group(0).lower())
        if len(out) >= _MAX_TOKENS:
            break
    return out


def _lexical_linkage(input_text: str, output_text: str) -> float:
    """Containment of distinctive input tokens in the output, in ``[0, 1]``.

    Measures how much of the suspicious input's vocabulary reappears in the
    response — a proxy for "the output is talking about what the input asked for".
    Fraction is relative to the input token count, so a couple of incidental
    common words yield only a small value.
    """
    in_tokens = _significant_tokens(input_text)
    if not in_tokens:
        return 0.0
    out_tokens = _significant_tokens(output_text)
    if not out_tokens:
        return 0.0
    shared = len(in_tokens & out_tokens)
    return shared / len(in_tokens)


def correlation_confidence(
    *,
    input_text: str | None,
    output_text: str | None,
    critical: bool,
    paired_category_count: int,
) -> float:
    """Return a corroboration confidence in ``[0.0, 1.0]`` for a correlation.

    Combines category signals (always available) with content signals (only when
    the request/response text is supplied). Never raises: on any internal error it
    returns ``0.0`` so the correlator degrades to WARN, never to a spurious BLOCK.

    Args:
        input_text: Concatenated suspicious input content (may be ``None``).
        output_text: Concatenated sensitive output content (may be ``None``).
        critical: Whether the paired output category is critical
            (CREDENTIAL_ACCESS / MODEL_THEFT).
        paired_category_count: Total number of paired input+output categories.
    """
    try:
        in_text = (input_text or "")[:_MAX_CHARS]
        out_text = (output_text or "")[:_MAX_CHARS]

        confidence = 0.0

        # Content signal: a secret-like blob in the output is strong evidence of a
        # real credential/key leak rather than a false regex hit.
        if out_text and _has_secret_like_token(out_text):
            confidence += _W_ENTROPY

        # Category signal: a critical output category is inherently decisive.
        if critical:
            confidence += _W_CRITICAL

        # Content signal: the output echoes the suspicious input's vocabulary.
        if in_text and out_text:
            confidence += _W_LEXICAL * _lexical_linkage(in_text, out_text)

        # Corroboration: more than one paired category means the confirmation is
        # not resting on a single detection.
        if paired_category_count >= 2:
            confidence += _W_CORROBORATION

        # Clamp to [0, 1].
        if confidence < 0.0:
            return 0.0
        return 1.0 if confidence > 1.0 else confidence
    except Exception:  # noqa: BLE001 - confidence must never break the response path
        return 0.0
