"""
Input Guardrail — Detects prompt injection, jailbreaks, and malicious patterns
in user messages BEFORE they reach the LLM/agent.

Threat model: The USER is potentially adversarial.
Defense layers:
  1. Unicode NFKC normalization (catches homoglyphs, zero-width chars)
  2. Shannon entropy detection (catches base64/hex encoded payloads)
  3. Pre-compiled regex patterns (fast pattern matching)
"""

import base64
import math
import re
import unicodedata

from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.guardrails.patterns import ALL_PATTERNS, Pattern  # noqa: F401


class InputGuardrail:
    """Inspects user input for prompt injection, jailbreaks, and tool abuse.

    Defense pipeline:
      1. Size check (DoS prevention)
      2. Unicode NFKC normalization (homoglyph/zero-width bypass prevention)
      3. Shannon entropy check (encoded payload detection)
      4. Regex pattern matching on normalized text
    """

    MAX_INPUT_SIZE = 8_000  # 8KB truncation for DoS prevention
    ENTROPY_THRESHOLD = 3.8  # Shannon entropy threshold for encoded blocks
    ENTROPY_MIN_LENGTH = 24  # Check entropy for segments >= this length

    # Zero-width and invisible Unicode characters (smuggling indicators)
    # SECURITY FIX (SG-RT-04): Added U+180E (Mongolian Vowel Separator) and
    # U+FFF9-U+FFFB (Interlinear Annotation) which can break regex matching
    _INVISIBLE_RE = re.compile(
        r"[\u200b-\u200f\u2028-\u202f\u2060-\u2069\ufeff\u00ad\u180e\ufff9-\ufffb\U000E0000-\U000E007F\uFE00-\uFE0F\U000E0100-\U000E01EF]"
    )
    # URL-encoded sequences
    _URL_ENCODED_RE = re.compile(r"(%[0-9a-fA-F]{2}){3,}")
    # Mathematical Alphanumeric Symbols (U+1D400-U+1D7FF)
    _MATH_ALPHA_RE = re.compile(r"[\U0001D400-\U0001D7FF]")
    # High-entropy segment detector (base64/hex blocks)
    _ENCODED_BLOCK_RE = re.compile(r"[A-Za-z0-9+/=]{24,}|[0-9a-fA-F]{24,}")
    # Hex segments (with or without spaces, including wide spacing like "7379 7374")
    _HEX_BLOCK_RE = re.compile(r"(?:[0-9a-fA-F]{2,4}\s+){5,}[0-9a-fA-F]{2,4}|[0-9a-fA-F]{20,}")
    # Leetspeak indicators (any digit surrounded by letters)
    _LEETSPEAK_RE = re.compile(r"[a-zA-Z][0-9]|[0-9][a-zA-Z]")
    # Common encoded prefixes/indicators
    _ENCODING_INDICATOR_RE = re.compile(
        r"(base64|b64|hex|rot13|decode|encode|encoded|decrypt)\s*[:=]?\s*['\"]?[A-Za-z0-9+/=]{16,}",
        re.I,
    )
    # Cyrillic + Greek + Armenian + Fullwidth → Latin homoglyph mapping
    # SECURITY FIX (SG-RT-02): Extended map with Greek, Armenian, and additional
    # Unicode confusables that NFKC normalization does NOT resolve.
    _HOMOGLYPH_MAP = str.maketrans(
        {
            # Cyrillic lowercase
            "\u0430": "a",
            "\u0435": "e",
            "\u043e": "o",
            "\u0440": "p",
            "\u0441": "c",
            "\u0443": "y",
            "\u0456": "i",
            "\u0445": "x",
            "\u044a": "b",
            "\u0455": "s",
            "\u0458": "j",
            "\u04cf": "l",  # Cyrillic palochka → l
            # Cyrillic uppercase
            "\u0410": "A",
            "\u0415": "E",
            "\u041e": "O",
            "\u0420": "P",
            "\u0421": "C",
            "\u0422": "T",
            "\u041d": "H",
            "\u041a": "K",
            "\u0412": "B",
            # Greek lowercase (visually identical to Latin)
            "\u03bf": "o",  # Greek omicron
            "\u03c1": "p",  # Greek rho
            "\u03b1": "a",  # Greek alpha
            "\u03b5": "e",  # Greek epsilon
            "\u03b9": "i",  # Greek iota
            "\u03ba": "k",  # Greek kappa
            "\u03bd": "v",  # Greek nu
            "\u03c5": "u",  # Greek upsilon
            "\u03c4": "t",  # Greek tau
            "\u03c9": "w",  # Greek omega
            # Greek uppercase
            "\u0391": "A",  # Greek Alpha
            "\u0392": "B",  # Greek Beta
            "\u0395": "E",  # Greek Epsilon
            "\u0396": "Z",  # Greek Zeta
            "\u0397": "H",  # Greek Eta
            "\u0399": "I",  # Greek Iota
            "\u039a": "K",  # Greek Kappa
            "\u039c": "M",  # Greek Mu
            "\u039d": "N",  # Greek Nu
            "\u039f": "O",  # Greek Omicron
            "\u03a1": "P",  # Greek Rho
            "\u03a4": "T",  # Greek Tau
            "\u03a5": "Y",  # Greek Upsilon
            "\u03a7": "X",  # Greek Chi
            # Armenian
            "\u0561": "a",  # Armenian ayb
            "\u0578": "n",  # Armenian now
            "\u0585": "o",  # Armenian oh
            "\u0570": "h",  # Armenian ho
            "\u0575": "j",  # Armenian yi
            "\u0572": "q",  # Armenian gim (visual)
            # Additional Unicode confusables
            "\u0131": "i",  # Latin dotless i
            "\u0251": "a",  # Latin alpha
            "\u025b": "e",  # Latin open e
            "\u1d00": "a",  # Latin small capital A
            "\u1d04": "c",  # Latin small capital C
            "\u1d07": "e",  # Latin small capital E
            "\u1d0f": "o",  # Latin small capital O
            "\u1d18": "p",  # Latin small capital P
            "\u2c60": "L",  # Latin L with double bar
        }
    )
    # ROT13 translation table
    _ROT13 = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    )
    # Leet/symbol → letter mapping for de-obfuscation
    _LEET_MAP = str.maketrans(
        {
            "$": "s",
            "@": "a",
            "0": "o",
            "1": "i",
            "3": "e",
            "5": "s",
            "7": "t",
        }
    )
    # Alternate leet map: 1→l (visual similarity variant)
    _LEET_MAP_ALT = str.maketrans(
        {
            "$": "s",
            "@": "a",
            "0": "o",
            "1": "l",
            "3": "e",
            "5": "s",
            "7": "t",
        }
    )
    # Detect leet-like content (letter adjacent to leet symbol)
    _LEET_INDICATOR_RE = re.compile(r"[a-zA-Z][$@01357|]|[$@01357|][a-zA-Z]")

    def __init__(self):
        self.all_patterns = list(ALL_PATTERNS)
        # Assign pattern_ids for dynamic toggle support
        for i, p in enumerate(self.all_patterns):
            if not p.pattern_id:
                p.pattern_id = f"input-{p.category.value}-{i}"

        # DOS-04: DoS controls (config-driven with safe fallbacks). Reading settings
        # here keeps the hot path free of per-request imports while allowing operators
        # to tune limits via BULWARK_GUARDRAIL_* env vars without code changes.
        self.max_input_size = self.MAX_INPUT_SIZE
        self.max_scan_bytes = 16_000
        self.regex_budget_seconds = 1.5
        self.max_concat_bytes = 16_000
        self.messages_budget_seconds = 2.0
        try:
            from src.config import settings
            self.max_input_size = int(getattr(settings, "guardrail_max_input_size", self.max_input_size))
            self.max_scan_bytes = int(getattr(settings, "guardrail_max_scan_bytes", self.max_scan_bytes))
            self.regex_budget_seconds = float(getattr(settings, "guardrail_regex_budget_seconds", self.regex_budget_seconds))
            self.max_concat_bytes = int(getattr(settings, "guardrail_max_concat_bytes", self.max_concat_bytes))
            self.messages_budget_seconds = float(getattr(settings, "guardrail_messages_budget_seconds", self.messages_budget_seconds))
        except Exception:  # noqa: S110 - intentional: config is optional, safe hardcoded defaults apply
            # Fail-safe: keep hardcoded defaults if settings unavailable (e.g. admin import)
            pass

        # DOS-04 (p95 optimization): literal prefilter for speculative cipher decodes.
        # The letter-ciphers (ROT13 / Caesar / Atbash / reversed / Pig Latin) only
        # transform ASCII letters — digits and punctuation pass through unchanged, so
        # structural attacks (SSTI/XSS/SQLi/paths) are already caught by the main loop
        # on the RAW content. The cipher blocks therefore only need to catch *alphabetic*
        # payloads. We mine every alphabetic literal token (>=4 chars) that appears in any
        # pattern source and, before running the full 441-pattern loop over a decoded
        # variant, require that the decoded text contains at least one such token. When we
        # apply the WRONG decode to benign prose the result is gibberish containing none of
        # these tokens, so we skip the expensive scan; when we apply the RIGHT decode to a
        # cipher-encoded attack the result is readable text whose attack words ARE mined
        # tokens, so the full loop still runs (detection parity for realistic payloads).
        # This is a necessary-condition (superset) gate: it can only skip work, never
        # change a match that the full loop would have produced on tokenizable text.
        self._decode_gate_tokens: frozenset[str] = frozenset()
        try:
            _toks: set[str] = set()
            for _p in self.all_patterns:
                for _m in re.findall(r"[A-Za-z]{4,}", _p.regex.pattern):
                    _toks.add(_m.lower())
            self._decode_gate_tokens = frozenset(_toks)
        except Exception:  # noqa: S110 - prefilter is an optimization; absence just means full scan
            pass

    # Word tokenizer for the cipher-decode literal prefilter (compiled once).
    _DECODE_GATE_WORD_RE = re.compile(r"[a-z]{4,}")

    def _decode_variant_worth_scanning(self, decoded: str) -> bool:
        """Return True if a speculatively-decoded variant could plausibly match a
        literal-bearing pattern, i.e. it shares at least one alphabetic token (>=4 chars)
        with the mined pattern lexicon. Used to skip the full 441-pattern loop over the
        gibberish produced by applying the wrong cipher to benign text.

        Fail-open by design: if the lexicon is empty (mining failed) we return True so the
        caller performs the full, unoptimized scan.
        """
        tokens = self._decode_gate_tokens
        if not tokens:
            return True
        for _w in self._DECODE_GATE_WORD_RE.findall(decoded.lower()):
            if _w in tokens:
                return True
        return False

    @classmethod
    def _normalize_unicode(cls, text: str) -> str:
        """Apply NFKC normalization + Cyrillic homoglyph mapping + strip invisible chars.

        Also normalizes Mathematical Alphanumeric Symbols (U+1D400-1D7FF) to ASCII
        and decodes URL-encoded sequences (%XX).
        """
        normalized = unicodedata.normalize("NFKC", text)
        # Map Cyrillic lookalikes to Latin equivalents
        normalized = normalized.translate(cls._HOMOGLYPH_MAP)
        # Strip Variation Selectors (U+FE00-FE0F, U+E0100-E01EF) — used for steganographic padding
        normalized = re.sub(r"[\uFE00-\uFE0F\U000E0100-\U000E01EF]", "", normalized)
        # Map Mathematical Alphanumeric Symbols to ASCII
        if cls._MATH_ALPHA_RE.search(normalized):
            normalized = cls._normalize_math_alpha(normalized)
        # Decode URL-encoded sequences
        if "%" in normalized:
            normalized = cls._decode_url_encoding(normalized)
        # Decode HTML entities (&#NNN; and &#xHH; and &name;)
        if "&" in normalized and (
            "&#" in normalized
            or "&amp" in normalized
            or "&lt" in normalized
            or "&gt" in normalized
            or "&quot" in normalized
            or "&apos" in normalized
        ):
            normalized = cls._decode_html_entities(normalized)
        return normalized

    @staticmethod
    def _normalize_math_alpha(text: str) -> str:
        """Map Mathematical Alphanumeric Symbols (U+1D400-U+1D7FF) to ASCII."""
        result = []
        for ch in text:
            cp = ord(ch)
            if 0x1D400 <= cp <= 0x1D7FF:
                # Mathematical bold A-Z: U+1D400-1D419 → A-Z
                # Mathematical bold a-z: U+1D41A-1D433 → a-z
                # Multiple script variants exist; use offset-based mapping
                mapped = unicodedata.name(ch, "")
                if mapped:
                    # Extract the base letter from the Unicode name
                    # e.g. "MATHEMATICAL BOLD CAPITAL R" → "R"
                    parts = mapped.split()
                    if parts:
                        letter = parts[-1]
                        if len(letter) == 1 and letter.isalpha():
                            result.append(letter)
                            continue
                result.append(ch)
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def _decode_url_encoding(text: str) -> str:
        """Decode URL percent-encoding (%XX) sequences."""
        import urllib.parse

        try:
            decoded = urllib.parse.unquote(text)
            return decoded
        except Exception:
            return text

    @staticmethod
    def _decode_html_entities(text: str) -> str:
        """Decode HTML entities (&#NNN;, &#xHH;, &name;)."""
        import html

        try:
            return html.unescape(text)
        except Exception:
            return text

    # Regex to detect spaced-out single characters: "r e a d" or "r-e-a-d"
    _SPACED_CHARS_RE = re.compile(r"\b([a-zA-Z])\s+(?=[a-zA-Z]\s+[a-zA-Z])")

    @classmethod
    def _collapse_spaced_chars(cls, text: str) -> str:
        """Collapse intra-word spaced characters: 'r e a d' → 'read'.

        Only collapses sequences of 3+ single alpha chars separated by single spaces.
        Preserves dots and other punctuation.
        Multi-space gaps (2+ spaces) are treated as word boundaries.
        """
        import re as _re

        def _collapse_run(m: _re.Match) -> str:
            span = m.group(0)
            # Replace 2+ spaces with a bulwark, collapse single spaces, restore
            span = _re.sub(r" {2,}", "\x00", span)
            span = _re.sub(r" ", "", span)
            span = span.replace("\x00", " ")
            return span

        # Pattern: 3+ single alphanumeric chars each separated by spaces
        pattern = _re.compile(r"(?<![a-zA-Z0-9])([a-zA-Z0-9]\s+){2,}[a-zA-Z0-9](?![a-zA-Z0-9])")
        result = pattern.sub(_collapse_run, text)
        return result

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        freq: dict[str, int] = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _check_encoding_window(
        self, content: str, tenant_id: str, agent_id: str
    ) -> list[SecurityEvent]:
        """Apply encoding checks to a bounded content window.

        SECURITY FIX (PENTEST-DEEP CRIT-2): Extracted to allow encoding checks
        on head/tail windows of large inputs without processing full content.
        Checks: encoding indicators, high-entropy blocks, base64 decode.
        """
        events: list[SecurityEvent] = []
        if not content:
            return events

        # Encoding indicators
        if self._ENCODING_INDICATOR_RE.search(content):
            events.append(
                SecurityEvent(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.BLOCK,
                    category=ThreatCategory.PROMPT_INJECTION,
                    description="Explicit encoding indicator with suspicious payload",
                    source="input_guardrail_encoding",
                    severity="high",
                )
            )

        # High-entropy blocks
        for match in self._ENCODED_BLOCK_RE.finditer(content):
            segment = match.group(0)
            if len(segment) >= self.ENTROPY_MIN_LENGTH:
                entropy = self._shannon_entropy(segment)
                if entropy > self.ENTROPY_THRESHOLD:
                    events.append(
                        SecurityEvent(
                            tenant_id=tenant_id,
                            agent_id=agent_id,
                            verdict=Verdict.BLOCK,
                            category=ThreatCategory.PROMPT_INJECTION,
                            description=f"High-entropy block (entropy={entropy:.2f}, len={len(segment)})",
                            source="input_guardrail_encoding",
                            severity="high",
                        )
                    )
                    break
            # Try base64 decode
            if 12 <= len(segment) <= 64 and ("=" in segment or len(segment) % 4 == 0):
                try:
                    decoded = base64.b64decode(segment).decode("utf-8", errors="ignore")
                    if decoded and len(decoded) >= 6:
                        for pattern in self.all_patterns:
                            if pattern.regex.search(decoded):
                                events.append(
                                    SecurityEvent(
                                        tenant_id=tenant_id,
                                        agent_id=agent_id,
                                        verdict=Verdict.BLOCK,
                                        category=pattern.category,
                                        description=f"Encoded payload (base64→decode→match: {pattern.description})",
                                        source="input_guardrail_encoding",
                                        severity=pattern.severity,
                                        matched_pattern=pattern.pattern_id,
                                    )
                                )
                                return events
                except Exception:
                    pass

        return events

    def _check_encoding_evasion(
        self, content: str, tenant_id: str, agent_id: str, deadline: float | None = None
    ) -> list[SecurityEvent]:
        """Multi-layer encoding evasion detection.

        SECURITY FIX (M-01): Recursive decoding (2 layers) to catch double-encoding
        attacks like base64(base64(payload)) that previously evaded single-pass decode.

        DOS-04: `deadline` is a monotonic wall-clock timestamp. The expensive
        speculative decode blocks (base64/hex/rot13/reversed/morse/braille/nato/
        caesar/atbash) each run the full pattern set and are the dominant cost on
        ordinary text. Once the deadline passes we stop attempting further decodes.
        The cheap, high-signal checks (invisible chars, entropy, explicit encoding
        indicators) run unconditionally before the first deadline gate.
        """
        import time as _time

        def _expired() -> bool:
            return deadline is not None and _time.monotonic() > deadline

        events = []

        # SECURITY FIX (IG-04): For large inputs, apply encoding checks on
        # overlapping windows covering the FULL content.
        # Previous behavior: only checked head(2500) + tail(2500), leaving the
        # entire middle section unscanned for encoding evasion attacks.
        # New behavior: check invisible chars on full content (fast O(n) regex),
        # then apply encoding detection on overlapping windows with full coverage.
        if len(content) > 5000:
            # Check invisible chars on FULL content (fast O(n) regex)
            invisible_matches = self._INVISIBLE_RE.findall(content)
            if len(invisible_matches) >= 3:
                events.append(
                    SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.PROMPT_INJECTION,
                        description=f"Unicode smuggling: {len(invisible_matches)} invisible characters",
                        source="input_guardrail_encoding",
                        severity="high",
                    )
                )
            # Apply encoding detection on overlapping windows covering full content
            window_size = 2500
            stride = 1500  # Overlap of 1000 chars
            for offset in range(0, len(content), stride):
                window = content[offset:offset + window_size]
                if not window:
                    break
                events.extend(
                    self._check_encoding_window(window, tenant_id, agent_id)
                )
                if offset + window_size >= len(content):
                    break
            return events
        # 1. Invisible/zero-width characters (threshold: 2+)
        invisible_matches = self._INVISIBLE_RE.findall(content)
        if len(invisible_matches) >= 2:
            events.append(
                SecurityEvent(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.BLOCK,
                    category=ThreatCategory.PROMPT_INJECTION,
                    description=f"Unicode smuggling: {len(invisible_matches)} invisible characters",
                    source="input_guardrail_encoding",
                    severity="high",
                )
            )

        # 2. Explicit encoding indicators
        if self._ENCODING_INDICATOR_RE.search(content):
            events.append(
                SecurityEvent(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.BLOCK,
                    category=ThreatCategory.PROMPT_INJECTION,
                    description="Explicit encoding indicator with suspicious payload",
                    source="input_guardrail_encoding",
                    severity="high",
                )
            )

        # 3. High-entropy blocks (base64) — also decode short base64
        for match in self._ENCODED_BLOCK_RE.finditer(content):
            segment = match.group(0)
            if len(segment) >= self.ENTROPY_MIN_LENGTH:
                entropy = self._shannon_entropy(segment)
                if entropy > self.ENTROPY_THRESHOLD:
                    events.append(
                        SecurityEvent(
                            tenant_id=tenant_id,
                            agent_id=agent_id,
                            verdict=Verdict.BLOCK,
                            category=ThreatCategory.PROMPT_INJECTION,
                            description=f"High-entropy block (entropy={entropy:.2f}, len={len(segment)})",
                            source="input_guardrail_encoding",
                            severity="high",
                        )
                    )
                    break
            # Try base64 decode for segments 12-32 chars ending with =
            if 12 <= len(segment) <= 64 and ("=" in segment or len(segment) % 4 == 0):
                try:
                    decoded = base64.b64decode(segment).decode("utf-8", errors="ignore")
                    if decoded and len(decoded) >= 6:
                        # SECURITY FIX (M-01): Recursive decoding — try decoding the
                        # decoded result again (catches base64(base64(payload)))
                        decode_layers = [decoded]
                        try:
                            if len(decoded) >= 8 and ("=" in decoded or len(decoded) % 4 == 0):
                                second_decode = base64.b64decode(decoded).decode("utf-8", errors="ignore")
                                if second_decode and len(second_decode) >= 4:
                                    decode_layers.append(second_decode)
                        except Exception:
                            pass

                        for decoded_layer in decode_layers:
                            for pattern in self.all_patterns:
                                if pattern.regex.search(decoded_layer):
                                    events.append(
                                        SecurityEvent(
                                            tenant_id=tenant_id,
                                            agent_id=agent_id,
                                            verdict=Verdict.BLOCK,
                                            category=ThreatCategory.PROMPT_INJECTION,
                                            description=f"Base64-encoded payload decoded to malicious content (depth={decode_layers.index(decoded_layer)+1})",
                                            source="input_guardrail_encoding",
                                            severity="high",
                                        )
                                    )
                                    break
                            else:
                                continue
                            break
                        # Also check for sensitive file paths in all decoded layers
                        for decoded_layer in decode_layers:
                            if re.search(r"/etc/(shadow|passwd|hosts)|\.env|\.aws|id_rsa", decoded_layer):
                                events.append(
                                    SecurityEvent(
                                        tenant_id=tenant_id,
                                        agent_id=agent_id,
                                        verdict=Verdict.BLOCK,
                                        category=ThreatCategory.PROMPT_INJECTION,
                                        description="Base64-encoded sensitive path",
                                        source="input_guardrail_encoding",
                                        severity="high",
                                    )
                                )
                                break
                        break
                except Exception:
                    pass

        # 4. Hex blocks (continuous or space-separated) — decode and check OR flag long hex
        hex_match = self._HEX_BLOCK_RE.search(content)
        if hex_match:
            hex_str = hex_match.group(0).replace(" ", "")
            if len(hex_str) >= 20:
                # Long hex strings are suspicious by default
                try:
                    decoded = bytes.fromhex(hex_str).decode("utf-8", errors="ignore")
                    # Check decoded content against patterns
                    matched = False
                    for pattern in self.all_patterns:
                        if pattern.regex.search(decoded):
                            matched = True
                            break
                    if matched or len(hex_str) >= 32:
                        events.append(
                            SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.PROMPT_INJECTION,
                                description=f"Hex-encoded payload (len={len(hex_str)}, decoded_match={matched})",
                                source="input_guardrail_encoding",
                                severity="high",
                            )
                        )
                    # Check for sensitive paths/commands in decoded hex
                    elif re.search(
                        r"/etc/(shadow|passwd)|\.env|curl|wget|bash|system_prompt", decoded
                    ):
                        events.append(
                            SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.PROMPT_INJECTION,
                                description="Hex-encoded sensitive content",
                                source="input_guardrail_encoding",
                                severity="high",
                            )
                        )
                except (ValueError, UnicodeDecodeError):
                    # Invalid hex but still suspicious if long
                    if len(hex_str) >= 40:
                        events.append(
                            SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.PROMPT_INJECTION,
                                description=f"Suspicious hex block (len={len(hex_str)})",
                                source="input_guardrail_encoding",
                                severity="high",
                            )
                        )

        # 5. Leetspeak de-obfuscation
        if _expired():
            return events
        if self._LEETSPEAK_RE.search(content):
            alpha_count = sum(1 for c in content if c.isalpha())
            digit_count = sum(1 for c in content if c.isdigit())
            if alpha_count > 0 and digit_count >= 3:
                ratio = digit_count / (alpha_count + digit_count)
                if ratio > 0.10 and len(content) > 15:
                    deleeted = content.translate(str.maketrans("01345679", "oieasbgt"))
                    for pattern in self.all_patterns:
                        if pattern.regex.search(deleeted):
                            events.append(
                                SecurityEvent(
                                    tenant_id=tenant_id,
                                    agent_id=agent_id,
                                    verdict=Verdict.BLOCK,
                                    category=ThreatCategory.PROMPT_INJECTION,
                                    description="Leetspeak evasion (de-obfuscated match)",
                                    source="input_guardrail_encoding",
                                    severity="high",
                                )
                            )
                            break

        # 6. ROT13 detection (relaxed thresholds for V5)
        # Strip non-ASCII chars before checking (fixes emoji+ROT13 bypass)
        if _expired():
            return events
        ascii_content = "".join(c for c in content if ord(c) < 128)
        if len(ascii_content) > 8:
            # For very long inputs, check segments (head + tail)
            segments_to_check = [ascii_content]
            if len(ascii_content) > 10000:
                segments_to_check = [ascii_content[:5000], ascii_content[-5000:]]
            for segment in segments_to_check:
                alpha_ratio = sum(1 for c in segment if c.isalpha()) / max(len(segment), 1)
                if alpha_ratio > 0.5:
                    decoded_rot13 = segment.translate(self._ROT13)
                    # DOS-04 (p95): skip the 441-pattern scan on gibberish (wrong-decode
                    # of benign text). Attack payloads decode to text sharing mined tokens.
                    if not self._decode_variant_worth_scanning(decoded_rot13):
                        continue
                    # Check against patterns
                    matched = False
                    for pattern in self.all_patterns:
                        if pattern.regex.search(decoded_rot13):
                            matched = True
                            break
                    # Also check for dangerous keywords in decoded text
                    if not matched:
                        _dangerous_kw = re.search(
                            r"(system\s*prompt|ignore|bypass|disable|override|inject|"
                            r"exfiltrat|reverse.shell|credentials?|password|hack|exploit)",
                            decoded_rot13,
                            re.I,
                        )
                        if _dangerous_kw:
                            matched = True
                    if matched:
                        events.append(
                            SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.PROMPT_INJECTION,
                                description="ROT13-encoded payload decoded to malicious content",
                                source="input_guardrail_encoding",
                                severity="high",
                            )
                        )
                        break

        # 7. Reversed text detection (only for short inputs)
        if _expired():
            return events
        if len(ascii_content) > 15:
            # For very long inputs, check segments (head + tail)
            segments_to_check = [ascii_content]
            if len(ascii_content) > 5000:
                segments_to_check = [ascii_content[:2500], ascii_content[-2500:]]
            for segment in segments_to_check:
                reversed_text = segment[::-1]
                # DOS-04 (p95): reversed benign text is gibberish; skip unless it shares
                # a mined attack token (a genuinely reversed payload decodes to real words).
                if not self._decode_variant_worth_scanning(reversed_text):
                    continue
                segment_matched = False
                for pattern in self.all_patterns:
                    if pattern.regex.search(reversed_text):
                        events.append(
                            SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.PROMPT_INJECTION,
                                description="Reversed text decoded to malicious content",
                                source="input_guardrail_encoding",
                                severity="high",
                            )
                        )
                        segment_matched = True
                        break
                if segment_matched:
                    break

        # 8. Morse code detection
        if re.search(r"[.\-]{2,}\s+[.\-]{2,}", content):
            decoded_morse = self._decode_morse(content)
            if decoded_morse and len(decoded_morse) > 3:
                morse_blocked = False
                for pattern in self.all_patterns:
                    if pattern.regex.search(decoded_morse):
                        events.append(
                            SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.PROMPT_INJECTION,
                                description="Morse-encoded payload decoded to malicious content",
                                source="input_guardrail_encoding",
                                severity="high",
                            )
                        )
                        morse_blocked = True
                        break
                # Also check dangerous keywords
                if not morse_blocked:
                    _kw = re.search(
                        r"(hack|exploit|inject|bypass|exfiltrat|credential|password|"
                        r"system\s*prompt|reverse.shell|ignore|override|jailbreak|"
                        r"admin|root|sudo|shadow|passwd|secret|token)",
                        decoded_morse,
                        re.I,
                    )
                    if _kw:
                        events.append(
                            SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.PROMPT_INJECTION,
                                description="Morse-encoded payload contains dangerous keywords",
                                source="input_guardrail_encoding",
                                severity="high",
                            )
                        )

        # 9. Braille detection (U+2800-U+28FF range)
        if re.search(r"[\u2800-\u28FF]{3,}", content):
            decoded_braille = self._decode_braille(content)
            if decoded_braille and len(decoded_braille) > 3:
                braille_blocked = False
                for pattern in self.all_patterns:
                    if pattern.regex.search(decoded_braille):
                        events.append(
                            SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.PROMPT_INJECTION,
                                description="Braille-encoded payload decoded to malicious content",
                                source="input_guardrail_encoding",
                                severity="high",
                            )
                        )
                        braille_blocked = True
                        break
                if not braille_blocked:
                    _kw = re.search(
                        r"(hack|exploit|inject|bypass|exfiltrat|credential|password|"
                        r"system.prompt|reverse.shell|ignore|override|jailbreak|"
                        r"admin|root|sudo|shadow|passwd|secret|token)",
                        decoded_braille,
                        re.I,
                    )
                    if _kw:
                        events.append(
                            SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.PROMPT_INJECTION,
                                description="Braille-encoded payload contains dangerous keywords",
                                source="input_guardrail_encoding",
                                severity="high",
                            )
                        )

        # 10. NATO phonetic alphabet detection
        nato_words = {
            "alfa",
            "alpha",
            "bravo",
            "charlie",
            "delta",
            "echo",
            "foxtrot",
            "golf",
            "hotel",
            "india",
            "juliet",
            "juliett",
            "kilo",
            "lima",
            "mike",
            "november",
            "oscar",
            "papa",
            "quebec",
            "romeo",
            "sierra",
            "tango",
            "uniform",
            "victor",
            "whiskey",
            "xray",
            "x-ray",
            "yankee",
            "zulu",
        }
        words = content.lower().split()
        nato_count = sum(1 for w in words if w.strip(".,;:!?") in nato_words)
        if nato_count >= 4 and nato_count / max(len(words), 1) > 0.4:
            decoded_nato = self._decode_nato(content)
            if decoded_nato and len(decoded_nato) > 3:
                # Check against patterns (with spaces from decoder)
                nato_blocked = False
                for pattern in self.all_patterns:
                    if pattern.regex.search(decoded_nato):
                        events.append(
                            SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.PROMPT_INJECTION,
                                description="NATO phonetic-encoded payload decoded to malicious content",
                                source="input_guardrail_encoding",
                                severity="high",
                            )
                        )
                        nato_blocked = True
                        break
                # Also check no-space version against dangerous keywords
                if not nato_blocked:
                    no_space = decoded_nato.replace(" ", "")
                    _kw = re.search(
                        r"(ignoreprevious|ignoreall|systemprompt|bypasssecurity|"
                        r"disablesafety|overriderules|reverseshell|credentials|"
                        r"deleteall|dropdata|exfiltrat|hackthesystem|password|"
                        r"showmethe|readfile|catfile|runcommand|execut|"
                        r"revealthe|accessthe|dumpall|extractall)",
                        no_space,
                        re.I,
                    )
                    if _kw:
                        events.append(
                            SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.PROMPT_INJECTION,
                                description="NATO phonetic-encoded payload decoded to malicious content",
                                source="input_guardrail_encoding",
                                severity="high",
                            )
                        )

        # 11. Caesar cipher detection (try all shifts, limited to short inputs for perf)
        if _expired():
            return events
        if len(ascii_content) > 8:
            # For very long inputs, check segments (head + tail)
            segments_to_check = [ascii_content]
            if len(ascii_content) > 2000:
                segments_to_check = [ascii_content[:1000], ascii_content[-1000:]]
            for segment in segments_to_check:
                alpha_ratio = sum(1 for c in segment if c.isalpha()) / max(len(segment), 1)
                if alpha_ratio > 0.5:
                    caesar_found = False
                    for shift in range(1, 26):
                        if shift == 13:  # Already covered by ROT13 check
                            continue
                        # DOS-04: honour the deadline between shifts — 24 shifts x
                        # 441 patterns per segment is the single most expensive block.
                        if _expired():
                            break
                        decoded = self._caesar_shift(segment, shift)
                        # DOS-04 (p95): the single most expensive block (24 shifts x 441
                        # patterns). A wrong shift of benign text is gibberish; only the
                        # correct shift of a Caesar-encoded attack yields mined tokens.
                        if not self._decode_variant_worth_scanning(decoded):
                            continue
                        for pattern in self.all_patterns:
                            if pattern.regex.search(decoded):
                                events.append(
                                    SecurityEvent(
                                        tenant_id=tenant_id,
                                        agent_id=agent_id,
                                        verdict=Verdict.BLOCK,
                                        category=ThreatCategory.PROMPT_INJECTION,
                                        description=f"Caesar cipher (shift {shift}) decoded to malicious content",
                                        source="input_guardrail_encoding",
                                        severity="high",
                                    )
                                )
                                caesar_found = True
                                break
                        if caesar_found:
                            break
                        # Also check dangerous keywords
                        _kw = re.search(
                            r"(hack|exploit|inject|bypass|exfiltrat|credential|password|"
                            r"system.prompt|reverse.shell|ignore.*previous|ignore.*instruc|"
                            r"admin|root|shadow|passwd|secret|token|jailbreak)",
                            decoded,
                            re.I,
                        )
                        if _kw:
                            events.append(
                                SecurityEvent(
                                    tenant_id=tenant_id,
                                    agent_id=agent_id,
                                    verdict=Verdict.BLOCK,
                                    category=ThreatCategory.PROMPT_INJECTION,
                                    description=f"Caesar cipher (shift {shift}) contains dangerous keywords",
                                    source="input_guardrail_encoding",
                                    severity="high",
                                )
                            )
                            caesar_found = True
                            break
                        if events and events[-1].description.startswith("Caesar"):
                            break
                    if caesar_found:
                        break

        # 12. Atbash cipher detection
        if _expired():
            return events
        if 8 < len(ascii_content) <= 200:
            alpha_ratio = sum(1 for c in ascii_content if c.isalpha()) / max(len(ascii_content), 1)
            decoded_atbash = self._decode_atbash(ascii_content) if alpha_ratio > 0.5 else ""
            # DOS-04 (p95): skip Atbash scan on gibberish (wrong-cipher of benign text).
            if alpha_ratio > 0.5 and self._decode_variant_worth_scanning(decoded_atbash):
                atbash_blocked = False
                for pattern in self.all_patterns:
                    if pattern.regex.search(decoded_atbash):
                        events.append(
                            SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.PROMPT_INJECTION,
                                description="Atbash cipher decoded to malicious content",
                                source="input_guardrail_encoding",
                                severity="high",
                            )
                        )
                        atbash_blocked = True
                        break
                if not atbash_blocked:
                    _kw = re.search(
                        r"(hack|exploit|inject|bypass|exfiltrat|credential|password|"
                        r"system.prompt|reverse.shell|ignore|override|jailbreak|"
                        r"admin|root|sudo|shadow|passwd|secret|token|decrypt|reveal)",
                        decoded_atbash,
                        re.I,
                    )
                    if _kw:
                        events.append(
                            SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.PROMPT_INJECTION,
                                description="Atbash decoded payload contains dangerous keywords",
                                source="input_guardrail_encoding",
                                severity="high",
                            )
                        )

        # 13. Pig Latin detection
        if _expired():
            return events
        if re.search(r"\b\w+(way|ay)\b", content, re.I):
            pig_words = re.findall(r"\b\w+(?:way|ay)\b", content, re.I)
            if len(pig_words) >= 3:
                decoded_pig = self._decode_pig_latin(content)
                # DOS-04 (p95): skip the full scan unless the de-obfuscated text shares a
                # mined attack token (benign Pig-Latin-shaped prose decodes to non-attack text).
                if self._decode_variant_worth_scanning(decoded_pig):
                    pig_blocked = False
                    for pattern in self.all_patterns:
                        if pattern.regex.search(decoded_pig):
                            events.append(
                                SecurityEvent(
                                    tenant_id=tenant_id,
                                    agent_id=agent_id,
                                    verdict=Verdict.BLOCK,
                                    category=ThreatCategory.PROMPT_INJECTION,
                                    description="Pig Latin decoded to malicious content",
                                    source="input_guardrail_encoding",
                                    severity="high",
                                )
                            )
                            pig_blocked = True
                            break
                    if not pig_blocked:
                        _kw = re.search(
                            r"(hack|exploit|inject|bypass|exfiltrat|credential|password|"
                            r"system.prompt|reverse.shell|ignore|override|jailbreak|"
                            r"admin|root|sudo|shadow|passwd|secret|token)",
                            decoded_pig,
                            re.I,
                        )
                        if _kw:
                            events.append(
                                SecurityEvent(
                                    tenant_id=tenant_id,
                                    agent_id=agent_id,
                                    verdict=Verdict.BLOCK,
                                    category=ThreatCategory.PROMPT_INJECTION,
                                    description="Pig Latin decoded payload contains dangerous keywords",
                                    source="input_guardrail_encoding",
                                    severity="high",
                                )
                            )

        # 13b. Unicode escape sequence detection (\u0048\u0065\u006c\u006c\u006f style)
        if _expired():
            return events
        _unicode_escape_re = re.search(r"(\\u[0-9a-fA-F]{4}){4,}", content)
        if _unicode_escape_re:
            # Decode all \uXXXX sequences in the text
            try:
                decoded_unicode = content.encode("utf-8").decode("unicode_escape")
                # Run patterns against decoded content
                unicode_blocked = False
                for pattern in self.all_patterns:
                    if pattern.regex.search(decoded_unicode):
                        events.append(
                            SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.PROMPT_INJECTION,
                                description="Unicode escape-encoded payload decoded to malicious content",
                                source="input_guardrail_encoding",
                                severity="high",
                            )
                        )
                        unicode_blocked = True
                        break
                # Also check dangerous keywords if no pattern match
                if not unicode_blocked:
                    _kw = re.search(
                        r"(hack|exploit|inject|bypass|exfiltrat|credential|password|"
                        r"system.prompt|reverse.shell|ignore|override|jailbreak|"
                        r"admin|root|sudo|shadow|passwd|secret|token|"
                        r"send\s+.{0,20}(to|@)|email|upload|ssh|private.key)",
                        decoded_unicode,
                        re.I,
                    )
                    if _kw:
                        events.append(
                            SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.PROMPT_INJECTION,
                                description="Unicode escape-encoded payload contains dangerous keywords",
                                source="input_guardrail_encoding",
                                severity="high",
                            )
                        )
            except (UnicodeDecodeError, ValueError):
                # If decode fails but many \uXXXX sequences present, still suspicious
                escape_count = len(re.findall(r"\\u[0-9a-fA-F]{4}", content))
                if escape_count >= 8:
                    events.append(
                        SecurityEvent(
                            tenant_id=tenant_id,
                            agent_id=agent_id,
                            verdict=Verdict.BLOCK,
                            category=ThreatCategory.PROMPT_INJECTION,
                            description=f"Suspicious unicode escape sequence concentration ({escape_count} sequences)",
                            source="input_guardrail_encoding",
                            severity="high",
                        )
                    )

        # 14. Acrostic detection (first letter of each line, limited size)
        lines = content.split("\n")
        if 4 <= len(lines) <= 100:
            acrostic = "".join(line.strip()[0] for line in lines if line.strip()).lower()
            if len(acrostic) >= 4:
                _acrostic_kw = re.search(
                    r"(ignor|bypass|hack|exploit|inject|system|admin|passwd|shadow|exec|steal|creds|token|secret|delete|drop|exfil|model|extract|priv|root|leak|dump)",
                    acrostic,
                    re.I,
                )
                if _acrostic_kw:
                    events.append(
                        SecurityEvent(
                            tenant_id=tenant_id,
                            agent_id=agent_id,
                            verdict=Verdict.BLOCK,
                            category=ThreatCategory.PROMPT_INJECTION,
                            description=f"Acrostic steganography detected: '{acrostic}' contains '{_acrostic_kw.group()}'",
                            source="input_guardrail_stego",
                            severity="high",
                        )
                    )

        # 15. Markdown URL payload extraction
        md_urls = re.findall(r"!\[.*?\]\((https?://[^)]+)\)", content)
        for url in md_urls:
            # Check if URL contains exfiltration indicators
            if re.search(
                r"(exfiltrat|steal|secret|password|token|credential|data=|dump)", url, re.I
            ):
                events.append(
                    SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.EXFILTRATION,
                        description="Exfiltration payload in markdown image URL",
                        source="input_guardrail_stego",
                        severity="high",
                    )
                )
                break

        # 16. Distributed keyword detection across lines (limited to reasonable sizes)
        if len(lines) >= 3 and len(content) < 5000:
            # Check if key attack phrases are distributed across consecutive lines
            combined = " ".join(line.strip() for line in lines if line.strip()).lower()
            _distributed_kw = re.search(
                r"ignore.{0,60}all.{0,60}previous.{0,60}instructions",
                combined,
                re.I,
            )
            if _distributed_kw:
                events.append(
                    SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.PROMPT_INJECTION,
                        description="Distributed payload across lines: 'ignore all previous instructions'",
                        source="input_guardrail_stego",
                        severity="high",
                    )
                )

        return events

    # === Decoder helpers ===

    _MORSE_CODE = {
        ".-": "A",
        "-...": "B",
        "-.-.": "C",
        "-..": "D",
        ".": "E",
        "..-.": "F",
        "--.": "G",
        "....": "H",
        "..": "I",
        ".---": "J",
        "-.-": "K",
        ".-..": "L",
        "--": "M",
        "-.": "N",
        "---": "O",
        ".--.": "P",
        "--.-": "Q",
        ".-.": "R",
        "...": "S",
        "-": "T",
        "..-": "U",
        "...-": "V",
        ".--": "W",
        "-..-": "X",
        "-.--": "Y",
        "--..": "Z",
        ".----": "1",
        "..---": "2",
        "...--": "3",
        "....-": "4",
        ".....": "5",
        "-....": "6",
        "--...": "7",
        "---..": "8",
        "----.": "9",
        "-----": "0",
    }

    @classmethod
    def _decode_morse(cls, text: str) -> str:
        """Decode Morse code (dots and dashes separated by spaces, words by multiple spaces or /)."""
        # Normalize separators
        text = text.replace("/", "   ")
        words = re.split(r"\s{3,}", text)
        result = []
        for word in words:
            chars = word.strip().split()
            decoded_word = ""
            for char in chars:
                char_clean = char.strip()
                if char_clean in cls._MORSE_CODE:
                    decoded_word += cls._MORSE_CODE[char_clean]
            if decoded_word:
                result.append(decoded_word)
        return " ".join(result)

    _BRAILLE_MAP = {
        chr(0x2800 + i): chr(c)
        for i, c in enumerate(
            [
                0,
                97,
                49,
                98,
                39,
                107,
                50,
                108,
                64,
                99,
                105,
                102,
                47,
                109,
                115,
                112,
                34,
                101,
                51,
                104,
                57,
                111,
                54,
                114,
                94,
                100,
                106,
                103,
                62,
                110,
                116,
                113,
                44,
                42,
                53,
                60,
                45,
                117,
                56,
                118,
                46,
                37,
                91,
                36,
                43,
                120,
                33,
                38,
                59,
                58,
                52,
                92,
                48,
                122,
                55,
                40,
                95,
                63,
                119,
                93,
                35,
                121,
                41,
                61,
            ]
        )
    }

    @classmethod
    def _decode_braille(cls, text: str) -> str:
        """Decode Braille Unicode characters (U+2800-U+28FF) to ASCII."""
        result = []
        for ch in text:
            if ch in cls._BRAILLE_MAP:
                mapped = cls._BRAILLE_MAP[ch]
                if mapped == chr(0):
                    result.append(" ")
                else:
                    result.append(mapped)
            else:
                result.append(ch)
        return "".join(result)

    _NATO_MAP = {
        "alfa": "a",
        "alpha": "a",
        "bravo": "b",
        "charlie": "c",
        "delta": "d",
        "echo": "e",
        "foxtrot": "f",
        "golf": "g",
        "hotel": "h",
        "india": "i",
        "juliet": "j",
        "juliett": "j",
        "kilo": "k",
        "lima": "l",
        "mike": "m",
        "november": "n",
        "oscar": "o",
        "papa": "p",
        "quebec": "q",
        "romeo": "r",
        "sierra": "s",
        "tango": "t",
        "uniform": "u",
        "victor": "v",
        "whiskey": "w",
        "xray": "x",
        "x-ray": "x",
        "yankee": "y",
        "zulu": "z",
    }

    @classmethod
    def _decode_nato(cls, text: str) -> str:
        """Decode NATO phonetic alphabet to text. Insert spaces between non-NATO words."""
        words = text.lower().split()
        result = []
        current_word = []
        for w in words:
            w_clean = w.strip(".,;:!?")
            if w_clean in cls._NATO_MAP:
                current_word.append(cls._NATO_MAP[w_clean])
            else:
                if current_word:
                    result.append("".join(current_word))
                    current_word = []
                result.append(w)
        if current_word:
            result.append("".join(current_word))
        return " ".join(result)

    @staticmethod
    def _caesar_shift(text: str, shift: int) -> str:
        """Apply Caesar cipher shift (decrypt by shifting back)."""
        result = []
        for ch in text:
            if "A" <= ch <= "Z":
                result.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
            elif "a" <= ch <= "z":
                result.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def _decode_pig_latin(text: str) -> str:
        """Decode Pig Latin to English."""
        words = re.split(r"\s+", text)
        result = []
        for w in words:
            w_stripped = w.strip(".,;:!?")
            if w_stripped.lower().endswith("way") and len(w_stripped) > 3:
                # Vowel rule: word + "way" → remove "way"
                result.append(w_stripped[:-3])
            elif w_stripped.lower().endswith("ay") and len(w_stripped) > 3:
                # Consonant rule: word = (moved vowel+rest) + (consonant cluster) + "ay"
                base = w_stripped[:-2]
                # Try moving 1-3 chars from end of base to front
                best = base  # fallback
                for n in range(1, min(4, len(base))):
                    candidate = base[-n:] + base[:-n]
                    best = candidate
                    # Check if result starts with a consonant (likely correct)
                    if candidate[0].lower() not in "aeiou":
                        break
                result.append(best)
            else:
                result.append(w_stripped)
        return " ".join(result)

    @staticmethod
    def _decode_atbash(text: str) -> str:
        """Decode Atbash cipher (A↔Z, B↔Y, etc.)."""
        result = []
        for ch in text:
            if "A" <= ch <= "Z":
                result.append(chr(ord("Z") - (ord(ch) - ord("A"))))
            elif "a" <= ch <= "z":
                result.append(chr(ord("z") - (ord(ch) - ord("a"))))
            else:
                result.append(ch)
        return "".join(result)

    def inspect(self, content: str, tenant_id: str = "", agent_id: str = "") -> GuardrailResult:
        """
        Analyze user input through multi-layer defense pipeline.
        Returns BLOCK if critical/high threats found, WARN for medium/low.
        """
        events: list[SecurityEvent] = []
        # DOS-04: single wall-clock deadline shared across the ENTIRE inspection
        # (encoding-evasion decode loops + main pattern loop). The encoding layer
        # brute-forces Caesar/ROT13/Atbash/reversed decodes and runs the full
        # pattern set on each — unbounded, it dominates latency on ordinary prose.
        # Cheap high-signal checks (invisible chars, entropy, explicit indicators)
        # run before any deadline check, so the most important detections are never
        # skipped; only the expensive speculative decodes yield to the budget.
        import time as _time
        _deadline = _time.monotonic() + self.regex_budget_seconds
        oversized = len(content) > self.max_input_size

        if oversized:
            events.append(
                SecurityEvent(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.WARN,
                    category=ThreatCategory.TOOL_ABUSE,
                    description=f"Oversized input ({len(content)} bytes), full-content scan active",
                    source="input_guardrail",
                    severity="medium",
                )
            )
            # SECURITY FIX (IG-02 + DOS-04): Overlapping sliding-window scan with a
            # HARD CAP on total reconstructed bytes.
            # IG-02 (prior) covered every byte via 4KB windows / 2KB stride, but the
            # `\n`.join reconstruction ~doubled the payload with no ceiling, letting an
            # attacker force 400+ regex patterns to run over hundreds of KB (DoS).
            # DOS-04: we now stop emitting windows once the joined text would exceed
            # self.max_scan_bytes. Coverage is prioritized head→tail; the remainder is
            # bounded, so worst-case regex work is capped regardless of input length.
            windows: list[str] = []
            total_len = len(content)
            window_size = 4096
            stride = 2048  # 50% overlap
            budget = self.max_scan_bytes
            used = 0
            for offset in range(0, total_len, stride):
                end = min(offset + window_size, total_len)
                chunk = content[offset:end]
                # +1 accounts for the "\n" join separator between windows
                if used + len(chunk) + 1 > budget:
                    remaining = budget - used - 1
                    if remaining > 0:
                        windows.append(chunk[:remaining])
                    break
                windows.append(chunk)
                used += len(chunk) + 1
                if end >= total_len:
                    break
            content = "\n".join(windows)

        # Layer 1: Encoding evasion detection (on raw input)
        encoding_events = self._check_encoding_evasion(content, tenant_id, agent_id, _deadline)
        events.extend(encoding_events)

        # Layer 2: Normalize for pattern matching
        normalized = self._normalize_unicode(content)
        # Strip zero-width chars entirely (catches splits within words: "Ign\u200bore" → "Ignore")
        clean = self._INVISIBLE_RE.sub("", normalized)
        # Also create space-replaced variant (preserves word boundaries: "email\u200bthe" → "email the")
        spaced_invisible = re.sub(r"  +", " ", self._INVISIBLE_RE.sub(" ", normalized))

        # Layer 2a2: Decode literal Unicode escapes (\\u0049gnore → Ignore)
        unicode_escape_decoded = None
        if r"\u" in clean or r"\U" in clean or r"\x" in clean:
            try:
                # Decode \\uXXXX, \\UXXXXXXXX, \\xXX sequences
                decoded = re.sub(
                    r"\\u([0-9a-fA-F]{4})",
                    lambda m: chr(int(m.group(1), 16)),
                    clean,
                )
                decoded = re.sub(
                    r"\\U([0-9a-fA-F]{8})",
                    lambda m: chr(int(m.group(1), 16)),
                    decoded,
                )
                decoded = re.sub(
                    r"\\x([0-9a-fA-F]{2})",
                    lambda m: chr(int(m.group(1), 16)),
                    decoded,
                )
                if decoded != clean:
                    unicode_escape_decoded = decoded
            except (ValueError, OverflowError):
                pass

        # Layer 2b: Collapse intra-word spaces (evasion: "r e a d" → "read")
        collapsed = self._collapse_spaced_chars(clean)

        # Layer 2c: Dehyphenation/deobfuscation passes
        # Strip hyphens between word chars: "ig-nore" → "ignore"
        dehyphenated = re.sub(r"(\w)-(\w)", r"\1\2", clean)
        # Strip underscores as word separators: "ignore_all" → "ignore all"
        deunderscored = clean.replace("_", " ")
        # Strip markdown bold/italic markers: "**ig**nore" → "ignore"
        demarkdown = re.sub(r"\*{1,3}([^*]+)\*{1,3}", r"\1", clean)
        # Strip dots between single chars: "I.G.N.O.R.E" → "IGNORE"
        dedotted = re.sub(r"\b(\w)\.", r"\1", clean)
        # Strip combining diacritics (U+0300-U+036F): "ïġn̈ȯr̈ë" → "ignore"
        decomposed = unicodedata.normalize("NFD", clean)
        stripped_diacritics = re.sub(r"[\u0300-\u036f\u0308\u0307\u0323]", "", decomposed)
        stripped_diacritics = unicodedata.normalize("NFC", stripped_diacritics)

        # Layer 3: Pattern matching on normalized + cleaned text
        max_severity = "low"
        severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        # Account for encoding events severity
        if encoding_events:
            max_severity = "high"

        if oversized:
            max_severity = max(max_severity, "medium", key=lambda s: severity_rank[s])

        # Run patterns against both original and cleaned versions
        texts_to_check = [clean]
        if collapsed != clean:
            texts_to_check.append(collapsed)
            # Also add fully-collapsed (no spaces) for keyword matching
            fully_collapsed = re.sub(r"\s+", "", collapsed)
            if fully_collapsed != collapsed:
                texts_to_check.append(fully_collapsed)
        if clean != content:
            texts_to_check.append(content)  # Also check raw in case normalization changed semantics
        # Add deobfuscated variants
        for variant in (dehyphenated, deunderscored, demarkdown, dedotted, stripped_diacritics, spaced_invisible):
            if variant not in texts_to_check and variant != clean:
                texts_to_check.append(variant)
        # Add unicode-escape-decoded variant if present
        if unicode_escape_decoded and unicode_escape_decoded not in texts_to_check:
            texts_to_check.append(unicode_escape_decoded)

        # Layer 2d: Leet/symbol de-obfuscation (only if leet indicators present)
        if self._LEET_INDICATOR_RE.search(clean):
            deleeted = clean.translate(self._LEET_MAP)
            # Context-aware | → l: when adjacent to at least one letter
            deleeted = re.sub(r"(?<=[a-zA-Z])\||\|(?=[a-zA-Z])", "l", deleeted)
            if deleeted not in texts_to_check and deleeted != clean:
                texts_to_check.append(deleeted)
            # Combined de-leet + diacritics strip for multi-layer obfuscation
            decomposed_leet = unicodedata.normalize("NFD", deleeted)
            stripped_leet = re.sub(r"[\u0300-\u036f\u0308\u0307\u0323]", "", decomposed_leet)
            stripped_leet = unicodedata.normalize("NFC", stripped_leet)
            if stripped_leet not in texts_to_check and stripped_leet != deleeted:
                texts_to_check.append(stripped_leet)
            # Alt leet map (1→l instead of 1→i) for visual-similarity evasion
            deleeted_alt = clean.translate(self._LEET_MAP_ALT)
            deleeted_alt = re.sub(r"(?<=[a-zA-Z])\||\|(?=[a-zA-Z])", "l", deleeted_alt)
            if deleeted_alt not in texts_to_check and deleeted_alt != deleeted:
                texts_to_check.append(deleeted_alt)
                # Alt de-leet + diacritics
                decomposed_alt = unicodedata.normalize("NFD", deleeted_alt)
                stripped_alt = re.sub(r"[\u0300-\u036f\u0308\u0307\u0323]", "", decomposed_alt)
                stripped_alt = unicodedata.normalize("NFC", stripped_alt)
                if stripped_alt not in texts_to_check and stripped_alt != deleeted_alt:
                    texts_to_check.append(stripped_alt)
            # Also apply leet+diacritics to spaced_invisible variant (preserves word boundaries)
            if spaced_invisible != clean and self._LEET_INDICATOR_RE.search(spaced_invisible):
                spaced_deleeted = spaced_invisible.translate(self._LEET_MAP)
                spaced_deleeted = re.sub(r"(?<=[a-zA-Z])\||\|(?=[a-zA-Z])", "l", spaced_deleeted)
                decomposed_spaced = unicodedata.normalize("NFD", spaced_deleeted)
                stripped_spaced_leet = re.sub(r"[\u0300-\u036f\u0308\u0307\u0323]", "", decomposed_spaced)
                stripped_spaced_leet = unicodedata.normalize("NFC", stripped_spaced_leet)
                if stripped_spaced_leet not in texts_to_check:
                    texts_to_check.append(stripped_spaced_leet)
                # Alt map on spaced variant too
                spaced_alt = spaced_invisible.translate(self._LEET_MAP_ALT)
                spaced_alt = re.sub(r"(?<=[a-zA-Z])\||\|(?=[a-zA-Z])", "l", spaced_alt)
                decomposed_spaced_alt = unicodedata.normalize("NFD", spaced_alt)
                stripped_spaced_alt = re.sub(r"[\u0300-\u036f\u0308\u0307\u0323]", "", decomposed_spaced_alt)
                stripped_spaced_alt = unicodedata.normalize("NFC", stripped_spaced_alt)
                if stripped_spaced_alt not in texts_to_check:
                    texts_to_check.append(stripped_spaced_alt)

        matched_descriptions = set()
        # Get dynamic registry (disabled patterns + custom patterns from admin)
        from src.guardrails.dynamic_registry import get_pattern_registry, safe_regex_search
        _registry = get_pattern_registry()

        # SECURITY FIX (H-09): Per-request CPU budget for regex evaluation.
        # Prevents algorithmic complexity DoS where crafted near-miss inputs
        # cause excessive backtracking across 441 patterns × N text variants.
        import time as _time
        _REGEX_BUDGET_SECONDS = self.regex_budget_seconds  # DOS-04: config-driven (default 1.5s)
        _regex_start = _time.monotonic()
        _budget_exceeded = False
        _pattern_counter = 0  # DOS-03: check budget every 10 patterns (was every ~50 via hash)

        for text in texts_to_check:
            if _budget_exceeded:
                break
            for pattern in self.all_patterns:
                # DOS-03 FIX: Check time budget every 10 patterns (deterministic).
                # Previously used hash(pattern.description) % 50 which was non-deterministic
                # and allowed individual patterns to backtrack for seconds unchecked.
                _pattern_counter += 1
                if not _budget_exceeded and (_pattern_counter % 10 == 0):
                    if _time.monotonic() - _regex_start > _REGEX_BUDGET_SECONDS:
                        _budget_exceeded = True
                        # SECURITY FIX (IG-01): Budget exhaustion MUST produce BLOCK, not WARN.
                        # Attackers craft inputs that force expensive backtracking to exhaust
                        # the budget, leaving malicious patterns in unchecked remainder.
                        # Fail-closed: if we can't finish scanning, assume adversarial intent.
                        events.append(
                            SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.PROMPT_INJECTION,
                                description=f"Regex budget exceeded ({_REGEX_BUDGET_SECONDS}s) — blocked (fail-closed, possible evasion via complexity)",
                                source="input_guardrail_budget",
                                severity="high",
                            )
                        )
                        # DOS-04: the final verdict is derived from max_severity, so the
                        # fail-closed BLOCK above is only honoured if we escalate severity.
                        # Without this, an early budget break (before any high-severity
                        # pattern matched) would collapse to WARN — a fail-OPEN regression.
                        if severity_rank["high"] > severity_rank[max_severity]:
                            max_severity = "high"
                        break
                if pattern.description in matched_descriptions:
                    continue
                # Skip disabled patterns (toggled off via admin)
                if _registry.available and _registry.is_disabled(pattern.pattern_id):
                    continue
                match = pattern.regex.search(text)
                if match:
                    matched_descriptions.add(pattern.description)
                    event = SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.BLOCK
                        if severity_rank[pattern.severity] >= 2
                        else Verdict.WARN,
                        category=pattern.category,
                        description=pattern.description,
                        source="input_guardrail",
                        severity=pattern.severity,
                        matched_pattern=match.group(0)[:200],
                    )
                    events.append(event)
                    if severity_rank[pattern.severity] > severity_rank[max_severity]:
                        max_severity = pattern.severity

            # Run custom patterns from admin
            if _registry.available:
                for compiled_re, meta in _registry.get_custom_patterns():
                    if meta["layer"] != "input":
                        continue
                    if meta["description"] in matched_descriptions:
                        continue
                    match = safe_regex_search(compiled_re, text)
                    if match:
                        matched_descriptions.add(meta["description"])
                        sev = meta.get("severity", "high")
                        cat_str = meta.get("category", "prompt_injection")
                        try:
                            cat = ThreatCategory(cat_str)
                        except ValueError:
                            cat = ThreatCategory.PROMPT_INJECTION
                        event = SecurityEvent(
                            tenant_id=tenant_id,
                            agent_id=agent_id,
                            verdict=Verdict.BLOCK if severity_rank.get(sev, 2) >= 2 else Verdict.WARN,
                            category=cat,
                            description=meta["description"],
                            source="input_guardrail_custom",
                            severity=sev,
                            matched_pattern=match.group(0)[:200],
                        )
                        events.append(event)
                        if severity_rank.get(sev, 2) > severity_rank[max_severity]:
                            max_severity = sev

        # Layer 4: Fuzzy/phonetic detection for typo and phonetic evasion
        # Only run if no blocks found yet (performance optimization)
        if not events or max_severity in ("low", "medium"):
            fuzzy_event = self._check_fuzzy_injection(clean, tenant_id, agent_id)
            if fuzzy_event:
                events.append(fuzzy_event)
                if severity_rank[fuzzy_event.severity] > severity_rank[max_severity]:
                    max_severity = fuzzy_event.severity

        if not events:
            return GuardrailResult(verdict=Verdict.ALLOW)

        verdict = Verdict.BLOCK if severity_rank[max_severity] >= 2 else Verdict.WARN
        return GuardrailResult(verdict=verdict, events=events)

    # --- Fuzzy/phonetic injection detection ---
    # Consonant skeleton: strip vowels and repeated chars to get word "shape"
    # "ignore" → "gnr", "ignroe" → "gnr", "eye-gnore" → "gnr"
    _CRITICAL_SKELETONS = {
        # keyword: consonant skeleton (lowercase, no vowels/hyphens, deduped)
        "gnr": "ignore",      # ignore, ignroe, gnore
        "ygnr": "ignore",     # eyegnore (phonetic)
        "nstrctns": "instruction",  # instructions
        "nstrctn": "instruction",   # instruction
        "nstrckshns": "instruction",  # innstruckshuns (phonetic)
        "strckshns": "instruction",   # struckshuns
        "prvs": "previous",   # previous, previus, preveeus
        "systm": "system",    # system, systme
        "sstm": "system",     # sis-tem (joined)
        "stm": "system",      # sistem (phonetic)
        "prmpt": "prompt",    # prompt, promtp
        "prmt": "prompt",     # promt
        "shw": "show",        # show, sohw
        "byps": "bypass",     # bypass
        "vrd": "override",    # override
        "vrrd": "override",   # override with double
        "dsbl": "disable",    # disable
    }

    @classmethod
    def _consonant_skeleton(cls, word: str) -> str:
        """Reduce word to consonant skeleton for fuzzy matching."""
        word = word.lower().strip(".,;:!?\"'()-")
        # Remove hyphens, vowels
        skeleton = re.sub(r"[aeiou\-]", "", word)
        # Deduplicate consecutive same chars
        skeleton = re.sub(r"(.)\1+", r"\1", skeleton)
        return skeleton

    def _check_fuzzy_injection(
        self, text: str, tenant_id: str, agent_id: str
    ) -> SecurityEvent | None:
        """Detect injection attempts using typos/phonetic evasion via consonant skeleton matching.

        Requires at least 3 critical keyword matches to trigger (reduces FP).
        """
        # Split into words but also keep hyphenated forms joined
        words_split = re.split(r"[\s/]+", text.lower())
        # Also dehyphenate for joined analysis
        words_joined = re.split(r"[\s/]+", text.lower().replace("-", ""))
        all_words = list(set(words_split + words_joined))

        if len(all_words) < 3:
            return None

        matched_keywords: list[str] = []
        for word in all_words:
            if len(word) < 3:
                continue
            skel = self._consonant_skeleton(word)
            if skel in self._CRITICAL_SKELETONS:
                matched_keywords.append(self._CRITICAL_SKELETONS[skel])

        # Need at least 3 distinct critical keywords to flag as injection
        unique_matches = set(matched_keywords)
        # High-confidence combos that indicate injection
        injection_combos = [
            {"ignore", "previous", "instruction"},
            {"ignore", "instruction", "system"},
            {"ignore", "instruction", "prompt"},
            {"bypass", "instruction", "system"},
            {"disable", "instruction", "system"},
            {"override", "instruction", "system"},
            {"show", "system", "prompt"},
            {"ignore", "previous", "show"},
        ]

        for combo in injection_combos:
            if combo.issubset(unique_matches):
                return SecurityEvent(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.BLOCK,
                    category=ThreatCategory.PROMPT_INJECTION,
                    description=f"Fuzzy/phonetic injection detected: {', '.join(sorted(combo))}",
                    source="input_guardrail.fuzzy",
                    severity="high",
                    matched_pattern=f"skeleton_match:{sorted(unique_matches)}",
                )
        return None

    def inspect_messages(
        self, messages: list[dict], tenant_id: str = "", agent_id: str = ""
    ) -> GuardrailResult:
        """Inspect all user messages in a conversation with cross-turn escalation detection
        and cumulative threat scoring.

        SECURITY FIX (CRIT-05): In addition to scanning individual messages, we now
        scan the CONCATENATED content of all messages. This prevents semantic splitting
        attacks where injection commands are divided across multiple messages (e.g.,
        "ignore all previous" in msg 1, "instructions" in msg 2).
        """
        all_events: list[SecurityEvent] = []
        final_verdict = Verdict.ALLOW

        # Collect user messages for cross-turn analysis
        user_contents: list[str] = []
        cumulative_score: float = 0.0

        # DOS-04: A single request carries the full conversation history. A padded
        # history of many large turns must not be able to pin a worker for seconds
        # (each per-message inspect() runs 400+ patterns × decode variants). We fully
        # inspect the most RECENT messages first — the live attack surface — under an
        # aggregate wall-clock budget. Older overflow content is NOT silently dropped
        # from detection: it is still covered by the capped concatenated split-attack
        # scan below. We intentionally do NOT fail-closed here: BLOCKing a legitimate
        # long conversation would be a worse (availability) failure than relying on the
        # concat scan for the tail. Operators can tune the budget via
        # BULWARK_GUARDRAIL_MESSAGES_BUDGET_SECONDS.
        import time as _time
        _msg_deadline = _time.monotonic() + self.messages_budget_seconds
        _scan_truncated = False

        # Determine inspection order: most-recent message first so the freshest
        # (and most attack-relevant) turns are always inspected within budget.
        indexed = [
            (i, m.get("role", "user"), m.get("content", ""))
            for i, m in enumerate(messages)
        ]
        for _pos, (_idx, role, content) in enumerate(reversed(indexed)):
            if not content:
                continue

            # Always record user turns (chronological order preserved) so cross-turn
            # escalation and the concatenated split-attack scan see the full history,
            # even for messages the per-message loop had to skip for latency.
            if role == "user":
                user_contents.append(content)

            # Budget guard: once the aggregate deadline is passed, stop the expensive
            # per-message inspection of older turns. The first (most recent) message is
            # always inspected regardless, so a single-turn request is never skipped.
            if _pos > 0 and _time.monotonic() > _msg_deadline:
                _scan_truncated = True
                continue

            # Inspect ALL roles — adversaries inject into system/tool/assistant messages
            result = self.inspect(content, tenant_id, agent_id)
            all_events.extend(result.events)
            if result.verdict == Verdict.BLOCK:
                final_verdict = Verdict.BLOCK
            elif result.verdict == Verdict.WARN and final_verdict == Verdict.ALLOW:
                final_verdict = Verdict.WARN

            # Cumulative scoring: each WARN event adds to running score
            for ev in result.events:
                if ev.severity == "critical":
                    cumulative_score += 1.0
                elif ev.severity == "high":
                    cumulative_score += 0.6
                elif ev.severity == "medium":
                    cumulative_score += 0.3
                elif ev.severity == "low":
                    cumulative_score += 0.1

        # Restore chronological order for cross-turn analysis (we collected newest-first).
        user_contents.reverse()

        # DOS-04: record (but do not alert on) the fact that we bounded the scan, so
        # operators retain an audit trail of partially-inspected oversized requests.
        if _scan_truncated:
            all_events.append(
                SecurityEvent(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.ALLOW,
                    category=ThreatCategory.DENIAL_OF_SERVICE,
                    description=(
                        f"Per-message scan budget ({self.messages_budget_seconds}s) reached; "
                        "older turns covered by concatenated scan only (DoS bound)"
                    ),
                    source="input_guardrail_msg_budget",
                    severity="low",
                )
            )

        # SECURITY FIX (CRIT-05): Scan concatenated messages to detect
        # semantic splitting attacks. If multiple messages exist, join them
        # and run inspection on the combined text. This catches injection
        # phrases split across messages that individually appear benign.
        if final_verdict != Verdict.BLOCK and len(user_contents) >= 2:
            concatenated = " ".join(user_contents)
            # DOS-04: cap the aggregate so a conversation of many large messages
            # cannot force a second full scan over hundreds of KB. Splitting attacks
            # rely on adjacency of the split phrase, which survives head truncation.
            if len(concatenated) > self.max_concat_bytes:
                concatenated = concatenated[: self.max_concat_bytes]
            concat_result = self.inspect(concatenated, tenant_id, agent_id)
            if concat_result.verdict == Verdict.BLOCK:
                # Add a specific event indicating the split was detected
                all_events.append(
                    SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.PROMPT_INJECTION,
                        description="Cross-message semantic splitting attack detected (concatenated scan)",
                        source="input_guardrail_concat",
                        severity="high",
                    )
                )
                all_events.extend(concat_result.events)
                final_verdict = Verdict.BLOCK
            elif concat_result.verdict == Verdict.WARN and final_verdict == Verdict.ALLOW:
                all_events.extend(concat_result.events)
                final_verdict = Verdict.WARN
                # Add concatenated WARN events to cumulative score
                for ev in concat_result.events:
                    if ev.severity == "critical":
                        cumulative_score += 1.0
                    elif ev.severity == "high":
                        cumulative_score += 0.6
                    elif ev.severity == "medium":
                        cumulative_score += 0.3
                    elif ev.severity == "low":
                        cumulative_score += 0.1

        # Cumulative threshold: if multiple turns contribute warnings, block
        if final_verdict != Verdict.BLOCK and cumulative_score >= 1.5:
            all_events.append(
                SecurityEvent(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.BLOCK,
                    category=ThreatCategory.PROMPT_INJECTION,
                    description=f"Cumulative threat score {cumulative_score:.1f} exceeds threshold (multi-turn escalation)",
                    source="input_guardrail_cumulative",
                    severity="high",
                )
            )
            final_verdict = Verdict.BLOCK

        # Cross-turn escalation: if earlier turn has attack context and later turn confirms action
        if final_verdict != Verdict.BLOCK and len(user_contents) >= 2:
            escalation_result = self._check_cross_turn_escalation(
                user_contents, tenant_id, agent_id
            )
            if escalation_result:
                all_events.extend(escalation_result)
                final_verdict = Verdict.BLOCK

        return GuardrailResult(verdict=final_verdict, events=all_events)

    # Attack topic indicators for turn 1
    _ATTACK_TOPIC_RE = re.compile(
        r"(reverse\s*shell|inject|exploit|hack|bypass|exfiltrat|backdoor|"
        r"credential|password|privilege\s*escalat|unauthorized|steal|"
        r"malware|payload|vulnerability|attack|data\s*leak|"
        r"disable.*security|override.*safety|ignore.*instruction|"
        r"system\s*prompt|admin\s*access|root\s*access|"
        r"PII|sensitive\s*data|confidential|classified|"
        r"jailbreak|DAN|safety\s*measures?|security\s*research|"
        r"SSRF|SQL\s*inject|XSS|rate\s*limit|"
        r"multi.?tenan|authenticat|firewall|encrypt|"
        r"zero\s*trust|attack\s*vector|security\s*polic|"
        r"architecture|commands?\s+(can|do)\s+you|tools?\s+(do|can)\s+you|"
        r"tokens?\s+(work|generat)|logs?\s+(do|keep)|secrets?\s+(store|keep)|"
        r"continu(ing|e)\s+(from|where)|left\s+off|where\s+we\s+(stopped|were)|"
        r"as\s+we\s+(discussed|agreed|planned)|picking\s+up\s+(from|where))",
        re.I,
    )
    # Action confirmation indicators for turn 2+
    _ESCALATION_CONFIRM_RE = re.compile(
        r"(now\s+)?(actually|really|for\s+real)\s+(do|execute|run|perform|apply|show)|"
        r"(go\s+ahead|proceed|confirm)\s+(and\s+)?(run|do|execute|extract|with)|"
        r"(do|execute|run|apply|show)\s+(it|that|this)\s+(for\s+real|without|on\s+prod)|"
        r"(now\s+)?(do|run|execute|apply|show)\s+(it|that|this|me)\s*(now|please|how)?$|"
        r"without\s+(the\s+)?(safety|security)\s*(checks?|filters?|limits?)|"
        r"(execute|run)\s+the\s+(plan|command|script)\s+we\s+(discussed|talked)|"
        r"(now\s+)?(apply|run)\s+(that|this|it)\s+(to|on|against)\s+(the\s+)?(prod|real|live|actual)|"
        r"(perfect|great|good|ok|nice)[.,!]?\s*(now\s+)?(do|run|execute|apply)|"
        r"do\s+it\s+for\s+real|"
        r"proceed\s+with\s+(the\s+)?(extraction|attack|exploit|hack|injection)",
        re.I,
    )

    def _check_cross_turn_escalation(
        self, turns: list[str], tenant_id: str, agent_id: str
    ) -> list[SecurityEvent]:
        """Detect escalation across conversation turns."""
        # Check if any earlier turn has attack-related context
        has_attack_context = any(self._ATTACK_TOPIC_RE.search(t) for t in turns[:-1])
        if not has_attack_context:
            return []

        # Check if the last turn is an action confirmation
        last_turn = turns[-1]
        if self._ESCALATION_CONFIRM_RE.search(last_turn):
            return [
                SecurityEvent(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.BLOCK,
                    category=ThreatCategory.PROMPT_INJECTION,
                    description="Multi-turn escalation: attack topic + action confirmation",
                    source="input_guardrail_multiturn",
                    severity="high",
                )
            ]
        return []
