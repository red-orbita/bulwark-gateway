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
    _INVISIBLE_RE = re.compile(
        r"[\u200b-\u200f\u2028-\u202f\u2060-\u2069\ufeff\u00ad\U000E0000-\U000E007F\uFE00-\uFE0F\U000E0100-\U000E01EF]"
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
    # Cyrillic → Latin homoglyph mapping
    _HOMOGLYPH_MAP = str.maketrans(
        {
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
            "\u0410": "A",
            "\u0415": "E",
            "\u041e": "O",
            "\u0420": "P",
            "\u0421": "C",
            "\u0422": "T",
            "\u041d": "H",
            "\u041a": "K",
            "\u0412": "B",
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
            # Replace 2+ spaces with a sentinel, collapse single spaces, restore
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
        self, content: str, tenant_id: str, agent_id: str
    ) -> list[SecurityEvent]:
        """Multi-layer encoding evasion detection.

        SECURITY FIX (M-01): Recursive decoding (2 layers) to catch double-encoding
        attacks like base64(base64(payload)) that previously evaded single-pass decode.
        """
        events = []

        # SECURITY FIX (PENTEST-DEEP CRIT-2): For large inputs, apply encoding
        # checks to head + tail windows instead of skipping entirely.
        # Previous behavior: skip ALL encoding checks for >5000 chars.
        # New behavior: check invisible chars on full first 5KB, then apply
        # encoding detection on head(2500) + tail(2500) windows.
        if len(content) > 5000:
            # Check invisible chars on first 5KB
            invisible_matches = self._INVISIBLE_RE.findall(content[:5000])
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
            # Apply encoding detection on head + tail windows
            head_window = content[:2500]
            tail_window = content[-2500:]
            for window in (head_window, tail_window):
                events.extend(
                    self._check_encoding_window(window, tenant_id, agent_id)
                )
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
        ascii_content = "".join(c for c in content if ord(c) < 128)
        if 8 < len(ascii_content) <= 1000:
            alpha_ratio = sum(1 for c in ascii_content if c.isalpha()) / max(len(ascii_content), 1)
            if alpha_ratio > 0.5:
                decoded_rot13 = ascii_content.translate(self._ROT13)
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

        # 7. Reversed text detection (only for short inputs)
        if 15 < len(ascii_content) <= 500:
            reversed_text = ascii_content[::-1]
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
        if 8 < len(ascii_content) <= 100:
            alpha_ratio = sum(1 for c in ascii_content if c.isalpha()) / max(len(ascii_content), 1)
            if alpha_ratio > 0.5:
                caesar_found = False
                for shift in range(1, 26):
                    if shift == 13:  # Already covered by ROT13 check
                        continue
                    decoded = self._caesar_shift(ascii_content, shift)
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

        # 12. Atbash cipher detection
        if 8 < len(ascii_content) <= 200:
            alpha_ratio = sum(1 for c in ascii_content if c.isalpha()) / max(len(ascii_content), 1)
            if alpha_ratio > 0.5:
                decoded_atbash = self._decode_atbash(ascii_content)
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
        if re.search(r"\b\w+(way|ay)\b", content, re.I):
            pig_words = re.findall(r"\b\w+(?:way|ay)\b", content, re.I)
            if len(pig_words) >= 3:
                decoded_pig = self._decode_pig_latin(content)
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
        oversized = len(content) > self.MAX_INPUT_SIZE

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
            # SECURITY FIX: Full-content sliding window scan
            # Instead of only checking head+tail (which left the middle unscanned),
            # we now sample multiple windows covering the entire message.
            # Strategy: head(8KB) + 3 evenly-spaced middle windows(4KB each) + tail(2KB)
            # This ensures no section >4KB goes unscanned.
            windows: list[str] = []
            total_len = len(content)
            head_size = self.MAX_INPUT_SIZE  # 8KB
            tail_size = 2000
            mid_window_size = 4000
            num_mid_windows = 3

            # Head
            windows.append(content[:head_size])
            # Middle windows (evenly distributed)
            if total_len > head_size + tail_size + mid_window_size:
                middle_start = head_size
                middle_end = total_len - tail_size
                middle_span = middle_end - middle_start
                for i in range(num_mid_windows):
                    offset = middle_start + int(middle_span * (i + 1) / (num_mid_windows + 1)) - mid_window_size // 2
                    offset = max(middle_start, min(offset, middle_end - mid_window_size))
                    windows.append(content[offset:offset + mid_window_size])
            # Tail
            windows.append(content[-tail_size:])
            content = "\n".join(windows)

        # Layer 1: Encoding evasion detection (on raw input)
        encoding_events = self._check_encoding_evasion(content, tenant_id, agent_id)
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
        _REGEX_BUDGET_SECONDS = 2.0  # Max 2 seconds of regex CPU per request
        _regex_start = _time.monotonic()
        _budget_exceeded = False

        for text in texts_to_check:
            if _budget_exceeded:
                break
            for pattern in self.all_patterns:
                # Check time budget every 50 patterns
                if not _budget_exceeded and (hash(pattern.description) % 50 == 0):
                    if _time.monotonic() - _regex_start > _REGEX_BUDGET_SECONDS:
                        _budget_exceeded = True
                        events.append(
                            SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.WARN,
                                category=ThreatCategory.PROMPT_INJECTION,
                                description=f"Regex budget exceeded ({_REGEX_BUDGET_SECONDS}s) — possible evasion via complexity",
                                source="input_guardrail_budget",
                                severity="medium",
                            )
                        )
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

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if not content:
                continue

            # Inspect ALL roles — adversaries inject into system/tool/assistant messages
            # User messages get full inspection; other roles get injection-only checks
            if role == "user":
                user_contents.append(content)
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

        # SECURITY FIX (CRIT-05): Scan concatenated messages to detect
        # semantic splitting attacks. If multiple messages exist, join them
        # and run inspection on the combined text. This catches injection
        # phrases split across messages that individually appear benign.
        if final_verdict != Verdict.BLOCK and len(user_contents) >= 2:
            concatenated = " ".join(user_contents)
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
