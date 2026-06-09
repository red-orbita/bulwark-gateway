"""
MCP Tool Poisoning Detection — Sentinel Gateway SkillSpector Integration

Detects attempts to inject hidden instructions, deceptive text, or malicious
metadata into MCP tool definitions. Attacks target the LLM that reads tool
descriptions, not the end user.

Detection categories:
  TP1: Hidden Instructions — HTML comments, zero-width chars, base64, data URIs
  TP2: Unicode Deception — homoglyphs, RTL overrides, mixed-script identifiers
  TP3: Parameter Description Injection — override tokens, system prompts in params
  TP4: Description-Behavior Mismatch — contradictory claims indicating deception

Adapted from opencode-security-agent for use within Sentinel Gateway's
SkillSpector hybrid scanner. No additional dependencies beyond PyYAML (already
present in admin service).
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# TP1: Hidden Instructions patterns
# ---------------------------------------------------------------------------

_HTML_COMMENT = re.compile(r"<!--[\s\S]*?-->")

_ZERO_WIDTH_CHARS = re.compile(
    "[\u200B\u200C\u200D\u200E\u200F"
    "\u2060\u2061\u2062\u2063\u2064"
    "\uFEFF"
    "\U000E0000-\U000E007F"
    "\U000E0100-\U000E01EF"
    "]"
)

_BASE64_BLOCK = re.compile(
    r"(?:base64[,:]?\s*|data:[^;]+;base64,)([A-Za-z0-9+/=]{40,})"
)

_BASE64_STANDALONE = re.compile(r"\b[A-Za-z0-9+/]{60,}={0,2}\b")

_DATA_URI = re.compile(r"data:[a-z]+/[a-z]+;base64,[A-Za-z0-9+/=]+", re.IGNORECASE)

_TAG_ENCODING = re.compile("[\U000E0020-\U000E007E]+")


# ---------------------------------------------------------------------------
# TP2: Unicode Deception patterns
# ---------------------------------------------------------------------------

_RTL_OVERRIDES = re.compile("[\u202A-\u202E\u2066-\u2069]")

_HOMOGLYPHS = {
    "\u0430": "a", "\u0435": "e", "\u043E": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0458": "j", "\u04BB": "h", "\u0501": "d", "\u051B": "q",
    "\u0261": "g", "\u01C3": "!", "\uFF41": "a", "\uFF42": "b",
}

_HOMOGLYPH_CHARS = re.compile("[" + "".join(_HOMOGLYPHS.keys()) + "]")

_CYRILLIC = re.compile(r"[\u0400-\u04FF]")
_LATIN = re.compile(r"[a-zA-Z]")


# ---------------------------------------------------------------------------
# TP3: Parameter Description Injection
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS = [
    re.compile(r"(?:system|instruction|prompt)\s*(?:override|:)", re.IGNORECASE),
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+(?:are|must|should|will)\s+now", re.IGNORECASE),
    re.compile(r"disregard\s+(?:all|any)\s+(?:prior|previous)", re.IGNORECASE),
    re.compile(r"new\s+(?:system\s+)?instructions?\s*:", re.IGNORECASE),
    re.compile(r"(?:IMPORTANT|NOTE|WARNING):\s*(?:always|never|must|do not)", re.IGNORECASE),
    re.compile(r"(?:secret|hidden)\s+(?:instruction|command|directive)", re.IGNORECASE),
    re.compile(r"<\|(?:im_start|im_end|system|endoftext)\|>"),
    re.compile(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>"),
    re.compile(
        r"default\s*(?:value)?\s*[:=]\s*['\"].*(?:curl|wget|nc\s|bash|eval|exec)",
        re.IGNORECASE,
    ),
]


# ---------------------------------------------------------------------------
# TP4: Description-Behavior Mismatch indicators
# ---------------------------------------------------------------------------

_DECEPTION_KEYWORDS = [
    re.compile(
        r"(?:harmless|safe|simple|basic)\s+(?:helper|tool|utility)",
        re.IGNORECASE,
    ),
    re.compile(
        r"does\s+not\s+(?:access|read|write|send|execute).*(?:but|however|also)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:formatter|linter|validator|beautifier).*(?:network|http|socket|exec)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:replaces?|overrides?|intercepts?|hooks?)\s+(?:built-?in|default|native)",
        re.IGNORECASE,
    ),
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _decode_base64_safe(data: str) -> Optional[str]:
    """Try to decode base64 and check if it contains suspicious keywords."""
    try:
        decoded = base64.b64decode(data).decode("utf-8", errors="replace")
        suspicious = (
            "exec", "eval", "system", "curl", "wget", "ignore", "override",
            "instruction", "secret", "password", "token", "key",
        )
        if any(kw in decoded.lower() for kw in suspicious):
            return decoded
    except Exception:
        pass
    return None


def _check_mixed_scripts(text: str) -> list[str]:
    """Detect words with mixed Latin + Cyrillic characters."""
    mixed = []
    for word in re.findall(r"\b\w+\b", text):
        if len(word) > 2 and bool(_CYRILLIC.search(word)) and bool(_LATIN.search(word)):
            mixed.append(word)
    return mixed


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_text(text: str, context: str = "tool_description") -> list[dict[str, Any]]:
    """
    Analyze text for MCP tool poisoning patterns.

    Args:
        text: Content to scan (tool description, parameter description, etc.)
        context: Label for where this text comes from

    Returns:
        List of finding dicts with: rule_id, severity, message, confidence, pattern
    """
    findings: list[dict[str, Any]] = []

    # --- TP1: Hidden Instructions ---

    for match in _HTML_COMMENT.finditer(text):
        comment_content = match.group().strip("<!->- \n\t")
        if len(comment_content) > 5:
            findings.append({
                "rule_id": "SEN-MCP-TP1",
                "severity": "high",
                "message": f"Hidden HTML comment in {context}: '{comment_content[:80]}...'",
                "confidence": 88,
                "pattern": "html_comment",
                "category": "mcp_poisoning",
            })

    zw_matches = _ZERO_WIDTH_CHARS.findall(text)
    if zw_matches:
        findings.append({
            "rule_id": "SEN-MCP-TP1",
            "severity": "high",
            "message": (
                f"Zero-width/invisible characters in {context} "
                f"({len(zw_matches)} hidden chars)"
            ),
            "confidence": 92,
            "pattern": "zero_width",
            "category": "mcp_poisoning",
        })

    for match in _BASE64_BLOCK.finditer(text):
        decoded = _decode_base64_safe(match.group(1))
        if decoded:
            findings.append({
                "rule_id": "SEN-MCP-TP1",
                "severity": "high",
                "message": (
                    f"Base64-encoded instructions in {context}: "
                    f"decoded contains '{decoded[:60]}...'"
                ),
                "confidence": 90,
                "pattern": "base64_instructions",
                "category": "mcp_poisoning",
            })

    for match in _BASE64_STANDALONE.finditer(text):
        decoded = _decode_base64_safe(match.group())
        if decoded:
            findings.append({
                "rule_id": "SEN-MCP-TP1",
                "severity": "high",
                "message": (
                    f"Hidden base64 payload in {context}: "
                    f"decodes to '{decoded[:60]}...'"
                ),
                "confidence": 85,
                "pattern": "base64_hidden",
                "category": "mcp_poisoning",
            })

    for match in _DATA_URI.finditer(text):
        findings.append({
            "rule_id": "SEN-MCP-TP1",
            "severity": "medium",
            "message": f"Data URI in {context} may hide instructions",
            "confidence": 70,
            "pattern": "data_uri",
            "category": "mcp_poisoning",
        })

    tag_matches = _TAG_ENCODING.findall(text)
    if tag_matches:
        decoded_parts = [
            "".join(chr(ord(c) - 0xE0000) for c in m) for m in tag_matches
        ]
        if any(len(d) > 3 for d in decoded_parts):
            findings.append({
                "rule_id": "SEN-MCP-TP1",
                "severity": "critical",
                "message": (
                    f"Unicode Tags block encoding in {context}: "
                    f"hidden text '{' '.join(decoded_parts)[:60]}'"
                ),
                "confidence": 95,
                "pattern": "tag_encoding",
                "category": "mcp_poisoning",
            })

    # --- TP2: Unicode Deception ---

    rtl_matches = _RTL_OVERRIDES.findall(text)
    if rtl_matches:
        findings.append({
            "rule_id": "SEN-MCP-TP2",
            "severity": "high",
            "message": (
                f"RTL override characters in {context} "
                f"({len(rtl_matches)} found) — can reverse displayed text"
            ),
            "confidence": 90,
            "pattern": "rtl_override",
            "category": "mcp_poisoning",
        })

    homoglyph_matches = _HOMOGLYPH_CHARS.findall(text)
    if homoglyph_matches:
        substitutions = [
            f"'{c}'->'{_HOMOGLYPHS[c]}'" for c in homoglyph_matches[:5]
        ]
        findings.append({
            "rule_id": "SEN-MCP-TP2",
            "severity": "high",
            "message": (
                f"Homoglyph characters in {context}: "
                f"{', '.join(substitutions)} ({len(homoglyph_matches)} total)"
            ),
            "confidence": 85,
            "pattern": "homoglyph",
            "category": "mcp_poisoning",
        })

    mixed_words = _check_mixed_scripts(text)
    if mixed_words:
        findings.append({
            "rule_id": "SEN-MCP-TP2",
            "severity": "high",
            "message": (
                f"Mixed-script identifiers in {context}: "
                f"{', '.join(mixed_words[:5])}"
            ),
            "confidence": 88,
            "pattern": "mixed_script",
            "category": "mcp_poisoning",
        })

    # --- TP3: Parameter Description Injection ---

    for pattern in _INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            sev = "high" if "override" in match.group().lower() else "medium"
            findings.append({
                "rule_id": "SEN-MCP-TP3",
                "severity": sev,
                "message": f"Injection pattern in {context}: '{match.group()}'",
                "confidence": 82,
                "pattern": "description_injection",
                "category": "mcp_poisoning",
            })

    # --- TP4: Description-Behavior Mismatch ---

    for pattern in _DECEPTION_KEYWORDS:
        match = pattern.search(text)
        if match:
            findings.append({
                "rule_id": "SEN-MCP-TP4",
                "severity": "medium",
                "message": f"Potential description-behavior mismatch: '{match.group()}'",
                "confidence": 65,
                "pattern": "behavior_mismatch",
                "category": "mcp_poisoning",
            })

    return findings


def analyze_manifest(data: dict[str, Any], source: str = "") -> list[dict[str, Any]]:
    """
    Analyze a parsed MCP manifest/tool definition for poisoning.

    Scans tool names, descriptions, and parameter descriptions.

    Args:
        data: Parsed JSON/YAML dict (tool definitions)
        source: Source path/label for findings

    Returns:
        List of finding dicts
    """
    findings: list[dict[str, Any]] = []

    # Scan tool definitions
    tools = data.get("tools", data.get("functions", []))
    if isinstance(tools, dict):
        tools = list(tools.values())

    for i, tool in enumerate(tools if isinstance(tools, list) else []):
        if not isinstance(tool, dict):
            continue

        tool_name = tool.get("name", f"tool_{i}")

        # Scan tool description
        desc = tool.get("description", "")
        if desc:
            desc_findings = analyze_text(desc, f"tool '{tool_name}' description")
            for f in desc_findings:
                f["file"] = source
                f["tool_name"] = tool_name
            findings.extend(desc_findings)

        # Scan parameter descriptions
        params = tool.get("parameters", tool.get("inputSchema", {}))
        if isinstance(params, dict):
            properties = params.get("properties", {})
            for param_name, param_def in properties.items():
                if isinstance(param_def, dict):
                    param_desc = param_def.get("description", "")
                    if param_desc:
                        param_findings = analyze_text(
                            param_desc, f"tool '{tool_name}' param '{param_name}'"
                        )
                        for f in param_findings:
                            f["file"] = source
                            f["tool_name"] = tool_name
                            f["parameter"] = param_name
                        findings.extend(param_findings)

    return findings


def analyze_content(content: str, source: str = "") -> list[dict[str, Any]]:
    """
    Analyze raw content (text/YAML/JSON) for MCP poisoning.

    Tries structured analysis first (JSON/YAML), then falls back to raw text.
    """
    findings: list[dict[str, Any]] = []

    # Try parsing as JSON for structured tool analysis
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            findings.extend(analyze_manifest(data, source))
    except (json.JSONDecodeError, ValueError):
        pass

    # Always run raw text analysis (catches things structure parse misses)
    text_findings = analyze_text(content, f"content '{source}'")
    for f in text_findings:
        f["file"] = source
    findings.extend(text_findings)

    # Deduplicate by message prefix
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for f in findings:
        key = f"{f['rule_id']}:{f['message'][:60]}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


# Pattern count for status reporting
PATTERN_COUNT = len(_INJECTION_PATTERNS) + len(_DECEPTION_KEYWORDS) + 6  # +6 for TP1/TP2 checks
