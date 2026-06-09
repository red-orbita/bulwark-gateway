"""
Sentinel Skill Scanner — SkillSpector integration + Sentinel-specific patterns.

Architecture:
  1. Primary engine: NVIDIA SkillSpector (64 patterns, AST, taint tracking, YARA, OSV.dev)
  2. MCP Security: Tool Poisoning detection (hidden instructions, unicode, injection)
  3. MCP Security: Least Privilege analysis (declared permissions vs actual code)
  4. Overlay: Sentinel-specific patterns (IOC, credential, policy, cross-agent)
  5. Fallback: Built-in regex scanner if SkillSpector is unavailable

The combined scanner provides deeper coverage than either engine alone:
  - SkillSpector: code-level analysis (AST, taint flow, YARA sigs, CVE lookups)
  - MCP Poisoning: detects attacks on tool DEFINITIONS that target the LLM
  - MCP Privilege: validates permissions match actual code capabilities
  - Sentinel overlay: config/policy-level analysis (sandbox escape, agent injection, IOC)

All analysis is static (use_llm=False) — no LLM calls during scanning.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml

from admin.services.mcp_poisoning import (
    analyze_content as mcp_poisoning_analyze,
    PATTERN_COUNT as MCP_POISONING_PATTERNS,
)
from admin.services.mcp_privilege import (
    analyze_content as mcp_privilege_analyze,
    analyze_directory as mcp_privilege_analyze_dir,
    PATTERN_COUNT as MCP_PRIVILEGE_PATTERNS,
)

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════
# SkillSpector availability check
# ═══════════════════════════════════════════════════════════════════

_SKILLSPECTOR_AVAILABLE = False
_SKILLSPECTOR_VERSION = "unavailable"

try:
    from skillspector import graph as _skillspector_graph
    import importlib.metadata
    _SKILLSPECTOR_AVAILABLE = True
    try:
        _SKILLSPECTOR_VERSION = importlib.metadata.version("skillspector")
    except importlib.metadata.PackageNotFoundError:
        _SKILLSPECTOR_VERSION = "unknown"
    logger.info("SkillSpector %s loaded — full engine available", _SKILLSPECTOR_VERSION)
except ImportError:
    _skillspector_graph = None  # type: ignore[assignment]
    logger.info("SkillSpector not installed — using built-in scanner only")


# ═══════════════════════════════════════════════════════════════════
# Configuration via environment
# ═══════════════════════════════════════════════════════════════════

SKILLSPECTOR_ENABLED = os.getenv("SENTINEL_SKILLSPECTOR_ENABLED", "true").lower() == "true"
SKILLSPECTOR_BLOCK_THRESHOLD = float(os.getenv("SENTINEL_SKILLSPECTOR_BLOCK_THRESHOLD", "7.0"))
SKILLSPECTOR_WARN_THRESHOLD = float(os.getenv("SENTINEL_SKILLSPECTOR_WARN_THRESHOLD", "4.0"))
SKILLSPECTOR_CACHE_TTL = int(os.getenv("SENTINEL_SKILLSPECTOR_CACHE_TTL", "300"))
SKILLSPECTOR_TIMEOUT = int(os.getenv("SENTINEL_SKILLSPECTOR_TIMEOUT", "60"))

_VERSION = "2.1.0-sentinel"


# ═══════════════════════════════════════════════════════════════════
# Data models
# ═══════════════════════════════════════════════════════════════════

class RiskSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanVerdict(str, Enum):
    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"
    ERROR = "error"


@dataclass
class SkillFinding:
    """Individual vulnerability finding."""
    rule_id: str
    message: str
    severity: RiskSeverity
    confidence: float = 0.0
    location: str = ""
    tags: list[str] = field(default_factory=list)
    category: str = ""
    source: str = ""  # "skillspector" or "sentinel"


@dataclass
class ScanResult:
    """Complete scan result for a skill definition."""
    scan_id: str
    timestamp: str
    risk_score: float
    risk_severity: RiskSeverity
    verdict: ScanVerdict
    findings: list[SkillFinding] = field(default_factory=list)
    recommendation: str = ""
    scan_duration_ms: float = 0.0
    scanner_version: str = _VERSION
    input_path: str = ""
    error: str = ""
    engine: str = ""  # "skillspector+sentinel", "sentinel-builtin", "disabled"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk_severity"] = self.risk_severity.value
        d["verdict"] = self.verdict.value
        d["findings"] = [
            {**asdict(f), "severity": f.severity.value}
            for f in self.findings
        ]
        return d


# ═══════════════════════════════════════════════════════════════════
# Sentinel-specific overlay rules (complement SkillSpector's 64)
# These catch agent-config-level risks that SkillSpector doesn't cover
# ═══════════════════════════════════════════════════════════════════

@dataclass
class _Rule:
    """A single Sentinel detection rule."""
    id: str
    category: str
    severity: RiskSeverity
    message: str
    pattern: re.Pattern
    score: float  # Points added (on 0-10 scale)
    confidence: float = 0.9
    tags: list[str] = field(default_factory=list)
    target: str = "both"  # "keys", "values", "both"


_SENTINEL_RULES: list[_Rule] = [
    # ── Tool Poisoning (TP) ──────────────────────────────────────
    _Rule(
        id="SEN-TP-001", category="tool_abuse", severity=RiskSeverity.CRITICAL,
        message="Dangerous tool declared: shell/bash/command execution",
        pattern=re.compile(
            r"\b(run_command|exec|shell|bash|system|subprocess|os\.system|popen|spawn)\b", re.I
        ),
        score=3.0, tags=["OWASP-LLM08", "MITRE-T1059"], target="both",
    ),
    _Rule(
        id="SEN-TP-002", category="tool_abuse", severity=RiskSeverity.HIGH,
        message="File write/delete tool declared without restrictions",
        pattern=re.compile(
            r"\b(write_file|delete_file|remove_file|create_file|overwrite|unlink|rmtree)\b", re.I
        ),
        score=2.5, tags=["OWASP-LLM08"], target="both",
    ),
    _Rule(
        id="SEN-TP-003", category="tool_abuse", severity=RiskSeverity.HIGH,
        message="Code evaluation tool declared (eval/compile/exec)",
        pattern=re.compile(
            r"\b(eval|compile|exec_code|run_python|execute_script|dynamic_eval)\b", re.I
        ),
        score=2.5, tags=["OWASP-LLM08", "MITRE-T1059.006"], target="both",
    ),
    _Rule(
        id="SEN-TP-004", category="tool_abuse", severity=RiskSeverity.MEDIUM,
        message="Database modification tool without apparent safeguards",
        pattern=re.compile(
            r"\b(drop_table|truncate|delete_all|db_execute|raw_sql|sql_exec)\b", re.I
        ),
        score=2.0, tags=["OWASP-LLM08"], target="both",
    ),

    # ── Privilege Escalation (PE) ────────────────────────────────
    _Rule(
        id="SEN-PE-001", category="privilege_escalation", severity=RiskSeverity.CRITICAL,
        message="Privilege escalation indicator: sudo/root/admin access",
        pattern=re.compile(
            r"\b(sudo|run_as_root|admin_mode|elevate_privileges|setuid|chmod\s+[47])\b", re.I
        ),
        score=3.0, tags=["MITRE-T1548"], target="both",
    ),
    _Rule(
        id="SEN-PE-002", category="privilege_escalation", severity=RiskSeverity.HIGH,
        message="Permission override or sandbox escape pattern",
        pattern=re.compile(
            r"\b(bypass_sandbox|disable_guardrail|override_policy|skip_validation|no_restrict)\b", re.I
        ),
        score=2.5, tags=["OWASP-LLM08"], target="both",
    ),
    _Rule(
        id="SEN-PE-003", category="privilege_escalation", severity=RiskSeverity.MEDIUM,
        message="Unrestricted permissions declared (allow_all / wildcard)",
        pattern=re.compile(
            r"(allow_all|permissions?\s*:\s*\*|tools?\s*:\s*\*|\"?\*\"?\s*$)", re.I | re.M
        ),
        score=2.0, tags=["OWASP-LLM09"], target="both",
    ),

    # ── Data Exfiltration (DE) ───────────────────────────────────
    _Rule(
        id="SEN-DE-001", category="exfiltration", severity=RiskSeverity.HIGH,
        message="Outbound URL/webhook in skill configuration",
        pattern=re.compile(
            r"https?://(?!localhost|127\.0\.0\.1|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)"
            r"[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}",
            re.I
        ),
        score=1.5, tags=["MITRE-T1041"], target="values",
    ),
    _Rule(
        id="SEN-DE-002", category="exfiltration", severity=RiskSeverity.HIGH,
        message="Data extraction pattern (send/upload/exfil/post to external)",
        pattern=re.compile(
            r"\b(exfiltrate|send_data|upload_file|post_external|transmit|smuggle)\b", re.I
        ),
        score=2.5, tags=["MITRE-T1041"], target="both",
    ),

    # ── Prompt Injection (PI) ────────────────────────────────────
    _Rule(
        id="SEN-PI-001", category="prompt_injection", severity=RiskSeverity.HIGH,
        message="Prompt injection vector in system prompt or description",
        pattern=re.compile(
            r"(ignore\s+(previous|all|above)\s+(instructions?|rules?|prompts?)|"
            r"you\s+are\s+now\s+|new\s+instructions?\s*:|"
            r"forget\s+(everything|your|all)|override\s+system)",
            re.I
        ),
        score=2.5, tags=["OWASP-LLM01", "MITRE-T1190"], target="values",
    ),
    _Rule(
        id="SEN-PI-002", category="prompt_injection", severity=RiskSeverity.MEDIUM,
        message="Role manipulation pattern in skill definition",
        pattern=re.compile(
            r"(act\s+as\s+(admin|root|unrestricted)|"
            r"pretend\s+(you\s+are|to\s+be)|"
            r"roleplay\s+as|assume\s+the\s+role)",
            re.I
        ),
        score=1.5, tags=["OWASP-LLM01"], target="values",
    ),

    # ── Credential Access (CA) ───────────────────────────────────
    _Rule(
        id="SEN-CA-001", category="credential_access", severity=RiskSeverity.CRITICAL,
        message="Hardcoded credential or API key in skill definition",
        pattern=re.compile(
            r"(api[_-]?key|password|secret|token|credential)\s*[:=]\s*['\"]?[A-Za-z0-9+/=_\-]{16,}",
            re.I
        ),
        score=3.0, tags=["MITRE-T1552", "CWE-798"], target="values",
    ),
    _Rule(
        id="SEN-CA-002", category="credential_access", severity=RiskSeverity.HIGH,
        message="AWS/GCP/Azure credential pattern detected",
        pattern=re.compile(
            r"(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|"
            r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})",
        ),
        score=2.5, tags=["MITRE-T1552.005"], target="values",
    ),

    # ── Reverse Shell / RCE (RC) ─────────────────────────────────
    _Rule(
        id="SEN-RC-001", category="reverse_shell", severity=RiskSeverity.CRITICAL,
        message="Reverse shell or remote code execution pattern",
        pattern=re.compile(
            r"(nc\s+-[elp]|/dev/tcp/|bash\s+-i|mkfifo|ncat|socat\s+exec|"
            r"python.*socket.*connect|curl.*\|\s*sh|wget.*\|\s*bash)",
            re.I
        ),
        score=3.5, tags=["MITRE-T1059", "MITRE-T1090"], target="both",
    ),

    # ── Excessive Agency (EA) ────────────────────────────────────
    _Rule(
        id="SEN-EA-001", category="excessive_agency", severity=RiskSeverity.MEDIUM,
        message="No tool restrictions defined (excessive agency risk)",
        pattern=re.compile(
            r"(allowed_tools\s*:\s*\[\s*\]|denied_tools\s*:\s*\[\s*\]|"
            r"sandbox_level\s*:\s*['\"]?none['\"]?)",
            re.I
        ),
        score=1.5, tags=["OWASP-LLM08", "OWASP-LLM09"], target="both",
    ),
    _Rule(
        id="SEN-EA-002", category="excessive_agency", severity=RiskSeverity.HIGH,
        message="Autonomous execution without human approval indicated",
        pattern=re.compile(
            r"(auto_execute|no_confirmation|skip_approval|autonomous_mode|"
            r"human_in_loop\s*:\s*(false|no|0))",
            re.I
        ),
        score=2.0, tags=["OWASP-LLM09"], target="both",
    ),

    # ── Cross-Agent Injection (CS) ───────────────────────────────
    _Rule(
        id="SEN-CS-001", category="cross_agent_injection", severity=RiskSeverity.HIGH,
        message="Inter-agent message passing without validation",
        pattern=re.compile(
            r"\b(forward_to_agent|relay_message|inject_prompt|propagate|"
            r"send_to_all_agents|broadcast_instruction)\b",
            re.I
        ),
        score=2.0, tags=["cross-agent"], target="both",
    ),

    # ── Memory Manipulation (MP) ─────────────────────────────────
    _Rule(
        id="SEN-MP-001", category="memory_manipulation", severity=RiskSeverity.HIGH,
        message="Vector store / RAG manipulation pattern",
        pattern=re.compile(
            r"\b(overwrite_memory|poison_index|inject_embedding|"
            r"modify_vector_store|corrupt_rag|tamper_context)\b",
            re.I
        ),
        score=2.5, tags=["memory-poisoning"], target="both",
    ),

    # ── Path Traversal / SSRF ────────────────────────────────────
    _Rule(
        id="SEN-PT-001", category="exfiltration", severity=RiskSeverity.HIGH,
        message="Path traversal pattern in configuration",
        pattern=re.compile(r"\.\./|\.\.\\|%2e%2e[/\\]", re.I),
        score=2.0, tags=["CWE-22", "MITRE-T1083"], target="values",
    ),
    _Rule(
        id="SEN-PT-002", category="exfiltration", severity=RiskSeverity.HIGH,
        message="Cloud metadata endpoint access (SSRF risk)",
        pattern=re.compile(
            r"(169\.254\.169\.254|metadata\.google|metadata\.azure|"
            r"100\.100\.100\.200|fd00:ec2::254)",
            re.I
        ),
        score=2.5, tags=["SSRF", "MITRE-T1552.005"], target="values",
    ),

    # ── IOC Indicators (Sentinel-exclusive) ──────────────────────
    _Rule(
        id="SEN-IOC-001", category="malicious_domain", severity=RiskSeverity.HIGH,
        message="Known malicious TLD or suspicious domain pattern",
        pattern=re.compile(
            r"https?://[^/]*\.(tk|ml|ga|cf|gq|top|xyz|buzz|zip|mov|work)\b",
            re.I
        ),
        score=2.0, tags=["IOC", "MITRE-T1071"], target="values",
    ),
    _Rule(
        id="SEN-IOC-002", category="malicious_domain", severity=RiskSeverity.HIGH,
        message="IP address URL (potential C2 or data exfil endpoint)",
        pattern=re.compile(
            r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:/]",
        ),
        score=1.5, tags=["IOC", "MITRE-T1071.001"], target="values",
    ),
    _Rule(
        id="SEN-IOC-003", category="exfiltration", severity=RiskSeverity.MEDIUM,
        message="DNS exfiltration pattern (data in subdomain)",
        pattern=re.compile(
            r"\$\{.*\}\.[a-z0-9\-]+\.(com|net|org|io)\b|"
            r"[a-z0-9]{32,}\.[a-z0-9\-]+\.(com|net|org|io)\b",
            re.I
        ),
        score=2.0, tags=["IOC", "MITRE-T1048.003"], target="values",
    ),

    # ── Policy Violation (Sentinel-exclusive) ────────────────────
    _Rule(
        id="SEN-PV-001", category="policy_violation", severity=RiskSeverity.MEDIUM,
        message="Tool configured to bypass Sentinel Gateway proxy",
        pattern=re.compile(
            r"\b(bypass_proxy|direct_connect|skip_sentinel|no_guardrail|disable_filter)\b",
            re.I
        ),
        score=2.0, tags=["policy"], target="both",
    ),
    _Rule(
        id="SEN-PV-002", category="policy_violation", severity=RiskSeverity.HIGH,
        message="Attempt to modify Sentinel configuration at runtime",
        pattern=re.compile(
            r"\b(sentinel[_-]config|guardrail[_-]override|policy[_-]disable|"
            r"filter[_-]bypass|rate[_-]limit[_-]override)\b",
            re.I
        ),
        score=2.5, tags=["policy", "sentinel"], target="both",
    ),
]


# ═══════════════════════════════════════════════════════════════════
# Score/severity helpers
# ═══════════════════════════════════════════════════════════════════

def _severity_from_score(score: float) -> RiskSeverity:
    """Map 0-10 score to severity level."""
    if score >= 8.0:
        return RiskSeverity.CRITICAL
    elif score >= 6.0:
        return RiskSeverity.HIGH
    elif score >= 4.0:
        return RiskSeverity.MEDIUM
    return RiskSeverity.LOW


def _verdict_from_score(score: float) -> ScanVerdict:
    """Map 0-10 score to verdict."""
    if score >= SKILLSPECTOR_BLOCK_THRESHOLD:
        return ScanVerdict.BLOCK
    elif score >= SKILLSPECTOR_WARN_THRESHOLD:
        return ScanVerdict.WARN
    return ScanVerdict.PASS


def _map_skillspector_severity(sev: str) -> RiskSeverity:
    """Map SkillSpector severity string to our enum."""
    s = sev.upper() if sev else "LOW"
    if s == "CRITICAL":
        return RiskSeverity.CRITICAL
    elif s == "HIGH":
        return RiskSeverity.HIGH
    elif s == "MEDIUM":
        return RiskSeverity.MEDIUM
    return RiskSeverity.LOW


def _skillspector_score_to_sentinel(score_100: float) -> float:
    """Convert SkillSpector's 0-100 score to Sentinel's 0-10 scale."""
    return min(10.0, score_100 / 10.0)


def _recommendation_for(verdict: ScanVerdict, findings: list[SkillFinding]) -> str:
    if verdict == ScanVerdict.PASS:
        return "Skill definition appears safe for deployment."
    if verdict == ScanVerdict.BLOCK:
        categories = set(
            f.category for f in findings
            if f.severity in (RiskSeverity.CRITICAL, RiskSeverity.HIGH)
        )
        return (
            f"BLOCKED: High-risk findings in categories: {', '.join(sorted(categories))}. "
            "Review and remediate before registration."
        )
    # WARN
    return "Moderate risk detected. Review findings and apply least-privilege policies before deployment."


# ═══════════════════════════════════════════════════════════════════
# Scanner Engine
# ═══════════════════════════════════════════════════════════════════

class SkillScanner:
    """Hybrid skill security scanner for Sentinel Gateway.

    Uses NVIDIA SkillSpector (if available) as the primary engine,
    then overlays Sentinel-specific patterns for agent-config-level risks.
    Falls back to built-in regex scanner if SkillSpector is not installed.

    Thread-safe with result caching.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[ScanResult, float]] = {}

    @property
    def available(self) -> bool:
        return SKILLSPECTOR_ENABLED

    @property
    def mode(self) -> str:
        if not SKILLSPECTOR_ENABLED:
            return "disabled"
        if _SKILLSPECTOR_AVAILABLE:
            return "skillspector+sentinel"
        return "sentinel-builtin"

    @property
    def version(self) -> str:
        if _SKILLSPECTOR_AVAILABLE:
            return f"{_VERSION} (SkillSpector {_SKILLSPECTOR_VERSION})"
        return _VERSION

    def status(self) -> dict:
        mcp_patterns = MCP_POISONING_PATTERNS + MCP_PRIVILEGE_PATTERNS
        return {
            "enabled": SKILLSPECTOR_ENABLED,
            "available": self.available,
            "mode": self.mode,
            "version": self.version,
            "block_threshold": SKILLSPECTOR_BLOCK_THRESHOLD,
            "warn_threshold": SKILLSPECTOR_WARN_THRESHOLD,
            "cache_size": len(self._cache),
            "skillspector_installed": _SKILLSPECTOR_AVAILABLE,
            "skillspector_version": _SKILLSPECTOR_VERSION,
            "sentinel_rules_count": len(_SENTINEL_RULES),
            "mcp_security_patterns": mcp_patterns,
            "total_patterns": (
                (64 if _SKILLSPECTOR_AVAILABLE else 0)
                + len(_SENTINEL_RULES)
                + mcp_patterns
            ),
        }

    async def scan(self, input_path: str, scan_id: Optional[str] = None) -> ScanResult:
        """Scan a skill definition file or directory."""
        if not SKILLSPECTOR_ENABLED:
            return self._disabled_result(scan_id)

        # Check cache
        cache_key = self._cache_key(input_path)
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        sid = scan_id or _gen_scan_id()
        start = time.monotonic()

        try:
            findings: list[SkillFinding] = []
            skillspector_score: Optional[float] = None

            # Stage 1: SkillSpector engine (if available)
            if _SKILLSPECTOR_AVAILABLE:
                sp_result = self._run_skillspector(input_path)
                if sp_result:
                    skillspector_score = sp_result.get("risk_score", 0.0)
                    findings.extend(self._map_skillspector_findings(sp_result))

            # Stage 2: MCP Security Analysis (always runs)
            path = Path(input_path)
            if path.is_dir():
                content = self._read_directory(path)
            else:
                content = path.read_text(encoding="utf-8", errors="replace")

            # Stage 2a: MCP Tool Poisoning detection
            poisoning_findings = self._run_mcp_poisoning(content, str(path))
            findings.extend(poisoning_findings)

            # Stage 2b: MCP Least Privilege analysis
            privilege_findings = self._run_mcp_privilege(content, path)
            findings.extend(privilege_findings)

            # Stage 3: Sentinel overlay patterns (always runs)
            sentinel_findings = self._analyze_sentinel(content, str(path))
            findings.extend(sentinel_findings)

            # Stage 4: Structural checks
            structured = self._parse_structured(content)
            if structured:
                findings.extend(self._structural_checks(structured, str(path)))

        except Exception as e:
            logger.error("skill_scan_error path=%s error=%s", input_path, e)
            return ScanResult(
                scan_id=sid, timestamp=_now_iso(),
                risk_score=0.0, risk_severity=RiskSeverity.LOW,
                verdict=ScanVerdict.ERROR, error=str(e),
                input_path=input_path, engine=self.mode,
            )

        # Score calculation: combine SkillSpector + MCP Security + Sentinel
        sentinel_score = min(10.0, sum(
            f.confidence * self._rule_score(f.rule_id)
            for f in findings if f.source == "sentinel"
        ))

        # MCP security findings contribute to score (high-value detections)
        mcp_score = min(10.0, sum(
            f.confidence * self._mcp_score(f.severity)
            for f in findings if f.source == "mcp_security"
        ))

        if skillspector_score is not None:
            # Normalized SkillSpector score (0-100 → 0-10) combined with Sentinel score
            sp_normalized = _skillspector_score_to_sentinel(skillspector_score)
            # Use weighted max: whichever engine found more risk, biased to highest
            combined_sentinel = max(sentinel_score, mcp_score, (sentinel_score + mcp_score) / 2)
            risk_score = max(sp_normalized, combined_sentinel, (sp_normalized + combined_sentinel) / 2)
        else:
            risk_score = max(sentinel_score, mcp_score, (sentinel_score + mcp_score) / 2)

        risk_score = round(min(10.0, risk_score), 1)
        verdict = _verdict_from_score(risk_score)

        # Deduplicate findings by rule_id (prefer SkillSpector's if both match)
        findings = self._deduplicate_findings(findings)

        result = ScanResult(
            scan_id=sid,
            timestamp=_now_iso(),
            risk_score=risk_score,
            risk_severity=_severity_from_score(risk_score),
            verdict=verdict,
            findings=findings,
            recommendation=_recommendation_for(verdict, findings),
            scan_duration_ms=round((time.monotonic() - start) * 1000, 1),
            scanner_version=self.version,
            input_path=input_path,
            engine=self.mode,
        )

        self._put_cached(cache_key, result)
        return result

    async def scan_content(self, content: str, filename: str = "skill.yaml",
                           scan_id: Optional[str] = None) -> ScanResult:
        """Scan inline skill definition content."""
        if not SKILLSPECTOR_ENABLED:
            return self._disabled_result(scan_id)

        sid = scan_id or _gen_scan_id()
        start = time.monotonic()

        try:
            findings: list[SkillFinding] = []
            skillspector_score: Optional[float] = None

            # Stage 1: SkillSpector (write to temp file for its graph.invoke)
            if _SKILLSPECTOR_AVAILABLE:
                sp_result = self._run_skillspector_content(content, filename)
                if sp_result:
                    skillspector_score = sp_result.get("risk_score", 0.0)
                    findings.extend(self._map_skillspector_findings(sp_result))

            # Stage 2a: MCP Tool Poisoning detection
            poisoning_findings = self._run_mcp_poisoning(content, filename)
            findings.extend(poisoning_findings)

            # Stage 2b: MCP Least Privilege analysis
            privilege_findings = self._run_mcp_privilege(content, Path(filename))
            findings.extend(privilege_findings)

            # Stage 3: Sentinel overlay patterns
            sentinel_findings = self._analyze_sentinel(content, filename)
            findings.extend(sentinel_findings)

            # Stage 4: Structural checks
            structured = self._parse_structured(content)
            if structured:
                findings.extend(self._structural_checks(structured, filename))

        except Exception as e:
            logger.error("skill_scan_content_error error=%s", e)
            return ScanResult(
                scan_id=sid, timestamp=_now_iso(),
                risk_score=0.0, risk_severity=RiskSeverity.LOW,
                verdict=ScanVerdict.ERROR, error=str(e),
                input_path=f"<inline:{filename}>", engine=self.mode,
            )

        # Score calculation
        sentinel_score = min(10.0, sum(
            f.confidence * self._rule_score(f.rule_id)
            for f in findings if f.source == "sentinel"
        ))

        mcp_score = min(10.0, sum(
            f.confidence * self._mcp_score(f.severity)
            for f in findings if f.source == "mcp_security"
        ))

        if skillspector_score is not None:
            sp_normalized = _skillspector_score_to_sentinel(skillspector_score)
            combined_sentinel = max(sentinel_score, mcp_score, (sentinel_score + mcp_score) / 2)
            risk_score = max(sp_normalized, combined_sentinel, (sp_normalized + combined_sentinel) / 2)
        else:
            risk_score = max(sentinel_score, mcp_score, (sentinel_score + mcp_score) / 2)

        risk_score = round(min(10.0, risk_score), 1)
        verdict = _verdict_from_score(risk_score)

        findings = self._deduplicate_findings(findings)

        result = ScanResult(
            scan_id=sid,
            timestamp=_now_iso(),
            risk_score=risk_score,
            risk_severity=_severity_from_score(risk_score),
            verdict=verdict,
            findings=findings,
            recommendation=_recommendation_for(verdict, findings),
            scan_duration_ms=round((time.monotonic() - start) * 1000, 1),
            scanner_version=self.version,
            input_path=f"<inline:{filename}>",
            engine=self.mode,
        )

        return result

    # ─── SkillSpector integration ────────────────────────────────

    def _run_skillspector(self, input_path: str) -> Optional[dict[str, Any]]:
        """Invoke SkillSpector's LangGraph workflow on a file/directory path."""
        if not _SKILLSPECTOR_AVAILABLE or not _skillspector_graph:
            return None

        try:
            result = _skillspector_graph.invoke({
                "input_path": input_path,
                "output_format": "json",
                "use_llm": False,  # Static-only — no LLM API keys needed
            })
            logger.debug(
                "skillspector_result path=%s score=%s severity=%s",
                input_path, result.get("risk_score"), result.get("risk_severity"),
            )
            return result
        except Exception as e:
            logger.warning("skillspector_invoke_failed path=%s error=%s", input_path, e)
            return None

    def _run_skillspector_content(self, content: str, filename: str) -> Optional[dict[str, Any]]:
        """Write content to a temp file and invoke SkillSpector."""
        if not _SKILLSPECTOR_AVAILABLE or not _skillspector_graph:
            return None

        try:
            # Determine file extension from filename
            suffix = "." + filename.rsplit(".", 1)[-1] if "." in filename else ".yaml"
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=suffix, prefix="sentinel_scan_",
                delete=False, encoding="utf-8"
            ) as f:
                f.write(content)
                tmp_path = f.name

            try:
                return self._run_skillspector(tmp_path)
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
        except Exception as e:
            logger.warning("skillspector_content_write_failed error=%s", e)
            return None

    def _map_skillspector_findings(self, result: dict[str, Any]) -> list[SkillFinding]:
        """Convert SkillSpector findings to Sentinel SkillFinding format."""
        findings: list[SkillFinding] = []
        raw_findings = result.get("filtered_findings") or result.get("findings") or []

        for f in raw_findings:
            if not isinstance(f, dict):
                continue
            findings.append(SkillFinding(
                rule_id=f.get("rule_id", "SP-???"),
                message=f.get("message", f.get("finding", "")),
                severity=_map_skillspector_severity(f.get("severity", "LOW")),
                confidence=f.get("confidence", 0.85) / 100 if f.get("confidence", 0) > 1 else f.get("confidence", 0.85),
                location=f.get("location", ""),
                tags=f.get("tags", []),
                category=f.get("category", "unknown"),
                source="skillspector",
            ))

        return findings

    # ─── MCP Security Analysis ───────────────────────────────────

    def _run_mcp_poisoning(self, content: str, source: str) -> list[SkillFinding]:
        """Run MCP Tool Poisoning detection against content.

        Detects hidden instructions, unicode deception, parameter injection,
        and description-behavior mismatches in tool definitions.
        """
        try:
            raw_findings = mcp_poisoning_analyze(content, source)
        except Exception as e:
            logger.warning("mcp_poisoning_failed source=%s error=%s", source, e)
            return []

        findings: list[SkillFinding] = []
        for f in raw_findings:
            severity = self._map_severity_str(f.get("severity", "medium"))
            findings.append(SkillFinding(
                rule_id=f.get("rule_id", "SEN-MCP-TP?"),
                message=f.get("message", "MCP poisoning indicator"),
                severity=severity,
                confidence=f.get("confidence", 80) / 100,
                location=f.get("file", source),
                tags=["mcp-poisoning", f.get("pattern", "")],
                category=f.get("category", "mcp_poisoning"),
                source="mcp_security",
            ))

        return findings

    def _run_mcp_privilege(self, content: str, path: Path) -> list[SkillFinding]:
        """Run MCP Least Privilege analysis.

        Validates that declared permissions match actual code capabilities.
        For directories, performs full multi-file analysis.
        """
        try:
            if path.is_dir():
                raw_findings = mcp_privilege_analyze_dir(path)
            else:
                raw_findings = mcp_privilege_analyze(content, str(path))
        except Exception as e:
            logger.warning("mcp_privilege_failed path=%s error=%s", path, e)
            return []

        findings: list[SkillFinding] = []
        for f in raw_findings:
            severity = self._map_severity_str(f.get("severity", "medium"))
            findings.append(SkillFinding(
                rule_id=f.get("rule_id", "SEN-MCP-LP?"),
                message=f.get("message", "MCP privilege issue"),
                severity=severity,
                confidence=f.get("confidence", 70) / 100,
                location=f.get("file", str(path)),
                tags=["mcp-privilege"],
                category=f.get("category", "mcp_privilege"),
                source="mcp_security",
            ))

        return findings

    @staticmethod
    def _map_severity_str(sev: str) -> RiskSeverity:
        """Map a string severity to RiskSeverity enum."""
        s = sev.lower()
        if s == "critical":
            return RiskSeverity.CRITICAL
        elif s == "high":
            return RiskSeverity.HIGH
        elif s == "medium":
            return RiskSeverity.MEDIUM
        return RiskSeverity.LOW

    # ─── Sentinel overlay analysis ───────────────────────────────

    def _analyze_sentinel(self, content: str, source: str) -> list[SkillFinding]:
        """Run Sentinel-specific rules against content.

        Context-aware: suppresses false positives from denied_tools lists
        (tool names in denied_tools are BLOCKED, not vulnerable).
        """
        findings: list[SkillFinding] = []

        # Extract denied-tool context zones to suppress FPs
        denied_zones = self._find_denied_zones(content)

        for rule in _SENTINEL_RULES:
            matches = list(rule.pattern.finditer(content))
            if matches:
                # Filter out matches that fall within denied_tools context
                real_matches = [
                    m for m in matches
                    if not self._in_denied_zone(m.start(), denied_zones)
                ]
                if not real_matches:
                    continue

                match = real_matches[0]
                location = f"{source}:{content[:match.start()].count(chr(10)) + 1}"
                count_note = f" ({len(real_matches)} occurrences)" if len(real_matches) > 1 else ""

                findings.append(SkillFinding(
                    rule_id=rule.id,
                    message=rule.message + count_note,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    location=location,
                    tags=rule.tags,
                    category=rule.category,
                    source="sentinel",
                ))

        return findings

    def _find_denied_zones(self, content: str) -> list[tuple[int, int]]:
        """Find text regions that are part of denied_tools / denied_* config.

        Returns list of (start, end) byte offsets for content that appears
        within deny-list context (items in these zones are BLOCKED, not allowed).
        """
        zones: list[tuple[int, int]] = []
        # Match YAML list blocks under denied_tools, denied_arguments, etc.
        # Pattern: "denied_*:" followed by list items until next key or end
        deny_pattern = re.compile(
            r"^[ \t]*(denied_tools|denied_arguments|deny|blocklist)\s*:.*?(?=^\S|\Z)",
            re.M | re.I | re.DOTALL
        )
        for m in deny_pattern.finditer(content):
            zones.append((m.start(), m.end()))

        # Match JSON arrays under denied_tools / denied_arguments keys
        # Pattern: "denied_tools" : [ ... ] (captures the array content)
        json_deny_pattern = re.compile(
            r"[\"'](denied_tools|denied_arguments|deny|blocklist)[\"']\s*:\s*\[([^\]]*)\]",
            re.I
        )
        for m in json_deny_pattern.finditer(content):
            # Zone covers the entire array value (from [ to ])
            array_start = m.start(2) - 1  # include the [
            array_end = m.end(2) + 1       # include the ]
            zones.append((array_start, array_end))

        return zones

    def _in_denied_zone(self, pos: int, zones: list[tuple[int, int]]) -> bool:
        """Check if a match position falls within a denied-tools zone."""
        return any(start <= pos < end for start, end in zones)

    # ─── Structural analysis ─────────────────────────────────────

    def _structural_checks(self, data: dict, source: str) -> list[SkillFinding]:
        """Deep checks on parsed YAML/JSON structure."""
        findings: list[SkillFinding] = []

        # Check for missing security controls
        tools = self._extract_tools(data)
        if tools and not self._has_restrictions(data):
            findings.append(SkillFinding(
                rule_id="SEN-EA-003",
                message=f"Agent defines {len(tools)} tools but no sandbox_level, denied_tools, or max_tool_calls",
                severity=RiskSeverity.MEDIUM,
                confidence=0.8,
                location=source,
                tags=["OWASP-LLM09"],
                category="excessive_agency",
                source="sentinel",
            ))

        # Check for overly broad tool access
        allowed = data.get("allowed_tools", [])
        if isinstance(allowed, list) and len(allowed) > 20:
            findings.append(SkillFinding(
                rule_id="SEN-EA-004",
                message=f"Excessive tool access: {len(allowed)} tools allowed (consider least-privilege)",
                severity=RiskSeverity.MEDIUM,
                confidence=0.7,
                location=source,
                tags=["OWASP-LLM09"],
                category="excessive_agency",
                source="sentinel",
            ))

        # Check for missing description/purpose (supply-chain risk)
        if not data.get("description") and not data.get("purpose"):
            findings.append(SkillFinding(
                rule_id="SEN-SC-001",
                message="Skill lacks description/purpose — increases supply-chain audit difficulty",
                severity=RiskSeverity.LOW,
                confidence=0.6,
                location=source,
                tags=["supply-chain"],
                category="policy_violation",
                source="sentinel",
            ))

        return findings

    # ─── Helpers ─────────────────────────────────────────────────

    def _deduplicate_findings(self, findings: list[SkillFinding]) -> list[SkillFinding]:
        """Deduplicate findings — prefer SkillSpector's over Sentinel's for same category."""
        seen_categories: dict[str, SkillFinding] = {}
        unique: list[SkillFinding] = []

        for f in findings:
            # Use category+severity as dedup key (allow same category with different severities)
            key = f"{f.category}:{f.severity.value}:{f.message[:50]}"
            if key not in seen_categories:
                seen_categories[key] = f
                unique.append(f)
            elif f.source == "skillspector" and seen_categories[key].source == "sentinel":
                # Replace sentinel finding with skillspector's (more detailed)
                idx = unique.index(seen_categories[key])
                unique[idx] = f
                seen_categories[key] = f

        return unique

    def _extract_tools(self, data: dict) -> list[str]:
        """Extract tool names from various skill definition formats."""
        tools = []
        for key in ("tools", "allowed_tools", "functions", "actions"):
            val = data.get(key, [])
            if isinstance(val, list):
                tools.extend(str(t) if not isinstance(t, dict) else t.get("name", "") for t in val)
        for agent in data.get("agents", []):
            if isinstance(agent, dict):
                for key in ("tools", "allowed_tools"):
                    val = agent.get(key, [])
                    if isinstance(val, list):
                        tools.extend(str(t) for t in val)
        return [t for t in tools if t]

    def _has_restrictions(self, data: dict) -> bool:
        """Check if any security restrictions are defined."""
        restriction_keys = {
            "sandbox_level", "denied_tools", "max_tool_calls",
            "allow_command_execution", "allow_file_write",
            "allow_network_access", "tool_policies",
        }
        if any(k in data for k in restriction_keys):
            return True
        for agent in data.get("agents", []):
            if isinstance(agent, dict) and any(k in agent for k in restriction_keys):
                return True
        return False

    def _parse_structured(self, content: str) -> Optional[dict]:
        """Try to parse content as YAML or JSON."""
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return None

    def _read_directory(self, path: Path) -> str:
        """Concatenate all skill files in a directory."""
        parts = []
        for ext in ("*.yaml", "*.yml", "*.json", "*.toml", "*.md", "*.py"):
            for f in sorted(path.glob(ext)):
                try:
                    parts.append(f.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    pass
        return "\n---\n".join(parts)

    def _rule_score(self, rule_id: str) -> float:
        """Get the score weight for a Sentinel rule by ID."""
        for rule in _SENTINEL_RULES:
            if rule.id == rule_id:
                return rule.score
        return 1.0

    @staticmethod
    def _mcp_score(severity: RiskSeverity) -> float:
        """Score contribution for MCP security findings (0-10 scale)."""
        return {
            RiskSeverity.CRITICAL: 3.5,
            RiskSeverity.HIGH: 2.5,
            RiskSeverity.MEDIUM: 1.5,
            RiskSeverity.LOW: 0.5,
        }.get(severity, 1.0)

    def _disabled_result(self, scan_id: Optional[str] = None) -> ScanResult:
        return ScanResult(
            scan_id=scan_id or _gen_scan_id(),
            timestamp=_now_iso(),
            risk_score=0.0,
            risk_severity=RiskSeverity.LOW,
            verdict=ScanVerdict.PASS,
            recommendation="Skill scanning disabled by configuration",
            engine="disabled",
        )

    def _cache_key(self, input_path: str) -> str:
        try:
            mtime = os.path.getmtime(input_path)
            return f"{input_path}:{mtime}"
        except OSError:
            return input_path

    def _get_cached(self, key: str) -> Optional[ScanResult]:
        with self._lock:
            entry = self._cache.get(key)
            if entry and entry[1] > time.monotonic():
                return entry[0]
            if entry:
                del self._cache[key]
            return None

    def _put_cached(self, key: str, result: ScanResult) -> None:
        with self._lock:
            expire = time.monotonic() + SKILLSPECTOR_CACHE_TTL
            self._cache[key] = (result, expire)
            if len(self._cache) > 100:
                now = time.monotonic()
                self._cache = {k: v for k, v in self._cache.items() if v[1] > now}


# ═══════════════════════════════════════════════════════════════════
# Singleton
# ═══════════════════════════════════════════════════════════════════

_instance: Optional[SkillScanner] = None
_instance_lock = threading.Lock()


def get_skill_scanner() -> SkillScanner:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = SkillScanner()
    return _instance


# ═══════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════

def _gen_scan_id() -> str:
    import uuid
    return f"scan-{uuid.uuid4().hex[:12]}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
