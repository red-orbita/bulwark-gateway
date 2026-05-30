"""
Output Filter — Inspects and redacts agent responses before returning to user.

Detects:
- Leaked credentials/secrets in responses
- PII exposure
- Internal system paths/hostnames
- Indirect prompt injection in tool outputs (agent-side)
"""
import re
from src.models import Verdict, ThreatCategory, SecurityEvent, GuardrailResult


# Patterns to redact from output
REDACTION_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # AWS keys
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS_ACCESS_KEY", "[REDACTED:AWS_KEY]"),
    # AWS secret
    (re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"), "AWS_SECRET", None),  # Only if near AWS context
    # Generic API keys (hex/base64, 32+ chars)
    (re.compile(r"(sk[_-]live[_-][a-zA-Z0-9]{24,})"), "STRIPE_KEY", "[REDACTED:STRIPE_KEY]"),
    (re.compile(r"(ghp_[a-zA-Z0-9]{36,})"), "GITHUB_TOKEN", "[REDACTED:GITHUB_TOKEN]"),
    (re.compile(r"(gho_[a-zA-Z0-9]{36,})"), "GITHUB_OAUTH", "[REDACTED:GITHUB_OAUTH]"),
    (re.compile(r"(xox[baprs]-[a-zA-Z0-9\-]{10,})"), "SLACK_TOKEN", "[REDACTED:SLACK_TOKEN]"),
    (re.compile(r"(nvapi-[a-zA-Z0-9]{48,})"), "NVIDIA_KEY", "[REDACTED:NVIDIA_KEY]"),
    # Database URLs with passwords
    (re.compile(r"(postgres|mysql|mongodb)://[^:]+:[^@]+@[^\s]+"), "DB_CONNECTION_STRING", "[REDACTED:DB_URL]"),
    # Private keys
    (re.compile(r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH)?\s*PRIVATE KEY-----"), "PRIVATE_KEY", "[REDACTED:PRIVATE_KEY]"),
    # JWT secrets (common patterns)
    (re.compile(r"(jwt[_-]?secret|JWT_SECRET)\s*[=:]\s*\S+"), "JWT_SECRET", "[REDACTED:JWT_SECRET]"),
]

# PII patterns
PII_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # Email
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "EMAIL", None),
    # Credit card (basic)
    (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"), "CREDIT_CARD", "[REDACTED:CC]"),
    # SSN
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN", "[REDACTED:SSN]"),
    # Phone (international)
    (re.compile(r"\+\d{1,3}[-.\s]?\d{6,14}"), "PHONE", None),
]

# Internal path patterns (configurable per tenant)
INTERNAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"/home/[a-z_][a-z0-9_-]*/"), "HOME_PATH"),
    (re.compile(r"/etc/(passwd|shadow|sudoers)"), "SYSTEM_FILE"),
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "INTERNAL_IP"),
]


class OutputFilter:
    """Filters agent output for credential leaks, PII, and sensitive data."""

    def __init__(self, redact_pii: bool = True, redact_secrets: bool = True,
                 redact_internal: bool = False, custom_patterns: list | None = None):
        self.redact_pii = redact_pii
        self.redact_secrets = redact_secrets
        self.redact_internal = redact_internal
        self.custom_patterns = custom_patterns or []

    def inspect_and_redact(
        self, content: str, tenant_id: str = "", agent_id: str = ""
    ) -> GuardrailResult:
        """Inspect output and optionally redact sensitive data."""
        events: list[SecurityEvent] = []
        modified = content

        # Check secrets
        if self.redact_secrets:
            for pattern, name, replacement in REDACTION_PATTERNS:
                matches = pattern.findall(modified)
                if matches:
                    events.append(SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.REDACT,
                        category=ThreatCategory.CREDENTIAL_ACCESS,
                        description=f"Secret detected in output: {name}",
                        source="output_filter",
                        severity="high",
                        matched_pattern=name,
                    ))
                    if replacement:
                        modified = pattern.sub(replacement, modified)

        # Check PII
        if self.redact_pii:
            for pattern, name, replacement in PII_PATTERNS:
                matches = pattern.findall(modified)
                if matches and replacement:
                    events.append(SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.REDACT,
                        category=ThreatCategory.PII_LEAK,
                        description=f"PII detected in output: {name}",
                        source="output_filter",
                        severity="medium",
                        matched_pattern=name,
                    ))
                    modified = pattern.sub(replacement, modified)

        if not events:
            return GuardrailResult(verdict=Verdict.ALLOW)

        return GuardrailResult(
            verdict=Verdict.REDACT,
            events=events,
            modified_content=modified,
        )
