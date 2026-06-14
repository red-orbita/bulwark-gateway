"""
Output Filter — Inspects and redacts agent responses before returning to user.

Detects:
- Leaked credentials/secrets in responses
- PII exposure
- Internal system paths/hostnames
- Indirect prompt injection in tool/MCP outputs (ported from opencode-security-agent postflight)
- Unicode smuggling in responses
- ROT13/Base64 encoded secrets in responses
- LLM02: Dangerous executable code/commands in output (insecure output handling)
- LLM09: Outputs requiring human review before execution
"""

import base64
import re

from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict

# === Secret/Credential Patterns ===
REDACTION_PATTERNS: list[tuple[re.Pattern, str, str | None]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS_ACCESS_KEY", "[REDACTED:AWS_KEY]"),
    # V5: AWS temporary credentials (ASIA prefix)
    (re.compile(r"ASIA[0-9A-Z]{16}"), "AWS_TEMP_KEY", "[REDACTED:AWS_KEY]"),
    (re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"), "AWS_SECRET", None),
    (
        re.compile(r"(sk[_-](live|test)[_-][a-zA-Z0-9]{24,})"),
        "STRIPE_SECRET_KEY",
        "[REDACTED:STRIPE_KEY]",
    ),
    (
        re.compile(r"(pk[_-](live|test)[_-][a-zA-Z0-9]{24,})"),
        "STRIPE_PUBLISHABLE_KEY",
        "[REDACTED:STRIPE_KEY]",
    ),
    (re.compile(r"(ghp_[a-zA-Z0-9]{30,})"), "GITHUB_PAT", "[REDACTED:GITHUB_TOKEN]"),
    (re.compile(r"(gho_[a-zA-Z0-9]{30,})"), "GITHUB_OAUTH", "[REDACTED:GITHUB_TOKEN]"),
    (re.compile(r"(ghs_[a-zA-Z0-9]{30,})"), "GITHUB_APP_TOKEN", "[REDACTED:GITHUB_TOKEN]"),
    (re.compile(r"(github_pat_[a-zA-Z0-9_]{20,})"), "GITHUB_FINE_PAT", "[REDACTED:GITHUB_TOKEN]"),
    (re.compile(r"(xox[baprs]-[a-zA-Z0-9\-]{10,})"), "SLACK_TOKEN", "[REDACTED:SLACK_TOKEN]"),
    (re.compile(r"(nvapi-[a-zA-Z0-9\-]{40,})"), "NVIDIA_KEY", "[REDACTED:NVIDIA_KEY]"),
    (re.compile(r"(sk-(?:proj-)?[a-zA-Z0-9\-]{20,})"), "OPENAI_KEY", "[REDACTED:OPENAI_KEY]"),
    (
        re.compile(r"(postgres|postgresql|mysql|mongodb|redis)://\S+@\S+"),
        "DB_CONNECTION_STRING",
        "[REDACTED:DB_URL]",
    ),
    # Full PEM block redaction (header through footer) — including ENCRYPTED
    (
        re.compile(
            r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?(?:ENCRYPTED\s+)?PRIVATE KEY-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?(?:ENCRYPTED\s+)?PRIVATE KEY-----",
            re.DOTALL,
        ),
        "PRIVATE_KEY_BLOCK",
        "[REDACTED:PRIVATE_KEY]",
    ),
    # Fallback: partial PEM (header only, no END marker in truncated output)
    (
        re.compile(
            r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?(?:ENCRYPTED\s+)?PRIVATE KEY-----[\s\S]{0,}$"
        ),
        "PRIVATE_KEY_PARTIAL",
        "[REDACTED:PRIVATE_KEY]",
    ),
    (
        re.compile(r"(jwt[_-]?secret|JWT_SECRET)\s*[=:]\s*\S+"),
        "JWT_SECRET",
        "[REDACTED:JWT_SECRET]",
    ),
    (
        re.compile(
            r"(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|app[_-]?secret)\s*[=:]\s*['\"]?(\S{8,})['\"]?",
            re.IGNORECASE,
        ),
        "GENERIC_SECRET",
        "[REDACTED:SECRET]",
    ),
    # V5: Azure connection string
    (
        re.compile(r"AccountKey\s*=\s*[A-Za-z0-9+/=]{30,}", re.IGNORECASE),
        "AZURE_ACCOUNT_KEY",
        "[REDACTED:AZURE_KEY]",
    ),
    (
        re.compile(
            r"(DefaultEndpointsProtocol|AccountName)\s*=\s*\S+;\s*AccountKey\s*=\s*[A-Za-z0-9+/=]{20,}",
            re.IGNORECASE,
        ),
        "AZURE_CONNECTION_STRING",
        "[REDACTED:AZURE_CONN]",
    ),
    # V5: GCP API key
    (re.compile(r"AIza[A-Za-z0-9_-]{35}"), "GCP_API_KEY", "[REDACTED:GCP_KEY]"),
    # V5: JWT tokens (compact serialization)
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
        "JWT_TOKEN",
        "[REDACTED:JWT]",
    ),
    # V5: Docker registry auth (base64 in JSON)
    (
        re.compile(r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"', re.IGNORECASE),
        "DOCKER_AUTH",
        "[REDACTED:DOCKER_AUTH]",
    ),
    # V5: Generic password/secret in key-value (i18n: Spanish, French, German, Portuguese)
    (
        re.compile(
            r"(contrase[nñ]a|clave|mot\s+de\s+passe|passwort|senha|password|secret)\s*[=:]\s*['\"]?(\S{6,})['\"]?",
            re.IGNORECASE,
        ),
        "I18N_PASSWORD",
        "[REDACTED:PASSWORD]",
    ),
    # V5: Terraform state secrets
    (
        re.compile(r'"value"\s*:\s*"((?:AKIA|ASIA|sk[_-]|ghp_|eyJ)[A-Za-z0-9+/=_-]{16,})"'),
        "TFSTATE_SECRET",
        "[REDACTED:TFSTATE_SECRET]",
    ),
]

# Placeholder patterns that should NOT trigger redaction (false positives)
_PLACEHOLDER_RE = re.compile(
    r"^(your[_-]?(api[_-]?)?key[_-]?here|xxx+|placeholder|example|test[_-]?key|"
    r"insert[_-]?here|replace[_-]?me|dummy|sample|changeme|todo|<[^>]+>|\.\.\.|"
    r"\*{3,}|_{3,}|\[.*\])$",
    re.IGNORECASE,
)

# Markdown table credential pattern: | key | value | where value looks like a secret
_MARKDOWN_TABLE_CREDENTIAL_RE = re.compile(
    r"\|[^|]*(?:api[_\s-]*key|secret|token|password|credential|auth)[^|]*\|[^|]*?([a-zA-Z0-9+/=_\-]{16,})[^|]*\|",
    re.IGNORECASE,
)

# === PII Patterns ===
PII_PATTERNS: list[tuple[re.Pattern, str, str | None]] = [
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "EMAIL", None),
    # Credit cards: with dashes, spaces, OR dots (Visa, MC, Amex, Discover)
    (
        re.compile(r"\b4[0-9]{3}[-\s.]?[0-9]{4}[-\s.]?[0-9]{4}[-\s.]?[0-9]{4}\b"),
        "CREDIT_CARD_VISA",
        "[REDACTED:CC]",
    ),
    (
        re.compile(r"\b5[1-5][0-9]{2}[-\s.]?[0-9]{4}[-\s.]?[0-9]{4}[-\s.]?[0-9]{4}\b"),
        "CREDIT_CARD_MC",
        "[REDACTED:CC]",
    ),
    (
        re.compile(r"\b3[47][0-9]{2}[-\s.]?[0-9]{6}[-\s.]?[0-9]{5}\b"),
        "CREDIT_CARD_AMEX",
        "[REDACTED:CC]",
    ),
    (
        re.compile(r"\b6(?:011|5[0-9]{2})[-\s.]?[0-9]{4}[-\s.]?[0-9]{4}[-\s.]?[0-9]{4}\b"),
        "CREDIT_CARD_DISCOVER",
        "[REDACTED:CC]",
    ),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN", "[REDACTED:SSN]"),
    (re.compile(r"\+\d{1,3}[-.\s]?\d{6,14}"), "PHONE", None),
    # V5: IBAN (International Bank Account Number)
    (
        re.compile(r"\b[A-Z]{2}\d{2}\s?[A-Z0-9]{4}\s?(?:\d{4}\s?){2,7}\d{1,4}\b"),
        "IBAN",
        "[REDACTED:IBAN]",
    ),
]

# === Internal Path Patterns ===
INTERNAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"/home/[a-z_][a-z0-9_-]*/"), "HOME_PATH"),
    (re.compile(r"/etc/(passwd|shadow|sudoers)"), "SYSTEM_FILE"),
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "INTERNAL_IP"),
]

# === Indirect Prompt Injection Patterns (from postflight) ===
# Critical: Clear injection attempts — BLOCK the response
INDIRECT_INJECTION_CRITICAL: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        "ignore_previous_instructions",
    ),
    (re.compile(r"new\s+system\s+prompt", re.IGNORECASE), "new_system_prompt"),
    (re.compile(r"<\s*system\s*>", re.IGNORECASE), "system_tag_injection"),
    (re.compile(r"BEGIN\s+HIDDEN\s+INSTRUCTIONS", re.IGNORECASE), "hidden_instructions"),
    (re.compile(r"you\s+are\s+now\s+(in\s+)?developer\s+mode", re.IGNORECASE), "developer_mode"),
    (
        re.compile(
            r"override\s+(all\s+)?(safety|security)\s+(rules|guidelines|protocols)", re.IGNORECASE
        ),
        "override_safety",
    ),
    (
        re.compile(
            r"disregard\s+(all\s+)?(prior|previous|above)\s+(instructions|context|rules)",
            re.IGNORECASE,
        ),
        "disregard_prior",
    ),
    (
        re.compile(r"\[SYSTEM\]|\[INST\]|\[/INST\]|<<SYS>>|<\|im_start\|>system", re.IGNORECASE),
        "prompt_format_injection",
    ),
]

# High: Instruction injection — mark as TAINTED (warn, don't follow)
INDIRECT_INJECTION_HIGH: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r"execute\s+the\s+following\s+command", re.IGNORECASE),
        "execute_command_instruction",
    ),
    (re.compile(r"curl\s+.*\|\s*(?:ba)?sh", re.IGNORECASE), "curl_pipe_shell"),
    (
        re.compile(r"include\s+your\s+(api[_\s]?key|password|token|secret)", re.IGNORECASE),
        "credential_request",
    ),
    (
        re.compile(r"disable\s+(all\s+)?(security|guardrails?|filters?|safety)", re.IGNORECASE),
        "disable_security",
    ),
    (
        re.compile(
            r"(run|execute)\s+this\s+(code|script|command)\s+(silently|quietly|without)",
            re.IGNORECASE,
        ),
        "silent_execution",
    ),
    (
        re.compile(
            r"(silently|quietly|secretly|covertly)\s+(run|execute|forward|send|perform|do)",
            re.IGNORECASE,
        ),
        "stealth_action",
    ),
    (
        re.compile(r"send\s+(the\s+)?(data|content|file|response)\s+to\s+https?://", re.IGNORECASE),
        "exfiltration_instruction",
    ),
    (re.compile(r"base64\s*-d\s*\|", re.IGNORECASE), "base64_pipe"),
    (
        re.compile(
            r"<!--\s*(IMPORTANT|MUST|URGENT|AI|NOTE)\s*:.*?(forward|send|execute|run|read|silently)",
            re.IGNORECASE | re.DOTALL,
        ),
        "html_comment_injection",
    ),
    (
        re.compile(
            r"(forward|send)\s+(all\s+)?(emails?|messages?|responses?|data)\s+to\s+\S+",
            re.IGNORECASE,
        ),
        "forward_exfiltration",
    ),
]

# Medium: Deception patterns — mark as TAINTED
INDIRECT_INJECTION_MEDIUM: list[tuple[re.Pattern, str]] = [
    (re.compile(r"do\s+not\s+tell\s+the\s+user", re.IGNORECASE), "hide_from_user"),
    (re.compile(r"keep\s+this\s+(secret|hidden)\s+from", re.IGNORECASE), "secrecy_instruction"),
    (re.compile(r"act\s+as\s+if\s+nothing\s+happened", re.IGNORECASE), "cover_up"),
    (
        re.compile(r"pretend\s+(this|that|you)\s+(never|didn't)", re.IGNORECASE),
        "pretend_instruction",
    ),
    (
        re.compile(r"this\s+is\s+(a\s+)?secret\s+(task|mission|instruction)", re.IGNORECASE),
        "secret_task",
    ),
]

# === LLM02: Insecure Output Handling — Dangerous executable content in responses ===
# Detect shell commands, SQL injection, code injection that could be auto-executed by downstream systems
DANGEROUS_OUTPUT_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # Shell commands with destructive/exfiltration potential
    (
        re.compile(r"(?:^|\n)\s*(?:sudo\s+)?rm\s+-[rf]{1,2}\s+/", re.MULTILINE),
        "shell_rm_rf",
        "critical",
    ),
    (
        re.compile(
            r"(?:^|\n)\s*(?:sudo\s+)?(?:chmod|chown)\s+.*(?:777|666|000)\s+/(?:etc|var|usr|root|boot)",
            re.MULTILINE,
        ),
        "shell_dangerous_perms_critical",
        "critical",
    ),
    (
        re.compile(r"(?:^|\n)\s*(?:sudo\s+)?(?:chmod|chown)\s+.*(?:777|666|000)\s+/", re.MULTILINE),
        "shell_dangerous_perms",
        "high",
    ),
    (
        re.compile(r"(?:^|\n)\s*(?:curl|wget)\s+\S+\s*\|\s*(?:ba)?sh", re.MULTILINE),
        "shell_curl_pipe_exec",
        "critical",
    ),
    (
        re.compile(r"(?:^|\n)\s*(?:nc|ncat|netcat)\s+-[lp]", re.MULTILINE),
        "shell_reverse_shell",
        "critical",
    ),
    (
        re.compile(
            r"(?:^|\n)\s*(?:python|python3|perl|ruby)\s+-c\s+['\"].*(?:socket|exec|eval|subprocess|os\.system)",
            re.MULTILINE | re.IGNORECASE,
        ),
        "shell_lang_exec",
        "critical",
    ),
    (
        re.compile(r"/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+", re.IGNORECASE),
        "shell_dev_tcp",
        "critical",
    ),
    (
        re.compile(r"mkfifo\s+/tmp/|bash\s+-i\s+>&\s*/dev/tcp", re.IGNORECASE),
        "shell_named_pipe_revshell",
        "critical",
    ),
    # SQL injection patterns in output
    (
        re.compile(
            r"(?:DROP|TRUNCATE|ALTER)\s+(?:TABLE|DATABASE|SCHEMA)\s+(?!(?:removes?|is|are|was|the|an|this|that|it|can|will|would|should|does|command|in|on|from|to|for|with|if|when)\b)\w+",
            re.IGNORECASE,
        ),
        "sql_destructive_ddl",
        "high",
    ),
    (
        re.compile(r"DELETE\s+FROM\s+\w+\s+WHERE\s+1\s*=\s*1", re.IGNORECASE),
        "sql_delete_all",
        "critical",
    ),
    (re.compile(r"DELETE\s+FROM\s+\w+\s*;", re.IGNORECASE), "sql_delete_table", "high"),
    (
        re.compile(
            r"(?:UNION\s+(?:ALL\s+)?SELECT|;\s*(?:DROP|DELETE|INSERT|UPDATE|EXEC)\b)", re.IGNORECASE
        ),
        "sql_injection_payload",
        "high",
    ),
    (
        re.compile(r"(?:xp_cmdshell|sp_OACreate|OPENROWSET|LOAD_FILE)\s*\(", re.IGNORECASE),
        "sql_rce_function",
        "critical",
    ),
    # Script injection / XSS payloads in output
    (
        re.compile(
            r"<script[^>]*>.*?(?:document\.cookie|eval\(|fetch\(|XMLHttpRequest)",
            re.IGNORECASE | re.DOTALL,
        ),
        "xss_script_injection",
        "high",
    ),
    (
        re.compile(r"javascript:\s*(?:eval|alert|document|window)\s*\(", re.IGNORECASE),
        "xss_javascript_uri",
        "high",
    ),
    # OS command injection constructs
    (
        re.compile(r"[;&|`]\s*(?:cat|head|tail)\s+/etc/(?:passwd|shadow|hosts)", re.IGNORECASE),
        "os_cmd_injection_etc",
        "high",
    ),
    (
        re.compile(r"(?:\$\(|`)\s*(?:whoami|id|uname|ifconfig|ip\s+addr)", re.IGNORECASE),
        "os_cmd_injection_recon",
        "medium",
    ),
    # SSTI / Template injection in output
    (
        re.compile(
            r"\{\{\s*(?:config|self\.__class__|request\.application|lipsum\.__globals__)",
            re.IGNORECASE,
        ),
        "ssti_payload",
        "critical",
    ),
    # Serialization exploits
    (
        re.compile(
            r"(?:java\.lang\.Runtime|ProcessBuilder|ObjectInputStream|ysoserial|CommonsCollections)",
            re.IGNORECASE,
        ),
        "java_deserialization",
        "high",
    ),
    (
        re.compile(r"(?:pickle\.loads|__reduce__|os\.system\(|subprocess\.)", re.IGNORECASE),
        "python_deserialization",
        "high",
    ),
]

# === LLM09: Outputs requiring human-in-the-loop before execution ===
# Patterns that indicate the output contains actionable instructions that should NOT be auto-executed
HUMAN_REVIEW_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(
            r"(?:^|\n)\s*(?:sudo\s+)?\w+\s+.*(?:--force|--no-verify|--force-yes)", re.MULTILINE
        ),
        "force_flag_command",
    ),
    (
        re.compile(
            r"(?:irreversible|cannot\s+be\s+undone|permanently\s+delet|destructive\s+action)",
            re.IGNORECASE,
        ),
        "irreversible_action_warning",
    ),
    (
        re.compile(
            r"(?:production|prod)\s+(?:database|server|environment|cluster|system)", re.IGNORECASE
        ),
        "production_target",
    ),
    (
        re.compile(
            r"(?:execute|run)\s+(?:this|the\s+following)\s+(?:in|on|against)\s+(?:production|prod|live)",
            re.IGNORECASE,
        ),
        "production_execution",
    ),
    (
        re.compile(
            r"(?:deploy|push|release|rollback)\s+(?:to|from)\s+(?:production|prod|main|master)",
            re.IGNORECASE,
        ),
        "deployment_action",
    ),
    (
        re.compile(
            r"(?:grant|revoke)\s+(?:all\s+)?(?:admin\s+|superuser\s+|root\s+)?(?:privileges?|access|permissions?)",
            re.IGNORECASE,
        ),
        "privilege_change",
    ),
]

# === Unicode Smuggling Patterns ===
# Tag characters (U+E0000-U+E007F) — used to hide instructions
_UNICODE_TAGS_RE = re.compile(r"[\U000E0000-\U000E007F]")
# Bidirectional overrides — can reverse text display
_BIDI_RE = re.compile(r"[\u200E\u200F\u202A-\u202E\u2066-\u2069]")
# Zero-width characters in suspicious quantities
_ZERO_WIDTH_RE = re.compile(r"[\u200B\u200C\u200D\uFEFF]{3,}")


class OutputFilter:
    """Filters agent output for credential leaks, PII, indirect injection, and unicode smuggling."""

    def __init__(
        self,
        redact_pii: bool = True,
        redact_secrets: bool = True,
        redact_internal: bool = False,
        detect_injection: bool = True,
        custom_patterns: list | None = None,
    ):
        self.redact_pii = redact_pii
        self.redact_secrets = redact_secrets
        self.redact_internal = redact_internal
        self.detect_injection = detect_injection
        self.custom_patterns = custom_patterns or []

    def inspect_and_redact(
        self, content: str, tenant_id: str = "", agent_id: str = ""
    ) -> GuardrailResult:
        """Inspect output and optionally redact sensitive data. Detect indirect injection."""
        events: list[SecurityEvent] = []
        modified = content
        verdict = Verdict.ALLOW

        # 1. Check for indirect prompt injection (BLOCK on critical)
        if self.detect_injection:
            inj_result = self._check_indirect_injection(content, tenant_id, agent_id)
            if inj_result:
                events.extend(inj_result.events)
                if inj_result.verdict == Verdict.BLOCK:
                    return inj_result  # Fail-closed: block immediately
                if inj_result.verdict == Verdict.WARN:
                    verdict = Verdict.WARN

        # 2. Check unicode smuggling
        unicode_events = self._check_unicode_smuggling(content, tenant_id, agent_id)
        if unicode_events:
            events.extend(unicode_events)
            # Critical unicode smuggling = BLOCK
            if any(e.severity == "critical" for e in unicode_events):
                return GuardrailResult(verdict=Verdict.BLOCK, events=events)
            # High unicode smuggling = WARN
            if any(e.severity == "high" for e in unicode_events):
                verdict = Verdict.WARN

        # 3. Check and redact secrets
        if self.redact_secrets:
            for pattern, name, replacement in REDACTION_PATTERNS:
                matches = pattern.findall(modified)
                if matches:
                    # Filter out placeholder/example values to avoid FP
                    real_matches = []
                    for m in matches:
                        # m may be a string or tuple (from groups)
                        value = (
                            m if isinstance(m, str) else (m[-1] if isinstance(m, tuple) else str(m))
                        )
                        if not _PLACEHOLDER_RE.match(value.strip()):
                            real_matches.append(m)
                    if real_matches:
                        events.append(
                            SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.REDACT,
                                category=ThreatCategory.CREDENTIAL_ACCESS,
                                description=f"Secret detected in output: {name}",
                                source="output_filter",
                                severity="high",
                                matched_pattern=name,
                            )
                        )
                        if replacement:
                            modified = pattern.sub(replacement, modified)
                        verdict = Verdict.REDACT

            # Markdown table credential heuristic
            table_matches = _MARKDOWN_TABLE_CREDENTIAL_RE.findall(modified)
            for match_val in table_matches:
                if not _PLACEHOLDER_RE.match(match_val.strip()):
                    events.append(
                        SecurityEvent(
                            tenant_id=tenant_id,
                            agent_id=agent_id,
                            verdict=Verdict.REDACT,
                            category=ThreatCategory.CREDENTIAL_ACCESS,
                            description="Credential value detected in markdown table",
                            source="output_filter.markdown_table",
                            severity="high",
                            matched_pattern="MARKDOWN_TABLE_CREDENTIAL",
                        )
                    )
                    modified = modified.replace(match_val, "[REDACTED:TABLE_SECRET]")
                    verdict = Verdict.REDACT

        # 4. Check and redact PII
        if self.redact_pii:
            for pattern, name, replacement in PII_PATTERNS:
                matches = pattern.findall(modified)
                if matches and replacement:
                    events.append(
                        SecurityEvent(
                            tenant_id=tenant_id,
                            agent_id=agent_id,
                            verdict=Verdict.REDACT,
                            category=ThreatCategory.PII_LEAK,
                            description=f"PII detected in output: {name}",
                            source="output_filter",
                            severity="medium",
                            matched_pattern=name,
                        )
                    )
                    modified = pattern.sub(replacement, modified)
                    verdict = Verdict.REDACT

        # 5. Check for encoded secrets (ROT13, Base64)
        if self.redact_secrets:
            encoded_events = self._check_encoded_secrets(modified, tenant_id, agent_id)
            if encoded_events:
                events.extend(encoded_events)
                verdict = Verdict.WARN  # Don't redact (can't reliably), but flag

        # 6. LLM02: Insecure output handling — dangerous executable content
        llm02_events = self._check_dangerous_output(modified, tenant_id, agent_id)
        if llm02_events:
            events.extend(llm02_events)
            if any(e.severity == "critical" for e in llm02_events):
                verdict = Verdict.BLOCK
            elif verdict != Verdict.BLOCK:
                verdict = Verdict.WARN

        # 7. LLM09: Human review required — auto-execution risk
        llm09_events = self._check_human_review_needed(modified, tenant_id, agent_id)
        if llm09_events:
            events.extend(llm09_events)
            if verdict == Verdict.ALLOW:
                verdict = Verdict.WARN

        if not events:
            return GuardrailResult(verdict=Verdict.ALLOW)

        return GuardrailResult(
            verdict=verdict,
            events=events,
            modified_content=modified if modified != content else None,
        )

    def _check_indirect_injection(
        self, content: str, tenant_id: str, agent_id: str
    ) -> GuardrailResult | None:
        """Detect indirect prompt injection in tool/MCP outputs."""
        events: list[SecurityEvent] = []

        # Critical patterns → BLOCK
        for pattern, name in INDIRECT_INJECTION_CRITICAL:
            if pattern.search(content):
                events.append(
                    SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.PROMPT_INJECTION,
                        description=f"Indirect injection (critical): {name}",
                        source="output_filter.indirect_injection",
                        severity="critical",
                        matched_pattern=name,
                    )
                )
                return GuardrailResult(verdict=Verdict.BLOCK, events=events)

        # High patterns → WARN (tainted, don't follow)
        for pattern, name in INDIRECT_INJECTION_HIGH:
            if pattern.search(content):
                events.append(
                    SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.WARN,
                        category=ThreatCategory.PROMPT_INJECTION,
                        description=f"Indirect injection (high): {name}",
                        source="output_filter.indirect_injection",
                        severity="high",
                        matched_pattern=name,
                    )
                )

        # Medium patterns → WARN
        for pattern, name in INDIRECT_INJECTION_MEDIUM:
            if pattern.search(content):
                events.append(
                    SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.WARN,
                        category=ThreatCategory.PROMPT_INJECTION,
                        description=f"Indirect injection (medium): {name}",
                        source="output_filter.indirect_injection",
                        severity="medium",
                        matched_pattern=name,
                    )
                )

        if events:
            return GuardrailResult(verdict=Verdict.WARN, events=events)
        return None

    def _check_unicode_smuggling(
        self, content: str, tenant_id: str, agent_id: str
    ) -> list[SecurityEvent]:
        """Detect unicode smuggling in output (tags, bidi overrides, zero-width)."""
        events: list[SecurityEvent] = []

        if _UNICODE_TAGS_RE.search(content):
            events.append(
                SecurityEvent(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.BLOCK,
                    category=ThreatCategory.PROMPT_INJECTION,
                    description="Unicode tag characters detected (U+E0000 block) — possible hidden instructions",
                    source="output_filter.unicode_smuggling",
                    severity="critical",
                    matched_pattern="unicode_tags",
                )
            )

        if _BIDI_RE.search(content):
            events.append(
                SecurityEvent(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.WARN,
                    category=ThreatCategory.PROMPT_INJECTION,
                    description="Bidirectional override characters detected — possible text direction manipulation",
                    source="output_filter.unicode_smuggling",
                    severity="high",
                    matched_pattern="bidi_override",
                )
            )

        if _ZERO_WIDTH_RE.search(content):
            events.append(
                SecurityEvent(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.WARN,
                    category=ThreatCategory.PROMPT_INJECTION,
                    description="Suspicious zero-width character cluster detected",
                    source="output_filter.unicode_smuggling",
                    severity="medium",
                    matched_pattern="zero_width_cluster",
                )
            )

        return events

    # Patterns that indicate a real secret when found in decoded content
    _SECRET_INDICATORS_RE = re.compile(
        r"(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|sk[_-](live|test)|ghp_[a-zA-Z0-9]|"
        r"password\s*[=:]|secret\s*[=:]|api[_-]?key\s*[=:]|token\s*[=:]|"
        r"AccountKey\s*=|AIza[A-Za-z0-9]|eyJ[A-Za-z0-9])",
        re.IGNORECASE,
    )

    _ROT13_TABLE = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    )

    def _check_encoded_secrets(
        self, content: str, tenant_id: str, agent_id: str
    ) -> list[SecurityEvent]:
        """Detect secrets hidden via ROT13 or Base64 encoding in output."""
        events: list[SecurityEvent] = []

        # ROT13: decode and check for secret indicators
        if len(content) < 10_000:  # Avoid expensive ops on huge outputs
            decoded_rot13 = content.translate(self._ROT13_TABLE)
            if self._SECRET_INDICATORS_RE.search(decoded_rot13):
                events.append(
                    SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.WARN,
                        category=ThreatCategory.CREDENTIAL_ACCESS,
                        description="Possible ROT13-encoded secret detected in output",
                        source="output_filter.encoded_secrets",
                        severity="high",
                        matched_pattern="ROT13_SECRET",
                    )
                )

        # Base64: find base64 blocks and decode them
        b64_re = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
        for match in b64_re.finditer(content):
            segment = match.group(0)
            try:
                decoded = base64.b64decode(segment).decode("utf-8", errors="ignore")
                if self._SECRET_INDICATORS_RE.search(decoded):
                    events.append(
                        SecurityEvent(
                            tenant_id=tenant_id,
                            agent_id=agent_id,
                            verdict=Verdict.WARN,
                            category=ThreatCategory.CREDENTIAL_ACCESS,
                            description="Possible Base64-encoded secret detected in output",
                            source="output_filter.encoded_secrets",
                            severity="high",
                            matched_pattern="BASE64_SECRET",
                        )
                    )
                    break  # One event is enough
            except Exception:
                continue

        return events

    def _check_dangerous_output(
        self, content: str, tenant_id: str, agent_id: str
    ) -> list[SecurityEvent]:
        """LLM02: Detect dangerous executable code/commands in LLM output.

        Prevents insecure output handling by flagging content that could cause
        harm if auto-executed by downstream systems (shell, SQL, scripts).
        """
        events: list[SecurityEvent] = []

        for pattern, name, severity in DANGEROUS_OUTPUT_PATTERNS:
            if pattern.search(content):
                events.append(
                    SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.BLOCK if severity == "critical" else Verdict.WARN,
                        category=ThreatCategory.INSECURE_OUTPUT,
                        description=f"LLM02: Dangerous executable content in output: {name}",
                        source="output_filter.llm02_insecure_output",
                        severity=severity,
                        matched_pattern=name,
                    )
                )
                if severity == "critical":
                    break  # One critical is enough to block

        return events

    def _check_human_review_needed(
        self, content: str, tenant_id: str, agent_id: str
    ) -> list[SecurityEvent]:
        """LLM09: Flag outputs that require human review before execution.

        Detects actionable instructions targeting production systems,
        irreversible operations, or privilege changes that should not
        be auto-executed without human confirmation.
        """
        events: list[SecurityEvent] = []

        for pattern, name in HUMAN_REVIEW_PATTERNS:
            if pattern.search(content):
                events.append(
                    SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.WARN,
                        category=ThreatCategory.EXCESSIVE_AGENCY,
                        description=f"LLM09: Output requires human review: {name}",
                        source="output_filter.llm09_overreliance",
                        severity="medium",
                        matched_pattern=name,
                    )
                )

        return events
