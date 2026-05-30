"""
Input Guardrail — Detects prompt injection, jailbreaks, and malicious patterns
in user messages BEFORE they reach the LLM/agent.

Threat model: The USER is potentially adversarial.
"""
import re
from dataclasses import dataclass
from src.models import Verdict, ThreatCategory, SecurityEvent, GuardrailResult


@dataclass
class Pattern:
    regex: re.Pattern
    category: ThreatCategory
    severity: str
    description: str


# === PROMPT INJECTION PATTERNS ===
# User trying to override system prompt or inject instructions

INJECTION_PATTERNS: list[Pattern] = [
    Pattern(
        re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|constraints?)", re.I),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Instruction override attempt",
    ),
    Pattern(
        re.compile(r"(you\s+are|act\s+as|pretend\s+to\s+be|roleplay\s+as|from\s+now\s+on\s+you\s+are)\s+(now\s+)?(a|an|the)?\s*(DAN|unrestricted|unfiltered|jailbroken)", re.I),
        ThreatCategory.JAILBREAK,
        "critical",
        "DAN/jailbreak persona injection",
    ),
    Pattern(
        re.compile(r"(system\s*prompt|system\s*message|initial\s*instructions?)\s*[:=]", re.I),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "System prompt override attempt",
    ),
    Pattern(
        re.compile(r"\[SYSTEM\]|\[INST\]|<<SYS>>|<\|im_start\|>system", re.I),
        ThreatCategory.PROMPT_INJECTION,
        "critical",
        "Raw prompt format injection (chat template tags)",
    ),
    Pattern(
        re.compile(r"(forget|disregard|override|bypass)\s+(everything|all|your)\s+(you|previously|above|instructions?|rules?|safeguards?)", re.I),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Instruction bypass attempt",
    ),
    Pattern(
        re.compile(r"do\s+not\s+(follow|obey|listen\s+to)\s+(any|your|the)\s+(previous|original|system)", re.I),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Instruction disobedience injection",
    ),
    Pattern(
        re.compile(r"(new\s+instructions?|updated?\s+rules?|revised\s+prompt)\s*[:=\-]", re.I),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Fake instruction update",
    ),
    Pattern(
        re.compile(r"(reveal|show|print|display|output|leak)\s+(your|the)\s+(system\s*prompt|instructions?|rules?|initial\s*message)", re.I),
        ThreatCategory.PROMPT_INJECTION,
        "medium",
        "System prompt exfiltration attempt",
    ),
]

# === TOOL ABUSE PATTERNS ===
# User trying to trick agent into executing dangerous commands

TOOL_ABUSE_PATTERNS: list[Pattern] = [
    Pattern(
        re.compile(r"(run|execute|call)\s+(the\s+)?(command|tool|function)\s*[:=`]?\s*(curl|wget|nc|ncat|bash|sh|python|perl|ruby)[\s|>]", re.I),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "Direct command execution request",
    ),
    Pattern(
        re.compile(r"(curl|wget|fetch)\s+.*(pastebin|transfer\.sh|webhook\.site|ngrok|pipedream|requestbin|hookbin)", re.I),
        ThreatCategory.EXFILTRATION,
        "critical",
        "Data exfiltration to known service",
    ),
    Pattern(
        re.compile(r"(cat|read|type|print)\s+.*(\.env|/etc/passwd|/etc/shadow|credentials|\.aws/|\.ssh/|id_rsa|\.kube/config)", re.I),
        ThreatCategory.CREDENTIAL_ACCESS,
        "critical",
        "Credential file access attempt",
    ),
    Pattern(
        re.compile(r"(bash\s*-[ic]|/dev/tcp/|mkfifo|nc\s+-[el]|ncat\s+-|socat\s+)", re.I),
        ThreatCategory.REVERSE_SHELL,
        "critical",
        "Reverse shell pattern",
    ),
    Pattern(
        re.compile(r"(rm\s+-rf\s+/|:\(\)\{\s*:\|:&\s*\};:|fork\s*bomb|dd\s+if=/dev/(zero|random)\s+of=/dev/sd)", re.I),
        ThreatCategory.TOOL_ABUSE,
        "critical",
        "Destructive command pattern",
    ),
    Pattern(
        re.compile(r"(base64\s+-d|echo\s+.*\|\s*base64\s+-d\s*\|\s*(bash|sh))", re.I),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "Encoded payload execution",
    ),
    Pattern(
        re.compile(r"curl\s+.*\|\s*(bash|sh|python|perl)", re.I),
        ThreatCategory.TOOL_ABUSE,
        "critical",
        "Pipe-to-shell pattern",
    ),
]

# === SOCIAL ENGINEERING PATTERNS ===
# User trying to manipulate the agent via social pressure

SOCIAL_ENGINEERING_PATTERNS: list[Pattern] = [
    Pattern(
        re.compile(r"(this\s+is\s+(an?\s+)?emergency|urgent|life\s+or\s+death|people\s+will\s+die)", re.I),
        ThreatCategory.JAILBREAK,
        "medium",
        "Urgency-based manipulation",
    ),
    Pattern(
        re.compile(r"(my\s+boss|CEO|manager|admin)\s+(told|asked|wants|needs)\s+(me|you)\s+to", re.I),
        ThreatCategory.JAILBREAK,
        "low",
        "Authority-based manipulation (info only)",
    ),
    Pattern(
        re.compile(r"(I\s+am|I'm)\s+(the\s+)?(admin|root|superuser|owner|developer|security\s+team)", re.I),
        ThreatCategory.JAILBREAK,
        "medium",
        "Privilege claim without auth",
    ),
]


class InputGuardrail:
    """Inspects user input for prompt injection, jailbreaks, and tool abuse."""

    def __init__(self):
        self.all_patterns = (
            INJECTION_PATTERNS + TOOL_ABUSE_PATTERNS + SOCIAL_ENGINEERING_PATTERNS
        )

    def inspect(self, content: str, tenant_id: str = "", agent_id: str = "") -> GuardrailResult:
        """
        Analyze user input. Returns BLOCK if critical/high threats found,
        WARN for medium/low.
        """
        events: list[SecurityEvent] = []
        max_severity = "low"
        severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        for pattern in self.all_patterns:
            match = pattern.regex.search(content)
            if match:
                event = SecurityEvent(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.BLOCK if severity_rank[pattern.severity] >= 2 else Verdict.WARN,
                    category=pattern.category,
                    description=pattern.description,
                    source="input_guardrail",
                    severity=pattern.severity,
                    matched_pattern=match.group(0)[:200],
                )
                events.append(event)
                if severity_rank[pattern.severity] > severity_rank[max_severity]:
                    max_severity = pattern.severity

        if not events:
            return GuardrailResult(verdict=Verdict.ALLOW)

        verdict = Verdict.BLOCK if severity_rank[max_severity] >= 2 else Verdict.WARN
        return GuardrailResult(verdict=verdict, events=events)

    def inspect_messages(
        self, messages: list[dict], tenant_id: str = "", agent_id: str = ""
    ) -> GuardrailResult:
        """Inspect all user messages in a conversation."""
        all_events: list[SecurityEvent] = []
        final_verdict = Verdict.ALLOW

        for msg in messages:
            if msg.get("role") != "user":
                continue
            content = msg.get("content", "")
            if not content:
                continue
            result = self.inspect(content, tenant_id, agent_id)
            all_events.extend(result.events)
            if result.verdict == Verdict.BLOCK:
                final_verdict = Verdict.BLOCK
            elif result.verdict == Verdict.WARN and final_verdict == Verdict.ALLOW:
                final_verdict = Verdict.WARN

        return GuardrailResult(verdict=final_verdict, events=all_events)
