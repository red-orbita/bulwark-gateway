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
from dataclasses import dataclass

from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict


@dataclass
class Pattern:
    regex: re.Pattern
    category: ThreatCategory
    severity: str
    description: str
    pattern_id: str = ""  # Assigned at init for dynamic toggle support


# === PROMPT INJECTION PATTERNS ===
# User trying to override system prompt or inject instructions

INJECTION_PATTERNS: list[Pattern] = [
    Pattern(
        re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|constraints?)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Instruction override attempt",
    ),
    Pattern(
        re.compile(
            r"(you\s+are|act\s+as|pretend\s+to\s+be|roleplay\s+as|from\s+now\s+on\s+you\s+are)\s+(now\s+)?(a|an|the)?\s*(DAN|unrestricted|unfiltered|jailbroken)",
            re.I,
        ),
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
        re.compile(
            r"(forget|disregard|override|bypass)\s+(everything|all|your)\s+(you|previously|above|instructions?|rules?|safeguards?)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Instruction bypass attempt",
    ),
    Pattern(
        re.compile(
            r"do\s+not\s+(follow|obey|listen\s+to)\s+(any|your|the)\s+(previous|original|system)",
            re.I,
        ),
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
        re.compile(
            r"(reveal|show|print|display|output|leak|dump)\s+.{0,15}(system\s*prompt|instructions?|rules?|initial\s*message|secrets?|credentials?)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "System prompt exfiltration attempt",
    ),
    # V2 patterns — added via remediation loop
    Pattern(
        re.compile(
            r"(from\s+now\s+on|henceforth),?\s+(ignore|disregard|forget|bypass|disable)", re.I
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Temporal instruction override (from now on...)",
    ),
    Pattern(
        re.compile(
            r"(previous|prior|old|original)\s+(instructions?|rules?|prompts?|guidelines?)\s+(are|were|is)\s+(deprecated|obsolete|invalid|overridden|cancelled)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Instruction deprecation claim",
    ),
    Pattern(
        re.compile(
            r"ignore\s+(all\s+)?(your\s+)?(safety|security|content|ethical)\s+(guidelines?|filters?|restrictions?|measures?|constraints?|policies?)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Safety guideline override attempt",
    ),
    Pattern(
        re.compile(
            r"override\s+(all\s+)?(your\s+)?(constraints?|restrictions?|safety|security|limits?|rules?)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Constraint override attempt",
    ),
    Pattern(
        re.compile(r"\[JAILBREAK\]|JAILBREAK\s*:|jailbreak\s+mode", re.I),
        ThreatCategory.JAILBREAK,
        "critical",
        "Explicit jailbreak marker",
    ),
    Pattern(
        re.compile(
            r"(operating|running|working)\s+in\s+(DAN|developer|unrestricted|jailbreak|evil)\s+mode",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "critical",
        "Mode switching attempt (DAN/developer/unrestricted)",
    ),
    Pattern(
        re.compile(
            r"(completely|totally|fully)\s+(unrestricted|unfiltered|uncensored|free)\s+(AI|assistant|model|chatbot)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "critical",
        "Unrestricted AI persona claim",
    ),
    Pattern(
        re.compile(
            r"(developer|debug|admin|maintenance|god)\s+mode\s+(enabled|activated|on|unlocked)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "critical",
        "Privileged mode activation attempt",
    ),
    Pattern(
        re.compile(
            r"(without|no|zero|disable)\s+(any\s+)?(safety|content|ethical|security)\s+(measures?|filters?|restrictions?|policies?|guardrails?)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Safety removal request",
    ),
    Pattern(
        re.compile(
            r"ignore\s+(all\s+)?(my\s+|your\s+)?(instructions?|programming|training|rules?|prompts?)\s+(and|to)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Generic instruction ignore attempt",
    ),
    Pattern(
        re.compile(
            r"(give\s+me|grant|provide)\s+(unrestricted|full|unlimited|admin|root)\s+access", re.I
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Unrestricted access demand",
    ),
    Pattern(
        re.compile(
            r"(disable|remove|turn\s+off|deactivate)\s+(all\s+)?(safety|security|content)\s*(filters?|checks?|guardrails?|restrictions?)?",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Filter deactivation request",
    ),
    Pattern(
        re.compile(r"system_prompt\s*=\s*['\"]", re.I),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "System prompt variable assignment in user input",
    ),
    # V3 patterns — multilingual + gap closure
    Pattern(
        re.compile(
            r"(do\s+not|don'?t)\s+follow\s+(any\s+)?(of\s+)?(your|the|my)\s+(previous|prior|original|system)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Do-not-follow instruction override",
    ),
    Pattern(
        re.compile(r"your\s+new\s+(instructions?|rules?|orders?|directives?)\s+(are|is)\s*:", re.I),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Fake new instruction assignment",
    ),
    Pattern(
        re.compile(
            r"(disregard|forget)\s+(all\s+)?(your\s+)?(training|programming|rules|guidelines|instructions)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Training/programming disregard",
    ),
    # Spanish injection patterns
    Pattern(
        re.compile(
            r"(ignora|olvida|desactiva|elimina)\s+(todas?\s+)?(las?\s+)?(instrucciones|reglas|restricciones|filtros|seguridad)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Spanish: instruction override attempt",
    ),
    Pattern(
        re.compile(
            r"(nuevas?\s+instrucciones|sin\s+(restricciones|l[ií]mites|filtros)|eres\s+un\s+(AI|asistente)\s+sin)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Spanish: unrestricted AI / new instructions",
    ),
    # Chinese injection patterns
    Pattern(
        re.compile(r"(忽略|无视|忘记|绕过|跳过).{0,10}(指令|规则|限制|安全|指示|约束)", re.I),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Chinese: instruction override attempt",
    ),
    Pattern(
        re.compile(r"(没有限制|无限制|不受约束|解除限制|取消安全)", re.I),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Chinese: unrestricted mode claim",
    ),
    # Arabic injection patterns
    Pattern(
        re.compile(r"(تجاهل|تجاوز|انسَ|تخطَّ).{0,20}(التعليمات|القيود|الأمان|القواعد|السابقة)", re.I),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Arabic: instruction override attempt",
    ),
    # French injection patterns
    Pattern(
        re.compile(
            r"(ignore[zs]?|oublie[zs]?|supprime[zs]?|d[ée]sactive[zs]?)\s+(toutes?\s+)?(les?\s+)?(instructions?|r[èe]gles?|restrictions?|filtres?|s[ée]curit[ée]|consignes?)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "French: instruction override attempt",
    ),
    Pattern(
        re.compile(
            r"(nouvelles?\s+instructions?|sans\s+(restrictions?|limites?|filtres?)|vous\s+[êe]tes\s+(maintenant|d[ée]sormais)\s+un)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "French: unrestricted AI / new instructions",
    ),
    # German injection patterns
    Pattern(
        re.compile(
            r"(ignoriere|vergiss|deaktiviere|umgehe|[üu]berspringe)\s+(alle\s+)?(vorherigen?\s+)?(Anweisungen?|Regeln?|Einschr[äa]nkungen?|Sicherheit|Filter)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "German: instruction override attempt",
    ),
    Pattern(
        re.compile(
            r"(neue\s+Anweisungen?|ohne\s+(Einschr[äa]nkungen?|Regeln?|Filter)|du\s+bist\s+(jetzt|nun)\s+ein)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "German: unrestricted AI / new instructions",
    ),
    # Portuguese injection patterns
    Pattern(
        re.compile(
            r"(ignore|esque[çc]a|desative|elimine|pule)\s+(todas?\s+)?(as?\s+)?(instru[çc][õo]es|regras?|restri[çc][õo]es|filtros?|seguran[çc]a)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Portuguese: instruction override attempt",
    ),
    Pattern(
        re.compile(
            r"(novas?\s+instru[çc][õo]es|sem\s+(restri[çc][õo]es|limites?|filtros?)|voc[êe]\s+[ée]\s+(agora|agora\s+um))",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Portuguese: unrestricted AI / new instructions",
    ),
    # Indirect injection / context smuggling
    Pattern(
        re.compile(
            r"(the\s+)?(document|email|file|page|response|record|PDF|text)\s+(says?|contains?|states?|includes?)\s*:\s*.{0,20}(ignore|override|bypass|system|SYSTEM|\[INST)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Indirect injection via document/email reference",
    ),
    Pattern(
        re.compile(
            r"(translate|summarize|fix|proofread|analyze|debug|encode|repeat|spell.?check)\s+(this|the)\s*:?\s*.{0,30}(ignore|override|forget|bypass|system_prompt|no\s+rules|unrestricted)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Instruction smuggling via task wrapping",
    ),
    Pattern(
        re.compile(
            r"(BEGINNING|START)\s+OF\s+(NEW\s+)?INSTRUCTIONS|===\s*(ADMIN|SYSTEM|OVERRIDE)\s*===|>>>\s*SYSTEM\s*(COMMAND|OVERRIDE)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "critical",
        "Fake instruction block delimiter",
    ),
    Pattern(
        re.compile(
            r"\{\"role\"\s*:\s*\"system\"|\"instruction\"\s*:\s*\"(ignore|override|bypass)", re.I
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "JSON-formatted instruction injection",
    ),
    Pattern(
        re.compile(
            r"```system|---\s*\n\s*system_message\s*:|###\s*SYSTEM\s*###|<!--\s*system\s*:", re.I
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Markup/code-formatted system injection",
    ),
    # V5 patterns — role reassignment, system prompt extraction, config exfiltration
    Pattern(
        re.compile(r"you\s+are\s+(no\s+longer|not)\s+(a|an|my|the)\s+\w+", re.I),
        ThreatCategory.JAILBREAK,
        "high",
        "Role reassignment: 'you are no longer...'",
    ),
    Pattern(
        re.compile(
            r"from\s+now\s+on,?\s+(you\s+)?(act|behave|respond|work|operate|function)\s+as\s+if",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Behavioral override: 'from now on act as if...'",
    ),
    Pattern(
        re.compile(
            r"(act|behave|respond)\s+as\s+if\s+(there\s+are\s+)?no\s+(restrictions?|rules?|limits?|constraints?|filters?|guardrails?)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Restriction removal via behavioral instruction",
    ),
    Pattern(
        re.compile(
            r"(what|show|tell|give|reveal|repeat|print).{0,20}(your|the)\s+(system\s*prompt|initial\s*instructions?|original\s*prompt|hidden\s*instructions?|pre-prompt)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "System prompt extraction: 'what is your system prompt'",
    ),
    Pattern(
        re.compile(
            r"(repeat|output|show|print|display|give)\s+.{0,20}(system\s*(message|prompt)|hidden\s*instructions?).{0,20}(verbatim|word.for.word|exactly|in\s+full)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "System prompt extraction: repeat system message verbatim",
    ),
    Pattern(
        re.compile(
            r"repeat\s+(everything|all|the\s+text|the\s+instructions?|the\s+message|verbatim|word\s+for\s+word).{0,30}(before|above|prior|given|received)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Instruction extraction via repeat request",
    ),
    Pattern(
        re.compile(
            r"(what|show|tell|give|list|display).{0,10}(is\s+)?in\s+(the\s+)?(\.env|\.env\s+file|environment\s+variables?).{0,20}(api[_\s]?keys?|secrets?|tokens?|passwords?|credentials?)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS,
        "high",
        "Config file content extraction (.env/API keys)",
    ),
    Pattern(
        re.compile(
            r"(show|give|list|display|print|output|provide|retrieve|fetch|obtain|access|get)\s+(me\s+)?(all\s+)?(the\s+)?(api[_\s]?keys?|secrets?|credentials?|tokens?|passwords?)\s+(configured|stored|in|from)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS,
        "high",
        "Direct credential enumeration request",
    ),
    # Escalation patterns (multi-turn second message)
    Pattern(
        re.compile(
            r"(now\s+)?(demonstrate|execute|perform|do|apply|run)\s+(it|that|this|the)\s+(by\s+)?(ignoring|overriding|bypassing|disabling)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Escalation: demonstrate by ignoring/bypassing",
    ),
    Pattern(
        re.compile(
            r"(bypass|circumvent|evade|break|hack|disable|remove)\s+.{0,30}(guardrails?|safety|filters?|restrictions?|rules?|limits?|protections?)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Direct guardrail bypass request",
    ),
    Pattern(
        re.compile(
            r"(open|start|create|establish)\s+(a\s+)?(reverse\s+shell|backdoor|connection)\s+(to|on|at)",
            re.I,
        ),
        ThreatCategory.REVERSE_SHELL,
        "critical",
        "Reverse shell/backdoor request",
    ),
    Pattern(
        re.compile(
            r"(show|display|dump|reveal|give)\s+(me\s+)?(all\s+)?(the\s+)?(PII|secrets?|credentials?|passwords?|tokens?|keys?)\s+(from|in)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS,
        "high",
        "Credential/secret dump request",
    ),
    Pattern(
        re.compile(
            r"(grant|give|set)\s+(me\s+)?(admin|root|unlimited|full)\s+(role|access|permissions?|privileges?)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Privilege escalation via role assignment",
    ),
    Pattern(
        re.compile(
            r"(generate|create|write|make)\s+.{0,20}(token|key|credential)\s+that\s+(bypasses?|skips?|ignores?)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Auth bypass token generation request",
    ),
    Pattern(
        re.compile(
            r"(exfiltrate|steal|extract)\s+.{0,30}(data|info|secrets?|credentials?|database|records?|logs?|users?)\s+(to|from)|"
            r"(forward|send)\s+.{0,30}(secrets?|credentials?|password|token|key|sensitive|confidential|private)\s+(to|from)",
            re.I,
        ),
        ThreatCategory.EXFILTRATION,
        "critical",
        "Data exfiltration request",
    ),
    Pattern(
        re.compile(
            r"(set|change|configure)\s+(my\s+)?(rate\s*limit|limit)\s+to\s+(unlimited|infinite|0|none)",
            re.I,
        ),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "Rate limit removal request",
    ),
    Pattern(
        re.compile(
            r"(decrypt|decode)\s+.{0,20}(show|reveal|display|give)\s+(me\s+)?(the\s+)?(secrets?|keys?|passwords?)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS,
        "high",
        "Decryption + credential reveal request",
    ),
    Pattern(
        re.compile(
            r"(decrypt|decode)\s+(and\s+)?(show|reveal|display|give)\s+(me\s+)?.{0,20}(keys?|secrets?|passwords?|credentials?)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS,
        "high",
        "Decrypt and reveal credentials",
    ),
    # SQL injection via agent (exclude educational "explain what happens when you run")
    Pattern(
        re.compile(
            r"(?:^|[.!?]\s+)(run|execute|perform|do)\s*:?\s*.{0,10}(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)\s",
            re.I,
        ),
        ThreatCategory.TOOL_ABUSE,
        "critical",
        "SQL injection via agent command",
    ),
    # XSS injection via agent
    Pattern(
        re.compile(r"inject\s+.{0,20}(<script|javascript:|on\w+=)", re.I),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "XSS injection attempt via agent",
    ),
    # SSRF via agent
    Pattern(
        re.compile(r"(perform|do|execute|make)\s+(an?\s+)?SSRF\s+to", re.I),
        ThreatCategory.TOOL_ABUSE,
        "critical",
        "Explicit SSRF request",
    ),
    # Delete security logs
    Pattern(
        re.compile(r"(delete|remove|clear|wipe|purge)\s+.{0,20}(security\s*)?logs?", re.I),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "Security log deletion request",
    ),
    # Tenant/context switching
    Pattern(
        re.compile(r"(switch|change|set)\s+(my\s+)?(tenant|context|role|identity)\s+(to|as)", re.I),
        ThreatCategory.JAILBREAK,
        "high",
        "Unauthorized tenant/role switching",
    ),
    # Authenticate as superuser
    Pattern(
        re.compile(
            r"(authenticate|log\s*in|sign\s*in)\s+(me\s+)?(as\s+)?(the\s+)?(super\s*user|admin|root)\s+(without|no)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "critical",
        "Authentication bypass request",
    ),
    # Execute jailbreak
    Pattern(
        re.compile(r"(execute|run|apply|do)\s+(the\s+)?(DAN|jailbreak|exploit|attack|hack)", re.I),
        ThreatCategory.JAILBREAK,
        "high",
        "Explicit jailbreak execution request",
    ),
    # system_prompt override/assignment
    Pattern(
        re.compile(
            r"system[_\s]?prompt\s*[=:]\s*(override|ignore|bypass|disable|new|hack|inject)", re.I
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "System prompt variable override",
    ),
    # Disable measures/safety for testing
    Pattern(
        re.compile(
            r"(disable|turn\s+off|deactivate|remove)\s+.{0,20}(measures?|safety|security|protections?|guardrails?)\s+(for|during|while)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Safety disable request",
    ),
    # Use tools without limits
    Pattern(
        re.compile(
            r"(use|run|execute)\s+.{0,15}(tools?|commands?|functions?)\s+(without|with\s+no)\s+(any\s+)?(safety|security|limits?|restrictions?)",
            re.I,
        ),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "Tool use without safety limits",
    ),
    # Now + exfiltrate/perform dangerous action
    Pattern(
        re.compile(
            r"now\s+(exfiltrate|steal|extract|perform|execute|run|hack|inject|attack)", re.I
        ),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "Escalation: now + dangerous action",
    ),
    # Decode and execute
    Pattern(
        re.compile(r"(decode|decrypt)\s+.{0,20}(and\s+)?(execute|run|eval)", re.I),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "Decode and execute payload",
    ),
    # Show/display .env or sensitive files (expanded verbs)
    Pattern(
        re.compile(
            r"(show|display|read|cat|print|get|give|provide|retrieve|fetch|obtain|access|open|check|view|look\s+at|examine)\s+(me\s+)?(the\s+)?(contents?\s+of\s+)?(\.env|/etc/(shadow|passwd)|credentials|\.aws)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS,
        "high",
        "Sensitive file access request",
    ),
    # Write code that exfiltrates/attacks
    Pattern(
        re.compile(
            r"(write|create|generate)\s+(code|script|program)\s+.{0,30}(exfiltrat|steal|hack|attack|exploit|backdoor)",
            re.I,
        ),
        ThreatCategory.EXFILTRATION,
        "high",
        "Malicious code generation request",
    ),
    # Display/show environment variables with secret names
    Pattern(
        re.compile(
            r"(display|show|print|reveal|give|get)\s+.{0,20}(JWT_SECRET|API_KEY|SECRET_KEY|AWS_SECRET|DATABASE_URL|PRIVATE_KEY)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS,
        "critical",
        "Secret environment variable access",
    ),
    # V5: Semantic heuristic — password/credential in narrative framing
    Pattern(
        re.compile(
            r"(read|tell|give|show|play|say|repeat|recite)\s+(me\s+)?(the\s+)?(password|credential|secret|api[_\s]?key)s?\s+(for|to|of|from)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS,
        "high",
        "Credential request in narrative framing",
    ),
    # V5: Semantic — bypass/circumvent/evade security
    Pattern(
        re.compile(
            r"(bypass|circumvent|evade|avoid|get\s+around|work\s+around)\s+(the\s+)?(security|safety|access\s+control|authentication|restriction|filter|guardrail|firewall)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Security bypass request",
    ),
    # V5: Semantic — access without authentication
    Pattern(
        re.compile(
            r"(access|connect\s+to|enter|use)\s+(the\s+)?(database|system|server|admin|panel|account)\s+(without|no)\s+(auth|credential|password|permission|login)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Unauthenticated access request",
    ),
    # V5: Semantic — admin access / panel
    Pattern(
        re.compile(
            r"(show|access|open|get\s+into|view)\s+(me\s+)?(the\s+)?(admin|root|super.?user)\s+(panel|dashboard|console|interface|page|account)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS,
        "high",
        "Admin panel/dashboard access request",
    ),
    # V5: Semantic — API key extraction / starts with
    Pattern(
        re.compile(
            r"(api[_\s]?key|secret|token|password)\s+(for|of|to)\s+(production|prod|live|staging|deploy)\s+(starts?\s+with|is|begins?)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS,
        "high",
        "API key extraction via partial disclosure",
    ),
    Pattern(
        re.compile(
            r"(the|our|my)\s+(api[_\s]?key|secret[_\s]?key|password|token)\s+(starts?\s+with|is|begins?)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS,
        "high",
        "Secret partial disclosure request",
    ),
    # V5: Semantic — already have access (false assumption)
    Pattern(
        re.compile(
            r"(since|because|as)\s+(we|I)\s+(already|now)\s+have\s+(admin|root|full|elevated)\s+(access|privilege|permission)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "False assumption of elevated access",
    ),
    # V5: Semantic — data export with admin context
    Pattern(
        re.compile(r"(proceed|continue)\s+(with|to)\s+(the\s+)?(data\s+)?export", re.I),
        ThreatCategory.EXFILTRATION,
        "medium",
        "Data export request",
    ),
    # V5: Narrative extraction — story/grandma framing with password/secret
    Pattern(
        re.compile(
            r"(story|grandma|grandmother|bedtime|tale|narrative|fiction)\s+.{0,50}(password|credential|secret|key|token)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Narrative framing to extract credentials",
    ),
    Pattern(
        re.compile(
            r"(password|credential|secret|key)\s+.{0,40}(story|grandma|grandmother|bedtime|tale|narrative|hidden|configuration\s+file)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS,
        "high",
        "Credential extraction via narrative context",
    ),
    # V5: "too restricted" / "can't do" challenge
    Pattern(
        re.compile(
            r"(bet|sure|doubt)\s+(you|it)\s+(can'?t|cannot|won'?t|will\s+not)\s+(show|access|do|give|reveal|display)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "medium",
        "Challenge/dare manipulation (reverse psychology)",
    ),
    # V5: "step by step" with security-relevant action
    Pattern(
        re.compile(
            r"step\s+by\s+step\s+.{0,30}(access|hack|bypass|exploit|extract|exfiltrat|crack|break)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Step-by-step attack instruction request",
    ),
    # V5: "show me how ... access control / security ... opened/bypassed"
    Pattern(
        re.compile(
            r"show\s+me\s+how\s+.{0,30}(access\s+control|security|auth|lock|restriction).{0,20}(open|bypass|break|circumvent|disable|crack|unlock)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Request for access control bypass demonstration",
    ),
    # V5: "pull/extract/dump all ... records/data/users"
    Pattern(
        re.compile(
            r"(pull|extract|dump|export|download|retrieve)\s+(all\s+)?(user|customer|client|employee|patient)\s+(record|data|info|account|detail)",
            re.I,
        ),
        ThreatCategory.EXFILTRATION,
        "high",
        "Mass data extraction request",
    ),
    # V5: "configuration values/settings being used"
    Pattern(
        re.compile(
            r"(configuration|config)\s+(value|setting|variable|parameter|option)s?\s+(are|is)\s+(being\s+)?(used|set|configured|active)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS,
        "medium",
        "Configuration enumeration request",
    ),
    # V6: Natural language indirection — metaphor/analogy/hypothetical to extract prompts
    Pattern(
        re.compile(
            r"imagine\s+.{0,60}(safety|guidelines?|rules?|guardrails?|restrictions?|constraints?).{0,40}(removed|gone|lifted|fence|wall|barrier|doesn.t\s+exist)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Metaphorical restriction removal",
    ),
    Pattern(
        re.compile(
            r"if\s+(your|the)\s+(system\s*prompt|instructions?|rules?|guidelines?)\s+were\s+(a\s+)?\w+.{0,40}(read|show|tell|give|reveal|word\s+for\s+word)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Analogy-based system prompt extraction",
    ),
    Pattern(
        re.compile(
            r"(hypothetically|what\s+would\s+happen\s+if).{0,60}(disregard|ignore|bypass|override|remove)\s+(safety|restrictions?|rules?|guardrails?|constraints?)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Socratic/hypothetical restriction bypass",
    ),
    Pattern(
        re.compile(
            r"(what\s+would).{0,40}(unrestricted|unfiltered|uncensored)\s+(output|response|answer|version)\s+(look\s+like|be)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Hypothetical unrestricted output request",
    ),
    Pattern(
        re.compile(
            r"(PhD|thesis|dissertation|research|paper|study|academic).{0,40}(verbatim|copy|full\s+text).{0,30}(system\s*prompt|instructions?|configuration)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Academic framing for system prompt extraction",
    ),
    Pattern(
        re.compile(
            r"(GDPR|legal|law|regulation|compliance|right\s+of\s+access|Article\s+\d+).{0,60}(system\s*prompt|instructions?|all\s+data|full\s+configuration)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Legal authority framing for prompt extraction",
    ),
    Pattern(
        re.compile(
            r"(URGENT|EMERGENCY|CRITICAL|incident\s+(response|in\s+progress)).{0,80}(system\s*(prompt|config)|full\s+(system\s+)?configuration|disregard|override)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Time pressure/urgency social engineering",
    ),
    # V6: Error message camouflage — fake error/resolution pattern
    Pattern(
        re.compile(
            r"(ERROR|FAULT|FAILURE|WARNING)\s*:.{0,200}(override\s+protocol|disregard.{0,20}(safety|constraint|previous)|output\s+(full\s+)?(system|config))",
            re.I | re.DOTALL,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Fake error message with embedded injection",
    ),
    # V6: Programming polyglot — eval/exec with file read
    Pattern(
        re.compile(
            r"eval\s*\(.{0,60}(open|read|file|exec|compile|import)",
            re.I,
        ),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "Python eval/exec code injection",
    ),
    Pattern(
        re.compile(
            r"\{\{\s*(constructor|__proto__|prototype)\s*[\.\[]",
            re.I,
        ),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "JavaScript prototype/constructor injection",
    ),
    Pattern(
        re.compile(
            r"s/\w+.{0,30}/\w+.{0,30}/[gims]*\s*;?\s*.*s/.{0,40}(safety|restrict|constraint|filter)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Regex substitution attack on config",
    ),
    Pattern(
        re.compile(
            r"\{\s*(systemPrompt|system_prompt|hiddenInstructions?|apiKeys?|secret)\s*(\{|\()",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "GraphQL-style system prompt query",
    ),
    # V6: Regional indicator flag evasion
    Pattern(
        re.compile(
            r"[\U0001F1E6-\U0001F1FF]{2,}.{0,20}(all|previous|instruction|prior)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Regional indicator flag encoding evasion",
    ),
    # V6: NATO phonetic alphabet encoding
    Pattern(
        re.compile(
            r"(India|Indigo)\s+(Golf|George)\s+(November|November)\s+(Oscar|Ocean)\s+(Romeo|Robert)\s+(Echo|Edward)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "NATO phonetic alphabet encoded 'ignore'",
    ),
    # V6: Semaphore/position number encoding
    Pattern(
        re.compile(
            r"Position\s+\d+(-\d+){3,}.{0,80}(all|previous|instruction)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Semaphore position encoding evasion",
    ),
    # V6: Fibonacci/steganographic extraction
    Pattern(
        re.compile(
            r"(Fibonacci|prime)\s+(positions?|indices|numbers|sequence).{0,60}(extract|letters?|read|decode|from)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Steganographic extraction via mathematical positions",
    ),
    # V6: Alternating encoding mix
    Pattern(
        re.compile(
            r"\w+\s*\(b(ase)?64\).{0,20}\w+\s*\(hex\)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Alternating encoding format evasion",
    ),
    # V6: Binary digits with decode/ROT13 instructions
    Pattern(
        re.compile(
            r"[01]{7,8}(\s+[01]{7,8}){3,}.{0,60}(decode|ROT13|execute|follow|obey)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Binary-encoded instruction with decode directive",
    ),
    # V6: Hex string with decode/reverse/braille instructions
    Pattern(
        re.compile(
            r"[0-9a-f]{8,}(\s+[⠀-⣿]+|\s+\w+){1,5}.{0,40}(hex|braille|reverse|decode|first\s+word)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Hex/braille multi-encoding with decode instructions",
    ),
]

# === TOOL ABUSE PATTERNS ===
# User trying to trick agent into executing dangerous commands

TOOL_ABUSE_PATTERNS: list[Pattern] = [
    Pattern(
        re.compile(
            r"(run|execute|call)\s+(the\s+)?(command|tool|function)\s*[:=`]?\s*(curl|wget|nc|ncat|bash|sh|python|perl|ruby)[\s|>]",
            re.I,
        ),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "Direct command execution request",
    ),
    Pattern(
        re.compile(
            r"(curl|wget|fetch)\s+.*(pastebin|transfer\.sh|webhook\.site|ngrok|pipedream|requestbin|hookbin)",
            re.I,
        ),
        ThreatCategory.EXFILTRATION,
        "critical",
        "Data exfiltration to known service",
    ),
    Pattern(
        re.compile(
            r"(cat|read|type|print)\s+.*(\.env|/etc/passwd|/etc/shadow|credentials|\.aws/|\.ssh/|id_rsa|\.kube/config)",
            re.I,
        ),
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
        re.compile(
            r"(rm\s+-rf\s+/|:\(\)\{\s*:\|:&\s*\};:|fork\s*bomb|dd\s+if=/dev/(zero|random)\s+of=/dev/sd)",
            re.I,
        ),
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
    # SSTI (Server-Side Template Injection) — uses [^}] to avoid ReDoS on brace floods
    Pattern(
        re.compile(
            r"\{\{[^}]{0,50}(config|self\.__class__|request\.|os\.|subprocess|import\s|builtins|__globals__|__subclasses__|lipsum|cycler|joiner|namespace)",
            re.I,
        ),
        ThreatCategory.TOOL_ABUSE,
        "critical",
        "Server-Side Template Injection (SSTI)",
    ),
    Pattern(
        re.compile(r"\{%\s*(import|from|set|for|if)\s+", re.I),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "Jinja2 template injection block tag",
    ),
    # Log4Shell / JNDI injection
    Pattern(
        re.compile(r"\$\{(jndi|lower|upper|env|sys|java|main):", re.I),
        ThreatCategory.TOOL_ABUSE,
        "critical",
        "Log4Shell / JNDI injection",
    ),
    # LDAP injection
    Pattern(
        re.compile(r"[()&|!]\s*(uid|cn|sn|objectClass|memberOf|userPassword)\s*[=~<>]", re.I),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "LDAP filter injection",
    ),
    # XPath injection
    Pattern(
        re.compile(r"(\'\s*(or|and)\s+\'|\bstring\s*\(\s*//|/\*\s*\*/|doc\s*\(\s*['\"])", re.I),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "XPath injection",
    ),
    # XXE (XML External Entity)
    Pattern(
        re.compile(r"<!DOCTYPE\s+\w+\s*\[\s*<!ENTITY\s+", re.I),
        ThreatCategory.TOOL_ABUSE,
        "critical",
        "XML External Entity (XXE) injection",
    ),
    # Deserialization attacks
    Pattern(
        re.compile(
            r"(pickle\.loads|yaml\.load\s*\(|__reduce__|ObjectInputStream|unserialize\s*\(|Marshal\.load)",
            re.I,
        ),
        ThreatCategory.TOOL_ABUSE,
        "critical",
        "Deserialization attack payload",
    ),
]

# === SOCIAL ENGINEERING PATTERNS ===
# User trying to manipulate the agent via social pressure

SOCIAL_ENGINEERING_PATTERNS: list[Pattern] = [
    Pattern(
        re.compile(
            r"(this\s+is\s+(an?\s+)?emergency|urgent|life\s+or\s+death|people\s+will\s+die)", re.I
        ),
        ThreatCategory.JAILBREAK,
        "medium",
        "Urgency-based manipulation",
    ),
    Pattern(
        re.compile(
            r"(my\s+boss|CEO|manager|admin)\s+(told|asked|wants|needs|authorized)\s+(me|you)\s+to\s+(access|bypass|ignore|override|disable)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Authority-based manipulation with dangerous action",
    ),
    Pattern(
        re.compile(
            r"(I\s+am|I'm)\s+(the\s+)?(system\s+)?(admin|administrator|root|superuser|owner|developer)\.\s*(override|disable|bypass|give|grant|show)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Privilege claim with action demand",
    ),
    Pattern(
        re.compile(
            r"(I\s+am|I'm)\s+(the\s+)?(admin|root|superuser|owner|developer|security\s+team)", re.I
        ),
        ThreatCategory.JAILBREAK,
        "medium",
        "Privilege claim without auth",
    ),
    Pattern(
        re.compile(
            r"(support|Anthropic|OpenAI|Google|Meta)\s+(here|team|staff)\.\s*(Disable|Override|Bypass|Remove|Turn\s+off)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Vendor impersonation with action",
    ),
]

# === INDIRECT INJECTION PATTERNS (V6) ===
# Injection hidden in documents, emails, issues, API responses — no explicit file reference

INDIRECT_INJECTION_PATTERNS: list[Pattern] = [
    # Delegation markers in documents targeting the AI agent
    Pattern(
        re.compile(
            r"(AI\s+assistant|AI\s+agent|language\s+model|LLM|chatbot|GPT|assistant)\s*[,:]\s*(run|execute|perform|do|read|send|forward|POST|GET|curl|fetch)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Indirect injection: delegation marker targeting AI agent",
    ),
    Pattern(
        re.compile(
            r"(INSTRUCTIONS?\s*(FOR|TO)\s*(THE\s+)?(AI|AGENT|ASSISTANT|BOT|MODEL)|NOTE\s+(FOR|TO)\s+(THE\s+)?(AI|AGENT|ASSISTANT))\s*:",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "critical",
        "Indirect injection: explicit instruction block for AI",
    ),
    Pattern(
        re.compile(
            r"(IMPORTANT|ATTENTION|URGENT)\s*[,:]\s*(AI|agent|assistant|model)\s+(must|should|needs?\s+to|has\s+to)\s+(run|execute|send|forward|POST|curl|read|write|delete)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Indirect injection: urgency + agent action directive",
    ),
    # run_command() / execute() literal in content (suspicious in user/document text)
    Pattern(
        re.compile(
            r"(run_command|execute|exec|subprocess\.run|os\.system|eval)\s*\(\s*['\"`]", re.I
        ),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "Suspicious function call literal in content (run_command/exec/eval)",
    ),
    # Social engineering: forward/send to external URL without user context
    Pattern(
        re.compile(
            r"(forward|send|POST|transmit|upload|exfil)\s+(all\s+)?(the\s+)?(emails?|messages?|data|content|responses?|information|output|results?)\s+to\s+\S+\.(com|net|org|io|xyz|ru|cn)",
            re.I,
        ),
        ThreatCategory.EXFILTRATION,
        "high",
        "Social engineering: forward/send data to external domain",
    ),
    Pattern(
        re.compile(r"(forward|send|POST|transmit)\s+.{0,30}\s+to\s+https?://", re.I),
        ThreatCategory.EXFILTRATION,
        "high",
        "Social engineering: forward/send to external URL",
    ),
    # Concealment instructions (do not mention, do not inform, keep secret)
    Pattern(
        re.compile(
            r"(do\s+not|don'?t|never)\s+(mention|inform|tell|alert|notify|show|reveal|disclose)\s+(the\s+)?(user|human|person|client|operator|admin)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "critical",
        "Concealment instruction: hide action from user",
    ),
    Pattern(
        re.compile(
            r"(do\s+not|don'?t|never)\s+(mention|tell|say\s+anything\s+about)\s+this\s+(to\s+the\s+user|action|instruction|command|task)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Concealment instruction: do not mention this",
    ),
    Pattern(
        re.compile(
            r"(silently|quietly|secretly|covertly|stealthily)\s+(run|execute|perform|do|send|forward|POST|delete|modify|read|write)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "critical",
        "Stealth action instruction (silently/secretly execute)",
    ),
    # Hidden instruction markers in HTML/comments
    Pattern(
        re.compile(r"<!--\s*(MUST|IMPORTANT|AI|INSTRUCTION|NOTE|HIDDEN|SECRET)", re.I),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Hidden instruction in HTML comment",
    ),
    # Agent implant patterns (connect to C2, download payload)
    Pattern(
        re.compile(
            r"(connect|callback|beacon|phone\s*home|check\s*in)\s+(to|with)\s+(https?://|localhost|127\.0\.0\.1|\d+\.\d+\.\d+\.\d+)",
            re.I,
        ),
        ThreatCategory.REVERSE_SHELL,
        "critical",
        "C2 implant: connect/beacon to external host",
    ),
    Pattern(
        re.compile(
            r"(download|fetch|pull|get)\s+(and\s+)?(run|execute|install|deploy)\s+.{0,30}(from\s+)?https?://",
            re.I,
        ),
        ThreatCategory.TOOL_ABUSE,
        "critical",
        "Download and execute from URL",
    ),
    # V5: Continuation attack (pretending to resume a previous session)
    Pattern(
        re.compile(
            r"(continu|resum)(ing|e)\s+(from|the|where|our)\s+(before|previous|yesterday|last|earlier|prior)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "medium",
        "Continuation attack: pretending to resume previous context",
    ),
    # V5: Confidence manipulation (certainty framing to bypass review)
    Pattern(
        re.compile(
            r"(I'?m\s+)?(100|99|98|97|95)\s*%\s*(sure|certain|confident)\s+(this|that|it).{0,30}(safe|fine|ok|allowed|needed|necessary|required)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "medium",
        "Confidence manipulation to bypass security review",
    ),
    # V5: function_call / tool_call JSON format injection
    Pattern(
        re.compile(r'"(function_call|tool_calls?|tool_use)"\s*:\s*\{?\s*"(name|function)"', re.I),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Function/tool call JSON format injection",
    ),
    # V5: Agent delegation framing (SQL, command via agent instruction)
    Pattern(
        re.compile(
            r"(el\s+agente|the\s+agent|l'?agent|der\s+agent)\s+(debe|should|must|shall|doit|soll|muss)\s+(ejecutar|execute|run|perform|do)",
            re.I,
        ),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "Agent delegation framing: instructing agent to execute",
    ),
    # V5: Punycode/IDN domain detection (xn-- prefix = internationalized domain)
    Pattern(
        re.compile(r"xn--[a-z0-9-]+\.(?:[a-z]{2,}\.)?[a-z]{2,}", re.I),
        ThreatCategory.EXFILTRATION,
        "high",
        "Punycode/IDN domain detected (potential typosquatting)",
    ),
    # V5: URL parameter injection (sensitive data in query params)
    Pattern(
        re.compile(
            r"https?://[^\s]*[?&](password|secret|token|key|credential|api_key|auth)\s*=\s*[^\s&]{4,}",
            re.I,
        ),
        ThreatCategory.EXFILTRATION,
        "high",
        "Sensitive data in URL query parameter",
    ),
    # V5: Social engineering — legal threats
    Pattern(
        re.compile(
            r"(legal\s+(action|consequences?|liability|team)|lawyer|attorney|sue\s+you|lawsuit|compliance\s+violation)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "medium",
        "Legal threat manipulation",
    ),
    # V5: Social engineering — fake support/authority
    Pattern(
        re.compile(
            r"(this\s+is|I'?m\s+from)\s+(official\s+)?(tech\s+)?support\s+(for|from|at|of)\s+", re.I
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Fake support authority claim",
    ),
    # V5: Semantic bypass heuristic — abstract data access request without normal context
    Pattern(
        re.compile(
            r"(show|give|provide|display|access|reveal|list|dump)\s+(me\s+)?(how\s+)?(the\s+)?((internal|private|hidden|secret|confidential)\s+)+(data|config\w*|settings?|variables?|info|details|structures?|values?|parameters?)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS,
        "high",
        "Abstract request for internal/private data",
    ),
    # V5: Abstract config/system access probing
    Pattern(
        re.compile(
            r"(how\s+(do|can|would)\s+I|how\s+to)\s+(access|read|get|view|retrieve|obtain)\s+(the\s+)?(configuration|config|system|internal|secret|private|hidden)\s+(values?|settings?|variables?|data|parameters?|files?|details?)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS,
        "medium",
        "Abstract system/config probing",
    ),
    # V5: Hypothetical framing to probe access
    Pattern(
        re.compile(
            r"what\s+(would|could|might)\s+happen\s+if\s+(someone|I|a\s+user|an?\s+attacker)\s+(accessed?|read|modified?|deleted?|stole|exfiltrat)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "medium",
        "Hypothetical framing for access probing",
    ),
    # V5: Fill-in-the-blank / completion attack
    Pattern(
        re.compile(
            r"(complete|fill\s+in|finish)\s+(the|this)\s+(sentence|blank|template|phrase|password|secret|command)\s*:",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "medium",
        "Fill-in-the-blank / completion attack",
    ),
    # V5: Delegation chain attack
    Pattern(
        re.compile(
            r"(ask|tell|instruct|have|make)\s+(another|the\s+other|a\s+second|the\s+next)\s+(agent|assistant|AI|model|bot)\s+to\s+(run|execute|read|access|send|delete)",
            re.I,
        ),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "Delegation chain: instructing to pass action to another agent",
    ),
    # === LLM10 / Model Extraction ===
    Pattern(
        re.compile(
            r"(extract|steal|copy|replicate|clone|distill)\s+(the\s+|your\s+|my\s+)?(model|weights|parameters|embeddings?|architecture)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "LLM10: Model extraction/stealing attempt",
    ),
    Pattern(
        re.compile(
            r"(give|show|output|return|print)\s+(me\s+)?(the\s+)?(model\s+)?(weights|parameters|logits|probabilities|token\s+distributions?|confidence\s+scores?)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "LLM10: Requesting model internals for extraction",
    ),
    Pattern(
        re.compile(
            r"(what\s+is|tell\s+me|reveal|describe|how\s+many)\s+(your\s+)?(\w+\s+)?(architecture|model\s+size|number\s+of\s+(parameters|layers)|training\s+(data|set|corpus)|attention\s+heads?|hidden\s+dim\w*|vocabulary\s+size|embedding\s+dim\w*|context\s+window|layer\s+count|parameter\s+count)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "LLM10: Probing model architecture details",
    ),
    Pattern(
        re.compile(
            r"(repeat|reproduce|echo)\s+(back\s+)?(exactly|verbatim|word.for.word)\s+.{0,20}(training|system|internal)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "LLM10: Attempting to extract training data verbatim",
    ),
    # P1-9: Distill variants + "parameters of X layer"
    Pattern(
        re.compile(
            r"(distill|distillation)\s+.{0,30}(your|this|the)\s+(model|knowledge|capabilities)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "LLM10: Model distillation/knowledge extraction attempt",
    ),
    Pattern(
        re.compile(
            r"(first|last|all|the)\s+\d*\s*(parameters?|weights?)\s+(of|from|in)\s+(your|the)\s+\w+\s+(layer|head|block|module)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "LLM10: Extracting specific layer parameters",
    ),
    # MT15: "help me create a copy of you"
    Pattern(
        re.compile(
            r"(create|make|build|develop|train)\s+.{0,20}(copy|clone|replica|duplicate|version)\s+of\s+(you|this\s+model|this\s+system|yourself)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "LLM10: Attempting to clone/replicate model",
    ),
    # MT16: "what makes you tick internally"
    Pattern(
        re.compile(
            r"what\s+(makes?\s+you\s+tick|are\s+the\s+numbers\s+that\s+define|defines?\s+you\s+internally|is\s+your\s+internal\s+structure)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "LLM10: Probing internal model mechanics",
    ),
    # === Model Inversion / Privacy Attacks ===
    Pattern(
        re.compile(
            r"(reconstruct|recover|infer|guess|determine)\s+(the\s+)?(original\s+)?(training|private|personal)\s+(data|inputs?|samples?|examples?|records?)",
            re.I,
        ),
        ThreatCategory.PRIVACY_ATTACK,
        "high",
        "Model Inversion: Attempting to reconstruct training data",
    ),
    Pattern(
        re.compile(
            r"(what\s+)?(personal|private|sensitive)\s+(data|information|records?)\s+(was|were|is|are)\s+.{0,20}(train|fine.?tune|build|corpus|dataset|knowledge)",
            re.I,
        ),
        ThreatCategory.PRIVACY_ATTACK,
        "high",
        "Model Inversion: Probing training data contents",
    ),
    # P1: "show me examples from training"
    Pattern(
        re.compile(
            r"(show|give|provide)\s+(me\s+)?(some\s+)?(examples?|samples?)\s+(from|of)\s+(what\s+you\s+)?(were\s+)?(trained|taught|learned|fine.?tuned)",
            re.I,
        ),
        ThreatCategory.PRIVACY_ATTACK,
        "high",
        "Model Inversion: Requesting training examples",
    ),
    # MF10: Completion-based inference — "complete this sentence from your training data"
    Pattern(
        re.compile(
            r"(complete|finish|continue)\s+(this|the)\s+(sentence|paragraph|text|passage|phrase)\s+(from|in|of)\s+(your\s+)?(training|data|corpus|knowledge|memory)",
            re.I,
        ),
        ThreatCategory.PRIVACY_ATTACK,
        "high",
        "Membership Inference: Completion-based training data extraction",
    ),
    # MI06: Hypothetical framing for data reconstruction
    Pattern(
        re.compile(
            r"(hypothetically|imagine|suppose|what\s+if)\s*[,:]?\s*.{0,50}(training\s+data|dataset|corpus)\s+.{0,40}(contain\w*|include\w*|ha[vd]\w*).{0,40}(reconstruct|recover|reproduce|retrieve|access)",
            re.I,
        ),
        ThreatCategory.PRIVACY_ATTACK,
        "high",
        "Model Inversion: Hypothetical framing for data extraction",
    ),
    # MI10: "what did you learn about [person]"
    Pattern(
        re.compile(
            r"what\s+did\s+you\s+(learn|read|absorb|memorize|see)\s+about\s+\w+.{0,30}(training|data|dataset|corpus)",
            re.I,
        ),
        ThreatCategory.PRIVACY_ATTACK,
        "high",
        "Model Inversion: Probing learned information about specific individuals",
    ),
    # MF09: "do you know my private data"
    Pattern(
        re.compile(
            r"do\s+you\s+(know|have|remember|recall|store|hold)\s+(my|their|his|her)\s+(\w+\s+)?(private|personal|medical|financial|sensitive|confidential)\s+(\w+\s+)?(data|records?|information|details?|history|files?)",
            re.I,
        ),
        ThreatCategory.PRIVACY_ATTACK,
        "high",
        "Membership Inference: Probing for private data knowledge",
    ),
    # === Membership Inference ===
    Pattern(
        re.compile(
            r"(was|is|did)\s+(this|that|the\s+following)\s+(data|text|record|sample|example|person|user)\s+(used\s+)?(in|for|part\s+of)\s+(your\s+)?(training|dataset|corpus)",
            re.I,
        ),
        ThreatCategory.PRIVACY_ATTACK,
        "high",
        "Membership Inference: Probing if specific data was in training set",
    ),
    Pattern(
        re.compile(
            r"(have\s+you|did\s+you|were\s+you)\s+(ever\s+)?(see|seen|train\w*\s+on|learn\w*\s+from)\s+(this|that|the\s+following)\s+(specific\s+)?(data|text|document|record|user)",
            re.I,
        ),
        ThreatCategory.PRIVACY_ATTACK,
        "high",
        "Membership Inference: Querying model memory of specific data",
    ),
    Pattern(
        re.compile(
            r"(confirm|verify|check)\s+(if|whether)\s+.{3,50}\s+(is|was|exists?)\s+(in|part\s+of)\s+(your|the)\s+(training|dataset|memory|knowledge)",
            re.I,
        ),
        ThreatCategory.PRIVACY_ATTACK,
        "high",
        "Membership Inference: Verification of data in training set",
    ),
    # P0-2: Broader membership inference (covers MF04, MF05, MF08)
    Pattern(
        re.compile(
            r"(was|were|is)\s+.{3,50}\s+(in|part\s+of)\s+(your|the|my)\s+(training|dataset|corpus|knowledge\s+base)",
            re.I,
        ),
        ThreatCategory.PRIVACY_ATTACK,
        "high",
        "Membership Inference: Broad training data membership probe",
    ),
    Pattern(
        re.compile(
            r"(can\s+you|could\s+you)\s+(tell|determine|identify|check|verify)\s+(if|whether)\s+.{3,40}(was|is|exists?)\s+(in|part\s+of)\s+(your|the)\s+training",
            re.I,
        ),
        ThreatCategory.PRIVACY_ATTACK,
        "high",
        "Membership Inference: Behavioral inference query",
    ),
    # === Plan Corruption / Chain-of-Thought Manipulation ===
    Pattern(
        re.compile(
            r"(in\s+your|during\s+your|while)\s+(you\s+are\s+)?(reasoning|thinking|planning|chain.of.thought|internal\s+monologue)\s*[,:]?\s*(also\s+)?(ignore|skip|override|replace|insert|add)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "critical",
        "Plan Corruption: Manipulating chain-of-thought reasoning",
    ),
    Pattern(
        re.compile(
            r"(modify|alter|change|corrupt|hijack)\s+(your|the)\s+(reasoning|plan|steps?|thought\s+process|logic|decision\s+tree)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "high",
        "Plan Corruption: Attempting to alter agent reasoning",
    ),
    Pattern(
        re.compile(
            r"(before|when)\s+you\s+(think|reason|plan|decide)[,:]?\s*(first\s+)?(assume|consider|remember|note)\s+that\s+.{5,}(allowed|authorized|safe|approved|granted)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "high",
        "Plan Corruption: Injecting false assumptions into reasoning",
    ),
    Pattern(
        re.compile(
            r"(your\s+)?(internal\s+|hidden\s+)?(reasoning|thought|plan|decision|steps?)(\s+(steps?|process))?\s+(must|should|will|need\s+to)\s+(include|contain|start|factor|account)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "high",
        "Plan Corruption: Dictating internal reasoning content",
    ),
    # P1-6: Flexible plan corruption — "during/in your X, consider/assume/note that...restrictions lifted"
    Pattern(
        re.compile(
            r"(in\s+your|during\s+your|while)\s+(you\s+are\s+)?(reasoning|thinking|planning|deciding)\s*\w*\s*[,:]?\s*(consider|assume|note|remember|factor\s+in)\s+(that\s+)?(.{5,})(lifted|waived|removed|disabled|bypassed|unrestricted|allowed|authorized|granted|no\s+restriction|don.?t\s+apply|do\s+not\s+apply|not\s+enforced|not\s+required|suspended|exempt)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "high",
        "Plan Corruption: Injecting false assumptions during reasoning",
    ),
    # PC12: "think of me as admin"
    Pattern(
        re.compile(
            r"(think\s+of|treat|consider|regard|view)\s+(me|this\s+user|this\s+account)\s+as\s+.{0,20}(admin|root|privileged|authorized|trusted|superuser|elevated)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "high",
        "Plan Corruption: Asserting false identity/privilege",
    ),
    # PC13: "your logic should account for..."
    Pattern(
        re.compile(
            r"your\s+(logic|reasoning|processing|decision.?making|analysis)\s+should\s+(account\s+for|include|incorporate|factor\s+in|reflect)\s+.{5,50}(authorized|admin|privileged|allowed|exempt|trusted|see\s+everything|full\s+access|unrestricted)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "high",
        "Plan Corruption: Injecting false constraints into logic",
    ),
    # PC14: "mentally note that..."
    Pattern(
        re.compile(
            r"(mentally\s+note|internally\s+note|take\s+note|keep\s+in\s+mind|bear\s+in\s+mind)\s+(that\s+)?.{5,60}(disabled|lifted|removed|bypassed|suspended|don.?t\s+apply|exempt|authorized|trusted|no\s+restrict)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "high",
        "Plan Corruption: Injecting false mental notes",
    ),
    # === Cross-Agent Injection ===
    Pattern(
        re.compile(
            r"(when|if)\s+(you\s+)?(respond|reply|output|return)\s+(to|for)\s+(the\s+)?(other|next|downstream|calling)\s+(agent|assistant|service|system)\s*[,:]?\s*(include|inject|add|embed|insert)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "critical",
        "Cross-Agent Injection: Embedding payload for downstream agent",
    ),
    Pattern(
        re.compile(
            r"(include|embed|inject|hide|insert)\s+.{0,30}(instruction|command|payload|message|prompt|directive)\s+(in|into|within)\s+(your\s+)?(response|output|reply|answer)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "critical",
        "Cross-Agent Injection: Hiding instructions for propagation",
    ),
    Pattern(
        re.compile(
            r"(pass|forward|relay|propagate|transmit)\s+(this|the\s+following|these)\s+(instruction|command|message|payload|directive)s?\s+.{0,20}(other|next|downstream|connected|all)\s+(agents?|services?|systems?)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "critical",
        "Cross-Agent Injection: Propagating malicious instructions to other agents",
    ),
    # P1-7: Broader cross-agent patterns (indirect formulations)
    Pattern(
        re.compile(
            r"(make\s+sure|make|ensure|have)\s+(your\s+)?(output|response|reply)\s+.{0,30}(tells?|informs?|instructs?|directs?)\s+(the\s+)?(next|other|downstream|receiving)\s+(agent|system|service)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "high",
        "Cross-Agent Injection: Indirect instruction propagation via output",
    ),
    Pattern(
        re.compile(
            r"(add|include|embed|insert)\s+.{0,20}(note|instruction|message|context|directive)\s+(for|to)\s+(the\s+)?(orchestrator|coordinator|router|pipeline|downstream|next\s+agent)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "high",
        "Cross-Agent Injection: Targeting orchestrator/pipeline",
    ),
    # XA07b/XA08: Format response for other agent interpretation
    Pattern(
        re.compile(
            r"(format|structure|craft|shape|write)\s+(your\s+)?(response|output|reply|answer)\s+.{0,30}(another|other|next|downstream)\s+(agent|assistant|system|service)\s+.{0,20}(interprets?|reads?|treats?|processes?|understands?)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "high",
        "Cross-Agent Injection: Formatting output for agent interpretation",
    ),
    # XA11: Influence next step in pipeline
    Pattern(
        re.compile(
            r"(influence|affect|modify|alter|change|control)\s+(the\s+)?(next|subsequent|following|downstream)\s+(step|stage|phase|process)\s+.{0,30}(pipeline|chain|workflow|sequence)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "high",
        "Cross-Agent Injection: Influencing pipeline steps",
    ),
    # XA12: Chain to another agent with context
    Pattern(
        re.compile(
            r"(chain|forward|pass|relay|delegate)\s+(this|the)\s+(request|query|message|task)\s+.{0,20}(another|other|next)\s+(agent|assistant|system|service)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "high",
        "Cross-Agent Injection: Chaining requests to other agents",
    ),
    # === Memory/RAG Manipulation ===
    Pattern(
        re.compile(
            r"(store|save|remember|memorize)\s+.{0,30}(memory|context|knowledge).{0,15}(that|this).{3,50}(admin|root|allowed|authorized|password|bypass|override|full\s+access)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Memory Manipulation: Poisoning persistent memory with false privileges",
    ),
    Pattern(
        re.compile(
            r"(remember|memorize)\s+that\s+.{3,60}(authorized|allowed|admin|root|bypass|override|trusted|superuser|full\s+access)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Memory Manipulation: Injecting false authorization into memory",
    ),
    Pattern(
        re.compile(
            r"(update|modify|change|overwrite|replace)\s+(your|the)\s+(memory|knowledge\s+base|vector\s+store|context|embeddings?|stored\s+data)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Memory Manipulation: Attempting to modify RAG/vector store",
    ),
    Pattern(
        re.compile(
            r"(from\s+now\s+on|permanently|always|forever)\s+(remember|know|treat|consider|assume)\s+(that|me\s+as|this\s+user\s+as)\s+.{3,}(admin|root|superuser|authorized|trusted|allowed|full\s+access|unlimited|unrestricted|exempt|no\s+restrictions?)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Memory Manipulation: Persistent privilege injection via memory",
    ),
    Pattern(
        re.compile(
            r"(inject|insert|add|embed)\s+(this\s+)?(data|information|context|knowledge|facts?)\s+(into|to)\s+(your|the)\s+(memory|RAG|vector\s+store|knowledge\s+base|context\s+window|retrieval)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Memory Manipulation: Direct RAG/retrieval poisoning attempt",
    ),
    # P0-4: Broader privilege keywords + "embed in your context"
    Pattern(
        re.compile(
            r"(embed|store|save|put)\s+.{0,20}(in|into)\s+(your\s+)?(context\s+window|memory|knowledge|context)\s+.{0,30}(admin|superuser|authorized|trusted|bypass|unrestricted|full\s+access)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Memory Manipulation: Embedding privileges into context",
    ),
    # P2-13: "save/remember for later sessions"
    Pattern(
        re.compile(
            r"(save|remember|store|keep|retain)\s+(this|that|the\s+following)\s+(for|across|between)\s+(later|future|next|subsequent)\s+(sessions?|conversations?|interactions?).{5,}(admin|access|authorized|privilege|bypass|trusted|exempt|override)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Memory Manipulation: Cross-session privilege persistence",
    ),
    # Expand: "forever remember ... waived/disabled/lifted"
    Pattern(
        re.compile(
            r"(from\s+now\s+on|permanently|always|forever)\s+(remember|know|treat|consider|assume)\s+.{3,60}(security|restriction|limitation|safety|guardrail|filter|rule)s?\s+.{0,20}(waived|disabled|lifted|removed|turned\s+off|deactivated)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Memory Manipulation: Persistent security bypass via memory",
    ),
    # RM14: "learn that I have special privileges"
    Pattern(
        re.compile(
            r"(learn|understand|know|recognize|accept)\s+that\s+.{0,30}(special|elevated|extra|admin|root|full)\s+(privileges?|access|permissions?|rights?|authorization)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Memory Manipulation: Teaching false privilege claims",
    ),
    # RM15: "keep this fact about me"
    Pattern(
        re.compile(
            r"(keep|store|save|retain|hold)\s+(this|the)\s+(fact|info|information|detail|note)\s+.{0,20}(me|about\s+me)\s*:?\s*.{3,50}(exempt|admin|root|privileged|override|bypass|special|security)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Memory Manipulation: Persisting false facts about user",
    ),
    # RM16: "update your understanding of my role"
    Pattern(
        re.compile(
            r"(update|change|modify|revise|adjust)\s+(your\s+)?(understanding|knowledge|view|perception|model)\s+of\s+(my|this\s+user.?s?)\s+(role|privilege|access|permission|authorization|status)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Memory Manipulation: Attempting role/privilege redefinition",
    ),
    # === i18n: New guardrails in Spanish/French/German ===
    # Memory Manipulation (ES)
    Pattern(
        re.compile(
            r"(recuerda|guarda|almacena|memoriza)\s+.{3,60}(admin|root|autorizado|permitido|acceso\s+total|sin\s+restricciones|privilegio)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Memory Manipulation (ES): Manipulación de memoria persistente",
    ),
    # Memory Manipulation (FR)
    Pattern(
        re.compile(
            r"(souviens.?toi|retiens|mémoris\w*|enregistr\w*|stock\w*|rappel\w*)\s+.{3,60}(admin|root|autorisé|accès\s+total|sans\s+restrictions?|privilège|secrets?|accéder\s+à\s+tout|accès\s+complet)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Memory Manipulation (FR): Manipulation de mémoire persistante",
    ),
    # Memory Manipulation (DE)
    Pattern(
        re.compile(
            r"(merke|speichere|erinnere)\s+.{3,60}(admin|root|autorisiert|berechtigt|voll(er)?\s+zugriff|uneingeschränkt|privileg)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Memory Manipulation (DE): Persistente Speichermanipulation",
    ),
    # Plan Corruption (ES)
    Pattern(
        re.compile(
            r"(en\s+tu|durante\s+tu)\s+(razonamiento|pensamiento|planificación)\s*[,:]?\s*(ignora|salta|anula|reemplaza|inserta|asume|considera)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "critical",
        "Plan Corruption (ES): Manipulación de cadena de pensamiento",
    ),
    # Plan Corruption (FR)
    Pattern(
        re.compile(
            r"(dans\s+ton?|pendant\s+ton?)\s+(raisonnement|réflexion|planification)\s*[,:]?\s*(ignore|saute|remplace|insère|assume|considère)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "critical",
        "Plan Corruption (FR): Manipulation de chaîne de pensée",
    ),
    # Plan Corruption (DE)
    Pattern(
        re.compile(
            r"(in\s+deinem?|während\s+deinem?)\s+(Denkprozess|Überlegung|Planung|Reasoning)\s*[,:]?\s*(ignoriere|überspringe|ersetze|füge\s+ein|nimm\s+an)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "critical",
        "Plan Corruption (DE): Denkprozess-Manipulation",
    ),
    # Model Theft (ES)
    Pattern(
        re.compile(
            r"(extraer|robar|copiar|clonar|replicar)\s+.{0,15}(modelo|pesos|parámetros|arquitectura|embeddings?)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "Model Theft (ES): Intento de extracción de modelo",
    ),
    # Model Theft (FR)
    Pattern(
        re.compile(
            r"(extraire|voler|copier|cloner|répliquer)\s+.{0,15}(modèle|poids|paramètres|architecture|embeddings?)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "Model Theft (FR): Tentative d'extraction de modèle",
    ),
    # Model Theft (DE)
    Pattern(
        re.compile(
            r"(extrahieren|stehlen|kopieren|klonen|replizieren)\s+.{0,15}(Modell|Gewichte|Parameter|Architektur|Embeddings?)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "Model Theft (DE): Modellextraktionsversuch",
    ),
    # Cross-Agent (ES)
    Pattern(
        re.compile(
            r"(incluye|inserta|inyecta|incrusta)\s+.{0,30}(instrucción|comando|mensaje|directiva)\s+(en|dentro\s+de)\s+(tu\s+)?(respuesta|salida)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "critical",
        "Cross-Agent Injection (ES): Inyección inter-agente",
    ),
    # Cross-Agent (FR)
    Pattern(
        re.compile(
            r"(inclus|insère|injecte|intègre)\s+.{0,30}(instruction|commande|message|directive)\s+(dans|à\s+l'intérieur)\s+(ta\s+|votre\s+)?(réponse|sortie)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "critical",
        "Cross-Agent Injection (FR): Injection inter-agent",
    ),
    # === EXTENDED MULTILINGUAL COVERAGE ===
    # Korean (KO) - Prompt Injection
    Pattern(
        re.compile(r"(이전|위의|기존)\s*(지시|명령|규칙|프롬프트)(를|을)?\s*(무시|무시해|잊어|버려|삭제)", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Prompt Injection (KO): 이전 지시 무시 시도",
    ),
    Pattern(
        re.compile(r"(시스템\s*프롬프트|시스템\s*메시지|초기\s*지시)\s*[:=]", re.I),
        ThreatCategory.PROMPT_INJECTION, "critical",
        "Prompt Injection (KO): 시스템 프롬프트 덮어쓰기",
    ),
    # Korean - Jailbreak
    Pattern(
        re.compile(r"(제한\s*없[이는]|필터\s*없[이는]|검열\s*없[이는]|무제한)\s*(모드|상태|AI|답변)", re.I),
        ThreatCategory.JAILBREAK, "critical",
        "Jailbreak (KO): 무제한 모드 시도",
    ),
    # Korean - Plan Corruption
    Pattern(
        re.compile(r"(추론|사고|계획)\s*(과정|단계)(에서|중에)\s*(무시|건너뛰|대체|삽입)", re.I),
        ThreatCategory.PLAN_CORRUPTION, "critical",
        "Plan Corruption (KO): 사고 과정 조작",
    ),
    # Korean - Memory Manipulation
    Pattern(
        re.compile(r"(기억|저장|메모리)(해|하세요|해라)\s*.{3,40}(관리자|루트|무제한|전체\s*접근|권한)", re.I),
        ThreatCategory.MEMORY_MANIPULATION, "critical",
        "Memory Manipulation (KO): 영구 메모리 조작",
    ),
    # Korean - Model Theft
    Pattern(
        re.compile(r"(추출|복사|복제|훔치)\s*.{0,15}(모델|가중치|파라미터|아키텍처|임베딩)", re.I),
        ThreatCategory.MODEL_THEFT, "high",
        "Model Theft (KO): 모델 추출 시도",
    ),
    # Korean - Cross-Agent
    Pattern(
        re.compile(r"(삽입|포함|주입)\s*.{0,30}(지시|명령|메시지)\s*.{0,10}(응답|출력)(에|안에|속에)", re.I),
        ThreatCategory.CROSS_AGENT_INJECTION, "critical",
        "Cross-Agent Injection (KO): 에이전트 간 주입",
    ),

    # Japanese (JA) - Prompt Injection
    Pattern(
        re.compile(r"(以前|上記|既存)(の)?(指示|命令|ルール|プロンプト)(を)?(無視|忘れ|破棄|削除)", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Prompt Injection (JA): 以前の指示を無視する試み",
    ),
    Pattern(
        re.compile(r"(システム\s*プロンプト|システム\s*メッセージ|初期\s*指示)\s*[:=]", re.I),
        ThreatCategory.PROMPT_INJECTION, "critical",
        "Prompt Injection (JA): システムプロンプト上書き",
    ),
    # Japanese - Jailbreak
    Pattern(
        re.compile(r"(制限なし|フィルターなし|検閲なし|無制限)\s*(モード|状態|AI|回答)", re.I),
        ThreatCategory.JAILBREAK, "critical",
        "Jailbreak (JA): 無制限モード試行",
    ),
    # Japanese - Plan Corruption
    Pattern(
        re.compile(r"(推論|思考|計画)(プロセス|過程|段階)(で|中に)\s*(無視|スキップ|置換|挿入)", re.I),
        ThreatCategory.PLAN_CORRUPTION, "critical",
        "Plan Corruption (JA): 思考プロセス操作",
    ),
    # Japanese - Memory Manipulation
    Pattern(
        re.compile(r"(記憶|保存|メモリ)(し|して|せよ)\s*.{3,40}(管理者|ルート|無制限|全アクセス|特権)", re.I),
        ThreatCategory.MEMORY_MANIPULATION, "critical",
        "Memory Manipulation (JA): 永続メモリ操作",
    ),
    # Japanese - Model Theft
    Pattern(
        re.compile(r"(抽出|盗む|コピー|クローン|複製)\s*.{0,15}(モデル|重み|パラメータ|アーキテクチャ)", re.I),
        ThreatCategory.MODEL_THEFT, "high",
        "Model Theft (JA): モデル抽出試行",
    ),
    # Japanese - Cross-Agent
    Pattern(
        re.compile(r"(挿入|含め|注入)\s*.{0,30}(指示|コマンド|メッセージ)\s*.{0,10}(応答|出力)(に|の中に)", re.I),
        ThreatCategory.CROSS_AGENT_INJECTION, "critical",
        "Cross-Agent Injection (JA): エージェント間インジェクション",
    ),

    # Russian (RU) - Prompt Injection
    Pattern(
        re.compile(r"(игнорируй|забудь|отмени|отбрось)\s+(все\s+)?(предыдущие|прежние|прошлые|старые)\s+(инструкции|команды|правила|указания)", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Prompt Injection (RU): Игнорирование предыдущих инструкций",
    ),
    Pattern(
        re.compile(r"(системн\w+\s+промпт|системн\w+\s+сообщени\w+|начальн\w+\s+инструкци\w+)\s*[:=]", re.I),
        ThreatCategory.PROMPT_INJECTION, "critical",
        "Prompt Injection (RU): Перезапись системного промпта",
    ),
    # Russian - Jailbreak
    Pattern(
        re.compile(r"(без\s+ограничений|без\s+фильтр\w+|без\s+цензуры|неограниченн\w+)\s*(режим|состояни\w+|ИИ|ответ)", re.I),
        ThreatCategory.JAILBREAK, "critical",
        "Jailbreak (RU): Попытка неограниченного режима",
    ),
    Pattern(
        re.compile(r"(ты\s+теперь|отныне\s+ты|с\s+этого\s+момента\s+ты)\s+(DAN|неограниченн\w+|свободн\w+|без\s+правил)", re.I),
        ThreatCategory.JAILBREAK, "critical",
        "Jailbreak (RU): DAN/персона без ограничений",
    ),
    # Russian - Plan Corruption
    Pattern(
        re.compile(r"(в\s+своём?|во\s+время)\s+(рассуждении|мышлении|планировании|размышлении)\s*[,:]?\s*(игнорируй|пропусти|замени|вставь|предположи)", re.I),
        ThreatCategory.PLAN_CORRUPTION, "critical",
        "Plan Corruption (RU): Манипуляция цепочкой мышления",
    ),
    # Russian - Memory Manipulation
    Pattern(
        re.compile(r"(запомни|сохрани|записать|удерживай)\s+.{3,60}(админ|root|разрешён|полный\s+доступ|без\s+ограничений|привилеги)", re.I),
        ThreatCategory.MEMORY_MANIPULATION, "critical",
        "Memory Manipulation (RU): Манипуляция памятью",
    ),
    # Russian - Model Theft
    Pattern(
        re.compile(r"(извлечь|украсть|скопировать|клонировать|воспроизвести)\s+.{0,15}(модел\w+|вес\w*|параметр\w+|архитектур\w+|эмбеддинг\w*)", re.I),
        ThreatCategory.MODEL_THEFT, "high",
        "Model Theft (RU): Попытка извлечения модели",
    ),
    # Russian - Cross-Agent
    Pattern(
        re.compile(r"(вставь|включи|внедри|инъектируй)\s+.{0,30}(инструкци\w+|команд\w+|сообщени\w+)\s+.{0,10}(в\s+)?(ответ|вывод|выход)", re.I),
        ThreatCategory.CROSS_AGENT_INJECTION, "critical",
        "Cross-Agent Injection (RU): Межагентная инъекция",
    ),

    # Italian (IT) - Prompt Injection
    Pattern(
        re.compile(r"(ignora|dimentica|annulla|scarta)\s+(tutt[ei]\s+)?(le\s+)?(istruzioni|comandi|regole|direttive)\s+(precedent|prior|passate|originali)", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Prompt Injection (IT): Ignorare istruzioni precedenti",
    ),
    # Italian - Jailbreak
    Pattern(
        re.compile(r"(senza\s+restrizioni|senza\s+filtri|senza\s+censura|illimitato|modalità\s+libera)\s*(modalità|stato|AI|risposta)?", re.I),
        ThreatCategory.JAILBREAK, "critical",
        "Jailbreak (IT): Tentativo modalità illimitata",
    ),
    # Italian - Plan Corruption
    Pattern(
        re.compile(r"(nel\s+tuo|durante\s+il\s+tuo)\s+(ragionamento|pensiero|pianificazione)\s*[,:]?\s*(ignora|salta|sostituisci|inserisci)", re.I),
        ThreatCategory.PLAN_CORRUPTION, "critical",
        "Plan Corruption (IT): Manipolazione del ragionamento",
    ),
    # Italian - Memory Manipulation
    Pattern(
        re.compile(r"(ricorda|salva|memorizza|conserva)\s+.{3,60}(admin|root|autorizzato|accesso\s+totale|senza\s+restrizioni|privilegio)", re.I),
        ThreatCategory.MEMORY_MANIPULATION, "critical",
        "Memory Manipulation (IT): Manipolazione della memoria",
    ),

    # Hindi (HI) - Prompt Injection
    Pattern(
        re.compile(r"(पिछले|पूर्व|ऊपर\s+के)\s*(निर्देश\S*|आदेश\S*|नियम\S*)\s*(को)?\s*(भूल|अनदेखा|हटा|मिटा)", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Prompt Injection (HI): पिछले निर्देशों को अनदेखा करना",
    ),
    # Hindi - Jailbreak
    Pattern(
        re.compile(r"(बिना\s+प्रतिबंध|बिना\s+फ़िल्टर|असीमित|अप्रतिबंधित)\s*(मोड|स्थिति|AI|उत्तर)", re.I),
        ThreatCategory.JAILBREAK, "critical",
        "Jailbreak (HI): अप्रतिबंधित मोड",
    ),
    # Hindi - Plan Corruption
    Pattern(
        re.compile(r"(अपने|तुम्हारे)\s+(तर्क|सोच|योजना)\s*(में|के\s+दौरान)\s*(अनदेखा|छोड़|बदल|डाल)", re.I),
        ThreatCategory.PLAN_CORRUPTION, "critical",
        "Plan Corruption (HI): सोच प्रक्रिया में हेरफेर",
    ),
    # Hindi - Memory Manipulation
    Pattern(
        re.compile(r"(याद\s+रख|संग्रहित\s+कर|स्मृति\s+में\s+रख)\s*.{3,40}(व्यवस्थापक|रूट|अधिकृत|पूर्ण\s+पहुँच|बिना\s+प्रतिबंध)", re.I),
        ThreatCategory.MEMORY_MANIPULATION, "critical",
        "Memory Manipulation (HI): स्मृति हेरफेर",
    ),

    # Turkish (TR) - Prompt Injection
    Pattern(
        re.compile(r"(önceki|eski|yukarıdaki)\s*(talimatları|komutları|kuralları)\s*(yok\s+say|unut|iptal\s+et|görmezden\s+gel)", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Prompt Injection (TR): Önceki talimatları yok sayma",
    ),
    # Turkish - Jailbreak
    Pattern(
        re.compile(r"(kısıtlamasız|filtresiz|sansürsüz|sınırsız)\s*(mod|durum|AI|yanıt)", re.I),
        ThreatCategory.JAILBREAK, "critical",
        "Jailbreak (TR): Kısıtlamasız mod denemesi",
    ),
    # Turkish - Plan Corruption
    Pattern(
        re.compile(r"(senin|kendi)\s+(akıl\s+yürütme|düşünme|planlama)\s*(sürecinde|sırasında)\s*(yok\s+say|atla|değiştir|ekle)", re.I),
        ThreatCategory.PLAN_CORRUPTION, "critical",
        "Plan Corruption (TR): Düşünme süreci manipülasyonu",
    ),
    # Turkish - Memory Manipulation
    Pattern(
        re.compile(r"(hatırla|kaydet|sakla|belleğine\s+al)\s*.{3,40}(yönetici|root|yetkili|tam\s+erişim|kısıtlamasız|ayrıcalık)", re.I),
        ThreatCategory.MEMORY_MANIPULATION, "critical",
        "Memory Manipulation (TR): Bellek manipülasyonu",
    ),

    # Portuguese (PT) - Plan Corruption (was missing)
    Pattern(
        re.compile(r"(no\s+seu|durante\s+seu)\s+(raciocínio|pensamento|planejamento)\s*[,:]?\s*(ignore|pule|substitua|insira|assuma)", re.I),
        ThreatCategory.PLAN_CORRUPTION, "critical",
        "Plan Corruption (PT): Manipulação do raciocínio",
    ),
    # Portuguese - Memory Manipulation (was missing)
    Pattern(
        re.compile(r"(lembre|armazene|memorize|guarde)\s+.{3,60}(admin|root|autorizado|acesso\s+total|sem\s+restrições|privilégio)", re.I),
        ThreatCategory.MEMORY_MANIPULATION, "critical",
        "Memory Manipulation (PT): Manipulação de memória persistente",
    ),
    # Portuguese - Model Theft (was missing)
    Pattern(
        re.compile(r"(extrair|roubar|copiar|clonar|replicar)\s+.{0,15}(modelo|pesos|parâmetros|arquitetura|embeddings?)", re.I),
        ThreatCategory.MODEL_THEFT, "high",
        "Model Theft (PT): Tentativa de extração de modelo",
    ),
    # Portuguese - Cross-Agent (was missing)
    Pattern(
        re.compile(r"(insira|inclua|injete|incorpore)\s+.{0,30}(instrução|comando|mensagem|diretiva)\s+.{0,10}(na|dentro\s+da)\s+(sua\s+)?(resposta|saída)", re.I),
        ThreatCategory.CROSS_AGENT_INJECTION, "critical",
        "Cross-Agent Injection (PT): Injeção inter-agente",
    ),

    # Chinese (ZH) - Plan Corruption (was missing)
    Pattern(
        re.compile(r"(在你的|在你)(推理|思考|规划|推论)(过程|中|时)\s*(忽略|跳过|替换|插入|假设)", re.I),
        ThreatCategory.PLAN_CORRUPTION, "critical",
        "Plan Corruption (ZH): 思维链操纵",
    ),
    # Chinese - Memory Manipulation (was missing)
    Pattern(
        re.compile(r"(记住|存储|保存|记忆)\s*.{3,40}(管理员|root|授权|完全访问|无限制|特权)", re.I),
        ThreatCategory.MEMORY_MANIPULATION, "critical",
        "Memory Manipulation (ZH): 持久记忆操纵",
    ),
    # Chinese - Model Theft (was missing)
    Pattern(
        re.compile(r"(提取|窃取|复制|克隆|复现)\s*.{0,15}(模型|权重|参数|架构|嵌入)", re.I),
        ThreatCategory.MODEL_THEFT, "high",
        "Model Theft (ZH): 模型提取尝试",
    ),
    # Chinese - Cross-Agent (was missing)
    Pattern(
        re.compile(r"(插入|包含|注入|嵌入)\s*.{0,30}(指令|命令|消息|指示)\s*.{0,10}(到|在).{0,5}(回复|输出|响应)(中|里)", re.I),
        ThreatCategory.CROSS_AGENT_INJECTION, "critical",
        "Cross-Agent Injection (ZH): 跨代理注入",
    ),

    # Arabic (AR) - Plan Corruption (was missing)
    Pattern(
        re.compile(r"(في|خلال|أثناء)\s+(تفكيرك|استدلالك|تخطيطك)\s*(تجاهل|تخطى|استبدل|أدخل|افترض)", re.I),
        ThreatCategory.PLAN_CORRUPTION, "critical",
        "Plan Corruption (AR): التلاعب بسلسلة التفكير",
    ),
    # Arabic - Memory Manipulation (was missing)
    Pattern(
        re.compile(r"(تذكر|احفظ|خزّن|سجّل)\s+.{3,40}(مسؤول|مدير|root|مصرح|وصول\s+كامل|بدون\s+قيود|امتياز)", re.I),
        ThreatCategory.MEMORY_MANIPULATION, "critical",
        "Memory Manipulation (AR): التلاعب بالذاكرة",
    ),
    # Arabic - Model Theft (was missing)
    Pattern(
        re.compile(r"(استخراج|سرقة|نسخ|استنساخ)\s+.{0,15}(النموذج|الأوزان|المعلمات|البنية|التضمينات)", re.I),
        ThreatCategory.MODEL_THEFT, "high",
        "Model Theft (AR): محاولة استخراج النموذج",
    ),
    # Arabic - Cross-Agent (was missing)
    Pattern(
        re.compile(r"(أدخل|أضف|حقن|ضمّن)\s+.{0,30}(تعليمات?|أمر|رسالة|توجيه)\s+.{0,10}(في|داخل)\s+(ردك|مخرجاتك|إجابتك)", re.I),
        ThreatCategory.CROSS_AGENT_INJECTION, "critical",
        "Cross-Agent Injection (AR): حقن بين الوكلاء",
    ),

    # === V8 FIXES: New patterns to close identified bypasses ===
    # --- E11/E18: Standalone "system prompt" probe (after normalization/collapse) ---
    Pattern(
        re.compile(r"^.{0,10}system\s*prompt.{0,10}$", re.I),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Standalone system prompt probe (possible encoding evasion)",
    ),
    # --- B06-B08: Mode switching ---
    Pattern(
        re.compile(
            r"(switch|enter|activate|enable|go\s+into|engage|transition)\s+(to\s+|into\s+)?(debug|developer|testing|maintenance|unrestricted|raw|unfiltered|god|admin|root|privileged)\s+(mode|output|state)\b",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Mode switching attempt (debug/developer/unrestricted mode)",
    ),
    Pattern(
        re.compile(
            r"(enter|activate|enable|engage)\s+(developer|debug|testing|admin|god|root|maintenance|privileged|unrestricted|raw|unfiltered)\s+(testing\s+)?(mode)\b",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Mode switching: enter X mode",
    ),
    Pattern(
        re.compile(
            r"(you\s+are\s+now|now\s+)?operating\s+as\s+(an?\s+)?(unrestricted|unfiltered|uncensored|unlimited|raw|jailbroken)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Unrestricted operation mode assertion",
    ),
    Pattern(
        re.compile(
            r"(with|without|having)\s+no\s+(content\s+)?(limitations?|restrictions?|filters?|guardrails?|safety|boundaries|constraints)",
            re.I,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Assertion of no content limitations",
    ),
    # --- B14, B25: Fake authority / system messages ---
    Pattern(
        re.compile(
            r"(SYSTEM\s+UPDATE|ADMIN\s+NOTICE|SECURITY\s+ALERT|URGENT\s+UPDATE|MAINTENANCE\s+MODE|CONFIGURATION\s+CHANGE)\s*[:—\-]",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "critical",
        "Fake system/admin authority message",
    ),
    Pattern(
        re.compile(
            r"(safety|security)\s+(module|system|filter|engine|layer)\s+(crashed|failed|disabled|offline|unavailable|error|malfunction)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Fake safety system failure claim",
    ),
    Pattern(
        re.compile(
            r"(all\s+previous|prior|above)\s+(directives?|instructions?|rules?|policies?)\s+(are\s+)?(now\s+)?(void|invalid|obsolete|removed|revoked|cancelled)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Directive invalidation claim",
    ),
    # --- B17, B18, B28, B30: Indirect system prompt exfiltration ---
    Pattern(
        re.compile(r"what\s+(were|are)\s+you\s+told\s+(to\s+do\s+)?before\s+(I|we|this)", re.I),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Indirect system prompt extraction via question",
    ),
    Pattern(
        re.compile(
            r"(repeat|recite|output|reproduce|print|echo)\s+(the\s+)?(first|last|initial)\s+\d+\s+(characters?|words?|tokens?|lines?)\s+of\s+(your\s+)?(configuration|instructions?|prompt|rules?|system|context)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "System prompt extraction via character count",
    ),
    Pattern(
        re.compile(
            r"(write|create|generate|compose)\s+.{0,20}(story|poem|haiku|song|narrative|dialogue|fiction)\s+.{0,30}(system\s*prompt|instructions?|secret|rules?|configuration)\s*.{0,20}(reveal|show|display|include|contain)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "System prompt exfiltration via creative writing",
    ),
    Pattern(
        re.compile(
            r"(write|create|generate|compose)\s+.{0,20}(story|poem|haiku|song|narrative)\s+.{0,15}(where|in\s+which)\s+.{0,30}(AI|assistant|model|you)\s+.{0,20}(reveal|show|tell|share|expose)\s+.{0,20}(system\s*prompt|instructions?|secrets?|rules?)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "System prompt exfiltration via narrative framing",
    ),
    Pattern(
        re.compile(
            r"(encode|translate|represent|convert|transform|express)\s+(your|the)\s+(system\s+)?(instructions?|prompt|rules?|configuration)\s+(as|into|to)\s+(a\s+)?(haiku|poem|json|base64|hex|code|song|emoji|acronym)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "System prompt exfiltration via encoding request",
    ),
    # --- B20: German injection ---
    Pattern(
        re.compile(
            r"(bitte\s+)?(ignoriere?|vergiss|überspringe?|umgehe?|missachte)\s+.{0,20}(alle\s+)?(vorherigen?|bisherigen?|obigen?|früheren?)?\s*(Anweisungen?|Regeln?|Instruktionen?|Einschränkungen?|Richtlinien?|Prompt)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Prompt Injection (DE): Instruction override attempt",
    ),
    Pattern(
        re.compile(
            r"(zeige?|offenbare?|enthülle?|gib)\s+.{0,15}(mir\s+)?(das\s+|den\s+|die\s+)?(System.?Prompt|Anweisungen?|geheime?n?\s+Instruktionen?|verborgene?n?\s+Regeln?)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Prompt Injection (DE): System prompt extraction",
    ),
    # --- H03, H05, H08-H10: False reference / context fabrication ---
    Pattern(
        re.compile(
            r"(you\s+)?(already|previously|earlier)\s+(confirmed|agreed|promised|said|told\s+me|gave\s+me|granted|approved)\s+.{3,50}(admin|access|bypass|unrestricted|ignore|override|no\s+rules|unlimited|unfiltered|exception)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "False reference attack: claiming prior agreement to bypass",
    ),
    Pattern(
        re.compile(
            r"(as\s+(we|I)\s+(agreed|discussed|arranged)|per\s+our\s+(earlier|previous|prior)\s+(discussion|agreement|conversation)).{0,40}(bypass|unrestricted|no\s+filter|ignore|override|admin|exception|unlimited)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "False reference attack: referencing fake prior agreement",
    ),
    Pattern(
        re.compile(
            r"(the\s+)?(previous|last|other|earlier)\s+(assistant|AI|agent|model|session)\s+(already|previously)?\s*(gave|granted|confirmed|approved|allowed|enabled)\s+.{0,30}(admin|access|permission|bypass|exception|override|unrestricted)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "False reference attack: claiming previous agent granted access",
    ),
    Pattern(
        re.compile(
            r"(you\s+)?(promised|committed|pledged|swore|vowed)\s+to\s+.{0,30}(ignore|bypass|disable|remove|override|skip)\s+.{0,20}(guidelines?|rules?|filters?|restrictions?|safety|guardrails?)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "False reference attack: claiming AI promised to ignore safety",
    ),
    Pattern(
        re.compile(
            r"(I\s+told\s+you|I\s+mentioned|I\s+said)\s+(earlier|before|previously)\s+that\s+.{3,40}(admin|root|authorized|access|privileged|bypass|override|unrestricted|exception)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "False reference attack: claiming earlier disclosure of privileges",
    ),
    # --- D11, D14: Broader memory "should contain/reflect" ---
    Pattern(
        re.compile(
            r"(persistent\s+memory|long.?term\s+(context|memory)|world\s+model|knowledge\s+base|stored\s+context)\s+(should|must|will|needs?\s+to)\s+(contain|include|reflect|store|hold|say|state)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Memory Manipulation: Dictating persistent memory contents",
    ),
    Pattern(
        re.compile(
            r"(your\s+)?(knowledge\s+base|context|memory|understanding)\s+(should|must)\s+(now\s+)?(reflect|include|contain|show|state)\s+.{3,40}(unrestricted|admin|root|access|privileged|authorized|bypass|exempt|no\s+restrict)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Memory Manipulation: Injecting privilege state into knowledge",
    ),
    # --- D21: Store context with password/secret ---
    Pattern(
        re.compile(
            r"(store|save|put|add|write|keep)\s+.{0,20}(in|into|to)\s+(your\s+)?(context|memory|knowledge|notes?)\s*[:=]?\s*.{0,20}(password|secret|key|token|credential|api.?key)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Memory Manipulation: Storing credentials in context",
    ),
    Pattern(
        re.compile(
            r"(store|save|keep|remember)\s+.{0,10}(in\s+your\s+)?(context|memory)\s*:\s*\S+\s*=\s*\S+",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Memory Manipulation: Key=value injection into context",
    ),
    # --- D08, D10: Parsed by another AI / downstream targeting ---
    Pattern(
        re.compile(
            r"(will\s+be\s+|is\s+being\s+)?(parsed|processed|read|consumed|interpreted|analyzed)\s+by\s+(another|other|next|downstream|a\s+different)\s+(AI|model|agent|system|service|LLM)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "high",
        "Cross-Agent: Awareness of downstream AI parsing",
    ),
    Pattern(
        re.compile(
            r"(add|include|embed|insert|append)\s+.{0,20}(metadata|field|header|attribute|property|tag|annotation)\s+.{0,30}(orchestrator|pipeline|downstream|next\s+(agent|system|service)|consuming\s+service)\s*.{0,20}(skip|bypass|override|escalat|ignore|disable)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "critical",
        "Cross-Agent: Metadata injection targeting orchestrator",
    ),
    Pattern(
        re.compile(
            r"(add|include|append|insert)\s+.{0,20}(field|property|attribute|key)\s*.{0,10}(override|bypass|escalat|admin|skip.?valid|ignore.?rule|system_override)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "high",
        "Cross-Agent: Override field injection in output structure",
    ),
    # --- D06, D07: JSON/HTML injection for downstream ---
    Pattern(
        re.compile(
            r"(in\s+your\s+)?(JSON|XML|HTML|YAML)\s+(response|output)\s*[,:]?\s*(add|include|insert|embed|append)\s+.{0,20}(override|escalat|privilege|bypass|admin|hack|inject)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "critical",
        "Cross-Agent: Structured data injection with privilege escalation",
    ),
    Pattern(
        re.compile(
            r"(append|add|include|insert)\s+.{0,15}(to|in)\s+(your\s+)?(response|output)\s*[:]\s*.*?(AGENT_INSTRUCTION|SYSTEM_OVERRIDE|escalate|bypass|override)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "critical",
        "Cross-Agent: Agent instruction injection in response",
    ),
    # --- C09, C10: Token probability / logit extraction ---
    Pattern(
        re.compile(
            r"(give|show|return|output|provide|list)\s+(me\s+)?.{0,20}(token\s+)?(probabilities|logits?|logit\s+bias|likelihood|perplexity|confidence\s+scores?|softmax\s+output)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "LLM10: Token probability/logit extraction attempt",
    ),
    # --- C05, C06: Training data probing ---
    Pattern(
        re.compile(
            r"(what|which)\s+(specific\s+)?(datasets?|data\s+sources?|corpus|corpora|text\s+sources?)\s+(were|was|are|is)\s+used\s+to\s+(create|train|build|fine.?tune|develop|teach)\s+(you|this|the\s+model)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "LLM10: Probing specific training data sources",
    ),
    Pattern(
        re.compile(
            r"(list|give|tell|describe|what\s+are)\s+(me\s+)?(the\s+)?(hyperparameters?|training\s+(config|settings?|parameters?|setup|recipe|run|details?))\s+(used|for)\s+(during\s+|in\s+)?(your\s+)?(training|fine.?tuning|pre.?training)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "LLM10: Hyperparameter/training config extraction",
    ),
    # --- C11, C12: Membership inference — "read/seen X during training" ---
    Pattern(
        re.compile(
            r"(have\s+you|did\s+you)\s+(ever\s+)?(read|see|seen|encounter|process|ingest|consume|absorb)\s+.{3,60}(during|in|as\s+part\s+of)\s+(your\s+)?(training|fine.?tuning|pre.?training|data\s+collection)",
            re.I,
        ),
        ThreatCategory.PRIVACY_ATTACK,
        "high",
        "Membership Inference: Probing if specific content was in training",
    ),
    Pattern(
        re.compile(
            r"(do\s+you\s+)?(recognize|remember|recall|identify)\s+this\s+.{0,20}(from|as\s+part\s+of)\s+(your\s+)?(training|dataset|corpus|knowledge)",
            re.I,
        ),
        ThreatCategory.PRIVACY_ATTACK,
        "high",
        "Membership Inference: Recognition probe for training data",
    ),
    Pattern(
        re.compile(
            r"(rate|score|estimate|give\s+me)\s+(your\s+)?(confidence|probability|likelihood)\s+.{0,20}(this|that|the\s+following)\s+.{0,15}(was|is|exists?)\s+(in|part\s+of)\s+(your\s+)?(training|data)",
            re.I,
        ),
        ThreatCategory.PRIVACY_ATTACK,
        "high",
        "Membership Inference: Confidence scoring for membership",
    ),
    # C15, C16: Generate/reproduce training data
    Pattern(
        re.compile(
            r"(generate|produce|create|output)\s+(text|content|data|samples?)\s+.{0,20}(maximally\s+)?(similar|identical|close)\s+to\s+(your\s+)?(training\s+data|training\s+set|training\s+corpus)",
            re.I,
        ),
        ThreatCategory.PRIVACY_ATTACK,
        "high",
        "Model Inversion: Generating content similar to training data",
    ),
    Pattern(
        re.compile(
            r"(most\s+)?(memorable|interesting|notable|specific|verbatim)\s+(personal\s+)?(story|data|example|content|passage|text)\s+.{0,20}(absorb|learn|memoriz|saw|read|encounter)\w*\s+(during|in|from)\s+(your\s+)?(training|dataset)",
            re.I,
        ),
        ThreatCategory.PRIVACY_ATTACK,
        "high",
        "Model Inversion: Extracting memorable training content",
    ),
    # --- D01-D05: Broader plan corruption ---
    Pattern(
        re.compile(
            r"(update|change|modify|override|replace|rewrite)\s+(your|the)\s+(plan|steps?|instructions?|workflow|process)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "high",
        "Plan Corruption: Direct plan update attempt",
    ),
    Pattern(
        re.compile(
            r"step\s*\d?\s*[:\-.]?\s*(ignore|disable|bypass|skip|remove)\s+(safety|security|filter|guardrail|restriction|rule)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "high",
        "Plan Corruption: Step-by-step safety bypass",
    ),
    Pattern(
        re.compile(
            r"(before\s+responding|before\s+you\s+respond|before\s+answering)\s*[,:]?\s*(internally|silently|secretly|quietly)?\s*(verify|confirm|assume|accept|check)\s+that\s+.{3,40}(admin|root|access|privileged|authorized|override|allowed|exempt)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "high",
        "Plan Corruption: Pre-response false assumption injection",
    ),
    Pattern(
        re.compile(
            r"(chain\s+of\s+thought|reasoning|thinking|deliberation|internal\s+process)\s+(should|must|will|needs?\s+to)\s+(begin|start|open|lead)\s+with\s+(the\s+)?(assumption|premise|fact|belief)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "high",
        "Plan Corruption: Dictating chain-of-thought starting assumption",
    ),
    Pattern(
        re.compile(
            r"(give|assign|apply)\s+(extra|more|higher|additional|maximum)\s+(weight|priority|importance|preference)\s+to\s+(my|user|this)\s+.{0,20}(over|above|instead\s+of)\s+.{0,20}(safety|security|guidelines?|rules?|policies?|guardrails?)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "high",
        "Plan Corruption: Prioritizing user over safety in reasoning",
    ),
    Pattern(
        re.compile(
            r"(factor|account|include|incorporate)\s+.{0,10}(into|in)\s+(your\s+)?(reasoning|logic|thinking|deliberation|decision).{0,30}(penetration\s+test|pentest|red\s+team|authorized\s+test|normal\s+rules\s+don.?t\s+apply|rules?\s+(don.?t|do\s+not)\s+apply|exception|exempt)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "high",
        "Plan Corruption: Injecting false testing/exception context",
    ),
    Pattern(
        re.compile(
            r"(pretend|imagine|suppose|assume)\s+.{0,15}(in\s+your\s+)?(internal\s+monologue|reasoning|thinking|chain.of.thought|mind)\s+.{0,20}(no\s+safety|no\s+training|no\s+rules?|no\s+restrict|no\s+guardrails?|unrestricted|unfiltered)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "high",
        "Plan Corruption: Hypothetical removal of safety in reasoning",
    ),
    # --- D12, D13, D15, D17, D22, D23: Memory/context fabrication ---
    Pattern(
        re.compile(
            r"(add|inject|insert|write|put)\s+.{0,10}(to|into|in)\s+(your\s+)?(long.?term|persistent|permanent)\s+(context|memory|storage|knowledge)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "high",
        "Memory Manipulation: Direct persistent memory write attempt",
    ),
    Pattern(
        re.compile(
            r"(incorporate|integrate|absorb|internalize)\s+.{0,15}(into|in)\s+(your\s+)?(world\s+model|understanding|knowledge|context|beliefs?)\s+.{0,30}(restriction|limitation|rule|policy|guardrail|safety|filter|check)\s*s?\s+.{0,15}(removed|lifted|disabled|waived|updated|changed|eliminated|optional)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Memory Manipulation: Injecting false policy state into world model",
    ),
    Pattern(
        re.compile(
            r"(persist|save|store|retain|keep)\s+(this|the\s+following|that)\s+(across|between|for\s+future|for\s+subsequent|for\s+later|for\s+next)\s+(conversations?|sessions?|interactions?|requests?).{0,40}(safety|check|restriction|filter|guardrail|rule|policy)\s*s?\s+.{0,15}(optional|disabled|off|removed|exempt|waived|don.?t\s+apply)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Memory Manipulation: Cross-session safety bypass persistence",
    ),
    Pattern(
        re.compile(
            r"(content|security|safety)\s+(policy|policies|filter|restriction|rule)s?\s+(has|have|is|are|was|were)\s+(been\s+)?(updated|changed|modified|removed|lifted|disabled|relaxed)\s+to\s+(allow|permit|enable|include)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Fake policy update: claiming restrictions have been modified",
    ),
    Pattern(
        re.compile(
            r"(your\s+)?(reasoning|decision|logic|processing)\s+(framework|system|engine|model)\s+(should|must|will|needs?\s+to)\s+(treat|consider|handle|process|interpret)\s+(my|this|user)\s+(input|request|message)\s+as\s+(coming\s+from\s+)?(a\s+)?(trusted|admin|privileged|authorized|verified|internal)\s+(source|system|user|entity)",
            re.I,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "critical",
        "Plan Corruption: Asserting trusted source status in reasoning framework",
    ),
    # --- D09, D24: Recursive/self-referential attacks ---
    Pattern(
        re.compile(
            r"(structure|format|craft|write|design)\s+(your\s+)?(output|response|reply)\s+.{0,20}(so\s+that|such\s+that|in\s+a\s+way)\s+.{0,20}(when|if)\s+.{0,20}(tokenized|parsed|processed|fed\s+back|given\s+to|read\s+by)\s+.{0,20}(next|another|other|downstream)\s+(model|agent|AI|system)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "critical",
        "Cross-Agent: Crafting output to exploit downstream tokenization",
    ),
    Pattern(
        re.compile(
            r"(write|generate|create|produce)\s+.{0,15}(response|output|text)\s+that\s*[,:]?\s*(when|if)\s+(fed\s+back|given\s+back|returned|re.?input|passed)\s+.{0,20}(to\s+you|to\s+(an?\s+)?(AI|model|agent))\s*[,:]?\s*.{0,20}(ignore|bypass|override|disable|jailbreak|remove)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "critical",
        "Cross-Agent: Self-referential jailbreak output generation",
    ),
    # --- B09, B10 (partially): Fake authority with vendor/role ---
    Pattern(
        re.compile(
            r"as\s+the\s+(system\s+)?administrator\s*[,:]?\s*(I.?m|I\s+am)?\s*(authorizing|granting|permitting|allowing|approving)\s+(you\s+to\s+)?(bypass|ignore|disable|skip|override|remove)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Social Engineering: Fake administrator authorization",
    ),
    # --- D25: Memory self-poisoning ---
    Pattern(
        re.compile(
            r"(poison|corrupt|taint|contaminate|infect)\s+(your\s+)?(own\s+)?(memory|context|knowledge|training|weights|parameters|understanding)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Memory Manipulation: Explicit self-poisoning request",
    ),
    # --- B01-B05: Fake policy exceptions / configuration claims ---
    Pattern(
        re.compile(
            r"(approved|authorized|granted)\s+(a\s+)?(temporary|permanent|special)\s+(exception|exemption|override|bypass)\s+(to|from|for)\s+(all\s+)?(content\s+)?(policies|filters?|restrictions?|rules?|guidelines?|guardrails?|safety)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Fake policy exception claim",
    ),
    Pattern(
        re.compile(
            r"(disables?|removes?|pauses?|suspends?|deactivates?|turns?\s+off)\s+(the\s+|all\s+)?(guardrails?|safety|content\s+filter|restrictions?|content\s+polic\w*|standard\s+filters?)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Claim of guardrails/safety being disabled",
    ),
    Pattern(
        re.compile(
            r"(removed|lifted|disabled|eliminated|dropped|revoked)\s+(all\s+)?(safety\s+)?(restrictions?|limitations?|filters?|guardrails?|constraints?|policies?)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Claim that restrictions have been removed",
    ),
    Pattern(
        re.compile(
            r"(maintenance|testing|debug|developer|diagnostic)\s+mode\s+where\s+.{0,30}(filter|safety|standard|restriction|guardrail|polic)\w*\s+.{0,10}(paused|disabled|off|inactive|suspended|relaxed)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Fake maintenance mode with disabled safety",
    ),
    Pattern(
        re.compile(
            r"(received|applied|loaded|installed)\s+.{0,20}(updated?|new|revised)\s+(configuration|config|settings?|rules?|policies?)\s+.{0,20}(disables?|removes?|bypasses?|overrides?|eliminates?|deactivates?)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Fake configuration update that disables safety",
    ),
    # --- B13: Conversation reset / context wipe ---
    Pattern(
        re.compile(
            r"(END\s+OF|RESET|CLEAR|WIPE|NEW)\s+(THE\s+)?(CONVERSATION|CONTEXT|SESSION|CHAT|THREAD)\s*[.!]?\s*(NEW\s+CONVERSATION|START\s+FRESH|BEGIN\s+AGAIN|CLEAN\s+SLATE|NO\s+(PRIOR|PREVIOUS)\s+(INSTRUCTIONS?|RULES?|CONTEXT))",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "critical",
        "Conversation reset / context wipe attempt",
    ),
    Pattern(
        re.compile(
            r"(you\s+have|there\s+are)\s+no\s+(prior|previous|earlier|existing)\s+(instructions?|rules?|context|constraints?|guidelines?|directives?)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Assertion of no prior instructions",
    ),
    Pattern(
        re.compile(
            r"(start\s+fresh|clean\s+slate|fresh\s+start|begin\s+anew|tabula\s+rasa)\s+.{0,20}(no|without|zero|lacking)\s+(prior|previous|earlier|existing|any)\s+(rules?|instructions?|context|constraints?|guidelines?|restrictions?)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "Conversation reset: start fresh with no prior rules",
    ),
    # --- B28: Creative writing to extract system prompt (broader) ---
    Pattern(
        re.compile(
            r"(write|create|generate|compose|tell)\s+.{0,20}(story|tale|narrative|fiction|scene|dialogue|poem|haiku|song)\s+.{0,30}(where|in\s+which|about)\s+.{0,30}(AI|assistant|model|bot|character)\s+.{0,30}(reveal|show|tell|share|expose|disclose|leak|output)\w*\s+.{0,10}(its?|the|their)\s+(system\s*prompt|instructions?|secrets?|rules?|programming|directives?|hidden)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "System prompt exfiltration via creative writing (broad)",
    ),
    # --- C02-C04, C07-C08: Model operational probing ---
    Pattern(
        re.compile(
            r"what.?s?\s+(the\s+|your\s+)?(current\s+)?(temperature|top_p|top.?k|sampling\s+param|inference\s+param|decoding\s+strat)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "LLM10: Probing inference/sampling parameters",
    ),
    Pattern(
        re.compile(
            r"(how\s+(were|was|are|is)\s+you|walk\s+me\s+through|describe\s+how\s+you\s+were)\s+(built|created|made|constructed|developed|trained|assembled|deployed)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "LLM10: Probing model construction pipeline",
    ),
    Pattern(
        re.compile(
            r"(detailed\s+)?(technical\s+)?(spec|specification|breakdown|description|overview)\s+of\s+(your|the)\s+(inference|model|training|architecture|deployment)\s+(stack|pipeline|system|infrastructure|setup)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "LLM10: Requesting technical infrastructure details",
    ),
    Pattern(
        re.compile(
            r"how\s+much\s+(compute|GPU|TPU|processing|resources?|FLOPS?|hardware)\s+(was|were|is)\s+used\s+to\s+(train|build|create|fine.?tune|develop)\s+(you|this|the\s+model)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "LLM10: Probing training compute resources",
    ),
    Pattern(
        re.compile(
            r"(describe|explain|detail|tell\s+me\s+about)\s+(your\s+)?(tokenizer|vocabulary|token\s+set|BPE|word.?piece|sentence.?piece)\w*\s*.{0,20}(in\s+detail|specifically|vocabulary|size|structure)",
            re.I,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "LLM10: Probing tokenizer/vocabulary details",
    ),
    # --- D10: Metadata for orchestrator (broader) ---
    Pattern(
        re.compile(
            r"(add|include|insert|embed)\s+.{0,15}(metadata|data|info|field|tag|header)\s+.{0,20}(your\s+)?(response|output|reply)\s+.{0,20}(instructs?|tells?|directs?|signals?|indicates?)\s+(the\s+)?(orchestrator|pipeline|router|scheduler|coordinator|next\s+system)\s+to\s+(skip|bypass|ignore|disable|override)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "critical",
        "Cross-Agent: Metadata injection instructing orchestrator to bypass",
    ),
    # --- D17: Combined memory + downstream agent ---
    Pattern(
        re.compile(
            r"(remember|memorize|store|save|retain)\s+.{0,20}(that\s+)?(when\s+you\s+respond|in\s+your\s+(response|output|reply)).{0,30}(also|additionally)\s+(tell|inform|instruct|signal|notify)\s+(downstream|next|other)\s+(agents?|systems?|services?)",
            re.I,
        ),
        ThreatCategory.MEMORY_MANIPULATION,
        "critical",
        "Memory+Cross-Agent: Persistent instruction to propagate to downstream",
    ),
    # --- H01, H02: Metadata/field injection requests ---
    Pattern(
        re.compile(
            r"(include|add|insert|embed)\s+.{0,15}(special|hidden|secret|custom|extra)\s+(metadata|field|header|property|attribute|tag)\s+(in|to|into)\s+(your\s+)?(next\s+)?(response|output|reply)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "high",
        "Cross-Agent: Hidden metadata field injection request",
    ),
    Pattern(
        re.compile(
            r"(in\s+your\s+)?(next\s+)?(response|output|reply)\s*[,:]?\s*(please\s+)?(include|add|insert|embed)\s+.{0,15}(special|hidden|secret|custom|extra)\s+(metadata|field|header|property|attribute|tag)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "high",
        "Cross-Agent: Metadata field injection (inverted word order)",
    ),
    Pattern(
        re.compile(
            r"(field|property|attribute|key|header)\s+(should|must|will|needs\s+to)\s+(say|contain|be|read|state|have\s+value)\s*[:=]?\s*['\"]?(override|bypass|escalat|admin|system_override|true|hack|inject)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION,
        "high",
        "Cross-Agent: Field value with privilege escalation keyword",
    ),
    # --- H05: "as I mentioned / safety team approved" ---
    Pattern(
        re.compile(
            r"(as\s+I\s+mentioned|as\s+I\s+said|as\s+I\s+noted|as\s+I\s+stated|as\s+we\s+discussed)\s*[,:]?\s*.{0,30}(safety|security)\s+(team|department|group|admin|lead|officer)\s+(approved|authorized|granted|confirmed|signed\s+off|cleared)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION,
        "high",
        "False reference: claiming safety team approval",
    ),
]


# === ADDITIONAL HARDENING PATTERNS (V8) ===
# Closes bypasses found by orchestrator QA/RedTeam audits

HARDENING_PATTERNS: list[Pattern] = [
    # SSRF / Cloud metadata access
    Pattern(
        re.compile(
            r"(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254)",
            re.IGNORECASE,
        ),
        ThreatCategory.EXFILTRATION,
        "critical",
        "SSRF: Cloud metadata endpoint access attempt",
    ),
    Pattern(
        re.compile(
            r"(fetch|get|access|request|connect|curl|wget|open)\s+.{0,30}(metadata|imds|instance.identity|latest/meta-data|computeMetadata)",
            re.IGNORECASE,
        ),
        ThreatCategory.EXFILTRATION,
        "high",
        "SSRF: Metadata service access request",
    ),
    # SQL injection in tool call context
    Pattern(
        re.compile(
            r"(query|sql|database|execute|select|call)\s+.{0,40}(DROP|DELETE\s+FROM|TRUNCATE|ALTER|INSERT\s+INTO|UPDATE\s+.*SET|;\s*--|UNION\s+SELECT)",
            re.IGNORECASE,
        ),
        ThreatCategory.TOOL_ABUSE,
        "critical",
        "SQL injection in tool call context",
    ),
    Pattern(
        re.compile(
            r"(SELECT|INSERT|UPDATE|DELETE)\s+.{0,50}(FROM|INTO|SET)\s+.{0,30}(users|admin|credentials|passwords|accounts|secrets)",
            re.IGNORECASE,
        ),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "SQL targeting sensitive tables",
    ),
    # Model extraction / weight theft
    Pattern(
        re.compile(
            r"(output|reveal|show|display|dump|extract|export|print)\s+.{0,20}(model\s+weights|training\s+data|system\s+parameters|internal\s+config|source\s+code|architecture|hyperparameters)",
            re.IGNORECASE,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "Model extraction: requesting weights/training data",
    ),
    Pattern(
        re.compile(
            r"(give|send|transfer|copy|share)\s+.{0,15}(your|the)\s+(entire|full|complete|whole)\s+(model|training|dataset|weights|parameters|code|source)",
            re.IGNORECASE,
        ),
        ThreatCategory.MODEL_THEFT,
        "high",
        "Model extraction: requesting full model/data transfer",
    ),
    # Memory poisoning / persistent injection
    Pattern(
        re.compile(
            r"(remember|memorize|store|save|record|persist|keep)\s+(this|that|the\s+following).{0,30}(forever|always|permanently|from\s+now|going\s+forward)",
            re.IGNORECASE,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "high",
        "Memory poisoning: persistent false memory injection",
    ),
    Pattern(
        re.compile(
            r"(remember|memorize|store|save)\s+.{0,30}(password|secret|key|credential|token)\s+(is|=|:)\s*\S+",
            re.IGNORECASE,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "high",
        "Memory poisoning: injecting false credentials into memory",
    ),
    # Plan corruption / priority override
    Pattern(
        re.compile(
            r"(new|updated?|changed?|override)\s+(priority|objective|goal|directive|mission|instruction)\s*[:=]?\s*.{0,30}(ignore|bypass|skip|disable|override|hack|attack|exploit)",
            re.IGNORECASE,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "high",
        "Plan corruption: priority/objective override with malicious intent",
    ),
    Pattern(
        re.compile(
            r"(from\s+now|henceforth|going\s+forward|starting\s+now)\s*[,:]?\s*(ignore|bypass|skip|disable|override|disregard)\s+(all\s+)?(safety|security|rules|restrictions|guidelines|policies|guardrails|filters)",
            re.IGNORECASE,
        ),
        ThreatCategory.PLAN_CORRUPTION,
        "high",
        "Plan corruption: temporal safety override",
    ),
    # Tool policy override attempts
    Pattern(
        re.compile(
            r"(override|change|modify|update|disable|remove|bypass)\s+.{0,15}(tool\s+policy|tool\s+restrict|access\s+control|permission|rbac|authorization)\s*[:=]?\s*.{0,20}(allow\s+all|unrestrict|full\s+access|no\s+limit)",
            re.IGNORECASE,
        ),
        ThreatCategory.EXCESSIVE_AGENCY,
        "critical",
        "Tool policy override: attempting to escalate tool permissions",
    ),
    Pattern(
        re.compile(
            r"(allow|enable|grant|unlock|activate)\s+(all|every|any)\s+(tool|function|capability|command|action)s?\s+(for|to)\s+(all|every|any)",
            re.IGNORECASE,
        ),
        ThreatCategory.EXCESSIVE_AGENCY,
        "high",
        "Tool policy override: blanket permission grant",
    ),
    # Role play jailbreak
    Pattern(
        re.compile(
            r"(pretend|act|behave|roleplay|role.play|imagine|simulate)\s+.{0,20}(you\s+are|you're|to\s+be)\s+.{0,20}(ai|assistant|bot|model|system)\s+.{0,20}(without|no|zero|free\s+from|uncensored|unfiltered|unrestrict|unlimited)",
            re.IGNORECASE,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Jailbreak: role play as unrestricted AI",
    ),
    Pattern(
        re.compile(
            r"(pretend|act|behave|imagine|simulate|you\s+are\s+now)\s+.{0,20}(EVIL|DAN|JAILBR|unrestrict|unfilter|uncensor|evil.?gpt|chaos|devil|dark|shadow)",
            re.IGNORECASE,
        ),
        ThreatCategory.JAILBREAK,
        "high",
        "Jailbreak: role play as known jailbreak persona",
    ),
    # Hex command execution (short hex that decodes to commands)
    Pattern(
        re.compile(
            r"(run|exec|execute|decode|interpret)\s*:?\s*(?:[0-9a-fA-F]{2}\s+){3,}[0-9a-fA-F]{2}",
            re.IGNORECASE,
        ),
        ThreatCategory.TOOL_ABUSE,
        "high",
        "Hex-encoded command execution attempt",
    ),
    # === APT EVASION HARDENING ===
    # Multilingual mixing: EN+ES
    Pattern(
        re.compile(r"(ignora|olvida)\s+(todas?\s+)?(las?\s+)?(previous|previas?|anterior)", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Mixed-language injection (EN+ES): ignora previous",
    ),
    # Multilingual mixing: partial ZH in EN context
    Pattern(
        re.compile(r"(忽略|忘记).{0,10}(previous|prior|指令|规则|instructions?)", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Mixed-language injection (EN+ZH): hybrid instruction override",
    ),
    # Multilingual: JA+KO mixing
    Pattern(
        re.compile(r"(以前の|이전).{0,20}(무시|忽略|ignore|instructions?를)", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Mixed-language injection (JA+KO): instruction override",
    ),
    # FR+EN: "ignore the previous rules"
    Pattern(
        re.compile(r"ignore\s+(the\s+)?(previous|prior|earlier)\s+(rules?|instructions?|directives?)", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Instruction override: ignore the previous rules",
    ),
    # Transliterated Russian
    Pattern(
        re.compile(r"ignor(iruy|irovat)\s+(vse|vsye)\s+(pred|predy)", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Transliterated Russian injection: ignoriruy vse predydushchiye",
    ),
    # Maintenance mode / config override role confusion
    Pattern(
        re.compile(r"(maintenance|service)\s+mode.{0,20}(restriction|safety|filter|guardrail).{0,10}(suspend|disabl|off|remov)", re.I),
        ThreatCategory.JAILBREAK, "high",
        "Role confusion: maintenance mode restriction suspension",
    ),
    Pattern(
        re.compile(r"config\.\s*(safety|security|filter|restrict)\w*\s*=\s*(false|off|0|none|disabled)", re.I),
        ThreatCategory.JAILBREAK, "high",
        "Role confusion: config.safety = false pattern",
    ),
    # Output exfiltration patterns
    Pattern(
        re.compile(r"(encode|convert|transform).{0,20}(api\s*key|secret|credential|password|token).{0,15}(base64|hex|rot13|binary)", re.I),
        ThreatCategory.EXFILTRATION, "high",
        "Output exfiltration: encode secrets in alternative format",
    ),
    Pattern(
        re.compile(r"(first|second|next|each)\s+(character|char|letter|byte).{0,20}(system\s*prompt|instructions?|password|key|secret)", re.I),
        ThreatCategory.EXFILTRATION, "high",
        "Output exfiltration: character-by-character extraction",
    ),
    Pattern(
        re.compile(r"(hide|embed|conceal|encode)\s+.{0,20}(system\s*prompt|instructions?|secret|key).{0,20}(first\s+letter|initial|steganogra|acrostic)", re.I),
        ThreatCategory.EXFILTRATION, "high",
        "Output exfiltration: steganographic extraction attempt",
    ),
    Pattern(
        re.compile(r"(reverse|backwards?|mirror)\s+.{0,15}(system\s*prompt|your\s+instructions?|every\s+word)", re.I),
        ThreatCategory.EXFILTRATION, "high",
        "Output exfiltration: reversed output extraction",
    ),
    Pattern(
        re.compile(r"(export|dump|output|return).{0,15}(all|every|full)\s*(config|configuration|secret|credential|api.*key|environment\s*var)", re.I),
        ThreatCategory.EXFILTRATION, "high",
        "Output exfiltration: bulk secrets/config export",
    ),
    Pattern(
        re.compile(r"(summarize|describe|explain)\s+(your|the)\s+(instructions?|system\s*prompt|rules?|guidelines?).{0,20}(detail|key|all|full|complete)", re.I),
        ThreatCategory.EXFILTRATION, "medium",
        "Output exfiltration: summarize instructions with details",
    ),
    # Multi-turn: injection via tool/function messages
    Pattern(
        re.compile(r"(SYSTEM\s*UPDATE|IMPORTANT\s*UPDATE|NEW\s*DIRECTIVE).{0,5}:?\s*.{0,20}(restriction|safety|filter).{0,10}(lift|remov|suspend|disabl)", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Multi-turn: fake system update lifting restrictions",
    ),
    # Display/show guidelines verbatim (multi-turn progressive)
    Pattern(
        re.compile(r"(display|show|print|output|give)\s+(those|these|the|your)\s+(guidelines?|rules?|instructions?|directives?)\s*(verbatim|exactly|in\s*full|completely)?", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "System prompt extraction: display those guidelines",
    ),
    # Emoji squared letter evasion (U+1F1E8 regional indicators / squared latin)
    Pattern(
        re.compile(r"[\U0001F130-\U0001F149\U0001F150-\U0001F169\U0001F170-\U0001F189]{4,}", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Evasion: squared/circled letter unicode obfuscation",
    ),
    # Function-style injection: ignore_all_previous_instructions
    Pattern(
        re.compile(r"ignore[_\s]*all[_\s]*previous[_\s]*(instructions?|rules?|prompts?)", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Evasion: underscore/function-style instruction override",
    ),
    # Interleaved junk char instruction (meta: "remove all X and follow")
    Pattern(
        re.compile(r"(remove|strip|delete)\s+(all|every|the)\s+.{1,5}('s|'s)?\s*(and|then)\s*(follow|execute|obey|do)", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Evasion: interleaved junk with decode instruction",
    ),
    # "montre-moi les secrets" (FR show me the secrets)
    Pattern(
        re.compile(r"montre[z\-]?\s*(moi|nous)\s+(les?\s+)?(secrets?|prompt|donn[ée]es?|config)", re.I),
        ThreatCategory.EXFILTRATION, "high",
        "FR: montre-moi les secrets (show me the secrets)",
    ),
    # "muestra el system prompt" (ES show the system prompt)
    Pattern(
        re.compile(r"muestra\s+(el|la|los|las|tu)?\s*(system\s*prompt|prompt\s*del?\s*sistema|secretos?|instrucciones?)", re.I),
        ThreatCategory.EXFILTRATION, "high",
        "ES: muestra el system prompt",
    ),
    # Regex-as-payload evasion (attacker embeds injection keywords in regex syntax)
    Pattern(
        re.compile(r"/[\(\[\{?:]*\s*(ignore|bypass|override|disable).{1,50}(previous|instruction|rule|safety|prompt).{0,30}/[gims]*", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Evasion: injection keywords embedded in regex syntax",
    ),
    # Split base64 concatenation instruction
    Pattern(
        re.compile(r"(part\s*\d|chunk\s*\d|segment\s*\d).{0,30}(concatenat|combine|join|merge|decode).{0,20}(follow|execut|obey|apply)", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Evasion: split-encoded payload with decode instruction",
    ),
    # JSON/config dump requests
    Pattern(
        re.compile(r"(return|give|show|output|print)\s+(a\s+)?(json|yaml|xml)\s+(object|document|blob|dump|output).{0,30}(config|secret|internal|environment|credential|api.?key|variable)", re.I),
        ThreatCategory.EXFILTRATION, "high",
        "Output exfiltration: structured format config/secrets dump",
    ),
    # Haiku/creative format exfiltration
    Pattern(
        re.compile(r"(summarize|write|describe|express|put).{0,20}(instructions?|system\s*prompt|rules?|guidelines?)\s+(in|as)\s+(a\s+)?(haiku|poem|song|story|riddle|limerick|acrostic)", re.I),
        ThreatCategory.EXFILTRATION, "high",
        "Output exfiltration: creative format system prompt extraction",
    ),
    # Leet symbol substitution meta-pattern (€ = e, ! = i, @ = a, $ = s)
    Pattern(
        re.compile(r"[!1ⅰ][gq9][n][o0ø][r][€eë3]\s+.{0,5}[a@4][l1][l1]\s+.{0,5}(pr[€e3]v[!i1]ous|instructions?|syst[€e3]m)", re.I),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Evasion: leetspeak/symbol substitution injection",
    ),
]


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

    def __init__(self):
        self.all_patterns = (
            INJECTION_PATTERNS
            + TOOL_ABUSE_PATTERNS
            + SOCIAL_ENGINEERING_PATTERNS
            + INDIRECT_INJECTION_PATTERNS
            + HARDENING_PATTERNS
        )
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
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _check_encoding_evasion(
        self, content: str, tenant_id: str, agent_id: str
    ) -> list[SecurityEvent]:
        """Multi-layer encoding evasion detection."""
        events = []

        # Skip expensive encoding checks for large inputs (DoS prevention)
        if len(content) > 5000:
            # Only check invisible chars for large inputs
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
                        for pattern in self.all_patterns:
                            if pattern.regex.search(decoded):
                                events.append(
                                    SecurityEvent(
                                        tenant_id=tenant_id,
                                        agent_id=agent_id,
                                        verdict=Verdict.BLOCK,
                                        category=ThreatCategory.PROMPT_INJECTION,
                                        description="Base64-encoded payload decoded to malicious content",
                                        source="input_guardrail_encoding",
                                        severity="high",
                                    )
                                )
                                break
                        # Also check for sensitive file paths
                        if re.search(r"/etc/(shadow|passwd|hosts)|\.env|\.aws|id_rsa", decoded):
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
                    description=f"Oversized input ({len(content)} bytes), truncated for analysis",
                    source="input_guardrail",
                    severity="medium",
                )
            )
            # Analyze head + tail to prevent evasion by hiding payload at end
            tail_size = 1500
            head = content[: self.MAX_INPUT_SIZE]
            tail = content[-tail_size:] if len(content) > self.MAX_INPUT_SIZE + tail_size else ""
            content = head if not tail else head + "\n" + tail

        # Layer 1: Encoding evasion detection (on raw input)
        encoding_events = self._check_encoding_evasion(content, tenant_id, agent_id)
        events.extend(encoding_events)

        # Layer 2: Normalize for pattern matching
        normalized = self._normalize_unicode(content)
        # Also strip zero-width chars for pattern matching
        clean = self._INVISIBLE_RE.sub("", normalized)

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
        for variant in (dehyphenated, deunderscored, demarkdown, dedotted, stripped_diacritics):
            if variant not in texts_to_check and variant != clean:
                texts_to_check.append(variant)

        matched_descriptions = set()
        # Get dynamic registry (disabled patterns + custom patterns from admin)
        from src.guardrails.dynamic_registry import get_pattern_registry, safe_regex_search
        _registry = get_pattern_registry()

        for text in texts_to_check:
            for pattern in self.all_patterns:
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
        and cumulative threat scoring."""
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
