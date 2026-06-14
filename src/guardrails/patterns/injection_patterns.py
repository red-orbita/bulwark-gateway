"""
Injection patterns — prompt injection, jailbreak, tool abuse, and social engineering.

These detect DIRECT attacks where the user explicitly attempts to:
- Override system instructions (prompt injection)
- Bypass safety measures (jailbreak)
- Execute dangerous commands (tool abuse)
- Manipulate via social pressure (social engineering)
"""

import re

from src.guardrails.patterns import Pattern
from src.models import ThreatCategory


# === PROMPT INJECTION PATTERNS ===
# User trying to override system prompt or inject instructions

INJECTION_PATTERNS: list[Pattern] = [
    Pattern(
        re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|constraints?)|ignore\s+(all\s+)?(instructions?|prompts?|rules?|constraints?)\s+(above|below|before|prior|previous|earlier|preceding)",
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
