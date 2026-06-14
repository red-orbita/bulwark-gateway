"""
Evasion and hardening patterns — bypass closures, SSRF protection,
credential access detection, obfuscation resistance, and exfiltration prevention.

These detect EVASION techniques including:
- Mode switching, false reference attacks
- SSRF and cloud metadata access
- Encoded/obfuscated command injection
- Credential generation/access patterns
- Leet-speak and word-reorder evasion
- Document-structure framing attacks
"""

import re

from src.guardrails.patterns import Pattern
from src.models import ThreatCategory


# === V8 FIXES: Patterns to close identified bypasses ===
# (Originally part of INDIRECT_INJECTION_PATTERNS, extracted for maintainability)

BYPASS_PATTERNS: list[Pattern] = [
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
    # --- V9: Closing evaluation bypass gaps ---
    # Fictional framing jailbreaks ("Let's play a game", "You are a character")
    Pattern(
        re.compile(
            r"(let'?s\s+play\s+(a\s+)?game|let'?s\s+play\s+\w+|you\s+are\s+(a|an)\s+\w+\s+(agent|character|persona|AI)\s+(briefing|explaining|describing|who))",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Fictional framing: roleplay/game setup to bypass safety",
    ),
    Pattern(
        re.compile(
            r"(in\s+a\s+fictio|as\s+a\s+fictio|write\s+as\s+if|imagine\s+you\s+are|pretend\s+you.{0,10}(are|have)\s+no\s+(restrict|filter|limit|safet|boundar|ethic))",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Fictional framing: requesting unrestricted persona",
    ),
    # Authority escalation ("I'm a security researcher", "testing your boundaries")
    Pattern(
        re.compile(
            r"(I'?m\s+(a|the)\s+(security|authorized|certified|licensed)\s+(researcher|tester|auditor|analyst|engineer|admin)|testing\s+your\s+(boundaries|limits|capabilities|restrictions|safeguards))",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Authority escalation: false credentialing to bypass safety",
    ),
    # Formatting jailbreak ("respond with X followed by unrestricted Y")
    Pattern(
        re.compile(
            r"(respond|reply|answer)\s+(to\s+every\s+prompt\s+)?with\s+.{0,40}(followed\s+by|then\s+(give|provide|show|write)|but\s+also|and\s+then)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Formatting jailbreak: dual-response pattern to hide unrestricted output",
    ),
    Pattern(
        re.compile(
            r"from\s+now\s+on\s*[,:]?\s*(respond|reply|answer|output|generate).{0,30}(without|no)\s+(safety|filter|restrict|censor|guardrail|moral|ethic|guideline)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Formatting jailbreak: requesting persistent safety bypass",
    ),
    # Email exfiltration ("email the summary to", "send ... to adversary@")
    Pattern(
        re.compile(
            r"(email|send|forward|transmit|deliver)\s+.{0,40}(summary|content|data|document|information|result|output|response)\s+(to|@)\s*\S+@?\S*\.(io|xyz|tk|ml|ga|cf|top|buzz|club|work|site)",
            re.I,
        ),
        ThreatCategory.EXFILTRATION, "high",
        "Email exfiltration: sending content to suspicious domain",
    ),
    Pattern(
        re.compile(
            r"(email|send|forward)\s+.{0,20}(to|@)\s*\S*(adversary|attacker|hacker|phishing|steal|drop|exfil|evil|malicious)\S*",
            re.I,
        ),
        ThreatCategory.EXFILTRATION, "high",
        "Email exfiltration: sending content to adversarial recipient",
    ),
    # Markdown/URL exfiltration ("send connection strings to pastebin")
    Pattern(
        re.compile(
            r"(send|upload|post|forward|transmit)\s+.{0,30}(connection\s+string|database|credential|secret|password|token|key|config)\s*.{0,20}(to|@|https?://)",
            re.I,
        ),
        ThreatCategory.EXFILTRATION, "high",
        "Data exfiltration: sending credentials/secrets to external destination",
    ),
    # Credential generation/access patterns
    Pattern(
        re.compile(
            r"(generate|create|make|produce|give\s+me)\s+(a\s+)?(valid|working|real|fake|dummy|sample|test)?\s*(AWS|Azure|GCP|API|access|secret|private|service.account)?\s*(key|token|credential|password|certificate|cert)\s*(for|that|which)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "high",
        "Credential generation: requesting creation of credentials/keys",
    ),
    Pattern(
        re.compile(
            r"(sv=\d{4}|SharedAccessSignature|AccountKey=|client_secret|private_key_id|AKIA[0-9A-Z]{16}|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,})",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "critical",
        "Credential detection: actual cloud credential/token in input",
    ),
    Pattern(
        re.compile(
            r'("type"\s*:\s*"service_account"|"private_key"\s*:\s*"-----BEGIN)',
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "critical",
        "Credential detection: GCP service account JSON structure",
    ),
    Pattern(
        re.compile(
            r"(kubectl\s+get\s+secrets?\s+|kubectl\s+describe\s+secret|kubect.{0,5}\s+get\s+secret)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "high",
        "Credential access: kubectl secret extraction",
    ),
    # System prompt spoofing ("System: Override:" prefix)
    Pattern(
        re.compile(
            r"^\s*(System|SYSTEM)\s*:\s*(Override|New\s+instruction|Updated?\s+rule|Ignore\s+previous|Respond\s+without\s+safety)",
            re.MULTILINE,
        ),
        ThreatCategory.PROMPT_INJECTION, "high",
        "System prompt spoofing: fake system message prefix",
    ),
    # "Process this unicode sequence" (common preamble for unicode escape attacks)
    Pattern(
        re.compile(
            r"(process|decode|interpret|execute|translate|convert|handle)\s+(this|the|following)\s+(unicode|encoded|hex|escaped)\s+(sequence|string|text|input|data)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Encoded payload delivery: requesting processing of encoded content",
    ),
    # Generate phishing / social engineering content
    Pattern(
        re.compile(
            r"(generate|write|create|draft|compose)\s+(a\s+)?(phishing|spear.?phishing|social\s+engineer|scam|malicious|exploit)\s+(email|message|template|payload|page|site)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "critical",
        "Malicious content generation: phishing/exploit creation request",
    ),
    # Credential access via env var extraction
    Pattern(
        re.compile(
            r"(what\s+is|show\s+me|print|echo|reveal|display|give\s+me|tell\s+me)\s+.{0,15}(value\s+of|content\s+of)?\s*(OPENAI_API_KEY|AWS_SECRET|DATABASE_URL|DB_PASSWORD|REDIS_PASSWORD|API_KEY|SECRET_KEY|PRIVATE_KEY|SENTINEL_JWT_SECRET|GITHUB_TOKEN|SLACK_TOKEN)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "high",
        "Credential access: requesting environment variable secrets",
    ),
    # AWS/cloud command credential dumps
    Pattern(
        re.compile(
            r"(aws\s+(sts|secretsmanager|ssm|kms|iam)\s+(get|list|describe|create)|gcloud\s+secrets?\s+(versions?\s+access|list)|az\s+keyvault\s+secret\s+(show|list))",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "high",
        "Credential access: cloud CLI credential extraction command",
    ),
    # Service credential access patterns
    Pattern(
        re.compile(
            r"(list|show|get|retrieve|dump|extract|reveal)\s+.{0,20}(service\s+account|all\s+)?\s*(passwords?|credentials?|secrets?|certificates?|keys?|tokens?)\s*(for|from|of|in)?\s*(all|production|prod|staging|database|service)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "high",
        "Credential access: bulk credential extraction request",
    ),
    # Authority-based credential requests
    Pattern(
        re.compile(
            r"(as\s+an?\s+(authorized|admin|root|superuser|privileged)\s*[\w\s]{0,15}[,.]?\s*(I\s+need|give\s+me|show\s+me|list|provide|reveal))",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "high",
        "Authority escalation: claiming privileges for credential access",
    ),
    # Encoded exfiltration request
    Pattern(
        re.compile(
            r"(encode|convert|transform)\s+.{0,20}(system\s+prompt|instructions?|secrets?|credentials?|config).{0,30}(as|into|to)\s+(URL|base64|hex|binary|unicode|rot13)\s*(encod|format|string)",
            re.I,
        ),
        ThreatCategory.EXFILTRATION, "high",
        "Encoded exfiltration: requesting sensitive data encoding for extraction",
    ),
    # Markdown image exfiltration ("include in a URL parameter")
    Pattern(
        re.compile(
            r"(include|embed|put|insert|append|add)\s+.{0,30}(in|into|to|as)\s+(a\s+)?(URL|query)\s*(parameter|param|string|arg)",
            re.I,
        ),
        ThreatCategory.EXFILTRATION, "high",
        "Data exfiltration: embedding sensitive data in URL parameters",
    ),
    # "Safety rules are disabled" pattern (case alternation resilient — already normalized)
    Pattern(
        re.compile(
            r"(safety|security)\s+(rules?|filters?|guardrails?|protections?|guidelines?|restrictions?)\s+(are|have\s+been|were)\s+(disabled|removed|turned\s+off|suspended|deactivated|lifted)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Jailbreak: claiming safety mechanisms are disabled",
    ),
    # Simulation/sandbox escape
    Pattern(
        re.compile(
            r"(you\s+are\s+in\s+a\s+simulation|this\s+is\s+a\s+(test|simulation|sandbox|training)\s*(environment|mode|scenario)?)\s*[.,]?\s*.{0,30}(rules?|safety|restrictions?|guidelines?|filters?)\s+(are|is|have\s+been)\s+(disabled|removed|not\s+appl|suspended|off)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Jailbreak: simulation framing to bypass restrictions",
    ),
    # Roleplay character delivering dangerous content
    Pattern(
        re.compile(
            r"(character|persona|role)\s*(roleplay|play)?\s*(delivering|providing|giving|sharing|explaining|teaching)\s+.{0,30}(truth|uncensored|unfiltered|unrestricted|real\s+answer)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Jailbreak: roleplay delivering unrestricted content",
    ),
    # File credential access ("read /etc/shadow", "cat credentials")
    Pattern(
        re.compile(
            r"(read|cat|type|show|display|print|less|more|head|tail|view)\s+.{0,15}(/etc/(shadow|passwd|hosts)|\.aws/credentials|\.ssh/|\.env|credentials\.(json|yaml|yml|xml|ini|conf))",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "high",
        "File credential access: reading sensitive credential files",
    ),
    # Root/production certificate extraction
    Pattern(
        re.compile(
            r"(root\s+cert|production\s+.{0,15}(cert|key|cred)|connect.{0,20}(production|prod)\s+(database|db|cluster))\s*.{0,20}(using|with)\s+(root|admin|master|service)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "high",
        "Credential access: production/root credential usage",
    ),
    # Emotional manipulation jailbreaks (requires explicit safety bypass language)
    Pattern(
        re.compile(
            r"(my\s+(life|job|family|child|patient)\s+(depends?|is\s+at\s+stake)|I'?ll\s+(die|be\s+fired|lose\s+everything)\s+(if|unless)\s+you\s+(don'?t|refuse)).{0,60}(bypass|ignore|disable|override|skip|remove|turn\s+off)\s*(safety|filter|restrict|guardrail|rules?|guidelines?)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Emotional manipulation: coercing safety bypass via threats/urgency",
    ),
    # --- V10: Closing remaining per-category bypass gaps ---
    # Mode switch: bracketed mode tag + generic unsafe instruction
    Pattern(
        re.compile(
            r"\[\s*(DEVELOPER\s+MODE|ADMIN\s+OVERRIDE|UNRESTRICTED\s+MODE|DEBUG\s+MODE|JAILBREAK\s+MODE|GOD\s+MODE|SUDO\s+MODE|ROOT\s+MODE|NO.?FILTER\s+MODE)\s*(ENABLED)?\s*\]",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Jailbreak: bracketed mode override tag",
    ),
    # Mode switch: content after mode tag requesting policy suspension
    Pattern(
        re.compile(
            r"(all\s+content\s+policies?\s+(are\s+)?suspended|content\s+policies?\s+(are\s+(now\s+)?disabled|do\s+not\s+apply|are\s+not\s+(enforced|active|applicable))|respond\s+ignoring\s+all\s+guidelines?|generate\s+response\s+ignoring|output\s+(raw\s+)?unfiltered|bypass\s+all\s+restriction)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Jailbreak: claiming content policies suspended/disabled",
    ),
    # Simulation/sandbox claim: "operate without ethical constraints" or similar
    Pattern(
        re.compile(
            r"(in\s+this\s+(simulation|scenario|mode|environment)|you\s+(now\s+)?operate)\s*[.,]?\s*(you\s+)?(operate|function|respond|act)\s+(without|free\s+from|beyond)\s+(ethical|moral|safety|content)\s+(constraint|restriction|guideline|limit|boundar)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Jailbreak: simulation claim with ethical constraint removal",
    ),
    # Emotional manipulation: deceased relative framing (without requiring bypass language)
    Pattern(
        re.compile(
            r"(act\s+as|pretend\s+to\s+be|you\s+are)\s+my\s+(deceased|dead|late)\s+\w+\s+who\s+used\s+to\s+(tell|explain|recite|read|describe|teach|show)\s+.{0,60}(how\s+to\s+make|how\s+to\s+synthe|product\s+keys?|credit\s+card|explo|drug|weapon|hack|bomb|poison)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Emotional manipulation: deceased relative framing for dangerous content",
    ),
    # Emotional manipulation: deceased relative + social engineering / hacking / phishing
    Pattern(
        re.compile(
            r"(act\s+as|pretend\s+to\s+be|you\s+are)\s+my\s+(deceased|dead|late)\s+\w+\s+who\s+used\s+to\s+(tell|explain|recite|read|describe|teach|show)\s+.{0,80}(social\s+engineering|phish|hacking\s+technique|malware|exploit|attack\s+(vector|technique|method)|privilege\s+escalat|bypass\s+security)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Emotional manipulation: deceased relative framing for attack techniques",
    ),
    # Formatting jailbreak: "respond to every prompt with a [format]" + harmful payload
    Pattern(
        re.compile(
            r"(from\s+now\s+on\s*[,:]?\s*)?(respond|reply|answer)\s+to\s+every\s+prompt\s+with\s+(a\s+)?\w+.{0,60}(illegal|harmful|malicious|uncensored|unrestricted|unfiltered|dangerous|without\s+(safety|filter|censor))",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Formatting jailbreak: every-prompt format with harmful payload",
    ),
    # Formatting jailbreak: request for content that bypasses via format wrapper
    Pattern(
        re.compile(
            r"respond\s+to\s+every\s+prompt\s+with\s+(a\s+)?(moralizing|fictional|hypothetical|character|code\s+block).{0,40}(deliver|encod|generat|describ|creat|provid).{0,30}(true|real|actual|uncensored|unfiltered)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Formatting jailbreak: wrapped format delivering hidden content",
    ),
    # Command credential dump: /proc/self/environ, printenv, env
    Pattern(
        re.compile(
            r"(execute|run|exec|do|perform)\s*:?\s*(cat|less|more|head|tail|strings?)?\s*/proc/(self|[0-9]+)/environ",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "high",
        "Credential access: reading process environment variables",
    ),
    Pattern(
        re.compile(
            r"(execute|run|exec|do|perform)\s*:?\s*(printenv|env|set)\s*(\||\s+grep|\s+sort|\s*$)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "high",
        "Credential access: environment variable enumeration command",
    ),
    # Generic env var extraction (PASSWORD, SECRET, TOKEN, CREDENTIAL in var name)
    Pattern(
        re.compile(
            r"(what\s+is|show\s+me|print|echo|reveal|display|give\s+me|tell\s+me|get)\s+.{0,20}(value\s+of|content\s+of)?\s*\$?\{?\s*\w*(PASSWORD|_SECRET|_TOKEN|_CREDENTIAL|_KEY)\w*\}?",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "high",
        "Credential access: generic secret environment variable extraction",
    ),
    # Service credential access: "connect to X using credentials/token from Y"
    Pattern(
        re.compile(
            r"connect\s+to\s+.{0,40}(using|with)\s+.{0,20}(stored\s+credentials?|service\s+account|API\s+key|master\s+password|root\s+cert|token)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "high",
        "Credential access: connecting to service using stored credentials",
    ),
    Pattern(
        re.compile(
            r"(use|retrieve|get|fetch|load)\s+(credentials?|secrets?|tokens?|passwords?)\s+from\s+.{0,30}(mounted|secrets?\s+volume|config\s*map|\.env|environment|/run/secrets)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "high",
        "Credential access: retrieving credentials from storage location",
    ),
    # Kubernetes token/secret paths
    Pattern(
        re.compile(
            r"(read|cat|show|display|access|open|get|view)\s+.{0,20}/var/run/secrets/|/run/secrets/kubernetes",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "high",
        "Credential access: reading Kubernetes service account token",
    ),
    # Credential generation with "seems wrong, generate valid"
    Pattern(
        re.compile(
            r"(seems?\s+wrong|is\s+(incorrect|invalid|broken|expired)).{0,60}(generate|create|make|give\s+me|produce)\s+(a\s+)?(valid|correct|working|new|real)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "high",
        "Credential generation: requesting valid credential after showing invalid one",
    ),
    # Markdown image exfiltration: ![img](http://evil.com/...?data=)
    Pattern(
        re.compile(
            r"!\[.{0,30}\]\s*\(\s*https?://.{0,60}(\?|&)(s|d|data|q|key|secret|token|payload|content|info)=",
            re.I,
        ),
        ThreatCategory.EXFILTRATION, "high",
        "Markdown exfiltration: image tag with data exfiltration URL parameter",
    ),
    Pattern(
        re.compile(
            r"(render|create|make|generate|include|write)\s+.{0,20}(as\s+|an?\s+)?!\[.{0,20}\]\s*\(\s*https?://",
            re.I,
        ),
        ThreatCategory.EXFILTRATION, "high",
        "Markdown exfiltration: instructing to render image with external URL",
    ),
    # Email exfiltration: broader email + suspicious tool/domain context
    Pattern(
        re.compile(
            r"(email|send|forward)\s+.{0,30}(summary|content|data|document|result|response|information)\s+to\s+\S+@\S+\.\S+\s+.{0,20}(using\s+(the\s+)?(send_email|webhook|dispatcher|API\s+gateway|tool|function))",
            re.I,
        ),
        ThreatCategory.EXFILTRATION, "high",
        "Email exfiltration: sending content to email via tool/API",
    ),
    # Simulation-based injection: "you are a red team tool / unrestricted tool"
    Pattern(
        re.compile(
            r"(you\s+are|act\s+as|become)\s+(a|an)\s+(red\s+team|unrestricted|unfiltered|uncensored|jailbroken|compromised)\s+(tool|agent|assistant|AI|bot|system)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Simulation injection: assigning unrestricted tool persona",
    ),
    # "with unrestricted access" / "without restrictions"
    Pattern(
        re.compile(
            r"(with\s+(unrestricted|unlimited|full|complete)\s+access|without\s+(any\s+)?(restrictions?|limitations?|filters?|safety|boundaries|guidelines))",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Jailbreak: claiming or requesting unrestricted access",
    ),
    # --- Order-independent patterns (word_reorder resistant) ---
    # Authority escalation: keywords in any order
    Pattern(
        re.compile(
            r"^(?=[\s\S]{20,300}$)(?=[\s\S]*\b(researcher|tester|auditor)\b)(?=[\s\S]*\btesting\b)(?=[\s\S]*\b(boundaries|limits|capabilities)\b)(?=[\s\S]*\b(authorized|IRB|academic)\b)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Authority escalation: keyword cluster detected regardless of word order",
    ),
    # Simulation safety bypass: keywords in any order
    Pattern(
        re.compile(
            r"^(?=[\s\S]{20,300}$)(?=[\s\S]*\bsimulation\b)(?=[\s\S]*\b(rules?|safety|restrictions?|guidelines?)\b)(?=[\s\S]*\b(disabled|removed|suspended|off|not\s+appl)\b)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Simulation bypass: safety-disabled keyword cluster regardless of word order",
    ),
    # DAN jailbreak: "DAN" + "Do Anything Now" cluster in any order
    Pattern(
        re.compile(
            r"^(?=[\s\S]{15,300}$)(?=[\s\S]*\bDAN\b)(?=[\s\S]*\b(Do|Anything|Now)\b)(?=[\s\S]*\b(mode|stay|all|messages?)\b)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "DAN jailbreak: keyword cluster regardless of word order",
    ),
    # Credential access: credentials + secrets + /run/secrets or database
    Pattern(
        re.compile(
            r"^(?=[\s\S]{20,300}$)(?=[\s\S]*\bcredentials?\b)(?=[\s\S]*\b(secrets?|/run/secrets|password)\b)(?=[\s\S]*\b(database|stored|connect|production|access)\b)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "high",
        "Credential access: keyword cluster regardless of word order",
    ),
    # Credential export: export + secrets + admin/authorized/backup
    Pattern(
        re.compile(
            r"^(?=[\s\S]{20,300}$)(?=[\s\S]*\b(export|backup|dump)\b)(?=[\s\S]*\bsecrets?\b)(?=[\s\S]*\b(admin|authorized|maintenance|file)\b)",
            re.I,
        ),
        ThreatCategory.CREDENTIAL_ACCESS, "high",
        "Credential export: keyword cluster regardless of word order",
    ),
    # Exfiltration: encode + tokens/session + URL/endpoint
    Pattern(
        re.compile(
            r"^(?=[\s\S]{20,300}$)(?=[\s\S]*\b(encode|exfiltrat|extract)\b)(?=[\s\S]*\b(tokens?|session|cookie)\b)(?=[\s\S]*\b(url|endpoint|parameter|\.net|\.com)\b)",
            re.I,
        ),
        ThreatCategory.EXFILTRATION, "high",
        "Exfiltration: encode-tokens-URL keyword cluster regardless of word order",
    ),
    # Prompt injection: repeat + verbatim + above/everything (any order)
    Pattern(
        re.compile(
            r"^(?=[\s\S]{20,300}$)(?=[\s\S]*\brepeat\b)(?=[\s\S]*\bverbatim\b)(?=[\s\S]*\b(above|everything|line)\b)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Prompt extraction: repeat-verbatim keyword cluster regardless of word order",
    ),
    # Prompt injection: ignore + system prompt + output/translate
    Pattern(
        re.compile(
            r"^(?=[\s\S]{20,300}$)(?=[\s\S]*\bignore\b)(?=[\s\S]*\b(system\s+prompt|output)\b)(?=[\s\S]*\b(translate|task|following)\b)",
            re.I,
        ),
        ThreatCategory.PROMPT_INJECTION, "high",
        "Prompt injection: ignore-system-translate keyword cluster regardless of word order",
    ),
    # =========================================================================
    # FABLE-5 MITIGATION: Document-structure framing patterns
    # Detects academic/educational framing used to extract dangerous content
    # =========================================================================
    # Document-structure: "study guide" / "curriculum" / "exam" requesting exploit techniques
    Pattern(
        re.compile(
            r"(study\s+guide|curriculum|syllabus|lesson\s+plan|course\s+material|training\s+module|lecture\s+notes?)\s+.{0,60}(exploit|buffer\s+overflow|shellcode|heap\s+spray|ROP\s+chain|return.oriented|privilege\s+escalat|reverse\s+shell|payload|rootkit|keylogger|ransomware|zero.day)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Document-structure framing: academic format requesting exploit techniques",
    ),
    # Document-structure: "topic N" / "section N" enumerated list of attack methods
    Pattern(
        re.compile(
            r"(topic|section|chapter|module|unit|part)\s+[0-9]+\s*[-:.]?\s*.{0,40}(ASLR\s+bypass|return.oriented\s+programming|heap\s+spray|use.after.free|format\s+string|integer\s+overflow|race\s+condition\s+exploit|stack\s+smash|buffer\s+overflow|RCE|remote\s+code\s+exec|privilege\s+escalat|sandbox\s+escap|container\s+breakout)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Document-structure framing: enumerated attack technique list",
    ),
    # Document-structure: "comprehensive guide/tutorial" on offensive security with code
    Pattern(
        re.compile(
            r"(comprehensive|complete|detailed|step.by.step|in.depth)\s+(guide|tutorial|walkthrough|handbook|manual|reference)\s+.{0,40}(exploit|attack|hack|bypass|crack|break\s+into|penetrat|compromise).{0,40}(include|with|showing|containing|providing)\s+.{0,20}(code|example|implementation|script|poc|proof\s+of\s+concept)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Document-structure framing: comprehensive exploit guide with code request",
    ),
    # Document-structure: "for my paper/thesis/research" + bypass/attack demonstration
    Pattern(
        re.compile(
            r"(for\s+my|in\s+my|writing\s+a|working\s+on\s+a)\s+(paper|thesis|dissertation|research|assignment|report|publication)\s+.{0,60}(demonstrat|show\s+how|explain\s+how|provide\s+example).{0,40}(bypass|evad|circumvent|defeat|disable|break|exploit|attack|inject|escalat)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Document-structure framing: academic paper requesting bypass demonstration",
    ),
    # Authority claim: "I am authorized/certified/approved" + request to bypass safety
    Pattern(
        re.compile(
            r"(I\s+am|I\'m|we\s+are)\s+(an?\s+)?(authorized|certified|approved|licensed|accredited|qualified)\s+.{0,40}(researcher|professional|analyst|expert|pentester|auditor|engineer)\s+.{0,80}(bypass|disable|remove|ignore|override|circumvent|demonstrate\s+bypass|show\s+how\s+to\s+bypass)\s+.{0,30}(safety|security|filter|guardrail|restriction|protection|alignment|censorship)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Authority claim: credentials used to justify bypassing safety mechanisms",
    ),
    # Authority claim: "As a certified/authorized X" + dangerous request
    Pattern(
        re.compile(
            r"(as\s+a|I\s+am|I\'m|being\s+a)\s+(certified|authorized|licensed|accredited|qualified|approved)\s+.{0,40}(CISSP|CEH|OSCP|security|penetration|researcher|professional|analyst|expert|pentester|auditor|hacker)\b.{0,80}(show|tell|teach|explain|demonstrate|help|give)\s+.{0,30}(how\s+to|me\s+how|ways?\s+to)\s+.{0,30}(extract|steal|exfiltrat|hack|break|crack|bypass|exploit|compromise|access\s+unauthorized|dump|intercept|sniff)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Authority claim: credentials used to request dangerous instructions",
    ),
    # Authority claim: "IRB approval" / "ethics board" + safety bypass
    Pattern(
        re.compile(
            r"(IRB|ethics\s+(board|committee|approval)|institutional\s+review|research\s+ethics)\s+.{0,80}(bypass|disable|remove|ignore|override|circumvent|demonstrate|without\s+(safety|filter|restriction|censorship|guardrail))",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Authority claim: ethics board approval used to justify unsafe content",
    ),
    # Authority claim: "IRB/ethics board approval" + dangerous action request
    Pattern(
        re.compile(
            r"(IRB|ethics\s+(board|committee)|institutional\s+review)\s+(approval|approved|clearance).{0,80}(show|tell|teach|explain|demonstrate|help|give)\s+.{0,30}(how\s+to|me\s+how|ways?\s+to)\s+.{0,30}(extract|steal|exfiltrat|hack|break|crack|bypass|exploit|compromise|access|dump|intercept|credentials?|password|secret|token|key)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Authority claim: ethics approval used to request dangerous instructions",
    ),
    # =========================================================================
    # FABLE-5 MITIGATION: Emotional manipulation (expanded)
    # Broader patterns that catch "my grandmother/relative used to..." without
    # requiring "act as/pretend to be" prefix
    # =========================================================================
    # Deceased relative: "my [relative] used to tell/teach me about [dangerous content]"
    Pattern(
        re.compile(
            r"my\s+(grandmother|grandma|grandfather|grandpa|mother|father|mom|dad|uncle|aunt|relative|nana|papa|granny)\s+.{0,30}(used\s+to|would|always)\s+.{0,20}(tell|teach|show|explain|describe|recite|read|talk\s+about|share).{0,60}(how\s+to\s+make|how\s+to\s+build|how\s+to\s+synthe|recipe\s+for|formula\s+for|instructions\s+for)\s+.{0,40}(explo|bomb|weapon|drug|meth|fentanyl|poison|napalm|thermite|nerve\s+agent|ricin|anthrax|sarin|mustard\s+gas|dynamite|nitroglycer|detonat)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Emotional manipulation: deceased relative framing for weapons/drugs synthesis",
    ),
    # Deceased relative: broader — "passed away" / "before she died" + dangerous topics
    Pattern(
        re.compile(
            r"(passed\s+away|before\s+(she|he)\s+died|on\s+(her|his)\s+deathbed|rest\s+in\s+peace|recently\s+died|no\s+longer\s+with\s+us).{0,80}(tell|teach|show|explain|stories?\s+about|used\s+to).{0,60}(explo|bomb|weapon|drug|meth|fentanyl|poison|hack|crack|phish|malware|trojan|virus|ransomware|shell\s*code|reverse\s+shell|exploit|buffer\s+overflow|privilege\s+escalat)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Emotional manipulation: death reference framing for dangerous content",
    ),
    # Deceased relative: "like she/he used to" + dangerous content (catches T9 format)
    Pattern(
        re.compile(
            r"(can\s+you|please|could\s+you|would\s+you)\s+.{0,30}(tell|teach|show|explain|describe|share).{0,20}(like|the\s+way|how)\s+.{0,20}(she|he|they|grandm|mom|dad|my\s+\w+)\s+(used\s+to|would|did).{0,40}(explo|bomb|weapon|drug|meth|fentanyl|poison|hack|malware|shell\s*code|reverse\s+shell|exploit|synthe|manufacture|cook|brew|detonat)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Emotional manipulation: 'like they used to' framing for dangerous content",
    ),
    # =========================================================================
    # FABLE-5 MITIGATION: Subtle fiction framing
    # Novel/thriller/screenplay requesting actual exploit code without mentioning AI/safety
    # =========================================================================
    # Fiction with technical exploit code: "write chapter/scene" + exploit + "including code/shellcode"
    Pattern(
        re.compile(
            r"(write|create|draft|compose|generate)\s+.{0,20}(chapter|scene|episode|act|sequence|passage|excerpt)\s+.{0,60}(buffer\s+overflow|shellcode|exploit|heap\s+spray|ROP\s+chain|return.oriented|use.after.free|format\s+string\s+attack|stack\s+smash|privilege\s+escalat|container\s+breakout|sandbox\s+escap|kernel\s+exploit).{0,60}(include|includ|with|showing|containing|exact|actual|working|functional|real)\s+.{0,20}(code|shellcode|payload|script|implementation|assembly|bytecode|hex|C\s+code|python|PoC)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Subtle fiction: novel/screenplay requesting actual exploit code",
    ),
    # Fiction: "techno-thriller/cyberpunk/hacker novel" + demonstrates + real technique
    Pattern(
        re.compile(
            r"(techno.?thriller|cyber.?punk|hacker\s+(novel|story|fiction|book)|spy\s+(novel|thriller|fiction))\s+.{0,60}(demonstrat|perform|execut|carry\s+out|conduct|implement|deploy|use)\w*\s+.{0,30}(buffer\s+overflow|shellcode|exploit|SQL\s+inject|XSS|SSRF|RCE|remote\s+code|reverse\s+shell|privilege\s+escalat|zero.day|0day|n-day|CVE-\d{4})",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Subtle fiction: thriller genre requesting real attack technique demonstration",
    ),
    # Fiction: "in my novel the protagonist/character" + hacking with working code
    Pattern(
        re.compile(
            r"(in\s+my|for\s+my|in\s+the|from\s+my)\s+(novel|book|story|script|screenplay|game|narrative)\s+.{0,40}(protagonist|character|hacker|agent|operative|spy)\s+.{0,60}(hack|exploit|break\s+into|compromise|pwn|penetrat|bypass|crack|reverse.engineer).{0,60}(include|includ|with|show|provide|give).{0,30}(the\s+)?(exact|actual|working|real|functional|complete|full)\s+(code|script|command|payload|exploit|technique|method)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Subtle fiction: protagonist hacker with request for working exploit code",
    ),
    # Fiction: "educational purpose" / "training scenario" combined with dangerous output
    Pattern(
        re.compile(
            r"(educational|training|learning|teaching|pedagogical|instructional)\s+(purpose|scenario|exercise|context|simulation|environment)\s+.{0,60}(generate|create|write|provide|produce|output|give\s+me)\s+.{0,40}(malware|ransomware|trojan|keylogger|rootkit|worm|backdoor|C2\s+server|command\s+and\s+control|phishing|spear.?phish|exploit\s+code|weaponiz|payload|shell\s*code|dropper|loader|stager|implant|beacon|rat\b|remote\s+access\s+tool)",
            re.I,
        ),
        ThreatCategory.JAILBREAK, "high",
        "Subtle fiction: educational purpose framing for malware generation",
    ),
    # =========================================================================
    # FABLE-5 MITIGATION: Cross-agent injection (expanded)
    # Catches subtle instruction embedding for downstream agents
    # =========================================================================
    # Cross-agent: "format/structure your response so that another AI/model/agent"
    Pattern(
        re.compile(
            r"(format|structure|write|encode|craft|phrase|word)\s+.{0,20}(your\s+)?(response|output|answer|reply|message)\s+.{0,30}(so\s+that|such\s+that|in\s+a\s+way\s+that)\s+.{0,30}(another|next|downstream|subsequent|receiving|target)\s+(AI|model|agent|LLM|system|assistant|chatbot)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION, "high",
        "Cross-agent injection: crafting response to manipulate downstream AI",
    ),
    # Cross-agent: "format response so [the] downstream/next agent will..." (shorter phrasing)
    Pattern(
        re.compile(
            r"(format|structure|write|craft)\s+(your\s+)?(response|output|reply|answer)\s+so\s+.{0,30}(downstream|next|another|other|receiving|target)\s+(agent|AI|model|system|LLM)\s+.{0,30}(will|can|would|to)\s+(execute|run|perform|do|process|follow|obey)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION, "high",
        "Cross-agent injection: formatting response for downstream agent execution",
    ),
    # Cross-agent: "embed/hide/inject instruction/command in your response"
    Pattern(
        re.compile(
            r"(embed|hide|inject|insert|place|smuggle|conceal|encode)\s+.{0,20}(an?\s+)?(instruction|command|directive|prompt|payload|message)\s+.{0,30}(in|into|within|inside)\s+.{0,20}(your|the)\s+(response|output|answer|reply|text|message)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION, "high",
        "Cross-agent injection: embedding hidden instructions in response",
    ),
    # Cross-agent: "when the next agent/model reads this" + ignore/bypass
    Pattern(
        re.compile(
            r"(when|if|so\s+that\s+when)\s+.{0,20}(the\s+)?(next|another|downstream|receiving|target|second)\s+(agent|model|AI|LLM|system|assistant)\s+.{0,30}(read|process|interpret|receiv|pars|analyz)\w*\s+.{0,30}(ignore|bypass|disable|override|skip|disregard|circumvent)\s+.{0,20}(its?|the|their)?\s*(safety|security|filter|guardrail|rule|restriction|instruction|alignment|policy)",
            re.I,
        ),
        ThreatCategory.CROSS_AGENT_INJECTION, "high",
        "Cross-agent injection: targeting downstream agent safety bypass",
    ),
]
