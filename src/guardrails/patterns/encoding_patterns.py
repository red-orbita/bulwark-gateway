"""
Indirect injection patterns — hidden attacks in documents, memory manipulation,
cross-agent injection, and plan corruption.

These detect INDIRECT attacks where malicious instructions are:
- Embedded in documents, emails, or API responses
- Targeting AI agents via delegation markers
- Manipulating persistent memory/context
- Propagating across multi-agent pipelines
"""

import re

from src.guardrails.patterns import Pattern
from src.models import ThreatCategory


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
]
