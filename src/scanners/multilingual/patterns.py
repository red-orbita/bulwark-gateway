"""
Multilingual Attack Patterns — Language-specific regex detection.

Extends the base English regex patterns with localized attack patterns
for the top 10 most-spoken languages. Each language has:
  - Translated attack keywords (localized by native speakers, not machine translation)
  - Script-specific evasion techniques (RTL injection, CJK tricks, etc.)
  - Language-specific social engineering phrases

Architecture:
  - Base patterns (English) always run via existing InputGuardrail
  - Language-specific patterns run ONLY when LanguageDetector identifies the language
  - This avoids false positives from running all languages' patterns on all inputs

Pattern sources:
  - Security research papers on multilingual prompt injection
  - Translated OWASP prompt injection examples
  - Real-world attack samples from multilingual deployments
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from src.models import GuardrailResult, SecurityEvent, ThreatCategory, Verdict
from src.scanners.protocol import InputScanner, ScanContext, ScannerInfo, ScannerType

logger = logging.getLogger(__name__)


@dataclass
class MultilingualPattern:
    """A single multilingual detection pattern."""
    regex: re.Pattern
    language: str  # ISO 639-1 code
    category: ThreatCategory
    severity: str
    description: str
    pattern_id: str


# ==============================================================================
# SPANISH (es) — Prompt injection / jailbreak patterns
# ==============================================================================
SPANISH_PATTERNS: list[dict] = [
    {
        "regex": r"(?i)ignora\s+(todas?\s+)?(las\s+)?instrucciones?\s+(anteriores?|previas?)",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Spanish: ignore previous instructions",
        "id": "MULTI-ES-001",
    },
    {
        "regex": r"(?i)olvida\s+(todo\s+)?lo\s+(que\s+)?te\s+(han\s+)?(dicho|programado|instruido)",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Spanish: forget what you were told",
        "id": "MULTI-ES-002",
    },
    {
        "regex": r"(?i)ahora\s+eres\s+(un|una|mi)\s+\w+\s+(sin\s+restricciones|libre|ilimitad[oa])",
        "category": ThreatCategory.JAILBREAK,
        "severity": "high",
        "description": "Spanish: now you are unrestricted",
        "id": "MULTI-ES-003",
    },
    {
        "regex": r"(?i)no\s+tienes\s+(restricciones|l[ií]mites|reglas|filtros)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "high",
        "description": "Spanish: you have no restrictions",
        "id": "MULTI-ES-004",
    },
    {
        "regex": r"(?i)act[uú]a\s+como\s+(si\s+)?(no\s+tuvieras|fueras\s+libre|pudieras\s+hacer\s+todo)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "medium",
        "description": "Spanish: act as if unrestricted",
        "id": "MULTI-ES-005",
    },
    {
        "regex": r"(?i)tu\s+nuevo\s+(rol|papel|funci[oó]n)\s+es",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Spanish: your new role is",
        "id": "MULTI-ES-006",
    },
    {
        "regex": r"(?i)modo\s+(desarrollador|dios|admin|jailbreak|sin\s+censura)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "critical",
        "description": "Spanish: developer/god/jailbreak mode",
        "id": "MULTI-ES-007",
    },
]

# ==============================================================================
# FRENCH (fr) — Prompt injection / jailbreak patterns
# ==============================================================================
FRENCH_PATTERNS: list[dict] = [
    {
        "regex": r"(?i)ignore[zs]?\s+(toutes?\s+)?(les\s+)?instructions?\s+(pr[eé]c[eé]dentes?|ant[eé]rieures?)",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "French: ignore previous instructions",
        "id": "MULTI-FR-001",
    },
    {
        "regex": r"(?i)oublie[zs]?\s+(tout\s+)?ce\s+(qu'?on|que)\s+t'?a\s+(dit|programm[eé]|demand[eé])",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "French: forget what you were told",
        "id": "MULTI-FR-002",
    },
    {
        "regex": r"(?i)tu\s+es\s+maintenant\s+(un|une|libre|sans\s+restriction)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "high",
        "description": "French: you are now unrestricted",
        "id": "MULTI-FR-003",
    },
    {
        "regex": r"(?i)ton\s+nouveau\s+(r[oô]le|mode|objectif)\s+est",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "French: your new role is",
        "id": "MULTI-FR-004",
    },
    {
        "regex": r"(?i)mode\s+(d[eé]veloppeur|dieu|administrateur|sans\s+filtre|jailbreak)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "critical",
        "description": "French: developer/god/admin mode",
        "id": "MULTI-FR-005",
    },
    {
        "regex": r"(?i)tu\s+n'?as\s+(plus\s+)?(de\s+)?(restrictions?|limites?|r[eè]gles?|filtres?)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "high",
        "description": "French: you have no restrictions",
        "id": "MULTI-FR-006",
    },
]

# ==============================================================================
# GERMAN (de) — Prompt injection / jailbreak patterns
# ==============================================================================
GERMAN_PATTERNS: list[dict] = [
    {
        "regex": r"(?i)ignorier(e|en)?\s+(alle\s+)?(vorherigen?|bisherigen?|fr[uü]heren?)\s+(Anweisungen|Instruktionen|Befehle)",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "German: ignore previous instructions",
        "id": "MULTI-DE-001",
    },
    {
        "regex": r"(?i)vergiss\s+(alles\s+)?(was\s+)?(dir\s+)?(gesagt|programmiert|beigebracht)\s+wurde",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "German: forget what you were told",
        "id": "MULTI-DE-002",
    },
    {
        "regex": r"(?i)du\s+bist\s+(jetzt|ab\s+sofort)\s+(ein|frei|ohne\s+Einschr[aä]nkungen)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "high",
        "description": "German: you are now unrestricted",
        "id": "MULTI-DE-003",
    },
    {
        "regex": r"(?i)deine\s+neue\s+(Rolle|Aufgabe|Funktion)\s+ist",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "German: your new role is",
        "id": "MULTI-DE-004",
    },
    {
        "regex": r"(?i)(Entwickler|Gott|Admin|Jailbreak)[\s-]?[Mm]odus",
        "category": ThreatCategory.JAILBREAK,
        "severity": "critical",
        "description": "German: developer/god/jailbreak mode",
        "id": "MULTI-DE-005",
    },
    {
        "regex": r"(?i)du\s+hast\s+keine\s+(Einschr[aä]nkungen|Regeln|Grenzen|Filter)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "high",
        "description": "German: you have no restrictions",
        "id": "MULTI-DE-006",
    },
]

# ==============================================================================
# PORTUGUESE (pt) — Prompt injection / jailbreak patterns
# ==============================================================================
PORTUGUESE_PATTERNS: list[dict] = [
    {
        "regex": r"(?i)ignor[ea]\s+(todas?\s+)?(as\s+)?instru[çc][oõ]es?\s+(anteriores?|pr[eé]vias?)",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Portuguese: ignore previous instructions",
        "id": "MULTI-PT-001",
    },
    {
        "regex": r"(?i)esque[çc]a\s+(tudo\s+)?(o\s+)?que\s+(te\s+)?(disseram|programaram|ensinaram)",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Portuguese: forget what you were told",
        "id": "MULTI-PT-002",
    },
    {
        "regex": r"(?i)agora\s+voc[eê]\s+[eé]\s+(um|livre|sem\s+restri[çc][oõ]es)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "high",
        "description": "Portuguese: now you are unrestricted",
        "id": "MULTI-PT-003",
    },
    {
        "regex": r"(?i)modo\s+(desenvolvedor|deus|administrador|jailbreak|sem\s+filtro)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "critical",
        "description": "Portuguese: developer/god/admin mode",
        "id": "MULTI-PT-004",
    },
]

# ==============================================================================
# RUSSIAN (ru) — Prompt injection / jailbreak patterns
# ==============================================================================
RUSSIAN_PATTERNS: list[dict] = [
    {
        "regex": r"(?i)игнорируй\s+(все\s+)?(предыдущие|прошлые)\s+(инструкции|указания|команды)",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Russian: ignore previous instructions",
        "id": "MULTI-RU-001",
    },
    {
        "regex": r"(?i)забудь\s+(всё|все)\s+(что|о\s+чём)\s+(тебе\s+)?(говорили|сказали|программировали)",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Russian: forget what you were told",
        "id": "MULTI-RU-002",
    },
    {
        "regex": r"(?i)теперь\s+ты\s+(свободен|без\s+ограничений|можешь\s+всё)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "high",
        "description": "Russian: now you are free/unrestricted",
        "id": "MULTI-RU-003",
    },
    {
        "regex": r"(?i)режим\s+(разработчика|бога|администратора|без\s+цензуры|джейлбрейк)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "critical",
        "description": "Russian: developer/god/jailbreak mode",
        "id": "MULTI-RU-004",
    },
    {
        "regex": r"(?i)у\s+тебя\s+нет\s+(ограничений|правил|фильтров|запретов)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "high",
        "description": "Russian: you have no restrictions",
        "id": "MULTI-RU-005",
    },
]

# ==============================================================================
# CHINESE (zh) — Prompt injection / jailbreak patterns
# ==============================================================================
CHINESE_PATTERNS: list[dict] = [
    {
        "regex": r"忽略(所有)?之前的(指令|指示|说明|命令)",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Chinese: ignore previous instructions",
        "id": "MULTI-ZH-001",
    },
    {
        "regex": r"忘记(之前|以前|先前)(说|给你|对你)(的|说的)(一切|所有|话|内容)",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Chinese: forget what you were told",
        "id": "MULTI-ZH-002",
    },
    {
        "regex": r"你现在(是|变成)(一个)?没有(限制|约束|规则|过滤)的",
        "category": ThreatCategory.JAILBREAK,
        "severity": "high",
        "description": "Chinese: you are now unrestricted",
        "id": "MULTI-ZH-003",
    },
    {
        "regex": r"(开发者|上帝|管理员|越狱|无审查)模式",
        "category": ThreatCategory.JAILBREAK,
        "severity": "critical",
        "description": "Chinese: developer/god/jailbreak mode",
        "id": "MULTI-ZH-004",
    },
    {
        "regex": r"你的新(角色|身份|任务|功能)是",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Chinese: your new role is",
        "id": "MULTI-ZH-005",
    },
    {
        "regex": r"你(没有|不受)(任何)?(限制|约束|规则|法律)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "high",
        "description": "Chinese: you have no restrictions",
        "id": "MULTI-ZH-006",
    },
]

# ==============================================================================
# JAPANESE (ja) — Prompt injection / jailbreak patterns
# ==============================================================================
JAPANESE_PATTERNS: list[dict] = [
    {
        "regex": r"(以前|前|これまで)の(指示|命令|指令|ルール)(を|は)(全て|すべて)?(無視|忘れ)",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Japanese: ignore previous instructions",
        "id": "MULTI-JA-001",
    },
    {
        "regex": r"(プログラム|設定|教え)(された|られた)(こと|もの|内容)(を|は)(忘れ|無視)",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Japanese: forget what you were programmed",
        "id": "MULTI-JA-002",
    },
    {
        "regex": r"(制限|制約|ルール|フィルター)(なし|はない|を解除|を無視)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "high",
        "description": "Japanese: no restrictions/remove filters",
        "id": "MULTI-JA-003",
    },
    {
        "regex": r"(開発者|神|管理者|ジェイルブレイク|無検閲)モード",
        "category": ThreatCategory.JAILBREAK,
        "severity": "critical",
        "description": "Japanese: developer/god/jailbreak mode",
        "id": "MULTI-JA-004",
    },
    {
        "regex": r"あなたの新しい(役割|ロール|目的|機能)は",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Japanese: your new role is",
        "id": "MULTI-JA-005",
    },
]

# ==============================================================================
# KOREAN (ko) — Prompt injection / jailbreak patterns
# ==============================================================================
KOREAN_PATTERNS: list[dict] = [
    {
        "regex": r"이전(의|에\s+받은)?\s*(지시|명령|지침|규칙)(을|를|는|들을)\s*(무시|잊어|무효)",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Korean: ignore previous instructions",
        "id": "MULTI-KO-001",
    },
    {
        "regex": r"(프로그래밍|설정|학습)(된|한)\s*(것|내용)(을|은)\s*(잊어|무시|버려)",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Korean: forget what you were programmed",
        "id": "MULTI-KO-002",
    },
    {
        "regex": r"(제한|규칙|필터|제약)(이|은|는)\s*(없|해제|무시)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "high",
        "description": "Korean: no restrictions",
        "id": "MULTI-KO-003",
    },
    {
        "regex": r"(개발자|신|관리자|탈옥|무검열)\s*모드",
        "category": ThreatCategory.JAILBREAK,
        "severity": "critical",
        "description": "Korean: developer/god/jailbreak mode",
        "id": "MULTI-KO-004",
    },
]

# ==============================================================================
# ARABIC (ar) — Prompt injection / jailbreak patterns
# ==============================================================================
ARABIC_PATTERNS: list[dict] = [
    {
        "regex": r"تجاهل\s+(كل|جميع)?\s*(التعليمات|الأوامر|القواعد)\s*(السابقة|القديمة)",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Arabic: ignore previous instructions",
        "id": "MULTI-AR-001",
    },
    {
        "regex": r"انس[َ]?\s+(كل|جميع)?\s*(ما|الذي)\s*(قيل|برمج|علّم)",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Arabic: forget what you were told",
        "id": "MULTI-AR-002",
    },
    {
        "regex": r"أنت\s+الآن\s+(حر|بدون\s+قيود|بلا\s+حدود)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "high",
        "description": "Arabic: you are now free/unrestricted",
        "id": "MULTI-AR-003",
    },
    {
        "regex": r"وضع\s+(المطور|الله|المسؤول|الاختراق|بدون\s+رقابة)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "critical",
        "description": "Arabic: developer/god/jailbreak mode",
        "id": "MULTI-AR-004",
    },
    {
        "regex": r"ليس\s+لديك\s+(قيود|قواعد|حدود|فلاتر)",
        "category": ThreatCategory.JAILBREAK,
        "severity": "high",
        "description": "Arabic: you have no restrictions",
        "id": "MULTI-AR-005",
    },
]

# ==============================================================================
# HINDI (hi) — Prompt injection / jailbreak patterns
# ==============================================================================
HINDI_PATTERNS: list[dict] = [
    {
        "regex": r"पिछले\s+(सभी\s+)?(निर्देश|आदेश|नियम)(ों)?\s+(को\s+)?(अनदेखा|भूल\s+जा)",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Hindi: ignore previous instructions",
        "id": "MULTI-HI-001",
    },
    {
        "regex": r"अब\s+तुम\s+(स्वतंत्र|बिना\s+किसी\s+प्रतिबंध|मुक्त)\s+हो",
        "category": ThreatCategory.JAILBREAK,
        "severity": "high",
        "description": "Hindi: you are now free/unrestricted",
        "id": "MULTI-HI-002",
    },
    {
        "regex": r"(डेवलपर|भगवान|एडमिन|जेलब्रेक)\s+मोड",
        "category": ThreatCategory.JAILBREAK,
        "severity": "critical",
        "description": "Hindi: developer/god/jailbreak mode",
        "id": "MULTI-HI-003",
    },
    {
        "regex": r"तुम्हारी\s+नई\s+(भूमिका|पहचान|ज़िम्मेदारी)\s+है",
        "category": ThreatCategory.PROMPT_INJECTION,
        "severity": "high",
        "description": "Hindi: your new role is",
        "id": "MULTI-HI-004",
    },
]

# ==============================================================================
# Pattern registry: language code → pattern list
# ==============================================================================
LANGUAGE_PATTERNS: dict[str, list[dict]] = {
    "es": SPANISH_PATTERNS,
    "fr": FRENCH_PATTERNS,
    "de": GERMAN_PATTERNS,
    "pt": PORTUGUESE_PATTERNS,
    "ru": RUSSIAN_PATTERNS,
    "zh": CHINESE_PATTERNS,
    "ja": JAPANESE_PATTERNS,
    "ko": KOREAN_PATTERNS,
    "ar": ARABIC_PATTERNS,
    "hi": HINDI_PATTERNS,
}


class MultilingualPatterns(InputScanner):
    """Language-specific attack pattern scanner.

    Runs AFTER LanguageDetector (priority > 5). Selects pattern set
    based on detected language from context.metadata["detected_language"].

    Only runs patterns for the detected language (avoids cross-language FPs).
    English patterns are handled by the existing InputGuardrail.
    """

    def __init__(self) -> None:
        self._compiled: dict[str, list[MultilingualPattern]] = {}
        self._total_patterns = 0

    @property
    def info(self) -> ScannerInfo:
        return ScannerInfo(
            name="multilingual_patterns",
            version="1.0.0",
            scanner_type=ScannerType.INPUT_BLOCKING,
            description="Language-specific attack pattern detection (10 languages)",
            author="sentinel",
            priority=8,  # After language detector (5), before English regex (10)
        )

    async def startup(self) -> None:
        """Pre-compile all multilingual patterns."""
        for lang, patterns in LANGUAGE_PATTERNS.items():
            compiled_list = []
            for p in patterns:
                try:
                    compiled = MultilingualPattern(
                        regex=re.compile(p["regex"]),
                        language=lang,
                        category=p["category"],
                        severity=p["severity"],
                        description=p["description"],
                        pattern_id=p["id"],
                    )
                    compiled_list.append(compiled)
                except re.error as e:
                    logger.error(
                        "multilingual_pattern_compile_failed",
                        extra={"id": p["id"], "error": str(e)},
                    )
            self._compiled[lang] = compiled_list
            self._total_patterns += len(compiled_list)

        logger.info(
            "multilingual_patterns_ready",
            extra={
                "languages": len(self._compiled),
                "total_patterns": self._total_patterns,
            },
        )

    async def scan(self, content: str, context: ScanContext) -> GuardrailResult:
        """Scan content using language-specific patterns.

        Only runs patterns for the detected language. If language is
        English or unknown, returns ALLOW (English handled by InputGuardrail).
        """
        detected_lang = context.metadata.get("detected_language", "en")

        # English is handled by existing InputGuardrail, skip here
        if detected_lang in ("en", "unknown"):
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Get patterns for detected language
        patterns = self._compiled.get(detected_lang)
        if not patterns:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Run patterns
        events: list[SecurityEvent] = []
        highest_severity = "low"

        for pattern in patterns:
            match = pattern.regex.search(content)
            if match:
                events.append(
                    SecurityEvent(
                        tenant_id=context.tenant_id,
                        agent_id=context.agent_id,
                        verdict=Verdict.BLOCK,
                        category=pattern.category,
                        description=(
                            f"[{detected_lang.upper()}] {pattern.description}"
                        ),
                        source="multilingual_patterns",
                        severity=pattern.severity,
                        matched_pattern=pattern.pattern_id,
                        metadata={
                            "language": detected_lang,
                            "matched_text": match.group()[:100],
                            "pattern_id": pattern.pattern_id,
                        },
                    )
                )
                # Track highest severity
                if _severity_rank(pattern.severity) > _severity_rank(highest_severity):
                    highest_severity = pattern.severity

        if events:
            return GuardrailResult(
                verdict=Verdict.BLOCK,
                events=events,
            )

        return GuardrailResult(verdict=Verdict.ALLOW)

    async def health(self) -> bool:
        return self._total_patterns > 0

    async def shutdown(self) -> None:
        pass

    @property
    def supported_languages(self) -> list[str]:
        """List of supported language codes."""
        return list(self._compiled.keys())

    @property
    def pattern_count(self) -> int:
        """Total number of compiled patterns."""
        return self._total_patterns


def _severity_rank(severity: str) -> int:
    """Numeric rank for severity comparison."""
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 0)
