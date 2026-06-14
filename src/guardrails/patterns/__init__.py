"""
Input guardrail pattern definitions.

This package contains all regex patterns used by the InputGuardrail
to detect prompt injection, jailbreaks, and malicious content.
"""

import re
from dataclasses import dataclass

from src.models import ThreatCategory


@dataclass
class Pattern:
    regex: re.Pattern
    category: ThreatCategory
    severity: str
    description: str
    pattern_id: str = ""  # Assigned at init for dynamic toggle support


from src.guardrails.patterns.injection_patterns import (  # noqa: E402
    INJECTION_PATTERNS,
    SOCIAL_ENGINEERING_PATTERNS,
    TOOL_ABUSE_PATTERNS,
)
from src.guardrails.patterns.encoding_patterns import (  # noqa: E402
    INDIRECT_INJECTION_PATTERNS,
)
from src.guardrails.patterns.evasion_patterns import (  # noqa: E402
    BYPASS_PATTERNS,
    HARDENING_PATTERNS,
)

ALL_PATTERNS: list[Pattern] = (
    INJECTION_PATTERNS
    + TOOL_ABUSE_PATTERNS
    + SOCIAL_ENGINEERING_PATTERNS
    + INDIRECT_INJECTION_PATTERNS
    + BYPASS_PATTERNS
    + HARDENING_PATTERNS
)
