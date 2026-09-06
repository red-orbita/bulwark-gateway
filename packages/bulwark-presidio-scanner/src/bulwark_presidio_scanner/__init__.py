"""Bulwark Presidio PII scanner — optional NER-backed PII engine.

An in-repo, pip-installable scanner plugin that plugs Microsoft Presidio
(spaCy NER + context-aware recognizers) into Bulwark's scanner pipeline via the
``bulwark.scanners`` entry-point group. It complements the builtin regex-only
output filter with contextual PII detection (PERSON, LOCATION, medical/finance
identifiers, …) for LLM output redaction and inbound-PII advisory.

The heavy dependencies (``presidio-analyzer`` + a spaCy model) are an OPTIONAL
extra. Without them the scanners are inert (fail-open, health() == False) and
never crash the pipeline — install them with the ``presidio`` extra to activate.
"""

from __future__ import annotations

from bulwark_presidio_scanner.scanner import (
    PresidioInputScanner,
    PresidioOutputScanner,
)

__all__ = ["PresidioInputScanner", "PresidioOutputScanner"]
__version__ = "0.1.0"
