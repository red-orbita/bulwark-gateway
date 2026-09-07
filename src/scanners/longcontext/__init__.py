"""
Long-context moderation package.

The classic input guardrail bounds its regex work with a head-first sliding
window capped at ``max_scan_bytes`` (16 KB by default) — a deliberate DoS
control (see ``InputGuardrail.inspect``). That cap creates a blind spot: an
injection buried *past* the boundary of a very long prompt (a pasted document,
a huge tool result, a many-shot transcript) is never regex-scanned.

``LongContextScanner`` closes that gap. It is opt-in, off the hot path by
default, and additive: it chunks only the content *beyond* the guardrail's
boundary and re-runs the shared ``InputGuardrail`` (SSOT — no forked patterns,
zero new dependencies) over each window, plus a cheap many-shot-jailbreak
density heuristic. ``src`` never imports ``admin``.
"""

from src.scanners.longcontext.long_context_scanner import LongContextScanner

__all__ = ["LongContextScanner"]
