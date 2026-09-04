"""Splunk/Wazuh-lite search parser for the Security Events viewer.

The events viewer exposes a single free-text search bar on top of the structured
dropdown filters. This module turns the raw query string an operator types into a
structured :class:`ParsedEventQuery` that the durable store can translate into a
SQL ``WHERE`` clause — deliberately server-side (Python, unit-testable) rather
than parsed in the browser.

Two token shapes are recognised:

* ``field:value`` — a scoped filter on a known column. Quoted values are honoured
  (``tenant:"acme corp"``). The supported fields mirror the columns exposed by the
  store: ``tenant``, ``agent``, ``category``, ``severity``, ``verdict``,
  ``request_id``, ``incident_id``, ``source``, ``pattern``, ``tool``/``tool_name``.
  A relative-time field ``last:<n><unit>`` (``30m``/``24h``/``7d``/``2w``) yields a
  ``since`` epoch lower bound.
* bare tokens — free-text *terms* matched (case-insensitively, substring) across
  every human-readable column. Multiple terms are AND-ed; each term may itself
  match any column (OR).

The parser is intentionally forgiving: an unknown ``foo:bar`` token (``foo`` not a
known field) degrades to a free-text term ``foo:bar`` rather than erroring, and a
malformed quote falls back to whitespace tokenisation. It never raises.
"""

from __future__ import annotations

import re
import shlex
import time
from dataclasses import dataclass, field
from typing import Optional

# Fields that map 1:1 onto a store filter param. ``tool`` is an alias for the
# ``tool_name`` column. ``last`` is handled separately (relative time window).
_SCALAR_FIELDS = {
    "tenant": "tenant",
    "agent": "agent",
    "category": "category",
    "severity": "severity",
    "verdict": "verdict",
    "request_id": "request_id",
    "incident_id": "incident_id",
    "source": "source",
    "pattern": "pattern",
    "tool": "tool_name",
    "tool_name": "tool_name",
}

# Relative-time units for ``last:<n><unit>`` → seconds.
_DURATION_UNITS = {
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
    "d": 86400.0,
    "w": 604800.0,
}

_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)([smhdw])$", re.IGNORECASE)


@dataclass
class ParsedEventQuery:
    """Structured result of parsing a raw search string.

    Scalar fields are ``None`` when unset; ``terms`` is the list of free-text
    fragments (possibly empty). ``since`` is an epoch-seconds lower bound derived
    from a ``last:`` token, or ``None``.
    """

    tenant: Optional[str] = None
    agent: Optional[str] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    verdict: Optional[str] = None
    request_id: Optional[str] = None
    incident_id: Optional[str] = None
    source: Optional[str] = None
    pattern: Optional[str] = None
    tool_name: Optional[str] = None
    since: Optional[float] = None
    terms: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        """True when the query carries no filter of any kind."""
        return (
            not self.terms
            and self.since is None
            and not any(
                getattr(self, attr) is not None
                for attr in _SCALAR_FIELDS.values()
            )
        )


def _tokenise(raw: str) -> list[str]:
    """Split a query string into tokens, honouring simple quoting.

    Uses ``shlex`` so ``tenant:"acme corp"`` stays one token; on any lexer error
    (e.g. an unbalanced quote) falls back to whitespace splitting so the search is
    still usable rather than rejected.
    """
    try:
        return shlex.split(raw)
    except ValueError:
        return raw.split()


def _parse_duration(value: str, *, now: float) -> Optional[float]:
    """Return an epoch-seconds lower bound for a ``last:`` value, or None."""
    m = _DURATION_RE.match(value.strip())
    if not m:
        return None
    amount = float(m.group(1))
    unit = _DURATION_UNITS[m.group(2).lower()]
    seconds = amount * unit
    if seconds <= 0:
        return None
    return now - seconds


def parse_event_query(raw: Optional[str], *, now: Optional[float] = None) -> ParsedEventQuery:
    """Parse a raw search string into a :class:`ParsedEventQuery`.

    ``now`` is injectable for deterministic tests of relative-time (``last:``)
    parsing; it defaults to the wall clock. Never raises — malformed input degrades
    to free-text terms.
    """
    parsed = ParsedEventQuery()
    if not raw or not raw.strip():
        return parsed
    now = time.time() if now is None else now

    for token in _tokenise(raw):
        if not token:
            continue
        head, sep, tail = token.partition(":")
        key = head.strip().lower()

        if sep and key == "last":
            since = _parse_duration(tail, now=now)
            if since is not None:
                # Keep the tightest (most recent) lower bound if repeated.
                parsed.since = since if parsed.since is None else max(parsed.since, since)
            else:
                # Unparseable duration → treat the whole token as free text.
                parsed.terms.append(token)
            continue

        if sep and key in _SCALAR_FIELDS and tail.strip():
            setattr(parsed, _SCALAR_FIELDS[key], tail.strip())
            continue

        # Bare word or unknown field: free-text term (keep the original token).
        parsed.terms.append(token)

    return parsed
