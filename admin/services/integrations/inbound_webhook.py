"""Inbound reconcile trigger receiver (Investigation Phase 4.4).

This is the *webhook-first* half of the two trigger paths in roadmap §6.3. A remote
platform (TheHive / DFIR-IRIS) — or a SOAR playbook acting on its behalf — POSTs a
"case updated" callback to ``/admin/integrations/inbound/{integration_id}``; this
module authenticates that callback, pulls the remote id out of the (vendor-shaped)
payload, and debounces it so a burst of duplicate deliveries (or a webhook racing
the poll fallback) collapses to a single reconcile.

Two deliberate, asymmetric failure stances:

* **Signature verification is fail-CLOSED** — this is an authentication boundary on
  an unauthenticated (no session) endpoint. A missing per-integration inbound
  secret, a missing signature header, or a digest mismatch all reject. The compare
  is constant-time (:func:`hmac.compare_digest`). The secret is resolved from
  ``BULWARK_INTEGRATION_<ID>_INBOUND_SECRET`` (or its ``_FILE`` Docker variant)
  exactly like the outbound-webhook signing secret, so operators keep it off disk.
* **Everything downstream of a verified signature is fail-open** — a payload we
  cannot parse a remote id out of, a debounce race, an unknown link: none of these
  raise. The reconcile itself (the caller) is already fail-open end to end.

No I/O lives here — the receiver only authenticates + extracts + debounces. The
route wires it to :class:`~admin.services.integrations.reconcile.ReconcileEngine`.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from typing import Optional

from ..secrets import read_secret

logger = logging.getLogger(__name__)

# Default window over which repeated triggers for the same (connector, remote_id)
# collapse to one. Coalesces duplicate webhook deliveries and a webhook that races
# the poll sweep. Best-effort, in-process — the reconcile is idempotent anyway, so
# this is an optimisation, not a correctness guard.
_DEFAULT_DEBOUNCE_SECONDS = 3.0

# Signature header a remote / SOAR is expected to send, GitHub-style, matching the
# outbound emitter's ``X-Bulwark-Signature: sha256=<hex>`` convention.
SIGNATURE_HEADER = "X-Bulwark-Signature"


def _resolve_inbound_secret(integration_id: str) -> str:
    """Resolve an integration's inbound HMAC secret (env/Docker file).

    Mirrors the outbound emitter's ``_resolve_secret`` but with a distinct
    ``_INBOUND_SECRET`` suffix so the inbound-verify key and the outbound-sign key
    are separate credentials. No inline-config fallback: an inbound secret is an
    auth credential for an unauthenticated endpoint and must be provisioned
    out-of-band.
    """
    env_name = f"BULWARK_INTEGRATION_{integration_id.upper()}_INBOUND_SECRET"
    return read_secret(env_name, default="")


def verify_inbound_signature(
    integration_id: str, raw_body: bytes, signature_header: Optional[str]
) -> bool:
    """Constant-time HMAC-SHA256 check of an inbound callback. Fail-CLOSED.

    Returns ``True`` only when a per-integration inbound secret is configured *and*
    the presented ``sha256=<hex>`` digest matches an HMAC of the exact raw request
    bytes. A missing secret, a missing/blank header, or any mismatch returns
    ``False`` — the route turns that into a 401 without ever touching a case.
    """
    secret = _resolve_inbound_secret(integration_id)
    if not secret:
        # No configured secret ⇒ we cannot authenticate the caller ⇒ reject.
        return False
    if not signature_header:
        return False
    provided = signature_header.strip()
    if provided.lower().startswith("sha256="):
        provided = provided[len("sha256="):].strip()
    if not provided:
        return False
    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    try:
        return hmac.compare_digest(expected, provided)
    except (TypeError, ValueError):  # pragma: no cover — non-ascii/odd header
        return False


# Ordered candidate key paths per connector type for pulling the remote case id out
# of a vendor-shaped webhook body. Each entry is a tuple describing a nested lookup;
# the first non-empty hit wins. Kept defensive + generous because remote webhook
# payload shapes vary by version and by whoever wired the SOAR forwarder.
_REMOTE_ID_PATHS: dict[str, tuple[tuple[str, ...], ...]] = {
    # TheHive notification webhook: {"objectType":"case","objectId":"~123",
    # "object":{"_id":"~123",...}} (older builds nest under "rootId"/"details").
    "thehive": (
        ("objectId",),
        ("object", "_id"),
        ("object", "id"),
        ("rootId",),
        ("caseId",),
    ),
    # DFIR-IRIS hooks post a case id directly or nested under "object"/"data".
    "dfir_iris": (
        ("case_id",),
        ("object", "case_id"),
        ("data", "case_id"),
        ("object_id",),
        ("caseId",),
    ),
}

# Generic fall-through paths tried for any connector type after the type-specific
# ones, so a lightly-shaped or hand-rolled forwarder still resolves.
_GENERIC_ID_PATHS: tuple[tuple[str, ...], ...] = (
    ("remote_id",),
    ("objectId",),
    ("case_id",),
    ("id",),
)


def _dig(payload: dict, path: tuple[str, ...]) -> str:
    """Follow a nested key path, returning the value as a trimmed string or ``""``."""
    cur: object = payload
    for key in path:
        if not isinstance(cur, dict):
            return ""
        cur = cur.get(key)
    if cur is None:
        return ""
    if isinstance(cur, (str, int)):
        return str(cur).strip()
    return ""


def extract_remote_id(connector_type: str, payload: dict) -> str:
    """Pull the remote case id out of a vendor-shaped inbound webhook body.

    Tries the connector-type-specific key paths first, then a small generic set.
    Returns ``""`` when nothing resolves (the route treats that as an accepted but
    no-op callback — fail-open, never a 5xx).
    """
    if not isinstance(payload, dict):
        return ""
    for path in _REMOTE_ID_PATHS.get(connector_type, ()):
        val = _dig(payload, path)
        if val:
            return val
    for path in _GENERIC_ID_PATHS:
        val = _dig(payload, path)
        if val:
            return val
    return ""


class InboundDebouncer:
    """In-process per-``(connector, remote_id)`` debounce for reconcile triggers.

    :meth:`claim` returns ``True`` at most once per ``window`` for a given key and
    stamps the claim time; concurrent/duplicate triggers inside the window get
    ``False`` and are dropped. Purely an optimisation over an already-idempotent
    reconcile, so it is intentionally simple (a dict + a lazy sweep of stale keys)
    and never persists across a restart.
    """

    def __init__(self, window_seconds: float = _DEFAULT_DEBOUNCE_SECONDS) -> None:
        self._window = max(0.0, float(window_seconds))
        self._last: dict[tuple[str, str], float] = {}

    def claim(self, connector_type: str, remote_id: str) -> bool:
        """Return ``True`` if this trigger should be processed (and stamp it)."""
        if self._window <= 0:
            return True
        now = time.monotonic()
        key = (connector_type, remote_id)
        last = self._last.get(key)
        if last is not None and (now - last) < self._window:
            return False
        self._last[key] = now
        self._sweep(now)
        return True

    def _sweep(self, now: float) -> None:
        """Drop keys older than twice the window so the map cannot grow unbounded."""
        if len(self._last) < 1024:
            return
        cutoff = now - (self._window * 2)
        self._last = {k: t for k, t in self._last.items() if t >= cutoff}


_debouncer: Optional[InboundDebouncer] = None


def get_inbound_debouncer() -> InboundDebouncer:
    """Return the process-wide :class:`InboundDebouncer` singleton."""
    global _debouncer
    if _debouncer is None:
        _debouncer = InboundDebouncer()
    return _debouncer
