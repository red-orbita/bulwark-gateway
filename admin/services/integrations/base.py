"""Connector abstraction for outbound case-management integrations (Phase 1).

Defines the small, dialect-neutral contract every connector implements plus a
reusable async HTTP mixin that wraps ``httpx`` calls with bounded retries and a
per-connector :class:`~src.telemetry.exporter.CircuitBreaker`. All of it is
**fail-open**: exhausted retries or an open circuit raise :class:`ConnectorError`,
which the route layer turns into an audited, non-blocking error response — it
never propagates into the case store or the UI request path.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from dataclasses import dataclass, field
from typing import Optional, Protocol, Self, runtime_checkable

import httpx

# admin/ is permitted to import from src/ (the reverse is forbidden). We reuse the
# telemetry circuit breaker rather than re-implement backpressure.
sys.path.insert(0, ".")
from src.telemetry.exporter import CircuitBreaker  # noqa: E402

logger = logging.getLogger(__name__)

# Bounded retry policy — outbound pushes are best-effort; we never want a slow or
# flapping SOC platform to tie up an admin worker, so both the attempt count and
# the per-request timeout are small and fixed.
_MAX_ATTEMPTS = 3
_BASE_BACKOFF_SECONDS = 0.5
_MAX_BACKOFF_SECONDS = 4.0
_DEFAULT_TIMEOUT_SECONDS = 15.0


class ConnectorError(Exception):
    """A recoverable outbound-integration failure (retried, audited, non-blocking)."""

    def __init__(self, message: str, *, status: Optional[int] = None) -> None:
        super().__init__(message)
        self.status = status


class TlpGateError(ConnectorError):
    """A push refused by a *local* data-sharing policy (not a remote failure).

    Raised when an outbound connector declines to share a case because its
    markings are too restrictive (e.g. every shareable observable is ``TLP:RED``).
    Unlike a plain :class:`ConnectorError` — which reflects a remote/transport
    problem and maps to ``502`` — this is a client-side policy decision the route
    layer surfaces as a ``400`` so operators understand nothing was sent and the
    remote was never contacted for the restricted data.
    """


@dataclass
class PushResult:
    """Outcome of pushing a case to a remote platform.

    ``remote_id`` / ``remote_url`` are persisted by the link store so a re-push
    updates the same remote record (idempotency). ``created`` distinguishes a
    first push from an update for audit/UX.
    """

    remote_id: str
    remote_url: str = ""
    etag: str = ""
    created: bool = True
    detail: str = ""


@dataclass
class ConnectorHealth:
    """Snapshot of a connector's reachability (surfaced in the health panel)."""

    ok: bool
    detail: str = ""
    checked_at: str = ""
    circuit_state: str = "closed"


# Normalized case-workflow statuses a remote state maps onto. Kept deliberately
# small and dialect-neutral: each connector translates its platform's own status
# vocabulary (TheHive stages, IRIS state ids) into one of these so the reconcile
# engine never has to know a platform's quirks. ``closed`` is the terminal marker
# the anti-reopen guard keys on.
REMOTE_STATUS_OPEN = "open"
REMOTE_STATUS_IN_PROGRESS = "in_progress"
REMOTE_STATUS_CLOSED = "closed"


@dataclass
class RemoteState:
    """A normalized snapshot of a case's *workflow* state on a remote platform.

    Returned by a connector's ``sync_status`` (Phase 4, inbound reconcile). It
    carries only the fields Bulwark is willing to reconcile inbound — workflow
    state, never detection facts — plus provenance for change detection. The
    ``raw_*`` fields preserve the platform's original vocabulary for audit/UX.
    """

    remote_id: str
    status: str = ""  # one of REMOTE_STATUS_* (normalized), "" if unknown
    raw_status: str = ""  # platform-native status string (for audit/UX)
    severity: str = ""  # normalized low|medium|high|critical, "" if unknown
    assignee: str = ""
    closed: bool = False
    last_remote_update: str = ""
    comments: list[str] = field(default_factory=list)
    detail: str = ""


@runtime_checkable
class Connector(Protocol):
    """The contract every outbound case-management connector implements."""

    @property
    def kind(self) -> str:
        """Stable connector type discriminator (e.g. ``thehive``, ``dfir_iris``)."""
        ...

    async def __aenter__(self) -> "Connector":
        """Enter pooled mode — reuse one keep-alive HTTP client for the block."""
        ...

    async def __aexit__(self, *exc: object) -> None:
        """Close the pooled HTTP client on block exit."""
        ...

    async def test_connection(self) -> ConnectorHealth:
        """Cheap reachability/auth probe. Never raises — returns a health snapshot."""
        ...

    async def push_case(
        self,
        case: dict,
        observables: list[dict],
        tasks: list[dict],
        *,
        remote_id: Optional[str] = None,
    ) -> PushResult:
        """Create (or update, when ``remote_id`` is given) the case on the remote.

        Raises :class:`ConnectorError` on an exhausted/again-failing push.
        """
        ...


@dataclass
class HttpConnectorBase:
    """Reusable async HTTP machinery shared by concrete connectors.

    Provides a single :meth:`_request` entrypoint that applies the connector's
    circuit breaker, bounded exponential backoff, and a fixed timeout. Concrete
    connectors supply the base URL, default headers and TLS preference and call
    :meth:`_request` for each REST call.
    """

    base_url: str
    verify_tls: bool = True
    timeout: float = _DEFAULT_TIMEOUT_SECONDS
    _headers: dict[str, str] = field(default_factory=dict)
    _circuit: CircuitBreaker = field(default_factory=CircuitBreaker)
    # Opt-in pooled client: set only for the duration of an ``async with connector``
    # block so a multi-request operation (a push that creates a case + N observables
    # + tasks, a Cortex enrich that submits then polls) reuses ONE keep-alive
    # connection instead of a fresh TCP/TLS handshake per call. Outside such a block
    # it stays ``None`` and each :meth:`_request` uses a short-lived client (still
    # reused across that call's retry attempts). ``init=False`` keeps it out of the
    # dataclass constructor; excluded from ``repr``/``compare`` as transient state.
    _client: Optional[httpx.AsyncClient] = field(
        default=None, init=False, repr=False, compare=False
    )

    @property
    def circuit_state(self) -> str:
        return self._circuit.state.value

    async def __aenter__(self) -> Self:
        """Enter *pooled* mode — one keep-alive client serves the whole block.

        Idempotent: a nested/re-entered ``async with`` on the same instance keeps
        the already-open client. The client is created here (inside the running
        loop) and torn down in :meth:`__aexit__`, so it never outlives the block or
        crosses event loops. Returns ``Self`` so a concrete connector stays a
        structural :class:`Connector` (whose ``__aenter__`` yields a ``Connector``)
        when used as an async context manager.
        """
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout, verify=self.verify_tls)
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close and drop the pooled client (no-op outside pooled mode)."""
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[dict] = None,
        expected: tuple[int, ...] = (200, 201),
    ) -> httpx.Response:
        """Perform an HTTP request with retries + circuit breaking.

        Returns the response on an expected status. Raises :class:`ConnectorError`
        when the circuit is open, all attempts fail, or the final status is
        unexpected.

        The HTTP client is the connector's pooled client when inside an
        ``async with`` block, else a short-lived client created once for this call
        and reused across its retry attempts (a retry re-uses the open connection
        rather than re-doing the TCP/TLS handshake). A short-lived client is always
        closed before returning; the response body is fully buffered by
        ``client.request`` before then, so callers can still read it.
        """
        if not self._circuit.can_execute():
            raise ConnectorError("circuit open — remote temporarily disabled")

        url = self.base_url.rstrip("/") + path
        last_error = ""
        last_status: Optional[int] = None

        pooled = self._client is not None
        client = self._client or httpx.AsyncClient(
            timeout=self.timeout, verify=self.verify_tls
        )
        try:
            for attempt in range(1, _MAX_ATTEMPTS + 1):
                try:
                    resp = await client.request(
                        method, url, json=json_body, headers=self._headers
                    )
                except (httpx.HTTPError, OSError) as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
                    last_status = None
                else:
                    if resp.status_code in expected:
                        self._circuit.record_success()
                        return resp
                    last_status = resp.status_code
                    last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
                    # 4xx (except 429) is not going to succeed on retry — fail fast.
                    if 400 <= resp.status_code < 500 and resp.status_code != 429:
                        self._circuit.record_failure()
                        raise ConnectorError(last_error, status=resp.status_code)

                if attempt < _MAX_ATTEMPTS:
                    backoff = min(
                        _BASE_BACKOFF_SECONDS * (2 ** (attempt - 1)), _MAX_BACKOFF_SECONDS
                    )
                    await asyncio.sleep(backoff)

            self._circuit.record_failure()
            raise ConnectorError(
                f"push failed after {_MAX_ATTEMPTS} attempts: {last_error}",
                status=last_status,
            )
        finally:
            # A short-lived (non-pooled) client is closed here; the pooled client
            # lives on until the ``async with`` block exits.
            if not pooled:
                await client.aclose()
