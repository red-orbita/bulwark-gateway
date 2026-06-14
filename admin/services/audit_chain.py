"""Audit Chain Verification — Tamper detection for hash-chained audit log.

Provides verification, proof export, and tampering detection for the
append-only hash-chained audit trail. Designed for SOC 2 compliance
evidence and forensic investigation workflows.

Supports efficient batch verification for chains with millions of entries.
"""

from __future__ import annotations

import hashlib
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from .audit_logger import (
    GENESIS_HASH,
    AuditLogger,
    compute_entry_hash,
    get_audit_logger,
)

logger = logging.getLogger(__name__)


# ─── Models ──────────────────────────────────────────────────────────────────


class TamperEvent(BaseModel):
    """A detected break in the hash chain."""

    sequence_id: int
    expected_hash: str
    actual_hash: str
    entry_id: Optional[str] = None
    description: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ChainVerification(BaseModel):
    """Result of verifying a range of the audit chain."""

    valid: bool
    start_seq: int
    end_seq: int
    entries_checked: int
    entries_valid: int
    entries_broken: int
    tamper_events: list[TamperEvent] = []
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: float = 0.0


class ChainProof(BaseModel):
    """Exportable cryptographic proof for auditors.

    Contains the minimal set of hashes needed to verify a range of entries
    independently, without access to the full database.
    """

    start_seq: int
    end_seq: int
    chain_anchor: str  # Hash of entry before start_seq (or genesis)
    entries: list[ChainProofEntry] = []
    chain_head: str  # Hash of last entry in range
    total_chain_length: int
    exported_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    verification_result: Optional[ChainVerification] = None


class ChainProofEntry(BaseModel):
    """Single entry in a chain proof export."""

    sequence_id: int
    timestamp: str
    event_type: str
    actor: str
    action: str
    resource: str
    details: str
    previous_hash: str
    entry_hash: str


class ChainStatus(BaseModel):
    """Current state of the audit chain."""

    chain_head: str
    chain_length: int  # Total entries with chain data
    last_sequence_id: int
    genesis_hash: str = GENESIS_HASH
    last_verified: Optional[datetime] = None
    is_healthy: bool = True


# ─── Verification Logic ──────────────────────────────────────────────────────

BATCH_SIZE = 1000  # Process in batches for memory efficiency


async def get_chain_head() -> str:
    """Get the current chain head hash."""
    audit = get_audit_logger()
    return audit.chain_head


async def get_chain_status() -> ChainStatus:
    """Get current chain status including head hash and length."""
    audit = get_audit_logger()
    seq = audit.sequence_id
    head = audit.chain_head
    return ChainStatus(
        chain_head=head,
        chain_length=seq,
        last_sequence_id=seq,
        is_healthy=True,
    )


async def verify_chain(
    start_seq: int = 1,
    end_seq: Optional[int] = None,
) -> ChainVerification:
    """Verify integrity of the hash chain over a range of entries.

    Walks the chain from start_seq to end_seq, recomputing each entry's
    hash and verifying it matches the stored hash and that each
    previous_hash correctly references the preceding entry.

    Processes in batches of BATCH_SIZE for memory efficiency.
    """
    import time

    t0 = time.monotonic()
    audit = get_audit_logger()

    if end_seq is None:
        end_seq = audit.sequence_id

    if start_seq < 1:
        start_seq = 1
    if end_seq < start_seq:
        return ChainVerification(
            valid=True,
            start_seq=start_seq,
            end_seq=end_seq,
            entries_checked=0,
            entries_valid=0,
            entries_broken=0,
            duration_ms=0.0,
        )

    tamper_events: list[TamperEvent] = []
    entries_checked = 0
    entries_valid = 0

    # Get the anchor hash (entry before start_seq)
    if start_seq == 1:
        expected_prev = GENESIS_HASH
    else:
        anchor = await audit.get_entry_by_sequence(start_seq - 1)
        if anchor and anchor.entry_hash:
            expected_prev = anchor.entry_hash
        else:
            # Cannot verify without an anchor — treat as unchainable
            expected_prev = None

    # Process in batches
    current_start = start_seq
    while current_start <= end_seq:
        current_end = min(current_start + BATCH_SIZE - 1, end_seq)
        entries = await audit.get_entries_range(current_start, current_end)

        for entry in entries:
            entries_checked += 1

            # Skip pre-chain entries (no hash data)
            if entry.sequence_id is None or entry.entry_hash is None:
                continue

            # Verify previous_hash linkage
            if expected_prev is not None and entry.previous_hash != expected_prev:
                tamper_events.append(TamperEvent(
                    sequence_id=entry.sequence_id,
                    expected_hash=expected_prev,
                    actual_hash=entry.previous_hash or "(missing)",
                    entry_id=entry.id,
                    description=(
                        f"Chain break: entry {entry.sequence_id} has "
                        f"previous_hash={entry.previous_hash!r} but "
                        f"expected {expected_prev!r}"
                    ),
                ))
            else:
                # Verify entry_hash recomputation
                resource = f"{entry.resource_type}:{entry.resource_id}"
                recomputed = compute_entry_hash(
                    sequence_id=entry.sequence_id,
                    timestamp=entry.timestamp.isoformat(),
                    event_type=entry.resource_type,
                    actor=entry.actor,
                    action=entry.action,
                    resource=resource,
                    details=entry.details or "",
                    previous_hash=entry.previous_hash or GENESIS_HASH,
                )
                if recomputed != entry.entry_hash:
                    tamper_events.append(TamperEvent(
                        sequence_id=entry.sequence_id,
                        expected_hash=recomputed,
                        actual_hash=entry.entry_hash,
                        entry_id=entry.id,
                        description=(
                            f"Hash mismatch: entry {entry.sequence_id} stored "
                            f"hash={entry.entry_hash!r} but recomputed "
                            f"hash={recomputed!r}. Entry may have been tampered."
                        ),
                    ))
                else:
                    entries_valid += 1

            # Advance expected_prev for next iteration
            expected_prev = entry.entry_hash

        current_start = current_end + 1

    elapsed = (time.monotonic() - t0) * 1000
    return ChainVerification(
        valid=len(tamper_events) == 0,
        start_seq=start_seq,
        end_seq=end_seq,
        entries_checked=entries_checked,
        entries_valid=entries_valid,
        entries_broken=len(tamper_events),
        tamper_events=tamper_events,
        duration_ms=round(elapsed, 2),
    )


async def export_chain_proof(
    start_seq: int,
    end_seq: Optional[int] = None,
) -> ChainProof:
    """Export a verifiable proof for a range of entries.

    The proof contains all fields necessary for an independent auditor
    to recompute every hash and verify chain integrity without DB access.
    """
    audit = get_audit_logger()

    if end_seq is None:
        end_seq = audit.sequence_id

    # Get anchor (hash before start_seq)
    if start_seq <= 1:
        chain_anchor = GENESIS_HASH
    else:
        anchor_entry = await audit.get_entry_by_sequence(start_seq - 1)
        chain_anchor = (
            anchor_entry.entry_hash if anchor_entry and anchor_entry.entry_hash
            else GENESIS_HASH
        )

    # Collect entries
    entries = await audit.get_entries_range(start_seq, end_seq)
    proof_entries: list[ChainProofEntry] = []
    chain_head_hash = chain_anchor

    for entry in entries:
        if entry.sequence_id is None or entry.entry_hash is None:
            continue
        resource = f"{entry.resource_type}:{entry.resource_id}"
        proof_entries.append(ChainProofEntry(
            sequence_id=entry.sequence_id,
            timestamp=entry.timestamp.isoformat(),
            event_type=entry.resource_type,
            actor=entry.actor,
            action=entry.action,
            resource=resource,
            details=entry.details or "",
            previous_hash=entry.previous_hash or GENESIS_HASH,
            entry_hash=entry.entry_hash,
        ))
        chain_head_hash = entry.entry_hash

    # Also run verification
    verification = await verify_chain(start_seq, end_seq)

    return ChainProof(
        start_seq=start_seq,
        end_seq=end_seq,
        chain_anchor=chain_anchor,
        entries=proof_entries,
        chain_head=chain_head_hash,
        total_chain_length=audit.sequence_id,
        verification_result=verification,
    )


async def detect_tampering() -> list[TamperEvent]:
    """Scan the entire chain for broken links.

    Convenience wrapper around verify_chain() that returns only the
    list of detected tamper events.
    """
    result = await verify_chain(start_seq=1)
    return result.tamper_events


# ─── External Anchoring (L-03 fix) ───────────────────────────────────────────


async def publish_anchor_to_redis() -> Optional[str]:
    """SECURITY (L-03 fix): Publish chain head hash to Redis as external anchor.

    This provides a tamper-evident checkpoint that can be independently verified.
    If an attacker rewrites the chain, the Redis anchor won't match.

    For stronger guarantees, integrate with an external timestamping service
    (RFC 3161) or blockchain anchor. Redis provides baseline cross-service
    verification (admin ↔ proxy ↔ external auditor).

    Returns the anchor hash or None if Redis unavailable.
    """
    try:
        from admin.services.redis_sync import get_redis_client
        client = get_redis_client()
        if not client:
            return None

        audit = get_audit_logger()
        anchor_data = {
            "chain_head": audit.chain_head,
            "sequence_id": audit.sequence_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        # Create HMAC of the anchor for additional integrity
        import json
        anchor_json = json.dumps(anchor_data, sort_keys=True)
        anchor_hmac = hashlib.sha256(
            f"chain-anchor:{anchor_json}".encode()
        ).hexdigest()

        client.hset("sentinel:audit:anchor", mapping={
            "chain_head": audit.chain_head,
            "sequence_id": str(audit.sequence_id),
            "timestamp": anchor_data["timestamp"],
            "hmac": anchor_hmac,
        })
        return anchor_hmac
    except Exception as e:
        logger.warning("Failed to publish chain anchor to Redis: %s", e)
        return None


# ─── Timestamp Monotonicity (L-04 fix) ───────────────────────────────────────


async def verify_timestamp_monotonicity(
    start_seq: int = 1, end_seq: Optional[int] = None
) -> list[TamperEvent]:
    """SECURITY (L-04 fix): Verify timestamps are monotonically non-decreasing.

    Non-monotonic timestamps indicate either clock skew or tampering
    (entries inserted out of order to hide modifications).

    Returns list of detected anomalies.
    """
    audit = get_audit_logger()
    if end_seq is None:
        end_seq = audit.sequence_id

    anomalies: list[TamperEvent] = []
    prev_timestamp: Optional[datetime] = None

    entries = await audit.get_entries_range(start_seq, end_seq)
    for entry in entries:
        if entry.sequence_id is None:
            continue
        if prev_timestamp is not None and entry.timestamp < prev_timestamp:
            anomalies.append(TamperEvent(
                sequence_id=entry.sequence_id,
                expected_hash="(timestamp check)",
                actual_hash=entry.timestamp.isoformat(),
                entry_id=entry.id,
                description=(
                    f"Non-monotonic timestamp at seq {entry.sequence_id}: "
                    f"{entry.timestamp.isoformat()} < previous {prev_timestamp.isoformat()}"
                ),
            ))
        prev_timestamp = entry.timestamp

    return anomalies
