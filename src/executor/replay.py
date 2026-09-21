"""Replay reservations are never released, including after ambiguous failures."""

import asyncio
import time
from typing import Protocol


class ReplayStore(Protocol):
    durable: bool

    async def reserve(self, token_key: str, action_key: str, ttl: int) -> bool:
        """Reserve BOTH keys before returning True; errors MUST propagate.

        False means already reserved. Partial reservations may remain on failure.
        Implementations must never evict live records to admit new work.
        """
        ...


class MemoryReplayStore:
    """Bounded, process-local test/dev store. Restart loses replay protection."""

    durable = False

    def __init__(self, capacity: int = 10000) -> None:
        if type(capacity) is not int or not 2 <= capacity <= 100000:
            raise ValueError("Invalid replay capacity")
        self.capacity = capacity
        self._records: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def reserve(self, token_key: str, action_key: str, ttl: int) -> bool:
        async with self._lock:
            now = time.monotonic()
            self._records = {k: v for k, v in self._records.items() if v > now}
            if token_key in self._records or action_key in self._records:
                return False
            if len(self._records) + 2 > self.capacity:
                raise RuntimeError("Replay capacity exhausted")
            self._records[token_key] = self._records[action_key] = now + ttl
            return True


class RedisReplayStore:
    """Use an operator-owned redis.asyncio client; no connections at import time.

    durability_confirmed is an operator attestation, NOT a Redis durability test.
    The deployment must preserve acknowledged writes, forbid eviction and prevent
    failover/restore to a stale ledger. Ordinary async Redis replication alone
    cannot guarantee this. There is deliberately no in-memory fallback.
    """

    durable = True

    def __init__(self, client, *, durability_confirmed: bool = False) -> None:
        if durability_confirmed is not True:
            raise ValueError("Replay durability must be confirmed by the operator")
        self._client = client

    async def reserve(self, token_key: str, action_key: str, ttl: int) -> bool:
        # No rollback: a crash between SETs burns the token, never reexecutes it.
        if not await self._client.set(token_key, "reserved", nx=True, ex=ttl):
            return False
        return bool(await self._client.set(action_key, "reserved", nx=True, ex=ttl))
