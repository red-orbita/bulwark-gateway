"""
Cost Tracking — Token usage and cost accounting per tenant/agent.

Parses `usage` from OpenAI-compatible responses and accumulates:
  - prompt_tokens, completion_tokens, total_tokens
  - Estimated cost based on configurable model pricing
  - Per-tenant and per-agent breakdown

Data is stored in Redis (persistent across pod restarts) with
in-memory fallback for environments without Redis.

Redis keys:
  sentinel:cost:{tenant_id}:tokens       — HASH {prompt, completion, total, requests}
  sentinel:cost:{tenant_id}:{agent_id}   — HASH {prompt, completion, total, requests}
  sentinel:cost:global                    — HASH {prompt, completion, total, requests}
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Default pricing per 1M tokens (USD) — configurable via config
# Based on approximate OpenAI/Anthropic pricing tiers
DEFAULT_PRICING: dict[str, dict[str, float]] = {
    # Model pattern → {"input": $/1M tokens, "output": $/1M tokens}
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4-turbo": {"input": 10.00, "output": 30.00},
    "gpt-4": {"input": 30.00, "output": 60.00},
    "gpt-3.5-turbo": {"input": 0.50, "output": 1.50},
    "claude-3-opus": {"input": 15.00, "output": 75.00},
    "claude-3-sonnet": {"input": 3.00, "output": 15.00},
    "claude-3-haiku": {"input": 0.25, "output": 1.25},
    "claude-3.5-sonnet": {"input": 3.00, "output": 15.00},
    "llama": {"input": 0.00, "output": 0.00},  # Self-hosted
    "tinyllama": {"input": 0.00, "output": 0.00},
    "mistral": {"input": 0.00, "output": 0.00},
    "_default": {"input": 1.00, "output": 3.00},  # Fallback
}


@dataclass
class UsageRecord:
    """Token usage from a single request."""

    tenant_id: str
    agent_id: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    estimated_cost_usd: float
    timestamp: float = field(default_factory=time.time)


@dataclass
class TenantUsageSummary:
    """Aggregated usage for a tenant."""

    tenant_id: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    total_requests: int = 0
    estimated_cost_usd: float = 0.0
    agents: dict[str, dict[str, Any]] = field(default_factory=dict)


class CostTracker:
    """Tracks token usage and costs per tenant/agent.

    Integrates with Redis for persistence. Falls back to in-memory
    if Redis is unavailable.
    """

    def __init__(self, pricing: dict[str, dict[str, float]] | None = None):
        self._pricing = pricing or DEFAULT_PRICING
        self._redis = None
        self._fallback: dict[str, dict[str, int]] = {}  # In-memory fallback
        self._init_redis()

    def _init_redis(self):
        """Try to connect to Redis for persistent storage."""
        try:
            from src.guardrails.dynamic_registry import get_pattern_registry
            registry = get_pattern_registry()
            self._redis = registry._redis
        except Exception:
            self._redis = None

    def record_usage(
        self,
        tenant_id: str,
        agent_id: str,
        model: str,
        usage: dict[str, Any],
    ) -> UsageRecord | None:
        """Record token usage from a backend response.

        Args:
            tenant_id: Tenant identifier.
            agent_id: Agent identifier.
            model: Model name from the response.
            usage: The `usage` dict from the OpenAI-compatible response.

        Returns:
            UsageRecord if usage data was present, None otherwise.
        """
        if not usage:
            return None

        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)
        total_tokens = usage.get("total_tokens", prompt_tokens + completion_tokens)

        if total_tokens == 0:
            return None

        # Calculate estimated cost
        cost = self._estimate_cost(model, prompt_tokens, completion_tokens)

        record = UsageRecord(
            tenant_id=tenant_id,
            agent_id=agent_id,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            estimated_cost_usd=cost,
        )

        # Persist to Redis (or fallback)
        self._persist(record)

        return record

    def get_tenant_usage(self, tenant_id: str) -> TenantUsageSummary:
        """Get aggregated usage for a tenant.

        Args:
            tenant_id: Tenant to query.

        Returns:
            TenantUsageSummary with token counts and cost.
        """
        summary = TenantUsageSummary(tenant_id=tenant_id)

        if self._redis:
            try:
                key = f"sentinel:cost:{tenant_id}:tokens"
                data = self._redis.hgetall(key)
                if data:
                    summary.prompt_tokens = int(data.get(b"prompt", data.get("prompt", 0)))
                    summary.completion_tokens = int(data.get(b"completion", data.get("completion", 0)))
                    summary.total_tokens = int(data.get(b"total", data.get("total", 0)))
                    summary.total_requests = int(data.get(b"requests", data.get("requests", 0)))
                    summary.estimated_cost_usd = float(data.get(b"cost_usd", data.get("cost_usd", 0.0)))
                return summary
            except Exception as e:
                logger.warning("cost_tracker_redis_read_error", extra={"error": str(e)[:100]})

        # Fallback to in-memory
        fallback_key = f"{tenant_id}:tokens"
        if fallback_key in self._fallback:
            data = self._fallback[fallback_key]
            summary.prompt_tokens = data.get("prompt", 0)
            summary.completion_tokens = data.get("completion", 0)
            summary.total_tokens = data.get("total", 0)
            summary.total_requests = data.get("requests", 0)
            summary.estimated_cost_usd = data.get("cost_usd", 0.0)

        return summary

    def get_global_usage(self) -> dict[str, Any]:
        """Get global usage across all tenants."""
        if self._redis:
            try:
                data = self._redis.hgetall("sentinel:cost:global")
                if data:
                    return {
                        "prompt_tokens": int(data.get(b"prompt", data.get("prompt", 0))),
                        "completion_tokens": int(data.get(b"completion", data.get("completion", 0))),
                        "total_tokens": int(data.get(b"total", data.get("total", 0))),
                        "total_requests": int(data.get(b"requests", data.get("requests", 0))),
                        "estimated_cost_usd": float(data.get(b"cost_usd", data.get("cost_usd", 0.0))),
                    }
            except Exception:
                pass

        # Fallback
        data = self._fallback.get("global", {})
        return {
            "prompt_tokens": data.get("prompt", 0),
            "completion_tokens": data.get("completion", 0),
            "total_tokens": data.get("total", 0),
            "total_requests": data.get("requests", 0),
            "estimated_cost_usd": data.get("cost_usd", 0.0),
        }

    def _estimate_cost(self, model: str, prompt_tokens: int, completion_tokens: int) -> float:
        """Estimate cost in USD based on model pricing."""
        # Find matching pricing tier
        pricing = self._pricing.get("_default", {"input": 1.0, "output": 3.0})
        model_lower = model.lower() if model else ""

        for model_pattern, model_pricing in self._pricing.items():
            if model_pattern == "_default":
                continue
            if model_pattern in model_lower:
                pricing = model_pricing
                break

        input_cost = (prompt_tokens / 1_000_000) * pricing["input"]
        output_cost = (completion_tokens / 1_000_000) * pricing["output"]
        return round(input_cost + output_cost, 6)

    def _persist(self, record: UsageRecord):
        """Persist usage record to Redis or in-memory fallback."""
        if self._redis:
            try:
                pipe = self._redis.pipeline(transaction=False)

                # Per-tenant totals
                tenant_key = f"sentinel:cost:{record.tenant_id}:tokens"
                pipe.hincrby(tenant_key, "prompt", record.prompt_tokens)
                pipe.hincrby(tenant_key, "completion", record.completion_tokens)
                pipe.hincrby(tenant_key, "total", record.total_tokens)
                pipe.hincrby(tenant_key, "requests", 1)
                pipe.hincrbyfloat(tenant_key, "cost_usd", record.estimated_cost_usd)

                # Per-agent totals
                agent_key = f"sentinel:cost:{record.tenant_id}:{record.agent_id}"
                pipe.hincrby(agent_key, "prompt", record.prompt_tokens)
                pipe.hincrby(agent_key, "completion", record.completion_tokens)
                pipe.hincrby(agent_key, "total", record.total_tokens)
                pipe.hincrby(agent_key, "requests", 1)
                pipe.hincrbyfloat(agent_key, "cost_usd", record.estimated_cost_usd)
                pipe.hset(agent_key, "model", record.model)

                # Global totals
                pipe.hincrby("sentinel:cost:global", "prompt", record.prompt_tokens)
                pipe.hincrby("sentinel:cost:global", "completion", record.completion_tokens)
                pipe.hincrby("sentinel:cost:global", "total", record.total_tokens)
                pipe.hincrby("sentinel:cost:global", "requests", 1)
                pipe.hincrbyfloat("sentinel:cost:global", "cost_usd", record.estimated_cost_usd)

                pipe.execute()
            except Exception as e:
                logger.warning("cost_tracker_redis_error", extra={"error": str(e)[:100]})
                self._persist_fallback(record)
        else:
            self._persist_fallback(record)

    def _persist_fallback(self, record: UsageRecord):
        """In-memory fallback persistence."""
        for key in [f"{record.tenant_id}:tokens", "global"]:
            if key not in self._fallback:
                self._fallback[key] = {"prompt": 0, "completion": 0, "total": 0, "requests": 0, "cost_usd": 0.0}
            self._fallback[key]["prompt"] += record.prompt_tokens
            self._fallback[key]["completion"] += record.completion_tokens
            self._fallback[key]["total"] += record.total_tokens
            self._fallback[key]["requests"] += 1
            self._fallback[key]["cost_usd"] += record.estimated_cost_usd


# === Singleton ===
_tracker: CostTracker | None = None


def get_cost_tracker() -> CostTracker:
    """Get or create the global cost tracker singleton."""
    global _tracker
    if _tracker is None:
        _tracker = CostTracker()
    return _tracker
