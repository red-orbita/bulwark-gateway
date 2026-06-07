"""
Sentinel Gateway — Enrichment Layer (Async, Background, Non-Blocking)

This module provides ML-based semantic scoring that runs OUTSIDE the hot path.
It NEVER blocks or delays the primary request/response flow.

Architecture:
    Request → [HOT PATH: regex-only ≤40ms] → Response
                    ↓ (fire-and-forget)
              [ENRICHMENT: async background]
                    ↓
              [AttackReplayDB + EmbeddingScanner + Metrics]

Components:
    - EmbeddingScanner: Cosine similarity vs known attack embeddings
    - AttackReplayDB: Store payloads, detect evasions, auto-generate regex

Constraints:
    - NEVER converts ALLOW → BLOCK (enrichment is advisory only)
    - NEVER adds latency to hot path
    - Fails silently (enrichment failure ≠ request failure)
    - Controlled by feature flag: SENTINEL_ENRICHMENT_ENABLED
"""
