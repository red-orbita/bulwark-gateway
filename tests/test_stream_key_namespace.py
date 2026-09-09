"""Regression test for B3 (3rd-pass): per-tenant stream counter namespace.

The distributed concurrent-stream limiter kept per-tenant counters at
``bulwark:streams:{tenant_id}`` and the aggregate at ``bulwark:streams:global``.
A tenant literally named ``global`` (a valid ``_SAFE_ID``) therefore shared the
aggregate key, so its stream open/close would inc/dec the GLOBAL counter (and
vice-versa) — corrupting both limits. Per-tenant counters now live under a
dedicated ``bulwark:streams:tenant:`` sub-namespace that can never collide.
"""

from __future__ import annotations

from src.routes import proxy


def test_tenant_key_uses_dedicated_subnamespace():
    key = f"{proxy._STREAM_KEY_TENANT_PREFIX}:acme"
    assert key == "bulwark:streams:tenant:acme"
    assert key.startswith(proxy._STREAM_KEY_PREFIX + ":tenant:")


def test_global_named_tenant_does_not_collide_with_aggregate():
    tenant_key = f"{proxy._STREAM_KEY_TENANT_PREFIX}:global"
    assert tenant_key != proxy._STREAM_KEY_GLOBAL
    assert proxy._STREAM_KEY_GLOBAL == "bulwark:streams:global"
    assert tenant_key == "bulwark:streams:tenant:global"


def test_no_tenant_id_can_reach_the_global_key():
    # For any tenant id, the tenant key carries the ``tenant:`` segment, so it can
    # never equal the aggregate ``bulwark:streams:global`` key.
    for tenant_id in ("global", "streams", "", "a", "tenant", "GLOBAL"):
        tenant_key = f"{proxy._STREAM_KEY_TENANT_PREFIX}:{tenant_id}"
        assert tenant_key != proxy._STREAM_KEY_GLOBAL
