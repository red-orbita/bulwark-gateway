"""Declarative service-account seeding (Phase 3.2d).

A SOAR/playbook runner needs its automation key to exist the moment a fresh
gateway comes up — waiting for an operator to mint one by hand in the UI defeats
unattended, GitOps-style deploys. This module provisions service accounts from a
declarative spec at startup, mirroring the ``*_FILE`` secret convention used
everywhere else in the gateway.

The spec is a JSON array read from ``BULWARK_SERVICE_ACCOUNTS_SEED`` (or its
``BULWARK_SERVICE_ACCOUNTS_SEED_FILE`` Docker-secret variant), each element::

    [
      {
        "name": "shuffle-soar",
        "permissions": ["investigation:write", "automation:respond"],
        "key": "bwk_sa_<hex>",
        "rate_limit_rpm": 120,
        "expires_at": "2027-01-01T00:00:00+00:00"
      }
    ]

Unlike an interactively minted account, the operator supplies the plaintext
``key`` here (from their IaC / secret store) so the SOAR side can be configured
with the same value out-of-band. Only its SHA-256 is ever persisted; the raw key
is never logged. Seeding is **idempotent** (keyed on the hash) so it is safe to
run on every boot, and **fail-open**: a malformed spec or a single bad entry is
logged and skipped — it must never crash the admin service or block startup.
"""

from __future__ import annotations

import json
import logging

from .secrets import read_secret
from .service_account_store import ServiceAccountStore

logger = logging.getLogger(__name__)

_SEED_ENV = "BULWARK_SERVICE_ACCOUNTS_SEED"


def _parse_spec(raw: str) -> list[dict]:
    """Parse the raw seed value into a list of entry dicts (never raises)."""
    if not raw or not raw.strip():
        return []
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        logger.warning("service_account_seed: invalid JSON, ignoring (%s)", exc)
        return []
    if not isinstance(parsed, list):
        logger.warning("service_account_seed: spec must be a JSON array, ignoring")
        return []
    return [e for e in parsed if isinstance(e, dict)]


async def seed_service_accounts() -> int:
    """Provision service accounts from the declarative startup spec.

    Returns the number of accounts newly created (0 when no spec is configured,
    every entry already exists, or the spec is invalid). Best-effort throughout:
    any error is logged and swallowed so a bad seed can never abort startup.
    """
    try:
        raw = read_secret(_SEED_ENV, default="")
    except Exception as exc:  # noqa: BLE001 — seeding is best-effort, never fatal
        logger.warning("service_account_seed: could not read spec (%s)", exc)
        return 0

    entries = _parse_spec(raw)
    if not entries:
        return 0

    store = ServiceAccountStore()
    created = 0
    for idx, entry in enumerate(entries):
        name = str(entry.get("name") or "").strip() or f"seed-{idx}"
        try:
            account_id = await store.seed_from_spec(
                name=name,
                permissions=entry.get("permissions", []),
                raw_key=str(entry.get("key") or ""),
                created_by="startup-seed",
                expires_at=entry.get("expires_at"),
                rate_limit_rpm=entry.get("rate_limit_rpm"),
            )
        except ValueError as exc:
            # Bad key shape / non-grantable permission — skip this entry only.
            logger.warning(
                "service_account_seed: skipping entry name=%s (%s)", name, exc
            )
            continue
        except Exception as exc:  # noqa: BLE001 — one bad entry must not abort the rest
            logger.warning(
                "service_account_seed: error seeding name=%s (%s)", name, exc
            )
            continue
        if account_id:
            created += 1

    if created:
        logger.info("service_account_seed: provisioned %d account(s)", created)
    return created
