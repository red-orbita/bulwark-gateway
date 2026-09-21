"""Attachment persistence contracts using independent real SQLite engines."""

import asyncio
import hashlib
import inspect
import json
from contextlib import asynccontextmanager

import pytest

from src.attachments import AttachmentStore, StoreError, get_attachment_store
from src.attachments.store import MAX_RAW_BYTES, MAX_TEXT_BYTES, PUBLIC_REASON_CODES, PostgreSQLAttachmentStore
from src.storage.attachment_migrations import POSTGRESQL_V1, SQLITE_V1
from src.storage.database import QueryTranslator, create_engine

SCOPE = {"tenant": "tenant-a", "agent": "agent-a", "owner": "owner-a"}


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """These standalone storage tests must not initialize the admin user store."""


@pytest.fixture
async def stores(tmp_path):
    instances = []

    async def make(**limits):
        db = create_engine(f"sqlite:///{tmp_path / 'attachments.db'}")
        store = AttachmentStore(db, **limits)
        instances.append(store)
        await store.initialize()
        return store

    yield make
    for store in instances:
        await store.close()


async def create(store, **changes):
    return await store.create(**{**SCOPE, "mime": "text/plain", "raw": b"hello", "policy_revision": "rev1", **changes})


async def counters(store):
    row = await store._db.fetch_one("SELECT documents, bytes FROM attachment_store_state")
    actual = await store._db.fetch_one("SELECT COUNT(*) AS documents, COALESCE(SUM(size_bytes), 0) AS bytes FROM attachment_documents")
    assert row.to_dict() == actual.to_dict()
    return row.to_dict()


async def test_roundtrip_public_metadata_and_terminal_scrubbing(stores):
    store = await stores()
    doc = await create(store)
    assert doc["state"] == "queued"
    assert doc["sha256"] == hashlib.sha256(b"hello").hexdigest()
    assert doc["expires_at"] - doc["created_at"] == 3600
    assert set(doc) == {"id", "state", "sha256", "created_at", "expires_at", "mime", "size_bytes", "policy_revision", "text_sha256", "reason"}
    assert doc["reason"] == ""
    with pytest.raises(StoreError, match="^not_ready$"):
        await store.resolve(doc["id"], **SCOPE, policy_revision="rev1")
    lease = await store.claim()
    assert lease == {"id": doc["id"], **SCOPE, "mime": "text/plain", "raw": b"hello", "policy_revision": "rev1", "lease_token": lease["lease_token"], "sha256": doc["sha256"]}
    assert await store.claim() is None
    assert await store.finish(doc["id"], lease["lease_token"], state="approved", text="safe text")
    assert await store.resolve(doc["id"], **SCOPE, policy_revision="rev1") == "safe text"
    metadata = await store.get(doc["id"], **SCOPE)
    assert metadata["state"] == "approved"
    assert metadata["text_sha256"] == hashlib.sha256(b"safe text").hexdigest()
    row = await store._db.fetch_one("SELECT raw_base64, lease_token FROM attachment_documents")
    assert row.to_dict() == {"raw_base64": None, "lease_token": ""}
    assert not await store.finish(doc["id"], lease["lease_token"], state="blocked")
    with pytest.raises(StoreError, match="^policy_changed$"):
        await store.resolve(doc["id"], **SCOPE, policy_revision="rev2")
    await counters(store)


@pytest.mark.parametrize("field", ["tenant", "agent", "owner"])
async def test_scope_no_existence_or_content_lookup(stores, field):
    store = await stores()
    doc = await create(store)
    wrong = {**SCOPE, field: "other"}
    assert await store.get(doc["id"], **wrong) is None
    assert not await store.delete(doc["id"], **wrong)
    with pytest.raises(StoreError, match="^not_found$"):
        await store.resolve(doc["id"], **wrong, policy_revision="rev1")
    assert await store.get(doc["sha256"], **SCOPE) is None
    assert (await store.get(doc["id"], **SCOPE))["state"] == "queued"


async def test_identical_uploads_are_independent_not_cached(stores):
    store = await stores()
    first = await create(store)
    lease = await store.claim()
    await store.finish(first["id"], lease["lease_token"], state="approved", text="first")
    second = await create(store)
    other = await create(store, tenant="tenant-b")
    assert len({d["id"] for d in (first, second, other)}) == 3
    assert second["sha256"] == other["sha256"] == first["sha256"]
    assert second["state"] == other["state"] == "queued"
    assert (await counters(store))["documents"] == 3


async def test_concurrent_engines_one_lease_and_delete_fences_finish(stores):
    first, second = await stores(), await stores()
    doc = await create(first)
    leases = await asyncio.wait_for(asyncio.gather(first.claim(), second.claim()), timeout=10)
    assert sum(lease is not None for lease in leases) == 1
    lease = next(lease for lease in leases if lease)
    assert await second.delete(doc["id"], **SCOPE)
    assert not await first.finish(doc["id"], lease["lease_token"], state="approved", text="late")
    assert not await first.delete(doc["id"], **SCOPE)
    assert await counters(first) == {"documents": 0, "bytes": 0}


async def test_expired_lease_fencing_and_three_attempt_ceiling(stores):
    store = await stores()
    doc = await create(store)
    tokens = []
    for _ in range(3):
        lease = await store.claim(lease_seconds=1)
        tokens.append(lease["lease_token"])
        await store._db.execute("UPDATE attachment_documents SET lease_until = 0 WHERE id = ?", (doc["id"],))
        assert not await store.finish(doc["id"], lease["lease_token"], state="approved", text="stale")
    assert len(set(tokens)) == 3
    assert await store.claim() is None
    assert (await store.get(doc["id"], **SCOPE))["state"] == "review_required"
    assert (await store.get(doc["id"], **SCOPE))["reason"] == "attempts_exhausted"
    row = await store._db.fetch_one("SELECT raw_base64, attempts FROM attachment_documents")
    assert row["raw_base64"] is None and row["attempts"] == 3
    await counters(store)


async def test_old_token_cannot_finish_reclaimed_live_lease(stores):
    store = await stores()
    doc = await create(store)
    first = await store.claim()
    await store._db.execute("UPDATE attachment_documents SET lease_until = 0")
    second = await store.claim()
    assert not await store.finish(doc["id"], first["lease_token"], state="approved", text="stale")
    assert await store.finish(doc["id"], second["lease_token"], state="approved", text="current")


@pytest.mark.parametrize("state", ["blocked", "failed", "review_required"])
async def test_unapproved_never_retains_text_or_raw(stores, state):
    store = await stores()
    doc = await create(store)
    lease = await store.claim()
    assert await store.finish(doc["id"], lease["lease_token"], state=state, text="do not expose", reason="internal-only")
    row = await store._db.fetch_one("SELECT raw_base64, text_json, text_sha256 FROM attachment_documents")
    assert all(value is None for value in row.values())
    assert "internal-only" not in json.dumps(await store.get(doc["id"], **SCOPE))
    assert (await store.get(doc["id"], **SCOPE))["reason"] == ""
    assert (await store._db.fetch_one("SELECT reason FROM attachment_documents"))["reason"] == '"internal-only"'
    with pytest.raises(StoreError, match="^not_ready$"):
        await store.resolve(doc["id"], **SCOPE, policy_revision="rev1")
    await counters(store)


async def test_ttl_enforced_without_cleanup_and_database_clock(stores, monkeypatch):
    store = await stores()
    doc = await create(store)
    lease = await store.claim()
    await store.finish(doc["id"], lease["lease_token"], state="approved", text="result")
    # Wall-clock skew of the application must not control validity.
    monkeypatch.setattr("time.time", lambda: 10**12)
    assert await store.resolve(doc["id"], **SCOPE, policy_revision="rev1") == "result"
    await store._db.execute("UPDATE attachment_documents SET expires_at = 0")
    with pytest.raises(StoreError, match="^not_found$"):
        await store.resolve(doc["id"], **SCOPE, policy_revision="rev1")
    assert await store.get(doc["id"], **SCOPE) is None
    assert await counters(store) == {"documents": 0, "bytes": 0}


async def test_bounded_expire_and_expired_processing_cannot_finish(stores):
    store = await stores()
    docs = [await create(store) for _ in range(3)]
    lease = await store.claim()
    await store._db.execute("UPDATE attachment_documents SET expires_at = 0")
    assert not await store.finish(lease["id"], lease["lease_token"], state="approved", text="late")
    assert await store.expire(limit=1) == 1
    assert (await counters(store))["documents"] == 2
    assert await store.expire() == 2
    assert await store.expire() == 0
    assert await counters(store) == {"documents": 0, "bytes": 0}
    assert await store.get(docs[0]["id"], **SCOPE) is None
    with pytest.raises(StoreError, match="invalid_input"):
        await store.expire(limit=101)


@pytest.mark.parametrize("limits,other_tenant", [({"max_documents": 1}, True), ({"max_per_tenant": 1}, False), ({"max_bytes": 6000}, True)])
async def test_concurrent_capacity_never_overshoots(stores, limits, other_tenant):
    first, second = await stores(**limits), await stores(**limits)
    results = await asyncio.wait_for(asyncio.gather(create(first), create(second, tenant="other" if other_tenant else SCOPE["tenant"]), return_exceptions=True), timeout=10)
    assert sum(isinstance(result, dict) for result in results) == 1
    assert next(result for result in results if isinstance(result, StoreError)).code == "capacity"
    assert (await counters(first))["documents"] == 1


async def test_rejected_admission_commits_bounded_cleanup_and_retries_progress(stores):
    store = await stores(max_documents=300, max_per_tenant=1)
    for index in range(201):
        await create(store, tenant=f"other-{index}")
    current = await create(store)
    await store._db.execute(
        "UPDATE attachment_documents SET expires_at = CASE WHEN id = ? THEN 2 ELSE 1 END",
        (current["id"],),
    )
    before = await counters(store)
    assert before["documents"] == 202
    for remaining in (102, 2):
        with pytest.raises(StoreError, match="^capacity$"):
            await create(store)
        after = await counters(store)
        assert after["documents"] == remaining
        assert after["bytes"] < before["bytes"]
        before = after
        # The tenant's expired row sorts after the other tenants' backlog.
        assert await store._db.fetch_one("SELECT id FROM attachment_documents WHERE id = ?", (current["id"],))
    accepted = await create(store)
    assert accepted["state"] == "queued"
    assert accepted["id"] != current["id"]
    assert (await counters(store))["documents"] == 1


async def test_capacity_release_on_finish_delete_and_expire(stores):
    store = await stores(max_bytes=12000)
    doc = await create(store, raw=b"a" * 2048)
    lease = await store.claim()
    before = (await counters(store))["bytes"]
    await store.finish(doc["id"], lease["lease_token"], state="approved", text="small")
    assert (await counters(store))["bytes"] < before
    second = await create(store, raw=b"a" * 2048)
    assert await store.delete(second["id"], **SCOPE)
    await store._db.execute("UPDATE attachment_documents SET expires_at = 0")
    await store.expire()
    assert await counters(store) == {"documents": 0, "bytes": 0}


async def test_finish_capacity_failure_preserves_lease_and_raw(stores):
    store = await stores(max_bytes=6000)
    doc = await create(store)
    lease = await store.claim()
    with pytest.raises(StoreError, match="^capacity$"):
        await store.finish(doc["id"], lease["lease_token"], state="approved", text="x" * 6000)
    assert (await store.get(doc["id"], **SCOPE))["state"] == "processing"
    assert await store.finish(doc["id"], lease["lease_token"], state="failed")
    await counters(store)


async def test_raw_and_utf8_text_bounds_and_exact_limit(stores):
    store = await stores()
    with pytest.raises(StoreError, match="^too_large$"):
        await create(store, raw=b"x" * (MAX_RAW_BYTES + 1))
    doc = await create(store, raw=b"x" * MAX_RAW_BYTES)
    lease = await store.claim()
    with pytest.raises(StoreError, match="^too_large$"):
        await store.finish(doc["id"], lease["lease_token"], state="approved", text="\u00e9" * MAX_TEXT_BYTES)
    text = "\u00e9" * (MAX_TEXT_BYTES // 2)
    assert await store.finish(doc["id"], lease["lease_token"], state="approved", text=text)
    assert await store.resolve(doc["id"], **SCOPE, policy_revision="rev1") == text
    await counters(store)


@pytest.mark.parametrize("change", [{"raw": b""}, {"raw": "text"}, {"tenant": ""}, {"owner": "x" * 257}, {"mime": None}, {"policy_revision": ""}])
async def test_create_validation(stores, change):
    store = await stores()
    with pytest.raises(StoreError, match="^invalid_input$"):
        await create(store, **change)
    assert await counters(store) == {"documents": 0, "bytes": 0}


@pytest.mark.parametrize("kwargs", [{"state": "queued"}, {"state": "approved"}, {"state": "failed", "reason": "x" * 257}, {"state": "approved", "text": 4}, {"state": "approved", "text": "\ud800"}])
async def test_finish_validation(stores, kwargs):
    store = await stores()
    doc = await create(store)
    lease = await store.claim()
    with pytest.raises(StoreError, match="^invalid_input$"):
        await store.finish(doc["id"], lease["lease_token"], **kwargs)


@pytest.mark.parametrize("lease", [0, -1, 3601, float("nan"), float("inf"), True, "120"])
async def test_lease_validation(stores, lease):
    store = await stores()
    with pytest.raises(StoreError, match="invalid_input"):
        await store.claim(lease_seconds=lease)


async def test_corrupt_raw_quarantined_and_result_hash_fail_closed(stores):
    store = await stores()
    doc = await create(store)
    await store._db.execute("UPDATE attachment_documents SET raw_base64 = ?", ("bad-base64!",))
    assert await store.claim() is None
    assert (await store.get(doc["id"], **SCOPE))["state"] == "failed"
    assert (await store.get(doc["id"], **SCOPE))["reason"] == "integrity_error"
    doc = await create(store)
    lease = await store.claim()
    await store.finish(doc["id"], lease["lease_token"], state="approved", text="safe")
    await store._db.execute("UPDATE attachment_documents SET text_json = ? WHERE id = ?", ('"tampered"', doc["id"]))
    with pytest.raises(StoreError, match="^integrity_error$"):
        await store.resolve(doc["id"], **SCOPE, policy_revision="rev1")


async def test_datetime_looking_scopes_and_text_roundtrip(stores):
    store = await stores()
    iso = "2026-06-13T13:00:42Z"
    scope = dict.fromkeys(SCOPE, iso)
    doc = await create(store, **scope, policy_revision=iso, mime=iso)
    row = await store._db.fetch_one("SELECT tenant, agent, owner, mime, policy_revision FROM attachment_documents")
    translator = QueryTranslator("postgresql")
    _, params = translator.translate("SELECT ?, ?, ?, ?, ?", tuple(row.values()))
    assert all(isinstance(value, str) for value in params)
    assert all(json.loads(value) == iso for value in params)
    lease = await store.claim()
    assert all(lease[k] == iso for k in scope)
    await store.finish(doc["id"], lease["lease_token"], state="approved", text=iso, reason=iso)
    assert await store.resolve(doc["id"], **scope, policy_revision=iso) == iso


async def test_migration_idempotence_and_replica_limit_mismatch(stores):
    store = await stores()
    await store.initialize()
    await create(store)
    second = await stores()
    assert (await counters(second))["documents"] == 1
    with pytest.raises(StoreError, match="^configuration_error$"):
        await stores(max_documents=200)


async def test_cancellation_keeps_lock_until_operation_finishes(stores, monkeypatch):
    store = await stores()
    entered, release = asyncio.Event(), asyncio.Event()
    original = store._db.transaction

    @asynccontextmanager
    async def delayed():
        async with original() as tx:
            entered.set()
            await release.wait()
            yield tx

    monkeypatch.setattr(store._db, "transaction", delayed)
    pending = asyncio.create_task(create(store))
    await asyncio.wait_for(entered.wait(), 2)
    pending.cancel()
    await asyncio.sleep(0)
    with pytest.raises(StoreError, match="^busy$") as exc:
        await store.claim()
    assert exc.value.retryable
    pending.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(pending, 5)
    monkeypatch.setattr(store._db, "transaction", original)
    assert (await counters(store))["documents"] == 1
    assert await store.claim() is not None


async def test_storage_error_is_safe_and_retryable(stores, monkeypatch):
    store = await stores()

    @asynccontextmanager
    async def broken():
        raise RuntimeError("secret db path and password")
        yield

    monkeypatch.setattr(store._db, "transaction", broken)
    with pytest.raises(StoreError) as exc:
        await create(store)
    assert str(exc.value) == "unavailable" and exc.value.retryable
    assert not store._lock.locked()


async def test_operation_timeout_rolls_back_and_releases_lock(stores, monkeypatch):
    store = await stores()
    monkeypatch.setattr("src.attachments.store.OPERATION_TIMEOUT", 0.02)
    original = store._db.transaction

    @asynccontextmanager
    async def stalled():
        async with original() as tx:
            await tx.execute("UPDATE attachment_store_state SET documents = 99")
            await asyncio.sleep(10)
            yield tx

    monkeypatch.setattr(store._db, "transaction", stalled)
    with pytest.raises(StoreError, match="^unavailable$"):
        await asyncio.wait_for(store.claim(), 2)
    monkeypatch.setattr(store._db, "transaction", original)
    assert await counters(store) == {"documents": 0, "bytes": 0}
    assert not store._lock.locked()


async def test_not_initialized_is_typed_not_ready():
    store = get_attachment_store("sqlite:///:memory:")
    with pytest.raises(StoreError, match="^not_ready$"):
        await store.claim()


@pytest.mark.parametrize("reason", sorted(PUBLIC_REASON_CODES))
async def test_public_reason_only_fixed_codes(stores, reason):
    store = await stores()
    doc = await create(store)
    lease = await store.claim()
    assert await store.finish(doc["id"], lease["lease_token"], state="approved", text="safe", reason=reason)
    assert (await store.get(doc["id"], **SCOPE))["reason"] == reason
    assert await store.get(doc["id"], **{**SCOPE, "owner": "other"}) is None


@pytest.mark.parametrize("persisted", ['"secret path /data/owner"', '"approved extra"', '"APPROVED"', '"approved\\n"', 'approved', '{"reason":"approved"}', '["approved"]', 'null'])
async def test_persisted_diagnostics_never_leak(stores, persisted):
    store = await stores()
    doc = await create(store)
    await store._db.execute("UPDATE attachment_documents SET reason = ?", (persisted,))
    assert (await store.get(doc["id"], **SCOPE))["reason"] == ""


async def test_empty_persisted_raw_never_reaches_worker(stores):
    store = await stores()
    doc = await create(store)
    await store._db.execute("UPDATE attachment_documents SET raw_base64 = '', raw_size = 0, sha256 = ?", (hashlib.sha256(b"").hexdigest(),))
    assert await store.claim() is None
    assert (await store.get(doc["id"], **SCOPE))["reason"] == "integrity_error"


async def test_close_public_lifecycle_and_persistence(tmp_path):
    url = f"sqlite:///{tmp_path / 'owned.db'}"
    store = get_attachment_store(url)
    await store.initialize()
    doc = await create(store)
    await store.close()
    await store.close()
    with pytest.raises(StoreError, match="^not_ready$"):
        await store.get(doc["id"], **SCOPE)
    with pytest.raises(StoreError, match="^not_ready$"):
        await store.initialize()
    reopened = get_attachment_store(url)
    try:
        await reopened.initialize()
        assert await reopened.get(doc["id"], **SCOPE) == doc
    finally:
        await reopened.close()


async def test_close_before_initialize():
    store = get_attachment_store("sqlite:///:memory:")
    await store.close()
    await store.close()
    with pytest.raises(StoreError, match="^not_ready$"):
        await store.initialize()


async def test_close_cancellation_drains_driver_and_clears_readiness(stores, monkeypatch):
    store = await stores()
    entered, release = asyncio.Event(), asyncio.Event()
    original = store._db.close

    async def delayed():
        entered.set()
        await release.wait()
        await original()

    monkeypatch.setattr(store._db, "close", delayed)
    pending = asyncio.create_task(store.close())
    await asyncio.wait_for(entered.wait(), 2)
    assert not store._ready
    pending.cancel()
    await asyncio.sleep(0)
    with pytest.raises(StoreError, match="^busy$"):
        await store.claim()
    with pytest.raises(StoreError, match="^busy$"):
        await store.close()
    pending.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(pending, 5)
    assert not store._ready and not store._lock.locked()
    with pytest.raises(StoreError, match="^not_ready$"):
        await store.claim()
    await store.close()


@pytest.mark.parametrize("timeout", [False, True])
async def test_close_error_or_timeout_stays_unready_and_can_retry(stores, monkeypatch, timeout):
    store = await stores()
    original = store._db.close

    async def broken():
        if timeout:
            await asyncio.sleep(10)
        raise RuntimeError("private driver diagnostic")

    with monkeypatch.context() as injected:
        injected.setattr("src.attachments.store.OPERATION_TIMEOUT", 0.02)
        injected.setattr(store._db, "close", broken)
        with pytest.raises(StoreError, match="^unavailable$"):
            await asyncio.wait_for(store.close(), 2)
        assert not store._ready
        with pytest.raises(StoreError, match="^not_ready$"):
            await store.initialize()
    # Restore the real operation budget as well as the driver before retrying.
    assert store._db.close == original
    await store.close()


async def test_close_rejects_busy_operation_without_closing_engine(stores):
    store = await stores()
    await store._lock.acquire()
    try:
        with pytest.raises(StoreError, match="^busy$"):
            await store.close()
        assert store._ready
    finally:
        store._lock.release()
    assert await create(store)


async def test_terminal_diagnostics_fit_full_store_for_tiny_upload(stores):
    identity_bytes = sum(len(json.dumps(v)) for v in (*SCOPE.values(), "text/plain", "rev1"))
    store = await stores(max_bytes=4096 + identity_bytes + 4)
    doc = await create(store, raw=b"x")
    lease = await store.claim()
    assert await store.finish(doc["id"], lease["lease_token"], state="failed", reason="\U0001f600" * 256)
    await counters(store)
    assert await store.delete(doc["id"], **SCOPE)
    doc = await create(store, raw=b"x")
    for _ in range(3):
        await store.claim()
        await store._db.execute("UPDATE attachment_documents SET lease_until = 0")
    assert await store.claim() is None
    assert (await store.get(doc["id"], **SCOPE))["state"] == "review_required"
    await counters(store)


def test_factory_and_exact_signatures():
    assert isinstance(get_attachment_store("sqlite:///:memory:"), AttachmentStore)
    assert isinstance(get_attachment_store("postgresql://localhost/unused"), PostgreSQLAttachmentStore)
    with pytest.raises(StoreError, match="configuration_error"):
        get_attachment_store("bad://password")
    expected = {
        "__init__": ["self", "db", "max_documents", "max_bytes", "max_per_tenant", "ttl_seconds"],
        "initialize": ["self"], "close": ["self"], "create": ["self", "tenant", "agent", "owner", "mime", "raw", "policy_revision"],
        "get": ["self", "id", "tenant", "agent", "owner"],
        "delete": ["self", "id", "tenant", "agent", "owner"],
        "claim": ["self", "lease_seconds"],
        "finish": ["self", "id", "token", "state", "text", "reason"],
        "resolve": ["self", "id", "tenant", "agent", "owner", "policy_revision"],
    }
    for name, names in expected.items():
        method = getattr(AttachmentStore, name)
        assert list(inspect.signature(method).parameters) == names
        if name != "__init__":
            assert inspect.iscoroutinefunction(method)
    for name, first_keyword in {"create": "tenant", "get": "tenant", "delete": "tenant", "claim": "lease_seconds", "finish": "state", "resolve": "tenant"}.items():
        parameters = list(inspect.signature(getattr(AttachmentStore, name)).parameters.values())
        boundary = next(i for i, p in enumerate(parameters) if p.name == first_keyword)
        assert all(p.kind == inspect.Parameter.KEYWORD_ONLY for p in parameters[boundary:])
        assert all(p.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD for p in parameters[:boundary])
    signature = inspect.signature(AttachmentStore)
    assert [p.default for p in list(signature.parameters.values())[1:]] == [100, 32 * 1024 * 1024, 20, 3600]
    assert list(inspect.signature(get_attachment_store).parameters) == ["url", "limits"]
    assert inspect.signature(AttachmentStore.claim).parameters["lease_seconds"].default == 120
    assert inspect.signature(AttachmentStore.finish).parameters["text"].default is None
    assert inspect.signature(AttachmentStore.finish).parameters["reason"].default == ""
    assert inspect.signature(AttachmentStore.create).parameters["tenant"].kind == inspect.Parameter.KEYWORD_ONLY
    assert all(" REAL " not in sql for sql in POSTGRESQL_V1)
    assert "DOUBLE PRECISION" in POSTGRESQL_V1[0]
    assert len(POSTGRESQL_V1) == len(SQLITE_V1)


@pytest.mark.parametrize("url", [
    "sqlite+cipher:///private.db?key=secret", "sqlite+aiosqlite:///private.db",
    "sqlite-invalid:///private.db", "sqlite://private.db", "sqlite", "",
    "postgresql+unsupported://user:secret@localhost/db", "postgresql-invalid://localhost/db",
    "mysql://user:secret@localhost/db", "file:///private.db", None,
])
def test_factory_rejects_cipher_and_unsupported_schemes_before_engine_creation(monkeypatch, url):
    def unexpected_engine(_url):
        pytest.fail("Rejected URL reached engine creation")

    monkeypatch.setattr("src.attachments.store.create_engine", unexpected_engine)
    with pytest.raises(StoreError, match="^configuration_error$"):
        get_attachment_store(url)


@pytest.mark.parametrize("url", ["sqlite:///:memory:", "postgresql://localhost/db", "postgresql+asyncpg://localhost/db", "postgres://localhost/db"])
def test_factory_supported_schemes(url):
    store = get_attachment_store(url)
    assert isinstance(store, AttachmentStore)
    assert isinstance(store, PostgreSQLAttachmentStore) == (not url.startswith("sqlite:///"))


@pytest.mark.parametrize("limits", [{"max_documents": 0}, {"max_bytes": -1}, {"max_per_tenant": True}, {"ttl_seconds": 0}, {"ttl_seconds": float("nan")}])
def test_configuration_validation(limits):
    with pytest.raises(StoreError, match="configuration_error"):
        AttachmentStore(create_engine("sqlite:///:memory:"), **limits)


async def test_factory_applies_limits():
    store = get_attachment_store("sqlite:///:memory:", max_documents=1, max_bytes=8192, max_per_tenant=1, ttl_seconds=60)
    await store.initialize()
    try:
        with pytest.raises(StoreError, match="capacity"):
            await create(store, raw=b"x" * 8192)
        doc = await create(store, raw=b"hello")
        assert doc["expires_at"] - doc["created_at"] == pytest.approx(60)
        with pytest.raises(StoreError, match="capacity"):
            await create(store, raw=b"x")
    finally:
        await store.close()
