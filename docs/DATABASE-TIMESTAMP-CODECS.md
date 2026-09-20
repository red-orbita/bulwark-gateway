# Type-Directed PostgreSQL Timestamps

## Rationale

`QueryTranslator` previously converted every ISO-looking parameter to `datetime`,
including TEXT titles, tenants and observable values. Removing that conversion
alone would break existing stores that send ISO strings to real TIMESTAMPTZ
columns. SQL parsing, column-name heuristics and a schema map in the translator
would duplicate PostgreSQL's own type resolution and miss expressions/casts.

The engine now registers asyncpg codecs for the `pg_catalog.timestamp` and
`pg_catalog.timestamptz` types. PostgreSQL resolves each bound parameter's type;
only a timestamp parameter invokes these encoders. TEXT retains its normal codec
and every string is passed unchanged by the translator. No schema migration or
store-by-store conversion is required. Persisted JSON-wrapped text in attachment
and outbox stores is deliberately unchanged.

## Contract

- `timestamp` accepts a naive `datetime` or validated naive ISO datetime string.
- `timestamptz` accepts an offset-aware `datetime` or validated ISO datetime string
  with `Z` or an explicit numeric offset. It preserves the instant, returning UTC.
- Aware input for `timestamp` and naive input for `timestamptz` are rejected. No
  offset is discarded, and neither process nor session timezone is assumed.
  This intentionally removes asyncpg's possible local-time assumption for native
  naive timestamptz values. Existing stores use offset-aware timestamps.
- String inputs require an explicit date and time including seconds, with a `T`
  or space separator and at most six fractional digits. Invalid dates, relative
  literals (`now`), date-only strings and excess precision are rejected rather
  than normalized or silently truncated. Native datetime inputs remain supported.
- NULL is handled by asyncpg without invoking the codec. Decoders return native
  datetime values; `_pg_row` retains the existing ISO-string store/API contract.
  PostgreSQL infinity reads retain asyncpg's `datetime.min`/`datetime.max`
  representation. Finite values outside Python's datetime range are unsupported.

The codecs use asyncpg's **tuple format**, not text format. The wire value is an
integer microsecond offset from 2000-01-01 (UTC for timestamptz), calculated without
floating point. This avoids text codec dependencies on PostgreSQL `DateStyle`,
session timezone and locale. PostgreSQL still handles parameter typing, arrays
and NULLs; there is no SQL parser or blanket TEXT override.

## Lifecycle And Security

The pool's `init` callback installs codecs on every physical connection, including
pool growth and reconnection. Direct synchronous operations install the same
codecs inside their connection-closing `try/finally`; transactions inherit their
pool connection's codecs. Registration failure cannot execute a query with a
partially configured connection. Pool setup and direct codec setup diagnostics
are generic and suppress exception chaining. The synchronous event-loop bridge
no longer retries a completed coroutine when its operation raises RuntimeError.

The shared TLS builder remains authoritative for pooled and direct connections:
verify-full validates chain and hostname, verify-ca validates the chain, require
encrypts without certificate verification, and disable explicitly disables TLS.
Unknown override modes fail closed; enabled TLS has a TLS 1.2 minimum. Without an
engine override, asyncpg retains its DSN/environment TLS configuration.

Ordinary driver query errors are not globally replaced: stores rely on SQLSTATE
for unique/FK conflict handling. Such errors can include parameter previews and
must not be sent to clients or logged verbatim by callers. Codec validation
messages themselves contain no input values.

## Verification

Offline tests (no operator database fixture):

```bash
python -m pytest tests/test_storage_database_review.py tests/telemetry/test_shared_outbox_postgres.py -q -p no:cacheprovider
```

Explicitly authorized live tests provision only a uniquely named, cached-image
PostgreSQL instance using `scripts/validation-live-stores.py` containment helpers:

```bash
BULWARK_DB_REVIEW_LIVE=1 python -m pytest tests/test_storage_database_live.py -q --tb=short -p no:cacheprovider
```

The live fixture accepts no external DSN, removes inherited DB settings, uses
generated private credentials and verified TLS, checks actual Docker/containerd
storage against a 5 GiB reserve, and uses `--pull=never`. It removes only its
ownership-labelled container, internal network and loopback relay. Private lab
data and a sanitized report remain under ignored `shared/bulwark-validation-db-review-*`.
Existing Wazuh, Minikube and user services are not modified.

Coverage includes TEXT identifiers/predicates alongside TIMESTAMP and TIMESTAMPTZ
in pooled, direct and transaction execute/fetch-one/fetch-all paths; ISO/native
values and offsets; invalid timezone combinations; raw driver datetime decoding;
pool growth/reconnection; arrays; non-default session formatting/timezone; real
admin migrations and case/observable writes; and certificate rejection. This is
focused live parity evidence, not a claim that every admin store has been tested.

Record the actual test results, database version and cleanup outcome for the
revision being reviewed. Do not substitute historical lab counts for release
acceptance or run these tests against an operator database.
