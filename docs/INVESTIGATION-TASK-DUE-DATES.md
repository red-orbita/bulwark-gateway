# Investigation Task Due Dates

## Shared Contract

`TaskStore.add` and `TaskStore.set_state` validate supplied `due_at` values at the
common store boundary, before any task database read or write. The contract is
identical on SQLite TEXT and PostgreSQL TIMESTAMPTZ columns. No database engine
or codec change is required.

A deadline must be an ISO-8601 date and time including seconds and an explicit
timezone (`Z` or a numeric offset). Fractional seconds are optional, up to six
digits. Surrounding whitespace is trimmed. The store normalizes the instant to
UTC, for example `2026-09-13T10:20:30+05:30` becomes
`2026-09-13T04:50:30+00:00`. Equivalent inputs normalize to the same value and do
not create a spurious due-date change note for newly normalized records.

Malformed dates, missing offsets, relative strings, more than six fractional
digits, invalid offset components and UTC conversion overflow are rejected with
a fixed `ValueError`, without including the submitted value. Both task routes
already translate that error to HTTP 400. Pydantic rejects wrong field types or
strings longer than the existing 64-character request bound with HTTP 422. The
same length bound also applies to callers using the store directly.

## Empty Values

| Operation | Input | Meaning |
|-----------|-------|---------|
| Create | omitted, null, empty or whitespace | No deadline (SQL NULL) |
| Update | omitted or null | Keep the existing deadline |
| Update | empty or whitespace | Clear the deadline (SQL NULL) |

The existing route rule also remains unchanged: an update with no status,
assignee or non-null due-date field returns HTTP 400 as an empty update. To clear
a deadline, send `{"due_at": ""}`, not `{"due_at": null}`.

## Compatibility Decision

Date-only and naive datetimes previously passed through SQLite as arbitrary
strings. They were not a portable timestamp contract: PostgreSQL rejects them
for TIMESTAMPTZ. Existing task tests do not specify date-only/naive deadlines,
and the task UI does not submit a due-date field. There is no tenant/operator
timezone or end-of-day policy at this boundary.

These ambiguous inputs are therefore explicitly rejected rather than silently
assigning UTC, local time, or midnight. Clients must provide an explicit offset.
This tightens previously permissive SQLite behavior. Existing persisted SQLite
values are not migrated or reinterpreted; they remain readable, and a user can
replace them with a valid deadline or clear them. A status-only update continues
to preserve an existing deadline.

## Verification

Focused tests: `tests/test_investigation_task_due_dates.py`.

```bash
python -m pytest tests/test_investigation_task_due_dates.py -q --tb=short -p no:cacheprovider
BULWARK_DB_REVIEW_LIVE=1 python -m pytest tests/test_investigation_task_due_dates.py -q --tb=short -p no:cacheprovider
```

Tests cover create/update normalization, equivalent instants, journal behavior,
null/empty/omitted values, pre-DB validation, route HTTP 400 mapping and rejection
without partial status/assignee changes. Route tests call the handlers directly;
they do not use existing endpoints or claim HTTP authentication coverage.

The live tests reuse the cached-image-only TLS lab fixture without changing it,
provisioning a unique PostgreSQL container, internal network and loopback relay.
They run real migrations against throwaway PostgreSQL and SQLite databases,
never the operator's database. Record actual execution and cleanup results for
the revision tested; skipped live fixtures are not PostgreSQL parity evidence.
