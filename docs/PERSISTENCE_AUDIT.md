# Persistent State and Audit Integrity

## Objective

The lab persists operational state in PostgreSQL for the deployed Azure environment
and maintains a tamper-evident, append-only audit chain.

SQLite remains available as the local/test fallback backend so the same security
logic can be exercised without requiring a cloud database.

This moves the design beyond process-local Python lists and allows:

- incidents to survive restart,
- approval requests to survive restart,
- privileged execution state to survive restart,
- security decisions to remain reviewable,
- modification of historical audit rows to be detected.

## Database

The deployed Azure API uses Azure Database for PostgreSQL Flexible Server.

When `SECURELAB_PGHOST` is present, the storage backend uses PostgreSQL with:

```text
SECURELAB_PGHOST
SECURELAB_PGDATABASE
SECURELAB_PGUSER
SECURELAB_PGPASSWORD
SECURELAB_PGPORT
SECURELAB_PGSSLMODE
```

The deployed environment requires TLS with `SECURELAB_PGSSLMODE=require`.

If PostgreSQL configuration is not present, the application falls back to SQLite
for local development and tests using:

```text
SECURELAB_DB_PATH
```

with the default:

```text
.local/securelab.db
```

The `.local/` directory is ignored by Git. Unit tests may use temporary or
in-memory SQLite databases.

## Stored State

The storage backend contains:

```text
incidents
incident_notes
approvals
privileged_state
audit_events
```

The lab still uses synthetic data only.

## PostgreSQL Concurrency Control

PostgreSQL audit appends are serialized with a transaction-scoped advisory lock
before the current chain head is read and the next event is written. This prevents
concurrent writers from creating two events from the same previous hash.

## Append-Only Audit Chain

Every security event is serialized into canonical JSON.

For event N:

```text
event_hash_N =
    SHA256(
        event_hash_N-1
        +
        canonical_event_JSON_N
    )
```

The first record uses a 64-character zero hash as the genesis previous hash.

Each row therefore stores:

```text
sequence
timestamp
event_json
prev_hash
event_hash
```

## What the Hash Chain Provides

If an older audit event is modified without recomputing the rest of the chain,
verification fails.

The lab exposes an independent-control-plane endpoint:

```text
GET /audit/verify
```

Only the human-approver control-plane role may call this endpoint.

## What the Hash Chain Does Not Provide

A local hash chain is **tamper-evident**, not fully tamper-proof.

An attacker with unrestricted database and application control could rewrite the
entire database and recompute every hash.

A production architecture should export audit evidence to an external,
append-only or immutable destination such as:

- a SIEM,
- immutable object storage,
- a write-once audit service,
- a separately administered logging account.

The lab intentionally makes this limitation explicit.

## Restart Safety

The following security state is restart-safe:

- pending approvals,
- approval decisions,
- privileged execution state,
- synthetic incident notes and status,
- audit evidence.

The approval service reloads original server-stored action arguments after
restart. An approver cannot substitute a new action or target during approval.

## Security Invariant

> A restart must not erase a pending privileged request or erase the evidence
> that produced it.

> Historical audit mutation must be detectable by chain verification.


## Live Validation Evidence

The deployed Microsoft 365-to-Azure path was validated with PostgreSQL-backed state:

- a synthetic incident note was written through Microsoft 365 Copilot and survived
  an Azure Container Apps revision restart;
- a privileged account-disable request entered `HOLD_FOR_APPROVAL` and remained
  pending with no execution;
- a separate Microsoft Entra identity holding only `SecureLab.HumanApprover`
  authenticated with MFA through the independent approval client;
- approval `APR-0001` executed only after independent human approval;
- PostgreSQL recorded the separate approver identity, execution timestamp, and
  execution result;
- the synthetic privileged state changed only `account_disabled` for
  `compromised@example.test`;
- `GET /audit/verify` returned `valid: true` for a four-event audit chain.

The validated chain included the original bounded write, incident read,
`HOLD_FOR_APPROVAL` gateway decision, and privileged execution event.
