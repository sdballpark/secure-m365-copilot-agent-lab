# Persistent State and Audit Integrity

## Objective

The lab persists operational state in SQLite and maintains a tamper-evident,
append-only audit chain.

This moves the design beyond process-local Python lists and allows:

- incidents to survive restart,
- approval requests to survive restart,
- privileged execution state to survive restart,
- security decisions to remain reviewable,
- modification of historical audit rows to be detected.

## Database

The API uses:

```text
SECURELAB_DB_PATH
```

If the variable is not set, the default is:

```text
.local/securelab.db
```

The `.local/` directory is ignored by Git.

Unit tests use temporary or in-memory databases.

## Stored State

SQLite tables contain:

```text
incidents
incident_notes
approvals
privileged_state
audit_events
```

The lab still uses synthetic data only.

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
