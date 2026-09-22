# Independent Human Approval Workflow

## Objective

Privileged actions must cross an authorization boundary that the AI agent cannot control.

The workflow is:

```text
Microsoft 365 Copilot
        |
        v
Privileged action request
        |
        v
Deterministic gateway
        |
        v
HOLD_FOR_APPROVAL
        |
        v
Pending approval queue
        |
        +-------------------+
        |                   |
        v                   v
Independent human        Independent human
APPROVE                  DENY
        |                   |
        v                   v
Allowlisted executor     Close request
        |
        v
Synthetic privileged change
        |
        v
Audit event
```

## Separation of Duties

The requesting agent role is:

```text
SecureLab.AccessRequest
```

The independent human approval role is:

```text
SecureLab.HumanApprover
```

The agent plugin does not expose approval functions.

A human approver may access the approval API, but a privileged request still cannot be approved by the same immutable `tid:oid` identity that created it.

## State Model

Approval requests move through these states:

```text
pending
   |
   +---- deny ----> denied
   |
   +---- approve ----> approved ----> executed
```

A request that is no longer `pending` cannot be decided a second time.

## Privileged Executor

Only these synthetic actions are currently allowlisted:

- account disablement,
- privileged group membership removal,
- token revocation.

The executor accepts the original server-stored approval request.

It does not accept a new action name or new target supplied by the approver at execution time.

That preserves the integrity of what was actually reviewed.

## Self-Approval Protection

Self-approval is blocked with the immutable caller key:

```text
{tid}:{oid}
```

The system compares the authenticated approver identity to the original requesting identity.

Display name and email are not used for this security decision.

## Audit Evidence

The audit chain records:

- original requester,
- action,
- correlation ID,
- approval ID,
- approver identity,
- approve/deny decision,
- execution state.

## Agent Isolation

The Copilot-facing plugin manifest intentionally contains no function for:

- approving requests,
- denying requests,
- executing privileged operations directly.

Approval is a separate human control plane.
