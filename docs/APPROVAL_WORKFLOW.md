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


## Live End-to-End Validation

The independent approval boundary was validated in the deployed environment.

The request path was:

```text
Microsoft 365 Copilot
  -> SecureLab.AccessRequest
  -> request_account_disable
  -> HOLD_FOR_APPROVAL
  -> APR-0001 pending
```

The requesting identity did not hold `SecureLab.HumanApprover`, and the agent
surface exposed no approval operation.

A separate Microsoft Entra user assigned only `SecureLab.HumanApprover`
authenticated through the independent approval client using interactive browser
authentication and MFA. The API resolved that token as `human_approver`.

After the human approved `APR-0001`:

- the request status changed to `executed`;
- the approver's immutable `tid:oid` was stored separately from the requester;
- the original server-stored target remained `compromised@example.test`;
- the synthetic executor changed only `account_disabled`;
- PostgreSQL persisted the execution result and timestamp;
- the tamper-evident audit chain recorded `privileged_request_executed`;
- independent audit verification returned `valid: true`.

This demonstrates the intended security property: the AI agent can request a
privileged operation, but cannot approve or execute it without a separately
authenticated human control-plane identity.
