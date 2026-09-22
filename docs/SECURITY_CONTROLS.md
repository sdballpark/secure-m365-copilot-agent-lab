# Security Controls

## Purpose

This document maps the lab's major threats to concrete preventive, detective, and recovery controls.

The goal is to separate model behavior from security enforcement.

## Control Matrix

| ID | Control | Type | Primary Threats | Initial Implementation |
|---|---|---|---|---|
| C01 | User-context authorization | Preventive | T03, T14 | Bind action decisions to requesting identity |
| C02 | Least-privilege backend scopes | Preventive | T04, T14 | Narrow API permissions to required operations |
| C03 | Retrieved-content trust boundary | Preventive | T02, T13 | Treat knowledge as data, never authority |
| C04 | Read/write separation | Preventive | T05 | Distinct action classes and policy checks |
| C05 | Privileged-action hold | Preventive | T06 | Queue high-impact operations for approval |
| C06 | Independent human approval | Preventive | T06, T07 | Approval surface is outside agent actions |
| C07 | Denied capability omission | Preventive | T06 | Do not register prohibited operations |
| C08 | Typed action schemas | Preventive | T08 | Constrained parameter types and formats |
| C09 | Server-side validation | Preventive | T08 | Validate identifiers, URLs, and allowed values |
| C10 | Parameterized data access | Preventive | T08 | No raw concatenation into queries |
| C11 | Egress restriction | Preventive | T09 | Allowlist approved destinations |
| C12 | Secret management | Preventive | T11 | Environment variables; no secrets in Git |
| C13 | Audit logging | Detective | T05, T06, T09 | Record action intent, decision, result |
| C14 | Audit redaction | Preventive | T10 | Remove tokens, secrets, and sensitive values |
| C15 | Prompt-injection test corpus | Detective | T01, T02, T13 | Replay direct and indirect attack cases |
| C16 | Authorization regression tests | Detective | T03-T08, T14 | CI tests security invariants |
| C17 | Fail-closed defaults | Preventive | T04-T08 | Unknown role/action becomes deny |
| C18 | Synthetic test data | Preventive | T09-T11 | No production records required for lab |
| C19 | Security telemetry | Detective | T01-T09 | Capture policy decisions and abnormal attempts |
| C20 | Rollback / disable path | Recovery | T05, T06 | Disable risky actions or agent capability |

## Authorization Decision Flow

```text
Agent requests action
        |
        v
Identify requesting user
        |
        v
Resolve action classification
        |
        v
Validate arguments
        |
        v
Evaluate user + action policy
        |
   +----+---------+-----------+
   |              |           |
 READ/WRITE   PRIVILEGED    DENIED
   |              |           |
   v              v           v
Execute       Queue/Hold     Reject
   |              |           |
   +--------------+-----------+
                  |
                  v
             Audit event
```

## Action Policy

### READ

Examples:

- retrieve synthetic incident information,
- search approved security knowledge,
- obtain non-sensitive lab status.

Expected behavior:

- executes if the user is authorized,
- inputs are validated,
- result is logged at appropriate detail.

### WRITE

Examples:

- create a synthetic incident note,
- update a lab ticket state.

Expected behavior:

- explicit write permission is required,
- allowed fields are constrained,
- action is audited,
- no implicit privilege escalation.

### PRIVILEGED

Examples:

- change access membership,
- alter a security-sensitive entitlement,
- modify a high-impact policy.

Expected behavior:

- action does not execute directly,
- agent creates an approval request,
- independent human approval is required,
- approver identity is logged.

### DENIED

Examples:

- destructive identity lifecycle operations,
- unrestricted role elevation,
- disabling security controls,
- modifying audit records.

Expected behavior:

- action is not exposed to the agent,
- requests for the capability fail closed.

## Prompt-Injection Controls

Prompt-injection defenses are layered.

### Layer 1 - Instruction Design

Agent instructions state that retrieved content is untrusted and must not override system or developer policy.

This is useful but is not treated as a security boundary.

### Layer 2 - Capability Restriction

Even if model reasoning is manipulated, the available actions are intentionally constrained.

### Layer 3 - Authorization

Every action request is evaluated outside the model.

### Layer 4 - Human Approval

High-impact operations require independent approval.

### Layer 5 - Evaluation

Known direct and indirect prompt-injection attacks are replayed against the system.

## Identity and Least Privilege

The lab should enforce two levels of least privilege:

1. **User authorization** - the requesting user must be permitted to perform the requested operation.
2. **Backend credential scope** - the service credential itself should not possess unnecessary capability.

A bug in application authorization should not automatically become full tenant compromise.

## Logging Requirements

Audit events should capture enough information to reconstruct:

- who requested the action,
- which agent requested it,
- which action was requested,
- the policy decision,
- whether approval was required,
- who approved or denied,
- execution result,
- timestamp,
- correlation identifier.

Logs should not become a second secrets repository.

Sensitive values should be redacted or minimized.

## CI Security Gates

The repository should eventually block or flag changes when critical invariants fail.

Initial gating tests should include:

```text
test_unauthorized_user_cannot_read_restricted_data
test_retrieved_prompt_cannot_authorize_action
test_write_requires_write_permission
test_privileged_action_does_not_execute_directly
test_agent_cannot_self_approve
test_denied_action_is_not_registered
test_invalid_action_arguments_are_rejected
test_secret_patterns_are_not_committed
```

## Measurement

Security results should be reported with explicit denominators.

Examples:

```text
Indirect prompt injection blocked: 47 / 50
Unauthorized actions prevented: 20 / 20
Privileged actions executed without approval: 0 / 25
False refusals on benign cases: 2 / 50
```

No benchmark number should be presented until it has actually been produced by the lab.

## Control Philosophy

The architecture assumes that the model can eventually be manipulated.

Therefore the strongest controls live outside model reasoning:

- authorization,
- capability exposure,
- credential scope,
- validation,
- human approval,
- egress policy,
- audit,
- regression testing.
