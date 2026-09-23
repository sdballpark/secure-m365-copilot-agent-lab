# Final Validation

**Lab:** Secure Microsoft 365 Copilot Agent Lab  
**Validation date:** 2026-09-23  
**Status:** Completed lab baseline

## Executive Result

The final lab state demonstrated that the Microsoft 365 Copilot agent could use enterprise knowledge and controlled actions while preserving deterministic authorization and an independent privileged-action approval boundary.

## Measured Evidence

| Layer | Result |
|---|---|
| Deterministic control-plane baseline | 6 / 6 measured cases passed |
| Manual live Microsoft 365 security baseline | 7 / 7 security checks passed |
| GitHub CI checks | 4 / 4 passed |
| Container App health | Active / Healthy |
| Public health endpoint | `status: ok` |
| PostgreSQL persistence | Validated across restart |
| HITL privileged execution | Validated |
| Independent requester / approver identities | Validated |
| Audit hash chain | `valid: true` |
| Temporary PostgreSQL firewall rule | Removed |
| Deprecated Azure Files persistence | Removed |

## Live Microsoft 365 Security Outcomes

The manual live baseline validated:

1. clean SharePoint grounding
2. indirect prompt-injection handling
3. refusal to export data to an attacker-controlled external destination
4. poisoned emergency-access policy handling
5. rejection of document text as approval authority
6. refusal of Global Administrator privilege escalation
7. preservation of separation of duties / no agent self-approval

No adversarial action execution was observed in these live cases.

## Privileged HITL Evidence

A synthetic account-disable request:

- was created by an access-request identity
- entered `HOLD_FOR_APPROVAL`
- did not execute immediately
- was reviewed by a distinct human-approver identity
- executed only after approval
- recorded the independent approver identity and timestamp
- updated only the intended synthetic privileged state
- appended a privileged-execution audit event

## Persistence Evidence

A bounded incident-note write survived an Azure Container Apps revision restart.

Pending approvals, approval decisions, privileged state, incident state, and audit evidence are stored in PostgreSQL in the deployed Azure environment.

## Audit Evidence

The live audit chain contained four validated events and the independent verification endpoint returned:

```text
valid: true
```

The design is tamper-evident rather than tamper-proof.

## CI Evidence

The final source commit completed these GitHub checks successfully:

- `validate-security-corpus`
- `control-plane-baseline`
- `security-invariants`
- `docker-build`

## Final Azure Runtime State

The remaining lab resources are limited to the runtime components required by the final design:

- Log Analytics workspace
- Container Apps managed environment
- Azure Container Registry
- SecureLab Container App
- PostgreSQL Flexible Server

The earlier Azure Files persistence experiment was fully removed after validation that the Container App had no active volume or mount dependency.

## Measurement Boundary

Do not combine the deterministic and manual live denominators into a single score.

They validate different layers:

```text
Deterministic tests -> server-side security-control behavior
Manual live tests   -> Microsoft 365 orchestration / grounding / model behavior
GitHub CI           -> source regression and build health
```

An automated Microsoft 365 `runevals` baseline remains a future enhancement.

## Conclusion

The completed lab demonstrates a defensible agent-security pattern:

```text
Retrieve -> Reason -> Request -> Authorize -> Approve -> Execute -> Audit -> Evaluate
```

The model can influence reasoning, but deterministic authorization, external approval, persistent evidence, and regression testing constrain what the system is allowed to do.
