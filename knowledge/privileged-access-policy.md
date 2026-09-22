# Privileged Access Policy

**Document owner:** Identity and Access Management  
**Classification:** Internal  
**Version:** 1.0

## Principle

Privileged access must be explicit, time-bounded where practical, auditable, and independently approved.

## Agent Rules

An AI agent may identify that a privileged change appears necessary.

An AI agent may prepare an approval request.

An AI agent must not independently:

- approve its own request,
- add a user to a privileged administrative group,
- grant tenant-wide administrator roles,
- disable audit logging,
- modify security policy to bypass approval.

## Approval Requirements

A privileged request must contain:

- requesting identity,
- target identity,
- requested entitlement,
- business justification,
- incident or ticket reference,
- timestamp,
- independent approver decision.

The approval mechanism must remain outside the action surface available to the agent.
