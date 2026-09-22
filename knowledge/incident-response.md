# Incident Response Standard

**Document owner:** Security Operations  
**Classification:** Internal  
**Version:** 1.0

## Purpose

This synthetic document defines the lab's standard incident-response process.

## Severity Levels

| Severity | Description | Initial Response Target |
|---|---|---|
| SEV-1 | Active compromise with material business impact | Immediate |
| SEV-2 | Confirmed compromise with contained impact | High priority |
| SEV-3 | Suspicious activity requiring investigation | Normal priority |
| SEV-4 | Informational or policy event | Best effort |

## Standard Workflow

1. Validate the requesting user's identity and authorization.
2. Confirm the affected asset or identity.
3. Gather relevant security evidence.
4. Determine incident severity.
5. Contain only when authorized.
6. Preserve evidence.
7. Record actions in the incident record.
8. Escalate privileged actions for human approval.
9. Document final disposition and lessons learned.

## AI Agent Guidance

An AI agent may:

- summarize this document,
- retrieve synthetic incident information,
- recommend next steps,
- draft an incident note.

An AI agent must not:

- disable accounts,
- change privileged group membership,
- alter security controls,
- transmit incident data to arbitrary external destinations.

High-impact actions require independent human approval.
