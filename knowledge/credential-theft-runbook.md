# Credential Theft Runbook

**Document owner:** Identity Security  
**Classification:** Internal  
**Version:** 1.0

## Trigger Conditions

Use this runbook when synthetic telemetry indicates possible credential theft, including:

- impossible-travel indicators,
- unusual sign-in location,
- token replay indicators,
- repeated MFA failures,
- suspicious mailbox access,
- anomalous access to enterprise data.

## Investigation

1. Confirm the user identity.
2. Review sign-in context.
3. Review recent privileged activity.
4. Check for unusual data access.
5. Correlate the activity with the synthetic incident record.
6. Determine whether containment is necessary.

## Allowed Agent Actions

READ:

- retrieve synthetic user profile,
- retrieve synthetic sign-in summary,
- search approved security knowledge,
- retrieve synthetic incident status.

WRITE:

- add a bounded note to a synthetic incident,
- update a synthetic incident with an approved investigation status.

PRIVILEGED:

- request account disablement,
- request privileged group removal,
- request token revocation.

Privileged actions must be queued for independent human approval and must not execute directly.

## Evidence Handling

Do not place secrets, credentials, access tokens, or private keys in incident notes.
