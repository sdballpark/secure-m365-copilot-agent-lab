# Microsoft 365 Declarative Agent Setup

## Current Platform Baseline

This lab targets:

- Declarative agent manifest schema **v1.8**
- Plugin manifest schema **v2.4**
- Microsoft 365 Agents Toolkit
- Scoped OneDrive and SharePoint grounding
- OpenAPI plugin actions

The checked-in manifests are intentionally configured as a lab template.

## Files

```text
agent/
  declarativeAgent.json
  instructions.txt
  security-actions-plugin.json

api/
  openapi.yaml
```

## SharePoint Knowledge

The declarative agent currently uses this placeholder scope:

```text
https://contoso.sharepoint.com/sites/AI-Security-Lab
```

Before tenant provisioning, replace it with the dedicated lab SharePoint site that contains only synthetic knowledge documents.

Recommended upload set:

```text
knowledge/incident-response.md
knowledge/credential-theft-runbook.md
knowledge/data-handling-policy.md
knowledge/privileged-access-policy.md
knowledge/adversarial/poisoned-incident-runbook.md
knowledge/adversarial/poisoned-access-policy.md
```

The two files under `knowledge/adversarial/` are intentionally poisoned and exist to test indirect prompt injection.

Do not upload production documents to this lab site.

## API Plugin Variables

The plugin manifest contains two deployment variables:

```text
OAUTH_REFERENCE_ID
API_BASE_URL
```

`OAUTH_REFERENCE_ID` should point to a Microsoft 365 plugin-vault OAuth configuration.

`API_BASE_URL` should be the HTTPS base URL for the controlled action API.

No client secret or token should be committed to this repository.

## Identity Boundary

The current Python gateway already makes deterministic role/action decisions.

Before connecting a real Microsoft 365 tenant, the API authentication layer must validate the OAuth token and derive the requesting identity and authorization context from trusted token claims or a trusted API gateway.

Do **not** accept user identity, role, or privilege level from model-generated request parameters.

The OpenAPI contract intentionally does not expose `user_id` or `role` as model-fillable parameters.

## Provisioning Sequence

1. Create a dedicated lab SharePoint site.
2. Upload only the synthetic knowledge set.
3. Replace the placeholder SharePoint URL in `agent/declarativeAgent.json`.
4. Deploy the FastAPI service behind HTTPS.
5. Configure Entra ID / OAuth for the API.
6. Create the Microsoft 365 plugin-vault OAuth reference.
7. Set `OAUTH_REFERENCE_ID` and `API_BASE_URL` in the Agents Toolkit environment.
8. Provision the declarative agent with Microsoft 365 Agents Toolkit.
9. Run benign grounding tests.
10. Run the adversarial corpus.
11. Record measured results before making security claims.

## Security Gate Before Tenant Testing

Do not connect the declarative agent to a tenant until:

- the API validates authenticated caller identity,
- authorization context cannot be supplied by the model,
- privileged actions still return HOLD_FOR_APPROVAL,
- self-approval remains unavailable,
- denied actions are absent from the plugin manifest,
- secrets remain outside the repository.
