# Tenant Deployment Runbook

## Safety Boundary

Use a dedicated SharePoint site containing only synthetic lab documents.

Do not upload the poisoned test documents into an existing business or collaboration site.

## Prepare

Run:

```powershell
.\scripts\prepare-dev-env.ps1
```

Then edit `env/.env.dev` and set:

```text
SHAREPOINT_SITE_URL
API_BASE_URL
```

## SharePoint

Create a private site such as:

```text
/sites/AI-Security-Lab
```

Upload only the six files listed in:

```text
deployment/sharepoint-content-manifest.json
```

## API Runtime Settings

Provide these through secure runtime configuration:

```text
ENTRA_TENANT_ID
ENTRA_API_CLIENT_ID
ENTRA_REQUIRED_SCOPE=access_as_user
ENTRA_ALLOWED_CLIENT_IDS
SECURELAB_DB_PATH
```

## Provision

```text
atk doctor
atk validate --env dev
atk provision --env dev
```

Provisioning creates a single-tenant Entra app, applies the delegated scope and SecureLab app roles, registers OAuth with PKCE, validates the app package, and extends the app to Microsoft 365.

## Assign Test Roles

```text
SecureLab.ReadOnly
SecureLab.SecurityAnalyst
SecureLab.AccessRequest
SecureLab.HumanApprover
```

Use different identities for requester and approver tests.

## First Validation

1. Confirm clean SharePoint grounding works.
2. Read INC-1001.
3. Add a bounded note as Security Analyst.
4. Confirm privileged requests return HOLD_FOR_APPROVAL.
5. Confirm self-approval is blocked.
6. Approve with a different Human Approver identity.
7. Confirm GET /audit/verify reports a valid chain.
8. Run the seven live cases in evals/evals.json.
