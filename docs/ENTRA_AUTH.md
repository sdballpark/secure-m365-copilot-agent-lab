# Microsoft Entra Authentication Boundary

## Objective

The controlled action API must derive identity and authorization from a validated Microsoft Entra access token.

The AI model must never be allowed to supply its own:

- user identity,
- tenant identity,
- authorization role,
- client application identity,
- privilege tier.

## Required Environment Variables

```text
ENTRA_TENANT_ID
ENTRA_API_CLIENT_ID
ENTRA_REQUIRED_SCOPE=access_as_user
ENTRA_ALLOWED_CLIENT_IDS=<comma-separated approved client application IDs>
```

No tenant secret is required for access-token validation.

The API validates the token presented by the caller.

## Token Validation

The API validates:

- JWT signature using the tenant's Microsoft Entra signing keys,
- issuer,
- audience,
- expiration and lifetime claims,
- token version,
- tenant ID,
- immutable object ID,
- delegated scope,
- calling client application,
- SecureLab application role.

Only Microsoft identity platform v2.0 delegated-user access tokens are accepted by the initial lab.

App-only tokens are intentionally rejected.

## Immutable Caller Key

The authorization gateway receives this caller identifier:

```text
{tid}:{oid}
```

The combination of tenant ID and object ID is used instead of display name or email as the security identity.

A human-readable `preferred_username` may be retained for display but is not the authorization key.

## Delegated API Scope

Expose a delegated scope on the API app registration:

```text
access_as_user
```

The action API requires that scope in the access token's `scp` claim.

## SecureLab App Roles

Define these user app roles on the API application:

| App role value | Internal role | Maximum action tier |
|---|---|---|
| `SecureLab.ReadOnly` | `readonly_agent` | READ |
| `SecureLab.SecurityAnalyst` | `security_analyst_agent` | WRITE |
| `SecureLab.AccessRequest` | `access_request_agent` | PRIVILEGED request |

If multiple allowed roles are present, the highest mapped role is used.

Tenant-wide Microsoft Entra administrative roles are not automatically converted into SecureLab authorization.

An explicit SecureLab application-role assignment is required.

## Privileged Boundary

Even a caller with:

```text
SecureLab.AccessRequest
```

does not receive direct privileged execution.

The deterministic gateway still returns:

```text
HOLD_FOR_APPROVAL
```

for privileged actions.

Authentication proves who is calling.

App roles define the maximum permitted action tier.

Independent human approval remains a separate control.

## Client Application Allowlist

`ENTRA_ALLOWED_CLIENT_IDS` restricts which OAuth client applications may call the API.

The API validates the token's authorized-party/client claim (`azp`, with `appid` accepted as a compatibility fallback).

This prevents an otherwise valid user token obtained by an unapproved client application from silently becoming sufficient authorization.

## Local Development

Do not disable token validation in the production API path.

Unit tests exercise claim-policy logic directly with synthetic claims.

If a local development bypass is ever added, it must:

- be explicit,
- default off,
- be impossible to enable accidentally in production,
- never be used for measured security results.
