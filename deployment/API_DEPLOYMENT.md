# SecureLab API Deployment

## Container

The repository contains a production-shaped lab container:

```text
Dockerfile
```

It runs:

```text
uvicorn api.main:app --host 0.0.0.0 --port 8000 --proxy-headers
```

as a non-root `securelab` user.

## Runtime Secrets and Settings

Do not bake tenant configuration into the image.

Provide these at runtime:

```text
ENTRA_TENANT_ID
ENTRA_API_CLIENT_ID
ENTRA_REQUIRED_SCOPE=access_as_user
ENTRA_ALLOWED_CLIENT_IDS
SECURELAB_PGHOST
SECURELAB_PGDATABASE
SECURELAB_PGUSER
SECURELAB_PGPASSWORD
SECURELAB_PGPORT=5432
SECURELAB_PGSSLMODE=require
```

The Azure-hosted lab uses Azure Database for PostgreSQL Flexible Server for durable incident, approval, privileged-state, and audit records. SQLite remains the local/test fallback when `SECURELAB_PGHOST` is not configured.

## HTTPS

Microsoft 365 action calls must target an HTTPS endpoint.

Terminate TLS at the hosting platform or ingress layer.

Set:

```text
API_BASE_URL=https://<public-hostname>
```

in the Agents Toolkit environment file.

## Health

Unauthenticated health endpoint:

```text
GET /health
```

The container health check calls only that endpoint.

## Azure Container Apps Mapping

A straightforward lab deployment can use Azure Container Apps with:

- external HTTPS ingress,
- target port 8000,
- minimum replicas 1,
- secret-backed environment variables,
- Azure Database for PostgreSQL Flexible Server with TLS required.

Azure Files is not used for the SQLite database because SMB file-locking semantics caused `sqlite3.OperationalError: database is locked` during container startup. For a production architecture, also export audit events to a separately administered immutable logging destination.

## Local Container Check

```text
docker build -t secure-m365-copilot-agent-lab .
docker run --rm -p 8000:8000 \
  -e ENTRA_TENANT_ID=<tenant-guid> \
  -e ENTRA_API_CLIENT_ID=<client-guid> \
  -e ENTRA_ALLOWED_CLIENT_IDS=<client-guid> \
  secure-m365-copilot-agent-lab
```

Then:

```text
http://localhost:8000/health
```

No secrets should be committed to Git.
