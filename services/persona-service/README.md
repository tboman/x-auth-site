# persona-service

Persona CRUD for **X-Auth for Agents** (product 2). A persona is a pre-authorized bundle
of OAuth scopes and claims that a tenant's security team defines up-front. Human admins
pick a persona at MCP install time; the broker-service later binds it to a pooled
identity via OIDC.

See `REQUIREMENTS.md` at the repo root for the full product spec. This service owns
section 4's `persona-service` contract.

## Scope

Phase 1: in-memory, tenant-scoped CRUD. Storage is swappable via the `Storage` interface
in `internal/storage.go` — phase 2 will add Postgres.

## Endpoints

All `/v1/*` endpoints require the `X-Tenant-Id` header. Tenancy is enforced at the
storage layer: a persona created under tenant A is invisible (404) to tenant B.

| Method | Path | Status codes |
|---|---|---|
| GET | `/healthz` | 200 |
| POST | `/v1/personas` | 201, 400 |
| GET | `/v1/personas` | 200, 400 |
| GET | `/v1/personas/{id}` | 200, 400, 404 |
| PATCH | `/v1/personas/{id}` | 200, 400, 404 |
| DELETE | `/v1/personas/{id}` | 204, 400, 404 |

### Persona shape

```json
{
  "id": "c2b5…",
  "tenant_id": "tenant-a",
  "name": "analytics-reader",
  "scopes": ["read:reports"],
  "claims": {"role": "analyst"},
  "token_ttl_seconds": 900,
  "created_at": "2026-04-20T12:00:00Z",
  "updated_at": "2026-04-20T12:00:00Z"
}
```

- `name` — required, 1-100 chars
- `scopes` — optional, defaults to `[]`
- `claims` — optional free-form map
- `token_ttl_seconds` — optional, defaults to 900, max 86400
- `tenant_id` — **never** accepted in the request body; always read from `X-Tenant-Id`

## Run locally

From the repo root:

```bash
go run ./services/persona-service/cmd
# listens on :8180 by default, or $PORT if set
```

Run tests:

```bash
go test ./services/persona-service/...
```

## Example cURL round-trip

```bash
# Create
curl -sX POST http://localhost:8180/v1/personas \
  -H 'X-Tenant-Id: tenant-a' \
  -H 'Content-Type: application/json' \
  -d '{"name":"analytics-reader","scopes":["read:reports"],"claims":{"role":"analyst"}}'

# List
curl -s http://localhost:8180/v1/personas -H 'X-Tenant-Id: tenant-a'

# Get (replace $ID with the id from the create response)
curl -s http://localhost:8180/v1/personas/$ID -H 'X-Tenant-Id: tenant-a'

# Patch
curl -sX PATCH http://localhost:8180/v1/personas/$ID \
  -H 'X-Tenant-Id: tenant-a' \
  -H 'Content-Type: application/json' \
  -d '{"token_ttl_seconds":1800}'

# Delete
curl -sX DELETE http://localhost:8180/v1/personas/$ID -H 'X-Tenant-Id: tenant-a'
```

## Build the container

```bash
docker build -f services/persona-service/Dockerfile -t persona-service .
docker run --rm -p 8080:8080 persona-service
```
