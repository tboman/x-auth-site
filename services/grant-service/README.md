# grant-service

Grant issuance, token introspection, and the append-only audit log for
**X-Auth for Agents** (product 2). A grant is the active OAuth binding between an
install and a pooled identity; the audit log records every lifecycle event across the
platform.

See `REQUIREMENTS.md` at the repo root for the full product spec. This service owns
section 4's `grant-service` contract.

## Scope

Phase 1: in-memory, tenant-scoped storage for grants and an append-only in-memory
audit log. Storage is swappable via the `GrantStore` / `AuditStore` interfaces in
`internal/storage.go` — phase 2 will add Postgres.

### Invariants

- Tokens are **never** stored in plaintext. Callers hand us the plaintext token at
  create/introspect time; this service hashes it with SHA-256 and only holds / returns
  the hex digest.
- `status` on a Grant is **derived** at read time from `revoked_at` / `expires_at`:
  - `revoked` if `revoked_at` is set (wins over expired)
  - `expired` if `now >= expires_at`
  - `active` otherwise
- The audit log is append-only: no update, no delete endpoints. Once an event is
  written it is immutable.

## Endpoints

All `/v1/*` endpoints require the `X-Tenant-Id` header.

| Method | Path | Status codes |
|---|---|---|
| GET | `/healthz` | 200 |
| POST | `/v1/grants` | 201, 400 |
| GET | `/v1/grants/{id}` | 200, 400, 404 |
| POST | `/v1/grants/{id}/revoke` | 204, 400, 404 (idempotent) |
| POST | `/v1/introspect` | 200, 400 |
| POST | `/v1/audit` | 201, 400 |
| GET | `/v1/audit` | 200, 400 |

### Grant shape (response)

```json
{
  "id": "c2b5…",
  "tenant_id": "tenant-a",
  "install_id": "install-1",
  "identity_id": "identity-1",
  "persona_id": "persona-1",
  "access_token_hash": "3a9f…",
  "refresh_token_hash": "8e12…",
  "issued_at": "2026-04-20T12:00:00Z",
  "expires_at": "2026-04-20T12:15:00Z",
  "revoked_at": null,
  "status": "active"
}
```

### Introspection (RFC 7662)

- Active: `{ "active": true, install_id, identity_id, persona_id, tenant_id, iat, exp }`
- Inactive / unknown / expired / revoked / cross-tenant: `{ "active": false }`

A token belonging to tenant B presented with tenant A's `X-Tenant-Id` header returns
`active: false` — the endpoint never leaks the existence or details of another
tenant's grant.

### Audit query parameters

- `install_id` — filter by install
- `grant_id` — filter by grant
- `type` — filter by event type
- `since` (RFC3339, inclusive) — events at or after this time
- `until` (RFC3339, exclusive) — events strictly before this time
- `limit` — default 100, max 1000

Results are sorted by `created_at` descending (most recent first).

## Run locally

From the repo root:

```bash
go run ./services/grant-service/cmd
# listens on :8183 by default, or $PORT if set
```

Run tests:

```bash
go test ./services/grant-service/...
```

## Example cURL round-trip

```bash
# 1. Create grant (server hashes the tokens; response carries hashes only)
curl -sX POST http://localhost:8183/v1/grants \
  -H 'X-Tenant-Id: tenant-a' \
  -H 'Content-Type: application/json' \
  -d '{
        "install_id":"install-1",
        "identity_id":"identity-1",
        "persona_id":"persona-1",
        "access_token":"tok-abc-123",
        "refresh_token":"ref-xyz-789",
        "ttl_seconds":900
      }'
# -> 201 {"id":"<GRANT_ID>", ..., "status":"active"}

# 2. Introspect — active
curl -sX POST http://localhost:8183/v1/introspect \
  -H 'X-Tenant-Id: tenant-a' \
  -H 'Content-Type: application/json' \
  -d '{"token":"tok-abc-123"}'
# -> {"active":true,"install_id":"install-1", ...}

# 3. Revoke (idempotent)
curl -sX POST http://localhost:8183/v1/grants/<GRANT_ID>/revoke \
  -H 'X-Tenant-Id: tenant-a'
# -> 204

# 4. Introspect — inactive
curl -sX POST http://localhost:8183/v1/introspect \
  -H 'X-Tenant-Id: tenant-a' \
  -H 'Content-Type: application/json' \
  -d '{"token":"tok-abc-123"}'
# -> {"active":false}

# 5. Query audit — grant_issued + grant_revoked
curl -s "http://localhost:8183/v1/audit?install_id=install-1" \
  -H 'X-Tenant-Id: tenant-a'
# -> {"items":[{"type":"grant_revoked", ...},{"type":"grant_issued", ...}]}
```

## Build the container

```bash
docker build -f services/grant-service/Dockerfile -t grant-service .
docker run --rm -p 8080:8080 grant-service
```
