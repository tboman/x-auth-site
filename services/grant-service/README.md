# grant-service

Grant issuance, token introspection, and the append-only audit log for
**X-Auth for Agents** (product 2). A grant is the active OAuth binding between an
install and a pooled identity; the audit log records every lifecycle event across the
platform.

See `REQUIREMENTS.md` at the repo root for the full product spec. This service owns
section 4's `grant-service` contract.

## Scope

Tenant-scoped grant store plus an append-only audit log. Storage is swappable via
the `GrantStore` / `AuditStore` interfaces in `internal/storage.go`:

- **`MemGrantStore` / `MemAuditStore`** — phase-1 in-memory implementations. Used
  when `PG_DSN` is unset (developer laptops, unit tests, short-lived CI).
- **`PGStorage`** — phase-2 Postgres implementation of both interfaces (see
  `docs/postgres.md`; migrations live in `services/grant-service/migrations/`).

### Invariants

- Tokens are **never** stored in plaintext. Callers hand us the plaintext token at
  create/introspect time; this service hashes it with SHA-256 and only holds / returns
  the hex digest.
- `status` on a Grant is **derived** at read time from `revoked_at` / `expires_at`:
  - `revoked` if `revoked_at` is set (wins over expired)
  - `expired` if `now >= expires_at`
  - `active` otherwise
- The audit log is append-only: no update, no delete endpoints. Once an event is
  written it is immutable. The Postgres backend issues no UPDATE/DELETE against
  `audit_events`; GDPR erasure is handled by pseudonymization, not row deletion.

## Endpoints

All `/v1/*` endpoints require the `X-Tenant-Id` header.

| Method | Path | Status codes |
|---|---|---|
| GET | `/healthz` | 200 |
| POST | `/v1/grants` | 201, 400 |
| GET | `/v1/grants/{id}` | 200, 400, 404 |
| POST | `/v1/grants/{id}/revoke` | 204, 400, 404 (idempotent) |
| POST | `/v1/installs/{install_id}/revoke-grants` | 200, 400 (cascade, idempotent) |
| POST | `/v1/revoke` | 200, 400 (RFC 7009 revoke-by-token; unknown token → silent 200) |
| POST | `/v1/introspect` | 200, 400 |
| POST | `/v1/audit` | 201, 400 |
| GET | `/v1/audit` | 200, 400 |

### `/internal/v1/` — service-to-service tree (ARCHITECTURE.md §10.3)

The **entire** `/v1` route tree above is also mounted under `/internal/v1/`
(same handlers, same store) behind `httpx.InternalAuth`. A request to the
internal tree is accepted when either:

1. it arrived over **mTLS** with a client certificate verified against
   `TLS_CLIENT_CA_FILE`, or
2. `INTERNAL_AUTH_SECRET` is set and the request carries a matching
   `X-Internal-Auth` header (constant-time compare).

With neither mechanism configured the internal tree is open — local-dev mode.
Once either is configured, unauthenticated internal requests get a structured
`401 {"error":"internal_auth_required"}`.

Sister services call the internal tree; broker-service specifically calls:

- `POST /internal/v1/grants` — issue a grant during install binding
- `POST /internal/v1/installs/{id}/revoke-grants` — install-revoke cascade
- `POST /internal/v1/revoke` — RFC 7009 token revocation forwarded from the
  broker's public `/revoke`

`/v1/*` stays mounted **without** the internal-auth guard for phase-1
back-compat; it will be retired once every caller has moved to
`/internal/v1/`.

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

## Environment

| Var | Default | Notes |
|---|---|---|
| `PORT` | `8183` | |
| `PG_DSN` | _(unset)_ | When set, phase-2 Postgres storage. Unset -> in-memory. |
| `PG_DSN_GRANT_SERVICE` | _(unset)_ | Per-service override of `PG_DSN`. |
| `PG_MAX_CONNS` | `10` | Pool ceiling. |
| `GRANT_PG_DSN` | _(unset)_ | DSN used by the `TestPG*` integration tests. Unset -> tests skip. |
| `TLS_CERT_FILE` | _(unset)_ | PEM certificate the server presents. Set together with `TLS_KEY_FILE` to serve HTTPS; setting only one is a fatal startup error. Both unset -> plaintext (dev). |
| `TLS_KEY_FILE` | _(unset)_ | PEM private key for `TLS_CERT_FILE`. |
| `TLS_CLIENT_CA_FILE` | _(unset)_ | CA bundle; when set the server **requires and verifies** client certificates (mTLS). Verified peers pass `InternalAuth` without the shared-secret header. |
| `INTERNAL_AUTH_SECRET` | _(unset)_ | Shared secret for `/internal/v1/*` when mTLS is not in play. Callers send it in `X-Internal-Auth`; mismatch/absence -> 401. Unset (and no mTLS) -> internal tree open (dev). |

## Run locally

Without Postgres (in-memory fallback):

```bash
go run ./services/grant-service/cmd
# listens on :8183 by default, or $PORT if set; grants and audit log are ephemeral
```

With Postgres (phase 2):

```bash
# 1. Start Postgres
docker run --rm -d --name xauth-pg \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=grant_db -p 5432:5432 postgres:16

# 2. Apply the migration (choose one)
migrate -path services/grant-service/migrations \
        -database "postgres://postgres:postgres@localhost:5432/grant_db?sslmode=disable" up
# or:
psql "postgres://postgres:postgres@localhost:5432/grant_db?sslmode=disable" \
     -f services/grant-service/migrations/000001_init.up.sql

# 3. Run the service
PG_DSN="postgres://postgres:postgres@localhost:5432/grant_db?sslmode=disable" \
  go run ./services/grant-service/cmd
```

Run tests (unit only, no DB needed):

```bash
go test ./services/grant-service/...
```

Run PG-backed integration tests too:

```bash
GRANT_PG_DSN="postgres://postgres:postgres@localhost:5432/grant_db?sslmode=disable" \
  go test ./services/grant-service/... -run PG
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
