# broker-service

Public-facing entry point for **X-Auth for Agents** (product 2). The broker speaks
MCP, OAuth 2.0, OIDC, RFC 7591 Dynamic Client Registration, and Client Identifier
Metadata Document (CIMD), and orchestrates install creation by calling the three
internal sister services.

See [`REQUIREMENTS.md`](../../REQUIREMENTS.md) §4 for the full service contract.

## Purpose

When an AI chat owner installs `mcp.x-auth.com` as a tool, broker-service:

1. handles the OIDC/OAuth handshake (or the manual install fallback)
2. looks up the chosen persona in **persona-service**
3. claims a free identity from the relevant pool in **pool-service**
4. records the active grant in **grant-service**
5. returns bearer tokens to the runtime

Every bound install is tracked here and can be individually revoked, which cascades
to grant revocation and identity release.

## Storage

Storage is swappable via the `Storage` interface in `internal/storage.go`:

- **`MemStorage`** — phase-1 in-memory implementation. Used when `PG_DSN` is unset
  (developer laptops, unit tests, short-lived CI).
- **`PGStorage`** — phase-2 Postgres implementation following the shared pattern in
  [`docs/postgres.md`](../../docs/postgres.md). Schema lives in `migrations/`
  (tables: `installs`, `dcr_clients`, `auth_codes`, `tokens`). Auth codes and the
  phase-1 opaque tokens are persisted as plain rows — no Redis yet; TTLs are
  enforced at the handler layer, and a background sweeper deletes expired rows
  every `PURGE_INTERVAL` (see **Environment**) so the tables don't grow unbounded.

## Phase 1 scope

- [x] Install CRUD + revoke
- [x] Orchestration against persona/pool/grant services
- [x] OAuth/OIDC discovery documents (RFC 8414, OpenID Connect Discovery)
- [x] RFC 7591 Dynamic Client Registration (`POST /register`)
- [x] CIMD metadata document (`GET /metadata.json`)
- [x] `/authorize` auto-approve stub, `/token` code exchange, `/revoke`, `/userinfo`
- [x] MCP SSE + RPC stubs
- [x] Unit tests with mocked HTTP clients

**Deferred to phase 2** (see the `TODO(phase-2)` comments in-code):

- JWT signing / JWKS publication — phase 1 tokens are opaque UUID strings
- Real MCP protocol handling
- ~~Persistent storage~~ — landed: Postgres-backed `PGStorage` (see **Storage** above)
- Initial-access-token-gated DCR
- Service-to-service mTLS / JWT
- Scope intersection per OAuth semantics

## Endpoints

### Public OAuth / OIDC (no tenant header required)

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | liveness probe, returns `{"status":"ok"}` |
| GET | `/.well-known/oauth-authorization-server` | RFC 8414 metadata |
| GET | `/.well-known/openid-configuration` | OIDC discovery |
| POST | `/register` | RFC 7591 Dynamic Client Registration |
| GET | `/metadata.json` | CIMD document for the default X-Auth MCP client |
| GET | `/authorize` | phase-1 stub: auto-approves and redirects back with `code` |
| POST | `/token` | exchanges `code` for an opaque access + refresh token, orchestrates install finalization |
| POST | `/revoke` | RFC 7009 token revocation, forwarded to grant-service |
| GET | `/userinfo` | returns `{sub, persona, scopes, install_id}` for the bearer |

### MCP stubs (phase 1)

| Method | Path | Purpose |
|---|---|---|
| GET | `/mcp/sse` | opens SSE, emits one `ready` event, closes |
| POST | `/mcp/rpc` | echoes JSON-RPC 2.0 envelopes with a canned `{stub:true}` result |

### Install admin (tenant-scoped, `X-Tenant-Id` required)

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/installs` | manual install creation — bypasses OIDC, returns `pending` install |
| GET | `/v1/installs` | list installs newest-first; keyset pagination via `limit` (default 100, max 500) and `cursor` (RFC3339). Returns `{"installs": [...], "next_cursor": "..."}`; `next_cursor` is present only when the page is full |
| GET | `/v1/installs/{id}` | read an install (tenant-scoped) |
| POST | `/v1/installs/{id}/revoke` | mark revoked, release identity, revoke grants — idempotent |

## Phase-1 shortcuts

- **Tenant on `/authorize`**: real OIDC derives the tenant from the authenticated
  user session. Phase 1 accepts `tenant_id` as a query parameter because there is
  no real login yet.
- **Pool on `/authorize`**: `pool_id` is required as a query parameter. In a
  production flow persona-service would expose which pool(s) a persona is
  eligible for and broker-service would pick one automatically. Keeping this in
  the URL avoids a cross-service dependency the sister team hasn't shipped yet.
- **Tokens**: opaque UUIDs stored in-memory. Phase 2 replaces these with signed
  JWTs and defers introspection to grant-service. Search for `TODO(phase-2)` in
  `internal/oidc.go` to find the sites that will change.
- **Scope resolution**: phase 1 returns the persona's scopes verbatim and ignores
  the `scope` parameter from `/authorize`. Proper intersection per RFC 6749 is
  phase 2.
- **`grant-service` revoke-by-install**: REQUIREMENTS.md §4 only lists
  `POST /v1/grants/{id}/revoke`. broker-service calls a convention endpoint
  `POST /v1/installs/{install_id}/revoke-grants` on grant-service. Confirmed with
  the parallel grant-service implementer; update `internal/clients.go:RevokeGrantsForInstall`
  if the contract changes.

## Orchestration flow (`/authorize` → `/token`)

```
GET /authorize?...&persona_id=P&pool_id=PL&tenant_id=T
  → broker stores a pending AuthCode
  → 302 redirect_uri?code=<uuid>&state=...

POST /token with code=<uuid>
  1. consume code (one-shot)
  2. create pending Install
  3. GET  persona-service /v1/personas/P        → Persona (scopes, ttl)
  4. POST pool-service    /v1/pools/PL/claim    → Identity
  5. mint opaque access + refresh tokens
  6. POST grant-service   /v1/grants             → Grant
     └─ on failure: release identity, revoke install, return 502
  7. mark Install active with identity_id
  → 200 { access_token, refresh_token, token_type, expires_in, scope }
```

If any downstream call fails, compensation runs best-effort (release identity,
mark install revoked) and the client receives 502 with `error: downstream_error`.

## Environment

| Var | Default | Notes |
|---|---|---|
| `PORT` | `8182` | |
| `PERSONA_SERVICE_URL` | `http://localhost:8180` | |
| `POOL_SERVICE_URL` | `http://localhost:8181` | |
| `GRANT_SERVICE_URL` | `http://localhost:8183` | |
| `BROKER_ISSUER` | `http://localhost:8182` | public base URL in discovery documents |
| `PG_DSN` | _(unset)_ | When set, phase-2 Postgres storage. Unset -> in-memory. |
| `PURGE_INTERVAL` | `5m` | Go duration between expired-artifact sweeps (tokens past `expires_at`, auth codes older than the 300s code TTL). Each sweep logs `purge_expired` with the removed count. Invalid values fall back to `5m`. |
| `PG_DSN_BROKER_SERVICE` | _(unset)_ | Per-service override of `PG_DSN`. |
| `PG_MAX_CONNS` | `10` | Pool ceiling. |
| `BROKER_PG_DSN` | _(unset)_ | DSN used by the `TestPGStorage*` integration tests. Unset -> tests skip. |

## Local run

Without Postgres (in-memory fallback):

```bash
# from repo root
make run-broker
# equivalent:
PORT=8182 SERVICE_NAME=broker-service \
    PERSONA_SERVICE_URL=http://localhost:8180 \
    POOL_SERVICE_URL=http://localhost:8181 \
    GRANT_SERVICE_URL=http://localhost:8183 \
    BROKER_ISSUER=http://localhost:8182 \
    go run ./services/broker-service/cmd
```

With Postgres (phase 2):

```bash
# 1. Start Postgres
docker run --rm -d --name xauth-pg \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=broker_db -p 5432:5432 postgres:16

# 2. Apply the migration (choose one)
migrate -path services/broker-service/migrations \
        -database "postgres://postgres:postgres@localhost:5432/broker_db?sslmode=disable" up
# or:
psql "postgres://postgres:postgres@localhost:5432/broker_db?sslmode=disable" \
     -f services/broker-service/migrations/000001_init.up.sql

# 3. Run the service
PG_DSN="postgres://postgres:postgres@localhost:5432/broker_db?sslmode=disable" \
  go run ./services/broker-service/cmd
```

## Example: end-to-end install via cURL

Assumes persona-service has persona `PERSONA_ID` with scopes=[mcp], and
pool-service has pool `POOL_ID` containing at least one `available` identity.

```bash
# 1. Kick off authorization — the stub auto-approves.
curl -sSI "http://localhost:8182/authorize?client_id=client-1&redirect_uri=https://app.example.com/cb&state=xyz&scope=openid+mcp&persona_id=$PERSONA_ID&pool_id=$POOL_ID&tenant_id=tenant-1&runtime=claude"
# → HTTP/1.1 302 Found
# → Location: https://app.example.com/cb?code=<CODE>&state=xyz

# 2. Exchange the code for tokens (triggers the orchestration cascade).
curl -sS -X POST http://localhost:8182/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=<CODE>&client_id=client-1"
# → 200 {
#     "access_token":  "<uuid>",
#     "refresh_token": "<uuid>",
#     "token_type":    "Bearer",
#     "expires_in":    900,
#     "scope":         "mcp"
#   }

# 3. Look up the install the broker just finalized.
curl -sS http://localhost:8182/v1/installs/<INSTALL_ID> \
  -H "X-Tenant-Id: tenant-1"
# → 200 {
#     "id":          "<INSTALL_ID>",
#     "tenant_id":   "tenant-1",
#     "runtime":     "claude",
#     "persona_id":  "<PERSONA_ID>",
#     "identity_id": "<IDENTITY_ID>",
#     "client_id":   "client-1",
#     "status":      "active",
#     "created_at":  "…",
#     "updated_at":  "…"
#   }

# 4. Revoke.
curl -sS -X POST http://localhost:8182/v1/installs/<INSTALL_ID>/revoke \
  -H "X-Tenant-Id: tenant-1"
# → 204 No Content
```

## Tests

Unit tests (no DB needed — they mock the three sister service clients and use
`MemStorage`; no network calls are made):

```bash
go test ./services/broker-service/...
```

Run the PG-backed integration tests too:

```bash
BROKER_PG_DSN="postgres://postgres:postgres@localhost:5432/broker_db?sslmode=disable" \
  go test ./services/broker-service/... -run PG
```
