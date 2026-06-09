# persona-service

Persona CRUD for **X-Auth for Agents** (product 2). A persona is a pre-authorized bundle
of OAuth scopes and claims that a tenant's security team defines up-front. Human admins
pick a persona at MCP install time; the broker-service later binds it to a pooled
identity via OIDC.

See `REQUIREMENTS.md` at the repo root for the full product spec. This service owns
section 4's `persona-service` contract.

## Scope

Tenant-scoped persona CRUD. Storage is swappable via the `Storage` interface in
`internal/storage.go`:

- **`MemStorage`** — phase-1 in-memory implementation. Used when `PG_DSN` is unset
  (developer laptops, unit tests, short-lived CI).
- **`PGStorage`** — phase-2 Postgres implementation (mirrors transaction-service's
  reference rollout; see `docs/postgres.md`).

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

### Internal tree (`/internal/v1/`)

The entire `/v1` route tree is also mounted under `/internal/v1/` (same handlers, same
status codes — e.g. `GET /internal/v1/personas/{id}`, the call broker-service makes when
resolving an install's persona). This is the service-to-service surface reintroduced per
ARCHITECTURE.md §10.3 and is guarded by `httpx.InternalAuth`: a request is accepted when
it arrives over mTLS with a verified client certificate, **or** when `INTERNAL_AUTH_SECRET`
is set and the request carries a matching `X-Internal-Auth` header. With neither
configured the tree is open (local-dev mode) and a warning is logged at startup.
Unauthenticated requests once a mechanism is configured get a structured
`401 internal_auth_required`.

`/v1/*` remains reachable for back-compat during the transition; new service-to-service
callers should use `/internal/v1/*` only.

```bash
curl -s http://localhost:8180/internal/v1/personas/$ID \
  -H 'X-Tenant-Id: tenant-a' \
  -H "X-Internal-Auth: $INTERNAL_AUTH_SECRET"
```

### List pagination

`GET /v1/personas` returns personas newest-first (`created_at` DESC, `id` DESC as
tiebreaker) inside an `{"items": [...], "next_cursor": "..."}` envelope, using keyset
pagination — same contract as transaction-service's `GET /v1/transactions`:

- `limit` — page size; positive integer, default 100, capped at 500. Non-numeric or
  non-positive values are rejected with 400 `invalid_limit`.
- `cursor` — RFC3339 timestamp; only personas strictly older than the cursor are
  returned. Malformed values are rejected with 400 `invalid_cursor`.
- `next_cursor` — present in the response only when a full page was returned; it is
  the `created_at` of the last item (RFC3339Nano). Pass it back as `cursor` to fetch
  the next page.

```bash
curl -s 'http://localhost:8180/v1/personas?limit=2' -H 'X-Tenant-Id: tenant-a'
# -> {"items":[...2 personas...],"next_cursor":"2026-04-20T12:00:00.123456Z"}
curl -s 'http://localhost:8180/v1/personas?limit=2&cursor=2026-04-20T12:00:00.123456Z' \
  -H 'X-Tenant-Id: tenant-a'
```

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

## Environment

| Var | Default | Notes |
|---|---|---|
| `PORT` | `8180` | |
| `PG_DSN` | _(unset)_ | When set, phase-2 Postgres storage. Unset -> in-memory. |
| `PG_DSN_PERSONA_SERVICE` | _(unset)_ | Per-service override of `PG_DSN`. |
| `PG_MAX_CONNS` | `10` | Pool ceiling. |
| `PERSONA_PG_DSN` | _(unset)_ | DSN used by the `TestPGStorage*` integration tests. Unset -> tests skip. |
| `TLS_CERT_FILE` | _(unset)_ | PEM certificate the server presents. Must be set together with `TLS_KEY_FILE`; setting only one is a startup error. Both unset -> plaintext (local dev). |
| `TLS_KEY_FILE` | _(unset)_ | PEM private key for `TLS_CERT_FILE`. |
| `TLS_CLIENT_CA_FILE` | _(unset)_ | CA bundle; when set, client certificates are **required and verified** (mTLS). Requires the cert/key pair above. |
| `INTERNAL_AUTH_SECRET` | _(unset)_ | Shared secret for `/internal/v1/*` when mTLS is not in play; callers send it in `X-Internal-Auth`. Unset and no mTLS -> internal tree is open (dev). |

## Run locally

Without Postgres (in-memory fallback):

```bash
go run ./services/persona-service/cmd
# listens on :8180 by default, or $PORT if set; personas are ephemeral
```

With Postgres (phase 2):

```bash
# 1. Start Postgres
docker run --rm -d --name xauth-pg \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=persona_db -p 5432:5432 postgres:16

# 2. Apply the migration (choose one)
migrate -path services/persona-service/migrations \
        -database "postgres://postgres:postgres@localhost:5432/persona_db?sslmode=disable" up
# or:
psql "postgres://postgres:postgres@localhost:5432/persona_db?sslmode=disable" \
     -f services/persona-service/migrations/000001_init.up.sql

# 3. Run the service
PG_DSN="postgres://postgres:postgres@localhost:5432/persona_db?sslmode=disable" \
  go run ./services/persona-service/cmd
```

Run tests (unit only, no DB needed):

```bash
go test ./services/persona-service/...
```

Run PG-backed integration tests too:

```bash
PERSONA_PG_DSN="postgres://postgres:postgres@localhost:5432/persona_db?sslmode=disable" \
  go test ./services/persona-service/... -run PG
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
