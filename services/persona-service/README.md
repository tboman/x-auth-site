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
