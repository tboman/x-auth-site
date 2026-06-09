# pool-service

Pool + Identity CRUD and the identity claim/release lifecycle for **X-Auth for Agents**.
Owns the two domain entities defined in [`REQUIREMENTS.md`](../../REQUIREMENTS.md) §2:

- **Pool** — a bucket of agent identities, with a size cap and a list of personas
  identities in the pool may be bound to.
- **Identity** — a concrete agent identity with lifecycle `available -> claimed -> available`
  (repeatable) or `available -> revoked` (terminal).

Port: **8181** (local dev). Visibility: **internal** (Cloud Run `--ingress=internal`).

## Scope

Tenant-scoped pool/identity store. Storage is swappable via the `Storage` interface
in `internal/storage.go`:

- **`MemStorage`** — phase-1 in-memory implementation. Used when `PG_DSN` is unset
  (developer laptops, unit tests, short-lived CI).
- **`PGStorage`** — phase-2 Postgres implementation (follows the transaction-service
  reference rollout; see `docs/postgres.md`).

## Endpoints

All `/v1/*` routes require the `X-Tenant-Id` header. `/healthz` is public.

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Liveness probe |
| POST | `/v1/pools` | Create pool `{name, size, persona_ids}` |
| GET | `/v1/pools` | List pools (tenant-scoped, paginated) |
| GET | `/v1/pools/{id}` | Read pool |
| DELETE | `/v1/pools/{id}` | Delete pool (cascades to identities) |
| POST | `/v1/pools/{id}/identities` | Add identity `{subject_id}` — 409 if pool full |
| GET | `/v1/pools/{id}/identities` | List pool identities (paginated) |
| POST | `/v1/pools/{id}/claim` | Atomically claim a free identity `{persona_id, install_id}` |
| POST | `/v1/identities/{id}/release` | Mark available; clears `claimed_by_install_id`. Idempotent |
| POST | `/v1/identities/{id}/revoke` | Terminal: mark revoked |

Error bodies are `{"error": "<snake_case_code>", "message": "..."}`.

### Pagination

Both list endpoints use keyset pagination (same contract as transaction-service):

- `limit` — page size, integer. Default **100**, capped at **500**. Non-positive or
  non-numeric values are a 400 `invalid_limit`.
- `cursor` — RFC3339 timestamp; only items **strictly older** than the cursor are
  returned. Malformed values are a 400 `invalid_cursor`.

Items are ordered `created_at DESC, id DESC` (newest first). The response envelope is
`{"items": [...], "next_cursor": "..."}` — `next_cursor` (the last item's `created_at`,
RFC3339Nano) is present only when a full page was returned; pass it back as `?cursor=`
to fetch the next page.

```bash
curl -sS 'http://localhost:8181/v1/pools?limit=2' -H 'X-Tenant-Id: acme'
# -> {"items":[...2 pools...],"next_cursor":"2026-04-20T12:00:02Z"}
curl -sS 'http://localhost:8181/v1/pools?limit=2&cursor=2026-04-20T12:00:02Z' -H 'X-Tenant-Id: acme'
```

Pagination affects the **list** endpoints only — the claim path still hands out the
*oldest* available identity (ASC pick), see below.

## Claim semantics

`POST /v1/pools/{id}/claim` is the hot path. In one atomic step the service:

1. Verifies the pool exists in the caller's tenant.
2. Verifies `persona_id` is present in the pool's `persona_ids`. If not — **404**.
3. Picks the oldest `available` identity in the pool.
4. Transitions it to `claimed` and sets `claimed_by_install_id = install_id`.
5. Returns the mutated identity.

If no identity is available (all `claimed` or `revoked`) — **409**. Returned identity
still reflects the in-memory row shape, so subsequent `/release` / `/revoke` calls
address the same record.

## Environment

| Var | Default | Notes |
|---|---|---|
| `PORT` | `8181` | |
| `PG_DSN` | _(unset)_ | When set, phase-2 Postgres storage. Unset -> in-memory. |
| `PG_DSN_POOL_SERVICE` | _(unset)_ | Per-service override of `PG_DSN`. |
| `PG_MAX_CONNS` | `10` | Pool ceiling. |
| `POOL_PG_DSN` | _(unset)_ | DSN used by the `TestPGStorage*` integration tests. Unset -> tests skip. |

## Running locally

Without Postgres (in-memory fallback), from repo root:

```bash
make run-pool
# or
PORT=8181 SERVICE_NAME=pool-service go run ./services/pool-service/cmd
```

With Postgres (phase 2):

```bash
# 1. Start Postgres
docker run --rm -d --name xauth-pg \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=pool_db -p 5432:5432 postgres:16

# 2. Apply the migration (choose one)
migrate -path services/pool-service/migrations \
        -database "postgres://postgres:postgres@localhost:5432/pool_db?sslmode=disable" up
# or:
psql "postgres://postgres:postgres@localhost:5432/pool_db?sslmode=disable" \
     -f services/pool-service/migrations/000001_init.up.sql

# 3. Run the service
PG_DSN="postgres://postgres:postgres@localhost:5432/pool_db?sslmode=disable" \
  go run ./services/pool-service/cmd
```

## Example session

```bash
# Create a pool.
POOL=$(curl -sS -X POST http://localhost:8181/v1/pools \
  -H 'X-Tenant-Id: acme' -H 'Content-Type: application/json' \
  -d '{"name":"support-agents","size":5,"persona_ids":["p-support"]}' | jq -r .id)

# Add an identity.
IDENT=$(curl -sS -X POST http://localhost:8181/v1/pools/$POOL/identities \
  -H 'X-Tenant-Id: acme' -H 'Content-Type: application/json' \
  -d '{"subject_id":"agent-001"}' | jq -r .id)

# Claim it.
curl -sS -X POST http://localhost:8181/v1/pools/$POOL/claim \
  -H 'X-Tenant-Id: acme' -H 'Content-Type: application/json' \
  -d '{"persona_id":"p-support","install_id":"inst-abc"}'

# Release it.
curl -sS -X POST http://localhost:8181/v1/identities/$IDENT/release \
  -H 'X-Tenant-Id: acme'
```

## Tests

Run tests (unit only, no DB needed):

```bash
go test ./services/pool-service/...
```

Run PG-backed integration tests too:

```bash
POOL_PG_DSN="postgres://postgres:postgres@localhost:5432/pool_db?sslmode=disable" \
  go test ./services/pool-service/... -run PG
```

## Storage notes

- `persona_ids` referenced at create-time are **not** validated against persona-service
  — the pool just stores the UUIDs it's given.
- Claim atomicity: a single mutex acquisition in `MemStorage.ClaimIdentity`; in
  `PGStorage` a single conditional `UPDATE` whose candidate row is picked with
  `FOR UPDATE SKIP LOCKED`, so concurrent claimers never receive the same identity.
- Tenant isolation is enforced inside both storage impls: cross-tenant reads/writes
  return `ErrPoolNotFound` / `ErrIdentityNotFound`. Identities are tenant-scoped via
  their pool (no `tenant_id` column on `identities`).
- Deleting a pool cascades to its identities (explicit loop in `MemStorage`,
  `ON DELETE CASCADE` FK in Postgres).
