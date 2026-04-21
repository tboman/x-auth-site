# pool-service

Pool + Identity CRUD and the identity claim/release lifecycle for **X-Auth for Agents**.
Owns the two domain entities defined in [`REQUIREMENTS.md`](../../REQUIREMENTS.md) §2:

- **Pool** — a bucket of agent identities, with a size cap and a list of personas
  identities in the pool may be bound to.
- **Identity** — a concrete agent identity with lifecycle `available -> claimed -> available`
  (repeatable) or `available -> revoked` (terminal).

Port: **8181** (local dev). Visibility: **internal** (Cloud Run `--ingress=internal`).

## Endpoints

All `/v1/*` routes require the `X-Tenant-Id` header. `/healthz` is public.

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Liveness probe |
| POST | `/v1/pools` | Create pool `{name, size, persona_ids}` |
| GET | `/v1/pools` | List pools (tenant-scoped) |
| GET | `/v1/pools/{id}` | Read pool |
| DELETE | `/v1/pools/{id}` | Delete pool (cascades to identities) |
| POST | `/v1/pools/{id}/identities` | Add identity `{subject_id}` — 409 if pool full |
| GET | `/v1/pools/{id}/identities` | List pool identities |
| POST | `/v1/pools/{id}/claim` | Atomically claim a free identity `{persona_id, install_id}` |
| POST | `/v1/identities/{id}/release` | Mark available; clears `claimed_by_install_id`. Idempotent |
| POST | `/v1/identities/{id}/revoke` | Terminal: mark revoked |

Error bodies are `{"error": "<snake_case_code>", "message": "..."}`.

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

## Running locally

From repo root:

```bash
make run-pool
# or
PORT=8181 SERVICE_NAME=pool-service go run ./services/pool-service/cmd
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

```bash
go test ./services/pool-service/...
```

## Phase 1 notes

- Storage is in-memory (`internal.MemStorage`). Postgres impl is phase 2.
- `persona_ids` referenced at create-time are **not** validated against persona-service
  in phase 1 — the pool just stores the UUIDs it's given.
- Claim atomicity is guaranteed by a single mutex acquisition in `MemStorage.ClaimIdentity`.
- Tenant isolation is enforced inside `MemStorage`: cross-tenant reads/writes return
  `ErrPoolNotFound` / `ErrIdentityNotFound`.
