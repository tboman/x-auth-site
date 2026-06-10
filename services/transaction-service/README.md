# transaction-service

Public-facing orchestrator for **X-Auth for Apps** (product 1). Receives access
requests, coordinates risk evaluation via `risk-service`, triggers step-up challenges
via `authenticator-service`, promotes sessions via `authentication-service`, and
persists a tenant-scoped audit trail of every orchestration decision.

`ARCHITECTURE.md` §4.1 is the source of truth for contracts. One deliberate naming
override applies: the canonical endpoint is now `POST /v1/advice`; `POST /v1/evaluate`
is kept as an alias pointing at the same handler so the original contract still works.

## Scope

Tenant-scoped transaction store with HTTP clients against the three sister services.
Storage is swappable via the `Storage` interface in `internal/storage.go`:

- **`MemStorage`** — phase-1 in-memory implementation. Used when `PG_DSN` is unset
  (developer laptops, unit tests, short-lived CI).
- **`PGStorage`** — phase-2 Postgres implementation (this service is the reference
  rollout; see `docs/postgres.md`).

## Endpoints

All `/v1/*` endpoints require the `X-Tenant-Id` header. Tenancy is enforced at the
storage layer: a transaction created under tenant A is invisible (404) to tenant B.

| Method | Path | Status codes |
|---|---|---|
| GET | `/healthz` | 200 |
| POST | `/v1/advice` | 200, 400, 502 |
| POST | `/v1/evaluate` | 200, 400, 502 (alias for `/v1/advice`) |
| POST | `/v1/step-up/verify` | 200, 400, 401, 404, 409, 502 |
| POST | `/v1/authorize` | 200, 400, 403, 502 |
| GET | `/v1/transactions` | 200, 400 |
| GET | `/v1/transactions/{id}` | 200, 400, 404 |

Every `/v1/*` endpoint may additionally return `429` when rate limited (see below).

## Rate limiting (ARCHITECTURE.md §10.5, layer 2)

Every `/v1/*` request is counted against a limit keyed by
**tenant + method + endpoint class** (the first two path segments, so
`GET /v1/transactions` and `GET /v1/transactions/{id}` share a bucket).
Over-limit requests get `429` with a `Retry-After` header and an
`{"error":"rate_limited"}` body. `/healthz` is never limited, and requests
without an `X-Tenant-Id` header bypass the limiter (they are rejected with
`400` by tenant enforcement immediately after).

**Backend selection** (mirrors storage selection):

- **Shared Redis** — when `REDIS_URL` or `REDIS_ADDR` is set, counters live in
  the shared Redis under `rate:txn:*` keys (ARCHITECTURE.md §6.3, fixed
  windows), so the §10.5 limits hold **across replicas**. Decisions fail open
  if Redis becomes unreachable at runtime (abuse prevention must not take the
  API down with the cache).
- **In-memory fallback** — when neither is set, the service logs
  `rate_limit_local` and uses the per-process sliding-window limiter. The
  per-replica caveat applies **only to this fallback**: the effective limit is
  `RATE_LIMIT × replica count`.
- **Fatal** — Redis configured but unreachable at startup exits 1; a
  configured shared limiter must not silently degrade to per-replica.

## Orchestration rules

### `/v1/advice`

1. Validate input. `user_id`, `action`, and `context.ip_address` are required.
2. Mint a `txn_*` UUID and persist a `pending` transaction up-front so we have a paper
   trail even if step 3 fails.
3. Call `POST {RISK_SERVICE_URL}/internal/v1/evaluations`.
4. Tier decides what happens next:
   - `low`    -> `allow`, no step-up.
   - `medium` -> create challenge with methods `["otp", "magic_link"]`, return
     `step_up_required`.
   - `high`   -> create challenge with methods `["fido2", "push"]`, return
     `step_up_required`.

### `/v1/step-up/verify`

1. Load the transaction (must be in `step_up_required` and match `challenge_id`).
2. Call `POST {AUTHENTICATOR_SERVICE_URL}/internal/v1/challenges/{id}/verify`.
3. If verified and the request carried `session_id`, upgrade the session via
   `POST {AUTHENTICATION_SERVICE_URL}/internal/v1/sessions/{id}/upgrade`.
4. Persist `decision: step_up_satisfied` and return `decision: allow` to the caller.

A soft verification failure (HTTP 200 with `verified: false`) returns 401 and leaves the
transaction in `step_up_required` so the caller can retry until the authenticator
service exhausts `attempts_remaining`.

### `/v1/authorize`

Post-authentication policy check. Fetches the session, then re-evaluates via
risk-service if **any** of the following:

- session fetch failed with a 4xx (session gone / wrong tenant);
- session `updated_at` is older than 5 minutes;
- the requested `resource_sensitivity` is `high` or `critical`.

Decision from the resulting tier:

- `low` | `medium` -> `allow` (200).
- `high`           -> `deny` with `reason: step_up_required` (403). Callers then
  re-enter the `/v1/advice` flow to pick up the challenge.

### Downstream errors

Any downstream 5xx or network error returns `502` with
`{"error":"upstream_unavailable","service":"...","transaction_id":"..."}`. The
transaction is still persisted with `decision: "error"` so the caller can audit.

## Transaction shape

```json
{
  "id": "txn_0f1e…",
  "tenant_id": "tenant-a",
  "user_id": "usr_abc",
  "session_id": "ses_xyz",
  "action": "transfer.initiate",
  "resource": "payments",
  "resource_sensitivity": "high",
  "risk_evaluation_id": "rev_001",
  "risk_tier": "high",
  "risk_score": 0.87,
  "decision": "step_up_satisfied",
  "step_up_used": true,
  "step_up_method": "fido2",
  "challenge_id": "ch_001",
  "policy_id": "pol_payments_v3",
  "history": [
    {"at": "…", "event": "advice_received",      "detail": "transfer.initiate"},
    {"at": "…", "event": "risk_evaluated",       "detail": "high"},
    {"at": "…", "event": "challenge_issued",     "detail": "ch_001"},
    {"at": "…", "event": "decision",             "detail": "step_up_required"},
    {"at": "…", "event": "challenge_verified",   "detail": "fido2"},
    {"at": "…", "event": "decision",             "detail": "step_up_satisfied"}
  ],
  "created_at": "2026-04-20T12:00:00Z",
  "decided_at": "2026-04-20T12:00:45Z"
}
```

## Environment

| Var | Default | Notes |
|---|---|---|
| `PORT` | `8080` | |
| `RISK_SERVICE_URL` | `http://localhost:8081` | |
| `AUTHENTICATION_SERVICE_URL` | `http://localhost:8082` | |
| `AUTHENTICATOR_SERVICE_URL` | `http://localhost:8083` | |
| `RATE_LIMIT` | `600/1m` | §10.5 layer-2 per-tenant, per-endpoint limit as `N/window` (e.g. `100/30s`). The literal `off` disables limiting. Invalid values are fatal at startup. Enforced across replicas with Redis; per replica on the in-memory fallback. |
| `REDIS_URL` | _(unset)_ | Full Redis URL (e.g. `redis://:pass@host:6379/0`; `rediss://` enables TLS, §10.3). When set, rate-limit counters live in shared Redis (`rate:txn:*`) and limits hold across replicas. Takes precedence over `REDIS_ADDR`. Set-but-unreachable is fatal at startup. |
| `REDIS_ADDR` | _(unset)_ | `host:port` shorthand when `REDIS_URL` is unset; combined with optional `REDIS_PASSWORD` and `REDIS_DB`. Neither set -> in-memory per-replica limiter (`rate_limit_local` warning). |
| `PG_DSN` | _(unset)_ | When set, phase-2 Postgres storage. Unset -> in-memory. |
| `PG_DSN_TRANSACTION_SERVICE` | _(unset)_ | Per-service override of `PG_DSN`. |
| `PG_MAX_CONNS` | `10` | Pool ceiling. |
| `TXN_PG_DSN` | _(unset)_ | DSN used by the `TestPGStorage*` integration tests. Unset -> tests skip. |
| `TLS_CERT_FILE` | _(unset)_ | PEM certificate this service presents — as server on the public listener and as client certificate when dialing sister services (mTLS). Requires `TLS_KEY_FILE`. |
| `TLS_KEY_FILE` | _(unset)_ | PEM private key for `TLS_CERT_FILE`. Both unset -> plaintext local dev; exactly one set is fatal. |
| `TLS_CLIENT_CA_FILE` | _(unset)_ | CA bundle; when set the public listener requires and verifies client certificates (mTLS). |
| `TLS_CA_FILE` | _(unset)_ | CA bundle used to verify sister services on outbound calls. |
| `INTERNAL_AUTH_SECRET` | _(unset)_ | Shared secret sent as `X-Internal-Auth` on every outbound downstream call — the non-mTLS fallback the callees' `/internal/v1` trees verify. |

All downstream calls target the sister services' **`/internal/v1`** trees
(ARCHITECTURE.md §10.3) — `POST /internal/v1/evaluations` (risk),
`POST /internal/v1/challenges` and `POST /internal/v1/challenges/{id}/verify`
(authenticator), `GET /internal/v1/sessions/{id}` and
`POST /internal/v1/sessions/{id}/upgrade` (authentication). Those routes are
guarded by internal auth on the callee side: a verified mTLS client
certificate, or the `X-Internal-Auth` shared secret.

## Run locally

Without Postgres (in-memory fallback):

```bash
go run ./services/transaction-service/cmd
# listens on :8080, transactions are ephemeral
```

With Postgres (phase 2):

```bash
# 1. Start Postgres
docker run --rm -d --name xauth-pg \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=txn_db -p 5432:5432 postgres:16

# 2. Apply the migration (choose one)
migrate -path services/transaction-service/migrations \
        -database "postgres://postgres:postgres@localhost:5432/txn_db?sslmode=disable" up
# or:
psql "postgres://postgres:postgres@localhost:5432/txn_db?sslmode=disable" \
     -f services/transaction-service/migrations/000001_init.up.sql

# 3. Run the service
PG_DSN="postgres://postgres:postgres@localhost:5432/txn_db?sslmode=disable" \
  go run ./services/transaction-service/cmd
```

Run tests (unit only, no DB needed):

```bash
go test ./services/transaction-service/...
```

Run PG-backed integration tests too:

```bash
TXN_PG_DSN="postgres://postgres:postgres@localhost:5432/txn_db?sslmode=disable" \
  go test ./services/transaction-service/... -run PG
```

## End-to-end cURL sketch

```bash
# 1. Ask for advice (medium/high-risk example returns step_up_required)
curl -sX POST http://localhost:8080/v1/advice \
  -H 'X-Tenant-Id: tenant-a' \
  -H 'Content-Type: application/json' \
  -d '{
    "user_id": "usr_abc",
    "session_id": "ses_xyz",
    "action": "transfer.initiate",
    "resource": "payments",
    "resource_sensitivity": "high",
    "context": {
      "ip_address": "203.0.113.42",
      "user_agent": "Mozilla/5.0",
      "device_fingerprint": "fp_a1b2c3d4",
      "geo": {"lat": 37.7749, "lon": -122.4194}
    }
  }'
# -> { "transaction_id": "txn_…", "decision": "step_up_required",
#      "step_up": { "challenge_id": "ch_…", "methods": ["fido2","push"], "expires_at": "…" } }

# 2. Verify the challenge (after the user satisfies it)
curl -sX POST http://localhost:8080/v1/step-up/verify \
  -H 'X-Tenant-Id: tenant-a' \
  -H 'Content-Type: application/json' \
  -d '{
    "transaction_id": "txn_…",
    "challenge_id":   "ch_…",
    "method":         "fido2",
    "response":       { "credential_id": "…", "signature": "…" }
  }'
# -> { "transaction_id": "txn_…", "decision": "allow",
#      "session": { "id": "ses_xyz", "risk_level": "high", "step_up_completed": true, … } }

# 3. Later, the same session requests access to a sensitive resource
curl -sX POST http://localhost:8080/v1/authorize \
  -H 'X-Tenant-Id: tenant-a' \
  -H 'Content-Type: application/json' \
  -d '{
    "user_id":    "usr_abc",
    "session_id": "ses_xyz",
    "action":     "transfer.initiate",
    "resource":   "payments",
    "attributes": { "amount": 5000, "currency": "USD", "resource_sensitivity": "high" }
  }'
# -> { "transaction_id": "txn_…", "decision": "allow", "policy_id": "pol_…", "evaluated_at": "…" }

# 4. Audit: list or fetch transactions
curl -s http://localhost:8080/v1/transactions?limit=10 -H 'X-Tenant-Id: tenant-a'
curl -s http://localhost:8080/v1/transactions/txn_…    -H 'X-Tenant-Id: tenant-a'
```

## Build the container

```bash
docker build -f services/transaction-service/Dockerfile -t transaction-service .
docker run --rm -p 8080:8080 \
  -e RISK_SERVICE_URL=http://host.docker.internal:8081 \
  -e AUTHENTICATION_SERVICE_URL=http://host.docker.internal:8082 \
  -e AUTHENTICATOR_SERVICE_URL=http://host.docker.internal:8083 \
  transaction-service
```
