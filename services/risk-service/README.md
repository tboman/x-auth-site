# risk-service

Internal risk scoring and policy engine for **X-Auth for Apps** (product 1). Ingests
identity signals (device, behavior, network, user) plus a resource sensitivity
level, aggregates a weighted risk score, applies tenant policies, and returns a
risk tier (`low` / `medium` / `high`) with a policy decision.

See `ARCHITECTURE.md` §4.2 for the contract and §7 for the full signal pipeline.
This service is internal — `transaction-service` is the only caller in phase 1.

## Scope

Tenant-scoped evaluation store and policy CRUD. Storage is swappable via the
`Storage` interface in `internal/storage.go`:

- **`MemStorage`** — phase-1 in-memory implementation. Used when `PG_DSN` is unset
  (developer laptops, unit tests, short-lived CI).
- **`PGStorage`** — phase-2 Postgres implementation (mirrors the
  `transaction-service` reference rollout; see `docs/postgres.md`).

Richer scorers and CAEP/SSF event emission remain phase-2 follow-ups.

The scorers here are deliberately simple, deterministic, and testable. The
thresholds and mock blocklists exist to make behaviour predictable while the
real reputation sources and behavioral baselines are built out in phase 2.

## Endpoints

All `/v1/*` endpoints require the `X-Tenant-Id` header. Tenancy is enforced at
the storage layer — an evaluation or policy written for tenant A is invisible
(404) to tenant B even if the id is known.

| Method | Path | Status codes |
|---|---|---|
| GET | `/healthz` | 200 |
| POST | `/v1/evaluations` | 201, 400 |
| GET | `/v1/evaluations/{id}` | 200, 400, 404 |
| POST | `/v1/policies` | 201, 400 |
| GET | `/v1/policies` | 200, 400 |
| GET | `/v1/policies/{id}` | 200, 400, 404 |
| PATCH | `/v1/policies/{id}` | 200, 400, 404 |
| DELETE | `/v1/policies/{id}` | 204, 400, 404 |

### `/internal/v1/` — service-to-service tree

The entire `/v1` route set above is also mounted under `/internal/v1/` (same
handlers, same contracts — e.g. `POST /internal/v1/evaluations`, plus the full
`/internal/v1/policies` CRUD). This is the canonical entry point for sister
services (ARCHITECTURE.md §10.3), guarded by `httpx.InternalAuth`:

1. **mTLS** — a request arriving with a verified client certificate (the
   server's `TLS_CLIENT_CA_FILE` already validated the peer) is accepted.
2. **Shared secret** — otherwise, if `INTERNAL_AUTH_SECRET` is set, the
   request must carry a matching `X-Internal-Auth` header; mismatch or absence
   yields a structured `401 internal_auth_required`.
3. **Open (dev)** — with neither mechanism configured, `/internal/v1/*` is
   open, mirroring the plaintext/in-memory local-dev fallbacks.

`/v1/*` stays unguarded for phase-1 back-compat; new callers should use
`/internal/v1/*`.

`GET /v1/policies` is keyset-paginated (same contract as transaction-service's
`GET /v1/transactions`):

- `limit` — page size; positive integer, default `100`, capped at `500`.
  Non-numeric or non-positive values are rejected with `400 invalid_limit`.
- `cursor` — RFC3339 timestamp; returns only policies strictly older than it
  (`400 invalid_cursor` if unparseable).

Results are ordered `created_at DESC, id DESC` (newest first). When a full
page is returned, the response includes `next_cursor` (the last item's
`created_at`, RFC3339Nano) to pass back as `?cursor=` for the next page:

```json
{ "items": [ … ], "next_cursor": "2026-04-20T12:00:00.000000001Z" }
```

### Evaluation shape

```json
{
  "id": "rev_…",
  "tenant_id": "tenant-a",
  "user_id": "usr_123",
  "session_id": "ses_abc",
  "action": "transfer.initiate",
  "resource": "payments",
  "resource_sensitivity": "high",
  "tier": "high",
  "score": 0.85,
  "signals": {
    "device":   { "score": 0.5, "flags": ["unknown_device"] },
    "behavior": { "score": 0.1, "flags": [] },
    "network":  { "score": 0.8, "flags": ["flagged_ip", "vpn_detected"] },
    "user":     { "score": 0.5, "flags": ["first_high_value_action"] }
  },
  "flags": ["unknown_device", "flagged_ip", "vpn_detected", "first_high_value_action"],
  "policy_decision": "allow",
  "matched_policies": [],
  "created_at": "2026-04-20T12:00:00Z"
}
```

### Scoring (phase 1)

Four scorers, each returning a score in `[0, 1]` plus zero or more flags.

| Scorer | Rules |
|---|---|
| **device** | base `0.2` if fingerprint starts with `fp_known_`; otherwise `0.5` + `unknown_device`. Missing fingerprint → `0.5` + `no_fingerprint`. |
| **behavior** | base `0.1`; server-local hour `< 6` or `> 22` adds `0.5` + `unusual_time`. `high_velocity` branch is stubbed off. |
| **network** | base `0.1`; IP prefix `203.0.113.` adds `0.4` + `flagged_ip`; IP suffix `.100` adds `0.3` + `vpn_detected`. Both can fire. |
| **user** | base `0.2`; action containing `transfer.` or `payment.` with no prior evaluations for this user adds `0.3` + `first_high_value_action`. |

Aggregation:

- Weighted sum: `device 0.25 + behavior 0.20 + network 0.30 + user 0.25` (clamp to `[0, 1]`).
- Sensitivity overlay: multiply by `1.00` (low), `1.15` (medium), `1.30` (high); clamp.
- Tier: `< 0.35` → `low`, `0.35–0.70` → `medium`, `> 0.70` → `high`.

### Policy

Each policy owns a list of rules. A rule is `{ condition: { field, op, value }, action: { tier_floor?, deny? } }`.

Supported fields: `action`, `resource`, `resource_sensitivity`, `user_id`,
`context.ip_address`, `context.country`.

Supported ops: `eq`, `in`, `gt`, `contains`.

Every tenant-scoped policy runs on every evaluation. Any matching rule can:

- **deny** — policy decision becomes `deny` (terminal, overrides all tier_floor).
- **tier_floor** — raises the effective tier to at least the supplied value.
  Multiple matches resolve to the highest floor.

Example policy:

```json
{
  "name": "high-value-transfers-require-step-up",
  "rules": [
    {
      "condition": { "field": "action", "op": "contains", "value": "transfer." },
      "action":    { "tier_floor": "high" }
    },
    {
      "condition": { "field": "context.country", "op": "in", "value": ["KP", "IR"] },
      "action":    { "deny": true }
    }
  ]
}
```

## Environment

| Var | Default | Notes |
|---|---|---|
| `PORT` | `8081` | |
| `PG_DSN` | _(unset)_ | When set, phase-2 Postgres storage. Unset -> in-memory. |
| `PG_DSN_RISK_SERVICE` | _(unset)_ | Per-service override of `PG_DSN`. |
| `PG_MAX_CONNS` | `10` | Pool ceiling. |
| `RISK_PG_DSN` | _(unset)_ | DSN used by the `TestPGStorage*` integration tests. Unset -> tests skip. |
| `TLS_CERT_FILE` | _(unset)_ | PEM certificate the service presents. Must be set together with `TLS_KEY_FILE`; setting only one is a fatal startup error. Both unset -> plaintext (dev). |
| `TLS_KEY_FILE` | _(unset)_ | PEM private key for `TLS_CERT_FILE`. |
| `TLS_CLIENT_CA_FILE` | _(unset)_ | CA bundle. When set (with the pair above) the server **requires and verifies client certificates** (mTLS); verified peers pass `/internal/v1/*` auth without a shared secret. |
| `INTERNAL_AUTH_SECRET` | _(unset)_ | Shared secret for `/internal/v1/*` when mTLS is not in play. Callers send it as `X-Internal-Auth`; mismatch -> `401 internal_auth_required`. Unset (and no mTLS) -> internal routes are open (dev). |

## Run locally

Without Postgres (in-memory fallback):

```bash
go run ./services/risk-service/cmd
# listens on :8081 by default, or $PORT if set; evaluations/policies are ephemeral
```

With Postgres (phase 2):

```bash
# 1. Start Postgres
docker run --rm -d --name xauth-pg \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=risk_db -p 5432:5432 postgres:16

# 2. Apply the migration (choose one)
migrate -path services/risk-service/migrations \
        -database "postgres://postgres:postgres@localhost:5432/risk_db?sslmode=disable" up
# or:
psql "postgres://postgres:postgres@localhost:5432/risk_db?sslmode=disable" \
     -f services/risk-service/migrations/000001_init.up.sql

# 3. Run the service
PG_DSN="postgres://postgres:postgres@localhost:5432/risk_db?sslmode=disable" \
  go run ./services/risk-service/cmd
```

Run tests (unit only, no DB needed):

```bash
go test ./services/risk-service/...
```

Run PG-backed integration tests too:

```bash
RISK_PG_DSN="postgres://postgres:postgres@localhost:5432/risk_db?sslmode=disable" \
  go test ./services/risk-service/... -run PG
```

## cURL examples

### Low-tier evaluation

Known device, benign IP, midday, non-high-value action. Expect `tier: "low"`.

```bash
curl -sX POST http://localhost:8081/v1/evaluations \
  -H 'X-Tenant-Id: tenant-a' \
  -H 'Content-Type: application/json' \
  -d '{
    "user_id": "usr_known",
    "session_id": "ses_1",
    "action": "read.profile",
    "resource": "profile",
    "resource_sensitivity": "low",
    "context": {
      "device_fingerprint": "fp_known_laptop",
      "ip_address": "10.0.0.5",
      "country": "US"
    }
  }'
```

### High-tier evaluation (two network flags + unknown device + high-value action)

Unknown fingerprint on an IP that matches both the flagged prefix and the VPN
suffix, doing a `transfer.` action the user has never performed before, against
a high-sensitivity resource. Expect `tier: "high"` whenever the server's hour
happens to be outside the 06:00–22:00 "normal" window, and `tier: "medium"`
during the day (behavior scorer doesn't contribute `unusual_time`). For a
guaranteed high tier at any hour, add a tier_floor policy (see below).

```bash
curl -sX POST http://localhost:8081/v1/evaluations \
  -H 'X-Tenant-Id: tenant-a' \
  -H 'Content-Type: application/json' \
  -d '{
    "user_id": "usr_new_high_value",
    "action": "transfer.initiate",
    "resource": "payments",
    "resource_sensitivity": "high",
    "context": {
      "device_fingerprint": "fp_unknown_xyz",
      "ip_address": "203.0.113.100",
      "country": "US"
    }
  }'
```

### Policy-deny outcome

Create a policy that denies any request from a sanctioned-country list, then
submit an evaluation with `context.country = "KP"`.

```bash
# 1. Create the deny policy.
curl -sX POST http://localhost:8081/v1/policies \
  -H 'X-Tenant-Id: tenant-a' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "sanctioned-country-block",
    "rules": [{
      "condition": { "field": "context.country", "op": "in", "value": ["KP", "IR"] },
      "action":    { "deny": true }
    }]
  }'

# 2. Evaluate a request from one of those countries — policy_decision will be "deny"
#    regardless of the derived tier.
curl -sX POST http://localhost:8081/v1/evaluations \
  -H 'X-Tenant-Id: tenant-a' \
  -H 'Content-Type: application/json' \
  -d '{
    "user_id": "usr_x",
    "action": "read.profile",
    "resource_sensitivity": "low",
    "context": {
      "device_fingerprint": "fp_known_laptop",
      "ip_address": "10.0.0.5",
      "country": "KP"
    }
  }'
```

## Build the container

```bash
docker build -f services/risk-service/Dockerfile -t risk-service .
docker run --rm -p 8081:8080 risk-service
```
