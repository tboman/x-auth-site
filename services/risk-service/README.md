# risk-service

Internal risk scoring and policy engine for **X-Auth for Apps** (product 1). Ingests
identity signals (device, behavior, network, user) plus a resource sensitivity
level, aggregates a weighted risk score, applies tenant policies, and returns a
risk tier (`low` / `medium` / `high`) with a policy decision.

See `ARCHITECTURE.md` §4.2 for the contract and §7 for the full signal pipeline.
This service is internal — `transaction-service` is the only caller in phase 1.

## Scope

Phase 1: in-memory, tenant-scoped. Storage is swappable via the `Storage`
interface in `internal/storage.go` — phase 2 will add a Postgres-backed
implementation, richer scorers, and CAEP/SSF event emission.

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

## Run locally

From the repo root:

```bash
go run ./services/risk-service/cmd
# listens on :8081 by default, or $PORT if set
```

Run tests:

```bash
go test ./services/risk-service/...
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
