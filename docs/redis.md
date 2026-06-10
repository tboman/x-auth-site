# Phase 2.2: Shared Redis

ARCHITECTURE.md §6.3 gives every service access to one **shared Redis** for
cross-replica state: rate-limit counters today; session cache, risk-score
cache, and OIDC nonces as later phases need them. This doc is the shared
contract, the companion to `docs/postgres.md`.

## Shared pieces

- **`pkg/redisx`** — one-shot `Open(ctx, cfg, logger)` mirroring `pkg/pgxdb`:
  env-driven resolution, startup ping (fail fast), a single `redis_connect`
  log line, and `ErrMissingAddr` as the in-memory-fallback signal.
- **`pkg/ratex`** — the `Allower` interface decouples rate-limit policy from
  backing store. `ratex.New` is the in-memory sliding window (per-replica);
  `ratex.NewRedis` is the shared fixed-window counter (§6.3 `rate:{key}`
  pattern, TTL = window, atomic via a Lua script). Redis decisions **fail
  open** — abuse prevention should not turn a cache outage into a total
  outage.
- **Driver: `github.com/redis/go-redis/v9` v9.5.1** (pinned — later versions
  raise the Go toolchain floor past our 1.22 pin, same story as pgx).
  Tests use `github.com/alicebob/miniredis/v2` v2.33.0 — an in-process Redis,
  so `go test ./...` needs no infrastructure.

## Env vars

| Var | Meaning |
|-----|---------|
| `REDIS_URL` | Full URL, e.g. `redis://:pass@host:6379/0`. `rediss://` enables TLS (§10.3). Takes precedence. |
| `REDIS_ADDR` | `host:port` shorthand; combined with `REDIS_PASSWORD` / `REDIS_DB`. |

Neither set → services fall back to their in-memory limiters (per-replica
limits, the local-dev mode). Configured but unreachable → the service exits at
startup; a configured Redis never silently degrades.

## Who uses it (phase 2.2)

| Service | Keys | Purpose |
|---------|------|---------|
| transaction-service | `rate:txn:{tenant\|method\|endpoint}` | §10.5 layer-2 per-tenant per-endpoint limits |
| authenticator-service | `rate:authr:challenge:{tenant\|user}` | §10.5 layer-3 challenge-creation limit |
| authenticator-service | `rate:authr:lockout:{tenant\|user}` | §10.5 layer-3 failure counting for account lockout |

Lockout nuance: failure *counting* is cross-replica; the in-process
`lockedUntil` cache is per-replica, so each replica trips its own lock on its
next counted failure after the shared counter crosses the threshold.

## Local dev

```bash
# miniredis covers go test; for a real instance:
docker run --rm -d --name xauth-redis -p 6379:6379 redis:7
export REDIS_ADDR=localhost:6379
```

## Later phases

Session cache, `risk_cache:{user}:{session}`, `nonce:{nonce}` replay
prevention, and `device:{fingerprint}` reputation (§6.3) — plus moving the
token deny-list checks off Postgres if they become hot.
