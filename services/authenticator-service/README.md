# authenticator-service

Internal (cluster-only) service that owns user authenticators and the challenge
lifecycle for X-Auth for Apps. Adapters are still phase-1 vendor stubs; it speaks
the same REST contracts a real deployment will, so transaction-service and
authentication-service can be exercised end to end.

Storage is swappable via the `Storage` interface in `internal/storage.go`:

- **`Store`** — phase-1 in-memory implementation. Used when `PG_DSN` is unset
  (developer laptops, unit tests, short-lived CI).
- **`PGStorage`** — phase-2 Postgres implementation, following the
  transaction-service reference rollout (see `docs/postgres.md`). Schema lives
  in `migrations/` (`authenticators` + `challenges` tables).

## Responsibilities

- Authenticator CRUD: enroll / list / read / soft-delete. Methods: `fido2`,
  `totp`, `push`, `sms`, `magic_link`.
- Challenge lifecycle: `POST /v1/challenges` selects an authenticator, dispatches
  via the method's adapter, and returns `{challenge_id, method, prompt, expires_at}`.
- Verify lifecycle: success → `completed`; three failures → `failed`; TTL past
  on next verify → `expired`. All terminal states return `410 Gone` on further
  verify attempts.
- Abuse prevention (ARCHITECTURE.md §10.5 layer 3): per-user challenge rate
  limit, max 3 attempts per challenge, exponential backoff on failed verifies,
  and account lockout after repeated failures — see
  [Abuse prevention](#abuse-prevention-105-layer-3).

Not in scope: OIDC, sessions, tokens (owned by authentication-service); policy
and scoring (owned by risk-service); orchestration (transaction-service).

## Ports & visibility

| Port | Visibility | Notes |
|---|---|---|
| 8083 | internal only | `X-Tenant-Id` header required on every `/v1/*` and `/internal/v1/*` call |

`/healthz` is the one route that skips the tenant gate.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | `{"status":"ok"}` |
| POST | `/v1/authenticators` | Enroll `{user_id, method, metadata?}` |
| GET | `/v1/authenticators?user_id=` | List enrollments for a user (tenant-scoped); returns `{"authenticators":[...]}` (ARCHITECTURE.md §4.4) |
| GET | `/v1/authenticators/{id}` | Read one |
| DELETE | `/v1/authenticators/{id}` | Soft-delete (status → `disabled`) — idempotent |
| POST | `/v1/challenges` | Create `{user_id, methods:[...]}` → dispatch |
| GET | `/v1/challenges/{id}` | Read status + attempt counter |
| POST | `/v1/challenges/{id}/verify` | Verify `{response:{...}}` |

### `/internal/v1/*` — service-to-service tree (ARCHITECTURE.md §10.3)

The entire `/v1` route table above is also mounted at `/internal/v1/*` — same
handlers, same storage — behind the shared `httpx.InternalAuth` gate. A request
is accepted when it arrives over mTLS with a verified client certificate, or
when `INTERNAL_AUTH_SECRET` is set and the `X-Internal-Auth` header matches it.
With neither configured the gate is open (local dev). The plain `/v1/*` prefix
stays mounted, ungated, for back-compat.

Known callers:

- `transaction-service` — `POST /internal/v1/challenges`,
  `POST /internal/v1/challenges/{id}/verify`
- `authentication-service` — `GET /internal/v1/authenticators?user_id={id}&tenant_id={id}`

On the authenticators list, `tenant_id` may be passed in the query string (the
§4.4 URL shape); the `X-Tenant-Id` header remains authoritative and a
conflicting `tenant_id` query param is rejected with `400`.

## Method selection

`POST /v1/challenges` honours the `methods` array as caller preference order.
The first method in the list that the user has an `active` authenticator for
wins; if several authenticators match (e.g. two TOTP apps), the oldest-enrolled
one is chosen, with authenticator id as the lexicographic tiebreaker. No match
against any `active` authenticator → `409 no_authenticator_available`.

## Abuse prevention (§10.5 layer 3)

ARCHITECTURE.md §10.5 assigns authenticator-service four layer-3 controls:

| Control | Mechanism | Config |
|---|---|---|
| Per-user challenge rate limit | `pkg/ratex` sliding window keyed `tenant\|user_id`, enforced inside the create handler on `POST /v1/challenges` (and therefore on the `/internal/v1` alias too — both mounts share the handler). Over limit → `429 rate_limited` + `Retry-After`. | `CHALLENGE_RATE_LIMIT`, default `10/1m`, `off` disables |
| Max attempts per challenge | 3 failed verifies flip the challenge to terminal `failed` (`MaxChallengeAttempts` code constant); further verifies are `410 Gone`. | constant |
| Exponential backoff on failed verifications | After each failed verify the challenge may not be retried until `2^attempts` seconds after the last failed attempt (2s after the 1st failure, 4s after the 2nd). A premature retry — even with the correct response — is `429 retry_backoff` + `Retry-After` and does **not** consume an attempt. Derived from persisted fields (`attempts` + `last_attempt_at`, migration 000002), so it holds across replicas and restarts. | always on |
| Account lockout | Failed verifications are counted per `tenant\|user_id` across challenges in a ratex sliding window; once the threshold trips, challenge **creation and verification** both answer `423 Locked` (`account_locked`) + `Retry-After` until the window slides past the oldest counted failure. A successful verify does not reset the window (sliding-window approximation of "consecutive"). | `LOCKOUT_THRESHOLD`, default `5/15m`, `off` disables |

**Scope caveat:** the rate limit and the lockout are in-memory and
**per replica** (the `pkg/ratex` phase-2.1 stance) — with N replicas a
determined client can get up to N× the configured budget until the
Redis-backed store lands. The backoff control is the exception: it reads
persisted challenge state, so it is consistent across replicas. An invalid
(non-`off`, unparseable) value for either env var is a fatal startup error.

## Adapter stubs (phase 1)

Every adapter logs dispatch + verify at info level with method and
`challenge_id`. All stubs are marked with a `// TODO(phase-2): real vendor
adapter` comment at the swap point.

| Method | Dispatch prompt | Verify success predicate |
|---|---|---|
| `fido2` | `WebAuthn ceremony initiated (stub)` | `response.signature == "stub_valid_signature"` |
| `totp` | `Enter 6-digit code from your authenticator app` | `response.code == "000000"` |
| `push` | `Push notification sent (stub)` | `response.approved == true` |
| `sms` | `SMS OTP sent to +15551234 (stub)` | `response.code == "123456"` |
| `magic_link` | `Magic link sent to user@example.com (stub)` | `response.token == "stub_magic_token"` |

## Environment

| Var | Default | Notes |
|---|---|---|
| `PORT` | `8083` | |
| `PG_DSN` | _(unset)_ | When set, phase-2 Postgres storage. Unset -> in-memory. |
| `PG_DSN_AUTHENTICATOR_SERVICE` | _(unset)_ | Per-service override of `PG_DSN`. |
| `PG_MAX_CONNS` | `10` | Pool ceiling. |
| `PURGE_INTERVAL` | `5m` | Go duration; how often the background sweeper deletes expired challenges (pending past `expires_at`, plus lazily-flipped `expired` rows). Completed/failed challenges are kept as the step-up audit trail. Each sweep logs `purge_expired` with the row count. |
| `CHALLENGE_RATE_LIMIT` | `10/1m` | §10.5 layer 3: max challenge creations per user (`N/window`, ratex syntax), keyed `tenant\|user_id`, sliding window, **per replica**. Over limit → `429 rate_limited` + `Retry-After`. `off` disables; any other unparseable value is a fatal startup error. |
| `LOCKOUT_THRESHOLD` | `5/15m` | §10.5 layer 3: failed verifications per user (`N/window`) before the account locks, keyed `tenant\|user_id`, sliding window, **per replica**. Once tripped, challenge creation and verification return `423 account_locked` + `Retry-After` until the window slides. `off` disables; unparseable is fatal. |
| `AUTHENTICATOR_PG_DSN` | _(unset)_ | DSN used by the `TestPGStorage*` integration tests. Unset -> tests skip. |
| `TLS_CERT_FILE` | _(unset)_ | PEM certificate the server presents. Set together with `TLS_KEY_FILE` to serve TLS; both unset -> plaintext (dev). Setting only one is a fatal startup error. |
| `TLS_KEY_FILE` | _(unset)_ | PEM private key for `TLS_CERT_FILE`. |
| `TLS_CLIENT_CA_FILE` | _(unset)_ | CA bundle; when set (with the pair above) client certificates are required and verified — mTLS. A verified peer cert satisfies the `/internal/v1/*` gate. |
| `INTERNAL_AUTH_SECRET` | _(unset)_ | Shared secret for `/internal/v1/*` when mTLS is not in play: callers send it in `X-Internal-Auth`. Unset and no mTLS -> internal routes are open (dev). |

## Run locally

Without Postgres (in-memory fallback):

```bash
go run ./services/authenticator-service/cmd
# listens on :8083 (override with PORT), authenticators/challenges are ephemeral
```

With Postgres (phase 2):

```bash
# 1. Start Postgres
docker run --rm -d --name xauth-pg \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=authr_db -p 5432:5432 postgres:16

# 2. Apply the migrations (choose one)
migrate -path services/authenticator-service/migrations \
        -database "postgres://postgres:postgres@localhost:5432/authr_db?sslmode=disable" up
# or:
psql "postgres://postgres:postgres@localhost:5432/authr_db?sslmode=disable" \
     -f services/authenticator-service/migrations/000001_init.up.sql \
     -f services/authenticator-service/migrations/000002_challenge_last_attempt.up.sql

# 3. Run the service
PG_DSN="postgres://postgres:postgres@localhost:5432/authr_db?sslmode=disable" \
  go run ./services/authenticator-service/cmd
```

Run tests (unit only, no DB needed):

```bash
go test ./services/authenticator-service/...
```

Run PG-backed integration tests too:

```bash
AUTHENTICATOR_PG_DSN="postgres://postgres:postgres@localhost:5432/authr_db?sslmode=disable" \
  go test ./services/authenticator-service/... -run PG
```

## Try it out

```bash
H='-H X-Tenant-Id:ten_demo -H Content-Type:application/json'

# 1. Enroll a TOTP authenticator.
curl -s $H -X POST localhost:8083/v1/authenticators \
  -d '{"user_id":"usr_abc","method":"totp","metadata":{"device_name":"phone"}}'

# 2. Create a challenge preferring fido2, falling back to totp.
curl -s $H -X POST localhost:8083/v1/challenges \
  -d '{"user_id":"usr_abc","methods":["fido2","totp"]}'
# → {"challenge_id":"ch_...","method":"totp","prompt":"Enter 6-digit code ...","expires_at":"..."}

# 3. Verify with a wrong code (401 + attempts++).
curl -s $H -X POST localhost:8083/v1/challenges/ch_.../verify \
  -d '{"response":{"code":"111111"}}'
# → 401 {"verified":false,"reason":"invalid_response"}

# 4. Wait out the exponential backoff (2s after the 1st failure — an immediate
#    retry would be 429 retry_backoff), then verify with the correct stub code.
sleep 2
curl -s $H -X POST localhost:8083/v1/challenges/ch_.../verify \
  -d '{"response":{"code":"000000"}}'
# → 200 {"verified":true,"authenticator_id":"authr_..."}

# 5. Read the challenge — status is now "completed".
curl -s $H localhost:8083/v1/challenges/ch_...
```

Tests live in `internal/handlers_test.go` (full lifecycle, cross-tenant
isolation, challenge failure after three attempts, lazy expiry, each adapter's
stub contract) and `internal/abuse_test.go` (§10.5 layer 3: per-user creation
rate limit incl. the `/internal/v1` alias, exponential backoff, account
lockout). `internal/pgstorage_test.go` adds PG-backed storage integration
tests, gated on `AUTHENTICATOR_PG_DSN`.
