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

Not in scope: OIDC, sessions, tokens (owned by authentication-service); policy
and scoring (owned by risk-service); orchestration (transaction-service).

## Ports & visibility

| Port | Visibility | Notes |
|---|---|---|
| 8083 | internal only | `X-Tenant-Id` header required on every `/v1/*` call |

`/healthz` is the one route that skips the tenant gate.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | `{"status":"ok"}` |
| POST | `/v1/authenticators` | Enroll `{user_id, method, metadata?}` |
| GET | `/v1/authenticators?user_id=` | List enrollments for a user (tenant-scoped) |
| GET | `/v1/authenticators/{id}` | Read one |
| DELETE | `/v1/authenticators/{id}` | Soft-delete (status → `disabled`) — idempotent |
| POST | `/v1/challenges` | Create `{user_id, methods:[...]}` → dispatch |
| GET | `/v1/challenges/{id}` | Read status + attempt counter |
| POST | `/v1/challenges/{id}/verify` | Verify `{response:{...}}` |

## Method selection

`POST /v1/challenges` honours the `methods` array as caller preference order.
The first method in the list that the user has an `active` authenticator for
wins; if several authenticators match (e.g. two TOTP apps), the oldest-enrolled
one is chosen, with authenticator id as the lexicographic tiebreaker. No match
against any `active` authenticator → `409 no_authenticator_available`.

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
| `AUTHENTICATOR_PG_DSN` | _(unset)_ | DSN used by the `TestPGStorage*` integration tests. Unset -> tests skip. |

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

# 2. Apply the migration (choose one)
migrate -path services/authenticator-service/migrations \
        -database "postgres://postgres:postgres@localhost:5432/authr_db?sslmode=disable" up
# or:
psql "postgres://postgres:postgres@localhost:5432/authr_db?sslmode=disable" \
     -f services/authenticator-service/migrations/000001_init.up.sql

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

# 4. Verify with the correct stub code (200 + marks completed).
curl -s $H -X POST localhost:8083/v1/challenges/ch_.../verify \
  -d '{"response":{"code":"000000"}}'
# → 200 {"verified":true,"authenticator_id":"authr_..."}

# 5. Read the challenge — status is now "completed".
curl -s $H localhost:8083/v1/challenges/ch_...
```

Tests live in `internal/handlers_test.go` and cover the full lifecycle,
cross-tenant isolation, lockout after three failures, lazy expiry, and each
adapter's stub contract. `internal/pgstorage_test.go` adds PG-backed storage
integration tests, gated on `AUTHENTICATOR_PG_DSN`.
