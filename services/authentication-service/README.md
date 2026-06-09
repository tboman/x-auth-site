# authentication-service

Public OIDC provider for **X-Auth for Apps** (product 1). Owns users, sessions,
tokens, OIDC endpoints, and phase-1 social-login stubs.

See [`ARCHITECTURE.md`](../../ARCHITECTURE.md) §4.3 for the source-of-truth
contract.

## Purpose

When an end-user signs into a tenant's application via X-Auth:

1. **authenticator-service** verifies the user's first factor (password, FIDO2,
   etc.).
2. **transaction-service** consults **risk-service** for a risk score.
3. **transaction-service** calls `POST /v1/sessions` on this service to mint a
   session bound to the user and the current risk level.
4. Downstream APIs call `GET /userinfo` (with the bearer) to resolve the user,
   or `GET /v1/sessions/{id}` (with `X-Tenant-Id`) to read the posture.
5. On step-up, **transaction-service** calls `POST /v1/sessions/{id}/upgrade`
   to flip `step_up_completed` to `true`.

## Phase 1 scope

- [x] User CRUD (`POST/GET/PATCH/DELETE /v1/users`)
- [x] Session lifecycle (`create`, `refresh`, `invalidate`, `upgrade`)
- [x] OIDC discovery (`/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration`)
- [x] OIDC `/authorize` (auto-approve stub with optional dev user auto-provision)
- [x] OIDC `/token` (authorization_code + refresh_token grants, refresh rotation)
- [x] OIDC `/revoke` (RFC 7009, always 200)
- [x] OIDC `/userinfo` (returns `{sub, email, name}`)
- [x] Social-login stubs for google / github / microsoft
- [x] Tokens stored as SHA-256 hex hashes (never plaintext)
- [x] In-memory, tenant-scoped, thread-safe storage
- [x] Unit tests with a mock authenticator-service client

**Phase 2** adds PostgreSQL-backed storage (see `docs/postgres.md`). Storage is
swappable via the `Storage` interface in `internal/storage.go`:

- **`MemStorage`** — phase-1 in-memory implementation. Used when `PG_DSN` is unset
  (developer laptops, unit tests, short-lived CI).
- **`PGStorage`** — phase-2 Postgres implementation (`internal/pgstorage.go`,
  schema in `migrations/`). The default `cli_default` dev client is seeded by the
  migration, mirroring `MemStorage`'s constructor seed.

**Phase 2.1 — JWT tokens (done).** Access and ID tokens are now RS256 JWTs per
ARCHITECTURE.md §10.1, signed by this service and verifiable by anyone against
the JWKS endpoint. See "JWT signing & hybrid revocation" below.

**Still deferred** (every `TODO(phase-2)` comment in the codebase):

- PKCE enforcement and strict client authentication
- Real first-factor verification (today `POST /v1/sessions` trusts the internal caller)
- Real social-provider OAuth2 handshakes
- Service-to-service signed tokens from transaction-service
- Soft-delete users with GDPR-safe pseudonymisation
- Distributed revocation (drop the access-token deny list — see below)
- Persisting `client_id` on refresh-token records so the `aud` claim survives
  refreshes even when the client omits `client_id` at refresh time

## JWT signing & hybrid revocation

**Token model (ARCHITECTURE.md §10.1):**

- **Access tokens** — RS256 JWTs, TTL 1 h, claims `sub` (user id), `iss`,
  `aud` (client_id), `exp`, `iat`, `jti`, `tenant_id`, `scope`, `session_id`.
- **ID tokens** — standard OIDC JWT issued by the code grant when scope
  contains `openid`; carries the `nonce` from the original `/authorize`
  request; signed with the same key as access tokens.
- **Refresh tokens** — stay opaque UUIDs, stored hashed, rotated on every use.

**JWKS:** the public key is served at `GET /v1/auth/jwks` (canonical, §4.3)
and `GET /.well-known/jwks.json` (the `jwks_uri` advertised by both discovery
documents). Sister services verify bearers with
`jwtx.NewVerifierFromJWKS(issuer, set)`.

**Hybrid revocation (deliberate):** access tokens are stateless per spec, but
the service still persists a hashed record of every access token. `/userinfo`
requires **both** (a) RS256 signature + time-window + issuer verification, and
(b) a live, non-revoked stored record. The record acts as a deny list so RFC
7009 `/revoke` keeps taking effect immediately; it goes away when distributed
revocation lands. The purge sweeper and Postgres storage are unchanged — only
the token *value* changed from UUID to JWT (`token_hash` is the SHA-256 of
whatever the plaintext is).

## Endpoints

### Public (no tenant header)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Liveness probe, returns `{"status":"ok"}` |
| `GET` | `/.well-known/oauth-authorization-server` | RFC 8414 metadata |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery |
| `GET` | `/authorize` | Phase-1 stub: auto-approves and redirects with `code` |
| `POST` | `/token` | Exchange `code` or `refresh_token` for a JWT access token + opaque refresh token (+ `id_token` when scope has `openid`) |
| `POST` | `/revoke` | RFC 7009 token revocation |
| `GET` | `/userinfo` | Returns `{sub, email, name}` for the bearer (hybrid JWT + deny-list check) |
| `GET` | `/v1/auth/jwks` | RFC 7517 JSON Web Key Set (canonical route, §4.3) |
| `GET` | `/.well-known/jwks.json` | JWKS alias advertised as `jwks_uri` in discovery |

### Social login stubs (public)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/social/{provider}/authorize` | Redirect to our own `/callback` with mock `code` after ~100 ms |
| `GET` | `/v1/social/{provider}/callback` | Upsert a user, mint a session, redirect to caller's `redirect_uri` |

Providers: `google`, `github`, `microsoft`. Any other value returns 400.

### Tenant-scoped admin (`X-Tenant-Id` required)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/users` | Create user `{email, name}`; 409 on duplicate email |
| `GET` | `/v1/users` | List users, newest first. Keyset-paginated: `?limit=` (default 100, max 500) and `?cursor=` (RFC3339; strictly older results). Full pages return `next_cursor`. |
| `GET` | `/v1/users/{id}` | Read user (tenant-scoped) |
| `PATCH` | `/v1/users/{id}` | Update email/name |
| `DELETE` | `/v1/users/{id}` | Delete |
| `POST` | `/v1/sessions` | Create session for a known user after first-factor auth |
| `GET` | `/v1/sessions/{id}` | Read session |
| `POST` | `/v1/sessions/{id}/refresh` | Extend TTL by 1 h |
| `POST` | `/v1/sessions/{id}/invalidate` | Stamp `invalidated_at`; idempotent 204 |
| `POST` | `/v1/sessions/{id}/upgrade` | Flip `step_up_completed` and optionally change `risk_level` |

## Phase-1 shortcuts

- **Tenant on `/authorize`**: real OIDC sources the tenant from an authenticated
  browser session. Phase 1 accepts `tenant_id` as a query parameter.
- **User on `/authorize`**: accepts an optional `user_id` query param. If
  omitted, a dev user (`dev@example.com`) is auto-provisioned on first call so
  smoke tests work without a pre-seeded user.
- **Consent**: `/authorize` auto-approves. No consent screen.
- **Client auth**: the seeded `cli_default` client has a known `dev-secret`,
  but `/token` permits unauthenticated use for public-client flows. Tighten in
  phase 2.
- **Tokens**: access/ID tokens are RS256 JWTs; refresh tokens are opaque
  UUIDv4. All stored as SHA-256 hex (access records double as the revocation
  deny list).
- **`POST /v1/sessions` trust model**: authentication-service does **not**
  re-verify credentials — it trusts the internal caller (transaction-service).
  TODO(phase-2): require a signed service-to-service token.
- **Social login**: mock code-for-profile, 100 ms simulated delay, canned
  `{stub-<provider>@example.com, "<Provider> Stub User"}` profile.

## Session lifecycle judgment calls

- **TTL**: 1 hour by default. `refresh` extends from *now* (not from the old
  expiry), so a session that has been idle for 55 min and is then refreshed
  gains the full 1 h rather than only 5 min.
- **Rotation**: on `grant_type=refresh_token`, both the access and the refresh
  token are rotated and the old refresh token is stamped `revoked_at`. Old
  refresh replays return 400.
- **Invalidate**: idempotent. Second invalidation is 204.
- **Upgrade on invalidated session**: 409. `step_up_completed=true` on a dead
  session would be misleading.
- **Session — token binding**: every issued token carries the session id. When
  the session is invalidated, tokens remain valid until their own expiry
  unless explicitly revoked. TODO(phase-2): cascade-revoke tokens on
  `invalidate`, or check the session's `invalidated_at` on every /userinfo
  read.

## Environment variables

| Var | Default | Purpose |
|---|---|---|
| `PORT` | `8082` | Listen port (Cloud Run sets this) |
| `AUTHENTICATOR_SERVICE_URL` | `http://localhost:8083` | Base URL for authenticator-service |
| `AUTH_ISSUER` | `http://localhost:8082` | Public base URL advertised in discovery docs |
| `JWT_SIGNING_KEY` | _(unset)_ | PEM-encoded RSA private key (PKCS#1 or PKCS#8) for RS256 token signing. **Unset -> an ephemeral per-process 2048-bit key is generated and a `jwt_ephemeral_key` warning is logged**: tokens won't survive a restart and replicas won't verify each other's tokens. Always set in production (from KMS/secret storage). |
| `JWT_ISSUER` | _value of `AUTH_ISSUER`_ | `iss` claim minted into access/ID tokens. Defaults to the discovery issuer so tokens match the published OIDC configuration. |
| `PG_DSN` | _(unset)_ | When set, phase-2 Postgres storage. Unset -> in-memory. |
| `PG_DSN_AUTHENTICATION_SERVICE` | _(unset)_ | Per-service override of `PG_DSN`. |
| `PG_MAX_CONNS` | `10` | Pool ceiling. |
| `PURGE_INTERVAL` | `5m` | Go duration (e.g. `30s`, `10m`) between background sweeps that purge expired tokens, stale auth codes, and long-expired sessions. Each sweep logs `purge_expired` with the count. |
| `AUTHN_PG_DSN` | _(unset)_ | DSN used by the `TestPGStorage*` integration tests. Unset -> tests skip. |

## Run locally

Without Postgres (in-memory fallback):

```bash
go run ./services/authentication-service/cmd
# listens on :8082, users/sessions/tokens are ephemeral
```

With Postgres (phase 2):

```bash
# 1. Start Postgres
docker run --rm -d --name xauth-pg \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=auth_db -p 5432:5432 postgres:16

# 2. Apply the migration (choose one)
migrate -path services/authentication-service/migrations \
        -database "postgres://postgres:postgres@localhost:5432/auth_db?sslmode=disable" up
# or:
psql "postgres://postgres:postgres@localhost:5432/auth_db?sslmode=disable" \
     -f services/authentication-service/migrations/000001_init.up.sql

# 3. Run the service
PG_DSN="postgres://postgres:postgres@localhost:5432/auth_db?sslmode=disable" \
  go run ./services/authentication-service/cmd
```

## cURL quickstart

Full end-to-end (user create → session create → session refresh → OIDC
authorize → token exchange → userinfo → revoke).

```bash
# 0. Health + signing keys
curl -s http://localhost:8082/healthz
curl -s http://localhost:8082/v1/auth/jwks   # same document as /.well-known/jwks.json

# 1. Create a user
USER_JSON=$(curl -s -X POST http://localhost:8082/v1/users \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: ten_acme" \
  -d '{"email":"alice@acme.test","name":"Alice"}')
USER_ID=$(echo "$USER_JSON" | jq -r .id)
echo "created $USER_ID"

# 2. Create a session for that user (as transaction-service would, after first-factor auth)
SESSION_JSON=$(curl -s -X POST http://localhost:8082/v1/sessions \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: ten_acme" \
  -d "{\"user_id\":\"$USER_ID\",\"risk_level\":\"low\",\"step_up_completed\":false}")
SESSION_ID=$(echo "$SESSION_JSON" | jq -r .id)
echo "session $SESSION_ID"

# 3. Refresh the session (bumps expires_at forward by 1h)
curl -s -X POST "http://localhost:8082/v1/sessions/$SESSION_ID/refresh" \
  -H "X-Tenant-Id: ten_acme"

# 4. OIDC authorize — auto-approves, redirects with ?code=...
#    Use -i to see the Location header; pick the code out by hand or with sed.
curl -s -i "http://localhost:8082/authorize?client_id=cli_default&redirect_uri=http://localhost:3000/callback&state=xyz&scope=openid%20profile%20email&tenant_id=ten_acme&user_id=$USER_ID"

# 5. Token exchange — POST application/x-www-form-urlencoded
CODE="<paste code from step 4>"
curl -s -X POST http://localhost:8082/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE&client_id=cli_default&redirect_uri=http://localhost:3000/callback"

# 6. /userinfo with the returned access_token
ACCESS="<paste access_token from step 5>"
curl -s http://localhost:8082/userinfo -H "Authorization: Bearer $ACCESS"

# 7. Refresh token rotation
REFRESH="<paste refresh_token from step 5>"
curl -s -X POST http://localhost:8082/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$REFRESH"

# 8. Revoke
curl -s -X POST http://localhost:8082/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ACCESS"

# 9. Session invalidate
curl -s -X POST "http://localhost:8082/v1/sessions/$SESSION_ID/invalidate" \
  -H "X-Tenant-Id: ten_acme"
```

### Social login stub

```bash
# /v1/social/google/authorize redirects to /v1/social/google/callback after ~100 ms.
# Follow redirects with -L and inspect the final Location.
curl -s -i "http://localhost:8082/v1/social/google/authorize?tenant_id=ten_acme&redirect_uri=http://app.acme.test/cb&state=s1"
```

## Testing

Unit tests only (no DB needed — PG integration tests skip):

```bash
go test ./services/authentication-service/...
```

Run the PG-backed integration tests too (Postgres up + migration applied):

```bash
AUTHN_PG_DSN="postgres://postgres:postgres@localhost:5432/auth_db?sslmode=disable" \
  go test ./services/authentication-service/... -run PG
```

Tests cover: health, discovery, user CRUD, user-list keyset pagination
(two-page walk, invalid `limit`/`cursor` rejection), cross-tenant isolation,
duplicate email, full session lifecycle, unknown-user session create, tenant
middleware enforcement, `/authorize` → `/token` happy path (access token is a
3-part JWS verified against the service's own JWKS endpoint with
sub/aud/tenant_id/session_id/scope/exp asserted; `id_token` carries the
`/authorize` nonce; refresh token stays opaque), auth-code one-shot,
refresh-token rotation + old-token revocation (refreshed access token is a
fresh, verifiable JWT), JWKS canonical route + well-known alias parity +
discovery `jwks_uri`, hybrid revocation (`/userinfo` 401s a JWT that still
verifies cryptographically but whose stored record is revoked), foreign-key
rejection (`/userinfo` 401s a JWT signed by a different RSA key even with a
planted record), `/revoke` always-200 semantics, unregistered-redirect
rejection, social authorize → callback round-trip, expired-artifact purge
(expired removed, live kept, purged token no longer authenticates), and
SHA-256 token hashing determinism.
