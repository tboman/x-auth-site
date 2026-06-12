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

**Phase 2.2 — token hardening (done).** Mandatory PKCE (S256 only, §10.4),
refresh-token rotation with **family-based revocation** (§10.1), 30-day
refresh TTL, and `client_id` persisted on token records so the `aud` claim
survives refreshes regardless of what the client presents at refresh time.
Schema changes live in `migrations/000002_token_families_pkce.up.sql`. See
"Refresh-token rotation & families" and "PKCE" below.

**Phase 2.3 — real Google social login (done).** When `GOOGLE_CLIENT_ID` +
`GOOGLE_CLIENT_SECRET` are set, `/v1/social/google/*` runs the real OAuth2
authorization-code handshake with PKCE against Google; unconfigured providers
keep the stub. See "Social login" below.

**Phase 2.4 — SMS-OTP second factor on /authorize (done, mock adapter).**
Clients request it with standard OIDC `acr_values=urn:xauth:otp:sms`:
`/authorize` parks the request, dispatches an SMS challenge through
authenticator-service, and serves a hosted OTP page; `POST /authorize/verify`
proxies the code (attempts/backoff/lockout enforced by authenticator-service)
and on success mints the authorization code with `acr`/`amr` recorded. The
token mint stamps `acr` + `amr: ["otp","sms"]` into the ID token and marks the
session `step_up_completed`. The SMS adapter is the authenticator-service stub
— accepted code is `123456`; swapping in Twilio touches only that adapter.
Discovery advertises `acr_values_supported`. Schema: migration `000003`
(`auth_codes.acr` / `.amr`). Users with no SMS authenticator get one
auto-enrolled (mock-stage convenience). Parked flows are in-process (10-min
TTL) — same single-replica constraint as the social handshake.

**Phase 2.5 — hosted developer console (done, stage/dev surface).** `GET /dev`
lets a Google-authenticated user register a public OIDC client and immediately
run a full OIDC authorization-code + PKCE round trip. The built-in tester can
launch the registered client with no ACR, with `acr_values=urn:xauth:otp:sms`,
or with `acr_values=urn:xauth:fido2` so developers can see the `acr`/`amr`
claims stamped into the ID token. The console uses the normal Google social
login, stores an HttpOnly cookie backed by an X-Auth session in tenant
`ten_developer`, and registers clients in the same `oidc_clients` store used
by `/authorize`.

**Phase 2.6 — FIDO2 stub second factor (same interlude, second acr).**
`acr_values=urn:xauth:fido2` runs the identical parked-flow ceremony against
authenticator-service's stub WebAuthn adapter: the hosted page simulates the
assertion with a "Touch your authenticator (stub)" button (the accepted
response is the adapter's `stub_valid_signature`) and success mints the code
with `acr=urn:xauth:fido2`, `amr: ["user","swk"]` (RFC 8176: presence +
software key — no UV claim until the real webauthn adapter lands; the
`:uv`/`:uv:hw` assurance tiers are deferred with it). `acr_values` is treated
as a client-preference-ordered list per OIDC Core §3.1.2.1 — the first
supported value wins.

**Still deferred** (every `TODO(phase-2)` comment in the codebase):

- Strict client authentication (public dev client still allowed without a secret)
- Real first-factor verification (today `POST /v1/sessions` trusts the internal caller)
- Real OAuth2 handshakes for github / microsoft (google is done)
- First-class OIDC client ownership / dynamic client registration API (the
  `/dev` console is a stage/dev bridge)
- Service-to-service signed tokens from transaction-service
- Soft-delete users with GDPR-safe pseudonymisation
- Distributed revocation (drop the access-token deny list — see below)

## JWT signing & hybrid revocation

**Token model (ARCHITECTURE.md §10.1):**

- **Access tokens** — RS256 JWTs, TTL 1 h, claims `sub` (user id), `iss`,
  `aud` (client_id), `exp`, `iat`, `jti`, `tenant_id`, `scope`, `session_id`.
- **ID tokens** — standard OIDC JWT issued by the code grant when scope
  contains `openid`; carries the `nonce` from the original `/authorize`
  request; signed with the same key as access tokens.
- **Refresh tokens** — stay opaque UUIDs, stored hashed, TTL **30 days**
  (§6.2 `refresh_ttl_sec` default), rotated on every use within a token
  family (see below).

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

## Refresh-token rotation & families (ARCHITECTURE.md §10.1)

- **Rotation**: every `grant_type=refresh_token` call issues a brand-new
  access + refresh pair and stamps `revoked_at` on the presented refresh
  token. The old token is dead the moment the new pair is issued.
- **Families**: each authorization-code login mints a fresh family id
  (`fam_<uuid>`) persisted on every token record (access AND refresh). Every
  rotation stays in the same family, so all tokens descending from one login
  share one lineage.
- **Replay = theft**: presenting a refresh token that was already rotated out
  (or otherwise revoked) is treated as a token-theft signal — a legitimate
  client never replays a spent token. The service revokes the **entire
  family** (every refresh token and access-token record in it) and rejects
  with a structured **401 `invalid_grant`**. Family-revoked access tokens
  immediately stop authenticating at `/userinfo` via the hybrid deny-list
  check. The event is logged as `refresh_token_replay_family_revoked`.
- **`aud` stability**: the issuing `client_id` is persisted on token records
  at login, and the refresh grant sources the rotated access token's `aud`
  claim from there — not from whatever the caller presents at refresh time.
  A refresh request that authenticates as a *different* client than the one
  the token was issued to is rejected with `invalid_grant`.
- **TTLs**: refresh tokens live **30 days** (`RefreshTokenTTLSeconds`,
  §6.2 default); access tokens 1 h.
- Legacy rows migrated by `000002` are backfilled into per-session
  `fam_legacy_<session_id>` families; rows whose family is empty are never
  bulk-revoked (guarded no-op).

## PKCE (ARCHITECTURE.md §10.4)

All authorization-code flows **require PKCE** (RFC 7636), S256 only:

- `GET /authorize` rejects requests missing `code_challenge`, missing
  `code_challenge_method`, or with any method other than `S256` (including
  `plain`) — structured **400 `invalid_request`**.
- `POST /token` (code grant) requires `code_verifier` (400
  `invalid_request` when missing) and verifies
  `BASE64URL(SHA-256(code_verifier)) == code_challenge`, rejecting mismatches
  with **400 `invalid_grant`**. There is no PKCE-optional path; codes minted
  before PKCE enforcement (no stored challenge) can no longer be exchanged.

## Endpoints

### Public (no tenant header)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Liveness probe, returns `{"status":"ok"}` |
| `GET` | `/.well-known/oauth-authorization-server` | RFC 8414 metadata |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery |
| `GET` | `/authorize` | Phase-1 stub: auto-approves and redirects with `code`. **Requires PKCE** (`code_challenge` + `code_challenge_method=S256`). With `acr_values=urn:xauth:otp:sms`, interrupts with a hosted SMS-OTP page first |
| `POST` | `/authorize/verify` | OTP-form submission for the second-factor interlude; on success redirects with `code` |
| `POST` | `/token` | Exchange `code` (+ `code_verifier`) or `refresh_token` for a JWT access token + opaque refresh token (+ `id_token` when scope has `openid`) |
| `POST` | `/revoke` | RFC 7009 token revocation |
| `GET` | `/userinfo` | Returns `{sub, email, name}` for the bearer (hybrid JWT + deny-list check) |
| `GET` | `/v1/auth/jwks` | RFC 7517 JSON Web Key Set (canonical route, §4.3) |
| `GET` | `/.well-known/jwks.json` | JWKS alias advertised as `jwks_uri` in discovery |

### Social login (public)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/social/{provider}/authorize` | Real mode: 302 to the provider's consent page (PKCE S256). Stub mode: redirect to our own `/callback` with a mock `code` after ~100 ms |
| `GET` | `/v1/social/{provider}/callback` | Real mode: exchange the code, fetch the profile from userinfo. Both modes: upsert a user, mint a session, redirect to caller's `redirect_uri` |

Providers: `google`, `github`, `microsoft`. Any other value returns 400.

**Real vs stub is decided per provider.** `google` runs the real handshake
when `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET` are set; `github` and
`microsoft` are always stubs today. Real-mode details:

- Our `state` is a single-use crypto-random nonce; the caller's `state` is
  held server-side and echoed only on the final redirect to `redirect_uri`.
- PKCE S256 on the provider leg; the verifier never leaves the process.
- The profile comes from the provider's `userinfo` endpoint; an unverified
  email is rejected (the user upsert is keyed by `(tenant_id, email)`).
- Consent denial (`?error=access_denied`) redirects back to the caller's
  `redirect_uri` with `error` + `state`; provider/back-channel failures are a
  structured 502 `provider_error`.
- In-flight state (nonce + verifier) lives in process memory with a 10-minute
  TTL — the callback must hit the instance that served `/authorize`. **Run a
  single replica** (or add a shared store) before scaling the real flow out.

Google console setup: create an OAuth client (type *Web application*) and add
`<AUTH_ISSUER>/v1/social/google/callback` as an authorized redirect URI —
e.g. `http://localhost:8082/v1/social/google/callback` for local dev.

### Hosted developer console

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/dev` | Browser UI. Signed-out users see "Sign in with Google"; signed-in users can register/test OIDC clients |
| `GET` | `/dev/login/google` | Starts Google social login for the console tenant (`ten_developer`) |
| `GET` | `/dev/social/callback` | Consumes the social-login result, validates state, and sets an HttpOnly console session cookie |
| `POST` | `/dev/clients` | Register a public OIDC client `{client_id, redirect_uris}` from the form |
| `GET` | `/dev/oidc/start?client_id=...` | Launch the built-in relying-party test flow for a registered client |
| `GET` | `/dev/oidc/start?client_id=...&acr=sms` | Same, but requests `acr_values=urn:xauth:otp:sms` and hits the hosted OTP interlude |
| `GET` | `/dev/oidc/callback` | Exchanges the code at `/token` with PKCE and renders token claims |
| `POST` | `/dev/logout` | Invalidates the console session and clears the cookie |

The console is intentionally small: clients are public PKCE clients, duplicate
`client_id`s are rejected, and the in-page registered-client list is
process-local even though the actual OIDC client row is persisted by storage.
For a real tenant admin product, add owner columns / a first-class registration
API instead of relying on this stage/dev bridge.

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

### Internal service-to-service (`/internal/v1/`, ARCHITECTURE.md §10.3)

The **session subtree only** is aliased under `/internal/v1/` — same handlers,
same `X-Tenant-Id` requirement — additionally guarded by `httpx.InternalAuth`:
a request is accepted with a verified mTLS client certificate **or** a matching
`X-Internal-Auth: <INTERNAL_AUTH_SECRET>` header. With neither mechanism
configured the tree is open (local dev). The OIDC/user surface is public-only
and is **not** aliased.

| Method | Path | Caller |
|---|---|---|
| `POST` | `/internal/v1/sessions` | transaction-service (mint session after first-factor auth) |
| `GET` | `/internal/v1/sessions/{id}` | transaction-service (read session posture) |
| `POST` | `/internal/v1/sessions/{id}/refresh` | internal callers |
| `POST` | `/internal/v1/sessions/{id}/invalidate` | internal callers |
| `POST` | `/internal/v1/sessions/{id}/upgrade` | transaction-service (after step-up verification) |

The `/v1/sessions` routes stay as-is for back-compat with phase-1 callers.

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
- **Social login (stub mode)**: mock code-for-profile, 100 ms simulated delay,
  canned `{stub-<provider>@example.com, "<Provider> Stub User"}` profile.
  Applies to providers without real OAuth credentials configured.

## Session lifecycle judgment calls

- **TTL**: 1 hour by default. `refresh` extends from *now* (not from the old
  expiry), so a session that has been idle for 55 min and is then refreshed
  gains the full 1 h rather than only 5 min.
- **Rotation**: on `grant_type=refresh_token`, both the access and the refresh
  token are rotated and the old refresh token is stamped `revoked_at`. Old
  refresh replays return **401 and revoke the whole token family** (see
  "Refresh-token rotation & families" above).
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
| `GOOGLE_CLIENT_ID` | _(unset)_ | OAuth client ID for real Google social login. Both this and the secret must be set, else google falls back to the stub (a partial pair logs `social_provider_partial_config`). |
| `GOOGLE_CLIENT_SECRET` | _(unset)_ | OAuth client secret paired with `GOOGLE_CLIENT_ID`. |
| `OIDC_CLIENTS` | _(unset)_ | Extra public OIDC clients to seed at boot: `id=uri[,uri...][;id=...]` (e.g. `cryptofreight-web=https://cryptofreight.org/callback.html`). Upserted on every boot; malformed values are fatal. Bridges the gap until dynamic client registration. |
| `CORS_ALLOWED_ORIGINS` | _(unset)_ | Comma-separated browser origins (or `*`) allowed to fetch the public OIDC surface (`/token`, `/userinfo`, `/revoke`, discovery, JWKS). Unset -> no CORS headers (server-side callers only). Never applies to the tenant admin API. |
| `AUTHN_PG_DSN` | _(unset)_ | DSN used by the `TestPGStorage*` integration tests. Unset -> tests skip. |
| `TLS_CERT_FILE` | _(unset)_ | PEM certificate this service presents — as the server, and as the client certificate on outbound calls to authenticator-service. Unset (with `TLS_KEY_FILE` also unset) -> plaintext local dev with a `tls_disabled` warning. Setting only one of the pair is fatal. |
| `TLS_KEY_FILE` | _(unset)_ | PEM private key for `TLS_CERT_FILE`. |
| `TLS_CLIENT_CA_FILE` | _(unset)_ | CA bundle; when set the server **requires and verifies** client certificates (mTLS). Verified peers pass `httpx.InternalAuth` without the shared secret. |
| `TLS_CA_FILE` | _(unset)_ | CA bundle used to verify authenticator-service's certificate on outbound calls (`tlsx.Transport`). |
| `INTERNAL_AUTH_SECRET` | _(unset)_ | Shared secret for the `/internal/v1/` tree when mTLS is not in play. Inbound: requests must carry `X-Internal-Auth: <secret>` (constant-time compare) or arrive over verified mTLS, else structured 401. Outbound: the same value is stamped on calls to authenticator-service. Unset -> internal routes are open (local dev). |

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

# 2. Apply the migrations (choose one)
migrate -path services/authentication-service/migrations \
        -database "postgres://postgres:postgres@localhost:5432/auth_db?sslmode=disable" up
# or, in order:
psql "postgres://postgres:postgres@localhost:5432/auth_db?sslmode=disable" \
     -f services/authentication-service/migrations/000001_init.up.sql \
     -f services/authentication-service/migrations/000002_token_families_pkce.up.sql

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
#    PKCE is mandatory: generate a verifier + S256 challenge first.
#    Use -i to see the Location header; pick the code out by hand or with sed.
VERIFIER=$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=')
curl -s -i "http://localhost:8082/authorize?client_id=cli_default&redirect_uri=http://localhost:3000/callback&state=xyz&scope=openid%20profile%20email&tenant_id=ten_acme&user_id=$USER_ID&code_challenge=$CHALLENGE&code_challenge_method=S256"

# 5. Token exchange — POST application/x-www-form-urlencoded (with the PKCE verifier)
CODE="<paste code from step 4>"
curl -s -X POST http://localhost:8082/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE&client_id=cli_default&redirect_uri=http://localhost:3000/callback&code_verifier=$VERIFIER"

# 6. /userinfo with the returned access_token
ACCESS="<paste access_token from step 5>"
curl -s http://localhost:8082/userinfo -H "Authorization: Bearer $ACCESS"

# 7. Refresh token rotation (replaying the old token afterwards returns 401
#    and revokes the whole token family)
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

Run the PG-backed integration tests too (Postgres up + both migrations applied):

```bash
AUTHN_PG_DSN="postgres://postgres:postgres@localhost:5432/auth_db?sslmode=disable" \
  go test ./services/authentication-service/... -run PG
```

Tests cover: health, discovery, user CRUD, user-list keyset pagination
(two-page walk, invalid `limit`/`cursor` rejection), cross-tenant isolation,
duplicate email, full session lifecycle, unknown-user session create, tenant
middleware enforcement, `/authorize` → `/token` happy path with S256 PKCE
(access token is a 3-part JWS verified against the service's own JWKS endpoint
with sub/aud/tenant_id/session_id/scope/exp asserted; `id_token` carries the
`/authorize` nonce; refresh token stays opaque), auth-code one-shot, PKCE
enforcement (`/authorize` 400s on missing challenge / missing method / `plain`;
the code grant 400s on missing or wrong `code_verifier`; fresh-verifier happy
path), refresh-token rotation + old-token revocation (refreshed access token
is a fresh, verifiable JWT whose `aud` comes from the persisted `client_id`,
not the refresh request), family-based revocation (replaying a rotated-out
refresh token 401s and kills every refresh + access record in the family,
including at `/userinfo`), JWKS canonical route + well-known alias parity +
discovery `jwks_uri`, hybrid revocation (`/userinfo` 401s a JWT that still
verifies cryptographically but whose stored record is revoked), foreign-key
rejection (`/userinfo` 401s a JWT signed by a different RSA key even with a
planted record), `/revoke` always-200 semantics, unregistered-redirect
rejection, social authorize → callback round-trip, expired-artifact purge
(expired removed, live kept, purged token no longer authenticates), SHA-256
token hashing determinism, `/internal/v1/sessions` alias parity with `/v1`
in dev mode (identical bodies, tenant header still enforced, users subtree
not aliased), `INTERNAL_AUTH_SECRET` enforcement (missing/wrong header →
structured 401, correct header → 200, public `/v1` stays open), and the
outbound authenticator client stamping `X-Internal-Auth`.
