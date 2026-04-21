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
- [x] Opaque UUID tokens stored as SHA-256 hex hashes
- [x] In-memory, tenant-scoped, thread-safe storage
- [x] Unit tests with a mock authenticator-service client

**Deferred to phase 2** (every `TODO(phase-2)` comment in the codebase):

- JWT signing / JWKS publication — phase 1 tokens are opaque UUID strings
- `id_token` issuance
- PKCE enforcement and strict client authentication
- Real first-factor verification (today `POST /v1/sessions` trusts the internal caller)
- Real social-provider OAuth2 handshakes
- PostgreSQL-backed storage (see ARCHITECTURE.md §6)
- Service-to-service signed tokens from transaction-service
- Soft-delete users with GDPR-safe pseudonymisation

## Endpoints

### Public (no tenant header)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Liveness probe, returns `{"status":"ok"}` |
| `GET` | `/.well-known/oauth-authorization-server` | RFC 8414 metadata |
| `GET` | `/.well-known/openid-configuration` | OIDC discovery |
| `GET` | `/authorize` | Phase-1 stub: auto-approves and redirects with `code` |
| `POST` | `/token` | Exchange `code` or `refresh_token` for opaque tokens |
| `POST` | `/revoke` | RFC 7009 token revocation |
| `GET` | `/userinfo` | Returns `{sub, email, name}` for the bearer |

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
| `GET` | `/v1/users` | List users |
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
- **Tokens**: opaque UUIDv4, stored as SHA-256 hex. No signing, no JWKS.
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

## cURL quickstart

Full end-to-end (user create → session create → session refresh → OIDC
authorize → token exchange → userinfo → revoke).

```bash
# 0. Health
curl -s http://localhost:8082/healthz

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

```bash
go test ./services/authentication-service/...
```

Tests cover: health, discovery, user CRUD, cross-tenant isolation, duplicate
email, full session lifecycle, unknown-user session create, tenant middleware
enforcement, `/authorize` → `/token` happy path, auth-code one-shot,
refresh-token rotation + old-token revocation, `/revoke` always-200 semantics,
unregistered-redirect rejection, social authorize → callback round-trip, and
SHA-256 token hashing determinism.
