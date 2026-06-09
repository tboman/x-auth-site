# broker-service

Public-facing entry point for **X-Auth for Agents** (product 2). The broker speaks
MCP, OAuth 2.0, OIDC, RFC 7591 Dynamic Client Registration, and Client Identifier
Metadata Document (CIMD), and orchestrates install creation by calling the three
internal sister services.

See [`REQUIREMENTS.md`](../../REQUIREMENTS.md) §4 for the full service contract.

## Purpose

When an AI chat owner installs `mcp.x-auth.com` as a tool, broker-service:

1. handles the OIDC/OAuth handshake (or the manual install fallback)
2. looks up the chosen persona in **persona-service**
3. claims a free identity from the relevant pool in **pool-service**
4. records the active grant in **grant-service**
5. returns bearer tokens to the runtime

Every bound install is tracked here and can be individually revoked, which cascades
to grant revocation and identity release.

## Storage

Storage is swappable via the `Storage` interface in `internal/storage.go`:

- **`MemStorage`** — phase-1 in-memory implementation. Used when `PG_DSN` is unset
  (developer laptops, unit tests, short-lived CI).
- **`PGStorage`** — phase-2 Postgres implementation following the shared pattern in
  [`docs/postgres.md`](../../docs/postgres.md). Schema lives in `migrations/`
  (tables: `installs`, `dcr_clients`, `auth_codes`, `tokens`). Auth codes and the
  phase-1 opaque tokens are persisted as plain rows — no Redis yet; TTLs are
  enforced at the handler layer, and a background sweeper deletes expired rows
  every `PURGE_INTERVAL` (see **Environment**) so the tables don't grow unbounded.

## Phase 1 scope

- [x] Install CRUD + revoke
- [x] Orchestration against persona/pool/grant services
- [x] OAuth/OIDC discovery documents (RFC 8414, OpenID Connect Discovery)
- [x] RFC 7591 Dynamic Client Registration (`POST /register`)
- [x] CIMD metadata document (`GET /metadata.json`)
- [x] `/authorize` auto-approve stub, `/token` code exchange, `/revoke`, `/userinfo`
- [x] PKCE enforcement, S256-only (RFC 7636; mandated by ARCHITECTURE.md §10.4 and the MCP authorization spec)
- [x] MCP SSE + RPC stubs
- [x] Unit tests with mocked HTTP clients

**Deferred to phase 2** (see the `TODO(phase-2)` comments in-code):

- ~~JWT signing / JWKS publication~~ — landed: RS256 access tokens + `/.well-known/jwks.json` (see **Token format** below)
- Real MCP protocol handling
- ~~Persistent storage~~ — landed: Postgres-backed `PGStorage` (see **Storage** above)
- Initial-access-token-gated DCR
- ~~Service-to-service mTLS / JWT~~ — landed: TLS/mTLS on the public listener via
  `tlsx.ServerConfig`, client TLS on downstream calls via `tlsx.Transport`, and
  `X-Internal-Auth` shared-secret header on every outbound request (see
  **Transport security** below)
- Scope intersection per OAuth semantics

## Endpoints

### Public OAuth / OIDC (no tenant header required)

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | liveness probe, returns `{"status":"ok"}` |
| GET | `/.well-known/oauth-authorization-server` | RFC 8414 metadata |
| GET | `/.well-known/openid-configuration` | OIDC discovery |
| GET | `/.well-known/jwks.json` | RFC 7517 key set — the public half of the access-token signing key (`jwks_uri` in both discovery docs) |
| POST | `/register` | RFC 7591 Dynamic Client Registration |
| GET | `/metadata.json` | CIMD document for the default X-Auth MCP client |
| GET | `/authorize` | phase-1 stub: auto-approves and redirects back with `code`. **PKCE required**: `code_challenge` + `code_challenge_method=S256` (anything else is a structured 400) |
| POST | `/token` | exchanges `code` + `code_verifier` for a signed JWT access token + opaque refresh token, orchestrates install finalization. SHA-256(verifier) base64url-no-pad must equal the stored challenge or the grant is rejected with `invalid_grant` |
| POST | `/revoke` | RFC 7009 token revocation, forwarded to grant-service |
| GET | `/userinfo` | returns `{sub, persona, scopes, install_id}` for the bearer — hybrid check: JWT signature/exp/iss **and** unrevoked local record |

## PKCE (mandatory, S256 only)

PKCE per RFC 7636 is enforced on every authorization-code exchange — there is no
PKCE-optional path. The MCP authorization spec mandates PKCE for MCP clients,
and ARCHITECTURE.md §10.4 applies it platform-wide.

- `/authorize` rejects requests missing `code_challenge`, and rejects any
  `code_challenge_method` other than `S256` (including an omitted method, which
  RFC 7636 would default to `plain`) with `400 {"error":"invalid_request"}`.
- The challenge is persisted on the one-shot auth-code record
  (`auth_codes.code_challenge`, migration `000002`).
- `/token` requires `code_verifier` (`400 invalid_request` if missing — checked
  before the code is consumed, so the one-shot code is not burned) and verifies
  `BASE64URL-NOPAD(SHA256(code_verifier)) == stored challenge` in constant time;
  mismatch — or a code with no stored challenge — is `400 {"error":"invalid_grant"}`.
- Both discovery documents advertise `code_challenge_methods_supported: ["S256"]`,
  which is exactly what is enforced.

## Token format

- **Access token** — compact RS256 JWS signed with the broker's key. Claims:
  `sub` = the claimed identity's `subject_id` (REQUIREMENTS.md §2: the stable
  identifier used in the OAuth `sub` claim), `iss` = `JWT_ISSUER`, `aud` = the
  requesting client id, `tenant_id`, `scope` (persona scopes), `exp` = `iat` +
  persona `token_ttl_seconds`, `jti`, plus install-binding extras `install_id`,
  `persona_id`, `identity_id`. Verify offline against `/.well-known/jwks.json`.
- **Refresh token** — opaque UUID, unchanged: it is only ever redeemed back at
  this service, so opacity limits blast radius.
- grant-service still receives only SHA-256 hex digests of both tokens
  (`access_token_hash` is the digest of the full JWT string).
- `/userinfo` applies **both** checks: cryptographic verification (signature,
  exp/iat with 30s leeway, issuer) *and* a local token-record lookup, which acts
  as the revocation deny-list — a revoked token stays cryptographically valid
  until `exp` but is rejected immediately.

### MCP stubs (phase 1)

| Method | Path | Purpose |
|---|---|---|
| GET | `/mcp/sse` | opens SSE, emits one `ready` event, closes |
| POST | `/mcp/rpc` | echoes JSON-RPC 2.0 envelopes with a canned `{stub:true}` result |

### Install admin (tenant-scoped, `X-Tenant-Id` required)

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/installs` | manual install creation — bypasses OIDC, returns `pending` install |
| GET | `/v1/installs` | list installs newest-first; keyset pagination via `limit` (default 100, max 500) and `cursor` (RFC3339). Returns `{"installs": [...], "next_cursor": "..."}`; `next_cursor` is present only when the page is full |
| GET | `/v1/installs/{id}` | read an install (tenant-scoped) |
| POST | `/v1/installs/{id}/revoke` | mark revoked, release identity, revoke grants — idempotent |

## Phase-1 shortcuts

- **Tenant on `/authorize`**: real OIDC derives the tenant from the authenticated
  user session. Phase 1 accepts `tenant_id` as a query parameter because there is
  no real login yet.
- **Pool on `/authorize`**: `pool_id` is required as a query parameter. In a
  production flow persona-service would expose which pool(s) a persona is
  eligible for and broker-service would pick one automatically. Keeping this in
  the URL avoids a cross-service dependency the sister team hasn't shipped yet.
- **Tokens**: access tokens are now signed RS256 JWTs (see **Token format**);
  refresh tokens remain opaque UUIDs. The broker still keeps a local token
  record per issued token — it backs `/userinfo` metadata and acts as the
  revocation deny-list. A later phase defers introspection to grant-service and
  drops that duplicated state.
- **Scope resolution**: phase 1 returns the persona's scopes verbatim and ignores
  the `scope` parameter from `/authorize`. Proper intersection per RFC 6749 is
  phase 2.
- **`grant-service` revoke-by-install**: REQUIREMENTS.md §4 only lists
  `POST /v1/grants/{id}/revoke`. broker-service calls a convention endpoint
  `POST /internal/v1/installs/{install_id}/revoke-grants` on grant-service. Confirmed
  with the parallel grant-service implementer; update `internal/clients.go:RevokeGrantsForInstall`
  if the contract changes.

## Orchestration flow (`/authorize` → `/token`)

```
GET /authorize?...&persona_id=P&pool_id=PL&tenant_id=T
                 &code_challenge=<S256(verifier)>&code_challenge_method=S256
  → broker stores a pending AuthCode (incl. the PKCE challenge)
  → 302 redirect_uri?code=<uuid>&state=...

POST /token with code=<uuid>&code_verifier=<verifier>
  1. consume code (one-shot) + verify SHA256(code_verifier) == stored challenge
  2. create pending Install
  3. GET  persona-service /internal/v1/personas/P     → Persona (scopes, ttl)
  4. POST pool-service    /internal/v1/pools/PL/claim → Identity
  5. mint RS256 JWT access token + opaque refresh token
  6. POST grant-service   /internal/v1/grants          → Grant (SHA-256 token hashes)
     └─ on failure: release identity, revoke install, return 502
  7. mark Install active with identity_id
  → 200 { access_token, refresh_token, token_type, expires_in, scope }
```

If any downstream call fails, compensation runs best-effort (release identity,
mark install revoked) and the client receives 502 with `error: downstream_error`.

## Environment

| Var | Default | Notes |
|---|---|---|
| `PORT` | `8182` | |
| `PERSONA_SERVICE_URL` | `http://localhost:8180` | |
| `POOL_SERVICE_URL` | `http://localhost:8181` | |
| `GRANT_SERVICE_URL` | `http://localhost:8183` | |
| `BROKER_ISSUER` | `http://localhost:8182` | public base URL in discovery documents (production: `https://mcp.x-auth.com`) |
| `JWT_SIGNING_KEY` | _(unset)_ | PEM-encoded RSA private key (PKCS#1 or PKCS#8) for RS256 access-token signing. Unset → ephemeral per-process key with a logged warning (tokens won't verify across restarts/replicas). |
| `JWT_ISSUER` | value of `BROKER_ISSUER` | `iss` claim in issued access tokens. Defaults to the discovery-document issuer so JWTs validate against the served metadata; override only for split-horizon deployments. |
| `PG_DSN` | _(unset)_ | When set, phase-2 Postgres storage. Unset -> in-memory. |
| `PURGE_INTERVAL` | `5m` | Go duration between expired-artifact sweeps (tokens past `expires_at`, auth codes older than the 300s code TTL). Each sweep logs `purge_expired` with the removed count. Invalid values fall back to `5m`. |
| `PG_DSN_BROKER_SERVICE` | _(unset)_ | Per-service override of `PG_DSN`. |
| `PG_MAX_CONNS` | `10` | Pool ceiling. |
| `BROKER_PG_DSN` | _(unset)_ | DSN used by the `TestPGStorage*` integration tests. Unset -> tests skip. |
| `TLS_CERT_FILE` | _(unset)_ | PEM certificate the public listener presents; also presented as the client certificate on downstream calls. Must be set together with `TLS_KEY_FILE`; setting only one is a startup error. Both unset -> plaintext (local dev). |
| `TLS_KEY_FILE` | _(unset)_ | PEM private key for `TLS_CERT_FILE`. |
| `TLS_CLIENT_CA_FILE` | _(unset)_ | CA bundle; when set, client certificates are **required and verified** on the public listener (mTLS). Requires the cert/key pair above. |
| `TLS_CA_FILE` | _(unset)_ | CA bundle used to verify persona/pool/grant-service certificates when dialing out. Unset -> system roots (or plaintext if downstreams serve plaintext). |
| `INTERNAL_AUTH_SECRET` | _(unset)_ | Shared secret sent as `X-Internal-Auth` on every downstream call when mTLS is not in play; must match the sister services' value. Unset -> header omitted (dev). |

## Transport security (ARCHITECTURE.md §10.3)

broker-service is on both sides of the trust boundary: it is the **public MCP
broker** (TLS server) and a **caller** of the three internal sister services
(TLS client).

- **Listener** — `tlsx.ServerConfig` builds TLS from `TLS_CERT_FILE` /
  `TLS_KEY_FILE` (plus optional `TLS_CLIENT_CA_FILE` for mTLS) and the server
  starts via `httpx.RunTLS`. No TLS vars -> plaintext local dev; a partial pair
  is a startup error, never a silent plaintext fallback.
- **Downstream calls** — the shared `http.Client` uses `tlsx.Transport`
  (`TLS_CA_FILE` verifies the callee, the cert/key pair is presented for the
  callee's mTLS check), and every request carries `X-Internal-Auth` when
  `INTERNAL_AUTH_SECRET` is set. All persona/pool/grant calls target the
  sister services' guarded `/internal/v1/` trees:
  `GET /internal/v1/personas/{id}`, `POST /internal/v1/pools/{id}/claim`,
  `POST /internal/v1/identities/{id}/release`, `POST /internal/v1/grants`,
  `POST /internal/v1/installs/{id}/revoke-grants`, `POST /internal/v1/revoke`.

## Local run

Without Postgres (in-memory fallback):

```bash
# from repo root
make run-broker
# equivalent:
PORT=8182 SERVICE_NAME=broker-service \
    PERSONA_SERVICE_URL=http://localhost:8180 \
    POOL_SERVICE_URL=http://localhost:8181 \
    GRANT_SERVICE_URL=http://localhost:8183 \
    BROKER_ISSUER=http://localhost:8182 \
    go run ./services/broker-service/cmd
```

With Postgres (phase 2):

```bash
# 1. Start Postgres
docker run --rm -d --name xauth-pg \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=broker_db -p 5432:5432 postgres:16

# 2. Apply the migrations (choose one)
migrate -path services/broker-service/migrations \
        -database "postgres://postgres:postgres@localhost:5432/broker_db?sslmode=disable" up
# or, in order:
psql "postgres://postgres:postgres@localhost:5432/broker_db?sslmode=disable" \
     -f services/broker-service/migrations/000001_init.up.sql \
     -f services/broker-service/migrations/000002_auth_code_pkce.up.sql

# 3. Run the service
PG_DSN="postgres://postgres:postgres@localhost:5432/broker_db?sslmode=disable" \
  go run ./services/broker-service/cmd
```

## Example: end-to-end install via cURL

Assumes persona-service has persona `PERSONA_ID` with scopes=[mcp], and
pool-service has pool `POOL_ID` containing at least one `available` identity.

```bash
# 0. PKCE setup: pick a random verifier, derive the S256 challenge.
VERIFIER=$(openssl rand -base64 48 | tr -d '=+/' | cut -c1-43)
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | basenc --base64url | tr -d '=')

# 1. Kick off authorization — the stub auto-approves. PKCE is mandatory.
curl -sSI "http://localhost:8182/authorize?client_id=client-1&redirect_uri=https://app.example.com/cb&state=xyz&scope=openid+mcp&persona_id=$PERSONA_ID&pool_id=$POOL_ID&tenant_id=tenant-1&runtime=claude&code_challenge=$CHALLENGE&code_challenge_method=S256"
# → HTTP/1.1 302 Found
# → Location: https://app.example.com/cb?code=<CODE>&state=xyz

# 2. Exchange the code for tokens (triggers the orchestration cascade).
#    code_verifier must hash to the challenge from step 1 or you get invalid_grant.
curl -sS -X POST http://localhost:8182/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=<CODE>&client_id=client-1&code_verifier=$VERIFIER"
# → 200 {
#     "access_token":  "<RS256 JWT — eyJhbGciOiJSUzI1NiIs...>",
#     "refresh_token": "<uuid>",
#     "token_type":    "Bearer",
#     "expires_in":    900,
#     "scope":         "mcp"
#   }

# 3. Look up the install the broker just finalized.
curl -sS http://localhost:8182/v1/installs/<INSTALL_ID> \
  -H "X-Tenant-Id: tenant-1"
# → 200 {
#     "id":          "<INSTALL_ID>",
#     "tenant_id":   "tenant-1",
#     "runtime":     "claude",
#     "persona_id":  "<PERSONA_ID>",
#     "identity_id": "<IDENTITY_ID>",
#     "client_id":   "client-1",
#     "status":      "active",
#     "created_at":  "…",
#     "updated_at":  "…"
#   }

# 4. Revoke.
curl -sS -X POST http://localhost:8182/v1/installs/<INSTALL_ID>/revoke \
  -H "X-Tenant-Id: tenant-1"
# → 204 No Content
```

## Tests

Unit tests (no DB needed — they mock the three sister service clients and use
`MemStorage`; no network calls are made):

```bash
go test ./services/broker-service/...
```

Run the PG-backed integration tests too:

```bash
BROKER_PG_DSN="postgres://postgres:postgres@localhost:5432/broker_db?sslmode=disable" \
  go test ./services/broker-service/... -run PG
```
