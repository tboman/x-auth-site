# cryptofreight.org × X-Auth — SPA OIDC integration

Drop-in browser client for X-Auth: real Google login chained into the
standard OIDC authorization-code + PKCE flow. No backend required on the
relying-app side; tokens are RS256 JWTs verifiable against X-Auth's JWKS.

Files:

- `auth.js` — the OIDC client (config block at the top: `issuer`, `clientId`,
  `redirectUri`, `scope`, plus X-Auth's `tenantId`/`provider` extensions).
- `callback.html` — handles both callback legs, then redirects to `/`.
- `index.html` — minimal demo page (login button / profile / logout).

## How the chain works

X-Auth's `/authorize` has no login UI yet (phase-1 stub), so identity comes
from the social leg first:

1. `login()` → `/v1/social/google/authorize` → **Google consent** → X-Auth
   callback verifies the code (PKCE) → redirects to `callback.html` with
   `session_id` + `user_id`.
2. `callback.html` immediately redirects to `/authorize` (OIDC leg) with
   PKCE + `tenant_id` + the verified `user_id` → back to `callback.html`
   with a one-shot `code`.
3. `auth.js` POSTs the `token_endpoint` with the PKCE verifier → stores the
   JWT access token / ID token / refresh token in `sessionStorage`, fetches
   `/userinfo`, and lands on a clean URL.

When X-Auth grows a real login UI on `/authorize`, leg 1 disappears and
`login()` starts at the `authorization_endpoint` directly — the rest of this
client is already standard OIDC.

## X-Auth side — required environment

```bash
GOOGLE_CLIENT_ID=...                 # real Google login
GOOGLE_CLIENT_SECRET=...
OIDC_CLIENTS="cryptofreight-web=https://cryptofreight.org/callback.html,http://localhost:3000/callback.html"
CORS_ALLOWED_ORIGINS="https://cryptofreight.org,http://localhost:3000"
AUTH_ISSUER=...                      # the service's public base URL
PG_DSN=...                           # persistence (in-memory loses users on restart)
```

`OIDC_CLIENTS` seeds the `cryptofreight-web` public client (redirect URIs are
strictly matched at /authorize). `CORS_ALLOWED_ORIGINS` lets the SPA origin
fetch `/token`, `/userinfo`, and `/revoke`.

## Local trial

```bash
# 1. X-Auth (from the x-auth repo root)
GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... \
OIDC_CLIENTS="cryptofreight-web=http://localhost:3000/callback.html" \
CORS_ALLOWED_ORIGINS="http://localhost:3000" \
  go run ./services/authentication-service/cmd

# 2. This demo (from this directory)
python -m http.server 3000
# → http://localhost:3000, click "Sign in with Google (via X-Auth)"
```

Google's console needs no changes for this — it only ever sees X-Auth's own
callback (`http://localhost:8082/v1/social/google/callback`), which is
already registered.

## Deploying on cryptofreight.org

1. Copy `auth.js` + `callback.html` into the site; edit the config block:
   `issuer` → your deployed authentication-service URL, `redirectUri` →
   `https://cryptofreight.org/callback.html`.
2. On the X-Auth deployment, set `OIDC_CLIENTS` and `CORS_ALLOWED_ORIGINS`
   to include the production values (see above), and make sure `AUTH_ISSUER`
   is the public HTTPS URL (it's baked into token `iss` claims and the
   Google redirect).
3. Add `<AUTH_ISSUER>/v1/social/google/callback` to the Google OAuth client's
   authorized redirect URIs.

## Validating tokens on the cryptofreight backend (optional)

The access token is an RS256 JWT. Any backend can verify it statelessly:
fetch `<issuer>/.well-known/jwks.json`, verify signature + `exp` + `iss`,
and read `sub` (X-Auth user id), `tenant_id`, `scope`, `session_id`. Claims
reference: x-auth ARCHITECTURE.md §10.1.

## Current limitations (phase-2 honesty)

- **Tokens live in `sessionStorage`** — per-tab, cleared on tab close, and
  readable by any XSS on the page. Standard SPA trade-off; move the exchange
  server-side (BFF pattern) if cryptofreight gets a backend.
- **Two visible redirects** through X-Auth (social leg + OIDC leg) until
  /authorize gets a real login UI.
- **Single X-Auth replica** for the social leg (in-process handshake state).
- The OIDC client is public (no secret) — fine, PKCE is the proof of
  possession, and /authorize enforces it.
