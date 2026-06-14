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

Identity comes from a hosted login leg first (X-Auth's `/authorize` mints the
code but does not host the login UI in this two-leg model):

1. `login()` → X-Auth's hosted chooser `/login`, where the user picks a method
   (**Google** or **phone**). The method leg authenticates and redirects to
   `callback.html` with `session_id` + `user_id`.
2. `callback.html` immediately redirects to `/authorize` (OIDC leg) with
   PKCE + `tenant_id` → back to `callback.html` with a one-shot `code`.
   (X-Auth derives the user from the session cookie the leg set, so no
   `user_id` is forwarded.)
3. `auth.js` POSTs the `token_endpoint` with the PKCE verifier → stores the
   JWT access token / ID token / refresh token in `sessionStorage`, fetches
   `/userinfo`, and lands on a clean URL.

`/login` is the single entry point — point your login button there and X-Auth
owns the method selection (and can grow new methods) without client changes.

### Step-up (reuse the session — no re-login)

To raise assurance for a sensitive action, call `stepUp(acr)` where `acr` is a
**protection level** — one of the eight `urn:xauth:protect:{high,ultra}:{protected,enhanced,restricted,strict}`
values — or a legacy method (`urn:xauth:otp:sms`, `urn:xauth:fido2`). Naming a
protection level lets X-Auth choose (and later strengthen) the challenge without
a client change. For example, `stepUp('urn:xauth:protect:ultra:strict')` for a
money movement, or `stepUp('urn:xauth:otp:sms')` for a quick check.
It goes **straight to `/authorize`**, reusing the X-Auth session from the
original login, so X-Auth shows only the OTP challenge — it does **not** send the
user back through Google. The fresh tokens come back with `acr`/`amr` claims
proving the step-up. If the session has expired, X-Auth returns `login_required`
and `handleCallback()` falls back to a full `login()` that re-applies the acr.

## X-Auth side — required environment

```bash
GOOGLE_CLIENT_ID=...                 # real Google login
GOOGLE_CLIENT_SECRET=...
CORS_ALLOWED_ORIGINS="https://cryptofreight.org,http://localhost:3000"
AUTH_ISSUER=...                      # the service's public base URL
PG_DSN=...                           # persistence (in-memory loses users on restart)
```

Register the `cryptofreight-web` public client from X-Auth's hosted developer
console (`<issuer>/dev`) after signing in with Google. Redirect URIs are
strictly matched at `/authorize`; include
`https://cryptofreight.org/callback.html` and any local callback you test with.
For non-interactive deployments, `OIDC_CLIENTS` can still seed the same row:
`OIDC_CLIENTS="cryptofreight-web=https://cryptofreight.org/callback.html"`.
`CORS_ALLOWED_ORIGINS` lets the SPA origin fetch `/token`, `/userinfo`, and
`/revoke`.

## Local trial

```bash
# 1. X-Auth (from the x-auth repo root)
GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... \
CORS_ALLOWED_ORIGINS="http://localhost:3000" \
  go run ./services/authentication-service/cmd

# 2. Visit http://localhost:8082/dev, sign in with Google, and register:
#    client_id: cryptofreight-web
#    redirect URI: http://localhost:3000/callback.html
#
# 3. This demo (from this directory)
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
2. On the X-Auth deployment, sign in at `<issuer>/dev` and register the
   `cryptofreight-web` client with the production callback URI, or seed it
   with `OIDC_CLIENTS` for automated environments. Set
   `CORS_ALLOWED_ORIGINS` to include the production origin, and make sure
   `AUTH_ISSUER` is the public HTTPS URL (it's baked into token `iss` claims
   and the Google redirect).
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
