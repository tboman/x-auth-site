# Integrating X-Auth social login into a web app

How a relying web application ("your app" — we'll use `cryptofreight.org` as
the running example) adds **"Sign in with Google" via X-Auth**, against the
authentication-service contract as it exists today (phase 2.3). No SDK is
required — the integration is two redirects and one server-side REST call.

## How it works

```
Browser                cryptofreight.org           X-Auth auth-service          Google
   │  click "Sign in"        │                            │                       │
   ├────────────────────────>│ 302 to /v1/social/google/  │                       │
   ├───────────────────────────────────────────────────-->│ 302 to consent page   │
   ├──────────────────────────────────────────────────────────────────────────-->│
   │                         │                            │<── code callback ─────┤
   │                         │                            │  (code→token→profile, │
   │                         │                            │   upsert user,        │
   │                         │                            │   mint session)       │
   │<── 302 to /auth/callback?session_id=…&user_id=…&state=… ┤                    │
   ├────────────────────────>│ verify state,              │                       │
   │                         │ GET /v1/sessions/{id} ────>│  (server-to-server)   │
   │<── Set-Cookie ──────────┤ set own login cookie       │                       │
```

X-Auth owns the entire Google handshake (PKCE, state, token exchange,
userinfo). Your app never sees Google credentials or tokens — it receives an
X-Auth `session_id` + `user_id` and validates them server-side.

## Prerequisites

1. **A reachable authentication-service.** For local trials,
   `http://localhost:8082`; for production, a public HTTPS URL (e.g.
   `https://auth.x-auth.com`) with `AUTH_ISSUER` set to that URL.
2. **Google OAuth configured on the X-Auth side** (`GOOGLE_CLIENT_ID` /
   `GOOGLE_CLIENT_SECRET`, and `<AUTH_ISSUER>/v1/social/google/callback`
   registered as an authorized redirect URI in the Google console). Your app
   does **not** need its own Google credentials — that's the point.
3. **A tenant id** for your app, e.g. `ten_cryptofreight`. Phase-2 note: there
   is no tenant-registration API yet — the tenant springs into existence on
   first use, and any string is accepted. Pick one and use it consistently.

If you are integrating with X-Auth as a **full OIDC client** rather than using
the lower-level `session_id` callback shown below, sign in at
`<XAUTH_URL>/dev` with Google and register your public client there. The hosted
console can immediately test that client with the normal code+PKCE round trip
or with `acr_values=urn:xauth:otp:sms` to exercise the SMS-OTP interlude.

## Step 1 — the login button

Link (or redirect) the browser to X-Auth's hosted login chooser, where the
visitor picks a method (Google or phone):

```
GET <XAUTH_URL>/login
      ?tenant_id=ten_cryptofreight
      &redirect_uri=https://cryptofreight.org/auth/callback
      &state=<random, stored in the visitor's cookie/session>
```

- `state` is **your app's** CSRF token for this flow: generate ≥16 random
  bytes per login attempt, stash it (signed cookie or server session), and
  compare on the way back. X-Auth echoes it verbatim; it is never forwarded
  to the provider.
- `redirect_uri` **must be registered** for your tenant's OIDC client (add it
  on the `/dev` or `/admin` dashboard). X-Auth rejects any unregistered
  redirect_uri with `invalid_redirect_uri` — this closes the open-redirect /
  session-leak vector, so the result is only ever delivered to a URL you
  registered. Keep verifying `state` regardless.

> Prefer to skip the hosted chooser and go straight to one method? You still
> can: `GET <XAUTH_URL>/v1/social/google/authorize?...` (same params) drives
> Google directly. `/login` is the recommended entry point because X-Auth owns
> the method selection there.

## Step 2 — the callback handler

X-Auth redirects back to:

```
https://cryptofreight.org/auth/callback?session_id=ses_…&user_id=usr_…&state=…
```

or, when the user cancels at Google: `…?error=access_denied&state=…`.

Your handler must:

1. **Verify `state`** matches what you stored; reject otherwise.
2. **Validate the session server-side** — never trust the query string alone:

   ```
   GET <XAUTH_URL>/v1/sessions/{session_id}
   X-Tenant-Id: ten_cryptofreight
   ```

   A `200` with `user_id` matching the query param, `expires_at` in the
   future, and no `invalidated_at` means the login is genuine. Anything else:
   treat as failed login.
3. **Fetch the profile** (optional):

   ```
   GET <XAUTH_URL>/v1/users/{user_id}
   X-Tenant-Id: ten_cryptofreight
   ```

   Returns `{id, email, name, …}` — your stable X-Auth identity is `id`
   (unique per tenant; stable across repeat logins via email upsert).
4. **Set your own login cookie** (your app's session, referencing the X-Auth
   `session_id` and `user_id`), then redirect to a clean URL so the
   `session_id` doesn't linger in the location bar / browser history.

## Express example

```js
import express from "express";
import crypto from "node:crypto";
import cookieParser from "cookie-parser";

const XAUTH = process.env.XAUTH_URL ?? "http://localhost:8082";
const TENANT = "ten_cryptofreight";
const app = express();
app.use(cookieParser());

// Step 1: kick off the flow — send the visitor to the hosted login chooser.
app.get("/auth/login", (req, res) => {
  const state = crypto.randomBytes(24).toString("base64url");
  res.cookie("xauth_state", state, { httpOnly: true, sameSite: "lax", maxAge: 600_000 });
  const u = new URL(`${XAUTH}/login`);
  u.searchParams.set("tenant_id", TENANT);
  u.searchParams.set("redirect_uri", `${req.protocol}://${req.get("host")}/auth/callback`);
  u.searchParams.set("state", state);
  res.redirect(u.toString());
});

// Step 2: receive the result
app.get("/auth/callback", async (req, res) => {
  const { session_id, user_id, state, error } = req.query;
  if (error) return res.redirect("/login?error=" + encodeURIComponent(error));
  if (!state || state !== req.cookies.xauth_state) return res.status(403).send("state mismatch");
  res.clearCookie("xauth_state");

  // Server-side validation — the trust anchor of the whole integration.
  const sess = await fetch(`${XAUTH}/v1/sessions/${session_id}`, {
    headers: { "X-Tenant-Id": TENANT },
  }).then(r => (r.ok ? r.json() : null));
  if (!sess || sess.user_id !== user_id || new Date(sess.expires_at) < new Date()) {
    return res.status(403).send("invalid session");
  }

  const user = await fetch(`${XAUTH}/v1/users/${user_id}`, {
    headers: { "X-Tenant-Id": TENANT },
  }).then(r => r.json());

  // Your app's own session. (Use your framework's session middleware in
  // production rather than a bare cookie.)
  res.cookie("cf_session", JSON.stringify({ sid: sess.id, uid: user.id, email: user.email }),
    { httpOnly: true, sameSite: "lax", secure: req.protocol === "https" });
  res.redirect("/");
});

// Logout: kill both your cookie and the X-Auth session.
app.post("/auth/logout", async (req, res) => {
  const s = req.cookies.cf_session && JSON.parse(req.cookies.cf_session);
  if (s) await fetch(`${XAUTH}/v1/sessions/${s.sid}/invalidate`,
    { method: "POST", headers: { "X-Tenant-Id": TENANT } });
  res.clearCookie("cf_session");
  res.redirect("/");
});

app.listen(3000);
```

## Session lifecycle from your app

| Action | Call |
|---|---|
| Check still valid | `GET /v1/sessions/{id}` — `expires_at` future, no `invalidated_at` |
| Keep alive | `POST /v1/sessions/{id}/refresh` — extends 1h from now |
| Logout | `POST /v1/sessions/{id}/invalidate` — idempotent |

All with `X-Tenant-Id: ten_cryptofreight`. Sessions live 1 hour unless
refreshed; refresh on activity if you want sliding sessions.

## Step-up & protection levels (`acr_values`)

For an **authenticated** user, your app guards a sensitive action by stating the
assurance it needs on the `acr_values` of an `/authorize` request — reusing the
existing session, so there's no second login (see `stepUp()` in the example
`auth.js`, or just navigate to `/authorize` directly with `acr_values` set).
X-Auth decides: if the session already satisfies the level it **passes through**
and mints the code immediately; otherwise it runs the matching **challenge**, and
the resulting token carries the achieved level in its `acr` claim (`amr` holds the
method actually used).

**Preferred — protection levels.** Instead of naming a method, name the
protection a level the action needs. Eight levels, two bands, increasing in
strength (rank 1–8). Once a session satisfies a level, an equal-or-lower request
passes through; a higher one re-challenges.

| Rank | `acr_values` | Band |
|---|---|---|
| 1 | `urn:xauth:protect:high:protected`   | High risk |
| 2 | `urn:xauth:protect:high:enhanced`    | High risk |
| 3 | `urn:xauth:protect:high:restricted`  | High risk |
| 4 | `urn:xauth:protect:high:strict`      | High risk |
| 5 | `urn:xauth:protect:ultra:protected`  | Ultra-high risk |
| 6 | `urn:xauth:protect:ultra:enhanced`   | Ultra-high risk |
| 7 | `urn:xauth:protect:ultra:restricted` | Ultra-high risk |
| 8 | `urn:xauth:protect:ultra:strict`     | Ultra-high risk (finance / critical) |

> The mapping from level → challenge (and, later, whether the live context even
> requires one) is owned by X-Auth and will be risk-driven; today it is a fixed
> escalation ladder. Your app only commits to the **level**, never the method —
> so the bar can get stronger without a client change.

**Legacy — explicit methods.** You can still request a specific method; kept for
back-compat:

| `acr_values` | Challenge |
|---|---|
| `urn:xauth:otp:sms` | SMS one-time code |
| `urn:xauth:fido2`   | Passkey / FIDO2 |

All ten values are advertised in discovery under `acr_values_supported` at
`/.well-known/openid-configuration`.

## Local trial (cryptofreight on your laptop)

1. Run authentication-service with Google credentials (see the service
   README); it listens on `:8082`.
2. Run your app on `:3000` with `XAUTH_URL=http://localhost:8082`.
3. `redirect_uri` becomes `http://localhost:3000/auth/callback` — no Google
   console change needed (Google only ever sees X-Auth's own callback, which
   is already registered).

## Going to production

- Deploy authentication-service behind HTTPS with a stable public URL, set
  `AUTH_ISSUER` to it, add `<AUTH_ISSUER>/v1/social/google/callback` to the
  Google client, and set `PG_DSN` (in-memory storage loses every user and
  session on restart).
- **Single replica** for now: the in-flight social handshake state is held in
  process memory (10-minute TTL).
- The tenant-scoped API (`/v1/sessions/*`, `/v1/users/*`) currently requires
  only the `X-Tenant-Id` header — no caller authentication. Until that
  tightens (phase-3), do not expose the authentication-service's tenant API
  to networks you don't trust; in the Cloud Run topology, front it so only
  your app's backend can reach those paths, or keep the service internal and
  proxy the two social endpoints.

## Today's limitations (read before shipping)

| Limitation | Consequence | Mitigation |
|---|---|---|
| ~~`redirect_uri` not allowlisted~~ **(fixed)** | — | `redirect_uri` must now match a redirect URI registered for your tenant's client (or be same-origin); unregistered URIs are rejected. Still verify `state`. |
| `session_id` arrives in the query string | It's a bearer credential in browser history / logs | Validate + set cookie + redirect to a clean URL immediately |
| Tenant API unauthenticated (header only) | Anyone who can reach the service can read/mint sessions for any tenant | Network isolation; phase-3 API keys |
| No `user_identities` table | Provider link is by email; email change at Google = new user | Acceptable for trial; linking table planned |
| In-memory handshake state | Multi-replica deployments break the social flow | Single replica or shared store |
