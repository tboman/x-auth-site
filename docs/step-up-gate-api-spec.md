# X-Auth Step-Up Gate API — draft spec

**Status:** draft v0.1 (2026-07-08) · **Owner:** XentraNET
**Product:** an additive "gate" you call *before* a risky action. It scores the action's risk, challenges the user (passkey / SMS) when needed, and hands you a signed, action-bound proof to verify before you execute. It sits on top of your existing auth — no login migration.

> One-line pitch: **"Fraud check + re-auth for the actions that lose money — one API call."**
> This is a repackaging of shipped X-Auth capabilities (`/v1/advice` risk scoring, the 8-level protection-ladder step-up, FIDO2 + SMS-OTP, hosted branded step-up pages). See [Mapping to existing services](#mapping-to-existing-services).

---

## 1. Design principles (non-negotiables)

1. **Additive, never in the login path.** You keep Clerk/Auth0/Supabase/your-own auth. The gate wraps individual *actions* (a payout, a payee change, an admin delete), so adopting it never means a migration.
2. **Fail-open by default.** If the API is unreachable or slow (>3s), the SDK returns `allow` with `degraded: true`. X-Auth's downtime must never lock your users out of their own app. Fail-closed is opt-in per key for genuinely critical actions.
3. **Action-bound proof.** The grant returned after a challenge is cryptographically bound to the *specific* action (type + material params). A grant for "send $1 to A" cannot be replayed for "send $10,000 to B."
4. **Legible in 10 lines.** The happy path is two calls: `gate()` before the action, `grants.verify()` before executing. No standards vocabulary required to use it.
5. **Verifiable without calling us.** Grants are JWTs verifiable locally against a JWKS endpoint, so your execute path has no hard runtime dependency on X-Auth.

---

## 2. Concepts

| Term | Meaning |
|---|---|
| **Action** | The risky thing your app is about to do: `payment.send`, `payout.create`, `user.email.change`, `admin.record.delete`. You define the taxonomy (dot-namespaced strings). |
| **Gate** | A single evaluation of one action. Returns a **decision**. |
| **Decision** | `allow` · `challenge` · `block` (enforce mode), or `advisory` (advisory mode). |
| **Challenge** | A step-up the user must pass (passkey / SMS-OTP), delivered via a hosted branded page (redirect) or headlessly via the SDK. |
| **Grant** | A short-lived, single-use, **action-bound** signed JWT proving the gate was satisfied. Your backend verifies it immediately before executing. |
| **Risk** | Score `0–100` + `level` (`low`/`medium`/`high`/`critical`) + human-readable `signals`. |
| **acr / amr** | The assurance level reached (`acr`, mapped to the 8-level ladder) and the methods used (`amr`, e.g. `["passkey"]`). |

---

## 3. Base URLs, versioning, auth

```
API base            https://api.x-auth.com/v1
Hosted step-up UI   https://step.x-auth.com
JWKS                https://api.x-auth.com/.well-known/jwks.json
```

- **Versioning:** date-based, pinned per request via `X-Auth-Version: 2026-07-08`. Absent → your account's default version.
- **Keys:** `sk_live_…` (secret, server-side only) and `pk_live_…` (publishable, browser SDK — device fingerprint + completing challenges only, never scores actions). Test-mode counterparts `sk_test_…` / `pk_test_…`.
- **Auth header:** `Authorization: Bearer sk_live_…` on all server calls.
- **Idempotency:** send `Idempotency-Key: <uuid>` on `POST /gate`; identical key + body within 24h returns the original result (critical for payment paths).

---

## 4. The happy path (2 calls)

### 4.1 `POST /v1/gate` — evaluate an action

Request:

```http
POST /v1/gate
Authorization: Bearer sk_live_…
Idempotency-Key: 6f1c…
X-Auth-Version: 2026-07-08
Content-Type: application/json
```
```json
{
  "user": {
    "id": "usr_abc",
    "email": "sam@example.com",
    "phone": "+15551234567"
  },
  "action": {
    "type": "payment.send",
    "params": { "amount": 4200, "currency": "USD", "destination": "acct_9f2" },
    "description": "Send $42.00 to Acme Payroll"
  },
  "context": {
    "ip": "203.0.113.5",
    "user_agent": "Mozilla/5.0 …",
    "device_token": "dvc_1a2b…",
    "session_acr": "urn:x-auth:acr:pwd"
  },
  "options": {
    "mode": "enforce",
    "allowed_methods": ["passkey", "sms_otp"],
    "return_url": "https://app.example.com/pay/confirm?order=987",
    "grant_ttl": 300,
    "fail_mode": "open"
  }
}
```

Field notes:
- `action.params` — **only these fields are bound into the grant.** Include everything that, if changed, should invalidate the proof (amount, currency, destination, resource id). Omit display-only fluff.
- `context.device_token` — from the browser SDK (`xauth.device()`); feeds device-recognition signals. Optional but improves scoring.
- `context.session_acr` — what the user already satisfied at login; lets the ladder skip redundant step-up.
- `options.mode` — `enforce` (returns allow/challenge/block) or `advisory` (returns score + recommendation, never blocks or challenges).
- `options.return_url` — present ⇒ **hosted-redirect mode**. Absent ⇒ **headless mode** (§6).
- `options.fail_mode` — `open` (default) or `closed`.

Responses:

**allow** (low risk, no challenge needed) — grant issued immediately:
```json
{
  "decision": "allow",
  "risk": { "score": 12, "level": "low", "signals": ["known_device", "same_geo", "amount_typical"] },
  "grant": "eyJhbGciOiJFUzI1Ni␣…",
  "grant_id": "grt_7 hQ…",
  "degraded": false
}
```

**challenge** (hosted-redirect mode):
```json
{
  "decision": "challenge",
  "risk": { "score": 74, "level": "high", "signals": ["new_device", "amount_anomaly", "new_payee"] },
  "challenge": {
    "id": "chl_Kd3…",
    "methods": ["passkey", "sms_otp"],
    "hosted_url": "https://step.x-auth.com/c/chl_Kd3…",
    "expires_at": "2026-07-08T10:12:00Z"
  }
}
```
Redirect the user to `hosted_url`. They complete passkey/SMS on your branded page; we redirect back to `return_url` with `?grant=<jwt>&grant_id=grt_…` on success, or `?error=abandoned|failed|expired&challenge_id=chl_…` otherwise.

**block** (over the hard threshold):
```json
{
  "decision": "block",
  "risk": { "score": 96, "level": "critical", "signals": ["impossible_travel", "credential_stuffing_pattern"] },
  "reason": "risk_threshold_exceeded"
}
```

**advisory** (`options.mode="advisory"`):
```json
{
  "decision": "advisory",
  "recommended": "challenge",
  "risk": { "score": 74, "level": "high", "signals": ["new_device", "amount_anomaly"] }
}
```

**degraded / fail-open** (API couldn't score in time; `fail_mode:"open"`):
```json
{ "decision": "allow", "risk": { "level": "unknown" }, "degraded": true }
```

### 4.2 `POST /v1/grants/introspect` — verify before executing

Prefer **local verification** against the JWKS (§7) — zero runtime dependency on us. Use introspect when you want us to also enforce single-use and match the action for you:

```json
POST /v1/grants/introspect
{
  "grant": "eyJhbGciOiJFUzI1Ni␣…",
  "expected_action": {
    "type": "payment.send",
    "params": { "amount": 4200, "currency": "USD", "destination": "acct_9f2" }
  }
}
```
```json
{
  "active": true,
  "action_matches": true,
  "sub": "usr_abc",
  "acr": "urn:x-auth:acr:l3",
  "amr": ["passkey"],
  "risk": 74,
  "consumed": true,
  "exp": "2026-07-08T10:12:00Z"
}
```
`consumed:true` means this call burned the single-use `jti`; a second introspect of the same grant returns `active:false, reason:"already_consumed"`. Only execute the action when `active && action_matches`.

---

## 5. The grant (proof) token

A compact ES256 JWT. Claims:

```json
{
  "iss": "https://api.x-auth.com",
  "sub": "usr_abc",
  "aud": "prj_live_8williams",         // your project id
  "act": "sha256-b64u:Xy9…",            // canonical hash of action.type + bound params
  "act_type": "payment.send",
  "amr": ["passkey"],                   // [] or ["none"] when allowed without a challenge
  "acr": "urn:x-auth:acr:l3",           // ladder level reached (§8)
  "risk": 74,
  "jti": "grt_7hQ…",                    // single-use id
  "iat": 1783934400,
  "exp": 1783934700                     // grant_ttl (default 300s)
}
```

**Action binding.** `act` = `base64url(sha256( canonical_json({type, params}) ))` with keys sorted and numbers normalized. To verify locally: recompute the hash from the action you're *about to perform* and compare to `act`. Mismatch ⇒ reject (the user approved a different action).

---

## 6. Headless mode (no redirect)

Omit `return_url`. The `gate` response returns per-method challenge material instead of a `hosted_url`:

```json
{
  "decision": "challenge",
  "challenge": {
    "id": "chl_Kd3…",
    "methods": ["passkey", "sms_otp"],
    "passkey": { "publicKey": { "challenge": "…", "allowCredentials": [ … ] } },
    "sms_otp": { "sent_to": "+1•••••34567", "length": 6 },
    "expires_at": "2026-07-08T10:12:00Z"
  }
}
```

Complete it:

```json
POST /v1/challenges/chl_Kd3…/verify
{ "method": "sms_otp", "code": "418923" }
```
```json
// success
{ "status": "completed", "grant": "eyJ…", "grant_id": "grt_…" }
// failure
{ "status": "failed", "attempts_remaining": 2 }
```
For passkey, submit `{ "method": "passkey", "assertion": <navigator.credentials.get result> }`.

Poll with `GET /v1/challenges/chl_Kd3…` (`status`: `pending` → `completed` / `failed` / `expired`).

---

## 7. Local grant verification

`GET /.well-known/jwks.json` publishes the ES256 public keys. Verify a grant with any JWT library:

1. Signature valid against JWKS `kid`.
2. `iss == https://api.x-auth.com`, `aud == <your project id>`, `exp` in future.
3. `act ==` your recomputed action hash.
4. `jti` not seen before (you enforce single-use, or delegate to introspect).

Then execute. No network call to X-Auth required on the execute path.

---

## 8. acr ladder (maps to the 8-level protection ladder)

| acr | Meaning | Typical trigger |
|---|---|---|
| `urn:x-auth:acr:l0` | session only | trivial action |
| `urn:x-auth:acr:l1` | recent auth / device recognized | low risk |
| `urn:x-auth:acr:l2` | OTP (SMS/email) | medium risk |
| `urn:x-auth:acr:l3` | phishing-resistant (passkey/FIDO2) | high risk / money movement |
| `urn:x-auth:acr:l4` | passkey + out-of-band confirm | critical *(uses CIBA once shipped — not in v0.1)* |

You can require a floor per action type via project config (e.g. `payment.send ⇒ min acr l3`).

---

## 9. Webhooks (optional)

Subscribe to `challenge.completed`, `challenge.failed`, `challenge.expired`. Payloads carry `grant_id` (not the grant itself), `challenge.id`, `action.type`, `sub`. Signed with `X-Auth-Signature: t=…,v1=HMAC-SHA256(secret, t + "." + body)`. Use for audit trails and async UIs; the redirect/poll flows don't require them.

---

## 10. Errors & rate limits

- Standard HTTP codes + `{ "error": { "type": "...", "message": "...", "param": "..." } }`.
- `type` ∈ `invalid_request` · `authentication_error` · `rate_limited` · `challenge_expired` · `grant_consumed` · `api_error`.
- `429` returns `Retry-After`. Default limits: 100 gate/s per project (burst 300); introspect 200/s. Raised on request.
- **`api_error` on the execute path is not fatal** — honor `fail_mode` (open ⇒ allow + log; closed ⇒ block).

---

## 11. SDK quickstart (the "10 lines")

Server (Node), before a risky action:

```js
import { XAuth } from "@x-auth/gate";              // open-source SDK
const xauth = new XAuth(process.env.XAUTH_SECRET_KEY);

const gate = await xauth.gate({
  user:    { id: user.id, phone: user.phone },
  action:  { type: "payment.send",
             params: { amount: 4200, currency: "USD", destination: payeeId } },
  context: { ip: req.ip, userAgent: req.get("user-agent"), deviceToken: req.body.deviceToken },
  options: { returnUrl: "https://app.example.com/pay/confirm" }
});

if (gate.decision === "block")     return res.status(403).send("Blocked");
if (gate.decision === "challenge") return res.redirect(gate.challenge.hostedUrl);
// "allow" → fall through and execute
```

On `return_url`, before executing:

```js
// introspect() consumes the single-use grant server-side, so a refreshed or
// replayed ?grant= URL cannot re-run the action within its TTL. (To verify
// locally instead — grants.verify — you MUST pass a jtiStore, or a valid grant
// replays until it expires.)
const grant = await xauth.grants.introspect(req.query.grant, {
  expectedAction: { type: "payment.send",
                    params: { amount: 4200, currency: "USD", destination: payeeId } }
});
if (!grant.active || !grant.actionMatches) return res.status(403).send("Re-auth required");
await executePayment(payeeId, 4200);
```

Browser (once, for device signal — `type="module"` is required so top-level `await` parses):

```html
<script src="https://js.x-auth.com/v1"></script>
<script type="module">const deviceToken = await XAuthGate("pk_live_…").device();</script>
```

---

## 12. Rollout posture (how a customer adopts safely)

1. **Advisory first.** Ship with `mode:"advisory"`; log scores for a week, tune thresholds, no user impact.
2. **Enforce on one action.** Flip the single highest-stakes action (payout, admin delete) to `enforce`.
3. **Expand.** Add action types as trust builds.

Fail-open + advisory-first is what makes a re-auth gate from a small vendor safe to depend on.

---

## 13. Mapping to existing services (why this is wiring, not a rewrite)

| Gate capability | Existing X-Auth asset |
|---|---|
| Risk score for an action | `transaction-service` `POST /v1/advice` (+ transaction types, advice history) |
| Decision thresholds / ladder | 8-level protection-ladder step-up engine + `risk-service` |
| Challenge (passkey) | `authenticator-service` FIDO2 (Postgres-backed) |
| Challenge (SMS-OTP) | `authenticator-service` Twilio Verify |
| Hosted branded challenge page | existing hosted step-up pages + per-tenant branding |
| `acr`/`amr` in the grant | already emitted in id_tokens today |
| Action-bound, single-use signed token | `pkg/jwtx` + the single-use-`jti` pattern already shipped for ID-JAG redemption |
| Device signal | existing device-fingerprinting + CAEP receiver |

New build is a thin **gate orchestration** endpoint (advice → decision → challenge → mint grant) + the developer-facing SDK + JWKS/introspect surface. Most of the hard parts are in production already.

---

## 14. Open decisions (for the founder)

1. **Metering unit / price.** Per `gate` call, per *challenge*, or MAU? (Leaning: free gate evaluations, meter challenges — you pay when it does work. Confirm.)
2. **Local-verify vs introspect as the documented default.** Local JWKS verify is the "no dependency" story; introspect is easier but re-adds a runtime call. Recommend documenting local-verify as default, introspect as the easy on-ramp.
3. **Methods in v0.1.** Passkey + SMS-OTP are shipped. Include email-OTP / TOTP now, or later? (Leaning: passkey + SMS only for v0.1; keep the surface tiny.)
4. **`acr:l4` (CIBA out-of-band confirm).** Explicitly deferred — CIBA isn't shipped. Ladder tops out at `l3` in v0.1.
5. **Self-host.** Open-source the SDK for v0.1; a self-hostable decision engine is the enterprise trust unlock but out of scope for the first paid design-partner integration.
6. **Naming.** "Step-Up Gate" vs "Action Gate" vs "Re-Auth API." The domain (`x-auth.com` / `api.x-auth.com` / `step.x-auth.com`) works for any of them.
