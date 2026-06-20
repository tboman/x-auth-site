# id-service — Remote Identity Verification (Web mDL)

Productized API + UIs at **`id.x-auth.com`** for high-assurance remote identity
verification in customer support and telehealth. A support agent triggers a
prompt; the customer clicks **"Verify with Wallet"**, their device wallet
presents an **ISO 18013-5 mobile driver's licence (mDL)** over the **W3C Digital
Credentials API + OpenID4VP**, and the service verifies it end-to-end —
returning cryptographically non-repudiable proof of identity to the agent.

It is the consumer-facing, decoupled ("CIBA-like") counterpart to the OIDC and
agent flows: the device signature is bound to a per-request nonce via the ISO
session transcript, so a verified result can't be replayed or repudiated.

## Flow

1. **Agent** `POST /v1/verifications` → a pending verification + a one-time
   `verifyUrl` (`https://id.x-auth.com/v/<token>`).
2. **Customer** opens the verify page (same-device prompt, or a cross-device
   secure link / QR). The page hands the OpenID4VP request to
   `navigator.credentials.get({ digital })`; the OS biometric + wallet returns a
   `vp_token` (an mdoc `DeviceResponse`), POSTed to the response endpoint.
3. **Service** verifies the mdoc: issuer-auth (COSE_Sign1) + IACA chain, MSO
   validity, value-digest match for each disclosed element, and device-auth over
   the session transcript. On success it mints a **Verified Identity Token**
   (RS256 JWT) and flips the verification to `verified`.
4. **Agent** dashboard polls `GET /v1/verifications/{id}` and sees the disclosed
   claims + assurance + proof.

## Endpoints

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /healthz` | none | liveness + trust posture |
| `GET /v1/jwks`, `GET /.well-known/jwks.json` | none | proof-token verification keys |
| `POST /v1/verifications` | `X-Tenant-Id` | create a verification |
| `GET /v1/verifications/{id}` | `X-Tenant-Id` | poll status + verified claims |
| `POST /v1/verifications/{id}/response` | token-bound | wallet/consumer posts `vp_token` (JSON or OID4VP `direct_post` form) |
| `GET /v/{token}` | one-time token | consumer "Verify with Wallet" page |
| `GET /dashboard` | agent (see note) | support-agent console |

The agent API uses `X-Tenant-Id` + the per-tenant rate limiter. The consumer
page is gated by the single-use, short-TTL token in the URL — the wallet
biometric is the authentication. The dashboard calls the same-origin tenant API;
in phase 1 the tenant is set client-side, and gating it behind an **X-Auth OIDC
session** (reusing the hosted login leg) is the production hook.

## Configuration

| Var | Default | Notes |
|---|---|---|
| `PORT` | `8185` | listen port |
| `ID_ISSUER` | `http://localhost:8185` | issuer / OpenID4VP `client_id`; canonically `https://id.x-auth.com` |
| `JWT_SIGNING_KEY` | _(ephemeral)_ | RS256 PEM for the Verified Identity Token |
| `TRUST_MODE` | `strict` | `strict` requires an IACA root; `insecure-accept-any` parses + flags untrusted (demos) |
| `IACA_ROOT_CERT_FILE` / `IACA_ROOTS_DIR` | _(unset)_ | mDL issuer trust anchors (PEM). AAMVA/state roots are membership-gated and **not bundled** |
| `VERIFICATION_TTL` | `10m` | pending lifetime (max 60m per request) |
| `RATE_LIMIT` | `600/1m` | `ratex.ParseRate`; `off` disables |
| `PG_DSN` / `PG_DSN_ID_SERVICE` | _(unset)_ | optional store (`id_db`); in-memory fallback otherwise |
| `REDIS_URL` / `REDIS_ADDR` (+pw/db) | _(unset)_ | optional token cache + shared limiter |
| `PURGE_INTERVAL` | `5m` | expired-pending sweep |
| `TLS_*` | _(unset)_ | `tlsx` (all-or-nothing) |

## Run locally

```sh
make run-id   # in-memory store, no Redis/PG
# or, to accept self-issued / unanchored test credentials:
TRUST_MODE=insecure-accept-any make run-id
```

Then open `http://localhost:8185/dashboard`, create a verification, and open the
`verifyUrl`. (A real wallet response needs a browser with the Digital
Credentials API + a platform wallet; the unit tests exercise the full verify
path with a generated fixture mdoc.)

## Notes / hardening follow-ups

- **Trust anchors**: production trust of real state mDLs needs the issuing
  authorities' IACA roots (AAMVA Digital Trust Service / state roots) supplied
  via `IACA_ROOT_CERT_FILE` / `IACA_ROOTS_DIR`. None are bundled.
- **Session transcript**: uses the OpenID4VP handover. The W3C Digital
  Credentials API "DC-API handover" variant is tracked as the spec finalizes.
- **Device MAC** binding (`COSE_Mac0`, ECDH-derived) is parsed but not yet
  verified; `deviceSignature` is.
- **Encrypted responses** (JARM / HPKE `vp_token`) and **SD-JWT VC** are out of
  scope this pass (mdoc/mDL + signed responses only).

The mDL dataset model is global, not tenant-partitioned; verifications ARE
tenant-scoped. Subdomain mapping (`id.x-auth.com`) is a manual post-Terraform
`gcloud beta run domain-mappings` step — see `deploy/terraform/README.md`.
