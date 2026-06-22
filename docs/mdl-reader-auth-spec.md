# Spec — reader authentication for id-service

Reader authentication is the missing piece that makes an mDL wallet **release** the
credential. Today `id-service` sends an **unsigned** OpenID4VP request, so issuer
wallets (CA DMV, Apple/Google Wallet) filter it out — the "picker shows, no
credential offered" symptom. This spec defines the change that makes id-service a
**signed, certified reader**.

> Hard dependency, out of scope here: a **reader certificate** whose chain the
> wallet trusts (Apple/Google/CA reader-CA enrolment). No code makes a wallet
> present without it. This spec is what we build to *use* that cert; it should land
> only once a cert is in hand. Until then, ship it behind a flag (default off) so
> the current unsigned/test-wallet path keeps working.

## Background: what "reader auth" is

In ISO/IEC 18013-5/-7 + OpenID4VP, the verifier proves its identity by sending a
**signed authorization request** (a JWT — "JAR") whose header carries the reader
**X.509 certificate chain (`x5c`)**. The wallet:
1. checks the request signature against the leaf cert's public key, and
2. checks that leaf chains to a **reader CA it trusts**, and (often)
3. checks the cert's usage/SANs and that the request's `client_id` matches the cert.

Only then does it show the credential and let the user consent. The mDL device
signature the holder returns is bound (via the session transcript) to *that signed
request's* parameters, so a signed request also tightens our proof of possession.

## Current state (what exists)

- `service.go` builds a `Verification` with `ClientID = issuer`, a `Nonce`, and a
  `ResponseURI`; `oid4vp.go:buildOID4VPRequest` returns the **plain** OID4VP
  request object the consumer page hands to `navigator.credentials.get`.
- `oid4vp.go:sessionTranscript` already reconstructs the ISO handover
  `[clientIdHash, responseUriHash, nonce]` for device-signature verification.
- `trust.go` verifies the *issuer* chain (IACA). There is **no reader key/cert** and
  **no request signing**.

## What to add

### 1. Reader credential config (`internal/reader.go`, new)
Load a reader **private key + cert chain** at boot, mirroring `trust.go`'s env style.

- Env: `READER_KEY_FILE` (PEM EC P-256 key), `READER_CERT_FILE` (PEM leaf [+
  intermediates], leaf first), optional `READER_CLIENT_ID` (the `client_id` the
  cert authorizes; defaults to issuer).
- `type ReaderCredential struct { key crypto.Signer; chain [][]byte /*DER*/;
  clientID string; algorithm string /* "ES256" */ }`
- `LoadReaderCredential(keyFile, certFile, clientID) (*ReaderCredential, error)` —
  parse key, parse cert chain, assert leaf public key matches the key, return nil
  (feature-off) when both files are empty.
- Mount the key as a **Secret Manager secret** (like `fido-pg-dsn`); the cert is
  public. SA `run-id@` gets `secretAccessor`.

### 2. Signed request builder (extend `oid4vp.go`)
Add `buildSignedOID4VPRequest(v, reader) (signedRequestJWT string, err error)`:

- Reuse `buildOID4VPRequest(v)` for the claims set; add JWT registered claims the
  profile expects: `iss`/`client_id` = `reader.clientID`, `aud` (wallet/`"https://self-issued.me/v2"`
  per profile), `nonce`, `response_uri`, `response_type=vp_token`,
  `response_mode=dc_api` (or `direct_post` for cross-device), `iat`, `exp`.
- Sign **ES256** with `reader.key`; JOSE header: `alg=ES256`, `typ` =
  `oauth-authz-req+jwt`, **`x5c` = `reader.chain`** (base64 DER, leaf first).
- This is small, self-contained crypto — use `github.com/golang-jwt/jwt/v5` (already
  an indirect dep) or `go-jose`; do **not** hand-roll JOSE.

### 3. Wire it into request delivery
- **Same-device (DC API):** the consumer page currently sends `{ protocol:
  "openid4vp", data: REQUEST }`. With signing on, send the **signed request
  object** instead (DC API accepts a `request` JWT in the OID4VP `data`). `console.go`
  passes the signed JWT into the page; `verify.html` forwards it unchanged.
- **Cross-device (QR):** expose a **`request_uri`** endpoint
  (`GET /v1/verifications/{id}/request`) that returns the signed request JWT
  (`application/oauth-authz-req+jwt`); the QR/openid4vp URL references it
  (`request_uri=…`, `client_id=READER_CLIENT_ID`). Keeps the QR small and lets the
  wallet fetch + verify the signed request.

### 4. Session-transcript alignment (`oid4vp.go`)
The handover hashes must match what the wallet used. Two cases:
- **`direct_post`/OID4VP handover** (today): `[clientIdHash, responseUriHash, nonce]`
  — unchanged, but `clientId` must now be the **reader `client_id` from the cert**,
  not the bare issuer. Make `sessionTranscript` take the effective client_id.
- **DC-API handover** (browser-mediated): a *different* transcript variant
  (`OpenID4VPDCAPIHandover` with the origin) — `mdoc.go` notes this as a tracked
  follow-up. Pick the handover by `response_mode`; add the DC-API variant when
  enabling signed same-device. Get this wrong → device signature fails to verify.

### 5. Verification result (`mdoc.go` / `service.go`)
No change to issuer-trust logic. Optionally record `reader_authenticated: true` and
the reader `client_id` on the result/proof token for audit symmetry with
`trust_anchor`.

## Config / rollout

- New env on id-service: `READER_KEY_FILE`, `READER_CERT_FILE`, `READER_CLIENT_ID`,
  and a `READER_AUTH=on|off` master switch (default off → today's unsigned path).
- Deploy: add the key secret + mount, set the env, redeploy id-service. No DB
  change. Strict issuer trust (`TRUST_MODE=strict` + IACA roots) is independent and
  can be enabled separately.

## Testing

- **Unit:** sign a request with a self-signed reader cert → assert JOSE header has
  `alg=ES256` + `x5c`, and the JWT verifies against the leaf key; assert the chosen
  session transcript matches a fixture for both handover variants.
- **Round-trip (test wallet):** a reference wallet (Multipaz / Google Identity
  Credential reference) that *requires* a signed request → confirm it now presents,
  the `POST …/response` arrives, and the device signature verifies against the
  DC-API transcript. (This validates plumbing without needing a CA-trusted cert.)
- **Real CA mDL:** only works once the reader cert chains to a CA/Apple/Google-
  trusted reader CA — the external enrolment gate.

## Effort & sequencing

| Piece | Size | Notes |
|---|---|---|
| reader.go (load key+cert) | S | mirrors trust.go |
| signed request builder | S–M | golang-jwt, don't hand-roll JOSE |
| request_uri endpoint + QR/page wiring | M | small handler + template/console tweak |
| DC-API session-transcript variant | M | correctness-critical; test against fixtures |
| flag + secret + deploy | S | env + Secret Manager mount |

**Critical path is the reader certificate, not this code.** Build it once a cert is
secured (or to test against a signed-request-requiring reference wallet); keep it
behind `READER_AUTH=off` until then so the current path is unaffected. Pair the
crypto with a vetted mdoc/JOSE library + review — this verifies government IDs.

See also: [mdl-trust-and-opencred.md](mdl-trust-and-opencred.md) (issuer trust +
the OpenCred/hosted alternatives), [mdl-verifier-rfp.md](mdl-verifier-rfp.md).
