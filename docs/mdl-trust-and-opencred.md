# mDL trust: strict issuer verification + the OpenCred path to real wallets

This documents two complementary tracks for making X-Auth's mDL verification real
against the California DMV (and AAMVA-aligned issuers generally):

- **(A)** Turn on **strict issuer trust** in `id-service` using CA DMV's published
  IACA roots — so a presented mDL is cryptographically proven to be a genuine CA
  credential (`issuer_trusted: true`). Free; config-only.
- **(B)** Adopt **OpenCred** (California's open-source verifier) so the wallet will
  actually **release** the mDL — solving the reader-authentication gap that an
  arbitrary raw OpenID4VP reader can't.

## Why a raw reader (today's `id-service`) can't get a CA mDL

There are two independent trust directions; don't conflate them:

| Direction | Who trusts whom | Mechanism | Cost | Status in id-service |
|---|---|---|---|---|
| **Issuer trust** | verifier → issuer | IACA roots / AAMVA **VICAL** | **free download** | supported (`TRUST_MODE` + `IACA_ROOTS_DIR`), roots not loaded yet |
| **Reader authentication** | issuer's wallet → verifier | signed request from an **approved reader** | onboarding (see below) | **not implemented** — we send unsigned requests |

The empty wallet picker you saw ("Android Chrome, picker shown, no CA DMV
credential") is the **reader-authentication** gap: California's wallet only
*releases* the mDL to readers it recognises. Our unsigned, unenrolled reader is
filtered out. Loading IACA roots (A) does **not** fix this — it only makes the
result trustworthy *once a presentation arrives*. (B) is what makes one arrive.

---

## (A) Strict issuer trust with CA DMV IACA roots — config only

`id-service` already reads `TRUST_MODE`, `IACA_ROOT_CERT_FILE` and
`IACA_ROOTS_DIR` (see `internal/trust.go`). No code change is needed.

`TrustStore.Verify` behaviour with roots loaded:

- **`strict`** — a chain that anchors to a configured root → `issuer_trusted:true`;
  anything that doesn't → **rejected**. (So strict also rejects *test* wallets that
  don't chain to CA — keep `insecure-accept-any` while validating plumbing.)
- **`insecure-accept-any` + roots** — best of both during bring-up: a CA chain →
  `issuer_trusted:true`; everything else is still accepted but flagged
  `issuer_trusted:false`. Recommended until real CA mDLs flow, then switch to
  `strict`.

### Getting the cert (the only manual step)

The CA DMV **ISO 18013-5 IACA root certificates (production + test)** are part of
the DMV developer package (referenced on the *mDL for Technology Developers* page),
**not** checked into the public OpenCred repo. Obtaining them is the (free, light)
onboarding. Before trusting one, confirm provenance:

```bash
openssl x509 -in ca-dmv-iaca-test.pem -noout -subject -issuer -dates
# expect Subject/Issuer to be the California DMV IACA, self-signed, in-date
```

### Activating it (no rebuild — mount as a secret)

```bash
# 1. Store the PEM as a secret (public cert, but Secret Manager keeps it tidy)
gcloud secrets create ca-dmv-iaca-roots --data-file=ca-dmv-iaca-test.pem
gcloud secrets add-iam-policy-binding ca-dmv-iaca-roots \
  --member=serviceAccount:run-id@xauth-2026.iam.gserviceaccount.com \
  --role=roles/secretmanager.secretAccessor

# 2. Mount it + point IACA_ROOTS_DIR at the mount; start in insecure+roots
gcloud run services update id-service --region=europe-north1 \
  --update-secrets=/etc/iaca/ca-dmv.pem=ca-dmv-iaca-roots:latest \
  --update-env-vars=IACA_ROOTS_DIR=/etc/iaca

# 3. Once a real CA presentation verifies as trusted, tighten:
gcloud run services update id-service --region=europe-north1 \
  --update-env-vars=TRUST_MODE=strict
```

Boot log goes from `trust_insecure_mode` → (strict) and `mdoc.go` sets
`issuer_trusted:true` + a real `trust_anchor` on CA credentials.

---

## (B) OpenCred — the realistic path to real wallets

`id-service` is a *raw* OpenID4VP/DC-API reader. California's intended online path
is **OpenCred**, an open-source W3C-VC **verifier that is also an OIDC Provider**.
Because X-Auth's `authentication-service` is already an OIDC system, OpenCred slots
in exactly like Google social login — as an external IdP.

### Why this solves the release problem

OpenCred *is* the trusted reader: it carries the reader-side plumbing (request
shaping, CA `trustedCredentialIssuers`, `caStore` for mDoc X.509, the
exchange protocols the CA wallet accepts). The wallet releases to OpenCred; X-Auth
never has to be an enrolled reader itself.

### The flow (OIDC code flow — mirrors our Google leg)

```
authn /enroll/mdl  ──redirect──►  OpenCred /login?client_id&redirect_uri&response_type=code&scope&state
                                       │  shows QR (OID4VP, cross-device) or same-device (CHAPI)
                                       │  user presents mDL → OpenCred verifies (trusted reader)
   authn callback  ◄──code───────────┘
   authn → OpenCred /token (client_id+secret)  ──►  id_token (ES256 JWT, claims inline; no userinfo)
   authn verifies id_token vs OpenCred /.well-known/jwks.json → creates the mdl anchor
```

This is **the same OIDC-RP shape we already implement** for Google
(`startGoogle`/`consumeGoogleEmail` in `signup_console.go`): a new
`opencredStart`/`opencredCallback` pair pointed at the OpenCred instance, reusing
`jwtx` to validate the returned `id_token`. The verified claims (name, DOB, doc
number) + the issuer become the `mdl` identity anchor — same `storeMDLAnchor` sink.

### What you stand up / configure (OpenCred side, self-hosted)

- Deploy OpenCred (Docker; another small Cloud Run service, e.g. `opencred` /
  `verify.x-auth.com`).
- A **workflow** with: `clientId`/`clientSecret` (X-Auth is the RP), an `id_token`
  **ES256** signing key (published at `/.well-known/jwks.json`), **claims mapping**
  (JSONPath → id_token claims), and `exchangeProtocols` (`OID4VP` for QR + `CHAPI`
  for same-device).
- **`trustedCredentialIssuers`**: add CA DMV's **production issuer DID** (valid
  through 2027) for live mDLs, or the **sandbox issuer DID** for testing (sandbox
  is explicitly not for production).
- `caStore`: the same CA DMV IACA roots from (A), for mDoc X.509 validation.

### Production issuer config (from CA DMV, captured 2026-06)

These are **public** issuer identities (not secrets) for OpenCred's
`trustedCredentialIssuers`. Validated: the `did:jwk` x5c is the *California DMV
IACA VC Signer* (CN), issued by *California DMV IACA Root*, valid 2026-04-10 →
2027-07-09.

```yaml
# OpenCred workflow → trustedCredentialIssuers (CA DMV PRODUCTION)
trustedCredentialIssuers:
  - did:web:credentials.dmv.ca.gov   # non-expiring
  - did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImJSbGpTekVyS0lfQk5OME1LRVBIVVdHcVR1Um5fVm42eXJvQlRfR0RDbFUiLCJ4NWMiOlsiTUlJQ2VUQ0NBaCtnQXdJQkFnSVVOYjF2czlucklGTmt4Vy9BaDVSYnFTazVENXN3Q2dZSUtvWkl6ajBFQXdJd1VURUxNQWtHQTFVRUJoTUNWVk14RGpBTUJnTlZCQWdNQlZWVExVTkJNUTh3RFFZRFZRUUtEQVpEUVMxRVRWWXhJVEFmQmdOVkJBTU1HRU5oYkdsbWIzSnVhV0VnUkUxV0lFbEJRMEVnVW05dmREQWVGdzB5TmpBME1UQXhOVE14TWpGYUZ3MHlOekEzTURreE5UTXhNakZhTUZZeEN6QUpCZ05WQkFZVEFsVlRNUTR3REFZRFZRUUlEQVZWVXkxRFFURVBNQTBHQTFVRUNnd0dRMEV0UkUxV01TWXdKQVlEVlFRRERCMURZV3hwWm05eWJtbGhJRVJOVmlCSlFVTkJJRlpESUZOcFoyNWxjakJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCRzBaWTBzeEt5aVB3VFRkRENoRHgxRmhxazdrWi8xWitzcTZBVS94Z3dwVkp5T0k4cVNYRHl6NFpPQTJtR21sSnlrUGtjdnRTRjRjUnJNQlhDRDRIVitqZ2M4d2djd3dIUVlEVlIwT0JCWUVGREdQUUxGRUhwaWp2b0ZYaUNpV2c1Z2VVeGpZTUI4R0ExVWRJd1FZTUJhQUZMdDlkV2VTZW0vUG4zSjd1QXIzTnkrY0RGQTJNQjBHQ1dDR1NBR0crRUlCRFFRUUZnNURZV3hwWm05eWJtbGhJRVJOVmpBT0JnTlZIUThCQWY4RUJBTUNCNEF3SVFZRFZSMFNCQm93R0lFV2FXRmpZUzF6YVdkdVpYSkFaRzEyTG1OaExtZHZkakE0QmdOVkhSOEVNVEF2TUMyZ0s2QXBoaWRvZEhSd2N6b3ZMMk55YkM1a2JYWXVZMkV1WjI5MkwybGhZMkV2YldSdll5MXphV2R1WlhJd0NnWUlLb1pJemowRUF3SURTQUF3UlFJZ01yaGlFQ005ZU1JeHRRTzFmK1daUFhuaGRxK0g0ZWlPcnA4a0xpUkFkc0VDSVFDZDI4MktSUEsyUTVtdkRPUGMrRGVrYzFhR3RaRnRhaHVreS9NeDZWQ2JsZz09Il0sInkiOiJKeU9JOHFTWER5ejRaT0EybUdtbEp5a1BrY3Z0U0Y0Y1JyTUJYQ0Q0SFY4In0   # VC signer, valid to 2027-07-09
```

Note: these are *issuer DIDs* for the OpenCred / W3C-VC path. For **id-service's
mdoc (A)** you still need the X.509 **IACA Root** PEM (the issuer of the signer
above) — from the DMV developer package or the AAMVA VICAL.

### Effort & sequencing

1. **(A) now** — drop in the IACA roots (free) so id-service's trust is real for
   any presentation that does arrive; keep `insecure-accept-any` until then.
2. **(B) when pursuing production** — stand up OpenCred, add a `opencred` OIDC-RP
   leg in `authn` enrollment (≈ the Google leg), point `trustedCredentialIssuers`
   at the CA DMV DID. This is the step that makes the CA wallet actually present.
3. Keep the existing raw `id-service` reader for non-CA / test-wallet / DC-API
   experimentation; it and the OpenCred leg can coexist (two enrollment sources,
   one `mdl` anchor sink).

### Cost recap (researched, 2026-06)

- AAMVA **VICAL** (issuer trust list): **free** to relying parties.
- CA DMV **IACA roots** (prod + test): published to developers; **no fee found**.
- **OpenCred**: open source; self-host; **no licence fee found**.
- Reader-authentication enrolment specifics / any vetting: **not publicly priced**
  — confirm with CA DMV. The published, intended route is OpenCred, so the real
  cost is engineering time, not licensing.

Sources: AAMVA mDL Digital Trust Service (for-relying-parties); CA DMV mDL for
Business / for Technology Developers; `github.com/stateofca/opencred`.
