# RFP — Hosted mobile driver's licence (mDL) verification

**From:** XentraNET / X-Auth (risk-based OIDC identity platform)
**Date:** ______   **Response requested by:** ______   **Contact:** ______

## What we're buying

A **hosted** service that lets our application verify a user's **mobile driver's
licence (ISO/IEC 18013-5 / -7)** online and return the verified result to us. We
are already an OIDC system, so our strong preference is to integrate as a thin
**OIDC relying party** — no verifier infrastructure on our side. Initial target:
**California (CA DMV) mDL**; broader US/AAMVA coverage is a plus.

---

## Two go / no-go questions (please answer first)

1. **Result delivery:** Do you return the verified mDL to the relying party via an
   **OIDC `id_token` / OpenID Connect redirect-login flow** (i.e. we redirect the
   user to you and receive signed claims back)? *(Yes / No — if No, describe the
   mechanism, e.g. REST + polling/callback.)*

2. **Reader authentication:** Do **you** carry the **reader-authentication
   credentials** required for wallets to release the mDL — specifically **Apple
   Wallet and Google Wallet reader certificates**, and any **CA DMV** reader
   trust — so that **we do not have to enrol as a reader ourselves**? *(Yes / No —
   if partial, state exactly what the relying party must obtain.)*

> A "Yes / Yes" makes this effectively turnkey for us. A "No" on either is not
> disqualifying but materially changes scope, so please be precise.

---

## Detailed questionnaire

**A. Integration**
- A1. OIDC/OAuth endpoints (authorization, token, JWKS) or SDK? Standard or proprietary?
- A2. Which claims are returned (e.g. `family_name`, `given_name`, `birth_date`,
  `age_over_NN`, `document_number`, portrait, issuing authority)? **Selective
  disclosure** supported (request only the fields we need)?
- A3. Do you return a **signed, verifiable proof** of the result (and its issuer
  trust status) we can store/audit?

**B. Reader auth & issuer trust**
- B1. List the wallets you are an **approved/enrolled reader** for (Apple Wallet,
  Google Wallet, CA DMV Wallet app, Samsung, etc.).
- B2. How do you establish **issuer trust** (AAMVA **VICAL** / IACA roots)? Which
  issuing authorities are currently trusted? Is **California** live in production?
- B3. Do you perform **device + issuer signature** verification (cryptographic), or
  only data extraction? Is the result flagged trusted vs untrusted?

**C. Coverage & standards**
- C1. ISO/IEC **18013-5** (in-person) and **18013-7** (online) support? **W3C
  Digital Credentials API** (`navigator.credentials.get`) support?
- C2. Production support for **CA DMV mDL today** (not just test/sandbox)? Which
  other US states / countries?

**D. Device & UX**
- D1. **Same-device** (wallet on the same device) and **cross-device** (QR) flows?
- D2. Hosted verification UI, or fully embeddable/headless? Branding/whitelabel?

**E. Data, privacy, security**
- E1. Do you **store** PII / the presented attributes, or pass-through only? Retention?
- E2. Data residency options. **SOC 2 Type II / ISO 27001**? GDPR/CCPA posture.
- E3. Consent + audit trail provided to the relying party?

**F. Commercials & availability**
- F1. **GA or beta?** If beta, production timeline and any "non-production only" limits.
- F2. Pricing model (per-verification / tiered / platform fee), minimums, free test tier.
- F3. Prerequisite to start (existing-customer requirement, contracts, KYB vetting)?
- F4. **SLA / uptime**, support model, and typical **time-to-integrate**.

---

## What we'll provide

A test OIDC client (redirect URIs on `auth.x-auth.com` / `id.x-auth.com`), a named
technical contact, and a short eval window. We can run a same-device + QR test with
a California mDL.

## How we'll score (internal)

| Weight | Criterion |
|---|---|
| 30% | Reader-auth **bundled** (Q2) — Apple + Google + CA |
| 25% | **OIDC `id_token`** delivery (Q1) — thin-RP integration |
| 20% | **CA mDL in production** today (B2/C2) |
| 10% | Selective disclosure + signed proof (A2/A3) |
| 10% | Commercials (price, no beta-only limit, SLA) |
| 5% | Security/compliance (SOC 2, residency) |

**Send to:** Okta/Auth0 (Digital ID Verification), walt.id, and 2–3 IDV vendors
(e.g. Persona, Incode, Stripe Identity, 1Kosmos, Credence ID). A "Yes/Yes" on the
two go/no-go questions + CA-in-production wins; X-Auth integration is then ~1 day.
