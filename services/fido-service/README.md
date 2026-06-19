# fido-service

The **FIDO2 Authenticator Risk & Metadata (MDS) API**, served at
`fido.x-auth.com`. It intakes an **AAGUID** or a WebAuthn **attestation object**
and returns an enriched **risk/posture JSON profile** for that authenticator,
folding the FIDO Alliance Metadata Service (MDS3) blob into one opinionated
shape:

- **Binding** — `hardware` (secure element / TEE), `synced` (multi-device /
  cloud passkey), `software`, or `unknown`.
- **Certification** — current FIDO MDS status (`FIDO_CERTIFIED_L1/L2/…`,
  `NOT_FIDO_CERTIFIED`) plus security advisories (`REVOKED`,
  `USER_VERIFICATION_BYPASS`, `ATTESTATION_KEY_COMPROMISE`, …).
- **Extensions** — `largeBlob`, `prf` (CTAP2 `hmac-secret`), `credProtect`,
  `credBlob`, `minPinLength`.
- **Risk tier / score** — `low | medium | high`, 0–100.

## How it works

On startup the service fetches the FIDO Alliance MDS3 blob (a compact JWS),
**verifies the signature against the pinned FIDO root CA via the `x5c` chain**,
parses it, and builds an in-memory `AAGUID → profile` index. A background job
re-fetches on `MDS_REFRESH_INTERVAL` (default 24h) and swaps the index in
atomically, so reads never block. The verified raw blob is cached in Redis
(shared across replicas) and persisted to Postgres (`fido_db`) for warm restarts
and audit; both are optional — without them the service simply re-fetches on a
cold start.

**Tenancy note:** the MDS dataset is *global*, not tenant-scoped. `X-Tenant-Id`
is required by convention and used only as the rate-limit key, not for data
isolation.

## Endpoints

All `/v1/*` routes require an `X-Tenant-Id` header and are rate limited. They
answer `503 mds_unavailable` until the first snapshot loads.

| Method & path | Purpose |
|---|---|
| `GET /healthz` | Liveness probe (unauthenticated). |
| `GET /v1/authenticators/{aaguid}` | Risk profile for an AAGUID (`404 aaguid_not_found`). |
| `POST /v1/attestation` | Profile from a posted attestation (see below). |
| `GET /v1/authenticators?offset=&limit=` | Paged list of all known profiles. |
| `GET /v1/mds/status` | Snapshot freshness + last refresh outcome. |

`POST /v1/attestation` body — supply **either**:

```json
{ "attestationObject": "<base64url or base64 CBOR>" }
```

**or** a full WebAuthn registration response:

```json
{ "credential": { "id": "...", "response": { "attestationObject": "...", "clientDataJSON": "..." }, "type": "public-key" } }
```

The attestation is parsed for its AAGUID and authenticator-data flags (UP, UV,
**BE/BS** backup-eligible/state, AT). `BackupEligible` is the authoritative
synced-credential signal. The attestation signature is **not** verified — this
service profiles posture, it is not the RP performing the ceremony.

## Configuration

| Env | Default | Notes |
|---|---|---|
| `PORT` | `8184` | |
| `MDS_URL` | `https://mds.fidoalliance.org` | FIDO Alliance MDS3 BLOB endpoint |
| `MDS_REFRESH_INTERVAL` | `24h` | Go duration |
| `MDS_ROOT_CERT_FILE` | _(unset)_ | PEM root CA overriding the pinned FIDO root |
| `RATE_LIMIT` | `600/1m` | `N/window`; `off` disables |
| `PG_DSN` / `PG_DSN_FIDO_SERVICE` / `PG_MAX_CONNS` | _(unset)_ / `10` | optional snapshot store |
| `REDIS_URL` / `REDIS_ADDR` (+`REDIS_PASSWORD`/`REDIS_DB`) | _(unset)_ | optional blob cache + shared limiter |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` / `TLS_CLIENT_CA_FILE` / `TLS_CA_FILE` | _(unset)_ | `tlsx` (all-or-nothing) |

## Run locally

```sh
make run-fido
# then (after the first MDS load):
curl -H 'X-Tenant-Id: demo' http://localhost:8184/v1/mds/status
curl -H 'X-Tenant-Id: demo' http://localhost:8184/v1/authenticators/ee882879-721c-4913-9775-3dfcce97072a
```

## Hardening follow-ups

- CRL/OCSP revocation checking of the MDS `x5c` chain (currently skipped to avoid
  a runtime network dependency on the certificate distribution points).
- CORS headers (needed for an in-browser demo on the docs page).
