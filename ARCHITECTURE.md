# X-Auth Platform Architecture

> **Status**: Requirements & Design · v0.1
> **Owner**: XentraNET Engineering
> **Last updated**: 2026-04-02

This document defines the architecture for the X-Auth backend platform — four Go microservices that deliver risk-based authentication, authorization, and risk intelligence as described on the [marketing site](public/index.html).

---

## Table of Contents

1. [System Context (C4 L1)](#1-system-context-c4-l1)
2. [Container Diagram (C4 L2)](#2-container-diagram-c4-l2)
3. [Domain Model](#3-domain-model)
4. [Service Contracts](#4-service-contracts)
5. [Key Flows](#5-key-flows)
6. [Data Stores](#6-data-stores)
7. [Risk Signal Pipeline](#7-risk-signal-pipeline)
8. [CAEP/SSF Considerations](#8-caepssf-considerations)
9. [Multi-Tenancy](#9-multi-tenancy)
10. [Security](#10-security)
11. [Compliance Certification Mapping](#11-compliance-certification-mapping)
12. [Appendix A — Go Service Directory Structure](#appendix-a--go-service-directory-structure)
13. [Appendix B — Deployment Topology](#appendix-b--deployment-topology)

---

## 1. System Context (C4 L1)

The X-Auth platform sits between client applications and external identity/threat services, providing risk-based authentication and authorization as a managed service.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          External Actors                                │
│                                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  ┌───────────────────┐   │
│  │ End User │  │ Client   │  │ Admin Console│  │ Threat Intel      │   │
│  │ (Browser/│  │ App      │  │ (Dashboard)  │  │ Feeds             │   │
│  │  Mobile) │  │ (Backend)│  │              │  │ (IP rep, fraud DB)│   │
│  └────┬─────┘  └────┬─────┘  └──────┬───────┘  └────────┬──────────┘   │
│       │              │               │                   │              │
│       │   HTTPS      │   HTTPS       │   HTTPS           │  HTTPS      │
│       ▼              ▼               ▼                   ▼              │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                                                                  │   │
│  │                      X-AUTH PLATFORM                             │   │
│  │                                                                  │   │
│  │   Risk-based authentication, authorization & risk intelligence   │   │
│  │                                                                  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│       │              │               │                   │              │
│       ▼              ▼               ▼                   ▼              │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  ┌───────────────────┐   │
│  │ Auth     │  │ Push     │  │ SMS/Email    │  │ FIDO2/WebAuthn   │   │
│  │ Vendors  │  │ Notif.   │  │ Providers    │  │ Relying Party    │   │
│  │ (Social, │  │ (APNs,   │  │ (Twilio,     │  │ Servers          │   │
│  │  SAML)   │  │  FCM)    │  │  SendGrid)   │  │                  │   │
│  └──────────┘  └──────────┘  └──────────────┘  └───────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Actors

| Actor | Description |
|-------|-------------|
| **End User** | Human authenticating via browser or mobile app |
| **Client App** | Customer's backend server calling X-Auth APIs (the primary integration point) |
| **Admin Console** | XentraNET dashboard for tenant config, policy management, analytics |
| **Threat Intel Feeds** | External IP reputation, fraud databases, device intelligence providers |
| **Auth Vendors** | Social login (Google, Apple, GitHub), SAML/OIDC enterprise IdPs |
| **Push Notification Services** | APNs, FCM for push-based step-up challenges |
| **SMS/Email Providers** | Twilio, SendGrid for OTP and magic link delivery |
| **FIDO2/WebAuthn RP** | Relying party server-side operations for passkey ceremonies |

---

## 2. Container Diagram (C4 L2)

Four Go microservices, each with its own PostgreSQL database, sharing a Redis cache layer.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              X-AUTH PLATFORM                                 │
│                                                                              │
│   External traffic                                                           │
│        │                                                                     │
│        ▼                                                                     │
│   ┌─────────────────────────────────────────┐                                │
│   │          API Gateway / Load Balancer     │                                │
│   │       (TLS termination, rate limiting)   │                                │
│   └──────────┬──────────────────┬────────────┘                                │
│              │                  │                                             │
│     Public API           OIDC endpoints                                      │
│              │                  │                                             │
│              ▼                  ▼                                             │
│   ┌─────────────────┐  ┌─────────────────────┐                               │
│   │  TRANSACTION    │  │  AUTHENTICATION      │                               │
│   │  SERVICE        │  │  SERVICE             │                               │
│   │                 │  │                       │                               │
│   │  • /evaluate    │  │  • OIDC provider      │                               │
│   │  • /step-up     │  │  • Session management │                               │
│   │  • /authorize   │  │  • Token issuance     │                               │
│   │  • /transactions│  │  • Token refresh       │                               │
│   │                 │  │  • Social login        │                               │
│   │  Orchestrator   │  │  • SAML/SSO           │                               │
│   └──┬──────┬───────┘  └──────┬───────────────┘                               │
│      │      │                 │                                               │
│      │      │    REST/JSON    │                                               │
│      ▼      ▼                 ▼                                               │
│   ┌─────────────────┐  ┌─────────────────────┐                               │
│   │  RISK           │  │  AUTHENTICATOR       │                               │
│   │  SERVICE        │  │  SERVICE             │                               │
│   │                 │  │                       │                               │
│   │  • Signal       │  │  • Authenticator CRUD │                               │
│   │    ingestion    │  │  • Vendor adapters    │                               │
│   │  • Risk scoring │  │  • Challenge dispatch │                               │
│   │  • Policy eval  │  │  • Challenge verify   │                               │
│   │  • Continuous   │  │  • FIDO2 ceremonies   │                               │
│   │    evaluation   │  │  • OTP generation     │                               │
│   └─────────────────┘  └─────────────────────┘                               │
│      │      │                 │                                               │
│      ▼      ▼                 ▼                                               │
│   ┌──────────────────────────────────────────┐                                │
│   │              Shared Redis                 │                                │
│   │  (session cache, rate limits, risk cache) │                                │
│   └──────────────────────────────────────────┘                                │
│      │             │              │            │                               │
│      ▼             ▼              ▼            ▼                               │
│   ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐                             │
│   │txn_db  │  │risk_db │  │auth_db │  │authr_db│                             │
│   │(PG)    │  │(PG)    │  │(PG)    │  │(PG)    │                             │
│   └────────┘  └────────┘  └────────┘  └────────┘                             │
│                                                                              │
│                ┌──────────────────┐                                           │
│                │  External APIs   │                                           │
│                │  • Twilio        │                                           │
│                │  • SendGrid      │                                           │
│                │  • APNs / FCM    │                                           │
│                │  • IP reputation │                                           │
│                │  • Social IdPs   │                                           │
│                └──────────────────┘                                           │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Service Responsibilities

| Service | Port | Visibility | Owns |
|---------|------|------------|------|
| **transaction-service** | 8080 | Public | Transaction lifecycle, orchestration, authorization decisions |
| **risk-service** | 8081 | Internal | Risk evaluations, signal ingestion, policy engine, scoring |
| **authentication-service** | 8082 | Public (OIDC) | OIDC provider, sessions, tokens, social login, SAML |
| **authenticator-service** | 8083 | Internal | Authenticator CRUD, vendor adapters, challenge dispatch/verify |

### Inter-Service Communication

All communication is **synchronous REST/JSON over internal network** (mTLS in production).

```
transaction-service ──→ risk-service          (POST /evaluate)
transaction-service ──→ authenticator-service  (POST /challenges)
transaction-service ──→ authentication-service (POST /sessions, /tokens)
authentication-service ──→ authenticator-service (GET /authenticators)
```

---

## 3. Domain Model

Entity ownership by service. All entities are tenant-scoped (implicit `tenant_id` on every table).

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           DOMAIN MODEL                                  │
│                                                                         │
│  transaction-service                                                    │
│  ┌──────────────┐    ┌──────────────┐                                   │
│  │ Transaction   │───▶│ AuditEvent   │                                   │
│  │              │    │              │                                   │
│  │ id           │    │ id           │                                   │
│  │ tenant_id    │    │ tenant_id    │                                   │
│  │ user_id      │    │ entity_type  │                                   │
│  │ session_id   │    │ entity_id    │                                   │
│  │ risk_eval_id │    │ action       │                                   │
│  │ action       │    │ actor_id     │                                   │
│  │ resource     │    │ metadata     │                                   │
│  │ decision     │    │ created_at   │                                   │
│  │ step_up_used │    └──────────────┘                                   │
│  │ created_at   │                                                       │
│  └──────────────┘                                                       │
│                                                                         │
│  risk-service                                                           │
│  ┌──────────────┐    ┌──────────────┐                                   │
│  │RiskEvaluation│    │ RiskPolicy   │                                   │
│  │              │    │              │                                   │
│  │ id           │    │ id           │                                   │
│  │ tenant_id    │    │ tenant_id    │                                   │
│  │ user_id      │    │ name         │                                   │
│  │ session_id   │    │ rules        │                                   │
│  │ signals      │    │ resource_map │                                   │
│  │ scores       │    │ weights      │                                   │
│  │ aggregate    │    │ thresholds   │                                   │
│  │ tier         │    │ active       │                                   │
│  │ policy_id    │    │ version      │                                   │
│  │ created_at   │    └──────────────┘                                   │
│  └──────────────┘                                                       │
│                                                                         │
│  authentication-service                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐               │
│  │ User         │    │ Session      │    │ OIDCClient   │               │
│  │              │    │              │    │              │               │
│  │ id           │    │ id           │    │ id           │               │
│  │ tenant_id    │    │ tenant_id    │    │ tenant_id    │               │
│  │ external_id  │    │ user_id      │    │ client_id    │               │
│  │ email        │    │ device_id    │    │ client_secret│               │
│  │ metadata     │    │ ip_address   │    │ redirect_uris│               │
│  │ created_at   │    │ risk_level   │    │ grant_types  │               │
│  │ updated_at   │    │ expires_at   │    │ scopes       │               │
│  └──────┬───────┘    │ created_at   │    │ created_at   │               │
│         │            └──────────────┘    └──────────────┘               │
│         │                                                               │
│         │  ┌──────────────┐                                             │
│         └─▶│ AuthFlow     │                                             │
│            │              │                                             │
│            │ id           │                                             │
│            │ tenant_id    │                                             │
│            │ user_id      │                                             │
│            │ type (oidc,  │                                             │
│            │   social,    │                                             │
│            │   saml)      │                                             │
│            │ state        │                                             │
│            │ code_challenge│                                            │
│            │ redirect_uri │                                             │
│            │ expires_at   │                                             │
│            └──────────────┘                                             │
│                                                                         │
│  authenticator-service                                                  │
│  ┌──────────────┐    ┌──────────────┐                                   │
│  │Authenticator  │    │ Challenge    │                                   │
│  │              │    │              │                                   │
│  │ id           │    │ id           │                                   │
│  │ tenant_id    │    │ tenant_id    │                                   │
│  │ user_id      │    │ user_id      │                                   │
│  │ type (fido2, │    │ authr_id     │                                   │
│  │   totp, sms, │    │ type         │                                   │
│  │   email,     │    │ state        │                                   │
│  │   push)      │    │ code_hash    │                                   │
│  │ credential   │    │ attempts     │                                   │
│  │ metadata     │    │ expires_at   │                                   │
│  │ verified     │    │ verified_at  │                                   │
│  │ created_at   │    └──────────────┘                                   │
│  └──────────────┘                                                       │
│                                                                         │
│  Tenant (shared config — replicated or read from config service)        │
│  ┌──────────────┐                                                       │
│  │ Tenant       │                                                       │
│  │              │                                                       │
│  │ id           │                                                       │
│  │ name         │                                                       │
│  │ plan         │                                                       │
│  │ config       │                                                       │
│  │ api_keys     │                                                       │
│  │ created_at   │                                                       │
│  └──────────────┘                                                       │
└─────────────────────────────────────────────────────────────────────────┘
```

### Entity Cross-Reference

| Entity | Service Owner | Referenced By |
|--------|--------------|---------------|
| Tenant | All (replicated config) | Every entity via `tenant_id` |
| User | authentication-service | transaction, risk-eval, authenticator |
| Session | authentication-service | transaction, risk-eval |
| Transaction | transaction-service | — |
| RiskEvaluation | risk-service | transaction |
| RiskPolicy | risk-service | risk-eval |
| Authenticator | authenticator-service | challenge |
| Challenge | authenticator-service | transaction (via step-up) |
| AuthFlow | authentication-service | — |
| OIDCClient | authentication-service | auth-flow |
| AuditEvent | transaction-service | — |

---

## 4. Service Contracts

### 4.1 transaction-service (Public API)

The **orchestrator** — the primary integration point for client applications. Receives access requests, coordinates risk evaluation, triggers step-up when needed, and issues access decisions.

#### `POST /v1/advice`

> Also reachable as `POST /v1/evaluate` (alias kept for backward compatibility with pre-pivot clients). New integrations should use `/v1/advice`.

Evaluate a user access request. Returns risk tier and required actions. `/v1/advice` is the universal risk-evaluation entry point — it covers login AND any other journey or transaction payload (checkout, transfer, sensitive read, etc.), not just authentication.

**Request:**
```json
{
  "user_id": "usr_abc123",
  "session_id": "ses_xyz789",
  "action": "transfer.initiate",
  "resource": "payments",
  "resource_sensitivity": "high",
  "context": {
    "ip_address": "203.0.113.42",
    "user_agent": "Mozilla/5.0 ...",
    "device_fingerprint": "fp_a1b2c3d4",
    "geo": {
      "lat": 37.7749,
      "lon": -122.4194
    }
  }
}
```

**Response (200):**
```json
{
  "transaction_id": "txn_001",
  "risk_evaluation": {
    "id": "rev_001",
    "tier": "high",
    "score": 0.87,
    "signals": {
      "device": { "score": 0.3, "flags": ["unknown_device"] },
      "behavior": { "score": 0.6, "flags": ["unusual_time"] },
      "network": { "score": 0.9, "flags": ["flagged_ip", "vpn_detected"] },
      "user": { "score": 0.4, "flags": ["first_high_value_action"] }
    }
  },
  "decision": "step_up_required",
  "step_up": {
    "challenge_id": "ch_001",
    "methods": ["fido2", "push"],
    "expires_at": "2026-04-02T12:05:00Z"
  }
}
```

#### `POST /v1/step-up/verify`

Submit step-up challenge response.

**Request:**
```json
{
  "transaction_id": "txn_001",
  "challenge_id": "ch_001",
  "method": "fido2",
  "response": {
    "credential_id": "cred_abc",
    "authenticator_data": "base64...",
    "client_data_json": "base64...",
    "signature": "base64..."
  }
}
```

**Response (200):**
```json
{
  "transaction_id": "txn_001",
  "decision": "allow",
  "session": {
    "id": "ses_xyz789",
    "risk_level": "high",
    "step_up_completed": true,
    "expires_at": "2026-04-02T13:00:00Z"
  }
}
```

#### `POST /v1/authorize`

Check authorization for a specific action after authentication.

**Request:**
```json
{
  "user_id": "usr_abc123",
  "session_id": "ses_xyz789",
  "action": "transfer.initiate",
  "resource": "payments",
  "attributes": {
    "amount": 5000,
    "currency": "USD"
  }
}
```

**Response (200):**
```json
{
  "transaction_id": "txn_002",
  "decision": "allow",
  "policy_id": "pol_payments_v3",
  "evaluated_at": "2026-04-02T12:01:00Z"
}
```

**Response (403):**
```json
{
  "transaction_id": "txn_002",
  "decision": "deny",
  "reason": "insufficient_role",
  "policy_id": "pol_payments_v3"
}
```

#### `GET /v1/transactions/{id}`

Retrieve transaction details (for audit/debugging).

**Response (200):**
```json
{
  "id": "txn_001",
  "tenant_id": "ten_abc",
  "user_id": "usr_abc123",
  "session_id": "ses_xyz789",
  "action": "transfer.initiate",
  "resource": "payments",
  "risk_evaluation_id": "rev_001",
  "decision": "allow",
  "step_up_used": true,
  "step_up_method": "fido2",
  "created_at": "2026-04-02T12:00:00Z",
  "decided_at": "2026-04-02T12:00:45Z"
}
```

#### `GET /v1/transactions`

List transactions with filtering.

**Query params:** `user_id`, `session_id`, `decision`, `tier`, `from`, `to`, `limit`, `cursor`

---

### 4.2 risk-service (Internal)

Computes risk scores from signals, applies tenant policies, and determines risk tiers.

#### `POST /v1/evaluations`

Run a full risk evaluation. (Phase-1 implementation uses the plural resource name to match REST conventions; the arch doc originally listed `/evaluate` singular.)

**Request:**
```json
{
  "tenant_id": "ten_abc",
  "user_id": "usr_abc123",
  "session_id": "ses_xyz789",
  "action": "transfer.initiate",
  "resource": "payments",
  "resource_sensitivity": "high",
  "signals": {
    "device": {
      "fingerprint": "fp_a1b2c3d4",
      "user_agent": "Mozilla/5.0 ...",
      "platform": "macOS",
      "screen_resolution": "2560x1440"
    },
    "network": {
      "ip_address": "203.0.113.42",
      "geo": { "lat": 37.7749, "lon": -122.4194, "country": "US" },
      "asn": "AS13335"
    },
    "behavior": {
      "session_duration_sec": 340,
      "actions_in_session": 12,
      "typing_cadence_ms": 145,
      "mouse_velocity": 0.73
    },
    "user": {
      "account_age_days": 365,
      "last_login": "2026-04-01T08:00:00Z",
      "failed_attempts_24h": 0,
      "mfa_enrolled": true
    }
  }
}
```

**Response (200):**
```json
{
  "id": "rev_001",
  "tier": "high",
  "score": 0.87,
  "scores": {
    "device": 0.3,
    "behavior": 0.6,
    "network": 0.9,
    "user": 0.4
  },
  "flags": ["flagged_ip", "vpn_detected", "unknown_device", "unusual_time"],
  "policy_id": "pol_default_v2",
  "resource_sensitivity": "high",
  "sensitivity_applied": true,
  "created_at": "2026-04-02T12:00:00Z"
}
```

#### `POST /v1/evaluate/session`

Re-evaluate an active session (continuous authentication).

**Request:**
```json
{
  "tenant_id": "ten_abc",
  "session_id": "ses_xyz789",
  "signals": {
    "behavior": {
      "typing_cadence_ms": 280,
      "mouse_velocity": 0.12,
      "navigation_pattern": "anomalous"
    }
  }
}
```

**Response (200):**
```json
{
  "id": "rev_002",
  "previous_tier": "low",
  "tier": "medium",
  "score": 0.55,
  "action": "step_up_required",
  "reason": "behavioral_drift"
}
```

#### `GET /v1/policies/{tenant_id}`

Get active risk policies for a tenant.

**Response (200):**
```json
{
  "policies": [
    {
      "id": "pol_default_v2",
      "name": "Default Risk Policy",
      "thresholds": {
        "low": { "max_score": 0.3 },
        "medium": { "min_score": 0.3, "max_score": 0.7 },
        "high": { "min_score": 0.7 }
      },
      "weights": {
        "device": 0.25,
        "behavior": 0.30,
        "network": 0.25,
        "user": 0.20
      },
      "resource_sensitivity_multipliers": {
        "low": 0.8,
        "medium": 1.0,
        "high": 1.3,
        "critical": 1.6
      },
      "active": true,
      "version": 2
    }
  ]
}
```

#### `PUT /v1/policies/{tenant_id}/{policy_id}`

Update a risk policy.

---

### 4.3 authentication-service (Public — OIDC endpoints)

Owns user identity, sessions, tokens, and OIDC/OAuth2 flows.

#### OIDC Discovery

`GET /.well-known/openid-configuration`

Standard OIDC discovery document.

#### `POST /v1/auth/token`

OAuth2 token endpoint (authorization code exchange, refresh).

**Request (authorization_code):**
```json
{
  "grant_type": "authorization_code",
  "code": "auth_code_abc",
  "redirect_uri": "https://app.example.com/callback",
  "client_id": "cli_abc123",
  "code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r..."
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "rt_abc123...",
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "scope": "openid profile email"
}
```

#### `POST /v1/auth/token` (refresh)

**Request:**
```json
{
  "grant_type": "refresh_token",
  "refresh_token": "rt_abc123...",
  "client_id": "cli_abc123"
}
```

#### `POST /v1/auth/token` (token exchange → Cross-App Access ID-JAG)

RFC 8693 token exchange that mints an **Identity Assertion Authorization Grant**
(ID-JAG, `draft-parecki-oauth-identity-assertion-authz-grant` — the mechanism
Okta ships as **Cross App Access**). A requesting app (an agent / MCP client)
converts a token X-Auth issued it into a short-lived, scoped assertion it can
present to a downstream MCP server's authorization server. The target `resource`
must be on the tenant's authorized MCP-server allow-list (owner dashboard → "MCP
servers"; `grant_types_supported` advertises the token-exchange grant).

**Request:**
```json
{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
  "subject_token": "eyJhbGciOiJSUzI1NiIs...",
  "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "resource": "https://mcp.acme.com",
  "scope": "crm.contacts.read"
}
```

**Response (200):**
```json
{
  "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
  "access_token": "eyJ0eXAiOiJvYXV0aC1pZC1qYWcrand0Iis...",
  "token_type": "N_A",
  "expires_in": 300,
  "scope": "crm.contacts.read"
}
```

The assertion is an RS256 JWT (`typ: oauth-id-jag+jwt`) with `aud` = the resource
URI, `sub` = the end user, and a `client_id` claim naming the requesting app.
Policy errors are structured: `invalid_target` (resource not on the enabled
allow-list), `invalid_scope` (request exceeds the server's authorized scopes),
`invalid_grant` (subject token unusable / wrong client).

#### `POST /v1/sessions`

Create a new session (called by transaction-service after successful auth).

**Request:**
```json
{
  "tenant_id": "ten_abc",
  "user_id": "usr_abc123",
  "device_id": "dev_xyz",
  "ip_address": "203.0.113.42",
  "risk_level": "low"
}
```

**Response (201):**
```json
{
  "id": "ses_xyz789",
  "user_id": "usr_abc123",
  "risk_level": "low",
  "expires_at": "2026-04-02T20:00:00Z",
  "created_at": "2026-04-02T12:00:00Z"
}
```

#### `POST /v1/sessions/{id}/upgrade`

Upgrade a session's risk level and/or mark step-up as completed. Typically called by transaction-service after a successful step-up verify, or after a fresh risk re-evaluation on `/v1/authorize`.

**Request:**
```json
{
  "risk_level": "medium",
  "step_up_completed": true
}
```

#### `GET /v1/sessions/{id}`

Get session details.

#### `DELETE /v1/sessions/{id}`

Revoke/terminate a session.

#### `POST /v1/users`

Register or get-or-create a user.

**Request:**
```json
{
  "tenant_id": "ten_abc",
  "external_id": "google|123456",
  "email": "user@example.com",
  "metadata": {
    "name": "Jane Doe",
    "provider": "google"
  }
}
```

**Response (201):**
```json
{
  "id": "usr_abc123",
  "tenant_id": "ten_abc",
  "email": "user@example.com",
  "created_at": "2026-04-02T12:00:00Z"
}
```

#### `GET /v1/auth/authorize`

OIDC authorization endpoint (browser redirect).

**Query params:** `response_type`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method`, `nonce`

#### `GET /v1/auth/userinfo`

OIDC UserInfo endpoint (Bearer token required).

#### `GET /v1/auth/jwks`

JSON Web Key Set for token verification.

---

### 4.4 authenticator-service (Internal)

Manages authenticator lifecycle and dispatches/verifies challenges.

#### `POST /v1/authenticators`

Register a new authenticator for a user.

**Request:**
```json
{
  "tenant_id": "ten_abc",
  "user_id": "usr_abc123",
  "type": "fido2",
  "credential": {
    "credential_id": "base64...",
    "public_key": "base64...",
    "attestation": "base64...",
    "transports": ["usb", "internal"]
  },
  "metadata": {
    "device_name": "MacBook Pro Touch ID",
    "aaguid": "00000000-0000-0000-0000-000000000000"
  }
}
```

**Response (201):**
```json
{
  "id": "authr_001",
  "tenant_id": "ten_abc",
  "user_id": "usr_abc123",
  "type": "fido2",
  "verified": true,
  "created_at": "2026-04-02T12:00:00Z"
}
```

#### `GET /v1/authenticators?user_id={id}&tenant_id={id}`

List authenticators for a user.

**Response (200):**
```json
{
  "authenticators": [
    {
      "id": "authr_001",
      "type": "fido2",
      "metadata": { "device_name": "MacBook Pro Touch ID" },
      "verified": true,
      "last_used_at": "2026-04-01T15:00:00Z",
      "created_at": "2026-03-01T10:00:00Z"
    },
    {
      "id": "authr_002",
      "type": "totp",
      "metadata": { "app": "Google Authenticator" },
      "verified": true,
      "last_used_at": "2026-03-28T09:00:00Z",
      "created_at": "2026-02-15T11:00:00Z"
    }
  ]
}
```

#### `DELETE /v1/authenticators/{id}`

Remove an authenticator.

#### `POST /v1/challenges`

Create and dispatch a step-up challenge.

**Request:**
```json
{
  "tenant_id": "ten_abc",
  "user_id": "usr_abc123",
  "methods": ["fido2", "push"],
  "context": {
    "transaction_id": "txn_001",
    "action": "transfer.initiate",
    "resource": "payments"
  }
}
```

**Response (201):**
```json
{
  "id": "ch_001",
  "methods_available": [
    {
      "method": "fido2",
      "authenticator_id": "authr_001",
      "challenge_data": {
        "challenge": "base64...",
        "rp_id": "x-auth.xentranet.com",
        "allowed_credentials": ["base64..."]
      }
    },
    {
      "method": "push",
      "authenticator_id": "authr_003",
      "status": "sent"
    }
  ],
  "expires_at": "2026-04-02T12:05:00Z"
}
```

#### `POST /v1/challenges/{id}/verify`

Verify a challenge response.

**Request:**
```json
{
  "method": "fido2",
  "response": {
    "credential_id": "cred_abc",
    "authenticator_data": "base64...",
    "client_data_json": "base64...",
    "signature": "base64..."
  }
}
```

**Response (200):**
```json
{
  "challenge_id": "ch_001",
  "verified": true,
  "method": "fido2",
  "authenticator_id": "authr_001",
  "verified_at": "2026-04-02T12:00:30Z"
}
```

**Response (401):**
```json
{
  "challenge_id": "ch_001",
  "verified": false,
  "reason": "signature_mismatch",
  "attempts_remaining": 2
}
```

---

### Common API Conventions

**Headers (all requests):**
```
Authorization: Bearer <api_key or access_token>
X-Tenant-ID: ten_abc
X-Request-ID: req_uuid
Content-Type: application/json
```

**Error response shape:**
```json
{
  "error": {
    "code": "invalid_request",
    "message": "Human-readable description",
    "details": {},
    "request_id": "req_uuid"
  }
}
```

**Standard error codes:**
| HTTP | Code | Meaning |
|------|------|---------|
| 400 | `invalid_request` | Malformed or missing fields |
| 401 | `unauthorized` | Missing or invalid credentials |
| 403 | `forbidden` | Valid credentials but insufficient permissions |
| 404 | `not_found` | Resource does not exist |
| 409 | `conflict` | Duplicate or state conflict |
| 429 | `rate_limited` | Too many requests |
| 500 | `internal_error` | Server error |

---

## 5. Key Flows

### 5.1 Low-Risk Login

User logs in from a trusted device — no step-up required.

```
End User          Client App        transaction-svc    risk-svc       auth-svc       authenticator-svc
   │                  │                   │               │               │               │
   │─── Login ───────▶│                   │               │               │               │
   │                  │── POST /evaluate ▶│               │               │               │
   │                  │                   │── POST ──────▶│               │               │
   │                  │                   │   /evaluate    │               │               │
   │                  │                   │               │── score ──┐   │               │
   │                  │                   │               │           │   │               │
   │                  │                   │               │◀── 0.15 ──┘   │               │
   │                  │                   │◀─ tier:low ───│               │               │
   │                  │                   │                               │               │
   │                  │                   │── POST /sessions ────────────▶│               │
   │                  │                   │◀─ session ────────────────────│               │
   │                  │                   │                               │               │
   │                  │◀── allow ─────────│               │               │               │
   │◀── Access ───────│                   │               │               │               │
   │   granted        │                   │               │               │               │
```

### 5.2 Medium-Risk Step-Up

New browser detected — soft step-up via SMS OTP or FIDO2.

```
End User          Client App        transaction-svc    risk-svc       auth-svc       authenticator-svc
   │                  │                   │               │               │               │
   │─── Login ───────▶│                   │               │               │               │
   │                  │── POST /evaluate ▶│               │               │               │
   │                  │                   │── POST ──────▶│               │               │
   │                  │                   │   /evaluate    │               │               │
   │                  │                   │◀─ tier:medium─│               │               │
   │                  │                   │                               │               │
   │                  │                   │── POST /challenges ──────────────────────────▶│
   │                  │                   │◀─ challenge (sms, fido2) ────────────────────│
   │                  │                   │                               │               │
   │                  │◀─ step_up_required│               │               │               │
   │◀── Challenge ────│  methods:[sms,    │               │               │               │
   │    prompt        │   fido2]          │               │               │               │
   │                  │                   │               │               │               │
   │── OTP code ─────▶│                   │               │               │               │
   │                  │── POST /step-up/ ▶│               │               │               │
   │                  │   verify          │── POST /challenges/{id}/verify ─────────────▶│
   │                  │                   │◀─ verified:true ─────────────────────────────│
   │                  │                   │                               │               │
   │                  │                   │── POST /sessions/{id}/upgrade ▶│               │
   │                  │                   │◀─ updated ────────────────────│               │
   │                  │                   │                               │               │
   │                  │◀── allow ─────────│               │               │               │
   │◀── Access ───────│                   │               │               │               │
```

### 5.3 High-Risk Strong Step-Up

Payment attempt from unknown device with flagged IP — requires FIDO2 + knowledge factor.

```
End User          Client App        transaction-svc    risk-svc       auth-svc       authenticator-svc
   │                  │                   │               │               │               │
   │─── Payment ─────▶│                   │               │               │               │
   │    request       │── POST /evaluate ▶│               │               │               │
   │                  │                   │── POST ──────▶│               │               │
   │                  │                   │   /evaluate    │               │               │
   │                  │                   │◀─ tier:high ──│               │               │
   │                  │                   │   score:0.87   │               │               │
   │                  │                   │                               │               │
   │                  │                   │── POST /challenges ──────────────────────────▶│
   │                  │                   │◀─ challenge (fido2+push) ────────────────────│
   │                  │                   │                               │               │
   │                  │◀─ step_up_required│               │               │               │
   │◀── FIDO2 + ─────│  methods:[fido2,  │               │               │               │
   │    Push prompt   │   push]           │               │               │               │
   │                  │                   │               │               │               │
   │── FIDO2 ────────▶│                   │               │               │               │
   │   assertion      │── POST /step-up/ ▶│               │               │               │
   │                  │   verify          │── POST /challenges/{id}/verify ─────────────▶│
   │                  │                   │◀─ verified:true ─────────────────────────────│
   │                  │                   │                               │               │
   │                  │                   │── POST /authorize ──┐         │               │
   │                  │                   │   (policy check)    │         │               │
   │                  │                   │◀────────────────────┘         │               │
   │                  │                   │                               │               │
   │                  │                   │── POST /sessions/{id}/upgrade ▶│               │
   │                  │                   │◀─ updated ────────────────────│               │
   │                  │                   │                               │               │
   │                  │◀── allow ─────────│               │               │               │
   │◀── Payment ─────│                   │               │               │               │
   │   approved       │                   │               │               │               │
```

### 5.4 Authenticator Registration

User enrolls a new FIDO2 passkey.

```
End User          Client App        authenticator-svc       auth-svc
   │                  │                   │                     │
   │── Register ─────▶│                   │                     │
   │   new passkey    │                   │                     │
   │                  │── GET /authenticators ──▶│              │
   │                  │◀─ existing list ────────│              │
   │                  │                         │              │
   │                  │── POST /authenticators ─▶│              │
   │                  │   type: fido2             │              │
   │                  │   (begin registration)    │              │
   │                  │◀─ creation options ───────│              │
   │                  │   (challenge, rp, user)   │              │
   │◀── WebAuthn ─────│                           │              │
   │    create()      │                           │              │
   │    prompt        │                           │              │
   │                  │                           │              │
   │── attestation ──▶│                           │              │
   │   response       │── POST /authenticators ──▶│              │
   │                  │   (complete registration)  │              │
   │                  │   credential + attestation │              │
   │                  │◀─ authr_001 (verified) ───│              │
   │                  │                           │              │
   │◀── Success ──────│                           │              │
   │   "Passkey added"│                           │              │
```

### 5.5 Session Re-Evaluation (Continuous Auth)

Mid-session behavioral drift triggers re-evaluation.

```
Client App        transaction-svc    risk-svc       auth-svc       authenticator-svc
   │                   │               │               │               │
   │── periodic ──────▶│               │               │               │
   │   signals         │── POST ──────▶│               │               │
   │   (behavior)      │ /evaluate/     │               │               │
   │                   │  session       │── re-score ─┐ │               │
   │                   │               │             │ │               │
   │                   │               │◀────────────┘ │               │
   │                   │◀─ tier drift: │               │               │
   │                   │  low→medium   │               │               │
   │                   │  action:       │               │               │
   │                   │  step_up       │               │               │
   │                   │                               │               │
   │                   │── POST /sessions/{id}/upgrade ▶│               │
   │                   │   risk_level: medium           │               │
   │                   │◀─ updated ────────────────────│               │
   │                   │                               │               │
   │                   │── POST /challenges ──────────────────────────▶│
   │                   │◀─ challenge ────────────────────────────────│
   │                   │                               │               │
   │◀── step_up ──────│               │               │               │
   │    required       │               │               │               │
   │                   │               │               │               │
   │── verify ────────▶│               │               │               │
   │                   │── POST /challenges/{id}/verify ─────────────▶│
   │                   │◀─ verified ─────────────────────────────────│
   │                   │                               │               │
   │                   │── POST /sessions/{id}/upgrade ▶│               │
   │                   │   step_up_completed: true      │               │
   │                   │◀─ updated ────────────────────│               │
   │                   │                               │               │
   │◀── session ──────│               │               │               │
   │    continues      │               │               │               │
```

### 5.6 OIDC Authorization Code Flow (with PKCE)

Standard OIDC flow for client applications using X-Auth as their identity provider.

```
End User          Browser           Client App        auth-svc           risk-svc       txn-svc
   │                 │                  │                 │                  │              │
   │── Click ───────▶│                  │                 │                  │              │
   │   "Login"       │── GET /authorize▶│                 │                  │              │
   │                 │  ?client_id=...  │                 │                  │              │
   │                 │  &redirect_uri=. │                 │                  │              │
   │                 │  &code_challenge= │                │                  │              │
   │                 │  &state=...      │                 │                  │              │
   │                 │                  │─── 302 ────────▶│                  │              │
   │                 │◀──── Login page ──────────────────│                  │              │
   │                 │                                    │                  │              │
   │── Credentials ─▶│                                    │                  │              │
   │                 │──────── POST /auth/login ─────────▶│                  │              │
   │                 │                                    │── evaluate ─────▶│              │
   │                 │                                    │◀─ tier:low ──────│              │
   │                 │                                    │                  │              │
   │                 │                                    │── create auth_flow              │
   │                 │                                    │   state=code_issued              │
   │                 │                                    │                  │              │
   │                 │◀── 302 redirect_uri?code=...&state=│                  │              │
   │                 │                                    │                  │              │
   │                 │── GET /callback ─▶│                 │                  │              │
   │                 │   ?code=...       │                 │                  │              │
   │                 │                  │── POST /token ─▶│                  │              │
   │                 │                  │  grant_type=     │                  │              │
   │                 │                  │  authorization_  │                  │              │
   │                 │                  │  code             │                  │              │
   │                 │                  │  code_verifier=   │                  │              │
   │                 │                  │◀─ access_token ──│                  │              │
   │                 │                  │   id_token        │                  │              │
   │                 │                  │   refresh_token   │                  │              │
   │                 │◀── Logged in ────│                  │                  │              │
   │◀── Dashboard ──│                  │                  │                  │              │
```

---

## 6. Data Stores

### 6.1 Storage Architecture

| Store | Purpose | Scope |
|-------|---------|-------|
| **PostgreSQL (per service)** | Primary data, ACID transactions, audit trail | Service-local |
| **Redis (shared)** | Session cache, rate limit counters, risk score cache, OIDC nonces | Cross-service |

### 6.2 Key Table DDL

#### transaction-service — `txn_db`

```sql
CREATE TABLE transactions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    user_id         UUID NOT NULL,
    session_id      UUID,
    risk_eval_id    UUID,
    action          TEXT NOT NULL,
    resource        TEXT NOT NULL,
    resource_sensitivity TEXT NOT NULL DEFAULT 'medium',
    decision        TEXT NOT NULL CHECK (decision IN ('allow', 'deny', 'step_up_required', 'pending')),
    step_up_used    BOOLEAN NOT NULL DEFAULT FALSE,
    step_up_method  TEXT,
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at      TIMESTAMPTZ,

    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

CREATE INDEX idx_txn_tenant_user ON transactions (tenant_id, user_id);
CREATE INDEX idx_txn_tenant_session ON transactions (tenant_id, session_id);
CREATE INDEX idx_txn_created ON transactions (tenant_id, created_at DESC);

CREATE TABLE audit_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    entity_type     TEXT NOT NULL,
    entity_id       UUID NOT NULL,
    action          TEXT NOT NULL,
    actor_id        UUID,
    actor_type      TEXT NOT NULL DEFAULT 'user',
    ip_address      INET,
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_tenant_entity ON audit_events (tenant_id, entity_type, entity_id);
CREATE INDEX idx_audit_tenant_created ON audit_events (tenant_id, created_at DESC);

CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    plan            TEXT NOT NULL CHECK (plan IN ('developer', 'growth', 'enterprise')),
    config          JSONB NOT NULL DEFAULT '{}',
    api_key_hash    TEXT NOT NULL,
    rate_limit      INTEGER NOT NULL DEFAULT 1000,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

#### risk-service — `risk_db`

```sql
CREATE TABLE risk_evaluations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    user_id             UUID NOT NULL,
    session_id          UUID,
    action              TEXT,
    resource            TEXT,
    resource_sensitivity TEXT,
    signals             JSONB NOT NULL,
    scores              JSONB NOT NULL,
    aggregate_score     REAL NOT NULL,
    tier                TEXT NOT NULL CHECK (tier IN ('low', 'medium', 'high')),
    flags               TEXT[] DEFAULT '{}',
    policy_id           UUID NOT NULL,
    sensitivity_applied BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_risk_tenant_user ON risk_evaluations (tenant_id, user_id);
CREATE INDEX idx_risk_tenant_session ON risk_evaluations (tenant_id, session_id);
CREATE INDEX idx_risk_created ON risk_evaluations (tenant_id, created_at DESC);

CREATE TABLE risk_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            TEXT NOT NULL,
    rules           JSONB NOT NULL,
    resource_map    JSONB NOT NULL DEFAULT '{}',
    weights         JSONB NOT NULL,
    thresholds      JSONB NOT NULL,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    version         INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, name, version)
);

CREATE INDEX idx_policy_tenant_active ON risk_policies (tenant_id) WHERE active = TRUE;
```

#### authentication-service — `auth_db`

```sql
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    external_id     TEXT,
    email           TEXT NOT NULL,
    email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, email),
    UNIQUE (tenant_id, external_id)
);

CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    user_id         UUID NOT NULL REFERENCES users(id),
    device_id       TEXT,
    ip_address      INET,
    risk_level      TEXT NOT NULL DEFAULT 'low',
    step_up_completed BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_session_tenant_user ON sessions (tenant_id, user_id);
CREATE INDEX idx_session_expires ON sessions (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE auth_flows (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    user_id             UUID,
    client_id           UUID NOT NULL,
    type                TEXT NOT NULL CHECK (type IN ('oidc', 'social', 'saml')),
    state               TEXT NOT NULL CHECK (state IN ('initiated', 'code_issued', 'exchanged', 'expired')),
    authorization_code  TEXT,
    code_challenge      TEXT,
    code_challenge_method TEXT DEFAULT 'S256',
    redirect_uri        TEXT NOT NULL,
    scope               TEXT NOT NULL DEFAULT 'openid',
    nonce               TEXT,
    expires_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_authflow_code ON auth_flows (authorization_code) WHERE state = 'code_issued';

CREATE TABLE oidc_clients (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    client_id       TEXT NOT NULL UNIQUE,
    client_secret_hash TEXT NOT NULL,
    name            TEXT NOT NULL,
    redirect_uris   TEXT[] NOT NULL,
    grant_types     TEXT[] NOT NULL DEFAULT '{authorization_code}',
    scopes          TEXT[] NOT NULL DEFAULT '{openid,profile,email}',
    token_ttl_sec   INTEGER NOT NULL DEFAULT 3600,
    refresh_ttl_sec INTEGER NOT NULL DEFAULT 2592000,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    user_id         UUID NOT NULL REFERENCES users(id),
    client_id       UUID NOT NULL REFERENCES oidc_clients(id),
    token_hash      TEXT NOT NULL UNIQUE,
    family_id       UUID NOT NULL,
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_refresh_family ON refresh_tokens (family_id);
```

#### authenticator-service — `authr_db`

```sql
CREATE TABLE authenticators (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    user_id         UUID NOT NULL,
    type            TEXT NOT NULL CHECK (type IN ('fido2', 'totp', 'sms', 'email', 'push')),
    credential      JSONB NOT NULL,
    metadata        JSONB DEFAULT '{}',
    verified        BOOLEAN NOT NULL DEFAULT FALSE,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, user_id, type, (credential->>'credential_id'))
);

CREATE INDEX idx_authr_tenant_user ON authenticators (tenant_id, user_id);

CREATE TABLE challenges (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    user_id         UUID NOT NULL,
    authenticator_id UUID REFERENCES authenticators(id),
    type            TEXT NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('pending', 'verified', 'failed', 'expired')),
    challenge_data  JSONB NOT NULL,
    code_hash       TEXT,
    attempts        INTEGER NOT NULL DEFAULT 0,
    max_attempts    INTEGER NOT NULL DEFAULT 3,
    expires_at      TIMESTAMPTZ NOT NULL,
    verified_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_challenge_tenant_user ON challenges (tenant_id, user_id);
CREATE INDEX idx_challenge_state ON challenges (state) WHERE state = 'pending';
```

### 6.3 Redis Key Patterns

```
session:{session_id}              → JSON session data (TTL = session expiry)
rate:{tenant_id}:{window}         → Counter (TTL = window size)
rate:{tenant_id}:{ip}:{window}    → Counter (TTL = window size)
risk_cache:{user_id}:{session_id} → Last risk evaluation (TTL = 60s)
nonce:{nonce}                     → 1 (TTL = 300s, prevents replay)
challenge:{challenge_id}          → Challenge state (TTL = 300s)
device:{fingerprint}              → Device reputation score (TTL = 24h)
```

---

## 7. Risk Signal Pipeline

The risk-service processes signals through a multi-stage pipeline to produce a risk tier. This pipeline reflects the four signal categories shown on the marketing site: Device Reputation, Behavioral Biometrics, Network Risk, and User Behavior.

### 7.1 Pipeline Stages

```
                     ┌────────────────────┐
                     │  Signal Collection  │
                     │  (from client SDK   │
                     │   + server context) │
                     └─────────┬──────────┘
                               │
                               ▼
                     ┌────────────────────┐
                     │    Enrichment       │
                     │  • IP → geo + ASN   │
                     │  • Fingerprint → DB │
                     │  • User → history   │
                     └─────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼                ▼
   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
   │   Device     │ │  Behavior    │ │   Network    │ │    User      │
   │   Scorer     │ │  Scorer      │ │   Scorer     │ │   Scorer     │
   │              │ │              │ │              │ │              │
   │ • fingerprint│ │ • typing     │ │ • IP rep     │ │ • acct age   │
   │ • fraud hist │ │ • mouse dyn  │ │ • geo-fence  │ │ • login freq │
   │ • browser    │ │ • touch press│ │ • VPN detect │ │ • failed att │
   │   entropy    │ │ • nav pattern│ │ • Tor detect │ │ • priv escal │
   │              │ │              │ │ • velocity   │ │ • session    │
   │ score: 0-1   │ │ score: 0-1   │ │ score: 0-1   │ │ score: 0-1   │
   └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
          │                │                │                │
          └────────────────┼────────────────┘                │
                           │                                 │
                           ▼                                 │
                ┌────────────────────┐                       │
                │ Weighted           │◀──────────────────────┘
                │ Aggregation        │
                │                    │
                │ device   × 0.25    │
                │ behavior × 0.30    │
                │ network  × 0.25    │
                │ user     × 0.20    │
                │ ─────────────────  │
                │ aggregate = Σ      │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │  Policy            │
                │  Application       │
                │                    │
                │  tenant policy     │
                │  overrides weights │
                │  & thresholds      │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │  Resource          │
                │  Sensitivity       │
                │  Overlay           │
                │                    │
                │  low    × 0.8      │
                │  medium × 1.0      │
                │  high   × 1.3      │
                │  critical × 1.6    │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │  Tier Assignment   │
                │                    │
                │  0.0 – 0.3 → LOW   │
                │  0.3 – 0.7 → MED   │
                │  0.7 – 1.0 → HIGH  │
                └────────────────────┘
```

### 7.2 Scorer Details

| Scorer | Inputs | Score Range | Key Thresholds |
|--------|--------|-------------|----------------|
| **Device** | Fingerprint hash, fraud DB match, browser entropy, known device | 0.0 – 1.0 | Unknown device: +0.4, Fraud history: +0.8 |
| **Behavior** | Typing cadence δ, mouse velocity δ, touch pressure δ, nav pattern | 0.0 – 1.0 | >2σ deviation from baseline: +0.5 |
| **Network** | IP reputation score, geo distance from norm, VPN/Tor flags, ASN risk | 0.0 – 1.0 | Tor exit node: +0.9, Flagged IP: +0.7 |
| **User** | Account age, login frequency, failed attempts, privilege patterns | 0.0 – 1.0 | >5 failed attempts/24h: +0.6, New account + high-value action: +0.5 |

### 7.3 Risk Tier Definitions

Aligned with the marketing site's three-tier model:

| Tier | Score Range | Marketing Copy | Auth Action |
|------|-------------|---------------|-------------|
| **Low** | 0.0 – 0.3 | "Seamless Access" — trusted identity signals + low-sensitivity operation | Instant access granted |
| **Medium** | 0.3 – 0.7 | "Soft Step-Up" — mild signal deviation or elevated resource sensitivity | SMS OTP, magic email link, or FIDO2 |
| **High** | 0.7 – 1.0 | "Strong Step-Up" — suspicious signals, high-value operation, or both | Push or FIDO2 with knowledge/possession factor |

---

## 8. CAEP/SSF Considerations

The [Continuous Access Evaluation Protocol (CAEP)](https://openid.net/specs/openid-caep-specification-1_0.html) and [Shared Signals Framework (SSF)](https://openid.net/specs/openid-sharedsignals-framework-1_0.html) standardize real-time security event sharing. X-Auth will adopt these incrementally.

### 8.1 Phased Approach

| Phase | Scope | Deliverable |
|-------|-------|-------------|
| **Phase 1** (Now) | Internal risk events between X-Auth services | Internal event types + REST-based propagation |
| **Phase 2** (Future) | SSF Transmitter | X-Auth publishes events to subscriber client apps via SSF |
| **Phase 3** (Future) | SSF Receiver | X-Auth ingests events from external SSF transmitters (e.g., IdP signals) |

### 8.2 Internal Event Types (Phase 1)

Events that flow between services via the existing REST contracts:

| Event | Source Service | Consumers | CAEP Mapping |
|-------|---------------|-----------|-------------|
| `session.risk_changed` | risk-service | transaction-svc, auth-svc | `assurance-level-change` |
| `session.revoked` | auth-service | transaction-svc | `session-revoked` |
| `credential.compromised` | authenticator-svc | auth-svc, risk-svc | `credential-change` (compromise) |
| `device.flagged` | risk-service | authenticator-svc | `device-compliance-change` |
| `user.lockout` | auth-service | transaction-svc | `account-disabled` |
| `ip.reputation_changed` | risk-service | transaction-svc | *(custom)* |

### 8.3 SSF Transmitter Design (Phase 2)

When X-Auth becomes an SSF transmitter, it will:

1. Expose `/.well-known/sse-configuration` discovery endpoint
2. Support the **push** delivery method (POST to subscriber endpoint)
3. Publish CAEP events as Security Event Tokens (SETs) — JWT-encoded
4. Allow client apps to subscribe to specific event types per subject (user, session, device)
5. The **transaction-service** will be the SSF transmitter (it has the full view of decisions)

### 8.4 SSF Receiver Design (Phase 3)

When X-Auth becomes an SSF receiver:

1. The **risk-service** will ingest external SETs as additional signals
2. External signals (e.g., "user credential compromised at IdP") feed into the risk pipeline
3. Mapped to internal event types and incorporated into scoring

---

## 9. Multi-Tenancy

### 9.1 Tenancy Model

| Plan | Infra Model | Isolation |
|------|-------------|-----------|
| **Developer** | Shared infrastructure | Logical (row-level `tenant_id`) |
| **Growth** | Shared infrastructure | Logical (row-level `tenant_id`) |
| **Enterprise** | Dedicated cluster | Physical (separate DB + Redis instances) |

Shared infrastructure tenants (Developer/Growth) share the same database instances with row-level isolation via `tenant_id` on every table. Enterprise tenants get a fully isolated deployment.

### 9.2 Tenant Configuration

```json
{
  "id": "ten_abc123",
  "name": "Acme Corp",
  "plan": "growth",
  "config": {
    "risk_policy": {
      "weights": {
        "device": 0.25,
        "behavior": 0.30,
        "network": 0.25,
        "user": 0.20
      },
      "thresholds": {
        "low_max": 0.3,
        "medium_max": 0.7
      },
      "resource_sensitivity_map": {
        "payments": "high",
        "reports": "medium",
        "profile": "low"
      }
    },
    "auth": {
      "session_ttl_hours": 8,
      "max_sessions_per_user": 5,
      "allowed_authenticators": ["fido2", "totp", "sms", "push"],
      "password_policy": null,
      "social_providers": ["google", "github"]
    },
    "branding": {
      "logo_url": "https://acme.com/logo.svg",
      "primary_color": "#4F46E5",
      "app_name": "Acme Portal"
    },
    "webhooks": {
      "enabled": true,
      "url": "https://acme.com/webhooks/xauth",
      "events": ["transaction.denied", "session.revoked", "risk.high"]
    }
  },
  "rate_limits": {
    "requests_per_minute": 600,
    "evaluations_per_minute": 200,
    "challenges_per_hour": 50
  }
}
```

### 9.3 Rate Limiting by Tier

| Limit | Developer | Growth | Enterprise |
|-------|-----------|--------|------------|
| API requests/min | 100 | 600 | Custom (no hard cap) |
| Risk evaluations/min | 50 | 200 | Custom |
| Challenges/hour/user | 10 | 50 | Custom |
| MAU cap | 5,000 | Unlimited | Unlimited |
| Concurrent sessions/user | 3 | 5 | Custom |

Rate limiting is enforced at three layers:
1. **API Gateway** — global per-tenant request rate
2. **transaction-service** — per-endpoint, per-tenant limits (Redis counters)
3. **authenticator-service** — per-user challenge rate (prevents brute force)

---

## 10. Security

### 10.1 Token Security

**Access Tokens (JWT):**
- Algorithm: RS256 (RSA 2048-bit minimum, 4096-bit recommended)
- TTL: 1 hour (configurable per OIDC client)
- Claims: `sub`, `iss`, `aud`, `exp`, `iat`, `tenant_id`, `scope`, `session_id`
- Signed by authentication-service; verified by any service via JWKS endpoint

**Refresh Tokens:**
- Opaque tokens stored hashed (`SHA-256`) in `refresh_tokens` table
- **Rotation**: every refresh issues a new token and invalidates the old one
- **Family-based revocation**: if a rotated-out token is reused, the entire token family is revoked (detects token theft)
- TTL: 30 days (configurable)

**ID Tokens (OIDC):**
- Standard OIDC ID Token (JWT)
- Contains `nonce` claim to prevent replay
- Signed with same RS256 key as access tokens

### 10.2 Key Management

| Key Type | Storage | Rotation |
|----------|---------|----------|
| JWT signing key (RSA) | KMS (AWS KMS / GCP Cloud KMS) | 90-day rotation, old keys kept for verification |
| Tenant API keys | Hashed (SHA-256) in `tenants` table | Revocable, multi-key support |
| OIDC client secrets | Hashed (bcrypt) in `oidc_clients` table | Client-initiated rotation |
| TOTP secrets | AES-256-GCM envelope encrypted (DEK in DB, KEK in KMS) | N/A |
| FIDO2 credential keys | Stored as-is (public keys only) | N/A (device-bound) |

**Envelope Encryption Pattern:**
```
KMS (KEK) ──encrypts──▶ DEK (per-tenant)
DEK ──encrypts──▶ sensitive fields (TOTP secrets, etc.)
```

### 10.3 Transport Security

| Path | Protocol |
|------|----------|
| Client → API Gateway | TLS 1.3 (minimum TLS 1.2) |
| API Gateway → Services | mTLS (mutual TLS with service certificates) |
| Service → Service | mTLS |
| Service → PostgreSQL | TLS with certificate verification |
| Service → Redis | TLS |

### 10.4 PKCE (Proof Key for Code Exchange)

All OIDC authorization code flows **require PKCE** (RFC 7636):
- `code_challenge_method`: S256 only (plain not supported)
- `code_challenge` stored in `auth_flows` table
- Verified at token exchange against `code_verifier`
- Prevents authorization code interception attacks

### 10.5 Rate Limiting & Abuse Prevention

```
Layer 1: API Gateway
├── Per-tenant global rate limit (requests/min)
├── Per-IP rate limit (prevents single-source flooding)
└── Request size limits (1MB max body)

Layer 2: transaction-service
├── Per-tenant, per-endpoint limits
├── Burst allowance with sliding window
└── 429 responses with Retry-After header

Layer 3: authenticator-service
├── Per-user challenge rate limit
├── Max attempts per challenge (3)
├── Exponential backoff on failed verifications
└── Account lockout after N consecutive failures
```

### 10.6 Audit Logging

Every security-relevant action produces an `AuditEvent`:

| Event Category | Examples | Retention |
|----------------|----------|-----------|
| Authentication | Login success/failure, token issue/refresh/revoke | 2 years |
| Authorization | Access granted/denied, policy evaluation | 2 years |
| Risk | Tier assignment, score details, policy match | 1 year |
| Admin | Tenant config change, policy update, key rotation | 5 years |
| Authenticator | Enrollment, removal, challenge success/failure | 2 years |

**Retention by plan:**
| Plan | Hot Storage | Cold Storage (S3/GCS) |
|------|------------|----------------------|
| Developer | 90 days | 1 year |
| Growth | 1 year | 2 years |
| Enterprise | 2 years | 5 years (or custom) |

Audit events are **append-only** and **immutable**. No UPDATE or DELETE operations are permitted on the `audit_events` table.

---

## 11. Compliance Certification Mapping

The marketing site advertises five compliance certifications: **SOC 2 Type II**, **ISO 27001**, **GDPR Ready**, **HIPAA Compliant**, and **PCI DSS**. This section maps X-Auth's architectural controls to each framework's requirements and identifies any remaining gaps for certification readiness.

### 11.1 SOC 2 Type II

SOC 2 evaluates controls across five Trust Service Criteria. X-Auth must demonstrate these controls operate effectively over a sustained period (typically 6–12 months).

| Trust Service Criteria | X-Auth Controls | Architecture Reference | Gaps / Action Items |
|----------------------|-----------------|----------------------|-------------------|
| **Security** (CC6–CC8) | mTLS between services; TLS 1.3 external; API key + JWT auth; rate limiting; PKCE | §10.3 Transport Security, §10.1 Token Security, §10.4 PKCE, §10.5 Rate Limiting | Penetration testing schedule; vulnerability management process |
| **Availability** (A1) | Kubernetes HPA; PG primary+replica; Redis cluster HA; health probes (`/healthz`, `/readyz`) | Appendix B Deployment Topology | Define RTO/RPO targets per plan tier; document failover runbooks |
| **Processing Integrity** (PI1) | Immutable audit log; transaction-service orchestration with deterministic decisions; risk policy versioning | §10.6 Audit Logging, §4.1 transaction-service, §4.2 risk-service policies | Input validation test suite; reconciliation process for risk evaluations |
| **Confidentiality** (C1) | Envelope encryption (KMS + DEK); hashed secrets (bcrypt/SHA-256); tenant isolation (row-level + dedicated clusters) | §10.2 Key Management, §9.1 Tenancy Model | Data classification policy document; encryption-at-rest for PG (TDE or disk-level) |
| **Privacy** (P1–P8) | Tenant-scoped data; session TTLs with expiry; audit retention by plan | §9 Multi-Tenancy, §10.6 Audit Logging | Privacy policy; data processing agreement (DPA) template; cookie/consent requirements for OIDC flows |

**Key deliverables for SOC 2 readiness:**
1. Formal security policies (access control, incident response, change management)
2. Continuous monitoring dashboard (Prometheus/Grafana alerts for anomalies)
3. Evidence collection automation (audit log exports, access reviews, config change history)
4. Annual penetration test by qualified third party
5. Employee security awareness training program

### 11.2 ISO 27001

ISO 27001 requires an Information Security Management System (ISMS). The controls below map to Annex A of ISO 27001:2022.

| Annex A Control Area | X-Auth Controls | Architecture Reference | Gaps / Action Items |
|---------------------|-----------------|----------------------|-------------------|
| **A.5 — Organizational** | Tenant config with policy-as-code; risk policies versioned | §4.2 Risk Policies, §9.2 Tenant Configuration | ISMS scope statement; security roles/responsibilities matrix; risk treatment plan |
| **A.6 — People** | *(Operational)* | — | Background checks; onboarding/offboarding procedures; security training |
| **A.7 — Physical** | Cloud-managed (AWS/GCP) | Appendix B | Inherit cloud provider physical controls; document shared responsibility model |
| **A.8 — Technological** | | | |
| A.8.1 — User endpoint devices | Device fingerprinting + reputation scoring | §7.2 Device Scorer | Document BYOD policy for internal staff |
| A.8.2 — Privileged access | API key scoping; tenant isolation; admin audit trail | §10.2, §10.6, §9 | Implement admin RBAC for dashboard; break-glass procedure |
| A.8.3 — Information access restriction | RBAC/ABAC via OPA; session-scoped tokens | §4.1 /authorize, §10.1 Token Security | Document access control matrix per service |
| A.8.5 — Secure authentication | FIDO2, TOTP, push MFA; risk-based step-up | §4.4 Authenticator Service, §7 Risk Pipeline | Enforce MFA for internal admin access |
| A.8.9 — Configuration management | Kubernetes manifests; Terraform IaC; policy versioning | Appendix A, Appendix B | GitOps audit trail; change approval workflow |
| A.8.15 — Logging | Structured JSON logs; immutable audit events; OpenTelemetry tracing | §10.6, Appendix B Health & Observability | SIEM integration; log tamper detection (signing) |
| A.8.16 — Monitoring | Prometheus metrics; distributed tracing; health probes | Appendix B Health & Observability | Alerting runbooks; incident severity classification |
| A.8.24 — Use of cryptography | RS256 JWT; AES-256-GCM envelope; TLS 1.3; bcrypt | §10.1, §10.2, §10.3 | Cryptographic inventory document; key lifecycle policy |
| A.8.25 — Secure development | Go service structure; migration-based schema changes | Appendix A | SSDLC policy; code review requirements; dependency scanning (Dependabot/Snyk) |
| A.8.28 — Secure coding | Input validation; parameterized queries; PKCE | §10.4, §4 Service Contracts | SAST/DAST integration in CI/CD; OWASP Top 10 checklist |

**Key deliverables for ISO 27001 readiness:**
1. ISMS scope document and Statement of Applicability (SoA)
2. Risk assessment methodology and risk register
3. Information security policy set (12–15 policies)
4. Internal audit program (annual cycle)
5. Management review process

### 11.3 GDPR Ready

GDPR applies when processing personal data of EU/EEA residents. X-Auth processes user identifiers, behavioral signals, device fingerprints, and IP addresses — all personal data under GDPR.

| GDPR Article | Requirement | X-Auth Implementation | Gaps / Action Items |
|-------------|------------|----------------------|-------------------|
| **Art. 5** — Principles | Lawful, fair, transparent; purpose limitation; data minimization; accuracy; storage limitation; integrity/confidentiality | Tenant-scoped data; session TTLs; audit retention limits by plan; encryption at rest and in transit | Document lawful basis per data category; data minimization review for signal collection |
| **Art. 6** — Lawful basis | Legal basis for each processing activity | Legitimate interest (security) + contract (service delivery) | Record of processing activities (RoPA) |
| **Art. 12–14** — Transparency | Privacy notice; information about processing | *(Operational)* | Privacy policy template for tenants; X-Auth's own privacy notice |
| **Art. 15** — Right of access | Data subject can request their data | User data queryable via `GET /v1/users`, session + transaction APIs | Build data export endpoint: `GET /v1/users/{id}/export` returning all user data across services |
| **Art. 17** — Right to erasure | "Right to be forgotten" | | **Significant gap**: Append-only audit log conflicts with erasure. Implement pseudonymization — replace user identifiers with opaque tokens in audit records upon erasure request, preserving log integrity while removing personal data |
| **Art. 20** — Data portability | Machine-readable data export | JSON API responses | Formalize data export format (JSON); include all user-related entities |
| **Art. 25** — Data protection by design | Privacy by default | Tenant isolation; encryption; minimal token claims; session expiry | Document DPbD assessment; default to minimal data collection |
| **Art. 28** — Processor obligations | DPA with sub-processors | *(Operational)* | DPA template; sub-processor list (Twilio, SendGrid, cloud provider); sub-processor change notification |
| **Art. 32** — Security of processing | Appropriate technical/organizational measures | mTLS, encryption, access controls, audit logging | Map Art. 32 controls to architecture sections (cross-ref table) |
| **Art. 33–34** — Breach notification | 72-hour notification to DPA; notify data subjects if high risk | *(Operational)* | Incident response plan with breach notification workflow; severity classification; DPA contact registry |
| **Art. 35** — DPIA | Data protection impact assessment for high-risk processing | Behavioral biometrics and device fingerprinting are high-risk | Conduct DPIA for: (1) behavioral biometrics scoring, (2) device fingerprinting, (3) continuous session monitoring |
| **Art. 44–49** — International transfers | Safeguards for data transfers outside EEA | *(Deployment-dependent)* | Standard Contractual Clauses (SCCs) if using non-EU cloud regions; document transfer mechanisms |

**GDPR-specific architecture requirements:**

```
User Erasure Flow (pseudonymization approach):

1. Erasure request received for user_id
2. authentication-service: delete User record, revoke all sessions
3. authenticator-service: delete all Authenticator records
4. risk-service: pseudonymize user_id → opaque hash in risk_evaluations
5. transaction-service: pseudonymize user_id → opaque hash in transactions + audit_events
6. Redis: flush all keys containing user_id or session_id
7. Return confirmation with erasure receipt ID
```

**Data retention alignment:**

| Data Category | GDPR Principle | Implementation |
|--------------|---------------|----------------|
| User profile | Storage limitation | Deleted on account closure or erasure request |
| Sessions | Storage limitation | Auto-expire via TTL; hard-delete after expiry + 30 days |
| Risk evaluations | Legitimate interest (security) | Pseudonymized after user erasure; retained per plan tier retention |
| Audit events | Legal obligation (security) | Pseudonymized (not deleted) — append-only integrity preserved |
| Device fingerprints | Legitimate interest | Redis TTL 24h; no long-term storage of raw fingerprints |

### 11.4 HIPAA Compliant

HIPAA applies when X-Auth tenants are healthcare entities processing Protected Health Information (PHI). X-Auth itself does not store PHI, but it processes access to systems that may contain PHI — making it a **Business Associate**.

| HIPAA Rule | Requirement | X-Auth Controls | Gaps / Action Items |
|-----------|------------|-----------------|-------------------|
| **Administrative Safeguards** (§164.308) | | | |
| Security management process | Risk analysis; risk management | Risk-based architecture; risk scoring pipeline | Formal risk analysis document; remediation tracking |
| Workforce security | Authorization, clearance | *(Operational)* | Background checks; role-based admin access; termination procedures |
| Information access management | Access control policies | RBAC/ABAC; tenant isolation; session scoping | Minimum necessary access review for each API endpoint |
| Security awareness training | Training program | *(Operational)* | Annual HIPAA training; phishing simulation |
| Security incident procedures | Incident response | Audit logging; anomaly detection via risk-service | Incident response plan; breach notification workflow (60-day window for HIPAA) |
| Contingency plan | Backup; disaster recovery; emergency mode | PG replicas; Redis HA; multi-AZ deployment | Document backup procedures; test DR annually; emergency access procedure |
| **Physical Safeguards** (§164.310) | | | |
| Facility access | Physical security | Cloud-managed (inherited) | Document shared responsibility; cloud provider BAA |
| Workstation/device security | Endpoint security | Device fingerprinting for end-users | *(Internal)* endpoint security policy for XentraNET staff |
| **Technical Safeguards** (§164.312) | | | |
| Access control | Unique user ID; emergency access; auto-logoff; encryption | User IDs; session TTL expiry; TLS + envelope encryption | Emergency access ("break-glass") procedure for admin |
| Audit controls | Record and examine activity | Immutable audit log; per-category retention; cold archival | HIPAA-specific audit report generation |
| Integrity controls | Protect data from improper alteration | Append-only audit; signed JWTs; PKCE | Database integrity checks; checksum validation |
| Transmission security | Encryption in transit | TLS 1.3; mTLS between services | Document all data flows with encryption status |
| **Organizational** (§164.314) | | | |
| Business Associate Agreement | BAA with covered entities | *(Operational)* | BAA template; sub-contractor BAAs (Twilio, SendGrid, cloud) |

**HIPAA-specific architecture requirements:**

1. **Enterprise-only**: HIPAA compliance available only on Enterprise plan (dedicated cluster isolation required)
2. **Audit log retention**: Minimum 6 years for HIPAA (override plan-tier defaults for HIPAA tenants)
3. **Emergency access**: Break-glass admin procedure that bypasses normal auth but creates elevated audit trail
4. **PHI boundary**: X-Auth does **not** store PHI; document this clearly — X-Auth controls access **to** systems containing PHI

**Tenant config addition for HIPAA:**
```json
{
  "compliance": {
    "hipaa_enabled": true,
    "audit_retention_years": 6,
    "require_mfa_admin": true,
    "emergency_access_enabled": true,
    "baa_signed_at": "2026-03-15T00:00:00Z"
  }
}
```

### 11.5 PCI DSS

PCI DSS applies when X-Auth processes, transmits, or stores cardholder data. X-Auth does **not** handle cardholder data directly, but it authenticates and authorizes access to systems that do — placing it in the **PCI DSS scope as a security-affecting system**.

| PCI DSS Req. | Requirement | X-Auth Controls | Gaps / Action Items |
|-------------|------------|-----------------|-------------------|
| **Req. 1** — Network security controls | Firewall/segmentation | Kubernetes network policies; mTLS; service-to-service isolation | Document network segmentation; verify no direct DB access from external |
| **Req. 2** — Secure configuration | Harden defaults | Env-based config; no default credentials; TLS enforced | CIS benchmark for container images; remove unnecessary packages from Docker images |
| **Req. 3** — Protect stored data | Encrypt sensitive data | Envelope encryption; hashed secrets; no raw credential storage | Verify no PAN/CVV ever reaches X-Auth logs or audit events |
| **Req. 4** — Encrypt transmission | Encrypt data in transit | TLS 1.3 (min 1.2); mTLS internal | Document all transmission paths; verify no plaintext fallback |
| **Req. 5** — Malware protection | Anti-malware | *(Runtime)* | Container image scanning (Trivy/Snyk); runtime threat detection |
| **Req. 6** — Secure development | Secure SDLC | Go service structure; migration-based changes | SAST in CI; dependency vulnerability scanning; code review policy; patch management SLA |
| **Req. 7** — Restrict access | Need-to-know | RBAC/ABAC; tenant isolation; scoped API keys | Document access control matrix; implement least-privilege for service accounts |
| **Req. 8** — Identify users | Unique IDs; MFA | User entity; FIDO2/TOTP MFA; session tracking | MFA for all administrative access; password complexity requirements (if passwords used) |
| **Req. 9** — Physical access | Physical security | Cloud-managed (inherited) | Cloud provider PCI AOC; document shared responsibility |
| **Req. 10** — Log and monitor | Audit trail | Immutable audit events; structured logging; OpenTelemetry | Log integrity verification; daily log review process; 1-year online + 1-year archive retention for PCI |
| **Req. 11** — Test security | Vulnerability scans; penetration tests | *(Operational)* | Quarterly ASV scans; annual penetration test; internal vulnerability scanning |
| **Req. 12** — Security policy | Organizational policy | *(Operational)* | Information security policy; incident response plan; vendor management; risk assessment |

**PCI DSS-specific architecture requirements:**

1. **Cardholder data boundary**: X-Auth never sees PAN, CVV, or track data. Document the CDE boundary — X-Auth sits **outside** the CDE but **within PCI scope** as a security control
2. **Log retention**: PCI requires 1 year retention with 3 months immediately available — verify plan-tier retention meets this minimum
3. **Key management**: PCI Req. 3.5–3.7 — document key custodians, split knowledge, and dual control for KMS master keys
4. **Segmentation testing**: Annual penetration test must verify that X-Auth services cannot access CDE networks directly

### 11.6 Compliance Control Matrix (Cross-Reference)

A unified view of which architecture controls satisfy which compliance framework requirements.

| X-Auth Control | Section | SOC 2 | ISO 27001 | GDPR | HIPAA | PCI DSS |
|---------------|---------|-------|-----------|------|-------|---------|
| mTLS (service-to-service) | §10.3 | CC6.1 | A.8.24 | Art. 32 | §164.312(e) | Req. 4 |
| TLS 1.3 (external) | §10.3 | CC6.1 | A.8.24 | Art. 32 | §164.312(e) | Req. 4 |
| JWT signing (RS256, KMS) | §10.1, §10.2 | CC6.1 | A.8.24 | Art. 32 | §164.312(a) | Req. 3, 8 |
| Refresh token rotation | §10.1 | CC6.1 | A.8.5 | Art. 25 | §164.312(d) | Req. 8 |
| Envelope encryption (KMS) | §10.2 | C1.1 | A.8.24 | Art. 32 | §164.312(a) | Req. 3 |
| Immutable audit log | §10.6 | PI1.1 | A.8.15 | Art. 5(2) | §164.312(b) | Req. 10 |
| Audit retention by tier | §10.6 | PI1.1 | A.8.10 | Art. 5(1)(e) | §164.312(b) | Req. 10 |
| Rate limiting (3 layers) | §10.5 | CC6.6 | A.8.16 | — | §164.308(a)(1) | Req. 6 |
| PKCE enforcement | §10.4 | CC6.1 | A.8.5 | Art. 25 | §164.312(a) | Req. 8 |
| Tenant isolation (row-level) | §9.1 | C1.2 | A.8.3 | Art. 25 | §164.312(a) | Req. 7 |
| Dedicated cluster (Enterprise) | §9.1 | C1.2 | A.8.3 | Art. 25 | §164.310 | Req. 1 |
| RBAC/ABAC authorization | §4.1 | CC6.3 | A.8.3 | Art. 25 | §164.312(a) | Req. 7 |
| Risk-based step-up auth | §7 | CC6.1 | A.8.5 | Art. 32 | §164.312(d) | Req. 8 |
| FIDO2/WebAuthn MFA | §4.4 | CC6.1 | A.8.5 | — | §164.312(d) | Req. 8 |
| Device fingerprinting | §7.2 | CC6.8 | A.8.1 | Art. 35* | §164.312(d) | Req. 8 |
| Behavioral biometrics | §7.2 | CC6.8 | A.8.16 | Art. 35* | §164.312(d) | — |
| Session expiry / revocation | §4.3 | CC6.1 | A.8.5 | Art. 5(1)(e) | §164.312(a) | Req. 8 |
| Health probes + metrics | App. B | A1.2 | A.8.16 | — | §164.308(a)(1) | Req. 10 |
| DB per service (isolation) | §6.1 | CC6.3 | A.8.3 | Art. 25 | §164.312(a) | Req. 1 |
| Kubernetes HPA + HA | App. B | A1.1 | A.8.14 | — | §164.308(a)(7) | Req. 1 |

*Art. 35: DPIA required for device fingerprinting and behavioral biometrics (high-risk automated profiling).

### 11.7 Compliance Roadmap

Phased approach to certification readiness, aligned with platform build-out:

| Phase | Timeline | Deliverables | Target Certifications |
|-------|----------|-------------|----------------------|
| **Phase 1 — Foundations** | During service build | Security controls implemented as designed in §10; audit logging operational; encryption at rest and in transit | — (No certifications yet) |
| **Phase 2 — Policy & Process** | Post-MVP | ISMS scope + policies (12–15 documents); RoPA; DPA template; incident response plan; DPIA for behavioral biometrics; BAA template | GDPR Ready (self-assessed) |
| **Phase 3 — SOC 2 Type I** | MVP + 3 months | Point-in-time SOC 2 audit; evidence collection; vulnerability scan; pentest | SOC 2 Type I |
| **Phase 4 — SOC 2 Type II + ISO** | MVP + 12 months | Operating effectiveness over 6+ months; ISO 27001 Stage 1 + Stage 2 audit | SOC 2 Type II, ISO 27001 |
| **Phase 5 — Healthcare & Payments** | On Enterprise demand | HIPAA controls + BAA; PCI DSS SAQ/ROC (scope depends on integration) | HIPAA, PCI DSS |

**Ongoing requirements (all phases):**
- Quarterly vulnerability scanning
- Annual penetration testing
- Annual risk assessment review
- Continuous monitoring and alerting
- Employee security awareness training (annual + onboarding)

---

## Appendix A — Go Service Directory Structure

Each service follows the same layout, adapted to its domain:

```
x-auth/
├── ARCHITECTURE.md
├── CLAUDE.md
├── CONTENT_GUIDE.md
├── REQUIREMENTS.md
├── public/                         # Marketing site (existing)
│   └── index.html
│
├── cmd/                            # Service entrypoints
│   ├── transaction-service/
│   │   └── main.go
│   ├── risk-service/
│   │   └── main.go
│   ├── authentication-service/
│   │   └── main.go
│   └── authenticator-service/
│       └── main.go
│
├── internal/                       # Private application code
│   ├── transaction/                # transaction-service domain
│   │   ├── handler.go              # HTTP handlers
│   │   ├── service.go              # Business logic
│   │   ├── repository.go           # DB access
│   │   ├── model.go                # Domain types
│   │   └── client.go               # REST clients (risk, auth, authr)
│   │
│   ├── risk/                       # risk-service domain
│   │   ├── handler.go
│   │   ├── service.go
│   │   ├── repository.go
│   │   ├── model.go
│   │   ├── scorer/                 # Individual scorers
│   │   │   ├── device.go
│   │   │   ├── behavior.go
│   │   │   ├── network.go
│   │   │   └── user.go
│   │   ├── pipeline.go             # Orchestrates scoring pipeline
│   │   └── policy.go               # Policy engine
│   │
│   ├── authentication/             # authentication-service domain
│   │   ├── handler.go
│   │   ├── service.go
│   │   ├── repository.go
│   │   ├── model.go
│   │   ├── oidc/                   # OIDC provider logic
│   │   │   ├── provider.go
│   │   │   ├── token.go
│   │   │   └── jwks.go
│   │   └── social/                 # Social login adapters
│   │       ├── google.go
│   │       └── github.go
│   │
│   ├── authenticator/              # authenticator-service domain
│   │   ├── handler.go
│   │   ├── service.go
│   │   ├── repository.go
│   │   ├── model.go
│   │   └── vendor/                 # Vendor adapters
│   │       ├── fido2.go
│   │       ├── totp.go
│   │       ├── sms.go              # Twilio adapter
│   │       ├── email.go            # SendGrid adapter
│   │       └── push.go             # APNs/FCM adapter
│   │
│   └── shared/                     # Shared utilities
│       ├── middleware/
│       │   ├── auth.go             # API key / JWT validation
│       │   ├── tenant.go           # Tenant extraction + config
│       │   ├── ratelimit.go        # Rate limiting middleware
│       │   ├── logging.go          # Structured logging
│       │   └── requestid.go        # X-Request-ID propagation
│       ├── config/
│       │   └── config.go           # Env-based configuration
│       ├── database/
│       │   ├── postgres.go         # Connection pool setup
│       │   └── redis.go            # Redis client setup
│       ├── crypto/
│       │   ├── jwt.go              # JWT signing / verification
│       │   ├── hash.go             # SHA-256, bcrypt helpers
│       │   └── envelope.go         # Envelope encryption
│       └── httputil/
│           ├── response.go         # Standard JSON responses
│           └── errors.go           # Error types + codes
│
├── migrations/                     # Database migrations (per service)
│   ├── transaction/
│   │   └── 001_initial.sql
│   ├── risk/
│   │   └── 001_initial.sql
│   ├── authentication/
│   │   └── 001_initial.sql
│   └── authenticator/
│       └── 001_initial.sql
│
├── deploy/                         # Deployment configs
│   ├── docker/
│   │   ├── Dockerfile.transaction
│   │   ├── Dockerfile.risk
│   │   ├── Dockerfile.authentication
│   │   └── Dockerfile.authenticator
│   ├── k8s/
│   │   ├── base/
│   │   └── overlays/
│   │       ├── dev/
│   │       ├── staging/
│   │       └── production/
│   └── terraform/
│       ├── shared/                 # VPC, Redis, KMS
│       └── services/               # Per-service infra
│
├── api/                            # OpenAPI specs
│   ├── transaction-service.yaml
│   ├── risk-service.yaml
│   ├── authentication-service.yaml
│   └── authenticator-service.yaml
│
├── go.mod
├── go.sum
└── Makefile
```

---

## Appendix B — Deployment Topology

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              PRODUCTION                                   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │                    Cloud Load Balancer                            │    │
│  │              (TLS termination, DDoS protection)                  │    │
│  └───────────────────────────┬──────────────────────────────────────┘    │
│                              │                                           │
│  ┌───────────────────────────┴──────────────────────────────────────┐    │
│  │                       API Gateway                                │    │
│  │            (routing, rate limiting, API key validation)          │    │
│  └──────┬──────────┬──────────────┬──────────────┬─────────────────┘    │
│         │          │              │              │                       │
│    /v1/*      /v1/auth/*    (internal)      (internal)                   │
│         │          │              │              │                       │
│         ▼          ▼              ▼              ▼                       │
│  ┌───────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐                  │
│  │transaction │ │  auth    │ │  risk    │ │ authr    │                  │
│  │ service   │ │ service  │ │ service  │ │ service  │                  │
│  │           │ │          │ │          │ │          │                  │
│  │ 2+ pods   │ │ 2+ pods  │ │ 2+ pods  │ │ 2+ pods  │                  │
│  │ HPA       │ │ HPA      │ │ HPA      │ │ HPA      │                  │
│  └─────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘                  │
│        │            │            │            │                         │
│        ▼            ▼            ▼            ▼                         │
│  ┌──────────────────────────────────────────────────┐                   │
│  │               Kubernetes Cluster                   │                   │
│  │            (Shared namespace: x-auth)              │                   │
│  │                                                    │                   │
│  │  Service mesh: mTLS between all pods               │                   │
│  └──────────────────────────────────────────────────┘                   │
│        │            │            │            │                         │
│        ▼            ▼            ▼            ▼                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐                  │
│  │ txn_db   │ │ auth_db  │ │ risk_db  │ │ authr_db │                  │
│  │ (PG 16)  │ │ (PG 16)  │ │ (PG 16)  │ │ (PG 16)  │                  │
│  │ Primary  │ │ Primary  │ │ Primary  │ │ Primary  │                  │
│  │ +Replica │ │ +Replica │ │ +Replica │ │ +Replica │                  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘                  │
│                                                                          │
│  ┌──────────────────────────────────────────────────┐                   │
│  │               Redis Cluster (shared)               │                   │
│  │        3 primaries + 3 replicas (HA)              │                   │
│  └──────────────────────────────────────────────────┘                   │
│                                                                          │
│  ┌──────────────────────────────────────────────────┐                   │
│  │            Cloud KMS                               │                   │
│  │   JWT signing keys, envelope encryption KEKs       │                   │
│  └──────────────────────────────────────────────────┘                   │
│                                                                          │
│  ┌──────────────────────────────────────────────────┐                   │
│  │            Object Storage (S3/GCS)                 │                   │
│  │   Audit log cold storage, backups                 │                   │
│  └──────────────────────────────────────────────────┘                   │
│                                                                          │
│  ── Enterprise tenants ─────────────────────────────────────────────    │
│  ┌──────────────────────────────────────────────────┐                   │
│  │         Dedicated Cluster (per enterprise tenant)  │                   │
│  │   Same topology, isolated namespace or cluster     │                   │
│  │   Separate PG instances + Redis                   │                   │
│  └──────────────────────────────────────────────────┘                   │
└──────────────────────────────────────────────────────────────────────────┘
```

### Environments

| Environment | Purpose | Scale |
|-------------|---------|-------|
| **dev** | Local development | 1 pod each, single PG, single Redis |
| **staging** | Pre-production validation | 2 pods each, HA PG, HA Redis |
| **production** | Live traffic | 2+ pods (HPA), HA PG primary+replica, Redis cluster |

### Health & Observability

Each service exposes:
- `GET /healthz` — liveness probe (process is running)
- `GET /readyz` — readiness probe (DB + Redis connections healthy)
- `GET /metrics` — Prometheus metrics (request rate, latency, error rate, risk score distribution)

Centralized logging via structured JSON → log aggregator (e.g., Datadog, Grafana Loki).
Distributed tracing via OpenTelemetry (trace IDs propagated via `X-Request-ID` header).
