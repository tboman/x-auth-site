# Requirements Document: X-Auth for Agents

X-Auth for Agents is the MCP-native identity broker for AI agents — product 2 in the X-Auth platform. This document is the source of truth for the product's scope, domain model, service boundaries, and phase-1 implementation contracts.

This document **does not** describe the marketing site or X-Auth for Apps (product 1 — see `ARCHITECTURE.md`).

---

## 1. Product Overview

Customers define **personas** (pre-authorized claim bundles) and provision **identity pools** (concrete agent identities eligible to assume one or more personas). When the owner of an AI chat installs `mcp.x-auth.com` as a tool, they select a persona. A standard OIDC handshake binds one available identity from a pool to that install for its lifetime. Every bound connection is auditable and individually revocable.

**Key invariants:**
- Persona selection happens at **install time** by the human admin, not at runtime by the agent.
- The MCP connection *is* the identity assignment — there is no runtime "checkout" call.
- Zero-config install requires the runtime to support **DCR** (RFC 7591 Dynamic Client Registration) or **CIMD** (Client Identifier Metadata Document). Legacy runtimes fall back to manual client provisioning.

## 2. Domain Model

### Persona
Pre-authorized bundle of claims. Created and owned by the tenant's security team.
- `id` (UUID)
- `tenant_id` (UUID)
- `name` (string)
- `scopes` ([]string) — OAuth scopes this persona authorizes
- `claims` (map[string]any) — additional claims (roles, attributes, entitlements)
- `token_ttl` (duration) — max lifetime of tokens issued under this persona
- `created_at` / `updated_at`

### Pool
Container of concrete agent identities eligible to assume one or more personas.
- `id`
- `tenant_id`
- `name`
- `size` (int) — max identities in pool
- `persona_ids` ([]UUID) — personas that identities in this pool may be bound to
- `created_at`

### Identity
A concrete identity that lives in a pool. One identity binds to at most one active install at a time.
- `id`
- `pool_id`
- `subject_id` (string) — stable identifier used in the OAuth `sub` claim
- `status` (enum: `available` | `claimed` | `revoked`)
- `claimed_by_install_id` (UUID, nullable)
- `created_at`

### Install
One MCP connection installed in a runtime, bound to one persona + one identity via OIDC.
- `id`
- `tenant_id`
- `runtime` (string: `"claude" | "chatgpt" | "cursor" | "custom"`)
- `persona_id`
- `identity_id` (filled after OIDC binding)
- `client_id` (OAuth client id — from DCR / CIMD / manual provisioning)
- `status` (enum: `pending` | `active` | `revoked`)
- `created_at`

### Grant
An active OAuth grant issued to an install.
- `id`
- `install_id`
- `identity_id`
- `persona_id`
- `access_token_hash`
- `refresh_token_hash`
- `issued_at` / `expires_at` / `revoked_at`
- `status` (enum: `active` | `expired` | `revoked`)

### AuditEvent
Append-only log of all lifecycle events.
- `id`
- `tenant_id`
- `type` (e.g., `install_created`, `persona_bound`, `grant_issued`, `grant_revoked`, `identity_released`)
- `actor` (`system` | `user:<id>` | `admin:<id>`)
- `payload` (JSON — full context)
- `created_at`

## 3. Architecture: 4 Cloud Run Services

Monorepo layout, shared Go module (`github.com/xentranet/x-auth`), shared `pkg/` for logging, HTTP, config, tenant helpers. Each service containerized with the same Dockerfile pattern and deployed as a Cloud Run service.

| Service | Port (local) | Visibility | Owns |
|---|---|---|---|
| **persona-service** | 8180 | Internal | Persona CRUD |
| **pool-service** | 8181 | Internal | Pool + Identity CRUD, identity claim/release |
| **broker-service** | 8182 | Public | MCP endpoint, OIDC authorize/token, DCR, CIMD, Install lifecycle |
| **grant-service** | 8183 | Internal | Grant issuance, token introspection, audit log |

### Service interaction (happy-path install flow)
```
 AI chat owner                                      Admin console
       │                                                  │
       │ install mcp.x-auth.com                           │ CRUD personas/pools
       ▼                                                  ▼
 ┌────────────────┐                              ┌──────────────────┐
 │ broker-service │ ◄──── (fetch persona) ─────► │ persona-service  │
 │   (public)     │                              └──────────────────┘
 │   port 8182    │                              ┌──────────────────┐
 │                │ ◄──── (claim identity) ────► │   pool-service   │
 │                │                              └──────────────────┘
 │                │                              ┌──────────────────┐
 │                │ ──── (record grant) ───────► │  grant-service   │
 └────────────────┘                              └──────────────────┘
```

Cloud Run `broker-service` is the only internet-facing service; the other three are internal (Cloud Run ingress: internal or internal-and-cloud-load-balancing).

## 4. Service Contracts (Phase 1)

All services speak REST/JSON. All requests carry `X-Tenant-Id` header (simple tenant isolation for phase 1; proper auth in phase 2).

### persona-service
| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/personas` | Create `{name, scopes, claims, token_ttl}` |
| GET | `/v1/personas` | List (tenant-scoped) |
| GET | `/v1/personas/{id}` | Read |
| PATCH | `/v1/personas/{id}` | Update |
| DELETE | `/v1/personas/{id}` | Delete |

### pool-service
| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/pools` | Create `{name, size, persona_ids}` |
| GET | `/v1/pools` | List |
| GET | `/v1/pools/{id}` | Read |
| DELETE | `/v1/pools/{id}` | Delete |
| POST | `/v1/pools/{id}/identities` | Add identity `{subject_id}` |
| GET | `/v1/pools/{id}/identities` | List pool identities |
| POST | `/v1/pools/{id}/claim` | Claim a free identity `{persona_id, install_id}` → returns identity |
| POST | `/v1/identities/{id}/release` | Release (mark available) |
| POST | `/v1/identities/{id}/revoke` | Revoke permanently |

### broker-service
OAuth / OIDC:
| Method | Path | Purpose |
|---|---|---|
| GET | `/.well-known/oauth-authorization-server` | RFC 8414 |
| GET | `/.well-known/openid-configuration` | OIDC discovery |
| POST | `/register` | DCR (RFC 7591) |
| GET | `/metadata.json` | CIMD |
| GET | `/authorize` | OIDC authorize — starts persona-binding consent |
| POST | `/token` | OIDC token |
| POST | `/revoke` | Token revocation |
| GET | `/userinfo` | OIDC userinfo |

MCP (stubs acceptable for phase 1):
| Method | Path | Purpose |
|---|---|---|
| GET | `/mcp/sse` | MCP SSE stream |
| POST | `/mcp/rpc` | MCP JSON-RPC |

Install lifecycle:
| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/installs` | Called internally after OIDC binding completes |
| GET | `/v1/installs/{id}` | Read |
| POST | `/v1/installs/{id}/revoke` | Revoke install (cascades to grants) |

### grant-service
| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/grants` | Create grant `{install_id, identity_id, persona_id, access_token_hash, refresh_token_hash, ttl}` |
| GET | `/v1/grants/{id}` | Read |
| POST | `/v1/grants/{id}/revoke` | Revoke |
| POST | `/v1/introspect` | RFC 7662 token introspection |
| POST | `/v1/audit` | Append audit event (called by any service) |
| GET | `/v1/audit` | Query audit log (filters: tenant, install, grant, type, time range) |

## 5. Shared Infrastructure

Monorepo structure:
```
/
├── go.mod                          — module github.com/xentranet/x-auth
├── Makefile                        — build, test, docker, run targets
├── pkg/
│   ├── httpx/                      — HTTP server + middleware
│   ├── logx/                       — slog wrapper
│   ├── config/                     — env var loading
│   └── tenantx/                    — tenant-id extraction
└── services/
    ├── persona-service/
    │   ├── cmd/main.go
    │   ├── internal/
    │   ├── Dockerfile
    │   └── README.md
    ├── pool-service/         (same shape)
    ├── broker-service/       (same shape)
    └── grant-service/        (same shape)
```

Each service's `Dockerfile` uses the same multi-stage pattern (golang:1.22-alpine build → distroless static run). Each service listens on `$PORT` (Cloud Run convention), defaulting to the port listed in §3 for local dev.

## 6. Phase 1 Scope (current implementation)

Per service, phase 1 delivers:
- Runnable Go HTTP server using shared `pkg/`
- Handlers for all §4 endpoints with JSON request/response
- Domain models (structs + JSON tags)
- **In-memory storage** behind a `Storage` interface (Postgres impl is phase 2)
- Basic input validation and tenant isolation via `X-Tenant-Id` header
- Structured request logging (via `pkg/httpx`)
- Dockerfile that produces a Cloud Run-deployable image
- `README.md` per service with: purpose, endpoints, local run command, example cURL

### Explicitly deferred to phase 2
- Postgres persistence (swap in-memory for real storage)
- Full OAuth/OIDC handshake cryptography (phase 1 stubs the flow — broker returns canned tokens)
- Real MCP protocol handling (phase 1 returns stub SSE / RPC responses)
- Service-to-service authentication (phase 1 is network-trusted)
- Rate limiting, IP allowlists
- End-to-end tests (phase 1 ships unit tests for handlers only)
- Tenant schema isolation in Postgres
- CAEP/SSF event emission

## 7. Deployment

- GCP project: **TBD** (to be set by ops)
- Each service deploys as a separate Cloud Run service (`gcloud run deploy persona-service --source services/persona-service …`)
- Broker's Cloud Run ingress: `all` (public); others: `internal` (VPC egress from broker)
- Environment per service:
  - `PORT` — injected by Cloud Run (default 8080 in the container)
  - `SERVICE_NAME` — used by logger
  - `PERSONA_SERVICE_URL` / `POOL_SERVICE_URL` / `GRANT_SERVICE_URL` — injected into broker and grant
  - `DATABASE_URL` — phase 2

## 8. Non-Goals for Product 2

- Human authentication — that's product 1 (X-Auth for Apps, `ARCHITECTURE.md`)
- General-purpose API gateway — X-Auth does not proxy downstream API calls; it issues tokens and audits, downstream APIs enforce scopes
- Custom SDKs for every runtime — phase 1 targets MCP + OAuth/OIDC standards only
