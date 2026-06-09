-- broker-service — broker_db initial schema (phase 2).
--
-- Mirrors the phase-1 MemStorage contract (services/broker-service/internal/storage.go)
-- and follows docs/postgres.md. Deviations / deliberate choices:
--   • All minted / prefixed ids (install id, client id, persona id, identity id,
--     tenant id, opaque tokens) are TEXT, not UUID — the services treat them as
--     opaque strings. UUID columns are a phase-2.1 cleanup (see docs/postgres.md).
--   • DCR client_metadata is a free-form RFC 7591 object, parked in a JSONB column.
--     Nullable so a nil map round-trips as nil (MemStorage parity).
--   • auth_codes and tokens are short-lived artifacts. No Redis in this phase, so
--     they get plain tables; TTL is enforced at the handler layer (AuthCodeTTLSeconds,
--     TokenRecord.ExpiresAt). Expired-row sweeping is a phase-2.1 cron concern.
--   • No FK from installs to personas/identities — those live in persona-service /
--     pool-service databases (one DB per service, cross-db FKs unavailable).

CREATE TABLE IF NOT EXISTS installs (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    runtime     TEXT NOT NULL CHECK (runtime IN (
        'claude', 'chatgpt', 'cursor', 'custom'
    )),
    persona_id  TEXT NOT NULL,
    identity_id TEXT,
    client_id   TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN (
        'pending', 'active', 'revoked'
    )),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ListInstalls scans per tenant ordered by (created_at, id); the same index serves
-- a future keyset-paginated DESC listing.
CREATE INDEX IF NOT EXISTS idx_installs_tenant_created
    ON installs (tenant_id, created_at, id);

-- RFC 7591 Dynamic Client Registration records. Cross-tenant by nature (anyone can
-- register in phase 1); the metadata object is stored verbatim.
CREATE TABLE IF NOT EXISTS dcr_clients (
    client_id       TEXT PRIMARY KEY,
    client_secret   TEXT,
    client_metadata JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One-shot authorization codes minted by /authorize and consumed (deleted) by /token.
-- The code carries the tenant it was issued for, so lookups are key-only.
CREATE TABLE IF NOT EXISTS auth_codes (
    code         TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    runtime      TEXT NOT NULL,
    persona_id   TEXT NOT NULL,
    pool_id      TEXT,
    client_id    TEXT NOT NULL,
    redirect_uri TEXT,
    state        TEXT,
    scope        TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Broker-local view of issued tokens (phase-1 opaque UUIDs, persisted as-is — JWT
-- signing is a later phase). /userinfo reads by access_token; /revoke deletes.
CREATE TABLE IF NOT EXISTS tokens (
    access_token  TEXT PRIMARY KEY,
    refresh_token TEXT,
    install_id    TEXT NOT NULL,
    persona_id    TEXT,
    identity_id   TEXT,
    subject       TEXT,
    scope         TEXT,
    tenant_id     TEXT NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL
);

-- Revoking an install will want every token bound to it (phase-2.1 cascade cleanup).
CREATE INDEX IF NOT EXISTS idx_tokens_install
    ON tokens (install_id);
