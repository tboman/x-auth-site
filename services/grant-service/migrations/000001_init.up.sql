-- grant-service — grant_db initial schema (phase 2).
--
-- Conventions follow transaction-service (the phase-2 reference; see docs/postgres.md):
--   • id / tenant_id / install_id / identity_id / persona_id are TEXT, not UUID.
--     The services mint ids and treat tenant / install / identity / persona ids as
--     opaque strings coming from the caller. UUID columns are phase-2.1 cleanup.
--   • Grant `status` is NOT a column — it is derived at read time from
--     revoked_at / expires_at (revoked wins over expired), same as MemGrantStore.
--   • Token values are never stored; only SHA-256 hex digests land here.
--     access_token_hash carries a UNIQUE index — the phase-1 O(n) introspection scan
--     becomes an index lookup.
--   • audit_events is append-only: the service exposes no UPDATE or DELETE path and
--     pgstorage.go issues neither statement against this table. GDPR erasure is
--     handled by pseudonymization (out-of-band tooling), not row deletion. When a
--     dedicated service role lands, it should receive INSERT + SELECT only.
--   • No FK from audit_events.grant_id to grants(id) — sister services emit audit
--     events for entities this service doesn't own (installs, personas, …), so the
--     references are intentionally soft.

CREATE TABLE IF NOT EXISTS grants (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    install_id          TEXT NOT NULL,
    identity_id         TEXT NOT NULL,
    persona_id          TEXT NOT NULL,
    access_token_hash   TEXT NOT NULL,
    refresh_token_hash  TEXT,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ
);

-- Introspection key (RFC 7662 lookups are cross-tenant by design; tenancy is
-- enforced after resolution, in the handler).
CREATE UNIQUE INDEX IF NOT EXISTS idx_grants_access_token_hash
    ON grants (access_token_hash);

-- Cascade-revoke key: /v1/installs/{install_id}/revoke-grants lists by
-- (tenant_id, install_id), ordered by issued_at.
CREATE INDEX IF NOT EXISTS idx_grants_tenant_install
    ON grants (tenant_id, install_id, issued_at);

CREATE TABLE IF NOT EXISTS audit_events (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    type        TEXT NOT NULL,
    actor       TEXT NOT NULL,
    install_id  TEXT,
    grant_id    TEXT,
    payload     JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Query key: tenant + (created_at DESC, id DESC). id as tiebreaker so identical
-- created_at values keep a stable order.
CREATE INDEX IF NOT EXISTS idx_audit_tenant_created
    ON audit_events (tenant_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_audit_tenant_install
    ON audit_events (tenant_id, install_id);

CREATE INDEX IF NOT EXISTS idx_audit_tenant_grant
    ON audit_events (tenant_id, grant_id);
