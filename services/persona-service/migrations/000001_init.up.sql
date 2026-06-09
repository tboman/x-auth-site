-- persona-service — persona_db initial schema (phase 2).
--
-- Deviations / notes (mirroring transaction-service's conventions):
--   • id / tenant_id are TEXT, not UUID. The service mints ids via uuid.NewString()
--     and treats tenant_id as an opaque string coming from the X-Tenant-Id header.
--     Moving to UUID columns is tracked as phase-2.1 work alongside the other services.
--   • scopes ([]string) and claims (free-form map) are JSONB so the Go shapes
--     round-trip through storage without a join table.
--   • token_ttl_seconds bounds match internal/models.go (DefaultTokenTTLSeconds /
--     MaxTokenTTLSeconds); the handler validates first, the CHECK is a backstop.
--   • No FK to tenants(id) in phase 2 — the tenants table lives on a separate admin
--     path and cross-db FKs aren't available. Phase 3 may co-locate.

CREATE TABLE IF NOT EXISTS personas (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL,
    name               TEXT NOT NULL,
    scopes             JSONB NOT NULL DEFAULT '[]'::jsonb,
    claims             JSONB,
    token_ttl_seconds  INTEGER NOT NULL DEFAULT 900 CHECK (
        token_ttl_seconds > 0 AND token_ttl_seconds <= 86400
    ),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- List ordering key: tenant + (created_at, id). The Storage.List contract returns the
-- whole tenant set ordered ascending (id as tiebreaker so identical created_at values
-- stay deterministic) — same ordering MemStorage.List produces.
CREATE INDEX IF NOT EXISTS idx_personas_tenant_created
    ON personas (tenant_id, created_at, id);
