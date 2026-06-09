-- pool-service — pool_db initial schema (phase 2).
--
-- Notes (mirrors the transaction-service conventions, see docs/postgres.md):
--   • id / tenant_id / pool_id / subject_id / claimed_by_install_id are TEXT, not
--     UUID. The service mints UUID strings and treats tenant / install / subject ids
--     as opaque strings coming from the caller. UUID columns are phase-2.1 work.
--   • persona_ids is a JSONB array of opaque persona-id strings. Pools reference
--     personas owned by persona-service; cross-db FKs aren't available, and phase 1
--     deliberately doesn't validate them — the pool stores what it's given.
--   • identities.pool_id has ON DELETE CASCADE so DeletePool keeps its phase-1
--     contract (deleting a pool removes every identity attached to it).
--   • Tenant isolation on identities is enforced via the pool join — identities
--     carry no tenant_id column, matching the in-memory model.

CREATE TABLE IF NOT EXISTS pools (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    name         TEXT NOT NULL,
    size         INTEGER NOT NULL CHECK (size >= 1),
    persona_ids  JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ListPools order: tenant + (created_at ASC, id ASC) — id as tiebreaker so identical
-- created_at values keep a deterministic order, same as MemStorage.
CREATE INDEX IF NOT EXISTS idx_pools_tenant_created
    ON pools (tenant_id, created_at, id);

CREATE TABLE IF NOT EXISTS identities (
    id                     TEXT PRIMARY KEY,
    pool_id                TEXT NOT NULL REFERENCES pools (id) ON DELETE CASCADE,
    subject_id             TEXT NOT NULL,
    status                 TEXT NOT NULL CHECK (status IN (
        'available', 'claimed', 'revoked'
    )),
    claimed_by_install_id  TEXT,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ListIdentities order + the claim path's "oldest available first" pick.
CREATE INDEX IF NOT EXISTS idx_identities_pool_created
    ON identities (pool_id, created_at, id);

-- Claim hot path: find an available identity in a pool.
CREATE INDEX IF NOT EXISTS idx_identities_pool_status
    ON identities (pool_id, status);
