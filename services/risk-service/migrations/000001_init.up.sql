-- risk-service — risk_db initial schema (phase 2).
--
-- Deviations from ARCHITECTURE.md §6.2 (all deliberate, all narrow):
--   • id / tenant_id / user_id / session_id are TEXT, not UUID. The service mints
--     prefixed ids ("rev_<uuid>", "pol_<uuid>") and treats tenant_id / user_id /
--     session_id as opaque strings coming from the caller. Architecture's UUID-only
--     shape is a future cleanup once prefixed-id policy lands — phase-2.1 work.
--   • The architecture doc splits `signals` and `scores` into two JSONB columns;
--     the service's domain model has a single SignalsBreakdown (per-scorer score +
--     flags together), so one `signals` JSONB column carries both.
--   • `flags` and `matched_policies` are JSONB arrays, not TEXT[] — keeps the
--     awkward list shapes in JSONB per the phase-2 convention and round-trips the
--     Go []string fields without pgx array mapping.
--   • `policy_decision` replaces the doc's `policy_id UUID NOT NULL` — phase-1
--     evaluations record the overall decision plus the matched policy ids, not a
--     single mandatory policy reference.
--   • risk_policies drops the doc's resource_map / weights / thresholds / active /
--     version columns — the phase-1 Policy model is {name, rules}; the richer shape
--     lands with the phase-2 scorer work.
--   • No FK to tenants(id) in phase 2 — the tenants table lives on a separate admin
--     path and cross-db FKs aren't available. Phase 3 may co-locate.

CREATE TABLE IF NOT EXISTS risk_evaluations (
    id                    TEXT PRIMARY KEY,
    tenant_id             TEXT NOT NULL,
    user_id               TEXT NOT NULL,
    session_id            TEXT,
    action                TEXT NOT NULL,
    resource              TEXT,
    resource_sensitivity  TEXT NOT NULL CHECK (resource_sensitivity IN (
        'low', 'medium', 'high'
    )),
    tier                  TEXT NOT NULL CHECK (tier IN ('low', 'medium', 'high')),
    score                 DOUBLE PRECISION NOT NULL,
    signals               JSONB NOT NULL DEFAULT '{}'::jsonb,
    flags                 JSONB NOT NULL DEFAULT '[]'::jsonb,
    policy_decision       TEXT NOT NULL CHECK (policy_decision IN ('allow', 'deny')),
    matched_policies      JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- UserHasPriorEvaluation probes (tenant_id, user_id) on every evaluation that
-- looks like a first high-value action — this index keeps that O(log n).
CREATE INDEX IF NOT EXISTS idx_risk_tenant_user
    ON risk_evaluations (tenant_id, user_id);

CREATE INDEX IF NOT EXISTS idx_risk_tenant_session
    ON risk_evaluations (tenant_id, session_id);

-- Future list pagination key: tenant + (created_at DESC, id DESC). id as
-- tiebreaker so identical created_at values don't skip rows between pages.
CREATE INDEX IF NOT EXISTS idx_risk_tenant_created
    ON risk_evaluations (tenant_id, created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS risk_policies (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    rules       JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ListPolicies returns every policy for a tenant ordered (created_at ASC, id ASC);
-- every evaluation also loads the full tenant policy set for the overlay.
CREATE INDEX IF NOT EXISTS idx_policy_tenant_created
    ON risk_policies (tenant_id, created_at, id);
