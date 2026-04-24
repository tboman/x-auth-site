-- transaction-service — txn_db initial schema (phase 2).
--
-- Deviations from ARCHITECTURE.md §6.2 (all deliberate, all narrow):
--   • id / tenant_id / user_id / session_id / risk_eval_id are TEXT, not UUID.
--     The service mints prefixed ids ("txn_<uuid>") and treats tenant_id / user_id
--     as opaque strings coming from the caller. Architecture's UUID-only shape is a
--     future cleanup once prefixed-id policy lands — tracked as phase-2.1 work.
--   • decision CHECK set includes 'error' and 'step_up_satisfied' — both are emitted
--     by transaction-service today and must round-trip through storage intact.
--   • history (HistoryEntry list) lives in metadata->'history' so the column set
--     stays aligned with the architecture table while capturing the service's
--     per-transaction audit trail.
--   • No FK to tenants(id) in phase 2 — the tenants table lives on a separate admin
--     path and cross-db FKs aren't available. Phase 3 may co-locate.

CREATE TABLE IF NOT EXISTS transactions (
    id                    TEXT PRIMARY KEY,
    tenant_id             TEXT NOT NULL,
    user_id               TEXT NOT NULL,
    session_id            TEXT,
    risk_evaluation_id    TEXT,
    risk_tier             TEXT,
    risk_score            DOUBLE PRECISION,
    action                TEXT NOT NULL,
    resource              TEXT,
    resource_sensitivity  TEXT,
    decision              TEXT NOT NULL CHECK (decision IN (
        'pending', 'allow', 'deny',
        'step_up_required', 'step_up_satisfied',
        'error'
    )),
    step_up_used          BOOLEAN NOT NULL DEFAULT FALSE,
    step_up_method        TEXT,
    challenge_id          TEXT,
    policy_id             TEXT,
    reason                TEXT,
    metadata              JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at            TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_txn_tenant_user
    ON transactions (tenant_id, user_id);

CREATE INDEX IF NOT EXISTS idx_txn_tenant_session
    ON transactions (tenant_id, session_id);

-- List pagination key: tenant + (created_at DESC, id DESC). id as tiebreaker so
-- identical created_at values don't skip rows between pages.
CREATE INDEX IF NOT EXISTS idx_txn_tenant_created
    ON transactions (tenant_id, created_at DESC, id DESC);
