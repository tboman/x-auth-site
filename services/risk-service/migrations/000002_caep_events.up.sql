-- risk-service — CAEP receiver state.
--
-- authentication-service emits CAEP Security Event Tokens (assurance-level-change,
-- session-revoked, device-compliance-change) when device-fingerprint analysis or
-- a step-up warrants it. risk-service is the receiver: it verifies each SET
-- against authn's JWKS and lands it here.
--
--   • caep_events     — append-only audit of every received event (raw payload).
--   • assurance_state — the current derived posture per (tenant, user): NIST AAL
--     level + compliance flag, updated from assurance-level-change /
--     device-compliance-change events, read by the risk evaluation.

CREATE TABLE IF NOT EXISTS caep_events (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL,
    subject_user_id    TEXT,
    subject_session_id TEXT,
    event_type         TEXT NOT NULL,
    payload            JSONB NOT NULL,
    received_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_caep_events_tenant
    ON caep_events (tenant_id, received_at DESC);

CREATE TABLE IF NOT EXISTS assurance_state (
    tenant_id  TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    level      TEXT NOT NULL,
    compliant  BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, user_id)
);
