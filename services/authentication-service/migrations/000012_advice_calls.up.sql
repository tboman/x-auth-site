-- authentication-service — append-only log of /v1/advice calls.
--
-- Every advice request (and the protection level it returned) is recorded here
-- so staff can review the history in the admin console, filtered by tenant and
-- user. The subject ids (user/session/device) are whatever the caller supplied;
-- they are not validated here.

CREATE TABLE IF NOT EXISTS advice_calls (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL,
    client_id        TEXT,
    user_id          TEXT,
    session_id       TEXT,
    device_id        TEXT,
    transaction_type TEXT NOT NULL,
    acr              TEXT NOT NULL,
    rank             INTEGER NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Newest-first per-tenant listing (the default staff filter).
CREATE INDEX IF NOT EXISTS idx_advice_calls_tenant_created
    ON advice_calls (tenant_id, created_at DESC);

-- User-id search across tenants.
CREATE INDEX IF NOT EXISTS idx_advice_calls_user
    ON advice_calls (user_id, created_at DESC);
