-- authentication-service — device-signal event log.
--
-- A client-side device fingerprint (FingerprintJS visitorId) is captured on the
-- hosted login/authorize pages and submitted at each validation stage — social
-- login, SMS OTP, and passkey (FIDO2). Each capture is appended here as one
-- immutable observation, so a tenant can analyse the devices behind their
-- users' logins and step-ups (and a future risk evaluation can read the
-- history). This is an append-only log, not per-session state.
--
--   • stage       — which validation produced the signal: 'social' | 'otp' |
--                   'passkey'.
--   • fingerprint — the FingerprintJS visitorId (opaque, browser-derived).
--   • user_id / session_id are nullable: best-effort, populated whenever the
--     stage knows them (it normally does — the signal is recorded on success).
--
-- No FK (consistent with the rest of the schema's deliberate no-FK stance).

CREATE TABLE IF NOT EXISTS device_signals (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    user_id      TEXT,
    session_id   TEXT,
    stage        TEXT NOT NULL CHECK (stage IN ('social', 'otp', 'passkey')),
    fingerprint  TEXT NOT NULL,
    ip_address   TEXT,
    user_agent   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Newest-first per-tenant listing for the device-analysis view.
CREATE INDEX IF NOT EXISTS idx_device_signals_tenant_created
    ON device_signals (tenant_id, created_at DESC);

-- Group/look up a tenant's observations by device.
CREATE INDEX IF NOT EXISTS idx_device_signals_fingerprint
    ON device_signals (tenant_id, fingerprint);
