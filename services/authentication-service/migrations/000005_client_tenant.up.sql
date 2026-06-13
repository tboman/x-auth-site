-- authentication-service — bind OIDC clients to a tenant.
--
--   • oidc_clients.tenant_id — when non-empty, /authorize treats this as the
--     authoritative tenant for the client and rejects a contradicting
--     tenant_id query parameter, so a client cannot drive flows in tenants it
--     was not registered for.
--
-- Existing rows default to '' (unbound) — /authorize falls back to the
-- request's tenant_id for them, exactly as before this migration.

ALTER TABLE oidc_clients
    ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '';
