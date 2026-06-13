-- authentication-service — self-service tenant registry.
--
-- Phase 1 had no tenant registry: tenants were derived purely from the
-- users/sessions that referenced a tenant_id (see PGStorage.ListTenants). The
-- marketing site's "Get Started Free" funnel now provisions a tenant from a
-- human-supplied company name, so we need a first-class row to store that name,
-- the slug the tenant id is derived from, and the owning Google account.
--
--   • slug        — UNIQUE: a company name (slugified) can be claimed once.
--   • owner_email — UNIQUE: a Google account owns at most one self-service
--     tenant, so a returning owner is routed back to their workspace instead
--     of minting a duplicate.
--
-- id is "ten_" + slug, kept as TEXT to match the opaque tenant_id strings used
-- everywhere else (users.tenant_id, sessions.tenant_id, oidc_clients.tenant_id).
-- Registry-less tenants (ten_admin, ten_developer, ten_signup) deliberately
-- have no row here — they are staging/console tenants, not customer workspaces.

CREATE TABLE IF NOT EXISTS tenants (
    id           TEXT PRIMARY KEY,
    company_name TEXT NOT NULL,
    slug         TEXT NOT NULL,
    owner_email  TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_tenants_slug        UNIQUE (slug),
    CONSTRAINT uq_tenants_owner_email UNIQUE (owner_email)
);
