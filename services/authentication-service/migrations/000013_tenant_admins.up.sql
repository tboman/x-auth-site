-- authentication-service — additional tenant administrators.
--
-- Beyond the tenant's creator (tenants.owner_email), staff can tag existing
-- users of a tenant as administrators. At owner login the Google email is
-- matched against owner_email AND these rows to build the set of tenants the
-- person may manage; if it's more than one, they pick which to manage.
--
-- Email is denormalized from the users row so the login lookup is a single
-- index scan. (tenant_id, user_id) is the primary key; no FK (no-FK convention).

CREATE TABLE IF NOT EXISTS tenant_admins (
    tenant_id  TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    email      TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);

-- Login matches administered tenants by Google email.
CREATE INDEX IF NOT EXISTS idx_tenant_admins_email
    ON tenant_admins (email);
