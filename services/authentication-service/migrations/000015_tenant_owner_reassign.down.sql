-- Best-effort restore. Re-adding the owner_email unique constraint fails if
-- multiple workspaces now share an owner — deduplicate first if rolling back.
CREATE TABLE IF NOT EXISTS tenant_admins (
    tenant_id  TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    email      TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_tenant_admins_email ON tenant_admins (email);

ALTER TABLE tenants ADD CONSTRAINT uq_tenants_owner_email UNIQUE (owner_email);
