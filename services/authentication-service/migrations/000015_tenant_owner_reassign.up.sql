-- authentication-service — single reassignable workspace owner.
--
-- Replaces the staff-tagged tenant_admins model with a single workspace owner
-- per tenant that staff can reassign. A Google account may now own MORE THAN
-- one workspace (staff can assign it as owner of several), so the
-- owner_email uniqueness is dropped and login lets a multi-workspace owner pick
-- which to manage.

ALTER TABLE tenants DROP CONSTRAINT IF EXISTS uq_tenants_owner_email;

DROP TABLE IF EXISTS tenant_admins;
