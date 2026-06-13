-- Reverses 000008_user_email_nullable.up.sql.
--
-- NOTE: restoring NOT NULL fails if any phone-only (email IS NULL) users exist.
-- Such rows must be backfilled or removed before rolling back.

DROP INDEX IF EXISTS uq_users_tenant_email;

ALTER TABLE users ADD CONSTRAINT uq_users_tenant_email UNIQUE (tenant_id, email);

ALTER TABLE users ALTER COLUMN email SET NOT NULL;
