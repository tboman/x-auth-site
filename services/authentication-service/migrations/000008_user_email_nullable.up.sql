-- authentication-service — make users.email optional.
--
-- Phone-first login (identity_anchors type='phone') can create an account from a
-- verified phone number alone, with no email until the owner links a social
-- login. Email therefore becomes nullable, and the (tenant_id, email) uniqueness
-- moves to a PARTIAL unique index so any number of phone-only users (email NULL)
-- can coexist while a present email is still unique within its tenant.
--
-- The constraint and the partial index share the name uq_users_tenant_email; the
-- service's ErrConflict contract (a 23505 on this index) is unchanged.

ALTER TABLE users ALTER COLUMN email DROP NOT NULL;

ALTER TABLE users DROP CONSTRAINT IF EXISTS uq_users_tenant_email;

CREATE UNIQUE INDEX IF NOT EXISTS uq_users_tenant_email
    ON users (tenant_id, email)
    WHERE email IS NOT NULL;
