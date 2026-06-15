-- authentication-service — per-tenant phone (SMS OTP) login opt-in.
--
-- The hosted /login chooser previously showed "Continue with phone" to every
-- tenant unconditionally, even though SMS delivery is still a stub (fixed code
-- 123456, no real text). Gate it behind a per-tenant flag, default OFF, so a
-- workspace owner must deliberately enable it.

ALTER TABLE tenants
    ADD COLUMN phone_login_enabled BOOLEAN NOT NULL DEFAULT false;
