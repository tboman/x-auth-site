DROP INDEX IF EXISTS idx_challenge_pending_expiry;
DROP INDEX IF EXISTS idx_challenge_tenant_user;
DROP TABLE IF EXISTS challenges;

DROP INDEX IF EXISTS idx_authr_tenant_created;
DROP INDEX IF EXISTS idx_authr_tenant_user_active;
DROP INDEX IF EXISTS idx_authr_tenant_user;
DROP TABLE IF EXISTS authenticators;
