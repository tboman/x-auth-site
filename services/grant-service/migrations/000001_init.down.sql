DROP INDEX IF EXISTS idx_audit_tenant_grant;
DROP INDEX IF EXISTS idx_audit_tenant_install;
DROP INDEX IF EXISTS idx_audit_tenant_created;
DROP TABLE IF EXISTS audit_events;

DROP INDEX IF EXISTS idx_grants_tenant_install;
DROP INDEX IF EXISTS idx_grants_access_token_hash;
DROP TABLE IF EXISTS grants;
