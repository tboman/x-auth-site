DROP TABLE IF EXISTS oidc_clients;
DROP TABLE IF EXISTS auth_codes;
DROP INDEX IF EXISTS idx_tokens_session;
DROP TABLE IF EXISTS tokens;
DROP INDEX IF EXISTS idx_sessions_tenant_user;
DROP TABLE IF EXISTS sessions;
DROP INDEX IF EXISTS idx_users_tenant_created;
DROP TABLE IF EXISTS users;
