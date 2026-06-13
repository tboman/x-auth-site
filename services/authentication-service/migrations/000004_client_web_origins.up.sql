-- authentication-service — per-client CORS web origins.
--
--   • oidc_clients.web_origins — browser origins (scheme://host[:port]) allowed
--     to make cross-origin fetch calls to the public OIDC surface on this
--     client's behalf. The CORS handler unions these with the
--     CORS_ALLOWED_ORIGINS env baseline, so a client registered through the
--     admin console can call /token from its SPA without an env change.
--
-- Existing rows default to {} — they fall back to the env-configured global
-- origins exactly as before this migration.

ALTER TABLE oidc_clients
    ADD COLUMN web_origins TEXT[] NOT NULL DEFAULT '{}';
