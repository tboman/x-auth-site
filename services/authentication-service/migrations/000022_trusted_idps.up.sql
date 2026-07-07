-- authentication-service — Cross-App Access redemption (ID-JAG consumption).
--
-- trusted_idps: a tenant's registry of external identity providers whose ID-JAG
-- identity assertions this service accepts at the token endpoint via the RFC
-- 7523 jwt-bearer grant (the resource-authorization-server side of Cross-App
-- Access; issuance is migration 000021 + idjag.go). issuer must exactly match
-- the assertion's iss; jwks_uri is where the IdP publishes its RS256 signing
-- keys. scopes optionally caps what an assertion from this IdP may grant
-- (space-delimited; blank = no cap). (tenant_id, issuer) is unique so an IdP
-- can't be trusted twice. No FK (schema's no-FK stance).
--
-- idjag_used_jtis: single-use enforcement for redeemed assertions. The jti of
-- every accepted assertion is recorded until the assertion would have expired
-- anyway; a second redemption hits the primary key and is rejected as replay.

CREATE TABLE IF NOT EXISTS trusted_idps (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL,
    name       TEXT NOT NULL,
    issuer     TEXT NOT NULL,
    jwks_uri   TEXT NOT NULL,
    scopes     TEXT NOT NULL DEFAULT '',
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, issuer)
);

CREATE INDEX IF NOT EXISTS idx_trusted_idps_tenant ON trusted_idps (tenant_id);

CREATE TABLE IF NOT EXISTS idjag_used_jtis (
    jti        TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);
