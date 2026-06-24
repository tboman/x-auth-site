-- authentication-service — per-tenant authorized MCP servers (Cross-App Access).
--
-- A tenant admin maintains the static allow-list of MCP servers their apps may
-- request authorization to on a user's behalf via Cross-App Access (ID-JAG /
-- RFC 8693 token exchange). Each row names a server and its canonical resource
-- URI (the audience an issued ID-JAG is scoped to). Issuance (a later increment)
-- will only mint an ID-JAG for a resource that appears here and is enabled.
--
-- id is the handle used by the dashboard (delete/toggle); (tenant_id,
-- resource_uri) is unique so a server can't be authorized twice. No FK
-- (schema's no-FK stance). scopes is space-delimited (OAuth scope syntax).

CREATE TABLE IF NOT EXISTS mcp_servers (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    name         TEXT NOT NULL,
    resource_uri TEXT NOT NULL,
    scopes       TEXT NOT NULL DEFAULT '',
    enabled      BOOLEAN NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, resource_uri)
);

CREATE INDEX IF NOT EXISTS idx_mcp_servers_tenant ON mcp_servers (tenant_id);
