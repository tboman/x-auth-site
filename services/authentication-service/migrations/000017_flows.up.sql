-- authentication-service — configurable flows (the flow/stage/policy engine).
--
-- A tenant's auth journey for a designation (authorization-stepup, …) is stored
-- as one row: the ordered stages + their inline policies live in the `stages`
-- JSONB document. The enabled flow for a (tenant_id, designation) is the one
-- /authorize selects when FLOW_ENGINE is on; when none exists the service falls
-- back to a code-defined default flow that reproduces the legacy behavior.
--
-- Single-table on purpose (P3): the whole flow is one editable document, so no
-- joins and no FKs (matching the schema's no-FK stance). Stage/policy rows can
-- be normalized later without changing the FlowDefinition contract.

CREATE TABLE IF NOT EXISTS flows (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    designation TEXT NOT NULL,
    slug        TEXT NOT NULL,
    title       TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT false,
    stages      JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_flows_tenant ON flows (tenant_id);

-- At most one ENABLED flow per (tenant, designation): the app keeps this true,
-- and the partial unique index is the backstop.
CREATE UNIQUE INDEX IF NOT EXISTS uq_flows_enabled_designation
    ON flows (tenant_id, designation) WHERE enabled;
