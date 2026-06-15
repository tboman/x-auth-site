-- authentication-service — tenant-defined transaction types.
--
-- A tenant names the transactions its app performs (e.g. "payment.high",
-- "login") and maps each to one of the eight protection levels by ACR
-- (urn:xauth:protect:{high,ultra}:{protected,enhanced,restricted,strict}). The
-- mapping is managed in the owner dashboard and read by POST /v1/advice, which
-- returns the mapped level for a caller's transaction_type.
--
-- (tenant_id, name) is the natural primary key; no FK (schema's no-FK stance).
-- acr is validated against the protection ladder in the app, not the DB.

CREATE TABLE IF NOT EXISTS transaction_types (
    tenant_id  TEXT NOT NULL,
    name       TEXT NOT NULL,
    acr        TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, name)
);
