-- id-service — id_db initial schema.
--
-- One row per remote identity-verification request. Pending rows carry the
-- OpenID4VP binding material (nonce, client_id, response_uri) and a one-time URL
-- token for the consumer "Verify with Wallet" page; once a wallet response is
-- verified the disclosed claims + assurance land in the result JSON. Expired
-- pending rows are swept by the service.

CREATE TABLE IF NOT EXISTS verifications (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    token        TEXT NOT NULL UNIQUE,
    status       TEXT NOT NULL,
    purpose      TEXT NOT NULL DEFAULT '',
    doctype      TEXT NOT NULL,
    claims       JSONB,
    channel      TEXT NOT NULL DEFAULT '',
    nonce        TEXT NOT NULL,
    client_id    TEXT NOT NULL DEFAULT '',
    response_uri TEXT NOT NULL DEFAULT '',
    verify_url   TEXT NOT NULL DEFAULT '',
    result       JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL
);

-- Agent listings are scoped per tenant; the sweeper scans pending + expiry.
CREATE INDEX IF NOT EXISTS idx_verifications_tenant ON verifications (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_verifications_expiry ON verifications (status, expires_at);
