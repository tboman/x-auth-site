-- risk-service — completed advice transactions.
--
-- authentication-service emits a CAEP assurance-level-change SET carrying a
-- transaction_id when an advice-tracked transaction finishes authentication.
-- risk-service records each here (keyed by the transaction_id) so the advice
-- lifecycle is queryable on the risk side and a risk evaluation can see the
-- protection level a recent transaction satisfied.

CREATE TABLE IF NOT EXISTS transaction_completions (
    transaction_id TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    user_id        TEXT,
    acr            TEXT,
    rank           INTEGER NOT NULL DEFAULT 0,
    completed_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_transaction_completions_tenant
    ON transaction_completions (tenant_id, completed_at DESC);
