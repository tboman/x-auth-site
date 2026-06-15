-- authentication-service — advice-call completion.
--
-- When an advice-tracked transaction finishes authentication at /authorize (its
-- transaction_id comes full circle), the originating advice_calls row is stamped
-- completed so the staff history shows pending vs completed and who/what level
-- satisfied it.

ALTER TABLE advice_calls
    ADD COLUMN IF NOT EXISTS completed_at      TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS completed_user_id TEXT,
    ADD COLUMN IF NOT EXISTS completed_acr     TEXT;
