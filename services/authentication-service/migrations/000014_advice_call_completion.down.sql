ALTER TABLE advice_calls
    DROP COLUMN IF EXISTS completed_acr,
    DROP COLUMN IF EXISTS completed_user_id,
    DROP COLUMN IF EXISTS completed_at;
