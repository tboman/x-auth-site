-- Revert refresh-token rotation support. Token rows are short-lived artifacts
-- (purged once expires_at passes), so dropping the column loses nothing durable;
-- in-flight rotated markers degrade to "refresh token still usable", matching
-- pre-000003 behaviour.

DROP INDEX IF EXISTS idx_tokens_refresh;

ALTER TABLE tokens
    DROP COLUMN IF EXISTS rotated_at;
