-- Revert phase-2 token hardening (token families + persisted client_id + PKCE).

DROP INDEX IF EXISTS idx_tokens_family;

ALTER TABLE tokens
    DROP COLUMN IF EXISTS family_id,
    DROP COLUMN IF EXISTS client_id;

ALTER TABLE auth_codes
    DROP COLUMN IF EXISTS code_challenge;
