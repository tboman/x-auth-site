-- Revert PKCE column on auth_codes. Codes are one-shot artifacts with a 300s
-- TTL, so dropping the column loses nothing durable.

ALTER TABLE auth_codes
    DROP COLUMN IF EXISTS code_challenge;
