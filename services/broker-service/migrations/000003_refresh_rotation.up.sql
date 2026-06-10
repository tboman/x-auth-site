-- broker-service — refresh-token rotation support (ARCHITECTURE.md §10.1).
--
-- The refresh grant rotates the refresh token on every use: the old token
-- record gets rotated_at stamped (NULL = still the live refresh token for its
-- access token). A rotated record's access token stays valid until expires_at,
-- but presenting its refresh token again is treated as theft and revokes the
-- whole install (the broker's token family == the install).
--
-- Broker refresh tokens carry no independent expiry: they live as long as
-- their install is active and they are unrotated, so rotated rows are swept by
-- the existing expires_at purge predicate once their access token expires.

ALTER TABLE tokens
    ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMPTZ;

-- The refresh grant looks tokens up by refresh_token — a hot path now.
CREATE INDEX IF NOT EXISTS idx_tokens_refresh
    ON tokens (refresh_token);
