-- authentication-service — phase-2 token hardening (ARCHITECTURE.md §10.1, §10.4).
--
--   • tokens.family_id — refresh-token family for family-based revocation.
--     The authorization-code grant mints one family per login; every refresh
--     rotation stays in the family. Replaying a rotated-out refresh token
--     revokes the entire family. Existing rows are backfilled with a
--     per-session legacy family ('fam_legacy_<session_id>'): phase 1 issued
--     exactly one token chain per session, so the session is the closest
--     equivalent of a family for pre-migration tokens.
--   • tokens.client_id — the OAuth client the token was issued to (from the
--     auth code). The refresh grant sources the rotated access token's `aud`
--     claim from here instead of trusting whatever the caller presents at
--     refresh time. Existing rows default to '' (aud omitted — the same
--     behaviour those tokens had before this migration).
--   • auth_codes.code_challenge — PKCE S256 challenge (§10.4). No method
--     column: S256 is the only method accepted, enforced at /authorize.
--     Pre-migration codes have no challenge and can no longer be exchanged
--     (codes live 5 minutes; PKCE is now mandatory on the code grant).

ALTER TABLE tokens
    ADD COLUMN IF NOT EXISTS family_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS client_id TEXT NOT NULL DEFAULT '';

-- Backfill: group legacy tokens into one family per session.
UPDATE tokens
   SET family_id = 'fam_legacy_' || session_id
 WHERE family_id = '';

-- Backs RevokeTokenFamily (UPDATE ... WHERE family_id = $1).
CREATE INDEX IF NOT EXISTS idx_tokens_family
    ON tokens (family_id);

ALTER TABLE auth_codes
    ADD COLUMN IF NOT EXISTS code_challenge TEXT;
