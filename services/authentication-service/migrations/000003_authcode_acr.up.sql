-- authentication-service — SMS-OTP authentication context (ARCHITECTURE.md §4.4 step-up).
--
--   • auth_codes.acr — the authentication context class satisfied at
--     /authorize (e.g. 'urn:xauth:otp:sms' after the OTP interlude). Carried
--     into the ID token's `acr` claim at the token mint.
--   • auth_codes.amr — RFC 8176 authentication-method references used (e.g.
--     {otp,sms}). Carried into the ID token's `amr` claim; a non-empty value
--     also marks the minted session step_up_completed.
--
-- Existing rows default to '' / {} — the same "no second factor" semantics
-- those codes had before this migration.

ALTER TABLE auth_codes
    ADD COLUMN acr TEXT   NOT NULL DEFAULT '',
    ADD COLUMN amr TEXT[] NOT NULL DEFAULT '{}';
