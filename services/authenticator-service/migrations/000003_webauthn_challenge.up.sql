-- authenticator-service — WebAuthn ceremony state on the challenge row.
--
-- A WebAuthn assertion needs two things the generic challenge lifecycle didn't
-- carry: the PublicKeyCredentialRequestOptions returned to the browser
-- (options_json) and the server-only go-webauthn SessionData (the random
-- challenge + allowed credential ids) the verify step matches against
-- (session_data). Both are NULL for non-WebAuthn methods, so existing
-- sms/totp/push/magic_link challenges are unaffected.

ALTER TABLE challenges
    ADD COLUMN IF NOT EXISTS options_json JSONB,
    ADD COLUMN IF NOT EXISTS session_data BYTEA;
