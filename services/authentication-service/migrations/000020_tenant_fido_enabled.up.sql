-- authentication-service — per-tenant passkey (FIDO2) step-up toggle.
--
-- Passkeys are the strongest step-up factor, so they are ON by default
-- (DEFAULT true — every existing tenant keeps FIDO enabled). A workspace owner
-- can turn it off from their dashboard; a step-up that would have used a passkey
-- then falls back to the next method (SMS one-time code).

ALTER TABLE tenants
    ADD COLUMN fido_enabled BOOLEAN NOT NULL DEFAULT true;
