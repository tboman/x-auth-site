-- broker-service — PKCE enforcement (ARCHITECTURE.md §10.4; the MCP authorization
-- spec mandates PKCE for MCP clients).
--
-- /authorize now requires an S256 code_challenge and persists it with the
-- one-shot auth code; /token recomputes SHA-256(code_verifier) base64url-no-pad
-- and rejects the grant on mismatch. The column is nullable only so the ALTER is
-- safe against in-flight pre-PKCE rows (auth codes live <= 300s); the handler
-- layer treats a NULL/empty challenge as invalid_grant — there is no
-- PKCE-optional path.

ALTER TABLE auth_codes
    ADD COLUMN IF NOT EXISTS code_challenge TEXT;
