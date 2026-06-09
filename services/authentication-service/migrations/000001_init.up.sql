-- authentication-service — auth_db initial schema (phase 2).
--
-- Deviations from ARCHITECTURE.md §6.2 (all deliberate, all narrow):
--   • id / tenant_id / user_id / session_id are TEXT, not UUID. The service mints
--     prefixed ids ("usr_<uuid>", "ses_<uuid>") and treats tenant ids as opaque
--     strings from the caller. UUID columns are a phase-2.1 cleanup that also
--     requires the ID-minting side to change (see docs/postgres.md).
--   • No FK from sessions.user_id to users(id): phase 1 hard-deletes users
--     (DELETE /v1/users/{id}) while their sessions may still exist, and the
--     in-memory store never enforced referential integrity. Revisit alongside the
--     phase-2 soft-delete / GDPR pseudonymisation work.
--   • ARCHITECTURE's auth_flows table is realised as a leaner auth_codes table
--     matching the service's AuthCode model. Codes are one-shot: ConsumeAuthCode
--     deletes the row, so no state machine column is needed. PKCE columns
--     (code_challenge / method) arrive with phase-2 PKCE enforcement.
--   • ARCHITECTURE's refresh_tokens table is generalised to a tokens table that
--     holds BOTH access and refresh records — phase-1 access tokens are opaque
--     UUIDs that must be resolvable server-side (/userinfo, /revoke). When access
--     tokens become signed JWTs this shrinks back to refresh-token-only.
--   • Short-lived artefacts (auth codes, tokens) live in Postgres, not Redis —
--     phase 2 has no Redis yet (ARCHITECTURE §6.3 is a later phase).
--   • oidc_clients is trimmed to the fields the service models today (client_id,
--     secret hash, redirect URIs). grant_types / scopes / TTL overrides land with
--     dynamic client registration.

CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    email       TEXT NOT NULL,
    name        TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Backs the ErrConflict contract on CreateUser / UpdateUser.
    CONSTRAINT uq_users_tenant_email UNIQUE (tenant_id, email)
);

-- ListUsers ordering: CreatedAt asc, id tie-break (mirrors MemStorage).
CREATE INDEX IF NOT EXISTS idx_users_tenant_created
    ON users (tenant_id, created_at, id);

CREATE TABLE IF NOT EXISTS sessions (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL,
    user_id            TEXT NOT NULL,
    risk_level         TEXT NOT NULL DEFAULT 'low' CHECK (risk_level IN ('low', 'medium', 'high')),
    step_up_completed  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    invalidated_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sessions_tenant_user
    ON sessions (tenant_id, user_id);

-- Opaque token records, keyed by the SHA-256 hex digest of the plaintext.
-- Plaintext tokens are never persisted.
CREATE TABLE IF NOT EXISTS tokens (
    token_hash  TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    token_type  TEXT NOT NULL CHECK (token_type IN ('access', 'refresh')),
    scope       TEXT,
    issued_at   TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ
);

-- Backs the phase-2 TODO to cascade-revoke tokens on session invalidate.
CREATE INDEX IF NOT EXISTS idx_tokens_session
    ON tokens (session_id);

-- One-shot authorization codes: written by /authorize, deleted on /token
-- exchange (ConsumeAuthCode is a DELETE ... RETURNING). Expiry is enforced in
-- the handler (AuthCodeTTLSeconds against created_at), not in the schema.
CREATE TABLE IF NOT EXISTS auth_codes (
    code          TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL,
    tenant_id     TEXT NOT NULL,
    user_id       TEXT NOT NULL,
    session_id    TEXT,
    redirect_uri  TEXT NOT NULL,
    scope         TEXT,
    state         TEXT,
    nonce         TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oidc_clients (
    client_id           TEXT PRIMARY KEY,
    client_secret_hash  TEXT NOT NULL DEFAULT '',
    redirect_uris       TEXT[] NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed the default dev client (MemStorage seeds the same row in its
-- constructor — see storage.go seedDefaultClient). An empty secret hash marks
-- it as a public client. TODO(phase-2): confidential client with a random,
-- hashed secret per environment, then drop this seed.
INSERT INTO oidc_clients (client_id, client_secret_hash, redirect_uris)
VALUES ('cli_default', '', '{http://localhost:3000/callback}')
ON CONFLICT (client_id) DO NOTHING;
