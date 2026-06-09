-- authenticator-service — authr_db initial schema (phase 2).
--
-- Deviations from ARCHITECTURE.md §6.2 (all deliberate, all narrow):
--   • id / tenant_id / user_id / authenticator_id are TEXT, not UUID. The service
--     mints prefixed ids ("authr_<uuid>", "ch_<uuid>") and treats tenant_id /
--     user_id as opaque strings coming from the caller. UUID columns are a
--     phase-2.1 cleanup that also requires the ID-minting side to change.
--   • The method column is named `method` (not `type`) and its CHECK set matches
--     the service's wire constants — `magic_link` instead of the doc's `email`,
--     plus `totp`. The wire form is what must round-trip through storage intact.
--   • authenticators carry `status` ('active' | 'disabled' soft-delete) and
--     `updated_at` instead of the doc's `verified` / `last_used_at` — phase 1 has
--     no enrollment-verification ceremony, and soft-delete is the service's
--     existing Delete contract.
--   • No `credential` column or credential-id UNIQUE constraint yet — phase-1
--     adapters are stubs; vendor credentials park in the `metadata` JSONB until
--     real adapters land. metadata is nullable so a nil map round-trips as nil.
--   • challenges use the service's status set ('pending' | 'completed' | 'failed'
--     | 'expired'; the doc says 'verified') and `prompt` / `completed_at` columns
--     in place of `challenge_data` / `code_hash` / `verified_at` — again matching
--     the persisted Go model. max_attempts stays a code constant (phase 1).
--   • No FK from challenges.authenticator_id to authenticators(id) — the
--     in-memory store has no such coupling and storage tests seed challenges
--     standalone; preserving swap-without-drift wins. Revisit in phase 2.1.
--   • Challenges are short-lived (5 min TTL) but still live in a table: there is
--     no Redis in the stack yet, and the rows double as an audit trail of step-up
--     attempts. A partial index keeps the future expiry sweeper cheap.

CREATE TABLE IF NOT EXISTS authenticators (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    method      TEXT NOT NULL CHECK (method IN (
        'fido2', 'totp', 'push', 'sms', 'magic_link'
    )),
    metadata    JSONB,
    status      TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_authr_tenant_user
    ON authenticators (tenant_id, user_id);

-- Challenge method selection only ever scans active authenticators.
CREATE INDEX IF NOT EXISTS idx_authr_tenant_user_active
    ON authenticators (tenant_id, user_id)
    WHERE status = 'active';

-- List ordering key: tenant + (created_at DESC, id DESC). id as tiebreaker so
-- identical created_at values keep a deterministic order.
CREATE INDEX IF NOT EXISTS idx_authr_tenant_created
    ON authenticators (tenant_id, created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS challenges (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    user_id           TEXT NOT NULL,
    method            TEXT NOT NULL CHECK (method IN (
        'fido2', 'totp', 'push', 'sms', 'magic_link'
    )),
    authenticator_id  TEXT NOT NULL,
    prompt            TEXT,
    status            TEXT NOT NULL CHECK (status IN (
        'pending', 'completed', 'failed', 'expired'
    )),
    attempts          INTEGER NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ NOT NULL,
    completed_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_challenge_tenant_user
    ON challenges (tenant_id, user_id);

-- For the eventual expiry sweeper (phase 1 flips pending→expired lazily on verify).
CREATE INDEX IF NOT EXISTS idx_challenge_pending_expiry
    ON challenges (expires_at)
    WHERE status = 'pending';
