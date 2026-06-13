-- authentication-service — identity anchors.
--
-- Today an identity (a users row) is anchored by a single Google-verified
-- email: the social-login leg keys the user by (tenant_id, email). This table
-- generalises "how an identity can be identified" so the same user can also be
-- anchored by a phone number or one-or-more passkeys (WebAuthn credential ids),
-- alongside that email.
--
--   • anchor_type  — 'email' | 'phone' | 'passkey'. A user can have several
--     anchors (notably one passkey per device), which is why this is a table
--     and not a pair of nullable columns on users.
--   • anchor_value — the email address, the E.164 phone number, or the passkey
--     credential id.
--   • verified_at  — NULL until an ownership-proof flow confirms the anchor.
--     The validation flows (SMS OTP for phone, WebAuthn registration for
--     passkey) are NOT implemented yet — rows are expected to sit here with
--     verified_at NULL until that work lands.
--
-- email stays the canonical primary anchor on users.email (the social-login
-- upsert and the (tenant_id, email) unique constraint are unchanged); this
-- table is the home for the additional/alternative anchors. The identities
-- views render users.email as the primary anchor and join these rows on for the
-- phone/passkey anchors, so no email mirror is needed here.
--
-- No FK to users(id): phase 1 hard-deletes users (DELETE /v1/users/{id}) and
-- the schema deliberately avoids cross-table FKs (see 000001_init). Anchors are
-- swept alongside their user by the same GDPR/erasure work that owns that gap.

CREATE TABLE IF NOT EXISTS identity_anchors (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    tenant_id     TEXT NOT NULL,
    anchor_type   TEXT NOT NULL CHECK (anchor_type IN ('email', 'phone', 'passkey')),
    anchor_value  TEXT NOT NULL,
    verified_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- An anchor value of a given type can identify at most one identity within a
    -- tenant — the cross-store mirror of MemStorage's conflict check.
    CONSTRAINT uq_identity_anchor UNIQUE (tenant_id, anchor_type, anchor_value)
);

-- Per-user fan-out (the identities views group a tenant's anchors by user).
CREATE INDEX IF NOT EXISTS idx_anchors_user
    ON identity_anchors (user_id);

-- Per-tenant listing for the master-admin identities view.
CREATE INDEX IF NOT EXISTS idx_anchors_tenant_type
    ON identity_anchors (tenant_id, anchor_type);
