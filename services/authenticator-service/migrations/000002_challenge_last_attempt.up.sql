-- §10.5 layer 3 — exponential backoff on failed verifications.
--
-- The backoff window is derived from persisted state (attempts +
-- last_attempt_at) rather than per-replica memory, so a premature retry is
-- rejected consistently across replicas and restarts. The column is NULL
-- until the challenge's first failed verification, matching the Go model's
-- *time.Time zero value.
ALTER TABLE challenges
    ADD COLUMN IF NOT EXISTS last_attempt_at TIMESTAMPTZ;
