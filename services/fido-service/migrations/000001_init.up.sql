-- fido-service — fido_db initial schema.
--
-- The hot path is an in-memory AAGUID index rebuilt from the verified MDS blob
-- on every refresh. This table only persists the latest verified blob(s) so a
-- cold start can come up warm without re-fetching, and to keep an audit trail of
-- refreshes. One row per MDS blob serial number ("no"); the service loads the
-- most recently fetched row. raw holds the original compact-JWS bytes so a
-- reload re-verifies the signature rather than trusting derived state.

CREATE TABLE IF NOT EXISTS mds_snapshots (
    blob_number  INTEGER PRIMARY KEY,
    next_update  TEXT,
    entry_count  INTEGER NOT NULL DEFAULT 0,
    blob_sha256  TEXT NOT NULL,
    raw          BYTEA NOT NULL,
    fetched_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Load ordering key: most recently fetched snapshot wins.
CREATE INDEX IF NOT EXISTS idx_mds_snapshots_fetched
    ON mds_snapshots (fetched_at DESC);
