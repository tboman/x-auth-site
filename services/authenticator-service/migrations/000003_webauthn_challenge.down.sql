ALTER TABLE challenges
    DROP COLUMN IF EXISTS options_json,
    DROP COLUMN IF EXISTS session_data;
