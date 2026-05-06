-- +goose Up
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS fix_version TEXT NULL DEFAULT NULL;

-- +goose Down
ALTER TABLE vulnerabilities
    DROP COLUMN IF EXISTS fix_version;
