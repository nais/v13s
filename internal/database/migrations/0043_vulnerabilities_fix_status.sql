-- +goose Up
CREATE TYPE fix_status AS ENUM(
    'fix_available',
    'no_fix_available',
    'installed_version_fixed',
    'unknown'
);

ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS fix_status fix_status NULL DEFAULT NULL;

-- +goose Down
ALTER TABLE vulnerabilities
    DROP COLUMN IF EXISTS fix_status;

DROP TYPE IF EXISTS fix_status;
