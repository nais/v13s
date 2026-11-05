-- +goose Up
ALTER TABLE cve
    ADD COLUMN reference_text TEXT NOT NULL DEFAULT '',
    ADD COLUMN cwes JSONB DEFAULT '[]';

-- +goose Down
ALTER TABLE cve
    DROP COLUMN reference_text,
    DROP COLUMN cwes;
