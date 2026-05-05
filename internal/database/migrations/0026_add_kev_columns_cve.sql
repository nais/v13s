-- +goose Up
ALTER TABLE cve
    ADD COLUMN IF NOT EXISTS has_kev_entry BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS known_ransomware_use BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down
ALTER TABLE cve
    DROP COLUMN IF EXISTS has_kev_entry,
    DROP COLUMN IF EXISTS known_ransomware_use;
