-- +goose Up
ALTER TABLE cve_kev_source
    ADD COLUMN IF NOT EXISTS short_description TEXT,
    ADD COLUMN IF NOT EXISTS reference_urls TEXT[] NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE cve_kev_source
    DROP COLUMN IF EXISTS short_description,
    DROP COLUMN IF EXISTS reference_urls;
