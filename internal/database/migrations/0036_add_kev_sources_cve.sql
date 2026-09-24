-- +goose Up
ALTER TABLE cve
    ADD COLUMN IF NOT EXISTS kev_sources TEXT[] NOT NULL DEFAULT '{}';

UPDATE cve SET kev_sources = ARRAY['cisa'] WHERE has_kev_entry = TRUE;

-- +goose Down
ALTER TABLE cve
    DROP COLUMN IF EXISTS kev_sources;
