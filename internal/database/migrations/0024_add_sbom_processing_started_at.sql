-- +goose Up
ALTER TABLE images
    ADD COLUMN IF NOT EXISTS sbom_processing_started_at TIMESTAMPTZ NULL;

-- +goose Down
ALTER TABLE images
    DROP COLUMN IF EXISTS sbom_processing_started_at
