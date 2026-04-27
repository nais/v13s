-- +goose Up
ALTER TABLE images
    ADD COLUMN sbom_processing_started_at TIMESTAMPTZ NULL;

-- +goose Down
ALTER TABLE images
    DROP COLUMN sbom_processing_started_at;
