-- +goose Up
ALTER TABLE images
    ADD COLUMN sbom_pending BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down
ALTER TABLE images
    DROP COLUMN sbom_pending;
