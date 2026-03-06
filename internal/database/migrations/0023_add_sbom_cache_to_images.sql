-- +goose Up
-- Store the compressed SBOM payload alongside the image so it can be re-uploaded
-- to the vulnerability source when the registry no longer has the manifest
-- (e.g. after a GCR/GHCR cleanup removes old tags).
ALTER TABLE images
    ADD COLUMN IF NOT EXISTS sbom BYTEA DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS sbom_updated_at TIMESTAMP WITH TIME ZONE DEFAULT NULL;

-- +goose Down
ALTER TABLE images
    DROP COLUMN IF EXISTS sbom,
    DROP COLUMN IF EXISTS sbom_updated_at;
