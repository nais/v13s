-- +goose Up
-- Covering index for stale summary fallback selection:
-- DISTINCT ON (image_name) ORDER BY updated_at DESC
CREATE INDEX IF NOT EXISTS idx_vuln_summary_image_name_updated
    ON vulnerability_summary(image_name, updated_at DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_vuln_summary_image_name_updated;

