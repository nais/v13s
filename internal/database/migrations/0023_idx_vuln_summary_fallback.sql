-- +goose Up
-- Covering index for the latest_summaries CTE (DISTINCT ON image_name ORDER BY updated_at DESC).
-- The vs_current LEFT JOIN on (image_name, image_tag) is handled by the existing image_name_tag constraint.
CREATE INDEX IF NOT EXISTS idx_vuln_summary_image_name_updated
    ON vulnerability_summary(image_name, updated_at DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_vuln_summary_image_name_updated;

