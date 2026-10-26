-- +goose Up
-- +goose NO TRANSACTION
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerabilities_severity_since_lookup ON vulnerabilities(image_name, package, cve_id, last_severity) INCLUDE (severity_since, created_at);

-- +goose Down
-- +goose NO TRANSACTION
DROP INDEX CONCURRENTLY IF EXISTS idx_vulnerabilities_severity_since_lookup;
