-- +goose Up
-- +goose NO TRANSACTION
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_vulnerabilities_cve_id_package ON vulnerabilities(cve_id, package);

-- +goose Down
-- +goose NO TRANSACTION
DROP INDEX CONCURRENTLY IF EXISTS idx_vulnerabilities_cve_id_package;
