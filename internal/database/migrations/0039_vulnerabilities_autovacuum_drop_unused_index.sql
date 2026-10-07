-- +goose Up
-- +goose NO TRANSACTION
ALTER TABLE vulnerabilities SET (autovacuum_vacuum_scale_factor = 0.02, autovacuum_analyze_scale_factor = 0.01);

-- Created by hand in prod and unused.
DROP INDEX CONCURRENTLY IF EXISTS idx_vuln_cveid_cvss;

-- +goose Down
-- +goose NO TRANSACTION
ALTER TABLE vulnerabilities RESET (autovacuum_vacuum_scale_factor, autovacuum_analyze_scale_factor);
