-- +goose Up

ALTER TABLE workload_vulnerabilities
    ADD COLUMN downgraded_at TIMESTAMP WITH TIME ZONE;