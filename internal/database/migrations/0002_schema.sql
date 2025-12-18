-- +goose Up
ALTER TABLE suppressed_vulnerabilities
    ADD COLUMN suppressed_by TEXT NOT NULL DEFAULT '';
