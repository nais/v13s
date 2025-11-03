-- +goose Up
ALTER TABLE vuln_daily_by_workload
    ADD COLUMN IF NOT EXISTS has_summary BOOLEAN NOT NULL DEFAULT FALSE;
