-- +goose Up
-- act_now was always COUNT(*) FILTER (WHERE has_kev_entry = TRUE); rename it to
-- what it is. v13s does not compute an "act now" verdict (that needs
-- internet-facing context only nais/api has); it exposes the raw KEV count.
--
-- This migration only renames columns, which is a catalog-only change and
-- commits in milliseconds. mv_vuln_summary_daily_by_workload is rebuilt in
-- migration 0035 instead: its stored query references base columns by attribute
-- number, so it keeps working across the rename (its own output column is still
-- named act_now until 0035 replaces it). Keeping the rebuild out of this
-- transaction avoids holding ACCESS EXCLUSIVE on vulnerability_summary for the
-- minutes the rebuild takes.
ALTER TABLE vulnerability_summary RENAME COLUMN act_now TO kev_count;

ALTER TABLE vuln_daily_by_workload RENAME COLUMN act_now TO kev_count;

-- +goose Down
ALTER TABLE vulnerability_summary RENAME COLUMN kev_count TO act_now;

ALTER TABLE vuln_daily_by_workload RENAME COLUMN kev_count TO act_now;
