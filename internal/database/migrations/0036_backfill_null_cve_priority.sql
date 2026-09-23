-- +goose Up
-- cve.priority has been nullable since it was introduced (migration 0030)
-- without a backfill, and RecalculateVulnerabilitySummary now reads it
-- directly instead of recomputing tiers from raw severity/EPSS/KEV on every
-- call. A NULL priority used to be harmless (the old inline CASE WHEN never
-- looked at the column); now it would silently under-report as MONITOR.
-- This is a one-time historical backfill only, computed with the same
-- formula the CEL evaluator's default rules encode. It does not become
-- ongoing logic: the application reprioritizes every CVE it touches from
-- here on.
UPDATE
    cve
SET
    priority = CASE WHEN has_kev_entry = TRUE
        OR known_ransomware_use = TRUE
        OR COALESCE(epss_percentile, 0) >= 0.95
        OR COALESCE(epss_score, 0) >= 0.10 THEN
        2
    WHEN severity IN (0, 1)
        AND epss_percentile >= 0.90 THEN
        3
    ELSE
        4
    END
WHERE
    priority IS NULL;

-- +goose Down
-- No-op: this is a backfill of previously-NULL rows, not a reversible schema
-- or behavior change.
SELECT
    1;
