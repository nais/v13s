-- +goose Up

CREATE TABLE vuln_fix_summary
(
    workload_id   UUID REFERENCES workloads (id) ON DELETE CASCADE,
    severity      INT    NOT NULL,
    introduced_at DATE    NOT NULL,
    fixed_at      DATE,
    fix_duration  INT,
    is_fixed      BOOLEAN NOT NULL,
    snapshot_date DATE    NOT NULL,
    PRIMARY KEY (workload_id, severity, introduced_at)
);

CREATE OR REPLACE VIEW vuln_upsert_data AS
WITH vuln_events AS (
    SELECT workload_id, snapshot_date, 0 AS severity, critical AS count
    FROM vuln_daily_by_workload
    UNION ALL
    SELECT workload_id, snapshot_date, 1, high
    FROM vuln_daily_by_workload
    UNION ALL
    SELECT workload_id, snapshot_date, 2, medium
    FROM vuln_daily_by_workload
    UNION ALL
    SELECT workload_id, snapshot_date, 3, low
    FROM vuln_daily_by_workload
    UNION ALL
    SELECT workload_id, snapshot_date, 4, unassigned
    FROM vuln_daily_by_workload
),
vuln_events_with_lag AS (
    SELECT *,
        LAG(count) OVER (PARTITION BY workload_id, severity ORDER BY snapshot_date) AS prev_count
    FROM vuln_events
),
introduced AS (
    SELECT workload_id, severity, snapshot_date AS introduced_at
    FROM vuln_events_with_lag
    WHERE count > 0 AND (prev_count = 0 OR prev_count IS NULL)
),
fixed AS (
    SELECT workload_id, severity, snapshot_date AS fixed_at
    FROM vuln_events_with_lag
    WHERE count = 0 AND prev_count > 0
)
SELECT
    i.workload_id,
    i.severity,
    i.introduced_at,
    MIN(f.fixed_at) AS fixed_at,
    COALESCE(MIN(f.fixed_at), CURRENT_DATE) - i.introduced_at AS fix_duration,
    CASE WHEN MIN(f.fixed_at) IS NOT NULL THEN TRUE ELSE FALSE END AS is_fixed,
    CURRENT_DATE AS snapshot_date
FROM introduced i
         LEFT JOIN fixed f
                   ON f.workload_id = i.workload_id
                       AND f.severity = i.severity
                       AND f.fixed_at > i.introduced_at
GROUP BY i.workload_id, i.severity, i.introduced_at;