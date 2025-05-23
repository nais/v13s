-- +goose Up
CREATE MATERIALIZED VIEW mv_vuln_daily_by_workload AS
WITH snapshot_start_date AS (
    SELECT COALESCE(
        (
            SELECT MAX(updated_at)::DATE
            FROM vulnerability_summary
            WHERE updated_at < CURRENT_DATE
        ),
        CURRENT_DATE
    ) AS start_date
),
date_series AS (
    SELECT generate_series(
        (SELECT start_date FROM snapshot_start_date),
        CURRENT_DATE,
        interval '1 day'
    )::date AS snapshot_date
),
all_workloads AS (
    SELECT id AS workload_id, image_name, cluster, namespace, workload_type, name AS workload_name
    FROM workloads
),
workload_dates AS (
    SELECT w.workload_id, w.image_name, w.cluster, w.namespace, w.workload_type, w.workload_name, d.snapshot_date
    FROM all_workloads w
    CROSS JOIN date_series d
),
latest_summary_per_day AS (
    SELECT DISTINCT ON (wd.workload_id, wd.snapshot_date)
        wd.snapshot_date,
        wd.workload_id,
        wd.cluster,
        wd.namespace,
        wd.workload_type,
        wd.workload_name,
        vs.critical,
        vs.high,
        vs.medium,
        vs.low,
        vs.unassigned,
        vs.risk_score
    FROM workload_dates wd
    LEFT JOIN vulnerability_summary vs
        ON wd.image_name = vs.image_name
        AND vs.updated_at::date <= wd.snapshot_date
    WHERE vs IS NOT NULL
    ORDER BY wd.workload_id, wd.snapshot_date, vs.updated_at DESC
)
SELECT *
FROM latest_summary_per_day
ORDER BY snapshot_date;

CREATE INDEX ON mv_vuln_daily_by_workload (workload_name, snapshot_date);
CREATE INDEX ON mv_vuln_daily_by_workload (cluster, namespace, workload_type, snapshot_date);
