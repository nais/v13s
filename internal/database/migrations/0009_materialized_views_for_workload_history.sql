-- +goose Up

CREATE MATERIALIZED VIEW mv_vuln_daily_by_workload AS
WITH date_series AS (
    SELECT generate_series(
        (SELECT MIN(created_at)::date FROM vulnerability_summary),
        CURRENT_DATE,
        interval '1 day'
    )::date AS snapshot_date
),
-- Get all workloads
all_workloads AS (
    SELECT
        id AS workload_id,
        image_name,
        name AS workload_name,
        cluster,
        namespace,
        workload_type
    FROM workloads
),
-- Cross join workloads with each snapshot date
workload_dates AS (
    SELECT
        w.workload_id,
        w.image_name,
        w.workload_name,
        w.cluster,
        w.namespace,
        w.workload_type,
        d.snapshot_date
    FROM all_workloads w
    CROSS JOIN date_series d
),
-- Pick latest summary per workload per day
latest_summary_per_day AS (
    SELECT DISTINCT ON (wd.workload_id, wd.snapshot_date)
        wd.snapshot_date,
        wd.workload_id,
        wd.workload_name,
        wd.cluster,
        wd.namespace,
        wd.workload_type,
        vs.critical,
        vs.high,
        vs.medium,
        vs.low,
        vs.unassigned,
        vs.risk_score
    FROM workload_dates wd
    LEFT JOIN vulnerability_summary vs
        ON wd.image_name = vs.image_name
        AND vs.created_at::date <= wd.snapshot_date
    WHERE vs IS NOT NULL
    ORDER BY wd.workload_id, wd.snapshot_date, vs.created_at DESC
)
SELECT
    snapshot_date,
    workload_id,
    workload_name,
    cluster,
    namespace,
    workload_type,
    COALESCE(critical, 0)::INT4 AS critical,
    COALESCE(high, 0)::INT4 AS high,
    COALESCE(medium, 0)::INT4 AS medium,
    COALESCE(low, 0)::INT4 AS low,
    COALESCE(unassigned, 0)::INT4 AS unassigned,
    (COALESCE(critical, 0) + COALESCE(high, 0) + COALESCE(medium, 0) + COALESCE(low, 0) + COALESCE(unassigned, 0))::INT4 AS total,
    COALESCE(risk_score, 0)::INT4 AS risk_score
FROM latest_summary_per_day;

CREATE UNIQUE INDEX idx_mv_vuln_daily_by_workload_unique
ON mv_vuln_daily_by_workload (snapshot_date, workload_id);
CREATE INDEX ON mv_vuln_daily_by_workload (workload_name, snapshot_date);
CREATE INDEX ON mv_vuln_daily_by_workload (cluster, namespace, workload_type, snapshot_date);
