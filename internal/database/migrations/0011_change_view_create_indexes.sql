-- +goose Up

-- Drop old materialized view and its indexes (if they exist)
DROP INDEX IF EXISTS idx_mv_vuln_daily_by_workload_unique;
DROP INDEX IF EXISTS mv_vuln_daily_by_workload_workload_name_snapshot_date_idx;
DROP INDEX IF EXISTS mv_vuln_daily_by_workload_cluster_namespace_workload_type_s_idx;
DROP MATERIALIZED VIEW IF EXISTS mv_vuln_daily_by_workload;

-- Add optimized composite index
CREATE INDEX IF NOT EXISTS idx_vuln_summary_snapshot_cluster_namespace
    ON vuln_daily_by_workload (
    snapshot_date,
    cluster,
    namespace,
    workload_type
    );

CREATE MATERIALIZED VIEW mv_vuln_summary_daily_by_workload AS
SELECT
    snapshot_date,
    cluster,
    namespace,
    workload_type,
    workload_name,
    COUNT(DISTINCT workload_id)::INT AS workload_count,
    SUM(critical)::INT AS critical,
    SUM(high)::INT AS high,
    SUM(medium)::INT AS medium,
    SUM(low)::INT AS low,
    SUM(unassigned)::INT AS unassigned,
    SUM(critical + high + medium + low + unassigned)::INT AS total,
    SUM(risk_score)::INT AS risk_score
FROM vuln_daily_by_workload
GROUP BY snapshot_date, cluster, namespace, workload_type, workload_name;

CREATE UNIQUE INDEX idx_mv_vuln_summary_daily_unique
    ON mv_vuln_summary_daily_by_workload (snapshot_date, cluster, namespace, workload_type, workload_name);


