-- +goose Up
-- Rebuild mv_vuln_summary_daily_by_workload so its output column is kev_count
-- rather than act_now (renamed on the base tables in migration 0033).
--
-- Split out from 0033 on purpose. This rebuild scans and rewrites every row in
-- vuln_daily_by_workload, which takes minutes at production size. Doing it here
-- means it only takes ACCESS SHARE on the base table, so it never blocks reads
-- or writes on the hot vulnerability_summary table.
--
-- Running after 0034 also means the rebuilt view reflects the normalized
-- top_risk_tier values rather than being stale from the moment it is created.
DROP INDEX IF EXISTS idx_mv_vuln_summary_daily_unique;

DROP MATERIALIZED VIEW IF EXISTS mv_vuln_summary_daily_by_workload;

CREATE MATERIALIZED VIEW mv_vuln_summary_daily_by_workload AS
SELECT
    snapshot_date,
    CLUSTER,
    namespace,
    workload_type,
    workload_name,
    COUNT(DISTINCT workload_id)::INT AS workload_count,
    SUM(critical)::INT AS critical,
    SUM(high)::INT AS high,
    SUM(medium)::INT AS medium,
    SUM(low)::INT AS low,
    SUM(unassigned)::INT AS unassigned,
    COALESCE(SUM(kev_count), 0)::INT AS kev_count,
    COALESCE(SUM(high_risk), 0)::INT AS high_risk,
    COALESCE(SUM(elevated_risk), 0)::INT AS elevated_risk,
    COALESCE(SUM(monitor), 0)::INT AS monitor,
    COALESCE(SUM(ransomware_count), 0)::INT AS ransomware_count,
    COALESCE(SUM(high_epss_count), 0)::INT AS high_epss_count,
    MIN(top_risk_tier) AS top_risk_tier,
    SUM(critical + high + medium + low + unassigned)::INT AS total,
    SUM(risk_score)::INT AS risk_score
FROM
    vuln_daily_by_workload
GROUP BY
    snapshot_date,
    CLUSTER,
    namespace,
    workload_type,
    workload_name;

-- Required by REFRESH MATERIALIZED VIEW CONCURRENTLY.
CREATE UNIQUE INDEX idx_mv_vuln_summary_daily_unique ON mv_vuln_summary_daily_by_workload(snapshot_date, CLUSTER, namespace, workload_type, workload_name);

-- +goose Down
DROP INDEX IF EXISTS idx_mv_vuln_summary_daily_unique;

DROP MATERIALIZED VIEW IF EXISTS mv_vuln_summary_daily_by_workload;

CREATE MATERIALIZED VIEW mv_vuln_summary_daily_by_workload AS
SELECT
    snapshot_date,
    CLUSTER,
    namespace,
    workload_type,
    workload_name,
    COUNT(DISTINCT workload_id)::INT AS workload_count,
    SUM(critical)::INT AS critical,
    SUM(high)::INT AS high,
    SUM(medium)::INT AS medium,
    SUM(low)::INT AS low,
    SUM(unassigned)::INT AS unassigned,
    COALESCE(SUM(kev_count), 0)::INT AS act_now,
    COALESCE(SUM(high_risk), 0)::INT AS high_risk,
    COALESCE(SUM(elevated_risk), 0)::INT AS elevated_risk,
    COALESCE(SUM(monitor), 0)::INT AS monitor,
    COALESCE(SUM(ransomware_count), 0)::INT AS ransomware_count,
    COALESCE(SUM(high_epss_count), 0)::INT AS high_epss_count,
    MIN(top_risk_tier) AS top_risk_tier,
    SUM(critical + high + medium + low + unassigned)::INT AS total,
    SUM(risk_score)::INT AS risk_score
FROM
    vuln_daily_by_workload
GROUP BY
    snapshot_date,
    CLUSTER,
    namespace,
    workload_type,
    workload_name;

CREATE UNIQUE INDEX idx_mv_vuln_summary_daily_unique ON mv_vuln_summary_daily_by_workload(snapshot_date, CLUSTER, namespace, workload_type, workload_name);
