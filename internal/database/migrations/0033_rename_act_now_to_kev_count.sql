-- +goose Up
-- act_now was always COUNT(*) FILTER (WHERE has_kev_entry = TRUE); rename it to
-- what it is. v13s does not compute an "act now" verdict (that needs
-- internet-facing context only nais/api has); it exposes the raw KEV count.
DROP INDEX IF EXISTS idx_mv_vuln_summary_daily_unique;

DROP MATERIALIZED VIEW IF EXISTS mv_vuln_summary_daily_by_workload;

ALTER TABLE vulnerability_summary RENAME COLUMN act_now TO kev_count;

ALTER TABLE vuln_daily_by_workload RENAME COLUMN act_now TO kev_count;

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

CREATE UNIQUE INDEX idx_mv_vuln_summary_daily_unique ON mv_vuln_summary_daily_by_workload(snapshot_date, CLUSTER, namespace, workload_type, workload_name);

-- +goose Down
DROP INDEX IF EXISTS idx_mv_vuln_summary_daily_unique;

DROP MATERIALIZED VIEW IF EXISTS mv_vuln_summary_daily_by_workload;

ALTER TABLE vulnerability_summary RENAME COLUMN kev_count TO act_now;

ALTER TABLE vuln_daily_by_workload RENAME COLUMN kev_count TO act_now;

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
    COALESCE(SUM(act_now), 0)::INT AS act_now,
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
