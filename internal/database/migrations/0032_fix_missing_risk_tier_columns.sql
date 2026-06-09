-- +goose Up
-- Compensating migration: 0030 was never applied in environments where 0031
-- was already present, because isMigrated() only compared the highest version.
ALTER TABLE cve
    ADD COLUMN IF NOT EXISTS priority INT;

ALTER TABLE vulnerability_summary
    ADD COLUMN IF NOT EXISTS act_now INT,
    ADD COLUMN IF NOT EXISTS high_risk INT,
    ADD COLUMN IF NOT EXISTS elevated_risk INT,
    ADD COLUMN IF NOT EXISTS monitor INT,
    ADD COLUMN IF NOT EXISTS ransomware_count INT,
    ADD COLUMN IF NOT EXISTS high_epss_count INT,
    ADD COLUMN IF NOT EXISTS top_risk_tier INT;

ALTER TABLE vuln_daily_by_workload
    ADD COLUMN IF NOT EXISTS act_now INT,
    ADD COLUMN IF NOT EXISTS high_risk INT,
    ADD COLUMN IF NOT EXISTS elevated_risk INT,
    ADD COLUMN IF NOT EXISTS monitor INT,
    ADD COLUMN IF NOT EXISTS ransomware_count INT,
    ADD COLUMN IF NOT EXISTS high_epss_count INT,
    ADD COLUMN IF NOT EXISTS top_risk_tier INT;

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

-- +goose Down
-- Drop MV + index first to remove column dependencies before altering tables.
DROP INDEX IF EXISTS idx_mv_vuln_summary_daily_unique;
DROP MATERIALIZED VIEW IF EXISTS mv_vuln_summary_daily_by_workload;

ALTER TABLE vulnerability_summary
    DROP COLUMN IF EXISTS top_risk_tier,
    DROP COLUMN IF EXISTS high_epss_count,
    DROP COLUMN IF EXISTS ransomware_count,
    DROP COLUMN IF EXISTS monitor,
    DROP COLUMN IF EXISTS elevated_risk,
    DROP COLUMN IF EXISTS high_risk,
    DROP COLUMN IF EXISTS act_now;

ALTER TABLE vuln_daily_by_workload
    DROP COLUMN IF EXISTS top_risk_tier,
    DROP COLUMN IF EXISTS high_epss_count,
    DROP COLUMN IF EXISTS ransomware_count,
    DROP COLUMN IF EXISTS monitor,
    DROP COLUMN IF EXISTS elevated_risk,
    DROP COLUMN IF EXISTS high_risk,
    DROP COLUMN IF EXISTS act_now;

ALTER TABLE cve
    DROP COLUMN IF EXISTS priority;

-- Recreate the original MV without the risk-tier columns.
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
