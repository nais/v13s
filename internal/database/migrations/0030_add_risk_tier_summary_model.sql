-- +goose Up
CREATE TYPE risk_tier AS ENUM(
    'act_now',
    'high_risk',
    'elevated_risk',
    'monitor'
);

ALTER TABLE vulnerability_summary
    ADD COLUMN IF NOT EXISTS act_now INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS high_risk INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS elevated_risk INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS monitor INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS exploitable INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS kev_count INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS ransomware_count INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS high_epss_count INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS top_risk_tier risk_tier NOT NULL DEFAULT 'monitor';

ALTER TABLE vuln_daily_by_workload
    ADD COLUMN IF NOT EXISTS act_now INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS high_risk INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS elevated_risk INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS monitor INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS exploitable INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS kev_count INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS ransomware_count INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS high_epss_count INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS top_risk_tier risk_tier NOT NULL DEFAULT 'monitor';

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
    SUM(act_now)::INT AS act_now,
    SUM(high_risk)::INT AS high_risk,
    SUM(elevated_risk)::INT AS elevated_risk,
    SUM(monitor)::INT AS monitor,
    SUM(exploitable)::INT AS exploitable,
    SUM(kev_count)::INT AS kev_count,
    SUM(ransomware_count)::INT AS ransomware_count,
    SUM(high_epss_count)::INT AS high_epss_count,
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
ALTER TABLE vulnerability_summary
    DROP COLUMN IF EXISTS top_risk_tier,
    DROP COLUMN IF EXISTS high_epss_count,
    DROP COLUMN IF EXISTS ransomware_count,
    DROP COLUMN IF EXISTS kev_count,
    DROP COLUMN IF EXISTS exploitable,
    DROP COLUMN IF EXISTS monitor,
    DROP COLUMN IF EXISTS elevated_risk,
    DROP COLUMN IF EXISTS high_risk,
    DROP COLUMN IF EXISTS act_now;

DROP INDEX IF EXISTS idx_mv_vuln_summary_daily_unique;

DROP MATERIALIZED VIEW IF EXISTS mv_vuln_summary_daily_by_workload;

ALTER TABLE vuln_daily_by_workload
    DROP COLUMN IF EXISTS top_risk_tier,
    DROP COLUMN IF EXISTS high_epss_count,
    DROP COLUMN IF EXISTS ransomware_count,
    DROP COLUMN IF EXISTS kev_count,
    DROP COLUMN IF EXISTS exploitable,
    DROP COLUMN IF EXISTS monitor,
    DROP COLUMN IF EXISTS elevated_risk,
    DROP COLUMN IF EXISTS high_risk,
    DROP COLUMN IF EXISTS act_now;

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

DROP TYPE IF EXISTS risk_tier;
