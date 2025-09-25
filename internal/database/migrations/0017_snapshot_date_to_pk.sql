-- +goose Up

DROP VIEW IF EXISTS vuln_upsert_data;

ALTER TABLE vuln_fix_summary DROP CONSTRAINT IF EXISTS vuln_fix_summary_pkey;

ALTER TABLE vuln_fix_summary
    ADD PRIMARY KEY (workload_id, severity, introduced_at, snapshot_date);

CREATE OR REPLACE FUNCTION vuln_upsert_data_for_date(for_date DATE)
RETURNS TABLE (
    workload_id   UUID,
    severity      INT,
    introduced_at DATE,
    fixed_at      DATE,
    fix_duration  INT,
    is_fixed      BOOLEAN,
    snapshot_date DATE
) AS $fn$
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
    COALESCE(MIN(f.fixed_at), for_date) - i.introduced_at AS fix_duration,
    CASE WHEN MIN(f.fixed_at) IS NOT NULL AND MIN(f.fixed_at) <= for_date
             THEN TRUE ELSE FALSE END AS is_fixed,
    for_date AS snapshot_date
FROM introduced i
         LEFT JOIN fixed f
                   ON f.workload_id = i.workload_id
                       AND f.severity = i.severity
                       AND f.fixed_at > i.introduced_at
GROUP BY i.workload_id, i.severity, i.introduced_at
    $fn$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION backfill_vuln_fix_summary() RETURNS void AS $fn$ DECLARE d DATE; BEGIN FOR d IN (SELECT DISTINCT snapshot_date FROM vuln_daily_by_workload ORDER BY snapshot_date) LOOP INSERT INTO vuln_fix_summary (workload_id,severity,introduced_at,fixed_at,fix_duration,is_fixed,snapshot_date) SELECT workload_id,severity,introduced_at,fixed_at,fix_duration,is_fixed,snapshot_date FROM vuln_upsert_data_for_date(d) ON CONFLICT (workload_id,severity,introduced_at,snapshot_date) DO UPDATE SET fixed_at=EXCLUDED.fixed_at, fix_duration=EXCLUDED.fix_duration, is_fixed=EXCLUDED.is_fixed; END LOOP; END; $fn$ LANGUAGE plpgsql;

SELECT backfill_vuln_fix_summary();
