-- name: UpsertVulnerabilityLifetimes :exec
INSERT INTO vuln_fix_lifetime(
    workload_id,
    severity,
    introduced_at,
    fixed_at)
SELECT
    v.workload_id,
    v.severity,
    v.introduced_at,
    CASE WHEN v.is_fixed THEN
        v.fixed_at
    END
FROM
    vuln_upsert_data_for_date(CURRENT_DATE) v
WHERE
    v.workload_id IN (
        SELECT
            id
        FROM
            workloads)
ON CONFLICT (workload_id,
    severity,
    introduced_at)
    DO UPDATE SET
        fixed_at = EXCLUDED.fixed_at
    WHERE
        vuln_fix_lifetime.fixed_at IS DISTINCT FROM EXCLUDED.fixed_at;

-- name: ListMeanTimeToFixTrendBySeverity :many
WITH fixes AS (
    SELECT
        l.workload_id,
        l.severity,
        l.fixed_at,
        l.fixed_at - l.introduced_at AS fix_duration
    FROM
        vuln_fix_lifetime l
        JOIN workloads w ON w.id = l.workload_id
    WHERE
        l.fixed_at IS NOT NULL
        AND (sqlc.narg('cluster')::TEXT IS NULL
            OR w.cluster = sqlc.narg('cluster')::TEXT)
        AND (sqlc.narg('namespace')::TEXT IS NULL
            OR w.namespace = sqlc.narg('namespace')::TEXT)
        AND (sqlc.narg('workload_types')::TEXT[] IS NULL
            OR w.workload_type = ANY (sqlc.narg('workload_types')::TEXT[]))
        AND (sqlc.narg('workload_name')::TEXT IS NULL
            OR w.name = sqlc.narg('workload_name')::TEXT)
        AND (sqlc.narg('since')::TIMESTAMPTZ IS NULL
            OR COALESCE(sqlc.narg('since_type')::TEXT, 'snapshot') <> 'fixed'
            OR l.fixed_at >= sqlc.narg('since')::TIMESTAMPTZ)
),
fixes_per_day AS (
    SELECT
        severity,
        fixed_at,
        SUM(fix_duration) AS total_days,
        COUNT(*) AS fixed_count,
        MIN(fixed_at) AS first_fixed_at
    FROM
        fixes
    GROUP BY
        severity,
        fixed_at
),
first_fix_per_workload AS (
    SELECT
        severity,
        MIN(fixed_at) AS fixed_at
    FROM
        fixes
    GROUP BY
        severity,
        workload_id
),
new_workloads_per_day AS (
    SELECT
        severity,
        fixed_at,
        COUNT(*) AS workload_count
    FROM
        first_fix_per_workload
    GROUP BY
        severity,
        fixed_at
),
days AS (
    SELECT
        s.severity,
        d::DATE AS snapshot_date
    FROM (
        SELECT
            severity,
            MIN(fixed_at) AS first_fixed_at
        FROM
            fixes_per_day
        GROUP BY
            severity) s
        CROSS JOIN LATERAL generate_series(s.first_fixed_at, CURRENT_DATE, INTERVAL '1 day') d
),
running AS (
    SELECT
        d.severity,
        d.snapshot_date,
        SUM(COALESCE(f.total_days, 0)) OVER w AS total_days,
            SUM(COALESCE(f.fixed_count, 0)) OVER w AS fixed_count,
                SUM(COALESCE(n.workload_count, 0)) OVER w AS registered_workloads,
                    MIN(f.first_fixed_at) OVER w AS first_fixed_at,
                        MAX(f.fixed_at) OVER w AS last_fixed_at
                        FROM
                            days d
                            LEFT JOIN fixes_per_day f ON f.severity = d.severity
                                AND f.fixed_at = d.snapshot_date
                        LEFT JOIN new_workloads_per_day n ON n.severity = d.severity
                            AND n.fixed_at = d.snapshot_date
WINDOW w AS (PARTITION BY d.severity ORDER BY d.snapshot_date))
SELECT
    severity,
    snapshot_date,
(total_days::NUMERIC / fixed_count)::INT AS mean_time_to_fix_days,
    fixed_count::INT AS fixed_count,
    registered_workloads::INT AS registered_workloads,
    first_fixed_at::DATE AS first_fixed_at,
    last_fixed_at::DATE AS last_fixed_at
FROM
    running
WHERE
    sqlc.narg('since')::TIMESTAMPTZ IS NULL
    OR snapshot_date >= sqlc.narg('since')::TIMESTAMPTZ
ORDER BY
    snapshot_date,
    severity;

-- name: ListWorkloadSeverityFixStats :many
SELECT
    l.workload_id,
    w.name AS workload_name,
    w.namespace AS workload_namespace,
    l.severity,
    MIN(l.introduced_at)::DATE AS introduced_date,
    MAX(l.fixed_at)::DATE AS fixed_at,
    COUNT(l.fixed_at)::INT AS fixed_count,
    COALESCE(AVG(l.fixed_at - l.introduced_at), 0)::INT AS mean_time_to_fix_days,
    CURRENT_DATE::TIMESTAMPTZ AS snapshot_date
FROM
    vuln_fix_lifetime l
    JOIN workloads w ON w.id = l.workload_id
WHERE (sqlc.narg('cluster')::TEXT IS NULL
    OR w.cluster = sqlc.narg('cluster')::TEXT)
AND (sqlc.narg('namespace')::TEXT IS NULL
    OR w.namespace = sqlc.narg('namespace')::TEXT)
AND (sqlc.narg('workload_types')::TEXT[] IS NULL
    OR w.workload_type = ANY (sqlc.narg('workload_types')::TEXT[]))
AND (sqlc.narg('workload_name')::TEXT IS NULL
    OR w.name = sqlc.narg('workload_name')::TEXT)
AND (sqlc.narg('since')::TIMESTAMPTZ IS NULL
    OR (
        CASE COALESCE(sqlc.narg('since_type')::TEXT, 'snapshot')
        WHEN 'fixed' THEN
            l.fixed_at
        ELSE
            COALESCE(l.fixed_at, CURRENT_DATE)
        END >= sqlc.narg('since')::TIMESTAMPTZ))
GROUP BY
    l.workload_id,
    w.name,
    w.namespace,
    l.severity
ORDER BY
    introduced_date DESC;
