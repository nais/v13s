-- name: UpsertVulnerabilityLifetimes :exec
INSERT INTO vuln_fix_summary(
    workload_id,
    severity,
    introduced_at,
    fixed_at,
    fix_duration,
    is_fixed,
    snapshot_date)
SELECT
    v.workload_id,
    v.severity,
    v.introduced_at,
    v.fixed_at,
    v.fix_duration,
    v.is_fixed,
    v.snapshot_date
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
    introduced_at,
    snapshot_date)
    DO UPDATE SET
        fixed_at = EXCLUDED.fixed_at,
        fix_duration = EXCLUDED.fix_duration,
        is_fixed = EXCLUDED.is_fixed;

-- name: ListMeanTimeToFixTrendBySeverity :many
WITH filtered AS (
    SELECT
        v.severity,
        v.snapshot_date,
        v.fix_duration,
        v.fixed_at,
        v.introduced_at,
        v.workload_id
    FROM
        vuln_fix_summary v
        JOIN workloads w ON w.id = v.workload_id
    WHERE
        v.is_fixed = TRUE
        AND (sqlc.narg('cluster')::TEXT IS NULL
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
                WHEN 'snapshot' THEN
                    v.snapshot_date
                WHEN 'fixed' THEN
                    v.fixed_at
                END >= sqlc.narg('since')::TIMESTAMPTZ))
),
aggregated AS (
    SELECT
        f.severity,
        f.snapshot_date,
        AVG(f.fix_duration)::INT AS mean_time_to_fix_days,
        COUNT(*)::INT AS fixed_count,
        MIN(f.fixed_at)::DATE AS first_fixed_at,
        MAX(f.fixed_at)::DATE AS last_fixed_at,
        COUNT(DISTINCT f.workload_id)::INT AS registered_workloads
    FROM ( SELECT DISTINCT
            severity,
            workload_id,
            introduced_at,
            fix_duration,
            fixed_at,
            snapshot_date
        FROM
            filtered) f
    GROUP BY
        f.snapshot_date,
        f.severity
)
SELECT
    severity,
    snapshot_date,
    mean_time_to_fix_days,
    fixed_count,
    registered_workloads,
    first_fixed_at,
    last_fixed_at
FROM
    aggregated
ORDER BY
    snapshot_date,
    severity;

-- name: ListWorkloadSeverityFixStats :many
WITH filtered AS (
    SELECT DISTINCT
        v.severity,
        v.workload_id,
        v.introduced_at,
        v.fixed_at,
        v.snapshot_date,
        v.is_fixed
    FROM
        vuln_fix_summary v
        JOIN workloads w ON w.id = v.workload_id
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
            WHEN 'snapshot' THEN
                v.snapshot_date
            WHEN 'fixed' THEN
                v.fixed_at
            END >= sqlc.narg('since')::TIMESTAMPTZ)))
SELECT
    f.workload_id,
    w.name AS workload_name,
    w.namespace AS workload_namespace,
    f.severity,
    MIN(f.introduced_at)::DATE AS introduced_date,
    MAX(f.fixed_at)::DATE AS fixed_at,
    COUNT(*) FILTER (WHERE f.is_fixed)::INT AS fixed_count,
    COALESCE(AVG(f.fixed_at::DATE - f.introduced_at::DATE), 0)::INT AS mean_time_to_fix_days,
    MAX(f.snapshot_date)::TIMESTAMPTZ AS snapshot_date
FROM
    filtered f
    JOIN workloads w ON w.id = f.workload_id
GROUP BY
    f.workload_id,
    w.name,
    w.namespace,
    f.severity
ORDER BY
    introduced_date DESC;
