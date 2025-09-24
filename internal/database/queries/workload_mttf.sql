-- name: UpsertVulnerabilityLifetimes :exec
INSERT INTO vuln_fix_summary (
    workload_id,
    severity,
    introduced_at,
    fixed_at,
    fix_duration,
    is_fixed,
    snapshot_date
)
SELECT
    workload_id,
    severity,
    introduced_at,
    fixed_at,
    fix_duration,
    is_fixed,
    snapshot_date
FROM vuln_upsert_data_for_date(CURRENT_DATE) ON CONFLICT (workload_id, severity, introduced_at, snapshot_date) DO
UPDATE
    SET
        fixed_at = EXCLUDED.fixed_at,
    fix_duration = EXCLUDED.fix_duration,
    is_fixed = EXCLUDED.is_fixed;

-- name: ListMeanTimeToFixTrendBySeverity :many
WITH mttr AS (
    SELECT
        v.severity,
        v.snapshot_date      AS snapshot_time,
        AVG(v.fix_duration)::INT AS mean_time_to_fix_days,
        COUNT(*)::INT        AS fixed_count,
        MIN(v.fixed_at)::date     AS first_fixed_at,
        MAX(v.fixed_at)::date      AS last_fixed_at
    FROM vuln_fix_summary v
             JOIN workloads w ON w.id = v.workload_id
    WHERE v.is_fixed = true
      AND (sqlc.narg('cluster')::TEXT IS NULL OR w.cluster = sqlc.narg('cluster')::TEXT)
      AND (sqlc.narg('namespace')::TEXT IS NULL OR w.namespace = sqlc.narg('namespace')::TEXT)
      AND (sqlc.narg('workload_types')::TEXT[] IS NULL OR w.workload_type = ANY(sqlc.narg('workload_types')::TEXT[]))
      AND (sqlc.narg('workload_name')::TEXT IS NULL OR w.name = sqlc.narg('workload_name')::TEXT)
      AND (
        sqlc.narg('since')::timestamptz IS NULL
          OR (
              sqlc.narg('since_type')::TEXT = 'snapshot' AND v.snapshot_date >= sqlc.narg('since')::timestamptz
          )
          OR (
              sqlc.narg('since_type')::TEXT = 'fixed' AND v.fixed_at >= sqlc.narg('since')::timestamptz
          )
        )
    GROUP BY v.snapshot_date, v.severity
)
SELECT
    severity,
    snapshot_time,
    mean_time_to_fix_days,
    fixed_count,
    first_fixed_at,
    last_fixed_at
FROM mttr
ORDER BY snapshot_time, severity;

-- name: ListWorkloadSeverityFixStats :many
SELECT
    v.workload_id,
    w.name       AS workload_name,
    w.namespace  AS workload_namespace,
    w.cluster    AS workload_cluster,
    v.severity,
    MIN(v.introduced_at)::date AS introduced_date,
    MAX(v.fixed_at)::date AS fixed_at,
    COUNT(*) FILTER (WHERE v.is_fixed)::INT AS fixed_count,
    COALESCE(AVG((v.fixed_at::date - v.introduced_at::date)), 0)::INT mean_time_to_fix_days,
    MAX(v.snapshot_date)::timestamptz AS snapshot_time
FROM vuln_fix_summary v
         JOIN workloads w ON w.id = v.workload_id
WHERE (
          (sqlc.narg('cluster')::TEXT IS NULL OR w.cluster = sqlc.narg('cluster')::TEXT)
              AND (sqlc.narg('namespace')::TEXT IS NULL OR w.namespace = sqlc.narg('namespace')::TEXT)
              AND (sqlc.narg('workload_types')::TEXT[] IS NULL OR w.workload_type = ANY(sqlc.narg('workload_types')::TEXT[]))
              AND (sqlc.narg('workload_name')::TEXT IS NULL OR w.name = sqlc.narg('workload_name')::TEXT)
          )
GROUP BY v.workload_id, w.name, w.namespace, w.cluster, v.severity
ORDER BY introduced_date DESC;
