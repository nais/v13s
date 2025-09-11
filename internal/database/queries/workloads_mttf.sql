-- name: RefreshWorkloadVulnerabilityLifetimes :exec
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
FROM vuln_upsert_data ON CONFLICT (workload_id, severity, introduced_at) DO
UPDATE
    SET
        fixed_at = EXCLUDED.fixed_at,
    fix_duration = EXCLUDED.fix_duration,
    is_fixed = EXCLUDED.is_fixed,
    snapshot_date = EXCLUDED.snapshot_date;

-- name: ListMeanTimeToFixPerSeverity :many
SELECT
    v.severity,
    v.snapshot_date,
    AVG(v.fix_duration) AS mean_time_to_fix_days,
    COUNT(*)::INT AS fixed_count
FROM vuln_fix_summary v
         JOIN workloads w ON w.id = v.workload_id
WHERE v.is_fixed = true
AND
    (sqlc.narg('cluster')::TEXT IS NULL OR w.cluster = sqlc.narg('cluster')::TEXT)
AND (sqlc.narg('namespace')::TEXT IS NULL OR w.namespace = sqlc.narg('namespace')::TEXT)
AND (sqlc.narg('workload_types')::TEXT[] IS NULL OR w.workload_type = ANY(sqlc.narg('workload_types')::TEXT[]))
AND (sqlc.narg('workload_name')::TEXT IS NULL OR w.name = sqlc.narg('workload_name')::TEXT)
GROUP BY v.snapshot_date, v.severity
ORDER BY v.snapshot_date, v.severity;

-- name: ListWorkloadSeveritiesWithMeanTimeToFix :many
SELECT
    v.workload_id,
    w.name AS workload_name,
    w.namespace,
    w.cluster,
    v.severity,
    MIN(v.introduced_at)::date AS first_introduced_date,
    MAX(v.fixed_at)::date AS last_fixed_date,
    COUNT(*) FILTER (WHERE v.is_fixed)::INT AS fixed_count,
    COALESCE(AVG((v.fixed_at::date - v.introduced_at::date)), 0)::INT AS mean_time_to_fix_days_for_severity
FROM vuln_fix_summary v
         JOIN workloads w ON w.id = v.workload_id
WHERE (
          (sqlc.narg('cluster')::TEXT IS NULL OR w.cluster = sqlc.narg('cluster')::TEXT)
              AND (sqlc.narg('namespace')::TEXT IS NULL OR w.namespace = sqlc.narg('namespace')::TEXT)
              AND (sqlc.narg('workload_types')::TEXT[] IS NULL OR w.workload_type = ANY(sqlc.narg('workload_types')::TEXT[]))
              AND (sqlc.narg('workload_name')::TEXT IS NULL OR w.name = sqlc.narg('workload_name')::TEXT)
          )
GROUP BY v.workload_id, w.name, w.namespace, w.cluster, v.severity
ORDER BY first_introduced_date DESC;
