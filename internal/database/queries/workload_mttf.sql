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
    v.workload_id,
    v.severity,
    v.introduced_at,
    v.fixed_at,
    v.fix_duration,
    v.is_fixed,
    v.snapshot_date
FROM vuln_upsert_data_for_date(CURRENT_DATE) v
WHERE v.workload_id IN (SELECT id FROM workloads)
    ON CONFLICT (workload_id, severity, introduced_at, snapshot_date)
DO UPDATE
           SET
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
              CASE COALESCE(sqlc.narg('since_type')::TEXT, 'snapshot')
                  WHEN 'snapshot' THEN v.snapshot_date
                  WHEN 'fixed' THEN v.fixed_at
              END >= sqlc.narg('since')::timestamptz
          )
        )
),
     aggregated AS (
         SELECT
             severity,
             snapshot_date,
             AVG(fix_duration)::INT AS mean_time_to_fix_days,
             COUNT(*)::INT AS fixed_count,
             MIN(fixed_at)::date AS first_fixed_at,
             MAX(fixed_at)::date AS last_fixed_at
         FROM (
                  SELECT DISTINCT severity, workload_id, introduced_at, fix_duration, fixed_at, snapshot_date
                  FROM filtered
              ) f
         GROUP BY snapshot_date, severity
     )
SELECT
    severity,
    snapshot_date,
    mean_time_to_fix_days,
    fixed_count,
    first_fixed_at,
    last_fixed_at
FROM aggregated
ORDER BY snapshot_date, severity;

-- name: ListWorkloadSeverityFixStats :many
SELECT
    v.workload_id,
    w.name AS workload_name,
    w.namespace AS workload_namespace,
    v.severity,
    MIN(v.introduced_at)::date AS introduced_date,
    MAX(v.fixed_at)::date AS fixed_at,
    COUNT(DISTINCT v.workload_id || '-' || v.severity || '-' || v.introduced_at)
        FILTER (WHERE v.is_fixed)::INT AS fixed_count,
    COALESCE(AVG((v.fixed_at::date - v.introduced_at::date)), 0)::INT AS mean_time_to_fix_days,
    MAX(v.snapshot_date)::timestamptz AS snapshot_time
FROM vuln_fix_summary v
         JOIN workloads w ON w.id = v.workload_id
WHERE
    (sqlc.narg('cluster')::TEXT IS NULL OR w.cluster = sqlc.narg('cluster')::TEXT)
  AND (sqlc.narg('namespace')::TEXT IS NULL OR w.namespace = sqlc.narg('namespace')::TEXT)
  AND (sqlc.narg('workload_types')::TEXT[] IS NULL OR w.workload_type = ANY(sqlc.narg('workload_types')::TEXT[]))
  AND (sqlc.narg('workload_name')::TEXT IS NULL OR w.name = sqlc.narg('workload_name')::TEXT)
  AND (
    sqlc.narg('since')::timestamptz IS NULL
    OR (
        CASE COALESCE(sqlc.narg('since_type')::TEXT, 'snapshot')
            WHEN 'snapshot' THEN v.snapshot_date
            WHEN 'fixed' THEN v.fixed_at
        END >= sqlc.narg('since')::timestamptz
    )
    )
GROUP BY v.workload_id, w.name, w.namespace, v.severity
ORDER BY introduced_date DESC;
