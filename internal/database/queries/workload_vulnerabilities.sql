-- name: SyncWorkloadVulnerabilitiesForImage :exec
INSERT INTO workload_vulnerabilities (
    workload_id,
    vulnerability_id,
    created_at,
    became_critical_at
)
SELECT
    w.id,
    v.id,
    COALESCE(sqlc.arg(created_at), now()) AS created_at,
    CASE
        WHEN v.last_severity = 0 THEN COALESCE(sqlc.arg(created_at), now())
        ELSE NULL
        END AS became_critical_at
FROM workloads w
         JOIN vulnerabilities v
              ON w.image_name = v.image_name
                  AND w.image_tag = v.image_tag
         LEFT JOIN workload_vulnerabilities wv
                   ON wv.workload_id = w.id
                       AND wv.vulnerability_id = v.id
WHERE wv.id IS NULL
  AND v.last_severity = 0
  AND w.image_name = $1
  AND w.image_tag = $2
;

-- name: ResolveWorkloadVulnerabilitiesForImage :exec
UPDATE workload_vulnerabilities wv
SET resolved_at = NOW()
    FROM workloads w
WHERE wv.workload_id = w.id
  AND wv.vulnerability_id NOT IN (
    SELECT v.id
    FROM vulnerabilities v
    WHERE v.image_name = w.image_name
  AND v.image_tag = w.image_tag
    )
  AND wv.resolved_at IS NULL
  AND w.image_name = $1
  AND w.image_tag  = $2
;

-- name: ListWorkloadVulnerabilitiesBecameCriticalSince :many
SELECT
    w.id AS workload_id,
    w.name AS workload_name,
    w.workload_type,
    w.namespace,
    w.cluster,
    w.image_name,
    w.image_tag,
    v.cve_id,
    v.package,
    wv.became_critical_at,
    wv.resolved_at,
    wv.created_at,
    v.last_severity,
    COALESCE(sv.suppressed, FALSE) AS suppressed,
    sv.reason,
    sv.reason_text,
    sv.suppressed_by,
    sv.updated_at AS suppressed_at
FROM workload_vulnerabilities wv
         JOIN workloads w ON wv.workload_id = w.id
         JOIN vulnerabilities v ON wv.vulnerability_id = v.id
         LEFT JOIN suppressed_vulnerabilities sv
                   ON v.image_name = sv.image_name
                       AND v.package    = sv.package
                       AND v.cve_id     = sv.cve_id
WHERE (CASE WHEN sqlc.narg('cluster')::TEXT IS NOT NULL THEN w.cluster = sqlc.narg('cluster')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('namespace')::TEXT IS NOT NULL THEN w.namespace = sqlc.narg('namespace')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_type')::TEXT IS NOT NULL THEN w.workload_type = sqlc.narg('workload_type')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_name')::TEXT IS NOT NULL THEN w.name = sqlc.narg('workload_name')::TEXT ELSE TRUE END)
  AND (sqlc.narg('include_suppressed')::BOOLEAN IS TRUE OR COALESCE(sv.suppressed, FALSE) = FALSE)
  AND (sqlc.narg('since')::timestamptz IS NULL OR wv.became_critical_at > sqlc.narg('since')::timestamptz)
ORDER BY w.id, v.cve_id, v.package LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset');
;


-- name: ListWorkloadsMeanHoursToFixCriticalVulns :many
WITH filtered_workloads AS (
    SELECT *
    FROM workloads w
    WHERE (sqlc.narg('cluster')::TEXT IS NULL OR w.cluster = sqlc.narg('cluster')::TEXT)
      AND (sqlc.narg('namespace')::TEXT IS NULL OR w.namespace = sqlc.narg('namespace')::TEXT)
      AND (sqlc.narg('workload_type')::TEXT IS NULL OR w.workload_type = sqlc.narg('workload_type')::TEXT)
      AND (sqlc.narg('workload_name')::TEXT IS NULL OR w.name = sqlc.narg('workload_name')::TEXT)
),
     mhtf AS (
         SELECT
             wv.workload_id,
             AVG(EXTRACT(EPOCH FROM (wv.resolved_at - wv.became_critical_at)) / 3600.0)::double precision AS mean_hours_to_fix
FROM workload_vulnerabilities wv
    JOIN filtered_workloads fw ON wv.workload_id = fw.id
WHERE wv.became_critical_at IS NOT NULL
  AND wv.resolved_at IS NOT NULL
GROUP BY wv.workload_id
    )
SELECT
    w.id,
    w.name AS workload_name,
    w.workload_type,
    w.namespace,
    w.cluster,
    w.state AS workload_state,
    w.updated_at AS workload_updated_at,
    i.name AS image_name,
    i.tag AS image_tag,
    i.state AS image_state,
    i.updated_at AS image_updated_at,
    COALESCE(m.mean_hours_to_fix, 0) AS mean_hours_to_fix
FROM filtered_workloads w
         JOIN images i ON w.image_name = i.name AND w.image_tag = i.tag
         LEFT JOIN mhtf m ON w.id = m.workload_id
ORDER BY
    CASE WHEN sqlc.narg('order_by') = 'workload_asc' THEN w.name END ASC,
    CASE WHEN sqlc.narg('order_by') = 'workload_desc' THEN w.name END DESC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_asc' THEN w.namespace END ASC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_desc' THEN w.namespace END DESC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_asc' THEN w.cluster END ASC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_desc' THEN w.cluster END DESC,
    w.id ASC LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset');

-- name: CountWorkloadVulnerabilities :one
SELECT COUNT(*) AS total
FROM workload_vulnerabilities v
         JOIN workloads w ON v.workload_id = w.id
         LEFT JOIN suppressed_vulnerabilities sv
                   ON v.vulnerability_id = sv.id
WHERE (CASE WHEN sqlc.narg('cluster')::TEXT IS NOT NULL THEN w.cluster = sqlc.narg('cluster')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('namespace')::TEXT IS NOT NULL THEN w.namespace = sqlc.narg('namespace')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_type')::TEXT IS NOT NULL THEN w.workload_type = sqlc.narg('workload_type')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_name')::TEXT IS NOT NULL THEN w.name = sqlc.narg('workload_name')::TEXT ELSE TRUE END)
  AND (sqlc.narg('include_suppressed')::BOOLEAN IS TRUE OR COALESCE(sv.suppressed, FALSE) = FALSE);