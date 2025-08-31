-- name: SyncWorkloadVulnerabilitiesForImage :exec
INSERT INTO workload_vulnerabilities (workload_id, vulnerability_id, introduced_at, became_critical_at)
SELECT
    w.id,
    v.id,
    w.created_at,
    CASE
        WHEN v.last_severity = 0 THEN COALESCE(v.became_critical_at, NOW())
        ELSE NULL
        END
FROM workloads w
         JOIN vulnerabilities v
              ON w.image_name = v.image_name
                  AND w.image_tag = v.image_tag
         LEFT JOIN workload_vulnerabilities wv
                   ON wv.workload_id = w.id
                       AND wv.vulnerability_id = v.id
WHERE wv.id IS NULL
  AND w.image_name = $1
  AND w.image_tag  = $2
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

-- name: GetWorkloadCriticalVulnBecameCriticalAt :one
SELECT wv.became_critical_at
FROM workload_vulnerabilities wv
         JOIN workloads w ON wv.workload_id = w.id
         JOIN vulnerabilities v ON wv.vulnerability_id = v.id
         LEFT JOIN suppressed_vulnerabilities sv
                   ON v.image_name = sv.image_name
                       AND v.package    = sv.package
                       AND v.cve_id    = sv.cve_id
WHERE w.id = $1
  AND v.cve_id = $2
  AND v.package = $3
  AND COALESCE(sv.suppressed, FALSE) = FALSE;

-- name: GetMeanHoursToFixCriticalVulnsForWorkload :one
SELECT AVG(EXTRACT(EPOCH FROM (wv.resolved_at - wv.became_critical_at)) / 3600.0)::double precision AS mean_hours_to_fix
FROM workload_vulnerabilities wv
WHERE wv.became_critical_at IS NOT NULL
  AND wv.resolved_at IS NOT NULL
  AND wv.workload_id = $1;
