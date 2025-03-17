-- name: BatchUpsertCve :batchexec
INSERT INTO cve(cve_id,
                cve_title,
                cve_desc,
                cve_link,
                severity,
                refs)
VALUES (@cve_id,
        @cve_title,
        @cve_desc,
        @cve_link,
        @severity,
        @refs)
    ON CONFLICT (cve_id)
    DO UPDATE
               SET cve_title = EXCLUDED.cve_title,
               cve_desc  = EXCLUDED.cve_desc,
               cve_link  = EXCLUDED.cve_link,
               severity  = EXCLUDED.severity,
               refs      = EXCLUDED.refs
       WHERE NOT (
           cve.cve_title = EXCLUDED.cve_title
         AND cve.cve_desc = EXCLUDED.cve_desc
         AND cve.cve_link = EXCLUDED.cve_link
         AND cve.severity = EXCLUDED.severity
         AND cve.refs = EXCLUDED.refs
           )
;

-- name: BatchUpsertVulnerabilities :batchexec
INSERT INTO vulnerabilities(image_name,
                            image_tag,
                            package,
                            cve_id,
                            source,
                            latest_version)
VALUES (@image_name,
        @image_tag,
        @package,
        @cve_id,
        @source,
        @latest_version)
ON CONFLICT (image_name, image_tag, package, cve_id)
DO UPDATE
    SET latest_version = EXCLUDED.latest_version
    WHERE vulnerabilities.latest_version <> EXCLUDED.latest_version
;

-- name: GetCve :one
SELECT *
FROM cve
WHERE cve_id = @cve_id
;

-- name: GetVulnerability :one
SELECT *
FROM vulnerabilities
WHERE image_name = @image_name
  AND image_tag = @image_tag
  AND package = @package
  AND cve_id = @cve_id
;

-- name: GetVulnerabilityById :one
SELECT v.id,
       v.image_name,
       v.image_tag,
       v.package,
       v.latest_version,
       v.source,
       v.cve_id,
       v.created_at,
       v.updated_at,
       c.cve_title,
       c.cve_desc,
       c.cve_link,
       c.severity AS severity,
       COALESCE(sv.suppressed, FALSE) AS suppressed,
       c.refs,
       sv.reason,
       sv.reason_text
FROM vulnerabilities v
    JOIN cve c ON v.cve_id = c.cve_id
    LEFT JOIN suppressed_vulnerabilities sv
              ON v.image_name = sv.image_name
                  AND v.package = sv.package
                  AND v.cve_id = sv.cve_id
WHERE v.id = @id
;

-- name: SuppressVulnerability :exec
INSERT INTO suppressed_vulnerabilities(image_name,
                                       package,
                                       cve_id,
                                       suppressed,
                                       suppressed_by,
                                       reason,
                                       reason_text)
VALUES (@image_name,
        @package,
        @cve_id,
        @suppressed,
        @suppressed_by,
        @reason,
        @reason_text) ON CONFLICT
ON CONSTRAINT image_name_package_cve_id DO
UPDATE
    SET suppressed = @suppressed,
    suppressed_by = @suppressed_by,
    reason = @reason,
    reason_text = @reason_text
;

-- name: GetSuppressedVulnerability :one
SELECT *
FROM suppressed_vulnerabilities
WHERE image_name = @image_name
  AND package = @package
  AND cve_id = @cve_id
;

-- name: ListAllSuppressedVulnerabilities :many
SELECT *
FROM suppressed_vulnerabilities
ORDER BY updated_at DESC
;

-- name: ListSuppressedVulnerabilities :many
SELECT DISTINCT sv.*, v.*, c.*, w.cluster, w.namespace
FROM suppressed_vulnerabilities sv
         JOIN vulnerabilities v
              ON sv.image_name = v.image_name
                  AND sv.package = v.package
                  AND sv.cve_id = v.cve_id
         JOIN cve c ON v.cve_id = c.cve_id
         JOIN (
    SELECT DISTINCT image_name, image_tag, cluster, namespace
    FROM workloads
) w ON v.image_name = w.image_name AND v.image_tag = w.image_tag
WHERE (CASE WHEN sqlc.narg('cluster')::TEXT IS NOT NULL THEN w.cluster = sqlc.narg('cluster')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('namespace')::TEXT IS NOT NULL THEN w.namespace = sqlc.narg('namespace')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('image_name')::TEXT IS NOT NULL THEN v.image_name = sqlc.narg('image_name')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('image_tag')::TEXT IS NOT NULL THEN v.image_tag = sqlc.narg('image_tag')::TEXT ELSE TRUE END)
ORDER BY
    CASE WHEN sqlc.narg('order_by') = 'severity_asc' THEN c.severity END ASC,
    CASE WHEN sqlc.narg('order_by') = 'severity_desc' THEN c.severity END DESC,
    CASE WHEN sqlc.narg('order_by') = 'workload_asc' THEN w.name END ASC,
    CASE WHEN sqlc.narg('order_by') = 'workload_desc' THEN w.name END DESC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_asc' THEN namespace END ASC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_desc' THEN namespace END DESC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_asc' THEN cluster END ASC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_desc' THEN cluster END DESC,
    v.id ASC
    LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset')
;

-- name: CountSuppressedVulnerabilities :one
SELECT COUNT(*) AS total
FROM suppressed_vulnerabilities sv
         JOIN vulnerabilities v
              ON sv.image_name = v.image_name
                  AND sv.package = v.package
                  AND sv.cve_id = v.cve_id
         JOIN cve c ON v.cve_id = c.cve_id
         JOIN workloads w ON v.image_name = w.image_name AND v.image_tag = w.image_tag
WHERE (CASE WHEN sqlc.narg('cluster')::TEXT is not null THEN w.cluster = sqlc.narg('cluster')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('namespace')::TEXT is not null THEN w.namespace = sqlc.narg('namespace')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_type')::TEXT is not null THEN w.workload_type = sqlc.narg('workload_type')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_name')::TEXT is not null THEN w.name = sqlc.narg('workload_name')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('image_name')::TEXT is not null THEN v.image_name = sqlc.narg('image_name')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('image_tag')::TEXT is not null THEN v.image_tag = sqlc.narg('image_tag')::TEXT ELSE TRUE END)
;

-- name: CountVulnerabilities :one
SELECT COUNT(*) AS total
FROM vulnerabilities v
         JOIN cve c ON v.cve_id = c.cve_id
         JOIN workloads w ON v.image_name = w.image_name AND v.image_tag = w.image_tag
         LEFT JOIN suppressed_vulnerabilities sv
                   ON v.image_name = sv.image_name
                       AND v.package = sv.package
                       AND v.cve_id = sv.cve_id
WHERE (CASE WHEN sqlc.narg('cluster')::TEXT is not null THEN w.cluster = sqlc.narg('cluster')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('namespace')::TEXT is not null THEN w.namespace = sqlc.narg('namespace')::TEXT ELSE TRUE END)
  AND (CASE
           WHEN sqlc.narg('workload_type')::TEXT is not null THEN w.workload_type = sqlc.narg('workload_type')::TEXT
           ELSE TRUE END)
  AND (CASE
           WHEN sqlc.narg('workload_name')::TEXT is not null THEN w.name = sqlc.narg('workload_name')::TEXT
           ELSE TRUE END)
  AND (sqlc.narg('include_suppressed')::BOOLEAN IS TRUE OR COALESCE(sv.suppressed, FALSE) = FALSE)
;

-- name: ListVulnerabilitiesForImage :many
SELECT v.id,
       v.image_name,
       v.image_tag,
       v.package,
       v.cve_id,
       v.latest_version,
       v.created_at,
       v.updated_at,
       c.cve_title,
       c.cve_desc,
       c.cve_link,
       c.severity,
       c.refs,
       COALESCE(sv.suppressed, FALSE) AS suppressed,
       sv.reason,
       sv.reason_text
FROM vulnerabilities v
        JOIN cve c ON v.cve_id = c.cve_id
        LEFT JOIN suppressed_vulnerabilities sv
                ON v.image_name = sv.image_name
                    AND v.package = sv.package
                    AND v.cve_id = sv.cve_id
WHERE v.image_name = @image_name
    AND v.image_tag = @image_tag
    AND (sqlc.narg('include_suppressed')::BOOLEAN IS TRUE OR COALESCE(sv.suppressed, FALSE) = FALSE)
ORDER BY
    CASE WHEN sqlc.narg('order_by') = 'severity_asc' THEN c.severity END ASC,
    CASE WHEN sqlc.narg('order_by') = 'severity_desc' THEN c.severity END DESC,
    v.id ASC
    LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset')
;

-- name: CountVulnerabilitiesForImage :one
SELECT COUNT(*) AS total
FROM vulnerabilities v
         JOIN cve c ON v.cve_id = c.cve_id
         JOIN workloads w ON v.image_name = w.image_name AND v.image_tag = w.image_tag
         LEFT JOIN suppressed_vulnerabilities sv
                   ON v.image_name = sv.image_name
                       AND v.package = sv.package
                       AND v.cve_id = sv.cve_id
WHERE v.image_name = @image_name
    AND v.image_tag = @image_tag
    AND (sqlc.narg('include_suppressed')::BOOLEAN IS TRUE OR COALESCE(sv.suppressed, FALSE) = FALSE)
;

-- name: ListVulnerabilities :many
SELECT v.id,
       w.name                         AS workload_name,
       w.workload_type,
       w.namespace,
       w.cluster,
       v.image_name,
       v.image_tag,
       v.package,
       v.cve_id,
       v.created_at,
       v.updated_at,
       c.cve_title,
       c.cve_desc,
       c.cve_link,
       c.severity AS severity,
       COALESCE(sv.suppressed, FALSE) AS suppressed,
       sv.reason,
       sv.reason_text
FROM vulnerabilities v
         JOIN cve c ON v.cve_id = c.cve_id
         JOIN workloads w ON v.image_name = w.image_name AND v.image_tag = w.image_tag
         LEFT JOIN suppressed_vulnerabilities sv
                   ON v.image_name = sv.image_name
                       AND v.package = sv.package
                       AND v.cve_id = sv.cve_id
WHERE (CASE WHEN sqlc.narg('cluster')::TEXT is not null THEN w.cluster = sqlc.narg('cluster')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('namespace')::TEXT is not null THEN w.namespace = sqlc.narg('namespace')::TEXT ELSE TRUE END)
  AND (CASE
           WHEN sqlc.narg('workload_type')::TEXT is not null THEN w.workload_type = sqlc.narg('workload_type')::TEXT
           ELSE TRUE END)
  AND (CASE
           WHEN sqlc.narg('workload_name')::TEXT is not null THEN w.name = sqlc.narg('workload_name')::TEXT
           ELSE TRUE END)
  AND (CASE
           WHEN sqlc.narg('image_name')::TEXT is not null THEN v.image_name = sqlc.narg('image_name')::TEXT
           ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('image_tag')::TEXT is not null THEN v.image_tag = sqlc.narg('image_tag')::TEXT ELSE TRUE END)
  AND (sqlc.narg('include_suppressed')::BOOLEAN IS TRUE OR COALESCE(sv.suppressed, FALSE) = FALSE)
ORDER BY
    CASE WHEN sqlc.narg('order_by') = 'severity_asc' THEN c.severity END ASC,
    CASE WHEN sqlc.narg('order_by') = 'severity_desc' THEN c.severity END DESC,
    CASE WHEN sqlc.narg('order_by') = 'workload_asc' THEN w.name END ASC,
    CASE WHEN sqlc.narg('order_by') = 'workload_desc' THEN w.name END DESC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_asc' THEN namespace END ASC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_desc' THEN namespace END DESC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_asc' THEN cluster END ASC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_desc' THEN cluster END DESC,
    v.id ASC
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset')
;

-- name: ListSuppressedVulnerabilitiesForImage :many
SELECT *
FROM suppressed_vulnerabilities
WHERE image_name = @image_name
ORDER BY updated_at DESC
;

-- name: GenerateVulnerabilitySummaryForImage :one
SELECT COUNT(*) AS total,
       SUM(CASE WHEN c.severity = 5 THEN 1 ELSE 0 END) AS critical,
       SUM(CASE WHEN c.severity = 4 THEN 1 ELSE 0 END) AS high,
       SUM(CASE WHEN c.severity = 3 THEN 1 ELSE 0 END) AS medium,
       SUM(CASE WHEN c.severity = 2 THEN 1 ELSE 0 END) AS low,
       SUM(CASE WHEN c.severity = 1 THEN 1 ELSE 0 END) AS unassigned,
       -- 10*critical + 5*high + 3*medium + 1*low + 5*unassigned
         10 * SUM(CASE WHEN c.severity = 5 THEN 1 ELSE 0 END) +
            5 * SUM(CASE WHEN c.severity = 4 THEN 1 ELSE 0 END) +
            3 * SUM(CASE WHEN c.severity = 3 THEN 1 ELSE 0 END) +
            1 * SUM(CASE WHEN c.severity = 2 THEN 1 ELSE 0 END) +
            5 * SUM(CASE WHEN c.severity = 1 THEN 1 ELSE 0 END) AS risk_score

FROM vulnerabilities v
         JOIN cve c ON v.cve_id = c.cve_id
WHERE v.image_name = @image_name
    AND v.image_tag = @image_tag
;