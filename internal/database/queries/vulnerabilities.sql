-- name: BatchUpsertVulnerabilities :batchexec
INSERT INTO vulnerabilities(image_name,
                            image_tag,
                            package,
                            cve_id,
                            source)

VALUES (@image_name,
        @image_tag,
        @package,
        @cve_id,
        @source)
ON CONFLICT DO NOTHING
;

-- name: BatchUpsertCve :batchexec
INSERT INTO cve(cve_id,
                cve_title,
                cve_desc,
                cve_link,
                severity)
VALUES (@cve_id,
        @cve_title,
        @cve_desc,
        @cve_link,
        @severity)
ON CONFLICT (cve_id)
    DO UPDATE
    SET cve_title = @cve_title,
        cve_desc  = @cve_desc,
        cve_link  = @cve_link,
        severity  = @severity
;

-- name: GetCve :one
SELECT *
FROM cve
WHERE cve_id = @cve_id;


-- name: GetVulnerability :one
SELECT *
FROM vulnerabilities
WHERE image_name = @image_name
  AND image_tag = @image_tag
  AND package = @package
  AND cve_id = @cve_id;


-- name: SuppressVulnerability :exec
INSERT INTO suppressed_vulnerabilities(image_name,
                                       package,
                                       cve_id,
                                       suppressed,
                                       reason,
                                       reason_text)
VALUES (@image_name,
        @package,
        @cve_id,
        @suppressed,
        @reason,
        @reason_text)
ON CONFLICT
    ON CONSTRAINT image_name_package_cve_id DO UPDATE
    SET suppressed  = @suppressed,
        reason      = @reason,
        reason_text = @reason_text
;

-- name: GetSuppressedVulnerability :one
SELECT *
FROM suppressed_vulnerabilities
WHERE image_name = @image_name
  AND package = @package
  AND cve_id = @cve_id;

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

-- name: ListVulnerabilities :many
SELECT w.name                         AS workload_name,
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
       c.severity,
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
ORDER BY (w.cluster, w.namespace, w.name, v.id) ASC
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset')
;

-- name: ListSuppressedVulnerabilitiesForImage :many
SELECT *
FROM suppressed_vulnerabilities
WHERE image_name = @image_name
ORDER BY updated_at DESC
LIMIT sqlc.arg('limit') OFFSET sqlc.arg('offset')
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
    AND v.image_tag = @image_tag;