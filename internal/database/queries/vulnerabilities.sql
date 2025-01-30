-- name: BatchUpsertVulnerabilities :batchexec
INSERT INTO vulnerabilities(image_name,
                                  image_tag,
                                  package,
                                  cwe_id)

VALUES (@image_name,
        @image_tag,
        @package,
        @cwe_id)
ON CONFLICT DO NOTHING
;

-- name: BatchUpsertCwe :batchexec
INSERT INTO cwe(cwe_id,
                cwe_title,
                cwe_desc,
                cwe_link,
                severity)
VALUES (@cwe_id,
        @cwe_title,
        @cwe_desc,
        @cwe_link,
        @severity)
ON CONFLICT (cwe_id)
    DO
        UPDATE
    SET cwe_title = @cwe_title,
        cwe_desc = @cwe_desc,
        cwe_link = @cwe_link,
        severity = @severity
;

-- name: GetCwe :one
SELECT * FROM cwe WHERE cwe_id = @cwe_id;


-- name: GetVulnerability :one
SELECT * FROM vulnerabilities WHERE image_name = @image_name AND image_tag = @image_tag AND package = @package AND cwe_id = @cwe_id;


-- name: SuppressVulnerability :exec
INSERT INTO suppressed_vulnerabilities(image_name,
                                       package,
                                       cwe_id,
                                       suppressed,
                                       reason,
                                       reason_text)
VALUES (@image_name,
        @package,
        @cwe_id,
        @suppressed,
        @reason,
        @reason_text) ON CONFLICT
ON CONSTRAINT image_name_package_cwe_id DO UPDATE
SET suppressed = @suppressed,
    reason = @reason,
    reason_text = @reason_text
;

-- name: GetSuppressedVulnerability :one
SELECT * FROM suppressed_vulnerabilities WHERE image_name = @image_name AND package = @package AND cwe_id = @cwe_id;

-- name: CountVulnerabilities :one
SELECT COUNT(*) AS total
FROM vulnerabilities v
         JOIN cwe c ON v.cwe_id = c.cwe_id
         JOIN workloads w ON v.image_name = w.image_name AND v.image_tag = w.image_tag
         LEFT JOIN suppressed_vulnerabilities sv
                   ON v.image_name = sv.image_name
                       AND v.package = sv.package
                       AND v.cwe_id = sv.cwe_id
WHERE (CASE WHEN sqlc.narg('cluster')::TEXT is not null THEN w.cluster = sqlc.narg('cluster')::TEXT ELSE TRUE END)
   AND (CASE WHEN sqlc.narg('namespace')::TEXT is not null THEN w.namespace = sqlc.narg('namespace')::TEXT ELSE TRUE END)
   AND (CASE WHEN sqlc.narg('workload_type')::TEXT is not null THEN w.workload_type = sqlc.narg('workload_type')::TEXT ELSE TRUE END)
   AND (CASE WHEN sqlc.narg('workload_name')::TEXT is not null THEN w.name = sqlc.narg('workload_name')::TEXT ELSE TRUE END)
   AND (sqlc.narg('include_suppressed')::BOOLEAN IS TRUE OR COALESCE(sv.suppressed, FALSE) = FALSE)
;

-- name: ListVulnerabilities :many
SELECT
    w.name AS workload_name,
    w.workload_type,
    w.namespace,
    w.cluster,
    v.image_name,
    v.image_tag,
    v.package,
    v.cwe_id,
    v.created_at,
    v.updated_at,
    c.cwe_title,
    c.cwe_desc,
    c.cwe_link,
    c.severity,
    COALESCE(sv.suppressed, FALSE) AS suppressed,
    sv.reason,
    sv.reason_text
FROM vulnerabilities v
         JOIN cwe c ON v.cwe_id = c.cwe_id
         JOIN workloads w ON v.image_name = w.image_name AND v.image_tag = w.image_tag
         LEFT JOIN suppressed_vulnerabilities sv
                   ON v.image_name = sv.image_name
                       AND v.package = sv.package
                       AND v.cwe_id = sv.cwe_id
WHERE (CASE WHEN sqlc.narg('cluster')::TEXT is not null THEN w.cluster = sqlc.narg('cluster')::TEXT ELSE TRUE END)
   AND (CASE WHEN sqlc.narg('namespace')::TEXT is not null THEN w.namespace = sqlc.narg('namespace')::TEXT ELSE TRUE END)
   AND (CASE WHEN sqlc.narg('workload_type')::TEXT is not null THEN w.workload_type = sqlc.narg('workload_type')::TEXT ELSE TRUE END)
   AND (CASE WHEN sqlc.narg('workload_name')::TEXT is not null THEN w.name = sqlc.narg('workload_name')::TEXT ELSE TRUE END)
   AND (sqlc.narg('include_suppressed')::BOOLEAN IS TRUE OR COALESCE(sv.suppressed, FALSE) = FALSE)
ORDER BY (w.cluster, w.namespace, w.name, v.id) ASC
LIMIT
    sqlc.arg('limit')
OFFSET
    sqlc.arg('offset')
;

-- name: ListSuppressedVulnerabilitiesForImage :many
SELECT * FROM suppressed_vulnerabilities WHERE image_name = @image_name
ORDER BY updated_at DESC
LIMIT
    sqlc.arg('limit')
OFFSET
    sqlc.arg('offset')
;
