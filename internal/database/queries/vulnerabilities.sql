-- name: RecalculateVulnerabilitySummary :exec
WITH resolved_vulnerabilities AS (
     SELECT DISTINCT
         c.cve_id AS id,
         c.severity,
         v.package,
         v.image_name,
         v.image_tag
     FROM vulnerabilities v
              LEFT JOIN cve_alias ca
                        ON v.cve_id = ca.alias
              JOIN cve c
                   ON c.cve_id = COALESCE(ca.canonical_cve_id, v.cve_id)
     WHERE v.image_name = @image_name
       AND v.image_tag  = @image_tag
 ),
 severity_counts AS (
     SELECT COUNT(*)                             AS total,
            COUNT(*) FILTER (WHERE severity = 0) AS critical,
            COUNT(*) FILTER (WHERE severity = 1) AS high,
            COUNT(*) FILTER (WHERE severity = 2) AS medium,
            COUNT(*) FILTER (WHERE severity = 3) AS low,
            COUNT(*) FILTER (WHERE severity = 4) AS unassigned
     FROM resolved_vulnerabilities rv
              LEFT JOIN suppressed_vulnerabilities sv
                        ON  rv.image_name = sv.image_name
                            AND rv.package    = sv.package
                            AND rv.id         = sv.cve_id
     WHERE NOT COALESCE(sv.suppressed, FALSE)
 ),
summary AS (
    SELECT @image_name AS image_name,
           @image_tag  AS image_tag,
           total,
           critical,
           high,
           medium,
           low,
           unassigned,
           10 * critical
               + 5 * high
               + 3 * medium
               + 1 * low
               + 5 * unassigned AS risk_score
    FROM severity_counts
)
INSERT INTO vulnerability_summary (
    image_name,
    image_tag,
    critical,
    high,
    medium,
    low,
    unassigned,
    risk_score,
    created_at,
    updated_at
)
SELECT
    image_name,
    image_tag,
    critical,
    high,
    medium,
    low,
    unassigned,
    risk_score,
    NOW(),
    NOW()
FROM summary
    ON CONFLICT (image_name, image_tag)
        DO UPDATE SET
           critical    = EXCLUDED.critical,
           high        = EXCLUDED.high,
           medium      = EXCLUDED.medium,
           low         = EXCLUDED.low,
           unassigned  = EXCLUDED.unassigned,
           risk_score  = EXCLUDED.risk_score,
           updated_at  = NOW();


-- name: BatchUpsertCve :batchexec
INSERT INTO cve(cve_id,
                cve_title,
                cve_desc,
                cve_link,
                severity,
                refs,
                cvss_score)
VALUES (@cve_id,
        @cve_title,
        @cve_desc,
        @cve_link,
        @severity,
        @refs,
        @cvss_score)
    ON CONFLICT (cve_id)
    DO UPDATE
               SET cve_title = EXCLUDED.cve_title,
               cve_desc  = EXCLUDED.cve_desc,
               cve_link  = EXCLUDED.cve_link,
               severity  = EXCLUDED.severity,
               refs      = EXCLUDED.refs,
               cvss_score = EXCLUDED.cvss_score,
               updated_at = NOW()
   WHERE
           cve.cve_title  IS DISTINCT FROM EXCLUDED.cve_title OR
           cve.cve_desc   IS DISTINCT FROM EXCLUDED.cve_desc OR
           cve.cve_link   IS DISTINCT FROM EXCLUDED.cve_link OR
           cve.severity   IS DISTINCT FROM EXCLUDED.severity OR
           cve.refs       IS DISTINCT FROM EXCLUDED.refs OR
           cve.cvss_score IS DISTINCT FROM EXCLUDED.cvss_score
;

-- name: BatchUpsertCveAlias :batchexec
INSERT INTO cve_alias(alias,
                canonical_cve_id)
VALUES (@alias,
        @canonical_cve_id)
ON CONFLICT (alias) DO UPDATE
    SET canonical_cve_id = EXCLUDED.canonical_cve_id
WHERE
    cve_alias.canonical_cve_id  IS DISTINCT FROM EXCLUDED.canonical_cve_id
;

-- name: BatchUpsertVulnerabilities :batchexec
INSERT INTO vulnerabilities (
    image_name,
    image_tag,
    package,
    cve_id,
    source,
    latest_version,
    last_severity,
    severity_since,
    cvss_score
)
VALUES (
           @image_name,
           @image_tag,
           @package,
           @cve_id,
           @source,
           @latest_version,
           @last_severity,
           COALESCE(@severity_since::timestamptz, NOW()),
           @cvss_score) ON CONFLICT (image_name, image_tag, package, cve_id) DO
UPDATE
    SET
        latest_version = EXCLUDED.latest_version,
    updated_at = NOW(),
    last_severity = EXCLUDED.last_severity,
    cvss_score = EXCLUDED.cvss_score,
    severity_since = CASE
    WHEN EXCLUDED.last_severity <> vulnerabilities.last_severity
    THEN COALESCE (EXCLUDED.severity_since, NOW())
    ELSE vulnerabilities.severity_since
END;

-- name: GetEarliestSeveritySinceForVulnerability :one
SELECT (COALESCE(
        (SELECT MIN(v1.severity_since)
         FROM vulnerabilities v1
         WHERE v1.image_name = $1
           AND v1.package = $2
           AND v1.cve_id = $3
           AND v1.last_severity = $4
           AND v1.severity_since IS NOT NULL),
        (SELECT MIN(v2.created_at)
         FROM vulnerabilities v2
         WHERE v2.image_name = $1
           AND v2.package = $2
           AND v2.cve_id = $3
         AND v2.last_severity = $4)
        )::timestamptz) AS earliest_severity_since
;

-- name: GetCve :one
SELECT *
FROM cve
WHERE cve_id = @cve_id
;

-- name: GetVulnerability :one
SELECT v.id,
       v.image_name,
       v.image_tag,
       v.package,
       v.latest_version,
       v.source,
       v.cve_id,
       v.last_severity,
       v.severity_since,
       v.created_at,
       v.updated_at,
       c.cve_title,
       c.cve_desc,
       c.cve_link,
       c.severity AS severity,
       c.refs,
       COALESCE(sv.suppressed, FALSE) AS suppressed,
       sv.reason,
       sv.reason_text,
       sv.suppressed_by,
       sv.updated_at AS suppressed_at
FROM vulnerabilities v
         JOIN cve c ON v.cve_id = c.cve_id
         LEFT JOIN suppressed_vulnerabilities sv
                   ON v.image_name = sv.image_name
                       AND v.package = sv.package
                       AND v.cve_id = sv.cve_id
WHERE v.image_name = @image_name
  AND v.image_tag = @image_tag
  AND v.package = @package
  AND v.cve_id = @cve_id;

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
       sv.reason_text,
       sv.suppressed_by,
       sv.updated_at as suppressed_at
FROM vulnerabilities v
    JOIN cve c ON v.cve_id = c.cve_id
    LEFT JOIN suppressed_vulnerabilities sv
              ON v.image_name = sv.image_name
                  AND v.package = sv.package
                  AND v.cve_id = sv.cve_id
WHERE v.id = @id
;

-- name: ListWorkloadsForVulnerabilityById :many
SELECT w.id,
       w.cluster,
       w.namespace,
       w.name,
       w.workload_type,
       w.image_name,
       w.image_tag
FROM workloads w
         JOIN vulnerabilities v
              ON v.image_name = w.image_name
                  AND v.image_tag = w.image_tag
WHERE v.id = @vulnerability_id
ORDER BY w.cluster, w.namespace, w.name;

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
    SET
        suppressed = EXCLUDED.suppressed,
    suppressed_by = EXCLUDED.suppressed_by,
    reason = EXCLUDED.reason,
    reason_text = EXCLUDED.reason_text,
    updated_at = NOW()
WHERE
    suppressed_vulnerabilities.suppressed     IS DISTINCT FROM EXCLUDED.suppressed OR
    suppressed_vulnerabilities.suppressed_by  IS DISTINCT FROM EXCLUDED.suppressed_by OR
    suppressed_vulnerabilities.reason         IS DISTINCT FROM EXCLUDED.reason OR
    suppressed_vulnerabilities.reason_text    IS DISTINCT FROM EXCLUDED.reason_text;
;

-- name: ListSuppressedVulnerabilities :many
SELECT sv.*, v.*, c.*, w.cluster, w.namespace
FROM suppressed_vulnerabilities sv
         JOIN vulnerabilities v
              ON sv.image_name = v.image_name
                  AND sv.package = v.package
                  AND sv.cve_id = v.cve_id
         JOIN cve c ON v.cve_id = c.cve_id
         JOIN workloads w ON v.image_name = w.image_name
    AND v.image_tag = w.image_tag
WHERE (CASE WHEN sqlc.narg('cluster')::TEXT IS NOT NULL THEN w.cluster = sqlc.narg('cluster')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('namespace')::TEXT IS NOT NULL THEN w.namespace = sqlc.narg('namespace')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('image_name')::TEXT IS NOT NULL THEN v.image_name = sqlc.narg('image_name')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('image_tag')::TEXT IS NOT NULL THEN v.image_tag = sqlc.narg('image_tag')::TEXT ELSE TRUE END)
ORDER BY
    CASE WHEN sqlc.narg('order_by') = 'severity_asc' THEN c.severity END ASC,
    CASE WHEN sqlc.narg('order_by') = 'severity_desc' THEN c.severity END DESC,
    CASE WHEN sqlc.narg('order_by') = 'workload_asc' THEN w.name END ASC,
    CASE WHEN sqlc.narg('order_by') = 'workload_desc' THEN w.name END DESC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_asc' THEN w.namespace END ASC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_desc' THEN w.namespace END DESC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_asc' THEN w.cluster END ASC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_desc' THEN w.cluster END DESC,
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
WITH image_all_vulns AS (
    -- Only the vulnerabilities for this image/tag
    SELECT *
    FROM vulnerabilities v
    WHERE v.image_name = @image_name
      AND v.image_tag  = @image_tag
),
resolved_vulnerabilities AS (
     SELECT
         COALESCE(ca.canonical_cve_id, v.cve_id)::TEXT AS cve_id,
         c.cve_title,
         c.cve_desc,
         c.cve_link,
         c.severity,
         c.refs::jsonb AS cve_refs,
         c.created_at AS cve_created_at,
         c.updated_at AS cve_updated_at,
         v.id,
         v.image_name,
         v.image_tag,
         v.package,
         v.latest_version,
         v.created_at,
         v.updated_at,
         v.severity_since,
         v.cvss_score
    FROM image_all_vulns v
    LEFT JOIN cve_alias ca ON v.cve_id = ca.alias
    JOIN cve c ON c.cve_id = COALESCE(ca.canonical_cve_id, v.cve_id)
),
distinct_image_vulnerabilities AS (
    SELECT DISTINCT ON (v.image_name, v.image_tag, v.package, v.cve_id)
        v.*,
        COALESCE(sv.suppressed, FALSE) AS suppressed,
        sv.reason,
        sv.reason_text,
        sv.suppressed_by,
        sv.updated_at as suppressed_at
    FROM resolved_vulnerabilities v
             LEFT JOIN suppressed_vulnerabilities sv
                       ON v.image_name       = sv.image_name
                           AND v.package          = sv.package
                           AND v.cve_id = sv.cve_id
    WHERE (sqlc.narg('include_suppressed')::BOOLEAN IS TRUE OR COALESCE(sv.suppressed, FALSE) = FALSE)
     AND (sqlc.narg('since')::timestamptz IS NULL OR v.severity_since > sqlc.narg('since')::timestamptz)
     AND (sqlc.narg('severity')::INT IS NULL OR v.severity = sqlc.narg('severity')::INT)
)
SELECT id,
       image_name,
       image_tag,
       package,
       cve_id,
       latest_version,
       created_at,
       updated_at,
       severity_since,
       cvss_score,
       cve_title,
       cve_desc,
       cve_link,
       severity,
       cve_refs as cve_refs,
       cve_created_at,
       cve_updated_at,
       COALESCE(suppressed, FALSE) AS suppressed,
       reason,
       reason_text,
       suppressed_by,
       suppressed_at,
       COUNT(id) OVER() as total_count
FROM distinct_image_vulnerabilities
ORDER BY CASE WHEN sqlc.narg('order_by') = 'severity_asc' THEN severity END ASC,
         CASE WHEN sqlc.narg('order_by') = 'severity_desc' THEN severity END DESC,
         CASE WHEN sqlc.narg('order_by') = 'severity_since_asc' THEN severity_since END ASC,
         CASE WHEN sqlc.narg('order_by') = 'severity_since_desc' THEN severity_since END DESC,
         CASE WHEN sqlc.narg('order_by') = 'package_asc' THEN package END ASC,
         CASE WHEN sqlc.narg('order_by') = 'package_desc' THEN package END DESC,
         CASE WHEN sqlc.narg('order_by') = 'cve_id_asc' THEN cve_id END ASC,
         CASE WHEN sqlc.narg('order_by') = 'cve_id_desc' THEN cve_id END DESC,
         CASE WHEN sqlc.narg('order_by') = 'suppressed_asc' THEN COALESCE(suppressed, FALSE) END ASC,
         CASE WHEN sqlc.narg('order_by') = 'suppressed_desc' THEN COALESCE(suppressed, FALSE) END DESC,
         CASE WHEN sqlc.narg('order_by') = 'reason_asc' THEN reason END ASC,
         CASE WHEN sqlc.narg('order_by') = 'reason_desc' THEN reason END DESC,
         CASE WHEN sqlc.narg('order_by') = 'created_at_asc' THEN created_at END ASC,
         CASE WHEN sqlc.narg('order_by') = 'created_at_desc' THEN created_at END DESC,
         CASE WHEN sqlc.narg('order_by') = 'updated_at_asc' THEN updated_at END ASC,
         CASE WHEN sqlc.narg('order_by') = 'updated_at_desc' THEN updated_at END DESC,
         severity, id ASC
    LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset')
;

-- TODO: use ctes like ListVulnerabilitiesForImage to handle aliases for CVE IDs
-- name: ListVulnerabilities :many
SELECT v.id,
       w.name                         AS workload_name,
       w.workload_type,
       w.namespace,
       w.cluster,
       v.image_name,
       v.image_tag,
       v.latest_version,
       v.severity_since,
       v.package,
       v.cve_id,
       v.created_at,
       v.updated_at,
       c.cve_title,
       c.cve_desc,
       c.cve_link,
       c.severity AS severity,
       c.created_at AS cve_created_at,
       c.updated_at AS cve_updated_at,
       COALESCE(sv.suppressed, FALSE) AS suppressed,
       sv.reason,
       sv.reason_text,
       sv.suppressed_by,
       sv.updated_at as suppressed_at,
       v.cvss_score
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
    CASE WHEN sqlc.narg('order_by') = 'namespace_asc' THEN w.namespace END ASC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_desc' THEN w.namespace END DESC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_asc' THEN w.cluster END ASC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_desc' THEN w.cluster END DESC,
    CASE WHEN sqlc.narg('order_by') = 'created_at_asc' THEN v.created_at END ASC,
    CASE WHEN sqlc.narg('order_by') = 'created_at_desc' THEN v.created_at END DESC,
    CASE WHEN sqlc.narg('order_by') = 'updated_at_asc' THEN v.updated_at END ASC,
    CASE WHEN sqlc.narg('order_by') = 'updated_at_desc' THEN v.updated_at END DESC,
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

-- name: ListSeverityVulnerabilitiesSince :many
SELECT
    v.id,
    w.name AS workload_name,
    w.workload_type,
    w.namespace,
    w.cluster,
    v.image_name,
    v.image_tag,
    v.latest_version,
    v.package,
    v.cve_id,
    v.created_at,
    v.updated_at,
    v.severity_since,
    v.last_severity,
    c.cve_title,
    c.cve_desc,
    c.cve_link,
    c.severity AS severity,
    c.created_at AS cve_created_at,
    c.updated_at AS cve_updated_at,
    COALESCE(sv.suppressed, FALSE) AS suppressed,
    sv.reason,
    sv.reason_text,
    sv.suppressed_by,
    sv.updated_at AS suppressed_at,
    v.cvss_score
FROM vulnerabilities v
         JOIN cve c ON v.cve_id = c.cve_id
         JOIN workloads w ON v.image_name = w.image_name AND v.image_tag = w.image_tag
         LEFT JOIN suppressed_vulnerabilities sv
                   ON v.image_name = sv.image_name
                       AND v.package = sv.package
                       AND v.cve_id = sv.cve_id
WHERE v.severity_since IS NOT NULL
  AND (CASE WHEN sqlc.narg('cluster')::TEXT IS NOT NULL THEN w.cluster = sqlc.narg('cluster')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('namespace')::TEXT IS NOT NULL THEN w.namespace = sqlc.narg('namespace')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_type')::TEXT IS NOT NULL THEN w.workload_type = sqlc.narg('workload_type')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_name')::TEXT IS NOT NULL THEN w.name = sqlc.narg('workload_name')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('image_name')::TEXT IS NOT NULL THEN v.image_name = sqlc.narg('image_name')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('image_tag')::TEXT IS NOT NULL THEN v.image_tag = sqlc.narg('image_tag')::TEXT ELSE TRUE END)
  AND (sqlc.narg('include_suppressed')::BOOLEAN IS TRUE OR COALESCE(sv.suppressed, FALSE) = FALSE)
  AND (sqlc.narg('since')::timestamptz IS NULL OR v.severity_since > sqlc.narg('since')::timestamptz)
ORDER BY
         CASE WHEN sqlc.narg('order_by') = 'severity_since_desc' THEN v.severity_since END DESC,
         CASE WHEN sqlc.narg('order_by') = 'severity_since_asc' THEN v.severity_since END ASC,
         CASE WHEN sqlc.narg('order_by') = 'workload_asc' THEN w.name END ASC,
         CASE WHEN sqlc.narg('order_by') = 'workload_desc' THEN w.name END DESC,
         CASE WHEN sqlc.narg('order_by') = 'namespace_asc' THEN w.namespace END ASC,
         CASE WHEN sqlc.narg('order_by') = 'namespace_desc' THEN w.namespace END DESC,
         CASE WHEN sqlc.narg('order_by') = 'cluster_asc' THEN w.cluster END ASC,
         CASE WHEN sqlc.narg('order_by') = 'cluster_desc' THEN w.cluster END DESC,
         v.id ASC LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset');

-- name: ListWorkloadsForVulnerabilities :many
SELECT
    v.id,
    w.name AS workload_name,
    w.workload_type,
    w.namespace,
    w.cluster,
    w.image_name,
    w.image_tag,
    v.latest_version,
    v.package,
    v.cve_id,
    v.created_at,
    v.updated_at,
    v.severity_since,
    v.last_severity,
    c.cve_title,
    c.cve_desc,
    c.cve_link,
    c.severity AS severity,
    c.created_at AS cve_created_at,
    c.updated_at AS cve_updated_at,
    COALESCE(sv.suppressed, FALSE) AS suppressed,
    sv.reason,
    sv.reason_text,
    sv.suppressed_by,
    sv.updated_at AS suppressed_at,
    v.cvss_score,
    COUNT(v.id) OVER() as total_count
FROM vulnerabilities v
    JOIN cve c ON v.cve_id = c.cve_id
    JOIN workloads w ON w.image_name = v.image_name AND w.image_tag = v.image_tag
    LEFT JOIN suppressed_vulnerabilities sv
              ON v.image_name = sv.image_name
                  AND v.package = sv.package
                  AND v.cve_id = sv.cve_id
WHERE
    (sqlc.narg('cve_ids')::TEXT[] IS NULL OR v.cve_id = ANY(sqlc.narg('cve_ids')::TEXT[]))
    AND
    (sqlc.narg('cvss_score')::FLOAT8 IS NULL OR (v.cvss_score IS NOT NULL AND v.cvss_score >= sqlc.narg('cvss_score')::FLOAT8))
    AND (CASE WHEN sqlc.narg('cluster')::TEXT IS NOT NULL THEN w.cluster = sqlc.narg('cluster')::TEXT ELSE TRUE END)
    AND (CASE WHEN sqlc.narg('namespace')::TEXT IS NOT NULL THEN w.namespace = sqlc.narg('namespace')::TEXT ELSE TRUE END)
    AND (sqlc.narg('workload_types')::TEXT[] IS NULL OR w.workload_type = ANY(sqlc.narg('workload_types')::TEXT[]))
    AND (CASE WHEN sqlc.narg('workload_name')::TEXT IS NOT NULL THEN w.name = sqlc.narg('workload_name')::TEXT ELSE TRUE END)
    AND (CASE WHEN sqlc.narg('image_name')::TEXT IS NOT NULL THEN v.image_name = sqlc.narg('image_name')::TEXT ELSE TRUE END)
    AND (CASE WHEN sqlc.narg('image_tag')::TEXT IS NOT NULL THEN v.image_tag = sqlc.narg('image_tag')::TEXT ELSE TRUE END)
ORDER BY
    CASE WHEN sqlc.narg('order_by') = 'cve_id_desc' THEN v.cve_id END DESC,
    CASE WHEN sqlc.narg('order_by') = 'cve_id_asc' THEN v.cve_id END ASC,
    CASE WHEN sqlc.narg('order_by') = 'workload_asc' THEN w.name END ASC,
    CASE WHEN sqlc.narg('order_by') = 'workload_desc' THEN w.name END DESC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_asc' THEN w.namespace END ASC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_desc' THEN w.namespace END DESC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_asc' THEN w.cluster END ASC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_desc' THEN w.cluster END DESC,
    v.id ASC LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset')
;

