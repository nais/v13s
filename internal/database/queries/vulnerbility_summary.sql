-- name: BatchUpsertVulnerabilitySummary :batchexec
INSERT INTO vulnerability_summary(image_name,
                                  image_tag,
                                  critical,
                                  high,
                                  medium,
                                  low,
                                  unassigned,
                                  risk_score)
VALUES (@image_name,
        @image_tag,
        @critical,
        @high,
        @medium,
        @low,
        @unassigned,
        @risk_score) ON CONFLICT
ON CONSTRAINT image_name_tag DO
UPDATE
    SET critical = @critical,
    high = @high,
    medium = @medium,
    low = @low,
    unassigned = @unassigned,
    risk_score = @risk_score
;

-- name: CreateVulnerabilitySummary :one
INSERT INTO
    vulnerability_summary (image_name, image_tag, critical, high, medium, low, unassigned, risk_score)
VALUES
    (@image_name, @image_tag, @critical, @high, @medium, @low, @unassigned, @risk_score)
RETURNING
    *
;

-- name: UpdateVulnerabilitySummary :one
UPDATE vulnerability_summary
SET
    critical = COALESCE(sqlc.narg(critical), critical),
    high = COALESCE(sqlc.narg(high), high),
    medium = COALESCE(sqlc.narg(medium), medium),
    low = COALESCE(sqlc.narg(low), low),
    unassigned = COALESCE(sqlc.narg(unassigned), unassigned),
    risk_score = COALESCE(sqlc.narg(risk_score), risk_score)
WHERE
    vulnerability_summary.id = @id
RETURNING
    *
;

-- name: ListAllVulnerabilitySummaries :many
SELECT * FROM vulnerability_summary
ORDER BY
    CASE
        WHEN @order_by::TEXT = 'risk_score:asc' THEN LOWER(vulnerability_summary.risk_score)
END ASC,
	CASE
		WHEN @order_by::TEXT = 'risk_score:desc' THEN LOWER(vulnerability_summary.risk_score)
END DESC,
	vulnerability_summary.risk_score,
	vulnerability_summary.critical ASC
LIMIT
	sqlc.arg('limit')
OFFSET
	sqlc.arg('offset')
;

-- name: ListVulnerabilitySummaries :many
SELECT
    w.id,
    w.name AS workload_name,
    w.workload_type,
    w.namespace,
    w.cluster,
    w.image_name,
    w.image_tag,
    v.critical,
    v.high,
    v.medium,
    v.low,
    v.unassigned,
    v.risk_score,
    w.created_at AS workload_created_at,
    w.updated_at AS workload_updated_at,
    v.created_at AS summary_created_at,
    v.updated_at AS summary_updated_at,
    CASE WHEN v.image_name IS NOT NULL THEN TRUE ELSE FALSE END AS has_sbom
FROM workloads w
         LEFT JOIN vulnerability_summary v
                   ON w.image_name = v.image_name AND w.image_tag = v.image_tag
WHERE
    (CASE WHEN sqlc.narg('cluster')::TEXT is not null THEN w.cluster = sqlc.narg('cluster')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('namespace')::TEXT is not null THEN w.namespace = sqlc.narg('namespace')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_type')::TEXT is not null THEN w.workload_type = sqlc.narg('workload_type')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_name')::TEXT is not null THEN w.name = sqlc.narg('workload_name')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('image_name')::TEXT is not null THEN v.image_name = sqlc.narg('image_name')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('image_tag')::TEXT is not null THEN v.image_tag = sqlc.narg('image_tag')::TEXT ELSE TRUE END)
ORDER BY
    CASE WHEN sqlc.narg('order_by') = 'workload_asc' THEN w.name END ASC,
    CASE WHEN sqlc.narg('order_by') = 'workload_desc' THEN w.name END DESC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_asc' THEN namespace END ASC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_desc' THEN namespace END DESC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_asc' THEN cluster END ASC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_desc' THEN cluster END DESC,
    CASE WHEN sqlc.narg('order_by') = 'critical_asc' THEN v.critical END ASC,
    CASE WHEN sqlc.narg('order_by') = 'critical_desc' THEN v.critical END DESC,
    CASE WHEN sqlc.narg('order_by') = 'high_asc' THEN v.high END ASC,
    CASE WHEN sqlc.narg('order_by') = 'high_desc' THEN v.high END DESC,
    CASE WHEN sqlc.narg('order_by') = 'medium_asc' THEN v.medium END ASC,
    CASE WHEN sqlc.narg('order_by') = 'medium_desc' THEN v.medium END DESC,
    CASE WHEN sqlc.narg('order_by') = 'low_asc' THEN v.low END ASC,
    CASE WHEN sqlc.narg('order_by') = 'low_desc' THEN v.low END DESC,
    CASE WHEN sqlc.narg('order_by') = 'unassigned_asc' THEN v.unassigned END ASC,
    CASE WHEN sqlc.narg('order_by') = 'unassigned_desc' THEN v.unassigned END DESC,
    CASE WHEN sqlc.narg('order_by') = 'risk_score_asc' THEN v.risk_score END ASC,
    CASE WHEN sqlc.narg('order_by') = 'risk_score_desc' THEN v.risk_score END DESC,
 v.id ASC
LIMIT
    sqlc.arg('limit')
OFFSET
    sqlc.arg('offset')
;

-- name: CountVulnerabilitySummaries :one
SELECT COUNT(*) AS total
FROM workloads w
         LEFT JOIN vulnerability_summary v
                   ON w.image_name = v.image_name AND w.image_tag = v.image_tag
WHERE
    (CASE WHEN sqlc.narg('cluster')::TEXT is not null THEN w.cluster = sqlc.narg('cluster')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('namespace')::TEXT is not null THEN w.namespace = sqlc.narg('namespace')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_type')::TEXT is not null THEN w.workload_type = sqlc.narg('workload_type')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_name')::TEXT is not null THEN w.name = sqlc.narg('workload_name')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('image_name')::TEXT is not null THEN v.image_name = sqlc.narg('image_name')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('image_tag')::TEXT is not null THEN v.image_tag = sqlc.narg('image_tag')::TEXT ELSE TRUE END)
;

-- name: ListVulnerabilitySummaryHistory :many
SELECT
    w.id,
    w.name AS workload_name,
    w.workload_type,
    w.namespace,
    w.cluster,
    w.image_name,
    w.image_tag,
    v.critical,
    v.high,
    v.medium,
    v.low,
    v.unassigned,
    v.risk_score,
    w.created_at AS workload_created_at,
    w.updated_at AS workload_updated_at,
    v.created_at AS summary_created_at,
    v.updated_at AS summary_updated_at,
    CASE WHEN v.image_name IS NOT NULL THEN TRUE ELSE FALSE END AS has_sbom
FROM workloads w
         LEFT JOIN vulnerability_summary v
                   ON w.image_name = v.image_name
WHERE
  v.updated_at > sqlc.arg('from')::TIMESTAMP WITH TIME ZONE
  AND (CASE WHEN sqlc.narg('cluster')::TEXT is not null THEN w.cluster = sqlc.narg('cluster')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('namespace')::TEXT is not null THEN w.namespace = sqlc.narg('namespace')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_type')::TEXT is not null THEN w.workload_type = sqlc.narg('workload_type')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_name')::TEXT is not null THEN w.name = sqlc.narg('workload_name')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('image_name')::TEXT is not null THEN v.image_name = sqlc.narg('image_name')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('image_tag')::TEXT is not null THEN v.image_tag = sqlc.narg('image_tag')::TEXT ELSE TRUE END)
ORDER BY
    CASE WHEN sqlc.narg('order_by') = 'workload_asc' THEN w.name END ASC,
    CASE WHEN sqlc.narg('order_by') = 'workload_desc' THEN w.name END DESC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_asc' THEN namespace END ASC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_desc' THEN namespace END DESC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_asc' THEN cluster END ASC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_desc' THEN cluster END DESC,
    CASE WHEN sqlc.narg('order_by') = 'critical_asc' THEN v.critical END ASC,
    CASE WHEN sqlc.narg('order_by') = 'critical_desc' THEN v.critical END DESC,
    CASE WHEN sqlc.narg('order_by') = 'high_asc' THEN v.high END ASC,
    CASE WHEN sqlc.narg('order_by') = 'high_desc' THEN v.high END DESC,
    CASE WHEN sqlc.narg('order_by') = 'medium_asc' THEN v.medium END ASC,
    CASE WHEN sqlc.narg('order_by') = 'medium_desc' THEN v.medium END DESC,
    CASE WHEN sqlc.narg('order_by') = 'low_asc' THEN v.low END ASC,
    CASE WHEN sqlc.narg('order_by') = 'low_desc' THEN v.low END DESC,
    CASE WHEN sqlc.narg('order_by') = 'unassigned_asc' THEN v.unassigned END ASC,
    CASE WHEN sqlc.narg('order_by') = 'unassigned_desc' THEN v.unassigned END DESC,
    CASE WHEN sqlc.narg('order_by') = 'risk_score_asc' THEN v.risk_score END ASC,
    CASE WHEN sqlc.narg('order_by') = 'risk_score_desc' THEN v.risk_score END DESC,
    v.updated_at DESC, v.id DESC
    LIMIT
    sqlc.arg('limit')
OFFSET
    sqlc.arg('offset')
;

-- name: CountVulnerabilitySummaryHistory :one
SELECT COUNT(*) AS total
FROM workloads w
         LEFT JOIN vulnerability_summary v
                   ON w.image_name = v.image_name
WHERE
    (CASE WHEN sqlc.narg('cluster')::TEXT is not null THEN w.cluster = sqlc.narg('cluster')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('namespace')::TEXT is not null THEN w.namespace = sqlc.narg('namespace')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_type')::TEXT is not null THEN w.workload_type = sqlc.narg('workload_type')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_name')::TEXT is not null THEN w.name = sqlc.narg('workload_name')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('image_name')::TEXT is not null THEN v.image_name = sqlc.narg('image_name')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('image_tag')::TEXT is not null THEN v.image_tag = sqlc.narg('image_tag')::TEXT ELSE TRUE END)
;

-- name: GetVulnerabilitySummary :one
WITH filtered_workloads AS (
    SELECT w.id, w.image_name, w.image_tag
    FROM workloads w
    WHERE
        (sqlc.narg('cluster')::TEXT IS NULL OR w.cluster = sqlc.narg('cluster')::TEXT)
      AND (sqlc.narg('namespace')::TEXT IS NULL OR w.namespace = sqlc.narg('namespace')::TEXT)
      AND (sqlc.narg('workload_type')::TEXT IS NULL OR w.workload_type = sqlc.narg('workload_type')::TEXT)
      AND (sqlc.narg('workload_name')::TEXT IS NULL OR w.name = sqlc.narg('workload_name')::TEXT)
)
SELECT
    CAST(COUNT(DISTINCT fw.id) AS INT4) AS workload_count,
    CAST(COUNT(DISTINCT CASE WHEN v.image_name IS NOT NULL THEN fw.id END) AS INT4) AS workload_with_sbom,
    CAST(COALESCE(SUM(v.critical), 0) AS INT4) AS critical_vulnerabilities,
    CAST(COALESCE(SUM(v.high), 0) AS INT4) AS high_vulnerabilities,
    CAST(COALESCE(SUM(v.medium), 0) AS INT4) AS medium_vulnerabilities,
    CAST(COALESCE(SUM(v.low), 0) AS INT4) AS low_vulnerabilities,
    CAST(COALESCE(SUM(v.unassigned), 0) AS INT4) AS unassigned_vulnerabilities,
    CAST(COALESCE(SUM(v.risk_score), 0) AS INT4) AS total_risk_score
FROM filtered_workloads fw
         LEFT JOIN vulnerability_summary v
                   ON fw.image_name = v.image_name AND fw.image_tag = v.image_tag;

-- name: GetVulnerabilitySummaryForImage :one
SELECT * FROM vulnerability_summary
WHERE image_name = @image_name
  AND image_tag = @image_tag;
