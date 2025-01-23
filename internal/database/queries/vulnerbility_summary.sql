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
    v.created_at AS vulnerability_created_at,
    v.updated_at AS vulnerability_updated_at
FROM workloads w
         LEFT JOIN vulnerability_summary v
                   ON w.image_name = v.image_name AND w.image_tag = v.image_tag
WHERE
    (CASE WHEN sqlc.narg('cluster')::TEXT is not null THEN w.cluster = sqlc.narg('cluster')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('namespace')::TEXT is not null THEN w.namespace = sqlc.narg('namespace')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_type')::TEXT is not null THEN w.workload_type = sqlc.narg('workload_type')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_name')::TEXT is not null THEN w.name = sqlc.narg('workload_name')::TEXT ELSE TRUE END)
ORDER BY w.updated_at DESC
LIMIT
    sqlc.arg('limit')
OFFSET
    sqlc.arg('offset')
;

-- name: GetVulnerabilitySummary :one
SELECT
    CAST(COUNT(w.id) AS INT4) AS total_workloads,
    CAST(COALESCE(SUM(v.critical), 0) AS INT4) AS critical_vulnerabilities,
    CAST(COALESCE(SUM(v.high), 0) AS INT4) AS high_vulnerabilities,
    CAST(COALESCE(SUM(v.medium), 0) AS INT4) AS medium_vulnerabilities,
    CAST(COALESCE(SUM(v.low), 0) AS INT4) AS low_vulnerabilities,
    CAST(COALESCE(SUM(v.unassigned), 0) AS INT4) AS unassigned_vulnerabilities,
    CAST(COALESCE(SUM(v.risk_score), 0) AS INT4) AS total_risk_score,
    TO_CHAR(COALESCE(MAX(v.updated_at), '1970-01-01 00:00:00'), 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS vulnerability_updated_at
FROM workloads w
         LEFT JOIN vulnerability_summary v
                   ON w.image_name = v.image_name AND w.image_tag = v.image_tag
WHERE
    (CASE WHEN sqlc.narg('cluster')::TEXT IS NOT NULL THEN w.cluster = sqlc.narg('cluster')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('namespace')::TEXT IS NOT NULL THEN w.namespace = sqlc.narg('namespace')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_type')::TEXT IS NOT NULL THEN w.workload_type = sqlc.narg('workload_type')::TEXT ELSE TRUE END)
  AND (CASE WHEN sqlc.narg('workload_name')::TEXT IS NOT NULL THEN w.name = sqlc.narg('workload_name')::TEXT ELSE TRUE END);
