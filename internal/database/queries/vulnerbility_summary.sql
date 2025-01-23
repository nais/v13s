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

-- name: ListVulnerabilitySummary :many
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