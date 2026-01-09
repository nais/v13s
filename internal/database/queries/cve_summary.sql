-- name: ListCveSummaries :many
WITH cve_data AS (
    SELECT
        c.*,
        COUNT(DISTINCT w.id)::INT AS affected_workloads
    FROM
        vulnerabilities v
        JOIN cve c ON v.cve_id = c.cve_id
        JOIN workloads w ON w.image_name = v.image_name
            AND w.image_tag = v.image_tag
    WHERE (sqlc.narg('cluster')::TEXT IS NULL
        OR w.cluster = sqlc.narg('cluster')::TEXT)
    AND (sqlc.narg('namespace')::TEXT IS NULL
        OR w.namespace = sqlc.narg('namespace')::TEXT)
    AND (sqlc.narg('workload_type')::TEXT IS NULL
        OR w.workload_type = sqlc.narg('workload_type')::TEXT)
    AND (sqlc.narg('workload_name')::TEXT IS NULL
        OR w.name = sqlc.narg('workload_name')::TEXT)
    AND (sqlc.narg('image_name')::TEXT IS NULL
        OR v.image_name = sqlc.narg('image_name')::TEXT)
    AND (sqlc.narg('image_tag')::TEXT IS NULL
        OR v.image_tag = sqlc.narg('image_tag')::TEXT)
    AND (sqlc.narg('include_management_cluster')::BOOLEAN IS TRUE
        OR w.cluster != 'management')
GROUP BY
    c.cve_id
)
SELECT
    *,
    COUNT(*) OVER ()::INT AS total_count
FROM
    cve_data
ORDER BY
    CASE WHEN sqlc.narg('order_by') = 'cvss_score_desc' THEN
        CASE WHEN cvss_score = 0
            OR cvss_score IS NULL THEN
            1
        ELSE
            0
        END
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'cvss_score_desc' THEN
        cvss_score
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'cvss_score_asc' THEN
        cvss_score
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'affected_workloads_desc' THEN
        affected_workloads
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'affected_workloads_asc' THEN
        affected_workloads
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'cve_id_asc' THEN
        cve_id
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'cve_id_desc' THEN
        cve_id
    END DESC
LIMIT sqlc.arg('limit')
    OFFSET sqlc.arg('offset');
