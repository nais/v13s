-- name: ListCveSummaries :many
WITH cve_data AS (
    SELECT
        c.*,
        COUNT(DISTINCT w.id)::INT AS affected_workloads
    FROM
        vulnerabilities v
        LEFT JOIN cve_alias ca ON v.cve_id = ca.alias
        JOIN cve c ON c.cve_id = COALESCE(ca.canonical_cve_id, v.cve_id)
        JOIN workloads w ON w.image_name = v.image_name
            AND w.image_tag = v.image_tag
        JOIN images i ON i.name = w.image_name
            AND i.tag = w.image_tag
        LEFT JOIN suppressed_vulnerabilities sv ON v.image_name = sv.image_name
            AND v.package = sv.package
            AND COALESCE(ca.canonical_cve_id, v.cve_id) = sv.cve_id
    WHERE
        workload_has_usable_sbom(w.state, i.state)
        AND (sqlc.narg('cluster')::TEXT IS NULL
            OR w.cluster = sqlc.narg('cluster')::TEXT)
        AND (sqlc.narg('namespace')::TEXT IS NULL
            OR w.namespace = sqlc.narg('namespace')::TEXT)
        AND (cardinality(sqlc.arg('exclude_namespaces')::TEXT[]) = 0
            OR w.namespace <> ALL (sqlc.arg('exclude_namespaces')::TEXT[]))
        AND (sqlc.narg('workload_types')::TEXT[] IS NULL
            OR w.workload_type = ANY (sqlc.narg('workload_types')::TEXT[]))
        AND (sqlc.narg('workload_name')::TEXT IS NULL
            OR w.name = sqlc.narg('workload_name')::TEXT)
        AND (sqlc.narg('image_name')::TEXT IS NULL
            OR v.image_name = sqlc.narg('image_name')::TEXT)
        AND (sqlc.narg('image_tag')::TEXT IS NULL
            OR v.image_tag = sqlc.narg('image_tag')::TEXT)
        AND (cardinality(sqlc.arg('exclude_clusters')::TEXT[]) = 0
            OR w.cluster <> ALL (sqlc.arg('exclude_clusters')::TEXT[]))
        AND (sqlc.narg('include_suppressed')::BOOLEAN IS TRUE
            OR COALESCE(sv.suppressed, FALSE) = FALSE)
        AND (sqlc.narg('priorities')::INT[] IS NULL
            OR COALESCE(c.priority, 4) = ANY (sqlc.narg('priorities')::INT[]))
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
        CASE WHEN cvss_score = 0
            OR cvss_score IS NULL THEN
            1
        ELSE
            0
        END
    END ASC,
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
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'severity_asc' THEN
        severity
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'severity_desc' THEN
        severity
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'priority_asc' THEN
        COALESCE(priority, 4)
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'priority_desc' THEN
        COALESCE(priority, 4)
    END DESC,
    severity ASC,
    cve_id ASC
LIMIT sqlc.arg('limit')
    OFFSET sqlc.arg('offset');

-- name: ListCveSummariesFromCounts :many
WITH cve_counts AS (
    SELECT
        m.cve_id,
        SUM(
            CASE WHEN sqlc.narg('include_suppressed')::BOOLEAN IS TRUE THEN
                m.affected_workloads
            ELSE
                m.unsuppressed_workloads
            END)::INT AS affected_workloads
    FROM
        mv_cve_workload_counts m
    WHERE (sqlc.narg('cluster')::TEXT IS NULL
        OR m.cluster = sqlc.narg('cluster')::TEXT)
    AND (sqlc.narg('namespace')::TEXT IS NULL
        OR m.namespace = sqlc.narg('namespace')::TEXT)
    AND (cardinality(sqlc.arg('exclude_namespaces')::TEXT[]) = 0
        OR m.namespace <> ALL (sqlc.arg('exclude_namespaces')::TEXT[]))
    AND (sqlc.narg('workload_types')::TEXT[] IS NULL
        OR m.workload_type = ANY (sqlc.narg('workload_types')::TEXT[]))
    AND (cardinality(sqlc.arg('exclude_clusters')::TEXT[]) = 0
        OR m.cluster <> ALL (sqlc.arg('exclude_clusters')::TEXT[]))
GROUP BY
    m.cve_id
),
ranked AS (
    SELECT
        cc.cve_id,
        cc.affected_workloads,
        ROW_NUMBER() OVER (ORDER BY CASE WHEN sqlc.narg('order_by') = 'cvss_score_desc' THEN
                CASE WHEN c.cvss_score = 0
                    OR c.cvss_score IS NULL THEN
                    1
                ELSE
                    0
                END
            END ASC,
            CASE WHEN sqlc.narg('order_by') = 'cvss_score_desc' THEN
                c.cvss_score
            END DESC,
            CASE WHEN sqlc.narg('order_by') = 'cvss_score_asc' THEN
                CASE WHEN c.cvss_score = 0
                    OR c.cvss_score IS NULL THEN
                    1
                ELSE
                    0
                END
            END ASC,
            CASE WHEN sqlc.narg('order_by') = 'cvss_score_asc' THEN
                c.cvss_score
            END ASC,
            CASE WHEN sqlc.narg('order_by') = 'affected_workloads_desc' THEN
                cc.affected_workloads
            END DESC,
            CASE WHEN sqlc.narg('order_by') = 'affected_workloads_asc' THEN
                cc.affected_workloads
            END ASC,
            CASE WHEN sqlc.narg('order_by') = 'cve_id_asc' THEN
                c.cve_id
            END ASC,
            CASE WHEN sqlc.narg('order_by') = 'cve_id_desc' THEN
                c.cve_id
            END DESC,
            CASE WHEN sqlc.narg('order_by') = 'severity_asc' THEN
                c.severity
            END ASC,
            CASE WHEN sqlc.narg('order_by') = 'severity_desc' THEN
                c.severity
            END DESC,
            CASE WHEN sqlc.narg('order_by') = 'priority_asc' THEN
                COALESCE(c.priority, 4)
            END ASC,
            CASE WHEN sqlc.narg('order_by') = 'priority_desc' THEN
                COALESCE(c.priority, 4)
            END DESC,
            c.severity ASC,
            c.cve_id ASC)::INT AS row_number,
        COUNT(*) OVER ()::INT AS total_count
    FROM
        cve_counts cc
        JOIN cve c ON c.cve_id = cc.cve_id
    WHERE
        cc.affected_workloads > 0
        AND (sqlc.narg('priorities')::INT[] IS NULL
            OR COALESCE(c.priority, 4) = ANY (sqlc.narg('priorities')::INT[])))
SELECT
    c.*,
    r.affected_workloads,
    r.total_count
FROM
    ranked r
    JOIN cve c ON c.cve_id = r.cve_id
WHERE
    r.row_number > sqlc.arg('offset')::INT
    AND r.row_number <= sqlc.arg('offset')::INT + sqlc.arg('limit')::INT
ORDER BY
    r.row_number;

-- name: RefreshCveWorkloadCounts :exec
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_cve_workload_counts;
