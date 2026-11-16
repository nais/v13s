-- name: ListImagePackageTypes :many
SELECT
    split_part(split_part(v.package, '/', 1), ':', 2)::TEXT AS value,
    COUNT(DISTINCT (v.package, c.cve_id))::BIGINT AS count
FROM
    vulnerabilities v
    LEFT JOIN cve_alias ca ON ca.alias = v.cve_id
    JOIN cve c ON c.cve_id = COALESCE(ca.canonical_cve_id, v.cve_id)
    LEFT JOIN suppressed_vulnerabilities sv ON sv.image_name = v.image_name
        AND sv.package = v.package
        AND sv.cve_id = c.cve_id
WHERE
    v.image_name = sqlc.arg('image_name')::TEXT
    AND v.image_tag = sqlc.arg('image_tag')::TEXT
    AND v.package ~ '^pkg:[a-z][a-z0-9.+-]*/'
    AND (sqlc.narg('package_type')::TEXT IS NULL
        OR starts_with(v.package, 'pkg:' || sqlc.narg('package_type')::TEXT || '/'))
    AND (sqlc.narg('include_suppressed')::BOOLEAN IS TRUE
        OR COALESCE(sv.suppressed, FALSE) = FALSE)
    AND (sqlc.narg('since')::TIMESTAMPTZ IS NULL
        OR v.severity_since > sqlc.narg('since')::TIMESTAMPTZ)
    AND (sqlc.narg('severity')::INT IS NULL
        OR c.severity = sqlc.narg('severity')::INT)
    AND (sqlc.narg('risk_tiers')::INT[] IS NULL
        OR c.priority = ANY (sqlc.narg('risk_tiers')::INT[]))
    AND (sqlc.narg('has_kev')::BOOL IS NULL
        OR c.has_kev_entry = sqlc.narg('has_kev')::BOOL)
GROUP BY
    value
ORDER BY
    value;

-- name: ListWorkloadPackageTypes :many
WITH scoped_images AS (
    SELECT DISTINCT
        w.image_name,
        w.image_tag
    FROM
        workloads w
    WHERE (sqlc.narg('cluster')::TEXT IS NULL
        OR w.cluster = sqlc.narg('cluster')::TEXT)
    AND (sqlc.narg('namespace')::TEXT IS NULL
        OR w.namespace = sqlc.narg('namespace')::TEXT)
    AND (sqlc.narg('workload_types')::TEXT[] IS NULL
        OR w.workload_type = ANY (sqlc.narg('workload_types')::TEXT[]))
    AND (sqlc.narg('workload_name')::TEXT IS NULL
        OR w.name = sqlc.narg('workload_name')::TEXT)
    AND (sqlc.narg('image_name')::TEXT IS NULL
        OR w.image_name = sqlc.narg('image_name')::TEXT)
    AND (sqlc.narg('image_tag')::TEXT IS NULL
        OR w.image_tag = sqlc.narg('image_tag')::TEXT)
    AND NOT EXISTS (
        SELECT
            1
        FROM
            jsonb_to_recordset(COALESCE(sqlc.narg('label_filters')::JSONB, '[]'::JSONB)) AS f(key TEXT,
                value TEXT)
        WHERE
            NOT (w.labels ? f.key)
            OR (f.value IS NOT NULL
                AND w.labels ->> f.key IS DISTINCT FROM f.value)))
SELECT
    split_part(split_part(v.package, '/', 1), ':', 2)::TEXT AS value,
    COUNT(DISTINCT (v.image_name, v.image_tag, v.package, c.cve_id))::BIGINT AS count
FROM
    scoped_images i
    JOIN vulnerabilities v ON v.image_name = i.image_name
        AND v.image_tag = i.image_tag
    LEFT JOIN cve_alias ca ON ca.alias = v.cve_id
    JOIN cve c ON c.cve_id = COALESCE(ca.canonical_cve_id, v.cve_id)
WHERE
    v.package ~ '^pkg:[a-z][a-z0-9.+-]*/'
GROUP BY
    value
ORDER BY
    value;
