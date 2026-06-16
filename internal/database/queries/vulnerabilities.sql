-- name: RecalculateVulnerabilitySummary :exec
WITH resolved_vulnerabilities AS (
    SELECT DISTINCT
        c.cve_id AS id,
        c.severity,
        c.epss_percentile,
        c.has_kev_entry,
        c.known_ransomware_use,
        v.package,
        v.image_name,
        v.image_tag
    FROM
        vulnerabilities v
        LEFT JOIN cve_alias ca ON v.cve_id = ca.alias
        JOIN cve c ON c.cve_id = COALESCE(ca.canonical_cve_id, v.cve_id)
    WHERE
        v.image_name = @image_name
        AND v.image_tag = @image_tag
),
unsuppressed_vulnerabilities AS (
    SELECT
        rv.id,
        rv.severity,
        rv.epss_percentile,
        rv.has_kev_entry,
        rv.known_ransomware_use
    FROM
        resolved_vulnerabilities rv
        LEFT JOIN suppressed_vulnerabilities sv ON rv.image_name = sv.image_name
            AND rv.package = sv.package
            AND rv.id = sv.cve_id
    WHERE
        NOT COALESCE(sv.suppressed, FALSE)
),
counts AS (
    SELECT
        COUNT(*) FILTER (WHERE severity = 0) AS critical,
    COUNT(*) FILTER (WHERE severity = 1) AS high,
    COUNT(*) FILTER (WHERE severity = 2) AS medium,
    COUNT(*) FILTER (WHERE severity = 3) AS low,
    COUNT(*) FILTER (WHERE severity = 4) AS unassigned,
    COUNT(*) FILTER (WHERE has_kev_entry = TRUE) AS act_now,
    COUNT(*) FILTER (WHERE has_kev_entry = FALSE
        AND (known_ransomware_use = TRUE
        OR COALESCE(epss_percentile, 0) >= 0.90)) AS high_risk,
COUNT(*) FILTER (WHERE has_kev_entry = FALSE
    AND NOT (known_ransomware_use = TRUE
    OR COALESCE(epss_percentile, 0) >= 0.90)
AND severity IN (0, 1)
AND COALESCE(epss_percentile, 0) >= 0.50) AS elevated_risk,
COUNT(*) FILTER (WHERE NOT (has_kev_entry = TRUE
    OR known_ransomware_use = TRUE
    OR COALESCE(epss_percentile, 0) >= 0.90
    OR (severity IN (0, 1)
    AND COALESCE(epss_percentile, 0) >= 0.50))) AS monitor,
COUNT(*) FILTER (WHERE known_ransomware_use = TRUE) AS ransomware_count,
COUNT(*) FILTER (WHERE epss_percentile >= 0.90) AS high_epss_count,
MIN(
    CASE WHEN has_kev_entry = TRUE THEN
        1
    WHEN known_ransomware_use = TRUE
        OR COALESCE(epss_percentile, 0) >= 0.90 THEN
        2
    WHEN severity IN (0, 1)
        AND COALESCE(epss_percentile, 0) >= 0.50 THEN
        3
    ELSE
        4
    END) AS top_risk_tier
FROM
    unsuppressed_vulnerabilities)
INSERT INTO vulnerability_summary(
    image_name,
    image_tag,
    critical,
    high,
    medium,
    low,
    unassigned,
    act_now,
    high_risk,
    elevated_risk,
    monitor,
    ransomware_count,
    high_epss_count,
    top_risk_tier,
    risk_score,
    created_at,
    updated_at)
SELECT
    @image_name,
    @image_tag,
    critical,
    high,
    medium,
    low,
    unassigned,
    act_now,
    high_risk,
    elevated_risk,
    monitor,
    ransomware_count,
    high_epss_count,
    top_risk_tier,
    10 * critical + 5 * high + 3 * medium + 1 * low + 5 * unassigned AS risk_score,
    NOW(),
    NOW()
FROM
    counts
ON CONFLICT (image_name,
    image_tag)
    DO UPDATE SET
        critical = EXCLUDED.critical,
        high = EXCLUDED.high,
        medium = EXCLUDED.medium,
        low = EXCLUDED.low,
        unassigned = EXCLUDED.unassigned,
        act_now = EXCLUDED.act_now,
        high_risk = EXCLUDED.high_risk,
        elevated_risk = EXCLUDED.elevated_risk,
        monitor = EXCLUDED.monitor,
        ransomware_count = EXCLUDED.ransomware_count,
        high_epss_count = EXCLUDED.high_epss_count,
        top_risk_tier = EXCLUDED.top_risk_tier,
        risk_score = EXCLUDED.risk_score,
        updated_at = NOW();

-- name: BatchUpsertCve :batchexec
INSERT INTO cve(
    cve_id,
    cve_title,
    cve_desc,
    cve_link,
    severity,
    refs,
    cvss_score,
    epss_score,
    epss_percentile)
VALUES (
    @cve_id,
    @cve_title,
    @cve_desc,
    @cve_link,
    @severity,
    @refs,
    @cvss_score,
    @epss_score,
    @epss_percentile)
ON CONFLICT (
    cve_id)
    DO UPDATE SET
        cve_title = EXCLUDED.cve_title,
        cve_desc = EXCLUDED.cve_desc,
        cve_link = EXCLUDED.cve_link,
        severity = EXCLUDED.severity,
        refs = EXCLUDED.refs,
        cvss_score = EXCLUDED.cvss_score,
        epss_score = EXCLUDED.epss_score,
        epss_percentile = EXCLUDED.epss_percentile,
        updated_at = NOW()
    WHERE
        cve.cve_title IS DISTINCT FROM EXCLUDED.cve_title
        OR cve.cve_desc IS DISTINCT FROM EXCLUDED.cve_desc
        OR cve.cve_link IS DISTINCT FROM EXCLUDED.cve_link
        OR cve.severity IS DISTINCT FROM EXCLUDED.severity
        OR cve.refs IS DISTINCT FROM EXCLUDED.refs
        OR cve.cvss_score IS DISTINCT FROM EXCLUDED.cvss_score
        OR cve.epss_score IS DISTINCT FROM EXCLUDED.epss_score
        OR cve.epss_percentile IS DISTINCT FROM EXCLUDED.epss_percentile;

-- name: BatchUpsertCveAlias :batchexec
INSERT INTO cve_alias(
    alias,
    canonical_cve_id)
VALUES (
    @alias,
    @canonical_cve_id)
ON CONFLICT (
    alias)
    DO UPDATE SET
        canonical_cve_id = EXCLUDED.canonical_cve_id
    WHERE
        cve_alias.canonical_cve_id IS DISTINCT FROM EXCLUDED.canonical_cve_id;

-- name: BatchUpsertVulnerabilities :batchexec
INSERT INTO vulnerabilities(
    image_name,
    image_tag,
    package,
    cve_id,
    source,
    latest_version,
    last_severity,
    severity_since,
    cvss_score)
VALUES (
    @image_name,
    @image_tag,
    @package,
    @cve_id,
    @source,
    @latest_version,
    @last_severity,
    COALESCE(
        @severity_since::TIMESTAMPTZ, NOW()),
    @cvss_score)
ON CONFLICT (
    image_name,
    image_tag,
    package,
    cve_id)
    DO UPDATE SET
        latest_version = EXCLUDED.latest_version,
        updated_at = NOW(),
        last_severity = EXCLUDED.last_severity,
        cvss_score = EXCLUDED.cvss_score,
        severity_since = CASE WHEN EXCLUDED.last_severity <> vulnerabilities.last_severity THEN
            COALESCE(EXCLUDED.severity_since, NOW())
        ELSE
            vulnerabilities.severity_since
        END;

-- name: GetEarliestSeveritySinceForVulnerability :one
SELECT
    (COALESCE((
            SELECT
                MIN(v1.severity_since)
            FROM vulnerabilities v1
            WHERE
                v1.image_name = $1
                AND v1.package = $2
                AND v1.cve_id = $3
                AND v1.last_severity = $4
                AND v1.severity_since IS NOT NULL),(
                SELECT
                    MIN(v2.created_at)
                FROM vulnerabilities v2
                WHERE
                    v2.image_name = $1
                    AND v2.package = $2
                    AND v2.cve_id = $3
                    AND v2.last_severity = $4))::TIMESTAMPTZ) AS earliest_severity_since;

-- name: GetCve :one
SELECT
    *
FROM
    cve
WHERE
    cve_id = @cve_id;

-- name: GetAliasesByCanonicalCveId :many
SELECT
    alias
FROM
    cve_alias
WHERE
    canonical_cve_id = @canonical_cve_id
ORDER BY
    alias;

-- name: GetVulnerability :one
SELECT
    v.id,
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
    sv.updated_at AS suppressed_at,
    v.fix_version,
    c.cvss_score,
    c.epss_score,
    c.epss_percentile,
    c.has_kev_entry,
    c.known_ransomware_use,
    c.priority
FROM
    vulnerabilities v
    LEFT JOIN cve_alias ca ON v.cve_id = ca.alias
    JOIN cve c ON c.cve_id = COALESCE(ca.canonical_cve_id, v.cve_id)
    LEFT JOIN suppressed_vulnerabilities sv ON v.image_name = sv.image_name
        AND v.package = sv.package
        AND COALESCE(ca.canonical_cve_id, v.cve_id) = sv.cve_id
WHERE
    v.image_name = @image_name
    AND v.image_tag = @image_tag
    AND v.package = @package
    AND v.cve_id = @cve_id;

-- name: GetVulnerabilityById :one
SELECT
    v.id,
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
    sv.updated_at AS suppressed_at,
    v.fix_version,
    c.cvss_score,
    c.epss_score,
    c.epss_percentile,
    c.has_kev_entry,
    c.known_ransomware_use,
    c.priority
FROM
    vulnerabilities v
    LEFT JOIN cve_alias ca ON v.cve_id = ca.alias
    JOIN cve c ON c.cve_id = COALESCE(ca.canonical_cve_id, v.cve_id)
    LEFT JOIN suppressed_vulnerabilities sv ON v.image_name = sv.image_name
        AND v.package = sv.package
        AND COALESCE(ca.canonical_cve_id, v.cve_id) = sv.cve_id
WHERE
    v.id = @id;

-- name: ListWorkloadsForVulnerabilityById :many
SELECT
    w.id,
    w.cluster,
    w.namespace,
    w.name,
    w.workload_type,
    w.image_name,
    w.image_tag
FROM
    workloads w
    JOIN vulnerabilities v ON v.image_name = w.image_name
        AND v.image_tag = w.image_tag
WHERE
    v.id = @vulnerability_id
ORDER BY
    w.cluster,
    w.namespace,
    w.name;

-- name: SuppressVulnerability :exec
INSERT INTO suppressed_vulnerabilities(
    image_name,
    package,
    cve_id,
    suppressed,
    suppressed_by,
    reason,
    reason_text)
VALUES (
    @image_name,
    @package,
    @cve_id,
    @suppressed,
    @suppressed_by,
    @reason,
    @reason_text)
ON CONFLICT ON CONSTRAINT image_name_package_cve_id
    DO UPDATE SET
        suppressed = EXCLUDED.suppressed,
        suppressed_by = EXCLUDED.suppressed_by,
        reason = EXCLUDED.reason,
        reason_text = EXCLUDED.reason_text,
        updated_at = NOW()
    WHERE
        suppressed_vulnerabilities.suppressed IS DISTINCT FROM EXCLUDED.suppressed
        OR suppressed_vulnerabilities.suppressed_by IS DISTINCT FROM EXCLUDED.suppressed_by
        OR suppressed_vulnerabilities.reason IS DISTINCT FROM EXCLUDED.reason
        OR suppressed_vulnerabilities.reason_text IS DISTINCT FROM EXCLUDED.reason_text;

-- name: RekeySuppressedAliasesToCanonical :execrows
INSERT INTO suppressed_vulnerabilities(
    image_name,
    package,
    cve_id,
    suppressed,
    suppressed_by,
    reason,
    reason_text,
    created_at,
    updated_at)
SELECT
    sv.image_name,
    sv.package,
    ca.canonical_cve_id AS cve_id,
    sv.suppressed,
    sv.suppressed_by,
    sv.reason,
    sv.reason_text,
    sv.created_at,
    NOW()
FROM
    suppressed_vulnerabilities sv
    JOIN cve_alias ca ON ca.alias = sv.cve_id
WHERE
    sv.suppressed = TRUE
    AND ca.alias <> ca.canonical_cve_id
ON CONFLICT ON CONSTRAINT image_name_package_cve_id
    DO UPDATE SET
        suppressed = EXCLUDED.suppressed,
        suppressed_by = EXCLUDED.suppressed_by,
        reason = EXCLUDED.reason,
        reason_text = EXCLUDED.reason_text,
        updated_at = NOW()
    WHERE
        suppressed_vulnerabilities.suppressed IS DISTINCT FROM EXCLUDED.suppressed
        OR suppressed_vulnerabilities.suppressed_by IS DISTINCT FROM EXCLUDED.suppressed_by
        OR suppressed_vulnerabilities.reason IS DISTINCT FROM EXCLUDED.reason
        OR suppressed_vulnerabilities.reason_text IS DISTINCT FROM EXCLUDED.reason_text;

-- name: GetImagesForCveAndWorkloads :many
SELECT DISTINCT
    v.image_name,
    v.image_tag,
    v.package,
    w.name AS workload_name,
    w.cluster AS workload_cluster,
    w.namespace AS workload_namespace,
    w.workload_type
FROM
    vulnerabilities v
    JOIN workloads w ON v.image_name = w.image_name
        AND v.image_tag = w.image_tag
    LEFT JOIN cve_alias ca ON v.cve_id = ca.alias
    JOIN (
        SELECT
            unnest(@clusters::TEXT[]) AS c,
            unnest(@namespaces::TEXT[]) AS ns,
            unnest(@names::TEXT[]) AS n,
            unnest(@workload_types::TEXT[]) AS wt,
            generate_series(1, array_length(@clusters::TEXT[], 1)) AS ord) AS wl ON w.cluster = wl.c
        AND w.namespace = wl.ns
        AND w.name = wl.n
        AND w.workload_type = wl.wt
WHERE
    COALESCE(ca.canonical_cve_id, v.cve_id) = @cve_id
ORDER BY
    v.image_name,
    v.image_tag,
    v.package;

-- name: ListSuppressedVulnerabilities :many
SELECT
    sv.*,
    v.*,
    c.*,
    w.cluster,
    w.namespace
FROM
    suppressed_vulnerabilities sv
    JOIN vulnerabilities v ON sv.image_name = v.image_name
        AND sv.package = v.package
        AND sv.cve_id = v.cve_id
    JOIN cve c ON v.cve_id = c.cve_id
    JOIN workloads w ON v.image_name = w.image_name
        AND v.image_tag = w.image_tag
WHERE (
    CASE WHEN sqlc.narg('cluster')::TEXT IS NOT NULL THEN
        w.cluster = sqlc.narg('cluster')::TEXT
    ELSE
        TRUE
    END)
AND (
    CASE WHEN sqlc.narg('namespace')::TEXT IS NOT NULL THEN
        w.namespace = sqlc.narg('namespace')::TEXT
    ELSE
        TRUE
    END)
AND (
    CASE WHEN sqlc.narg('image_name')::TEXT IS NOT NULL THEN
        v.image_name = sqlc.narg('image_name')::TEXT
    ELSE
        TRUE
    END)
AND (
    CASE WHEN sqlc.narg('image_tag')::TEXT IS NOT NULL THEN
        v.image_tag = sqlc.narg('image_tag')::TEXT
    ELSE
        TRUE
    END)
ORDER BY
    CASE WHEN sqlc.narg('order_by') = 'severity_asc' THEN
        c.severity
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'severity_desc' THEN
        c.severity
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'workload_asc' THEN
        w.name
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'workload_desc' THEN
        w.name
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_asc' THEN
        w.namespace
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_desc' THEN
        w.namespace
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_asc' THEN
        w.cluster
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_desc' THEN
        w.cluster
    END DESC,
    v.id ASC
LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset');

-- name: CountSuppressedVulnerabilities :one
SELECT
    COUNT(*) AS total
FROM
    suppressed_vulnerabilities sv
    JOIN vulnerabilities v ON sv.image_name = v.image_name
        AND sv.package = v.package
        AND sv.cve_id = v.cve_id
    JOIN cve c ON v.cve_id = c.cve_id
    JOIN workloads w ON v.image_name = w.image_name
        AND v.image_tag = w.image_tag
WHERE (
    CASE WHEN sqlc.narg('cluster')::TEXT IS NOT NULL THEN
        w.cluster = sqlc.narg('cluster')::TEXT
    ELSE
        TRUE
    END)
AND (
    CASE WHEN sqlc.narg('namespace')::TEXT IS NOT NULL THEN
        w.namespace = sqlc.narg('namespace')::TEXT
    ELSE
        TRUE
    END)
AND (
    CASE WHEN sqlc.narg('workload_type')::TEXT IS NOT NULL THEN
        w.workload_type = sqlc.narg('workload_type')::TEXT
    ELSE
        TRUE
    END)
AND (
    CASE WHEN sqlc.narg('workload_name')::TEXT IS NOT NULL THEN
        w.name = sqlc.narg('workload_name')::TEXT
    ELSE
        TRUE
    END)
AND (
    CASE WHEN sqlc.narg('image_name')::TEXT IS NOT NULL THEN
        v.image_name = sqlc.narg('image_name')::TEXT
    ELSE
        TRUE
    END)
AND (
    CASE WHEN sqlc.narg('image_tag')::TEXT IS NOT NULL THEN
        v.image_tag = sqlc.narg('image_tag')::TEXT
    ELSE
        TRUE
    END);

-- name: CountVulnerabilities :one
SELECT
    COUNT(*) AS total
FROM
    vulnerabilities v
    LEFT JOIN cve_alias ca ON v.cve_id = ca.alias
    JOIN cve c ON c.cve_id = COALESCE(ca.canonical_cve_id, v.cve_id)
    JOIN workloads w ON v.image_name = w.image_name
        AND v.image_tag = w.image_tag
    LEFT JOIN suppressed_vulnerabilities sv ON v.image_name = sv.image_name
        AND v.package = sv.package
        AND COALESCE(ca.canonical_cve_id, v.cve_id) = sv.cve_id
WHERE (
    CASE WHEN sqlc.narg('cluster')::TEXT IS NOT NULL THEN
        w.cluster = sqlc.narg('cluster')::TEXT
    ELSE
        TRUE
    END)
AND (
    CASE WHEN sqlc.narg('namespace')::TEXT IS NOT NULL THEN
        w.namespace = sqlc.narg('namespace')::TEXT
    ELSE
        TRUE
    END)
AND (
    CASE WHEN sqlc.narg('workload_type')::TEXT IS NOT NULL THEN
        w.workload_type = sqlc.narg('workload_type')::TEXT
    ELSE
        TRUE
    END)
AND (
    CASE WHEN sqlc.narg('workload_name')::TEXT IS NOT NULL THEN
        w.name = sqlc.narg('workload_name')::TEXT
    ELSE
        TRUE
    END)
AND (sqlc.narg('include_suppressed')::BOOLEAN IS TRUE
    OR COALESCE(sv.suppressed, FALSE) = FALSE);

-- name: ListVulnerabilitiesForImage :many
WITH image_all_vulns AS (
    -- Only the vulnerabilities for this image/tag
    SELECT
        *
    FROM
        vulnerabilities v
    WHERE
        v.image_name = @image_name
        AND v.image_tag = @image_tag
),
resolved_vulnerabilities AS (
    SELECT
        COALESCE(ca.canonical_cve_id, v.cve_id)::TEXT AS cve_id,
        c.cve_title,
        c.cve_desc,
        c.cve_link,
        c.severity,
        c.refs::JSONB AS cve_refs,
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
        c.cvss_score,
        c.epss_score,
        c.epss_percentile,
        c.has_kev_entry,
        c.known_ransomware_use,
        c.priority,
        v.fix_version
    FROM
        image_all_vulns v
        LEFT JOIN cve_alias ca ON v.cve_id = ca.alias
        JOIN cve c ON c.cve_id = COALESCE(ca.canonical_cve_id, v.cve_id)
),
distinct_image_vulnerabilities AS (
    SELECT DISTINCT ON (v.image_name,
        v.image_tag,
        v.package,
        v.cve_id)
        v.*,
        COALESCE(sv.suppressed, FALSE) AS suppressed,
        sv.reason,
        sv.reason_text,
        sv.suppressed_by,
        sv.updated_at AS suppressed_at
    FROM
        resolved_vulnerabilities v
        LEFT JOIN suppressed_vulnerabilities sv ON v.image_name = sv.image_name
            AND v.package = sv.package
            AND v.cve_id = sv.cve_id
    WHERE (sqlc.narg('include_suppressed')::BOOLEAN IS TRUE
        OR COALESCE(sv.suppressed, FALSE) = FALSE)
    AND (sqlc.narg('since')::TIMESTAMPTZ IS NULL
        OR v.severity_since > sqlc.narg('since')::TIMESTAMPTZ)
    AND (sqlc.narg('severity')::INT IS NULL
        OR v.severity = sqlc.narg('severity')::INT))
SELECT
    id,
    image_name,
    image_tag,
    package,
    cve_id,
    latest_version,
    created_at,
    updated_at,
    severity_since,
    cvss_score,
    epss_score,
    epss_percentile,
    has_kev_entry,
    known_ransomware_use,
    cve_title,
    cve_desc,
    cve_link,
    severity,
    cve_refs AS cve_refs,
    cve_created_at,
    cve_updated_at,
    COALESCE(suppressed, FALSE) AS suppressed,
    reason,
    reason_text,
    suppressed_by,
    suppressed_at,
    fix_version,
    priority,
    COUNT(id) OVER () AS total_count
FROM
    distinct_image_vulnerabilities
ORDER BY
    CASE WHEN sqlc.narg('order_by') = 'priority_asc' THEN
        priority
    END ASC NULLS LAST,
    CASE WHEN sqlc.narg('order_by') = 'priority_desc' THEN
        priority
    END DESC NULLS LAST,
    CASE WHEN sqlc.narg('order_by') = 'severity_asc' THEN
        severity
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'severity_desc' THEN
        severity
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'severity_since_asc' THEN
        severity_since
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'severity_since_desc' THEN
        severity_since
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'package_asc' THEN
        package
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'package_desc' THEN
        package
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'cve_id_asc' THEN
        cve_id
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'cve_id_desc' THEN
        cve_id
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'suppressed_asc' THEN
        COALESCE(suppressed, FALSE)
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'suppressed_desc' THEN
        COALESCE(suppressed, FALSE)
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'reason_asc' THEN
        reason
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'reason_desc' THEN
        reason
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'created_at_asc' THEN
        created_at
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'created_at_desc' THEN
        created_at
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'updated_at_asc' THEN
        updated_at
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'updated_at_desc' THEN
        updated_at
    END DESC,
    severity,
    id ASC
LIMIT sqlc.arg('limit')
    OFFSET sqlc.arg('offset');

-- name: ListVulnerabilities :many
SELECT
    v.id,
    w.name AS workload_name,
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
    sv.updated_at AS suppressed_at,
    c.cvss_score,
    c.epss_score,
    c.epss_percentile,
    c.has_kev_entry,
    c.known_ransomware_use,
    v.fix_version,
    c.priority
FROM
    vulnerabilities v
    LEFT JOIN cve_alias ca ON v.cve_id = ca.alias
    JOIN cve c ON c.cve_id = COALESCE(ca.canonical_cve_id, v.cve_id)
    JOIN workloads w ON v.image_name = w.image_name
        AND v.image_tag = w.image_tag
    LEFT JOIN suppressed_vulnerabilities sv ON v.image_name = sv.image_name
        AND v.package = sv.package
        AND COALESCE(ca.canonical_cve_id, v.cve_id) = sv.cve_id
WHERE (
    CASE WHEN sqlc.narg('cluster')::TEXT IS NOT NULL THEN
        w.cluster = sqlc.narg('cluster')::TEXT
    ELSE
        TRUE
    END)
AND (
    CASE WHEN sqlc.narg('namespace')::TEXT IS NOT NULL THEN
        w.namespace = sqlc.narg('namespace')::TEXT
    ELSE
        TRUE
    END)
AND (
    CASE WHEN sqlc.narg('workload_type')::TEXT IS NOT NULL THEN
        w.workload_type = sqlc.narg('workload_type')::TEXT
    ELSE
        TRUE
    END)
AND (
    CASE WHEN sqlc.narg('workload_name')::TEXT IS NOT NULL THEN
        w.name = sqlc.narg('workload_name')::TEXT
    ELSE
        TRUE
    END)
AND (
    CASE WHEN sqlc.narg('image_name')::TEXT IS NOT NULL THEN
        v.image_name = sqlc.narg('image_name')::TEXT
    ELSE
        TRUE
    END)
AND (
    CASE WHEN sqlc.narg('image_tag')::TEXT IS NOT NULL THEN
        v.image_tag = sqlc.narg('image_tag')::TEXT
    ELSE
        TRUE
    END)
AND (sqlc.narg('include_suppressed')::BOOLEAN IS TRUE
    OR COALESCE(sv.suppressed, FALSE) = FALSE)
ORDER BY
    CASE WHEN sqlc.narg('order_by') = 'priority_asc' THEN
        c.priority
    END ASC NULLS LAST,
    CASE WHEN sqlc.narg('order_by') = 'priority_desc' THEN
        c.priority
    END DESC NULLS LAST,
    CASE WHEN sqlc.narg('order_by') = 'severity_asc' THEN
        c.severity
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'severity_desc' THEN
        c.severity
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'workload_asc' THEN
        w.name
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'workload_desc' THEN
        w.name
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_asc' THEN
        w.namespace
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_desc' THEN
        w.namespace
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_asc' THEN
        w.cluster
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_desc' THEN
        w.cluster
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'created_at_asc' THEN
        v.created_at
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'created_at_desc' THEN
        v.created_at
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'updated_at_asc' THEN
        v.updated_at
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'updated_at_desc' THEN
        v.updated_at
    END DESC,
    v.id ASC
LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset');

-- name: ListSuppressedVulnerabilitiesForImage :many
SELECT
    *
FROM
    suppressed_vulnerabilities
WHERE
    image_name = @image_name
ORDER BY
    updated_at DESC;

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
    c.severity AS last_severity,
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
    c.cvss_score,
    c.epss_score,
    c.epss_percentile,
    c.has_kev_entry,
    c.known_ransomware_use,
    v.fix_version,
    c.priority,
    COUNT(v.id) OVER () AS total_count
FROM
    vulnerabilities v
    LEFT JOIN cve_alias ca ON v.cve_id = ca.alias
    JOIN cve c ON c.cve_id = COALESCE(ca.canonical_cve_id, v.cve_id)
    JOIN workloads w ON v.image_name = w.image_name
        AND v.image_tag = w.image_tag
    LEFT JOIN suppressed_vulnerabilities sv ON v.image_name = sv.image_name
        AND v.package = sv.package
        AND COALESCE(ca.canonical_cve_id, v.cve_id) = sv.cve_id
    LEFT JOIN vulnerabilities v_canonical ON ca.canonical_cve_id IS NOT NULL
        AND v_canonical.image_name = v.image_name
        AND v_canonical.image_tag = v.image_tag
        AND v_canonical.package = v.package
        AND v_canonical.cve_id = ca.canonical_cve_id
WHERE
    v_canonical.id IS NULL
    AND (sqlc.narg('cve_ids')::TEXT[] IS NULL
        OR COALESCE(ca.canonical_cve_id, v.cve_id) = ANY (sqlc.narg('cve_ids')::TEXT[]))
    AND (sqlc.narg('cvss_score')::FLOAT8 IS NULL
        OR (c.cvss_score IS NOT NULL
            AND c.cvss_score >= sqlc.narg('cvss_score')::FLOAT8))
    AND (
        CASE WHEN sqlc.narg('cluster')::TEXT IS NOT NULL THEN
            w.cluster = sqlc.narg('cluster')::TEXT
        ELSE
            TRUE
        END)
    AND (cardinality(sqlc.arg('exclude_clusters')::TEXT[]) = 0
        OR w.cluster <> ALL (sqlc.arg('exclude_clusters')::TEXT[]))
    AND (cardinality(sqlc.arg('namespaces')::TEXT[]) = 0
        OR w.namespace = ANY (sqlc.arg('namespaces')::TEXT[]))
    AND (cardinality(sqlc.arg('exclude_namespaces')::TEXT[]) = 0
        OR w.namespace <> ALL (sqlc.arg('exclude_namespaces')::TEXT[]))
    AND (sqlc.narg('workload_types')::TEXT[] IS NULL
        OR w.workload_type = ANY (sqlc.narg('workload_types')::TEXT[]))
    AND (
        CASE WHEN sqlc.narg('workload_name')::TEXT IS NOT NULL THEN
            w.name = sqlc.narg('workload_name')::TEXT
        ELSE
            TRUE
        END)
    AND (
        CASE WHEN sqlc.narg('image_name')::TEXT IS NOT NULL THEN
            v.image_name = sqlc.narg('image_name')::TEXT
        ELSE
            TRUE
        END)
    AND (
        CASE WHEN sqlc.narg('image_tag')::TEXT IS NOT NULL THEN
            v.image_tag = sqlc.narg('image_tag')::TEXT
        ELSE
            TRUE
        END)
    AND (sqlc.narg('include_suppressed')::BOOLEAN IS TRUE
        OR COALESCE(sv.suppressed, FALSE) = FALSE)
ORDER BY
    CASE WHEN sqlc.narg('order_by') = 'priority_asc' THEN
        c.priority
    END ASC NULLS LAST,
    CASE WHEN sqlc.narg('order_by') = 'priority_desc' THEN
        c.priority
    END DESC NULLS LAST,
    CASE WHEN sqlc.narg('order_by') = 'cvss_score_desc' THEN
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
        c.cvss_score
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'cve_id_desc' THEN
        v.cve_id
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'cve_id_asc' THEN
        v.cve_id
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'workload_asc' THEN
        w.name
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'workload_desc' THEN
        w.name
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_asc' THEN
        w.namespace
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'namespace_desc' THEN
        w.namespace
    END DESC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_asc' THEN
        w.cluster
    END ASC,
    CASE WHEN sqlc.narg('order_by') = 'cluster_desc' THEN
        w.cluster
    END DESC,
    v.id ASC
LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset');

-- name: GetCanonicalCveIdByAlias :one
SELECT
    canonical_cve_id
FROM
    cve_alias
WHERE
    alias = @alias;

-- name: UpdateCvePriority :exec
UPDATE
    cve
SET
    priority = CASE WHEN has_kev_entry = TRUE THEN
        1
    WHEN known_ransomware_use = TRUE
        OR COALESCE(epss_percentile, 0) >= 0.90 THEN
        2
    WHEN severity IN (0, 1)
        AND COALESCE(epss_percentile, 0) >= 0.50 THEN
        3
    ELSE
        4
    END
WHERE
    priority IS DISTINCT FROM CASE WHEN has_kev_entry = TRUE THEN
        1
    WHEN known_ransomware_use = TRUE
        OR COALESCE(epss_percentile, 0) >= 0.90 THEN
        2
    WHEN severity IN (0, 1)
        AND COALESCE(epss_percentile, 0) >= 0.50 THEN
        3
    ELSE
        4
    END;
