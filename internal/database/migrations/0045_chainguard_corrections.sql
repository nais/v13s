-- +goose Up
CREATE TABLE chainguard_corrections(
    advisory_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
    package_purl TEXT NOT NULL,
    fix_status fix_status NOT NULL,
    fix_version TEXT,
    source_url TEXT NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (advisory_id, package_purl)
);

-- +goose StatementBegin
CREATE FUNCTION recalculate_vulnerability_summary(target_image_name TEXT, target_image_tag TEXT)
    RETURNS VOID VOLATILE
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM
        pg_advisory_xact_lock_shared(7705370004);
    WITH resolved_vulnerabilities AS(
        SELECT DISTINCT
            c.cve_id AS id,
            c.severity,
            c.epss_score,
            c.epss_percentile,
            c.has_kev_entry,
            c.known_ransomware_use,
            v.package,
            v.image_name,
            v.image_tag
        FROM
            vulnerabilities v
        LEFT JOIN chainguard_corrections cc ON cc.advisory_id = v.cve_id
            AND cc.package_purl = v.package
        LEFT JOIN cve_alias ca ON v.cve_id = ca.alias
        JOIN cve c ON c.cve_id = COALESCE(ca.canonical_cve_id, v.cve_id)
    WHERE
        v.image_name = target_image_name
        AND v.image_tag = target_image_tag
        AND cc.fix_status IS DISTINCT FROM 'installed_version_fixed'
),
unsuppressed_vulnerabilities AS(
    SELECT
        rv.id,
        rv.severity,
        rv.epss_score,
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
counts AS(
    SELECT
        COUNT(*) FILTER(WHERE severity = 0) AS critical,
    COUNT(*) FILTER(WHERE severity = 1) AS high,
    COUNT(*) FILTER(WHERE severity = 2) AS medium,
    COUNT(*) FILTER(WHERE severity = 3) AS low,
    COUNT(*) FILTER(WHERE severity = 4) AS unassigned,
    COUNT(*) FILTER(WHERE has_kev_entry = TRUE) AS kev_count,
    COUNT(*) FILTER(WHERE has_kev_entry = TRUE
        OR known_ransomware_use = TRUE
        OR COALESCE(epss_percentile, 0) >= 0.95
        OR COALESCE(epss_score, 0) >= 0.10) AS high_risk,
    COUNT(*) FILTER(WHERE NOT(has_kev_entry = TRUE
        OR known_ransomware_use = TRUE
        OR COALESCE(epss_percentile, 0) >= 0.95
        OR COALESCE(epss_score, 0) >= 0.10)
    AND severity IN(0, 1)
    AND epss_percentile >= 0.90) AS elevated_risk,
COUNT(*) FILTER(WHERE NOT(has_kev_entry = TRUE
    OR known_ransomware_use = TRUE
    OR COALESCE(epss_percentile, 0) >= 0.95
    OR COALESCE(epss_score, 0) >= 0.10)
AND(severity NOT IN(0, 1)
    OR epss_percentile IS NULL
    OR epss_percentile < 0.90)) AS monitor,
COUNT(*) FILTER(WHERE known_ransomware_use = TRUE) AS ransomware_count,
COUNT(*) FILTER(WHERE epss_percentile >= 0.90) AS high_epss_count,
MIN(
    CASE WHEN has_kev_entry = TRUE
        OR known_ransomware_use = TRUE
        OR COALESCE(epss_percentile, 0) >= 0.95
        OR COALESCE(epss_score, 0) >= 0.10 THEN
        2
    WHEN severity IN(0, 1)
        AND epss_percentile >= 0.90 THEN
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
    kev_count,
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
    target_image_name,
    target_image_tag,
    critical,
    high,
    medium,
    low,
    unassigned,
    kev_count,
    high_risk,
    elevated_risk,
    monitor,
    ransomware_count,
    high_epss_count,
    top_risk_tier,
    10 * critical + 5 * high + 3 * medium + low + 5 * unassigned,
    NOW(),
    NOW()
FROM
    counts
ON CONFLICT(image_name,
    image_tag)
    DO UPDATE SET
        critical = EXCLUDED.critical,
        high = EXCLUDED.high,
        medium = EXCLUDED.medium,
        low = EXCLUDED.low,
        unassigned = EXCLUDED.unassigned,
        kev_count = EXCLUDED.kev_count,
        high_risk = EXCLUDED.high_risk,
        elevated_risk = EXCLUDED.elevated_risk,
        monitor = EXCLUDED.monitor,
        ransomware_count = EXCLUDED.ransomware_count,
        high_epss_count = EXCLUDED.high_epss_count,
        top_risk_tier = EXCLUDED.top_risk_tier,
        risk_score = EXCLUDED.risk_score,
        updated_at = NOW();
END;
$$;

-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION refresh_cve_workload_counts()
    RETURNS VOID VOLATILE
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM
        pg_advisory_xact_lock_shared(7705370004);
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_cve_workload_counts;
END;
$$;

-- +goose StatementEnd
CREATE MATERIALIZED VIEW mv_cve_workload_counts_new AS
WITH active_workloads AS (
    SELECT
        w.*
    FROM
        workloads w
        JOIN images i ON i.name = w.image_name
            AND i.tag = w.image_tag
    WHERE
        workload_has_usable_sbom(w.state, i.state)
),
used_images AS (
    SELECT DISTINCT
        image_name,
        image_tag
    FROM
        active_workloads
),
image_cves AS (
    SELECT
        v.image_name,
        v.image_tag,
        COALESCE(ca.canonical_cve_id, v.cve_id) AS cve_id,
        BOOL_OR(NOT COALESCE(sv.suppressed, FALSE)) AS has_unsuppressed
    FROM
        used_images ui
        JOIN vulnerabilities v ON v.image_name = ui.image_name
            AND v.image_tag = ui.image_tag
        LEFT JOIN chainguard_corrections cc ON cc.advisory_id = v.cve_id
            AND cc.package_purl = v.package
        LEFT JOIN cve_alias ca ON ca.alias = v.cve_id
        LEFT JOIN suppressed_vulnerabilities sv ON sv.image_name = v.image_name
            AND sv.package = v.package
            AND sv.cve_id = COALESCE(ca.canonical_cve_id, v.cve_id)
    WHERE
        cc.fix_status IS DISTINCT FROM 'installed_version_fixed'
    GROUP BY
        v.image_name,
        v.image_tag,
        COALESCE(ca.canonical_cve_id, v.cve_id))
SELECT
    ic.cve_id,
    w.cluster,
    w.namespace,
    w.workload_type,
    COUNT(*)::INT AS affected_workloads,
(COUNT(*) FILTER (WHERE ic.has_unsuppressed))::INT AS unsuppressed_workloads
FROM
    image_cves ic
    JOIN active_workloads w ON w.image_name = ic.image_name
        AND w.image_tag = ic.image_tag
GROUP BY
    ic.cve_id,
    w.cluster,
    w.namespace,
    w.workload_type;

CREATE UNIQUE INDEX idx_mv_cve_workload_counts_unique_new ON mv_cve_workload_counts_new(cve_id, CLUSTER, namespace, workload_type);

DROP MATERIALIZED VIEW mv_cve_workload_counts;

ALTER MATERIALIZED VIEW mv_cve_workload_counts_new RENAME TO mv_cve_workload_counts;

ALTER INDEX idx_mv_cve_workload_counts_unique_new RENAME TO idx_mv_cve_workload_counts_unique;

ANALYZE mv_cve_workload_counts;

-- +goose Down
CREATE MATERIALIZED VIEW mv_cve_workload_counts_new AS
WITH active_workloads AS (
    SELECT
        w.*
    FROM
        workloads w
        JOIN images i ON i.name = w.image_name
            AND i.tag = w.image_tag
    WHERE
        workload_has_usable_sbom(w.state, i.state)
),
used_images AS (
    SELECT DISTINCT
        image_name,
        image_tag
    FROM
        active_workloads
),
image_cves AS (
    SELECT
        v.image_name,
        v.image_tag,
        COALESCE(ca.canonical_cve_id, v.cve_id) AS cve_id,
        BOOL_OR(NOT COALESCE(sv.suppressed, FALSE)) AS has_unsuppressed
    FROM
        used_images ui
        JOIN vulnerabilities v ON v.image_name = ui.image_name
            AND v.image_tag = ui.image_tag
        LEFT JOIN cve_alias ca ON ca.alias = v.cve_id
        LEFT JOIN suppressed_vulnerabilities sv ON sv.image_name = v.image_name
            AND sv.package = v.package
            AND sv.cve_id = COALESCE(ca.canonical_cve_id, v.cve_id)
    GROUP BY
        v.image_name,
        v.image_tag,
        COALESCE(ca.canonical_cve_id, v.cve_id))
SELECT
    ic.cve_id,
    w.cluster,
    w.namespace,
    w.workload_type,
    COUNT(*)::INT AS affected_workloads,
(COUNT(*) FILTER (WHERE ic.has_unsuppressed))::INT AS unsuppressed_workloads
FROM
    image_cves ic
    JOIN active_workloads w ON w.image_name = ic.image_name
        AND w.image_tag = ic.image_tag
GROUP BY
    ic.cve_id,
    w.cluster,
    w.namespace,
    w.workload_type;

CREATE UNIQUE INDEX idx_mv_cve_workload_counts_unique_new ON mv_cve_workload_counts_new(cve_id, CLUSTER, namespace, workload_type);

DROP MATERIALIZED VIEW mv_cve_workload_counts;

ALTER MATERIALIZED VIEW mv_cve_workload_counts_new RENAME TO mv_cve_workload_counts;

ALTER INDEX idx_mv_cve_workload_counts_unique_new RENAME TO idx_mv_cve_workload_counts_unique;

ANALYZE mv_cve_workload_counts;

DROP FUNCTION recalculate_vulnerability_summary(TEXT, TEXT);

DROP FUNCTION refresh_cve_workload_counts();

DROP TABLE chainguard_corrections;
