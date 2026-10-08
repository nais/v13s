-- +goose Up
-- Only count workloads with a usable SBOM, matching ListVulnerabilitySummaries.
CREATE MATERIALIZED VIEW mv_cve_workload_counts_new AS
WITH active_workloads AS (
    SELECT
        w.*
    FROM
        workloads w
        JOIN images i ON i.name = w.image_name
            AND i.tag = w.image_tag
    WHERE
        w.state NOT IN ('no_attestation', 'failed', 'unrecoverable')
        AND i.state NOT IN ('failed', 'unused')
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

-- +goose Down
DROP MATERIALIZED VIEW IF EXISTS mv_cve_workload_counts;

CREATE MATERIALIZED VIEW mv_cve_workload_counts AS
WITH used_images AS (
    SELECT DISTINCT
        image_name,
        image_tag
    FROM
        workloads
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
    JOIN workloads w ON w.image_name = ic.image_name
        AND w.image_tag = ic.image_tag
GROUP BY
    ic.cve_id,
    w.cluster,
    w.namespace,
    w.workload_type;

CREATE UNIQUE INDEX idx_mv_cve_workload_counts_unique ON mv_cve_workload_counts(cve_id, CLUSTER, namespace, workload_type);
