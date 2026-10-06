-- +goose Up
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
        v.cve_id,
        BOOL_OR(NOT COALESCE(sv.suppressed, FALSE)) AS has_unsuppressed
    FROM
        used_images ui
        JOIN vulnerabilities v ON v.image_name = ui.image_name
            AND v.image_tag = ui.image_tag
        LEFT JOIN suppressed_vulnerabilities sv ON sv.image_name = v.image_name
            AND sv.package = v.package
            AND sv.cve_id = v.cve_id
    GROUP BY
        v.image_name,
        v.image_tag,
        v.cve_id
)
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

-- Required by REFRESH MATERIALIZED VIEW CONCURRENTLY.
CREATE UNIQUE INDEX idx_mv_cve_workload_counts_unique ON mv_cve_workload_counts(cve_id, CLUSTER, namespace, workload_type);

-- +goose Down
DROP MATERIALIZED VIEW IF EXISTS mv_cve_workload_counts;
