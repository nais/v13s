-- +goose Up

CREATE OR REPLACE VIEW v_cve_alias AS
SELECT
    r.v::text AS alias_id,
    r.k       AS canonical_id
FROM cve
    CROSS JOIN LATERAL jsonb_each_text(refs) AS r(k, v);

CREATE OR REPLACE VIEW v_canonical_vulnerabilities AS
SELECT
    DISTINCT ON(v.image_name, v.image_tag, v.package, COALESCE(ca.canonical_id, v.cve_id)::TEXT)
    COALESCE(ca.canonical_id, v.cve_id)::TEXT AS cve_id,
    c.cve_title,
    c.cve_desc,
    c.cve_link,
    c.severity,
    c.refs::jsonb AS cve_refs,
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
    v.cvss_score,
    COALESCE(sv.suppressed, FALSE) AS suppressed,
    sv.reason,
    sv.reason_text,
    sv.suppressed_by,
    sv.updated_at as suppressed_at
FROM vulnerabilities v
    LEFT JOIN v_cve_alias ca ON v.cve_id = ca.alias_id
    JOIN cve c ON c.cve_id = COALESCE(ca.canonical_id, v.cve_id)
    LEFT JOIN suppressed_vulnerabilities sv ON
        v.image_name = sv.image_name
        AND v.package = sv.package
        -- TODO: what about aliasing here? should we have a separate view for canonical suppressed vulnerabilities, i.e. adding the join in another view?
        AND COALESCE(ca.canonical_id, v.cve_id) = sv.cve_id
;

CREATE OR REPLACE VIEW v_calc_summary_by_image AS
WITH severity_counts AS (
    SELECT image_name,
           image_tag,
           COUNT(*)                             AS total,
           COUNT(*) FILTER (WHERE severity = 0) AS critical,
           COUNT(*) FILTER (WHERE severity = 1) AS high,
           COUNT(*) FILTER (WHERE severity = 2) AS medium,
           COUNT(*) FILTER (WHERE severity = 3) AS low,
           COUNT(*) FILTER (WHERE severity = 4) AS unassigned
    FROM v_canonical_vulnerabilities
    WHERE NOT suppressed
    GROUP BY image_name, image_tag
)
SELECT  image_name,
        image_tag,
        critical,
        high,
        medium,
        low,
        unassigned,
        10 * critical
        + 5 * high
        + 3 * medium
        + 1 * low
        + 5 * unassigned AS risk_score,
        total
FROM severity_counts
;
