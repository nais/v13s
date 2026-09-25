-- name: BulkUpdateKevData :execrows
-- Never clears KEV data (see CONTEXT.md); ransomware only resets when complete.
WITH data AS (
    SELECT
        unnest(@cve_ids::TEXT[]) AS cve_id,
        unnest(@known_ransomware_use::BOOLEAN[]) AS known_ransomware_use
),
source_pairs AS (
    SELECT
        unnest(@source_cve_ids::TEXT[]) AS cve_id,
        unnest(@source_names::TEXT[]) AS source
),
sources AS (
    SELECT
        cve_id,
        array_agg(source ORDER BY source) AS kev_sources
    FROM
        source_pairs
    GROUP BY
        cve_id
),
merged AS (
    SELECT
        c.cve_id,
        CASE WHEN @complete::BOOLEAN THEN d.known_ransomware_use
            ELSE c.known_ransomware_use OR d.known_ransomware_use
        END AS known_ransomware_use,
        ARRAY(SELECT DISTINCT x FROM unnest(c.kev_sources || s.kev_sources) AS x ORDER BY x) AS kev_sources
    FROM
        data d
        JOIN sources s ON s.cve_id = d.cve_id
        JOIN cve c ON c.cve_id = d.cve_id
)
UPDATE
    cve
SET
    has_kev_entry = TRUE,
    known_ransomware_use = m.known_ransomware_use,
    kev_sources = m.kev_sources,
    updated_at = NOW()
FROM
    merged m
WHERE
    cve.cve_id = m.cve_id
    AND (cve.has_kev_entry = FALSE
        OR cve.known_ransomware_use != m.known_ransomware_use
        OR cve.kev_sources IS DISTINCT FROM m.kev_sources);

-- name: GetVulnerabilitiesForOsvEnrichment :many
-- apk/deb excluded: OSV has no purl-tagged fix data for OS-distro packages.
SELECT DISTINCT
    cve_id,
    package
FROM
    vulnerabilities
WHERE
    cve_id != ''
    AND package != ''
    AND package NOT LIKE 'pkg:apk/%'
    AND package NOT LIKE 'pkg:deb/%'
ORDER BY
    cve_id, package;

-- name: BulkUpdateFixVersions :execrows
UPDATE
    vulnerabilities
SET
    fix_version = data.fix_version,
    updated_at = NOW()
FROM (
    SELECT
        unnest(@cve_ids::TEXT[]) AS cve_id,
        unnest(@packages::TEXT[]) AS package,
        unnest(@fix_versions::TEXT[]) AS fix_version) AS data
WHERE
    vulnerabilities.cve_id = data.cve_id
    AND vulnerabilities.package = data.package
    AND vulnerabilities.fix_version IS DISTINCT FROM data.fix_version;

-- name: BulkClearFixVersions :execrows
UPDATE
    vulnerabilities
SET
    fix_version = NULL,
    updated_at = NOW()
FROM (
    SELECT
        unnest(@cve_ids::TEXT[]) AS cve_id,
        unnest(@packages::TEXT[]) AS package) AS data
WHERE
    vulnerabilities.cve_id = data.cve_id
    AND vulnerabilities.package = data.package
    AND vulnerabilities.fix_version IS NOT NULL;
